import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import datetime as dt
from typing import TYPE_CHECKING, cast
from collections.abc import Iterator

from AWSApiModule import *

# The following import are used only for type hints and autocomplete.
# It is not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_securityhub import SecurityHubClient
    from mypy_boto3_securityhub.type_defs import AwsSecurityFindingTypeDef


VENDOR = 'AWS'
PRODUCT = 'Security Hub'
TIME_FIELD = 'CreatedAt'
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_FIRST_FETCH = '3 days'
DEFAULT_MAX_RESULTS = 1000
API_MAX_PAGE_SIZE = 100  # The API only allows a maximum of 100 results per request. Using more raises an error.


def generate_last_run(events: list["AwsSecurityFindingTypeDef"]) -> dict[str, Any]:
    """
    Generate the last run object using events data.

    Args:
        events (list[dict]): List of events to generate the last run object from.

    Note:
        Since the time filters seem to be equal or greater than (which results in duplicate from the last run),
        we add findings that are equal to 'last_finding_update_time' and filter them out in the next fetch.


    Returns:
        dict: Last run object.
    """
    ignore_list: list[str] = []
    last_update_date = events[-1].get(TIME_FIELD)

    # Since the "_time" key is added to each event, the event type changes from "AwsSecurityFindingTypeDef" to just dict
    events = cast(list[dict[str, Any]], events)
    for event in events:
        event['_time'] = event[TIME_FIELD]

        if event[TIME_FIELD] == last_update_date:
            ignore_list.append(event['Id'])

    return {
        'last_update_date': last_update_date,
        'last_update_date_finding_ids': ignore_list,
    }


def get_events(client: "SecurityHubClient", start_time: dt.datetime | None = None,
               end_time: dt.datetime | None = None, id_ignore_list: list[str] | None = None,
               page_size: int = API_MAX_PAGE_SIZE, limit: int = 0) -> Iterator[List["AwsSecurityFindingTypeDef"]]:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (SecurityHubClient): Boto3 client to use.
        start_time (datetime | None, optional): Start time to fetch events from. Required if end_time is set.
        end_time (datetime | None, optional): Time to fetch events until. Defaults to current time.
        id_ignore_list (list[str] | None, optional): List of finding IDs to not include in the results.
            Defaults to None.
        page_size (int, optional): Number of results to fetch per request. Defaults to API_MAX_PAGE_SIZE.
        limit (int, optional): Maximum number of results to fetch. Defaults to 0.

    Yields:
        tuple[list, CommandResults]: A tuple containing the events and the CommandResults object.
    """
    kwargs: dict = {'SortCriteria': [{'Field': TIME_FIELD, 'SortOrder': 'asc'}]}
    filters: dict = {}

    if end_time and not start_time:
        raise ValueError('start_time must be set if end_time is used.')

    if start_time:
        filters[TIME_FIELD] = [{
            'Start':
                start_time.strftime(DATETIME_FORMAT),
            'End':
                end_time.strftime(DATETIME_FORMAT) if end_time else
                dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        }]

    if id_ignore_list:
        id_ignore_set = set(id_ignore_list)
    else:
        id_ignore_set = set()

    if filters:
        # We send kwargs because passing Filters=None to get_findings() tries to use a None value for filters,
        # which raises an error.
        kwargs['Filters'] = filters

    count = 0

    while True:
        if limit and limit - count < page_size:
            kwargs['MaxResults'] = limit - count

        else:
            kwargs['MaxResults'] = page_size

        response = client.get_findings(**kwargs)
        result = response.get('Findings', [])

        # Filter out events based on id_ignore_set
        result = [event for event in result if event['Id'] not in id_ignore_set]

        count += len(result)
        yield result  # type: ignore

        if 'NextToken' in response and (limit == 0 or count < limit):
            kwargs['NextToken'] = response['NextToken']

        else:
            break


def fetch_events(client: "SecurityHubClient", last_run: dict, first_fetch_time: dt.datetime | None,
                 page_size: int = API_MAX_PAGE_SIZE, limit: int = 0
                 ) -> tuple[list["AwsSecurityFindingTypeDef"], dict, Exception | None]:
    """
    Fetch events from AWS Security Hub and send them to XSIAM.

    Args:
        client (SecurityHubClient): Boto3 client to use.
        last_run (dict): Dict containing the last fetched event creation time.
        first_fetch_time (datetime | None, optional): In case of first fetch, fetch events from this datetime.
        page_size (int, optional): Number of results to fetch per request. Defaults to API_MAX_PAGE_SIZE.
        limit (int, optional): Maximum number of events to fetch. Defaults to 0 (no limit).
    """
    if last_run.get('last_update_date'):
        start_time = parse_date_string(last_run['last_update_date'])

    else:
        start_time = first_fetch_time

    id_ignore_list: list = last_run.get('last_update_date_finding_ids', [])

    events: list[AwsSecurityFindingTypeDef] = []
    error = None

    try:
        for events_batch in get_events(client=client, start_time=start_time, id_ignore_list=id_ignore_list,
                                       page_size=page_size, limit=limit):
            events.extend(events_batch)

    except Exception as e:
        demisto.error(f'Error while fetching events.'
                      f'Events fetched so far: {len(events)}'
                      f'Error: {e}')
        error = e

    # --- Set next_run data ---
    if events:
        demisto.info(f'Fetched {len(events)} findings.')
        next_run = generate_last_run(events)
        demisto.info(f'Last run data updated to: {next_run}.')

    else:
        demisto.info('No new findings were found.')
        next_run = last_run

    return events, next_run, error


def get_events_command(client: "SecurityHubClient", should_push_events: bool,
                       page_size: int, limit: int = 0) -> CommandResults:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (SecurityHubClient): Boto3 client to use.
        should_push_events (bool): Whether to push events to XSIAM.
        page_size (int, optional): Number of results to fetch per request. Defaults to API_MAX_PAGE_SIZE.
        limit (int, optional): Maximum number of events to fetch. Defaults to 0 (no limit).

    Returns:
        CommandResults: CommandResults object containing the events.
    """
    events = []

    for events_batch in get_events(client=client, page_size=page_size, limit=limit):
        events.extend(events_batch)

    if should_push_events:
        send_events_to_xsiam(
            events,
            vendor=VENDOR,
            product=PRODUCT
        )

    return CommandResults(
        readable_output=tableToMarkdown('AWS Security Hub Events', events, sort_headers=False),
    )


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    aws_role_arn = params.get('role_arn')
    aws_role_session_name = params.get('role_session_name')
    aws_default_region = params.get('default_region')
    aws_role_session_duration = params.get('role_session_duration')
    aws_access_key_id = demisto.get(params, 'credentials.identifier')
    aws_secret_access_key = demisto.get(params, 'credentials.password')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries', 5)

    limit = arg_to_number(params.get('max_fetch')) or DEFAULT_MAX_RESULTS

    if limit <= 0:
        raise ValueError("Max fetch value cannot be lower than 1.")

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', DEFAULT_FIRST_FETCH),
        arg_name='First fetch time',
        required=True
    )

    try:
        validate_params(
            aws_default_region=aws_default_region,
            aws_role_arn=aws_role_arn,
            aws_role_session_name=aws_role_session_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

        aws_client = AWSClient(
            aws_default_region=aws_default_region,
            aws_role_arn=aws_role_arn,
            aws_role_session_name=aws_role_session_name,
            aws_role_session_duration=aws_role_session_duration,
            aws_role_policy=None,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            verify_certificate=verify_certificate,
            timeout=timeout,
            retries=retries,
        )

        client: SecurityHubClient = aws_client.aws_session(
            service='securityhub',
            region=aws_default_region,
            role_arn=aws_role_arn,
            role_session_name=aws_role_session_name,
            role_session_duration=aws_role_session_duration,
        )

        demisto.info(f'Executing \"{command}\" command...')

        if command == 'test-module':
            next(get_events(client=client, limit=1))
            return_results('ok')

        elif command == 'aws-securityhub-get-events':
            should_push_events = argToBoolean(args.get('should_push_events', False))
            page_size = arg_to_number(args.get('page_size', API_MAX_PAGE_SIZE))

            if page_size is None or page_size > 100:
                raise ValueError('Page size cannot be larger than 100 (not supported by the API).')

            limit = arg_to_number(args.get('limit')) or 1

            if limit is None or limit <= 0:
                raise ValueError("Max fetch value cannot be lower than 1.")

            return_results(
                get_events_command(client=client,
                                   should_push_events=should_push_events,
                                   page_size=page_size,
                                   limit=limit))

        elif command == 'fetch-events':
            events, next_run, error = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                limit=limit,
            )

            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

            if error and events:
                raise Exception(f'An error occurred while running fetch-events. '
                                f'The operation was partially successful, but failed midway.\n'
                                f'A total of {len(events)} events were successfully fetched '
                                f'before the error occurred.') from error

            elif error:
                raise error

        else:
            raise NotImplementedError(f'Command \"{command}\" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
