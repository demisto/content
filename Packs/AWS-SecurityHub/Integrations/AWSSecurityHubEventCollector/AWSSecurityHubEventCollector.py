import datetime as dt

import demistomock as demisto
from AWSApiModule import *

import urllib3

import boto3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = 'AWS'
PRODUCT = 'Security Hub'
TIME_FIELD = 'UpdatedAt'
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_FIRST_FETCH = '3 days'
DEFAULT_MAX_RESULTS = 1000  # Default maximum number of results to fetch


def get_events(client: boto3.client, start_time: dt.datetime | None = None,
               end_time: dt.datetime | None = None,
               id_ignore_list: list[str] | None = None, limit: int = 0) -> list[dict]:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (boto3.client): Boto3 client to use.
        start_time (datetime | None, optional): Start time to fetch events from. Required if end_time is set.
        end_time (datetime | None, optional): Time to fetch events until. Defaults to current time.
        limit (int): Maximum number of events to fetch. Defaults to 0 (no limit).
        id_ignore_list (list[str] | None, optional): List of finding IDs to not include in the results.
            Defaults to None.

    Returns:
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
        ignore_filters = []
        for event_id in id_ignore_list:
            ignore_filters.append({'Value': event_id, 'Comparison': 'NOT_EQUALS'})

        filters['Id'] = ignore_filters

    if filters:
        # We send kwargs because passing Filters=None to get_findings() tries to use a None value for filters,
        # which raises an error.
        kwargs['Filters'] = filters

    events: list[dict] = []

    while True:
        # The API only allows a maximum of 100 results per request. Using more raises an error.
        if limit and limit - len(events) < 100:
            kwargs['MaxResults'] = limit - len(events)

        else:
            kwargs['MaxResults'] = 100

        response = client.get_findings(**kwargs)
        events.extend(response.get('Findings', []))

        if 'NextToken' in response and (limit == 0 or len(events) < limit):
            kwargs['NextToken'] = response['NextToken']

        else:
            break

    return events


def fetch_events(client: boto3.client, last_run: dict,
                 first_fetch_time: dt.datetime | None, limit: int = 0) -> tuple[dict, list]:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (boto3.client): Boto3 client to use.
        last_run (dict): Dict containing the last fetched event creation time.
        first_fetch_time (datetime | None, optional): In case of first fetch, fetch events from this datetime.
        limit (int): Maximum number of events to fetch. Defaults to 0 (no limit).

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be generated in XSIAM.
    """
    if last_run.get('last_update_date'):
        start_time = parse_date_string(last_run['last_update_date'])

    else:
        start_time = first_fetch_time

    id_ignore_list: list = last_run.get('last_update_date_finding_ids', [])

    events = get_events(
        client=client,
        start_time=start_time,
        id_ignore_list=id_ignore_list,
        limit=limit
    )

    last_finding_update_time: str | None = events[-1].get(TIME_FIELD) if events else last_run.get('last_update_date')
    demisto.info(f'Fetched {len(events)} findings.\nUpdate time of last finding: {last_finding_update_time}.')

    # --- Set next_run data ---
    # Since the time filters seem to be equal or greater than (which results in duplicate from the last run),
    # we add findings that are equal to 'last_finding_update_time' and filter them out in the next fetch.
    ignore_list: list[str] = []

    for event in reversed(events):
        if event[TIME_FIELD] == last_finding_update_time:
            ignore_list.append(event['Id'])

        else:
            break  # Since it's a sorted list, no need to check the rest.

    next_run = {
        'last_update_date': last_finding_update_time,
        'last_update_date_finding_ids': ignore_list,
    }

    demisto.info(f'Setting next run to: {next_run}.')
    return next_run, events


def get_events_command(client: boto3.client, should_push_events: bool = False, limit: int = 0) -> CommandResults:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (boto3.client): Boto3 client to use.
        should_push_events (bool, optional): Whether to push events to XSIAM. Defaults to False.
        limit (int, optional): Maximum number of events to fetch. Defaults to 0 (no limit).

    Returns:
        CommandResults: CommandResults object containing the events.
    """
    events = get_events(client=client, limit=limit)

    if should_push_events:
        send_events_to_xsiam(
            events,
            vendor=VENDOR,
            product=PRODUCT
        )

    return CommandResults(
        readable_output=tableToMarkdown('AWS Security Hub Events', events, sort_headers=False),
    )


def main():
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

    limit: int = arg_to_number(params.get('max_fetch', DEFAULT_MAX_RESULTS))  # type: ignore

    # How much time before the first fetch to retrieve events
    first_fetch_time: dt.datetime = arg_to_datetime(
        arg=params.get('first_fetch', DEFAULT_FIRST_FETCH),
        arg_name='First fetch time',
        required=True
    )   # type: ignore

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

        client = aws_client.aws_session(
            service='securityhub',
            region=aws_default_region,
            role_arn=aws_role_arn,
            role_session_name=aws_role_session_name,
            role_session_duration=aws_role_session_duration,
        )

        demisto.info(f'Executing \"{command}\" command...')

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            get_events(client, limit=1)
            return_results('ok')

        elif command == 'aws-securityhub-get-events':
            should_push_events = argToBoolean(args.get('should_push_events', False))
            command_limit: int = arg_to_number(args.get('limit', limit))  # type: ignore
            return_results(
                get_events_command(client=client, should_push_events=should_push_events, limit=command_limit))

        elif command == 'fetch-events':
            next_run, events = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                limit=limit,
            )

            # Saves next_run for the time fetch-events is invoked
            demisto.setLastRun(next_run)
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

        else:
            raise NotImplementedError(f'Command \"{command}\" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
