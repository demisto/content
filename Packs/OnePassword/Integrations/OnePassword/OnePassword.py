import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

from http import HTTPStatus
from operator import itemgetter
from requests.structures import CaseInsensitiveDict
from datetime import datetime, timedelta, UTC


''' CONSTANTS '''

EVENT_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # For XSIAM events - second precision
FILTER_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # For 1Password date filter - microsecond precision
VENDOR = '1Password'
PRODUCT = '1Password'

# Default results per page (optimal value)
# > 1000 causes HTTP 400 [Bad Request]
# < 1000 increases the number of requests and may eventually trigger HTTP 429 [Rate Limit]
DEFAULT_RESULTS_PER_PAGE = 1000

DEFAULT_MAX_EVENTS_PER_FETCH = 100  # Consistent with API default

DEFAULT_FETCH_FROM_DATE = datetime.now(tz=UTC) - timedelta(minutes=1)  # 1 minute ago in UTC timezone

EVENT_TYPE_FEATURE = CaseInsensitiveDict(
    {
        # Display name: API Feature and endpoint name
        'Item usage actions': 'itemusages',
        'Audit events': 'auditevents',
        'Sign in attempts': 'signinattempts',
    }
)

EVENT_TYPE_LIMIT_PARAM = CaseInsensitiveDict(
    {
        # Display name: Max events per fetch (limit) param name
        'Item usage actions': 'item_usage_actions_limit',
        'Audit events': 'audit_events_limit',
        'Sign in attempts': 'sign_in_attempts_limit',
    }
)


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the 1Password Events API"""

    def get_events(self, event_feature: str, body: dict[str, Any]) -> dict[str, Any]:
        """Gets events from 1Password based on the specified event type

        Args:
            feature (str): 1Password event feature (e.g. 'itemusages', 'signinattempts').
            body (dict): The request body containing either a Reset Cursor (date filter) or a Pagination Cursor.

        Raises:
            DemistoException: If API responds with an HTTP error status code.

        Returns:
            dict: The response JSON from the event endpoint.
        """
        demisto.debug(f'Requesting events of feature: {event_feature} using request body: {body}')
        return self._http_request(method='POST', url_suffix=f'/api/v2/{event_feature}', json_data=body, raise_on_status=True)


''' HELPER FUNCTIONS '''


def get_limit_param_for_event_type(params: dict[str, str], event_type: str) -> int:
    """Gets the limit parameter for a given event type. The limit represents the maximum number of events per fetch.

    Args:
        params (dict): The instance configuration parameters.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').

    Returns:
        int: The maximum number of events per fetch.
    """
    param_name = EVENT_TYPE_LIMIT_PARAM[event_type]
    limit = arg_to_number(params.get(param_name)) or DEFAULT_MAX_EVENTS_PER_FETCH
    demisto.debug(f'Maximum number of events per fetch for {event_type} is set to {limit}.')
    return limit


def create_get_events_request_body(
    from_date: datetime | None = None,
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
    pagination_cursor: str | None = None,
) -> dict[str, Any]:
    """Creates the request body for the `Client.get_events` method.

    Args:
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        from_date (datetime | None): Optional datetime from which to get events.
        results_per_page (int): The maximum number of records in response (Recommended to use default value).

    Raises:
        ValueError: If missing cursor and from date.

    Returns:
        dict[str, Any]: The request body.
    """
    if pagination_cursor:
        return {'cursor': pagination_cursor}

    if from_date:
        formatted_from_date: str = from_date.strftime(FILTER_DATE_FORMAT)
        return {'limit': results_per_page, 'start_time': formatted_from_date}

    raise ValueError("Either a 'pagination_cursor' or a 'from_date' need to be specified.")


def add_fields_to_event(event: dict[str, Any], event_type: str):
    """Sets the '_time', 'SOURCE_LOG_TYPE', and 'timestamp_ms' fields in the event dictionary.

    Args:
        event (dict): Event dictionary with the new fields.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
    """
    event_time = arg_to_datetime(event['timestamp'], required=True)
    # Required by XSIAM
    event['SOURCE_LOG_TYPE'] = event_type.upper()
    event['_time'] = event_time.strftime(EVENT_DATE_FORMAT)  # type: ignore[union-attr]
    # Matches precision of date filter - ensures correct and accurate list of already fetched IDs
    event['timestamp_ms'] = event_time.strftime(FILTER_DATE_FORMAT)  # type: ignore[union-attr]


def get_events_from_client(
    client: Client,
    event_type: str,
    from_date: datetime,
    max_events: int,
    already_fetched_ids_to_skip: set[str] | None = None
) -> list[dict]:
    """Gets events of the specified type based on the `from_date` filter and `max_events` argument using cursor-based pagination.

    The first API call in each fetch run uses a "Reset Cursor" (date filter). Subsequent API calls in the same fetch run use
    "Pagination / Continuing Cursor". This ensures that even if we fetch part of the records on a given page and stop in the
    middle because we reached `max_events`, we can continue exactly where we stopped in the next fetch run via the Reset Cursor.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        from_date (datetime): Datetime from which to get events.
        max_events (int): Maximum number of events to fetch.
        already_fetched_ids_to_skip (set | None): Optional set of already-fetched event UUIDs that should be skipped.

    Raises:
        ValueError: If invalid event type or request body.
        DemistoException: If API request failed.

    Returns:
        list[dict]: List of events.
    """
    event_feature = EVENT_TYPE_FEATURE.get(event_type)
    if not event_feature:
        raise ValueError(f'Invalid or unsupported {VENDOR} event type: {event_type}.')

    events: list[dict] = []
    already_fetched_ids_to_skip = already_fetched_ids_to_skip or set()

    # Reset Cursor - First call to the paginated API needs to to include a date filter
    has_more_events = True
    request_body = create_get_events_request_body(from_date=from_date)

    while has_more_events:
        response_events: list[dict] = []
        response_skipped_ids: set[str] = set()
        response = client.get_events(event_feature, body=request_body)
        pagination_cursor = response['cursor']

        for event in response['items']:
            event_id = event['uuid']

            if event_id in already_fetched_ids_to_skip:
                response_skipped_ids.add(event_id)
                demisto.debug(f'Skipped duplicate event with ID: {event_id}')
                continue

            if len(events) == max_events:
                demisto.debug(f'Reached maximum number of events {max_events}. Last event ID: {event_id}')
                break

            add_fields_to_event(event, event_type)
            response_events.append(event)
            already_fetched_ids_to_skip.add(event_id)

        demisto.debug(
            f'Response has {len(response["items"])} events of type {event_type}. Saved {len(response_events)} events. '
            f'Skipped {len(response_skipped_ids)} duplicates: ({", ".join(response_skipped_ids)}). '
            f'Got pagination cursor: {pagination_cursor}. Used request body: {request_body}.'
        )
        events.extend(response_events)

        # Pagination / Continuing cursor - Followup API calls need to the unique page ID (if any more events)
        has_more_events = False if len(events) == max_events else response['has_more']
        request_body = create_get_events_request_body(pagination_cursor=pagination_cursor)

    return events


def push_events(events: list[dict]) -> None:
    """Sends events to the relevant `VENDOR` and `PRODUCT` dataset in XSIAM.

    Args:
        events (list): List of event dictionaries.
    """
    demisto.debug(f'Starting to send {len(events)} events to XSIAM.')
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)


def set_next_run(next_run: dict[str, Any]) -> None:
    """Sets next run for all event features. Should be called after events are successfully sent to XSIAM.

    Args:
        next_run (dict): Next run dictionary containing `from_date` in `FILTER_DATE_FORMAT` and `ids` list per event feature.

    Example:
        >>> set_next_run({"auditevents": {"from_date": "2024-12-02T11:54:19.710457Z", "ids": []}, "itemusages": ...})
    """
    demisto.debug(f'Setting next run to {next_run}.')
    demisto.setLastRun(next_run)


''' COMMAND FUNCTIONS '''


def fetch_events(
    client: Client,
    event_type: str,
    event_type_last_run: dict[str, Any],
    event_type_max_results: int,
) -> tuple[dict, list]:
    """Fetches new events via 1Password Events API client based on a specified event type.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        event_type_last_run (dict): Dictionary of the event type last run (if exists) with optional 'from_date' and 'ids' list.
        event_type_max_results (int): Maximum number of events of the event type to fetch.

    Returns:
        tuple[dict, list]: Dictionary of the next run of the event type with 'from_date' and 'ids' list, list of fetched events.
    """
    last_run_ids_to_skip = set(event_type_last_run.get('ids') or [])
    from_date = arg_to_datetime(event_type_last_run.get('from_date')) or DEFAULT_FETCH_FROM_DATE

    demisto.debug(f'Fetching events of type: {event_type} from date: {from_date.strftime(FILTER_DATE_FORMAT)}')

    event_type_events = get_events_from_client(
        client=client,
        event_type=event_type,
        from_date=from_date,
        max_events=event_type_max_results,
        already_fetched_ids_to_skip=last_run_ids_to_skip,
    )

    if event_type_events:
        # Use event 'timestamp_ms' since it is consistent with FILTER_DATE_FORMAT
        last_event_time = max(event_type_events, key=itemgetter('timestamp_ms'))['timestamp_ms']
        next_run_ids_to_skip = {event['uuid'] for event in event_type_events if event['timestamp_ms'] == last_event_time}
        event_type_next_run = {'from_date': last_event_time, 'ids': list(next_run_ids_to_skip)}
    else:
        last_event_time = None
        event_type_next_run = {'from_date': from_date.strftime(FILTER_DATE_FORMAT), 'ids': list(last_run_ids_to_skip)}

    demisto.debug(
        f'Fetched {len(event_type_events)} events of type: {event_type} out of a maximum of {event_type_max_results}. '
        f'Last event time: {last_event_time}.'
    )

    return event_type_next_run, event_type_events


def test_module_command(client: Client, event_types: list[str]) -> str:
    """Tests connectivity and authentication with 1Password Events API and verifies that the token has access to the
    configured event types.

    Args:
        client (Client): 1Password Events API client.
        event_types (list): List of event types from the integration configuration params.

    Returns:
        str: 'ok' if test passed, anything else will fail the test.

    Raises:
        DemistoException: If API call responds with an unhandled HTTP error status code or token does not have access to the
        configured event types.
    """
    for event_type in event_types:
        try:
            get_events_from_client(client, event_type=event_type, from_date=DEFAULT_FETCH_FROM_DATE, max_events=1)

        except DemistoException as e:
            error_status_code = e.res.status_code if isinstance(e.res, requests.Response) else None

            if error_status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                return 'Authorization Error: Make sure the API server URL and token are correctly set'

            if error_status_code == HTTPStatus.NOT_FOUND:
                return 'Endpoint Not Found: Make sure the API server URL is correctly set'

            # Some other unknown / unexpected error
            raise

    return 'ok'


def get_events_command(client: Client, args: dict[str, str]) -> tuple[list[dict], CommandResults]:
    """Implements `one-password-get-events` command, which returns a markdown table of events to the war room.

    Args:
        client (Client): 1Password Events API client.
        args (dict): The '1password-get-events' command arguments.

    Returns:
        tuple[list[dict], CommandResults]: List of events and CommandResults with human readable output.
    """
    event_type = args['event_type']
    limit = arg_to_number(args.get('limit')) or DEFAULT_MAX_EVENTS_PER_FETCH
    from_date = arg_to_datetime(args.get('from_date')) or DEFAULT_FETCH_FROM_DATE

    events = get_events_from_client(client, event_type=event_type, from_date=from_date, max_events=limit)

    human_readable = tableToMarkdown(name=event_type.capitalize(), t=flattenTable(events))

    return events, CommandResults(readable_output=human_readable)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    # required
    base_url: str = params['url']
    token: str = params.get('credentials', {}).get('password', '')
    event_types: list[str] = argToList(params['event_types'], transform=lambda event_type: event_type.strip())

    # optional
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    demisto.debug(f'Command being called is {command!r}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
            proxy=proxy,
        )

        if command == 'test-module':
            result = test_module_command(client, event_types)
            return_results(result)

        elif command == 'one-password-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))

            events, results = get_events_command(client, args)
            return_results(results)

            if should_push_events:
                push_events(events)

        elif command == 'fetch-events':
            all_events: list[dict] = []
            last_run = demisto.getLastRun()
            next_run: dict[str, Any] = {}

            for event_type in event_types:
                event_type_key = EVENT_TYPE_FEATURE[event_type]

                event_type_last_run: dict = last_run.get(event_type_key, {})
                event_type_max_results: int = get_limit_param_for_event_type(params, event_type)

                event_type_next_run, event_type_events = fetch_events(
                    client=client,
                    event_type=event_type,
                    event_type_last_run=event_type_last_run,
                    event_type_max_results=event_type_max_results,
                )
                all_events.extend(event_type_events)
                next_run[event_type_key] = event_type_next_run

            push_events(all_events)
            set_next_run(next_run)

        else:
            raise NotImplementedError(f'Unknown command {command!r}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command!r} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
