import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

from http import HTTPStatus
from requests.structures import CaseInsensitiveDict
from datetime import datetime, timedelta, UTC
from collections.abc import Mapping


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC
VENDOR = '1Password'
PRODUCT = '1Password'

# Default results per page (optimal value)
# > 1000 causes HTTP 400 [Bad Request]
# < 1000 increases the number of requests and may eventually trigger HTTP 429 [Rate Limit]
DEFAULT_RESULTS_PER_PAGE = 1000

DEFAULT_MAX_EVENTS_PER_FETCH = 1000

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
            ValueError: If unknown event type or missing cursor and start time.
            DemistoException: If API responds with an HTTP error status code.

        Returns:
            dict: The response JSON from the event endpoint.
        """
        demisto.debug(f'Requesting events of feature: {event_feature} using request body: {body}')
        return self._http_request(method='POST', url_suffix=f'/{event_feature}', json_data=body, raise_on_status=True)


''' HELPER FUNCTIONS '''


def get_event_from_dict(event_type: str, mapping: Mapping[str, Any]) -> Any:
    """_summary_

    Args:
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        mapping (Mapping): A key-value mapping (either a `dict` object or a `CaseInsensitiveDict`).

    Raises:
        ValueError: If unknown event type.

    Returns:
        Any: Value from the mapping dictionary.
    """
    if not (value := mapping.get(event_type)):
        raise ValueError(f'Invalid or unsupported {VENDOR} event type: {event_type}.')

    return value


def get_limit_param_for_event_type(params: dict[str, str], event_type: str) -> int | None:
    """Gets the limit parameter for a given event type. The limit represents the maximum number of events per fetch.

    Args:
        params (dict): The instance configuration parameters.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').

    Returns:
        int | None: The maximum number of events per fetch, if specified.
    """
    param_name = get_event_from_dict(event_type, mapping=EVENT_TYPE_LIMIT_PARAM)
    return arg_to_number(params.get(param_name))


def create_get_events_request_body(
    from_date: datetime | None = None,
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
    pagination_cursor: str | None = None,
) -> dict[str, Any]:
    if pagination_cursor:
        return {'cursor': pagination_cursor}

    if from_date:
        formatted_from_date: str = from_date.strftime(DATE_FORMAT)
        return {'limit': results_per_page, 'start_time': formatted_from_date}

    raise ValueError("Either a 'pagination_cursor' or a 'from_date' need to be specified.")


def add_fields_to_event(event: dict[str, Any], event_type: str):
    """Sets the '_time' and 'event_type' fields to an event.

    Args:
        event (dict): Event dictionary with the new fields.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
    """
    event_time = arg_to_datetime(event['timestamp'], required=True)
    event['_time'] = event_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]
    event['event_type'] = event_type


def get_events_from_client(
    client: Client,
    event_type: str,
    from_date: datetime,
    max_events: int | None = None,
    ids_to_skip: set[str] | None = None
) -> list[dict]:
    """Gets events of the specified type based on the `from_date` filter and `max_events` argument using cursor-based pagination.

    The first API call in each fetch run uses a "Reset Cursor" (date filter). Subsequent API calls in the same fetch run use
    "Pagination / Continuing Cursor". This ensures that even if we fetch part of the records on a given page and stop in the
    middle because we reached `max_events`, we can continue exactly where we stopped in the next fetch run via the Reset Cursor.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        from_date (datetime): Datetime from which to get events.
        max_events (int | None): Optional maximum number of events to fetch - uses API default (100) if not specified.
        ids_to_skip (set | None): Optional set of already-fetched event UUIDs that should be skipped.

    Raises:
        ValueError: If invalid event type or request body.
        DemistoException: If API request failed.

    Returns:
        list[dict]: List of events.
    """
    event_feature = get_event_from_dict(event_type, mapping=EVENT_TYPE_FEATURE)

    events: list[dict] = []
    ids_to_skip = ids_to_skip or set()

    # Reset Cursor - First call to the paginated API needs to to include a date filter
    has_more_events = True
    request_body = create_get_events_request_body(from_date=from_date)

    while has_more_events:
        response_duplicate_count = 0
        response = client.get_events(event_feature, body=request_body)
        pagination_cursor = response['cursor']

        for event in response['items']:
            event_id = event['uuid']

            if event_id in ids_to_skip:
                response_duplicate_count += 1
                demisto.debug(f'Skipped duplicate event with ID: {event_id}')
                continue

            if len(events) == max_events:
                demisto.debug(f'Reached maximum number of events {max_events}. Last event ID: {event_id}')
                break

            add_fields_to_event(event, event_type)
            events.append(event)
            ids_to_skip.add(event_id)

        demisto.debug(
            f'Response has {len(response["items"])} events of type {event_type} '
            f'(including {response_duplicate_count} skipped duplicates). '
            f'Got pagination cursor: {pagination_cursor}. Used request body: {request_body}.'
        )

        # Pagination / Continuing cursor - Followup API calls need to the unique page ID (if any more events)
        has_more_events = False if len(events) == max_events else response['has_more']
        request_body = create_get_events_request_body(pagination_cursor=pagination_cursor)

    return events


def push_events(events: list[dict], next_run: dict[str, Any] | None = None) -> None:
    """Sends events to XSIAM and optionally sets next run (if `next_run` is given).

    Args:
        events (list): List of event dictionaries.
        next_run (dict | None): Optional next run dictionary of all event types. Defaults to None.
    """
    demisto.debug(f'Starting to send {len(events)} events to XSIAM')
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

    if next_run:
        demisto.debug(f'Setting next run to {next_run}')
        demisto.setLastRun(next_run)


''' COMMAND FUNCTIONS '''


def fetch_events(
    client: Client,
    event_type: str,
    event_type_last_run: dict[str, Any],
    event_type_max_results: int | None,
) -> tuple[dict, list]:
    """Fetches new events via 1Password Events API client based on a specified event type.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        event_type_last_run (dict): Dictionary of the event type last run (if exists) with optional 'from_date' and 'ids' list.
        event_type_max_results (int | None): Maximum number of events to fetch - uses API default (100) if not specified.

    Returns:
        tuple[dict, list]: Dictionary of the next run of the event type with 'from_date' and 'ids' list, list of fetched events.
    """
    last_run_skip_ids = set(event_type_last_run.get('ids') or [])
    from_date = arg_to_datetime(event_type_last_run.get('from_date')) or DEFAULT_FETCH_FROM_DATE

    demisto.debug(f'Fetching events of type: {event_type} from date: {from_date.isoformat()}')

    event_type_events = get_events_from_client(
        client=client,
        event_type=event_type,
        from_date=from_date,
        max_events=event_type_max_results,
        ids_to_skip=last_run_skip_ids,
    )

    if event_type_events:
        # API returns events sorted by timestamp in ascending order (oldest to newest), so last event has max timestamp
        max_timestamp = event_type_events[-1]['timestamp']
        next_run_skip_ids = [event['uuid'] for event in event_type_events if event['timestamp'] == max_timestamp]
        event_type_next_run = {'from_date': max_timestamp, 'ids': next_run_skip_ids}
    else:
        event_type_next_run = event_type_last_run
        max_timestamp = None

    demisto.debug(
        f'Fetched {len(event_type_events)} events of type: {event_type} out of a maximum of {event_type_max_results}. '
        f'Last event timestamp: {max_timestamp}'
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
    limit = arg_to_number(args.get('limit'))
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
    base_url: str = urljoin(params['url'], '/api/v2')
    token: str = params['credentials']['password']
    event_types: list[str] = argToList(params['event_types'])

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
                event_type_key = get_event_from_dict(event_type, mapping=EVENT_TYPE_FEATURE)

                event_type_last_run: dict = last_run.get(event_type_key, {})
                event_type_max_results: int | None = get_limit_param_for_event_type(params, event_type)

                event_type_next_run, event_type_events = fetch_events(
                    client=client,
                    event_type=event_type,
                    event_type_last_run=event_type_last_run,
                    event_type_max_results=event_type_max_results,
                )
                all_events.extend(event_type_events)
                next_run[event_type_key] = event_type_next_run

            push_events(all_events, next_run=next_run)

        else:
            raise NotImplementedError(f'Unknown command {command!r}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command!r} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
