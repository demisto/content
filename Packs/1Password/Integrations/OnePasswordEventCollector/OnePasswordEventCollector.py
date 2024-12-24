import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

from http import HTTPStatus
from requests.structures import CaseInsensitiveDict
from datetime import datetime, timedelta, UTC


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC
VENDOR = '1Password'
PRODUCT = '1Password'

# Default results per page (optimal value)
# > 1000 causes HTTP 400 [Bad Request]
# < 1000 increases the number of requests and may eventually trigger HTTP 429 [Rate Limit]
DEFAULT_RESULTS_PER_PAGE = 1000

DEFAULT_MAX_EVENTS_PER_FETCH = 1000

DEFAULT_FETCH_FROM_DATE = datetime.now(tz=UTC) - timedelta(weeks=2)  # 2 weeks ago in UTC timezone

EVENT_TYPE_MAPPING = CaseInsensitiveDict(
    {
        # Display name: API Feature and endpoint name
        'Item usage actions': 'itemusages',
        'Audit events': 'auditevents',
        'Sign in attempts': 'signinattempts',
    }
)


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the 1Password Events API"""

    def introspect(self) -> dict:
        """Performs an introspect API call to check authentication status and the features (scopes) that the token can access,
        including one or more of: 'auditevents', 'itemusage', and 'signinattempts'.

        Raises:
            DemistoException: If API responds with an HTTP error status code.

        Returns:
            dict: The response JSON from the 'Auth introspect' endpoint.
        """
        return self._http_request(method='GET', url_suffix='/auth/introspect', raise_on_status=True)

    def get_events(
        self,
        event_type: str,
        from_date: datetime | None = None,
        results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
        pagination_cursor: str | None = None,
    ):
        """Gets events from 1Password based on the specified event type

        Args:
            event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
            from_date (datetime | None): Optional datetime from which to get events.
            results_per_page (int): The maximum number of records in response (Recommended to use default value).
            pagination_cursor (str | None): Pagination Cursor from previous API response.

        Raises:
            ValueError: If unknown event type or missing cursor and start time.
            DemistoException: If API responds with an HTTP error status code.

        Returns:
            dict: The response JSON from the event endpoint.
        """
        if not (feature := EVENT_TYPE_MAPPING.get(event_type)):
            raise ValueError(f'Invalid or unsupported 1Password event type: {event_type}.')

        body: dict[str, Any]
        if pagination_cursor:
            demisto.debug(f'Requesting events of type: {event_type} using pagination cursor: {pagination_cursor}')
            body = {'cursor': pagination_cursor}

        elif from_date:
            formatted_from_date: str = from_date.isoformat()
            demisto.debug(f'Requesting events of type: {event_type} using from date: {formatted_from_date}')
            body = {'limit': results_per_page, 'start_time': formatted_from_date}

        else:
            raise ValueError("Either a 'pagination_cursor' or a 'from_date' need to be specified.")

        return self._http_request(method='POST', url_suffix=f'/{feature}', json_data=body, raise_on_status=True)


''' HELPER FUNCTIONS '''


def get_limit_param(params: dict[str, str], event_type: str) -> int:
    """Gets the limit parameter for a given event type. The limit represents the maximum number of events per fetch.

    Args:
        params (dict): The instance configuration parameters.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').

    Returns:
        int: The maximum number of events per fetch.
    """
    param_name = event_type.lower().replace(' ', '_') + '_limit'
    return arg_to_number(params.get(param_name)) or DEFAULT_MAX_EVENTS_PER_FETCH


def get_unauthorized_event_types(auth_introspection_response: dict[str, Any], event_types: list[str]) -> list[str]:
    """Checks if the bearer token has no access to any of the configured event types.

    Args:
        auth_introspection_response (dict): Response JSON from Client.introspect call.
        event_types (list): List of event types from the integration configuration params.

    Returns:
        list[str]: List of unauthorized event types that the token does not have access to.
    """
    authorized_features = auth_introspection_response['features']
    return [
        event_type for event_type in event_types
        if EVENT_TYPE_MAPPING.get(event_type) not in authorized_features
    ]


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
    max_events: int,
    ids_to_skip: set[str] | None = None
) -> list[dict]:
    """Gets events of the specified type based on the 'from_date' filter and 'max_events' argument.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        from_date (datetime): Datetime from which to get events.
        max_events (int): The maximum number of events to fetch.
        ids_to_skip (set | None): Optional set of already-fetched event UUIDs that should be skipped.

    Returns:
        list[dict]: List of events.
    """
    events: list[dict] = []
    ids_to_skip = ids_to_skip or set()

    # First call to the paginated API needs to to include a date filter
    has_more_events = True
    client_kwargs: dict[str, Any] = {'event_type': event_type, 'from_date': from_date}

    while has_more_events:
        response = client.get_events(**client_kwargs)
        pagination_cursor = response['cursor']

        for event in response['items']:
            event_id = event['uuid']

            if event_id in ids_to_skip:
                demisto.debug(f'Skipped duplicate event with ID: {event_id}')
                continue

            if len(events) == max_events:
                demisto.debug(f'Reached maximum number of events {max_events}. Last event ID: {event_id}')
                break

            add_fields_to_event(event, event_type)
            events.append(event)
            ids_to_skip.add(event_id)

        demisto.debug(
            f'Response has {len(response["items"])} events and pagination cursor: {pagination_cursor}.'
            f'Used client arguments: {client_kwargs}.'
        )

        # Followup API calls need to include pagination cursor (if any more events)
        has_more_events = False if len(events) == max_events else response['has_more']
        client_kwargs = {'event_type': event_type, 'pagination_cursor': pagination_cursor}

    return events


def push_events(events: list[dict], next_run: dict[str, Any] | None = None) -> None:
    """Sends events to XSIAM and optionally sets next run (if `next_run` is given).

    Args:
        events (list): List of event dictionaries.
        next_run (dict | None): Optional next run dictionary of all event types. Defaults to None.
    """
    demisto.debug(f'Sending {len(events)} to XSIAM')
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

    if next_run:
        demisto.debug(f'Setting next run to {next_run}')
        demisto.setLastRun(next_run)


''' COMMAND FUNCTIONS '''


def fetch_events(
    client: Client,
    event_type: str,
    first_fetch_date: datetime,
    event_type_last_run: dict[str, Any],
    event_type_max_results: int
) -> tuple[dict, list]:
    """Fetches new events via 1Password Events API client based on a specified event type.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        first_fetch_date (datetime): Datetime from which to get events.
        event_type_last_run (dict): Dictionary of the event type last run (if exists) with optional 'from_date' and 'ids' list.
        event_type_max_results (int): The maximum number of events of the specified event type to fetch.

    Returns:
        tuple[dict, list]: Dictionary of the next run of the event type with 'from_date' and 'ids' list, list of fetched events.
    """
    last_run_skip_ids = set(event_type_last_run.get('ids') or [])
    from_date = arg_to_datetime(event_type_last_run.get('from_date')) or first_fetch_date

    demisto.debug(f'Fetching events of type: {event_type} from date: {from_date.isoformat()}')

    event_type_events = get_events_from_client(
        client=client,
        event_type=event_type,
        from_date=from_date,
        max_events=event_type_max_results,
        ids_to_skip=last_run_skip_ids,
    )

    # API returns events sorted by timestamp in ascending order (oldest to newest), so last event has max timestamp
    max_timestamp = event_type_events[-1]['timestamp'] if event_type_events else None
    next_run_skip_ids = [event['uuid'] for event in event_type_events if event['timestamp'] == max_timestamp]
    event_type_next_run = {'from_date': max_timestamp, 'ids': next_run_skip_ids}

    demisto.debug(
        f'Fetched {len(event_type_events)} events of type: {event_type} out of a maximum of {event_type_max_results}.'
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
    try:
        response = client.introspect()

        if unauthorized_event_types := get_unauthorized_event_types(response, event_types):
            return f'The API token does not have access to the event types: {", ".join(unauthorized_event_types)}'

        return 'ok'

    except DemistoException as e:
        error_status_code = e.res.status_code if isinstance(e.res, requests.Response) else None

        if error_status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
            return 'Authorization Error: Make sure the API server URL and token are correctly set'

        if error_status_code == HTTPStatus.NOT_FOUND:
            return 'Endpoint Not Found: Make sure the API server URL is correctly set'

        # Some other unknown / unexpected error
        raise


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
    base_url: str = urljoin(params['url'], '/api/v2')
    token: str = params['credentials']['password']
    event_types: list[str] = argToList(params['event_types'])
    first_fetch_date: datetime = dateparser.parse(params.get('first_fetch', '')) or DEFAULT_FETCH_FROM_DATE

    # optional
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    demisto.debug(f'Command being called is {command!r}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
            proxy=proxy
        )

        if command == 'test-module':
            result = test_module_command(client, event_types)
            return_results(result)

        if command == 'one-password-get-events':
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
                event_type_key = EVENT_TYPE_MAPPING[event_type]

                event_type_last_run: dict = last_run.get(event_type_key, {})
                event_type_max_results: int = get_limit_param(params, event_type)

                event_type_next_run, event_type_events = fetch_events(
                    client=client,
                    event_type=event_type,
                    first_fetch_date=first_fetch_date,
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
