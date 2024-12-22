import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from http import HTTPStatus
from datetime import datetime, timedelta

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC
VENDOR = '1Password'
PRODUCT = '1Password'

# Default results per page (optimal value)
# > 1000 causes HTTP 400 [Bad Request]
# < 1000 increases the number of requests and may eventually trigger HTTP 429 [Rate Limit]
DEFAULT_RESULTS_PER_PAGE = 1000

DEFAULT_FETCH_FROM_DATE = datetime.now() - timedelta(weeks=2)

EVENT_TYPE_MAPPING = {
    # Lowercase display name: API Feature and endpoint name
    'item usage actions': 'itemusages',
    'audit events': 'auditevents',
    'sign in attempts': 'signinattempts',
}

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
        feature = EVENT_TYPE_MAPPING.get(event_type)
        if not feature:
            raise ValueError(f'Invalid or unsupported 1Password event type: {event_type}.')

        body: dict[str, Any]
        if pagination_cursor:
            body = {'cursor': pagination_cursor}

        elif from_date:
            body = {'limit': results_per_page, 'start_time': from_date.isoformat()}

        else:
            raise ValueError("Either a 'pagination_cursor' or a 'from_date' need to be specified.")

        return self._http_request(method='POST', url_suffix=f'/{feature}', data=json.dumps(body), raise_on_status=True)


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
    return arg_to_number(params.get(param_name)) or 1000


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
    should_fetch_more_events = True
    client_kwargs: dict[str, Any] = {'event_type': event_type, 'from_date': from_date}

    while should_fetch_more_events:
        response = client.get_events(**client_kwargs)

        for event in response['items']:
            event_id = event['uuid']

            if event_id in ids_to_skip:
                continue

            if len(events) == max_events:
                break

            add_fields_to_event(event, event_type)
            events.append(event)
            ids_to_skip.add(event_id)

        # Followup API calls need to include pagination cursor (if any more events)
        should_fetch_more_events = False if len(events) == max_events else response['has_more']
        client_kwargs = {'event_type': event_type, 'pagination_cursor': response['cursor']}

    return events


''' COMMAND FUNCTIONS '''


def fetch_events(
    client: Client,
    event_type: str,
    first_fetch_date: datetime,
    event_last_run: dict[str, Any],
    max_events: int
) -> tuple[dict, list]:
    """Fetches new events via 1Password Events API client based on a specified event type.

    Args:
        client (Client): 1Password Events API client.
        event_type (str): Type of 1Password event (e.g. 'Item usage actions', 'Sign in attempts').
        first_fetch_date (datetime): Datetime from which to get events.
        event_last_run (dict): Dictionary of the last run (if any) of the event type with optional 'from_date' and 'ids' list.
        max_events (int): The maximum number of events to fetch.

    Returns:
        tuple[dict, list]: Dictionary of the next run of the event type with 'from_date' and 'ids' list, list of fetched events.
    """
    last_run_ids = set(event_last_run.get('ids', []))
    from_date = arg_to_datetime(event_last_run.get('from_date')) or first_fetch_date

    events = get_events_from_client(
        client=client,
        event_type=event_type,
        from_date=from_date,
        max_events=max_events,
        ids_to_skip=last_run_ids,
    )

    # API returns events sorted by timestamp in ascending order (oldest to newest), so last event has max timestamp
    max_timestamp = events[-1]['timestamp'] if events else None
    next_run_ids = [event['uuid'] for event in events if event['timestamp'] == max_timestamp]

    event_type_next_run = {'from_date': max_timestamp, 'ids': next_run_ids}

    return event_type_next_run, events


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
        raise e


def get_events_command(client: Client, args: dict[str, str]) -> tuple[list[dict], CommandResults]:
    """Implements `one-password-get-events` command, which returns a markdown table of events to the war room.

    Args:
        client (Client): 1Password Events API client.
        args (dict): The '1password-get-events' command arguments.

    Returns:
        tuple[list[dict], list[CommandResults]]: List of events and list of CommandResults with human readable output.
    """
    event_type = args['event_type'].lower()
    limit = arg_to_number(args.get('limit')) or 1000
    from_date = arg_to_datetime(args.get('from_date')) or DEFAULT_FETCH_FROM_DATE

    events = get_events_from_client(client, event_type=event_type, from_date=from_date, max_events=limit)

    human_readable = tableToMarkdown(name=f'Events of type: {event_type}', t=flattenTable(events))

    return events, CommandResults(readable_output=human_readable)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    # required
    base_url: str = urljoin(params['url'], '/api/v2')
    token: str = params['credentials']['password']
    event_types: list[str] = argToList(params['event_types'], transform=lambda event_type: event_type.lower())
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
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()

            next_run: dict[str, Any] = {}
            for event_type in event_types:
                event_type_key = EVENT_TYPE_MAPPING[event_type]

                event_last_run: dict = last_run.get(event_type_key, {})
                event_max_results: int = get_limit_param(params, event_type)

                next_run, events = fetch_events(
                    client=client,
                    event_type=event_type,
                    first_fetch_date=first_fetch_date,
                    event_last_run=event_last_run,
                    max_events=event_max_results,
                )

                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                next_run[event_type_key] = next_run

            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f'Unknown command {command!r}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command!r} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
