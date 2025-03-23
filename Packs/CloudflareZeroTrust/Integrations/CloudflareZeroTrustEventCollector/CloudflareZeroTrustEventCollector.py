import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

VENDOR = 'Cloudflare'
PRODUCT = 'ZeroTrust'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
ACCOUNT_AUDIT_PAGE_SIZE = 1000
USER_AUDIT_PAGE_SIZE = 1000
ACCESS_AUTHENTICATION_PAGE_SIZE = 1000
DEFAULT_MAX_FETCH_ACCOUNT_AUDIT = 5000
DEFAULT_MAX_FETCH_USER_AUDIT = 5000
DEFAULT_MAX_FETCH_ACCESS_AUTHENTICATION = 5000
DEFAULT_COMMAND_LIMIT = 10

ACCOUNT_AUDIT_TYPE = "Account Audit Logs"
USER_AUDIT_TYPE = "User Audit Logs"
ACCESS_AUTHENTICATION_TYPE = "Access Authentication Logs"

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, headers: Dict[str, str], account_id: str):
        """
        Initializes the Client with API details.

        Args:
            base_url (str): The base URL of the API.
            verify (bool): Whether to verify SSL certificates.
            proxy (bool): Whether to use a proxy.
            headers (Dict[str, str]): The HTTP headers for authentication and other configurations.
            account_id (str): The Cloudflare account ID to be used for account-specific API requests.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.account_id = account_id
        self.headers = headers

    def get_events(self, start_date: str, page_size: int, page: int, event_type: str) -> Dict[str, Any]:
        """
        Fetches events from the API for the specified event type.

        Args:
            start_date (str): The start date for fetching events, in ISO 8601 format.
            page_size (int): The maximum number of events to fetch per page.
            page (int): The page number to fetch.
            event_type (str): The type of events to fetch. Supported types include:
                              - ACCOUNT_AUDIT_TYPE
                              - USER_AUDIT_TYPE
                              - ACCESS_AUTHENTICATION_TYPE

        Returns:
            Dict[str, Any]: The API response containing the fetched events.

        Raises:
            ValueError: If the event_type is invalid or unsupported.
        """
        demisto.debug(
            f"Fetching events with start_date={start_date}, page_size={page_size}, page={page}, event_type={event_type}")

        endpoint_urls = {
            ACCOUNT_AUDIT_TYPE: f"/client/v4/accounts/{self.account_id}/audit_logs",
            USER_AUDIT_TYPE: "/client/v4/user/audit_logs",
            ACCESS_AUTHENTICATION_TYPE: f"/client/v4/accounts/{self.account_id}/access/logs/access_requests"
        }
        params = {
            'per_page': page_size,
            'page': page,
            'since': start_date,
            'direction': 'asc'
        }
        return self._http_request(
            method="GET",
            url_suffix=endpoint_urls[event_type],
            headers=self.headers,
            params=params
        )


def test_module(client: Client, event_types: list) -> str:
    """
    Tests API connectivity and authentication.

    When 'ok' is returned, it indicates that the integration is working as expected and the connection to the
    service is successful. If something goes wrong, the function raises exceptions with meaningful error messages.

    Args:
        client (Client): The Cloudflare Zero Trust client to use for testing connectivity.

    Returns:
        str: 'ok' if the test passed, otherwise raises an exception.
    """
    try:
        fetch_events(
            client=client,
            last_run={},
            max_fetch_account_audit=1,
            max_fetch_user_audit=1,
            max_fetch_authentication=1,
            event_types_to_fetch=event_types
        )

    except Exception as e:
        raise e

    return 'ok'


def fetch_events_for_type(
    client: Client,
    last_run: dict[str, Any],
    max_fetch: int,
    max_page_size: int,
    event_type: str,
    start_fetch_date: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetches events for a specific event type and returns the fetched events and updated last run details.

    Args:
        client (Client): The API client instance.
        last_run (dict): A dictionary containing the last fetch timestamp and event IDs to avoid duplicates.
        max_fetch (int): The maximum number of events to fetch.
        max_page_size (int): The maximum number of events to fetch per page.
        event_type (str): The type of events to fetch.
        start_fetch_date (str, optional): The starting date for fetching events. Defaults to "".

    Returns:
        tuple: A tuple containing:
            - list[dict[str, Any]]: The list of fetched events.
            - dict[str, Any]: The updated last run data with new timestamps and event IDs.
    """
    demisto.debug(f"Fetching events for event_type={event_type} with last_run={last_run}")

    start_date = calculate_fetch_dates(last_run, start_fetch_date)
    previous_event_ids = last_run.get("events_ids", [])
    events_to_fetch = max_fetch + len(previous_event_ids)
    page_size = min(events_to_fetch, max_page_size)

    page = 1
    events: list[dict[str, Any]] = []
    while len(events) < events_to_fetch:
        response = client.get_events(start_date, page_size, page, event_type)
        result = response.get("result", [])
        demisto.debug(f"Fetched {len(result)} events on page {page}")
        events.extend(result)
        if len(result) < page_size:
            break
        page += 1

    unique_events = handle_duplicates(events, previous_event_ids)[:max_fetch]
    demisto.debug(f"Unique events after deduplication: {len(unique_events)}")

    for event in unique_events:
        event["SOURCE_LOG_TYPE"] = event_type

    if unique_events:
        start_date, previous_event_ids = prepare_next_run(unique_events)

    new_last_run = {"last_fetch": start_date, "events_ids": previous_event_ids}
    demisto.debug(f"New last_run: {new_last_run}")
    return unique_events, new_last_run


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    max_fetch_account_audit: int,
    max_fetch_user_audit: int,
    max_fetch_authentication: int,
    event_types_to_fetch: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetches events for multiple event types and aggregates them.

    Args:
        client (Client): The API client instance.
        last_run (dict[str, Any]): A dictionary containing the last run data for all event types.
        max_fetch_account_audit (int): Maximum number of account audit events to fetch.
        max_fetch_user_audit (int): Maximum number of user audit events to fetch.
        max_fetch_authentication (int): Maximum number of authentication events to fetch.
        event_types_to_fetch (list[str]): List of event types to fetch.

    Returns:
        tuple: A tuple containing:
            - dict[str, Any]: The updated last run data for all event types.
            - list[dict[str, Any]]: The aggregated list of fetched events.
    """
    events = []
    next_run = {}

    event_type_params = {
        ACCOUNT_AUDIT_TYPE: {
            "last_run": last_run.get(ACCOUNT_AUDIT_TYPE, {}),
            "max_fetch": max_fetch_account_audit,
            "event_type": ACCOUNT_AUDIT_TYPE,
            "max_page_size": ACCOUNT_AUDIT_PAGE_SIZE,
        },
        USER_AUDIT_TYPE: {
            "last_run": last_run.get(USER_AUDIT_TYPE, {}),
            "max_fetch": max_fetch_user_audit,
            "event_type": USER_AUDIT_TYPE,
            "max_page_size": USER_AUDIT_PAGE_SIZE,
        },
        ACCESS_AUTHENTICATION_TYPE: {
            "last_run": last_run.get(ACCESS_AUTHENTICATION_TYPE, {}),
            "max_fetch": max_fetch_authentication,
            "event_type": ACCESS_AUTHENTICATION_TYPE,
            "max_page_size": ACCESS_AUTHENTICATION_PAGE_SIZE,
        },
    }

    for event_type in event_types_to_fetch:
        fetched_events, updated_last_run = fetch_events_for_type(client=client, **event_type_params[event_type])
        next_run[event_type] = updated_last_run
        events.extend(fetched_events)

    return next_run, events


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict[str, Any]], list[CommandResults]]:
    """
    Fetches events for specified event types and prepares results for display.

    Args:
        client (Client): The API client instance.
        args (dict[str, Any]): Command arguments containing:
            - limit (int): The maximum number of events to fetch per event type.
            - event_types_to_fetch (list[str]): The list of event types to fetch.
            - start_date (str): The start date for fetching events.

    Returns:
        tuple: A tuple containing:
            - list[dict[str, Any]]: A list of all fetched events across event types.
            - list[CommandResults]: A list of CommandResults for displaying fetched events.
    """
    event_types, start_date = validate_args(args)
    limit = arg_to_number(args.get("limit", DEFAULT_COMMAND_LIMIT)) or DEFAULT_COMMAND_LIMIT

    all_fetched_events: list[dict[str, Any]] = []
    command_results: list[CommandResults] = []

    for event_type in event_types:
        events, _ = fetch_events_for_type(
            client=client,
            last_run={},
            max_fetch=limit,
            max_page_size=100,
            event_type=event_type,
            start_fetch_date=start_date
        )
        all_fetched_events.extend(events)

        if events:
            command_results.append(CommandResults(
                readable_output=tableToMarkdown(f"Cloudflare Zero Trust {event_type} Events", events),
                raw_response=events
            ))

    if not all_fetched_events:
        command_results.append(CommandResults(readable_output="No events found."))

    return all_fetched_events, command_results


def calculate_fetch_dates(next_run: dict[str, Any], start_date: str = "") -> str:
    """
    Calculates the start date for fetching events. If no start date is provided, it uses the last fetched date or,
    if that is also unavailable, the current time minus 1 minute.

    Args:
        next_run (dict[str, Any]): A dictionary containing the last run timestamp.
        start_date (str): The provided start date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format.

    Returns:
        str: The calculated start date in '%Y-%m-%dT%H:%M:%SZ' format.
    """
    now_utc_time = get_current_time()
    start_date = start_date or next_run.get('last_fetch') or (
        (now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    return start_date


def prepare_next_run(events: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """
    Prepares the next run data by extracting the latest timestamp and event IDs.

    Args:
        events (list[dict[str, Any]]): A list of fetched events.

    Returns:
        tuple: A tuple containing:
            - str: The latest timestamp (up to seconds) of the fetched events.
            - list[str]: A list of IDs for the events with the latest timestamp.
    """
    latest_time = events[-1].get('when') or events[-1].get('created_at') or ""
    latest_time_obj = datetime.fromisoformat(latest_time.rstrip("Z"))
    latest_time_truncated = latest_time_obj.replace(microsecond=0).isoformat() + "Z"

    latest_ids = [
        event['id']
        for event in events
        if (datetime.fromisoformat((event.get('when') or event.get('created_at') or "").rstrip("Z"))
            .replace(microsecond=0).isoformat() + "Z") == latest_time_truncated
    ]

    return latest_time_truncated, latest_ids


def handle_duplicates(events: list[dict[str, Any]], previous_event_ids: list[str]) -> list[dict[str, Any]]:
    """
    Filters out events that have already been fetched.

    Args:
        events (list[dict[str, Any]]): The list of events to process.
        previous_event_ids (list[str]): A list of IDs of previously fetched events.

    Returns:
        list[dict[str, Any]]: A list of events excluding duplicates.
    """
    unique_events = [event for event in events if event.get("id") not in previous_event_ids]
    demisto.debug(f"Deduplicated events: {len(unique_events)} (removed {len(events) - len(unique_events)} duplicates)")
    return unique_events


def add_time_to_events(events: list[dict[str, Any]] | None):
    """
    Adds the '_time' key to events based on their creation or occurrence timestamp.

    Args:
        events (list[dict[str, Any]] | None): A list of events.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('when') or event.get('created_at'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def validate_args(args: dict):
    """
    Validates the provided arguments for fetch events command.

    Args:
        args (dict): Arguments to validate.

    Raises:
        DemistoException: If an invalid event type or start date is provided.
    """
    start_date_str = ""
    event_types = argToList(args.get("event_types_to_fetch", []))
    valid_types = [ACCOUNT_AUDIT_TYPE, USER_AUDIT_TYPE, ACCESS_AUTHENTICATION_TYPE]

    invalid_types = [event_type for event_type in event_types if event_type not in valid_types]
    if invalid_types:
        raise DemistoException(
            f"Invalid event types provided: {', '.join(invalid_types)}. Valid options are: {', '.join(valid_types)}."
        )

    if start_date := arg_to_datetime(args.get("start_date", "")):
        start_date_str = start_date.strftime(DATE_FORMAT)

    return event_types, start_date_str


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    credentials = params.get("credentials", {})
    max_fetch_account_audit = arg_to_number(params.get('max_fetch_account_audit_logs')) or DEFAULT_MAX_FETCH_ACCOUNT_AUDIT
    max_fetch_user_audit = arg_to_number(params.get('max_fetch_user_audit_logs')) or DEFAULT_MAX_FETCH_USER_AUDIT
    max_fetch_authentication = (arg_to_number(params.get("max_fetch_access_authentication_logs"))
                                or DEFAULT_MAX_FETCH_ACCESS_AUTHENTICATION)
    event_types_to_fetch = argToList(params.get("event_types_to_fetch"))

    try:
        headers = {
            'X-Auth-Email': credentials.get('identifier'),
            'X-Auth-Key': credentials.get('password'),
        }
        client = Client(
            base_url=params.get('url', ""),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            account_id=params.get('account_id', ""),
            headers=headers
        )

        if command == 'test-module':
            result = test_module(client=client, event_types=event_types_to_fetch)
            return_results(result)

        elif command == 'cloudflare-zero-trust-get-events':
            events, results = get_events_command(client=client, args=args)
            return_results(results)
            if events and argToBoolean(args.get("should_push_events")):
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_fetch_account_audit=max_fetch_account_audit,
                max_fetch_user_audit=max_fetch_user_audit,
                max_fetch_authentication=max_fetch_authentication,
                event_types_to_fetch=event_types_to_fetch
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
