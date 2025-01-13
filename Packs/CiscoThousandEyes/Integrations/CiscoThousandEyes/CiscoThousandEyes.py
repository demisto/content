import demistomock as demisto
from CommonServerPython import *
import urllib3
from urllib.parse import unquote, urlencode


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "Cisco"
PRODUCT = "ThousandEyes"
DEFAULT_MAX_FETCH_ALERT = 2500
DEFAULT_MAX_FETCH_AUDIT_EVENTS = 5000
PAGE_SIZE = 500
DEFAULT_LIMIT = 10
AUDIT = "audit"
ALERTS = "alerts"
ENDPOINTS = {ALERTS: "/v7/alerts", AUDIT: "/v7/audit-user-events"}
DATE_KEYS = {ALERTS: "startDate", AUDIT: "date"}
RESPONSE_MAPPING_KEY = {ALERTS: "alerts", AUDIT: "auditEvents"}

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, headers, verify, proxy):
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)


def get_events(
    client: Client,
    fetch_type: str,
    fetch_limit: int,
    last_run: dict = {},
    start_date: str = "",
    end_date: str = ""
) -> tuple:
    """
    Fetches events of the specified type (ALERTS or AUDIT) with support for pagination and deduplication.

    Args:
        client (Client): API client for making HTTP requests.
        fetch_type (str): Type of events to fetch.
        fetch_limit (int): Maximum number of events to fetch.
        last_run (dict, optional): Metadata from the last fetch, including offset, next page, and last fetch date.
        start_date (str, optional): Start date for fetching events.
        end_date (str, optional): End date for fetching events.

    Returns:
        tuple:
            - fetched_events (list[dict]): List of fetched events.
            - next_run (dict): Metadata for the next fetch, including "last_fetch", "next_page", and "offset".

    Explanation:
        - Calculates fetch dates dynamically if not provided.
        - Handles pagination, deduplication, and enforces fetch limits.
        - Builds the next run metadata to resume fetching seamlessly.
    """
    start_date, end_date = calculate_fetch_dates(
        start_date, last_run.get(fetch_type, {}), end_date
    )
    last_run = last_run.get(fetch_type, {})
    demisto.debug(f"start fetching {fetch_type} type. with last_run: {last_run}")

    next_page_url = last_run.get("next_page", "")
    pagination_offset = last_run.get("offset", 0)
    params = {} if next_page_url else {"startDate": start_date, "endDate": end_date, "max": PAGE_SIZE}

    fetched_events: list[dict] = []
    has_next = True
    while has_next:
        has_next = False
        request_url = (
            unquote(next_page_url)
            if next_page_url
            else f"{client._base_url}{ENDPOINTS.get(fetch_type, '')}?{unquote(urlencode(params))}"
        )
        response = client._http_request("GET", full_url=request_url)
        if next_page_url := response.get("_links", {}).get("next", {}).get("href"):
            has_next = True
        current_batch_events = response.get(RESPONSE_MAPPING_KEY.get(fetch_type), [])
        deduplicate_events(
            current_batch_events, params.get("startDate"), DATE_KEYS.get(fetch_type, "")
        )
        fetched_events.extend(current_batch_events[pagination_offset:])
        if len(fetched_events) >= fetch_limit:
            demisto.debug(f"We reached the fetch limit . limit is: {fetch_limit}. received: {len(fetched_events)} events.")
            fetched_events = fetched_events[:fetch_limit]
            return fetched_events, prepare_next_run(fetch_type=fetch_type, fetch_limit=fetch_limit,
                                                    last_batch_events=current_batch_events, fetched_events=fetched_events,
                                                    request_url=request_url, previous_offset=last_run.get("offset", 0),
                                                    last_run=last_run)
        pagination_offset = 0
    # Events are fetched in descending order by date.
    # For new fetches (not paginated), use the latest event's date as the "last_fetch".
    # For paginated fetches, retain the "last_fetch" from the previous batch.
    last_fetch = (
        last_run.get("last_fetch")
        if last_run.get("next_page")
        else (
            fetched_events[0].get(DATE_KEYS.get(fetch_type, ""))
            if fetched_events
            else params.get("last_fetch")
        )
    )
    return fetched_events, {"last_fetch": last_fetch}


def prepare_next_run(
    fetch_type: str,
    fetch_limit: int,
    last_batch_events: list[dict],
    fetched_events: list[dict],
    request_url: str,
    previous_offset: int,
    last_run: dict
) -> dict:
    """
    Calculates metadata for the next fetch, including the last fetch timestamp, next page URL, and pagination offset.

    Args:
        fetch_type (str): Type of events (ALERTS or AUDIT).
        fetch_limit (int): Maximum number of events to fetch.
        last_batch_events (list[dict]): Events from the last batch.
        fetched_events (list[dict]): All fetched events so far.
        request_url (str): URL of the current request.
        last_run (dict): Metadata from the previous fetch.

    Returns:
        dict: Contains "last_fetch" (str), "next_page" (str), and "offset" (int).

    Notes:
        Pagination logic varies by fetch type (ALERTS vs AUDIT).
    """
    previous_page_url = last_run.get("next_page", "")
    previous_last_date = last_run.get("last_fetch", "")

    pagination_offset = fetch_limit % len(last_batch_events)
    next_page_url = (
        request_url if fetch_type == AUDIT or pagination_offset else previous_page_url
    )
    is_paginated_fetch = is_fetch_paginated(
        fetch_type, next_page_url, request_url, previous_page_url
    )
    return {
        "last_fetch": (
            previous_last_date
            if previous_page_url
            else fetched_events[0].get(DATE_KEYS.get(fetch_type, ""))
        ),
        "next_page": next_page_url,
        "offset": (
            pagination_offset
            if is_paginated_fetch
            else pagination_offset + previous_offset
        ),
    }


def is_fetch_paginated(
    fetch_type: str, next_page_url: str, request_url: str, previous_page_url: str
) -> bool:
    """
    Determines whether the fetch process is paginated between fetches.

    For 'alerts', checks if the next page URL is different from the current request URL.
    For other types (e.g., 'events'), checks if the current request URL differs from the previous page URL.

    Args:
        fetch_type (str): The type of fetch ('alerts' or 'events').
        next_page_url (str): The URL of the next page, if available.
        request_url (str): The URL of the current request.
        previous_page_url (str): The URL of the previous request.

    Returns:
        bool: True if the fetch is paginated, False otherwise.
    """
    if fetch_type == ALERTS:
        return next_page_url != request_url
    return request_url != previous_page_url


def deduplicate_events(events: list, start_date: Any, date_key: str) -> None:
    """
    Filters and modifies the given list of events to only include events
    that occurred after the specified start date.

    Args:
        events: A list of event dictionaries.
            Each dictionary is expected to have the `date_key` containing the event date as a string.
        start_date: The start date as a string in ISO 8601 format.
            Events with dates earlier than this will be excluded. If None, the function does nothing.
        date_key (str): The key in each event dictionary that contains the event's date.

    Returns:
        None: The function modifies the `events` list in place.
    """
    if not start_date:
        return
    demisto.debug(f"got {len(events)} before deduplication")
    start_date = arg_to_datetime(start_date)
    events[:] = [
        event
        for event in events
        if (event_date := arg_to_datetime(event.get(date_key)))
        and start_date
        and event_date > start_date
    ]
    demisto.debug(f"got {len(events)} after deduplication")


def calculate_fetch_dates(
    start_date: str, last_run: dict, end_date: str = ""
) -> tuple[str, str]:
    """
    Calculates the start and end dates for fetching events.

    This function takes the start date and end date provided as arguments.
    If these are not provided, it uses the last run information to calculate the start and end dates.
    If the last run information is also not available,
     it uses the current time as the end date and the time one minute before the current time as the start date.

    Args:
        start_date (str): The start date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format.
        last_run_key (str): The key to retrieve the last fetch date from the last run dictionary.
        last_run (dict): A dictionary containing information about the last run.
        end_date (str, optional): The end date for fetching events in '%Y-%m-%dT%H:%M:%SZ' format. Defaults to "".

    Returns:
        tuple: A tuple containing two elements:
            - The start date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.
            - The end date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.
    """
    now_utc_time = get_current_time()
    # argument > last run > current time
    start_date = (
        start_date
        or last_run.get("last_fetch")
        or ((now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    )
    # argument > current time
    end_date = end_date or now_utc_time.strftime(DATE_FORMAT)
    return start_date, end_date


def test_module(client: Client) -> str:
    """
    This method is used to test the connectivity and functionality of the client.

    Args:
        client (Client): The client object with methods for interacting with the API.

    Returns:
        str: Returns "ok" if the client is able to interact with the API successfully, raises an exception otherwise.
    """
    try:
        fetch_events(client, max_fetch_audits=1, max_fetch_alerts=1)
    except Exception as e:
        if "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        raise e
    return "ok"


def validate_start_and_end_dates(args):
    """
    Validates the start and end dates provided in the arguments.

    This function checks if the start date is missing or if it is greater than the end date.
     If either of these conditions is true, it raises a ValueError. Otherwise, it returns the start and end dates.

    Args:
        args (dict): A dictionary containing the arguments for the command.
                     It should contain keys 'start_date' and 'end_date' with values representing the date range.

    Returns:
        tuple: A tuple containing two elements:
            - The start date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.
            - The end date as a string in the format '%Y-%m-%dT%H:%M:%SZ'.

    Raises:
        ValueError: If the start date is missing or if it is greater than the end date.
    """
    start_date_str = ""
    end_date_str = ""
    if start_date := arg_to_datetime(args.get("start_date")):
        start_date_str = start_date.strftime(DATE_FORMAT)
    if end_date := arg_to_datetime(args.get("end_date")):
        end_date_str = end_date.strftime(DATE_FORMAT)
    if (end_date and not start_date) or (
        start_date and end_date and start_date >= end_date
    ):
        raise ValueError(
            "Either the start date is missing or it is greater than the end date. Please provide valid dates."
        )
    return start_date_str, end_date_str


def get_events_command(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    start_date, end_date = validate_start_and_end_dates(args)
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    _, all_events = fetch_events(
        client=client,
        max_fetch_alerts=limit,
        max_fetch_audits=limit,
        start_date=start_date,
        end_date=end_date,
    )
    alerts = [item for item in all_events if "id" in item]
    events = [item for item in all_events if "id" not in item]

    alerts_table = tableToMarkdown(name="Test Alerts", t=alerts, headers=["SOURCE_LOG_TYPE", "alertType", "startDate", "id",
                                                                          "duration", "suppressed", "meta", "violationCount"])
    event_table = tableToMarkdown("Test Events", events, ["SOURCE_LOG_TYPE", "aid", "date", "event", "ipAddress",
                                                          "uid", "user", "accountGroupName"])

    return all_events, CommandResults(readable_output=f"{alerts_table}\n{event_table}", raw_response=all_events)


def fetch_events(
    client: Client,
    max_fetch_alerts: int,
    max_fetch_audits: int,
    start_date: str = "",
    end_date: str = "",
) -> tuple[Dict, List[Dict]]:
    """
    Fetches alert and audit events from the specified client within the provided date range.

    Args:
        client (Client): The client instance to interact with the data source.
        max_fetch_alerts (int): Maximum number of alerts to fetch per request.
        max_fetch_audits (int): Maximum number of audit events to fetch per request.
        start_date (str, optional): The start date for fetching events in ISO 8601 format. Defaults to an empty string.
        end_date (str, optional): The end date for fetching events in ISO 8601 format. Defaults to an empty string.

    Returns:
        tuple[Dict, List[Dict]]:
            - A dictionary containing the next run information, including timestamps and pagination data.
            - A list of events (alerts and audits) to be ingested into XSIAM.
    """
    alert_events, audit_events = [], []
    alert_next_run, audit_next_run = {}, {}

    last_run = demisto.getLastRun()
    is_new_fetch = "nextTrigger" not in last_run

    if is_new_fetch or last_run.get(ALERTS, {}).get("next_page"):
        alert_events, alert_next_run = get_events(
            client, ALERTS, start_date=start_date, end_date=end_date, fetch_limit=max_fetch_alerts, last_run=last_run
        )
    if is_new_fetch or last_run.get(AUDIT, {}).get("next_page"):
        audit_events, audit_next_run = get_events(
            client, AUDIT, start_date=start_date, end_date=end_date, fetch_limit=max_fetch_audits, last_run=last_run
        )

    events = alert_events + audit_events
    add_type_to_events(events)

    next_run: Dict[str, Any] = {ALERTS: alert_next_run, AUDIT: audit_next_run}
    if any(d.get("next_page") for d in (alert_next_run, audit_next_run)):
        next_run["nextTrigger"] = "0"
    demisto.debug(f"Setting next run {next_run}.")
    return next_run, events


""" MAIN FUNCTION """


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(
                arg=event.get("startDate") or event.get("date")
            )
            event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def add_type_to_events(events: List[Dict]) -> None:
    """
    Adds a source log type to each event in the list based on the provided fetch type.

    Args:
        events (List[Dict]): A list of events to be updated. Each event is represented as a dictionary.
        fetch_type (str): The type of fetch operation, used to determine the corresponding source log type.

    Returns:
        None: The function modifies the input list of events in place.

    Notes:
        - The `SOURCE_LOG_TYPE` dictionary is expected to map fetch types to their respective source log type strings.
        - If the `events` list is empty, the function does nothing.
    """
    if events:
        for event in events:
            event["SOURCE_LOG_TYPE"] = "Alerts" if "id" in event else "AuditEvents"


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("api_token", {}).get("password")
    base_url = params.get("url")
    verify_certificate = not params.get("insecure", True)

    proxy = params.get("proxy", False)
    max_alerts_per_fetch = (
        arg_to_number(params.get("max_alerts_per_fetch")) or DEFAULT_MAX_FETCH_ALERT
    )
    max_events_per_fetch = (
        arg_to_number(params.get("max_events_per_fetch"))
        or DEFAULT_MAX_FETCH_AUDIT_EVENTS
    )

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "cisco-thousandeyes-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", "false"))
            events, results = get_events_command(client, demisto.args())
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            next_run, events = fetch_events(
                client=client,
                max_fetch_alerts=max_alerts_per_fetch,
                max_fetch_audits=max_events_per_fetch,
            )

            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
