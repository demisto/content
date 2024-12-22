import uuid
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
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


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, headers, verify, proxy):
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

def get_events_ALERTS(
    client: Client,
    endpoint_path: str,
    fetch_limit: int,
    query_params: dict = {},
    next_page_url: str = "",
    pagination_offset: int = 0
):
    fetched_events: list[dict] = []
    has_next = True
    previous_offset = pagination_offset
    while has_next:
        has_next = False
        request_url = (
            unquote(next_page_url)
            if next_page_url
            else f"{client._base_url}{endpoint_path}?{unquote(urlencode(query_params))}"
        )
        params = {} if next_page_url else query_params
        response = client._http_request("GET", full_url=request_url, params=params)
        if next_page_url := response.get("_links", {}).get("next", {}).get("href"):
            has_next = True
        current_batch_events = response.get("auditEvents") or response.get("alerts", [])
        fetched_events.extend(current_batch_events[pagination_offset:])
        pagination_offset = 0 if current_batch_events else pagination_offset
        if len(fetched_events) >= fetch_limit:
            fetched_events = fetched_events[:fetch_limit]
            next_page_url = next_page_url or request_url
            pagination_offset = len(fetched_events) % 500
            return fetched_events, {
                "last_fetch": fetched_events[0].get("startDate"),
                "next_page": next_page_url,
                "offset": pagination_offset if next_page_url != request_url else pagination_offset + previous_offset,
            }
    return fetched_events, {"last_fetch": fetched_events[0].get("startDate") if fetched_events else "",
                "next_page": next_page_url or "",
                "offset": 0
                }


def get_events_AUDIT_LOGS(
    client: Client,
    endpoint_path: str,
    fetch_limit: int,
    query_params: dict = {},
    next_page_url: str = "",
    pagination_offset: int = 0
):
    fetched_events: list[dict] = []
    has_next = True
    previous_offset = pagination_offset
    previous_page_url = next_page_url
    while has_next:
        has_next = False
        request_url = (
            unquote(next_page_url)
            if next_page_url
            else f"{client._base_url}{endpoint_path}?{unquote(urlencode(query_params))}"
        )
        params = {} if next_page_url else query_params
        response = client._http_request("GET", full_url=request_url, params=params)
        if next_page_url := response.get("_links", {}).get("next", {}).get("href"):
            has_next = True
        current_batch_events = response.get("auditEvents") or response.get("alerts", [])
        fetched_events.extend(current_batch_events[pagination_offset:])
        pagination_offset = 0 if current_batch_events else pagination_offset
        if len(fetched_events) >= fetch_limit:
            fetched_events = fetched_events[:fetch_limit]
            pagination_offset = min(abs(len(fetched_events) - fetch_limit - len(current_batch_events)), len(fetched_events))
            return fetched_events, {
                "last_fetch": fetched_events[0].get("date"),
                "next_page": request_url,
                "offset": pagination_offset if request_url != previous_page_url else pagination_offset + previous_offset,
            }
    return fetched_events, {"last_fetch": fetched_events[0].get("date") if fetched_events else query_params.get("last_fetch", ""),
                "next_page": response.get("_links", {}).get("self", {}).get("href"),
                "offset": 0
                }


def get_events_alert_type(client: Client, start_date: str, end_date: str, max_fetch: int, last_run: dict) -> tuple:
    start_date, end_date = calculate_fetch_dates(start_date, "alerts", last_run, end_date)

    last_run_next_page = last_run.get("alerts", {}).get("next_page", "")
    offset = last_run.get("alerts", {}).get("offset", 0)
    params = {} if "nextTrigger" in last_run else {"startDate": start_date, "endDate": end_date, "max": PAGE_SIZE}

    events, next_run = get_events_ALERTS(
        client=client,
        endpoint_path="/v7/alerts",
        fetch_limit=max_fetch,
        query_params=params,
        next_page_url=last_run_next_page,
        pagination_offset=offset
    )
    deduplicate_events(events, start_date, "startDate")

    return events, next_run


def get_audit_events_type(client: Client, start_date: str, end_date: str, max_fetch: int, last_run: dict) -> tuple:
    start_date, end_date = calculate_fetch_dates(start_date, "events", last_run, end_date)

    last_run_next_page = last_run.get("events", {}).get("next_page", "")
    offset = last_run.get("events", {}).get("offset", 0)
    params = {} if "nextTrigger" in last_run else {"startDate": start_date, "endDate": end_date}

    events, next_run = get_events_AUDIT_LOGS(
        client=client,
        endpoint_path="/v7/audit-user-events",
        fetch_limit=max_fetch,
        query_params=params,
        next_page_url=last_run_next_page,
        pagination_offset=offset
    )
    deduplicate_events(events, start_date, "date")
    return events, next_run


def deduplicate_events(events, start_date, date_key):
    start_date = arg_to_datetime(start_date)
    events[:] = [
        event
        for event in events
        if (event_date := arg_to_datetime(event.get(date_key)))
        and start_date
        and event_date > start_date
    ]


def calculate_fetch_dates(
    start_date: str, last_run_key: str, last_run: dict, end_date: str = ""
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
        or last_run.get(last_run_key, {}).get("last_fetch")
        or ((now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    )
    # argument > current time
    end_date = end_date or now_utc_time.strftime(DATE_FORMAT)
    return start_date, end_date


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time(str): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        fetch_events(client, max_fetch_audits=1, max_fetch_alerts=1)
    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
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


def get_events_command(
    client: Client, args: dict
) -> tuple[List[Dict], CommandResults]:
    start_date, end_date = validate_start_and_end_dates(args)
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    _, events = fetch_events(
        client=client,
        max_fetch_alerts=limit,
        max_fetch_audits=limit,
        start_date=start_date,
        end_date=end_date,
    )
    hr = tableToMarkdown(name="Test Event", t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(
    client: Client,
    max_fetch_alerts: int,
    max_fetch_audits: int,
    start_date: str = "",
    end_date: str = "",
) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    last_run = demisto.getLastRun()
    alert_events, alert_next_run = get_events_alert_type(
        client, start_date, end_date, max_fetch_alerts, last_run
    )
    audit_events, audit_next_run = get_audit_events_type(
        client, start_date, end_date, max_fetch_audits, last_run
    )

    events = alert_events + audit_events

    next_run = {"alerts": alert_next_run,
                "events": audit_next_run}
    if any(d.get("offset") for d in (alert_next_run, audit_next_run)):
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
    max_alerts_per_fetch = params.get("max_alerts_per_fetch", DEFAULT_MAX_FETCH_ALERT)
    max_events_per_fetch = params.get("max_events_per_fetch", DEFAULT_MAX_FETCH_AUDIT_EVENTS)

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "cisko-thousandeyes-get-events":
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
