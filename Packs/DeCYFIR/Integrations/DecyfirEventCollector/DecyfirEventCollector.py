import math
import uuid
from xml.etree.ElementTree import Element

from requests import Response

import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "decyfir"
PRODUCT = "decyfir"
PAGE_SIZE = 1000
MAX_EVENTS_PER_FETCH = 3000
ACCESS_LOGS = "Access Logs"
ASSETS_LOGS = "Assets Logs"
DRK_LOGS = "Digital Risk Keywords Logs"
EVENT_LOGS_API_SUFFIX = {
    ACCESS_LOGS: "access-logs",
    ASSETS_LOGS: "assets-logs",
    DRK_LOGS: "dr-keywords-logs"
}

SOURCE_LOG_TYPES = {
    ACCESS_LOGS: "access_logs",
    ASSETS_LOGS: "asset_logs",
    DRK_LOGS: "dr_keywords_logs"
}


def get_timestamp_from_datetime(value: datetime, event_type: str) -> int:
    """
    Converts a `datetime` object to a Unix timestamp in milliseconds.

    Args:
        value (datetime): The datetime object to convert.

    Returns:
        int: The corresponding Unix timestamp in milliseconds.

    """
    if event_type == ACCESS_LOGS:
        return int(value.timestamp())  # epoch timestamp in seconds #todo: test the resolution - do i need to deduct a second?
    return int(value.timestamp() * 1000)  # epoch timestamp in milliseconds


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url, verify, proxy, api_key):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._api_key = api_key

    def get_event_logs(self, url_suffix: str, page: int, after: Optional[int] = None,
                       size: int = PAGE_SIZE) -> dict | str | bytes | Element | Response:

        params = assign_params(key=self._api_key, after=after, page=page, size=size)
        raw_response = self._http_request(url_suffix=url_suffix, method="GET", params=params)
        return raw_response

    def search_events(self, event_type: str, max_events_per_fetch: int, after: Optional[int]) -> list[dict]:
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            limit: limit.
            from_date: get events from from_date.

        Returns:
            List[Dict]: the next event
        """
        events = []
        url_suffix = EVENT_LOGS_API_SUFFIX.get(event_type)
        total_pages = math.ceil(max_events_per_fetch / PAGE_SIZE)
        demisto.debug(f"after for suffix: {url_suffix} {after}")
        for page in range(total_pages):
            response = self.get_event_logs(url_suffix=url_suffix, page=page, after=after, size=PAGE_SIZE)
            if not response:
                break
            events.extend(response)
            if len(response) < PAGE_SIZE:
                break
        return events


def time_field_mapping(event: dict, event_type: str) -> str | None:
    """
    Determines the relevant timestamp for the event based on its type.

    Args:
        event: A dictionary representing the event.
        event_type: A string indicating the event type.

    Returns:
        A formatted datetime string or None.
    """
    if event_type == ACCESS_LOGS:
        raw_time = event.get("event_date")
    else:
        raw_time = event.get("created_date") or event.get("modified_date")

    if not raw_time:
        return None

    return arg_to_datetime(raw_time).strftime(DATE_FORMAT)


def set_entry_status(event: dict) -> str | None:
    """
    Determines if the entry is 'new' or 'modified' based on timestamps.

    Args:
        event: A dictionary representing the event.

    Returns:
        'new', 'modified', or None if dates are invalid.
    """
    created_date = arg_to_datetime(event.get("created_date"))
    modified_date = arg_to_datetime(event.get("modified_date"))

    if not created_date or not modified_date:
        return

    if modified_date == created_date:
        event["_ENTRY_STATUS"] = 'new'
    if modified_date > created_date:
        event["_ENTRY_STATUS"] = 'modified'


def add_fields_to_events(events: list[dict], event_type: str) -> None:
    """
    Enhances each event with '_time', 'source_log_type', and optionally '_ENTRY_STATUS'.

    Args:
        events: A list of event dictionaries.
        event_type: The event type.
    """
    for event in events:
        event["_time"] = time_field_mapping(event, event_type)
        event["source_log_type"] = SOURCE_LOG_TYPES.get(event_type)
        if event_type in {ASSETS_LOGS, DRK_LOGS}:
            set_entry_status(event)


def test_module(client: Client, first_fetch_time: datetime, event_types_to_fetch: list[str],
                max_events_per_fetch: dict[str, int]) -> str:
    """
    Tests API connectivity and authentication.

    This function performs a sample fetch of events to verify that the integration is correctly configured
    and that the connection to the external service is functioning properly.

    If the fetch is successful, the integration is considered operational.

    Args:
        client (Client): An instance of the  API client used for making requests.
        first_fetch_time (datetime): The starting point in time from which to begin fetching events.
        event_types_to_fetch (list[str]): A list of event types to fetch during the test.
        max_events_per_fetch (dict[str, int]): A dictionary specifying the maximum number of events to fetch
                                               per event type.

    Returns:
        str: 'ok' if the test passed successfully.

    Raises:
        Exception: If any error occurs during the event fetching process, the function will raise an exception,
                   indicating the test failed.
    """

    fetch_events(client, {}, first_fetch_time, event_types_to_fetch, max_events_per_fetch)

    return "ok"


def get_events(client: Client, event_types_to_fetch: list[str], max_events_per_fetch: Dict[str, int],
               from_date: Optional[datetime] = None, should_add_fields=False) -> tuple[
    List[Dict], CommandResults]:
    """Gets events from API

    Args:
        client (Client): The client
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        args (dict): Additional arguments

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """

    all_events = []
    hr = ""
    for event_type in event_types_to_fetch:
        after = get_timestamp_from_datetime(from_date, event_type) if from_date else None
        events = client.search_events(
            event_type=event_type,
            max_events_per_fetch=max_events_per_fetch.get(event_type, MAX_EVENTS_PER_FETCH),
            after=after
        )
        if events:
            hr += tableToMarkdown(name=f"{event_type}", t=events)
            if should_add_fields:
                add_fields_to_events(events, event_type=event_type)
            all_events.extend(events)
        else:
            hr += f"###  No events found for {event_type}.\n"

    return all_events, CommandResults(readable_output=hr)


def increase_datetime_for_next_fetch(
    events: List[Dict],
    prev_dt: datetime,
    next_dt,
    event_type: str
) -> Optional[str]:
    """
    Gets the latest datetime from events based on event_type and the previous fetch datetime,
    adds 1 millisecond, and returns it as ISO 8601 string for the next fetch.

    Args:
        events: List of event dicts.
        latest_datetime_previous_fetch: ISO 8601 datetime string from the previous fetch.
        event_type: String specifying event type (affects which date field is used).

    Returns:
        ISO 8601 datetime string for next fetch, or None if no dates found.
    """

    def extract_event_time(event: Dict) -> Optional[datetime]:

        if event_type == ACCESS_LOGS:
            raw_time = event.get("event_date")
        else:
            raw_time = event.get("created_date") or event.get("modified_date")
        extracted_time = arg_to_datetime(raw_time).replace(tzinfo=timezone.utc)
        demisto.debug(f"extracted_time {extracted_time}")
        return extracted_time

    # Extract all valid datetimes from events

    event_datetimes = [extract_event_time(e) for e in events]
    event_datetimes = [dt for dt in event_datetimes if dt is not None]

    # If no event datetimes and no previous datetime, return None
    if not event_datetimes and prev_dt is None and next_dt is None:
        return None

    next_dt = arg_to_datetime(next_dt)
    next_dt = next_dt.replace(tzinfo=timezone.utc) if next_dt else None
    # Find the max datetime between current events and previous fetch
    candidates = event_datetimes + ([prev_dt] if prev_dt else []) + ([next_dt] if next_dt else [])
    latest_date_time = max(candidates)

    # Add 1 millisecond
    next_fetch_time = latest_date_time.replace(tzinfo=timezone.utc) + timedelta(milliseconds=1)

    return next_fetch_time.isoformat()


def save_potential_duplicates_for_next_run(next_fetch_time, log_events):
    pass


def remove_duplicate_events(log_events, duplicate_events):
    pass


def fetch_events(client: Client, last_run: dict[str, int],
                 first_fetch_time, event_types_to_fetch: list[str], max_events_per_fetch: Dict[str, int]
                 ) -> tuple[Dict, List[Dict]]:
    next_run: dict[str, dict] = {}
    events = []

    for event_type in event_types_to_fetch:
        last_time = arg_to_datetime(last_run.get(event_type, {}).get("next_fetch_time", None))
        last_time = last_time.replace(tzinfo=timezone.utc) if last_time else None
        start_date = first_fetch_time if not last_time else last_time
        after = get_timestamp_from_datetime(start_date)
        demisto.debug(f"start date, after {event_type} {start_date} {after}")
        log_events = client.search_events(
            event_type=event_type,
            max_events_per_fetch=max_events_per_fetch.get(event_type, MAX_EVENTS_PER_FETCH),
            after=after
        )
        if event_type == ACCESS_LOGS:
            log_events = remove_duplicate_events(log_events, next_run.get(ACCESS_LOGS).get("duplicate_events", []))
        next_fetch_time = increase_datetime_for_next_fetch(log_events, start_date, next_run.get(event_type), event_type)
        next_run[event_type] = {"next_fetch_time": next_fetch_time}
        if event_type == ACCESS_LOGS:
            save_potential_duplicates_for_next_run(next_fetch_time, next_run)

        demisto.debug(f"Received {len(log_events)} events for event type {event_type}")
        add_fields_to_events(log_events, event_type)
        events.extend(log_events)

    demisto.debug(f"Returning {len(events)} events in total")
    demisto.debug(f"Returning next run {next_run}.")
    return next_run, events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("api_key", "")
    base_url = urljoin(params.get("url"), "/org/api-ua/v1/event-logs/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    first_fetch_time = datetime.now(tz=timezone.utc)
    event_types_to_fetch = [event_type.strip() for event_type in argToList(params.get("event_types_to_fetch", []))]
    max_events_per_fetch = {
        ACCESS_LOGS: int(params.get("max_access_logs_events_per_fetch", MAX_EVENTS_PER_FETCH)),
        ASSETS_LOGS: int(params.get("max_assets_logs_events_per_fetch", MAX_EVENTS_PER_FETCH)),
        DRK_LOGS: int(params.get("max_drkl_events_per_fetch", MAX_EVENTS_PER_FETCH)),
    }

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, api_key=api_key)

        if command == "test-module":
            result = test_module(client, first_fetch_time, event_types_to_fetch, max_events_per_fetch)
            return_results(result)

        elif command == "decyfir-event-collector-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            from_date = arg_to_datetime(args.get("from_date"))
            event_types = argToList(args.get("event_types")) or event_types_to_fetch
            events, results = get_events(client, event_types, max_events_per_fetch, from_date, should_push_events)
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                event_types_to_fetch=event_types_to_fetch,
                max_events_per_fetch=max_events_per_fetch,
            )

            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
