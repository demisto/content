import traceback
from datetime import datetime

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "Proofpoint"
PRODUCT = "Isolation"
DEFAULT_FETCH_LIMIT = 50000
ITEMS_PER_PAGE = 10000
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url, verify: bool, api_key: str) -> None:
        self.api_key = api_key
        super().__init__(base_url=base_url, verify=verify)

    def get_events(self, start_date: str, end_date: str) -> dict:
        """
        Gets events from the specified start date to the end date using the API.

        Args:
            start_date (str): The start date for the data retrieval in YYYY-MM-DD format.
            end_date (str): The end date for the data retrieval in YYYY-MM-DD format.

        Returns:
            dict: The API response containing the usage data events.
        """
        demisto.debug(f"[HTTP Call] Making request: {start_date=}, {end_date=}, pageSize={ITEMS_PER_PAGE}")
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/v2/reporting/usage-data?key={self.api_key}&pageSize={ITEMS_PER_PAGE}"
            f"&from={start_date}&to={end_date}",
            retries=3,
        )
        demisto.debug(
            "[HTTP Call] Request completed. Response keys: ",
            f"{list(results.keys()) if isinstance(results, dict) else type(results)}",
        )
        return results


""" HELPER FUNCTIONS """


def get_and_parse_date(event: dict) -> str | None:
    """
    Parses the date string from an event dictionary and formats it according to the specified date format.

    Args:
        event (dict): A dictionary containing event data.

    Returns:
        str: The formatted date string if parsing is successful.

    Raises:
        ValueError: If the 'date' value in the event dictionary is invalid or cannot be parsed.
    """
    date_str = event.get("date")
    try:
        start = parse_date_string(date_str, DATE_FORMAT)
        return start.strftime(DATE_FORMAT)
    except ValueError:
        raise ValueError("Invalid date format")


def sort_events_by_date(events: list) -> list:
    """
    Sorts a list of events by their date in ascending order.

    Args:
        events (list): A list of dictionaries.

    Returns:
        list: The sorted list of events based on the 'date' field.
    """
    return sorted(events, key=lambda x: datetime.strptime(x["date"], "%Y-%m-%dT%H:%M:%S.%f%z"))


def hash_user_name_and_url(event: dict) -> str:
    """
    Generates a hash-like string by concatenating the 'url' and 'userName' fields from an event dictionary.

    Args:
        event (dict): A dictionary containing event data.

    Returns:
        str: A string in the format '<url>&<userName>'.
    """
    url = event.get("url", "")
    user_name = event.get("userName", "")
    return f"{url}&{user_name}"


def remove_duplicate_events(start_date, ids: set, events: list) -> None:
    """
    Removes duplicate events from a list of events based on a set of unique identifiers and a specified start date.

    Args:
        start_date (str): The date to check against, in the same format as the event dates.
        ids (set): A set of hashed identifiers for detecting duplicates.
        events (list): A list of sorted event dictionaries to process.
    """
    events_copy = events.copy()
    for event in events_copy:
        event_date = get_and_parse_date(event)
        if event_date != start_date:
            break
        hashed_id = hash_user_name_and_url(event)
        if hashed_id in ids:
            demisto.debug(f"[Dedup] Removing duplicated event with hash_id {hashed_id}")
            events.remove(event)


def get_and_reorganize_events(client: Client, start: str, end: str, ids: set) -> list:
    """
    Fetches events, sorts them by date, and removes duplicates.

    Args:
        client (Client): The client to fetch events from.
        start (str): The start date for fetching events.
        end (str): The end date for fetching events.
        ids (set): A set of already processed event IDs to filter out duplicates.

    Returns:
        list: A list of sorted and deduplicated events.
    """
    demisto.debug(f"[API Fetch] Fetching events: {start=}, {end=}, existing_ids_count={len(ids)}")
    events: list = client.get_events(start, end).get("data", [])
    demisto.debug(f"[API Fetch] Got {len(events)} raw events from API.")
    events = sort_events_by_date(events)
    remove_duplicate_events(start, ids, events)
    demisto.debug(f"[Dedup] {len(events)} events remain after dedup.")
    return events


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests the connection to the service by attempting to fetch events within a date range.

    Args:
        client (Client): The client object used to interact with the service.

    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    try:
        current_time = get_current_time()
        start_date = (current_time - timedelta(minutes=1)).strftime(DATE_FORMAT)
        end_date = current_time.strftime(DATE_FORMAT)
        demisto.debug(f"[Test Module] Testing connection: {start_date=}, {end_date=}")
        fetch_events(client, 1, {"start_date": start_date, "end_date": end_date})
        demisto.debug("[Test Module] Success")
        message = "ok"
    except DemistoException as e:
        raise e
    return message


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    output: list = []

    if get_events_args:  # handle get_event command
        event_date = get_events_args.get("start_date", "")
        end = get_events_args.get("end_date", "")
        ids: set = set()
        demisto.debug(f"[Fetch] get-events mode: {event_date=}, {end=}")
    else:  # handle fetch_events case
        last_run = demisto.getLastRun() or {}
        demisto.debug(f"[Fetch] fetch-events mode: {last_run=}")
        event_date = last_run.get("start_date", "")
        if not event_date:
            event_date = get_current_time().strftime(DATE_FORMAT)
        end = get_current_time().strftime(DATE_FORMAT)
        ids = set(last_run.get("ids", []))

    current_start_date = event_date
    demisto.debug(f"[Fetch] Starting fetch loop: {current_start_date=}, {end=}, {fetch_limit=}")
    iteration = 0
    while True:
        iteration += 1
        demisto.debug(f"[Fetch Pagination Loop] Loop iteration {iteration}: {event_date=}")
        events = get_and_reorganize_events(client, event_date, end, ids)
        if not events:
            demisto.debug(f"[Fetch] No more events found. Total: {len(output)}")
            event_date = end
            ids = set()
            break

        demisto.debug(f"[Fetch] Processing {len(events)} events.")
        for event in events:
            event["_TIME"] = event.get("date")
            output.append(event)
            event_date = get_and_parse_date(event)

            if event_date != current_start_date:
                current_start_date = event_date
                ids = set()
            hashed_id = hash_user_name_and_url(event)
            ids.add(hashed_id)

            if len(output) >= fetch_limit:
                demisto.debug(f"[Fetch] Reached fetch limit. Total: {len(output)}")
                new_last_run = {"start_date": event_date, "ids": list(ids)}
                return output, new_last_run

    new_last_run = {"start_date": event_date, "ids": list(ids)}
    demisto.debug(f"[Fetch] Fetch complete. Total: {len(output)}")
    return output, new_last_run


def get_events(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Fetches events within the specified date range and returns them.

    Args:
        client (Client): The client to fetch events from.
        args (dict): A dictionary containing the start and end dates for the query.

    Returns:
        list: A list of events fetched within the specified date range.
    """
    start_date = args.get("start_date")
    end_date = args.get("end_date")
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_FETCH_LIMIT
    demisto.debug(f"[Get Events Command]: {start_date=}, {end_date=}, {limit=}")

    output, _ = fetch_events(client, limit, {"start_date": start_date, "end_date": end_date})
    demisto.debug(f"[Get Events Command] fetched {len(output)} events.")

    filtered_events = []
    for event in output:
        filtered_event = {
            "User ID": event.get("userId"),
            "User Name": event.get("userName"),
            "URL": event.get("url"),
            "Date": event.get("date"),
        }
        filtered_events.append(filtered_event)

    human_readable = tableToMarkdown(name="Proofpoint Isolation Events", t=filtered_events, removeNull=True)
    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix="ProofpointIsolationEventCollector",
    )
    return output, command_results


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"[Main] Command being called is {command}")
    try:
        base_url = params.get("base_url")
        verify = not params.get("insecure", False)
        api_key = params.get("credentials").get("password")
        fetch_limit = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_FETCH_LIMIT

        client = Client(base_url=base_url, verify=verify, api_key=api_key)

        if command == "test-module":
            result = test_module(client)
            return_results(result)
        elif command == "fetch-events":
            demisto.debug(f"[Fetch] Starting with last_run={demisto.getLastRun()}")
            events, new_last_run_dict = fetch_events(client, fetch_limit)
            if events:
                demisto.debug(f"[Fetch] Sending {len(events)} events to XSIAM.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.debug(f"[Fetch] Successfully sent {len(events)} events to XSIAM.")
            else:
                demisto.debug("[Fetch] No events fetched in this cycle.")
            demisto.setLastRun(new_last_run_dict)
            demisto.debug(f"[Fetch] Last run updated: {new_last_run_dict}")
        elif command == "proofpoint-isolation-get-events":
            events, command_results = get_events(client, args)
            if events and argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}\nTraceback:\n{traceback.format_exc()}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
