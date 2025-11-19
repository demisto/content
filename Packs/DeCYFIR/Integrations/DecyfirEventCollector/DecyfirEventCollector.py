import math
from datetime import datetime, timedelta, UTC
from typing import Any
import urllib3

import demistomock as demisto
from CommonServerPython import *

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

EVENT_LOGS_API_SUFFIX: dict[str, str] = {
    ACCESS_LOGS: "access-logs",
    ASSETS_LOGS: "assets-logs",
    DRK_LOGS: "dr-keywords-logs",
}

SOURCE_LOG_TYPES: dict[str, str] = {
    ACCESS_LOGS: "access_logs",
    ASSETS_LOGS: "asset_logs",
    DRK_LOGS: "dr_keywords_logs",
}

""" UTILITY FUNCTIONS """


def get_timestamp_from_datetime(value: datetime, event_type: str) -> int:
    """
    Convert a datetime object into a Unix timestamp (milliseconds precision).

    Args:
        value (datetime): The datetime to convert.
        event_type (str): The type of event, used for rounding logic.

    Returns:
        int: Unix timestamp in milliseconds.
    """
    timestamp_ms = int(value.timestamp() * 1000)
    if event_type == ACCESS_LOGS:
        timestamp_ms -= timestamp_ms % 1000  # Round down to nearest second
    return timestamp_ms


""" CLIENT """


class Client(BaseClient):
    """
    Client for interacting with the Decyfir event logs API.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, api_key: str) -> None:
        """
        Initialize the client.

        Args:
            base_url (str): Base URL of the Decyfir API.
            verify (bool): Whether to verify SSL certificates.
            proxy (bool): Whether to use system proxy settings.
            api_key (str): Decyfir API key.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def get_event_logs(self, url_suffix: str, page: int, after: int | None, size: int = PAGE_SIZE) -> list[dict[str, Any]]:
        """
        Retrieve raw event log data from a specific API endpoint.

        Args:
            url_suffix (str): API path suffix for the log type.
            page (int): Page number to retrieve.
            after (Optional[int]): Timestamp (ms) after which to fetch events.
            size (int): Page size (default is PAGE_SIZE).

        Returns:
            List[Dict[str, Any]]: List of raw event records.
        """
        params = assign_params(key=self.api_key, after=after, page=page, size=size)
        demisto.debug(f"Fetching logs {url_suffix}, {page}, {after}")
        return self._http_request(url_suffix=url_suffix, method="GET", params=params)

    def search_events(self, event_type: str, max_events_per_fetch: int, after: int | None) -> list[dict[str, Any]]:
        """
        Paginate and retrieve multiple pages of events for a specific event type.

        Args:
            event_type (str): Type of log to fetch.
            max_events_per_fetch (int): Maximum number of events to retrieve.
            after (Optional[int]): Timestamp to filter logs created after.

        Returns:
            List[Dict[str, Any]]: Aggregated list of event logs.
        """
        url_suffix = EVENT_LOGS_API_SUFFIX[event_type]
        total_pages = math.ceil(max_events_per_fetch / PAGE_SIZE)
        all_events: list[dict[str, Any]] = []

        for page in range(total_pages):
            response = self.get_event_logs(url_suffix, page, after)
            if not response:
                break

            all_events.extend(response)
            if len(response) < PAGE_SIZE:
                break

        demisto.debug(f"Fetched {len(all_events)} {event_type} events")
        return all_events


""" EVENT PROCESSING """


def extract_event_time(event: dict[str, Any], event_type: str) -> datetime | None:
    """
    Extract event timestamp as a datetime object.

    Args:
        event (Dict[str, Any]): Event record.
        event_type (str): Type of event log.

    Returns:
        Optional[datetime]: Parsed datetime or None if unavailable.
    """
    field = "event_date" if event_type == ACCESS_LOGS else "created_date"
    raw = event.get(field) or event.get("modified_date")
    datetime_arg = arg_to_datetime(raw)
    return datetime_arg.replace(tzinfo=UTC) if datetime_arg else None


def add_event_fields(events: list[dict[str, Any]], event_type: str) -> None:
    """
    Enrich events with XSIAM-required fields (_time, source_log_type, _ENTRY_STATUS).

    Args:
        events (List[Dict[str, Any]]): List of events to modify.
        event_type (str): Type of events being processed.
    """
    for e in events:
        event_time = extract_event_time(e, event_type)
        e["_time"] = event_time.strftime(DATE_FORMAT) if event_time else None
        e["source_log_type"] = SOURCE_LOG_TYPES.get(event_type)

        if event_type in {ASSETS_LOGS, DRK_LOGS}:
            created = arg_to_datetime(e.get("created_date"))
            modified = arg_to_datetime(e.get("modified_date"))
            if created and modified:
                e["_ENTRY_STATUS"] = "new" if created == modified else "modified"


""" FETCH HELPERS """


def get_after_param(last_run: dict[str, Any], event_type: str, first_fetch_time: datetime) -> int:
    """
    Compute the 'after' parameter for API queries.

    Args:
        last_run (Dict[str, Any]): Last run metadata.
        event_type (str): Event type.
        first_fetch_time (datetime): Initial fetch start time.

    Returns:
        int: Unix timestamp (ms) for next fetch start.
    """
    last_time = arg_to_datetime(last_run.get(event_type, {}).get("next_fetch_time"))
    start_date = last_time or first_fetch_time
    after = get_timestamp_from_datetime(start_date, event_type)
    demisto.debug(f"After parameter computed for {event_type} -  {start_date}  {after}")
    return after


def remove_duplicate_logs(logs: list[dict[str, Any]], last_run: dict[str, Any], event_type: str) -> list[dict[str, Any]]:
    """
    Remove logs already fetched in the previous run.

    Args:
        logs (List[Dict[str, Any]]): Current logs.
        last_run (Dict[str, Any]): Previous run data.
        event_type (str): Event type.

    Returns:
        List[Dict[str, Any]]: Deduplicated list of logs.
    """
    prev_ids = set(last_run.get(event_type, {}).get("fetched_events_ids", []))
    unique_logs = [log for log in logs if log.get("uid") not in prev_ids]
    demisto.debug(f"Removed duplicates for {event_type} -  before {len(logs)} after {len(unique_logs)}")
    return unique_logs


def update_fetched_event_ids(
    current_run: dict[str, Any], event_type: str, logs: list[dict[str, Any]], latest_time: datetime
) -> None:
    """
    Update 'fetched_events_ids' in current_run for deduplication, keeping only logs
    whose event time falls within the same date and within the same second resolution for access logs.

    Args:
        current_run (Dict[str, Any]): Run state dictionary.
        event_type (str): Event type.
        logs (List[Dict[str, Any]]): Fetched logs.
        latest_time (datetime): latest time to be saved in current_run
    """

    current_run.setdefault(event_type, {})

    def same_second(t1, t2):
        return t1.replace(microsecond=0) == t2.replace(microsecond=0)

    filtered_ids = []

    for log in logs:
        event_time = extract_event_time(log, event_type)
        if event_time is None:
            continue

        if event_type == ACCESS_LOGS:
            # ACCESS_LOGS: match within the same second
            should_keep = same_second(event_time, latest_time)
        else:
            # Other event types: exact time match
            should_keep = event_time == latest_time

        if should_keep and (uid := log.get("uid")):
            filtered_ids.append(uid)

    current_run[event_type]["fetched_events_ids"] = filtered_ids
    demisto.debug(f"Updated fetched_event_ids for {event_type}. Count: {len(filtered_ids)}")


def compute_next_fetch_time(events: List[dict[str, Any]], after: int, event_type: str) -> str:
    """
    Determine next fetch time based on the latest event timestamp.

    Args:
        events (List[Dict[str, Any]]): List of fetched events.
        after (int): Last recorded fetch time timestamp in ms- after param used in the current call.
        event_type (str): Type of event.

    Returns:
        str: ISO formatted datetime for the next fetch cycle.
    """
    # Extract valid datetimes only (filter out None explicitly)
    times: List[datetime] = [t for e in events if (t := extract_event_time(e, event_type)) is not None]

    if times:
        next_time: datetime = max(times).replace(tzinfo=timezone.utc)

    else:
        # Fall back to previous time if no valid timestamps found
        next_time = datetime.fromtimestamp(after / 1000).replace(tzinfo=timezone.utc)

    return next_time.isoformat()


""" FETCH EVENTS """


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    first_fetch_time: datetime,
    event_types_to_fetch: list[str],
    max_events_per_fetch: dict[str, int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetch and process events for all configured event types.

    Args:
        client (Client): API client instance.
        last_run (Dict[str, Any]): State of last execution.
        first_fetch_time (datetime): Initial fetch baseline.
        event_types_to_fetch (List[str]): List of log types to fetch.
        max_events_per_fetch (Dict[str, int]): Max number of events per type.

    Returns:
        Tuple[Dict[str, Any], List[Dict[str, Any]]]: Updated run state and fetched events.
    """
    demisto.debug("Starting fetch_events")
    current_run: dict[str, dict[str, Any]] = {}
    all_events: list[dict[str, Any]] = []

    for event_type in event_types_to_fetch:
        filtered_events = []
        demisto.debug(f"Fetching for {event_type}")
        after = get_after_param(last_run, event_type, first_fetch_time)
        events = client.search_events(event_type, max_events_per_fetch.get(event_type, MAX_EVENTS_PER_FETCH), after)

        if events:
            filtered_events = remove_duplicate_logs(events, last_run, event_type)
            add_event_fields(filtered_events, event_type)
            all_events.extend(filtered_events)

        latest_time = compute_next_fetch_time(filtered_events, after, event_type)
        current_run.setdefault(event_type, {})["next_fetch_time"] = latest_time
        update_fetched_event_ids(current_run, event_type, events, arg_to_datetime(latest_time))

    demisto.debug(f"Fetch complete. Total events: {len(all_events)}")
    return current_run, all_events


""" COMMANDS """


def test_module(client: Client) -> str:
    """
    Test connectivity and authentication.

    Returns:
        str: "ok" if successful.
    """
    fetch_events(client, {}, datetime.now(tz=UTC) - timedelta(minutes=5), [ACCESS_LOGS], {ACCESS_LOGS: 1})
    return "ok"


def get_events_command(
    client: Client,
    event_types: list[str],
    max_events: dict[str, int],
    from_date: datetime | None,
    should_push: bool,
) -> None:
    """
    Manual command for retrieving and optionally pushing events.

    Args:
        client (Client): API client instance.
        event_types (List[str]): Types of events to fetch.
        max_events (Dict[str, int]): Limits per event type.
        from_date (Optional[datetime]): Optional start date.
        should_push (bool): Whether to send results to XSIAM.
    """
    after = get_timestamp_from_datetime(from_date, event_types[0]) if from_date else None
    all_events: list[dict[str, Any]] = []

    hrs = []
    for event_type in event_types:
        events = client.search_events(event_type, max_events.get(event_type, MAX_EVENTS_PER_FETCH), after)
        add_event_fields(events, event_type)
        all_events.extend(events)
        hrs.append(tableToMarkdown(name=event_type, t=events))

    demisto.debug("Manual get-events completed")
    return_results(CommandResults(readable_output="\n".join(hrs)))

    if should_push:
        demisto.debug(f"Pushing {len(all_events)} events to XSIAM")
        send_events_to_xsiam(all_events, vendor=VENDOR, product=PRODUCT)


""" MAIN """


def main() -> None:
    """
    Integration entry point.
    Handles Cortex XSIAM command routing and lifecycle.
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command received: {command}")

    credentials = params.get("credentials", {})
    api_key = credentials.get("password")
    base_url = urljoin(params.get("url"), "/org/api-ua/v1/event-logs/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    event_types_to_fetch = [e.strip() for e in argToList(params.get("event_types_to_fetch", []))]
    max_events_per_fetch = {
        ACCESS_LOGS: int(params.get("max_access_logs_events_per_fetch", MAX_EVENTS_PER_FETCH)),
        ASSETS_LOGS: int(params.get("max_assets_logs_events_per_fetch", MAX_EVENTS_PER_FETCH)),
        DRK_LOGS: int(params.get("max_drkl_events_per_fetch", MAX_EVENTS_PER_FETCH)),
    }

    first_fetch_time = datetime.now(tz=UTC)
    client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, api_key=api_key)

    try:
        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "decyfir-get-events":
            get_events_command(
                client=client,
                event_types=argToList(args.get("event_types")) or event_types_to_fetch,
                max_events=max_events_per_fetch,
                from_date=arg_to_datetime(args.get("from_date")),
                should_push=argToBoolean(args.get("should_push_events", False)),
            )

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            current_run, events = fetch_events(client, last_run, first_fetch_time, event_types_to_fetch, max_events_per_fetch)
            demisto.debug(f"Sending {len(events)} fetched events to XSIAM")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(current_run)
            demisto.debug(f"Updated last_run {current_run}")

    except Exception as e:
        tb = traceback.format_exc()
        demisto.error("Exception occurred", {"error": str(e), "traceback": tb})
        return_error(f"Failed to execute {command}. Error: {e}\n\nTraceback:\n{tb}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
