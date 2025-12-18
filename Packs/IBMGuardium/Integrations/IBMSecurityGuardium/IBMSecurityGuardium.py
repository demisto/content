import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
import hashlib
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "IBM"
PRODUCT = "Guardium"
DEFAULT_MAX_FETCH = 10000
MAX_BATCH_SIZE = 1000
DEFAULT_FIELD_MAPPING = {
    "1": "ClientIP",
    "2": "DBUserName",
    "3": "SourceProgram",
    "4": "ServerIP",
    "5": "ServiceName",
    "6": "DatabaseName",
    "7": "SessionStart",
}

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, auth: tuple, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def run_report(self, report_id: str, fetch_size: int, offset: int, from_date: str, to_date: str) -> dict[str, Any]:
        """
        Run a report to fetch events.
        """
        payload = {
            "fetch_size": fetch_size,
            "offset": offset,
            "report_id": report_id,
            "runtime_parameter_list": [
                {"key": "QUERY_FROM_DATE", "operator_type": "GREATER_THAN_OR_EQUAL", "value": from_date},
                {"key": "QUERY_TO_DATE", "operator_type": "LESS_THAN", "value": to_date},
            ],
            "without_limit": True,
            # TODO: Verify if CUSTOM date_range type is necessary for the query
            # Using CUSTOM type to ensure our specific date range is respected
            "date_range": {"type": "CUSTOM", "from_date": from_date, "to_date": to_date},
            # Order by SessionStart (field 7) in ascending order to ensure chronological order
            "order_by": [{"column_id": "7", "order": "ASC"}],
        }
        demisto.debug(f"Running report {report_id} with payload: {payload}")
        response = self._http_request(method="POST", url_suffix="/api/v3/reports/run", json_data=payload)
        demisto.debug(f"run_report response: {str(response)[:500]}")
        return response


""" HELPER FUNCTIONS """


def extract_field_mapping(response: dict[str, Any]) -> dict[str, str]:
    """
    Extract field mapping from the API response's report_headers.
    Maps the sequence number to the header_name.
    Will raise KeyError if expected structure is missing.
    
    Args:
        response: API response containing report_layout with report_headers
    
    Returns:
        Dictionary mapping sequence number to header_name
        Example: {"1": "ClientID", "2": "DBUserName", ...}
    """
    field_mapping = {}
    
    # Strict access - will raise KeyError if structure is wrong
    headers = response["result"]["report_layout"]["report_headers"]
    
    for header in headers:
        # Use sequence (1-7) as the key, not header_id
        sequence = str(header["sequence"])
        header_name = header["header_name"]
        field_mapping[sequence] = header_name
    
    demisto.debug(f"Extracted field mapping: {field_mapping}")
    return field_mapping


def get_event_hash(event: dict[str, Any]) -> str:
    """
    Generate a hash for an event based on its content.
    Uses first 16 characters of SHA-256 hash to create a stable, compact identifier.
    This provides excellent collision resistance while reducing storage overhead.
    """
    # Create a stable string representation of the event for hashing
    # Sort keys to ensure consistent ordering
    event_str = json.dumps(event, sort_keys=True)
    # Return first 16 characters of the hash (still ~18 quintillion possible values)
    return hashlib.sha256(event_str.encode()).hexdigest()[:16]


def map_event(raw_event: dict[str, Any], field_mapping: dict[str, str] | None = None) -> dict[str, Any]:
    """
    Map raw event fields to readable names using provided field mapping or fallback to default.
    
    Args:
        raw_event: Raw event data with numbered fields
        field_mapping: Optional mapping from field IDs to field names from API response
    
    Returns:
        Mapped event with readable field names
    """
    # Use provided mapping or fallback to default
    mapping = field_mapping if field_mapping else DEFAULT_FIELD_MAPPING
    
    demisto.debug(f"Mapping event with keys: {list(raw_event.keys())}")
    mapped_event = {}
    for key, value in raw_event.items():
        if key in mapping:
            mapped_event[mapping[key]] = value
        else:
            mapped_event[key] = value

    return mapped_event


def send_events_to_xsiam_with_time(events: list[dict[str, Any]]) -> None:
    """
    Add _time field to events and send them to XSIAM.
    The _time field is required by XSIAM for event ingestion.
    
    Args:
        events: List of events to send to XSIAM
    """
    if not events:
        demisto.debug("No events to send to XSIAM")
        return
    
    demisto.debug(f"Preparing to send {len(events)} events to XSIAM")
    
    # Add _time field to each event based on SessionStart
    for event in events:
        if "SessionStart" in event:
            event["_time"] = event["SessionStart"]
            #TODO consider removing
        else:
            demisto.debug(f"Warning: SessionStart not found in event, _time not set for event: {event}")
    
    # Send events to XSIAM
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"Successfully sent {len(events)} events to XSIAM")


def deduplicate_events(events: list[dict[str, Any]], last_run: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Deduplicate events based on the ignore list from last run.
    
    Args:
        events: List of events ordered by SessionStart ascending
        last_run: Dictionary containing last_fetch_time and fetched_event_hashes
    
    Returns:
        List of deduplicated events
    """
    if not events:
        return events
    
    last_fetch_time = last_run.get("last_fetch_time")
    fetched_event_hashes = set(last_run.get("fetched_event_hashes", []))
    
    demisto.debug(f"Deduplicating {len(events)} events. Last fetch time: {last_fetch_time}, "
                  f"Ignore list size: {len(fetched_event_hashes)}")
    
    deduplicated = []
    for event in events:
        event_time = event.get("SessionStart")
        
        # If event timestamp is greater than last_fetch_time, all remaining events are new
        if event_time and event_time > last_fetch_time:
            # Add this event and all remaining events without checking
            deduplicated.extend(events[len(deduplicated):])
            demisto.debug(f"Found event with timestamp {event_time} > last_fetch_time {last_fetch_time}, "
                         f"adding remaining {len(events) - len(deduplicated)} events without duplicate check")
            break
        
        # If event has the same timestamp as last_fetch_time, check if it's a duplicate
        if event_time == last_fetch_time:
            event_hash = get_event_hash(event)
            if event_hash in fetched_event_hashes:
                demisto.debug(f"Skipping duplicate event with hash {event_hash} at time {event_time}")
                continue
        
        deduplicated.append(event)
    
    demisto.debug(f"Deduplication complete. Original: {len(events)}, Deduplicated: {len(deduplicated)}, "
                  f"Filtered: {len(events) - len(deduplicated)}")
    
    return deduplicated


def build_ignore_list(events: list[dict[str, Any]]) -> set[str]:
    """
    Build an ignore list of event hashes for all events with the same timestamp as the last event.
    This is used to prevent duplicate fetching of events with the same timestamp in the next fetch cycle.
    
    Args:
        events: List of events ordered by SessionStart ascending
    
    Returns:
        Set of event hashes for events with the same timestamp as the last event
    """
    ignore_set = set()
    if not events:
        return ignore_set
    
    last_event_time = events[-1].get("SessionStart")
    
    # Iterate backwards from the end to find all events with the same timestamp
    for event in reversed(events):
        if event.get("SessionStart") == last_event_time:
            event_hash = get_event_hash(event)
            ignore_set.add(event_hash)
        else:
            # Stop when we hit a different timestamp
            break
    
    demisto.debug(f"Created ignore list with {len(ignore_set)} event hashes at timestamp {last_event_time}")
    
    return ignore_set


""" COMMAND FUNCTIONS """


def test_module(client: Client, report_id: str) -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    """
    try:
        demisto.debug("Starting test_module")
        # Try to fetch 1 event to verify connectivity
        now = datetime.utcnow()
        # Assuming there are events in the last 5 hours
        from_date = (now - timedelta(hours=5)).strftime(DATE_FORMAT)
        to_date = now.strftime(DATE_FORMAT)

        demisto.debug(f"Test module: fetching 1 event from {from_date} to {to_date}")
        client.run_report(report_id, fetch_size=1, offset=0, from_date=from_date, to_date=to_date)
        demisto.debug("Test module: fetch successful")
        return "ok"
    except Exception as e:
        demisto.debug(f"Test module failed: {str(e)}")
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key and Secret are correctly set"
        raise e


def fetch_events(
    client: Client, report_id: str, max_fetch: int, last_run: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch events from IBM Guardium.
    """
    demisto.debug(f"Starting fetch_events with last_run: {last_run}, max_fetch: {max_fetch}")
    last_fetch_time_str = last_run.get("last_fetch_time")

    # Determine fetch time range
    now = datetime.utcnow()
    if last_fetch_time_str:
        last_fetch_time = datetime.strptime(last_fetch_time_str, DATE_FORMAT)
    else:
        # Default to 1 hour ago if no last run
        last_fetch_time = now - timedelta(hours=1)
        demisto.debug(f"No last_fetch_time found, using default: 1 hour ago")

    from_date = last_fetch_time.strftime(DATE_FORMAT)
    to_date = now.strftime(DATE_FORMAT)
    demisto.debug(f"Fetching events from {from_date} to {to_date}")

    events: list[dict[str, Any]] = []
    offset = 0
    field_mapping: dict[str, str] = {}

    while len(events) < max_fetch:
        # Calculate how many events we still need
        remaining = max_fetch - len(events)
        batch_size = min(MAX_BATCH_SIZE, remaining)
        demisto.debug(f"Fetching batch with offset: {offset}, batch_size: {batch_size}, remaining: {remaining}")
        response = client.run_report(
            report_id=report_id, fetch_size=batch_size, offset=offset, from_date=from_date, to_date=to_date
        )

        # Extract field mapping and events from the response structure
        # Response format: {"result": {"report_layout": {...}, "data": [{"results": {...}}, ...]}}
        if offset == 0:
            field_mapping = extract_field_mapping(response)
        
        raw_events = response["result"]["data"]
        
        demisto.debug(f"Raw events count: {len(raw_events)}")

        if not raw_events:
            demisto.debug("No events returned in batch, stopping fetch loop")
            break

        for raw_event in raw_events:
            # Each event is wrapped in {"results": {...}}
            event_data = raw_event["results"]
            mapped_event = map_event(event_data, field_mapping)
            events.append(mapped_event)

            if len(events) >= max_fetch:
                demisto.debug(f"Reached max_fetch limit of {max_fetch}, stopping event collection")
                break

        demisto.debug(f"Fetched batch of {len(raw_events)} events. Total events so far: {len(events)}")

        if len(raw_events) < batch_size:
            demisto.debug(f"Received fewer events ({len(raw_events)}) than batch_size ({batch_size}), no more events available")
            break

        offset += len(raw_events)
        demisto.debug(f"Updated offset to {offset} for next batch")

    # Deduplicate events based on the ignore list from last run
    deduplicated_events = deduplicate_events(events, last_run)
    
    # Build ignore list for the next fetch cycle
    new_ignore_set = build_ignore_list(deduplicated_events)
    
    if deduplicated_events:
        last_event = deduplicated_events[-1]
        if "SessionStart" in last_event:
            next_run = {
                "last_fetch_time": last_event["SessionStart"],
                "fetched_event_hashes": list(new_ignore_set)
            }
            demisto.debug(f"Setting last_fetch_time to last event's SessionStart: {last_event['SessionStart']}, "
                         f"with {len(new_ignore_set)} event hashes in ignore list")
        else:
            #TODO consider removing
            # Fallback if SessionStart is missing
            next_run = {"last_fetch_time": to_date, "fetched_event_hashes": list(new_ignore_set)}
            demisto.debug("Warning: SessionStart not found in last event, using to_date as fallback")
    else:
        # No events after deduplication - keep last_run unchanged to retry the same window
        next_run = last_run
        demisto.debug(f"No events after deduplication, keeping last_run unchanged: {next_run}")

    demisto.debug(f"Fetch completed. Total events: {len(events)}, Deduplicated: {len(deduplicated_events)}. Next run: {next_run}")
    return deduplicated_events, next_run


def get_events_command(client: Client, report_id: str, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Manual command to fetch events.
    """
    demisto.debug(f"Executing get_events_command with args: {args}")
    limit = arg_to_number(args.get("limit", 50)) or 50

    # Parse start_time and end_time from arguments
    start_time_arg = args.get("start_time")
    end_time_arg = args.get("end_time")
    
    now = datetime.utcnow()
    
    # Parse start_time - supports ISO format or natural language
    if start_time_arg:
        start_time = dateparser.parse(start_time_arg)
        if not start_time:
            raise DemistoException(f"Invalid start_time format: {start_time_arg}")
    else:
        # Default to 1 hour ago if not provided
        start_time = now - timedelta(hours=1)
        demisto.debug("No start_time provided, using default: 1 hour ago")
    
    # Parse end_time - supports ISO format or natural language
    if end_time_arg:
        end_time = dateparser.parse(end_time_arg)
        if not end_time:
            raise DemistoException(f"Invalid end_time format: {end_time_arg}")
    else:
        # Default to now if not provided
        end_time = now
        demisto.debug("No end_time provided, using default: now")
    
    from_date = start_time.strftime(DATE_FORMAT)
    to_date = end_time.strftime(DATE_FORMAT)

    demisto.debug(f"Fetching events from {from_date} to {to_date} with limit {limit}")

    # We'll reuse the logic but just fetch one batch or up to limit
    response = client.run_report(report_id=report_id, fetch_size=limit, offset=0, from_date=from_date, to_date=to_date)

    # Extract field mapping from response
    field_mapping = extract_field_mapping(response)
    
    # Extract events - will raise KeyError/TypeError if format is wrong
    raw_events = response["result"]["data"]
    
    demisto.debug(f"get_events_command: Raw events count: {len(raw_events)}")

    # Map events, extracting from {"results": {...}} wrapper
    events = []
    for raw_event in raw_events[:limit]:
        event_data = raw_event["results"]
        mapped_event = map_event(event_data, field_mapping)
        events.append(mapped_event)

    demisto.debug(f"get_events_command: Fetched {len(events)} events out of {len(raw_events)} raw events")

    headers = list(field_mapping.values()) if field_mapping else list(DEFAULT_FIELD_MAPPING.values())
    
    return events, CommandResults(
        readable_output=tableToMarkdown("IBM Guardium Events", events, headers=headers, removeNull=True),
    )


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()

    base_url = params.get("url", "")
    credentials = params.get("credentials", {})
    api_key = credentials.get("identifier")
    api_secret = credentials.get("password")
    report_id = str(params.get("report_id", ""))
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Trim base_url
    base_url = base_url.rstrip("/")

    try:
        demisto.debug(
            f"Creating Client with base_url: {base_url}, api_key: ...{api_key[-4:] if api_key else 'None'}, api_secret: ...{api_secret[-4:] if api_secret else 'None'}"
        )
        client = Client(base_url=base_url, auth=(api_key, api_secret), verify=verify_certificate, proxy=proxy)

        demisto.debug(f"Client initialized successfully")

        command = demisto.command()
        demisto.debug(f"Command being executed is {command}")

        if command == "test-module":
            return_results(test_module(client, report_id))

        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
            demisto.debug(f"fetch-events: max_fetch set to {max_fetch}")
            last_run = demisto.getLastRun()
            demisto.debug(f"fetch-events: Retrieved last_run: {last_run}")
            events, next_run = fetch_events(client, report_id, max_fetch, last_run)

            send_events_to_xsiam_with_time(events)

            # Save next run
            demisto.setLastRun(next_run)
            demisto.debug(f"fetch-events: Successfully saving next_run: {next_run}")

        elif command == "ibm-guardium-get-events":
            events, results = get_events_command(client, report_id, args)
            
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam_with_time(events)
            else:
                return_results(results)

    except Exception as e:
        error_msg = f"Failed to execute {demisto.command()} command.\nError: {str(e)}"
        return_error(error_msg)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
