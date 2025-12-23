import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
import hashlib
import traceback
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "IBM"
PRODUCT = "Guardium"
DEFAULT_MAX_FETCH = 10000
MAX_BATCH_SIZE = 1000

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, auth: tuple, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

    def run_report(self, report_id: str, fetch_size: int, offset: int, from_date: str, to_date: str) -> dict[str, Any]:
        """
        Run a report to fetch events from IBM Guardium.
        
        Args:
            report_id: The ID of the report to run
            fetch_size: Number of events to fetch
            offset: Offset for pagination
            from_date: Start date in ISO format
            to_date: End date in ISO format
            
        Returns:
            API response containing report data
        """
        payload = {
            "fetch_size": fetch_size,
            "offset": offset,
            "report_id": report_id,
            "runtime_parameter_list": [
                {"key": "QUERY_FROM_DATE", "runtime_parameter_type": "DATE", "operator_type": "GREATER_THAN_OR_EQUAL", "value": from_date},
                {"key": "QUERY_TO_DATE", "runtime_parameter_type": "DATE", "operator_type": "LESS_THAN", "value": to_date},
            ],
            "without_limit": True,
            "date_range": {"type": "CUSTOM", "from_date": from_date, "to_date": to_date},
            "order_by": "ASC",
        }
        demisto.debug(f"Running report {report_id} with payload: {payload}")
        response = self._http_request(
            method="POST",
            url_suffix="/api/v3/reports/run",
            json_data=payload,
            resp_type='text'
        )
        # The API returns multiple JSON objects separated by newlines
        # Parse the first JSON object which contains the report data
        lines = response.strip().split('\n')
        #TODO Remove
        demisto.debug(f"{lines=}")
        if lines:
            #TODO consider getting more lines
            parsed_response = json.loads(lines[0])
            #TODO Remove
            demisto.debug(f"{parsed_response=}")
            return parsed_response
        else:
            raise DemistoException("Empty response from API")


""" HELPER FUNCTIONS """


def extract_field_mapping(response: dict[str, Any]) -> dict[str, str]:
    """
    Extract field mapping from the API response's report_headers.
    Uses the user-friendly field_name.nls_value when available, otherwise falls back to header_name.
    
    Args:
        response: API response containing report_layout with report_headers
    
    Returns:
        Dictionary mapping sequence number to field display name (e.g., {"1": "Date created (local time)", "2": "Performed by"})
        
    Raises:
        DemistoException: If field mapping extraction fails
    """
    try:
        headers = response["result"]["report_layout"]["report_headers"]
        field_mapping = {}
        for header in headers:
            sequence = str(header["sequence"])
            field_name = header.get("field_name", {}).get("nls_value") or header["header_name"]
            field_mapping[sequence] = field_name
        demisto.debug(f"Extracted field mapping: {field_mapping}")
        return field_mapping
    except (KeyError, TypeError) as e:
        raise DemistoException(f"Failed to extract field mapping from API response: {e}")


def find_timestamp_field(event: dict[str, Any]) -> str:
    """
    Find the timestamp field in an event by looking for date-like values.
    
    Args:
        event: Event dictionary
        
    Returns:
        Name of the timestamp field
        
    Raises:
        DemistoException: If no timestamp field is found in the event
    """
    for key, value in event.items():
        if isinstance(value, str):
            # Check if value matches common date patterns (YYYY-MM-DD or contains time)
            if any(char in value for char in ["-", ":"]) and len(value) >= 10:
                try:
                    # Try to parse as date to verify it's a valid timestamp
                    dateparser.parse(value)
                    demisto.debug(f"Found timestamp field by value pattern: {key} = {value}")
                    return key
                except Exception:
                    continue
    
    raise DemistoException("No timestamp field found in event. Unable to process events without a timestamp field.")


def get_event_hash(event: dict[str, Any]) -> str:
    """
    Generate a SHA-256 hash for an event.
    
    Args:
        event: Event dictionary to hash
        
    Returns:
        First 16 characters of SHA-256 hash
    """
    event_str = json.dumps(event, sort_keys=True)
    return hashlib.sha256(event_str.encode()).hexdigest()[:16]


def map_event(raw_event: dict[str, Any], field_mapping: dict[str, str]) -> dict[str, Any]:
    """
    Map raw event fields to readable names.
    
    Args:
        raw_event: Raw event data with numbered fields
        field_mapping: Mapping from field IDs to field names
    
    Returns:
        Event with readable field names
    """
    return {field_mapping.get(key, key): value for key, value in raw_event.items()}


def send_events_to_xsiam_with_time(events: list[dict[str, Any]], timestamp_field: str) -> None:
    """
    Add _time field to events and send them to XSIAM.
    The _time field is required by XSIAM for event ingestion.

    Args:
        events: List of events to send to XSIAM
        timestamp_field: Name of the timestamp field to use for _time (required)
    """
    if not events:
        demisto.debug("No events to send to XSIAM")
        return

    demisto.debug(f"Preparing to send {len(events)} events to XSIAM with timestamp field: {timestamp_field}")

    # Add _time field to each event based on the timestamp field
    for event in events:
        if timestamp_field in event:
            event["_time"] = event[timestamp_field]
        else:
            raise DemistoException(f"Timestamp field '{timestamp_field}' not found in event")

    # Send events to XSIAM
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"Successfully sent {len(events)} events to XSIAM")


def deduplicate_events(events: list[dict[str, Any]], last_run: dict[str, Any], timestamp_field: str) -> list[dict[str, Any]]:
    """
    Deduplicate events based on the ignore list from last run.

    Args:
        events: List of events ordered by timestamp ascending
        last_run: Dictionary containing last_fetch_time and fetched_event_hashes
        timestamp_field: Name of the timestamp field to use (required)

    Returns:
        List of deduplicated events
    """
    if not events:
        return events

    last_fetch_time = last_run.get("last_fetch_time")
    fetched_event_hashes = set(last_run.get("fetched_event_hashes", []))

    demisto.debug(
        f"Deduplicating {len(events)} events using timestamp field '{timestamp_field}'. "
        f"Last fetch time: {last_fetch_time}, Ignore list size: {len(fetched_event_hashes)}"
    )

    deduplicated = []
    for event in events:
        event_time = event.get(timestamp_field)

        # If event timestamp is greater than last_fetch_time, all remaining events are new
        if event_time and event_time > last_fetch_time:
            # Add this event and all remaining events without checking
            deduplicated.extend(events[len(deduplicated) :])
            demisto.debug(
                f"Found event with timestamp {event_time} > last_fetch_time {last_fetch_time}, "
                f"adding remaining {len(events) - len(deduplicated)} events without duplicate check"
            )
            break

        # If event has the same timestamp as last_fetch_time, check if it's a duplicate
        if event_time == last_fetch_time:
            event_hash = get_event_hash(event)
            if event_hash in fetched_event_hashes:
                demisto.debug(f"Skipping duplicate event with hash {event_hash} at time {event_time}")
                continue

        deduplicated.append(event)

    demisto.debug(
        f"Deduplication complete. Original: {len(events)}, Deduplicated: {len(deduplicated)}, "
        f"Filtered: {len(events) - len(deduplicated)}"
    )

    return deduplicated


def build_ignore_list(events: list[dict[str, Any]], timestamp_field: str) -> set[str]:
    """
    Build ignore list of event hashes with the same timestamp as the last event.
    
    Args:
        events: List of events ordered by timestamp ascending
        timestamp_field: Name of the timestamp field to use (required)
    
    Returns:
        Set of event hashes for events with the same timestamp as the last event
    """
    ignore_set = set()
    if not events:
        return ignore_set
    
    last_event_time = events[-1].get(timestamp_field)
    
    if not last_event_time:
        raise DemistoException(f"Timestamp field '{timestamp_field}' not found in last event")
    
    for event in reversed(events):
        event_time = event.get(timestamp_field)
        if event_time == last_event_time:
            ignore_set.add(get_event_hash(event))
        else:
            break
    
    demisto.debug(f"Created ignore list with {len(ignore_set)} event hashes at timestamp {last_event_time}")
    return ignore_set


""" COMMAND FUNCTIONS """


def test_module(client: Client, report_id: str) -> str:
    """
    Test API connectivity and authentication.
    
    Args:
        client: IBM Guardium client
        report_id: Report ID to test with
        
    Returns:
        'ok' if successful, error message otherwise
    """
    try:
        now = datetime.utcnow()
        from_date = (now - timedelta(hours=5)).strftime(DATE_FORMAT)
        to_date = now.strftime(DATE_FORMAT)
        
        demisto.debug(f"Testing connectivity: fetching 1 event from {from_date} to {to_date}")
        client.run_report(report_id, fetch_size=1, offset=0, from_date=from_date, to_date=to_date)
        return "ok"
    except Exception as e:
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return f"Authorization Error: make sure API Key and Secret are correctly set. Full error: {e}"
        raise


def fetch_events(
    client: Client, report_id: str, max_fetch: int, last_run: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """
    Fetch events from IBM Guardium with deduplication.
    
    Args:
        client: IBM Guardium client
        report_id: Report ID to fetch events from
        max_fetch: Maximum number of events to fetch
        last_run: Last run context with last_fetch_time and fetched_event_hashes
        
    Returns:
        Tuple of (deduplicated events list, next run context, timestamp field name)
    """
    demisto.debug(f"Starting fetch_events with last_run: {last_run}, max_fetch: {max_fetch}")
    last_fetch_time_str = last_run.get("last_fetch_time")

    # Determine fetch time range
    now = datetime.utcnow()
    if last_fetch_time_str:
        last_fetch_time = datetime.strptime(last_fetch_time_str, DATE_FORMAT)
    else:
        last_fetch_time = now - timedelta(hours=1)
        demisto.debug("No last_fetch_time found, using default: 1 hour ago")

    from_date = last_fetch_time.strftime(DATE_FORMAT)
    to_date = now.strftime(DATE_FORMAT)
    demisto.debug(f"Fetching events from {from_date} to {to_date}")

    events: list[dict[str, Any]] = []
    offset = 0
    field_mapping: dict[str, str] = {}
    timestamp_field: str = ""

    while len(events) < max_fetch:
        remaining = max_fetch - len(events)
        batch_size = min(MAX_BATCH_SIZE, remaining)
        demisto.debug(f"Fetching batch with offset: {offset}, batch_size: {batch_size}, remaining: {remaining}")
        response = client.run_report(
            report_id=report_id, fetch_size=batch_size, offset=offset, from_date=from_date, to_date=to_date
        )
        
        # Extract field mapping and timestamp field only on first batch (offset == 0)
        # to avoid redundant processing on subsequent batches
        if offset == 0:
            field_mapping = extract_field_mapping(response)
            raw_events_temp = response.get("result", {}).get("data", [])
            if raw_events_temp:
                first_event = map_event(raw_events_temp[0]["results"], field_mapping)
                # Find timestamp field from first event - all events in the report have the same structure
                timestamp_field = find_timestamp_field(first_event)

        raw_events = response.get("result", {}).get("data", [])

        demisto.debug(f"Raw events count: {len(raw_events)}")

        if not raw_events:
            demisto.debug("No events returned in batch, stopping fetch loop")
            break

        for raw_event in raw_events:
            event_data = raw_event["results"]
            mapped_event = map_event(event_data, field_mapping)
            events.append(mapped_event)

            if len(events) >= max_fetch:
                demisto.debug(f"Reached max_fetch limit of {max_fetch}, stopping event collection")
                break

        demisto.debug(f"Fetched batch of {len(raw_events)} events. Total events so far: {len(events)}")

        if len(raw_events) < batch_size:
            demisto.debug(f"Received {len(raw_events)} events (less than batch_size {batch_size}), stopping")
            break

        offset += len(raw_events)
    
    deduplicated_events = deduplicate_events(events, last_run, timestamp_field)
    new_ignore_set = build_ignore_list(deduplicated_events, timestamp_field)

    if deduplicated_events:
        last_event = deduplicated_events[-1]
        if timestamp_field in last_event:
            next_run = {"last_fetch_time": last_event[timestamp_field], "fetched_event_hashes": list(new_ignore_set)}
        else:
            raise DemistoException(f"Timestamp field '{timestamp_field}' not found in last event")
    else:
        next_run = last_run
        demisto.debug(f"No events after deduplication, keeping last_run unchanged: {next_run}")

    demisto.debug(f"Fetch completed. Total events: {len(events)}, Deduplicated: {len(deduplicated_events)}. Next run: {next_run}")
    return deduplicated_events, next_run, timestamp_field


def get_events_command(client: Client, report_id: str, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults, str | None]:
    """
    Manual command to fetch events within a specified time range.
    
    Args:
        client: IBM Guardium client
        report_id: Report ID to fetch events from
        args: Command arguments (limit, start_time, end_time, should_push_events)
        
    Returns:
        Tuple of (events list, CommandResults, timestamp field name or None if no events)
    """
    demisto.debug(f"Executing get_events_command with args: {args}")
    limit = arg_to_number(args.get("limit", 50)) or 50
    now = datetime.utcnow()
    
    if args.get("start_time"):
        start_time = dateparser.parse(args["start_time"])
        if not start_time:
            raise DemistoException(f"Invalid start_time format: {args['start_time']}")
    else:
        start_time = now - timedelta(hours=1)
    
    if args.get("end_time"):
        end_time = dateparser.parse(args["end_time"])
        if not end_time:
            raise DemistoException(f"Invalid end_time format: {args['end_time']}")
    else:
        end_time = now

    from_date = start_time.strftime(DATE_FORMAT)
    to_date = end_time.strftime(DATE_FORMAT)

    demisto.debug(f"Getting events from {from_date} to {to_date} with limit {limit}")
    
    response = client.run_report(report_id=report_id, fetch_size=limit, offset=0, from_date=from_date, to_date=to_date)
    field_mapping = extract_field_mapping(response)
    raw_events = response.get("result", {}).get("data", [])
    
    events = [map_event(raw_event["results"], field_mapping) for raw_event in raw_events]
    demisto.debug(f"Got {len(events)} events")
    
    # Find timestamp field from first event if events exist
    timestamp_field = find_timestamp_field(events[0]) if events else None
    headers = list(field_mapping.values()) if field_mapping else []

    return events, CommandResults(
        readable_output=tableToMarkdown("IBM Guardium Events", events, headers=headers, removeNull=True),
    ), timestamp_field


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()

    base_url = params.get("url", "").rstrip("/")
    credentials = params.get("credentials", {})
    api_key = credentials.get("identifier")
    api_secret = credentials.get("password")
    report_id = str(params.get("report_id", ""))
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    try:
        client = Client(base_url=base_url, auth=(api_key, api_secret), verify=verify_certificate, proxy=proxy)
        command = demisto.command()
        demisto.debug(f"Executing command: {command}")

        if command == "test-module":
            return_results(test_module(client, report_id))

        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
            last_run = demisto.getLastRun()
            events, next_run, timestamp_field = fetch_events(client, report_id, max_fetch, last_run)
            
            send_events_to_xsiam_with_time(events, timestamp_field)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully sent {len(events)} events to XSIAM and set last run to: {next_run}")
            
        elif command == "ibm-guardium-get-events":
            events, results, timestamp_field = get_events_command(client, report_id, args)

            if argToBoolean(args.get("should_push_events", False)) and timestamp_field:
                send_events_to_xsiam_with_time(events, timestamp_field)
                demisto.debug(f"Successfully sent {len(events)} events to XSIAM")
                return_results(f"Sent {len(events)} events to XSIAM")
            
            return_results(results)

    except Exception as e:
        error_msg = f"Failed to execute {demisto.command()} command.\nError: {str(e)}\nTraceback: {traceback.format_exc()}"
        return_error(error_msg)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()