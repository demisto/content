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

API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # Format for dates sent in API requests
VENDOR = "IBM"
PRODUCT = "Guardium_dsc"
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
            API response containing report data and pagination metadata
        """
        payload = {
            "fetch_size": fetch_size,
            "offset": offset,
            "report_id": report_id,
            "runtime_parameter_list": [
                {
                    "key": "QUERY_FROM_DATE",
                    "runtime_parameter_type": "DATE",
                    "operator_type": "GREATER_THAN_OR_EQUAL",
                    "value": from_date,
                },
                {"key": "QUERY_TO_DATE", "runtime_parameter_type": "DATE", "operator_type": "LESS_THAN", "value": to_date},
            ],
            "without_limit": True,
        }
        demisto.debug(f"Running report {report_id} with payload: {payload}")
        response = self._http_request(method="POST", url_suffix="/api/v3/reports/run", json_data=payload, resp_type="text")

        # The API returns multiple JSON objects separated by newlines
        # First line: report data with report_layout and data array
        # Second line (optional): pagination metadata with limit_reached, total_number_of_rows, final_result
        # If the second line doesn't exist, the metadata is included in the first line
        lines = response.strip().split("\n")
        demisto.debug(f"Received {len(lines)} JSON response line(s)")

        if not lines:
            raise DemistoException("Empty response from API")

        # Parse first line containing report data
        try:
            parsed_response = json.loads(lines[0])
            demisto.debug(f"Parsed first line successfully. Keys: {list(parsed_response.keys())}")

            # Validate expected structure in first line
            if "result" not in parsed_response:
                raise DemistoException("First line missing expected 'result' key")

            result_data = parsed_response.get("result", {})
            if "report_layout" not in result_data or "data" not in result_data:
                demisto.debug(f"Warning: First line result keys: {list(result_data.keys())}")

        except json.JSONDecodeError as e:
            demisto.debug(f"Failed to parse JSON. Full response text: {response}")
            raise DemistoException(f"Failed to parse first line as JSON: {e}")

        # Parse second line if present and merge pagination metadata
        if len(lines) > 1:
            try:
                pagination_data = json.loads(lines[1])
                demisto.debug(f"Parsed second line successfully. Keys: {list(pagination_data.keys())}")

                # Merge pagination metadata into the main response
                if "result" in pagination_data:
                    parsed_response.setdefault("result", {}).update(pagination_data["result"])
                    demisto.debug(f"Merged pagination metadata: {pagination_data['result']}")
                else:
                    demisto.debug(f"Warning: Second line missing 'result' key. Available keys: {list(pagination_data.keys())}")
            except json.JSONDecodeError as e:
                demisto.debug(f"Failed to parse pagination JSON. Full response text: {response}")
                raise DemistoException(f"Failed to parse pagination data (second line): {e}")

        return parsed_response


""" HELPER FUNCTIONS """


def extract_field_mapping(response: dict[str, Any]) -> dict[str, str]:
    """
    Extract field mapping from the API response's report_headers.
    Uses the user-friendly field_name.nls_value.

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
            field_name = header.get("field_name", {}).get("nls_value")
            field_mapping[sequence] = field_name
        demisto.debug(f"Extracted field mapping: {field_mapping}")
        return field_mapping
    except (KeyError, TypeError) as e:
        raise DemistoException(f"Failed to extract field mapping from API response: {e}")


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


def validate_timestamp_field(timestamp_field: str | None, field_mapping: dict[str, str], is_fetch_flow: bool = True) -> None:
    """
    Validate that the timestamp field exists in the report headers.

    Args:
        timestamp_field: Name of the timestamp field to validate
        field_mapping: Dictionary mapping field IDs to field names from report headers
        is_fetch_flow: True if called from fetch-events, False if called from get-events with should_push_events

    Raises:
        DemistoException: If timestamp field is empty/None or not found in available fields
    """
    if not timestamp_field:
        if is_fetch_flow:
            raise DemistoException("Timestamp Field Name is required when using fetch events.")
        else:
            raise DemistoException("Timestamp Field Name is required when should_push_events=true.")

    available_fields = list(field_mapping.values())
    if timestamp_field not in available_fields:
        raise DemistoException(
            f"Timestamp field '{timestamp_field}' not found in this report's headers. "
            f"Available fields in this report: {', '.join(available_fields)}"
        )
    demisto.debug(f"Validated timestamp field '{timestamp_field}' exists in report headers")


def send_events_to_xsiam_with_time(events: list[dict[str, Any]], timestamp_field: str) -> None:
    """
    Add _time field to events and send them to XSIAM.
    The _time field is required by XSIAM for event ingestion.
    If timestamp field is missing, uses None as fallback.

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
            # Log error and use None as fallback to avoid failing the entire fetch
            demisto.error(
                f"Timestamp field '{timestamp_field}' not found in event. Using None as fallback. "
                f"Event keys: {list(event.keys())}"
            )
            event["_time"] = None

    # Send events to XSIAM
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"Successfully sent {len(events)} events to XSIAM")


def deduplicate_events(events: list[dict[str, Any]], last_run: dict[str, Any], timestamp_field: str) -> list[dict[str, Any]]:
    """
    Deduplicate events based on the ignore list from last run.
    Events are in descending order (newest first).

    Args:
        events: List of events ordered by timestamp descending (newest first)
        last_run: Dictionary containing last_fetch_time and fetched_event_hashes
        timestamp_field: Name of the timestamp field to use (required)

    Returns:
        List of deduplicated events in descending order
    """
    if not events:
        return events

    last_fetch_time = last_run.get("last_fetch_time")
    fetched_event_hashes = set(last_run.get("fetched_event_hashes", []))

    demisto.debug(
        f"Deduplicating {len(events)} events using timestamp field '{timestamp_field}'. "
        f"Last fetch time: {last_fetch_time}, Ignore list size: {len(fetched_event_hashes)}"
    )

    deduplicated: list[dict[str, Any]] = []

    # Iterate from the end (oldest first)
    for idx in range(len(events) - 1, -1, -1):
        event = events[idx]
        event_time = event.get(timestamp_field)

        # If timestamp is greater than last_fetch_time, add this event and all remaining (newer) events
        if event_time and last_fetch_time and event_time > last_fetch_time:
            deduplicated = events[: idx + 1]
            demisto.debug(
                f"Found event at index {idx} with timestamp {event_time} > last_fetch_time {last_fetch_time}, "
                f"added {idx + 1} newer events without duplicate check"
            )
            break

        # If event has the same timestamp as last_fetch_time, check if it's a duplicate
        if event_time == last_fetch_time:
            event_hash = get_event_hash(event)
            if event_hash in fetched_event_hashes:
                demisto.debug(f"Skipping duplicate event with hash {event_hash} at time {event_time}")
                continue

        deduplicated.insert(0, event)  # Insert at beginning to maintain descending order

    demisto.debug(
        f"Deduplication complete. Original: {len(events)}, Deduplicated: {len(deduplicated)}, "
        f"Filtered: {len(events) - len(deduplicated)}"
    )

    return deduplicated


def build_ignore_list(events: list[dict[str, Any]], timestamp_field: str) -> set[str]:
    """
    Build ignore list of event hashes with the same timestamp as the most recent event.
    Events are expected in descending order (newest first).

    Args:
        events: List of events ordered by timestamp descending (newest first)
        timestamp_field: Name of the timestamp field to use (required)

    Returns:
        Set of event hashes for events with the same timestamp as the most recent (first) event
    """
    ignore_set: set[str] = set()
    if not events:
        return ignore_set

    # Most recent event is the first one (descending order)
    most_recent_time = events[0].get(timestamp_field)

    if not most_recent_time:
        raise DemistoException(f"Timestamp field '{timestamp_field}' not found in first event")

    # Iterate from the beginning to collect all events with the same timestamp as the most recent
    for event in events:
        event_time = event.get(timestamp_field)
        if event_time == most_recent_time:
            ignore_set.add(get_event_hash(event))
        else:
            break

    demisto.debug(f"Created ignore list with {len(ignore_set)} event hashes at timestamp {most_recent_time}")
    return ignore_set


""" COMMAND FUNCTIONS """


def test_module_command(client: Client, report_id: str, is_fetch: bool, timestamp_field: str | None) -> str:
    """
    Test API connectivity and authentication.
    If fetch is enabled, also validates that the timestamp field exists in the response.

    Args:
        client: IBM Guardium client
        report_id: Report ID to test with
        is_fetch: Whether fetch events is enabled
        timestamp_field: Name of the timestamp field (required if is_fetch is True)

    Returns:
        'ok' if successful, error message otherwise
    """
    try:
        now = datetime.utcnow()
        from_date = (now - timedelta(hours=5)).strftime(API_DATE_FORMAT)
        to_date = now.strftime(API_DATE_FORMAT)

        demisto.debug(f"Testing connectivity: fetching 1 event from {from_date} to {to_date}")
        response = client.run_report(report_id, fetch_size=1, offset=0, from_date=from_date, to_date=to_date)

        # If fetch is enabled, validate timestamp field exists in response headers
        if is_fetch:
            # Extract field mapping (headers) and validate timestamp field
            field_mapping = extract_field_mapping(response)
            validate_timestamp_field(timestamp_field, field_mapping, is_fetch_flow=True)

        return "ok"
    except DemistoException as e:
        error_str = str(e)
        demisto.debug(f"Test module failed with DemistoException: {error_str}\nTraceback: {traceback.format_exc()}")

        if "Forbidden" in error_str or "Unauthorized" in error_str or "401" in error_str or "403" in error_str:
            return "Authorization Error: Please verify that the API Key and Secret are correctly configured."
        elif "ConnectionError" in error_str or "Name does not resolve" in error_str or "Failed to resolve" in error_str:
            return "Connection Error: Unable to connect to the server. Please verify the Server URL is correct and accessible."
        elif "timeout" in error_str.lower() or "timed out" in error_str.lower():
            return "Connection Error: Request timed out. Please verify the Server URL and network connectivity."
        else:
            return f"Error: {error_str}"
    except Exception as e:
        demisto.debug(f"Test module failed with unexpected exception: {str(e)}\nTraceback: {traceback.format_exc()}")
        return f"Unexpected error during connection test: {str(e)}"


def fetch_events_command(
    client: Client, report_id: str, max_fetch: int, last_run: dict[str, Any], timestamp_field: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch events from IBM Guardium with deduplication.
    The API returns events in descending order (newest first).

    Args:
        client: IBM Guardium client
        report_id: Report ID to fetch events from
        max_fetch: Maximum number of events to fetch
        last_run: Last run context with last_fetch_time and fetched_event_hashes
        timestamp_field: Name of the timestamp field to use for deduplication and _time

    Returns:
        Tuple of (deduplicated events list in descending order, next run context)
    """
    demisto.debug(f"Starting fetch_events with last_run: {last_run}, max_fetch: {max_fetch}")
    last_fetch_time_str = last_run.get("last_fetch_time")

    # Determine fetch time range
    now = datetime.utcnow()
    if last_fetch_time_str:
        # Use dateparser to handle various timestamp formats flexibly
        last_fetch_time = dateparser.parse(last_fetch_time_str)
        if not last_fetch_time:
            raise DemistoException(f"Failed to parse last_fetch_time: {last_fetch_time_str}")
    else:
        # Default to 12 hours ago for first fetch to account for IBM Guardium's event indexing delays.
        # Events may be indexed with significant delays (e.g., 2+ hours). Without a sufficient lookback period,
        # the integration may never retrieve any events, as the fetch window would always be ahead of the indexed events.
        last_fetch_time = now - timedelta(hours=12)
        demisto.debug("No last_fetch_time found, using default: 12 hours ago")

    from_date = last_fetch_time.strftime(API_DATE_FORMAT)
    to_date = now.strftime(API_DATE_FORMAT)
    demisto.debug(f"Fetching events from {from_date} to {to_date}")

    events: list[dict[str, Any]] = []
    offset = 0
    field_mapping: dict[str, str] = {}
    final_result = False

    while len(events) < max_fetch and not final_result:
        remaining = max_fetch - len(events)
        batch_size = min(MAX_BATCH_SIZE, remaining)
        demisto.debug(f"Fetching batch with offset={offset}, batch_size={batch_size}, remaining={remaining}")

        response = client.run_report(
            report_id=report_id, fetch_size=batch_size, offset=offset, from_date=from_date, to_date=to_date
        )

        # Extract field mapping only on first batch (offset == 0)
        if offset == 0:
            field_mapping = extract_field_mapping(response)
            # Validate timestamp field exists in report headers
            validate_timestamp_field(timestamp_field, field_mapping, is_fetch_flow=True)

        raw_events = response.get("result", {}).get("data", [])
        demisto.debug(f"Raw events count: {len(raw_events)}")

        if not raw_events:
            demisto.debug("No events returned in batch, stopping fetch loop")
            break

        # Process events
        for raw_event in raw_events:
            event_data = raw_event["results"]
            mapped_event = map_event(event_data, field_mapping)
            events.append(mapped_event)

            if len(events) >= max_fetch:
                demisto.debug(f"Reached max_fetch limit of {max_fetch}, stopping event collection")
                break

        # Check for final_result flag in the response
        result_data = response.get("result", {})
        final_result = result_data.get("final_result")
        limit_reached = result_data.get("limit_reached")

        demisto.debug(
            f"Batch complete: fetched {len(raw_events)} events, total so far: {len(events)}, "
            f"final_result={final_result}, limit_reached={limit_reached}"
        )

        # Stop if we've reached the final result
        if final_result:
            demisto.debug("Received final_result=true, stopping pagination")
            break

        # Stop if limit not reached (no more data available)
        if not limit_reached:
            demisto.debug("limit_reached is false or absent, stopping pagination")
            break

        # Update offset for next iteration
        offset += len(raw_events)

    # Deduplicate events (events are in descending order - newest first)
    deduplicated_events = deduplicate_events(events, last_run, timestamp_field)
    new_ignore_set = build_ignore_list(deduplicated_events, timestamp_field)

    # Update last_run with the most recent event (first event in descending order)
    if deduplicated_events:
        most_recent_event = deduplicated_events[0]  # First event is the newest
        if timestamp_field in most_recent_event:
            next_run = {"last_fetch_time": most_recent_event[timestamp_field], "fetched_event_hashes": list(new_ignore_set)}
        else:
            raise DemistoException(f"Timestamp field '{timestamp_field}' not found in most recent event")
    else:
        next_run = last_run
        demisto.debug(f"No events after deduplication, keeping last_run unchanged: {next_run}")

    demisto.debug(
        f"Fetch completed. Total events: {len(events)}, Deduplicated: {len(deduplicated_events)}. " f"Next run: {next_run}"
    )
    return deduplicated_events, next_run


def get_events_command(
    client: Client, report_id: str, args: dict[str, Any], timestamp_field: str
) -> tuple[list[dict[str, Any]], CommandResults, str | None]:
    """
    Manual command to fetch events within a specified time range.

    Args:
        client: IBM Guardium client
        report_id: Report ID to fetch events from
        args: Command arguments (limit, start_time, end_time, should_push_events, timestamp_field)
        timestamp_field: Timestamp field from integration configuration

    Returns:
        Tuple of (events list, CommandResults, timestamp_field to use for XSIAM or None)
    """
    demisto.debug(f"Executing get_events_command with args: {args}")
    limit = arg_to_number(args.get("limit", 50)) or 50

    # Validate limit does not exceed 1000
    if limit > 1000:
        raise DemistoException("The limit parameter cannot exceed 1000. Please use a smaller value.")

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

    from_date = start_time.strftime(API_DATE_FORMAT)
    to_date = end_time.strftime(API_DATE_FORMAT)

    demisto.debug(f"Getting events from {from_date} to {to_date} with limit {limit}")

    response = client.run_report(report_id=report_id, fetch_size=limit, offset=0, from_date=from_date, to_date=to_date)
    field_mapping = extract_field_mapping(response)
    raw_events = response.get("result", {}).get("data", [])

    events = [map_event(raw_event["results"], field_mapping) for raw_event in raw_events]
    demisto.debug(f"Got {len(events)} events")

    headers = list(field_mapping.values()) if field_mapping else []

    # Determine timestamp field for XSIAM if should_push_events is true
    timestamp_field_result = None
    if argToBoolean(args.get("should_push_events", False)):
        # Get timestamp_field from command argument or fall back to config parameter
        cmd_timestamp_field = args.get("timestamp_field") or timestamp_field

        # Validate timestamp field (checks for None/empty and existence in headers)
        validate_timestamp_field(cmd_timestamp_field, field_mapping, is_fetch_flow=False)
        timestamp_field_result = cmd_timestamp_field

    return (
        events,
        CommandResults(
            readable_output=tableToMarkdown("IBM Guardium Events", events, headers=headers, removeNull=True),
        ),
        timestamp_field_result,
    )


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
    is_fetch = params.get("isFetchEvents", False)
    timestamp_field = params.get("timestamp_field", "")

    try:
        client = Client(base_url=base_url, auth=(api_key, api_secret), verify=verify_certificate, proxy=proxy)
        command = demisto.command()
        demisto.debug(f"Executing command: {command}")

        if command == "test-module":
            return_results(test_module_command(client, report_id, is_fetch, timestamp_field))

        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
            last_run = demisto.getLastRun()
            events, next_run = fetch_events_command(client, report_id, max_fetch, last_run, timestamp_field)

            send_events_to_xsiam_with_time(events, timestamp_field)
            demisto.setLastRun(next_run)
            demisto.debug(f"Successfully sent {len(events)} events to XSIAM and set last run to: {next_run}")

        elif command == "ibm-guardium-get-events":
            events, results, timestamp_field_result = get_events_command(client, report_id, args, timestamp_field)

            if argToBoolean(args.get("should_push_events", False)) and timestamp_field_result:
                send_events_to_xsiam_with_time(events, timestamp_field_result)
                demisto.debug(f"Successfully sent {len(events)} events to XSIAM")
                return_results(f"Sent {len(events)} events to XSIAM")

            return_results(results)

    except Exception as e:
        error_msg = f"Failed to execute {demisto.command()} command.\nError: {str(e)}\nTraceback: {traceback.format_exc()}"
        return_error(error_msg)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
