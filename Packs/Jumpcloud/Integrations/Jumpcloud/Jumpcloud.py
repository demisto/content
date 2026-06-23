import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

"""
JumpCloud
Integration for fetching events from the JumpCloud Directory Insights API.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "Jumpcloud"


class ApiPaths:
    """Centralized JumpCloud API endpoint paths."""

    DIRECTORY_EVENTS = "/insights/directory/v1/events"


class Config:
    """Global static configuration."""

    VENDOR = "jumpcloud"
    PRODUCT = "directory"

    # Date format for API requests (ISO 8601)
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # Pagination
    DEFAULT_PAGE_SIZE = 1000
    MAX_PAGE_SIZE = 1000
    MAX_PAGES_PER_FETCH = 50

    # Fetch defaults
    DEFAULT_MAX_FETCH = 5000
    DEFAULT_FROM_TIME = "5 minutes ago"

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 5
    TEST_MODULE_MAX_EVENTS = 1


class EventType(Enum):
    """Enum to hold all configuration for different event types.

    Each member maps a user-facing title to the JumpCloud service name
    used in the API request body.
    """

    DIRECTORY = ("directory", "Directory Events", "directory")
    SYSTEMS = ("systems", "System Events", "systems")
    ALERTS = ("alerts", "Alert Events", "all")
    OBJECT_STORAGE = ("object_storage", "Object Storage Events", "software")

    def __init__(self, type_string: str, title: str, service_name: str):
        self.type_string = type_string
        self.title = title
        self.service_name = service_name


# Map of all event types by title for lookup
ALL_EVENT_TYPES = list(EventType)


def get_formatted_utc_time(date_input: str | None) -> str:
    """Parse input and return the formatted UTC time string for JumpCloud API.

    Args:
        date_input: Date string to parse (e.g., '3 days ago', '2024-01-01T00:00:00Z')

    Returns:
        Formatted UTC time string in ISO 8601 format.
    """
    parsed_dt = parse_date_or_use_current(date_input)
    formatted_time = parsed_dt.strftime(Config.DATE_FORMAT)
    demisto.debug(f"[Date Helper] Input: '{date_input}' -> Output: '{formatted_time}' (UTC)")
    return formatted_time


def parse_date_or_use_current(date_string: str | None) -> datetime:
    """Parse a date string or return current UTC datetime if parsing fails.

    Args:
        date_string: Date string to parse, or None to use current UTC time.

    Returns:
        Parsed datetime object in UTC.
    """
    if not date_string:
        current_time = datetime.now(UTC)
        demisto.debug(f"[Date Helper] No input provided. Using current UTC: {current_time}")
        return current_time

    demisto.debug(f"[Date Helper] Attempting to parse date string: '{date_string}'")
    parsed_datetime = arg_to_datetime(arg=date_string, is_utc=True)

    if not parsed_datetime:
        demisto.debug(f"[Date Helper] Failed to parse '{date_string}'. Fallback to current UTC.")
        return datetime.now(UTC)

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


def get_event_types_from_titles(event_types_to_fetch: list[str]) -> list[EventType]:
    """Convert user-facing event type titles into EventType Enum members.

    If the list contains 'all' or is empty, returns all event types.

    Args:
        event_types_to_fetch: List of event type titles.

    Raises:
        DemistoException: If any of the provided event type titles are invalid.

    Returns:
        List of EventType Enum members.
    """
    if not event_types_to_fetch or "all" in event_types_to_fetch:
        demisto.debug("[Config] Fetching all event types")
        return ALL_EVENT_TYPES

    valid_titles = {et.title for et in EventType}
    invalid_types = [title for title in event_types_to_fetch if title not in valid_titles]

    if invalid_types:
        valid_options = ", ".join(sorted(valid_titles))
        raise DemistoException(
            f"Invalid event type(s) provided: {invalid_types}. "
            f"Please select from the following list: {valid_options}"
        )

    return [et for et in EventType if et.title in event_types_to_fetch]


def extract_time_from_event(event: dict) -> str | None:
    """Extract the time field value from an event.

    JumpCloud events use the 'timestamp' field in ISO 8601 format.

    Args:
        event: The event dictionary.

    Returns:
        ISO 8601 formatted time string, or None if not found.
    """
    return event.get("timestamp")


def add_time_to_events(events: list[dict], event_type: EventType) -> None:
    """Add _time and source_log_type fields to events for XSIAM ingestion.

    Args:
        events: List of event dictionaries to enrich.
        event_type: The EventType Enum member representing the source.
    """
    for event in events:
        event_time = extract_time_from_event(event)
        if event_time:
            event["_time"] = event_time
        else:
            demisto.debug(f"[Event Time] WARNING: Event missing time field: {event.get('id', 'unknown')}")

        event["source_log_type"] = event_type.title


def get_event_id(event: dict) -> str | None:
    """Extract the event ID from an event dictionary.

    Args:
        event: The event dictionary.

    Returns:
        The event ID string, or None if not found.
    """
    event_id = event.get("id")
    if event_id:
        return str(event_id)
    return None


def deduplicate_events(events: list[dict], last_fetched_ids: list[str]) -> list[dict]:
    """Remove already-processed events based on previously fetched IDs.

    Args:
        events: List of events to deduplicate.
        last_fetched_ids: List of event IDs from the previous run.

    Returns:
        List of new (non-duplicate) events.
    """
    if not events:
        demisto.debug("[Dedup] No events to process")
        return events

    if not last_fetched_ids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous IDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_ids)} previously fetched IDs")

    fetched_ids_set = set(last_fetched_ids)
    new_events = [event for event in events if get_event_id(event) not in fetched_ids_set]

    skipped_count = len(events) - len(new_events)
    if skipped_count > 0:
        demisto.debug(f"[Dedup] Skipped {skipped_count} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] No duplicates found.")

    return new_events


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Args:
        params: Raw parameters from demisto.params().

    Returns:
        Validated configuration dictionary.
    """
    base_url = params.get("url", "https://api.jumpcloud.com").rstrip("/")

    api_key = params.get("api_key", {})
    if isinstance(api_key, dict):
        api_key = api_key.get("password", "")

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    demisto.debug(f"[Config] URL: {base_url}")

    return {
        "base_url": base_url,
        "api_key": api_key,
        "verify": verify_certificate,
        "proxy": proxy,
    }


# endregion

# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """JumpCloud API client.

    Extends ContentClient with JumpCloud-specific functionality including
    API key authentication and methods for fetching directory insight events.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        """Initialize the JumpCloud client.

        Args:
            base_url: JumpCloud API server URL.
            api_key: JumpCloud API key for x-api-key header authentication.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use proxy settings.
        """
        auth_handler = ApiKeyAuthHandler(key=api_key, header_name="x-api-key")

        retry_policy = RetryPolicy(  # type: ignore[call-arg]
            max_attempts=4,
            retryable_status_codes=(429, 500, 502, 503, 504),
        )

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name="Jumpcloud",
            timeout=60,
            retry_policy=retry_policy,
        )

    def get_events_page(
        self,
        event_type: EventType,
        start_time: str,
        end_time: str | None = None,
        limit: int = Config.DEFAULT_PAGE_SIZE,
        search_after: dict | None = None,
    ) -> dict[str, Any]:
        """Fetch a single page of events from the JumpCloud Directory Insights API.

        Uses POST /insights/directory/v1/events with the appropriate service filter.

        Args:
            event_type: The EventType to fetch.
            start_time: Start time filter (ISO 8601).
            end_time: End time filter (ISO 8601) or None for current time.
            limit: Number of results per page (max 1000).
            search_after: Pagination cursor from previous response.

        Returns:
            Full API response dictionary containing events and optional search_after cursor.
        """
        body: dict[str, Any] = {
            "service": [event_type.service_name],
            "start_time": start_time,
            "limit": min(limit, Config.MAX_PAGE_SIZE),
            "sort": "ASC",
        }

        if end_time:
            body["end_time"] = end_time

        if search_after:
            body["search_after"] = search_after

        demisto.debug(
            f"[API Fetch] {event_type.type_string} | Limit: {limit} | "
            f"search_after: {search_after is not None} | Body: {body}"
        )

        response = self._http_request(
            method="POST",
            url_suffix=ApiPaths.DIRECTORY_EVENTS,
            json_data=body,
            headers={"Content-Type": "application/json"},
        )

        # Response is a list of events directly, or a dict with events
        if isinstance(response, list):
            events = response
            demisto.debug(f"[API Fetch] {event_type.type_string}: {len(events)} events returned (list response)")
            return {"events": events, "search_after": None}

        events = response if isinstance(response, list) else response.get("events", response.get("results", []))
        next_cursor = response.get("search_after") if isinstance(response, dict) else None

        demisto.debug(f"[API Fetch] {event_type.type_string}: {len(events)} events returned")
        return {"events": events, "search_after": next_cursor}

    def send_events(self, events: list[dict]) -> None:
        """Send events to XSIAM using the ContentClient context.

        Args:
            events: List of event dicts to send.
        """
        demisto.debug(f"[API] Sending {len(events)} events to XSIAM")
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[API] Successfully sent {len(events)} events to XSIAM")


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by fetching a small number of events.

    Args:
        client: The JumpCloud client.

    Returns:
        'ok' if test passed, otherwise raises an exception.
    """
    demisto.debug("[Test Module] Starting...")
    try:
        utc_now = datetime.now(UTC)
        test_time = (utc_now - timedelta(minutes=Config.TEST_MODULE_LOOKBACK_MINUTES)).strftime(Config.DATE_FORMAT)

        demisto.debug(f"[Test Module] Fetching directory events from: {test_time}")
        fetch_events_with_pagination(
            client,
            event_type=EventType.DIRECTORY,
            start_time=test_time,
            max_events=Config.TEST_MODULE_MAX_EVENTS,
        )

        demisto.debug("[Test Module] Success")
        return "ok"

    except Exception as error:
        error_msg = str(error)
        demisto.debug(f"[Test Module] Failed: {error_msg}")
        if "401" in error_msg or "403" in error_msg:
            return "Authorization Error: Verify your API Key."
        raise


def fetch_events_with_pagination(
    client: Client,
    event_type: EventType,
    start_time: str,
    end_time: str | None = None,
    max_events: int = Config.DEFAULT_MAX_FETCH,
) -> tuple[list[dict], dict | None]:
    """Fetch events with cursor-based pagination support.

    Uses the search_after cursor returned by the JumpCloud API
    to paginate through results.

    Args:
        client: The JumpCloud client.
        event_type: The EventType to fetch.
        start_time: Start time (ISO 8601).
        end_time: End time (ISO 8601) or None.
        max_events: Maximum number of events to fetch.

    Returns:
        Tuple of (list of event dictionaries, last search_after cursor or None).
    """
    events: list[dict] = []
    search_after: dict | None = None
    page = 0
    page_size = min(Config.MAX_PAGE_SIZE, max_events)

    demisto.debug(
        f"[Pagination Loop] Start | Type: {event_type.type_string} | Goal: {max_events} | "
        f"Time: {start_time} -> {end_time or 'Now'}"
    )

    while len(events) < max_events:
        response = client.get_events_page(
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
            limit=page_size,
            search_after=search_after,
        )

        page_events = response.get("events", [])
        new_cursor = response.get("search_after")

        if not page_events:
            demisto.debug(f"[Pagination Loop] Page {page}: Empty. Stopping.")
            break

        events.extend(page_events)
        demisto.debug(f"[Pagination Loop] Page {page}: +{len(page_events)} events. Total: {len(events)}")

        # Update cursor for next page
        if new_cursor:
            search_after = new_cursor
        else:
            # No cursor means no more pages - but also try to extract from last event
            if page_events:
                last_event = page_events[-1]
                # JumpCloud uses the last event's id and timestamp as search_after
                event_id = get_event_id(last_event)
                event_time = extract_time_from_event(last_event)
                if event_id and event_time:
                    search_after = {"id": event_id, "timestamp": event_time}
                else:
                    demisto.debug("[Pagination Loop] Cannot construct search_after cursor. Stopping.")
                    break
            else:
                break

        if len(page_events) < page_size:
            demisto.debug("[Pagination Loop] Last page (partial). Stopping.")
            break

        page += 1

        if page > Config.MAX_PAGES_PER_FETCH:
            demisto.debug(f"[Pagination Loop] Max page limit reached ({Config.MAX_PAGES_PER_FETCH}). Stopping.")
            break

        if len(events) >= max_events:
            demisto.debug(f"[Pagination Loop] Threshold reached ({len(events)} >= {max_events}). Stopping.")
            break

    # Slice to limit
    if len(events) > max_events:
        demisto.debug(f"[Pagination Result] Slicing {len(events)} events to limit {max_events}")
        events = events[:max_events]

    demisto.debug(f"[Pagination Result] Returning {len(events)} {event_type.type_string} events")
    return events, search_after


def get_events_command(client: Client, args: dict, params: dict) -> CommandResults | str:
    """Manual command to get events for debugging/development.

    Args:
        client: The JumpCloud client.
        args: Command arguments.
        params: Integration parameters.

    Returns:
        CommandResults or string message.
    """
    demisto.debug("[Command] jumpcloud-get-events triggered")

    limit = int(args.get("limit", "50"))
    start_time_input = args.get("start_time", Config.DEFAULT_FROM_TIME)
    end_time_input = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    event_type_arg = argToList(args.get("event_type"))
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", []))
    event_types = get_event_types_from_titles(event_type_arg if event_type_arg else event_types_to_fetch)

    created_after = get_formatted_utc_time(start_time_input)
    created_before = get_formatted_utc_time(end_time_input) if end_time_input else None

    demisto.debug(
        f"[Command Params] From: {created_after}, To: {created_before}, Limit: {limit}, Push: {should_push_events}"
    )

    all_events: list[dict] = []

    for event_type in event_types:
        events, _ = fetch_events_with_pagination(
            client,
            event_type=event_type,
            start_time=created_after,
            end_time=created_before,
            max_events=limit,
        )
        add_time_to_events(events, event_type)
        all_events.extend(events)

    demisto.debug(f"[Command Result] Total events retrieved: {len(all_events)}")

    if should_push_events and all_events:
        client.send_events(all_events)
        return f"Successfully retrieved and pushed {len(all_events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", all_events, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Jumpcloud.Event",
        outputs_key_field="id",
        outputs=all_events,
    )


@dataclass
class FetchResult:
    """Result of fetching events for a single event type."""

    event_type: EventType
    new_events: list[dict] = field(default_factory=list)
    last_run_updates: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _fetch_single_event_type(
    client: Client,
    event_type: EventType,
    last_run: dict[str, Any],
    max_events: int,
) -> FetchResult:
    """Fetch and process events for a single event type.

    This function is executed in a separate thread by fetch_events_command via
    ThreadPoolExecutor, enabling parallel fetching of multiple event types.
    Each thread receives an immutable copy of last_run to avoid shared mutable state.

    Thread safety:
        - Receives a dict copy of last_run (no shared mutable state).
        - Returns a FetchResult with last_run_updates (merged by the main thread after completion).
        - Uses demisto.debug() for logging (thread-safe in XSOAR runtime).

    Args:
        client: The JumpCloud client (thread-safe — ContentClient uses httpx which is thread-safe).
        event_type: The EventType to fetch.
        last_run: Immutable copy of the current last_run state dict.
        max_events: Maximum events to fetch per type.

    Returns:
        FetchResult containing new_events, last_run_updates, and any error message.
    """
    result = FetchResult(event_type=event_type)

    try:
        last_fetch_key = f"last_fetch_{event_type.type_string}"
        previous_ids_key = f"previous_ids_{event_type.type_string}"
        search_after_key = f"search_after_{event_type.type_string}"

        raw_timestamp = last_run.get(last_fetch_key)
        last_fetch_timestamp: str | None = raw_timestamp if isinstance(raw_timestamp, str) else None
        raw_ids = last_run.get(previous_ids_key)
        last_fetched_ids: list[str] = raw_ids if isinstance(raw_ids, list) else []

        if last_fetch_timestamp:
            time_input = last_fetch_timestamp
            demisto.debug(
                f"[Fetch] {event_type.type_string}: Continuing from {time_input}. "
                f"Prev ID count: {len(last_fetched_ids)}"
            )
        else:
            time_input = Config.DEFAULT_FROM_TIME
            demisto.debug(f"[Fetch] {event_type.type_string}: First run - starting from default time")

        created_after = get_formatted_utc_time(time_input)

        # Fetch events using the unified pagination function
        events, _ = fetch_events_with_pagination(
            client,
            event_type=event_type,
            start_time=created_after,
            max_events=max_events,
        )

        if not events:
            demisto.debug(f"[Fetch] {event_type.type_string}: No events found.")
            return result

        # Pre-compute time values to avoid redundant extract_time_from_event calls.
        event_times: list[str] = [extract_time_from_event(event) or "" for event in events]

        # Deduplicate
        new_events = deduplicate_events(events, last_fetched_ids)

        if new_events:
            add_time_to_events(new_events, event_type)
            result.new_events = new_events
            demisto.debug(f"[Fetch] {event_type.type_string}: {len(new_events)} new events after dedup")
        else:
            demisto.debug(f"[Fetch] {event_type.type_string}: All events were duplicates.")

        # Update Last Run - always update based on ALL fetched events (not just new_events)
        new_last_run_time = event_times[-1] if event_times else None

        if new_last_run_time:
            # Collect IDs for the new high-water mark timestamp using pre-computed times
            ids_at_last_timestamp: list[str] = [
                event_id
                for event, event_time in zip(events, event_times)
                if event_time == new_last_run_time and (event_id := get_event_id(event))
            ]

            # If the HWM timestamp hasn't changed, merge with previous IDs to prevent duplicates
            if new_last_run_time == last_fetch_timestamp:
                ids_at_last_timestamp = list(set(last_fetched_ids) | set(ids_at_last_timestamp))

            result.last_run_updates[last_fetch_key] = new_last_run_time
            result.last_run_updates[previous_ids_key] = ids_at_last_timestamp
            demisto.debug(f"[Fetch] {event_type.type_string}: State updated. New HWM: {new_last_run_time}")
        else:
            demisto.debug(f"[Fetch] {event_type.type_string}: Warning: Last event missing time. State not updated.")

    except Exception as e:
        result.error = str(e)
        demisto.debug(f"[Fetch] {event_type.type_string}: Error fetching events: {e!s}.")

    return result


def fetch_events_command(client: Client) -> None:
    """Scheduled command to fetch events using parallel threads.

    Uses ThreadPoolExecutor to fetch all configured event types simultaneously.
    This ensures that if one type takes a long time or fails,
    the other types still complete within the XSOAR execution timeout.

    Architecture:
        1. Single getLastRun() read at the start.
        2. Each event type is fetched in a separate thread via _fetch_single_event_type().
           Each thread receives an immutable copy of last_run (no shared mutable state).
        3. After all threads complete, results are merged sequentially:
           - New events from successful types are collected.
           - last_run updates from successful types are applied.
           - Failed types are skipped (their previous state is preserved).
        4. All events are sent to XSIAM in a single batch.
        5. Single setLastRun() write at the end.

    Args:
        client: The JumpCloud client.
    """
    params = demisto.params()
    max_events_to_fetch = int(params.get("max_fetch", Config.DEFAULT_MAX_FETCH))

    event_types_to_fetch = argToList(params.get("event_types_to_fetch", []))
    event_types = get_event_types_from_titles(event_types_to_fetch)

    # Single read of last_run state — no race condition
    last_run = demisto.getLastRun()
    demisto.debug(f"[Fetch] Starting with last_run: {last_run}")

    # Guard against an empty event_types selection
    if not event_types:
        demisto.debug("[Fetch] No event types selected. Nothing to fetch. Preserving last_run as-is.")
        demisto.setLastRun(last_run)
        return

    # Fetch all event types in parallel so one slow type doesn't block the others
    results: list[FetchResult] = []
    with ThreadPoolExecutor(max_workers=len(event_types)) as executor:
        futures = {
            executor.submit(
                _fetch_single_event_type,
                client=client,
                event_type=event_type,
                last_run=dict(last_run),
                max_events=max_events_to_fetch,
            ): event_type
            for event_type in event_types
        }
        for future in as_completed(futures):
            event_type = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                demisto.debug(f"[Fetch] {event_type.type_string}: Thread failed: {e!s}")

    # Merge results — collect all new events and last_run updates
    all_new_events: list[dict] = []
    updated_last_run: dict[str, Any] = dict(last_run)

    for result in results:
        if result.error:
            demisto.debug(f"[Fetch] {result.event_type.type_string}: Skipped due to error: {result.error}")
            continue
        all_new_events.extend(result.new_events)
        updated_last_run.update(result.last_run_updates)

    # Send all successfully fetched events to XSIAM
    if all_new_events:
        client.send_events(all_new_events)

    # Single write of last_run state — preserves progress from successful types
    demisto.setLastRun(updated_last_run)
    demisto.debug(f"[Fetch] Last run updated: {updated_last_run}")


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "jumpcloud-get-events": get_events_command,
    "fetch-events": fetch_events_command,
}


def main() -> None:
    """Main entry point for JumpCloud integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started")
    command = demisto.command()

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")

        params = demisto.params()
        args = demisto.args()
        config = parse_integration_params(params)

        client = Client(
            base_url=config["base_url"],
            api_key=config["api_key"],
            verify=config["verify"],
            proxy=config["proxy"],
        )

        command_func = COMMAND_MAP[command]

        if command == "test-module":
            result = command_func(client)
            return_results(result)
        elif command == "fetch-events":
            command_func(client)
        elif command == "jumpcloud-get-events":
            result = command_func(client, args, params)
            return_results(result)
        else:
            result = command_func(client, args)
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
