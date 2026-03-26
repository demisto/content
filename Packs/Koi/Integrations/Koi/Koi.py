import traceback
from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any

import dateparser
import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

"""
Koi Event Collector
Integration for fetching Alerts and Audit Logs from the Koi API.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "Koi Event Collector"


class Config:
    """Global static configuration."""

    VENDOR = "koi"
    PRODUCT = "koi"

    # Date format for API requests (ISO 8601)
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # Pagination
    DEFAULT_PAGE_SIZE = 100
    MAX_PAGE_SIZE = 500
    MAX_PAGES_PER_FETCH = 10

    # Fetch defaults
    DEFAULT_MAX_FETCH = 5000
    # Default lookback time for first fetch or get-events command
    DEFAULT_FROM_TIME = "5 minutes ago"

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 5
    TEST_MODULE_MAX_EVENTS = 1


class LogType(Enum):
    """Enum to hold all configuration for different log types."""

    ALERTS = ("alerts", "Alerts", "/api/external/v2/alerts")
    AUDIT = ("audit", "Audit", "/api/external/v2/audit-logs")

    def __init__(self, type_string: str, title: str, api_endpoint: str):
        self.type_string = type_string
        self.title = title
        self.api_endpoint = api_endpoint


# Valid audit log type filters
VALID_AUDIT_TYPES = [
    "approval_requests",
    "devices",
    "endpoints",
    "extensions",
    "firewall",
    "guardrails",
    "notifications",
    "policies",
    "remediation",
    "requests",
    "settings",
    "vetting",
]


def get_formatted_utc_time(date_input: str | None) -> str:
    """Parse input and return the formatted UTC time string for Koi API.

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
    """Parse a date string or return current UTC datetime if parsing fails."""
    if not date_string:
        current_time = datetime.now(UTC)
        demisto.debug(f"[Date Helper] No input provided. Using current UTC: {current_time}")
        return current_time

    demisto.debug(f"[Date Helper] Attempting to parse date string: '{date_string}'")
    parsed_datetime = dateparser.parse(
        date_string, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"}
    )

    if not parsed_datetime:
        demisto.debug(f"[Date Helper] Failed to parse '{date_string}'. Fallback to current UTC.")
        return datetime.now(UTC)

    if parsed_datetime.tzinfo != UTC:
        parsed_datetime = parsed_datetime.astimezone(UTC)

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


def get_log_types_from_titles(event_types_to_fetch: list[str]) -> list[LogType]:
    """Convert user-facing event type titles into LogType Enum members.

    Args:
        event_types_to_fetch: List of event type titles (e.g., ["Alerts", "Audit"]).

    Raises:
        DemistoException: If any of the provided event type titles are invalid.

    Returns:
        List of LogType Enum members.
    """
    valid_titles = {lt.title for lt in LogType}
    invalid_types = [title for title in event_types_to_fetch if title not in valid_titles]

    if invalid_types:
        valid_options = ", ".join(sorted(valid_titles))
        raise DemistoException(
            f"Invalid event type(s) provided: {invalid_types}. " f"Please select from the following list: {valid_options}"
        )

    return [lt for lt in LogType if lt.title in event_types_to_fetch]


def extract_time_from_event(event: dict, log_type: LogType) -> str | None:
    """Extract the time field value from an event based on log type.

    For alerts: finding_info.created_time (epoch ms) -> converted to ISO 8601.
    For audit logs: created_at (ISO 8601 string).

    Args:
        event: The event dictionary.
        log_type: The LogType Enum member.

    Returns:
        ISO 8601 formatted time string, or None if not found.
    """
    if log_type == LogType.ALERTS:
        finding_info = event.get("finding_info", {})
        created_time_ms = finding_info.get("created_time")
        if created_time_ms:
            try:
                dt = datetime.fromtimestamp(created_time_ms / 1000, tz=UTC)
                return dt.strftime(Config.DATE_FORMAT)
            except (ValueError, TypeError, OSError):
                demisto.debug(f"[Time Extract] Failed to parse alert created_time: {created_time_ms}")
                return None
    else:
        return event.get("created_at")

    return None


def add_time_to_events(events: list[dict], log_type: LogType) -> None:
    """Add _time and source_log_type fields to events for XSIAM ingestion.

    Args:
        events: List of event dictionaries to enrich.
        log_type: The LogType Enum member representing the source.
    """
    for event in events:
        if log_type == LogType.ALERTS:
            finding_info = event.get("finding_info", {})
            created_time_ms = finding_info.get("created_time")
            if created_time_ms:
                event["_time"] = str(created_time_ms)
            else:
                demisto.debug(f"[Event Time] WARNING: Alert missing 'finding_info.created_time': {event.get('id', 'unknown')}")
        else:
            created_at = event.get("created_at")
            if created_at:
                event["_time"] = created_at
            else:
                demisto.debug(f"[Event Time] WARNING: Audit log missing 'created_at': {event.get('id', 'unknown')}")

        event["source_log_type"] = log_type.title


def get_event_id(event: dict) -> str | None:
    """Extract the event ID from an event dictionary.

    Args:
        event: The event dictionary.

    Returns:
        The event ID string, or None if not found.
    """
    for id_field in ("id", "alert_id", "log_id", "uuid"):
        event_id = event.get(id_field)
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


# endregion

# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """Koi API client.

    Extends ContentClient with Koi-specific functionality including
    Bearer token authentication and API methods for alerts and audit logs.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        """Initialize the Koi client.

        Args:
            base_url: Koi API server URL.
            api_key: Koi API key for Bearer token authentication.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use proxy settings.
        """
        auth_handler = BearerTokenAuthHandler(token=api_key)

        retry_policy = RetryPolicy(  # type: ignore[call-arg]
            max_attempts=4,
            retryable_status_codes=(429, 500, 502, 503, 504),
        )

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name="Koi",
            timeout=60,
            retry_policy=retry_policy,
        )

    def get_events_page(
        self,
        log_type: LogType,
        created_at_gte: str | None = None,
        created_at_lte: str | None = None,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        audit_types: list[str] | None = None,
    ) -> list[dict]:
        """Fetch a single page of events from the Koi API.

        This is the single unified method used by all commands (test-module,
        fetch-events, get-events) to retrieve events from the API.

        Args:
            log_type: The LogType to fetch (ALERTS or AUDIT).
            created_at_gte: Filter events created at or after this datetime (ISO 8601).
            created_at_lte: Filter events created at or before this datetime (ISO 8601).
            page: Page number (1-based).
            page_size: Number of results per page (max 500).
            audit_types: Optional list of audit log types to filter by (only for AUDIT).

        Returns:
            List of event dictionaries from the API response.
        """
        params: dict[str, Any] = {
            "page": page,
            "page_size": min(page_size, Config.MAX_PAGE_SIZE),
        }

        if created_at_gte:
            params["created_at_gte"] = created_at_gte
        if created_at_lte:
            params["created_at_lte"] = created_at_lte
        if log_type == LogType.AUDIT and audit_types:
            params["types"] = ",".join(audit_types)

        demisto.debug(f"[API Fetch] {log_type.type_string} | Page: {page} | Params: {params}")

        response = self._http_request(
            method="GET",
            url_suffix=log_type.api_endpoint,
            params=params,
        )

        events = response.get("data", response.get("items", response.get("results", [])))
        demisto.debug(f"[API Fetch] {log_type.type_string} | Page {page}: {len(events)} events returned")

        return events


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by fetching a small number of events.

    Args:
        client: The Koi client.

    Returns:
        'ok' if test passed, otherwise raises an exception.
    """
    demisto.debug("[Test Module] Starting...")
    try:
        utc_now = datetime.now(UTC)
        test_time = (utc_now - timedelta(minutes=Config.TEST_MODULE_LOOKBACK_MINUTES)).strftime(Config.DATE_FORMAT)

        demisto.debug(f"[Test Module] Fetching alerts from: {test_time}")
        fetch_events_with_pagination(
            client,
            log_type=LogType.ALERTS,
            created_after=test_time,
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
    log_type: LogType,
    created_after: str,
    created_before: str | None = None,
    max_events: int = Config.DEFAULT_MAX_FETCH,
    audit_types: list[str] | None = None,
) -> list[dict]:
    """Fetch events with pagination support.

    This is the single unified pagination function used by all commands
    (test-module, fetch-events, get-events).

    Args:
        client: The Koi client.
        log_type: The LogType to fetch.
        created_after: Start time (ISO 8601).
        created_before: End time (ISO 8601) or None.
        max_events: Maximum number of events to fetch.
        audit_types: Optional list of audit log types to filter by.

    Returns:
        List of event dictionaries.
    """
    events: list[dict] = []
    page = 1
    page_size = min(Config.MAX_PAGE_SIZE, max_events)

    demisto.debug(
        f"[Pagination Loop] Start | Type: {log_type.type_string} | Goal: {max_events} | "
        f"Time: {created_after} -> {created_before or 'Now'}"
    )

    while len(events) < max_events:
        page_events = client.get_events_page(
            log_type=log_type,
            created_at_gte=created_after,
            created_at_lte=created_before,
            page=page,
            page_size=page_size,
            audit_types=audit_types if log_type == LogType.AUDIT else None,
        )

        if not page_events:
            demisto.debug(f"[Pagination Loop] Page {page}: Empty. Stopping.")
            break

        events.extend(page_events)
        demisto.debug(f"[Pagination Loop] Page {page}: +{len(page_events)} events. Total: {len(events)}")

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

    demisto.debug(f"[Pagination Result] Returning {len(events)} {log_type.type_string} events")
    return events


def get_events_command(client: Client, args: dict, params: dict) -> CommandResults | str:
    """Manual command to get events for debugging/development.

    Args:
        client: The Koi client.
        args: Command arguments.
        params: Integration parameters.

    Returns:
        CommandResults or string message.
    """
    demisto.debug("[Command] koi-get-events triggered")

    limit = int(args.get("limit", "50"))
    start_time_input = args.get("start_time", Config.DEFAULT_FROM_TIME)
    end_time_input = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    event_type_arg = argToList(args.get("event_type"))
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", ["Alerts", "Audit"]))
    log_types = get_log_types_from_titles(event_type_arg if event_type_arg else event_types_to_fetch)

    created_after = get_formatted_utc_time(start_time_input)
    created_before = get_formatted_utc_time(end_time_input) if end_time_input else None

    audit_types_filter = argToList(params.get("audit_types_filter")) or None

    demisto.debug(f"[Command Params] From: {created_after}, To: {created_before}, Limit: {limit}, Push: {should_push_events}")

    all_events: list[dict] = []

    for log_type in log_types:
        events = fetch_events_with_pagination(
            client,
            log_type=log_type,
            created_after=created_after,
            created_before=created_before,
            max_events=limit,
            audit_types=audit_types_filter,
        )
        add_time_to_events(events, log_type)
        all_events.extend(events)

    if should_push_events and all_events:
        send_events_to_xsiam(events=all_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Command] Pushed {len(all_events)} events to XSIAM")
        return f"Successfully retrieved and pushed {len(all_events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", all_events, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Event",
        outputs_key_field="id",
        outputs=all_events,
    )


def fetch_events_command(client: Client) -> None:
    """Scheduled command to fetch events.

    Args:
        client: The Koi client.
    """
    params = demisto.params()
    max_events_to_fetch = int(params.get("max_fetch", Config.DEFAULT_MAX_FETCH))

    event_types_to_fetch = argToList(params.get("event_types_to_fetch", ["Alerts", "Audit"]))
    log_types = get_log_types_from_titles(event_types_to_fetch)

    audit_types_filter = argToList(params.get("audit_types_filter")) or None

    last_run = demisto.getLastRun()
    demisto.debug(f"[Fetch] Starting with last_run: {last_run}")

    all_new_events: list[dict] = []
    updated_last_run = dict(last_run)

    for log_type in log_types:
        last_fetch_key = f"last_fetch_{log_type.type_string}"
        previous_ids_key = f"previous_ids_{log_type.type_string}"

        last_fetch_timestamp = updated_last_run.get(last_fetch_key)
        raw_ids = updated_last_run.get(previous_ids_key)
        last_fetched_ids: list[str] = raw_ids if isinstance(raw_ids, list) else []

        if last_fetch_timestamp:
            time_input = last_fetch_timestamp
            demisto.debug(
                f"[Fetch] {log_type.type_string}: Continuing from {time_input}. " f"Prev ID count: {len(last_fetched_ids)}"
            )
        else:
            time_input = Config.DEFAULT_FROM_TIME
            demisto.debug(f"[Fetch] {log_type.type_string}: First run - starting from default time")

        created_after = get_formatted_utc_time(time_input)

        # Fetch events using the unified pagination function
        events = fetch_events_with_pagination(
            client,
            log_type=log_type,
            created_after=created_after,
            max_events=max_events_to_fetch,
            audit_types=audit_types_filter if log_type == LogType.AUDIT else None,
        )

        if not events:
            demisto.debug(f"[Fetch] {log_type.type_string}: No events found.")
            continue

        # Deduplicate
        new_events = deduplicate_events(events, last_fetched_ids)

        if new_events:
            add_time_to_events(new_events, log_type)
            all_new_events.extend(new_events)
            demisto.debug(f"[Fetch] {log_type.type_string}: {len(new_events)} new events after dedup")
        else:
            demisto.debug(f"[Fetch] {log_type.type_string}: All events were duplicates.")

        # Update Last Run - always update based on ALL fetched events (not just new_events)
        last_event = events[-1]
        new_last_run_time = extract_time_from_event(last_event, log_type)

        if new_last_run_time:
            # Collect IDs for the new high-water mark timestamp
            ids_at_last_timestamp = [
                get_event_id(event)
                for event in events
                if extract_time_from_event(event, log_type) == new_last_run_time and get_event_id(event)
            ]

            updated_last_run[last_fetch_key] = new_last_run_time
            updated_last_run[previous_ids_key] = ids_at_last_timestamp
            demisto.debug(f"[Fetch] {log_type.type_string}: State updated. New HWM: {new_last_run_time}")
        else:
            demisto.debug(f"[Fetch] {log_type.type_string}: Warning: Last event missing time. State not updated.")

    # Send all events to XSIAM
    if all_new_events:
        send_events_to_xsiam(events=all_new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Pushed {len(all_new_events)} total events to XSIAM")

    # Update last run state
    demisto.setLastRun(updated_last_run)
    demisto.debug(f"[Fetch] Last run updated: {updated_last_run}")


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "koi-get-events": get_events_command,
    "fetch-events": fetch_events_command,
}


def main() -> None:
    """Main entry point for Koi integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started")
    command = demisto.command()

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")

        # Parse parameters
        params = demisto.params()
        base_url = params.get("url", "https://api.prod.koi.security/").rstrip("/")
        api_key = params.get("api_key", {})
        if isinstance(api_key, dict):
            api_key = api_key.get("password", "")

        verify_certificate = not argToBoolean(params.get("insecure", False))
        proxy = argToBoolean(params.get("proxy", False))

        # Validate audit types filter if provided
        audit_types_filter = argToList(params.get("audit_types_filter"))
        if audit_types_filter:
            invalid = [t for t in audit_types_filter if t not in VALID_AUDIT_TYPES]
            if invalid:
                raise DemistoException(f"Invalid audit log type(s): {invalid}. Valid types: {VALID_AUDIT_TYPES}")

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        command_func = COMMAND_MAP[command]

        if command == "test-module":
            result = command_func(client)
            return_results(result)
        elif command == "fetch-events":
            command_func(client)
        else:
            result = command_func(client, demisto.args(), params)
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
