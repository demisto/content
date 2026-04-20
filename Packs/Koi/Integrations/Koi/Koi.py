import json
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
KOI
Integration for fetching Alerts and Audit Logs from the KOI API.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "KOI"

# ---------- API Endpoint Paths ----------
API_BASE = "/api/external/v2"
API_ALERTS = f"{API_BASE}/alerts"
API_AUDIT_LOGS = f"{API_BASE}/audit-logs"
API_POLICIES = f"{API_BASE}/policies"
API_ALLOWLIST = f"{API_BASE}/policies/allowlist"


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
    DEFAULT_PAGE = 1
    DEFAULT_LIMIT = 100
    MAX_LIMIT = 500

    # Fetch defaults
    DEFAULT_MAX_FETCH = 5000
    # Default lookback time for first fetch or get-events command
    DEFAULT_FROM_TIME = "5 minutes ago"

    # API sort direction for chronological ordering
    SORT_DIRECTION = "asc"

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 5
    TEST_MODULE_MAX_EVENTS = 1


class LogType(Enum):
    """Enum to hold all configuration for different log types."""

    ALERTS = ("alerts", "Alerts", API_ALERTS)
    AUDIT = ("audit", "Audit", API_AUDIT_LOGS)

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

# Valid marketplace values for allowlist operations
VALID_MARKETPLACES = [
    "chocolatey",
    "chrome_web_store",
    "claude_desktop_extensions",
    "cursor",
    "docker",
    "edge_add_ons",
    "firefox_add_ons",
    "github_mcp_registry",
    "homebrew",
    "hugging_face",
    "jetbrains",
    "linux",
    "mac",
    "notepad++",
    "npm",
    "office_add_ins",
    "open_vsx_registry",
    "pypi",
    "visual_studio",
    "vscode",
    "windows",
    "windsurf",
]


def get_formatted_utc_time(date_input: str | None) -> str:
    """Parse input and return the formatted UTC time string for KOI API.

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

    Uses arg_to_datetime from CommonServerPython for consistent date parsing.

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

    Uses extract_time_from_event for consistent time extraction across all code paths.

    Args:
        events: List of event dictionaries to enrich.
        log_type: The LogType Enum member representing the source.
    """
    for event in events:
        event_time = extract_time_from_event(event, log_type)
        if event_time:
            event["_time"] = event_time
        else:
            demisto.debug(f"[Event Time] WARNING: Event missing time field: {event.get('id', 'unknown')}")

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


def parse_allowlist_items_from_entry_id(entry_id: str) -> list[dict[str, Any]]:
    """Read and parse a JSON file from a War Room entry ID containing allowlist items.

    The JSON file must contain a list of item objects, each with at least 'item_id' and 'marketplace'.

    Args:
        entry_id: The War Room entry ID of the uploaded JSON file.

    Returns:
        List of item dictionaries parsed from the JSON file.

    Raises:
        DemistoException: If the file cannot be read, parsed, or has invalid structure.
    """
    try:
        filepath_result = demisto.getFilePath(entry_id)
    except Exception as e:
        raise DemistoException(f"Could not find file for entry ID '{entry_id}': {e}")

    if not filepath_result or "path" not in filepath_result:
        raise DemistoException(f"Entry ID '{entry_id}' is not a valid file entry.")

    file_path = filepath_result["path"]
    demisto.debug(f"[File Parse] Reading items from file: {file_path}")

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise DemistoException(f"Failed to parse JSON file from entry ID '{entry_id}': {e}")
    except OSError as e:
        raise DemistoException(f"Failed to read file from entry ID '{entry_id}': {e}")

    if not isinstance(data, list):
        raise DemistoException(
            f"Invalid JSON structure in entry ID '{entry_id}': expected a list of items, got {type(data).__name__}."
        )

    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise DemistoException(f"Invalid item at index {i}: expected a dictionary, got {type(item).__name__}.")
        if "item_id" not in item or "marketplace" not in item:
            raise DemistoException(f"Invalid item at index {i}: each item must contain 'item_id' and 'marketplace'.")
        if item["marketplace"] not in VALID_MARKETPLACES:
            raise DemistoException(
                f"Invalid marketplace '{item['marketplace']}' at index {i}. Valid values: {VALID_MARKETPLACES}"
            )

    demisto.debug(f"[File Parse] Parsed {len(data)} items from entry ID '{entry_id}'")
    return data


# endregion

# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """KOI API client.

    Extends ContentClient with KOI-specific functionality including
    Bearer token authentication and API methods for alerts and audit logs.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        """Initialize the KOI client.

        Args:
            base_url: KOI API server URL.
            api_key: KOI API key for Bearer token authentication.
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
            client_name="KOI",
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
        """Fetch a single page of events from the KOI API.

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
            "sort_direction": Config.SORT_DIRECTION,
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

        events = response.get("alerts") or response.get("data") or response.get("items") or response.get("results") or []
        demisto.debug(f"[API Fetch] {log_type.type_string} | Page {page}: {len(events)} events returned")

        return events

    def get_policies(
        self,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        """Fetch a single page of policies from the Koi API.

        Args:
            page: Page number for pagination (1-based).
            page_size: Number of results per page (max 500).

        Returns:
            The full API response dictionary containing 'policies' list and 'total_count'.
        """
        params: dict[str, Any] = {
            "page": page,
            "page_size": min(page_size, Config.MAX_PAGE_SIZE),
        }

        demisto.debug(f"[API] Fetching policies | Params: {params}")

        response = self._http_request(
            method="GET",
            url_suffix=API_POLICIES,
            params=params,
        )

        demisto.debug("[API] Policies response received")
        return response

    def get_allowlist(self) -> dict[str, Any]:
        """Fetch all items in the allowlist from the Koi API.

        Returns:
            The full API response dictionary containing 'items' list.
        """
        demisto.debug("[API] Fetching allowlist")

        response = self._http_request(
            method="GET",
            url_suffix=API_ALLOWLIST,
        )

        items = response.get("items", [])
        demisto.debug(f"[API] Allowlist response received: {len(items)} items")
        return response

    def remove_allowlist_item(
        self,
        item_id: str,
        marketplace: str,
        created_by: str | None = None,
        notes: str | None = None,
    ) -> None:
        """Remove an item from the global allowlist.

        Args:
            item_id: The unique identifier of the item to remove.
            marketplace: The source marketplace corresponding to the item_id.
            created_by: Optional email of the user associated with the removal.
            notes: Optional additional context or notes regarding the removal.
        """
        body: dict[str, Any] = {
            "item_id": item_id,
            "marketplace": marketplace,
        }
        if created_by:
            body["created_by"] = created_by
        if notes:
            body["notes"] = notes

        demisto.debug(
            f"[API] Removing allowlist item: {item_id} (marketplace={marketplace}, " f"created_by={created_by}, notes={notes})"
        )

        self._http_request(
            method="DELETE",
            url_suffix=API_ALLOWLIST,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

        demisto.debug(
            f"[API] Successfully removed allowlist item: {item_id} (marketplace={marketplace}, "
            f"created_by={created_by}, notes={notes})"
        )

    def add_allowlist_items(
        self,
        items: list[dict[str, Any]],
    ) -> None:
        """Add one or more items to the global allowlist.

        Args:
            items: List of item dictionaries, each containing at least 'item_id' and 'marketplace'.
        """
        body: dict[str, Any] = {"items": items}

        demisto.debug(f"[API] Adding {len(items)} allowlist item(s): {items}")

        self._http_request(
            method="POST",
            url_suffix=API_ALLOWLIST,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

        demisto.debug(f"[API] Successfully added {len(items)} allowlist item(s)")

    def send_events(self, events: list[dict]) -> None:
        """Send events to XSIAM using the ContentClient context.

        Wraps send_events_to_xsiam to keep event sending encapsulated
        within the client class for consistent logging and diagnostics.

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
        client: The KOI client.

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
        client: The KOI client.
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
        client: The KOI client.
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
            audit_types=audit_types_filter if log_type == LogType.AUDIT else None,
        )
        add_time_to_events(events, log_type)
        all_events.extend(events)

    demisto.debug(f"[Command Result] Total events retrieved: {len(all_events)}")

    if should_push_events and all_events:
        client.send_events(all_events)
        return f"Successfully retrieved and pushed {len(all_events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", all_events, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="KOI.Event",
        outputs_key_field="id",
        outputs=all_events,
    )


@dataclass
class FetchResult:
    """Result of fetching events for a single log type."""

    log_type: LogType
    new_events: list[dict] = field(default_factory=list)
    last_run_updates: dict[str, str | list[str]] = field(default_factory=dict)
    error: str | None = None


def _fetch_single_log_type(
    client: Client,
    log_type: LogType,
    last_run: dict[str, str | list[str]],
    max_events: int,
    audit_types: list[str] | None,
) -> FetchResult:
    """Fetch and process events for a single log type.

    This function is executed in a separate thread by fetch_events_command via
    ThreadPoolExecutor, enabling parallel fetching of multiple log types.
    Each thread receives an immutable copy of last_run to avoid shared mutable state.

    The function handles its own errors — if an API call fails, the error is captured
    in FetchResult.error and the thread returns gracefully without affecting other threads.

    Thread safety:
        - Receives a dict copy of last_run (no shared mutable state).
        - Returns a FetchResult with last_run_updates (merged by the main thread after completion).
        - Uses demisto.debug() for logging (thread-safe in XSOAR runtime).

    Args:
        client: The KOI client (thread-safe — ContentClient uses httpx which is thread-safe).
        log_type: The LogType to fetch (ALERTS or AUDIT).
        last_run: Immutable copy of the current last_run state dict.
        max_events: Maximum events to fetch per type.
        audit_types: Optional audit type filter (only applied for AUDIT log type).

    Returns:
        FetchResult containing new_events, last_run_updates, and any error message.
    """
    result = FetchResult(log_type=log_type)

    try:
        last_fetch_key = f"last_fetch_{log_type.type_string}"
        previous_ids_key = f"previous_ids_{log_type.type_string}"

        raw_timestamp = last_run.get(last_fetch_key)
        last_fetch_timestamp: str | None = raw_timestamp if isinstance(raw_timestamp, str) else None
        raw_ids = last_run.get(previous_ids_key)
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
            max_events=max_events,
            audit_types=audit_types if log_type == LogType.AUDIT else None,
        )

        if not events:
            demisto.debug(f"[Fetch] {log_type.type_string}: No events found.")
            return result

        # Pre-compute time values to avoid redundant extract_time_from_event calls.
        # Events are already sorted chronologically by the API (sort_direction=asc).
        event_times: list[str] = [extract_time_from_event(event, log_type) or "" for event in events]

        # Deduplicate
        new_events = deduplicate_events(events, last_fetched_ids)

        if new_events:
            add_time_to_events(new_events, log_type)
            result.new_events = new_events
            demisto.debug(f"[Fetch] {log_type.type_string}: {len(new_events)} new events after dedup")
        else:
            demisto.debug(f"[Fetch] {log_type.type_string}: All events were duplicates.")

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
            demisto.debug(f"[Fetch] {log_type.type_string}: State updated. New HWM: {new_last_run_time}")
        else:
            demisto.debug(f"[Fetch] {log_type.type_string}: Warning: Last event missing time. State not updated.")

    except Exception as e:
        result.error = str(e)
        demisto.debug(f"[Fetch] {log_type.type_string}: Error fetching events: {e!s}.")

    return result


def fetch_events_command(client: Client) -> None:
    """Scheduled command to fetch events using parallel threads.

    Uses ThreadPoolExecutor to fetch all configured log types (Alerts, Audit)
    simultaneously. This ensures that if one type takes a long time or fails,
    the other type still completes within the XSOAR execution timeout.

    Architecture:
        1. Single getLastRun() read at the start.
        2. Each log type is fetched in a separate thread via _fetch_single_log_type().
           Each thread receives an immutable copy of last_run (no shared mutable state).
        3. After all threads complete, results are merged sequentially:
           - New events from successful types are collected.
           - last_run updates from successful types are applied.
           - Failed types are skipped (their previous state is preserved).
        4. All events are sent to XSIAM in a single batch.
        5. Single setLastRun() write at the end.

    Race condition prevention:
        - One getLastRun() call, one setLastRun() call.
        - Threads don't share mutable state — each gets a dict copy.
        - Merge happens after all threads complete (no concurrent writes).

    Args:
        client: The KOI client.
    """
    params = demisto.params()
    max_events_to_fetch = int(params.get("max_fetch", Config.DEFAULT_MAX_FETCH))

    event_types_to_fetch = argToList(params.get("event_types_to_fetch", ["Alerts", "Audit"]))
    log_types = get_log_types_from_titles(event_types_to_fetch)

    audit_types_filter = argToList(params.get("audit_types_filter")) or None

    # Single read of last_run state — no race condition
    last_run = demisto.getLastRun()
    demisto.debug(f"[Fetch] Starting with last_run: {last_run}")

    # Fetch all log types in parallel so one slow type doesn't block the other
    results: list[FetchResult] = []
    with ThreadPoolExecutor(max_workers=len(log_types)) as executor:
        futures = {
            executor.submit(
                _fetch_single_log_type,
                client=client,
                log_type=log_type,
                last_run=dict(last_run),
                max_events=max_events_to_fetch,
                audit_types=audit_types_filter,
            ): log_type
            for log_type in log_types
        }
        for future in as_completed(futures):
            log_type = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                demisto.debug(f"[Fetch] {log_type.type_string}: Thread failed: {e!s}")

    # Merge results — collect all new events and last_run updates
    all_new_events: list[dict] = []
    updated_last_run: dict[str, str | list[str]] = dict(last_run)

    for result in results:
        if result.error:
            demisto.debug(f"[Fetch] {result.log_type.type_string}: Skipped due to error: {result.error}")
            continue
        all_new_events.extend(result.new_events)
        updated_last_run.update(result.last_run_updates)

    # Send all successfully fetched events to XSIAM
    if all_new_events:
        client.send_events(all_new_events)

    # Single write of last_run state — preserves progress from successful types
    demisto.setLastRun(updated_last_run)
    demisto.debug(f"[Fetch] Last run updated: {updated_last_run}")


def koi_policy_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List policies with pagination support.

    Supports two modes:
    - Single page: provide 'page' and/or 'page_size' to fetch a specific page.
    - Auto-paginate: provide 'limit' to automatically paginate and collect up to 'limit' policies.

    If 'page' is provided, single-page mode is used (limit is ignored).
    If only 'limit' is provided, auto-pagination mode is used.

    Args:
        client: The KOI client.
        args: Command arguments (page, page_size, limit).

    Returns:
        CommandResults with the policy list.
    """
    demisto.debug("[Command] koi-policy-list triggered")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))

    if page_arg:
        # Single-page mode: fetch the requested page
        demisto.debug(f"[Command] Single-page mode: page={page_arg}, page_size={page_size}")
        response = client.get_policies(page=page_arg, page_size=page_size)
        policies = response.get("policies", [])
        total_count = response.get("total_count")
        demisto.debug(f"[Command Result] Retrieved {len(policies)} policies (total_count={total_count})")
    else:
        # Auto-paginate mode: fetch pages until limit is reached
        limit = limit_arg or Config.DEFAULT_LIMIT
        demisto.debug(f"[Command] Auto-paginate mode: limit={limit}")
        policies = _fetch_policies_with_pagination(client, limit=limit)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Policies",
        policies,
        headers=["id", "name", "description", "action", "enabled", "group_ids", "creator_fullname", "created_at", "updated_at"],
        removeNull=True,
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Policy",
        outputs_key_field="id",
        outputs=policies,
    )


def _fetch_policies_with_pagination(
    client: Client,
    limit: int,
    page_size: int = Config.MAX_PAGE_SIZE,
) -> list[dict]:
    """Auto-paginate through policies until limit is reached.

    Args:
        client: The Koi client.
        limit: Maximum total number of policies to collect.
        page_size: Number of results per API page.

    Returns:
        List of policy dictionaries.
    """
    policies: list[dict] = []
    page = Config.DEFAULT_PAGE

    while len(policies) < limit:
        response = client.get_policies(page=page, page_size=page_size)
        page_policies = response.get("policies", [])

        if not page_policies:
            demisto.debug(f"[Pagination] Page {page}: Empty. Stopping.")
            break

        policies.extend(page_policies)
        demisto.debug(f"[Pagination] Page {page}: +{len(page_policies)} policies. Total: {len(policies)}")

        if len(page_policies) < page_size:
            demisto.debug("[Pagination] Last page (partial). Stopping.")
            break

        page += 1

    # Trim to limit
    if len(policies) > limit:
        demisto.debug(f"[Pagination] Trimming {len(policies)} policies to limit {limit}")
        policies = policies[:limit]

    demisto.debug(f"[Pagination] Returning {len(policies)} policies")
    return policies


def koi_allowlist_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve all items in the allowlist.

    Args:
        client: The KOI client.
        args: Command arguments (unused, no inputs for this command).

    Returns:
        CommandResults with the allowlist items.
    """
    demisto.debug("[Command] koi-allowlist-get triggered")

    response = client.get_allowlist()
    items = response.get("items", [])

    demisto.debug(f"[Command Result] Retrieved {len(items)} allowlist items")

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Allowlist",
        items,
        headers=[
            "item_id",
            "item_name",
            "item_display_name",
            "marketplace",
            "publisher_name",
            "package_name",
            "notes",
            "created_by",
            "created_at",
        ],
        removeNull=True,
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Allowlist",
        outputs_key_field="item_id",
        outputs=items,
    )


def koi_allowlist_item_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove an item from the global allowlist.

    Args:
        client: The KOI client.
        args: Command arguments (item_id, marketplace, created_by, notes).

    Returns:
        CommandResults with a success message.
    """
    demisto.debug("[Command] koi-allowlist-item-remove triggered")

    item_id: str = args["item_id"]
    marketplace: str = args["marketplace"]
    created_by: str | None = args.get("created_by")
    notes: str | None = args.get("notes")

    if marketplace not in VALID_MARKETPLACES:
        raise DemistoException(f"Invalid marketplace '{marketplace}'. Valid values: {VALID_MARKETPLACES}")

    client.remove_allowlist_item(
        item_id=item_id,
        marketplace=marketplace,
        created_by=created_by,
        notes=notes,
    )

    demisto.debug(f"[Command Result] Allowlist item '{item_id}' removed successfully")

    return CommandResults(
        readable_output=f"Allowlist item '{item_id}' (marketplace: {marketplace}) was removed successfully.",
    )


def koi_allowlist_item_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add one or more items to the global allowlist.

    Supports two input modes:
    - Single item: provide 'item_id' and 'marketplace' (with optional 'created_by' and 'notes').
    - Bulk from file: provide 'items_list_raw_json_entry_id' with a War Room entry ID of a JSON file
      containing a list of item objects.

    Args:
        client: The KOI client.
        args: Command arguments.

    Returns:
        CommandResults with a success message.
    """
    demisto.debug("[Command] koi-allowlist-item-add triggered")

    entry_id: str | None = args.get("items_list_raw_json_entry_id")
    item_id: str | None = args.get("item_id")
    marketplace: str | None = args.get("marketplace")

    if entry_id:
        # Bulk mode: read items from uploaded JSON file
        items = parse_allowlist_items_from_entry_id(entry_id)
    elif item_id and marketplace:
        # Single item mode
        if marketplace not in VALID_MARKETPLACES:
            raise DemistoException(f"Invalid marketplace '{marketplace}'. Valid values: {VALID_MARKETPLACES}")

        item: dict[str, Any] = {
            "item_id": item_id,
            "marketplace": marketplace,
        }
        created_by: str | None = args.get("created_by")
        notes: str | None = args.get("notes")
        if created_by:
            item["created_by"] = created_by
        if notes:
            item["notes"] = notes

        items = [item]
    else:
        raise DemistoException(
            "Either 'item_id' and 'marketplace' must be provided, or 'items_list_raw_json_entry_id' must be provided."
        )

    client.add_allowlist_items(items)

    item_count = len(items)
    demisto.debug(f"[Command Result] {item_count} allowlist item(s) added successfully")

    if item_count == 1:
        readable = f"Allowlist item '{items[0]['item_id']}' (marketplace: {items[0]['marketplace']}) was added successfully."
    else:
        readable = f"{item_count} allowlist items were added successfully."

    return CommandResults(readable_output=readable)


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "koi-get-events": get_events_command,
    "fetch-events": fetch_events_command,
    "koi-policy-list": koi_policy_list_command,
    "koi-allowlist-get": koi_allowlist_get_command,
    "koi-allowlist-item-remove": koi_allowlist_item_remove_command,
    "koi-allowlist-item-add": koi_allowlist_item_add_command,
}


def main() -> None:
    """Main entry point for KOI integration."""
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
        elif command == "koi-get-events":
            result = command_func(client, demisto.args(), params)
            return_results(result)
        else:
            result = command_func(client, demisto.args())
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
