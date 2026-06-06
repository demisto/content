import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any


import urllib3


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


class ApiPaths:
    """Centralized KOI API endpoint paths.

    All paths are relative to the KOI base URL configured in integration parameters.
    Use the classmethods for parameterized routes (e.g., a specific policy or item)
    so URL construction lives in exactly one place.
    """

    BASE = "/api/external/v2"
    ALERTS = f"{BASE}/alerts"
    AUDIT_LOGS = f"{BASE}/audit-logs"
    POLICIES = f"{BASE}/policies"
    ALLOWLIST = f"{BASE}/policies/allowlist"
    BLOCKLIST = f"{BASE}/policies/blocklist"
    INVENTORY = f"{BASE}/inventory"
    INVENTORY_SEARCH = f"{BASE}/inventory/search"
    # Tier-1 expansion (v1.2.0) — read-only surface across sections 2,4,5,6,7,9,11,13.
    APPROVAL_REQUESTS = f"{BASE}/approval-requests"
    DEVICES = f"{BASE}/devices"
    FINDINGS = f"{BASE}/findings"
    GROUPS = f"{BASE}/groups"
    RUNTIME_POLICIES = f"{BASE}/hardening/runtime-policies"
    KOIDEX_SEARCH = f"{BASE}/koidex/search"
    KOIDEX_RISK_REPORT = f"{BASE}/koidex/risk-report"
    REMEDIATIONS = f"{BASE}/remediations"
    USERS = f"{BASE}/users"

    @classmethod
    def policy(cls, policy_id: int) -> str:
        """Return the path for a specific policy by ID."""
        return f"{cls.POLICIES}/{policy_id}"

    @classmethod
    def inventory_item(cls, item_id: str) -> str:
        """Return the path for a specific inventory item by ID.

        item_id is URL-encoded because Koi accepts identifiers that
        contain `/` (npm scoped packages: `@scope/name`) and full URLs
        (remote MCP servers: `https://...`). Without encoding, Koi's
        router treats the slashes as path separators and returns 404.
        """
        from urllib.parse import quote

        return f"{cls.INVENTORY}/{quote(item_id, safe='')}"

    @classmethod
    def inventory_item_endpoints(cls, item_id: str) -> str:
        """Return the path for the endpoints of a specific inventory item.
        Same URL-encoding rationale as `inventory_item`."""
        from urllib.parse import quote

        return f"{cls.INVENTORY}/{quote(item_id, safe='')}/endpoints"

    @classmethod
    def device_inventory(cls, device_id: str) -> str:
        """Items installed on a specific device. URL-encoding the id
        guards against future device-id schemes that include reserved
        characters."""
        from urllib.parse import quote

        return f"{cls.DEVICES}/{quote(device_id, safe='')}/inventory"

    @classmethod
    def runtime_policy(cls, policy_id: str) -> str:
        """A single runtime (hardening) policy by ID."""
        from urllib.parse import quote

        return f"{cls.RUNTIME_POLICIES}/{quote(policy_id, safe='')}"


class Config:
    """Global static configuration."""

    VENDOR = "koi"
    PRODUCT = "koi"

    # Date format for API requests (ISO 8601)
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # Pagination
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 500
    MAX_PAGES_PER_FETCH = 10
    DEFAULT_PAGE = 1
    DEFAULT_LIMIT = 50
    MAX_LIMIT = 1000

    # Fetch defaults
    DEFAULT_MAX_FETCH = 5000
    # Default lookback time for first fetch or get-events command
    DEFAULT_FROM_TIME = "3 days ago"

    # API sort direction for chronological ordering
    SORT_DIRECTION = "asc"

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 5
    TEST_MODULE_MAX_EVENTS = 1


class LogType(Enum):
    """Enum to hold all configuration for different log types."""

    ALERTS = ("alerts", "Alerts", ApiPaths.ALERTS)
    AUDIT = ("audit", "Audit", ApiPaths.AUDIT_LOGS)

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


def _extract_observable_value(event: dict, name: str) -> str:
    """Return the .value for a named observable, or empty string."""
    obs = event.get("observables")
    if isinstance(obs, list):
        for o in obs:
            if isinstance(o, dict) and o.get("name") == name:
                return str(o.get("value") or "")
    return ""


def _extract_resource_data_id(event: dict, resource_type: str) -> str:
    """Return the .data.id for the first resource of the given type, or empty."""
    resources = event.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if isinstance(r, dict) and r.get("type") == resource_type:
                data = r.get("data") or {}
                if isinstance(data, dict) and data.get("id"):
                    return str(data["id"])
    return ""


def get_event_id(event: dict, log_type: LogType | None = None) -> str | None:
    """Extract a stable per-occurrence event identifier for dedup across
    fetch cycles.

    History (bug #001 / #004 from the bug tracker):
      * v1.1.0 (Cortex original): only looked at top-level id/uuid/alert_id —
        returned None for every Koi event, disabled dedup entirely → 21×
        duplication at HWM boundary.
      * v1.1.1: added nested finding_info.uid path → dedup re-enabled but
        keyed only by FINDING identity, not per-occurrence.
      * v1.3.11 (this): one finding can fire on many (device, item) tuples
        and Koi emits each as a separate event with identical
        finding_info.uid + observables.event.id. Collapsing them all to
        `alert:<finding_uid>` was over-aggressive: we kept the first 99
        on first run but then dedup-dropped 0 vs. the expected 99 on
        subsequent runs (silently lost per-item granularity). New key
        adds device + item + time to make each occurrence distinct.

    Strategy:
      * Alerts (OCSF): composite key
            alert:<finding_uid>|<device_id>|<item_id>|<time>
        where:
          - finding_uid = finding_info.uid
          - device_id   = first resources[type=device].data.id
          - item_id     = first observables[name=item.id].value
          - time        = top-level `time` (epoch ms)
        Missing components are replaced with empty string. As long as
        finding_uid is present, an id is returned.
      * Audit: deterministic SHA-1 of
        (created_at, type, action, object_id, triggered_by, message).
        Already per-occurrence-stable; no change in this version.

    Args:
        event: The event dictionary.
        log_type: Optional LogType to select the strategy.

    Returns:
        The event ID string, or None if no identifying signal is present.
    """
    # Top-level fields — kept for forward compat in case Koi adds them.
    for id_field in ("id", "alert_id", "log_id", "uuid", "event_id"):
        eid = event.get(id_field)
        if eid:
            return str(eid)

    if log_type == LogType.ALERTS or "finding_info" in event:
        # OCSF alerts: composite key (finding_uid, device_id, item_id, time)
        # so 99 distinct per-item occurrences of one finding stay distinct.
        finding_info = event.get("finding_info")
        finding_uid = ""
        if isinstance(finding_info, dict):
            for key in ("uid", "id", "alert_id"):
                v = finding_info.get(key)
                if v:
                    finding_uid = str(v)
                    break
        if finding_uid:
            device_id = _extract_resource_data_id(event, "device")
            item_id = _extract_observable_value(event, "item.id")
            time_val = str(event.get("time") or "")
            return f"alert:{finding_uid}|{device_id}|{item_id}|{time_val}"

    if log_type == LogType.AUDIT or "created_at" in event:
        # Audit: stable composite. Include `message` because a few audit
        # event types fire multiple distinct actions at the same
        # (created_at, type, action, object_id, triggered_by) tuple
        # (e.g., extension policy bulk-apply events).
        parts = (
            str(event.get("created_at") or ""),
            str(event.get("type") or ""),
            str(event.get("action") or ""),
            str(event.get("object_id") or ""),
            str(event.get("triggered_by") or ""),
            str(event.get("message") or ""),
        )
        if any(parts):
            import hashlib

            digest = hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]
            return f"audit:{digest}"
    return None


def deduplicate_events(
    events: list[dict],
    last_fetched_ids: list[str],
    log_type: LogType | None = None,
) -> list[dict]:
    """Two-stage dedup for one fetch cycle's results.

    Stage 1 (within-batch): the same API response can carry the same
    logical event more than once. We observed this on Koi alert clusters
    where multi-page or duplicate-payload responses delivered the same
    (finding_uid, device_id, item_id, time) tuple twice in one batch.
    Cross-cycle dedup alone would let both copies through on the
    first encounter because neither matches `last_fetched_ids` yet.

    Stage 2 (cross-cycle): drop events whose id is already in
    `last_fetched_ids` (the at-HWM IDs from prior fetches), the
    classic HWM-boundary-overlap defense.

    Both stages key off `get_event_id(event, log_type)` so adding a new
    discriminator field (composite key change) automatically tightens
    both within-batch and cross-cycle dedup.

    Args:
        events: List of events to deduplicate.
        last_fetched_ids: List of event IDs from the previous run.
        log_type: Source log type; forwarded to get_event_id so the
            type-specific identifier strategy is applied (alerts use
            composite key, audit uses a composite hash).

    Returns:
        List of new (non-duplicate) events. Order preserved per first-
        occurrence within the input batch.
    """
    if not events:
        demisto.debug("[Dedup] No events to process")
        return events

    fetched_ids_set = set(last_fetched_ids or [])

    # Stage 1: within-batch dedup. Track ids we've seen in THIS batch.
    seen_in_batch: set[str] = set()
    after_batch_dedup: list[dict] = []
    within_batch_skipped = 0
    no_id_kept = 0
    for event in events:
        eid = get_event_id(event, log_type)
        if eid is None:
            # No identifier — can't dedup; keep the event so we don't
            # accidentally drop legitimate data when the dedup key is
            # missing (defensive: drop later only when we KNOW it's
            # a dup).
            after_batch_dedup.append(event)
            no_id_kept += 1
            continue
        if eid in seen_in_batch:
            within_batch_skipped += 1
            continue
        seen_in_batch.add(eid)
        after_batch_dedup.append(event)

    if within_batch_skipped:
        demisto.debug(f"[Dedup] Within-batch: removed {within_batch_skipped} duplicate events from {len(events)} total")
    if no_id_kept:
        demisto.debug(f"[Dedup] Within-batch: kept {no_id_kept} events with no dedup key (cannot safely drop)")

    # Stage 2: cross-cycle dedup against last_fetched_ids.
    if not fetched_ids_set:
        demisto.debug(f"[Dedup] No prior IDs — within-batch dedup only. {len(after_batch_dedup)} events remain.")
        return after_batch_dedup

    demisto.debug(f"[Dedup] Cross-cycle: checking {len(after_batch_dedup)} against {len(fetched_ids_set)} prior IDs")
    new_events = [e for e in after_batch_dedup if get_event_id(e, log_type) not in fetched_ids_set]
    cross_cycle_skipped = len(after_batch_dedup) - len(new_events)
    if cross_cycle_skipped:
        demisto.debug(f"[Dedup] Cross-cycle: removed {cross_cycle_skipped} duplicates. {len(new_events)} new events remain.")
    else:
        demisto.debug("[Dedup] Cross-cycle: no duplicates found.")
    return new_events


def parse_list_items_from_entry_id(entry_id: str) -> list[dict[str, Any]]:
    """Read and parse a JSON file from a War Room entry ID containing list items.

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

    if not filepath_result or not (file_path := filepath_result.get("path")):
        raise DemistoException(f"Entry ID '{entry_id}' is not a valid file entry.")
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


def resolve_items_from_args(args: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve list items from command arguments.

    Supports two input modes:
    - Bulk from file: 'items_list_raw_json_entry_id' with a War Room entry ID.
    - Single item: 'item_id' and 'marketplace' (with optional 'created_by' and 'notes').

    File entry ID takes priority when both modes are provided.

    Args:
        args: Command arguments dictionary.

    Returns:
        List of item dictionaries.

    Raises:
        DemistoException: If neither mode provides valid input, or marketplace is invalid.
    """
    entry_id: str | None = args.get("items_list_raw_json_entry_id")
    item_id: str | None = args.get("item_id")
    marketplace: str | None = args.get("marketplace")

    if entry_id:
        return parse_list_items_from_entry_id(entry_id)

    if item_id and marketplace:
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

        return [item]

    raise DemistoException(
        "Either 'item_id' and 'marketplace' must be provided, or 'items_list_raw_json_entry_id' must be provided."
    )


def parse_filter_from_args(args: dict[str, Any]) -> dict[str, Any]:
    """Resolve a filter object from command arguments.

    Supports two input modes:
    - Inline JSON: 'filter_json' with a JSON string.
    - File upload: 'filter_raw_json_entry_id' with a War Room entry ID of a JSON file.

    File entry ID takes priority when both are provided.

    Args:
        args: Command arguments dictionary.

    Returns:
        Parsed filter dictionary.

    Raises:
        DemistoException: If no filter is provided, the JSON cannot be parsed, or the file cannot be read.
    """
    entry_id: str | None = args.get("filter_raw_json_entry_id")
    filter_json: str | None = args.get("filter_json")

    if entry_id:
        try:
            filepath_result = demisto.getFilePath(entry_id)
        except Exception as e:
            raise DemistoException(f"Could not find file for entry ID '{entry_id}': {e}")

        if not filepath_result or "path" not in filepath_result:
            raise DemistoException(f"Entry ID '{entry_id}' is not a valid file entry.")

        file_path = filepath_result["path"]
        demisto.debug(f"[Filter Parse] Reading filter from file: {file_path}")

        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise DemistoException(f"Failed to parse JSON filter file from entry ID '{entry_id}': {e}")
        except OSError as e:
            raise DemistoException(f"Failed to read filter file from entry ID '{entry_id}': {e}")

        if not isinstance(data, dict):
            raise DemistoException(
                f"Invalid filter JSON structure in entry ID '{entry_id}': " f"expected a dictionary, got {type(data).__name__}."
            )

        demisto.debug(f"[Filter Parse] Parsed filter from file: {data}")
        return data

    if filter_json:
        try:
            data = json.loads(filter_json)
        except json.JSONDecodeError as e:
            raise DemistoException(f"Failed to parse filter_json: {e}")

        if not isinstance(data, dict):
            raise DemistoException(f"Invalid filter_json structure: expected a dictionary, got {type(data).__name__}.")

        demisto.debug(f"[Filter Parse] Parsed inline filter: {data}")
        return data

    raise DemistoException("Either 'filter_json' or 'filter_raw_json_entry_id' must be provided.")


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Extracts connection settings from the raw demisto.params() dictionary
    and validates audit type filters if provided.

    Args:
        params: Raw parameters from demisto.params().

    Returns:
        Validated configuration dictionary with keys: base_url, api_key, verify, proxy.

    Raises:
        DemistoException: If audit type filter contains invalid values.
    """
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
            "page_size": page_size,
        }

        demisto.debug(f"[API] Fetching policies | Params: {params}")

        response = self._http_request(
            method="GET",
            url_suffix=ApiPaths.POLICIES,
            params=params,
        )

        demisto.debug("[API] Policies response received")
        return response

    def update_policy_status(self, policy_id: int, enabled: bool) -> dict[str, Any]:
        """Update the enabled/disabled status of a policy.

        Args:
            policy_id: The ID of the policy to update.
            enabled: Whether to enable (True) or disable (False) the policy.

        Returns:
            The full updated policy object from the API.
        """
        url_suffix = ApiPaths.policy(policy_id)
        body: dict[str, Any] = {"enabled": enabled}

        demisto.debug(f"[API] Updating policy {policy_id} status to enabled={enabled}")

        response = self._http_request(
            method="PUT",
            url_suffix=url_suffix,
            json_data=body,
        )

        demisto.debug(f"[API] Policy {policy_id} status updated successfully")
        return response

    def get_allowlist(self) -> dict[str, Any]:
        """Fetch all items in the allowlist from the Koi API.

        Returns:
            The full API response dictionary containing 'items' list.
        """
        demisto.debug("[API] Fetching allowlist")

        response = self._http_request(
            method="GET",
            url_suffix=ApiPaths.ALLOWLIST,
        )

        items = response.get("items", [])
        demisto.debug(f"[API] Allowlist response received: {len(items)} items")
        return response

    def get_blocklist(self) -> dict[str, Any]:
        """Fetch all items in the blocklist from the Koi API.

        Returns:
            The full API response dictionary containing 'items' list.
        """
        demisto.debug("[API] Fetching blocklist")

        response = self._http_request(
            method="GET",
            url_suffix=ApiPaths.BLOCKLIST,
        )

        items = response.get("items", [])
        demisto.debug(f"[API] Blocklist response received: {len(items)} items")
        return response

    def remove_allowlist_items(
        self,
        items: list[dict[str, Any]],
    ) -> None:
        """Remove one or more items from the global allowlist.

        Args:
            items: List of item dictionaries, each containing at least 'item_id' and 'marketplace'.
        """
        body: dict[str, Any] = {"items": items}

        demisto.debug(f"[API] Removing {len(items)} allowlist item(s): {items}")

        self._http_request(
            method="DELETE",
            url_suffix=ApiPaths.ALLOWLIST,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

        demisto.debug(f"[API] Successfully removed {len(items)} allowlist item(s)")

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
            url_suffix=ApiPaths.ALLOWLIST,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

        demisto.debug(f"[API] Successfully added {len(items)} allowlist item(s)")

    def remove_blocklist_items(
        self,
        items: list[dict[str, Any]],
    ) -> None:
        """Remove one or more items from the global blocklist.

        Args:
            items: List of item dictionaries, each containing at least 'item_id' and 'marketplace'.
        """
        body: dict[str, Any] = {"items": items}

        demisto.debug(f"[API] Removing {len(items)} blocklist item(s): {items}")

        self._http_request(
            method="DELETE",
            url_suffix=ApiPaths.BLOCKLIST,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

        demisto.debug(f"[API] Successfully removed {len(items)} blocklist item(s)")

    def add_blocklist_items(
        self,
        items: list[dict[str, Any]],
    ) -> None:
        """Add one or more items to the global blocklist.

        Args:
            items: List of item dictionaries, each containing at least 'item_id' and 'marketplace'.
        """
        body: dict[str, Any] = {"items": items}

        demisto.debug(f"[API] Adding {len(items)} blocklist item(s): {items}")

        self._http_request(
            method="POST",
            url_suffix=ApiPaths.BLOCKLIST,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

        demisto.debug(f"[API] Successfully added {len(items)} blocklist item(s)")

    def get_inventory(
        self,
        page: int,
        page_size: int,
        brew_category_koi: str | None = None,
        browser_category_koi: str | None = None,
        chocolatey_category_koi: str | None = None,
        device_id: str | None = None,
        finding_id: str | None = None,
        first_seen: str | None = None,
        ide_category_koi: str | None = None,
        installation_method: str | None = None,
        item_display_name: str | None = None,
        item_id: str | None = None,
        marketplace: str | None = None,
        platform: str | None = None,
        publisher_name: str | None = None,
        risk_level: str | None = None,
        software_category_koi: str | None = None,
        sort_by: str | None = None,
        sort_direction: str | None = None,
        view: str | None = None,
    ) -> dict[str, Any]:
        """Fetch a single page of inventory items from the Koi API.

        Args:
            page: Page number for pagination (1-based).
            page_size: Number of results per page (max 500).
            brew_category_koi: Filter by Homebrew package category (Koi classification).
            browser_category_koi: Filter by browser extension category (Koi classification).
            chocolatey_category_koi: Filter by Chocolatey package category (Koi classification).
            device_id: Filter devices by device id.
            finding_id: Filter devices by finding id.
            first_seen: Filter by first seen date (ISO 8601 format).
            ide_category_koi: Filter by IDE extension category (Koi classification).
            installation_method: Filter by installation method.
            item_display_name: Filter by item display name (case-insensitive partial match).
            item_id: Filter by item ID.
            marketplace: Filter by marketplace.
            platform: Filter by platform.
            publisher_name: Filter by publisher name (case-insensitive partial match).
            risk_level: Filter by risk level.
            software_category_koi: Filter by software category (Koi classification).
            sort_by: Column to sort by.
            sort_direction: Sort direction (asc or desc).
            view: Filter by predefined view (marketplace group).

        Returns:
            The full API response dictionary containing 'items' list and 'total_count'.
        """
        params: dict[str, Any] = assign_params(
            page=page,
            page_size=page_size,
            brew_category_koi=brew_category_koi,
            browser_category_koi=browser_category_koi,
            chocolatey_category_koi=chocolatey_category_koi,
            device_id=device_id,
            finding_id=finding_id,
            first_seen=first_seen,
            ide_category_koi=ide_category_koi,
            installation_method=installation_method,
            item_display_name=item_display_name,
            item_id=item_id,
            marketplace=marketplace,
            platform=platform,
            publisher_name=publisher_name,
            risk_level=risk_level,
            software_category_koi=software_category_koi,
            sort_by=sort_by,
            sort_direction=sort_direction,
            view=view,
        )

        demisto.debug(f"[API] Fetching inventory | Params: {params}")

        response = self._http_request(
            method="GET",
            url_suffix=ApiPaths.INVENTORY,
            params=params,
        )

        demisto.debug("[API] Inventory response received")
        return response

    def get_inventory_item(
        self,
        item_id: str,
        marketplace: str,
        version: str,
    ) -> dict[str, Any]:
        """Fetch details for a specific inventory item from the Koi API.

        Args:
            item_id: Unique identifier for the item.
            marketplace: The marketplace where the item is hosted.
            version: The specific version of the item to retrieve.

        Returns:
            The full API response dictionary with item details.
        """
        params: dict[str, Any] = {
            "marketplace": marketplace,
            "version": version,
        }

        url_suffix = ApiPaths.inventory_item(item_id)
        demisto.debug(f"[API] Fetching inventory item {item_id} | Params: {params}")

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
        )

        demisto.debug(f"[API] Inventory item {item_id} response received")
        return response

    def get_inventory_item_endpoints(
        self,
        item_id: str,
        marketplace: str,
        version: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        """Fetch endpoints that have a specific inventory item installed.

        Args:
            item_id: Unique identifier for the item.
            marketplace: The marketplace where the item is hosted.
            version: The specific version of the item.
            page: Page number for pagination (1-based).
            page_size: Number of results per page (max 500).

        Returns:
            The full API response dictionary containing 'endpoints' list and 'total_count'.
        """
        params: dict[str, Any] = {
            "marketplace": marketplace,
            "version": version,
            "page": page,
            "page_size": page_size,
        }

        url_suffix = ApiPaths.inventory_item_endpoints(item_id)
        demisto.debug(f"[API] Fetching endpoints for item {item_id} | Params: {params}")

        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
        )

        demisto.debug(f"[API] Endpoints for item {item_id} response received")
        return response

    def search_inventory(
        self,
        page: int,
        page_size: int,
        filter_obj: dict[str, Any],
        sort_by: str | None = None,
        sort_direction: str | None = None,
    ) -> dict[str, Any]:
        """Search inventory items using advanced filters via POST.

        Args:
            page: Page number for pagination (1-based).
            page_size: Number of results per page (max 500).
            filter_obj: Filter object using query builder syntax.
            sort_by: Column to sort by.
            sort_direction: Sort direction (asc or desc).

        Returns:
            The full API response dictionary containing 'items' list and 'total_count'.
        """
        body: dict[str, Any] = {
            "page": page,
            "page_size": page_size,
            "filter": filter_obj,
        }

        if sort_by:
            body["sort_by"] = sort_by
        if sort_direction:
            body["sort_direction"] = sort_direction

        demisto.debug(f"[API] Searching inventory | Body: {body}")

        response = self._http_request(
            method="POST",
            url_suffix=ApiPaths.INVENTORY_SEARCH,
            json_data=body,
        )

        demisto.debug("[API] Inventory search response received")
        return response

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

    # ── v1.2.0 tier-1 read-only expansion ─────────────────────────
    # Eleven new endpoint wrappers. Same shape as `get_policies`:
    # build params, call _http_request, return raw dict. Pagination +
    # filter merging happen in the command layer via _paginate_simple.

    def get_devices(
        self,
        page: int,
        page_size: int,
        status: str | None = None,
        last_seen_gte: str | None = None,
        last_seen_lte: str | None = None,
    ) -> dict[str, Any]:
        """List devices. status ∈ {active, stale}."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        if last_seen_gte:
            params["last_seen_gte"] = last_seen_gte
        if last_seen_lte:
            params["last_seen_lte"] = last_seen_lte
        demisto.debug(f"[API] Fetching devices | Params: {params}")
        return self._http_request(method="GET", url_suffix=ApiPaths.DEVICES, params=params)

    def get_device_inventory(
        self,
        device_id: str,
        page: int,
        page_size: int,
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        """Items installed on a single device."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if finding_id:
            params["finding_id"] = finding_id
        url_suffix = ApiPaths.device_inventory(device_id)
        demisto.debug(f"[API] Fetching inventory for device {device_id} | Params: {params}")
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def get_runtime_policies(
        self,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        """Agent runtime / hardening enforcement policies."""
        params = {"page": page, "page_size": page_size}
        demisto.debug(f"[API] Fetching runtime policies | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.RUNTIME_POLICIES,
            params=params,
        )

    def get_runtime_policy(self, policy_id: str) -> dict[str, Any]:
        """Single hardening policy by ID. Returns the full rule tree."""
        url_suffix = ApiPaths.runtime_policy(policy_id)
        demisto.debug(f"[API] Fetching runtime policy {policy_id}")
        return self._http_request(method="GET", url_suffix=url_suffix)

    def get_findings(self, page: int, page_size: int) -> dict[str, Any]:
        """Catalog of detection definitions (risk + description)."""
        params = {"page": page, "page_size": page_size}
        demisto.debug(f"[API] Fetching findings | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.FINDINGS,
            params=params,
        )

    def get_approval_requests(
        self,
        page: int,
        page_size: int,
        approval_status: str | None = None,
        marketplace: str | None = None,
        requested_by: str | None = None,
        created_at_gte: str | None = None,
        created_at_lte: str | None = None,
    ) -> dict[str, Any]:
        """Pending/approved/rejected approval requests."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        for k, v in (
            ("approval_status", approval_status),
            ("marketplace", marketplace),
            ("requested_by", requested_by),
            ("created_at_gte", created_at_gte),
            ("created_at_lte", created_at_lte),
        ):
            if v:
                params[k] = v
        demisto.debug(f"[API] Fetching approval requests | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.APPROVAL_REQUESTS,
            params=params,
        )

    def get_remediations(
        self,
        page: int,
        page_size: int,
        status: str | None = None,
        risk_level: str | None = None,
        platform: str | None = None,
        hostname: str | None = None,
        reason: str | None = None,
        sort_by: str | None = None,
        sort_direction: str | None = None,
    ) -> dict[str, Any]:
        """Remediation queue. status ∈ {open, pending, remediated, dismissed}."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        for k, v in (
            ("status", status),
            ("risk_level", risk_level),
            ("platform", platform),
            ("hostname", hostname),
            ("reason", reason),
            ("sort_by", sort_by),
            ("sort_direction", sort_direction),
        ):
            if v:
                params[k] = v
        demisto.debug(f"[API] Fetching remediations | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.REMEDIATIONS,
            params=params,
        )

    def get_groups(self, page: int, page_size: int) -> dict[str, Any]:
        """Device groups (max 9 per customer)."""
        params = {"page": page, "page_size": page_size}
        demisto.debug(f"[API] Fetching groups | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.GROUPS,
            params=params,
        )

    def get_users(self) -> dict[str, Any]:
        """All users. Endpoint is not paginated — single GET returns the
        complete list."""
        demisto.debug("[API] Fetching users")
        return self._http_request(method="GET", url_suffix=ApiPaths.USERS)

    def get_koidex_search(
        self,
        marketplace: str,
        search_term: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        """Search the Koi catalog database for items by name/term."""
        params = {
            "marketplace": marketplace,
            "search_term": search_term,
            "page": page,
            "page_size": page_size,
        }
        demisto.debug(f"[API] Koidex search | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.KOIDEX_SEARCH,
            params=params,
        )

    def get_koidex_risk_report(
        self,
        item_id: str,
        marketplace: str,
        version: str | None = None,
    ) -> dict[str, Any]:
        """Full risk + compliance report for an item from the Koi catalog."""
        params: dict[str, Any] = {"item_id": item_id, "marketplace": marketplace}
        if version:
            params["version"] = version
        demisto.debug(f"[API] Koidex risk-report | Params: {params}")
        return self._http_request(
            method="GET",
            url_suffix=ApiPaths.KOIDEX_RISK_REPORT,
            params=params,
        )


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
    should_push_events = resolve_should_push_events(args)

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
    first_fetch_time: str | None = None,
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
        first_fetch_time: Optional lookback for the first fetch (e.g., "3 days ago").
            Overrides Config.DEFAULT_FROM_TIME when no last_run state exists.

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
            time_input = first_fetch_time or Config.DEFAULT_FROM_TIME
            demisto.debug(f"[Fetch] {log_type.type_string}: First run - starting from '{time_input}'")

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

        # Deduplicate (log_type matters: audit IDs are synthesized from
        # the event payload because Koi audit responses have no native id).
        new_events = deduplicate_events(events, last_fetched_ids, log_type)

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
                if event_time == new_last_run_time and (event_id := get_event_id(event, log_type))
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

    first_fetch = params.get("first_fetch", "").strip()
    first_fetch_time = f"{first_fetch} ago" if first_fetch and "ago" not in first_fetch else first_fetch

    # Single read of last_run state — no race condition
    last_run = demisto.getLastRun()
    demisto.debug(f"[Fetch] Starting with last_run: {last_run}")

    # Guard against an empty log_types selection — ThreadPoolExecutor(max_workers=0) raises ValueError.
    if not log_types:
        demisto.debug("[Fetch] No event types selected. Nothing to fetch. Preserving last_run as-is.")
        demisto.setLastRun(last_run)
        return

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
                first_fetch_time=first_fetch_time or None,
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
    per_type_counts: dict[str, int] = {}
    per_type_errors: dict[str, str] = {}

    for result in results:
        type_label = result.log_type.type_string
        if result.error:
            per_type_errors[type_label] = result.error
            demisto.debug(f"[Fetch] {type_label}: Skipped due to error: {result.error}")
            continue
        per_type_counts[type_label] = len(result.new_events)
        all_new_events.extend(result.new_events)
        updated_last_run.update(result.last_run_updates)

    # Send all successfully fetched events to XSIAM
    if all_new_events:
        client.send_events(all_new_events)

    # ── Always-advance execution-time markers ─────────────────────
    # These update on every cycle regardless of whether events arrived,
    # so operators can tell from `last_run` that the scheduler IS firing
    # at the configured interval (vs. the HWM advancing only when Koi
    # has new events to give us). Separate keys from `last_fetch_<type>`
    # so the dedup machinery isn't disturbed.
    now_iso = datetime.now(UTC).strftime(Config.DATE_FORMAT)
    updated_last_run["last_execution_time"] = now_iso
    for log_type in log_types:
        updated_last_run[f"last_execution_{log_type.type_string}"] = now_iso

    # Single write of last_run state — preserves progress from successful types
    demisto.setLastRun(updated_last_run)

    # Operator-facing summary: distinguishes "ran, found nothing" from
    # "didn't run at all". Combined with last_execution_time, the
    # operator can spot a scheduling issue vs. a quiet Koi tenant.
    summary_parts = [f"executed_at={now_iso}"]
    for type_label, count in per_type_counts.items():
        summary_parts.append(f"{type_label.lower()}_new={count}")
    for type_label, err in per_type_errors.items():
        summary_parts.append(f"{type_label.lower()}_error={err[:60]!r}")
    demisto.debug(f"[Fetch] Cycle summary: {' '.join(summary_parts)}")
    demisto.debug(f"[Fetch] Last run state: {updated_last_run}")


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

    if page_size > Config.MAX_PAGE_SIZE:
        raise DemistoException(f"page_size ({page_size}) exceeds the maximum allowed value of {Config.MAX_PAGE_SIZE}.")
    if limit_arg and limit_arg > Config.MAX_LIMIT:
        raise DemistoException(f"limit ({limit_arg}) exceeds the maximum allowed value of {Config.MAX_LIMIT}.")

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
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Allowlist",
        outputs_key_field="item_id",
        outputs=items,
    )


def koi_allowlist_items_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove one or more items from the global allowlist.

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
    demisto.debug("[Command] koi-allowlist-items-remove triggered")

    items = resolve_items_from_args(args)
    client.remove_allowlist_items(items)

    item_count = len(items)
    demisto.debug(f"[Command Result] {item_count} allowlist item(s) removed successfully")

    if item_count == 1:
        readable = f"Allowlist item '{items[0]['item_id']}' (marketplace: {items[0]['marketplace']}) was removed successfully."
    else:
        readable = f"{item_count} allowlist items were removed successfully."

    return CommandResults(readable_output=readable)


def koi_allowlist_items_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    demisto.debug("[Command] koi-allowlist-items-add triggered")

    items = resolve_items_from_args(args)
    client.add_allowlist_items(items)

    item_count = len(items)
    demisto.debug(f"[Command Result] {item_count} allowlist item(s) added successfully")

    if item_count == 1:
        readable = f"Allowlist item '{items[0]['item_id']}' (marketplace: {items[0]['marketplace']}) was added successfully."
    else:
        readable = f"{item_count} allowlist items were added successfully."

    return CommandResults(readable_output=readable)


def koi_blocklist_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve all items in the blocklist.

    Args:
        client: The KOI client.
        args: Command arguments (unused, no inputs for this command).

    Returns:
        CommandResults with the blocklist items.
    """
    demisto.debug("[Command] koi-blocklist-get triggered")

    response = client.get_blocklist()
    items = response.get("items", [])

    demisto.debug(f"[Command Result] Retrieved {len(items)} blocklist items")

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Blocklist",
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
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Blocklist",
        outputs_key_field="item_id",
        outputs=items,
    )


def koi_blocklist_items_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove one or more items from the global blocklist.

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
    demisto.debug("[Command] koi-blocklist-items-remove triggered")

    items = resolve_items_from_args(args)
    client.remove_blocklist_items(items)

    item_count = len(items)
    demisto.debug(f"[Command Result] {item_count} blocklist item(s) removed successfully")

    if item_count == 1:
        readable = f"Blocklist item '{items[0]['item_id']}' (marketplace: {items[0]['marketplace']}) was removed successfully."
    else:
        readable = f"{item_count} blocklist items were removed successfully."

    return CommandResults(readable_output=readable)


def koi_blocklist_items_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add one or more items to the global blocklist.

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
    demisto.debug("[Command] koi-blocklist-items-add triggered")

    items = resolve_items_from_args(args)
    client.add_blocklist_items(items)

    item_count = len(items)
    demisto.debug(f"[Command Result] {item_count} blocklist item(s) added successfully")

    if item_count == 1:
        readable = f"Blocklist item '{items[0]['item_id']}' (marketplace: {items[0]['marketplace']}) was added successfully."
    else:
        readable = f"{item_count} blocklist items were added successfully."

    return CommandResults(readable_output=readable)


def koi_policy_status_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Enable or disable a policy by ID.

    Args:
        client: The KOI client.
        args: Command arguments (policy_id, enabled).

    Returns:
        CommandResults with the updated policy.
    """
    demisto.debug("[Command] koi-policy-status-update triggered")

    policy_id = arg_to_number(args.get("policy_id"))
    if policy_id is None:
        raise DemistoException("policy_id is required and must be a valid integer.")
    enabled = argToBoolean(args.get("enabled"))

    response = client.update_policy_status(policy_id=policy_id, enabled=enabled)

    status_text = "enabled" if enabled else "disabled"
    demisto.debug(f"[Command Result] Policy {policy_id} {status_text} successfully")

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Policy Updated",
        response,
        headers=[
            "id",
            "name",
            "description",
            "action",
            "enabled",
            "group_ids",
            "creator_fullname",
            "created_at",
            "updated_at",
        ],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Policy",
        outputs_key_field="id",
        outputs=response,
    )


def koi_inventory_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List inventory items with pagination and filtering support.

    Supports two modes:
    - Single page: provide 'page' and/or 'page_size' to fetch a specific page.
    - Auto-paginate: provide 'limit' to automatically paginate and collect up to 'limit' items.

    If 'page' is provided, single-page mode is used (limit is ignored).
    If only 'limit' is provided, auto-pagination mode is used.

    Args:
        client: The KOI client.
        args: Command arguments including pagination and filter parameters.

    Returns:
        CommandResults with the inventory item list.
    """
    demisto.debug("[Command] koi-inventory-list triggered")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))

    if page_size > Config.MAX_PAGE_SIZE:
        raise DemistoException(f"page_size ({page_size}) exceeds the maximum allowed value of {Config.MAX_PAGE_SIZE}.")
    if limit_arg and limit_arg > Config.MAX_LIMIT:
        raise DemistoException(f"limit ({limit_arg}) exceeds the maximum allowed value of {Config.MAX_LIMIT}.")

    # Extract filter arguments
    filter_kwargs: dict[str, Any] = assign_params(
        brew_category_koi=args.get("brew_category_koi"),
        browser_category_koi=args.get("browser_category_koi"),
        chocolatey_category_koi=args.get("chocolatey_category_koi"),
        device_id=args.get("device_id"),
        finding_id=args.get("finding_id"),
        first_seen=args.get("first_seen"),
        ide_category_koi=args.get("ide_category_koi"),
        installation_method=args.get("installation_method"),
        item_display_name=args.get("item_display_name"),
        item_id=args.get("item_id"),
        marketplace=args.get("marketplace"),
        platform=args.get("platform"),
        publisher_name=args.get("publisher_name"),
        risk_level=args.get("risk_level"),
        software_category_koi=args.get("software_category_koi"),
        sort_by=args.get("sort_by"),
        sort_direction=args.get("sort_direction"),
        view=args.get("view"),
    )

    if page_arg:
        # Single-page mode: fetch the requested page
        demisto.debug(f"[Command] Single-page mode: page={page_arg}, page_size={page_size}")
        response = client.get_inventory(page=page_arg, page_size=page_size, **filter_kwargs)
        items = response.get("items", [])
        total_count = response.get("total_count")
        demisto.debug(f"[Command Result] Retrieved {len(items)} inventory items (total_count={total_count})")
    else:
        # Auto-paginate mode: fetch pages until limit is reached
        limit = limit_arg or Config.DEFAULT_LIMIT
        demisto.debug(f"[Command] Auto-paginate mode: limit={limit}")
        items = _fetch_inventory_with_pagination(client, limit=limit, filter_kwargs=filter_kwargs)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Inventory",
        items,
        headers=[
            "item_id",
            "item_display_name",
            "marketplace",
            "platforms",
            "publisher_name",
            "risk",
            "risk_level",
            "version",
            "status",
            "endpoint_count",
            "installs_count",
            "installation_method",
            "is_first_party",
            "is_signed",
            "first_seen",
            "last_seen",
            "last_used",
            "released_at",
            "short_description",
            "categories",
            "findings",
            "brew_category_koi",
            "browser_category_koi",
            "chocolatey_category_koi",
            "ide_category_koi",
            "software_category_koi",
            "governed_details",
        ],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Inventory",
        outputs_key_field="item_id",
        outputs=items,
    )


def _fetch_inventory_with_pagination(
    client: Client,
    limit: int,
    filter_kwargs: dict[str, Any],
    page_size: int = Config.MAX_PAGE_SIZE,
) -> list[dict]:
    """Auto-paginate through inventory items until limit is reached.

    Args:
        client: The Koi client.
        limit: Maximum total number of items to collect.
        filter_kwargs: Filter parameters to pass to the API.
        page_size: Number of results per API page.

    Returns:
        List of inventory item dictionaries.
    """
    items: list[dict] = []
    page = Config.DEFAULT_PAGE

    while len(items) < limit:
        response = client.get_inventory(page=page, page_size=page_size, **filter_kwargs)
        page_items = response.get("items", [])

        if not page_items:
            demisto.debug(f"[Pagination] Page {page}: Empty. Stopping.")
            break

        items.extend(page_items)
        demisto.debug(f"[Pagination] Page {page}: +{len(page_items)} items. Total: {len(items)}")

        if len(page_items) < page_size:
            demisto.debug("[Pagination] Last page (partial). Stopping.")
            break

        page += 1

    # Trim to limit
    if len(items) > limit:
        demisto.debug(f"[Pagination] Trimming {len(items)} items to limit {limit}")
        items = items[:limit]

    demisto.debug(f"[Pagination] Returning {len(items)} inventory items")
    return items


def koi_inventory_item_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Retrieve comprehensive details for a specific inventory item.

    Args:
        client: The KOI client.
        args: Command arguments (item_id, marketplace, version).

    Returns:
        CommandResults with the inventory item details.
    """
    demisto.debug("[Command] koi-inventory-item-get triggered")

    item_id: str = args["item_id"]
    marketplace: str = args["marketplace"]
    version: str = args["version"]

    response = client.get_inventory_item(
        item_id=item_id,
        marketplace=marketplace,
        version=version,
    )

    demisto.debug(f"[Command Result] Retrieved inventory item {item_id}")

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Inventory Item",
        response,
        headers=[
            "item_id",
            "item_display_name",
            "marketplace",
            "platforms",
            "publisher_name",
            "risk",
            "risk_level",
            "version",
            "status",
            "endpoint_count",
            "installs_count",
            "installation_method",
            "is_first_party",
            "is_signed",
            "first_seen",
            "last_seen",
            "last_used",
            "released_at",
            "short_description",
            "categories",
            "findings",
            "brew_category_koi",
            "browser_category_koi",
            "chocolatey_category_koi",
            "ide_category_koi",
            "software_category_koi",
            "governed_details",
        ],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Inventory",
        outputs_key_field="item_id",
        outputs=response,
    )


def koi_inventory_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Search inventory items using advanced filters.

    Supports two modes:
    - Single page: provide 'page' and/or 'page_size' to fetch a specific page.
    - Auto-paginate: provide 'limit' to automatically paginate and collect up to 'limit' items.

    If 'page' is provided, single-page mode is used (limit is ignored).
    If only 'limit' is provided, auto-pagination mode is used.

    Args:
        client: The KOI client.
        args: Command arguments including filter, pagination, and sorting parameters.

    Returns:
        CommandResults with the search results.
    """
    demisto.debug("[Command] koi-inventory-search triggered")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))

    if page_size > Config.MAX_PAGE_SIZE:
        raise DemistoException(f"page_size ({page_size}) exceeds the maximum allowed value of {Config.MAX_PAGE_SIZE}.")
    if limit_arg and limit_arg > Config.MAX_LIMIT:
        raise DemistoException(f"limit ({limit_arg}) exceeds the maximum allowed value of {Config.MAX_LIMIT}.")

    filter_obj: dict[str, Any] = parse_filter_from_args(args)
    sort_by: str | None = args.get("sort_by")
    sort_direction: str | None = args.get("sort_direction")

    if page_arg:
        # Single-page mode
        demisto.debug(f"[Command] Single-page mode: page={page_arg}, page_size={page_size}")
        response = client.search_inventory(
            page=page_arg,
            page_size=page_size,
            filter_obj=filter_obj,
            sort_by=sort_by,
            sort_direction=sort_direction,
        )
        items = response.get("items", [])
        total_count = response.get("total_count")
        demisto.debug(f"[Command Result] Retrieved {len(items)} items (total_count={total_count})")
    else:
        # Auto-paginate mode
        limit = limit_arg or Config.DEFAULT_LIMIT
        demisto.debug(f"[Command] Auto-paginate mode: limit={limit}")
        items = _search_inventory_with_pagination(
            client,
            limit=limit,
            filter_obj=filter_obj,
            sort_by=sort_by,
            sort_direction=sort_direction,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Inventory Search",
        items,
        headers=[
            "item_id",
            "item_display_name",
            "marketplace",
            "platforms",
            "publisher_name",
            "risk",
            "risk_level",
            "version",
            "status",
            "endpoint_count",
            "installs_count",
            "installation_method",
            "is_first_party",
            "is_signed",
            "first_seen",
            "last_seen",
            "last_used",
            "released_at",
            "short_description",
            "categories",
            "findings",
            "brew_category_koi",
            "browser_category_koi",
            "chocolatey_category_koi",
            "ide_category_koi",
            "software_category_koi",
            "governed_details",
        ],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Inventory",
        outputs_key_field="item_id",
        outputs=items,
    )


def _search_inventory_with_pagination(
    client: Client,
    limit: int,
    filter_obj: dict[str, Any],
    sort_by: str | None = None,
    sort_direction: str | None = None,
    page_size: int = Config.MAX_PAGE_SIZE,
) -> list[dict]:
    """Auto-paginate through inventory search results until limit is reached.

    Args:
        client: The Koi client.
        limit: Maximum total number of items to collect.
        filter_obj: Filter object for the search.
        sort_by: Column to sort by.
        sort_direction: Sort direction.
        page_size: Number of results per API page.

    Returns:
        List of inventory item dictionaries.
    """
    items: list[dict] = []
    page = Config.DEFAULT_PAGE

    while len(items) < limit:
        response = client.search_inventory(
            page=page,
            page_size=page_size,
            filter_obj=filter_obj,
            sort_by=sort_by,
            sort_direction=sort_direction,
        )
        page_items = response.get("items", [])

        if not page_items:
            demisto.debug(f"[Pagination] Page {page}: Empty. Stopping.")
            break

        items.extend(page_items)
        demisto.debug(f"[Pagination] Page {page}: +{len(page_items)} items. Total: {len(items)}")

        if len(page_items) < page_size:
            demisto.debug("[Pagination] Last page (partial). Stopping.")
            break

        page += 1

    # Trim to limit
    if len(items) > limit:
        demisto.debug(f"[Pagination] Trimming {len(items)} items to limit {limit}")
        items = items[:limit]

    demisto.debug(f"[Pagination] Returning {len(items)} inventory search results")
    return items


def koi_inventory_item_endpoints_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List endpoints that have a specific inventory item installed.

    Supports two modes:
    - Single page: provide 'page' and/or 'page_size' to fetch a specific page.
    - Auto-paginate: provide 'limit' to automatically paginate and collect up to 'limit' endpoints.

    If 'page' is provided, single-page mode is used (limit is ignored).
    If only 'limit' is provided, auto-pagination mode is used.

    Args:
        client: The KOI client.
        args: Command arguments (item_id, marketplace, version, page, page_size, limit).

    Returns:
        CommandResults with the endpoint list.
    """
    demisto.debug("[Command] koi-inventory-item-endpoints-list triggered")

    item_id: str = args["item_id"]
    marketplace: str = args["marketplace"]
    version: str = args["version"]

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))

    if page_size > Config.MAX_PAGE_SIZE:
        raise DemistoException(f"page_size ({page_size}) exceeds the maximum allowed value of {Config.MAX_PAGE_SIZE}.")
    if limit_arg and limit_arg > Config.MAX_LIMIT:
        raise DemistoException(f"limit ({limit_arg}) exceeds the maximum allowed value of {Config.MAX_LIMIT}.")

    if page_arg:
        # Single-page mode
        demisto.debug(f"[Command] Single-page mode: page={page_arg}, page_size={page_size}")
        response = client.get_inventory_item_endpoints(
            item_id=item_id,
            marketplace=marketplace,
            version=version,
            page=page_arg,
            page_size=page_size,
        )
        endpoints = response.get("endpoints", [])
        total_count = response.get("total_count")
        demisto.debug(f"[Command Result] Retrieved {len(endpoints)} endpoints (total_count={total_count})")
    else:
        # Auto-paginate mode
        limit = limit_arg or Config.DEFAULT_LIMIT
        demisto.debug(f"[Command] Auto-paginate mode: limit={limit}")
        endpoints = _fetch_item_endpoints_with_pagination(
            client,
            item_id=item_id,
            marketplace=marketplace,
            version=version,
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Inventory Item Endpoints",
        endpoints,
        headers=[
            "id",
            "hostname",
            "os",
            "platform",
            "serial",
            "last_logged_on_user",
            "activation_status",
            "path",
            "first_seen",
            "last_seen",
        ],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Inventory.Endpoint",
        outputs_key_field="id",
        outputs=endpoints,
    )


def _fetch_item_endpoints_with_pagination(
    client: Client,
    item_id: str,
    marketplace: str,
    version: str,
    limit: int,
    page_size: int = Config.MAX_PAGE_SIZE,
) -> list[dict]:
    """Auto-paginate through item endpoints until limit is reached.

    Args:
        client: The Koi client.
        item_id: Unique identifier for the item.
        marketplace: The marketplace where the item is hosted.
        version: The specific version of the item.
        limit: Maximum total number of endpoints to collect.
        page_size: Number of results per API page.

    Returns:
        List of endpoint dictionaries.
    """
    endpoints: list[dict] = []
    page = Config.DEFAULT_PAGE

    while len(endpoints) < limit:
        response = client.get_inventory_item_endpoints(
            item_id=item_id,
            marketplace=marketplace,
            version=version,
            page=page,
            page_size=page_size,
        )
        page_endpoints = response.get("endpoints", [])

        if not page_endpoints:
            demisto.debug(f"[Pagination] Page {page}: Empty. Stopping.")
            break

        endpoints.extend(page_endpoints)
        demisto.debug(f"[Pagination] Page {page}: +{len(page_endpoints)} endpoints. Total: {len(endpoints)}")

        if len(page_endpoints) < page_size:
            demisto.debug("[Pagination] Last page (partial). Stopping.")
            break

        page += 1

    # Trim to limit
    if len(endpoints) > limit:
        demisto.debug(f"[Pagination] Trimming {len(endpoints)} endpoints to limit {limit}")
        endpoints = endpoints[:limit]

    demisto.debug(f"[Pagination] Returning {len(endpoints)} endpoints")
    return endpoints


# endregion

# region v1.2.0 tier-1 expansion command implementations
# =================================
# 11 new read-only commands covering API sections 2, 4, 5, 6, 7, 9, 11, 13.
# Each follows the existing convention: validate args, call the matching
# client.get_X() method, build a tableToMarkdown summary + CommandResults.
# A single _paginate_list_endpoint helper keeps the auto-paginate logic
# DRY across the eight list-style endpoints.
# =================================


def _paginate_list_endpoint(
    fetch_one_page,
    result_key: str,
    limit: int,
    page_size: int = Config.MAX_PAGE_SIZE,
) -> list[dict]:
    """Generic auto-paginator for list endpoints.

    `fetch_one_page` is a callable taking (page, page_size) and returning
    the raw dict response. `result_key` is the top-level key under which
    the items list lives ("devices", "items", "policies", ...).
    """
    out: list[dict] = []
    page = Config.DEFAULT_PAGE
    while len(out) < limit:
        response = fetch_one_page(page=page, page_size=page_size)
        batch = response.get(result_key, []) if isinstance(response, dict) else []
        if not batch:
            demisto.debug(f"[Pagination] Page {page}: Empty. Stopping.")
            break
        out.extend(batch)
        demisto.debug(f"[Pagination] Page {page}: +{len(batch)} ({result_key}). Total: {len(out)}")
        if len(batch) < page_size:
            demisto.debug("[Pagination] Last page (partial). Stopping.")
            break
        page += 1
    if len(out) > limit:
        out = out[:limit]
    demisto.debug(f"[Pagination] Returning {len(out)} {result_key}")
    return out


def _validate_pagination_args(args: dict[str, Any]) -> tuple[int | None, int, int | None]:
    """Parse + validate the common pagination args (page, page_size, limit).
    Raises DemistoException on out-of-range values."""
    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    if page_size > Config.MAX_PAGE_SIZE:
        raise DemistoException(f"page_size ({page_size}) exceeds the maximum allowed value of {Config.MAX_PAGE_SIZE}.")
    if limit_arg and limit_arg > Config.MAX_LIMIT:
        raise DemistoException(f"limit ({limit_arg}) exceeds the maximum allowed value of {Config.MAX_LIMIT}.")
    return page_arg, page_size, limit_arg


def koi_devices_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List devices registered with Koi."""
    demisto.debug("[Command] koi-devices-list triggered")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)
    status = args.get("status")
    last_seen_gte = args.get("last_seen_gte")
    last_seen_lte = args.get("last_seen_lte")

    if page_arg:
        response = client.get_devices(
            page=page_arg,
            page_size=page_size,
            status=status,
            last_seen_gte=last_seen_gte,
            last_seen_lte=last_seen_lte,
        )
        devices = response.get("devices", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        devices = _paginate_list_endpoint(
            lambda page, page_size: client.get_devices(
                page=page,
                page_size=page_size,
                status=status,
                last_seen_gte=last_seen_gte,
                last_seen_lte=last_seen_lte,
            ),
            result_key="devices",
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Devices",
        devices,
        headers=["id", "hostname", "os", "status", "last_seen", "last_logged_on_user", "serial", "registered_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Device",
        outputs_key_field="id",
        outputs=devices,
    )


def koi_device_inventory_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List items installed on a single device."""
    demisto.debug("[Command] koi-device-inventory-get triggered")
    device_id = args.get("device_id")
    if not device_id:
        raise DemistoException("device_id is required.")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)
    finding_id = args.get("finding_id")

    if page_arg:
        response = client.get_device_inventory(
            device_id=device_id,
            page=page_arg,
            page_size=page_size,
            finding_id=finding_id,
        )
        items = response.get("inventory", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_list_endpoint(
            lambda page, page_size: client.get_device_inventory(
                device_id=device_id,
                page=page,
                page_size=page_size,
                finding_id=finding_id,
            ),
            result_key="inventory",
            limit=limit,
        )

    # Decorate each item with the parent device id so downstream
    # automations can join without re-querying.
    for it in items:
        it["device_id"] = device_id

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Device Inventory — {device_id}",
        items,
        headers=[
            "item_id",
            "item_display_name",
            "version",
            "marketplace",
            "platform",
            "publisher",
            "risk_level",
            "activation_status",
            "first_seen",
            "last_seen",
            "local_full_path",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.DeviceInventory",
        outputs_key_field="item_id",
        outputs=items,
    )


def koi_runtime_policies_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List agent runtime (hardening) policies."""
    demisto.debug("[Command] koi-runtime-policies-list triggered")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)

    if page_arg:
        response = client.get_runtime_policies(page=page_arg, page_size=page_size)
        policies = response.get("policies", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        policies = _paginate_list_endpoint(
            lambda page, page_size: client.get_runtime_policies(page=page, page_size=page_size),
            result_key="policies",
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Runtime Policies",
        policies,
        headers=[
            "id",
            "display_name",
            "description",
            "agents",
            "enforcement_mode",
            "enabled",
            "group_ids",
            "created_by",
            "created_at",
            "updated_at",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.RuntimePolicy",
        outputs_key_field="id",
        outputs=policies,
    )


def koi_runtime_policy_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a single runtime policy by ID (returns the full rule tree)."""
    demisto.debug("[Command] koi-runtime-policy-get triggered")
    policy_id = args.get("policy_id")
    if not policy_id:
        raise DemistoException("policy_id is required.")
    policy = client.get_runtime_policy(policy_id=policy_id)

    # Render the rule tree as a sub-table so operators can see the
    # enforcement payload without dropping to raw JSON.
    summary_rows = [
        {
            "id": policy.get("id"),
            "display_name": policy.get("display_name"),
            "enforcement_mode": policy.get("enforcement_mode"),
            "enabled": policy.get("enabled"),
            "agents": policy.get("agents"),
            "rules_count": len(policy.get("rules", []) or []),
        }
    ]
    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Runtime Policy — {policy.get('display_name', policy_id)}",
        summary_rows,
        headers=["id", "display_name", "enforcement_mode", "enabled", "agents", "rules_count"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.RuntimePolicy",
        outputs_key_field="id",
        outputs=policy,
    )


def koi_findings_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List finding (detection) definitions."""
    demisto.debug("[Command] koi-findings-list triggered")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)

    if page_arg:
        response = client.get_findings(page=page_arg, page_size=page_size)
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_list_endpoint(
            lambda page, page_size: client.get_findings(page=page, page_size=page_size),
            result_key="items",
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Findings",
        items,
        headers=["id", "name", "risk", "description"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Finding",
        outputs_key_field="id",
        outputs=items,
    )


def koi_approval_requests_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List approval requests."""
    demisto.debug("[Command] koi-approval-requests-list triggered")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)
    approval_status = args.get("approval_status")
    marketplace = args.get("marketplace")
    requested_by = args.get("requested_by")
    created_at_gte = args.get("created_at_gte")
    created_at_lte = args.get("created_at_lte")

    if page_arg:
        response = client.get_approval_requests(
            page=page_arg,
            page_size=page_size,
            approval_status=approval_status,
            marketplace=marketplace,
            requested_by=requested_by,
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
        )
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_list_endpoint(
            lambda page, page_size: client.get_approval_requests(
                page=page,
                page_size=page_size,
                approval_status=approval_status,
                marketplace=marketplace,
                requested_by=requested_by,
                created_at_gte=created_at_gte,
                created_at_lte=created_at_lte,
            ),
            result_key="items",
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Approval Requests",
        items,
        headers=[
            "id",
            "approval_status",
            "marketplace",
            "name",
            "item_id",
            "version",
            "requested_by",
            "justification",
            "created_at",
            "resolved_at",
            "reject_reason",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.ApprovalRequest",
        outputs_key_field="id",
        outputs=items,
    )


def koi_remediations_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List remediation suggestions."""
    demisto.debug("[Command] koi-remediations-list triggered")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)
    filters = {
        "status": args.get("status"),
        "risk_level": args.get("risk_level"),
        "platform": args.get("platform"),
        "hostname": args.get("hostname"),
        "reason": args.get("reason"),
        "sort_by": args.get("sort_by"),
        "sort_direction": args.get("sort_direction"),
    }

    if page_arg:
        response = client.get_remediations(page=page_arg, page_size=page_size, **filters)
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_list_endpoint(
            lambda page, page_size: client.get_remediations(
                page=page,
                page_size=page_size,
                **filters,
            ),
            result_key="items",
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Remediations",
        items,
        headers=[
            "device_id",
            "hostname",
            "item_id",
            "item_display_name",
            "version",
            "platform",
            "risk_level",
            "status",
            "reason",
            "triggered_at",
            "triggered_by",
            "last_script_run",
            "dismissed_at",
            "dismissed_by",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Remediation",
        outputs_key_field="item_id",
        outputs=items,
    )


def koi_groups_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List device groups."""
    demisto.debug("[Command] koi-groups-list triggered")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)

    if page_arg:
        response = client.get_groups(page=page_arg, page_size=page_size)
        groups = response.get("groups", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        groups = _paginate_list_endpoint(
            lambda page, page_size: client.get_groups(page=page, page_size=page_size),
            result_key="groups",
            limit=limit,
        )

    # Flatten device count for the table — full devices array remains in outputs.
    table_rows = [
        {
            "id": g.get("id"),
            "name": g.get("name"),
            "device_count": len(g.get("devices", []) or []),
            "created_at": g.get("created_at"),
        }
        for g in groups
    ]
    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Groups",
        table_rows,
        headers=["id", "name", "device_count", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.Group",
        outputs_key_field="id",
        outputs=groups,
    )


def koi_users_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List users. Endpoint is unpaginated — single GET returns all rows."""
    demisto.debug("[Command] koi-users-list triggered")
    response = client.get_users()
    users = response.get("users", []) if isinstance(response, dict) else []

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Users",
        users,
        headers=["id", "email", "first_name", "last_name", "role", "status", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.User",
        outputs_key_field="id",
        outputs=users,
    )


def koi_koidex_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Search the Koi catalog database for items by name/term."""
    demisto.debug("[Command] koi-koidex-search triggered")
    marketplace = args.get("marketplace")
    search_term = args.get("search_term")
    if not marketplace or not search_term:
        raise DemistoException("marketplace and search_term are required.")
    page_arg, page_size, limit_arg = _validate_pagination_args(args)

    if page_arg:
        response = client.get_koidex_search(
            marketplace=marketplace,
            search_term=search_term,
            page=page_arg,
            page_size=page_size,
        )
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_list_endpoint(
            lambda page, page_size: client.get_koidex_search(
                marketplace=marketplace,
                search_term=search_term,
                page=page,
                page_size=page_size,
            ),
            result_key="items",
            limit=limit,
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Koidex Search — {marketplace}/{search_term}",
        items,
        headers=["item_id", "item_display_name", "marketplace", "package_name", "version", "installs"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.KoidexItem",
        outputs_key_field="item_id",
        outputs=items,
    )


def koi_koidex_risk_report_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Risk + compliance report for a single catalog item."""
    demisto.debug("[Command] koi-koidex-risk-report triggered")
    item_id = args.get("item_id")
    marketplace = args.get("marketplace")
    version = args.get("version")
    if not item_id or not marketplace:
        raise DemistoException("item_id and marketplace are required.")

    report = client.get_koidex_risk_report(
        item_id=item_id,
        marketplace=marketplace,
        version=version,
    )

    # Operator-facing summary row — the full report goes to outputs.
    findings_block = report.get("findings") or {}
    compliance_block = report.get("compliance") or {}
    summary = [
        {
            "item_id": report.get("item_id"),
            "item_display_name": report.get("item_display_name"),
            "marketplace": report.get("marketplace"),
            "version": report.get("version"),
            "risk_level": report.get("risk_level"),
            "risk": report.get("risk"),
            "findings_count": findings_block.get("total_count", len(findings_block.get("findings", []) or [])),
            "compliance_count": compliance_block.get("total_count", len(compliance_block.get("rules", []) or [])),
        }
    ]
    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Koidex Risk Report — {item_id}",
        summary,
        headers=[
            "item_id",
            "item_display_name",
            "marketplace",
            "version",
            "risk_level",
            "risk",
            "findings_count",
            "compliance_count",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Koi.KoidexRiskReport",
        outputs_key_field="item_id",
        outputs=report,
    )


# endregion

# region Main router
# =================================
# Main router
# =================================

# region Fetch-state diagnostics & maintenance


def _hwm_future_log_types(last_run: dict[str, Any], now: datetime) -> list[str]:
    """Return log_type strings whose last_fetch_<type> HWM is set in the future.

    A future high-water-mark silently stalls the scheduled fetch: it queries
    the KOI API with ``created_after=<future>`` and gets nothing back, so
    ``koi_koi_raw`` stops updating until wall-clock time passes the HWM.
    """
    future: list[str] = []
    for log_type in LogType:
        hwm = last_run.get(f"last_fetch_{log_type.type_string}")
        if isinstance(hwm, str) and hwm:
            try:
                hwm_dt = datetime.strptime(hwm, Config.DATE_FORMAT).replace(tzinfo=UTC)
            except ValueError:
                continue
            if hwm_dt > now:
                future.append(log_type.type_string)
    return future


def koi_fetch_context_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Read-only diagnostic: print the integration's fetch state and context.

    Surfaces both demisto-managed stores:
      * ``demisto.getLastRun()``  — the per-instance fetch state where the
        scheduled fetch's high-water-mark lives (``last_fetch_<type>``,
        ``previous_ids_<type>``, ``last_execution_*``).
      * ``demisto.getIntegrationContext()`` — the general key/value store.

    Highlights a FUTURE high-water-mark, the failure mode where the scheduled
    fetch returns nothing while a manual ``koi-get-events`` (which ignores the
    HWM) still works. Does not modify any state.
    """
    last_run = demisto.getLastRun() or {}
    integration_context = demisto.getIntegrationContext() or {}
    params = demisto.params()
    now = datetime.now(UTC)
    now_str = now.strftime(Config.DATE_FORMAT)

    per_type_rows: list[dict[str, Any]] = []
    for log_type in LogType:
        ts = log_type.type_string
        hwm = last_run.get(f"last_fetch_{ts}")
        prev_ids = last_run.get(f"previous_ids_{ts}") or []
        last_exec = last_run.get(f"last_execution_{ts}")
        status = "unset (first run uses first_fetch)"
        if isinstance(hwm, str) and hwm:
            try:
                hwm_dt = datetime.strptime(hwm, Config.DATE_FORMAT).replace(tzinfo=UTC)
                delta_h = (hwm_dt - now).total_seconds() / 3600.0
                status = (
                    f"FUTURE by {delta_h:.1f}h - scheduled fetch returns nothing"
                    if delta_h > 0
                    else f"{abs(delta_h):.1f}h in the past (ok)"
                )
            except ValueError:
                status = "unparseable"
        per_type_rows.append(
            {
                "Log Type": log_type.title,
                "HWM (last_fetch)": hwm or "-",
                "HWM vs now": status,
                "previous_ids": len(prev_ids) if isinstance(prev_ids, list) else "n/a",
                "last_execution": last_exec or "never",
            }
        )

    future = _hwm_future_log_types(last_run, now)
    params_view = {
        "url": params.get("url"),
        "event_types_to_fetch": params.get("event_types_to_fetch"),
        "audit_types_filter": params.get("audit_types_filter") or "(none)",
        "first_fetch": params.get("first_fetch") or "(default)",
        "max_fetch": params.get("max_fetch"),
    }

    md = [
        f"# KOI - Fetch Context (diagnostic)\n"
        f"**now (UTC):** {now_str}  |  **last_execution_time:** {last_run.get('last_execution_time', 'never')}"
    ]
    if future:
        md.append(
            f"> **WARNING - stuck FUTURE high-water-mark for: {', '.join(future)}.** "
            f"The scheduled fetch queries `created_after=<HWM>`; with the HWM ahead of now the KOI API "
            f"returns nothing and `koi_koi_raw` stops updating. Recover with "
            f"`!koi-fetch-context-set clear_future_hwm=true` (or set a specific HWM)."
        )
    md.append(
        tableToMarkdown(
            "High-water-mark state per log type",
            per_type_rows,
            headers=["Log Type", "HWM (last_fetch)", "HWM vs now", "previous_ids", "last_execution"],
        )
    )
    md.append(tableToMarkdown("Fetch parameters", [params_view], headers=list(params_view)))
    md.append("### Raw last_run\n```json\n" + json.dumps(last_run, indent=2, default=str, sort_keys=True) + "\n```")
    if integration_context:
        md.append(
            "### Raw integration_context\n```json\n"
            + json.dumps(integration_context, indent=2, default=str, sort_keys=True)
            + "\n```"
        )

    outputs = {
        "now_utc": now_str,
        "future_hwm_log_types": future,
        "last_run": last_run,
        "integration_context": integration_context,
    }
    return CommandResults(
        readable_output="\n\n".join(md),
        outputs_prefix="KOI.FetchContext",
        outputs=outputs,
        raw_response=outputs,
    )


def koi_fetch_context_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Maintenance: modify the integration's fetch state via ``demisto.setLastRun()``.

    Recovers a stuck high-water-mark without redeploying or using the UI reset.
    At least one action argument is required.

    Args (all optional, but one is required):
        clear_future_hwm: 'true' resets any future ``last_fetch_<type>`` to now.
        last_fetch_alerts: Set the Alerts HWM (ISO 8601 or relative, e.g. "2 days ago").
        last_fetch_audit: Set the Audit HWM (ISO 8601 or relative).
        clear_previous_ids: 'true' clears the cross-cycle dedup sets (previous_ids_*).
        reset_all: 'true' clears the ENTIRE last_run (next fetch uses first_fetch;
            may re-ingest and duplicate the overlap window). Use with caution.
    """
    clear_future = argToBoolean(args.get("clear_future_hwm", "false"))
    clear_prev = argToBoolean(args.get("clear_previous_ids", "false"))
    reset_all = argToBoolean(args.get("reset_all", "false"))
    set_alerts = args.get("last_fetch_alerts")
    set_audit = args.get("last_fetch_audit")

    if not any([clear_future, clear_prev, reset_all, set_alerts, set_audit]):
        raise DemistoException(
            "No action specified. Provide at least one of: clear_future_hwm, "
            "last_fetch_alerts, last_fetch_audit, clear_previous_ids, reset_all."
        )

    before = demisto.getLastRun() or {}
    now = datetime.now(UTC)
    now_str = now.strftime(Config.DATE_FORMAT)
    changes: list[str] = []

    if reset_all:
        after: dict[str, Any] = {}
        changes.append("reset_all: cleared the entire last_run (next fetch uses first_fetch)")
    else:
        after = dict(before)
        if clear_future:
            future = _hwm_future_log_types(before, now)
            for ts in future:
                changes.append(f"clear_future_hwm: last_fetch_{ts} {before.get(f'last_fetch_{ts}')} -> {now_str}")
                after[f"last_fetch_{ts}"] = now_str
            if not future:
                changes.append("clear_future_hwm: no future HWM found (nothing to do)")
        for ts, val in (("alerts", set_alerts), ("audit", set_audit)):
            if val:
                normalized = get_formatted_utc_time(val)
                changes.append(f"set last_fetch_{ts} -> {normalized}")
                after[f"last_fetch_{ts}"] = normalized
        if clear_prev:
            for log_type in LogType:
                key = f"previous_ids_{log_type.type_string}"
                if key in after:
                    after[key] = []
                    changes.append(f"cleared {key}")

    demisto.setLastRun(after)

    md = ["# KOI - Fetch Context updated", "**Changes applied:**"]
    md += [f"- {c}" for c in changes]
    md.append("### last_run before\n```json\n" + json.dumps(before, indent=2, default=str, sort_keys=True) + "\n```")
    md.append("### last_run after\n```json\n" + json.dumps(after, indent=2, default=str, sort_keys=True) + "\n```")
    return CommandResults(
        readable_output="\n\n".join(md),
        outputs_prefix="KOI.FetchContextUpdate",
        outputs={"changes": changes, "last_run_after": after},
        raw_response={"before": before, "after": after, "changes": changes},
    )


# endregion


COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "koi-fetch-context-get": koi_fetch_context_get_command,
    "koi-fetch-context-set": koi_fetch_context_set_command,
    "koi-get-events": get_events_command,
    "fetch-events": fetch_events_command,
    "koi-policy-list": koi_policy_list_command,
    "koi-allowlist-get": koi_allowlist_get_command,
    "koi-allowlist-items-remove": koi_allowlist_items_remove_command,
    "koi-allowlist-items-add": koi_allowlist_items_add_command,
    "koi-blocklist-get": koi_blocklist_get_command,
    "koi-blocklist-items-remove": koi_blocklist_items_remove_command,
    "koi-blocklist-items-add": koi_blocklist_items_add_command,
    "koi-policy-status-update": koi_policy_status_update_command,
    "koi-inventory-list": koi_inventory_list_command,
    "koi-inventory-item-get": koi_inventory_item_get_command,
    "koi-inventory-search": koi_inventory_search_command,
    "koi-inventory-item-endpoints-list": koi_inventory_item_endpoints_list_command,
    # v1.2.0 tier-1 expansion — read-only commands across §2/§4/§5/§6/§7/§9/§11/§13.
    "koi-devices-list": koi_devices_list_command,
    "koi-device-inventory-get": koi_device_inventory_get_command,
    "koi-runtime-policies-list": koi_runtime_policies_list_command,
    "koi-runtime-policy-get": koi_runtime_policy_get_command,
    "koi-findings-list": koi_findings_list_command,
    "koi-approval-requests-list": koi_approval_requests_list_command,
    "koi-remediations-list": koi_remediations_list_command,
    "koi-groups-list": koi_groups_list_command,
    "koi-users-list": koi_users_list_command,
    "koi-koidex-search": koi_koidex_search_command,
    "koi-koidex-risk-report": koi_koidex_risk_report_command,
}


def main() -> None:
    """Main entry point for KOI integration."""
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
        elif command == "koi-get-events":
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
