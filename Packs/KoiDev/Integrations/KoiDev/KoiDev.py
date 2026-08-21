import json
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from enum import Enum
from typing import Any
from collections.abc import Callable

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
INDICATOR_TYPE = "Koi Software Item Dev"

SHA1_RE = re.compile(r'^[A-Fa-f0-9]{40}$')
SHA256_RE = re.compile(r'^[A-Fa-f0-9]{64}$')


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
    AGENT_ACTIVITY_EVENTS = f"{BASE}/agent-activity/events"
    AGENT_ACTIVITY_SESSIONS = f"{BASE}/agent-activity/sessions"
    APPROVAL_REQUESTS = f"{BASE}/approval-requests"
    DEVICES = f"{BASE}/devices"
    FINDINGS = f"{BASE}/findings"
    FINDINGS_CUSTOMIZE_RISK = f"{BASE}/findings/customize-risk"
    GROUPS = f"{BASE}/groups"
    RUNTIME_POLICIES = f"{BASE}/hardening/runtime-policies"
    KOIDEX_FETCH = f"{BASE}/koidex/fetch"
    KOIDEX_RISK_REPORT = f"{BASE}/koidex/risk-report"
    KOIDEX_SEARCH = f"{BASE}/koidex/search"
    PRIVATE_ITEMS = f"{BASE}/private-items"
    REMEDIATIONS = f"{BASE}/remediations"
    REMEDIATIONS_DISMISS = f"{BASE}/remediations/dismiss"
    REPORTS = f"{BASE}/reports"
    USERS = f"{BASE}/users"

    @classmethod
    def policy(cls, policy_id: int) -> str:
        """Return the path for a specific policy by ID."""
        return f"{cls.POLICIES}/{policy_id}"

    @classmethod
    def inventory_item(cls, item_id: str) -> str:
        """Return the path for a specific inventory item by ID."""
        return f"{cls.INVENTORY}/{item_id}"

    @classmethod
    def inventory_item_endpoints(cls, item_id: str) -> str:
        """Return the path for the endpoints of a specific inventory item."""
        return f"{cls.INVENTORY}/{item_id}/endpoints"

    @classmethod
    def approval_request_approve(cls, request_id: str) -> str:
        return f"{cls.APPROVAL_REQUESTS}/{request_id}/approve"

    @classmethod
    def approval_request_reject(cls, request_id: str) -> str:
        return f"{cls.APPROVAL_REQUESTS}/{request_id}/reject"

    @classmethod
    def device(cls, device_id: str) -> str:
        return f"{cls.DEVICES}/{device_id}"

    @classmethod
    def device_archive(cls, device_id: str) -> str:
        return f"{cls.DEVICES}/{device_id}/archive"

    @classmethod
    def device_inventory(cls, device_id: str) -> str:
        return f"{cls.DEVICES}/{device_id}/inventory"

    @classmethod
    def group(cls, group_id: int) -> str:
        return f"{cls.GROUPS}/{group_id}"

    @classmethod
    def group_device(cls, group_id: int, device_id: str) -> str:
        return f"{cls.GROUPS}/{group_id}/devices/{device_id}"

    @classmethod
    def runtime_policy(cls, policy_id: str) -> str:
        return f"{cls.RUNTIME_POLICIES}/{policy_id}"

    @classmethod
    def private_item(cls, item_id: str) -> str:
        return f"{cls.PRIVATE_ITEMS}/{item_id}"

    @classmethod
    def report(cls, report_id: str) -> str:
        return f"{cls.REPORTS}/{report_id}"

    @classmethod
    def user(cls, user_id: str) -> str:
        return f"{cls.USERS}/{user_id}"


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
    DEFAULT_FROM_TIME = "5 minutes ago"

    # API sort direction for chronological ordering
    SORT_DIRECTION = "asc"

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 5
    TEST_MODULE_MAX_EVENTS = 1


class LogType(Enum):
    """Enum to hold all configuration for different log types."""

    ALERTS = ("alerts", "Alerts", ApiPaths.ALERTS, "alerts")
    AUDIT = ("audit", "Audit", ApiPaths.AUDIT_LOGS, "items")

    def __init__(self, type_string: str, title: str, api_endpoint: str, response_key: str):
        self.type_string = type_string
        self.title = title
        self.api_endpoint = api_endpoint
        self.response_key = response_key


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
    "binaries",
    "bitbucket",
    "chocolatey",
    "chrome_web_store",
    "claude_desktop_extensions",
    "cursor",
    "docker",
    "edge_add_ons",
    "firefox_add_ons",
    "github",
    "github_mcp_registry",
    "gitlab",
    "homebrew",
    "hugging_face",
    "jetbrains",
    "linux",
    "mac",
    "mcp_registry",
    "notepad++",
    "npm",
    "office_add_ins",
    "ollama",
    "open_vsx_registry",
    "pypi",
    "skill",
    "visual_studio",
    "vscode",
    "windows",
    "windsurf",
]

VALID_PLATFORMS = [
    "antigravity",
    "aqua",
    "arc",
    "brave",
    "brew",
    "chatgpt_atlas",
    "chocolatey",
    "chrome",
    "chromium",
    "claude",
    "claude_code",
    "claude_desktop",
    "clion",
    "codex",
    "comet",
    "cursor",
    "datagrip",
    "dataspell",
    "dia",
    "edge",
    "excel",
    "firefox",
    "fleet",
    "goland",
    "hugging_face",
    "ollama",
    "intellij_community",
    "intellij",
    "kiro",
    "mac",
    "npm",
    "notepad++",
    "opera",
    "outlook",
    "phpstorm",
    "powerpoint",
    "prisma_access_browser",
    "pycharm",
    "pypi",
    "rider",
    "rubymine",
    "rustrover",
    "vscode",
    "webstorm",
    "windsurf",
    "word",
    "windows",
    "writerside",
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
            f"Invalid event type(s) provided: {invalid_types}. Please select from the following list: {valid_options}"
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
                f"Invalid filter JSON structure in entry ID '{entry_id}': expected a dictionary, got {type(data).__name__}."
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


def _validate_pagination_args(page_size: int, limit_arg: int | None) -> None:
    """Validate page_size and limit against configured maximums."""
    if page_size > Config.MAX_PAGE_SIZE:
        raise DemistoException(f"page_size ({page_size}) exceeds the maximum allowed value of {Config.MAX_PAGE_SIZE}.")
    if limit_arg and limit_arg > Config.MAX_LIMIT:
        raise DemistoException(f"limit ({limit_arg}) exceeds the maximum allowed value of {Config.MAX_LIMIT}.")


def koi_risk_to_dbot_score(risk_score: float | None, risk_level: str | None) -> int:
    """Map Koi risk score (0-10) to DBot score (0-3).

    Koi risk levels: Low (1-3), Medium (4-6), High (7-9), Critical (10).
    DBot scores: 0=Unknown, 1=Good, 2=Suspicious, 3=Malicious.
    """
    if risk_score is None and risk_level is None:
        return Common.DBotScore.NONE
    if risk_level == "pending":
        return Common.DBotScore.NONE
    if risk_score is not None:
        if risk_score <= 3:
            return Common.DBotScore.GOOD
        if risk_score <= 6:
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.BAD
    level_map = {"low": Common.DBotScore.GOOD, "medium": Common.DBotScore.SUSPICIOUS,
                 "high": Common.DBotScore.BAD, "critical": Common.DBotScore.BAD}
    return level_map.get(risk_level, Common.DBotScore.NONE)


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

        events = response.get(log_type.response_key, [])
        demisto.debug(f"[API Fetch] {log_type.type_string} | Page {page}: {len(events)} events returned")

        return events

    def get_alerts(
        self,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        alert_type: str | None = None,
        created_at_gte: str | None = None,
        created_at_lte: str | None = None,
        event_id: str | None = None,
        sort_direction: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            alert_type=alert_type,
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
            event_id=event_id,
            sort_direction=sort_direction,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.ALERTS, params=params)

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

    # --- Agent Activity ---

    def get_agent_activity_events(
        self,
        created_at_gte: str,
        created_at_lte: str,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            session_id=session_id,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.AGENT_ACTIVITY_EVENTS, params=params)

    def get_agent_activity_sessions(
        self,
        created_at_gte: str,
        created_at_lte: str,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        **kwargs: Any,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            **kwargs,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.AGENT_ACTIVITY_SESSIONS, params=params)

    # --- Approval Requests ---

    def get_approval_requests(
        self,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        approval_status: str | None = None,
        marketplace: str | None = None,
        requested_by: str | None = None,
        created_at_gte: str | None = None,
        created_at_lte: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            approval_status=approval_status,
            marketplace=marketplace,
            requested_by=requested_by,
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.APPROVAL_REQUESTS, params=params)

    def create_approval_request(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(method="POST", url_suffix=ApiPaths.APPROVAL_REQUESTS, json_data=body)

    def approve_approval_request(self, request_id: str, approved_by: str | None = None) -> None:
        body: dict[str, Any] = assign_params(approved_by=approved_by)
        self._http_request(
            method="POST",
            url_suffix=ApiPaths.approval_request_approve(request_id),
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

    def reject_approval_request(self, request_id: str, rejected_by: str | None = None, reason: str | None = None) -> None:
        body: dict[str, Any] = assign_params(rejected_by=rejected_by, reason=reason)
        self._http_request(
            method="POST",
            url_suffix=ApiPaths.approval_request_reject(request_id),
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

    # --- Devices ---

    def get_devices(
        self,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        status: str | None = None,
        last_seen_gte: str | None = None,
        last_seen_lte: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            status=status,
            last_seen_gte=last_seen_gte,
            last_seen_lte=last_seen_lte,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.DEVICES, params=params)

    def archive_device(self, device_id: str, archived_by_user_email: str) -> None:
        body: dict[str, Any] = {"archived_by_user_email": archived_by_user_email}
        self._http_request(
            method="POST",
            url_suffix=ApiPaths.device_archive(device_id),
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

    def get_device_inventory(
        self,
        device_id: str,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            finding_id=finding_id,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.device_inventory(device_id), params=params)

    # --- Findings ---

    def get_findings(self, page: int = 1, page_size: int = Config.DEFAULT_PAGE_SIZE) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "page_size": min(page_size, Config.MAX_PAGE_SIZE)}
        return self._http_request(method="GET", url_suffix=ApiPaths.FINDINGS, params=params)

    def customize_finding_risk(self, finding_id: str, risk: int) -> None:
        body: dict[str, Any] = {"finding_id": finding_id, "risk": risk}
        self._http_request(
            method="POST",
            url_suffix=ApiPaths.FINDINGS_CUSTOMIZE_RISK,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

    # --- Groups ---

    def get_groups(self, page: int = 1, page_size: int = Config.DEFAULT_PAGE_SIZE) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "page_size": min(page_size, Config.MAX_PAGE_SIZE)}
        return self._http_request(method="GET", url_suffix=ApiPaths.GROUPS, params=params)

    def create_groups(self, groups: list[dict[str, Any]], creator: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"groups": groups}
        if creator:
            body["creator"] = creator
        return self._http_request(method="POST", url_suffix=ApiPaths.GROUPS, json_data=body)

    def update_group(self, group_id: int, name: str) -> None:
        body: dict[str, Any] = {"name": name}
        self._http_request(
            method="PUT",
            url_suffix=ApiPaths.group(group_id),
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

    def add_device_to_group(self, group_id: int, device_id: str) -> None:
        self._http_request(
            method="POST",
            url_suffix=ApiPaths.group_device(group_id, device_id),
            resp_type="response",
            ok_codes=(204,),
        )

    def remove_device_from_group(self, group_id: int, device_id: str) -> None:
        self._http_request(
            method="DELETE",
            url_suffix=ApiPaths.group_device(group_id, device_id),
            resp_type="response",
            ok_codes=(204,),
        )

    # --- Runtime Policies ---

    def get_runtime_policies(self, page: int = 1, page_size: int = Config.DEFAULT_PAGE_SIZE) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "page_size": min(page_size, Config.MAX_PAGE_SIZE)}
        return self._http_request(method="GET", url_suffix=ApiPaths.RUNTIME_POLICIES, params=params)

    def create_runtime_policy(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(method="POST", url_suffix=ApiPaths.RUNTIME_POLICIES, json_data=body)

    def get_runtime_policy(self, policy_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=ApiPaths.runtime_policy(policy_id))

    def update_runtime_policy(self, policy_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(method="PUT", url_suffix=ApiPaths.runtime_policy(policy_id), json_data=body)

    def delete_runtime_policy(self, policy_id: str) -> None:
        self._http_request(
            method="DELETE",
            url_suffix=ApiPaths.runtime_policy(policy_id),
            resp_type="response",
            ok_codes=(204,),
        )

    # --- Koidex ---

    def koidex_fetch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        body: dict[str, Any] = {"items": items}
        return self._http_request(method="POST", url_suffix=ApiPaths.KOIDEX_FETCH, json_data=body)

    def get_koidex_risk_report(self, item_id: str, marketplace: str, version: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(item_id=item_id, marketplace=marketplace, version=version)
        return self._http_request(method="GET", url_suffix=ApiPaths.KOIDEX_RISK_REPORT, params=params)

    def search_koidex(
        self,
        marketplace: str,
        search_term: str,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "marketplace": marketplace,
            "search_term": search_term,
            "page": page,
            "page_size": min(page_size, Config.MAX_PAGE_SIZE),
        }
        return self._http_request(method="GET", url_suffix=ApiPaths.KOIDEX_SEARCH, params=params)

    # --- Private Items ---

    def get_private_items(self) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=ApiPaths.PRIVATE_ITEMS)

    def upload_private_item(self, file_data: bytes, file_name: str, created_by: str, marketplace: str) -> dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix=ApiPaths.PRIVATE_ITEMS,
            files={"item": (file_name, file_data)},
            data={"created_by": created_by, "marketplace": marketplace},
        )

    def get_private_item_details(self, item_id: str, version: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(version=version)
        return self._http_request(method="GET", url_suffix=ApiPaths.private_item(item_id), params=params)

    # --- Remediations ---

    def get_remediations(
        self,
        page: int = 1,
        page_size: int = Config.DEFAULT_PAGE_SIZE,
        **kwargs: Any,
    ) -> dict[str, Any]:
        params: dict[str, Any] = assign_params(
            page=page,
            page_size=min(page_size, Config.MAX_PAGE_SIZE),
            **kwargs,
        )
        return self._http_request(method="GET", url_suffix=ApiPaths.REMEDIATIONS, params=params)

    def submit_remediations(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        body: dict[str, Any] = {"items": items}
        return self._http_request(method="POST", url_suffix=ApiPaths.REMEDIATIONS, json_data=body)

    def dismiss_remediations(self, items: list[dict[str, Any]], dismissed_by: str | None = None) -> None:
        body: dict[str, Any] = {"items": items}
        if dismissed_by:
            body["dismissed_by"] = dismissed_by
        self._http_request(
            method="POST",
            url_suffix=ApiPaths.REMEDIATIONS_DISMISS,
            json_data=body,
            resp_type="response",
            ok_codes=(204,),
        )

    # --- Reports ---

    def create_report(self, report_type: str, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"report_type": report_type}
        if filters:
            body["filters"] = filters
        return self._http_request(method="POST", url_suffix=ApiPaths.REPORTS, json_data=body)

    def get_report_status(self, report_id: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=ApiPaths.report(report_id))

    # --- Users ---

    def get_users(self) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=ApiPaths.USERS)

    def create_user(self, email: str, role: str) -> dict[str, Any]:
        body: dict[str, Any] = {"email": email, "role": role}
        return self._http_request(method="POST", url_suffix=ApiPaths.USERS, json_data=body)

    def delete_user(self, user_id: str) -> None:
        self._http_request(
            method="DELETE",
            url_suffix=ApiPaths.user(user_id),
            resp_type="response",
            ok_codes=(204,),
        )

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
        outputs_prefix="KoiDev.Event",
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
            demisto.debug(f"[Fetch] {log_type.type_string}: Continuing from {time_input}. Prev ID count: {len(last_fetched_ids)}")
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

    _validate_pagination_args(page_size, limit_arg)

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
        policies = _paginate_generic(
            lambda p, ps: client.get_policies(page=p, page_size=ps),
            limit=limit,
            items_key="policies",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Policies",
        policies,
        headers=["id", "name", "description", "action", "enabled", "group_ids", "creator_fullname", "created_at", "updated_at"],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="KoiDev.Policy",
        outputs_key_field="id",
        outputs=policies,
    )


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
        outputs_prefix="KoiDev.Allowlist",
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
        outputs_prefix="KoiDev.Blocklist",
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
        outputs_prefix="KoiDev.Policy",
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

    _validate_pagination_args(page_size, limit_arg)

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
        items = _paginate_generic(
            lambda p, ps: client.get_inventory(page=p, page_size=ps, **filter_kwargs),
            limit=limit,
            items_key="items",
        )

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
        outputs_prefix="KoiDev.Inventory",
        outputs_key_field="item_id",
        outputs=items,
    )


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
        outputs_prefix="KoiDev.Inventory",
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

    _validate_pagination_args(page_size, limit_arg)

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
        items = _paginate_generic(
            lambda p, ps: client.search_inventory(
                page=p, page_size=ps, filter_obj=filter_obj, sort_by=sort_by, sort_direction=sort_direction
            ),
            limit=limit,
            items_key="items",
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
        outputs_prefix="KoiDev.Inventory",
        outputs_key_field="item_id",
        outputs=items,
    )


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

    _validate_pagination_args(page_size, limit_arg)

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
        endpoints = _paginate_generic(
            lambda p, ps: client.get_inventory_item_endpoints(
                item_id=item_id, marketplace=marketplace, version=version, page=p, page_size=ps
            ),
            limit=limit,
            items_key="endpoints",
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
        outputs_prefix="KoiDev.Inventory.Endpoint",
        outputs_key_field="id",
        outputs=endpoints,
    )


# --- Agent Activity Commands ---


def koi_agent_activity_events_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-agent-activity-events-list triggered")

    created_at_gte = get_formatted_utc_time(args["created_at_gte"])
    created_at_lte = get_formatted_utc_time(args["created_at_lte"])
    session_id = args.get("session_id")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_agent_activity_events(
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
            page=page_arg,
            page_size=page_size,
            session_id=session_id,
        )
        items = response.get("data", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_agent_activity_events(
                created_at_gte=created_at_gte,
                created_at_lte=created_at_lte,
                page=p,
                page_size=ps,
                session_id=session_id,
            ),
            limit=limit,
            items_key="data",
        )

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Agent Activity Events", items, headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.AgentActivityEvent", outputs_key_field="id", outputs=items
    )


def koi_agent_activity_sessions_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-agent-activity-sessions-list triggered")

    created_at_gte = get_formatted_utc_time(args["created_at_gte"])
    created_at_lte = get_formatted_utc_time(args["created_at_lte"])

    filter_kwargs = assign_params(
        agent=args.get("agent"),
        host=args.get("host"),
        model=args.get("model"),
        user_email=args.get("user_email"),
        verdict=args.get("verdict"),
        mcp=args.get("mcp"),
        skill=args.get("skill"),
        action=args.get("action"),
        governed_by=args.get("governed_by"),
        filter=args.get("filter"),
        sort_by=args.get("sort_by"),
        sort_direction=args.get("sort_direction"),
    )

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_agent_activity_sessions(
            created_at_gte=created_at_gte,
            created_at_lte=created_at_lte,
            page=page_arg,
            page_size=page_size,
            **filter_kwargs,
        )
        items = response.get("data", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_agent_activity_sessions(
                created_at_gte=created_at_gte,
                created_at_lte=created_at_lte,
                page=p,
                page_size=ps,
                **filter_kwargs,
            ),
            limit=limit,
            items_key="data",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Agent Activity Sessions", items, headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.AgentActivitySession", outputs_key_field="id", outputs=items
    )


# --- Approval Request Commands ---


def koi_approval_request_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-approval-request-list triggered")

    filter_kwargs = assign_params(
        approval_status=args.get("approval_status"),
        marketplace=args.get("marketplace"),
        requested_by=args.get("requested_by"),
        created_at_gte=get_formatted_utc_time(args["created_at_gte"]) if args.get("created_at_gte") else None,
        created_at_lte=get_formatted_utc_time(args["created_at_lte"]) if args.get("created_at_lte") else None,
    )

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_approval_requests(page=page_arg, page_size=page_size, **filter_kwargs)
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_approval_requests(page=p, page_size=ps, **filter_kwargs),
            limit=limit,
            items_key="items",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Approval Requests",
        items,
        headers=[
            "id",
            "item_id",
            "name",
            "marketplace",
            "platform",
            "approval_status",
            "requested_by",
            "justification",
            "reject_reason",
            "created_at",
            "updated_at",
            "resolved_at",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.ApprovalRequest", outputs_key_field="id", outputs=items
    )


def koi_approval_request_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-approval-request-create triggered")

    body: dict[str, Any] = {
        "item_id": args["item_id"],
        "marketplace": args["marketplace"],
        "platform": args["platform"],
        "justification": args["justification"],
        "requested_by": args["requested_by"],
    }
    if args.get("version"):
        body["version"] = args["version"]

    response = client.create_approval_request(body)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Approval Request Created",
        response,
        headers=["id", "item_id", "name", "marketplace", "platform", "approval_status", "requested_by", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.ApprovalRequest", outputs_key_field="id", outputs=response
    )


def koi_approval_request_approve_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-approval-request-approve triggered")
    request_id = args["approval_request_id"]
    client.approve_approval_request(request_id, approved_by=args.get("approved_by"))
    return CommandResults(readable_output=f"Approval request '{request_id}' was approved successfully.")


def koi_approval_request_reject_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-approval-request-reject triggered")
    request_id = args["approval_request_id"]
    client.reject_approval_request(request_id, rejected_by=args.get("rejected_by"), reason=args.get("reason"))
    return CommandResults(readable_output=f"Approval request '{request_id}' was rejected successfully.")


# --- Device Commands ---


def koi_device_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-device-list triggered")

    filter_kwargs = assign_params(
        status=args.get("status"),
        last_seen_gte=get_formatted_utc_time(args["last_seen_gte"]) if args.get("last_seen_gte") else None,
        last_seen_lte=get_formatted_utc_time(args["last_seen_lte"]) if args.get("last_seen_lte") else None,
    )

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_devices(page=page_arg, page_size=page_size, **filter_kwargs)
        items = response.get("devices", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_devices(page=p, page_size=ps, **filter_kwargs),
            limit=limit,
            items_key="devices",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Devices",
        items,
        headers=["id", "hostname", "os", "platform", "status", "last_seen", "serial"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.Device", outputs_key_field="id", outputs=items)


def koi_device_archive_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-device-archive triggered")
    device_id = args["device_id"]
    client.archive_device(device_id, archived_by_user_email=args["archived_by_user_email"])
    return CommandResults(readable_output=f"Device '{device_id}' was archived successfully.")


def koi_device_inventory_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-device-inventory-get triggered")

    device_id = args["device_id"]
    finding_id = args.get("finding_id")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_device_inventory(device_id=device_id, page=page_arg, page_size=page_size, finding_id=finding_id)
        items = response.get("inventory", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_device_inventory(device_id=device_id, page=p, page_size=ps, finding_id=finding_id),
            limit=limit,
            items_key="inventory",
        )

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Device Inventory", items, headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.DeviceInventory", outputs_key_field="item_id", outputs=items
    )


# --- Finding Commands ---


def koi_finding_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-finding-list triggered")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_findings(page=page_arg, page_size=page_size)
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_findings(page=p, page_size=ps),
            limit=limit,
            items_key="items",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Findings",
        items,
        headers=["id", "name", "description", "risk"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.Finding", outputs_key_field="id", outputs=items)


def koi_finding_customize_risk_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-finding-customize-risk triggered")
    finding_id = args["finding_id"]
    risk = arg_to_number(args["risk"])
    if risk is None or risk < 0 or risk > 10:
        raise DemistoException("risk must be an integer between 0 and 10.")
    client.customize_finding_risk(finding_id=finding_id, risk=risk)
    return CommandResults(readable_output=f"Finding '{finding_id}' risk level was updated to {risk}.")


# --- Group Commands ---


def koi_group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-group-list triggered")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_groups(page=page_arg, page_size=page_size)
        groups = response.get("groups", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        groups = _paginate_generic(
            lambda p, ps: client.get_groups(page=p, page_size=ps),
            limit=limit,
            items_key="groups",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Groups",
        groups,
        headers=["id", "name", "created_at", "devices"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.Group", outputs_key_field="id", outputs=groups)


def koi_group_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-group-create triggered")

    name = args["name"]
    device_ids = argToList(args.get("device_ids"))
    creator = args.get("creator")

    group_input: dict[str, Any] = {"name": name}
    if device_ids:
        group_input["device_ids"] = device_ids

    response = client.create_groups(groups=[group_input], creator=creator)
    groups = response.get("groups", [])

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Group Created",
        groups,
        headers=["id", "name", "created_at", "devices"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.Group", outputs_key_field="id", outputs=groups)


def koi_group_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-group-update triggered")
    group_id = arg_to_number(args["group_id"])
    if group_id is None:
        raise DemistoException("group_id is required and must be a valid integer.")
    name = args["name"]
    client.update_group(group_id=group_id, name=name)
    return CommandResults(readable_output=f"Group {group_id} was renamed to '{name}' successfully.")


def koi_group_device_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-group-device-add triggered")
    group_id = arg_to_number(args["group_id"])
    if group_id is None:
        raise DemistoException("group_id is required and must be a valid integer.")
    device_id = args["device_id"]
    client.add_device_to_group(group_id=group_id, device_id=device_id)
    return CommandResults(readable_output=f"Device '{device_id}' was added to group {group_id} successfully.")


def koi_group_device_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-group-device-remove triggered")
    group_id = arg_to_number(args["group_id"])
    if group_id is None:
        raise DemistoException("group_id is required and must be a valid integer.")
    device_id = args["device_id"]
    client.remove_device_from_group(group_id=group_id, device_id=device_id)
    return CommandResults(readable_output=f"Device '{device_id}' was removed from group {group_id} successfully.")


# --- Runtime Policy Commands ---


def koi_runtime_policy_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-runtime-policy-list triggered")

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_runtime_policies(page=page_arg, page_size=page_size)
        items = response.get("policies", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_runtime_policies(page=p, page_size=ps),
            limit=limit,
            items_key="policies",
        )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Runtime Policies",
        items,
        headers=[
            "id",
            "display_name",
            "description",
            "enforcement_mode",
            "enabled",
            "agents",
            "rules",
            "group_ids",
            "created_at",
            "updated_at",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.RuntimePolicy", outputs_key_field="id", outputs=items
    )


def koi_runtime_policy_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-runtime-policy-create triggered")

    body: dict[str, Any] = {
        "display_name": args["display_name"],
        "enforcement_mode": args["enforcement_mode"],
        "agents": argToList(args["agents"]),
        "rules": json.loads(args["rules"]) if isinstance(args.get("rules"), str) else args.get("rules", []),
        "enabled": argToBoolean(args.get("enabled", "true")),
    }
    if args.get("description"):
        body["description"] = args["description"]
    if args.get("group_ids"):
        body["group_ids"] = [int(gid) for gid in argToList(args["group_ids"])]

    response = client.create_runtime_policy(body)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Runtime Policy Created",
        response,
        headers=["id", "display_name", "enforcement_mode", "enabled", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.RuntimePolicy", outputs_key_field="id", outputs=response
    )


def koi_runtime_policy_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-runtime-policy-get triggered")
    policy_id = args["policy_id"]
    response = client.get_runtime_policy(policy_id)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Runtime Policy",
        response,
        headers=[
            "id",
            "display_name",
            "description",
            "enforcement_mode",
            "enabled",
            "agents",
            "rules",
            "group_ids",
            "created_at",
            "updated_at",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.RuntimePolicy", outputs_key_field="id", outputs=response
    )


def koi_runtime_policy_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-runtime-policy-update triggered")

    policy_id = args["policy_id"]
    body: dict[str, Any] = {}
    if args.get("display_name"):
        body["display_name"] = args["display_name"]
    if args.get("enforcement_mode"):
        body["enforcement_mode"] = args["enforcement_mode"]
    if args.get("agents"):
        body["agents"] = argToList(args["agents"])
    if args.get("rules"):
        body["rules"] = json.loads(args["rules"]) if isinstance(args["rules"], str) else args["rules"]
    if args.get("enabled") is not None:
        body["enabled"] = argToBoolean(args["enabled"])
    if args.get("description"):
        body["description"] = args["description"]
    if args.get("group_ids"):
        body["group_ids"] = [int(gid) for gid in argToList(args["group_ids"])]

    response = client.update_runtime_policy(policy_id, body)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Runtime Policy Updated",
        response,
        headers=["id", "display_name", "enforcement_mode", "enabled", "updated_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.RuntimePolicy", outputs_key_field="id", outputs=response
    )


def koi_runtime_policy_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-runtime-policy-delete triggered")
    policy_id = args["policy_id"]
    client.delete_runtime_policy(policy_id)
    return CommandResults(readable_output=f"Runtime policy '{policy_id}' was deleted successfully.")


# --- Koidex Commands ---


def _parse_items_arg(args: dict[str, Any]) -> list:
    """Parse and validate the 'items' JSON array argument."""
    items_json = args.get("items")
    if not items_json:
        raise DemistoException("The 'items' argument is required and must be a JSON array.")
    if isinstance(items_json, str):
        items = json.loads(items_json)
    else:
        items = items_json
    if not isinstance(items, list):
        raise DemistoException(f"The 'items' argument must be a JSON array, got {type(items).__name__}.")
    return items


def koi_koidex_fetch_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-koidex-fetch triggered")

    items = _parse_items_arg(args)

    response = client.koidex_fetch(items)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Koidex Fetch Triggered", response, headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.KoidexFetch", outputs_key_field="id", outputs=response
    )


def koi_koidex_risk_report_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-koidex-risk-report-get triggered")

    response = client.get_koidex_risk_report(
        item_id=args["item_id"],
        marketplace=args["marketplace"],
        version=args.get("version"),
    )

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Koidex Risk Report", response, headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.KoidexRiskReport", outputs_key_field="item_id", outputs=response
    )


def koi_koidex_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-koidex-search triggered")

    marketplace = args["marketplace"]
    search_term = args["search_term"]

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.search_koidex(marketplace=marketplace, search_term=search_term, page=page_arg, page_size=page_size)
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.search_koidex(marketplace=marketplace, search_term=search_term, page=p, page_size=ps),
            limit=limit,
            items_key="items",
        )

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Koidex Search Results", items, headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.KoidexSearch", outputs_key_field="item_id", outputs=items
    )


# --- Private Item Commands ---


def koi_private_item_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-private-item-list triggered")

    response = client.get_private_items()
    items = response.get("items", []) if isinstance(response, dict) else response

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Private Items", items, headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.PrivateItem", outputs_key_field="id", outputs=items
    )


def koi_private_item_upload_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-private-item-upload triggered")

    entry_id = args["entry_id"]
    created_by = args["created_by"]
    marketplace = args["marketplace"]

    file_result = demisto.getFilePath(entry_id)
    file_path = file_result["path"]
    file_name = file_result["name"]

    with open(file_path, "rb") as f:
        file_data = f.read()

    response = client.upload_private_item(
        file_data=file_data, file_name=file_name, created_by=created_by, marketplace=marketplace
    )

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Private Item Uploaded", response, headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.PrivateItem", outputs_key_field="id", outputs=response
    )


def koi_private_item_details_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-private-item-details-get triggered")

    item_id = args["item_id"]
    version = args.get("version")
    response = client.get_private_item_details(item_id=item_id, version=version)

    overview = response.get("overview", {})
    extension = overview.get("extension", {})
    findings = overview.get("findings", [])
    vulnerabilities_data = response.get("vulnerabilities", {})
    vulns = vulnerabilities_data.get("vulnerabilities", []) if isinstance(vulnerabilities_data, dict) else []
    secrets_data = response.get("secrets", {})
    secrets = secrets_data.get("secrets", []) if isinstance(secrets_data, dict) else []
    ext_comms = response.get("externalCommunication", {})
    domains = ext_comms.get("domains", []) if isinstance(ext_comms, dict) else []
    code_analysis = response.get("codeAnalysis", {})
    safer_alts = response.get("saferAlternatives", [])

    overview_row = {
        "item_id": extension.get("extensionId", item_id),
        "display_name": extension.get("displayName"),
        "version": extension.get("version"),
        "marketplace": extension.get("marketplace"),
        "publisher": extension.get("publisherName"),
        "risk_level": extension.get("riskLevel"),
        "risk_score": extension.get("riskScore"),
        "installs": extension.get("installs"),
    }
    overview_table = tableToMarkdown(
        f"{INTEGRATION_NAME} Private Item Overview", overview_row,
        headers=["item_id", "display_name", "version", "marketplace", "publisher",
                 "risk_level", "risk_score", "installs"],
        headerTransform=string_to_table_header,
    )

    findings_table = tableToMarkdown(
        "Security Findings", findings,
        headers=["name", "category", "riskLevel", "description"],
        headerTransform=string_to_table_header,
    ) if findings else ""

    vuln_table = tableToMarkdown(
        "Vulnerabilities", vulns,
        headers=["cve", "packageName", "packageVersion", "cvssScore"],
        headerTransform=string_to_table_header,
    ) if vulns else ""

    secrets_table = tableToMarkdown(
        "Hardcoded Secrets", secrets,
        headers=["name", "path", "verified"],
        headerTransform=string_to_table_header,
    ) if secrets else ""

    domains_table = tableToMarkdown(
        "External Domains", domains[:20],
        headers=["domain", "path"],
        headerTransform=string_to_table_header,
    ) if domains else ""

    insights = code_analysis.get("insights") if isinstance(code_analysis, dict) else None
    insights_section = f"\n\n### Code Analysis Insights\n{insights}" if insights else ""

    alts_table = tableToMarkdown(
        "Safer Alternatives", safer_alts,
        headers=["displayName", "marketplace", "riskLevel"],
        headerTransform=string_to_table_header,
    ) if safer_alts else ""

    sections = [overview_table, findings_table, vuln_table, secrets_table,
                domains_table, insights_section, alts_table]
    readable_output = "\n\n".join(s for s in sections if s)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="KoiDev.PrivateItem",
        outputs_key_field="overview.extension.extensionId",
        outputs=response,
    )


# --- Remediation Commands ---


def koi_remediation_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-remediation-list triggered")

    filter_kwargs = assign_params(
        hostname=args.get("hostname"),
        platform=args.get("platform"),
        risk_level=args.get("risk_level"),
        status=args.get("status"),
        reason=args.get("reason"),
        sort_by=args.get("sort_by"),
        sort_direction=args.get("sort_direction"),
    )

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_remediations(page=page_arg, page_size=page_size, **filter_kwargs)
        items = response.get("items", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        items = _paginate_generic(
            lambda p, ps: client.get_remediations(page=p, page_size=ps, **filter_kwargs),
            limit=limit,
            items_key="items",
        )

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Remediations", items, headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.Remediation", outputs_key_field="id", outputs=items
    )


def koi_remediation_submit_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-remediation-submit triggered")

    items = _parse_items_arg(args)

    response = client.submit_remediations(items)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Remediation Submitted", response, headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output, outputs_prefix="KoiDev.Remediation", outputs_key_field="id", outputs=response
    )


def koi_remediation_dismiss_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-remediation-dismiss triggered")

    items = _parse_items_arg(args)

    dismissed_by = args.get("dismissed_by")
    client.dismiss_remediations(items, dismissed_by=dismissed_by)
    return CommandResults(readable_output=f"{len(items)} remediation(s) were dismissed successfully.")


# --- Report Commands ---


def koi_report_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-report-create triggered")

    report_type = args["report_type"]
    filters_raw = args.get("filters")
    filters = json.loads(filters_raw) if isinstance(filters_raw, str) else filters_raw

    response = client.create_report(report_type=report_type, filters=filters)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Report Created",
        response,
        headers=["id", "report_type", "status"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.Report", outputs_key_field="id", outputs=response)


def koi_report_status_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-report-status-get triggered")

    report_id = args["report_id"]
    response = client.get_report_status(report_id)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Report Status",
        response,
        headers=["id", "report_type", "status", "download_url", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.Report", outputs_key_field="id", outputs=response)


# --- User Commands ---


def koi_user_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-user-list triggered")

    response = client.get_users()
    users = response.get("users", []) if isinstance(response, dict) else response

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Users",
        users,
        headers=["id", "email", "role", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.User", outputs_key_field="id", outputs=users)


def koi_user_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-user-create triggered")

    response = client.create_user(email=args["email"], role=args["role"])

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} User Created",
        response,
        headers=["id", "email", "role", "created_at"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output, outputs_prefix="KoiDev.User", outputs_key_field="id", outputs=response)


def koi_user_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-user-delete triggered")
    user_id = args["user_id"]
    client.delete_user(user_id)
    return CommandResults(readable_output=f"User '{user_id}' was deleted successfully.")


# --- Generic Pagination Helper ---


def _paginate_generic(
    fetch_fn: Callable[[int, int], dict[str, Any]],
    limit: int,
    items_key: str = "items",
    page_size: int = Config.MAX_PAGE_SIZE,
) -> list[dict]:
    items: list[dict] = []
    page = Config.DEFAULT_PAGE

    while len(items) < limit:
        response = fetch_fn(page, page_size)
        page_items = response.get(items_key, [])

        if not page_items:
            break

        items.extend(page_items)

        if len(page_items) < page_size:
            break

        page += 1

    if len(items) > limit:
        items = items[:limit]

    return items


# --- Alert Commands ---


def koi_alert_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    demisto.debug("[Command] koi-alert-list triggered")

    filter_kwargs = assign_params(
        alert_type=args.get("alert_type"),
        created_at_gte=get_formatted_utc_time(args["created_at_gte"]) if args.get("created_at_gte") else None,
        created_at_lte=get_formatted_utc_time(args["created_at_lte"]) if args.get("created_at_lte") else None,
        event_id=args.get("event_id"),
        sort_direction=args.get("sort_direction"),
    )

    page_arg = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size")) or Config.DEFAULT_PAGE_SIZE
    limit_arg = arg_to_number(args.get("limit"))
    _validate_pagination_args(page_size, limit_arg)

    if page_arg:
        response = client.get_alerts(page=page_arg, page_size=page_size, **filter_kwargs)
        demisto.debug(f"[Command] koi-alert-list raw response keys: {list(response.keys())}, "
                      f"total_count: {response.get('total_count')}, alerts count: {len(response.get('alerts', []))}")
        alerts = response.get("alerts", [])
    else:
        limit = limit_arg or Config.DEFAULT_LIMIT
        alerts = _paginate_generic(
            lambda p, ps: client.get_alerts(page=p, page_size=ps, **filter_kwargs),
            limit=limit,
            items_key="alerts",
        )
        demisto.debug(f"[Command] koi-alert-list auto-paginated {len(alerts)} alerts")

    display_rows = []
    for alert in alerts:
        finding_info = alert.get("finding_info", {})
        metadata = alert.get("metadata", {})
        resources = alert.get("resources", [])
        item_resource = next((r for r in resources if r.get("type") == "item"), None)
        device_resource = next((r for r in resources if r.get("type") == "device"), None)

        row = {
            "notification_event_id": metadata.get("notification_event_id"),
            "title": finding_info.get("title"),
            "type": ", ".join(finding_info.get("types", [])),
            "severity": alert.get("severity"),
            "risk_level": alert.get("risk_level"),
            "risk_score": alert.get("risk_score"),
            "status": alert.get("status"),
            "confidence": alert.get("confidence"),
            "message": alert.get("message"),
            "item_name": item_resource.get("name") if item_resource else None,
            "item_uid": item_resource.get("uid") if item_resource else None,
            "device_name": device_resource.get("name") if device_resource else None,
            "time": datetime.fromtimestamp(alert["time"] / 1000, tz=UTC).strftime(Config.DATE_FORMAT) if alert.get("time") else None,
        }
        display_rows.append(row)

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Alerts",
        display_rows,
        headers=["notification_event_id", "title", "type", "severity", "risk_level", "risk_score",
                 "status", "item_name", "device_name", "time", "message"],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="KoiDev.Alert",
        outputs_key_field="metadata.notification_event_id",
        outputs=alerts,
    )


# --- Enrichment Commands ---


def koi_item_enrich_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    demisto.debug("[Command] koi-item-enrich triggered")

    item_id = args["item_id"]
    marketplace = args["marketplace"]
    version = args.get("version")

    response = client.get_koidex_risk_report(
        item_id=item_id, marketplace=marketplace, version=version
    )

    risk_score = response.get("risk")
    risk_level = response.get("risk_level")
    indicator_value = f"{item_id}:{marketplace}"

    dbot_score = Common.DBotScore(
        indicator=indicator_value,
        indicator_type=DBotScoreType.CUSTOM,
        integration_name=INTEGRATION_NAME,
        score=koi_risk_to_dbot_score(risk_score, risk_level),
        reliability=demisto.params().get("integrationReliability", "B - Usually reliable"),
    )

    findings_data = response.get("findings", {})
    findings_list = findings_data.get("findings", []) if isinstance(findings_data, dict) else []
    compliance_data = response.get("compliance", {})
    compliance_rules = compliance_data.get("rules", []) if isinstance(compliance_data, dict) else []

    indicator_data = {
        "item_id": item_id,
        "marketplace": marketplace,
        "version": response.get("version"),
        "item_display_name": response.get("item_display_name"),
        "package_name": response.get("package_name"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_status": response.get("risk_status"),
        "ai_risk_summary": response.get("ai_risk_summary"),
        "findings_count": findings_data.get("total_count", 0) if isinstance(findings_data, dict) else 0,
        "compliance_count": compliance_data.get("total_count", 0) if isinstance(compliance_data, dict) else 0,
    }

    custom_indicator = Common.CustomIndicator(
        indicator_type="Koi Software Item Dev",
        dbot_score=dbot_score,
        value=indicator_value,
        data=indicator_data,
        context_prefix="KoiSoftwareItem",
    )

    results: list[CommandResults] = []

    findings_table = tableToMarkdown(
        "Findings", findings_list,
        headers=["finding_id", "finding_name", "severity", "description"],
        headerTransform=string_to_table_header,
    ) if findings_list else "No findings."

    compliance_table = tableToMarkdown(
        "Compliance Rules", compliance_rules,
        headers=["rule_id", "rule_name", "status", "description"],
        headerTransform=string_to_table_header,
    ) if compliance_rules else "No compliance data."

    summary_table = tableToMarkdown(
        f"{INTEGRATION_NAME} Item Enrichment",
        indicator_data,
        headers=["item_id", "item_display_name", "marketplace", "version",
                 "risk_score", "risk_level", "risk_status", "findings_count", "compliance_count"],
        headerTransform=string_to_table_header,
    )

    relationships: list[EntityRelationship] = []
    reliability = demisto.params().get("integrationReliability", "B - Usually reliable")

    sha256 = response.get("sha256", "")
    if sha256 and SHA256_RE.match(sha256):
        relationships.append(EntityRelationship(
            entity_a=indicator_value,
            entity_a_type=INDICATOR_TYPE,
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_b=sha256,
            entity_b_type=FeedIndicatorType.File,
            reverse_name=EntityRelationship.Relationships.RELATED_TO,
            source_reliability=reliability,
            brand=INTEGRATION_NAME,
        ))
    elif SHA1_RE.match(item_id) or SHA256_RE.match(item_id):
        relationships.append(EntityRelationship(
            entity_a=indicator_value,
            entity_a_type=INDICATOR_TYPE,
            name=EntityRelationship.Relationships.RELATED_TO,
            entity_b=item_id,
            entity_b_type=FeedIndicatorType.File,
            reverse_name=EntityRelationship.Relationships.RELATED_TO,
            source_reliability=reliability,
            brand=INTEGRATION_NAME,
        ))

    for finding in findings_list:
        finding_name = finding.get("finding_name", "")
        if finding_name.upper().startswith("CVE-"):
            relationships.append(EntityRelationship(
                entity_a=indicator_value,
                entity_a_type=INDICATOR_TYPE,
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_b=finding_name,
                entity_b_type=FeedIndicatorType.CVE,
                reverse_name=EntityRelationship.Relationships.RELATED_TO,
                source_reliability=reliability,
                brand=INTEGRATION_NAME,
            ))

    readable = f"{summary_table}\n\n### AI Risk Summary\n{response.get('ai_risk_summary', 'N/A')}\n\n{findings_table}\n\n{compliance_table}"

    results.append(CommandResults(
        readable_output=readable,
        outputs_prefix="KoiDev.ItemEnrichment",
        outputs_key_field="item_id",
        outputs=response,
        indicator=custom_indicator,
        relationships=relationships,
        raw_response=response,
    ))

    for finding in findings_list:
        finding_name = finding.get("finding_name", "")
        if finding_name.startswith("CVE-"):
            cve_dbot = Common.DBotScore(
                indicator=finding_name,
                indicator_type=DBotScoreType.CVE,
                integration_name=INTEGRATION_NAME,
                score=koi_risk_to_dbot_score(None, finding.get("severity")),
            )
            cve = Common.CVE(
                id=finding_name,
                description=finding.get("description", ""),
                dbot_score=cve_dbot,
            )
            results.append(CommandResults(
                readable_output=f"CVE {finding_name} found in {response.get('item_display_name', item_id)}",
                indicator=cve,
            ))

    return results


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "koi-dev-get-events": get_events_command,
    "fetch-events": fetch_events_command,
    # Alerts
    "koi-dev-alert-list": koi_alert_list_command,
    # Policies
    "koi-dev-policy-list": koi_policy_list_command,
    "koi-dev-policy-status-update": koi_policy_status_update_command,
    # Allowlist / Blocklist
    "koi-dev-allowlist-get": koi_allowlist_get_command,
    "koi-dev-allowlist-items-remove": koi_allowlist_items_remove_command,
    "koi-dev-allowlist-items-add": koi_allowlist_items_add_command,
    "koi-dev-blocklist-get": koi_blocklist_get_command,
    "koi-dev-blocklist-items-remove": koi_blocklist_items_remove_command,
    "koi-dev-blocklist-items-add": koi_blocklist_items_add_command,
    # Inventory
    "koi-dev-inventory-list": koi_inventory_list_command,
    "koi-dev-inventory-item-get": koi_inventory_item_get_command,
    "koi-dev-inventory-search": koi_inventory_search_command,
    "koi-dev-inventory-item-endpoints-list": koi_inventory_item_endpoints_list_command,
    # Agent Activity
    "koi-dev-agent-activity-events-list": koi_agent_activity_events_list_command,
    "koi-dev-agent-activity-sessions-list": koi_agent_activity_sessions_list_command,
    # Approval Requests
    "koi-dev-approval-request-list": koi_approval_request_list_command,
    "koi-dev-approval-request-create": koi_approval_request_create_command,
    "koi-dev-approval-request-approve": koi_approval_request_approve_command,
    "koi-dev-approval-request-reject": koi_approval_request_reject_command,
    # Devices
    "koi-dev-device-list": koi_device_list_command,
    "koi-dev-device-archive": koi_device_archive_command,
    "koi-dev-device-inventory-get": koi_device_inventory_get_command,
    # Findings
    "koi-dev-finding-list": koi_finding_list_command,
    "koi-dev-finding-customize-risk": koi_finding_customize_risk_command,
    # Groups
    "koi-dev-group-list": koi_group_list_command,
    "koi-dev-group-create": koi_group_create_command,
    "koi-dev-group-update": koi_group_update_command,
    "koi-dev-group-device-add": koi_group_device_add_command,
    "koi-dev-group-device-remove": koi_group_device_remove_command,
    # Runtime Policies
    "koi-dev-runtime-policy-list": koi_runtime_policy_list_command,
    "koi-dev-runtime-policy-create": koi_runtime_policy_create_command,
    "koi-dev-runtime-policy-get": koi_runtime_policy_get_command,
    "koi-dev-runtime-policy-update": koi_runtime_policy_update_command,
    "koi-dev-runtime-policy-delete": koi_runtime_policy_delete_command,
    # Koidex
    "koi-dev-koidex-fetch": koi_koidex_fetch_command,
    "koi-dev-koidex-risk-report-get": koi_koidex_risk_report_get_command,
    "koi-dev-koidex-search": koi_koidex_search_command,
    # Private Items
    "koi-dev-private-item-list": koi_private_item_list_command,
    "koi-dev-private-item-upload": koi_private_item_upload_command,
    "koi-dev-private-item-details-get": koi_private_item_details_get_command,
    # Remediations
    "koi-dev-remediation-list": koi_remediation_list_command,
    "koi-dev-remediation-submit": koi_remediation_submit_command,
    "koi-dev-remediation-dismiss": koi_remediation_dismiss_command,
    # Reports
    "koi-dev-report-create": koi_report_create_command,
    "koi-dev-report-status-get": koi_report_status_get_command,
    # Users
    "koi-dev-user-list": koi_user_list_command,
    "koi-dev-user-create": koi_user_create_command,
    "koi-dev-user-delete": koi_user_delete_command,
    # Enrichment
    "koi-dev-item-enrich": koi_item_enrich_command,
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
        elif command == "koi-dev-get-events":
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
