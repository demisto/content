import base64
import time
import traceback
from datetime import datetime, timezone  # noqa: UP017
from enum import Enum
from typing import Any

import dateparser
import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

"""
CyberArk Identity Security Platform (ISP)
Integration for fetching Audit Events via OAuth2 Client Credentials.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "CyberArk Identity Security Platform"


class Config:
    """Global static configuration."""

    VENDOR = "CyberArk"
    PRODUCT = "Identity Security Platform"

    # CyberArk ISP date format
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    DEFAULT_LIMIT = 10000
    MAX_PAGE_SIZE = 1000
    CACHE_BUFFER_SECONDS = 60

    # Token default settings
    DEFAULT_TOKEN_TTL_HOURS = 6
    DEFAULT_TOKEN_TTL_SECONDS = DEFAULT_TOKEN_TTL_HOURS * 60 * 60

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 1
    TEST_MODULE_MAX_EVENTS = 1

    # Telemetry
    INTEGRATION_VERSION = "1.0"
    INTEGRATION_TYPE = "SIEM"
    VENDOR_NAME = "Palo Alto Networks"
    VENDOR_VERSION = "3.x"


class ContextKeys(str, Enum):
    """Keys used for Integration Context (Caching)."""

    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    VALID_UNTIL = "valid_until"


class APIKeys(str, Enum):
    """API Parameter Keys and Header Names."""

    HEADER_AUTH = "Authorization"
    HEADER_API_KEY = "x-api-key"
    HEADER_TELEMETRY = "x-cybr-telemetry"
    HEADER_CONTENT_TYPE = "Content-Type"
    GRANT_TYPE = "grant_type"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    SCOPE = "scope"
    CURSOR_REF = "cursorRef"
    FILTER_MODEL = "filterModel"
    SORT_MODEL = "sortModel"
    FIELD_NAME = "field_name"
    DIRECTION = "direction"
    DATE_FROM = "dateFrom"
    DATE_TO = "dateTo"
    DATA = "data"
    PAGING = "paging"
    CURSOR = "cursor"


class APIValues(str, Enum):
    """API Endpoint paths and fixed Parameter Values."""

    CREATE_QUERY_ENDPOINT = "/api/audits/stream/createQuery"
    STREAM_RESULTS_ENDPOINT = "/api/audits/stream/results"
    GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
    SCOPE_AUDIT_READ = "isp.audit.events:read"
    CONTENT_TYPE_JSON = "application/json"
    CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"


class DefaultValues(str, Enum):
    """Default values for command arguments."""

    FROM_TIME = "1 minute ago"
    MAX_FETCH = "10000"


def get_formatted_time(date_input: str | None) -> str:
    """Helper to parse input and return the formatted time string for CyberArk ISP.

    Args:
        date_input: Date string to parse (e.g., '3 days ago', '2025-09-15 17:10:00')

    Returns:
        Formatted time string in CyberArk ISP format (YYYY-MM-DD HH:MM:SS)
    """
    start_datetime = parse_date_or_use_current(date_input)
    formatted_time = start_datetime.strftime(Config.DATE_FORMAT)
    demisto.debug(f"[Date Helper] Input: '{date_input}' -> Output: '{formatted_time}'")
    return formatted_time


def parse_date_or_use_current(date_string: str | None) -> datetime:
    """Parse a date string or return current UTC datetime if parsing fails.

    Ensures the result is always a timezone-aware UTC datetime object.
    """
    if not date_string:
        current_time = datetime.now(timezone.utc)  # noqa: UP017
        demisto.debug(f"[Date Helper] No input provided. Using current UTC: {current_time}")
        return current_time

    demisto.debug(f"[Date Helper] Attempting to parse date string: '{date_string}'")
    parsed_datetime = dateparser.parse(
        date_string, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"}
    )

    if not parsed_datetime:
        demisto.debug(f"[Date Helper] Failed to parse '{date_string}'. Fallback to current UTC.")
        return datetime.now(timezone.utc)  # noqa: UP017

    # Ensure UTC timezone explicitly
    if parsed_datetime.tzinfo != timezone.utc:  # noqa: UP017
        parsed_datetime = parsed_datetime.astimezone(timezone.utc)  # noqa: UP017

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


def generate_telemetry_header() -> str:
    """Generate the base64-encoded telemetry header value.

    Returns:
        Base64-encoded telemetry string
    """
    telemetry_data = (
        f"in={INTEGRATION_NAME}&"
        f"it={Config.INTEGRATION_TYPE}&"
        f"iv={Config.INTEGRATION_VERSION}&"
        f"vn={Config.VENDOR_NAME}&"
        f"VV={Config.VENDOR_VERSION}"
    )
    encoded = base64.b64encode(telemetry_data.encode()).decode()
    demisto.debug(f"[Telemetry] Generated header: {telemetry_data}")
    return encoded


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters."""
    demisto.debug("[Config] Starting parameter validation")

    base_url = (params.get("url", "")).strip().rstrip("/")
    if not base_url:
        raise DemistoException("Server URL is required. Please provide the Audit API base URL.")

    identity_url = (params.get("identity_url", "")).strip().rstrip("/")
    if not identity_url:
        raise DemistoException("Identity URL is required. Please provide the CyberArk Identity FQDN.")

    web_app_id = params.get("web_app_id", "").strip()
    if not web_app_id:
        raise DemistoException("OAuth2 Web App ID is required.")

    client_id = params.get("client_id", "").strip()
    if not client_id:
        raise DemistoException("Client ID is required.")

    credentials = params.get("client_secret", {})
    client_secret = credentials.get("password", "").strip()
    if not client_secret:
        raise DemistoException("Client Secret is required.")

    api_key = params.get("api_key", "").strip()
    if not api_key:
        raise DemistoException("API Key is required.")

    proxy = argToBoolean(params.get("proxy", False))
    verify_certificate = not argToBoolean(params.get("insecure", False))

    # Construct token URL
    token_url = f"{identity_url}/OAuth2/Token/{web_app_id}"

    demisto.debug(f"[Config] Base URL: {base_url} | Token URL: {token_url}")

    return {
        "base_url": base_url,
        "token_url": token_url,
        "verify": verify_certificate,
        "proxy": proxy,
        "client_id": client_id,
        "client_secret": client_secret,
        "api_key": api_key,
    }


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Add _time field to events for XSIAM ingestion.

    Maps the event's 'timestamp' field to '_time' for proper XSIAM indexing.
    The value is copied as-is without any parsing or transformation.
    """
    for event in events:
        event_timestamp = event.get("timestamp")
        if event_timestamp:
            event["_time"] = event_timestamp
        else:
            demisto.debug(f"[Event Time] WARNING: Event missing 'timestamp' field: {event.get('uuid', 'unknown')}")


def deduplicate_events(events: list[dict[str, Any]], last_fetched_uuids: list[str]) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched UUIDs."""
    if not events:
        demisto.debug("[Dedup] No events to process")
        return events

    if not last_fetched_uuids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous UUIDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_uuids)} previously fetched UUIDs")

    fetched_uuids_set = set(last_fetched_uuids)
    new_events = [event for event in events if event.get("uuid") not in fetched_uuids_set]
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


class Client(BaseClient):
    """CyberArk ISP API client."""

    def __init__(
        self,
        base_url: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        base_url = base_url.rstrip("/") + "/"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_key = api_key
        self.telemetry_header = generate_telemetry_header()

    def _get_access_token(self) -> str:
        """Get or refresh OAuth2 access token with caching."""
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ContextKeys.ACCESS_TOKEN.value)
        cached_valid_until = cached_context.get(ContextKeys.VALID_UNTIL.value)

        # Check if cached token is valid
        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(float(cached_valid_until))
                if current_timestamp < valid_until_timestamp:
                    demisto.debug("[Token Cache] Hit! Token is still valid.")
                    return cached_token
                demisto.debug("[Token Cache] Miss. Token expired.")
            except (ValueError, TypeError):
                demisto.debug("[Token Cache] Error parsing cache. Ignoring.")

        # Request new token
        demisto.debug(f"[Token Request] Requesting new token from {self.token_url}")

        # Prepare request data
        token_data = {
            APIKeys.GRANT_TYPE.value: APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value,
            APIKeys.CLIENT_ID.value: self.client_id,
            APIKeys.CLIENT_SECRET.value: self.client_secret,
            APIKeys.SCOPE.value: APIValues.SCOPE_AUDIT_READ.value,
        }

        headers = {APIKeys.HEADER_CONTENT_TYPE.value: APIValues.CONTENT_TYPE_FORM.value}

        try:
            token_response = self._http_request(
                method="POST",
                full_url=self.token_url,
                data=token_data,
                headers=headers,
                resp_type="json",
            )
        except DemistoException as error:
            error_msg = str(error)
            demisto.error(f"[Token Request] Failed: {error_msg}")
            raise DemistoException(f"Failed to obtain access token: {error_msg}")

        access_token = token_response.get(ContextKeys.ACCESS_TOKEN.value)

        if not access_token:
            raise DemistoException("Failed to obtain access token. Response missing access_token.")

        # Update Cache
        token_expires_in = token_response.get(ContextKeys.EXPIRES_IN.value, Config.DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - Config.CACHE_BUFFER_SECONDS

        demisto.debug(f"[Token Request] Success. Expires in {token_expires_in}s.")

        new_context = {ContextKeys.ACCESS_TOKEN.value: access_token, ContextKeys.VALID_UNTIL.value: str(token_valid_until)}
        set_integration_context(new_context)

        return access_token

    def http_request(
        self,
        method: str,
        url_suffix: str,
        json_data: dict[str, Any] | None = None,
        return_full_response: bool = False,
    ) -> Any:
        """Execute HTTP request with authentication and detailed logging."""
        access_token = self._get_access_token()

        auth_headers = {
            APIKeys.HEADER_AUTH.value: f"Bearer {access_token}",
            APIKeys.HEADER_API_KEY.value: self.api_key,
            APIKeys.HEADER_TELEMETRY.value: self.telemetry_header,
            APIKeys.HEADER_CONTENT_TYPE.value: APIValues.CONTENT_TYPE_JSON.value,
        }

        demisto.debug(f"[HTTP Call] {method} {url_suffix}")

        try:
            http_response = self._http_request(
                method=method,
                url_suffix=url_suffix,
                json_data=json_data,
                headers=auth_headers,
                resp_type="response",
                ok_codes=(200, 201, 202, 204),
                retries=3,
                backoff_factor=2,
            )
        except DemistoException as error:
            error_msg = str(error)
            if "401" in error_msg or "403" in error_msg:
                demisto.error(f"[HTTP Error] Authentication failed: {error_msg}")
                raise DemistoException(f"Authentication error: {error_msg}. Please check credentials.")
            raise

        status_code = http_response.status_code
        demisto.debug(f"[HTTP Call] Response Status: {status_code}")

        if status_code == 204:
            demisto.debug("[HTTP Call] 204 No Content received.")
            return ({}, http_response.headers) if return_full_response else {}

        try:
            response_json = http_response.json()
        except ValueError:
            demisto.debug(f"[HTTP Error] Failed to parse JSON. Status: {status_code}, Body: {http_response.text[:200]}")
            raise DemistoException(f"API returned non-JSON response with status {status_code}")

        if return_full_response:
            return response_json, http_response.headers

        return response_json

    def create_stream_query(self, date_from: str, date_to: str | None = None) -> str:
        """Create a stream query and return the cursor reference.

        Args:
            date_from: Start date/time string
            date_to: End date/time string or None

        Returns:
            Cursor reference string for pagination
        """
        demisto.debug(f"[API Create Query] From: {date_from} | To: {date_to or 'Now'}")

        filter_model: dict[str, Any] = {APIKeys.DATE_FROM.value: date_from}
        if date_to:
            filter_model[APIKeys.DATE_TO.value] = date_to

        sort_model = [{APIKeys.FIELD_NAME.value: "timestamp", APIKeys.DIRECTION.value: "asc"}]

        request_body = {APIKeys.FILTER_MODEL.value: filter_model, APIKeys.SORT_MODEL.value: sort_model}

        response = self.http_request(method="POST", url_suffix=APIValues.CREATE_QUERY_ENDPOINT.value, json_data=request_body)

        cursor_ref = response.get(APIKeys.CURSOR_REF.value)
        if not cursor_ref:
            raise DemistoException("Failed to create stream query. Response missing cursorRef.")

        demisto.debug(f"[API Create Query] Success. Cursor: {cursor_ref[:50]}...")
        return cursor_ref

    def get_stream_results(self, cursor_ref: str) -> tuple[list[dict[str, Any]], str | None]:
        """Retrieve a page of audit events using cursor reference.

        Args:
            cursor_ref: Cursor reference from create_query or previous page

        Returns:
            Tuple of (List of events, Next cursor reference or None)
        """
        demisto.debug("[API Stream Results] Fetching page...")

        request_body = {APIKeys.CURSOR_REF.value: cursor_ref}

        response = self.http_request(method="POST", url_suffix=APIValues.STREAM_RESULTS_ENDPOINT.value, json_data=request_body)

        events_list = response.get(APIKeys.DATA.value, [])
        paging_info = response.get(APIKeys.PAGING.value, {})
        cursor_info = paging_info.get(APIKeys.CURSOR.value, {})
        next_cursor_ref = cursor_info.get(APIKeys.CURSOR_REF.value)

        demisto.debug(
            f"[API Stream Results] Page fetched. Count: {len(events_list)}. Next cursor exists: {bool(next_cursor_ref)}"
        )

        return events_list, next_cursor_ref


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by fetching 1 minute of data."""
    demisto.debug("[Test Module] Starting...")
    try:
        utc_now = datetime.now(timezone.utc)  # noqa: UP017
        test_time = (utc_now - timedelta(minutes=Config.TEST_MODULE_LOOKBACK_MINUTES)).strftime(Config.DATE_FORMAT)

        demisto.debug(f"[Test Module] Fetching from: {test_time}")
        fetch_events_with_pagination(client, date_from=test_time, max_events=Config.TEST_MODULE_MAX_EVENTS)

        demisto.debug("[Test Module] Success")
        return "ok"

    except Exception as error:
        error_msg = str(error)
        demisto.debug(f"[Test Module] Failed: {error_msg}")
        if "401" in error_msg or "403" in error_msg:
            return "Authorization Error: Verify Client ID, Secret, or API Key."
        raise


def fetch_events_with_pagination(
    client: Client, date_from: str, date_to: str | None = None, max_events: int = Config.DEFAULT_LIMIT
) -> list[dict[str, Any]]:
    """Fetch events with pagination support.

    Fetches pages until the limit is reached or no more pages exist.
    """
    events: list[dict[str, Any]] = []
    page_count = 0

    demisto.debug(f"[Pagination Loop] Start. Goal: {max_events}. Time: {date_from} -> {date_to or 'Now'}")

    # Step 1: Create initial query
    cursor_ref: str | None = client.create_stream_query(date_from=date_from, date_to=date_to)

    # Step 2: Fetch pages
    while len(events) < max_events and cursor_ref:
        page_count += 1
        page_events, next_cursor = client.get_stream_results(cursor_ref=cursor_ref)

        if not page_events:
            demisto.debug(f"[Pagination Loop] Page {page_count}: Empty. Stopping.")
            break

        events.extend(page_events)
        demisto.debug(f"[Pagination Loop] Page {page_count}: +{len(page_events)} events. Total accumulated: {len(events)}")

        cursor_ref = next_cursor

        if not cursor_ref:
            demisto.debug("[Pagination Loop] No next cursor. Stopping.")
            break

        # Safety break to prevent infinite loops
        if len(events) >= max_events:
            demisto.debug(f"[Pagination Loop] Threshold reached ({len(events)} >= {max_events}). Stopping fetch.")
            break

    if not events:
        demisto.debug("[Pagination Result] No events found.")
        return []

    # Events are already sorted by the API (sortModel with timestamp asc)
    # Just slice to limit if needed (Keep the Oldest X events)
    if len(events) > max_events:
        demisto.debug(f"[Pagination Loop] Slicing {len(events)} events to limit {max_events}")
        events = events[:max_events]

    demisto.debug(f"[Pagination Result] Returning {len(events)} events (API-sorted by timestamp asc)")
    return events


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """Manual command to get events."""
    demisto.debug("[Command] cyberark-isp-get-events triggered")

    date_from_input = args.get("date_from", DefaultValues.FROM_TIME.value)
    date_to_input = args.get("date_to")
    limit = int(args.get("limit", "50"))
    should_push_events = argToBoolean(args.get("should_push_events", False))

    date_from = get_formatted_time(date_from_input)
    date_to = get_formatted_time(date_to_input) if date_to_input else None

    demisto.debug(f"[Command Params] From: {date_from}, To: {date_to}, Limit: {limit}, Push: {should_push_events}")

    events = fetch_events_with_pagination(client, date_from, date_to, limit)

    if should_push_events and events:
        add_time_to_events(events)
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Command] Pushed {len(events)} events to XSIAM")
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", events, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CyberArkISP.Event",
        outputs_key_field="uuid",
        outputs=events,
    )


def fetch_events_command(client: Client) -> None:
    """Scheduled command to fetch events."""
    params = demisto.params()
    max_events_to_fetch = int(params.get("max_fetch", DefaultValues.MAX_FETCH.value))

    last_run = demisto.getLastRun()
    last_fetch_timestamp = last_run.get("last_fetch")
    raw_uuids = last_run.get("last_fetched_uuids")
    last_fetched_uuids: list[str] = raw_uuids if isinstance(raw_uuids, list) else []

    if last_fetch_timestamp:
        time_input = last_fetch_timestamp
        demisto.debug(
            f"[Fetch] Continuing from Last Run. Fetching from: {time_input}. Prev UUID count: {len(last_fetched_uuids)}"
        )
    else:
        time_input = DefaultValues.FROM_TIME.value
        demisto.debug("[Fetch] First Run - starting from default time")

    date_from = get_formatted_time(time_input)

    # Fetch events
    events = fetch_events_with_pagination(client, date_from, None, max_events_to_fetch)

    if not events:
        demisto.debug("[Fetch] No events found.")
        return

    # Deduplicate
    new_events = deduplicate_events(events, last_fetched_uuids)

    if not new_events:
        demisto.debug("[Fetch] All events were duplicates.")
    else:
        add_time_to_events(new_events)
        send_events_to_xsiam(events=new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Pushed {len(new_events)} events to XSIAM")

        # Update Last Run
        last_event = events[-1]
        new_last_run_timestamp = last_event.get("timestamp")

        if new_last_run_timestamp:
            # Convert timestamp to formatted string for next run
            try:
                last_event_dt = datetime.fromtimestamp(new_last_run_timestamp / 1000, tz=timezone.utc)  # noqa: UP017
                new_last_run_time = last_event_dt.strftime(Config.DATE_FORMAT)
            except (ValueError, TypeError, OSError):
                demisto.debug("[Fetch] Warning: Failed to convert last event timestamp. Using raw value.")
                new_last_run_time = str(new_last_run_timestamp)

            # Collect UUIDs for the new high-water mark timestamp
            uuids_at_last_timestamp = [
                event.get("uuid") for event in events if event.get("timestamp") == new_last_run_timestamp and event.get("uuid")
            ]

            demisto.setLastRun({"last_fetch": new_last_run_time, "last_fetched_uuids": uuids_at_last_timestamp})
            demisto.debug(f"[Fetch] State updated. New HWM: {new_last_run_time}")
        else:
            demisto.debug("[Fetch] Warning: Last event missing timestamp. State not updated.")


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "cyberark-isp-get-events": get_events_command,
    "fetch-events": fetch_events_command,
}


def main() -> None:
    """Main entry point for CyberArk ISP integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started")
    command = demisto.command()

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")

        config = parse_integration_params(demisto.params())

        client = Client(
            base_url=config["base_url"],
            token_url=config["token_url"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            api_key=config["api_key"],
            verify=config["verify"],
            proxy=config["proxy"],
        )

        command_func = COMMAND_MAP[command]

        if command == "test-module":
            result = command_func(client)  # pylint: disable=E1120
            return_results(result)
        elif command == "fetch-events":
            command_func(client)  # pylint: disable=E1120
        else:
            result = command_func(client, demisto.args())
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {str(error)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
