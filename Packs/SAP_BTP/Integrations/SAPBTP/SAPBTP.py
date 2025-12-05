import tempfile
import time
import traceback
from datetime import datetime, timedelta, timezone  # noqa: UP017
from enum import Enum
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401, F403

urllib3.disable_warnings()

"""
SAP BTP (Business Technology Platform)
Integration for fetching Audit Logs via OAuth2 Client Credentials or mTLS.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "SAP BTP (Business Technology Platform)"


class Config:
    """Global static configuration."""

    VENDOR = "SAP"
    PRODUCT = "BTP"

    # SAP requires strict formatting without 'Z' or microseconds
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

    DEFAULT_LIMIT = 5000
    MAX_PAGE_SIZE = 500
    CACHE_BUFFER_SECONDS = 60

    # Token default settings
    DEFAULT_TOKEN_TTL_HOURS = 6
    DEFAULT_TOKEN_TTL_SECONDS = DEFAULT_TOKEN_TTL_HOURS * 60 * 60

    # Test module settings
    TEST_MODULE_LOOKBACK_MINUTES = 1
    TEST_MODULE_MAX_EVENTS = 1


class AuthType(str, Enum):
    """Authentication methods."""

    MTLS = "mTLS"
    NON_MTLS = "Non-mTLS"


class ContextKeys(str, Enum):
    """Keys used for Integration Context (Caching)."""

    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    VALID_UNTIL = "valid_until"


class APIKeys(str, Enum):
    """API Parameter Keys and Header Names."""

    HEADER_PAGING = "Paging"
    HEADER_AUTH = "Authorization"
    TIME_FROM = "time_from"
    TIME_TO = "time_to"
    HANDLE = "handle"
    GRANT_TYPE = "grant_type"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"


class APIValues(str, Enum):
    """API Endpoint paths and fixed Parameter Values."""

    AUDIT_ENDPOINT = "/auditlog/v2/auditlogrecords"
    GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"


class DefaultValues(str, Enum):
    """Default values for command arguments."""

    FROM_TIME = "1 minute ago"
    FIRST_FETCH = "3 minute ago"
    MAX_FETCH = "5000"


def get_formatted_utc_time(date_input: str | None) -> str:
    """Helper to parse input and return the strictly formatted UTC string for SAP.

    Args:
        date_input: Date string to parse (e.g., '3 days ago', '2024-01-01')

    Returns:
        Formatted UTC time string in SAP BTP format (%Y-%m-%dT%H:%M:%S)
    """
    start_datetime = parse_date_or_use_current(date_input)
    formatted_time = start_datetime.strftime(Config.DATE_FORMAT)
    demisto.debug(f"[Date Helper] Input: '{date_input}' -> Output: '{formatted_time}' (UTC)")
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
    parsed_datetime = dateparser.parse(date_string, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True})

    if not parsed_datetime:
        demisto.debug(f"[Date Helper] Failed to parse '{date_string}'. Fallback to current UTC.")
        return datetime.now(timezone.utc)  # noqa: UP017

    # Ensure UTC timezone
    if parsed_datetime.tzinfo != timezone.utc:  # noqa: UP017
        parsed_datetime = parsed_datetime.astimezone(timezone.utc)  # noqa: UP017

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


def create_mtls_cert_files(certificate: str, private_key: str) -> tuple[str, str]:
    """Create temporary certificate files for mTLS authentication."""
    demisto.debug("[Cert Manager] Creating temporary mTLS certificate files")

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as cert_file:
            cert_file.write(certificate)
            cert_file.flush()
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".key") as key_file:
            key_file.write(private_key)
            key_file.flush()
            key_path = key_file.name

        demisto.debug(f"[Cert Manager] Files created successfully: {cert_path}, {key_path}")
        return cert_path, key_path

    except Exception as error:
        raise DemistoException(f"Failed to create mTLS certificate files. Error: {str(error)}")


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters."""
    demisto.debug("[Config] Starting parameter validation")

    base_url = (params.get("url", "")).strip().rstrip("/")
    token_url_param = params.get("token_url", "").strip().rstrip("/")

    if not base_url:
        raise DemistoException("API URL is required. Please provide the Service Key 'url' field.")
    if not token_url_param:
        raise DemistoException("Token URL is required. Please provide the Service Key 'uaa.url' field.")

    token_url = f"{token_url_param}/oauth/token"

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    auth_type = params.get("auth_type", AuthType.NON_MTLS.value)

    client_id = params.get("client_id", "").strip() or None
    client_secret = params.get("client_secret", "").strip() or None
    certificate = params.get("certificate", "").strip() or None
    private_key = params.get("private_key", "").strip() or None

    if not client_id:
        raise DemistoException("Client ID is required.")

    demisto.debug(f"[Config] URL: {base_url} | Token URL: {token_url} | Auth Type: {auth_type}")

    if auth_type == AuthType.MTLS.value:
        if not certificate or not private_key:
            raise DemistoException("mTLS authentication requires both Certificate and Private Key.")
    elif auth_type == AuthType.NON_MTLS.value:
        if not client_secret:
            raise DemistoException("Non-mTLS authentication requires Client Secret.")
    else:
        raise DemistoException(f"Invalid authentication type '{auth_type}'.")

    return {
        "base_url": base_url,
        "token_url": token_url,
        "verify": verify_certificate,
        "proxy": proxy,
        "auth_type": auth_type,
        "client_id": client_id,
        "client_secret": client_secret,
        "certificate": certificate,
        "private_key": private_key,
    }


# endregion

# region Client
# =================================
# Client
# =================================


class Client(BaseClient):
    """SAP BTP API client."""

    def __init__(
        self,
        base_url: str,
        token_url: str,
        client_id: str,
        client_secret: str | None,
        verify: bool,
        proxy: bool,
        auth_type: str,
        cert_data: tuple[str, str] | None = None,
    ):
        base_url = base_url.rstrip("/") + "/"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_type = auth_type
        self.cert_data = cert_data

    def _get_access_token(self) -> str:
        """Get or refresh OAuth2 access token with caching."""
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ContextKeys.ACCESS_TOKEN.value)
        cached_valid_until = cached_context.get(ContextKeys.VALID_UNTIL.value)

        # Check if cached token is valid
        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(cached_valid_until)
                if current_timestamp < valid_until_timestamp:
                    time_left = valid_until_timestamp - current_timestamp
                    demisto.debug(f"[Token Cache] Hit! Valid for another {time_left}s")
                    return cached_token
                demisto.debug("[Token Cache] Miss. Token expired.")
            except (ValueError, TypeError):
                demisto.debug("[Token Cache] Error parsing cache. Ignoring.")

        # Request new token
        demisto.debug(f"[Token Request] Requesting new token from {self.token_url} ({self.auth_type})")
        request_kwargs: dict[str, Any] = {"method": "POST", "full_url": self.token_url}

        if self.auth_type == AuthType.NON_MTLS.value:
            request_kwargs["auth"] = (self.client_id, self.client_secret)
            request_kwargs["params"] = {
                APIKeys.GRANT_TYPE.value: APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value,
            }
        elif self.auth_type == AuthType.MTLS.value:
            if not self.cert_data:
                raise DemistoException("mTLS authentication requires certificate files.")
            request_kwargs["cert"] = self.cert_data
            request_kwargs["data"] = {
                APIKeys.GRANT_TYPE.value: APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value,
                APIKeys.CLIENT_ID.value: self.client_id,
            }

        token_response = self._http_request(**request_kwargs)
        access_token = token_response.get(ContextKeys.ACCESS_TOKEN.value)

        if not access_token:
            raise DemistoException("Failed to obtain access token from SAP BTP. Response missing access_token.")

        # Update Cache
        token_expires_in = token_response.get(ContextKeys.EXPIRES_IN.value, Config.DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - Config.CACHE_BUFFER_SECONDS

        demisto.debug(f"[Token Request] Success. Expires in {token_expires_in}s.")

        new_context = {ContextKeys.ACCESS_TOKEN.value: access_token, ContextKeys.VALID_UNTIL.value: str(token_valid_until)}
        set_integration_context(new_context)

        demisto.debug("[Token Request] Token stored securely in integration context.")
        return access_token

    def http_request(
        self, method: str, url_suffix: str, params: dict[str, Any] | None = None, return_full_response: bool = False
    ) -> Any:
        """Execute HTTP request with authentication and detailed logging."""
        access_token = self._get_access_token()
        auth_headers = {APIKeys.HEADER_AUTH.value: f"Bearer {access_token}"}

        demisto.debug(f"[HTTP Call] {method} {url_suffix} | Params: {params}")

        http_response = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            headers=auth_headers,
            resp_type="response",
            ok_codes=(200, 201, 202, 204),
        )

        status_code = http_response.status_code
        demisto.debug(f"[HTTP Call] Response Status: {status_code}")

        if status_code == 204:
            demisto.debug("[HTTP Call] 204 No Content received.")
            return ({}, http_response.headers) if return_full_response else {}

        try:
            response_json = http_response.json()
        except ValueError:
            demisto.debug(f"[HTTP Error] Failed to parse JSON. Raw body preview: {http_response.text[:200]}")
            raise DemistoException(f"API returned non-JSON response with status {status_code}")

        if return_full_response:
            return response_json, http_response.headers

        return response_json

    def _parse_events_from_response(self, response_body: Any) -> list[dict[str, Any]]:
        """Defensively parse events from a response body.

        This handles several known SAP BTP response formats:
        1. A list of events (standard).
        2. A dictionary with a "results" key.
        3. A nested dictionary like {"d": {"results": [...]}} (OData format).
        4. A single event dictionary returned directly.

        Args:
            response_body: The raw response body from the API.

        Returns:
            A list of event dictionaries.
        """
        demisto.debug("[Response Parser] Parsing response body.")

        if isinstance(response_body, list):
            demisto.debug(f"[Response Parser] Direct list format detected with {len(response_body)} events")
            return response_body

        # Handle dictionary-based responses
        events_list = response_body.get("results") or response_body.get("d", {}).get("results") or []

        # Safety net: Single object response (Edge case)
        if not events_list and isinstance(response_body, dict) and "message_uuid" in response_body:
            demisto.debug("[Response Parser] Detected single object response, wrapping in list.")
            return [response_body]

        return events_list

    def get_audit_log_events(
        self, created_after: str, created_before: str | None = None, limit: int = 0, pagination_handle: str | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Retrieve a single page of audit log events from SAP BTP.

        Note: SAP BTP API returns events in ascending order (oldest to newest).
        Page 1 contains the oldest events, subsequent pages contain progressively newer events.

        Args:
            created_after: Start time string (UTC)
            created_before: End time string (UTC) or None
            pagination_handle: Handle for next page or None

        Returns:
            Tuple of (List of events, Next pagination handle)
        """
        demisto.debug("[API Fetch] Starting to fetch a page of events.")
        request_params: dict[str, Any] = {}

        if pagination_handle:
            demisto.debug("[API Fetch] Using pagination handle for next page...")
            request_params[APIKeys.HANDLE.value] = pagination_handle
        else:
            demisto.debug(f"[API Fetch] Initial Request | From: {created_after} | To: {created_before or 'Now'}")
            request_params[APIKeys.TIME_FROM.value] = created_after
            if created_before:
                request_params[APIKeys.TIME_TO.value] = created_before

        response_body, response_headers = self.http_request(
            method="GET", url_suffix=APIValues.AUDIT_ENDPOINT.value, params=request_params, return_full_response=True
        )

        events_list = self._parse_events_from_response(response_body)
        next_page_handle = self._extract_pagination_handle(response_headers)

        demisto.debug(
            f"[API Fetch] Finished fetching page. Found {len(events_list)} events. "
            f"Next handle available: {next_page_handle is not None}"
        )

        return events_list, next_page_handle

    def _extract_pagination_handle(self, headers: dict[str, Any]) -> str | None:
        """Extract handle from the 'Paging' header."""
        demisto.debug("[Pagination] Starting to extract pagination handle from headers.")
        paging_header_value = headers.get(APIKeys.HEADER_PAGING.value) or headers.get(APIKeys.HEADER_PAGING.value.lower())

        if not paging_header_value:
            demisto.debug("[Pagination] No 'Paging' header found. No next page.")
            return None

        if "handle=" not in paging_header_value:
            demisto.debug(f"[Pagination] Header present but 'handle=' not found: {paging_header_value}")
            demisto.debug("[Pagination] No handle extracted. This is the last page.")
            return None

        try:
            handle = paging_header_value.split("handle=")[1].strip()
            demisto.debug("[Pagination] Successfully extracted handle for the next page.")
            return handle
        except IndexError:
            demisto.debug("[Pagination] Failed to split handle from header. Assuming no next page.")
            return None


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
        fetch_events_with_pagination(client, created_after=test_time, max_events=Config.TEST_MODULE_MAX_EVENTS)

        demisto.debug("[Test Module] Success")
        return "ok"

    except Exception as error:
        error_msg = str(error)
        demisto.debug(f"[Test Module] Failed: {error_msg}")

        if "401" in error_msg or "403" in error_msg:
            return "Authorization Error: Verify Client ID, Secret, or Certificates."
        raise


def fetch_events_with_pagination(
    client: Client, created_after: str, max_events: int, created_before: str | None = None
) -> list[dict[str, Any]]:
    """Fetch, Sort (Oldest First), and Slice events.

    Implements "Fetch-Sort-Slice" strategy:
    - Fetch pages until we have at least 'max_events' raw items.
    - Sort raw list by time (Oldest -> Newest).
    - Slice to return exactly 'max_events' (the oldest ones).
    """
    events: list[dict[str, Any]] = []
    pagination_handle: str | None = None
    page_count = 0

    demisto.debug(f"[Pagination Loop] Start. Goal: {max_events}. Time: {created_after} -> {created_before or 'Now'}")

    # Fetch Loop
    while len(events) < max_events:
        page_count += 1

        page_events, pagination_handle = client.get_audit_log_events(
            created_after=created_after, created_before=created_before, pagination_handle=pagination_handle
        )

        if not page_events:
            demisto.debug(f"[Pagination Loop] Page {page_count}: Empty. Stopping.")
            break

        events.extend(page_events)
        demisto.debug(f"[Pagination Loop] Page {page_count}: +{len(page_events)} events. Total accumulated: {len(events)}")

        if not pagination_handle:
            demisto.debug("[Pagination Loop] No next page handle. Stopping.")
            break

        # Stop fetching if we have enough
        if len(events) >= max_events:
            demisto.debug(f"[Pagination Loop] Threshold reached ({len(events)} >= {max_events}). Stopping fetch.")
            break

    if not events:
        demisto.debug("[Pagination Result] No events found.")
        return []

    # Sort events by time (Oldest First)
    demisto.debug(f"[Pagination Process] Sorting {len(events)} raw events by time...")
    events.sort(key=lambda x: x.get("time", ""))

    # Slice to limit
    if len(events) > max_events:
        discarded_count = len(events) - max_events
        demisto.debug(f"[Pagination Slice] Cutting list to {max_events}. Discarding {discarded_count} newer events.")
        final_events = events[:max_events]
    else:
        demisto.debug("[Pagination Slice] Returning all fetched events (count is under limit).")
        final_events = events

    # Log results
    first_time = final_events[0].get("time", "N/A")
    last_time = final_events[-1].get("time", "N/A")
    demisto.debug(f"[Pagination Final] Returning {len(final_events)} events. Range: {first_time} to {last_time}")

    return final_events


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """Manual command to get events."""
    demisto.debug("[Command] get-events triggered")

    from_time_input = args.get("from_time", DefaultValues.FROM_TIME.value)
    end_time_input = args.get("end_time")
    limit = int(args.get("limit", DefaultValues.MAX_FETCH.value))
    should_push_events = argToBoolean(args.get("should_push_events", False))

    created_after = get_formatted_utc_time(from_time_input)
    created_before = get_formatted_utc_time(end_time_input) if end_time_input else None

    demisto.debug(f"[Command Params] From: {created_after}, To: {created_before}, Limit: {limit}, Push: {should_push_events}")

    events = fetch_events_with_pagination(client, created_after, limit, created_before)

    if should_push_events and events:
        send_events_to_xsiam(events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Command] Pushed {len(events)} events to XSIAM")
        return f"Successfully retrieved and pushed {len(events)} events to XSIAM"

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Events", events, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SAPBTP.Event",
        outputs_key_field="uuid",
        outputs=events,
    )


def fetch_events_command(client: Client) -> None:
    """Scheduled command to fetch events."""
    demisto.debug("[Command] fetch-events triggered")

    params = demisto.params()
    max_events_to_fetch = int(params.get("max_fetch", DefaultValues.MAX_FETCH.value))
    first_fetch_param = argToBoolean(params.get("first_fetch", False))

    last_run = demisto.getLastRun()
    last_fetch_timestamp = last_run.get("last_fetch")

    if last_fetch_timestamp:
        time_input = last_fetch_timestamp
        demisto.debug(f"[Fetch Logic] Continuing from Last Run. Fetching from: {time_input}")
    elif first_fetch_param:
        time_input = DefaultValues.FIRST_FETCH.value
        demisto.debug(f"[Fetch Logic] First Run. Fetching from: {time_input}")
    else:
        time_input = DefaultValues.FROM_TIME.value
        demisto.debug(f"[Fetch Logic] Fallback (no last_run and first_fetch disabled). Fetching from: {time_input}")

    created_after = get_formatted_utc_time(time_input)

    # Fetch events
    events = fetch_events_with_pagination(client, created_after, max_events_to_fetch)

    if events:
        # Update Last Run using the Newest event in our processed batch
        last_event = events[-1]
        new_last_run_time = last_event.get("time")

        if new_last_run_time:
            demisto.setLastRun({"last_fetch": new_last_run_time})
            demisto.debug(f"[Last Run] Updated to: {new_last_run_time}")
        else:
            demisto.debug("[Last Run] WARNING: Last event missing 'time' field. Not updating.")

        send_events_to_xsiam(events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Command] Sent {len(events)} events to XSIAM")
    else:
        demisto.debug("[Command] No new events found.")


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "sap-btp-get-events": get_events_command,
    "fetch-events": fetch_events_command,
}


def main() -> None:
    """Main entry point for SAP BTP integration."""
    demisto.debug(f"{INTEGRATION_NAME} integration started")

    command = demisto.command()
    demisto.debug(f"[Main] Command: {command}")

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")

        config = parse_integration_params(demisto.params())

        cert_data = None
        if config["auth_type"] == AuthType.MTLS.value:
            cert_data = create_mtls_cert_files(config["certificate"], config["private_key"])

        client = Client(
            base_url=config["base_url"],
            token_url=config["token_url"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            verify=config["verify"],
            proxy=config["proxy"],
            auth_type=config["auth_type"],
            cert_data=cert_data,
        )

        command_func = COMMAND_MAP[command]

        if command == "test-module":
            result = command_func(client)
            return_results(result)
        elif command == "fetch-events":
            command_func(client)
        else:
            result = command_func(client, demisto.args())
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command=}. Error: {str(error)}"
        demisto.debug(f"[Critical Error] {error_msg}\nTrace: {traceback.format_exc()}")
        return_error(error_msg)

    finally:
        demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
