import contextlib
import os
import tempfile
import time
import traceback
from collections.abc import Generator
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
    # Using strict settings for dateparser to avoid ambiguous timezone guessing
    parsed_datetime = dateparser.parse(
        date_string, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True, "TO_TIMEZONE": "UTC"}
    )

    if not parsed_datetime:
        demisto.debug(f"[Date Helper] Failed to parse '{date_string}'. Fallback to current UTC.")
        return datetime.now(timezone.utc)  # noqa: UP017

    # Ensure UTC timezone explicitly even if dateparser didn't set it (safety check)
    if parsed_datetime.tzinfo != timezone.utc:  # noqa: UP017
        parsed_datetime = parsed_datetime.astimezone(timezone.utc)  # noqa: UP017

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


@contextlib.contextmanager
def temporary_cert_files(certificate: str, private_key: str) -> Generator[tuple[str, str], None, None]:
    """Context manager to create temporary certificate files for mTLS authentication.

    Automatically handles cleanup of files upon exiting the context.
    """
    cert_path = ""
    key_path = ""
    try:
        demisto.debug("[Cert Manager] Creating temporary mTLS certificate files")
        # Replace escaped newlines if they exist
        cert_content = certificate.replace("\\n", "\n")
        key_content = private_key.replace("\\n", "\n")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as cert_file:
            cert_file.write(cert_content)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".key") as key_file:
            key_file.write(key_content)
            key_path = key_file.name

        demisto.debug(f"[Cert Manager] Files created: {cert_path}, {key_path}")
        yield cert_path, key_path

    except Exception as error:
        raise DemistoException(f"Failed to process mTLS certificates: {str(error)}")
    finally:
        # Cleanup
        for path in [cert_path, key_path]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                    demisto.debug(f"[Cert Manager] Removed temp file: {path}")
                except OSError as e:
                    demisto.debug(f"[Cert Manager] Warning: Failed to remove {path}: {str(e)}")


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters."""
    demisto.debug("[Config] Starting parameter validation")

    base_url = (params.get("url", "")).strip().rstrip("/")
    if not base_url:
        raise DemistoException("API URL is required. Please provide the Service Key 'url' field.")

    token_url_param = params.get("token_url", "").strip().rstrip("/")
    if not token_url_param:
        raise DemistoException("Token URL is required. For Non-mTLS use 'uaa.url', for mTLS use 'uaa.certurl'.")

    if not token_url_param.endswith("/token"):
        token_url = f"{token_url_param}/oauth/token"
    else:
        token_url = token_url_param

    client_id = params.get("client_id", "").strip() or None
    if not client_id:
        raise DemistoException("Client ID is required.")

    auth_type = params.get("auth_type", AuthType.NON_MTLS.value)
    proxy = argToBoolean(params.get("proxy", False))
    verify_certificate = not argToBoolean(params.get("insecure", False))

    demisto.debug(f"[Config] URL: {base_url} | Token URL: {token_url} | Auth Type: {auth_type}")

    # Parse credentials based on auth type
    client_secret = None
    certificate = None
    private_key = None

    if auth_type == AuthType.MTLS.value:
        certificate = params.get("certificate", "").strip() or None
        private_key = params.get("private_key", "").strip() or None
        if not certificate or not private_key:
            raise DemistoException("mTLS authentication requires both Certificate and Private Key.")
    elif auth_type == AuthType.NON_MTLS.value:
        credentials = params.get("client_secret", {})
        client_secret = credentials.get("password")

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


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Add _time field to events for XSIAM ingestion.

    Maps the event's 'time' field to '_time' for proper XSIAM indexing.
    The value is copied as-is without any parsing or transformation.
    """
    for event in events:
        event_time = event.get("time")
        if event_time:
            event["_time"] = event_time
        else:
            demisto.debug(f"[Event Time] WARNING: Event missing 'time' field: {event.get('uuid', 'unknown')}")


def deduplicate_events(events: list[dict[str, Any]], last_fetched_uuids: list[str]) -> list[dict[str, Any]]:
    """Remove already-processed events based on previously fetched UUIDs."""
    if not events:
        demisto.debug("[Dedup] No events to process")
        return events

    if not last_fetched_uuids:
        demisto.debug("[Dedup] No deduplication needed (first run - no previous UUIDs)")
        return events

    demisto.debug(f"[Dedup] Checking {len(events)} events against {len(last_fetched_uuids)} previously fetched UUIDs")

    # Convert to set for O(1) lookup
    fetched_uuids_set = set(last_fetched_uuids)

    # Filter out events that were already fetched
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
                valid_until_timestamp = int(float(cached_valid_until))
                if current_timestamp < valid_until_timestamp:
                    demisto.debug("[Token Cache] Hit! Token is still valid.")
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

        return access_token

    def http_request(
        self, method: str, url_suffix: str, params: dict[str, Any] | None = None, return_full_response: bool = False
    ) -> Any:
        """Execute HTTP request with authentication and detailed logging."""
        access_token = self._get_access_token()
        auth_headers = {APIKeys.HEADER_AUTH.value: f"Bearer {access_token}"}

        demisto.debug(f"[HTTP Call] {method} {url_suffix} | Params: {params}")

        try:
            http_response = self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
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
                raise DemistoException(f"Authentication error: {error_msg}. Please check credentials/certificates.")
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

    def _parse_events_from_response(self, response_body: Any) -> list[dict[str, Any]]:
        """Defensively parse events from a response body."""
        if isinstance(response_body, list):
            return response_body

        # Handle dictionary-based responses
        # SAP BTP Audit log often uses "d" wrapper for OData
        events_list = response_body.get("results") or response_body.get("d", {}).get("results") or []

        # Safety net: Single object response (Edge case)
        if not events_list and isinstance(response_body, dict) and "message_uuid" in response_body:
            demisto.debug("[Response Parser] Detected single object response, wrapping in list.")
            return [response_body]

        return events_list

    def get_audit_log_events(
        self, created_after: str, created_before: str | None = None, pagination_handle: str | None = None
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
            demisto.debug("[API Fetch] Using pagination handle...")
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

        demisto.debug(f"[API Fetch] Page fetched. Count: {len(events_list)}. Next handle exists: {bool(next_page_handle)}")

        return events_list, next_page_handle

    def _extract_pagination_handle(self, headers: dict[str, Any]) -> str | None:
        """Extract handle from the 'Paging' header."""
        demisto.debug("[Pagination] Starting to extract pagination handle from headers.")
        paging_header_value = headers.get(APIKeys.HEADER_PAGING.value) or headers.get(APIKeys.HEADER_PAGING.value.lower())

        if not paging_header_value:
            demisto.debug("[Pagination] No 'Paging' header found. No next page.")
            return None

        if "handle=" not in paging_header_value:
            demisto.debug(f"[Pagination] Header present but 'handle=' missing: {paging_header_value}")
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
    client: Client, created_after: str, created_before: str | None = None, max_events: int = Config.DEFAULT_LIMIT
) -> list[dict[str, Any]]:
    """Fetch events with pagination support.

    Fetches pages until the limit is reached or no more pages exist.
    """
    events: list[dict[str, Any]] = []
    pagination_handle: str | None = None
    page_count = 0

    demisto.debug(f"[Pagination Loop] Start. Goal: {max_events}. Time: {created_after} -> {created_before or 'Now'}")

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

        # Safety break to prevent infinite loops in case of weird API behavior
        if len(events) >= max_events:
            demisto.debug(f"[Pagination Loop] Threshold reached ({len(events)} >= {max_events}). Stopping fetch.")
            break

    if not events:
        demisto.debug("[Pagination Result] No events found.")
        return []

    # Sort events by time (Oldest -> Newest) because SAP usually returns oldest first
    demisto.debug(f"[Pagination Process] Sorting {len(events)} raw events by time...")
    events.sort(key=lambda x: x.get("time", ""))

    # Slice to limit (Keep the Oldest X events)
    if len(events) > max_events:
        demisto.debug(f"[Pagination Loop] Slicing {len(events)} events to limit {max_events}")
        events = events[:max_events]

    return events


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults | str:
    """Manual command to get events."""
    demisto.debug("[Command] get-events triggered")

    start_time_input = args.get("start_time", DefaultValues.FROM_TIME.value)
    end_time_input = args.get("end_time")
    limit = int(args.get("limit", DefaultValues.MAX_FETCH.value))
    should_push_events = argToBoolean(args.get("should_push_events", False))

    created_after = get_formatted_utc_time(start_time_input)
    created_before = get_formatted_utc_time(end_time_input) if end_time_input else None

    demisto.debug(f"[Command Params] From: {created_after}, To: {created_before}, Limit: {limit}, Push: {should_push_events}")

    events = fetch_events_with_pagination(client, created_after, created_before, limit)

    if should_push_events and events:
        add_time_to_events(events)
        send_events_to_xsiam(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)
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

    created_after = get_formatted_utc_time(time_input)

    # Fetch events
    events = fetch_events_with_pagination(client, created_after, None, max_events_to_fetch)

    if not events:
        demisto.debug("[Fetch] No events found.")
        return

    # Deduplicate
    new_events = deduplicate_events(events, last_fetched_uuids)

    if new_events:
        add_time_to_events(new_events)
        send_events_to_xsiam(events=new_events, vendor=Config.VENDOR, product=Config.PRODUCT)
        demisto.debug(f"[Fetch] Pushed {len(new_events)} events to XSIAM")

        # Update Last Run
        last_event = events[-1]
        new_last_run_time = last_event.get("time")

        if new_last_run_time:
            # Collect UUIDs for the new high-water mark timestamp
            uuids_at_last_timestamp = [
                event.get("uuid") for event in events if event.get("time") == new_last_run_time and event.get("uuid")
            ]

            demisto.setLastRun({"last_fetch": new_last_run_time, "last_fetched_uuids": uuids_at_last_timestamp})
            demisto.debug(f"[Fetch] State updated. New HWM: {new_last_run_time}")
        else:
            demisto.debug("[Fetch] Warning: Last event missing time. State not updated.")
    else:
        demisto.debug("[Fetch] All events were duplicates.")


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

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")

        config = parse_integration_params(demisto.params())

        if config["auth_type"] == AuthType.MTLS.value:
            cert_context = temporary_cert_files(config["certificate"], config["private_key"])
        else:
            # Create a dummy context that yields None if not using mTLS
            @contextlib.contextmanager
            def no_op_context():
                yield None

            cert_context = no_op_context()

        with cert_context as cert_data:
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
        error_msg = f"Failed to execute {command}. Error: {str(error)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
