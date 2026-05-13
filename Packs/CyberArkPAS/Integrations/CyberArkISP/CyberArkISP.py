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
    PRODUCT = "ISP"

    # CyberArk ISP date format
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    DEFAULT_LIMIT = 10000
    CACHE_BUFFER_SECONDS = 60

    # Token default settings
    DEFAULT_TOKEN_TTL_SECONDS = 6 * 60 * 60  # 6 hours

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
    # Distinct cache keys for the directory-data (Redrock) auth flow so the
    # audit-events token cache is never overwritten by a token with a different
    # scope (siem vs isp.audit.events:read).
    REDROCK_ACCESS_TOKEN = "redrock_access_token"
    REDROCK_VALID_UNTIL = "redrock_valid_until"


# region Directory-data (Redrock) constants
# =================================
# Constants for the new fetch-assets / Cloud Directory Snapshots feature
# (CIAC-16176). These are intentionally separate from the audit-events
# constants above to keep the two flows decoupled.
# =================================


class DirectorySource(str, Enum):
    """The four CyberArk Cloud Directory sources we collect as snapshots.

    Each value matches the customer-facing label in the integration's
    `directory_data_collection` multi-select config parameter, and maps to a
    distinct XSIAM dataset (see ``DATASET_BY_SOURCE``).
    """

    USERS = "Users"
    GROUPS = "Groups"
    ROLES = "Roles"
    APPLICATIONS = "Applications"


# Per the design doc (CIAC-16176). The Script values are passed verbatim to
# CyberArk's Redrock /Redrock/Query endpoint. They MUST NOT be edited without
# updating the design doc — these are the contract with CyberArk.
REDROCK_QUERY_BY_SOURCE: dict[DirectorySource, str] = {
    DirectorySource.USERS: "SELECT * FROM User",
    DirectorySource.GROUPS: "SELECT * FROM ADGroup",
    DirectorySource.ROLES: "SELECT ID, Name, Description FROM Role",
    DirectorySource.APPLICATIONS: "SELECT ID, Name, AppType FROM Application",
}

# The XSIAM dataset name is `<vendor>_<product>_raw`. We use vendor="cyberark"
# and one product per source so each source lands in its own snapshot dataset
# (e.g. cyberark_users_raw). This is the proven multi-dataset pattern from
# Tenable_io / Qualysv2.
DIRECTORY_VENDOR = "cyberark"
PRODUCT_BY_SOURCE: dict[DirectorySource, str] = {
    DirectorySource.USERS: "users",
    DirectorySource.GROUPS: "groups",
    DirectorySource.ROLES: "roles",
    DirectorySource.APPLICATIONS: "applications",
}

# Stable per-record identifier returned by Redrock in every Row. Used as the
# snapshot dedup key. If a given source returns rows that don't have an "ID"
# field we fall back to a hash of the row dict.
REDROCK_ROW_ID_FIELD = "ID"

# Output context-prefix per source for the manual debug commands.
CONTEXT_PREFIX_BY_SOURCE: dict[DirectorySource, str] = {
    DirectorySource.USERS: "CyberArkISP.User",
    DirectorySource.GROUPS: "CyberArkISP.Group",
    DirectorySource.ROLES: "CyberArkISP.Role",
    DirectorySource.APPLICATIONS: "CyberArkISP.Application",
}

# Default page size for the Redrock query Args.PageSize.
REDROCK_DEFAULT_PAGE_SIZE = 10000

# nextTrigger value the platform recognises. "30" tells the platform to
# re-invoke fetch-assets in ~30 seconds within the same fetch cycle. Matches
# Tenable_io's choice (`Packs/Tenable_io/.../Tenable_io.py:1889`).
NEXT_TRIGGER_VALUE = "30"

# Last-run keys for the assets flow.
ASSETS_LAST_RUN_SNAPSHOT_ID = "snapshot_id"
ASSETS_LAST_RUN_PAGE_INDEX_BY_SOURCE = "page_index_by_source"
ASSETS_LAST_RUN_TOTAL_BY_SOURCE = "total_by_source"
ASSETS_LAST_RUN_PENDING_SOURCES = "pending_sources"


# endregion


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
    PAGE_SIZE = "pageSize"
    QUERY = "query"
    DATE = "date"
    TIMESTAMP = "timestamp"


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
    PAGE_SIZE = 1000


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

    credentials = params.get("credentials", {})
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

    # Directory-data (Redrock) configuration. CIAC-16176.
    # Working assumption: reuse the existing client_id / client_secret against
    # /oauth2/platformtoken with scope=siem. If CyberArk requires a separate
    # OAuth client for the 'siem' scope, swap in two new params
    # `directory_client_id` + `directory_client_secret` here without changing
    # the rest of the pipeline.
    is_fetch_assets = argToBoolean(params.get("isFetchAssets", False))
    directory_data_collection_raw = params.get("directory_data_collection") or []
    directory_sources = parse_directory_sources(directory_data_collection_raw)
    redrock_token_url = f"{identity_url}/oauth2/platformtoken"
    redrock_query_base = f"{identity_url}/Redrock/Query"
    try:
        max_records_per_page = int(params.get("max_assets_per_source_per_page") or REDROCK_DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        max_records_per_page = REDROCK_DEFAULT_PAGE_SIZE
        demisto.debug(f"[Config] max_assets_per_source_per_page invalid; defaulting to {max_records_per_page}")

    demisto.debug(
        f"[Config] Base URL: {base_url} | Token URL: {token_url} | "
        f"is_fetch_assets={is_fetch_assets} | directory_sources={[s.value for s in directory_sources]} | "
        f"redrock_token_url={redrock_token_url}"
    )

    return {
        "base_url": base_url,
        "token_url": token_url,
        "verify": verify_certificate,
        "proxy": proxy,
        "client_id": client_id,
        "client_secret": client_secret,
        "api_key": api_key,
        # Directory-data extras
        "is_fetch_assets": is_fetch_assets,
        "directory_sources": directory_sources,
        "redrock_token_url": redrock_token_url,
        "redrock_query_base": redrock_query_base,
        "max_records_per_page": max_records_per_page,
    }


def parse_directory_sources(raw: Any) -> list[DirectorySource]:
    """Normalise the `directory_data_collection` config value into a list of
    ``DirectorySource`` enum members.

    The XSOAR multi-select widget can deliver either a list (`["Users", "Groups"]`)
    or a comma-separated string (`"Users,Groups"`) depending on platform version.
    Unknown labels are dropped with a debug log so a typo in the config doesn't
    break the entire fetch cycle.
    """
    if isinstance(raw, str):
        raw_items = [item.strip() for item in raw.split(",") if item.strip()]
    elif isinstance(raw, list):
        raw_items = [str(item).strip() for item in raw if str(item).strip()]
    else:
        raw_items = []

    valid_labels = {member.value for member in DirectorySource}
    sources: list[DirectorySource] = []
    for label in raw_items:
        if label in valid_labels:
            sources.append(DirectorySource(label))
        else:
            demisto.debug(f"[Config] Ignoring unknown directory_data_collection value: {label!r}")
    return sources


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Add _time field to events for XSIAM ingestion.

    Maps the event's 'timestamp' field to '_time' for proper XSIAM indexing.
    If an event doesn't have a timestamp, sets _time to current time in milliseconds.
    """
    current_time_ms = int(time.time() * 1000)

    for event in events:
        event_timestamp = event.get("timestamp")
        if event_timestamp:
            event["_time"] = event_timestamp
        else:
            event["_time"] = current_time_ms
            demisto.debug(
                f"[Event Time] WARNING: Event missing 'timestamp' field (UUID: {event.get('uuid', 'unknown')}). "
                f"Using current time: {current_time_ms}"
            )


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

        filter_model: dict[str, Any] = {APIKeys.DATE.value: {APIKeys.DATE_FROM.value: date_from}}
        if date_to:
            filter_model[APIKeys.DATE.value][APIKeys.DATE_TO.value] = date_to

        sort_model = [{APIKeys.FIELD_NAME.value: APIKeys.TIMESTAMP.value, APIKeys.DIRECTION.value: "asc"}]

        request_body = {
            APIKeys.QUERY.value: {
                APIKeys.PAGE_SIZE.value: DefaultValues.PAGE_SIZE.value,
                APIKeys.FILTER_MODEL.value: filter_model,
                APIKeys.SORT_MODEL.value: sort_model,
            }
        }

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

# region Redrock client (Directory Data / fetch-assets)
# =================================
# Separate HTTP client for the new Cloud Directory Snapshots feature.
# Lives alongside Client (audit-events) so the two flows can evolve
# independently. See CIAC-16176 for the design discussion.
# =================================


class RedrockClient(BaseClient):
    """HTTP client for the CyberArk Cloud Directory ``/Redrock/Query`` API.

    Uses the ``/oauth2/platformtoken`` endpoint with Basic-auth
    (``client_id:client_secret``) and ``scope=siem``. The bearer token is
    cached in ``demisto.getIntegrationContext()`` under a separate key from
    the audit-events token to avoid collisions when both flows are active.

    Working assumption (CIAC-16176): the existing ``client_id`` /
    ``client_secret`` from the audit-events config can also be used here.
    If CyberArk requires a separate confidential client, swap the credentials
    for two new params (`directory_client_id` / `directory_client_secret`)
    in ``parse_integration_params``.
    """

    def __init__(
        self,
        identity_url: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
    ):
        identity_url = identity_url.rstrip("/")
        super().__init__(base_url=identity_url, verify=verify, proxy=proxy)
        self.identity_url = identity_url
        self.token_url = f"{identity_url}/oauth2/platformtoken"
        self.query_url_suffix = "/Redrock/Query"
        self.client_id = client_id
        self.client_secret = client_secret

    def _get_access_token(self) -> str:
        """Fetch and cache an OAuth2 token from ``/oauth2/platformtoken``.

        Uses Basic auth (the curl example in the design doc shows
        ``Authorization: Basic XXXXX``) and ``scope=siem``. The token is
        cached for ``expires_in - CACHE_BUFFER_SECONDS`` seconds under
        ``ContextKeys.REDROCK_*`` to avoid clobbering the audit-events token.
        """
        current_timestamp = int(time.time())
        cached_context = get_integration_context() or {}
        cached_token = cached_context.get(ContextKeys.REDROCK_ACCESS_TOKEN.value)
        cached_valid_until = cached_context.get(ContextKeys.REDROCK_VALID_UNTIL.value)

        if cached_token and cached_valid_until:
            try:
                valid_until_timestamp = int(float(cached_valid_until))
                if current_timestamp < valid_until_timestamp:
                    demisto.debug("[Redrock Token Cache] Hit. Reusing cached siem-scope token.")
                    return cached_token
                demisto.debug("[Redrock Token Cache] Miss. Token expired.")
            except (ValueError, TypeError):
                demisto.debug("[Redrock Token Cache] Error parsing cache. Ignoring.")

        demisto.debug(f"[Redrock Token Request] Requesting new token from {self.token_url}")

        basic_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        headers = {
            APIKeys.HEADER_AUTH.value: f"Basic {basic_auth}",
            APIKeys.HEADER_CONTENT_TYPE.value: APIValues.CONTENT_TYPE_FORM.value,
        }
        token_data = {
            APIKeys.GRANT_TYPE.value: APIValues.GRANT_TYPE_CLIENT_CREDENTIALS.value,
            APIKeys.SCOPE.value: "siem",
        }

        try:
            token_response = self._http_request(
                method="POST",
                full_url=self.token_url,
                data=token_data,
                headers=headers,
                resp_type="json",
            )
        except DemistoException as error:
            demisto.error(f"[Redrock Token Request] Failed: {error}")
            raise DemistoException(
                "Failed to obtain Directory-data access token from /oauth2/platformtoken. "
                "If this persists with valid credentials, CyberArk may require a separate "
                "OAuth confidential client for the 'siem' scope. "
                f"Underlying error: {error}"
            )

        access_token = token_response.get(ContextKeys.ACCESS_TOKEN.value)
        if not access_token:
            raise DemistoException("Redrock token response missing access_token field.")

        token_expires_in = token_response.get(ContextKeys.EXPIRES_IN.value, Config.DEFAULT_TOKEN_TTL_SECONDS)
        token_valid_until = current_timestamp + token_expires_in - Config.CACHE_BUFFER_SECONDS

        demisto.debug(f"[Redrock Token Request] Success. Expires in {token_expires_in}s.")

        # Preserve any existing audit-events keys when updating context.
        new_context = dict(cached_context)
        new_context[ContextKeys.REDROCK_ACCESS_TOKEN.value] = access_token
        new_context[ContextKeys.REDROCK_VALID_UNTIL.value] = str(token_valid_until)
        set_integration_context(new_context)

        return access_token

    def query(self, script: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a single Redrock SQL-like query.

        Args:
            script: The SELECT statement (e.g. ``SELECT * FROM User``) — must
                come unchanged from ``REDROCK_QUERY_BY_SOURCE``.
            args:   Optional Args dict (typically ``{"PageNumber": 1, "PageSize": 10000}``).

        Returns:
            Parsed JSON response. Caller is responsible for extracting
            ``Result.Results`` (the list of row dicts).
        """
        access_token = self._get_access_token()
        headers = {
            APIKeys.HEADER_AUTH.value: f"Bearer {access_token}",
            APIKeys.HEADER_CONTENT_TYPE.value: APIValues.CONTENT_TYPE_JSON.value,
            "X-IDAP-NATIVE-CLIENT": "true",
        }
        body: dict[str, Any] = {"Script": script}
        if args:
            body["Args"] = args

        demisto.debug(f"[Redrock Query] POST {self.query_url_suffix} | Script: {script!r} | Args: {args}")
        try:
            response = self._http_request(
                method="POST",
                url_suffix=self.query_url_suffix,
                json_data=body,
                headers=headers,
                resp_type="json",
                ok_codes=(200,),
                retries=2,
                backoff_factor=2,
            )
        except DemistoException as error:
            error_msg = str(error)
            demisto.error(f"[Redrock Query] Failed: {error_msg}")
            if "401" in error_msg or "403" in error_msg:
                raise DemistoException(f"Redrock authentication error: {error_msg}. Verify Client ID / Client Secret.")
            raise

        if not response.get("success", True):
            message = response.get("Message") or response.get("MessageID") or "unknown Redrock error"
            raise DemistoException(f"Redrock query failed: {message}")

        return response


def extract_rows_from_redrock_response(response: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Extract the list of row dicts and a `has_more` flag from a Redrock response.

    The Redrock response shape (per CyberArk docs) is approximately::

        {
            "success": true,
            "Result": {
                "Results": [
                    {"Row": {"ID": "...", "Username": "..."}, "Entities": [...]},
                    ...
                ],
                "FullCount": 12345,
                "Count": 1000,
                "ReturnID": "...",
            }
        }

    We flatten ``Result.Results[*].Row`` into a plain list of row dicts so the
    snapshot pipeline can use them directly.

    ``has_more`` is True when ``FullCount`` is set and is greater than the
    cumulative ``Count`` returned so far in this page; the caller tracks the
    cumulative count across pages.
    """
    result_block = response.get("Result") or {}
    raw_results = result_block.get("Results") or []
    rows: list[dict[str, Any]] = []
    for entry in raw_results:
        row = entry.get("Row") if isinstance(entry, dict) else None
        if isinstance(row, dict):
            rows.append(row)
        elif isinstance(entry, dict):
            # Some sources may return rows directly without a Row wrapper.
            rows.append(entry)

    full_count = result_block.get("FullCount")
    page_count = result_block.get("Count", len(rows))
    has_more = bool(full_count and isinstance(full_count, int) and page_count and page_count >= 0 and full_count > page_count)

    demisto.debug(f"[Redrock Extract] rows={len(rows)} | page_count={page_count} | full_count={full_count} | has_more={has_more}")
    return rows, has_more


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

    # Update Last Run - always update based on ALL fetched events (not just new_events)
    # This ensures we advance the high-water mark even if some/all events were duplicates
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


# region Directory-data (fetch-assets) command implementations
# =================================
# Snapshot-based collection of CyberArk Cloud Directory data (CIAC-16176).
# =================================


def fetch_redrock_page(
    redrock_client: RedrockClient,
    source: DirectorySource,
    page_number: int,
    page_size: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Fetch a single Redrock page for ``source`` and return (rows, has_more).

    Args:
        redrock_client: The Redrock HTTP client.
        source:         Which directory source to query.
        page_number:    1-based page index (Redrock uses 1-based PageNumber).
        page_size:      Args.PageSize value.

    Returns:
        Tuple (rows, has_more) where ``rows`` is the flat list of row dicts and
        ``has_more`` indicates whether another page should be requested.
    """
    script = REDROCK_QUERY_BY_SOURCE[source]
    args = {"PageNumber": page_number, "PageSize": page_size}
    demisto.debug(f"[Fetch Assets] {source.value} page {page_number} (size {page_size}) script={script!r}")
    response = redrock_client.query(script=script, args=args)
    return extract_rows_from_redrock_response(response)


def annotate_assets(rows: list[dict[str, Any]], source: DirectorySource) -> list[dict[str, Any]]:
    """Add a `_source` field and ensure each row has a stable id under ``ID``.

    The dataset will already be partitioned by source (different `product`),
    but having `_source` on every row makes cross-dataset XQL convenient.
    """
    annotated: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        item.setdefault("_source", source.value)
        annotated.append(item)
    return annotated


def push_snapshot(
    rows: list[dict[str, Any]],
    source: DirectorySource,
    snapshot_id: str,
    items_count: int,
) -> None:
    """Send one chunk of a snapshot to XSIAM.

    Uses ``send_data_to_xsiam`` with ``data_type="assets"`` so the platform
    treats the dataset as a snapshot (replace-by-id) rather than an
    append-only event stream. The same ``snapshot_id`` is used across all
    pages of the same source within a fetch cycle (so the platform appends
    chunks to one snapshot); on the final page the caller passes
    ``items_count = total_collected_so_far`` to seal the snapshot.

    Sends regardless of whether ``rows`` is empty so an "empty snapshot"
    intentionally seals an empty source (matches Tenable_io behaviour, see
    CIAC-16176 design questions Q3).
    """
    product = PRODUCT_BY_SOURCE[source]
    demisto.info(
        f"[Fetch Assets] Pushing {len(rows)} {source.value} rows to "
        f"{DIRECTORY_VENDOR}_{product}_raw (snapshot_id={snapshot_id}, items_count={items_count})"
    )
    send_data_to_xsiam(
        data=rows,
        vendor=DIRECTORY_VENDOR,
        product=product,
        data_type="assets",
        snapshot_id=snapshot_id,
        items_count=items_count,
    )


def fetch_assets_command(redrock_client: RedrockClient, config: dict[str, Any]) -> None:
    """Snapshot fetch orchestrator. Called by the platform on the assets-fetch
    schedule when ``isFetchAssets`` is enabled.

    Within one customer-configured fetch cycle, this function may be invoked
    multiple times via ``nextTrigger``. Each invocation processes the next
    chunk of work for the next pending source. State is persisted in
    ``demisto.getAssetsLastRun()`` between invocations:

    * ``snapshot_id`` — generated once per cycle, reused across all pages
      and across all sources within the cycle.
    * ``page_index_by_source`` — 1-based next page number to request for
      each source. ``0`` means "this source is done".
    * ``total_by_source`` — cumulative row count per source so we can seal
      with the correct ``items_count``.
    * ``pending_sources`` — list of selected sources still to process this
      cycle. Sources that complete are removed.

    Behaviours intentionally chosen for V1:

    * Zero-rows source still gets a sealed empty snapshot (mirrors Tenable_io;
      ensures a CyberArk-side deletion of all rows in a source is reflected
      in the dataset on the next fetch).
    * Partial-failure: a transient error in one source aborts that source
      for this cycle, but other sources continue. The failed source will
      retry from page 1 on the next cycle.
    """
    sources: list[DirectorySource] = config["directory_sources"]
    if not sources:
        demisto.debug("[Fetch Assets] No directory sources selected; nothing to do.")
        return

    last_run = demisto.getAssetsLastRun() or {}
    snapshot_id: str = last_run.get(ASSETS_LAST_RUN_SNAPSHOT_ID) or str(round(time.time() * 1000))
    page_index_by_source: dict[str, int] = dict(last_run.get(ASSETS_LAST_RUN_PAGE_INDEX_BY_SOURCE) or {})
    total_by_source: dict[str, int] = dict(last_run.get(ASSETS_LAST_RUN_TOTAL_BY_SOURCE) or {})
    pending_sources_raw: list[str] = list(last_run.get(ASSETS_LAST_RUN_PENDING_SOURCES) or [src.value for src in sources])

    # Initialise state for any selected source that doesn't have it yet (first
    # invocation of a new cycle). A source enabled by the customer mid-cycle
    # waits for the next cycle's fresh start to avoid clobbering the active
    # snapshot_id with a partially-initialised source — that's the right
    # semantics, not a bug.
    for src in sources:
        page_index_by_source.setdefault(src.value, 1)
        total_by_source.setdefault(src.value, 0)

    pending_sources = [DirectorySource(v) for v in pending_sources_raw if v in {s.value for s in sources}]
    page_size = int(config.get("max_records_per_page") or REDROCK_DEFAULT_PAGE_SIZE)

    demisto.debug(
        f"[Fetch Assets] cycle snapshot_id={snapshot_id} | pending={[s.value for s in pending_sources]} | "
        f"page_index_by_source={page_index_by_source} | total_by_source={total_by_source}"
    )

    if not pending_sources:
        # All sources completed in a previous nextTrigger pass; clear state
        # so the next scheduled cycle starts fresh.
        demisto.debug("[Fetch Assets] No pending sources; cycle is complete. Clearing assets last-run state.")
        demisto.setAssetsLastRun({})
        return

    # Process the FIRST pending source this invocation. Other pending sources
    # are deferred to the next nextTrigger so each invocation does bounded work.
    current_source = pending_sources[0]
    current_page = page_index_by_source[current_source.value]

    try:
        rows, has_more = fetch_redrock_page(
            redrock_client=redrock_client,
            source=current_source,
            page_number=current_page,
            page_size=page_size,
        )
    except Exception as error:
        # Q4 partial-failure: drop this source from the cycle so the others
        # can still complete. State for the failed source is reset so it
        # restarts cleanly on the next cycle.
        demisto.error(
            f"[Fetch Assets] Source {current_source.value} failed on page {current_page}: {error}. "
            "Removing from this cycle; will retry next cycle."
        )
        pending_sources_raw = [v for v in pending_sources_raw if v != current_source.value]
        page_index_by_source[current_source.value] = 1
        total_by_source[current_source.value] = 0
        _save_assets_state(snapshot_id, page_index_by_source, total_by_source, pending_sources_raw)
        return

    annotated = annotate_assets(rows, current_source)
    new_total = total_by_source[current_source.value] + len(annotated)

    if has_more:
        # Mid-cycle chunk: send with items_count=1 so the platform knows more
        # chunks are coming for this snapshot_id+product. Advance page index.
        push_snapshot(annotated, current_source, snapshot_id=snapshot_id, items_count=1)
        page_index_by_source[current_source.value] = current_page + 1
        total_by_source[current_source.value] = new_total
        next_run_payload = _build_next_run(
            snapshot_id, page_index_by_source, total_by_source, pending_sources_raw, has_pending_work=True
        )
        demisto.setAssetsLastRun(next_run_payload)
        demisto.debug(
            f"[Fetch Assets] {current_source.value} page {current_page} pushed; "
            f"more pages remain. Next page={current_page + 1}, cumulative={new_total}."
        )
        return

    # Last page for this source: seal the snapshot with items_count=cumulative.
    push_snapshot(annotated, current_source, snapshot_id=snapshot_id, items_count=new_total)
    pending_sources_raw = [v for v in pending_sources_raw if v != current_source.value]
    page_index_by_source[current_source.value] = 0  # done marker
    total_by_source[current_source.value] = new_total

    demisto.info(
        f"[Fetch Assets] {current_source.value} sealed: {new_total} rows in snapshot {snapshot_id}. "
        f"Remaining sources this cycle: {pending_sources_raw}"
    )

    next_run_payload = _build_next_run(
        snapshot_id,
        page_index_by_source,
        total_by_source,
        pending_sources_raw,
        has_pending_work=bool(pending_sources_raw),
    )
    demisto.setAssetsLastRun(next_run_payload)


def _build_next_run(
    snapshot_id: str,
    page_index_by_source: dict[str, int],
    total_by_source: dict[str, int],
    pending_sources_raw: list[str],
    has_pending_work: bool,
) -> dict[str, Any]:
    """Build the dict to persist via ``demisto.setAssetsLastRun``.

    When ``has_pending_work`` is True we include ``nextTrigger`` so the
    platform re-invokes us within the same fetch cycle. When False we omit
    it so the next invocation happens at the regular schedule and we drop
    the in-flight cycle state.
    """
    payload: dict[str, Any] = {
        ASSETS_LAST_RUN_SNAPSHOT_ID: snapshot_id,
        ASSETS_LAST_RUN_PAGE_INDEX_BY_SOURCE: page_index_by_source,
        ASSETS_LAST_RUN_TOTAL_BY_SOURCE: total_by_source,
        ASSETS_LAST_RUN_PENDING_SOURCES: pending_sources_raw,
    }
    if has_pending_work:
        payload["nextTrigger"] = NEXT_TRIGGER_VALUE
    return payload


def _save_assets_state(
    snapshot_id: str,
    page_index_by_source: dict[str, int],
    total_by_source: dict[str, int],
    pending_sources_raw: list[str],
) -> None:
    """Convenience wrapper that calls ``setAssetsLastRun`` based on whether
    there is more pending work."""
    payload = _build_next_run(
        snapshot_id, page_index_by_source, total_by_source, pending_sources_raw, has_pending_work=bool(pending_sources_raw)
    )
    demisto.setAssetsLastRun(payload)


def get_assets_command(
    redrock_client: RedrockClient,
    args: dict[str, Any],
    source: DirectorySource,
    config: dict[str, Any],
) -> CommandResults | str:
    """Generic implementation for the four ``cyberark-isp-get-<source>`` debug
    commands. Fetches a single Redrock page for the requested source and
    optionally pushes it to XSIAM.

    Caution: pushing manually mid-cycle uses a fresh snapshot_id and may
    interfere with the scheduled fetch cycle's snapshot sealing.
    """
    limit = int(args.get("limit", "50"))
    should_push = argToBoolean(args.get("should_push_assets", False))
    page_size = min(limit, int(config.get("max_records_per_page") or REDROCK_DEFAULT_PAGE_SIZE))

    demisto.debug(f"[Manual Assets] source={source.value} limit={limit} push={should_push} page_size={page_size}")

    rows, _ = fetch_redrock_page(redrock_client=redrock_client, source=source, page_number=1, page_size=page_size)
    annotated = annotate_assets(rows[:limit], source)

    if should_push and annotated:
        snapshot_id = str(round(time.time() * 1000))
        push_snapshot(annotated, source, snapshot_id=snapshot_id, items_count=len(annotated))
        msg = (
            f"Successfully retrieved and pushed {len(annotated)} {source.value} record(s) to "
            f"{DIRECTORY_VENDOR}_{PRODUCT_BY_SOURCE[source]}_raw (snapshot_id={snapshot_id})."
        )
        return msg

    readable = tableToMarkdown(f"{INTEGRATION_NAME} - {source.value}", annotated, removeNull=True)
    return CommandResults(
        readable_output=readable,
        outputs_prefix=CONTEXT_PREFIX_BY_SOURCE[source],
        outputs_key_field=REDROCK_ROW_ID_FIELD,
        outputs=annotated,
    )


# endregion

# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "cyberark-isp-get-events": get_events_command,
    "fetch-events": fetch_events_command,
    # New for CIAC-16176. fetch-assets is dispatched by the platform when
    # isFetchAssets=true. The four cyberark-isp-get-* commands are manual
    # debug commands the user can invoke from the playground / REST API.
    "fetch-assets": fetch_assets_command,
    "cyberark-isp-get-users": get_assets_command,
    "cyberark-isp-get-groups": get_assets_command,
    "cyberark-isp-get-roles": get_assets_command,
    "cyberark-isp-get-applications": get_assets_command,
}

DIRECTORY_COMMAND_TO_SOURCE: dict[str, DirectorySource] = {
    "cyberark-isp-get-users": DirectorySource.USERS,
    "cyberark-isp-get-groups": DirectorySource.GROUPS,
    "cyberark-isp-get-roles": DirectorySource.ROLES,
    "cyberark-isp-get-applications": DirectorySource.APPLICATIONS,
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
        elif command == "fetch-assets":
            redrock_client = _build_redrock_client(config)
            command_func(redrock_client, config)  # pylint: disable=E1120
        elif command in DIRECTORY_COMMAND_TO_SOURCE:
            redrock_client = _build_redrock_client(config)
            source = DIRECTORY_COMMAND_TO_SOURCE[command]
            result = command_func(redrock_client, demisto.args(), source, config)
            return_results(result)
        else:
            result = command_func(client, demisto.args())
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {str(error)}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


def _build_redrock_client(config: dict[str, Any]) -> RedrockClient:
    """Construct a RedrockClient from the parsed integration config.

    Lives outside ``main()`` so unit tests can build one directly.
    """
    # The Redrock token URL is derived from identity_url. We pull the
    # identity host out of redrock_token_url so we don't need an extra config
    # key just for this.
    identity_root = config["redrock_token_url"].rsplit("/oauth2/platformtoken", 1)[0]
    return RedrockClient(
        identity_url=identity_root,
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        verify=config["verify"],
        proxy=config["proxy"],
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
