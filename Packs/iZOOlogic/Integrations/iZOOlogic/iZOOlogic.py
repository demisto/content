import asyncio
import json
import threading
import traceback
from datetime import datetime, UTC
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *

"""
iZOOlogic
Integration for fetching threat incidents from the iZOOlogic API.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "iZOOlogic"


class ApiPaths:
    """Centralized iZOOlogic API endpoint paths."""

    AUTHENTICATE = "/api/Token/Authenticate"
    FETCH_INCIDENTS = "/api/ThreatManagement/FetchIncidents"
    REPORT_NEW_INCIDENT = "/api/ThreatManagement/ReportNewIncident"


class Config:
    """Global static configuration."""

    # Pagination
    DEFAULT_LIMIT = 50
    DEFAULT_MAX_FETCH_PER_TYPE = 5000

    # Fetch defaults
    DEFAULT_FROM_TIME = "5 minutes ago"
    DEFAULT_FETCH_COMMAND_FROM_TIME = "1 day ago"

    # Max date range for API (31 days)
    MAX_DATE_RANGE_DAYS = 31


class ApiCodes:
    """Centralized API code mappings used across multiple commands."""

    # API error codes
    NO_DATA_FOUND = "iZOO2011"

    # Mapping of incident type display names to API integer codes
    INCIDENT_TYPE: dict[str, int] = {
        "brand abuse": 1,
        "phishing": 2,
        "malware": 3,
        "pharming": 4,
        "smishing": 5,
        "vishing": 6,
        "mobile apps": 7,
        "social media": 8,
        "other": 9,
        "email": 23,
        "executive": 56,
    }

    # Mapping of threat type display names to API integer codes
    THREAT_TYPE: dict[str, int] = {
        "low threat": 10,
        "moderate threat": 11,
        "substantial threat": 12,
        "high threat": 13,
        "critical threat": 14,
        "redirect to whitelist": 48,
    }

    # Mapping of case type display names to API integer codes
    CASE_TYPE: dict[str, int] = {
        "incident": 6,
        "brand abuse monitoring": 2,
        "domain monitoring": 1,
        "social media monitoring": 4,
        "mobile app monitoring": 3,
        "executive monitoring": 5,
    }


def date_to_unix_timestamp(date_input: str) -> str:
    """Parse a date string and return a Unix timestamp string for the iZOOlogic API.

    Args:
        date_input: Date string to parse (e.g., '3 days ago', '2024-01-01T00:00:00Z').

    Returns:
        Unix timestamp as a string.
    """
    parsed_dt = parse_date(date_input)
    timestamp = str(int(parsed_dt.timestamp()))
    demisto.debug(f"[Date Helper] Input: '{date_input}' -> Unix timestamp: '{timestamp}'")
    return timestamp


def get_current_unix_timestamp() -> str:
    """Return the current UTC time as a Unix timestamp string.

    Returns:
        Current Unix timestamp as a string.
    """
    timestamp = str(int(datetime.now(UTC).timestamp()))
    demisto.debug(f"[Date Helper] Current UTC Unix timestamp: '{timestamp}'")
    return timestamp


def snap_to_day_boundary_utc(unix_timestamp: str, boundary: str = "start") -> str:
    """Snap a Unix timestamp to a UTC day boundary.

    The iZOOlogic API uses day-level filtering with the following rules:

    * ``fromdate`` is **rounded up** to the next UTC midnight (unless already
      at midnight).  The resulting day is **inclusive**.
    * ``todate`` is **floored** to its UTC midnight.  The resulting day is
      **inclusive**.
    * The effective range is ``[ceil(fromdate)_day, floor(todate)_day]``.

    Because ``fromdate`` rounds *up*, a non-midnight value skips the current
    day entirely.  Snapping to ``"start"`` (midnight) prevents this.

    For same-day queries where ``fromdate == todate`` (both at midnight), the
    API rejects the request.  Snapping ``todate`` to ``"end"`` (23:59:59)
    keeps it on the same day after flooring, producing ``[Day, Day]``.

    Args:
        unix_timestamp: Unix timestamp as a string.
        boundary: Either ``"start"`` (00:00:00) or ``"end"`` (23:59:59).

    Returns:
        Unix timestamp string snapped to the requested boundary of the same UTC day.
    """
    dt = datetime.fromtimestamp(int(unix_timestamp), tz=UTC)
    if boundary == "end":
        snapped = dt.replace(hour=23, minute=59, second=59, microsecond=0)
    else:
        snapped = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    result = str(int(snapped.timestamp()))
    demisto.debug(f"[DayBoundary:{boundary}] {unix_timestamp} -> {result}")
    return result


def parse_date(date_string: str) -> datetime:
    """Parse a date string into a datetime object.

    Args:
        date_string: Date string to parse (e.g., '3 days ago', '2024-01-01T00:00:00Z').

    Returns:
        Parsed datetime object in UTC.

    Raises:
        DemistoException: If the date string cannot be parsed.
    """
    demisto.debug(f"[Date Helper] Attempting to parse date string: '{date_string}'")
    parsed_datetime = arg_to_datetime(arg=date_string, is_utc=True)

    if not parsed_datetime:
        raise DemistoException(
            f"Failed to parse date string: '{date_string}'. "
            "Please provide a valid date in ISO 8601 format (e.g., '2024-01-01T00:00:00Z') "
            "or a relative time expression (e.g., '3 days ago')."
        )

    demisto.debug(f"[Date Helper] Final parsed date: {parsed_datetime.isoformat()}")
    return parsed_datetime


def create_incidents(raw_incidents: list[dict]) -> list[dict]:
    """Convert API incidents to Cortex incident format.

    Each incident includes a name, occurred timestamp, and the full raw data as rawJSON.

    Args:
        raw_incidents: List of incident dictionaries from the API.

    Returns:
        List of Cortex incident dictionaries.
    """
    incidents: list[dict] = []
    for raw in raw_incidents:
        incident_type = raw.get("incidentType", "Unknown")
        incident_id = raw.get("incidentID", "Unknown")
        created_on = raw.get("createdOn", "")

        occurred_iso = datetime.fromtimestamp(int(created_on), tz=UTC).isoformat() if created_on else ""

        incident = {
            "name": f"iZOOlogic - {incident_type} - {incident_id}",
            "occurred": occurred_iso,
            "rawJSON": json.dumps(raw),
        }
        incidents.append(incident)

    demisto.debug(f"[Convert] Converted {len(incidents)} raw incidents to Cortex incidents")
    return incidents


def filter_by_ids(raw_incidents: list[dict], ids_to_skip: list[str]) -> list[dict]:
    """Filter out incidents whose IDs are in the given skip set.

    Args:
        raw_incidents: List of incident dictionaries from the API.
        ids_to_skip: List of incident IDs to filter out.

    Returns:
        List of incidents not in the skip set.
    """
    if not raw_incidents or not ids_to_skip:
        return raw_incidents

    skip_set = set(ids_to_skip)
    filtered = [inc for inc in raw_incidents if inc.get("incidentID") not in skip_set]

    skipped = len(raw_incidents) - len(filtered)
    if skipped > 0:
        demisto.debug(f"[Filter] Skipped {skipped} incidents by ID. {len(filtered)} remain.")

    return filtered


def _validate_api_response(response: dict) -> dict:
    """Validate the API response and return the 'result' object.

    Handles known non-error codes like 'no data found' gracefully.

    Args:
        response: The full API response dictionary.

    Returns:
        The 'result' object from the response, or empty dict if no data found.

    Raises:
        DemistoException: If the API returned a real error.
    """
    if not response.get("success", True):
        error_code = response.get("errorCode", "")
        message = response.get("message", "Unknown error")

        if error_code == ApiCodes.NO_DATA_FOUND:
            demisto.debug(f"[API] No data found for the given time range (errorCode: {error_code})")
            return {}

        raise DemistoException(f"API error: {message} (errorCode: {error_code})")

    result = response.get("result", {})
    demisto.debug(
        f"[API Response] currentPage={result.get('currentPage')}, "
        f"totalRecords={result.get('totalRecords')}, "
        f"message={response.get('message')}, "
        f"errorCode={response.get('errorCode')}"
    )
    return result


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate integration configuration parameters.

    Args:
        params: Raw parameters from demisto.params().

    Returns:
        Validated configuration dictionary.

    Raises:
        DemistoException: If required parameters are missing or invalid.
    """
    base_url = params.get("url", "").rstrip("/")
    if not base_url:
        raise DemistoException("Server URL is required.")

    api_key_param = params.get("api_key", {})
    api_key = api_key_param.get("password", "") if isinstance(api_key_param, dict) else api_key_param
    if not api_key:
        raise DemistoException("API Key is required.")

    secret_key_param = params.get("secret_key", {})
    secret_key = secret_key_param.get("password", "") if isinstance(secret_key_param, dict) else secret_key_param
    if not secret_key:
        raise DemistoException("Secret Key is required.")

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    # Parse and validate incident types filter — default to all types if none specified
    incident_types_filter = argToList(params.get("incident_types_filter"))
    incident_type_codes = (
        resolve_type_codes(incident_types_filter) if incident_types_filter else list(ApiCodes.INCIDENT_TYPE.values())
    )

    max_fetch = int(params.get("max_fetch", Config.DEFAULT_MAX_FETCH_PER_TYPE))
    if max_fetch <= 0:
        raise DemistoException(f"Invalid max_fetch value: {params.get('max_fetch')}. Must be a positive integer.")

    demisto.debug(f"[Config] URL: {base_url}")

    return {
        "base_url": base_url,
        "api_key": api_key,
        "secret_key": secret_key,
        "verify": verify_certificate,
        "proxy": proxy,
        "incident_type_codes": incident_type_codes,
        "max_fetch": max_fetch,
    }


def validate_date_range(from_date: str, to_date: str) -> None:
    """Validate that the date range is valid and does not exceed the API maximum of 31 days.

    Checks:
    1. ``to_date`` must not be earlier than ``from_date`` (different-day inversion).
    2. The span must not exceed ``Config.MAX_DATE_RANGE_DAYS`` (31 days).

    Note: same-day cases where ``to_date == from_date`` after snapping to midnight
    are handled separately by callers (e.g. ``get_incidents_command``).

    Args:
        from_date: Start date as Unix timestamp string.
        to_date: End date as Unix timestamp string.

    Raises:
        DemistoException: If the date range is inverted or exceeds 31 days.
    """
    from_dt = datetime.fromtimestamp(int(from_date), tz=UTC)
    to_dt = datetime.fromtimestamp(int(to_date), tz=UTC)

    if to_dt.date() < from_dt.date():
        raise DemistoException(
            f"'end_time' ({to_dt.isoformat()}) is before 'start_time' ({from_dt.isoformat()}). "
            "Please provide a valid date range where end_time >= start_time."
        )

    if (to_dt - from_dt).days > Config.MAX_DATE_RANGE_DAYS:
        raise DemistoException(
            f"Date range exceeds the maximum of {Config.MAX_DATE_RANGE_DAYS} days. "
            f"From: {from_dt.isoformat()}, To: {to_dt.isoformat()}."
        )


def resolve_type_codes(type_names: list[str]) -> list[int]:
    """Resolve incident type display names to API codes.

    Args:
        type_names: List of incident type display names (e.g., ['phishing', 'malware']).

    Returns:
        List of API integer codes.

    Raises:
        DemistoException: If any type name is invalid.
    """
    codes: list[int] = []
    for name in type_names:
        code = ApiCodes.INCIDENT_TYPE.get(name.lower().strip())
        if code is None:
            raise DemistoException(f"Invalid incident type: '{name}'. Valid types: {list(ApiCodes.INCIDENT_TYPE.keys())}")
        codes.append(code)
    return codes


# endregion

# region Auth Handler
# =================================
# Auth Handler
# =================================


class IZOOlogicAuthHandler(AuthHandler):
    """Custom authentication handler for iZOOlogic two-step token auth.

    Flow:
    1. POST to /api/Token/Authenticate with apikey + secretkey → get accesstoken
    2. Set Authorization: Bearer <accesstoken> on each request
    3. On 401, re-authenticate and retry
    """

    name = "izoologic_token"

    def __init__(self, api_key: str, secret_key: str):
        self._api_key = api_key
        self._secret_key = secret_key
        self._token: str | None = None
        self._authenticating: bool = False
        self._auth_lock = threading.Lock()

    async def on_request(self, client: ContentClient, request: Any) -> None:
        """Add Bearer token to each request, authenticating if needed."""
        if self._authenticating:
            return  # Skip auth for the auth request itself to prevent recursion
        if not self._token:
            await self._authenticate(client)
        request.headers["Authorization"] = f"Bearer {self._token}"

    async def on_auth_failure(self, client: ContentClient, response: Any) -> bool:
        """Re-authenticate on 401 and retry the request."""
        demisto.debug("[Auth] Authentication failed (401). Re-authenticating...")
        self._token = None  # Clear expired token so _authenticate doesn't skip
        await self._authenticate(client)
        return True  # Retry the request with new token

    async def _authenticate(self, client: ContentClient) -> None:
        """Authenticate with the iZOOlogic API and store the token.

        Uses a threading.Lock to ensure thread safety when concurrent fetches
        run via asyncio.to_thread. The double-check on self._token prevents
        redundant auth calls when multiple threads queue up on the lock.
        """
        with self._auth_lock:
            if self._token:
                demisto.debug("[Auth] Token already obtained by another thread, skipping.")
                return

            demisto.debug("[Auth] Authenticating with iZOOlogic API...")
            self._authenticating = True

            try:
                body = {
                    "apikey": self._api_key,
                    "secretkey": self._secret_key,
                }

                raw_response = await client._request(
                    method="POST",
                    url_suffix=ApiPaths.AUTHENTICATE,
                    json_data=body,
                )
                response: dict = raw_response.json()

                if not response.get("success", True):
                    error_code = response.get("errorCode", "")
                    message = response.get("message", "Unknown error")
                    raise DemistoException(
                        f"Authentication failed: {message} (errorCode: {error_code}). "
                        "Verify your API Key and Secret Key are correct."
                    )

                result = response.get("result", {})
                token = result.get("accessToken") if isinstance(result, dict) else None
                if not token:
                    raise DemistoException(
                        "Authentication failed: No token received from the API. "
                        "Verify your API Key and Secret Key are correct."
                    )

                self._token = token
                demisto.debug("[Auth] Successfully authenticated")
            finally:
                self._authenticating = False


# endregion

# region Client
# =================================
# Client
# =================================


class Client(ContentClient):
    """iZOOlogic API client.

    Extends ContentClient with iZOOlogic-specific API methods.
    Authentication is handled automatically by IZOOlogicAuthHandler.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        secret_key: str,
        verify: bool,
        proxy: bool,
    ):
        """Initialize the iZOOlogic client.

        Args:
            base_url: iZOOlogic API server URL.
            api_key: API key for authentication.
            secret_key: Secret key for authentication.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use proxy settings.
        """
        auth_handler = IZOOlogicAuthHandler(api_key, secret_key)
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            auth_handler=auth_handler,
            client_name="iZOOlogic",
        )

    def fetch_incidents_page(
        self,
        from_date: str,
        to_date: str,
        incident_type: int | None = None,
        page_token: str | None = None,
        threat_type: int | None = None,
        brand_code: str | None = None,
        executive_name: str | None = None,
        client_ref_id: str | None = None,
        client_code: str | None = None,
    ) -> dict[str, Any]:
        """Fetch a single page of incidents from the iZOOlogic API.

        The API uses day-level filtering: ``fromdate`` is rounded up to the
        next UTC midnight (inclusive), ``todate`` is floored to its UTC
        midnight (inclusive).  The effective range is
        ``[ceil(fromdate)_day, floor(todate)_day]``.

        Args:
            from_date: Start date as Unix timestamp string (must be midnight UTC
                to avoid the round-up skipping the intended day).
            to_date: End date as Unix timestamp string (floored to its day by the API).
            incident_type: Optional incident type code to filter by.
            page_token: Pagination token for retrieving the next page.
            threat_type: Optional threat level code to filter by.
            brand_code: Optional brand identifier to filter by.
            executive_name: Optional executive name to filter by.
            client_ref_id: Optional client reference ID for specific incident lookup.
            client_code: Optional client identifier to filter by.

        Returns:
            The 'result' object from the API response containing incidents and pagination info.
        """
        body: dict[str, Any] = assign_params(
            fromdate=from_date,
            todate=to_date,
            incidenttype=incident_type,
            token=page_token,
            threattype=threat_type,
            brandcode=brand_code,
            executivename=executive_name,
            clientrefid=client_ref_id,
            clientcode=client_code,
        )

        demisto.debug(f"[API Fetch] Fetching incidents | Params: {body}")

        response = self._http_request(
            method="POST",
            url_suffix=ApiPaths.FETCH_INCIDENTS,
            json_data=body,
        )

        return _validate_api_response(response)

    def report_new_incident(
        self,
        incident_url: str,
        incident_type: int,
        brand_code: str,
        threat_type: int | None = None,
        case_type: int | None = None,
        comment: str | None = None,
        executive_name: str | None = None,
        client_code: str | None = None,
    ) -> dict[str, Any]:
        """Report a new security incident to the iZOOlogic API.

        Args:
            incident_url: URL, email, or target of the security incident (max 1000 chars).
            incident_type: Type of incident (API integer code).
            brand_code: Brand identifier associated with the incident.
            threat_type: Optional threat level code. Defaults to moderate threat if not specified.
            case_type: Optional case type code. Defaults to incident (6) if not specified.
            comment: Optional comments about the incident (max 2500 chars).
            executive_name: Optional executive name for executive-related incidents (max 2500 chars).
            client_code: Optional client identifier for validation and access control.

        Returns:
            The full API response dictionary.
        """
        body: dict[str, Any] = assign_params(
            incidenturl=incident_url,
            incidenttype=incident_type,
            brandcode=brand_code,
            threattype=threat_type,
            casetype=case_type,
            comment=comment,
            executivename=executive_name,
            clientcode=client_code,
        )

        demisto.debug(f"[API ReportNewIncident] Creating incident | Params: {body}")

        response = self._http_request(
            method="POST",
            url_suffix=ApiPaths.REPORT_NEW_INCIDENT,
            json_data=body,
        )

        return response


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by authenticating and fetching incidents.

    Uses _fetch_all_pages with midnight UTC of today as fromdate.
    An empty result (no incidents) still proves connectivity — the test passes.

    Args:
        client: The iZOOlogic client.

    Returns:
        'ok' if test passed, otherwise raises an exception.
    """
    demisto.debug("[Test Module] Starting...")
    try:
        from_date = snap_to_day_boundary_utc(get_current_unix_timestamp(), "start")
        to_date = get_current_unix_timestamp()

        _fetch_all_pages(client, from_date=from_date, to_date=to_date)

        demisto.debug("[Test Module] Success")
        return "ok"

    except Exception as error:
        error_msg = str(error)
        demisto.debug(f"[Test Module] Failed: {error_msg}")
        if "401" in error_msg or "403" in error_msg or "unauthorized" in error_msg.lower():
            return "Authorization Error: Verify your API Key and Secret Key."
        raise


def _fetch_all_pages(
    client: Client,
    from_date: str,
    to_date: str,
    incident_type: int | None = None,
    threat_type: int | None = None,
    brand_code: str | None = None,
    executive_name: str | None = None,
    client_ref_id: str | None = None,
    client_code: str | None = None,
) -> list[dict]:
    """Fetch ALL pages of incidents until pagination is exhausted.

    Loops through all pages using opaque nextPage tokens until nextPage is null
    or the API returns an empty page. No max_results cap — fetches everything
    in the time window.

    Used by all commands: test_module, get_incidents_command, fetch_incidents_command,
    and izoolabs_incident_fetch_command.

    Args:
        client: The iZOOlogic client.
        from_date: Start date as Unix timestamp string (must be midnight UTC).
        to_date: End date as Unix timestamp string.
        incident_type: Optional incident type code.
        threat_type: Optional threat level code to filter by.
        brand_code: Optional brand identifier to filter by.
        executive_name: Optional executive name to filter by.
        client_ref_id: Optional client reference ID for specific incident lookup.
        client_code: Optional client identifier to filter by.

    Returns:
        List of ALL raw incident dictionaries from all pages.
    """
    all_incidents: list[dict] = []
    page_token: str | None = None
    page_count = 0

    while True:
        result_obj = client.fetch_incidents_page(
            from_date=from_date,
            to_date=to_date,
            incident_type=incident_type,
            page_token=page_token,
            threat_type=threat_type,
            brand_code=brand_code,
            executive_name=executive_name,
            client_ref_id=client_ref_id,
            client_code=client_code,
        )

        page_incidents = result_obj.get("incidents") or []
        if not page_incidents:
            break

        all_incidents.extend(page_incidents)
        page_count += 1
        demisto.debug(
            f"[FetchAll] Type {incident_type or 'all'} | Page {page_count}: "
            f"+{len(page_incidents)} incidents (total: {len(all_incidents)})"
        )

        page_token = result_obj.get("nextPage")
        if not page_token:
            break

    demisto.debug(
        f"[FetchAll] Type {incident_type or 'all'} | Done: {len(all_incidents)} incidents " f"across {page_count} pages"
    )
    return all_incidents


def get_incidents_command(
    client: Client,
    args: dict,
    default_type_codes: list[int],
) -> CommandResults:
    """Manual command to get incidents for debugging/development.

    Args:
        client: The iZOOlogic client.
        args: Command arguments.
        default_type_codes: Default incident type codes from integration config.

    Returns:
        CommandResults with the retrieved incidents.
    """
    demisto.debug("[Command] izoologic-get-incidents triggered")

    limit = arg_to_number(args.get("limit", Config.DEFAULT_LIMIT))
    if not limit or limit <= 0:
        raise DemistoException(f"Invalid limit value: {args.get('limit')}. Must be a positive integer.")
    limit = int(limit)

    start_time_input = args.get("start_time", Config.DEFAULT_FROM_TIME)
    end_time_input = args.get("end_time")

    # Use incident_type from command args if provided, otherwise fall back to config
    incident_type_arg = argToList(args.get("incident_type"))
    type_codes = resolve_type_codes(incident_type_arg) if incident_type_arg else default_type_codes

    from_ts = date_to_unix_timestamp(start_time_input)
    from_date = snap_to_day_boundary_utc(from_ts, "start")
    to_date = date_to_unix_timestamp(end_time_input) if end_time_input else get_current_unix_timestamp()

    validate_date_range(from_date, to_date)

    # When from_date and to_date are both at midnight of the same day, the API
    # rejects the request ("from date should not be greater than or equal to
    # to date").  Snap to_date to 23:59:59 so the API floors it to the same
    # day, producing the valid range [Day, Day].
    if int(to_date) == int(from_date):
        to_date = snap_to_day_boundary_utc(to_date, "end")

    demisto.debug(
        f"[Command Params] From: {from_date} (requested: {from_ts}), To: {to_date}, Limit: {limit}, Types: {type_codes}"
    )

    all_incidents: list[dict] = []
    for type_code in type_codes:
        type_incidents = _fetch_all_pages(
            client,
            from_date=from_date,
            to_date=to_date,
            incident_type=type_code,
        )
        # Client-side filter: the API returns all incidents in the
        # [ceil(fromdate)_day, floor(todate)_day] day range, so discard
        # incidents outside the precise requested timestamp range.
        type_incidents = [inc for inc in type_incidents if int(from_ts) <= int(inc.get("createdOn", "0")) <= int(to_date)]
        all_incidents.extend(type_incidents[:limit])

    demisto.debug(f"[Command Result] Total incidents retrieved: {len(all_incidents)} (limit per type: {limit})")

    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} Incidents", all_incidents, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="iZOOlogic.Incident",
        outputs_key_field="incidentID",
        outputs=all_incidents,
    )


def _filter_and_dedup(
    raw_incidents: list[dict],
    last_created_on: str | None,
    last_ids: list[str],
    type_key: str,
) -> list[dict]:
    """Filter out already-seen incidents and deduplicate by ID.

    Steps:
    1. Discard incidents with ``createdOn`` strictly before ``last_created_on``.
    2. For incidents at exactly ``last_created_on``, remove those in ``last_ids``.

    Args:
        raw_incidents: Raw incidents from the API.
        last_created_on: Timestamp of the last consumed incident (or None on first run).
        last_ids: IDs already consumed at ``last_created_on``.
        type_key: Type key string used for debug logging.

    Returns:
        Filtered and deduplicated list of incidents.
    """
    if last_created_on:
        threshold = int(last_created_on)
        before_count = len(raw_incidents)
        raw_incidents = [inc for inc in raw_incidents if int(inc.get("createdOn", "0")) >= threshold]
        demisto.debug(f"[Fetch] Type {type_key}: Time filter (>= {threshold}): {before_count} -> {len(raw_incidents)}")

    if last_ids and last_created_on:
        raw_incidents = filter_by_ids(raw_incidents, last_ids)

    return raw_incidents


def _compute_new_state(
    consumed: list[dict],
    type_key: str,
) -> dict:
    """Compute the new last_run state from consumed incidents.

    Sets ``last_created_on`` to the maximum ``createdOn`` among the consumed
    incidents and collects all incident IDs at that timestamp into ``last_ids``
    for deduplication on the next run.

    Args:
        consumed: Incidents to consume (already sorted ascending and sliced to max_fetch).
        type_key: Type key string used for debug logging.

    Returns:
        Updated state dict with ``last_created_on`` and ``last_ids``.
    """
    max_created_on = consumed[-1].get("createdOn", "")
    new_last_ids = [inc.get("incidentID", "") for inc in consumed if inc.get("createdOn") == max_created_on]

    demisto.debug(
        f"[Fetch] Type {type_key}: {len(consumed)} incidents consumed. "
        f"New last_created_on={max_created_on}, dedup IDs={new_last_ids}."
    )

    return {
        "last_created_on": max_created_on,
        "last_ids": new_last_ids,
    }


def _fetch_for_type(
    client: Client,
    type_code: int,
    type_state: dict,
    max_fetch_per_type: int,
) -> tuple[str, list[dict], dict]:
    """Fetch incidents for a single type using fetch-all-sort-slice pattern.

    Algorithm:
    1. Determine fromdate = midnight UTC of last_created_on day (or first_fetch)
    2. todate = current time
    3. Fetch ALL pages via _fetch_all_pages()
    4. Client-side filter + dedup via _filter_and_dedup()
    5. Sort ascending by createdOn, slice to max_fetch_per_type
    6. Compute new state via _compute_new_state()

    Args:
        client: The iZOOlogic client.
        type_code: Incident type code.
        type_state: Per-type state from last_run.
        max_fetch_per_type: Maximum incidents to return for this type.

    Returns:
        Tuple of (type_key, cortex_incidents, updated_state).
    """
    type_key = str(type_code)
    last_created_on: str | None = type_state.get("last_created_on")
    last_ids: list[str] = type_state.get("last_ids", [])

    from_date = snap_to_day_boundary_utc(
        last_created_on if last_created_on else date_to_unix_timestamp(Config.DEFAULT_FROM_TIME),
        "start",
    )
    to_date = get_current_unix_timestamp()

    demisto.debug(
        f"[Fetch] Type {type_key}: from_date={from_date}, to_date={to_date}, "
        f"last_created_on={last_created_on}, last_ids({len(last_ids)})={last_ids}"
    )

    try:
        validate_date_range(from_date, to_date)
    except DemistoException as e:
        demisto.debug(f"[Fetch] Type {type_key}: {e!s}. Skipping.")
        return type_key, [], type_state

    raw_incidents = _fetch_all_pages(client, from_date, to_date, type_code)

    # Advance cursor to to_date when no incidents are returned so we don't
    # re-query the same empty window on the next run.
    if not raw_incidents:
        demisto.debug(f"[Fetch] Type {type_key}: No incidents found. Advancing cursor to {to_date}.")
        return type_key, [], {"last_created_on": to_date, "last_ids": []}

    raw_incidents = _filter_and_dedup(raw_incidents, last_created_on, last_ids, type_key)

    # Advance cursor even when all incidents were filtered/deduped out.
    if not raw_incidents:
        demisto.debug(f"[Fetch] Type {type_key}: All incidents filtered out. Advancing cursor to {to_date}.")
        return type_key, [], {"last_created_on": to_date, "last_ids": []}

    raw_incidents.sort(key=lambda inc: int(inc.get("createdOn", "0")))
    consumed = raw_incidents[:max_fetch_per_type]
    demisto.debug(f"[Fetch] Type {type_key}: Sorted {len(raw_incidents)} incidents, consuming {len(consumed)}")

    updated_state = _compute_new_state(consumed, type_key)
    cortex_incidents = create_incidents(consumed)
    return type_key, cortex_incidents, updated_state


async def fetch_incidents_command(
    client: Client,
    max_fetch_per_type: int,
    incident_type_codes: list[int],
) -> None:
    """Scheduled command to fetch incidents from iZOOlogic.

    Fetches all incident types concurrently using asyncio.to_thread().
    Each type maintains its own last_created_on and last_ids in last_run.

    The API returns incidents sorted descending by createdOn with day-level filtering.
    For each type, we:
    1. Fetch ALL pages (exhaust pagination)
    2. Client-side filter by last_created_on timestamp
    3. Sort ascending by createdOn
    4. Slice to max_fetch_per_type
    5. Advance last_created_on to the max createdOn of consumed incidents

    Args:
        client: The iZOOlogic client.
        max_fetch_per_type: Maximum number of incidents to fetch per type per run.
        incident_type_codes: Incident type codes from integration config.
    """
    last_run = demisto.getLastRun()
    demisto.debug(f"[Fetch] Starting with last_run keys: {list(last_run.keys())}")

    # Launch concurrent fetches for all types
    tasks = [
        asyncio.to_thread(
            _fetch_for_type,
            client,
            type_code,
            last_run.get(str(type_code), {}),  # type: ignore[arg-type]
            max_fetch_per_type,
        )
        for type_code in incident_type_codes
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    all_cortex_incidents: list[dict] = []
    updated_last_run: dict = dict(last_run)

    for result in results:
        if isinstance(result, Exception):
            demisto.error(f"[Fetch] Error fetching type: {result!s}")
            continue

        type_key, cortex_incidents, updated_state = result  # type: ignore[misc]
        all_cortex_incidents.extend(cortex_incidents)
        updated_last_run[type_key] = updated_state

    demisto.incidents(all_cortex_incidents)
    demisto.setLastRun(updated_last_run)
    demisto.debug(f"[Fetch] Done. Total incidents: {len(all_cortex_incidents)}. Last run updated.")


def _resolve_code_by_name(raw_value: str, code_map: dict[str, int], field_name: str) -> int:
    """Resolve a display name to an API integer code.

    Args:
        raw_value: The user-provided display name.
        code_map: Mapping of display names to integer codes.
        field_name: Argument name used in error messages.

    Returns:
        The resolved integer code.

    Raises:
        DemistoException: If the name is not found in the code map.
    """
    normalized = raw_value.lower().strip()
    code = code_map.get(normalized)
    if code is None:
        raise DemistoException(f"Invalid '{field_name}': '{raw_value}'. " f"Valid values: {list(code_map.keys())}.")
    return code


def _validate_incident_creation_args(args: dict[str, Any]) -> dict[str, Any]:
    """Validate and parse arguments for the izoolabs-incident-create command.

    Args:
        args: Raw command arguments from demisto.args().

    Returns:
        Validated and parsed arguments dictionary ready for the API call.

    Raises:
        DemistoException: If required arguments are missing or invalid.
    """
    # Required: incident_url
    incident_url = args.get("incident_url", "")
    if not incident_url:
        raise DemistoException("'incident_url' is a required argument.")

    # Required: incident_type (name only, mapped to integer code)
    incident_type_raw = args.get("incident_type", "")
    if not incident_type_raw:
        raise DemistoException("'incident_type' is a required argument.")
    incident_type = _resolve_code_by_name(str(incident_type_raw), ApiCodes.INCIDENT_TYPE, "incident_type")

    # Required: brand_code
    brand_code = args.get("brand_code", "")
    if not brand_code:
        raise DemistoException("'brand_code' is a required argument.")

    # Optional: threat_type (name only, mapped to integer code)
    threat_type: int | None = None
    threat_type_raw = args.get("threat_type")
    if threat_type_raw:
        threat_type = _resolve_code_by_name(str(threat_type_raw), ApiCodes.THREAT_TYPE, "threat_type")

    # Optional: case_type (name only, mapped to integer code)
    case_type: int | None = None
    case_type_raw = args.get("case_type")
    if case_type_raw:
        case_type = _resolve_code_by_name(str(case_type_raw), ApiCodes.CASE_TYPE, "case_type")

    # Optional: comment
    comment = args.get("comment")

    # Optional: executive_name
    executive_name = args.get("executive_name")

    # Optional: client_code
    client_code = args.get("client_code")

    return {
        "incident_url": incident_url,
        "incident_type": incident_type,
        "brand_code": brand_code,
        "threat_type": threat_type,
        "case_type": case_type,
        "comment": comment,
        "executive_name": executive_name,
        "client_code": client_code,
    }


def create_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a new security incident in iZOOlogic.

    Args:
        client: The iZOOlogic client.
        args: Command arguments from demisto.args().

    Returns:
        CommandResults with the API response.
    """
    demisto.debug("[Command] izoolabs-incident-create triggered")

    validated_args = _validate_incident_creation_args(args)

    response = client.report_new_incident(
        incident_url=validated_args["incident_url"],
        incident_type=validated_args["incident_type"],
        brand_code=validated_args["brand_code"],
        threat_type=validated_args["threat_type"],
        case_type=validated_args["case_type"],
        comment=validated_args["comment"],
        executive_name=validated_args["executive_name"],
        client_code=validated_args["client_code"],
    )

    if not response.get("success", False):
        error_code = response.get("errorCode", "")
        message = response.get("message", "Unknown error")
        raise DemistoException(f"Failed to create incident: {message} (errorCode: {error_code})")

    result = response.get("result", {})

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} - New Incident Created",
        result,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="iZOOlabs.Incident",
        outputs_key_field="reportedincidentid",
        outputs=result,
    )


def incident_fetch_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch incidents from iZOOlogic with advanced filtering.

    Retrieves incidents based on specified filters including date range, brand,
    incident type, threat type, and other criteria. Supports pagination for
    large result sets.

    Args:
        client: The iZOOlogic client.
        args: Command arguments from demisto.args().

    Returns:
        CommandResults with the retrieved incidents.
    """
    demisto.debug("[Command] izoolabs-incident-fetch triggered")

    # Date range — default: 1 day ago to now
    from_date_input = args.get("from_date", Config.DEFAULT_FETCH_COMMAND_FROM_TIME)
    to_date_input = args.get("to_date")

    from_ts = date_to_unix_timestamp(from_date_input)
    from_date = snap_to_day_boundary_utc(from_ts, "start")
    to_date = date_to_unix_timestamp(to_date_input) if to_date_input else get_current_unix_timestamp()

    validate_date_range(from_date, to_date)

    # When from_date and to_date are both at midnight of the same day, snap to_date to end of day
    if int(to_date) == int(from_date):
        to_date = snap_to_day_boundary_utc(to_date, "end")

    # Optional: incident_type (name only, mapped to integer code)
    incident_type: int | None = None
    incident_type_raw = args.get("incident_type")
    if incident_type_raw:
        incident_type = _resolve_code_by_name(str(incident_type_raw), ApiCodes.INCIDENT_TYPE, "incident_type")

    # Optional: threat_type (name only, mapped to integer code)
    threat_type: int | None = None
    threat_type_raw = args.get("threat_type")
    if threat_type_raw:
        threat_type = _resolve_code_by_name(str(threat_type_raw), ApiCodes.THREAT_TYPE, "threat_type")

    # Optional string filters
    brand_code = args.get("brand_code")
    executive_name = args.get("executive_name")
    client_ref_id = args.get("client_ref_id")
    client_code = args.get("client_code")

    demisto.debug(
        f"[Command Params] From: {from_date}, To: {to_date}, "
        f"IncidentType: {incident_type}, ThreatType: {threat_type}, "
        f"BrandCode: {brand_code}, ExecutiveName: {executive_name}, "
        f"ClientRefId: {client_ref_id}, ClientCode: {client_code}"
    )

    all_incidents = _fetch_all_pages(
        client,
        from_date=from_date,
        to_date=to_date,
        incident_type=incident_type,
        threat_type=threat_type,
        brand_code=brand_code,
        executive_name=executive_name,
        client_ref_id=client_ref_id,
        client_code=client_code,
    )

    demisto.debug(f"[Command Result] Total incidents retrieved: {len(all_incidents)}")

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Incidents",
        all_incidents,
        headers=[
            "incidentID",
            "incidentType",
            "subIncidentType",
            "brand",
            "url",
            "status",
            "statusCode",
            "threatType",
            "detectionDate",
            "createdOn",
            "closedOn",
            "detectedBy",
        ],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="iZOOlabs.Incident",
        outputs_key_field="incidentID",
        outputs=all_incidents,
    )


# endregion

# region Command Map and Main
# =================================
# Command Map and Main
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "izoologic-get-incidents": get_incidents_command,
    "fetch-incidents": fetch_incidents_command,
    "izoolabs-incident-create": create_incident_command,
    "izoolabs-incident-fetch": incident_fetch_command,
}


def main() -> None:
    """Main entry point for iZOOlogic integration."""
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
            secret_key=config["secret_key"],
            verify=config["verify"],
            proxy=config["proxy"],
        )

        command_func = COMMAND_MAP[command]

        if command == "test-module":
            result = command_func(client)
            return_results(result)
        elif command == "fetch-incidents":
            asyncio.run(command_func(client, config["max_fetch"], config["incident_type_codes"]))
        elif command == "izoologic-get-incidents":
            result = command_func(client, args, config["incident_type_codes"])
            return_results(result)
        elif command in ("izoolabs-incident-create", "izoolabs-incident-fetch"):
            result = command_func(client, args)
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
