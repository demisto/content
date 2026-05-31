import asyncio
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
Integration for fetching threat events from the iZOOlogic API.
"""

# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "iZOOlogic"


class ApiPaths:
    """Centralized iZOOlogic API endpoint paths."""

    AUTHENTICATE = "/api/Token/Authenticate"
    FETCH_EVENTS = "/api/ThreatManagement/FetchIncidents"


class Config:
    """Global static configuration."""

    # Pagination
    DEFAULT_LIMIT = 50
    DEFAULT_MAX_FETCH_PER_TYPE = 5000

    # Fetch defaults
    DEFAULT_FROM_TIME = "5 minutes ago"

    # Max date range for API (31 days)
    MAX_DATE_RANGE_DAYS = 31


# API error codes
NO_DATA_FOUND_ERROR_CODE = "iZOO2011"

# Mapping of event type display names to API integer codes
EVENT_TYPE_CODES: dict[str, int] = {
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


def add_time_to_events(events: list[dict]) -> None:
    """Add _time and source_log_type fields to events for XSIAM ingestion.

    Converts the ``createdOn`` Unix timestamp to ISO 8601 format and sets it as ``_time``.
    Also sets ``source_log_type`` to the event type for each event.

    Args:
        events: List of event dictionaries from the API. Modified in place.
    """
    for event in events:
        created_on = event.get("createdOn", "")
        if created_on:
            try:
                dt = datetime.fromtimestamp(int(created_on), tz=UTC)
                event["_time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError, OSError):
                demisto.debug(f"[Time] Failed to parse createdOn: {created_on}")

        event["source_log_type"] = event.get("incidentType", "Unknown")


def create_events(events: list[dict]) -> None:
    """Format events and send them to XSIAM.

    Args:
        events: List of raw event dictionaries from the API.
    """
    demisto.debug(f"[Create Events] Formatting and sending {len(events)} XSIAM events.")
    add_time_to_events(events)
    send_events_to_xsiam(
        events=events,
        vendor=INTEGRATION_NAME,
        product=INTEGRATION_NAME,
    )


def filter_by_ids(raw_events: list[dict], ids_to_skip: list[str]) -> list[dict]:
    """Filter out events whose IDs are in the given skip set.

    Args:
        raw_events: List of event dictionaries from the API.
        ids_to_skip: List of event IDs to filter out.

    Returns:
        List of events not in the skip set.
    """
    if not raw_events or not ids_to_skip:
        return raw_events

    skip_set = set(ids_to_skip)
    filtered = [inc for inc in raw_events if inc.get("incidentID") not in skip_set]

    skipped = len(raw_events) - len(filtered)
    if skipped > 0:
        demisto.debug(f"[Filter] Skipped {skipped} events by ID. {len(filtered)} remain.")

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

        if error_code == NO_DATA_FOUND_ERROR_CODE:
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

    # Parse and validate event types filter — default to all types if none specified
    event_types_filter = argToList(params.get("events_types_filter"))
    event_type_codes = resolve_type_codes(event_types_filter) if event_types_filter else list(EVENT_TYPE_CODES.values())

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
        "event_type_codes": event_type_codes,
        "max_fetch": max_fetch,
    }


def validate_date_range(from_date: str, to_date: str) -> None:
    """Validate that the date range is valid and does not exceed the API maximum of 31 days.

    Checks:
    1. ``to_date`` must not be earlier than ``from_date`` (different-day inversion).
    2. The span must not exceed ``Config.MAX_DATE_RANGE_DAYS`` (31 days).

    Note: same-day cases where ``to_date == from_date`` after snapping to midnight
    are handled separately by callers (e.g. ``get_events_command``).

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
    """Resolve event type display names to API codes.

    Args:
        type_names: List of event type display names (e.g., ['phishing', 'malware']).

    Returns:
        List of API integer codes.

    Raises:
        DemistoException: If any type name is invalid.
    """
    codes: list[int] = []
    for name in type_names:
        code = EVENT_TYPE_CODES.get(name.lower().strip())
        if code is None:
            raise DemistoException(f"Invalid event type: '{name}'. Valid types: {list(EVENT_TYPE_CODES.keys())}")
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

    def fetch_events_page(
        self,
        from_date: str,
        to_date: str,
        event_type: int | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        """Fetch a single page of events from the iZOOlogic API.

        The API uses day-level filtering: ``fromdate`` is rounded up to the
        next UTC midnight (inclusive), ``todate`` is floored to its UTC
        midnight (inclusive).  The effective range is
        ``[ceil(fromdate)_day, floor(todate)_day]``.

        Args:
            from_date: Start date as Unix timestamp string (must be midnight UTC
                to avoid the round-up skipping the intended day).
            to_date: End date as Unix timestamp string (floored to its day by the API).
            event_type: Optional event type code to filter by.
            page_token: Pagination token for retrieving the next page.

        Returns:
            The 'result' object from the API response containing events and pagination info.
        """
        body: dict[str, Any] = {
            "fromdate": from_date,
            "todate": to_date,
        }

        if event_type is not None:
            body["incidenttype"] = event_type

        if page_token:
            body["token"] = page_token

        demisto.debug(f"[API Fetch] Fetching events | Params: {body}")

        response = self._http_request(
            method="POST",
            url_suffix=ApiPaths.FETCH_EVENTS,
            json_data=body,
        )

        return _validate_api_response(response)


# endregion

# region Command implementations
# =================================
# Command implementations
# =================================


def test_module(client: Client) -> str:
    """Test API connectivity by authenticating and fetching events.

    Uses _fetch_all_pages with midnight UTC of today as fromdate.
    An empty result (no events) still proves connectivity — the test passes.

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
    event_type: int | None = None,
) -> list[dict]:
    """Fetch ALL pages of events until pagination is exhausted.

    Loops through all pages using opaque nextPage tokens until nextPage is null
    or the API returns an empty page. No max_results cap — fetches everything
    in the time window.

    Used by all commands: test_module, get_events_command, and fetch_events_command.

    Args:
        client: The iZOOlogic client.
        from_date: Start date as Unix timestamp string (must be midnight UTC).
        to_date: End date as Unix timestamp string.
        event_type: Optional event type code.

    Returns:
        List of ALL raw event dictionaries from all pages.
    """
    all_events: list[dict] = []
    page_token: str | None = None
    page_count = 0

    while True:
        result_obj = client.fetch_events_page(
            from_date=from_date,
            to_date=to_date,
            event_type=event_type,
            page_token=page_token,
        )

        page_events = result_obj.get("incidents") or []
        if not page_events:
            break

        all_events.extend(page_events)
        page_count += 1
        demisto.debug(
            f"[FetchAll] Type {event_type or 'all'} | Page {page_count}: "
            f"+{len(page_events)} events (total: {len(all_events)})"
        )

        page_token = result_obj.get("nextPage")
        if not page_token:
            break

    demisto.debug(f"[FetchAll] Type {event_type or 'all'} | Done: {len(all_events)} events " f"across {page_count} pages")
    return all_events


def get_events_command(
    client: Client,
    args: dict,
    default_type_codes: list[int],
) -> CommandResults:
    """Manual command to get events for debugging/development.

    Args:
        client: The iZOOlogic client.
        args: Command arguments.
        default_type_codes: Default event type codes from integration config.

    Returns:
        CommandResults with the retrieved events.
    """
    demisto.debug("[Command] izoologic-get-events triggered")

    should_push_events = argToBoolean(args.get("should_push_events", False))

    limit = arg_to_number(args.get("limit", Config.DEFAULT_LIMIT))
    if not limit or limit <= 0:
        raise DemistoException(f"Invalid limit value: {args.get('limit')}. Must be a positive integer.")
    limit = int(limit)

    start_time_input = args.get("start_time", Config.DEFAULT_FROM_TIME)
    end_time_input = args.get("end_time")

    # Use event_type from command args if provided, otherwise fall back to config
    event_type_arg = argToList(args.get("event_type"))
    type_codes = resolve_type_codes(event_type_arg) if event_type_arg else default_type_codes

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

    all_events: list[dict] = []
    for type_code in type_codes:
        type_events = _fetch_all_pages(
            client,
            from_date=from_date,
            to_date=to_date,
            event_type=type_code,
        )
        # Client-side filter: the API returns all events in the
        # [ceil(fromdate)_day, floor(todate)_day] day range, so discard
        # events outside the precise requested timestamp range.
        type_events = [e for e in type_events if int(from_ts) <= int(e.get("createdOn", "0")) <= int(to_date)]
        all_events.extend(type_events[:limit])

    demisto.debug(f"[Command Result] Total events retrieved: {len(all_events)} (limit per type: {limit})")

    if should_push_events and all_events:
        create_events(list(all_events))

    readable_output = tableToMarkdown(
        f"{INTEGRATION_NAME} Events",
        all_events,
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
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="iZOOlogic.Incident",
        outputs_key_field="incidentID",
        outputs=all_events,
    )


def _filter_and_dedup(
    raw_events: list[dict],
    last_created_on: str | None,
    last_ids: list[str],
    type_key: str,
) -> list[dict]:
    """Filter out already-seen events and deduplicate by ID.

    Steps:
    1. Discard events with ``createdOn`` strictly before ``last_created_on``.
    2. For events at exactly ``last_created_on``, remove those in ``last_ids``.

    Args:
        raw_events: Raw events from the API.
        last_created_on: Timestamp of the last consumed event (or None on first run).
        last_ids: IDs already consumed at ``last_created_on``.
        type_key: Type key string used for debug logging.

    Returns:
        Filtered and deduplicated list of events.
    """
    if last_created_on:
        threshold = int(last_created_on)
        before_count = len(raw_events)
        raw_events = [inc for inc in raw_events if int(inc.get("createdOn", "0")) >= threshold]
        demisto.debug(f"[Fetch] Type {type_key}: Time filter (>= {threshold}): {before_count} -> {len(raw_events)}")

    if last_ids and last_created_on:
        raw_events = filter_by_ids(raw_events, last_ids)

    return raw_events


def _compute_new_state(
    consumed: list[dict],
    type_key: str,
) -> dict:
    """Compute the new last_run state from consumed events.

    Sets ``last_created_on`` to the maximum ``createdOn`` among the consumed
    events and collects all event IDs at that timestamp into ``last_ids``
    for deduplication on the next run.

    Args:
        consumed: Events to consume (already sorted ascending and sliced to max_fetch).
        type_key: Type key string used for debug logging.

    Returns:
        Updated state dict with ``last_created_on`` and ``last_ids``.
    """
    max_created_on = consumed[-1].get("createdOn", "")
    new_last_ids = [inc.get("incidentID", "") for inc in consumed if inc.get("createdOn") == max_created_on]

    demisto.debug(
        f"[Fetch] Type {type_key}: {len(consumed)} events consumed. "
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
    """Fetch events for a single type within a ≤31-day window.

    Uses ``Config.DEFAULT_FROM_TIME`` as the starting point on first fetch.
    The date range must not exceed 31 days (enforced by ``validate_date_range``).

    Args:
        client: The iZOOlogic client.
        type_code: Event type code.
        type_state: Per-type state from last_run.
        max_fetch_per_type: Maximum events to return for this type.

    Returns:
        Tuple of (type_key, consumed_events, updated_state).
    """
    type_key = str(type_code)
    last_created_on: str | None = type_state.get("last_created_on")
    last_ids: list[str] = type_state.get("last_ids", [])

    effective_first_fetch = date_to_unix_timestamp(Config.DEFAULT_FROM_TIME)
    from_date = snap_to_day_boundary_utc(
        last_created_on if last_created_on else effective_first_fetch,
        "start",
    )
    to_date = get_current_unix_timestamp()

    demisto.debug(
        f"[Fetch] Type {type_key}: from_date={from_date}, to_date={to_date}, "
        f"last_created_on={last_created_on}, last_ids({len(last_ids)})={last_ids}"
    )

    from_ts = int(from_date)
    to_ts = int(to_date)

    if from_ts >= to_ts:
        demisto.debug(f"[Fetch] Type {type_key}: from_date >= to_date. Skipping.")
        return type_key, [], type_state

    validate_date_range(from_date, to_date)

    raw_events = _fetch_all_pages(client, from_date, to_date, type_code)

    if not raw_events:
        demisto.debug(f"[Fetch] Type {type_key}: No events found.")
        return type_key, [], {"last_created_on": to_date, "last_ids": []}

    raw_events = _filter_and_dedup(raw_events, last_created_on, last_ids, type_key)

    if not raw_events:
        demisto.debug(f"[Fetch] Type {type_key}: All events filtered out.")
        return type_key, [], {"last_created_on": to_date, "last_ids": []}

    raw_events.sort(key=lambda inc: int(inc.get("createdOn", "0")))
    consumed = raw_events[:max_fetch_per_type]
    demisto.debug(f"[Fetch] Type {type_key}: Consuming {len(consumed)} events")

    updated_state = _compute_new_state(consumed, type_key)
    return type_key, consumed, updated_state


async def fetch_events_command(
    client: Client,
    max_fetch_per_type: int,
    event_type_codes: list[int],
) -> None:
    """Scheduled command to fetch events from iZOOlogic and send to XSIAM.

    Fetches all event types concurrently using asyncio.to_thread().
    Each type maintains its own last_created_on and last_ids in last_run.

    The API returns events sorted descending by createdOn with day-level filtering.
    For each type, we:
    1. Fetch ALL pages (exhaust pagination)
    2. Client-side filter by last_created_on timestamp
    3. Sort ascending by createdOn
    4. Slice to max_fetch_per_type
    5. Advance last_created_on to the max createdOn of consumed events

    Args:
        client: The iZOOlogic client.
        max_fetch_per_type: Maximum number of events to fetch per type per run.
        event_type_codes: Event type codes from integration config.
    """
    last_run = demisto.getLastRun()
    demisto.debug(f"[Fetch Events] Starting with last_run keys: {list(last_run.keys())}")

    # Launch concurrent fetches for all types
    tasks = [
        asyncio.to_thread(
            _fetch_for_type,
            client,
            type_code,
            last_run.get(str(type_code), {}),  # type: ignore[arg-type]
            max_fetch_per_type,
        )
        for type_code in event_type_codes
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    all_events: list[dict] = []
    updated_last_run: dict = dict(last_run)

    for result in results:
        if isinstance(result, Exception):
            demisto.error(f"[Fetch Events] Error fetching type: {result!s}")
            continue

        type_key, consumed_events, updated_state = result  # type: ignore[misc]
        all_events.extend(consumed_events)
        updated_last_run[type_key] = updated_state

    if all_events:
        create_events(all_events)

    demisto.setLastRun(updated_last_run)
    demisto.debug(f"[Fetch Events] Done. Total events: {len(all_events)}. Last run updated.")


# endregion

# region Command Map and Main
# =================================
# Command Map and Main
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "izoologic-get-events": get_events_command,
    "fetch-events": fetch_events_command,
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
        elif command == "fetch-events":
            asyncio.run(command_func(client, config["max_fetch"], config["event_type_codes"]))
        elif command == "izoologic-get-events":
            result = command_func(client, args, config["event_type_codes"])
            return_results(result)

    except Exception as error:
        error_msg = f"Failed to execute {command}. Error: {error!s}"
        demisto.error(f"{error_msg}\n{traceback.format_exc()}")
        return_error(error_msg)

    demisto.debug(f"{INTEGRATION_NAME} integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
