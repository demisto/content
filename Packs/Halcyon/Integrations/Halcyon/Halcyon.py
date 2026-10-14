import time

import urllib3
from enum import Enum
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "halcyon"
PRODUCT = "halcyon"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format with milliseconds
API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # Format for API requests
DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_FETCH = 1000
CLIENT_NAME = "Halcyon"

# Events lookback. The Halcyon events API indexes events late: an event can become queryable
# minutes after its occurredAt. Every cycle re-reads [now - EVENTS_LOOKBACK, now] and drops the
# events already sent (tracked in a dedup cache), so late-indexed events are still collected
# without re-sending the ones we already have. In busy hours Halcyon delivers events up to ~5
# minutes after occurredAt and the API can lag a few minutes more, so 10 minutes leaves margin.
EVENTS_LOOKBACK = timedelta(minutes=10)
# Extra time dedup IDs are kept beyond the window (like SailPoint's lookback + 1 minute), so a query
# that starts slightly earlier than expected (API rounding of occurredAfter, clock skew between
# engines) does not re-send events whose IDs were already dropped.
EVENTS_DEDUP_CACHE_MARGIN = timedelta(minutes=1)
# When an events fetch reaches max_fetch, run the next fetch after this many seconds instead of
# waiting for the full fetch interval, so a burst drains quickly (like Code42's NEXT_TRIGGER_VALUE).
EVENTS_NEXT_TRIGGER_SECONDS = "1"
# Every events log line starts with this prefix, so one search shows the whole lookback flow.
EVENTS_LOG_PREFIX = "HALCYON-EVENTS"
# Maximum number of individual events listed per log line (late-indexed / future-dated).
EVENTS_LOG_MAX_SAMPLES = 20
# Events last-run keys.
EVENTS_WATERMARK_KEY = "last_fetch_events"  # Everything up to this time was processed. Same key as the legacy format.
EVENTS_DEDUP_CACHE_KEY = "events_dedup_cache"  # {eventId: occurredAt} of events already sent.
EVENTS_FLOOR_KEY = "events_fetch_floor"  # Set by the migration: never query before the legacy watermark.
LEGACY_EVENTS_IDS_KEY = "previous_ids_events"  # Legacy dedup list, replaced by EVENTS_DEDUP_CACHE_KEY.

# TEMPORARY DIAGNOSTICS - remove once answered. Checks whether /v2/events can filter or sort by the
# time an event was inserted (indexed). Each candidate filter is sent with a value one day in the
# future: if the API honors it, no event matches; if it ignores it, events come back as usual.
INSERT_TIME_PROBE_ENABLED = True
INSERT_TIME_PROBE_INTERVAL = timedelta(hours=1)
INSERT_TIME_PROBE_LAST_RUN_KEY = "insert_time_probe_last_run"
INSERT_TIME_PROBE_LOG_PREFIX = "HALCYON-INSERT-TIME-PROBE"
INSERT_TIME_FILTER_CANDIDATES = [
    "insertedAfter",
    "ingestedAfter",
    "indexedAfter",
    "createdAfter",
    "receivedAfter",
    "processedAfter",
    "updatedAfter",
    "modifiedAfter",
    "reportedAfter",
    "lastSeenAfter",
]
INSERT_TIME_SORT_CANDIDATES = ["InsertedAt", "IngestedAt", "IndexedAt", "CreatedAt", "ReceivedAt", "UpdatedAt"]

""" LOG TYPE ENUM """


class LogType(Enum):
    """Enum to hold all configuration for different log types."""

    ALERTS = ("alerts", "Alerts", "/v2/alerts", "firstOccurredAt", "lastSeenAfter", "lastSeenBefore", "LastSeen")
    EVENTS = ("events", "Events", "/v2/events", "occurredAt", "occurredAfter", "occurredBefore", "OccurredAt")

    def __init__(
        self,
        type_string: str,
        title: str,
        api_endpoint: str,
        time_field: str,
        after_param: str,
        before_param: str,
        sort_by: str,
    ):
        self.type_string = type_string
        self.title = title
        self.api_endpoint = api_endpoint
        self.time_field = time_field
        self.after_param = after_param
        self.before_param = before_param
        self.sort_by = sort_by


""" CUSTOM AUTH HANDLER """


class HalcyonAuthHandler(AuthHandler):
    """Custom authentication handler for Halcyon API.

    Handles username/password login and automatic token refresh.
    Uses the Halcyon Login API to authenticate and stores tokens in integration context.
    """

    def __init__(
        self,
        username: str,
        password: str,
        tenant_id: str,
        login_url: str = "/identity/auth/login",
        refresh_url: str = "/identity/auth/refresh",
        context_store: ContentClientContextStore | None = None,
    ):
        """Initialize the Halcyon auth handler.

        Args:
            username: Halcyon account username.
            password: Halcyon account password.
            tenant_id: Halcyon Tenant ID (required for all API requests).
            login_url: URL suffix for login endpoint.
            refresh_url: URL suffix for token refresh endpoint.
            context_store: Optional context store for persisting tokens.
        """
        if not username:
            raise ContentClientAuthenticationError("HalcyonAuthHandler requires a non-empty username")
        if not password:
            raise ContentClientAuthenticationError("HalcyonAuthHandler requires a non-empty password")

        self.username = username
        self.password = password
        self.tenant_id = tenant_id
        self.login_url = login_url
        self.refresh_url = refresh_url
        self.context_store = context_store or ContentClientContextStore(CLIENT_NAME)

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._load_tokens_from_context()

    def _load_tokens_from_context(self) -> None:
        """Load tokens from integration context."""
        context = self.context_store.read()
        token_data = context.get(CLIENT_NAME, {})
        if token_data:
            self._access_token = token_data.get("access_token")
            self._refresh_token = token_data.get("refresh_token")
            demisto.debug("Loaded tokens from integration context")

    def _save_tokens_to_context(self) -> None:
        """Save tokens to integration context."""
        context = self.context_store.read()
        context[CLIENT_NAME] = {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
        }
        self.context_store.write(context)
        demisto.debug("Saved tokens to integration context")

    async def on_request(self, client: "ContentClient", request) -> None:
        """Add authentication header to the request.

        Args:
            client: The ContentClient instance.
            request: The HTTP request to modify.
        """
        # Ensure we have a valid token
        if not self._access_token:
            await self._login(client)

        request.headers["Authorization"] = f"Bearer {self._access_token}"

    async def on_auth_failure(self, client: "ContentClient", response) -> bool:
        """Handle authentication failure by refreshing the token.

        Args:
            client: The ContentClient instance.
            response: The HTTP response that failed.

        Returns:
            True if token was refreshed and request should be retried.
        """
        demisto.debug("Authentication failed, attempting token refresh")

        try:
            await self._refresh_access_token(client)
            return True
        except ContentClientAuthenticationError:
            demisto.debug("Token refresh failed, attempting full login")
            try:
                await self._login(client)
                return True
            except ContentClientAuthenticationError:
                return False

    async def _login(self, client: "ContentClient") -> None:
        """Authenticate with the Halcyon API using username/password.

        Args:
            client: The ContentClient instance.

        Raises:
            ContentClientAuthenticationError: If login fails.
        """
        import httpx

        demisto.debug("Authenticating with Halcyon API using username/password")

        # Build headers including X-TenantID which is required for all Halcyon API requests
        request_headers = {
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            request_headers["X-TenantID"] = self.tenant_id

        try:
            async with httpx.AsyncClient(verify=client._verify) as http_client:
                response = await http_client.post(
                    f"{client._base_url}{self.login_url}",
                    json={"username": self.username, "password": self.password},
                    headers=request_headers,
                )
                response.raise_for_status()
                data = response.json()

                self._access_token = data.get("accessToken")
                self._refresh_token = data.get("refreshToken")

                if not self._access_token or not self._refresh_token:
                    raise ContentClientAuthenticationError("No tokens in login response")

                self._save_tokens_to_context()
                demisto.debug("Successfully authenticated with Halcyon API")

        except httpx.HTTPStatusError as e:
            raise ContentClientAuthenticationError(f"Login failed with status {e.response.status_code}: {e.response.text}") from e
        except Exception as e:
            raise ContentClientAuthenticationError(f"Failed to login: {e!s}") from e

    async def _refresh_access_token(self, client: "ContentClient") -> None:
        """Refresh the access token using the refresh token.

        Args:
            client: The ContentClient instance.

        Raises:
            ContentClientAuthenticationError: If token refresh fails.
        """
        import httpx

        if not self._refresh_token:
            raise ContentClientAuthenticationError("No refresh token available")

        demisto.debug("Refreshing access token")

        # Build headers including X-TenantID which is required for all Halcyon API requests
        request_headers = {
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            request_headers["X-TenantID"] = self.tenant_id

        try:
            async with httpx.AsyncClient(verify=client._verify) as http_client:
                response = await http_client.post(
                    f"{client._base_url}{self.refresh_url}",
                    json={"refreshToken": self._refresh_token},
                    headers=request_headers,
                )
                response.raise_for_status()
                data = response.json()

                self._access_token = data.get("accessToken")
                self._refresh_token = data.get("refreshToken")

                if not self._access_token or not self._refresh_token:
                    raise ContentClientAuthenticationError("No tokens in refresh response")

                self._save_tokens_to_context()
                demisto.debug("Successfully refreshed access token")

        except httpx.HTTPStatusError as e:
            raise ContentClientAuthenticationError(
                f"Token refresh failed with status {e.response.status_code}: {e.response.text}"
            ) from e
        except Exception as e:
            raise ContentClientAuthenticationError(f"Failed to refresh token: {e!s}") from e


""" CLIENT CLASS """


class Client(ContentClient):
    """Client class to interact with the Halcyon API.

    Extends ContentClient with Halcyon-specific functionality including
    custom authentication and API methods for alerts and events.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        tenant_id: str,
        verify: bool,
        proxy: bool,
        max_fetch: int,
    ):
        """Initialize the Halcyon client.

        Args:
            base_url: Halcyon API server URL.
            username: Halcyon account username.
            password: Halcyon account password.
            tenant_id: Halcyon Tenant ID (X-TenantID header).
            verify: Whether to verify SSL certificates.
            proxy: Whether to use proxy settings.
            max_fetch: Maximum events to fetch per type per cycle.
        """
        # Create context store for token persistence
        context_store = ContentClientContextStore(CLIENT_NAME)

        # Create custom auth handler
        auth_handler = HalcyonAuthHandler(
            username=username,
            password=password,
            tenant_id=tenant_id,
            context_store=context_store,
        )

        # Create retry policy with custom settings
        retry_policy = RetryPolicy(  # type: ignore[call-arg]
            max_attempts=4,  # 3 retries + 1 initial attempt
            retryable_status_codes=(429, 500, 502, 503, 504),
        )

        # Set default headers including X-TenantID
        # Note: The Halcyon API expects X-TenantID as a plain UUID (e.g., "87d50c45-af11-405d-a556-f659e30a978d")
        # NOT in URN format (e.g., "urn:uuid:...")
        demisto.debug(f"Halcyon Client: Initializing with tenant_id={tenant_id}")
        headers = {
            "X-TenantID": tenant_id,
        }

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            auth_handler=auth_handler,
            client_name=CLIENT_NAME,
            timeout=30,
            retry_policy=retry_policy,
        )

        self.max_fetch = max_fetch

    def get_alerts(
        self,
        last_seen_after: str | None = None,
        last_seen_before: str | None = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict:
        """Fetch alerts from the Halcyon API.

        Args:
            last_seen_after: Filter alerts last seen after this datetime.
            last_seen_before: Filter alerts last seen before this datetime.
            page: Page number (1-based).
            page_size: Number of results per page.

        Returns:
            API response containing alerts.
        """
        params: dict[str, Any] = {
            "page": page,
            "pageSize": page_size,
            "sortBy": "LastSeen",
            "sortOrder": "Asc",  # Ascending to get oldest first for proper pagination
        }

        if last_seen_after:
            params["lastSeenAfter"] = last_seen_after
        if last_seen_before:
            params["lastSeenBefore"] = last_seen_before

        demisto.debug(f"Fetching alerts with params: {params}")
        return self._http_request(method="GET", url_suffix="/v2/alerts", params=params)

    def get_events(
        self,
        occurred_after: str | None = None,
        occurred_before: str | None = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict:
        """Fetch events from the Halcyon API.

        Args:
            occurred_after: Filter events occurred after this datetime.
            occurred_before: Filter events occurred before this datetime.
            page: Page number (1-based).
            page_size: Number of results per page.

        Returns:
            API response containing events.
        """
        params: dict[str, Any] = {
            "page": page,
            "pageSize": page_size,
            "sortBy": "OccurredAt",
            "sortOrder": "Asc",  # Ascending to get oldest first for proper pagination
        }

        if occurred_after:
            params["occurredAfter"] = occurred_after
        if occurred_before:
            params["occurredBefore"] = occurred_before

        demisto.debug(f"Fetching events with params: {params}")
        return self._http_request(method="GET", url_suffix="/v2/events", params=params)

    def probe_events(self, params: dict[str, Any]) -> dict:
        """TEMPORARY DIAGNOSTICS: call /v2/events with arbitrary query parameters.

        Args:
            params: The query parameters to send as-is.

        Returns:
            The raw API response.
        """
        return self._http_request(method="GET", url_suffix="/v2/events", params=params)


""" HELPER FUNCTIONS """


def get_log_types_from_titles(event_types_to_fetch: list[str]) -> list[LogType]:
    """Converts a list of user-facing event type titles into a list of LogType Enum members.

    Args:
        event_types_to_fetch: A list of event type titles from the integration parameters
                              (e.g., ["Alerts", "Events"]).

    Raises:
        DemistoException: If any of the provided event type titles are invalid.

    Returns:
        A list of LogType Enum members corresponding to the provided titles.
    """
    valid_titles = {lt.title for lt in LogType}

    invalid_types = [title for title in event_types_to_fetch if title not in valid_titles]

    if invalid_types:
        valid_options = ", ".join(valid_titles)
        raise DemistoException(
            f"Invalid event type(s) provided: {invalid_types}. " f"Please select from the following list: {valid_options}"
        )

    return [lt for lt in LogType if lt.title in event_types_to_fetch]


def enrich_events(events: list[dict], log_type: LogType) -> list[dict]:
    """Enriches a list of events with the '_time' and 'source_log_type' fields.

    Args:
        events: A list of event dictionaries to enrich.
        log_type: The LogType Enum member representing the source of these events.

    Returns:
        The enriched list of events.
    """
    for event in events:
        # Set _time based on the log type's time field
        time_value = event.get(log_type.time_field)
        if time_value:
            event["_time"] = time_value
        event["source_log_type"] = log_type.type_string

    return events


def get_event_id(event: dict, log_type: LogType) -> str | None:
    """Extract the event ID from an event dictionary.

    The Halcyon API may return different ID field names depending on the endpoint.
    This function tries multiple possible field names to find the ID.

    Args:
        event: The event dictionary.
        log_type: The LogType Enum member for the logs being processed.

    Returns:
        The event ID string, or None if not found.
    """
    # Primary ID fields based on log type
    if log_type == LogType.ALERTS:
        primary_fields = ["alertId", "id", "alert_id", "AlertId", "ID"]
    else:
        primary_fields = ["eventId", "id", "event_id", "EventId", "ID"]

    for id_field_name in primary_fields:
        event_id = event.get(id_field_name)
        if event_id:
            return str(event_id)

    return None


def deduplicate_events(
    events: list[dict],
    previous_run_ids: set[str],
    previous_timestamp: str | None,
    log_type: LogType,
) -> tuple[list[dict], set[str], str | None]:
    """Removes duplicate events based on their IDs and tracks the last timestamp.

    This function implements proper deduplication based on end times:
    1. Events with timestamps earlier than the previous timestamp are skipped (already processed)
    2. Events with the same timestamp as the previous run are checked against previous_run_ids
    3. Events with timestamps later than the previous timestamp are always included
    4. The new set of IDs only contains events that share the LAST timestamp (for next run dedup)

    Args:
        events: List of events fetched from the API.
        previous_run_ids: Set of event IDs from the previous run that share the same timestamp.
        previous_timestamp: The timestamp from the previous run (used for comparison).
        log_type: The LogType Enum member for the logs being processed.

    Returns:
        A tuple containing:
        - A list of unique event dictionaries.
        - The new set of event IDs that share the last timestamp (for next run deduplication).
        - The last event timestamp (or None if no events).
    """
    unique_events = []
    last_timestamp: str | None = None
    last_timestamp_ids: set[str] = set()
    events_without_id = 0

    # Log the first event's keys to help debug ID field issues
    if events:
        first_event_keys = list(events[0].keys())
        demisto.debug(f"First {log_type.type_string} event keys: {first_event_keys}")

    for event in events:
        event_id = get_event_id(event, log_type)
        time_value = event.get(log_type.time_field)

        if not event_id:
            events_without_id += 1
            # Still track the timestamp even for events without ID
            if time_value and (not last_timestamp or time_value > last_timestamp):
                last_timestamp = time_value
            continue

        # If this event has the same timestamp as the previous run's last timestamp,
        # check if we've already processed it
        if previous_timestamp and time_value == previous_timestamp and event_id in previous_run_ids:
            # Already processed this event, skip it
            continue

        # This is a new event, add it
        unique_events.append(event)

        # Track the last timestamp and IDs that share it
        if time_value:
            if time_value != last_timestamp:
                # New timestamp, reset the ID set
                last_timestamp = time_value
                last_timestamp_ids = {event_id}
            else:
                # Same timestamp, add to the set
                last_timestamp_ids.add(event_id)

    if events_without_id > 0:
        demisto.debug(
            f"Warning: {events_without_id} {log_type.type_string} events had no recognizable ID field. "
            f"First event keys were: {first_event_keys if events else 'N/A'}"
        )

    demisto.debug(
        f"Deduplicated {log_type.type_string}: {len(events)} -> {len(unique_events)} events. "
        f"Previous IDs: {len(previous_run_ids)}, Last timestamp IDs: {len(last_timestamp_ids)}, "
        f"Last timestamp: {last_timestamp}"
    )

    return unique_events, last_timestamp_ids, last_timestamp


def normalize_timestamp(time_value: str | None) -> str | None:
    """Convert a Halcyon timestamp to one fixed-width UTC format (``DATE_FORMAT``).

    The API returns timestamps with and without fractional seconds. A single fixed-width
    format makes plain string comparison equal to time comparison.

    Args:
        time_value: The raw timestamp string (may be None).

    Returns:
        The timestamp in ``DATE_FORMAT``, or None if it is empty or cannot be parsed.
    """
    if not time_value:
        return None
    for known_format in (DATE_FORMAT, "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(time_value, known_format).strftime(DATE_FORMAT)
        except ValueError:
            continue
    parsed = dateparser.parse(time_value, settings={"TIMEZONE": "UTC", "TO_TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": False})
    if parsed:
        return parsed.strftime(DATE_FORMAT)
    demisto.debug(f"Could not parse timestamp {time_value!r}.")
    return None


def migrate_events_last_run(last_run: dict) -> dict:
    """Convert a legacy events last run to the lookback format. Does nothing if already migrated.

    Legacy format: ``last_fetch_events`` (watermark) and ``previous_ids_events`` (IDs of the
    events at exactly that watermark). The IDs become the dedup cache. The legacy watermark
    becomes a floor: the old code did not remember which events before it were sent, so the
    first lookback cycles must not query before it, or they would send those events again.

    Args:
        last_run: The last run dictionary.

    Returns:
        The last run dictionary in the lookback format.
    """
    legacy_watermark = last_run.get(EVENTS_WATERMARK_KEY)
    if EVENTS_DEDUP_CACHE_KEY in last_run or not legacy_watermark:
        last_run.pop(LEGACY_EVENTS_IDS_KEY, None)
        return last_run

    watermark = normalize_timestamp(legacy_watermark) or legacy_watermark
    legacy_ids = last_run.pop(LEGACY_EVENTS_IDS_KEY, None) or []
    last_run[EVENTS_WATERMARK_KEY] = watermark
    last_run[EVENTS_DEDUP_CACHE_KEY] = {str(event_id): watermark for event_id in legacy_ids}
    last_run[EVENTS_FLOOR_KEY] = watermark
    log_events_info(
        f"{EVENTS_LOG_PREFIX} migrated the legacy last run: watermark and migration floor={watermark}, "
        f"{len(legacy_ids)} legacy IDs moved to the dedup cache. Queries will not start before the floor "
        f"until the lookback window passes it."
    )
    return last_run


def get_events_query_start(watermark: str | None, floor: str | None, cycle_start: datetime) -> tuple[str, str | None]:
    """Return where this cycle's events query starts, and the floor to keep for later cycles.

    Normally the query starts at ``cycle_start - EVENTS_LOOKBACK`` to catch late-indexed events.
    If the previous cycle stopped before reaching that point (``max_fetch`` reached), it starts
    from the watermark instead, so the backlog is drained without gaps. It never starts before
    the migration floor. The floor is dropped once the lookback window has moved past it.

    Args:
        watermark: Everything up to this time was processed (None on the first run).
        floor: The migration floor (None when not migrating).
        cycle_start: When this fetch cycle started.

    Returns:
        A tuple of (query start, floor to store or None).
    """
    window_start = (cycle_start - EVENTS_LOOKBACK).strftime(DATE_FORMAT)
    query_start = min(watermark, window_start) if watermark else window_start
    if floor and floor > window_start:
        return max(query_start, floor), floor
    return query_start, None


def log_events_info(message: str) -> None:
    """Write an info log line for the events flow. Never raises, so logging can never fail the fetch.

    Args:
        message: The log line.
    """
    try:
        demisto.info(message)
    except Exception:  # noqa: S110 - a logging failure must not fail the fetch
        pass


def describe_query_start(query_start: str, watermark: str | None, floor: str | None, cycle_start: datetime) -> str:
    """Explain, for the log, why the events query starts where it does.

    Args:
        query_start: Where the query starts.
        watermark: The watermark from the previous cycle (None on the first run).
        floor: The migration floor (None when not migrating).
        cycle_start: When this fetch cycle started.

    Returns:
        A short human-readable reason.
    """
    window_start = (cycle_start - EVENTS_LOOKBACK).strftime(DATE_FORMAT)
    if floor and floor > window_start and query_start == floor:
        return "migration floor: not querying before the legacy watermark, to avoid re-sending events"
    if watermark and watermark < window_start and query_start == watermark:
        return "resuming a backlog from the watermark (the previous fetch reached max_fetch or fetching was paused)"
    if not watermark:
        return f"first fetch: last {EVENTS_LOOKBACK.total_seconds():.0f}s"
    return f"lookback window: last {EVENTS_LOOKBACK.total_seconds():.0f}s"


def seconds_from_cycle_start(event_time: str, cycle_start: datetime) -> float:
    """Return how many seconds ``event_time`` is after ``cycle_start`` (negative when it is before).

    Args:
        event_time: An event time in ``DATE_FORMAT``.
        cycle_start: When this fetch cycle started.

    Returns:
        The offset in seconds.
    """
    return (datetime.strptime(event_time, DATE_FORMAT).replace(tzinfo=timezone.utc) - cycle_start).total_seconds()


def format_event_samples(samples: list[tuple[str, str]], cycle_start: datetime) -> str:
    """Format events for the log as ``id@occurredAt(offset from the cycle start)``, up to ``EVENTS_LOG_MAX_SAMPLES``.

    Args:
        samples: (event ID, occurredAt) pairs.
        cycle_start: When this fetch cycle started.

    Returns:
        The formatted list.
    """
    shown = [
        f"{event_id}@{event_time}({seconds_from_cycle_start(event_time, cycle_start):+.0f}s)"
        for event_id, event_time in samples[:EVENTS_LOG_MAX_SAMPLES]
    ]
    extra = len(samples) - EVENTS_LOG_MAX_SAMPLES
    return ", ".join(shown) + (f" ... and {extra} more" if extra > 0 else "")


def collect_new_events(
    client: Client, query_start: str, cycle_start: str, dedup_cache: dict[str, str], max_fetch: int
) -> tuple[list[dict], str, dict[str, Any]]:
    """Page through events from ``query_start`` to ``cycle_start`` and keep only unseen ones.

    Pages until a short page (everything up to ``cycle_start`` was read) or until ``max_fetch``
    new events were collected. Events already in ``dedup_cache`` are skipped and do not count
    toward ``max_fetch``. Events dated after ``cycle_start`` (the API returns some with a future
    occurredAt) are skipped too: they are not sent and do not move the watermark, so a later
    cycle collects them. Events without an ID cannot be deduplicated and are skipped, as before.
    New events are added to ``dedup_cache``.

    Args:
        client: The Halcyon client.
        query_start: The occurredAfter value (inclusive).
        cycle_start: When this cycle started, in ``DATE_FORMAT``.
        dedup_cache: {eventId: occurredAt} of events already sent. Updated in place.
        max_fetch: Maximum number of new events to return.

    Returns:
        A tuple of (new events, the time up to which all events were processed, counters for the log).
    """
    new_events: list[dict] = []
    processed_through = query_start
    stats: dict[str, Any] = {"pages": 0, "rows": 0, "duplicates": 0, "no_id": 0, "future": [], "stop_reason": ""}
    page = 1
    while True:
        response = client.get_events(
            occurred_after=query_start, occurred_before=cycle_start, page=page, page_size=DEFAULT_PAGE_SIZE
        )
        rows = response.get("data", response.get("items", response.get("results", [])))
        stats["pages"] = page
        stats["rows"] += len(rows)
        new_before_page = len(new_events)
        for event in rows:
            event_time = normalize_timestamp(event.get(LogType.EVENTS.time_field))
            event_id = get_event_id(event, LogType.EVENTS)
            if event_time and event_time > cycle_start:
                stats["future"].append((event_id or "<no id>", event_time))  # Held back to a later cycle.
                continue
            if not event_id:
                stats["no_id"] += 1
                demisto.debug(f"{EVENTS_LOG_PREFIX} skipping an event with no recognizable ID field. Keys: {sorted(event)}")
            elif event_id in dedup_cache:
                stats["duplicates"] += 1
            else:
                dedup_cache[event_id] = event_time or cycle_start
                new_events.append(event)
            processed_through = max(processed_through, event_time or processed_through)
            if len(new_events) >= max_fetch:
                stats["stop_reason"] = f"reached max_fetch={max_fetch} on page {page}"
                return new_events, processed_through, stats
        demisto.debug(f"{EVENTS_LOG_PREFIX} page {page}: {len(rows)} rows, {len(new_events) - new_before_page} new")
        if len(rows) < DEFAULT_PAGE_SIZE:
            stats["stop_reason"] = f"page {page} was the last page ({len(rows)} rows): read everything up to the cycle start"
            return new_events, cycle_start, stats
        page += 1


def log_events_cycle(cycle_start: datetime, new_events: list[dict], stats: dict[str, Any], summary: dict[str, Any]) -> None:
    """Log this cycle's late-indexed and future-dated events, then a one-line summary. Never raises.

    A late-indexed event is a new event whose occurredAt is before the previous cycle's watermark:
    the previous version of this collector would have missed it.

    Args:
        cycle_start: When this fetch cycle started.
        new_events: The events sent this cycle.
        stats: Counters from ``collect_new_events``.
        summary: Values computed in ``fetch_events_with_lookback`` for the summary line.
    """
    try:
        previous_watermark = summary["watermark_before"]
        late: list[tuple[str, str]] = []
        for event in new_events:
            event_time = normalize_timestamp(event.get(LogType.EVENTS.time_field))
            if previous_watermark and event_time and event_time < previous_watermark:
                late.append((get_event_id(event, LogType.EVENTS) or "<no id>", event_time))

        if late:
            demisto.info(
                f"{EVENTS_LOG_PREFIX} LATE-INDEXED events caught by the lookback (occurred before the previous "
                f"watermark {previous_watermark}): {len(late)}: {format_event_samples(late, cycle_start)}"
            )
            oldest_age = max(-seconds_from_cycle_start(event_time, cycle_start) for _, event_time in late)
            lookback_seconds = EVENTS_LOOKBACK.total_seconds()
            if oldest_age >= 0.8 * lookback_seconds:
                demisto.info(
                    f"{EVENTS_LOG_PREFIX} WARNING the oldest late-indexed event occurred {oldest_age:.0f}s before the "
                    f"cycle start, close to the {lookback_seconds:.0f}s lookback. Events indexed later than the "
                    f"lookback are missed; consider a longer lookback."
                )
        if stats["future"]:
            demisto.info(
                f"{EVENTS_LOG_PREFIX} FUTURE-DATED events held back for a later cycle: {len(stats['future'])}: "
                f"{format_event_samples(stats['future'], cycle_start)}"
            )

        demisto.info(
            f"{EVENTS_LOG_PREFIX} SUMMARY cycle_start={cycle_start.strftime(DATE_FORMAT)} | "
            f"query {summary['query_start']} -> {cycle_start.strftime(DATE_FORMAT)} [{summary['query_reason']}] | "
            f"pages={stats['pages']} rows={stats['rows']} new={len(new_events)} duplicates={stats['duplicates']} "
            f"late_indexed={len(late)} future_held_back={len(stats['future'])} no_id_skipped={stats['no_id']} | "
            f"stop: {stats['stop_reason']} | watermark {previous_watermark} -> {summary['watermark_after']} | "
            f"migration_floor={summary['floor']} | dedup cache loaded={summary['cache_loaded']} "
            f"after_fetch={summary['cache_after_fetch']} saved={summary['cache_saved']} "
            f"(keeps IDs from {summary['keep_from']}) | "
            f"next fetch: {summary['next_fetch']} | took {summary['took_seconds']:.1f}s"
        )
    except Exception as e:
        demisto.debug(f"{EVENTS_LOG_PREFIX} logging failed, the fetch continues: {e}")


def fetch_events_with_lookback(client: Client, last_run: dict, max_fetch: int, cycle_start: datetime) -> tuple[list[dict], dict]:
    """Fetch events by re-reading the last ``EVENTS_LOOKBACK`` every cycle and dropping duplicates.

    Args:
        client: The Halcyon client.
        last_run: The last run dictionary (legacy or lookback format).
        max_fetch: Maximum number of new events to return.
        cycle_start: When this fetch cycle started.

    Returns:
        A tuple of (new events, updated last run).
    """
    started = time.monotonic()
    last_run = migrate_events_last_run(last_run)
    cycle_start_str = cycle_start.strftime(DATE_FORMAT)
    watermark_before = last_run.get(EVENTS_WATERMARK_KEY)
    floor_before = last_run.get(EVENTS_FLOOR_KEY)
    dedup_cache: dict[str, str] = dict(last_run.get(EVENTS_DEDUP_CACHE_KEY) or {})
    cache_loaded = len(dedup_cache)
    query_start, floor = get_events_query_start(watermark_before, floor_before, cycle_start)
    query_reason = describe_query_start(query_start, watermark_before, floor_before, cycle_start)
    log_events_info(
        f"{EVENTS_LOG_PREFIX} START query {query_start} -> {cycle_start_str} [{query_reason}] | "
        f"max_fetch={max_fetch} | watermark={watermark_before} | dedup cache {cache_loaded} keys"
    )

    new_events, processed_through, stats = collect_new_events(client, query_start, cycle_start_str, dedup_cache, max_fetch)

    # The next cycle never queries before min(processed_through, its own window start), and its
    # window start is at least cycle_start - lookback. Older cache entries can never match again,
    # except when that query starts slightly earlier than expected, which the margin covers.
    next_earliest_start = min(processed_through, (cycle_start - EVENTS_LOOKBACK).strftime(DATE_FORMAT))
    keep_from = (datetime.strptime(next_earliest_start, DATE_FORMAT) - EVENTS_DEDUP_CACHE_MARGIN).strftime(DATE_FORMAT)
    last_run[EVENTS_DEDUP_CACHE_KEY] = {
        event_id: occurred_at for event_id, occurred_at in dedup_cache.items() if occurred_at >= keep_from
    }
    last_run[EVENTS_WATERMARK_KEY] = processed_through
    if floor:
        last_run[EVENTS_FLOOR_KEY] = floor
    else:
        last_run.pop(EVENTS_FLOOR_KEY, None)

    reached_max_fetch = len(new_events) >= max_fetch
    if reached_max_fetch:
        last_run["nextTrigger"] = EVENTS_NEXT_TRIGGER_SECONDS
    else:
        last_run.pop("nextTrigger", None)

    summary = {
        "watermark_before": watermark_before,
        "watermark_after": processed_through,
        "query_start": query_start,
        "query_reason": query_reason,
        "floor": floor,
        "cache_loaded": cache_loaded,
        "cache_after_fetch": len(dedup_cache),
        "cache_saved": len(last_run[EVENTS_DEDUP_CACHE_KEY]),
        "keep_from": keep_from,
        "next_fetch": f"in {EVENTS_NEXT_TRIGGER_SECONDS}s (reached max_fetch)" if reached_max_fetch else "regular interval",
        "took_seconds": time.monotonic() - started,
    }
    log_events_cycle(cycle_start, new_events, stats, summary)
    return enrich_events(new_events, LogType.EVENTS), last_run


def summarize_last_run(last_run: dict) -> dict:
    """Return a copy of the last run that is safe to log: the dedup cache is replaced by its size.

    Args:
        last_run: The last run dictionary.

    Returns:
        The last run with ``events_dedup_cache`` shown as a key count.
    """
    summary = {key: value for key, value in last_run.items() if key != EVENTS_DEDUP_CACHE_KEY}
    if EVENTS_DEDUP_CACHE_KEY in last_run:
        summary[EVENTS_DEDUP_CACHE_KEY] = f"<{len(last_run[EVENTS_DEDUP_CACHE_KEY])} keys>"
    return summary


def get_max_timestamp_from_events(events: list[dict], log_type: LogType) -> str | None:
    """Get the maximum timestamp from a list of events.

    This is used to ensure the fetch timestamp advances even when all events
    are deduplicated (e.g., when events don't have recognizable ID fields).

    Args:
        events: List of event dictionaries.
        log_type: The LogType Enum member for the logs being processed.

    Returns:
        The maximum timestamp string, or None if no timestamps found.
    """
    max_timestamp: str | None = None
    for event in events:
        time_value = event.get(log_type.time_field)
        if time_value and (max_timestamp is None or time_value > max_timestamp):
            max_timestamp = time_value
    return max_timestamp


def fetch_events_for_log_type(
    client: Client,
    log_type: LogType,
    last_run: dict,
    max_fetch: int,
    cycle_start: datetime | None = None,
) -> tuple[list[dict], dict]:
    """Fetches events for a specific log type.

    Events use the lookback mechanism (see ``fetch_events_with_lookback``). Alerts keep the
    watermark-only logic below.

    Args:
        client: The Halcyon client.
        log_type: The LogType to fetch.
        last_run: The last run dictionary.
        max_fetch: Maximum number of events to fetch.
        cycle_start: When the fetch cycle started. Defaults to now.

    Returns:
        A tuple of (events, updated_last_run).
    """
    if log_type == LogType.EVENTS:
        return fetch_events_with_lookback(client, last_run, max_fetch, cycle_start or datetime.now(timezone.utc))

    # Get last run state for this log type
    last_fetch_key = f"last_fetch_{log_type.type_string}"
    previous_ids_key = f"previous_ids_{log_type.type_string}"

    last_fetch_time = last_run.get(last_fetch_key)
    previous_run_ids = set(last_run.get(previous_ids_key, []))

    # If no last fetch time, start from now (per Confluence guidelines)
    if not last_fetch_time:
        last_fetch_time = datetime.now(timezone.utc).strftime(API_DATE_FORMAT)
        demisto.debug(f"No previous fetch time for {log_type.type_string}, starting from: {last_fetch_time}")

    all_events: list[dict] = []
    page = 1
    page_size = min(DEFAULT_PAGE_SIZE, max_fetch)

    while len(all_events) < max_fetch:
        demisto.debug(f"Fetching {log_type.type_string} page {page} with page_size {page_size}")

        if log_type == LogType.ALERTS:
            response = client.get_alerts(
                last_seen_after=last_fetch_time,
                page=page,
                page_size=page_size,
            )
        else:  # LogType.EVENTS
            response = client.get_events(
                occurred_after=last_fetch_time,
                page=page,
                page_size=page_size,
            )

        # Extract events from response - adjust based on actual API response structure
        events = response.get("data", response.get("items", response.get("results", [])))

        if not events:
            demisto.debug(f"No more {log_type.type_string} to fetch.")
            break

        all_events.extend(events)
        demisto.debug(f"Fetched {len(events)} {log_type.type_string}, total: {len(all_events)}")

        # Check if we've reached the end
        if len(events) < page_size:
            break

        page += 1

        # Safety check to prevent infinite loops
        if page > 100:
            demisto.debug(f"Reached maximum page limit for {log_type.type_string}")
            break

    # Limit to max_fetch
    all_events = all_events[:max_fetch]

    # Get the max timestamp from raw events BEFORE deduplication
    # This ensures we advance even if all events are deduplicated
    raw_max_timestamp = get_max_timestamp_from_events(all_events, log_type)

    # Deduplicate events
    unique_events, new_ids, last_timestamp = deduplicate_events(
        events=all_events,
        previous_run_ids=previous_run_ids,
        previous_timestamp=last_fetch_time,
        log_type=log_type,
    )

    # Enrich events
    enriched_events = enrich_events(unique_events, log_type)

    # Update last run - use the deduplication timestamp if available,
    # otherwise fall back to the raw max timestamp to ensure progress
    if last_timestamp:
        last_run[last_fetch_key] = last_timestamp
        last_run[previous_ids_key] = list(new_ids)
    elif raw_max_timestamp:
        # All events were deduplicated but we still need to advance the timestamp
        # to prevent fetching the same events again
        demisto.debug(
            f"All {len(all_events)} {log_type.type_string} events were deduplicated. "
            f"Advancing timestamp from {last_fetch_time} to {raw_max_timestamp}"
        )
        last_run[last_fetch_key] = raw_max_timestamp
        # Clear previous IDs since we're moving to a new timestamp
        last_run[previous_ids_key] = []
    elif not last_run.get(last_fetch_key):
        # If no events and no previous fetch time, set current time
        last_run[last_fetch_key] = datetime.now(timezone.utc).strftime(API_DATE_FORMAT)

    return enriched_events, last_run


def run_events_probe_call(client: Client, description: str, params: dict[str, Any], log_all_keys: bool = False) -> int | None:
    """TEMPORARY DIAGNOSTICS: make one /v2/events call and log the result. Never raises.

    The whole body (API call, parsing and logging) is inside one try/except, so nothing
    that goes wrong here can fail the fetch.

    Args:
        client: The Halcyon client.
        description: What this call checks, for the log line.
        params: The query parameters.
        log_all_keys: Also log every field name of the first event.

    Returns:
        The number of events returned, or None if anything failed.
    """
    try:
        response = client.probe_events(params)
        if not isinstance(response, dict):
            demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} {description}: OK but the response is a {type(response).__name__}")
            return None
        rows = response.get("data", response.get("items", response.get("results", []))) or []
        envelope = {key: response.get(key) for key in ("totalCount", "totalPages", "page", "pageSize") if key in response}
        first_event = rows[0] if rows and isinstance(rows[0], dict) else {}
        time_fields = {key: value for key, value in first_event.items() if key.lower().endswith(("at", "time", "date"))}
        demisto.info(
            f"{INSERT_TIME_PROBE_LOG_PREFIX} {description}: OK rows={len(rows)} envelope={envelope} "
            f"first_event_time_fields={time_fields}"
        )
        if log_all_keys:
            demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} {description}: first_event_keys={sorted(first_event)}")
        return len(rows)
    except Exception as e:
        try:
            demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} {description}: ERROR {str(e)[:1000]}")
        except Exception:  # noqa: S110 - even a logging failure must not fail the fetch
            pass
        return None


def get_insert_time_filter_verdict(baseline_rows: int | None, filtered_rows: int | None) -> str:
    """TEMPORARY DIAGNOSTICS: explain what a filter probe result means.

    Args:
        baseline_rows: Events returned with no time filter.
        filtered_rows: Events returned with the candidate filter set one day in the future.

    Returns:
        A short verdict for the log.
    """
    if filtered_rows is None:
        return "REJECTED - see the error above; it may list the valid parameters"
    if not baseline_rows:
        return "INCONCLUSIVE - the call with no filter returned no events"
    if filtered_rows == 0:
        return "HONORED - a future value returned no events, so the API filters on this parameter"
    return "IGNORED - events came back despite a future value"


def probe_insert_time_filters(client: Client, cycle_start: datetime) -> None:
    """TEMPORARY DIAGNOSTICS: check which /v2/events parameters filter or sort by insert time.

    Args:
        client: The Halcyon client.
        cycle_start: When this fetch cycle started.
    """
    base_params: dict[str, Any] = {"page": 1, "pageSize": 10}
    future_value = (cycle_start + timedelta(days=1)).strftime(DATE_FORMAT)
    demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} starting; candidate filters are sent with {future_value}")

    baseline_rows = run_events_probe_call(client, "baseline (no time filter)", base_params, log_all_keys=True)
    for filter_name in INSERT_TIME_FILTER_CANDIDATES:
        filtered_rows = run_events_probe_call(client, f"filter {filter_name}", {**base_params, filter_name: future_value})
        verdict = get_insert_time_filter_verdict(baseline_rows, filtered_rows)
        demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} filter {filter_name}: {verdict}")

    for sort_by in INSERT_TIME_SORT_CANDIDATES:
        run_events_probe_call(client, f"sortBy={sort_by} Desc", {**base_params, "sortBy": sort_by, "sortOrder": "Desc"})
    demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} finished")


def maybe_probe_insert_time_filters(client: Client, last_run: dict, cycle_start: datetime) -> None:
    """TEMPORARY DIAGNOSTICS: run the insert-time probe at most once per INSERT_TIME_PROBE_INTERVAL. Never raises.

    Args:
        client: The Halcyon client.
        last_run: The last run dictionary. The probe time is stored in it.
        cycle_start: When this fetch cycle started.
    """
    if not INSERT_TIME_PROBE_ENABLED:
        return
    try:
        last_probe = last_run.get(INSERT_TIME_PROBE_LAST_RUN_KEY)
        if last_probe:
            last_probe_time = datetime.strptime(last_probe, DATE_FORMAT).replace(tzinfo=timezone.utc)
            if cycle_start - last_probe_time < INSERT_TIME_PROBE_INTERVAL:
                return
        # Stored before probing, so a failing probe is not retried on every cycle.
        last_run[INSERT_TIME_PROBE_LAST_RUN_KEY] = cycle_start.strftime(DATE_FORMAT)
        probe_insert_time_filters(client, cycle_start)
    except Exception as e:
        demisto.info(f"{INSERT_TIME_PROBE_LOG_PREFIX} probe failed, the fetch continues: {e}")


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Args:
        client: The Halcyon client.

    Returns:
        'ok' if test passed, otherwise raises an exception.
    """
    try:
        # Try to fetch a small number of alerts to verify API access
        # Note: Halcyon API only accepts pageSize values of 10, 30, 50, or 100
        client.get_alerts(page=1, page_size=10)
        return "ok"
    except Exception as e:
        diagnosis = client.diagnose_error(e)
        raise DemistoException(f"Test failed: {e}. Diagnosis: {diagnosis}")


def get_events_command(
    client: Client,
    args: dict,
    event_types_to_fetch: list[str],
) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch events for debugging/development.

    This command is used for developing/debugging and is to be used with caution,
    as it can create events, leading to events duplication and API request limitation exceeding.

    Supports fetching both alerts and events based on the event_type argument.

    Args:
        client: The Halcyon client.
        args: Command arguments.
        event_types_to_fetch: Default event types from integration parameters.

    Returns:
        A tuple of (events, CommandResults).
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    # Determine which event types to fetch - use argument if provided, otherwise fall back to parameter
    event_type_arg = argToList(args.get("event_type"))
    if event_type_arg:
        log_types = get_log_types_from_titles(event_type_arg)
    else:
        log_types = get_log_types_from_titles(event_types_to_fetch)

    # Parse time arguments using dateparser for flexibility
    if start_time:
        parsed_start = dateparser.parse(start_time)
        if parsed_start:
            start_time = parsed_start.strftime(API_DATE_FORMAT)

    if end_time:
        parsed_end = dateparser.parse(end_time)
        if parsed_end:
            end_time = parsed_end.strftime(API_DATE_FORMAT)

    all_events: list[dict] = []

    for log_type in log_types:
        demisto.debug(f"Fetching {log_type.type_string} for get-events command")

        page = 1
        page_size = min(DEFAULT_PAGE_SIZE, limit)
        type_events: list[dict] = []

        while len(type_events) < limit:
            if log_type == LogType.ALERTS:
                response = client.get_alerts(
                    last_seen_after=start_time,
                    last_seen_before=end_time,
                    page=page,
                    page_size=page_size,
                )
            else:
                response = client.get_events(
                    occurred_after=start_time,
                    occurred_before=end_time,
                    page=page,
                    page_size=page_size,
                )

            events = response.get("data", response.get("items", response.get("results", [])))

            if not events:
                break

            type_events.extend(events)

            if len(events) < page_size:
                break

            page += 1

        # Limit and enrich
        type_events = type_events[:limit]
        enriched = enrich_events(type_events, log_type)
        all_events.extend(enriched)

    # Push events to XSIAM if requested
    if should_push_events and all_events:
        send_events_to_xsiam(all_events, vendor=VENDOR, product=PRODUCT)

    # Create human-readable output
    hr = tableToMarkdown(
        name="Halcyon Events",
        t=all_events,
        removeNull=True,
        headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
    )

    return all_events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client,
    last_run: dict,
    log_types: list[LogType],
    max_fetch: int,
) -> tuple[list[dict], dict]:
    """Fetches events for all specified log types from Halcyon.

    Args:
        client: The Halcyon client.
        last_run: The last run dictionary.
        log_types: List of log types to fetch.
        max_fetch: Maximum events to fetch per type.

    Returns:
        A tuple of (all_events, updated_last_run).
    """
    all_events: list[dict] = []
    # Taken once, before any API call: the end of the events query and the future-dated cut-off.
    cycle_start = datetime.now(timezone.utc)

    for log_type in log_types:
        demisto.debug(f"Fetching {log_type.type_string} with max_fetch={max_fetch}")

        events, last_run = fetch_events_for_log_type(
            client=client,
            log_type=log_type,
            last_run=last_run,
            max_fetch=max_fetch,
            cycle_start=cycle_start,
        )

        demisto.debug(f"Fetched {len(events)} {log_type.type_string}")
        all_events.extend(events)

    if LogType.EVENTS in log_types:
        maybe_probe_insert_time_filters(client, last_run, cycle_start)

    return all_events, last_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    # Get parameters
    base_url = params.get("url", "https://api.halcyon.ai").rstrip("/")
    credentials = params.get("credentials", {})
    username = credentials.get("identifier", "")
    password = credentials.get("password", "")
    tenant_id = params.get("tenant_id", "")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    event_types_to_fetch = argToList(params.get("event_types_to_fetch", ["Alerts", "Events"]))
    log_types_to_fetch = get_log_types_from_titles(event_types_to_fetch)

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            tenant_id=tenant_id,
            verify=verify_certificate,
            proxy=proxy,
            max_fetch=max_fetch,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "halcyon-get-events":
            events, results = get_events_command(
                client=client,
                args=args,
                event_types_to_fetch=event_types_to_fetch,
            )
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Starting fetch with last_run: {summarize_last_run(last_run)}")

            events, next_run = fetch_events_command(
                client=client,
                last_run=last_run,
                log_types=log_types_to_fetch,
                max_fetch=max_fetch,
            )

            demisto.debug(f"Fetched {len(events)} total events")

            if events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            if next_run:
                demisto.debug(f"Setting new last_run: {summarize_last_run(next_run)}")
                demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
