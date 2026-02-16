import demistomock as demisto
from CommonServerPython import *
import urllib3
import base64
import json
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "iManage"
PRODUCT = "Threat"
MAX_EVENTS_PER_FETCH = 900  # Default events per type
# Maximum page size for Behavior Analytics alerts
# Used for all types to simplify pagination logic, even though only Behavior Analytics has this limit
MAX_PAGE_SIZE = 90
DEFAULT_TIMEZONE = "UTC"
SORT_FIELD = "alert_time"  # API filters and sorts by this field only
SORT_ORDER = -1  # -1 for descending (newest first), 1 for ascending (oldest first)

# Retry configuration for API throttling
MAX_RETRIES = 3
RETRY_DELAYS = [30, 60, 90]  # Delays in seconds: 30s, 1min, 1.5min

# Event type configurations: maps event type names to their configuration
EVENT_TYPE_CONFIG = {
    "Behavior Analytics alerts": {
        "source_log_type": "BehaviorAnalytics",
        "url_suffix": "/tm-api/getAlertList",
        "use_token_auth": True,
    },
    "Get Addressable Alerts": {
        "source_log_type": "AddressableAlerts",
        "url_suffix": "/tm-api/getAddressableAlerts",
        "use_token_auth": False,
    },
    "Get Detect And Protect Alerts": {
        "source_log_type": "DetectAndProtectAlerts",
        "url_suffix": "/tm-api/getDetectAndProtectAlerts",
        "use_token_auth": False,
    },
}

# Event type constants - derived from EVENT_TYPE_CONFIG keys
BEHAVIOR_ANALYTICS, ADDRESSABLE_ALERTS, DETECT_AND_PROTECT_ALERTS = EVENT_TYPE_CONFIG.keys()

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the iManage Threat Manager API"""

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        secret: str | None = None,
    ):
        """
        Initialize the Client.

        Args:
            base_url: The base URL of the iManage Threat Manager instance.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use system proxy settings.
            username: Username for user sign-in authentication (for Detect and Protect alerts and Addressable Alerts).
            password: Password for user sign-in authentication (for Detect and Protect alerts and Addressable Alerts).
            token: Application token for API token authentication (for Behavior Analytics alerts).
            secret: Application secret for API token authentication (for Behavior Analytics alerts).
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.token = token
        self.secret = secret
        self._access_token: str | None = None
        self._user_access_token: str | None = None

    def _extract_jwt_expiration(self, token: str) -> int:
        """
        Extract expiration timestamp from JWT token.

        Args:
            token: JWT token string (e.g., "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzA3MzMwMjl9.signature")

        Returns:
            int: Expiration timestamp in seconds since epoch (e.g., 1770733029).
                 Returns current time + 30 minutes (1800 seconds) if extraction fails.
        """
        try:
            # JWT format: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")

            # Decode the payload (second part)
            # Add padding if needed for base64 decoding
            payload = parts[1]
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += "=" * padding

            decoded = base64.b64decode(payload)
            payload_data = json.loads(decoded)

            exp = payload_data.get("exp")
            if not exp:
                raise ValueError("No 'exp' field in JWT payload")

            return exp
        except Exception as e:
            demisto.debug(f"Failed to extract JWT expiration: {str(e)}, using 30-minute default")
            # Default to 30 minutes from now if extraction fails
            return int(datetime.now().timestamp()) + 1800

    def _get_cached_token(self, token_key: str, expiry_key: str) -> str | None:
        """
        Get cached token from integration context if still valid.

        Args:
            token_key: Key for the cached token in integration context (e.g., "api_access_token")
            expiry_key: Key for the token expiry timestamp (e.g., "api_token_expiry")

        Returns:
            str | None: Cached token if valid, None otherwise
        """
        integration_context = demisto.getIntegrationContext()
        cached_token = integration_context.get(token_key)
        token_expiry = integration_context.get(expiry_key, 0)
        current_time = int(datetime.now().timestamp())

        # Check if cached token is still valid (with 5 minute buffer to avoid edge cases)
        if cached_token and isinstance(token_expiry, int) and token_expiry > (current_time + 300):
            demisto.debug(f"Using cached token from {token_key} (expires in {token_expiry - current_time} seconds)")
            return cached_token

        if cached_token:
            demisto.debug(f"Cached token from {token_key} is expired or invalid, will request new token")

        return None

    def _cache_token(self, token: str, token_key: str, expiry_key: str) -> None:
        """
        Cache token in integration context with its expiration time.

        Args:
            token: The JWT access token to cache
            token_key: Key to store the token under (e.g., "api_access_token")
            expiry_key: Key to store the expiry timestamp under (e.g., "api_token_expiry")
        """
        if not token:
            demisto.debug(f"Cannot cache empty token for {token_key}")
            return

        integration_context = demisto.getIntegrationContext()
        expiry_time = self._extract_jwt_expiration(token)
        integration_context[token_key] = token
        integration_context[expiry_key] = expiry_time
        demisto.setIntegrationContext(integration_context)
        demisto.debug(f"Cached token under {token_key} (expires at {expiry_time})")

    def get_access_token_from_token_secret(self, force_new: bool = False) -> str:
        """
        Acquire a JWT access token using application token and secret.
        Uses cached token from integration context if still valid.

        Args:
            force_new: If True, forces generation of a new token (ignores cache and instance variable)

        Returns:
            str: The JWT access token.
        """
        if self._access_token and not force_new:
            return self._access_token

        # Try to get cached token (unless force_new is True)
        if not force_new:
            cached_token = self._get_cached_token("api_access_token", "api_token_expiry")
            if cached_token:
                self._access_token = cached_token
                return self._access_token

        # Request new token
        demisto.debug("Acquiring new JWT access token using application token and secret.")
        response = self._http_request(
            method="POST",
            url_suffix="/tm-api/v2/login/api_token",
            json_data={"token": self.token, "secret": self.secret},
            resp_type="json",
        )
        self._access_token = response.get("access_token")
        if not self._access_token:
            raise DemistoException("Failed to acquire access token: no access_token in response")

        # Cache the new token
        self._cache_token(self._access_token, "api_access_token", "api_token_expiry")

        return self._access_token

    def get_access_token_from_username_password(self, force_new: bool = False) -> str:
        """
        Acquire a JWT access token using username and password.
        Uses cached token from integration context if still valid.

        Args:
            force_new: If True, forces generation of a new token (ignores cache and instance variable)

        Returns:
            str: The JWT access token.
        """
        if self._user_access_token and not force_new:
            return self._user_access_token

        # Try to get cached token (unless force_new is True)
        if not force_new:
            cached_token = self._get_cached_token("user_access_token", "user_token_expiry")
            if cached_token:
                self._user_access_token = cached_token
                return self._user_access_token

        # Request new token
        demisto.debug("Acquiring new JWT access token using username and password.")
        response = self._http_request(
            method="POST",
            url_suffix="/tm-api/v2/login",
            json_data={"username": self.username, "password": self.password},
            resp_type="json",
        )
        self._user_access_token = response.get("access_token")
        if not self._user_access_token:
            raise DemistoException("Failed to acquire user access token: no access_token in response")

        # Cache the new token
        self._cache_token(self._user_access_token, "user_access_token", "user_token_expiry")

        return self._user_access_token

    def _fetch_alerts(
        self,
        event_type: str,
        start_date: int,
        end_date: int,
        page_size: int = MAX_PAGE_SIZE,
    ) -> List[Dict[str, Any]]:
        """
        Fetch alerts from iManage Threat Manager for a specific event type with retry logic.

        Args:
            event_type: Type of events to fetch (e.g., "Behavior Analytics alerts").
            start_date: Timestamp in milliseconds marking the beginning of the alert range.
            end_date: Timestamp in milliseconds marking the end of the alert range.
            page_size: Number of alerts per page.

        Returns:
            List[Dict[str, Any]]: List of alerts sorted by alert_time (newest first).

        Raises:
            DemistoException: If all retry attempts fail.

        Note:
            Implements retry mechanism with exponential backoff for API throttling:
            - Retry 1: Wait 30s, regenerate token
            - Retry 2: Wait 60s, regenerate token
            - Retry 3: Wait 90s, regenerate token
            - After 3 failures: Raise exception
        """
        # Get configuration for this event type
        config = EVENT_TYPE_CONFIG[event_type]
        use_token_auth = config["use_token_auth"]

        demisto.debug(f"Fetching {event_type} from {start_date} to {end_date} with page size {page_size}.")

        for attempt in range(MAX_RETRIES + 1):
            try:
                # Get appropriate access token based on auth type
                # Force new token on retries (attempt > 0)
                access_token = (
                    self.get_access_token_from_token_secret(force_new=(attempt > 0))
                    if use_token_auth
                    else self.get_access_token_from_username_password(force_new=(attempt > 0))
                )

                response = self._http_request(
                    method="POST",
                    url_suffix=config["url_suffix"],
                    headers={"X-Auth-Token": access_token},
                    json_data={
                        "timezone": DEFAULT_TIMEZONE,
                        "start_date": str(start_date),
                        "end_date": str(end_date),
                        "page_size": min(page_size, MAX_PAGE_SIZE),
                        "sort_field": SORT_FIELD,
                        "sort_order": SORT_ORDER,
                    },
                    resp_type="json",
                )

                alerts = response.get("results", [])
                demisto.debug(f"Fetched {len(alerts)} {event_type}.")
                return alerts

            except Exception as e:
                error_str = str(e)
                # Check if it's a retryable error (401 Unauthorized, 429 Too Many Requests, or 503 Service Unavailable)
                # 401: Token expired - regenerate token
                # 429: Rate limiting - wait and retry
                # 503: Temporary service issue - wait and retry
                is_retryable = any(
                    indicator in error_str.lower()
                    for indicator in [
                        "401",
                        "unauthorized",
                        "429",
                        "too many requests",
                        "rate limit",
                        "503",
                        "service unavailable",
                    ]
                )

                if is_retryable and attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    demisto.debug(
                        f"Retryable error on attempt {attempt + 1}/{MAX_RETRIES + 1}. "
                        f"Waiting {delay} seconds before regenerating token and retrying..."
                    )
                    time.sleep(delay)
                    # Force new token on next iteration
                    continue

                # Not a retryable error, or max retries exceeded
                if attempt == MAX_RETRIES and is_retryable:
                    demisto.error(f"Failed to fetch {event_type} after {MAX_RETRIES + 1} attempts. " f"Last error: {error_str}")
                raise

        # This should never be reached, but added for type safety
        raise DemistoException(f"Failed to fetch {event_type} after {MAX_RETRIES + 1} attempts")


""" HELPER FUNCTIONS """


def _calculate_timestamp_ms(date_str: str | None, default_hours_ago: int = 0) -> int:
    """
    Calculate timestamp in milliseconds from a date string or default offset.

    Args:
        date_str: Date string to convert (e.g., "2024-01-01T00:00:00Z"). If None, uses default.
        default_hours_ago: Hours to subtract from current time if date_str is None (default: 0 for now).

    Returns:
        int: Timestamp in milliseconds since epoch.
    """
    if date_str:
        dt = arg_to_datetime(date_str)
        if dt is None:
            raise ValueError(f"Failed to parse date string: {date_str}")
        return int(dt.timestamp() * 1000)

    base_time = datetime.now()
    if default_hours_ago > 0:
        base_time -= timedelta(hours=default_hours_ago)

    return int(base_time.timestamp() * 1000)


def _deduplicate_events(events: List[Dict[str, Any]], last_run_ids: List[str], last_fetch_time: int) -> List[Dict[str, Any]]:
    """
    Remove duplicate events based on event IDs.

    Args:
        events: List of events to deduplicate (sorted newest first by alert_time)
        last_run_ids: List of event IDs from the last run to filter out
        last_fetch_time: Timestamp in milliseconds from the last fetch (alert_time value)

    Returns:
        List of deduplicated events
    """
    if not events:
        return []

    demisto.debug(f"Deduplicating {len(events)} events against {len(last_run_ids)} previous IDs")
    # Convert last_run_ids to a set for faster lookup
    seen_ids = set(last_run_ids)
    deduplicated = []

    # Iterate from the end (oldest events) backwards
    for i in range(len(events) - 1, -1, -1):
        event = events[i]
        event_id = event.get("id")
        event_time = event.get("alert_time")

        if not event_id:
            demisto.debug(f"Event at index {i} and at alert_time {event_time} has no ID, Adding it without deduplication.")
            deduplicated.append(event)
            continue

        if event_time and event_time > last_fetch_time:
            # Event is newer than last_fetch_time, add it
            deduplicated.append(event)

            # Add all remaining events (from index i-1 down to 0) - they're all newer too
            for j in range(i - 1, -1, -1):
                remaining_event = events[j]
                deduplicated.append(remaining_event)

            demisto.debug(f"Found event newer than last_fetch_time at index {i}, added all {i + 1} newer events")
            break

        # Event is at or before last_fetch_time, check against seen IDs
        if event_id not in seen_ids:
            deduplicated.append(event)
            seen_ids.add(event_id)
        else:
            demisto.debug(f"Duplicate event found with ID {event_id} at index {i}, skipping.")

    # Reverse to maintain original order (newest first)
    deduplicated.reverse()

    demisto.debug(f"Deduplication complete: {len(deduplicated)} unique events")
    return deduplicated


def _add_fields_to_events(events: List[Dict] | None, source_log_type: str) -> None:
    """
    Adds required fields to events for ingestion.

    Args:
        events: List of event dictionaries. Can be None or empty list.
        source_log_type: The source log type string (e.g., "BehaviorAnalytics").
    """
    if not events:
        return

    for event in events:
        # IMPORTANT: _time uses update_time, NOT alert_time (which is used for filtering/sorting)
        update_time = event.get("update_time")
        if update_time and isinstance(update_time, int | float):
            try:
                # update_time is in milliseconds, convert to seconds for datetime
                event_datetime = datetime.fromtimestamp(update_time / 1000, tz=timezone.utc)
                event["_time"] = event_datetime.strftime(DATE_FORMAT)
            except (ValueError, OSError) as e:
                demisto.debug(f"Failed to convert update_time {update_time} to datetime: {str(e)}")

        # Add _source_log_type field
        event["_source_log_type"] = source_log_type

        # Add _ENTRY_STATUS field by comparing update_time with alert_time
        alert_time = event.get("alert_time")
        if update_time and alert_time and isinstance(update_time, int | float) and isinstance(alert_time, int | float):
            if update_time == alert_time:
                event["_ENTRY_STATUS"] = "new"
            elif update_time > alert_time:
                event["_ENTRY_STATUS"] = "modified"


def _fetch_events_with_pagination(
    client: Client, event_type: str, start_time: int, end_time: int, limit: int
) -> List[Dict[str, Any]]:
    """
    Fetch events with pagination support for any event type.

    Args:
        client: iManage Threat Manager client instance.
        event_type: Type of events to fetch.
        start_time: Start timestamp in milliseconds.
        end_time: End timestamp in milliseconds.
        limit: Maximum number of events to fetch.

    Returns:
        List of fetched events sorted by alert_time (newest first).

    Note:
        Uses backward time-based pagination (cursor-based pagination using timestamps).
        The API returns events sorted by alert_time in descending order (newest first).

        Pagination strategy:
        - Page 1: Fetch events from [start_time, end_time] → Returns newest events first
        - Page 2: Fetch events from [start_time, oldest_alert_time_from_page_1] → Returns next oldest events
        - Continue narrowing the end_time window to exclude already-fetched events

        Example: Requesting events from time 100 to 200 with page_size=90:
        - Page 1: [100, 200] → Events 200, 199, 198...150 (90 events)
        - Page 2: [100, 150] → Events 149, 148, 147...100 (remaining events)

    """
    demisto.debug(f"Fetching {event_type} with pagination (limit={limit}, page_size={MAX_PAGE_SIZE})")
    events: List[Dict[str, Any]] = []
    current_end_time = end_time
    last_page_ids: List[str] = []  # Track IDs from the last page for deduplication
    last_page_time = end_time  # Track the oldest timestamp from the last page

    while len(events) < limit:
        # Calculate how many more events we need
        remaining = limit - len(events)
        page_size = min(remaining, MAX_PAGE_SIZE)

        demisto.debug(
            f"Fetching page: start_time={start_time}, end_time={current_end_time}, "
            f"page_size={page_size}, total_so_far={len(events)}"
        )

        batch = client._fetch_alerts(event_type, start_time, current_end_time, page_size)

        if not batch:
            demisto.debug("No more events available, stopping pagination")
            break

        # Track original batch size before deduplication to determine if more events exist
        original_batch_size = len(batch)

        # Deduplicate the batch against events from the previous page
        # This handles cases where events have the same alert_time at page boundaries
        batch = _deduplicate_events(batch, last_page_ids, last_page_time)

        events.extend(batch)
        demisto.debug(f"Fetched {len(batch)} events in this batch (after deduplication), total now: {len(events)}")

        # If the original batch had fewer events than requested, we've reached the end
        if original_batch_size < page_size:
            demisto.debug(f"Received {original_batch_size} events (less than page_size {page_size}), no more events available")
            break

        # Move the end_time cursor backward to the oldest event in this batch
        # This excludes already-fetched events from the next request
        # Since events are sorted newest first, batch[-1] is the oldest event in this page
        oldest_alert_time = batch[-1].get("alert_time")
        if oldest_alert_time:
            # Store IDs of events with the oldest alert_time for next iteration's deduplication
            last_page_ids = []
            last_page_time = oldest_alert_time
            for event in reversed(batch):  # Iterate from oldest to newest
                event_time = event.get("alert_time")
                if event_time == oldest_alert_time:
                    event_id = event.get("id")
                    if event_id:
                        last_page_ids.append(event_id)
                else:
                    # Events are sorted, so we can stop once we pass the oldest_alert_time
                    break

            current_end_time = oldest_alert_time
            demisto.debug(
                f"Updated end_time to {current_end_time} (oldest alert_time), stored {len(last_page_ids)} IDs for deduplication"
            )
        else:
            demisto.debug("No alert_time in last event, stopping pagination")
            break

    return events


""" COMMAND FUNCTIONS """


def validate_credentials_for_event_types(client: Client, event_types: List[str]) -> None:
    """
    Validate that the correct credentials are provided for the selected event types.

    Args:
        client (Client): iManage Threat Manager client to use.
        event_types (List[str]): List of event types to fetch.

    Raises:
        DemistoException: If required credentials are missing for the selected event types.
    """
    demisto.debug(f"Validating credentials for event types: {event_types}")
    missing_creds = []

    for event_type in event_types:
        if event_type == BEHAVIOR_ANALYTICS and not (client.token and client.secret):
            missing_creds.append(f"{event_type} requires Token and Secret credentials")
        elif event_type in [ADDRESSABLE_ALERTS, DETECT_AND_PROTECT_ALERTS] and not (client.username and client.password):
            missing_creds.append(f"{event_type} requires Username and Password credentials")

    if missing_creds:
        error_msg = "Missing required credentials:\n" + "\n".join(f"- {msg}" for msg in missing_creds)
        demisto.debug(f"Credential validation failed: {error_msg}")
        raise DemistoException(error_msg)

    demisto.debug("Credential validation successful")


def test_module_command(client: Client, params: dict[str, Any], event_types: List[str]) -> str:
    """
    Tests API connectivity and authentication.

    Args:
        client: iManage Threat Manager client to use.
        params: Integration parameters.
        event_types: List of event types to fetch.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        demisto.debug(f"Testing module with event types: {event_types}")
        # Test with a small time window (last hour)
        end_time = int(datetime.now().timestamp() * 1000)
        start_time = end_time - (3600 * 1000)  # 1 hour ago

        # Test each configured event type
        for event_type in event_types:
            demisto.debug(f"Testing connectivity for event type: {event_type}")
            client._fetch_alerts(event_type, start_time, end_time, 1)

    except Exception as e:
        if "Forbidden" in str(e) or "401" in str(e) or "Unauthorized" in str(e):
            demisto.debug(f"Authorization error during test: {str(e)}")
            return "Authorization Error: make sure credentials are correctly set"
        demisto.debug(f"Test module failed with error: {str(e)}")
        raise

    demisto.debug("Test module completed successfully")
    return "ok"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[List[Dict[str, Any]], CommandResults]:
    """
    Gets events from iManage Threat Manager API.

    Args:
        client: iManage Threat Manager client instance
        args: Command arguments containing:
            - limit: Maximum number of events to return (default: 50)
            - from_date: Start date for event retrieval (default: 1 hour ago)
            - to_date: End date for event retrieval (default: now)
            - event_type: Type of events to fetch (default: Behavior Analytics alerts)

    Returns:
        tuple: (List of events, CommandResults for display)
    """
    limit = arg_to_number(args.get("limit", 50)) or 50
    from_date = args.get("from_date")
    to_date = args.get("to_date")
    event_type = args.get("event_type", BEHAVIOR_ANALYTICS)

    demisto.debug(f"Getting events: type={event_type}, limit={limit}, from_date={from_date}, to_date={to_date}")

    # Calculate time range in milliseconds
    start_time = _calculate_timestamp_ms(from_date, default_hours_ago=1)
    end_time = _calculate_timestamp_ms(to_date)

    # Fetch events with pagination support for all event types
    events = _fetch_events_with_pagination(client, event_type, start_time, end_time, limit)

    demisto.debug(f"Retrieved {len(events)} total events for {event_type}")
    hr = tableToMarkdown(name=f"iManage Threat Manager {event_type}", t=events[:10], removeNull=True)
    return events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client, last_run: dict[str, Any], event_types: List[str], max_events_per_type: int
) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Fetches events from iManage Threat Manager for all configured event types.

    Handles deduplication, pagination, and state management across fetch cycles.

    Args:
        client: iManage Threat Manager client instance
        last_run: Dictionary containing the latest event timestamps and IDs for each event type.
                  Keys: last_fetch_{source_log_type}, last_ids_{source_log_type}
        event_types: List of event types to fetch (e.g., ["Behavior Analytics alerts"])
        max_events_per_type: Maximum number of events to fetch per type (max: 900)

    Returns:
        tuple: (next_run dictionary for state persistence, list of deduplicated events)

    Note:
        - First fetch retrieves events from last 24 hours
        - Subsequent fetches use last_fetch timestamp from last_run
        - Events are deduplicated based on IDs from previous fetch
        - Errors for individual event types don't stop fetching other types
    """
    demisto.debug(f"Starting fetch_events_command with event_types: {event_types}, max_events_per_type: {max_events_per_type}")
    all_events: List[Dict[str, Any]] = []
    next_run: Dict[str, Any] = {}
    current_time = int(datetime.now().timestamp() * 1000)

    for event_type in event_types:
        demisto.debug(f"Fetching events for type: {event_type}")

        # Get source log type for this event type (used for state keys)
        config = EVENT_TYPE_CONFIG.get(event_type, EVENT_TYPE_CONFIG[BEHAVIOR_ANALYTICS])
        source_log_type = str(config["source_log_type"])

        # Get last fetch time and IDs for this event type using source_log_type
        last_fetch_key = f"last_fetch_{source_log_type}"
        last_ids_key = f"last_ids_{source_log_type}"

        last_fetch_time = last_run.get(last_fetch_key)
        last_run_ids = last_run.get(last_ids_key, [])

        if not last_fetch_time:
            # First fetch - get events from last 24 hours
            last_fetch_time = current_time - (24 * 3600 * 1000)
            demisto.debug(f"First fetch for {event_type}, fetching from last 24 hours")
        else:
            demisto.debug(f"Continuing fetch for {event_type} from timestamp {last_fetch_time}")

        events: List[Dict[str, Any]] = []

        try:
            # Fetch events for this type with pagination support
            events = _fetch_events_with_pagination(client, event_type, last_fetch_time, current_time, max_events_per_type)

            demisto.debug(f"Fetched {len(events)} events for {event_type} (after pagination deduplication)")

            # Deduplicate events based on IDs from last run (cross-fetch deduplication)
            events = _deduplicate_events(events, last_run_ids, last_fetch_time)
            demisto.debug(f"After cross-fetch deduplication: {len(events)} events for {event_type}")

            # Add fields to events before extending
            _add_fields_to_events(events, source_log_type)

            all_events.extend(events)

            # Update next run for this event type
            if events:
                # Since events are sorted newest first by alert_time,
                # the first event has the latest alert_time
                latest_alert_time = events[0].get("alert_time", last_fetch_time)
                next_run[last_fetch_key] = latest_alert_time

                # Store IDs of events with the latest alert_time for deduplication
                latest_time_event_ids = []
                for event in events:
                    event_time = event.get("alert_time")
                    if event_time == latest_alert_time:
                        event_id = event.get("id")
                        if event_id:
                            latest_time_event_ids.append(event_id)
                    elif event_time and event_time < latest_alert_time:
                        # Events are sorted newest first, so we can stop here
                        break

                next_run[last_ids_key] = latest_time_event_ids
                demisto.debug(f"Stored {len(latest_time_event_ids)} event IDs with alert_time {latest_alert_time}")
            else:
                # No new events, update timestamp to current time and clear IDs
                demisto.debug(f"No new events for {event_type}, updating timestamp to current time")
                next_run[last_fetch_key] = current_time
                next_run[last_ids_key] = []

        except Exception as e:
            demisto.error(f"Error fetching {event_type}: {str(e)}")
            # Keep the last fetch time and IDs if there's an error
            next_run[last_fetch_key] = last_fetch_time
            next_run[last_ids_key] = last_run_ids

    demisto.debug(f"Fetch complete: Total {len(all_events)} events across all types")
    return next_run, all_events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    Main function that parses params and runs command functions.
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Parse connection parameters
    base_url = params.get("url", "").rstrip("/")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Parse authentication parameters
    username = params.get("credentials_user", {}).get("identifier")
    password = params.get("credentials_user", {}).get("password")

    token = params.get("credentials_token", {}).get("identifier")
    secret = params.get("credentials_token", {}).get("password")

    # Parse fetch parameters
    event_types = argToList(params.get("event_types", [BEHAVIOR_ANALYTICS]))
    if not event_types:
        event_types = [BEHAVIOR_ANALYTICS]

    max_events_per_type = arg_to_number(params.get("max_events_per_type", MAX_EVENTS_PER_FETCH)) or MAX_EVENTS_PER_FETCH

    demisto.debug(f"Command being called is {command}")
    demisto.debug(f"Event types configured: {event_types}, Max events per type: {max_events_per_type}")

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            username=username,
            password=password,
            token=token,
            secret=secret,
        )

        if command == "test-module" or command == "fetch-events":
            # Validate credentials for selected event types (from params)
            validate_credentials_for_event_types(client, event_types)

        if command == "test-module":
            result = test_module_command(client, params, event_types)
            return_results(result)

        elif command == "imanage-threat-manager-get-events":
            event_type = args.get("event_type", BEHAVIOR_ANALYTICS)
            # Validate credentials for the specific event type requested (from args)
            validate_credentials_for_event_types(client, [event_type])
            should_push_events = argToBoolean(args.pop("should_push_events", False))
            demisto.debug(f"Executing get-events command, should_push_events={should_push_events}")
            events, results = get_events_command(client, args)
            if should_push_events:
                # Determine source_log_type based on event_type
                config = EVENT_TYPE_CONFIG.get(event_type, EVENT_TYPE_CONFIG[BEHAVIOR_ANALYTICS])
                source_log_type_param = str(config["source_log_type"])

                _add_fields_to_events(events, source_log_type_param)
                demisto.debug(f"Sending {len(events)} events to XSIAM.")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                if results.readable_output:
                    results.readable_output += f"\n\n{len(events)} events sent to XSIAM."
                demisto.debug("Events sent to XSIAM successfully")
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Last run state: {last_run}")
            next_run, events = fetch_events_command(
                client=client, last_run=last_run, event_types=event_types, max_events_per_type=max_events_per_type
            )

            # Events already have _time and _source_log_type added in fetch_events_command
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug("Sent events to XSIAM successfully")
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
