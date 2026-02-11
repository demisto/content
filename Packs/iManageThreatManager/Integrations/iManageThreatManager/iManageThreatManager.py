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
MAX_PAGE_SIZE = 90  # Maximum page size for Behavior Analytics alerts - Used for all types to simplify pagination logic, even though only Behavior Analytics has this limit
DEFAULT_TIMEZONE = "UTC"

# Event type configurations: maps event type names to their source log types
EVENT_TYPES = {
    "Behavior Analytics alerts": "BehaviorAnalytics",
    "Get Addressable Alerts": "AddressableAlerts",
    "Get Detect And Protect Alerts": "DetectAndProtectAlerts",
}

# Event type constants - derived from EVENT_TYPES keys
BEHAVIOR_ANALYTICS, ADDRESSABLE_ALERTS, DETECT_AND_PROTECT_ALERTS = EVENT_TYPES.keys()

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the iManage Threat Manager API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

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
            username: Username for user sign-in authentication (for Detect and Protect alerts).
            password: Password for user sign-in authentication (for Detect and Protect alerts).
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

        Example:
            >>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NzA3MzMwMjl9.signature"
            >>> expiration = self._extract_jwt_expiration(token)
            >>> # Returns: 1770733029 (the 'exp' value from the JWT payload)
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

    def get_access_token_from_token_secret(self) -> str:
        """
        Acquire a JWT access token using application token and secret.
        Uses cached token from integration context if still valid.

        Returns:
            str: The JWT access token.
        """
        if self._access_token:
            return self._access_token

        # Try to get cached token
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
        self._access_token = response.get("access_token", "")

        # Cache the new token
        self._cache_token(self._access_token, "api_access_token", "api_token_expiry")

        return self._access_token

    def get_access_token_from_username_password(self) -> str:
        """
        Acquire a JWT access token using username and password.
        Uses cached token from integration context if still valid.

        Returns:
            str: The JWT access token.
        """
        if self._user_access_token:
            return self._user_access_token

        # Try to get cached token
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
        self._user_access_token = response.get("access_token", "")

        # Cache the new token
        self._cache_token(self._user_access_token, "user_access_token", "user_token_expiry")

        return self._user_access_token

    def _fetch_alerts(
        self,
        url_suffix: str,
        alert_type: str,
        use_token_auth: bool,
        start_date: int,
        end_date: int,
        page_size: int = MAX_PAGE_SIZE,
        sort_field: str = "update_time",
        sort_order: int = -1,
        timezone: str = DEFAULT_TIMEZONE,
    ) -> List[Dict[str, Any]]:
        """
        Generic method to fetch alerts from iManage Threat Manager.

        Args:
            url_suffix: API endpoint suffix.
            alert_type: Type of alert for logging purposes.
            use_token_auth: If True, use token/secret auth; otherwise use username/password.
            start_date: Timestamp in milliseconds marking the beginning of the alert range.
            end_date: Timestamp in milliseconds marking the end of the alert range.
            page_size: Number of alerts per page.
            sort_field: Field to sort by (default: "update_time").
            sort_order: Sort direction. Use -1 for descending (newest first), 1 for ascending (oldest first).
            timezone: Timezone for interpreting date ranges (default: "UTC").

        Returns:
            List[Dict[str, Any]]: List of alerts sorted by update_time.
        """
        demisto.debug(f"Fetching {alert_type} from {start_date} to {end_date}.")

        access_token = (
            self.get_access_token_from_token_secret() if use_token_auth else self.get_access_token_from_username_password()
        )

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            headers={"X-Auth-Token": access_token},
            json_data={
                "timezone": timezone,
                "start_date": str(start_date),
                "end_date": str(end_date),
                "page_size": min(page_size, MAX_PAGE_SIZE) if use_token_auth else page_size,
                "sort_field": sort_field,
                "sort_order": sort_order,
            },
            resp_type="json",
        )

        alerts = response.get("results", [])
        demisto.debug(f"Fetched {len(alerts)} {alert_type}.")
        return alerts

    def get_behavior_analytics_alerts(
        self,
        start_date: int,
        end_date: int,
        page_size: int = MAX_PAGE_SIZE,
        sort_field: str = "update_time",
        sort_order: int = -1,
        timezone: str = DEFAULT_TIMEZONE,
    ) -> List[Dict[str, Any]]:
        """
        Fetch Behavior Analytics alerts from iManage Threat Manager.

        Args:
            start_date: Timestamp in milliseconds marking the beginning of the alert range.
            end_date: Timestamp in milliseconds marking the end of the alert range.
            page_size: Number of alerts per page (max 90).
            sort_field: Field to sort by (default: "update_time").
            sort_order: Sort direction. Use -1 for descending (newest first), 1 for ascending (oldest first).
            timezone: Timezone for interpreting date ranges (default: "UTC").

        Returns:
            List[Dict[str, Any]]: List of alerts sorted by update_time.
        """
        return self._fetch_alerts(
            url_suffix="/tm-api/getAlertList",
            alert_type="Behavior Analytics alerts",
            use_token_auth=True,
            start_date=start_date,
            end_date=end_date,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            timezone=timezone,
        )

    def get_addressable_alerts(
        self,
        start_date: int,
        end_date: int,
        page_size: int = MAX_PAGE_SIZE,
        sort_field: str = "update_time",
        sort_order: int = -1,
        timezone: str = DEFAULT_TIMEZONE,
    ) -> List[Dict[str, Any]]:
        """
        Fetch Addressable Alerts from iManage Threat Manager.
        Requires user sign-in authentication.

        Args:
            start_date: Timestamp in milliseconds marking the beginning of the alert range.
            end_date: Timestamp in milliseconds marking the end of the alert range.
            page_size: Number of alerts per page.
            sort_field: Field to sort by (default: "update_time").
            sort_order: Sort direction. Use -1 for descending (newest first), 1 for ascending (oldest first).
            timezone: Timezone for interpreting date ranges (default: "UTC").

        Returns:
            List[Dict[str, Any]]: List of alerts sorted by update_time.
        """
        return self._fetch_alerts(
            url_suffix="/tm-api/getAddressableAlerts",
            alert_type="Addressable Alerts",
            use_token_auth=False,
            start_date=start_date,
            end_date=end_date,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            timezone=timezone,
        )

    def get_detect_and_protect_alerts(
        self,
        start_date: int,
        end_date: int,
        page_size: int = MAX_PAGE_SIZE,
        sort_field: str = "update_time",
        sort_order: int = -1,
        timezone: str = DEFAULT_TIMEZONE,
    ) -> List[Dict[str, Any]]:
        """
        Fetch Detect and Protect Alerts from iManage Threat Manager.
        Requires user sign-in authentication.

        Args:
            start_date: Timestamp in milliseconds marking the beginning of the alert range.
            end_date: Timestamp in milliseconds marking the end of the alert range.
            page_size: Number of alerts per page.
            sort_field: Field to sort by (default: "update_time").
            sort_order: Sort direction. Use -1 for descending (newest first), 1 for ascending (oldest first).
            timezone: Timezone for interpreting date ranges (default: "UTC").

        Returns:
            List[Dict[str, Any]]: List of alerts sorted by update_time.
        """
        return self._fetch_alerts(
            url_suffix="/tm-api/getDetectAndProtectAlerts",
            alert_type="Detect and Protect Alerts",
            use_token_auth=False,
            start_date=start_date,
            end_date=end_date,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            timezone=timezone,
        )


""" HELPER FUNCTIONS """


def deduplicate_events(events: List[Dict[str, Any]], last_run_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Remove duplicate events based on event IDs.

    Args:
        events: List of events to deduplicate
        last_run_ids: List of event IDs from the last run to filter out

    Returns:
        List of deduplicated events
    """
    if not events:
        return []

    demisto.debug(f"Deduplicating {len(events)} events against {len(last_run_ids)} previous IDs")
    # Convert last_run_ids to a set for faster lookup
    seen_ids = set(last_run_ids)
    deduplicated = []

    for event in events:
        event_id = event.get("id")
        if event_id and event_id not in seen_ids:
            deduplicated.append(event)
            seen_ids.add(event_id)

    demisto.debug(f"Deduplication complete: {len(deduplicated)} unique events")
    return deduplicated


def add_fields_to_events(events: List[Dict] | None, source_log_type: str) -> None:
    """
    Adds required fields to events for ingestion.

    Adds _time and _source_log_type fields to each event.
    The _time field is formatted according to DATE_FORMAT constant.
    The _source_log_type is set using the provided source_log_type parameter.

    Args:
        events: List of event dictionaries. Can be None or empty list.
        source_log_type: The source log type string (e.g., "BehaviorAnalytics").

    Note:
        - Modifies events in-place
        - update_time is expected to be in milliseconds
        - Events without update_time field are skipped for _time
        - _source_log_type is set directly from the source_log_type parameter
    """
    if not events:
        return

    for event in events:
        # Add _time field
        update_time = event.get("update_time")
        if update_time and isinstance(update_time, (int, float)):
            try:
                # update_time is in milliseconds, convert to seconds for datetime
                event_datetime = datetime.fromtimestamp(update_time / 1000, tz=timezone.utc)
                event["_time"] = event_datetime.strftime(DATE_FORMAT)
            except (ValueError, OSError) as e:
                demisto.debug(f"Failed to convert update_time {update_time} to datetime: {str(e)}")

        # Add _source_log_type field
        event["_source_log_type"] = source_log_type


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
        if event_type == BEHAVIOR_ANALYTICS:
            if not (client.token and client.secret):
                missing_creds.append(f"{event_type} requires Token and Secret credentials")
        elif event_type in [ADDRESSABLE_ALERTS, DETECT_AND_PROTECT_ALERTS]:
            if not (client.username and client.password):
                missing_creds.append(f"{event_type} requires Username and Password credentials")

    if missing_creds:
        error_msg = "Missing required credentials:\n" + "\n".join(f"- {msg}" for msg in missing_creds)
        demisto.debug(f"Credential validation failed: {error_msg}")
        raise DemistoException(error_msg)

    demisto.debug("Credential validation successful")


# Mapping of event types to their fetch methods
EVENT_TYPE_FETCH_METHODS = {
    BEHAVIOR_ANALYTICS: lambda client, start, end, page_size: client.get_behavior_analytics_alerts(
        start_date=start, end_date=end, page_size=page_size
    ),
    ADDRESSABLE_ALERTS: lambda client, start, end, page_size: client.get_addressable_alerts(
        start_date=start, end_date=end, page_size=page_size
    ),
    DETECT_AND_PROTECT_ALERTS: lambda client, start, end, page_size: client.get_detect_and_protect_alerts(
        start_date=start, end_date=end, page_size=page_size
    ),
}


def test_module_command(client: Client, params: dict[str, Any], event_types: List[str]) -> str:
    """
    Tests API connectivity and authentication.
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

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
            fetch_method = EVENT_TYPE_FETCH_METHODS.get(event_type)
            if fetch_method:
                fetch_method(client, start_time, end_time, 1)

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

    This is a manual command for testing/debugging purposes.
    For Behavior Analytics alerts, implements pagination to fetch more than 90 events.

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

    # Calculate time range
    if from_date:
        start_time = int(arg_to_datetime(from_date).timestamp() * 1000)  # type: ignore
    else:
        # Default to 1 hour ago
        start_time = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)

    if to_date:
        end_time = int(arg_to_datetime(to_date).timestamp() * 1000)  # type: ignore
    else:
        # Default to now
        end_time = int(datetime.now().timestamp() * 1000)

    events: List[Dict[str, Any]] = []

    # Fetch events based on type
    if event_type == BEHAVIOR_ANALYTICS:
        # For Behavior Analytics, implement pagination due to 90 page_size limit
        events = _fetch_behavior_analytics_with_pagination(client, start_time, end_time, limit)
    else:
        # For other event types, use the fetch method from the mapping
        fetch_method = EVENT_TYPE_FETCH_METHODS.get(event_type)
        if not fetch_method:
            demisto.debug(f"Unknown event type: {event_type}")
            return [], CommandResults(readable_output=f"Unknown event type: {event_type}")
        events = fetch_method(client, start_time, end_time, limit)

    source_log_type = EVENT_TYPES.get(event_type, EVENT_TYPES[BEHAVIOR_ANALYTICS])

    demisto.debug(f"Retrieved {len(events)} total events for {event_type}")
    hr = tableToMarkdown(name=f"iManage Threat Manager {event_type}", t=events[:10], removeNull=True)
    return events, CommandResults(readable_output=hr)


def _fetch_behavior_analytics_with_pagination(client: Client, start_time: int, end_time: int, limit: int) -> List[Dict[str, Any]]:
    """
    Fetch Behavior Analytics alerts with pagination support.

    Args:
        client: iManage Threat Manager client instance.
        start_time: Start timestamp in milliseconds.
        end_time: End timestamp in milliseconds.
        limit: Maximum number of events to fetch.

    Returns:
        List of fetched events.
    """
    demisto.debug(f"Fetching Behavior Analytics with pagination (limit={limit}, page_size={MAX_PAGE_SIZE})")
    events: List[Dict[str, Any]] = []
    current_start_time = start_time

    while len(events) < limit:
        # Calculate how many more events we need
        remaining = limit - len(events)
        page_size = min(remaining, MAX_PAGE_SIZE)

        demisto.debug(f"Fetching page: start_time={current_start_time}, page_size={page_size}, total_so_far={len(events)}")

        batch = client.get_behavior_analytics_alerts(start_date=current_start_time, end_date=end_time, page_size=page_size)

        if not batch:
            demisto.debug("No more events available, stopping pagination")
            break

        events.extend(batch)
        demisto.debug(f"Fetched {len(batch)} events in this batch, total now: {len(events)}")

        # If we got fewer events than requested, we've reached the end
        if len(batch) < page_size:
            demisto.debug(f"Received {len(batch)} events (less than page_size {page_size}), no more events available")
            break

        # Update start_time to the oldest event in this batch (last one, since sorted newest first)
        # Add 1ms to avoid fetching the same event again
        oldest_event_time = batch[-1].get("update_time")
        if oldest_event_time:
            current_start_time = oldest_event_time + 1
            demisto.debug(f"Updated start_time to {current_start_time} for next page")
        else:
            demisto.debug("No update_time in last event, stopping pagination")
            break

    return events


def _fetch_events_for_type(
    client: Client,
    event_type: str,
    last_fetch_time: int,
    current_time: int,
    max_events_per_type: int,
) -> List[Dict[str, Any]]:
    """
    Fetch events for a specific event type.

    Args:
        client: iManage Threat Manager client instance.
        event_type: Type of events to fetch.
        last_fetch_time: Last fetch timestamp in milliseconds.
        current_time: Current timestamp in milliseconds.
        max_events_per_type: Maximum number of events to fetch.

    Returns:
        List of fetched events.
    """
    if event_type == BEHAVIOR_ANALYTICS:
        # For Behavior Analytics, respect the page_size limit
        page_size = min(max_events_per_type, MAX_PAGE_SIZE)
        return client.get_behavior_analytics_alerts(start_date=last_fetch_time, end_date=current_time, page_size=page_size)

    fetch_method = EVENT_TYPE_FETCH_METHODS.get(event_type)
    if fetch_method:
        return fetch_method(client, last_fetch_time, current_time, max_events_per_type)

    return []


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
        source_log_type = EVENT_TYPES.get(event_type, EVENT_TYPES[BEHAVIOR_ANALYTICS])
        
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
            # Fetch events for this type
            events = _fetch_events_for_type(client, event_type, last_fetch_time, current_time, max_events_per_type)

            demisto.debug(f"Fetched {len(events)} events for {event_type} (before deduplication)")

            # Deduplicate events based on IDs from last run
            events = deduplicate_events(events, last_run_ids)
            demisto.debug(f"After deduplication: {len(events)} events for {event_type}")

            # Add fields to events before extending
            add_fields_to_events(events, source_log_type)

            all_events.extend(events)

            # Update next run for this event type
            if events:
                # Since events are sorted newest first (sort_order=-1),
                # the first event has the latest update_time
                latest_time = events[0].get("update_time", last_fetch_time)
                next_run[last_fetch_key] = latest_time

                # Store IDs of events with the latest update_time for deduplication
                # Only iterate until we hit a different timestamp (optimization)
                latest_time_event_ids = []
                for event in events:
                    event_time = event.get("update_time")
                    if event_time == latest_time:
                        event_id = event.get("id")
                        if event_id:
                            latest_time_event_ids.append(event_id)
                    elif event_time and event_time < latest_time:
                        # Events are sorted newest first, so we can stop here
                        break

                next_run[last_ids_key] = latest_time_event_ids
                demisto.debug(f"Stored {len(latest_time_event_ids)} event IDs with update_time {latest_time}")
            else:
                # No new events, keep the current timestamp and clear IDs
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

    Handles all integration commands:
    - test-module: Tests connectivity and authentication
    - imanage-threat-manager-get-events: Manual event retrieval
    - fetch-events: Automated event collection for XSIAM
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # Parse connection parameters
    base_url = params.get("url", "").rstrip("/")
    if not base_url:
        return_error("Server URL is required")
        return

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Parse authentication parameters
    credentials_user = params.get("credentials_user", {})
    username = credentials_user.get("identifier") if isinstance(credentials_user, dict) else None
    password = credentials_user.get("password") if isinstance(credentials_user, dict) else None

    credentials_token = params.get("credentials_token", {})
    token = credentials_token.get("identifier") if isinstance(credentials_token, dict) else None
    secret = credentials_token.get("password") if isinstance(credentials_token, dict) else None

    # Parse fetch parameters
    event_types = argToList(params.get("event_types", [BEHAVIOR_ANALYTICS]))
    if not event_types:
        event_types = [BEHAVIOR_ANALYTICS]

    max_events_per_type = arg_to_number(params.get("max_events_per_type", MAX_EVENTS_PER_FETCH)) or MAX_EVENTS_PER_FETCH
    max_events_per_type = min(max_events_per_type, MAX_EVENTS_PER_FETCH)  # Enforce maximum

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
            # This is the call made when pressing the integration Test button.
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
                source_log_type_param = EVENT_TYPES.get(event_type, EVENT_TYPES[BEHAVIOR_ANALYTICS])

                add_fields_to_events(events, source_log_type_param)
                demisto.debug(f"Sending {len(events)} events to XSIAM.")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
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

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
