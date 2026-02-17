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
) -> tuple[list[dict], dict]:
    """Fetches events for a specific log type.

    Args:
        client: The Halcyon client.
        log_type: The LogType to fetch.
        last_run: The last run dictionary.
        max_fetch: Maximum number of events to fetch.

    Returns:
        A tuple of (events, updated_last_run).
    """
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

    for log_type in log_types:
        demisto.debug(f"Fetching {log_type.type_string} with max_fetch={max_fetch}")

        events, last_run = fetch_events_for_log_type(
            client=client,
            log_type=log_type,
            last_run=last_run,
            max_fetch=max_fetch,
        )

        demisto.debug(f"Fetched {len(events)} {log_type.type_string}")
        all_events.extend(events)

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
            demisto.debug(f"Starting fetch with last_run: {last_run}")

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
                demisto.debug(f"Setting new last_run: {next_run}")
                demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
