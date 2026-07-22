import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
from datetime import datetime, timedelta

urllib3.disable_warnings()


VENDOR = "vercara"
PRODUCT = "ultradns"
MAX_EVENTS_PER_FETCH = 2500
PAGINATION_LIMIT = 250
DEFAULT_GET_EVENTS_LIMIT = 50
TOKEN_ENDPOINT = "/authorization/token"
AUDIT_LOG_ENDPOINT = "/reports/dns_configuration/audit"
DATE_FORMAT = "%Y%m%d%H%M%S"
API_DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
MARGIN_TOKEN_EXPIRY_SECONDS = 60
MARGIN_FETCH_OVERLAP_SECONDS = 3
MARGIN_DEDUP_SAFETY_SECONDS = 1


class Client(BaseClient):
    """UltraDNS API client with OAuth authentication and audit log fetching."""

    def __init__(self, base_url: str, username: str, password: str, verify: bool = True, proxy: bool = False) -> None:
        """Initialize UltraDNS client with OAuth authentication support.

        Args:
            base_url: Base URL for UltraDNS API (e.g., https://api.ultradns.com)
            username: Username for OAuth authentication
            password: Password for OAuth authentication
            verify: Whether to verify SSL certificates (default: True)
            proxy: Whether to use proxy (default: False)
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.username = username
        self.password = password

        context = demisto.getIntegrationContext()
        self.access_token: str | None = context.get("access_token")
        self.refresh_token: str | None = context.get("refresh_token")
        expires_in = context.get("token_expires_in")
        self.token_expires_in: int | None = int(expires_in) if expires_in is not None else None
        self.token_obtained_time: datetime | None = None
        if context.get("token_obtained_time"):
            self.token_obtained_time = datetime.fromisoformat(context["token_obtained_time"])

    def get_access_token(self) -> str:
        """Get valid access token, refreshing if needed.

        Returns:
            str: Valid access token for API authentication
        """
        if self._is_token_valid():
            demisto.debug("Access token is valid, using existing token")
            return self.access_token  # type: ignore[return-value]

        if self.refresh_token:
            try:
                # Try refreshing the token first
                demisto.debug("Refreshing access token...")
                return self._request_access_token("refresh_token", refresh_token=self.refresh_token)
            except Exception as e:
                demisto.debug(f"Token refresh failed: {e}, obtaining new token")

        # Obtain a new token
        return self._request_access_token("password", username=self.username, password=self.password)

    def _is_token_valid(self) -> bool:
        """Check if current access token is valid.

        Returns:
            bool: True if token is valid and not expired, False otherwise
        """
        if not self.access_token or not self.token_expires_in or not self.token_obtained_time:
            demisto.debug("Token validation failed: missing token, expiration, or obtained time")
            return False

        token_expiry = self.token_obtained_time.timestamp() + self.token_expires_in - MARGIN_TOKEN_EXPIRY_SECONDS
        current_time = datetime.now().timestamp()
        is_valid = current_time < token_expiry

        return is_valid

    def _request_access_token(self, grant_type: str, **token_data) -> str:
        """Request new or refresh existing access token.

        Args:
            grant_type: Type of grant ("password" or "refresh_token")
            **token_data: Additional token data for request (e.g., username, password, or refresh_token)

        Returns:
            str: New access token
        """
        data = {"grant_type": grant_type, **token_data}
        response = self._http_request(
            method="POST", url_suffix=TOKEN_ENDPOINT, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        self.access_token = response.get("accessToken")
        if "refreshToken" in response:
            self.refresh_token = response.get("refreshToken")
        self.token_expires_in = int(response.get("expiresIn", 3600))
        self.token_obtained_time = datetime.now()

        if not self.access_token:
            raise DemistoException("Failed to obtain access token")

        self._save_tokens_to_context()
        return self.access_token

    def _save_tokens_to_context(self) -> None:
        """Save OAuth tokens to integration context.

        Returns:
            None
        """
        context = {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_expires_in": self.token_expires_in,
            "token_obtained_time": self.token_obtained_time.isoformat() if self.token_obtained_time else None,
        }
        demisto.setIntegrationContext(context)
        demisto.debug(f"Saved new token, expires in {self.token_expires_in}s")

    def get_audit_logs(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        limit: int = PAGINATION_LIMIT,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Fetch audit logs from UltraDNS API.

        Note: API returns audit events in reverse chronological order (newest first).

        Args:
            start_time: Start time for audit log query (datetime object)
            end_time: End time for audit log query (defaults is now if None)
            limit: Maximum number of records to fetch (default: PAGINATION_LIMIT)
            cursor: Pagination cursor for next page (optional)

        Returns:
            dict[str, Any]: API response with auditRecords in reverse chronological order

        Raises:
            DemistoException: If JSON parsing fails
        """
        if not end_time:
            end_time = datetime.now()

        start_time_str = start_time.strftime(DATE_FORMAT)
        end_time_str = end_time.strftime(DATE_FORMAT)
        date_range = f"{start_time_str}-{end_time_str}"
        actual_limit = min(limit, PAGINATION_LIMIT)

        params = {"limit": actual_limit, "filter": f"date_range:{date_range}"}

        if cursor:
            params["cursor"] = cursor
            params["cursorOperation"] = "NEXT"

        headers = {"Authorization": f"Bearer {self.get_access_token()}", "Accept": "application/json"}

        cursor_info = f", cursor: {cursor[:20]}..." if cursor else "first page"
        demisto.debug(f"Requesting audit logs - Date range: {date_range}, limit: {actual_limit}, cursor info: {cursor_info}")

        response = self._http_request(
            method="GET", url_suffix=AUDIT_LOG_ENDPOINT, params=params, headers=headers, resp_type="response"
        )

        demisto.debug(f"API response status: {response.status_code}")
        demisto.debug(f"API response headers: {response.headers}")
        pagination_info = self._parse_pagination_headers(response.headers)

        try:
            json_response = response.json()
            events_count = len(json_response.get("auditRecords", []))
            demisto.debug(f"Received {events_count} events from API")
        except ValueError as e:
            demisto.error(f"Failed to parse API response as JSON: {e}")
            raise DemistoException(f"Failed to parse JSON response: {e}")

        json_response.update(pagination_info)
        return json_response

    def _parse_pagination_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        """Parse pagination info from response headers.

        Args:
            headers: Response headers from API

        Returns:
            dict[str, Any]: Pagination info with next_cursor, limit, and results
        """
        import re

        pagination_info = {}

        link_header = headers.get("Link", "")
        if link_header and 'rel="next"' in link_header:
            cursor_match = re.search(r"cursor=([^&>]+)", link_header)
            if cursor_match:
                pagination_info["next_cursor"] = cursor_match.group(1)

        pagination_info["limit"] = headers.get("Limit")
        pagination_info["results"] = headers.get("Results")
        return pagination_info


def convert_time_string(time_str: str) -> datetime:
    """Convert API time string to datetime object.

    Args:
        time_str: Time string from API in format 'YYYY-MM-DD HH:MM:SS.f'

    Returns:
        datetime: Parsed datetime object

    Raises:
        DemistoException: If time string parsing fails
    """
    try:
        return datetime.strptime(time_str, API_DATE_FORMAT)
    except ValueError as e:
        raise DemistoException(f"Failed to parse time string '{time_str}' with expected format '{API_DATE_FORMAT}': {e}")


def _calculate_event_hash(event: dict[str, Any]) -> str:
    """Calculate hash of event for deduplication.

    Args:
        event: Event dictionary to hash

    Returns:
        str: SHA256 hash of the event content
    """
    import hashlib
    import json

    # Create a stable string representation of the event
    # Sort keys to ensure consistent hashing regardless of dict order
    event_str = json.dumps(event, sort_keys=True, default=str)
    return hashlib.sha256(event_str.encode()).hexdigest()


def _deduplicate_events(
    events: list[dict[str, Any]], event_cache: dict[str, str], upper_bound: datetime | None
) -> list[dict[str, Any]]:
    """Deduplicate events using hash-based comparison in boundary zone only.

    Args:
        events: List of processed events in reverse chronological order (newest first)
        event_cache: Cache of previous events {event_hash: timestamp_str}
        upper_bound: Only check duplicates for events <= this time (last_event_time + safety_margin)

    Returns:
        list[dict[str, Any]]: Deduplicated events (maintains original reverse order)
    """
    if not events:
        return []

    filtered_events: list[dict[str, Any]] = []

    # Process events from oldest to newest (iterate backwards through array)
    for i, event in reversed(list(enumerate(events))):
        # Parse event timestamp
        event_time_str = event["changeTime"]
        event_datetime = convert_time_string(event_time_str)

        # If event is newer than upper boundary, add all remaining events and break
        if upper_bound and event_datetime > upper_bound:
            remaining_count = i + 1
            demisto.debug(
                f"Reached boundary at {event_time_str}, adding {remaining_count} remaining newer events without duplicate check"
            )
            filtered_events = events[: i + 1] + filtered_events
            break

        # Event is in boundary zone - check for duplicates
        event_hash = _calculate_event_hash(event)
        if event_hash in event_cache:
            demisto.debug(f"Duplicate detected - time: {event_time_str}, hash: {event_hash[:12]}..., dropping event {event}")
            continue

        # Event is unique
        filtered_events.insert(0, event)
    return filtered_events


def _cache_recent_events(events: list[dict[str, Any]], cache: dict[str, str], cutoff_time: datetime | None) -> None:
    """Cache recent events for future duplicate detection.

    Args:
        events: List of events in reverse chronological order (newest first)
        cache: Cache dictionary to update {event_hash: timestamp_str}
        cutoff_time: Only cache events newer or equal to this time
    """
    if not cutoff_time or not events:
        return

    for event in events:
        event_time_str = event["changeTime"]
        event_datetime = convert_time_string(event_time_str)

        if event_datetime < cutoff_time:
            break  # Events are newest first, so we can stop here

        event_hash = _calculate_event_hash(event)
        cache[event_hash] = event_datetime.strftime("%Y-%m-%dT%H:%M:%S")


def _cleanup_event_cache(event_cache: dict[str, str], cutoff_time: datetime) -> dict[str, str]:
    """Clean up old event cache entries that are outside the retention window.

    Args:
        event_cache: Dictionary with event hash as key and ISO timestamp string as value
        cutoff_time: Time cutoff for retention (overlap + safety margin before latest event)

    Returns:
        dict[str, str]: Cleaned cache with only recent entries
    """
    cleaned_cache = {}
    removed_count = 0
    cutoff_time_str = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S")

    for event_hash, timestamp_str in event_cache.items():
        try:
            if timestamp_str >= cutoff_time_str:
                cleaned_cache[event_hash] = timestamp_str
            else:
                removed_count += 1
        except Exception:
            # Keep entries with invalid timestamps to avoid data loss
            cleaned_cache[event_hash] = timestamp_str

    if removed_count > 0:
        demisto.debug(f"Cleaned {removed_count} old entries from event cache")

    return cleaned_cache


def process_events_for_xsiam(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process events for XSIAM ingestion - adds _time, _vendor, _product fields."""
    demisto.debug(f"Processing {len(events)} events for XSIAM ingestion")

    for event in events:
        datetime_obj = convert_time_string(event["changeTime"])
        event["_time"] = datetime_obj.timestamp()
        event["_vendor"] = VENDOR
        event["_product"] = PRODUCT
    return events


def test_module(client: Client, params: dict) -> str:
    """Test API connectivity and authentication.

    Args:
        client: UltraDNS client instance
        params: Integration parameters

    Returns:
        str: 'ok' if successful, error message if failed
    """
    demisto.debug("Starting test-module validation")

    # Validate max_events_per_fetch parameter in test-module
    configured_limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_EVENTS_PER_FETCH
    if configured_limit > MAX_EVENTS_PER_FETCH:
        raise DemistoException(
            f"The maximum number of audit logs per fetch cannot exceed {MAX_EVENTS_PER_FETCH}. Configured: {configured_limit}"
        )
    try:
        demisto.debug("Testing OAuth authentication...")
        access_token = client.get_access_token()
        if not access_token:
            demisto.error("Test failed: Could not obtain access token")
            return "Authentication failed: Could not obtain access token"

        demisto.debug("Authentication successful, testing API connectivity...")
        end_time = datetime.now()
        start_time = end_time.replace(hour=0, minute=0, second=0, microsecond=0)
        response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=1)

        if "auditRecords" not in response:
            demisto.error("API test failed: Response missing auditRecords field")
            return "API connectivity test failed: Invalid response format"

        event_count = len(response.get("auditRecords", []))
        demisto.debug(f"API connectivity test successful, received {event_count} events")
        return "ok"

    except Exception as e:
        demisto.debug(f"Test failed: {e}")
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authentication Error: Please verify your username and password"
        elif "timeout" in str(e).lower():
            return "Connection timeout: Please verify the server URL"
        else:
            return f"Connection failed: {str(e)}"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch UltraDNS audit events.

    Note: UltraDNS API returns events in reverse chronological order (newest first).

    Args:
        client: UltraDNS client instance
        args: Command arguments dictionary containing limit, start_time, end_time, should_push_events

    Returns:
        tuple[list[dict], CommandResults]: Events list (newest first) and CommandResults object

    Raises:
        DemistoException: If limit exceeds maximum or date parsing fails
    """
    demisto.debug(f"Executing get-events command with args: {args}")
    requested_limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    if requested_limit > MAX_EVENTS_PER_FETCH:
        demisto.error(f"Requested limit {requested_limit} exceeds maximum {MAX_EVENTS_PER_FETCH}")
        raise DemistoException(f"Limit cannot exceed {MAX_EVENTS_PER_FETCH}. Requested: {requested_limit}")
    limit = requested_limit

    should_push_events = argToBoolean(args.get("should_push_events", False))

    start_time = dateparser.parse(args.get("start_time") or "")
    if not start_time:
        raise DemistoException(f"Invalid start_time format: {args.get('start_time')}")

    end_time_arg = args.get("end_time")
    if end_time_arg:
        end_time = dateparser.parse(end_time_arg)
        if not end_time:
            raise DemistoException(f"Invalid end_time format: {end_time_arg}")
    else:
        end_time = datetime.now()

    demisto.debug(f"Fetching events from {start_time} to {end_time}")

    all_events: list[dict[str, Any]] = []
    cursor = None
    page_count = 0

    while len(all_events) < limit:
        page_count += 1
        remaining_limit = min(limit - len(all_events), PAGINATION_LIMIT)
        demisto.debug(f"Get-events page {page_count}, requesting {remaining_limit} events")

        response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=remaining_limit, cursor=cursor)
        page_events = response.get("auditRecords", [])

        if not page_events:
            demisto.debug(f"No more events on page {page_count}, stopping")
            break

        all_events.extend(page_events)
        cursor = response.get("next_cursor")

        if not cursor:
            demisto.debug(f"No more pages after page {page_count}")
            break

    events = all_events
    demisto.debug(f"Get-events retrieved a total of {len(events)} events across {page_count} pages")

    hr = tableToMarkdown(
        name="Vercara UltraDNS Audit Events",
        t=events,
        removeNull=True,
    )

    command_results = CommandResults(readable_output=hr, outputs_prefix="VercaraUltraDNS.AuditEvents", outputs=events)

    if should_push_events:
        processed_events = process_events_for_xsiam(events)
        send_events_to_xsiam(processed_events, vendor=VENDOR, product=PRODUCT)
        xsiam_msg = f"\n\nSuccessfully sent {len(processed_events)} events to XSIAM."
        command_results.readable_output = (command_results.readable_output or "") + xsiam_msg
        demisto.debug(f"Successfully pushed {len(processed_events)} events to XSIAM")
    else:
        demisto.debug("Events displayed only, not pushed to XSIAM")

    return events, command_results


def fetch_events(
    client: Client, last_run: dict[str, Any], max_events_per_fetch: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch audit events with deduplication using hash-based approach.

    Note: UltraDNS API returns events in reverse chronological order (newest first).

    Args:
        client: UltraDNS client instance
        last_run: Previous run state containing last_fetch_time and event_cache
        max_events_per_fetch: Maximum number of events to fetch per cycle

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: Next run state and events (newest first)

    Raises:
        Exception: If event fetching fails
    """
    demisto.debug(f"Starting fetch with last_run: {last_run}")
    last_fetch_time_str = last_run.get("last_fetch_time")
    event_cache = last_run.get("event_cache", {})
    # Determine fetch time window
    if last_fetch_time_str:
        last_event_time = datetime.fromisoformat(last_fetch_time_str)
        # Since the api can filter only by seconds (not milliseconds),
        # we need to add a small overlap to ensure we don't miss any events
        start_time = last_event_time - timedelta(seconds=MARGIN_FETCH_OVERLAP_SECONDS)
        demisto.debug(
            f"Starting fetch from {last_event_time} with adding {MARGIN_FETCH_OVERLAP_SECONDS}s overlap, "
            f"{len(event_cache)} cached events"
        )
    else:
        last_event_time = None
        start_time = datetime.now() - timedelta(hours=3)
        demisto.debug("First fetch: collecting events from last 3 hours")

    end_time = datetime.now()

    # Initialize pagination variables
    raw_events: list[dict[str, Any]] = []
    cursor = None
    page_count = 0
    latest_event_time = last_event_time  # Will be updated with newest event from this fetch

    while len(raw_events) < max_events_per_fetch:
        page_count += 1
        remaining_limit = min(max_events_per_fetch - len(raw_events), PAGINATION_LIMIT)

        response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=remaining_limit, cursor=cursor)

        events = response.get("auditRecords", [])
        if not events:
            demisto.debug(f"No events returned on page {page_count}, stopping pagination")
            break

        demisto.debug(f"Page {page_count}: collected {len(events)} raw events")
        raw_events.extend(events)
        cursor = response.get("next_cursor")
        if not cursor:
            break

    demisto.debug(f"Pagination complete: collected {len(raw_events)} total raw events from {page_count} pages")

    unique_events = []
    if raw_events:
        # Remove duplicates only in boundary zone where overlaps can occur
        duplication_upper_bound = last_event_time + timedelta(seconds=MARGIN_DEDUP_SAFETY_SECONDS) if last_event_time else None
        unique_events = _deduplicate_events(raw_events, event_cache, duplication_upper_bound)

    # Process unique events (update time, cache, and format for XSIAM)
    if unique_events:
        # Update latest event time
        newest_event = unique_events[0]
        latest_event_time = convert_time_string(newest_event["changeTime"])
        demisto.debug(f"Latest event timestamp: {latest_event_time}")

        # Cache recent events and cleanup old cache entries using same cutoff
        cache_cutoff_time = latest_event_time - timedelta(seconds=MARGIN_FETCH_OVERLAP_SECONDS + MARGIN_DEDUP_SAFETY_SECONDS)
        _cache_recent_events(unique_events, event_cache, cache_cutoff_time)
        cleaned_cache = _cleanup_event_cache(event_cache, cache_cutoff_time)
        next_run_state = {"last_fetch_time": latest_event_time.strftime("%Y-%m-%dT%H:%M:%S"), "event_cache": cleaned_cache}

        unique_events = process_events_for_xsiam(unique_events)

        # Summary for events processed
        total_processed = len(raw_events)
        duplicates_filtered = total_processed - len(unique_events)
        demisto.debug(
            f"Fetch complete: {len(unique_events)} unique events from {total_processed} total "
            f"(filtered {duplicates_filtered} duplicates), next fetch from {latest_event_time}"
        )
    else:
        demisto.debug("No new events fetched, keeping last run unchanged")
        next_run_state = last_run

    return next_run_state, unique_events


def main() -> None:
    """Main entry point for UltraDNS integration.

    Returns:
        None

    Raises:
        Exception: If command execution fails, handled by return_error
    """

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get("url", "").rstrip("/")
    username = params.get("credentials", {}).get("identifier") or params.get("username", "")
    password = params.get("credentials", {}).get("password") or params.get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    # Handle max_events_per_fetch with graceful fallback
    configured_limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_EVENTS_PER_FETCH
    if configured_limit > MAX_EVENTS_PER_FETCH:
        demisto.info(
            f"Requested limit {configured_limit} exceeds maximum {MAX_EVENTS_PER_FETCH}. Using {MAX_EVENTS_PER_FETCH} instead."
        )
    max_events_per_fetch = min(configured_limit, MAX_EVENTS_PER_FETCH)

    try:
        client = Client(base_url=base_url, username=username, password=password, verify=verify_certificate, proxy=proxy)
        demisto.debug(f"Client initialized, executing command: {command}")

        if command == "test-module":
            result = test_module(client, params)
            return_results(result)

        elif command == "vercara-ultradns-get-events":
            events, results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=max_events_per_fetch)

            if events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.debug(f"Successfully sent {len(events)} events to XSIAM")
            else:
                demisto.debug("No events to send to XSIAM")

            demisto.setLastRun(next_run)
            demisto.debug("Fetch-events cycle completed successfully, set last run: ", next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
