import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
from datetime import datetime, timezone, timedelta

urllib3.disable_warnings()

# Constants
DATE_FORMAT = "%Y%m%d%H%M%S"
API_DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
VENDOR = "vercara"
PRODUCT = "ultradns"
MAX_EVENTS_PER_FETCH = 2500
PAGINATION_LIMIT = 250
DEFAULT_GET_EVENTS_LIMIT = 50
TOKEN_ENDPOINT = "/authorization/token"
AUDIT_LOG_ENDPOINT = "/reports/dns_configuration/audit"


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

        if self.access_token:
            demisto.debug("Found existing access token in context")
        else:
            demisto.debug("No existing access token found, will obtain new token when needed")

    def get_access_token(self) -> str:
        """Get valid access token, refreshing if needed.

        Returns:
            str: Valid access token for API authentication
        """
        if self._is_token_valid():
            return self.access_token

        if self.refresh_token:
            try:
                # Try refreshing the token first
                return self._request_access_token("refresh_token", refresh_token=self.refresh_token)
            except Exception as e:
                demisto.debug(f"Token refresh failed: {e}, obtaining new token")

        # If refresh token is not available or refresh fails, obtain a new token
        return self._request_access_token("password", username=self.username, password=self.password)

    def _is_token_valid(self) -> bool:
        """Check if current access token is valid.

        Returns:
            bool: True if token is valid and not expired, False otherwise
        """
        if not self.access_token or not self.token_expires_in or not self.token_obtained_time:
            demisto.debug("Token validation failed: missing token, expiration, or obtained time")
            return False

        token_expiry = self.token_obtained_time.timestamp() + self.token_expires_in - 60
        current_time = datetime.now().timestamp()
        is_valid = current_time < token_expiry

        if is_valid:
            remaining_seconds = int(token_expiry - current_time)
            demisto.debug(f"Token is valid, expires in {remaining_seconds}s")
        else:
            demisto.debug("Token has expired, will refresh or obtain new token")

        return is_valid

    def _request_access_token(self, grant_type: str, **token_data) -> str:
        """Request new access token or refresh existing token via OAuth endpoint.
        
        Handles both scenarios:
        - Getting a new token using username/password (password grant)
        - Refreshing an existing token using refresh_token (refresh_token grant)

        Args:
            grant_type: OAuth grant type ('password' for new token, 'refresh_token' for refresh)
            **token_data: Grant-specific parameters:
                - For 'password': username, password
                - For 'refresh_token': refresh_token

        Returns:
            str: Valid access token from OAuth response

        Raises:
            DemistoException: If token request or refresh fails
        """
        action = "Obtaining new" if grant_type == "password" else "Refreshing"
        demisto.debug(f"{action} access token")

        data = {"grant_type": grant_type, **token_data}

        response = self._http_request(
            method="POST", url_suffix=TOKEN_ENDPOINT, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        self.access_token = response.get("accessToken")
        if "refreshToken" in response:
            self.refresh_token = response.get("refreshToken")
            if grant_type == "refresh_token":
                demisto.debug("Received new refresh token")
        self.token_expires_in = int(response.get("expiresIn", 3600))
        self.token_obtained_time = datetime.now()

        if not self.access_token:
            error_msg = "Failed to obtain access token" if grant_type == "password" else "Failed to refresh access token"
            demisto.error("OAuth response missing access token")
            raise DemistoException(error_msg)

        action_past = "obtained new" if grant_type == "password" else "refreshed"
        demisto.debug(f"Successfully {action_past} access token, expires in {self.token_expires_in}s")
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
        demisto.debug(f"Saved tokens, expires in {self.token_expires_in}s")

    def get_audit_logs(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        limit: int = PAGINATION_LIMIT,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Fetch audit logs from UltraDNS API.

        Args:
            start_time: Start time for audit log query (datetime object)
            end_time: End time for audit log query (defaults to now if None)
            limit: Maximum number of records to fetch (default: PAGINATION_LIMIT)
            cursor: Pagination cursor for next page (optional)

        Returns:
            dict[str, Any]: API response containing auditRecords and pagination info

        Raises:
            DemistoException: If JSON parsing fails
        """
        if not end_time:
            end_time = datetime.now(timezone.utc)

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
        demisto.debug(
            f"Requesting audit logs from UltraDNS API - Date range: {date_range}, limit: {actual_limit}, cursor info: {cursor_info}"
        )

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
            headers: HTTP response headers dictionary

        Returns:
            dict[str, Any]: Pagination information including next_cursor, limit, and results
        """
        pagination_info = {}

        link_header = headers.get("Link", "")
        if link_header and 'rel="next"' in link_header:
            import re

            cursor_match = re.search(r"cursor=([^&>]+)", link_header)
            if cursor_match:
                pagination_info["next_cursor"] = cursor_match.group(1)
                demisto.debug(f"Found next page cursor: {cursor_match.group(1)[:20]}...")
        else:
            demisto.debug("No pagination cursor found - this is the last page")

        pagination_info["limit"] = headers.get("Limit")
        pagination_info["results"] = headers.get("Results")

        if pagination_info.get("results"):
            next_cursor_info = pagination_info.get("next_cursor", "None")
            demisto.debug(
                f"Page results: {pagination_info['results']}, limit: {pagination_info['limit']}, next cursor: {next_cursor_info}"
            )

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
    except ValueError:
        parsed_time = dateparser.parse(time_str)
        if not parsed_time:
            raise DemistoException(f"Failed to parse time string: {time_str}")
        return parsed_time


def _deduplicate_events(
    events: list[dict[str, Any]], processed_event_ids: set[str], cutoff_time: datetime | None
) -> tuple[list[dict[str, Any]], set[str]]:
    """Deduplicate events using composite ID and cutoff time.

    Args:
        events: List of processed events to deduplicate
        processed_event_ids: Set of previously processed event IDs
        cutoff_time: Cutoff time for deduplication (events before this are not checked)

    Returns:
        tuple[list[dict[str, Any]], set[str]]: Deduplicated events and new event IDs
    """
    filtered_events = []
    new_event_ids = set()
    duplicates_found = 0

    for event in events:
        event_time = event.get("_time")

        if cutoff_time and event_time and event_time >= cutoff_time.timestamp():
            event_id = (
                f"{event.get('changeTime', '')}_{event.get('user', '')}_{event.get('object', '')}"
                f"_{event.get('changeType', '')}"
            )

            if event_id not in processed_event_ids:
                filtered_events.append(event)
                new_event_ids.add(event_id)
            else:
                duplicates_found += 1
        else:
            filtered_events.append(event)

    if duplicates_found > 0:
        demisto.debug(f"Filtered {duplicates_found} duplicate events")

    return filtered_events, new_event_ids


def _cleanup_event_ids(processed_event_ids: set[str], cutoff_time: datetime) -> list[str]:
    """Clean up old event IDs that are outside the retention window.

    Args:
        processed_event_ids: Set of all processed event IDs
        cutoff_time: Time cutoff for retention (6 seconds before latest event)

    Returns:
        list[str]: List of recent event IDs to keep
    """
    recent_event_ids = []
    invalid_ids = 0

    for event_id in processed_event_ids:
        timestamp_str = event_id.split("_")[0]
        try:
            event_time = convert_time_string(timestamp_str)
            if event_time >= cutoff_time:
                recent_event_ids.append(event_id)
        except Exception:
            recent_event_ids.append(event_id)
            invalid_ids += 1

    if invalid_ids > 0:
        demisto.debug(f"Kept {invalid_ids} event IDs with unparseable timestamps")

    return recent_event_ids


def process_events_for_xsiam(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process events for XSIAM ingestion - adds _time, _vendor, _product fields.

    Args:
        events: List of raw audit events from API

    Returns:
        list[dict[str, Any]]: Processed events with XSIAM required fields
    """
    demisto.debug(f"Processing {len(events)} events for XSIAM ingestion")
    processed_events = []

    for event in events:
        if "changeTime" in event:
            try:
                datetime_obj = convert_time_string(event["changeTime"])
                event["_time"] = datetime_obj.timestamp()
            except Exception as e:
                demisto.debug(f"Failed to convert changeTime '{event.get('changeTime')}': {e}")
        event["_vendor"] = VENDOR
        event["_product"] = PRODUCT
        processed_events.append(event)

    demisto.debug(f"Successfully processed {len(processed_events)} events for XSIAM")
    return processed_events


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Test API connectivity and authentication.

    Args:
        client: UltraDNS client instance
        params: Integration parameters dictionary

    Returns:
        str: 'ok' if successful, error message if failed
    """
    demisto.debug("Starting test-module validation")
    try:
        demisto.debug("Testing OAuth authentication...")
        access_token = client.get_access_token()
        if not access_token:
            demisto.error("Test failed: Could not obtain access token")
            return "Authentication failed: Could not obtain access token"

        demisto.debug("Authentication successful, testing API connectivity...")
        end_time = datetime.now(timezone.utc)
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

    Args:
        client: UltraDNS client instance
        args: Command arguments dictionary containing limit, start_time, end_time, should_push_events

    Returns:
        tuple[list[dict], CommandResults]: Events list and CommandResults object

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

    start_time = dateparser.parse(args.get("start_time"))
    if not start_time:
        raise DemistoException(f"Invalid start_time format: {args.get('start_time')}")

    end_time_arg = args.get("end_time")
    if end_time_arg:
        end_time = dateparser.parse(end_time_arg)
        if not end_time:
            raise DemistoException(f"Invalid end_time format: {end_time_arg}")
    else:
        end_time = datetime.now(timezone.utc)

    demisto.debug(f"Fetching events from {start_time} to {end_time}")

    # Implement pagination for get-events command
    all_events = []
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
        demisto.debug("Processing and pushing events to XSIAM")
        processed_events = process_events_for_xsiam(events)
        send_events_to_xsiam(processed_events, vendor=VENDOR, product=PRODUCT)
        command_results.readable_output += f"\n\nSuccessfully sent {len(processed_events)} events to XSIAM."
        demisto.debug(f"Successfully pushed {len(processed_events)} events to XSIAM")
    else:
        demisto.debug("Events displayed only, not pushed to XSIAM")

    return events, command_results


def fetch_events(
    client: Client, last_run: dict[str, Any], max_events_per_fetch: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch audit events with deduplication using 5s lookback window.

    Args:
        client: UltraDNS client instance
        last_run: Previous run state containing last_fetch_time and processed_event_ids
        max_events_per_fetch: Maximum number of events to fetch per cycle

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: Next run state and list of events

    Raises:
        Exception: If event fetching fails
    """
    last_fetch_timestamp = last_run.get("last_fetch_time")
    processed_event_ids = set(last_run.get("processed_event_ids", []))
    last_event_time = None

    if last_fetch_timestamp:
        last_event_time = datetime.fromtimestamp(last_fetch_timestamp, tz=timezone.utc)
        start_time = last_event_time - timedelta(seconds=5)
        demisto.debug(f"Resuming from {last_event_time} (5s lookback), {len(processed_event_ids)} cached IDs")
    else:
        start_time = datetime.now(timezone.utc) - timedelta(hours=3)
        demisto.debug("First fetch: starting 3 hours ago")

    end_time = datetime.now(timezone.utc)
    limit = max_events_per_fetch
    all_events = []
    cursor = None
    latest_event_time = start_time

    try:
        page_count = 0
        while len(all_events) < limit:
            page_count += 1
            remaining_limit = min(limit - len(all_events), PAGINATION_LIMIT)
            demisto.debug(f"Fetching page {page_count}, remaining limit: {remaining_limit}")

            response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=remaining_limit, cursor=cursor)

            events = response.get("auditRecords", [])
            if not events:
                demisto.debug(f"No events returned on page {page_count}, stopping pagination")
                break

            processed_events = process_events_for_xsiam(events)

            # Deduplicate events using the helper function
            cutoff_time = last_event_time - timedelta(seconds=6) if last_event_time else None
            filtered_events, new_event_ids = _deduplicate_events(processed_events, processed_event_ids, cutoff_time)

            processed_event_ids.update(new_event_ids)
            demisto.debug(f"Page {page_count}: {len(filtered_events)} new events after deduplication")

            all_events.extend(filtered_events)
            demisto.debug(f"Total events collected so far: {len(all_events)}")

            cursor = response.get("next_cursor")
            if not cursor:
                demisto.debug(f"No more pages available after page {page_count}")
                break

            demisto.debug(f"Page {page_count} complete, continuing to next page")

    except Exception as e:
        demisto.error(f"Error fetching events: {e}")
        raise

    if all_events:
        last_event = all_events[-1]
        last_event_timestamp = last_event.get("_time")
        if last_event_timestamp:
            latest_event_time = datetime.fromtimestamp(last_event_timestamp, tz=timezone.utc)
            demisto.debug(f"Latest event timestamp: {latest_event_time}")
    else:
        demisto.debug("No events fetched, keeping previous latest_event_time")

    # Clean up old event IDs using the helper function
    cutoff_time = latest_event_time - timedelta(seconds=6)
    recent_event_ids = _cleanup_event_ids(processed_event_ids, cutoff_time)

    next_run = {"last_fetch_time": latest_event_time.timestamp(), "processed_event_ids": recent_event_ids}

    demisto.debug(
        f"Fetch complete: {len(all_events)} events collected, "
        f"cached {len(recent_event_ids)} IDs for deduplication, "
        f"next fetch starts from {latest_event_time}"
    )

    return next_run, all_events


def main() -> None:
    """Main entry point for UltraDNS Event Collector integration.

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
    configured_limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_EVENTS_PER_FETCH
    if configured_limit > MAX_EVENTS_PER_FETCH:
        raise DemistoException(
            f"The maximum number of audit logs per fetch cannot exceed {MAX_EVENTS_PER_FETCH}. Configured: {configured_limit}"
        )
    max_events_per_fetch = configured_limit

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
            demisto.debug(f"Starting fetch-events with max_events_per_fetch={max_events_per_fetch}")
            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=max_events_per_fetch)

            if events:
                demisto.debug(f"Sending {len(events)} events to XSIAM")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.debug("Events successfully sent to XSIAM")
            else:
                demisto.debug("No events to send to XSIAM")

            demisto.setLastRun(next_run)
            demisto.debug("Fetch-events cycle completed successfully")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
