import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
from datetime import datetime, timezone, timedelta

# Disable insecure warnings
urllib3.disable_warnings()

""" CONFIGURATION CONSTANTS """

DATE_FORMAT = "%Y%m%d%H%M%S"  # GMT format: yyyyMMddHHmmss
API_DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"  # Format used by API response
VENDOR = "vercara"
PRODUCT = "ultradns"
MAX_EVENTS_PER_FETCH = 2500  # Default for fetch_events and max for get_events_command
PAGINATION_LIMIT = 250  # API pagination limit per request
DEFAULT_GET_EVENTS_LIMIT = 50  # Default for get_events_command

# API Endpoints
TOKEN_ENDPOINT = "/authorization/token"
AUDIT_LOG_ENDPOINT = "/reports/dns_configuration/audit"

""" API CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the Vercara UltraDNS API

    This Client implements API calls for OAuth authentication and audit log fetching.
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool = True, proxy: bool = False) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.username = username
        self.password = password

        # Load tokens from integration context
        integration_context = demisto.getIntegrationContext()
        self.access_token: str | None = integration_context.get("access_token")
        self.refresh_token: str | None = integration_context.get("refresh_token")
        # Ensure token_expires_in is always an integer
        expires_in = integration_context.get("token_expires_in")
        self.token_expires_in: int | None = int(expires_in) if expires_in is not None else None
        self.token_obtained_time: datetime | None = None
        if integration_context.get("token_obtained_time"):
            self.token_obtained_time = datetime.fromisoformat(integration_context["token_obtained_time"])

    def get_access_token(self) -> str:
        """Get a valid access token, refreshing if necessary.

        Returns:
            str: Valid access token
        """
        if self._is_token_valid():
            return self.access_token

        if self.refresh_token:
            try:
                return self._refresh_access_token()
            except Exception as e:
                demisto.debug(f"Failed to refresh token: {e}. Getting new token.")

        return self._get_new_access_token()

    def _is_token_valid(self) -> bool:
        """Check if the current access token is still valid.

        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.access_token or not self.token_expires_in or not self.token_obtained_time:
            return False

        # Add 60 second buffer to avoid edge cases
        token_expiry = self.token_obtained_time.timestamp() + self.token_expires_in - 60
        return datetime.now().timestamp() < token_expiry

    def _get_new_access_token(self) -> str:
        """Get a new access token using username and password.

        Returns:
            str: New access token
        """
        demisto.debug("Getting new access token")

        data = {"grant_type": "password", "username": self.username, "password": self.password}

        response = self._http_request(
            method="POST", url_suffix=TOKEN_ENDPOINT, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        self.access_token = response.get("accessToken")
        self.refresh_token = response.get("refreshToken")
        self.token_expires_in = int(response.get("expiresIn", 3600))
        self.token_obtained_time = datetime.now()

        if not self.access_token:
            raise DemistoException("Failed to obtain access token")

        # Save tokens to integration context
        self._save_tokens_to_context()

        demisto.debug("Successfully obtained new access token")
        return self.access_token

    def _refresh_access_token(self) -> str:
        """Refresh the access token using the refresh token.

        Returns:
            str: Refreshed access token
        """
        demisto.debug("Refreshing access token")

        data = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}

        response = self._http_request(
            method="POST", url_suffix=TOKEN_ENDPOINT, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        self.access_token = response.get("accessToken")
        # Refresh token might be renewed
        if "refreshToken" in response:
            self.refresh_token = response.get("refreshToken")
        self.token_expires_in = int(response.get("expiresIn", 3600))
        self.token_obtained_time = datetime.now()

        if not self.access_token:
            raise DemistoException("Failed to refresh access token")

        # Save tokens to integration context
        self._save_tokens_to_context()

        demisto.debug("Successfully refreshed access token")
        return self.access_token

    def _save_tokens_to_context(self) -> None:
        """Save OAuth tokens to integration context for persistence between executions."""
        context = {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_expires_in": self.token_expires_in,
            "token_obtained_time": self.token_obtained_time.isoformat() if self.token_obtained_time else None,
        }
        demisto.setIntegrationContext(context)
        demisto.debug(f"Saved OAuth tokens to integration context with expiration in {self.token_expires_in} seconds")

    def get_audit_logs(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        limit: int = PAGINATION_LIMIT,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Fetch audit logs from Vercara UltraDNS API.

        Args:
            start_time (datetime): Start time for fetching logs
            end_time (datetime, optional): End time for fetching logs. Defaults to now.
            limit (int): Maximum number of events to fetch per request
            cursor (str, optional): Pagination cursor for next page

        Returns:
            Dict[str, Any]: API response containing audit logs and pagination info
        """
        if not end_time:
            end_time = datetime.now(timezone.utc)

        # Convert datetime to GMT format required by API
        start_time_str = start_time.strftime(DATE_FORMAT)
        end_time_str = end_time.strftime(DATE_FORMAT)
        date_range = f"{start_time_str}-{end_time_str}"

        # Limit to maximum allowed by API
        actual_limit = min(limit, PAGINATION_LIMIT)

        params = {"limit": actual_limit, "filter": f"date_range:{date_range}"}

        if cursor:
            params["cursor"] = cursor
            params["cursorOperation"] = "NEXT"

        headers = {"Authorization": f"Bearer {self.get_access_token()}", "Accept": "application/json"}

        demisto.debug(f"Fetching audit logs with params: {params}")

        response = self._http_request(
            method="GET", url_suffix=AUDIT_LOG_ENDPOINT, params=params, headers=headers, resp_type="response"
        )

        # Parse pagination info from headers
        pagination_info = self._parse_pagination_headers(response.headers)

        try:
            json_response = response.json()
        except ValueError as e:
            raise DemistoException(f"Failed to parse JSON response: {e}")

        json_response.update(pagination_info)
        return json_response

    def _parse_pagination_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        """Parse pagination information from response headers.

        Args:
            headers (Dict[str, str]): Response headers

        Returns:
            Dict[str, Any]: Pagination information
        """
        pagination_info = {}

        # Parse Link header for next/previous page URLs
        link_header = headers.get("Link", "")
        # Extract cursor from next page link if available
        if link_header and 'rel="next"' in link_header:
            import re

            cursor_match = re.search(r"cursor=([^&>]+)", link_header)
            if cursor_match:
                pagination_info["next_cursor"] = cursor_match.group(1)

        # Get other pagination info from headers
        pagination_info["limit"] = headers.get("Limit")
        pagination_info["results"] = headers.get("Results")

        return pagination_info


""" UTILITY FUNCTIONS """


def convert_time_string(time_str: str) -> datetime:
    """Convert API time string to datetime object.

    Args:
        time_str (str): Time string from API response

    Returns:
        datetime: Converted datetime object
    """
    try:
        # Handle the API date format: "2016-06-12 21:48:02.0"
        return datetime.strptime(time_str, API_DATE_FORMAT)
    except ValueError:
        # Fallback to dateparser for other formats
        parsed_time = dateparser.parse(time_str)
        if not parsed_time:
            raise DemistoException(f"Failed to parse time string: {time_str}")
        return parsed_time


def process_audit_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process raw audit events for XSIAM ingestion.
    
    Converts API response events into XSIAM-compatible format by:
    - Adding _time field from changeTime
    - Adding vendor and product metadata
    - Converting timestamp formats

    Args:
        events: Raw events from UltraDNS API response

    Returns:
        Processed events ready for XSIAM ingestion
    """
    processed_events = []

    for event in events:
        # Set the _time field required by XSIAM (must be Unix timestamp)
        if "changeTime" in event:
            datetime_obj = convert_time_string(event["changeTime"])
            event["_time"] = datetime_obj.timestamp()

        # Add vendor and product information
        event["_vendor"] = VENDOR
        event["_product"] = PRODUCT

        processed_events.append(event)

    return processed_events


""" INTEGRATION COMMANDS """


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Tests API connectivity and authentication.
    
    Performs a complete integration test by:
    1. Testing OAuth authentication (getting access token)
    2. Testing API connectivity (fetching audit logs)
    3. Validating response format

    Args:
        client: Configured UltraDNS API client
        params: Integration configuration parameters

    Returns:
        'ok' if all tests pass, descriptive error message otherwise
    """
    try:
        # Test authentication by getting access token
        access_token = client.get_access_token()
        if not access_token:
            return "Authentication failed: Could not obtain access token"

        # Test API connectivity with a small audit log request
        end_time = datetime.now(timezone.utc)
        start_time = end_time.replace(hour=0, minute=0, second=0, microsecond=0)  # Start of today

        response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=1)

        if "auditRecords" not in response:
            return "API connectivity test failed: Invalid response format"

        return "ok"

    except Exception as e:
        demisto.debug(f"Test module failed: {str(e)}")
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authentication Error: Please verify your username and password"
        elif "timeout" in str(e).lower():
            return "Connection timeout: Please verify the server URL"
        else:
            return f"Connection failed: {str(e)}"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch and display UltraDNS audit events.
    
    Fetches events from the API within specified time range and optionally
    pushes them to XSIAM. Used for testing and manual event retrieval.

    Args:
        client: Configured UltraDNS API client
        args: Command arguments including start_time, end_time, limit, should_push_events

    Returns:
        Tuple of (events_list, command_results) for display in War Room
    """
    limit = min(arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT, MAX_EVENTS_PER_FETCH)

    should_push_events = argToBoolean(args.get("should_push_events", False))

    # Parse required start_time
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

    # Fetch events
    response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=limit)

    events = response.get("auditRecords", [])
    processed_events = process_audit_events(events)

    # Create human readable output
    hr = tableToMarkdown(
        name="Vercara UltraDNS Audit Events",
        t=processed_events,
        removeNull=True,
        headers=["changeTime", "user", "changeType", "object"],
    )

    command_results = CommandResults(readable_output=hr, outputs_prefix="VercaraUltraDNS.AuditEvents", outputs=processed_events)

    if should_push_events:
        # Send events to XSIAM
        send_events_to_xsiam(processed_events, vendor=VENDOR, product=PRODUCT)
        command_results.readable_output += f"\n\n✅ Successfully sent {len(processed_events)} events to XSIAM."

    return processed_events, command_results


def fetch_events(
    client: Client, last_run: dict[str, Any], max_events_per_fetch: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch audit events from UltraDNS API with intelligent deduplication.
    
    Implements a sophisticated event collection strategy:
    
    **Deduplication Strategy:**
    - Uses 5-second lookback window to handle timestamp precision differences
    - Creates composite event IDs from changeTime + user + object + changeType
    - Only deduplicates events within 6-second overlap window for performance
    - Maintains sliding window of recent event IDs in last_run
    
    **Pagination & Sorting:**
    - Supports API pagination with cursor-based navigation
    - Sorts events chronologically to ensure proper ordering
    - Respects API rate limits with configurable batch sizes
    
    **Error Handling:**
    - Graceful handling of authentication token refresh
    - Comprehensive logging for debugging
    - Safe fallbacks for edge cases

    Args:
        client: Authenticated UltraDNS API client
        last_run: Previous execution state with timestamp and processed event IDs
        max_events_per_fetch: Maximum events to collect per execution

    Returns:
        Tuple of (next_run_state, collected_events) for XSIAM ingestion
    """
    demisto.debug("Starting to fetch Vercara UltraDNS audit events")

    # Initialize fetch parameters from last run state
    last_fetch_timestamp = last_run.get("last_fetch_time")
    processed_event_ids = set(last_run.get("processed_event_ids", []))
    last_event_time = None
    
    if last_fetch_timestamp:
        last_event_time = datetime.fromtimestamp(last_fetch_timestamp, tz=timezone.utc)
        # Look back 5 seconds to handle second vs microsecond precision mismatch
        start_time = last_event_time - timedelta(seconds=5)
        demisto.debug(f"Using 5-second look-back from last event time: {last_event_time}")
        demisto.debug(f"Loaded {len(processed_event_ids)} processed event IDs for deduplication")
    else:
        start_time = datetime.now(timezone.utc) - timedelta(hours=3)
        demisto.debug("No last fetch time found, starting from 3 hours ago")

    end_time = datetime.now(timezone.utc)

    # Limit events per fetch
    limit = min(max_events_per_fetch, MAX_EVENTS_PER_FETCH)

    all_events = []
    cursor = None
    latest_event_time = start_time

    try:
        # Fetch events with pagination support
        while len(all_events) < limit:
            response = client.get_audit_logs(
                start_time=start_time, end_time=end_time, limit=min(limit - len(all_events), PAGINATION_LIMIT), cursor=cursor
            )

            events = response.get("auditRecords", [])
            if not events:
                demisto.debug("No more events found")
                break

            # Process events and filter duplicates using composite key deduplication
            processed_events = process_audit_events(events)
            
            # Create composite event IDs and filter duplicates
            # Only check events within 6-second overlap window for deduplication
            cutoff_time = last_event_time - timedelta(seconds=6) if last_event_time else None
            filtered_events = []
            new_event_ids = set()
            
            for event in processed_events:
                event_time = event.get("_time")
                
                # Only deduplicate events within the 6-second overlap window
                # Convert cutoff_time to timestamp for comparison
                if cutoff_time and event_time and event_time >= cutoff_time.timestamp():
                    # Create composite key from multiple fields for better deduplication
                    event_id = (f"{event.get('changeTime', '')}_{event.get('user', '')}_{event.get('object', '')}"
                               f"_{event.get('changeType', '')}")
                    
                    # Only include events we haven't processed before
                    if event_id not in processed_event_ids:
                        filtered_events.append(event)
                        new_event_ids.add(event_id)
                    # else: skip duplicate event
                else:
                    # Event is older than 6-second window, no need to check for duplicates
                    filtered_events.append(event)
            
            processed_events = filtered_events
            processed_event_ids.update(new_event_ids)
            demisto.debug(f"After deduplication: {len(processed_events)} new events, {len(new_event_ids)} new unique IDs")
            
            all_events.extend(processed_events)

            # Sort events by timestamp to ensure chronological order
            all_events.sort(key=lambda x: x.get('_time', 0))

            # Check for next page
            cursor = response.get("next_cursor")
            if not cursor:
                demisto.debug("No more pages available")
                break

            demisto.debug(f"Fetched {len(events)} events, continuing with cursor: {cursor}")

    except Exception as e:
        demisto.error(f"Error fetching events: {str(e)}")
        raise

    # Store the actual latest event time for deduplication
    # We'll use 5 second lookback on next fetch to handle precision mismatch
    if all_events:
        # Events are now sorted chronologically
        last_event = all_events[-1]
        last_event_timestamp = last_event.get("_time")
        if last_event_timestamp:
            # Convert timestamp back to datetime for consistency with start_time logic
            latest_event_time = datetime.fromtimestamp(last_event_timestamp, tz=timezone.utc)

    demisto.debug(f"Total events fetched: {len(all_events)}")

    # Update last run state with sliding window approach
    # Keep only event IDs within 6 seconds of latest timestamp to limit memory usage
    cutoff_time = latest_event_time - timedelta(seconds=6)
    recent_event_ids = []
    
    for event_id in processed_event_ids:
        # Extract timestamp from composite key (first part before first underscore)
        timestamp_str = event_id.split('_')[0]
        try:
            event_time = convert_time_string(timestamp_str)
            if event_time >= cutoff_time:
                recent_event_ids.append(event_id)
        except Exception:
            # Keep event ID if we can't parse timestamp (safety fallback)
            recent_event_ids.append(event_id)
    
    next_run = {
        "last_fetch_time": latest_event_time.timestamp(),
        "processed_event_ids": recent_event_ids
    }
    
    demisto.debug(f"Kept {len(recent_event_ids)} event IDs within 6 seconds of latest timestamp")

    demisto.debug(
        f"Successfully fetched {len(all_events)} audit events. "
        f"Next fetch will start from: {latest_event_time}"
    )

    return next_run, all_events


""" ENTRY POINT """


def main() -> None:
    """Main entry point - parses integration parameters and executes commands.
    
    Handles all integration commands:
    - test-module: Validates configuration and connectivity
    - vercara-ultradns-get-events: Manual event retrieval
    - fetch-events: Automated event collection for XSIAM
    """

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    # Extract integration configuration parameters
    base_url = params.get("url", "").rstrip("/")
    username = params.get("credentials", {}).get("identifier") or params.get("username", "")
    password = params.get("credentials", {}).get("password") or params.get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Configure event collection limits with safety bounds
    configured_limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_EVENTS_PER_FETCH
    max_events_per_fetch = min(configured_limit, MAX_EVENTS_PER_FETCH)

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(base_url=base_url, username=username, password=password, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            result = test_module(client, params)
            return_results(result)

        elif command == "vercara-ultradns-get-events":
            events, results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=max_events_per_fetch)

            # Send events to XSIAM
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" MODULE EXECUTION """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
