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
        """Get valid access token, refreshing if needed."""
        if self._is_token_valid():
            return self.access_token

        if self.refresh_token:
            try:
                return self._refresh_access_token()
            except Exception as e:
                demisto.debug(f"Token refresh failed: {e}, obtaining new token")

        return self._get_new_access_token()

    def _is_token_valid(self) -> bool:
        """Check if current access token is valid."""
        if not self.access_token or not self.token_expires_in or not self.token_obtained_time:
            return False

        token_expiry = self.token_obtained_time.timestamp() + self.token_expires_in - 60
        return datetime.now().timestamp() < token_expiry

    def _get_new_access_token(self) -> str:
        """Obtain new access token using username/password grant."""
        demisto.debug("Obtaining new access token")

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

        self._save_tokens_to_context()
        return self.access_token

    def _refresh_access_token(self) -> str:
        """Refresh access token using refresh token."""
        demisto.debug("Refreshing access token")

        data = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}

        response = self._http_request(
            method="POST", url_suffix=TOKEN_ENDPOINT, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        self.access_token = response.get("accessToken")
        if "refreshToken" in response:
            self.refresh_token = response.get("refreshToken")
        self.token_expires_in = int(response.get("expiresIn", 3600))
        self.token_obtained_time = datetime.now()

        if not self.access_token:
            raise DemistoException("Failed to refresh access token")

        self._save_tokens_to_context()
        return self.access_token

    def _save_tokens_to_context(self) -> None:
        """Save OAuth tokens to integration context."""
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
        """Fetch audit logs from UltraDNS API."""
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

        demisto.debug(f"Fetching logs: {date_range}, limit: {actual_limit}")

        response = self._http_request(
            method="GET", url_suffix=AUDIT_LOG_ENDPOINT, params=params, headers=headers, resp_type="response"
        )

        pagination_info = self._parse_pagination_headers(response.headers)

        try:
            json_response = response.json()
        except ValueError as e:
            raise DemistoException(f"Failed to parse JSON response: {e}")

        json_response.update(pagination_info)
        return json_response

    def _parse_pagination_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        """Parse pagination info from response headers."""
        pagination_info = {}

        link_header = headers.get("Link", "")
        if link_header and 'rel="next"' in link_header:
            import re
            cursor_match = re.search(r"cursor=([^&>]+)", link_header)
            if cursor_match:
                pagination_info["next_cursor"] = cursor_match.group(1)
                demisto.debug(f"Found next page cursor: {cursor_match.group(1)[:20]}...")

        pagination_info["limit"] = headers.get("Limit")
        pagination_info["results"] = headers.get("Results")
        
        if pagination_info.get("results"):
            demisto.debug(f"Page results: {pagination_info['results']}, limit: {pagination_info['limit']}")

        return pagination_info


def convert_time_string(time_str: str) -> datetime:
    """Convert API time string to datetime object."""
    try:
        return datetime.strptime(time_str, API_DATE_FORMAT)
    except ValueError:
        parsed_time = dateparser.parse(time_str)
        if not parsed_time:
            raise DemistoException(f"Failed to parse time string: {time_str}")
        return parsed_time


def process_events_for_xsiam(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process events for XSIAM ingestion - adds _time, _vendor, _product fields."""
    processed_events = []

    for event in events:
        if "changeTime" in event:
            datetime_obj = convert_time_string(event["changeTime"])
            event["_time"] = datetime_obj.timestamp()
        event["_vendor"] = VENDOR
        event["_product"] = PRODUCT

        processed_events.append(event)

    return processed_events


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Test API connectivity and authentication."""
    try:
        access_token = client.get_access_token()
        if not access_token:
            return "Authentication failed: Could not obtain access token"

        end_time = datetime.now(timezone.utc)
        start_time = end_time.replace(hour=0, minute=0, second=0, microsecond=0)
        response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=1)

        if "auditRecords" not in response:
            return "API connectivity test failed: Invalid response format"

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
    """Manual command to fetch UltraDNS audit events."""
    requested_limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    if requested_limit > MAX_EVENTS_PER_FETCH:
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

    response = client.get_audit_logs(start_time=start_time, end_time=end_time, limit=limit)
    events = response.get("auditRecords", [])
    hr = tableToMarkdown(
        name="Vercara UltraDNS Audit Events",
        t=events,
        removeNull=True,
    )

    command_results = CommandResults(readable_output=hr, outputs_prefix="VercaraUltraDNS.AuditEvents", outputs=events)

    if should_push_events:
        processed_events = process_events_for_xsiam(events)
        send_events_to_xsiam(processed_events, vendor=VENDOR, product=PRODUCT)
        command_results.readable_output += f"\n\nSuccessfully sent {len(processed_events)} events to XSIAM."

    return events, command_results


def fetch_events(
    client: Client, last_run: dict[str, Any], max_events_per_fetch: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch audit events with deduplication using 5s lookback window."""
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
    limit = min(max_events_per_fetch, MAX_EVENTS_PER_FETCH)
    all_events = []
    cursor = None
    latest_event_time = start_time

    try:
        while len(all_events) < limit:
            response = client.get_audit_logs(
                start_time=start_time, end_time=end_time, limit=min(limit - len(all_events), PAGINATION_LIMIT), cursor=cursor
            )

            events = response.get("auditRecords", [])
            if not events:
                break

            processed_events = process_events_for_xsiam(events)
            
            cutoff_time = last_event_time - timedelta(seconds=6) if last_event_time else None
            filtered_events = []
            new_event_ids = set()
            
            for event in processed_events:
                event_time = event.get("_time")
                
                if cutoff_time and event_time and event_time >= cutoff_time.timestamp():
                    event_id = (f"{event.get('changeTime', '')}_{event.get('user', '')}_{event.get('object', '')}"
                               f"_{event.get('changeType', '')}")
                    
                    if event_id not in processed_event_ids:
                        filtered_events.append(event)
                        new_event_ids.add(event_id)
                else:
                    filtered_events.append(event)
            
            processed_events = filtered_events
            processed_event_ids.update(new_event_ids)
            demisto.debug(f"Deduplicated: {len(processed_events)} new, {len(new_event_ids)} unique IDs")
            
            all_events.extend(processed_events)
            all_events.sort(key=lambda x: x.get('_time', 0))

            cursor = response.get("next_cursor")
            if not cursor:
                break

            demisto.debug(f"Fetched {len(events)} events, continuing with next page")

    except Exception as e:
        demisto.error(f"Error fetching events: {e}")
        raise

    if all_events:
        last_event = all_events[-1]
        last_event_timestamp = last_event.get("_time")
        if last_event_timestamp:
            latest_event_time = datetime.fromtimestamp(last_event_timestamp, tz=timezone.utc)

    cutoff_time = latest_event_time - timedelta(seconds=6)
    recent_event_ids = []
    
    for event_id in processed_event_ids:
        timestamp_str = event_id.split('_')[0]
        try:
            event_time = convert_time_string(timestamp_str)
            if event_time >= cutoff_time:
                recent_event_ids.append(event_id)
        except Exception:
            recent_event_ids.append(event_id)
    
    next_run = {
        "last_fetch_time": latest_event_time.timestamp(),
        "processed_event_ids": recent_event_ids
    }
    
    demisto.debug(f"Fetched {len(all_events)} events, cached {len(recent_event_ids)} IDs for next run")

    return next_run, all_events


def main() -> None:
    """Main entry point for UltraDNS Event Collector integration."""

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
        raise DemistoException(f"The maximum number of audit logs per fetch cannot exceed {MAX_EVENTS_PER_FETCH}. Configured: {configured_limit}")
    max_events_per_fetch = configured_limit

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
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
