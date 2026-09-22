import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # RFC3339 with millis
VENDOR = "ibm"
PRODUCT = "secrets_manager"
SOURCE_LOG_TYPE = "ibm_secrets_manager_audit"

DEFAULT_IAM_URL = "https://iam.cloud.ibm.com"
DEFAULT_PAGE_SIZE = 50000  # max results per /v1/query call
# Base query scoping to Secrets Manager audit events
DEFAULT_QUERY = 'source logs | filter applicationname == "secrets-manager"'
DEFAULT_FIRST_FETCH = "1 hour"
# per-cycle cap = page_size x MAX_CALLS_PER_FETCH (e.g. 50000 x 10 = 500000)
MAX_CALLS_PER_FETCH = 10
TOKEN_EXPIRY_SAFETY_WINDOW = 60  # seconds; refresh token proactively before it expires
DEFAULT_TOKEN_TTL = 3600  # fallback token lifetime (~1h) if IAM omits expiry

""" CLIENT CLASS """


class Client(BaseClient):
    """Client for IBM Cloud Logs (audit collection) and IBM Cloud IAM (auth)."""

    def __init__(self, server_url: str, api_key: str, iam_url: str, verify: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.iam_url = iam_url.rstrip("/")

    def get_access_token(self) -> str:
        """Return a valid IAM Bearer token, reusing the cached one until it nears expiry."""
        context = get_integration_context()
        cached_token = context.get("access_token")
        expires_at = context.get("expires_at", 0)
        now = int(time.time())

        if cached_token and now < (expires_at - TOKEN_EXPIRY_SAFETY_WINDOW):
            demisto.debug("[get_access_token] Reusing cached IAM token.")
            return cached_token

        demisto.debug("[get_access_token] Cached token missing/expiring, minting a new one.")
        return self._request_new_token()

    def _request_new_token(self) -> str:
        """Exchange the API key for a new token and cache it in the integration context."""
        demisto.debug(f"[_request_new_token] Requesting IAM token from {self.iam_url}/identity/token.")
        response = self._http_request(
            method="POST",
            full_url=f"{self.iam_url}/identity/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self.api_key,
            },
        )
        access_token = response.get("access_token")
        if not access_token:
            raise DemistoException("Failed to obtain an IAM access token from the provided API key.")

        response_expires_in = arg_to_number(response.get("expires_in"))
        expires_in = response_expires_in or DEFAULT_TOKEN_TTL
        ttl_source = "API response" if response_expires_in else f"fallback (DEFAULT_TOKEN_TTL={DEFAULT_TOKEN_TTL})"
        demisto.debug(f"[_request_new_token] expires_in={expires_in}s (source: {ttl_source}).")
        expires_at = int(time.time()) + expires_in
        set_integration_context({"access_token": access_token, "expires_at": expires_at})
        demisto.debug(f"[_request_new_token] New token cached, expires_at={expires_at}.")
        return access_token

    def query_events(self, query: str, start_date: str, end_date: str, limit: int) -> list[dict]:
        """Run a DataPrime query against POST /v1/query and parse the SSE response."""
        token = self.get_access_token()
        body = {
            "query": f"{query} | limit {limit}",
            "metadata": {"start_date": start_date, "end_date": end_date, "syntax": "dataprime"},
        }
        demisto.debug(f"[query_events] POST /v1/query window=[{start_date}, {end_date}) limit={limit}.")
        raw_response = self._http_request(
            method="POST",
            url_suffix="/v1/query",
            headers={
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            data=json.dumps(body),
            resp_type="text",
        )
        results = parse_sse_results(raw_response)
        demisto.debug(f"[query_events] Parsed {len(results)} results from the SSE stream.")
        _debug_verify_order(results)  # TODO: TEMPORARY - remove _debug_verify_order after confirming API order in testing.
        return results


""" HELPER FUNCTIONS """


def parse_sse_results(raw_response: str) -> list[dict]:
    """Parse a text/event-stream body; results live under result.results in each data frame."""
    events: list[dict] = []
    data_lines: list[str] = []

    def flush() -> None:
        if not data_lines:
            return
        payload = "".join(data_lines)
        data_lines.clear()
        try:
            parsed = json.loads(payload)
        except (ValueError, TypeError):
            demisto.debug(f"[parse_sse_results] Skipping non-JSON frame: {payload[:200]}")
            return
        results = dict_safe_get(parsed, ["result", "results"], default_return_value=[])
        if isinstance(results, list):
            events.extend(res for res in results if isinstance(res, dict))

    for raw_line in raw_response.splitlines():
        line = raw_line.rstrip("\r")
        if line == "":  # blank line ends a frame
            flush()
            continue
        if line.startswith(":"):  # keep-alive comment
            continue
        if line.startswith("data:"):
            data_lines.append(line[len("data:"):].lstrip())
    flush()  # trailing frame not followed by a blank line
    demisto.debug(f"[parse_sse_results] Extracted {len(events)} events.")
    return events


def get_event_timestamp(event: dict) -> str:
    """Return the event's metadata.timestamp (used for _TIME and de-dup), or ''."""
    metadata = event.get("metadata") or {}
    return metadata.get("timestamp", "")


def get_event_id(event: dict) -> str:
    """Return the event's id (falls back to logid), or ''."""
    return event.get("id") or event.get("logid") or ""


def _debug_verify_order(events: list[dict]) -> None:
    # TODO: TEMPORARY - remove this function (and its call in query_events) after confirming API order in testing.
    """TEMPORARY: log whether the batch is timestamp-ordered and in which direction. Remove after testing."""
    timestamps = [get_event_timestamp(event) for event in events]
    if len(timestamps) < 2:
        demisto.debug(f"[_debug_verify_order] Only {len(timestamps)} event(s); order not determinable.")
        return
    ascending = all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1))
    descending = all(timestamps[i] >= timestamps[i + 1] for i in range(len(timestamps) - 1))
    order = "ascending" if ascending else "descending" if descending else "UNORDERED"
    demisto.debug(
        f"[_debug_verify_order] batch order={order}; first_ts={timestamps[0]} last_ts={timestamps[-1]} count={len(timestamps)}."
    )


def add_time_to_events(events: list[dict]) -> None:
    """Enrich events in-place with _time and _source_log_type."""
    demisto.debug(f"[add_time_to_events] Enriching {len(events)} events.")
    for event in events:
        event["_time"] = get_event_timestamp(event)
        event["_source_log_type"] = SOURCE_LOG_TYPE


def dedup_events(events: list[dict], last_ids: set[str], boundary_ts: str) -> tuple[list[dict], set[str], str]:
    """Drop boundary duplicates and return new state.

    Assumes events are timestamp-ascending (oldest first), so boundary duplicates (same ts as last run)
    are only at the head, and the newest events are at the tail. Scans only those ends.
    """
    # Head: skip only the leading run whose timestamp == boundary and whose id was already seen.
    start = 0
    while start < len(events) and get_event_timestamp(events[start]) == boundary_ts:
        if get_event_id(events[start]) in last_ids:
            start += 1
        else:
            break
    new_events = events[start:]

    if not new_events:
        demisto.debug("[dedup_events] All events were boundary duplicates; state unchanged.")
        return [], last_ids, boundary_ts

    # Tail: the newest timestamp is the last event's; collect the trailing run sharing it.
    latest_ts = get_event_timestamp(new_events[-1])
    latest_ids: set[str] = set()
    for event in reversed(new_events):
        if get_event_timestamp(event) != latest_ts:
            break
        latest_ids.add(get_event_id(event))
    demisto.debug(f"[dedup_events] Kept {len(new_events)} events (skipped {start} head dupes); new boundary_ts={latest_ts}.")
    return new_events, latest_ids, latest_ts


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validate connectivity/credentials via a minimal query."""
    demisto.debug("[test_module] Running connectivity check.")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = (now - timedelta(minutes=1)).strftime(DATE_FORMAT)
    end_date = now.strftime(DATE_FORMAT)
    client.query_events(query=DEFAULT_QUERY, start_date=start_date, end_date=end_date, limit=1)
    return "ok"


def fetch_events(client: Client, query: str, page_size: int, last_run: dict) -> tuple[list[dict], dict]:
    """Fetch audit events since last run, paging via time-window slicing (cap = page_size x MAX_CALLS_PER_FETCH)."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    end_date = now.strftime(DATE_FORMAT)

    cursor = last_run.get("last_timestamp")
    if not cursor:
        first_fetch = dateparser.parse(DEFAULT_FIRST_FETCH, settings={"TIMEZONE": "UTC"})
        cursor = first_fetch.strftime(DATE_FORMAT) if first_fetch else end_date
        demisto.debug(f"[fetch_events] First run; starting from {cursor}.")
    seen_ids = set(last_run.get("last_ids", []))

    collected: list[dict] = []
    for call_number in range(1, MAX_CALLS_PER_FETCH + 1):
        demisto.debug(f"[fetch_events] Call {call_number}/{MAX_CALLS_PER_FETCH}, window=[{cursor}, {end_date}).")
        raw_events = client.query_events(query=query, start_date=cursor, end_date=end_date, limit=page_size)

        new_events, seen_ids, cursor = dedup_events(raw_events, seen_ids, cursor)
        collected.extend(new_events)

        if len(raw_events) < page_size:
            demisto.debug(f"[fetch_events] Short page ({len(raw_events)} < {page_size}); stopping.")
            break

    add_time_to_events(collected)
    new_last_run = {"last_timestamp": cursor, "last_ids": list(seen_ids)}
    demisto.debug(f"[fetch_events] Collected {len(collected)} events; new_last_run={new_last_run}.")
    return collected, new_last_run


def get_events_command(client: Client, args: dict) -> tuple[list[dict], CommandResults]:
    """Manually pull events for an optional [start_date, end_date) window (no run state)."""
    limit = arg_to_number(args.get("limit")) or 50

    end_dt = arg_to_datetime(args.get("end_date")) or datetime.now(timezone.utc)
    start_dt = arg_to_datetime(args.get("start_date")) or (end_dt - timedelta(hours=1))
    start_date = start_dt.strftime(DATE_FORMAT)
    end_date = end_dt.strftime(DATE_FORMAT)
    demisto.debug(f"[get_events_command] window=[{start_date}, {end_date}) limit={limit}.")

    raw_events = client.query_events(query=DEFAULT_QUERY, start_date=start_date, end_date=end_date, limit=limit)
    events = raw_events[:limit]
    add_time_to_events(events)

    human_readable = tableToMarkdown(
        name="IBM Secrets Manager Events",
        t=[
            {
                "Timestamp": get_event_timestamp(event),
                "Action": (event.get("userData") or {}).get("action") or event.get("action"),
                "ID": event.get("id") or event.get("logid"),
            }
            for event in events
        ],
        removeNull=True,
    )
    demisto.debug(f"[get_events_command] Returning {len(events)} events.")
    return events, CommandResults(readable_output=human_readable)


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get("url", "").rstrip("/")
    api_key = (params.get("credentials") or {}).get("password") or params.get("api_key")
    iam_url = params.get("iam_url") or DEFAULT_IAM_URL
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    page_size = arg_to_number(params.get("max_events_per_fetch")) or DEFAULT_PAGE_SIZE

    demisto.debug(f"[main] Command being called is {command}.")
    try:
        client = Client(server_url=server_url, api_key=api_key, iam_url=iam_url, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "ibm-secrets-manager-get-events":
            events, command_results = get_events_command(client, args)
            if events and argToBoolean(args.get("should_push_events", False)):
                demisto.debug(f"[main] Pushing {len(events)} events to Cortex from get-events.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"[main] fetch-events last_run={last_run}.")
            events, new_last_run = fetch_events(client, query=DEFAULT_QUERY, page_size=page_size, last_run=last_run)
            if events:
                demisto.debug(f"[main] Sending {len(events)} events to Cortex.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(new_last_run)
            demisto.debug(f"[main] Saved last_run={new_last_run}.")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
