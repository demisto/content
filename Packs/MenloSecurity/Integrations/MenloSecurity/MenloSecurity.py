import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *

""" CONSTANTS """

VENDOR = "Menlo"
PRODUCT = "Menlo Security Isolation Platform"

DEFAULT_MAX_EVENTS_PER_FETCH = 5000
MAX_EVENTS_PER_PAGE = 1000  # API default limit per request
DEFAULT_FIRST_FETCH = "3 hours"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Per Menlo docs: Admin-UI-generated tokens use the v2 endpoint; legacy CSV-based tokens use v1.
API_PATH_TEMPLATE = "/api/rep/{api_version}/fetch/client_select"
TOKEN_TYPE_TO_API_VERSION = {"Admin token": "v2", "token": "v1"}
DEFAULT_TOKEN_TYPE = "Admin token"

# Default log types to pre-select in the UI (per design — not all available types).
DEFAULT_LOG_TYPES = ["web", "safemail", "audit", "smtp", "attachment", "dlp"]

# Mapping from UI log type name to API log_type value.
# "safemail" is the UI label used in the official Menlo Python script; the API body uses "email".
# "heat" replaces the deprecated "isoc" log type per the latest Menlo Logging API docs.
LOG_TYPE_MAP: dict[str, str] = {
    "web": "web",
    "safemail": "email",
    "audit": "audit",
    "auth_flows": "auth_flows",
    "smtp": "smtp",
    "attachment": "attachment",
    "bandwidth": "bandwidth",
    "heat": "heat",
    "firewall": "firewall",
    "dlp": "dlp",
    "ms_client_logs": "ms_client_logs",
}

# Maps UI log type name to the source_log_type field added to each enriched event.
SOURCE_LOG_TYPE_MAP: dict[str, str] = {
    "web": "web_logs",
    "safemail": "email_logs",
    "audit": "audit_logs",
    "auth_flows": "auth_flows_logs",
    "smtp": "smtp_logs",
    "attachment": "attachment_logs",
    "bandwidth": "bandwidth_logs",
    "heat": "heat_logs",
    "firewall": "firewall_logs",
    "dlp": "dlp_logs",
    "ms_client_logs": "ms_client_logs",
}

ALL_LOG_TYPES = list(LOG_TYPE_MAP.keys())


""" CLIENT CLASS """


class Client(ContentClient):
    """Menlo Security Logging API client.

    Extends ContentClient for built-in retry, rate-limit handling, and thread safety.
    Authenticates via an API token passed in the POST body of each request.
    """

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool, token_type: str = DEFAULT_TOKEN_TYPE) -> None:
        self._token = token
        # Admin-UI tokens use v2; legacy CSV-based tokens use v1.
        api_version = TOKEN_TYPE_TO_API_VERSION.get(token_type, TOKEN_TYPE_TO_API_VERSION[DEFAULT_TOKEN_TYPE])
        self._api_path = API_PATH_TEMPLATE.format(api_version=api_version)
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            client_name="MenloSecurity",
            ok_codes=(200,),
        )

    def fetch_log_page(
        self,
        log_type: str,
        start: int,
        end: int,
        limit: int = MAX_EVENTS_PER_PAGE,
        paging_identifiers: dict | None = None,
    ) -> dict | list | None:
        """Fetch a single page of logs from the Menlo Security API.

        Args:
            log_type: API log_type value (e.g. "web", "email", "audit").
            start: UTC start time in seconds since epoch.
            end: UTC end time in seconds since epoch.
            limit: Maximum records per page (API default: 1000).
            paging_identifiers: Pagination state from the previous response; None for first page.

        Returns:
            Parsed JSON response (dict per docs, or a list of response wrappers as observed
            on the live v2 endpoint). Returns None when the API returns an empty 200
            (Content-Length: 0), which the docs describe as "no data for this time window".

        Raises:
            ValueError: If the response body is non-empty but not valid JSON (e.g. HTML auth-error pages).
        """
        params = {"start": start, "end": end, "limit": limit, "format": "json"}
        body: dict[str, Any] = {"token": self._token, "log_type": log_type}
        if paging_identifiers:
            body["pagingIdentifiers"] = paging_identifiers

        # Use resp_type="response" to handle empty 200s and non-JSON bodies (e.g. HTML auth errors)
        # explicitly. Per Menlo docs: "The API may occasionally return an empty 200 response when
        # a JSON object is expected... Content-Length: 0."
        response = self.post(url_suffix=self._api_path, params=params, json_data=body, resp_type="response")

        demisto.debug(f"[{log_type}] HTTP {response.status_code}, body-bytes={len(response.content)}")

        # Empty body (Content-Length: 0) means "no data" — not an error.
        if not response.content:
            return None

        try:
            return response.json()
        except json.JSONDecodeError as e:
            snippet = response.text[:500] if response.text else "<empty>"
            raise ValueError(f"Non-JSON response from Menlo API (status {response.status_code}): {snippet}") from e


""" HELPER FUNCTIONS """


def epoch_to_timestamp(epoch_seconds: int) -> str:
    """Convert epoch seconds to ISO 8601 timestamp string."""
    return datetime.fromtimestamp(epoch_seconds, UTC).strftime(DATE_FORMAT)


def timestamp_to_epoch(timestamp: str) -> int:
    """Convert ISO 8601 timestamp string to epoch seconds."""
    dt = arg_to_datetime(timestamp)
    if dt is None:
        raise ValueError(f"Could not parse timestamp: {timestamp!r}")
    return int(dt.timestamp())


def hash_event(event: dict) -> str:
    """Return a stable MD5 hex digest of an event dict (used for cross-cycle dedup)."""
    serialized = json.dumps(event, sort_keys=True, default=str)
    return hashlib.md5(serialized.encode()).hexdigest()  # noqa: S324


def get_boundary_hashes(events: list[dict], boundary_time: str) -> list[str]:
    """Return hashes of all events at boundary_time.

    Iterates backwards (boundary events are at the end) and stops at the first
    event with a different timestamp.

    Args:
        events: Events in ascending time order.
        boundary_time: The event_time of the last (most recent) event.

    Returns:
        MD5 hashes of all events at the boundary timestamp.
    """
    hashes: list[str] = []
    for event in reversed(events):
        if event.get("event_time", "") == boundary_time:
            hashes.append(hash_event(event))
        else:
            break
    return hashes


def get_events_for_log_type(
    client: Client,
    log_type_ui: str,
    start_epoch: int,
    end_epoch: int,
    max_events: int,
    enrich: bool = True,
) -> list[dict]:
    """Fetch all events for a single log type, paginating as needed.

    Args:
        client: The Menlo Security API client.
        log_type_ui: UI log type name (e.g. "web", "safemail").
        start_epoch: Fetch start time as epoch seconds.
        end_epoch: Fetch end time as epoch seconds.
        max_events: Maximum total events to collect.
        enrich: Add _time and source_log_type to each event. True when sending to XSIAM.

    Returns:
        Collected events, enriched if enrich=True.
    """
    # Rename the worker thread to the log type for cleaner logs (e.g. "[web]" instead of "[ThreadPoolExecutor-12_0]").
    threading.current_thread().name = log_type_ui
    thread_name = log_type_ui
    api_log_type = LOG_TYPE_MAP[log_type_ui]
    events: list[dict] = []
    paging_identifiers: dict | None = None

    # Page-size: first call uses min(MAX_EVENTS_PER_PAGE, max_events); subsequent calls
    # must use MAX_EVENTS_PER_PAGE since the pagingIdentifiers cursor is bound to it.
    # The final list is trimmed to max_events (we may overshoot on the last page).
    while len(events) < max_events:
        if paging_identifiers is None:
            page_limit = min(MAX_EVENTS_PER_PAGE, max_events)
        else:
            page_limit = MAX_EVENTS_PER_PAGE
        demisto.debug(f"[{thread_name}] Fetching: start={start_epoch}, end={end_epoch}, limit={page_limit}")

        try:
            response = client.fetch_log_page(
                log_type=api_log_type,
                start=start_epoch,
                end=end_epoch,
                limit=page_limit,
                paging_identifiers=paging_identifiers,
            )
        except Exception as e:
            demisto.error(f"[{thread_name}] Error fetching: {e}")
            break

        # The API may return an empty 200 response (Content-Length: 0) when there is no data.
        if not response:
            demisto.debug(f"[{thread_name}] Empty response — no data.")
            break

        # The live `web` endpoint returns a LIST of response wrappers, each carrying its own
        # events + pagingIdentifiers. Other log types may follow the documented single-object
        # shape. Normalize into a list of wrappers and flatten their inner events.
        wrappers = response if isinstance(response, list) else [response]

        page_events: list[dict] = []
        next_paging: dict | None = None
        for wrapper in wrappers:
            # Per docs the events live under result.events; some shapes have events at top level.
            result = wrapper.get("result", wrapper)
            page_events.extend(result.get("events", []))
            # Use the LAST non-empty pagingIdentifiers as the cursor for the next request.
            wrapper_paging = result.get("pagingIdentifiers") or None
            if wrapper_paging:
                next_paging = wrapper_paging

        if not page_events:
            demisto.debug(f"[{thread_name}] No more events.")
            break

        demisto.debug(f"[{thread_name}] Got {len(page_events)} events.")

        # Per the API docs, each element in the events list is {"event": {...}}.
        source_log_type = SOURCE_LOG_TYPE_MAP[log_type_ui] if enrich else None
        for event in page_events:
            inner = event.get("event", event)  # unwrap the {"event": {...}} envelope
            if enrich:
                event_time_str = inner.get("event_time")
                if event_time_str:
                    try:
                        dt = arg_to_datetime(event_time_str)
                        inner["_time"] = dt.strftime(DATE_FORMAT) if dt else event_time_str
                    except Exception:
                        inner["_time"] = event_time_str
                inner["source_log_type"] = source_log_type
            events.append(inner)

        paging_identifiers = next_paging or {}
        if not paging_identifiers:
            demisto.debug(f"[{thread_name}] All events fetched.")
            break

    # Trim to the user-requested cap (we may have fetched a few extra in the last page).
    if len(events) > max_events:
        demisto.debug(f"[{thread_name}] Trimming from {len(events)} to {max_events} events.")
        events = events[:max_events]

    demisto.debug(f"[{thread_name}] Collected {len(events)} events total.")
    return events


""" COMMAND FUNCTIONS """


def test_module(client: Client, log_types: list[str]) -> str:  # noqa: PT
    """Test API connectivity and authentication.

    Fetches one record per configured log type using the default first-fetch window.
    Returns 'ok' on success, a descriptive string for known errors, or re-raises unexpected ones.
    """
    end_epoch = int(datetime.now(UTC).timestamp())
    first_fetch_dt = arg_to_datetime(DEFAULT_FIRST_FETCH)
    if first_fetch_dt is None:
        raise ValueError(f"Invalid DEFAULT_FIRST_FETCH: {DEFAULT_FIRST_FETCH!r}")
    start_epoch = int(first_fetch_dt.timestamp())

    for log_type_ui in log_types or ALL_LOG_TYPES:
        api_log_type = LOG_TYPE_MAP.get(log_type_ui, log_type_ui)
        demisto.debug(f"[test-module] Testing log type: {log_type_ui}")
        try:
            client.fetch_log_page(log_type=api_log_type, start=start_epoch, end=end_epoch, limit=1)
        except Exception as e:
            error_str = str(e)
            if "401" in error_str or "Unauthorized" in error_str:
                return "Authorization Error: make sure the Auth Token is correct and has the Log Export API permission."
            if "403" in error_str or "Forbidden" in error_str:
                return f"Authorization Error: the token does not have permission to access '{log_type_ui}' logs."
            if "ConnectionError" in error_str or "Failed to establish" in error_str:
                return "Connection Error: could not reach the Menlo Security API. Check the Server URL and network connectivity."
            raise

    return "ok"


test_module.__test__ = False  # type: ignore[attr-defined]  # prevent pytest collection


@dataclass
class FetchResult:
    """Result of fetching events for a single log type in a thread."""

    log_type_ui: str
    events: list[dict] = field(default_factory=list)
    next_run_state: dict | None = None  # None means preserve previous state
    error: str | None = None


def _fetch_log_type_task(
    client: Client,
    log_type_ui: str,
    last_run: dict,
    first_fetch_time: str,
    end_epoch: int,
    end_timestamp: str,
    max_events_per_fetch: int,
) -> FetchResult:
    """Fetch and process events for a single log type (runs in a thread).

    Each thread receives a copy of last_run — no shared mutable state.
    Results are merged by the main thread after all threads complete.

    Args:
        client: Thread-safe API client (ContentClient/httpx).
        log_type_ui: UI log type name (e.g. "web", "safemail").
        last_run: Copy of the current last_run state dict.
        first_fetch_time: Human-readable first fetch time (e.g. "3 hours").
        end_epoch: Fetch end time as epoch seconds (read-only).
        end_timestamp: Fetch end time as ISO 8601 string (read-only).
        max_events_per_fetch: Maximum events to fetch for this log type.

    Returns:
        FetchResult with events, next_run_state, and any error.
    """
    # Rename the worker thread to the log type for cleaner logs (e.g. "[web]" instead of "[ThreadPoolExecutor-12_0]").
    threading.current_thread().name = log_type_ui
    thread_name = log_type_ui
    result = FetchResult(log_type_ui=log_type_ui)

    try:
        last_fetch_time = last_run.get(log_type_ui, {}).get("last_fetch_time")
        if last_fetch_time:
            start_epoch = timestamp_to_epoch(last_fetch_time)
            demisto.debug(f"[{thread_name}] resuming from {last_fetch_time}")
        else:
            first_fetch_dt = arg_to_datetime(first_fetch_time)
            if first_fetch_dt is None:
                raise ValueError(f"Invalid first_fetch_time: {first_fetch_time!r}")
            start_epoch = int(first_fetch_dt.timestamp())
            demisto.debug(f"[{thread_name}] first fetch from {epoch_to_timestamp(start_epoch)}")

        events = get_events_for_log_type(
            client=client,
            log_type_ui=log_type_ui,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            max_events=max_events_per_fetch,
        )

        # Dedup: API start is inclusive — leading events may duplicate the previous cycle.
        # Events are in ascending time order, so only leading events can be duplicates.
        boundary_hashes: set[str] = set(last_run.get(log_type_ui, {}).get("boundary_hashes", []))
        if last_fetch_time and events and boundary_hashes:
            skip = 0
            for e in events:
                if e.get("event_time", "") == last_fetch_time and hash_event(e) in boundary_hashes:
                    skip += 1
                else:
                    break
            if skip:
                demisto.debug(f"[{thread_name}] removed {skip} duplicate(s) at {last_fetch_time!r}")
                events = events[skip:]

        result.events = events

        if events:
            last_event_time = events[-1].get("event_time") or events[-1].get("_time", "")
            next_fetch_time = last_event_time or end_timestamp
            next_boundary_hashes = get_boundary_hashes(events, last_event_time)
            demisto.debug(
                f"[{thread_name}] next fetch from {next_fetch_time} " f"({len(next_boundary_hashes)} boundary hash(es))"
            )
            result.next_run_state = {"last_fetch_time": next_fetch_time, "boundary_hashes": next_boundary_hashes}
        else:
            # No events — preserve previous state so the next cycle retries from the same point.
            prev_state = last_run.get(log_type_ui)
            if prev_state:
                demisto.debug(f"[{thread_name}] no events — preserving state.")
                result.next_run_state = prev_state
            else:
                # First fetch with no results — advance to now to avoid re-querying the same empty window.
                demisto.debug(f"[{thread_name}] first fetch, no events — advancing to {end_timestamp}")
                result.next_run_state = {"last_fetch_time": end_timestamp, "boundary_hashes": []}

    except Exception as e:
        result.error = str(e)
        demisto.error(f"[{thread_name}] fetch failed: {e}")

    return result


def fetch_events(
    client: Client,
    last_run: dict,
    log_types: list[str],
    first_fetch_time: str,
    max_events_per_fetch: int,
) -> tuple[dict, list[dict]]:
    """Fetch events from all selected log types in parallel.

    Each log type runs in its own thread. Results are merged sequentially after
    all threads complete. Failed types preserve their previous last_run state.

    Args:
        client: Thread-safe API client.
        last_run: Last run dict from demisto.getLastRun().
        log_types: Selected log type UI names.
        first_fetch_time: Human-readable first fetch time (e.g. "3 hours").
        max_events_per_fetch: Maximum events per log type per cycle.

    Returns:
        (next_run dict, list of all events)
    """
    end_dt = datetime.now(UTC)
    end_epoch = int(end_dt.timestamp())
    end_timestamp = end_dt.strftime(DATE_FORMAT)

    demisto.debug(f"[fetch-events] Starting parallel fetch for: {log_types}")

    fetch_results: list[FetchResult] = []
    with ThreadPoolExecutor(max_workers=len(log_types)) as executor:
        futures = {
            executor.submit(
                _fetch_log_type_task,
                client=client,
                log_type_ui=log_type_ui,
                last_run=dict(last_run),  # copy per thread — no shared mutable state
                first_fetch_time=first_fetch_time,
                end_epoch=end_epoch,
                end_timestamp=end_timestamp,
                max_events_per_fetch=max_events_per_fetch,
            ): log_type_ui
            for log_type_ui in log_types
        }
        for future in as_completed(futures):
            log_type_ui = futures[future]
            try:
                fetch_results.append(future.result())
            except Exception as e:
                demisto.error(f"[fetch-events] Thread for {log_type_ui} raised: {e}")

    # Merge: start from last_run so failed types keep their previous state.
    all_events: list[dict] = []
    next_run: dict = dict(last_run)

    for result in fetch_results:
        if result.error:
            demisto.debug(f"[fetch-events] {result.log_type_ui}: error — previous state preserved.")
            continue
        all_events.extend(result.events)
        if result.next_run_state is not None:
            next_run[result.log_type_ui] = result.next_run_state

    demisto.debug(f"[fetch-events] Total events: {len(all_events)}")
    return next_run, all_events


def get_events_command(
    client: Client,
    args: dict,
    log_types: list[str],
    max_events_per_fetch: int,
) -> CommandResults:
    """Manual command to fetch and optionally push events.

    Args:
        client: The Menlo Security API client.
        args: Command arguments.
        log_types: Default log types from integration params.
        max_events_per_fetch: Default max events from integration params.

    Returns:
        CommandResults for display in the War Room.
    """
    start_time_str = args.get("start_time", "1 hour")
    end_time_str = args.get("end_time", "now")
    arg_log_types = argToList(args.get("log_types", "")) or log_types
    limit = arg_to_number(args.get("limit", max_events_per_fetch)) or max_events_per_fetch
    should_push = argToBoolean(args.get("should_push_events", False))

    start_dt = arg_to_datetime(start_time_str)
    end_dt = arg_to_datetime(end_time_str)
    if start_dt is None:
        raise ValueError(f"Invalid start_time: {start_time_str!r}")
    if end_dt is None:
        raise ValueError(f"Invalid end_time: {end_time_str!r}")

    start_epoch = int(start_dt.timestamp())
    end_epoch = int(end_dt.timestamp())

    all_events: list[dict] = []
    for log_type_ui in arg_log_types:
        if log_type_ui not in LOG_TYPE_MAP:
            demisto.debug(f"[get-events] Unknown log type: {log_type_ui}, skipping.")
            continue
        events = get_events_for_log_type(
            client=client,
            log_type_ui=log_type_ui,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            max_events=limit,
            enrich=should_push,
        )
        all_events.extend(events)

    if should_push:
        send_events_to_xsiam(all_events, vendor=VENDOR, product=PRODUCT)

    return CommandResults(
        readable_output=tableToMarkdown(name=f"{VENDOR} - {PRODUCT} Events", t=all_events, removeNull=True),
        raw_response=all_events,
    )


""" MAIN FUNCTION """


def main() -> None:
    """Main function — parses params and dispatches commands."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "https://logs.menlosecurity.com").rstrip("/")
    token = params.get("credentials", {}).get("password") or params.get("token", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    token_type = params.get("token_type", DEFAULT_TOKEN_TYPE)

    log_types: list[str] = argToList(params.get("log_types", ",".join(DEFAULT_LOG_TYPES))) or DEFAULT_LOG_TYPES
    max_events_per_fetch: int = (
        arg_to_number(params.get("max_events_per_fetch", DEFAULT_MAX_EVENTS_PER_FETCH)) or DEFAULT_MAX_EVENTS_PER_FETCH
    )

    demisto.debug(f"[main] Command: {command}, token_type: {token_type}, log types: {log_types}")

    try:
        client = Client(base_url=base_url, token=token, verify=verify_certificate, proxy=proxy, token_type=token_type)

        if command == "test-module":
            return_results(test_module(client, log_types))

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"[main] Last run: {last_run}")
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                log_types=log_types,
                first_fetch_time=DEFAULT_FIRST_FETCH,
                max_events_per_fetch=max_events_per_fetch,
            )
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"[main] Next run: {next_run}")

        elif command == "menlo-security-get-events":
            return_results(
                get_events_command(client=client, args=args, log_types=log_types, max_events_per_fetch=max_events_per_fetch)
            )

        else:
            raise NotImplementedError(f"Command {command!r} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
