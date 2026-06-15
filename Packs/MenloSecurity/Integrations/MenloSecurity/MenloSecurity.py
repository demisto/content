import hashlib
import json
import queue
import threading
import time
import traceback
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from ContentClientApiModule import *

""" CONSTANTS """

VENDOR = "Menlo"
PRODUCT = "Security IP"

DEFAULT_MAX_EVENTS_PER_FETCH_PER_TYPE = 10000
MAX_EVENTS_PER_PAGE = 10000
DEFAULT_FIRST_FETCH = "5 minutes"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Per Menlo support: API latency scales with the (end - start) span, not the page size. We cap each
# query to a bounded window and walk forward window-by-window so per-request latency stays low even
# with a large backlog (Menlo recommends ~5-minute windows for high-volume tenants).
MAX_FETCH_WINDOW_SECONDS = 300  # 5 minutes

# Per Menlo docs: Admin-UI-generated tokens use the v2 endpoint; legacy CSV-based tokens use v1.
API_PATH_TEMPLATE = "/api/rep/{api_version}/fetch/client_select"
TOKEN_TYPE_TO_API_VERSION = {"Admin Token": "v2", "Token": "v1"}
DEFAULT_TOKEN_TYPE = "Admin Token"

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
# Default log types: all available types are pre-selected in the UI.
DEFAULT_LOG_TYPES = ALL_LOG_TYPES


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

        demisto.debug(f"[{log_type}] HTTP {response.status_code}, body-bytes={len(response.content)}, requested limit={limit}")

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
    """Return a stable SHA-256 hex digest of an event dict (used for cross-cycle dedup)."""
    serialized = json.dumps(event, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def get_boundary_hashes(events: list[dict], boundary_time: str) -> list[str]:
    """Return hashes of all events at boundary_time.

    Iterates backwards (boundary events are at the end) and stops at the first
    event with a different timestamp.

    Args:
        events: Events in ascending time order.
        boundary_time: The event_time of the last (most recent) event.

    Returns:
        SHA-256 hashes of all events at the boundary timestamp.
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
    boundary_hashes: set[str] | None = None,
    last_fetch_time: str | None = None,
    on_page: Callable[[list[dict]], None] | None = None,
) -> list[dict]:
    """Fetch all events for a single log type, paginating as needed.

    Dedup: ``boundary_hashes`` + ``last_fetch_time`` (from the previous cycle) drop leading
    duplicates on the first page only — the API start is inclusive and events are time-ordered,
    so only the first page can collide with the previous boundary.

    Streaming: when ``on_page`` is supplied, each page is handed to the callback and dropped
    (not accumulated) to bound peak RAM. Only the last page is kept so the caller can compute
    next-run state (boundary hashes + last event time).

    Args:
        enrich: Add _time and source_log_type to each event. True when sending to XSIAM.
        boundary_hashes: Hashes of the previous cycle's boundary events; pairs with last_fetch_time.
        last_fetch_time: The previous cycle's last event_time.
        on_page: Callback per page; when set, streams pages out instead of accumulating them.

    Returns:
        The full event list (non-streaming) or only the last page (streaming).
    """
    # Rename the worker thread to the log type for cleaner logs (e.g. "[web]" instead of "[ThreadPoolExecutor-12_0]").
    threading.current_thread().name = log_type_ui
    thread_name = log_type_ui
    api_log_type = LOG_TYPE_MAP[log_type_ui]
    streaming = on_page is not None
    events: list[dict] = []  # In streaming mode: only the LAST page is kept (for boundary computation).
    total_emitted = 0  # Counts events handed to the consumer (or accumulated) AFTER dedup.
    paging_identifiers: dict | None = None
    is_first_page = True
    boundary_hashes = boundary_hashes or set()

    # Page-size: first call uses min(MAX_EVENTS_PER_PAGE, max_events); subsequent calls
    # must use MAX_EVENTS_PER_PAGE since the pagingIdentifiers cursor is bound to it.
    # The final list is trimmed to max_events (we may overshoot on the last page).
    while total_emitted < max_events:
        if paging_identifiers is None:
            page_limit = min(MAX_EVENTS_PER_PAGE, max_events)
        else:
            page_limit = MAX_EVENTS_PER_PAGE
        demisto.debug(f"[{thread_name}] Fetching: start={start_epoch}, end={end_epoch}, limit={page_limit}")

        response = client.fetch_log_page(
            log_type=api_log_type,
            start=start_epoch,
            end=end_epoch,
            limit=page_limit,
            paging_identifiers=paging_identifiers,
        )

        # The API may return an empty 200 response (Content-Length: 0) when there is no data.
        if not response:
            demisto.debug(f"[{thread_name}] Empty response — no data.")
            break

        # The v2 `web` endpoint returns a LIST of wrappers; other shapes are single objects.
        # Normalize to a list and flatten the inner events.
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

        # Fewer events than requested but a next-page cursor ⇒ server is capping page size.
        if len(page_events) < page_limit and next_paging:
            demisto.info(
                f"[{thread_name}] API returned {len(page_events)} events but we requested limit={page_limit} "
                f"(server may be capping page size below {MAX_EVENTS_PER_PAGE})."
            )

        demisto.debug(f"[{thread_name}] Got {len(page_events)} events (requested limit={page_limit}).")

        # Per the API docs, each element in the events list is {"event": {...}}.
        # Unwrap + enrich + (on page 1 only) drop leading boundary duplicates.
        source_log_type = SOURCE_LOG_TYPE_MAP[log_type_ui] if enrich else None
        processed: list[dict] = []
        for event in page_events:
            inner = event.get("event", event)  # unwrap the {"event": {...}} envelope
            if enrich:
                event_time_str = inner.get("event_time")
                if event_time_str:
                    # fromisoformat is ~1000x faster than arg_to_datetime and handles Menlo's naive
                    # ISO 8601 (e.g. "2026-05-26T17:20:28.090"); fall back to arg_to_datetime otherwise.
                    try:
                        inner["_time"] = datetime.fromisoformat(event_time_str).strftime(DATE_FORMAT)
                    except (ValueError, TypeError):
                        fallback_dt: datetime | None = arg_to_datetime(event_time_str)
                        inner["_time"] = fallback_dt.strftime(DATE_FORMAT) if fallback_dt else event_time_str
                inner["source_log_type"] = source_log_type
            processed.append(inner)

        # Dedup the first page only: start is inclusive, so leading events can repeat the previous
        # boundary; later pages have strictly later timestamps and can't collide.
        if is_first_page and last_fetch_time and boundary_hashes:
            skip = 0
            for e in processed:
                if e.get("event_time", "") == last_fetch_time and hash_event(e) in boundary_hashes:
                    skip += 1
                else:
                    break
            if skip:
                demisto.debug(f"[{thread_name}] removed {skip} duplicate(s) at {last_fetch_time!r}")
                processed = processed[skip:]

        is_first_page = False

        # Cap to max_events (last page may overshoot).
        remaining = max_events - total_emitted
        if len(processed) > remaining:
            demisto.debug(f"[{thread_name}] Trimming page from {len(processed)} to {remaining} events.")
            processed = processed[:remaining]

        if not processed:
            # Whole page was duplicates or trimmed away — stop here.
            paging_identifiers = next_paging or {}
            if not paging_identifiers:
                break
            continue

        total_emitted += len(processed)

        if on_page is not None:
            # Stream the page out; keep only the last one for the caller's boundary hashes.
            # Drop the previous page's reference first so we never hold two at once.
            events = []
            on_page(processed)
            events = processed
        else:
            events.extend(processed)

        paging_identifiers = next_paging or {}
        if not paging_identifiers:
            demisto.debug(f"[{thread_name}] All events fetched.")
            break

    demisto.debug(f"[{thread_name}] Collected {total_emitted} events total (streaming={streaming}).")
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


@dataclass
class FetchResult:
    """Result of fetching events for a single log type. In streaming mode ``events`` holds only
    the LAST page (for boundary-hash computation); the total count is in ``events_emitted``.
    """

    log_type_ui: str
    events: list[dict] = field(default_factory=list)  # streaming: last page only; non-streaming: full list
    events_emitted: int = 0  # total events handed to consumer (or accumulated); used for saturation check
    next_run_state: dict | None = None  # None means preserve previous state
    error: str | None = None
    window_capped: bool = False  # True ⇒ query window was capped below `now` (we're behind; more windows remain)


def _fetch_log_type_task(
    client: Client,
    log_type_ui: str,
    last_run: dict,
    first_fetch_time: str,
    end_epoch: int,
    max_events_per_fetch_per_type: int,
    on_page: Callable[[list[dict]], None] | None = None,
) -> FetchResult:
    """Fetch and process events for a single log type (runs in its own thread).

    Receives a copy of last_run (no shared state). Caps the query to one MAX_FETCH_WINDOW_SECONDS
    window and computes the next-run state. When ``on_page`` is supplied, pages are streamed out
    (post-dedup, post-enrichment) to keep memory bounded.

    Returns a FetchResult with the events (last page in streaming mode), events_emitted,
    next_run_state, window_capped, and any error.
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

        # Cap the query to one window so each request stays fast even when behind (see
        # MAX_FETCH_WINDOW_SECONDS). window_end is per-log-type (each has its own backlog).
        window_end_epoch = min(end_epoch, start_epoch + MAX_FETCH_WINDOW_SECONDS)
        window_capped = window_end_epoch < end_epoch  # True ⇒ we're behind; more windows remain
        window_end_timestamp = epoch_to_timestamp(window_end_epoch)
        demisto.debug(
            f"[{thread_name}] window [{epoch_to_timestamp(start_epoch)} → {window_end_timestamp}] "
            f"({window_end_epoch - start_epoch}s span, capped={window_capped})"
        )

        boundary_hashes: set[str] = set(last_run.get(log_type_ui, {}).get("boundary_hashes", []))

        # Count events emitted so the caller can compute saturation (in streaming mode
        # ``events`` only holds the last page).
        page_count = {"n": 0}
        if on_page is not None:
            original_callback = on_page

            def _counting_callback(page: list[dict]) -> None:
                page_count["n"] += len(page)
                original_callback(page)

            effective_callback: Callable[[list[dict]], None] | None = _counting_callback
        else:
            effective_callback = None

        events = get_events_for_log_type(
            client=client,
            log_type_ui=log_type_ui,
            start_epoch=start_epoch,
            end_epoch=window_end_epoch,  # bounded window, not `now`
            max_events=max_events_per_fetch_per_type,
            boundary_hashes=boundary_hashes,
            last_fetch_time=last_fetch_time,
            on_page=effective_callback,
        )

        # Non-streaming: `events` is the full list. Streaming: it's only the last page,
        # but `page_count["n"]` is the true total handed to the consumer.
        result.events = events
        result.events_emitted = page_count["n"] if on_page is not None else len(events)
        # Tell the caller whether this log type still has more windows to drain. When True, we're
        # behind ⇒ fetch_events sets nextTrigger=0 so the engine re-dispatches immediately.
        result.window_capped = window_capped

        if events:
            last_event_time = events[-1].get("event_time") or events[-1].get("_time", "")
            # Resume from last_event_time either way — it's the safe boundary whether we hit the
            # cap (more events may share it) or drained the window (later events may remain). Dedup
            # handles any overlap on the next cycle's first page.
            next_fetch_time = last_event_time or window_end_timestamp
            next_boundary_hashes = get_boundary_hashes(events, last_event_time)
            demisto.debug(f"[{thread_name}] next fetch from {next_fetch_time} ({len(next_boundary_hashes)} boundary hash(es))")
            result.next_run_state = {"last_fetch_time": next_fetch_time, "boundary_hashes": next_boundary_hashes}
        else:
            # No events in this window.
            if window_capped:
                # Empty AND behind: advance past this window or we'd re-query it forever (deadlock).
                demisto.debug(f"[{thread_name}] empty capped window — advancing start to {window_end_timestamp}")
                result.next_run_state = {"last_fetch_time": window_end_timestamp, "boundary_hashes": []}
            else:
                # Empty AND caught up: preserve state to re-poll the same boundary next cycle.
                prev_state = last_run.get(log_type_ui)
                if prev_state:
                    demisto.debug(f"[{thread_name}] caught up, no events — preserving state.")
                    result.next_run_state = prev_state
                else:
                    # First fetch, caught up, no events — advance to now to avoid re-querying empty.
                    demisto.debug(f"[{thread_name}] first fetch, no events — advancing to {window_end_timestamp}")
                    result.next_run_state = {"last_fetch_time": window_end_timestamp, "boundary_hashes": []}

    except Exception as e:
        result.error = str(e)
        demisto.error(f"[{thread_name}] fetch failed: {e}\n{traceback.format_exc()}")

    return result


def fetch_events(
    client: Client,
    last_run: dict,
    log_types: list[str],
    first_fetch_time: str,
    max_events_per_fetch_per_type: int,
    on_page: Callable[[list[dict]], None] | None = None,
) -> tuple[dict, list[dict]]:
    """Fetch events from all selected log types in parallel.

    Each log type runs in its own thread; failed types preserve their previous last_run state.
    Streaming mode (``on_page`` set): pages stream to the callback and the returned list is EMPTY.
    Non-streaming mode: returns the full list (used by ``menlo-security-get-events``).

    Returns (next_run dict, all events — empty in streaming mode). next_run carries
    "nextTrigger"=0 when any log type is saturated or behind, so the engine re-dispatches.
    """
    end_epoch = int(datetime.now(UTC).timestamp())
    streaming = on_page is not None

    demisto.debug(f"[fetch-events] Starting parallel fetch for: {log_types} (streaming={streaming})")

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
                max_events_per_fetch_per_type=max_events_per_fetch_per_type,
                on_page=on_page,
            ): log_type_ui
            for log_type_ui in log_types
        }
        for future in as_completed(futures):
            log_type_ui = futures[future]
            try:
                fetch_results.append(future.result())
            except Exception as e:
                demisto.error(f"[fetch-events] Thread for {log_type_ui} raised: {e}\n{traceback.format_exc()}")

    # Merge: start from last_run so failed types keep their previous state.
    all_events: list[dict] = []
    next_run: dict = dict(last_run)
    total_emitted = 0

    # Set nextTrigger=0 if ANY log type still has work: cap-saturated (hit the per-type cap) OR
    # window-capped (bounded below `now` because we're behind, so more windows remain).
    any_more_work = False
    progress_details: list[str] = []

    for result in fetch_results:
        if result.error:
            demisto.error(f"[fetch-events] {result.log_type_ui}: error — previous state preserved.")
            continue
        # Non-streaming: accumulate. Streaming: pages were already sent; result.events is only
        # the last page (for boundary computation) and must NOT be re-emitted.
        if not streaming:
            all_events.extend(result.events)
        total_emitted += result.events_emitted
        if result.next_run_state is not None:
            next_run[result.log_type_ui] = result.next_run_state

        is_saturated = result.events_emitted >= max_events_per_fetch_per_type
        more_work = is_saturated or result.window_capped
        flags = f"{'(SAT)' if is_saturated else ''}{'(BEHIND)' if result.window_capped else ''}"
        progress_details.append(f"{result.log_type_ui}={result.events_emitted}/{max_events_per_fetch_per_type}{flags}")
        if more_work:
            any_more_work = True

    if any_more_work:
        next_run["nextTrigger"] = "0"
        demisto.debug(f"[fetch-events] nextTrigger=0 (more work: saturated or behind) — {', '.join(progress_details)}")
    else:
        next_run.pop("nextTrigger", None)
        demisto.debug(f"[fetch-events] no nextTrigger (caught up) — {', '.join(progress_details)}")

    demisto.debug(f"[fetch-events] Total events emitted: {total_emitted} (returned in list: {len(all_events)})")
    return next_run, all_events


def get_events_command(
    client: Client,
    args: dict,
    log_types: list[str],
    max_events_per_fetch_per_type: int,
) -> CommandResults | list[CommandResults]:
    """Manual command to fetch and optionally push events.

    Args:
        client: The Menlo Security API client.
        args: Command arguments.
        log_types: Default log types from integration params.
        max_events_per_fetch_per_type: Default max events from integration params.

    Returns:
        CommandResults for display in the War Room.
    """
    start_time_str = args.get("start_time", "1 hour")
    end_time_str = args.get("end_time", "now")
    arg_log_types = argToList(args.get("log_types", "")) or log_types
    limit = arg_to_number(args.get("limit", max_events_per_fetch_per_type)) or max_events_per_fetch_per_type
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
    valid_log_types = [lt for lt in arg_log_types if lt in LOG_TYPE_MAP]
    invalid_log_types = [lt for lt in arg_log_types if lt not in LOG_TYPE_MAP]
    if invalid_log_types:
        raise ValueError(f"Unknown log type(s): {', '.join(invalid_log_types)}. Valid options: {', '.join(ALL_LOG_TYPES)}")

    for log_type_ui in valid_log_types:
        events = get_events_for_log_type(
            client=client,
            log_type_ui=log_type_ui,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            max_events=limit,
            enrich=should_push,
        )
        all_events.extend(events)

    readable = tableToMarkdown(name=f"{VENDOR} - {PRODUCT} Events", t=all_events, removeNull=True)
    results = CommandResults(readable_output=readable, raw_response=all_events)

    if should_push and all_events:
        send_events_to_xsiam(all_events, vendor=VENDOR, product=PRODUCT)
        return [results, CommandResults(readable_output=f"Successfully pushed {len(all_events)} events to XSIAM.")]

    return results


""" EVENT COLLECTION (producer/consumer streaming) """


# Producer/consumer queue capacity. Each page is ~17 MB (10k web events).
# maxsize=2 holds at most ~34 MB per log_type in flight = comfortable backpressure
# under the 1 GB container limit, while letting the producer race one page ahead of the consumer.
PAGE_QUEUE_MAXSIZE = 2
# Sentinel placed on the queue to signal the consumer to drain + exit cleanly.
_QUEUE_SENTINEL = object()


def _xsiam_consumer_loop(
    page_queue: "queue.Queue[Any]",
    stats: dict[str, Any],
) -> None:
    """Consumer thread: drain pages from the queue and send each to XSIAM sequentially.

    Single-threaded send (no ``multiple_threads=True``) keeps memory bounded — fan-out would
    re-introduce the chunk accumulation that caused the OOM, and the producer already overlaps
    its next fetch with the send. On failure, the error is recorded in ``stats['error']`` and the
    consumer keeps draining (it must consume the sentinel to unblock the producer); the caller
    re-raises after join so the next cycle retries (dedup handles overlap).
    """
    while True:
        item = page_queue.get()
        try:
            if item is _QUEUE_SENTINEL:
                return
            # On a prior error, keep draining (to unblock the producer) but skip the network call.
            if stats.get("error") is not None:
                continue
            try:
                send_events_to_xsiam(item, vendor=VENDOR, product=PRODUCT)
                stats["pages_sent"] = stats.get("pages_sent", 0) + 1
                stats["events_sent"] = stats.get("events_sent", 0) + len(item)
            except Exception as e:
                stats["error"] = e
                demisto.error(f"[fetch-events][consumer] send_events_to_xsiam failed: {e}\n{traceback.format_exc()}")
        finally:
            page_queue.task_done()
            del item  # release the ~17 MB page before the next blocking get()


def fetch_events_command(
    client: Client,
    log_types: list[str],
    first_fetch_time: str,
    max_events_per_fetch_per_type: int,
) -> None:
    """Scheduled fetch-events collector (producer/consumer streaming send).

    Fetches one window per log type, streaming each page to XSIAM as it arrives, then persists
    state via setLastRun. When still behind, fetch_events sets nextTrigger=0 in the persisted
    state so the engine re-dispatches immediately and the backlog drains across invocations.
    Pages stream through a bounded queue and are sent sequentially, so peak RAM stays ~2 pages
    regardless of volume (the OOM fix).
    """
    state = demisto.getLastRun() or {}
    demisto.info(
        f"[fetch-events] Starting collection (log_types={log_types}, "
        f"max_events_per_fetch_per_type={max_events_per_fetch_per_type}, queue_maxsize={PAGE_QUEUE_MAXSIZE})"
    )

    cycle_start = time.monotonic()
    page_queue: queue.Queue[Any] = queue.Queue(maxsize=PAGE_QUEUE_MAXSIZE)
    consumer_stats: dict[str, Any] = {"pages_sent": 0, "events_sent": 0, "error": None}
    consumer = threading.Thread(
        target=_xsiam_consumer_loop,
        args=(page_queue, consumer_stats),
        name="xsiam-consumer",
        daemon=True,
    )
    consumer.start()
    try:
        next_run, _ = fetch_events(
            client=client,
            last_run=state,
            log_types=log_types,
            first_fetch_time=first_fetch_time,
            max_events_per_fetch_per_type=max_events_per_fetch_per_type,
            on_page=page_queue.put,
        )
    finally:
        # Always signal + join the consumer (even if fetch_events raised) so it doesn't leak;
        # the timeouts give a definitive exit path if it stalls.
        try:
            if consumer.is_alive():
                page_queue.put(_QUEUE_SENTINEL, timeout=60)
        except queue.Full:
            demisto.error("[fetch-events] queue full and consumer not draining — aborting cycle.")
        consumer.join(timeout=120)
        if consumer.is_alive():
            demisto.error("[fetch-events] consumer thread did not exit within 120s. Investigate XSIAM ingestion latency.")

    # If the consumer hit a send failure, propagate it WITHOUT persisting state so the next cycle
    # re-fetches from the previous boundary (dedup catches anything that already landed).
    consumer_error = consumer_stats["error"]
    if consumer_error is not None:
        assert isinstance(consumer_error, BaseException)  # narrow type for pylint/mypy
        raise consumer_error

    # Persist next_run (including "nextTrigger"=0 when behind/saturated, so the engine re-dispatches).
    demisto.setLastRun(next_run)
    demisto.info(
        f"[fetch-events] Done in {time.monotonic() - cycle_start:.1f}s — "
        f"events_sent={consumer_stats['events_sent']} pages_sent={consumer_stats['pages_sent']} "
        f"more_work={next_run.get('nextTrigger') == '0'}"
    )


""" MAIN FUNCTION """


def main() -> None:
    """Main function — parses params and dispatches commands."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "https://logs.menlosecurity.com").rstrip("/")
    token = params.get("credentials", {}).get("password", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    token_type = params.get("token_type", DEFAULT_TOKEN_TYPE)

    log_types: list[str] = argToList(params.get("log_types", ",".join(DEFAULT_LOG_TYPES))) or DEFAULT_LOG_TYPES
    max_events_per_fetch_per_type: int = (
        arg_to_number(params.get("max_events_per_fetch_per_type", DEFAULT_MAX_EVENTS_PER_FETCH_PER_TYPE))
        or DEFAULT_MAX_EVENTS_PER_FETCH_PER_TYPE
    )
    demisto.debug(f"[main] Command: {command}, token_type: {token_type}, params: {json.dumps(params)}, args: {json.dumps(args)}")

    try:
        client = Client(base_url=base_url, token=token, verify=verify_certificate, proxy=proxy, token_type=token_type)

        if command == "test-module":
            return_results(test_module(client, log_types))

        elif command == "fetch-events":
            fetch_events_command(
                client=client,
                log_types=log_types,
                first_fetch_time=DEFAULT_FIRST_FETCH,
                max_events_per_fetch_per_type=max_events_per_fetch_per_type,
            )

        elif command == "menlo-security-get-events":
            return_results(
                get_events_command(
                    client=client, args=args, log_types=log_types, max_events_per_fetch_per_type=max_events_per_fetch_per_type
                )
            )

        else:
            raise NotImplementedError(f"Command {command!r} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
