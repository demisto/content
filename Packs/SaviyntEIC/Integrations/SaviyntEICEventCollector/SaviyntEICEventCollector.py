import hashlib
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

# Python 3.10 compatibility: datetime.UTC added in 3.11; use timezone.utc instead
UTC = UTC

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "saviynt"
PRODUCT = "eic"
TOKEN_SAFETY_BUFFER = 300  # seconds to refresh token before actual expiry
MAX_EVENTS = 50000
LAST_RUN_EVENT_HASHES = "recent_event_hashes"
DEFAULT_FETCH_TIME_FRAME_MINUTES = 1
LAST_RUN_TIMESTAMP = "last_fetch_timestamp"
MAX_EVENTS_PER_REQUEST = 10000
EVENT_TYPE_TO_FETCH = "SIEMAuditLogs"

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with Saviynt EIC API

    - Authentication:
      - Create token: POST /ECM/api/login
      - Refresh token: POST /ECM/oauth/access_token
    - Fetch Events:
      - POST /ECM/api/v5/fetchRuntimeControlsDataV2
    """

    def __init__(
        self,
        base_url: str,
        verify: bool = False,
        proxy: bool = False,
        credentials: dict[str, Any] | None = None,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._credentials = credentials or {}
        # Protects token refresh and header updates when multiple threads fetch pages concurrently.
        # Used in _post_fetch_with_retry during 401/Forbidden refresh to avoid races.
        self._auth_lock = threading.Lock()
        try:
            self.obtain_token()
        except Exception as e:
            raise DemistoException(f"[Client.__init__] failed to obtain access token: {e}")

    def _create_access_token(self):
        """
        Create an access token and update integration context and client headers.

        This method authenticates using the configured credentials, then stores the
        resulting access and refresh tokens in the integration context and applies
        the Authorization header on the client for immediate use.

        Returns:
            None
        """
        demisto.debug("[Client._create_access_token] creating access token")
        data = {
            "username": self._credentials["identifier"],
            "password": self._credentials["password"],
        }
        res = self._http_request(
            method="POST",
            url_suffix="api/login",
            json_data=data,
        )
        # Expected keys: token_type, access_token, refresh_token, expires_in
        access_token = res.get("access_token")
        refresh_token = res.get("refresh_token")
        expires_in = int(res.get("expires_in", 0))
        now_epoch = int(time.time())
        # Apply to integration context and client headers for immediate use
        expires_at = now_epoch + expires_in
        demisto.setIntegrationContext(
            {
                "token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expires_at,
            }
        )
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        demisto.debug(f"[Client._create_access_token] created token successfully (expires_at={expires_at})")

    def _refresh_access_token(self, refresh_token: str):
        """
        Refresh the access token using the provided refresh token.

        Args:
            refresh_token: The refresh token to exchange for a new access token.

        Returns:
            None

        Notes:
            Updates both the integration context and the client's Authorization header.
        """
        demisto.debug("[Client._refresh_access_token] attempting to refresh access token")
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        res = self._http_request(
            method="POST",
            url_suffix="oauth/access_token",
            data=data,
            resp_type="json",
        )
        access_token = res.get("access_token")
        new_refresh = res.get("refresh_token") or refresh_token
        expires_in = int(res.get("expires_in", 3600))
        now_epoch = int(time.time())
        expires_at = now_epoch + expires_in
        demisto.setIntegrationContext(
            {
                "token": access_token,
                "refresh_token": new_refresh,
                "expires_at": expires_at,
            }
        )
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        demisto.debug(f"[Client._refresh_access_token] refreshed token successfully (expires_at={expires_at})")

    def obtain_token(self, force_refresh: bool = False) -> None:
        """
        Ensure a valid access token and set request headers.

        This method uses the integration context as a cache. If the token is close
        to expiry or if `force_refresh` is True, it refreshes or re-creates the
        token as needed, and updates the client's Authorization header.

        Args:
            force_refresh: Whether to force a refresh or creation of the token
                regardless of cache state.

        Returns:
            None
        """
        demisto.debug(f"[Client.obtain_token] start (force_refresh={force_refresh})")
        try:
            if context := demisto.getIntegrationContext():
                now_epoch = int(time.time())
                token = context.get("token")
                refresh_token = context.get("refresh_token")
                expires_at = int(context.get("expires_at", 0))

                if not force_refresh and token and (now_epoch + TOKEN_SAFETY_BUFFER) < expires_at:
                    demisto.debug(f"[Client.obtain_token] using cached token (expires_at={expires_at})")
                    # Ensure headers are applied for the current client instance when using a cached token
                    self._headers = {
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    }
                    return

                # Try to refresh if possible
                if refresh_token:
                    try:
                        self._refresh_access_token(refresh_token)
                        return
                    except Exception as e:
                        demisto.debug(f"[Client.obtain_token] refresh failed: {e}; creating new token")
        except Exception as e:
            demisto.debug(f"[Client.obtain_token] unexpected error handling integration context: {e}; creating new token")

        # Fallback to create new token
        demisto.debug("[Client.obtain_token] creating new access token")
        self._create_access_token()

    def fetch_events(
        self,
        analytics_name: str,
        time_frame_minutes: int,
        max_results: int,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """
        Fetch events for a single Analytics Runtime Control.

        Args:
            analytics_name: The event type to fetch (for example, `"SIEMAuditLogs"`).
            time_frame_minutes: The time frame in minutes to fetch events from.
            max_results: The maximum number of results to request in this call
                (the server may cap this value, typically at 10,000).
            offset: The paging offset to start from, if any.

        Returns:
            dict[str, Any]: The JSON response returned by the API.

        Notes:
            On authentication failure (401/Forbidden/invalid token), the client
            refreshes the token under a lock and retries the request once.
        """
        body: dict[str, Any] = {
            "analyticsname": analytics_name,
            "attributes": {"timeFrame": str(time_frame_minutes)},
            "max": max_results,
        }
        if offset:
            body["offset"] = str(offset)

        # Log the executing worker/thread to aid concurrent diagnostics
        worker_name = threading.current_thread().name
        demisto.debug(
            f"[Client.fetch_events] worker={worker_name} analytics={analytics_name} "
            f"time_frame_minutes={time_frame_minutes} max_results={max_results} offset={offset}"
        )

        try:
            return self._http_request(
                method="POST",
                url_suffix="api/v5/fetchRuntimeControlsDataV2",
                headers=self._headers,
                json_data=body,
                timeout=120,
            )
        except Exception as e:
            # Attempt one retry on auth failure
            if any(x in str(e) for x in ("401", "Forbidden", "invalid token")):
                demisto.debug(f"Access token may be invalid/expired. Attempting to refresh and retry fetch. Error: {e}")
                # Force refresh token and retry under an auth lock to avoid races across threads
                with self._auth_lock:
                    self.obtain_token(force_refresh=True)
                return self._http_request(
                    method="POST",
                    url_suffix="api/v5/fetchRuntimeControlsDataV2",
                    headers=self._headers,
                    json_data=body,
                    timeout=120,
                )
            raise


""" HELPER FUNCTIONS """


def add_time_to_events(events: list[dict[str, Any]]):
    """
    Add the `_time` field to events based on their occurrence timestamp.

    Args:
        events: The events to enrich in-place.

    Returns:
        None
    """
    for event in events:
        create_time = arg_to_datetime(arg=event.get("Event Time"))
        event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def generate_event_hash(event: dict[str, Any]) -> str:
    """
    Generate a stable SHA-256 hash for a single event.

    The hash excludes integration-only/transient fields so that it remains stable
    across runs.

    Args:
        event: The event object to hash.

    Returns:
        str: The hexadecimal SHA-256 hash of the event payload.
    """
    excluded = {"_time", "event_hash"}
    event_for_hash = {k: v for k, v in event.items() if k not in excluded}
    try:
        payload = json.dumps(event_for_hash, sort_keys=True, separators=(",", ":"))
    except TypeError as e:
        demisto.debug(f"[generate_event_hash] encountered non-serializable value; falling back to default=str. error={e}")
        payload = json.dumps(event_for_hash, sort_keys=True, separators=(",", ":"), default=str)
    hash_hex = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return hash_hex


def compute_effective_time_frame_minutes(time_frame_minutes: int | None, last_run: dict[str, Any]) -> int:
    """
    Compute the effective time frame (minutes) for the fetch request.

    If `time_frame_minutes` is provided (e.g., via the `saviynt-eic-get-events` command),
    it is used as-is. Otherwise, for the `fetch-events` command, the value is derived from
    `last_run` as follows:

    - First run (no timestamp): return `DEFAULT_FETCH_TIME_FRAME_MINUTES`.
    - Subsequent runs: compute the minutes between now (UTC) and the recorded timestamp.

    Args:
        time_frame_minutes: The requested time frame in minutes, or `None` to compute
            it from the last run timestamp.
        last_run: The persistence object storing the previous run metadata.

    Returns:
        int: The effective time frame in minutes to use for the API request.
    """
    if time_frame_minutes is None:
        previous_ts = last_run.get(LAST_RUN_TIMESTAMP)
        if isinstance(previous_ts, int) and previous_ts > 0:  # if not first run
            if (prev_dt := arg_to_datetime(previous_ts)) is None:
                # Defensive: if parsing failed, fall back to default
                effective_minutes = DEFAULT_FETCH_TIME_FRAME_MINUTES
                demisto.debug(
                    "[compute_effective_time_frame_minutes] previous_ts present but parsing failed; "
                    f"using default: {effective_minutes} minutes"
                )
            else:
                now_dt = datetime.now(UTC)
                delta_seconds = (now_dt - prev_dt).total_seconds()
                effective_minutes = max(1, math.ceil(delta_seconds / 60))
                demisto.debug(
                    f"[compute_effective_time_frame_minutes] prev_dt={prev_dt}, now_dt={now_dt}, "
                    f"delta_seconds={delta_seconds}, effective_minutes={effective_minutes}"
                )
        else:
            effective_minutes = DEFAULT_FETCH_TIME_FRAME_MINUTES
            demisto.debug(
                f"[compute_effective_time_frame_minutes] first run (no previous timestamp). "
                f"Using default: {effective_minutes} minutes"
            )
    else:
        effective_minutes = time_frame_minutes
    return effective_minutes


def deduplicate_events(events: list[dict[str, Any]], last_run: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Deduplicate events using previous-run hashes and within-run uniqueness.

    This function drops events whose hashes appeared in the immediate previous run
    and ensures uniqueness within the current run. It also prepares the next run's
    cache of unique hashes (order-preserving).

    Args:
        events: The events collected in the current run.
        last_run: The previous run's persisted metadata (including hashes).

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of `(next_run, deduplicated_events)` where
        `next_run` contains the hashes from this run and `deduplicated_events` are the
        events after de-duplication.
    """
    previous_run_hashes = set(last_run.get(LAST_RUN_EVENT_HASHES, []))

    deduplicated_events: list[dict[str, Any]] = []
    seen_hashes_this_run: set[str] = set()

    # Build the cache for the next run from all unique hashes seen in this run
    current_run_hashes_in_order: list[str] = []
    seen_hashes_for_cache: set[str] = set()

    for event in events:
        event_hash = generate_event_hash(event)

        if event_hash not in seen_hashes_for_cache:
            current_run_hashes_in_order.append(event_hash)
            seen_hashes_for_cache.add(event_hash)

        # Within-run dedup
        if event_hash in seen_hashes_this_run:
            continue
        # Previous-run dedup
        if event_hash in previous_run_hashes:
            continue

        # Note: generate_event_hash() excludes 'event_hash', so adding it does not affect hash stability.
        event.setdefault("event_hash", event_hash)
        deduplicated_events.append(event)
        seen_hashes_this_run.add(event_hash)

    new_last_run = dict(last_run)
    new_last_run[LAST_RUN_EVENT_HASHES] = current_run_hashes_in_order

    demisto.debug(
        f"[deduplicate_events] summary: input={len(events)}, output={len(deduplicated_events)}, "
        f"previous_run_hashes={len(previous_run_hashes)}, next_run_hashes={len(new_last_run[LAST_RUN_EVENT_HASHES])}"
    )

    # Return order matches fetch_events: (next_run, events)
    return new_last_run, deduplicated_events


def update_last_run_timestamp_from_events(next_run: dict[str, Any], events: list[dict[str, Any]]) -> None:
    """
    Update `next_run[LAST_RUN_TIMESTAMP]` from the most recent event time.

    Prefers the enriched `_time` field (ISO string) and falls back to vendor
    `Event Time`. The computed timestamp is stored as epoch seconds. If no
    timestamps are present, the current time is used.

    Args:
        next_run: The next run metadata dictionary to update.
        events: The list of events collected in the current run.

    Returns:
        None
    """
    # Prefer enriched _time values, fallback to vendor 'Event Time'
    candidates: list[str] = [str(t) for e in events if (t := e.get("_time"))] or [
        str(t) for e in events if (t := e.get("Event Time"))
    ]
    latest_time_str: str | None = max(candidates) if candidates else None

    if latest_time_str is not None:
        latest_dt = arg_to_datetime(latest_time_str)
        if latest_dt:
            latest_epoch = int(latest_dt.timestamp())
            next_run[LAST_RUN_TIMESTAMP] = latest_epoch
            demisto.debug(
                f"[update_last_run_timestamp_from_events] set last_run from latest event: {latest_time_str} ({latest_epoch})"
            )
            return

    # Safe fallback: current time
    now_epoch_end = int(time.time())
    next_run[LAST_RUN_TIMESTAMP] = now_epoch_end
    demisto.debug(f"[update_last_run_timestamp_from_events] no event timestamps found; using now={now_epoch_end}")


def _fetch_analytics_pages_concurrently(
    client: "Client",
    analytics_name: str,
    effective_time_frame_minutes: int,
    overall_max_events: int,
    page_size: int,
    page_workers: int = 3,
) -> list[dict[str, Any]]:
    """
    Fetch events for a single analytics name using concurrent page requests.

    The function first fetches the first page to determine the server-reported
    `totalcount` and then fans out remaining offsets with a bounded thread pool.

    Args:
        client: The Saviynt EIC client.
        analytics_name: The analytics name (event type) to fetch.
        effective_time_frame_minutes: The effective time frame to query (in minutes).
        overall_max_events: The maximum total number of events to return.
        page_size: The per-request maximum number of results.
        page_workers: The maximum number of concurrent page requests (# of threads).

    Returns:
        list[dict[str, Any]]: The collected events.
    """
    # First page (no offset)
    demisto.debug(f"[_fetch_analytics_pages_concurrently] {analytics_name}: fetching first page")
    first_res = client.fetch_events(
        analytics_name=analytics_name,
        time_frame_minutes=effective_time_frame_minutes,
        max_results=page_size,
        offset=None,
    )
    results: list[dict[str, Any]] = first_res.get("results", []) or []
    total_count = int(first_res.get("totalcount", 0))
    collected = len(results)

    # Compute summary and decide whether to paginate
    max_needed = min(total_count, overall_max_events)
    remaining = max(0, max_needed - collected)
    remaining_offsets = math.ceil(remaining / page_size) if remaining > 0 else 0
    demisto.debug(
        f"[_fetch_analytics_pages_concurrently] {analytics_name}: "
        f"first_page_size={collected}, total_count_from_api={total_count}, "
        f"overall_max_events={overall_max_events}, request_page_size={page_size}, "
        f"remaining_offsets={remaining_offsets}"
    )
    if remaining == 0:
        return results

    # Build remaining offsets
    offsets = list(range(collected, max_needed, page_size))

    # Fan-out remaining pages
    demisto.debug(
        f"[_fetch_analytics_pages_concurrently] {analytics_name}: starting fan-out "
        f"with page_workers={page_workers}, offset_count={len(offsets)}"
    )
    with ThreadPoolExecutor(max_workers=page_workers, thread_name_prefix=f"saviynt-pager-{analytics_name}") as executor:
        future_to_offset = {
            executor.submit(
                client.fetch_events,
                analytics_name,
                effective_time_frame_minutes,
                page_size,
                offset,
            ): offset
            for offset in offsets
        }
        for future in as_completed(future_to_offset):
            offset = future_to_offset[future]
            try:
                response = future.result()
                page_results = response.get("results", []) or []
                results.extend(page_results)
                if len(results) >= overall_max_events:
                    demisto.debug(
                        f"[_fetch_analytics_pages_concurrently] {analytics_name}: reached overall max events at offset={offset}"
                    )
                    break
            except Exception as error:
                demisto.debug(
                    f"[_fetch_analytics_pages_concurrently] {analytics_name}: page fetch failed offset={offset} err={error}"
                )

    if len(results) > overall_max_events:
        results = results[:overall_max_events]
    demisto.debug(
        f"[_fetch_analytics_pages_concurrently] {analytics_name}: collected={len(results)} "
        f"(overall_max_events={overall_max_events})"
    )
    return results


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Test API connectivity and authentication.

    This command ensures a token can be obtained or refreshed successfully by
    performing a simple API request.

    Args:
        client: The Saviynt EIC client to use for the test.

    Returns:
        str: "ok" if the test succeeded, otherwise raises an exception.
    """
    try:
        # example fetch
        client.fetch_events(
            analytics_name=EVENT_TYPE_TO_FETCH,
            time_frame_minutes=1,
            max_results=1,
        )
    except Exception as e:
        if "Forbidden" in str(e) or "401" in str(e):
            raise DemistoException(f"Authorization Error: make sure Username and Password are correctly set. Error: {e}")
        else:
            raise DemistoException(f"Failed to fetch events. Error: {e}")
    return "ok"


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    max_events: int,
    time_frame_minutes: int | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetch events for the fixed analytics type defined by `EVENT_TYPE_TO_FETCH`.

    If `time_frame_minutes` is `None` (the `fetch-events` command), the function
    derives the effective time window from `last_run`. Otherwise, the provided
    value is used (e.g., for `saviynt-eic-get-events`).

    Args:
        client: The Saviynt EIC client to use for HTTP requests.
        last_run: The previous run metadata including the last timestamp and hashes.
        max_events: The maximum number of events to collect.
        time_frame_minutes: The time frame to query in minutes, or `None` to compute
            it from `last_run`.

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: A tuple of `(next_run, events)` where
        `next_run` is the metadata for the next run and `events` are the collected
        events after de-duplication and enrichment.
    """
    effective_time_frame_minutes = compute_effective_time_frame_minutes(time_frame_minutes, last_run)

    previous_run_event_hash_count = len(last_run.get(LAST_RUN_EVENT_HASHES, []))
    demisto.debug(
        f"[fetch_events] start: analytics={EVENT_TYPE_TO_FETCH}, max_events={max_events}, "
        f"time_frame_minutes_input={time_frame_minutes}, effective_time_frame_minutes={effective_time_frame_minutes}, "
        f"previous_run_event_hash_count={previous_run_event_hash_count}"
    )

    page_size = min(max_events, MAX_EVENTS_PER_REQUEST)

    demisto.debug(
        f"[fetch_events] concurrent pages for analytics_name={EVENT_TYPE_TO_FETCH} "
        f"time_frame_minutes={effective_time_frame_minutes} "
        f"request_page_size={page_size} overall_number_of_events_to_fetch={max_events}"
    )
    events = _fetch_analytics_pages_concurrently(
        client=client,
        analytics_name=EVENT_TYPE_TO_FETCH,
        effective_time_frame_minutes=effective_time_frame_minutes,
        overall_max_events=max_events,
        page_size=page_size,
    )
    demisto.debug(
        f"[fetch_events] {EVENT_TYPE_TO_FETCH}: collected={len(events)} for analytics_name={EVENT_TYPE_TO_FETCH} (concurrent)"
    )

    demisto.debug(f"[fetch_events] total events collected before dedup={len(events)}")
    # Deduplicate by comparing to previous run's hashes and persist only current run's hashes
    next_run, deduped_events = deduplicate_events(events, last_run)
    demisto.debug(f"[fetch_events] total events after dedup={len(deduped_events)}")

    # Enrich deduped events with _time for XDM mapping
    if deduped_events:
        add_time_to_events(deduped_events)
        demisto.debug("[fetch_events] added _time to deduplicated events")

    # Update last run timestamp at the end of fetch logic
    update_last_run_timestamp_from_events(next_run, deduped_events)
    return next_run, deduped_events


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    base_url = urljoin(params.get("url"), "/ECM/")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    credentials = params.get("credentials")
    max_events = int(params.get("max_fetch", MAX_EVENTS))

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            credentials=credentials,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "saviynt-eic-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            _, events = fetch_events(
                client=client,
                last_run={},
                max_events=arg_to_number(args.get("limit")) or MAX_EVENTS,
                time_frame_minutes=arg_to_number(args.get("time_frame")) or DEFAULT_FETCH_TIME_FRAME_MINUTES,
            )
            if should_push_events and events:
                demisto.debug(f"[saviynt-eic-get-events] Sending {len(events)} events to XSIAM")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            hr = tableToMarkdown(name="Saviynt EIC Events", t=events)
            return_results(CommandResults(readable_output=hr, raw_response=events))

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events=max_events,
                time_frame_minutes=None,
            )
            demisto.debug(f"[fetch-events] Sending {len(events)} events to XSIAM")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"[fetch-events] Setting next run to {next_run}.")

        else:
            raise NotImplementedError(f"Command '{command}' is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
