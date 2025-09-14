import hashlib
import json
import math
import time
from datetime import UTC, datetime
from typing import Any

import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

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
        try:
            self.obtain_token()
        except Exception as e:
            raise DemistoException(f"[Client.__init__] failed to obtain access token: {e}")

    def _create_access_token(self):
        """Create an access token using self._credentials and update integration context and headers."""
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
        """Refresh an access token using the refresh token and update integration context and headers."""
        demisto.debug("[Client._refresh_access_token] attempting to refresh access token")
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        res = self._http_request(
            method="POST",
            url_suffix="oauth/access_token",
            data=data,
            timeout=60,
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
        Ensure a valid access token using the integration context cache, Sets request headers and updates integration context.
        - If force_refresh is True, attempt a refresh (or create) regardless of current cache state.
        - If no integration context is found, create a new access token.
        - If the access token is expired or is about to expire, refresh it using refresh token.
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
            analytics_name: event type to fetch (e.g., "SIEMAuditLogs").
            time_frame_minutes: Time frame in minutes to fetch events from.
            max_results: Maximum number of results to request in this call (capped by server to 10,000).
            offset: Optional paging offset.

        Returns:
            A dict JSON response from the API.

        Behavior:
            On authentication failure (401/Forbidden/invalid token), forces a token refresh and retries once.
        """
        body: dict[str, Any] = {
            "analyticsname": analytics_name,
            "attributes": {"timeFrame": str(time_frame_minutes)},
            "max": max_results,
        }
        if offset:
            body["offset"] = str(offset)

        try:
            return self._http_request(
                method="POST",
                url_suffix="api/v5/fetchRuntimeControlsDataV2",
                headers=self._headers,
                json_data=body,
            )
        except Exception as e:
            # Attempt one retry on auth failure
            if any(x in str(e) for x in ("401", "Forbidden", "invalid token")):
                demisto.debug(f"Access token may be invalid/expired. Attempting to refresh and retry fetch. Error: {e}")
                # Force refresh token and retry
                self.obtain_token(force_refresh=True)
                return self._http_request(
                    method="POST",
                    url_suffix="api/v5/fetchRuntimeControlsDataV2",
                    headers=self._headers,
                    json_data=body,
                )
            raise


""" HELPER FUNCTIONS """


def add_time_to_events(events: list[dict[str, Any]]):
    """
    Add the '_time' key to events based on their creation or occurrence timestamp.

    Args:
        events (list[dict[str, Any]]): A list of events.
    """
    for event in events:
        create_time = arg_to_datetime(arg=event.get("Event Time"))
        event["_time"] = create_time.strftime(DATE_FORMAT) if create_time else None


def generate_event_hash(event: dict[str, Any]) -> str:
    """
    Generate a stable SHA-256 hash for a single event from vendor content.
    Excludes integration-only/transient fields so the hash remains stable across runs.
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
    Compute the effective time frame in minutes to use in the fetch events request.

    - If time_frame_minutes is an int, it means the saviynt-eic-get-events command was called with a time frame.
    - If time_frame_minutes is None, it means the fetch-events command was called:
      - First fetch run: return DEFAULT_FETCH_TIME_FRAME_MINUTES.
      - Not first fetch run: If last_run has a valid LAST_RUN_TIMESTAMP, compute minutes between now (UTC) and that timestamp
        using datetime arithmetic.
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
    Previous-run-only policy:
    - Drop events whose hashes appeared in the immediately previous run.
    - Persist only this run's unique hashes to lastRun for the next fetch.
    Also deduplicates within the same run.
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
    Update next_run[LAST_RUN_TIMESTAMP] based on the most recent event timestamp.

    Prefers the enriched "_time" field (ISO string), falls back to vendor "Event Time".
    Stores the timestamp as epoch seconds. If no timestamps exist, falls back to current time.
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


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication by ensuring a token can be obtained/refreshed."""
    try:
        # example fetch
        client.fetch_events(
            analytics_name="SIEMAuditLogs",
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
    analytics_name_list: list[str],
    max_events: int,
    time_frame_minutes: int | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch events for XSIAM ingest.

    If time_frame_minutes is None, the function will compute it based on last_run timestamp:
    - First run (no timestamp): use DEFAULT_FETCH_TIME_FRAME_MINUTES
    - Subsequent runs: compute minutes between now and last_run timestamp (ceil to minutes, min 1)
    """
    effective_time_frame_minutes = compute_effective_time_frame_minutes(time_frame_minutes, last_run)

    previous_run_event_hash_count = len(last_run.get(LAST_RUN_EVENT_HASHES, []))
    demisto.debug(
        f"[fetch_events] start: analytics={analytics_name_list}, max_events={max_events}, "
        f"time_frame_minutes_input={time_frame_minutes}, effective_time_frame_minutes={effective_time_frame_minutes}, "
        f"previous_run_event_hash_count={previous_run_event_hash_count}"
    )

    events = []

    for analytics_name in analytics_name_list:
        events_per_analytics_name = []
        collected_count = 0  # total number of events collected so far
        max_results = min(max_events, MAX_EVENTS_PER_REQUEST)

        demisto.debug(
            f"[fetch_events] fetching analytics_name={analytics_name} offset=None "
            f"time_frame_minutes={effective_time_frame_minutes}"
        )
        response = client.fetch_events(
            analytics_name=analytics_name,
            time_frame_minutes=effective_time_frame_minutes,
            max_results=max_results,
            offset=None,
        )

        raw_results = response.get("results", [])
        # total number of available events in the time frame, provided by the API
        total_count = int(response.get("totalcount", 0))
        demisto.debug(f"[fetch_events] {analytics_name}: initial_page_size={len(raw_results)} total_count={total_count}")

        events_per_analytics_name.extend(raw_results)
        collected_count += len(raw_results)

        while collected_count < total_count and collected_count < max_events:
            offset = collected_count
            demisto.debug(f"[fetch_events] {analytics_name}: paginating offset={offset} current_collected={collected_count}")
            response = client.fetch_events(
                analytics_name=analytics_name,
                time_frame_minutes=effective_time_frame_minutes,
                max_results=max_results,
                offset=offset,
            )
            raw_results = response.get("results", [])
            page_batch_size = len(raw_results)
            demisto.debug(
                f"[fetch_events] {analytics_name}: page_batch_size={page_batch_size} total collected so far={collected_count + page_batch_size}"  # noqa: E501
            )
            events_per_analytics_name.extend(raw_results)
            collected_count += page_batch_size

        demisto.debug(f"[fetch_events] {analytics_name}: finished collection. total collected={collected_count}")
        events.extend(events_per_analytics_name)

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
    analytics_name_list = argToList(params.get("analytics_name", []))
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
                analytics_name_list=analytics_name_list,
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
                analytics_name_list=analytics_name_list,
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
