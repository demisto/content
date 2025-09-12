import hashlib
import json
import time
from datetime import datetime, timedelta
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
MAX_EVENTS_PER_FETCH = 50000
LAST_RUN_EVENT_HASHES = "recent_event_hashes"

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
            timeout=60,
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
        # Some systems may also return a new refresh_token; fall back to existing one
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
        Ensure a valid access token using the integration context cache.
        If force_refresh is True, attempt a refresh (or create) regardless of current cache state.
        Sets self._headers and updates integration context.
        - If no integration context is found, create a new access token.
        - If the access token is expired or is about to expire, refresh it using refresh token.
        """
        try:
            if context := demisto.getIntegrationContext():
                now_epoch = int(time.time())
                token = context.get("token")
                refresh_token = context.get("refresh_token")
                expires_at = int(context.get("expires_at", 0))

                if not force_refresh and token and (now_epoch + TOKEN_SAFETY_BUFFER) < expires_at:
                    demisto.debug(f"[Client.obtain_token] using cached token (expires_at={expires_at})")
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
        # Ensure headers/token are ready
        self.obtain_token()
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
                timeout=120,
            )
        except Exception as e:
            # Attempt one retry on auth failure
            if any(x in str(e) for x in ("401", "Forbidden", "invalid token", "expired")):
                demisto.debug("Access token may be invalid/expired. Attempting to refresh and retry fetch.")
                # Force refresh token and retry
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


def add_time_to_events(events: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """
    Adds the '_time' key to events based on their creation or occurrence timestamp.

    Args:
        events (list[dict[str, Any]] | None): A list of events.
    """
    if events:
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
    except TypeError:
        payload = json.dumps(event_for_hash, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def deduplicate_events_previous_run_only(
    events: list[dict[str, Any]], last_run: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
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
        f"Dedup prev-run-only: input={len(events)}, output={len(deduplicated_events)}, "
        f"prev_cache={len(previous_run_hashes)}, next_cache={len(new_last_run[LAST_RUN_EVENT_HASHES])}"
    )

    # Return order matches fetch_events: (next_run, events)
    return new_last_run, deduplicated_events


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication by ensuring a token can be obtained/refreshed."""
    try:
        # example fetch
        client.fetch_events(
            analytics_name="SIEMAuditLogs",
            time_frame_minutes=60,
            max_results=1,
        )
    except Exception as e:
        if "Forbidden" in str(e) or "401" in str(e):
            raise DemistoException("Authorization Error: make sure Username and Password are correctly set. Error: {e}")
        else:
            raise DemistoException(f"Failed to fetch events. Error: {e}")
    return "ok"


def fetch_events(
    client: Client,
    last_run: dict[str, Any],
    analytics_name_list: list[str],
    max_events: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch events for XSIAM ingest."""
    events = []

    for analytics_name in analytics_name_list:
        events_per_analytics_name = []

        response = client.fetch_events(
            analytics_name=analytics_name,
            time_frame_minutes=1,
            max_results=min(max_events, 10000),
            offset=None,
        )

        raw_results = response.get("results", [])
        total_count = response.get("totalcount", 0)
        events_per_analytics_name.extend(raw_results)

        while len(events_per_analytics_name) < total_count and len(events_per_analytics_name) < max_events:
            offset = len(events_per_analytics_name)
            response = client.fetch_events(
                analytics_name=analytics_name,
                time_frame_minutes=1,
                max_results=min(max_events, 10000),
                offset=offset,
            )
            raw_results = response.get("results", [])
            events_per_analytics_name.extend(raw_results)

        events.extend(events_per_analytics_name)

    # Deduplicate by comparing to previous run's hashes and persist only current run's hashes
    next_run, deduped_events = deduplicate_events_previous_run_only(events, last_run)

    # Enrich deduped events with _time for XDM mapping/visibility
    add_time_to_events(deduped_events)
    return next_run, deduped_events


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    base_url = urljoin(params.get("url"), "/ECM/")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    credentials = params.get("credentials")
    analytics_name_list = argToList(params.get("analytics_name", []))
    max_events = int(params.get("max_fetch", MAX_EVENTS_PER_FETCH))

    client = Client(
        base_url=base_url,
        verify=verify,
        proxy=proxy,
        credentials=credentials,
    )

    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "saviynt-eic-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events", False))
            _, events = fetch_events(
                client=client,
                last_run={},
                analytics_name_list=analytics_name_list,
                max_events=max_events,
            )
            if should_push_events and events:
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
            )
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
