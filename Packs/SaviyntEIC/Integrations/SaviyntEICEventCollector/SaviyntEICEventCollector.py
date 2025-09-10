import time
from ast import Raise
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
EVENT_TYPES = {"siem_audit_logs": "SIEMAuditLogs"}

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
            "username": self._credentials["username"],
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
        if offset is not None:
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


def normalize_events(raw_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Optionally normalize/flatten event fields and add _time from 'Event Time'."""
    events: list[dict[str, Any]] = []
    for r in raw_results:
        ev = dict(r)  # shallow copy
        # Add _time from 'Event Time'
        event_time = ev.get("Event Time") or ev.get("event_time")
        dt = arg_to_datetime(event_time) if event_time else None
        ev["_time"] = dt.strftime(DATE_FORMAT) if dt else None
        # keep original keys; optionally derive common ones
        ev.setdefault("vendor", VENDOR)
        ev.setdefault("product", PRODUCT)
        events.append(ev)
    return events


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication by ensuring a token can be obtained/refreshed."""
    try:
        # example fetch
        client.fetch_events(
            analytics_name=EVENT_TYPES["siem_audit_logs"],
            time_frame_minutes=60,
            max_results=1,
        )
    except Exception as e:
        if "Forbidden" in str(e) or "401" in str(e):
            raise DemistoException("Authorization Error: make sure Username and Password are correctly set. Error: {e}")
        else:
            raise DemistoException(f"Failed to fetch events. Error: {e}")
    return "ok"


def command_get_events(
    client: Client,
    params: dict[str, Any],
    args: dict[str, Any],
) -> tuple[list[dict[str, Any]], CommandResults]:
    """Implements 'get-events' command."""
    analytics_name = params.get("analytics_name")
    limit = int(args.get("limit", 50))
    time_frame = arg_to_number(args.get("time_frame"))  # minutes
    offset = arg_to_number(args.get("offset"))

    if time_frame is None:
        # default to 60 minutes back if not provided
        time_frame = 60

    response = client.fetch_events(
        analytics_name=analytics_name,
        time_frame_minutes=int(time_frame),
        max_results=min(limit, 10000),
        offset=int(offset) if offset is not None else None,
    )

    raw_results = response.get("results", []) if isinstance(response, dict) else []
    events = normalize_events(raw_results)
    hr = tableToMarkdown(name="Saviynt EIC Events", t=events[:50])
    return events, CommandResults(readable_output=hr, raw_response=response)


def fetch_events(
    client: Client,
    params: dict[str, Any],
    last_run: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch events for XSIAM ingest.

    Strategy: compute time frame in minutes from last_run time to now; default from 'first_fetch'.
    """
    analytics_name = params.get("analytics_name")
    first_fetch = params.get("first_fetch", "3 days")
    max_events_per_fetch = int(params.get("max_events_per_fetch", 10000))

    # Determine the starting point
    last_event_time_str = last_run.get("last_event_time")
    if last_event_time_str:
        start_dt = arg_to_datetime(last_event_time_str)
    else:
        # parse relative time to datetime
        start_dt, _ = parse_date_range(first_fetch, to_time_zone="UTC", utc=True)

    now_dt = datetime.utcnow()
    if not start_dt:
        # fallback to 60 minutes
        start_dt = now_dt - timedelta(minutes=60)

    # compute minutes difference; ensure at least 1 minute
    delta_minutes = max(1, int((now_dt - start_dt).total_seconds() // 60))

    response = client.fetch_events(
        analytics_name=analytics_name,
        time_frame_minutes=delta_minutes,
        max_results=min(max_events_per_fetch, 10000),
        offset=None,
    )

    raw_results = response.get("results", []) if isinstance(response, dict) else []
    events = normalize_events(raw_results)

    # Set next run slightly overlapping by 1 minute to avoid misses
    next_time = (now_dt - timedelta(minutes=1)).strftime(DATE_FORMAT)
    next_run = {"last_event_time": next_time}
    return next_run, events


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # The Saviynt API base is /ECM; set base_url accordingly so url_suffix matches paths
    client = Client(
        base_url=urljoin(params.get("url"), "/ECM/"),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        credentials=params.get("credentials"),
    )

    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            result = test_module(client, params)
            return_results(result)

        elif command == "get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            events, results = command_get_events(client, params, args)
            return_results(results)
            if should_push_events:
                # Add _time to events and send
                for ev in events:
                    if "_time" not in ev or not ev["_time"]:
                        ev["_time"] = datetime.utcnow().strftime(DATE_FORMAT)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_events(client=client, params=params, last_run=last_run)
            for ev in events:
                if "_time" not in ev or not ev["_time"]:
                    ev["_time"] = datetime.utcnow().strftime(DATE_FORMAT)
            demisto.debug(f"Sending {len(events)} events to XSIAM.")
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
