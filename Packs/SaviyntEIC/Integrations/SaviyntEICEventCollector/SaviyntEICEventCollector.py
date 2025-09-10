import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403
import urllib3
from typing import Any
import time
from datetime import datetime, timedelta

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "saviynt"
PRODUCT = "eic"
TOKEN_SAFETY_BUFFER = 30  # seconds to refresh token before actual expiry


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with Saviynt EIC API

    - Authentication:
      - Create token: POST /ECM/api/login
      - Refresh token: POST /ECM/oauth/access_token
    - Fetch audit logs:
      - POST /ECM/api/v5/fetchRuntimeControlsDataV2
    """

    def __init__(
        self,
        base_url: str,
        verify: bool = False,
        proxy: bool = False,
        credentials: dict[str, Any] | None = None,
    ):
        # Initialize BaseClient
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._headers: dict[str, str] = {}
        self._access_token: str = ""
        if credentials:
            try:
                token, _ = ensure_token(self, credentials)
                self._access_token = token
                self._headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
            except Exception as e:
                demisto.debug(f"Client init: failed to obtain access token: {e}")

    def update_access_token(self, credentials: dict[str, Any] | None = None) -> None:
        """Refresh/recreate access token and update default headers."""
        try:
            if not credentials:
                params = demisto.params()
                credentials = params.get("credentials") or {}
            token, _ = ensure_token(self, credentials or {})
            self._access_token = token
            self._headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        except Exception as e:
            demisto.debug(f"update_access_token failed: {e}")


    def create_access_token(self, username: str, password: str) -> dict[str, Any]:
        """Create an access token using credentials.

        Returns a dict with: access_token, refresh_token, expires_at (epoch seconds).
        """
        data = {
            "username": username,
            "password": password,
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
        expires_in = int(res.get("expires_in", 3600))
        now_epoch = int(time.time())
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": now_epoch + expires_in,
        }

    def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh an access token using the refresh token.

        Returns a dict with: access_token, refresh_token (if provided), expires_at (epoch seconds).
        """
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
        return {
            "access_token": access_token,
            "refresh_token": new_refresh,
            "expires_at": now_epoch + expires_in,
        }

    def fetch_events(
        self,
        access_token: str,
        analytics_name: str,
        time_frame_minutes: int,
        max_results: int,
        offset: int | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
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
                headers=headers,
                json_data=body,
                timeout=120,
            )
        except Exception as e:
            # Attempt one retry on auth failure
            if any(x in str(e) for x in ("401", "Forbidden", "invalid token", "expired")):
                demisto.debug("Access token may be invalid/expired. Attempting to refresh and retry fetch.")
                self.update_access_token()
                headers["Authorization"] = f"Bearer {self._access_token}"
                return self._http_request(
                    method="POST",
                    url_suffix="api/v5/fetchRuntimeControlsDataV2",
                    headers=headers,
                    json_data=body,
                    timeout=120,
                )
            raise


""" HELPER FUNCTIONS """


def ensure_token(client: Client, credentials: dict[str, str]) -> tuple[str, dict[str, Any]]:
    """Ensure a valid access token, using integration context to cache tokens.

    Returns:
        access_token (str), updated_context (dict)
    """
    context = demisto.getIntegrationContext() or {}
    token = context.get("token")
    refresh_token = context.get("refresh_token")
    expires_at = int(context.get("expires_at", 0))
    now_epoch = int(time.time())

    # If we have a token and it's still valid, return it
    if token and (now_epoch + TOKEN_SAFETY_BUFFER) < expires_at:
        return token, context

    username = credentials.get("identifier") or credentials.get("username") or ""
    password = credentials.get("password") or ""

    # Try refresh if possible
    if refresh_token:
        try:
            new_tokens = client.refresh_access_token(refresh_token)
            new_context = {
                "token": new_tokens["access_token"],
                "refresh_token": new_tokens.get("refresh_token", refresh_token),
                "expires_at": new_tokens["expires_at"],
            }
            demisto.setIntegrationContext(new_context)
            return new_context["token"], new_context
        except Exception as e:
            demisto.debug(f"Token refresh failed: {e}. Will try to create a new token.")

    # Fallback to create new token
    new_tokens = client.create_access_token(username, password)
    new_context = {
        "token": new_tokens["access_token"],
        "refresh_token": new_tokens.get("refresh_token", ""),
        "expires_at": new_tokens["expires_at"],
    }
    demisto.setIntegrationContext(new_context)
    return new_context["token"], new_context


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


def test_module(client: Client, params: dict[str, Any]) -> str:
    """Tests API connectivity and authentication by performing a lightweight token creation."""
    credentials = params.get("credentials") or {}
    try:
        token_info = client.create_access_token(
            username=credentials.get("identifier") or credentials.get("username"),
            password=credentials.get("password"),
        )
        if not token_info.get("access_token"):
            return "Authorization Error: access token not received"
    except Exception as e:
        if "Forbidden" in str(e) or "401" in str(e):
            return "Authorization Error: make sure Username and Password are correctly set"
        raise
    return "ok"


def command_get_events(
    client: Client,
    params: dict[str, Any],
    args: dict[str, Any],
) -> tuple[list[dict[str, Any]], CommandResults]:
    """Implements 'get-events' command."""
    credentials = params.get("credentials") or {}
    analytics_name = params.get("analytics_name")
    limit = int(args.get("limit", 50))
    time_frame = arg_to_number(args.get("time_frame"))  # minutes
    offset = arg_to_number(args.get("offset"))

    if time_frame is None:
        # default to 60 minutes back if not provided
        time_frame = 60

    access_token, _ = ensure_token(client, credentials)
    response = client.fetch_events(
        access_token=access_token,
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
    credentials = params.get("credentials") or {}
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

    access_token, _ = ensure_token(client, credentials)
    response = client.fetch_events(
        access_token=access_token,
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

    base_url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # The Saviynt API base is /ECM; set base_url accordingly so url_suffix matches paths
    client = Client(
        base_url=urljoin(base_url, "/ECM/"),
        verify=verify_certificate,
        proxy=proxy,
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
