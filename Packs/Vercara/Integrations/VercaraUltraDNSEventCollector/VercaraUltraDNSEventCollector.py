import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Vercara UltraDNS Event Collector (XSIAM)

This integration fetches events (e.g., audit logs) from Vercara UltraDNS into Cortex XSIAM.
The code is modeled after standard Event Collector patterns as shown in existing collectors in the repository.

Note: API paths and field names may require adjustment based on the UltraDNS API you target. Use the
"events_endpoint" parameter to override the default path.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin

VENDOR = "Vercara"
PRODUCT = "UltraDNS"

# Default assumptions. Adjust based on the concrete API once confirmed.
DEFAULT_EVENTS_ENDPOINT = "/v2/report/auditlogs"
TIME_FIELD = "timestamp"  # ISO8601 string preferred, adjust if epoch or different field name
XSIAM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        api_token: str,
        events_endpoint: Optional[str] = None,
        verify: bool = True,
        proxy: bool = False,
        timeout: int = 60,
    ):
        headers = {
            "Content-Type": "application/json",
            # Adjust to the correct header format when confirmed. Many APIs use Bearer tokens.
            "Authorization": f"Bearer {api_token}",
        }
        super().__init__(
            base_url=base_url.rstrip("/") + "/",
            verify=verify,
            proxy=proxy,
            ok_codes=(200, 201, 202, 204),
            headers=headers,
            timeout=timeout,
        )
        self.events_endpoint = (events_endpoint or DEFAULT_EVENTS_ENDPOINT).lstrip("/")

    def get_events(
        self,
        start_iso: str,
        limit: int = 1000,
        page: Optional[int] = None,
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve events from UltraDNS.

        start_iso: ISO8601 string for the start time. Some APIs expect end, page, page_size, etc.
        limit: page size or max results depending on the API semantics.
        page: page index if supported.
        extra_params: additional raw params for flexibility.
        """
        params: Dict[str, Any] = {
            # These parameter names are placeholders and may need to be adapted to the real API.
            # If the API expects epoch, convert before passing.
            "start": start_iso,
            "page_size": limit,
        }
        if page is not None:
            params["page"] = page
        if extra_params:
            params.update(extra_params)

        return self._http_request(
            method="GET",
            url_suffix=self.events_endpoint,
            params=params,
        )


def to_xsiam_time(ts: float) -> str:
    return timestamp_to_datestring(ts * 1000, is_utc=True)


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure each event carries a _time suitable for XSIAM ingestion.
    """
    try:
        if TIME_FIELD in event and isinstance(event[TIME_FIELD], str):
            # Try ISO8601 parse
            dt = arg_to_datetime(event[TIME_FIELD])
            if dt:
                event["_time"] = timestamp_to_datestring(dt.timestamp() * 1000, is_utc=True)
            else:
                # Fallback to now
                event["_time"] = timestamp_to_datestring(datetime.utcnow().timestamp() * 1000, is_utc=True)
        elif TIME_FIELD in event and isinstance(event[TIME_FIELD], (int, float)):
            event["_time"] = to_xsiam_time(float(event[TIME_FIELD]))
        else:
            event["_time"] = timestamp_to_datestring(datetime.utcnow().timestamp() * 1000, is_utc=True)
    except Exception as e:
        demisto.debug(f"Failed to set _time for event. Error: {e!s}. Event: {event!r}")
        event["_time"] = timestamp_to_datestring(datetime.utcnow().timestamp() * 1000, is_utc=True)
    return event


def module_test(client: Client) -> str:
    """Test connectivity by performing a minimal fetch with a small window."""
    # Use a very small time window to minimize data
    now = datetime.utcnow()
    start = now - timedelta(minutes=5)
    start_iso = start.replace(microsecond=0).isoformat() + "Z"

    client.get_events(start_iso=start_iso, limit=1)
    return "ok"


def vercara_ultradns_get_events_command(client: Client, should_push_events: bool, first_fetch: datetime, fetch_limit: int) -> CommandResults:
    start_iso = first_fetch.replace(microsecond=0).isoformat() + "Z"
    raw = client.get_events(start_iso=start_iso, limit=fetch_limit)

    # Heuristics to find events list. Adjust keys once API is confirmed.
    events: List[Dict[str, Any]] = []
    if isinstance(raw, dict):
        for key in ("events", "results", "data", "audits", "items"):
            if key in raw and isinstance(raw[key], list):
                events = raw[key]  # type: ignore
                break
        if not events:
            # Sometimes the entire response is already the list
            if all(isinstance(v, dict) for v in raw.values()):
                # No obvious list container; treat response as single event
                events = [raw]  # type: ignore
    elif isinstance(raw, list):
        events = raw  # type: ignore

    parsed = [normalize_event(ev) for ev in events]

    md = tableToMarkdown(
        f"Vercara UltraDNS events (showing up to {len(parsed)})",
        parsed[:min(len(parsed), 50)],
    )

    if should_push_events and parsed:
        send_events_to_xsiam(parsed, vendor=VENDOR, product=PRODUCT)

    return CommandResults(
        readable_output=md,
        outputs_prefix=f"{VENDOR}.{PRODUCT}.Events",
        outputs_key_field="id",
        outputs=events,
    )


def fetch_events(client: Client, fetch_limit: int) -> None:
    last_run = demisto.getLastRun() or {}
    is_first = not bool(last_run)

    if is_first:
        first_fetch: datetime = arg_to_datetime(demisto.params().get("first_fetch", "3 days"))  # type: ignore
        start_iso = first_fetch.replace(microsecond=0).isoformat() + "Z"
        last_seen_ts = 0.0
    else:
        start_iso = last_run.get("next_since")  # type: ignore
        last_seen_ts = float(last_run.get("last_seen_ts", 0.0))

    demisto.debug(f"Fetching events since {start_iso}")
    raw = client.get_events(start_iso=start_iso, limit=fetch_limit)

    events: List[Dict[str, Any]] = []
    if isinstance(raw, dict):
        for key in ("events", "results", "data", "audits", "items"):
            if key in raw and isinstance(raw[key], list):
                events = raw[key]  # type: ignore
                break
        if not events and raw:
            events = [raw]  # type: ignore
    elif isinstance(raw, list):
        events = raw  # type: ignore

    parsed: List[Dict[str, Any]] = []
    max_seen_ts = last_seen_ts

    for ev in events:
        pev = normalize_event(ev)
        parsed.append(pev)
        # Update max seen timestamp if possible
        try:
            if TIME_FIELD in ev:
                if isinstance(ev[TIME_FIELD], str):
                    dt = arg_to_datetime(ev[TIME_FIELD])
                    if dt:
                        max_seen_ts = max(max_seen_ts, dt.timestamp())
                elif isinstance(ev[TIME_FIELD], (int, float)):
                    max_seen_ts = max(max_seen_ts, float(ev[TIME_FIELD]))
        except Exception as e:
            demisto.debug(f"Failed to parse event time for cursor: {e!s}")

    if parsed:
        send_events_to_xsiam(parsed, vendor=VENDOR, product=PRODUCT)

    # Inclusive time windows are common; advance by a small delta
    next_since_dt = datetime.utcfromtimestamp(max_seen_ts) + timedelta(seconds=1) if max_seen_ts > 0 else arg_to_datetime(demisto.params().get("first_fetch", "3 days"))  # type: ignore
    next_since = next_since_dt.replace(microsecond=0).isoformat() + "Z" if next_since_dt else start_iso

    demisto.setLastRun({
        "next_since": next_since,
        "last_seen_ts": max_seen_ts,
    })


def main() -> None:  # pragma: no cover
    params = demisto.params()
    url = params.get("url", "").strip()
    token = params.get("credentials", {}).get("password", "")
    events_endpoint = params.get("events_endpoint")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    cmd = demisto.command()
    args = demisto.args()

    client = Client(
        base_url=url,
        api_token=token,
        events_endpoint=events_endpoint,
        verify=verify,
        proxy=proxy,
    )

    try:
        if cmd == "test-module":
            result = module_test(client)
            return_results(result)

        elif cmd == "fetch-events":
            fetch_events(client, fetch_limit)
        else:
            raise NotImplementedError(f"Command '{cmd}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {cmd} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
