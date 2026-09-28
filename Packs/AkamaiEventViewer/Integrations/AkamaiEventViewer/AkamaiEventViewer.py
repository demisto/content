import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime, timedelta, UTC
from math import ceil
from typing import Any
from urllib.parse import parse_qs, urlparse

from akamai.edgegrid import EdgeGridAuth

""" CONSTANTS """

VENDOR = "akamai"
PRODUCT = "event_viewer"
API_BASE_PATH = "/event-viewer-api/v1"
API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"  # The API accepts second precision without a timezone (UTC assumed).
PAGE_SIZE = 50  # Maximum page size for application/json.
MAX_CALLS_PER_FETCH = 10
MAX_EVENTS_PER_FETCH = PAGE_SIZE * MAX_CALLS_PER_FETCH
DEFAULT_GET_EVENTS_LIMIT = 50
FIRST_FETCH_LOOKBACK = timedelta(minutes=1)
ALL_EVENT_TYPES = "all"

""" CLIENT CLASS """


class Client(BaseClient):
    """Akamai Event Viewer API client. Every request is signed by EdgeGridAuth."""

    def __init__(self, base_url: str, verify: bool, proxy: bool, auth: EdgeGridAuth, account_switch_key: str | None = None):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth, headers={"Accept": "application/json"})
        self.account_switch_key = account_switch_key

    def _params(self, **params: Any) -> dict:
        return assign_params(accountSwitchKey=self.account_switch_key, **params)

    def get_events(self, start: str, end: str, event_type_id: str | None = None, before_event_id: str | None = None) -> dict:
        params = self._params(limit=PAGE_SIZE, start=start, end=end, eventTypeId=event_type_id, beforeEventId=before_event_id)
        return self._http_request("GET", "/events", params=params)

    def get_event_types(self) -> list[dict]:
        return self._http_request("GET", "/event-types", params=self._params())


""" HELPER FUNCTIONS """


def format_time(value: datetime) -> str:
    return value.strftime(API_DATE_FORMAT)


def boundary_start(window_end: str) -> str:
    """The next window starts one second before the previous window end, so events at the edge are never lost."""
    return format_time(datetime.strptime(window_end, API_DATE_FORMAT) - timedelta(seconds=1))


def get_next_cursor(links: list[dict]) -> str | None:
    """Extract the beforeEventId cursor from the `rel: next` HATEOAS link."""
    for link in links:
        if link.get("rel") == "next":
            cursors = parse_qs(urlparse(link.get("href", "")).query).get("beforeEventId")
            return cursors[0] if cursors else None
    return None


def add_time_to_events(events: list[dict]) -> None:
    for event in events:
        event["_time"] = event.get("eventTime")


def resolve_event_type_ids(client: Client, names: list[str], cache: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """Map event type names (case-insensitive) to IDs. Only calls the API when the selection changes."""
    lowered = list(dict.fromkeys(name.strip().lower() for name in names if name.strip()))
    if ALL_EVENT_TYPES in lowered:
        return [], {}
    if len(lowered) > MAX_CALLS_PER_FETCH:
        raise DemistoException(f"At most {MAX_CALLS_PER_FETCH} event type names can be selected.")
    if all(name in cache for name in lowered):
        return [cache[name] for name in lowered], {name: cache[name] for name in lowered}

    available = {str(item.get("eventTypeName", "")).lower(): str(item.get("eventTypeId")) for item in client.get_event_types()}
    unknown = [name for name in lowered if name not in available]
    if unknown:
        raise DemistoException(f"Unknown event type name(s): {', '.join(unknown)}.")
    new_cache = {name: available[name] for name in lowered}
    return list(new_cache.values()), new_cache


def collect_events(
    client: Client,
    event_type_id: str | None,
    start: str,
    end: str,
    limit: int,
    max_calls: int,
    before_event_id: str | None = None,
) -> tuple[list[dict], str | None]:
    """Page newest-first through [start, end].

    Returns the collected events and the cursor to resume from, or None when the window is exhausted.
    """
    events: list[dict] = []
    for _ in range(max_calls):
        response = client.get_events(start, end, event_type_id, before_event_id)
        page = response.get("events") or []
        next_cursor = get_next_cursor(response.get("links") or [])
        for index, event in enumerate(page):
            events.append(event)
            if len(events) >= limit:
                is_last_on_page = index == len(page) - 1
                return events, (next_cursor if is_last_on_page else event.get("eventId"))
        if not page or not next_cursor:
            return events, None
        before_event_id = next_cursor
    return events, before_event_id


def next_window(state: dict, now: datetime) -> dict:
    """Resume the in-progress window, or open a new one from the previous window end up to now."""
    if state.get("before_event_id"):
        return state
    start = boundary_start(state["window_end"]) if state.get("window_end") else format_time(now - FIRST_FETCH_LOOKBACK)
    return {
        "window_start": start,
        "window_end": format_time(now),
        "before_event_id": None,
        "skip_ids": state.get("boundary_ids", []),
        "boundary_ids": [],
    }


def fetch_event_type(
    client: Client, event_type_id: str | None, state: dict, now: datetime, limit: int, max_calls: int
) -> tuple[list[dict], dict]:
    window = next_window(state, now)
    raw_events, cursor = collect_events(
        client, event_type_id, window["window_start"], window["window_end"], limit, max_calls, window["before_event_id"]
    )
    threshold = boundary_start(window["window_end"])
    new_boundary_ids = [event.get("eventId") for event in raw_events if str(event.get("eventTime", ""))[:19] >= threshold]
    skip_ids = set(window["skip_ids"])
    events = [event for event in raw_events if event.get("eventId") not in skip_ids]
    return events, window | {"before_event_id": cursor, "boundary_ids": window["boundary_ids"] + new_boundary_ids}


""" COMMAND FUNCTIONS """


def test_module(client: Client, event_type_names: list[str], max_events_param: Any) -> str:
    parse_limit(max_events_param, MAX_EVENTS_PER_FETCH, "max_events_per_fetch")
    resolve_event_type_ids(client, event_type_names, {})
    now = datetime.now(UTC)
    client.get_events(format_time(now - FIRST_FETCH_LOOKBACK), format_time(now))
    return "ok"


def fetch_events(
    client: Client, last_run: dict, event_type_ids: list[str], max_events: int, now: datetime
) -> tuple[list[dict], dict]:
    """The 10-call budget is shared across event types: floor(calls / N) calls each."""
    keys = event_type_ids or [ALL_EVENT_TYPES]
    max_calls = max(1, ceil(max_events / PAGE_SIZE) // len(keys))
    limit = min(max(1, max_events // len(keys)), max_calls * PAGE_SIZE)
    previous_windows = last_run.get("windows", {})
    events: list[dict] = []
    windows: dict[str, dict] = {}
    for key in keys:
        event_type_id = None if key == ALL_EVENT_TYPES else key
        type_events, windows[key] = fetch_event_type(client, event_type_id, previous_windows.get(key, {}), now, limit, max_calls)
        demisto.debug(f"Event type {key}: fetched {len(type_events)} events, window state {windows[key]}")
        events.extend(type_events)
    return events, last_run | {"windows": windows}


def fetch_events_command(client: Client, event_type_names: list[str], max_events: int) -> None:
    last_run: dict = demisto.getLastRun() or {}
    cached_ids: dict[str, str] = last_run.get("event_type_ids") or {}
    event_type_ids, cache = resolve_event_type_ids(client, event_type_names, cached_ids)
    events, next_run = fetch_events(client, last_run, event_type_ids, max_events, datetime.now(UTC))
    add_time_to_events(events)
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.setLastRun(next_run | {"event_type_ids": cache})


def get_events_command(client: Client, args: dict, event_type_names: list[str]) -> CommandResults:
    limit = parse_limit(args.get("limit"), DEFAULT_GET_EVENTS_LIMIT, "limit")
    now = datetime.now(UTC)
    start = arg_to_datetime(args.get("start_time")) or now - FIRST_FETCH_LOOKBACK
    end = arg_to_datetime(args.get("end_time")) or now
    event_type_ids, _ = resolve_event_type_ids(client, event_type_names, {})
    keys: list[str | None] = list(event_type_ids) or [None]
    per_type_limit = max(1, limit // len(keys))
    events: list[dict] = []
    for event_type_id in keys:
        type_events, _ = collect_events(
            client, event_type_id, format_time(start), format_time(end), per_type_limit, ceil(per_type_limit / PAGE_SIZE)
        )
        events.extend(type_events)
    add_time_to_events(events)
    if argToBoolean(args.get("should_push_events", False)):
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    return CommandResults(readable_output=events_to_markdown(events), raw_response=events)


def events_to_markdown(events: list[dict]) -> str:
    rows = [
        {
            "Event ID": event.get("eventId"),
            "Event Time": event.get("eventTime"),
            "Event Type": (event.get("eventType") or {}).get("eventTypeName"),
            "Event Name": ((event.get("eventType") or {}).get("eventDefinition") or {}).get("eventName"),
            "Username": event.get("username"),
        }
        for event in events
    ]
    return tableToMarkdown("Akamai Event Viewer Events", rows, removeNull=True)


def parse_limit(value: Any, default: int, name: str) -> int:
    parsed = arg_to_number(value, arg_name=name)
    limit = default if parsed is None else parsed
    if not 0 < limit <= MAX_EVENTS_PER_FETCH:
        raise DemistoException(f"{name} must be between 1 and {MAX_EVENTS_PER_FETCH}.")
    return limit


""" MAIN FUNCTION """


def build_client(params: dict) -> Client:
    return Client(
        base_url=urljoin(params.get("host", ""), API_BASE_PATH),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        auth=EdgeGridAuth(
            client_token=params.get("clienttoken_creds", {}).get("password"),
            access_token=params.get("accesstoken_creds", {}).get("password"),
            client_secret=params.get("clientsecret_creds", {}).get("password"),
        ),
        account_switch_key=params.get("account_switch_key") or None,
    )


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = build_client(params)
        event_type_names = argToList(params.get("event_type_names"))
        if command == "test-module":
            return_results(test_module(client, event_type_names, params.get("max_events_per_fetch")))
        elif command == "fetch-events":
            max_events = parse_limit(params.get("max_events_per_fetch"), MAX_EVENTS_PER_FETCH, "max_events_per_fetch")
            fetch_events_command(client, event_type_names, max_events)
        elif command == "akamai-event-viewer-get-events":
            return_results(get_events_command(client, demisto.args(), event_type_names))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
