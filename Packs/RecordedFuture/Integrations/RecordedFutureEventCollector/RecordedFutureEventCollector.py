from CommonServerPython import *
import json
import time
import urllib3
import requests
from datetime import UTC
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
BASE_URL = "https://api.recordedfuture.com/gw/xsiam"
STATUS_TO_RETRY = [500, 501, 502, 503, 504]
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "Recorded Future"
PRODUCT = "Intelligence Cloud"

# XSUP-80326 debug build constants
DEBUG_PREFIX = "[XSUP-80326 DEBUG]"
CURSOR_MODE_LEGACY = "legacy"  # original behaviour: cursor taken from events[0]
CURSOR_MODE_NEWEST = "newest"  # candidate fix: cursor taken from the newest event in the response

# ---- Debug controls: set here and re-upload. No customer action is needed. ----
# Which cursor logic fetch-events uses. Both are always computed and logged; this only decides which one is saved.
DEBUG_CURSOR_MODE = CURSOR_MODE_LEGACY
# Optional one-time rewind, e.g. "2026-11-08T00:00:00Z". None = no rewind.
# Applied by the first fetch-events run after upload; that run then saves its own result as the last run, as usual.
# The applied value is remembered in the integration context, so it is not applied again on later runs.
# To rewind again, set a different value and re-upload.
DEBUG_FORCE_START_TIME: str | None = None
APPLIED_FORCE_START_CONTEXT_KEY = "xsup_80326_applied_force_start_time"
# When True, every fetch-events run makes a few extra read-only /alert/search calls around a second taken from the
# response, and logs whether the API honours second precision (start and end) in the 'triggered' filter.
# These calls only log; they never change what is sent to XSIAM or what is saved as the last run.
# Answered by upload 2 (open-ended start honours seconds, closed ranges are ignored), so it is off now.
DEBUG_PROBE_SECONDS = False
# Kept short so the probe window stays under the API's 50-alert response cap.
PROBE_WINDOW_SECONDS = 10
SECONDS_FORMAT = "%Y-%m-%dT%H:%M:%S"
# Upload 3: request-shape probe (limit / from / direction / orderby / triggered formats). Read-only, logs only.
# Runs on the first fetch after upload, then at most once every DEBUG_REQUEST_PROBE_INTERVAL_MINUTES.
DEBUG_PROBE_REQUESTS = True
DEBUG_REQUEST_PROBE_INTERVAL_MINUTES = 15
# Bump to force the probe to run on the next fetch after a re-upload.
DEBUG_REQUEST_PROBE_VERSION = "upload3-v1"
REQUEST_PROBE_CONTEXT_KEY = "xsup_80326_request_probe"
# Responses with up to this many events log their full id list; bigger ones log the first/last ids only.
PROBE_FULL_IDS_MAX = 100
PROBE_EDGE_IDS = 10
# Accept error statuses in probes so we can log what the API says instead of raising.
PROBE_OK_CODES = (200, 400, 401, 403, 404, 405, 413, 422, 429, 500, 502, 503)
PROBE_REQUEST_TIMEOUT_SECONDS = 20
# Stop the probe if it has been running this long, so the fetch always has time to finish.
PROBE_TIME_BUDGET_SECONDS = 150

""" CLIENT CLASS """


class Client(BaseClient):
    def _call(self, url_suffix, **kwargs):
        request_kwargs = {
            "method": "get",
            "url_suffix": url_suffix,
            "timeout": 90,
            "retries": 3,
            "status_list_to_retry": STATUS_TO_RETRY,
        }
        request_kwargs.update(kwargs)

        return self._http_request(**request_kwargs)

    def test_connection(self) -> dict[str, Any]:
        """Check connection."""
        return self._call(url_suffix="/config/info")

    def get_alerts(self, params: dict = None) -> dict[str, Any]:
        """Get alerts."""
        return self._call(url_suffix="/alert/search", params=params)

    def get_alerts_raw(self, params: dict) -> requests.Response:
        """Debug only: returns the raw response (status, headers, final URL), without raising on error statuses."""
        return self._call(url_suffix="/alert/search", params=params, resp_type="response", ok_codes=PROBE_OK_CODES, retries=0)


""" DEBUG HELPERS (XSUP-80326) """


def debug_log(message: str) -> None:
    """Writes a prefixed diagnostic line so it is easy to filter in the server logs.

    Uses demisto.info (not demisto.debug) on purpose: info lines are forwarded to the tenant server log
    regardless of the instance log level, so the diagnostics are visible in Logs Explorer.
    """
    demisto.info(f"{DEBUG_PREFIX} {message}")


def summarize_events(events: list) -> list[dict]:
    """Returns a compact (id, triggered) view of the events, in the order the API returned them."""
    return [{"id": event.get("id"), "triggered": demisto.get(event, "log.triggered")} for event in events]


def get_response_order(events: list) -> str:
    """Describes the order of the 'triggered' values in the API response: asc, desc, unsorted or n/a."""
    triggered_values = [demisto.get(event, "log.triggered") or "" for event in events]
    if len(triggered_values) < 2:
        return "n/a"
    if triggered_values == sorted(triggered_values):
        return "asc"
    if triggered_values == sorted(triggered_values, reverse=True):
        return "desc"
    return "unsorted"


def log_response_diagnostics(request_params: dict, response: dict, events: list) -> None:
    """Logs everything needed to understand a single /alert/search response."""
    triggered_values = sorted(demisto.get(event, "log.triggered") or "" for event in events)
    debug_log(f"request params: {json.dumps(request_params)}")
    debug_log(f"response counts: {json.dumps(response.get('counts'))}, events returned: {len(events)}")
    debug_log(f"response order by log.triggered: {get_response_order(events)}")
    if events:
        debug_log(
            f"events[0].triggered={demisto.get(events[0], 'log.triggered')} "
            f"events[-1].triggered={demisto.get(events[-1], 'log.triggered')} "
            f"min.triggered={triggered_values[0]} max.triggered={triggered_values[-1]}"
        )
    debug_log(f"response events (id, triggered) in API order: {json.dumps(summarize_events(events))}")


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): RecordedFuture client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.test_connection()
        return_results("ok")
    except Exception as err:
        message = str(err)
        try:
            error = json.loads(str(err).split("\n")[1])
            if "fail" in error.get("result", {}).get("status", ""):
                message = error.get("result", {})["message"]
        except Exception:
            message = f"Unknown error. Please verify that the API URL and Token are correctly configured. RAW Error: {err}"
        raise DemistoException(f"Failed due to - {message}")


def get_events(client, params: dict) -> list:
    """
        Retrieves events using the RecordedFuture API.
    Args:
        client (Client): RecordedFuture client to use.
        params (dict): The params to send to the API, for example {'limit': '1000', 'triggered': '[start,end]'}.

    Returns:
        list: (list) of events that will be created in XSIAM.
    """

    result = client.get_alerts(params)
    events = result.get("data", [])
    counts = result.get("counts") or {}

    summary = (
        f"Request filter: {params.get('triggered', 'none')}\n"
        f"API counts: total={counts.get('total')} returned={counts.get('returned')} (events in response: {len(events)})\n"
        "The 'total' value is the number of alerts in Recorded Future that match the time range."
    )
    hr = summary + "\n\n" + tableToMarkdown(name="Test Event", t=events)
    return_results(CommandResults(readable_output=hr, raw_response=events))

    return events


def build_get_events_params(args: dict) -> dict:
    """Builds the /alert/search params for recorded-future-get-events from the command arguments.

    start_time / end_time accept any arg_to_datetime value ("2026-11-09T00:00:00Z", "3 days", ...).
    They are sent with second precision as triggered=[start,end]; an open side is left empty.
    """
    params: dict[str, Any] = {"limit": args.get("limit", 10)}
    start_time = arg_to_datetime(args.get("start_time"), arg_name="start_time")
    end_time = arg_to_datetime(args.get("end_time"), arg_name="end_time")
    if start_time or end_time:
        start = start_time.strftime(SECONDS_FORMAT) if start_time else ""
        end = end_time.strftime(SECONDS_FORMAT) if end_time else ""
        params.update({"triggered": f"[{start},{end}]", "orderby": "triggered", "direction": "asc"})
    return params


def summarize_probe(start: str, end: str, response: dict) -> dict:
    """Summarizes one probe response and checks that every returned event is inside [start, end] (second precision)."""
    events = response.get("data", [])
    triggered_seconds = sorted(get_triggered(event) for event in events)
    return {
        "filter": f"[{start},{end}]",
        "counts": response.get("counts"),
        "returned": len(events),
        "min_triggered": triggered_seconds[0] if triggered_seconds else None,
        "max_triggered": triggered_seconds[-1] if triggered_seconds else None,
        "all_ge_start": all(value >= start[:19] for value in triggered_seconds),
        "all_le_end": all(value <= end[:19] for value in triggered_seconds),
        "ids": [event.get("id") for event in events],
    }


def run_seconds_probe(client: Client, events: list) -> dict:
    """Checks whether the API honours second precision in the 'triggered' filter.

    Takes the oldest second T in the fetch response and asks for:
      A: [T, T+10s]      -> must include the events at second T
      B: [T+1s, T+10s]   -> must exclude the events at second T (start honoured at second precision)
      C: [T.500Z, T+10s] -> informational, shows whether milliseconds in the start are honoured
    Both A and B must return only events inside their window (start and end honoured).
    Read-only: the result is only logged.
    """
    anchor = min(get_triggered(event) for event in events)
    anchor_time = datetime.strptime(anchor, SECONDS_FORMAT)
    end = (anchor_time + timedelta(seconds=PROBE_WINDOW_SECONDS)).strftime(SECONDS_FORMAT)
    next_second = (anchor_time + timedelta(seconds=1)).strftime(SECONDS_FORMAT)
    ids_at_anchor = sorted({event.get("id") for event in events if get_triggered(event) == anchor})

    probes: dict[str, dict] = {}
    for name, start in (("A", anchor), ("B", next_second), ("C", f"{anchor}.500Z")):
        params = {"triggered": f"[{start},{end}]", "orderby": "triggered", "direction": "asc", "limit": 1000}
        try:
            probes[name] = summarize_probe(start, end, client.get_alerts(params))
        except Exception as error:  # a probe must never break the fetch
            probes[name] = {"filter": params["triggered"], "error": str(error)}
        debug_log(f"seconds probe {name}: {json.dumps(probes[name])}")

    verdict = evaluate_seconds_probe(ids_at_anchor, probes)
    debug_log(f"seconds probe verdict (anchor={anchor}, ids at anchor={ids_at_anchor}): {json.dumps(verdict)}")
    return verdict


def evaluate_seconds_probe(ids_at_anchor: list, probes: dict) -> dict:
    """Turns the probe summaries into yes/no answers."""
    probe_a, probe_b = probes.get("A", {}), probes.get("B", {})
    if "error" in probe_a or "error" in probe_b:
        return {"result": "inconclusive", "reason": "probe request failed (see probe lines)"}
    a_ids, b_ids = set(probe_a.get("ids", [])), set(probe_b.get("ids", []))
    return {
        "start_includes_anchor_second": all(event_id in a_ids for event_id in ids_at_anchor),
        "start_honours_seconds": not any(event_id in b_ids for event_id in ids_at_anchor) and probe_b.get("all_ge_start"),
        "end_bound_honoured": bool(probe_a.get("all_le_end") and probe_b.get("all_le_end")),
        # If returned hit the 50 cap, the window had more alerts than the API returns and the check may be partial.
        "hit_response_cap": max(probe_a.get("returned", 0), probe_b.get("returned", 0)) >= 50,
    }


def get_triggered(event: dict) -> str:
    """Get the 'triggered' value from an event without milliseconds since the API ignores them.

    Args:
        event (dict): The event from API.

    Returns:
        str: the "triggered" value.
    """
    if event:
        return event.get("log", {}).get("triggered", "").split(".")[0]
    return ""


def compute_next_run(events: list, limit: int, cursor_mode: str) -> dict:
    """Computes the next run object from the raw (unfiltered) API events.

    Args:
        events (list): The events as returned by the API (before filtering already-fetched IDs).
        limit (int): The limit used in the request.
        cursor_mode (str): 'legacy' takes the cursor from events[0] (original behaviour),
            'newest' takes it from the event with the latest 'triggered' value.

    Returns:
        dict: {"last_run_time": ..., "last_run_ids": [...]} or {} when there are no events.
    """
    if not events:
        return {}

    if cursor_mode == CURSOR_MODE_NEWEST:
        cursor_event = max(events, key=get_triggered)
    else:
        cursor_event = events[0]
    next_run_time = get_triggered(cursor_event)

    # We need the IDs of the events with the same trigger time as the cursor,
    # So that we can remove them in the next fetch, Since we are fetching from (including) this time.
    next_run_ids = {event.get("id") for event in events if get_triggered(event) == next_run_time}

    # In case all events were triggered at the same time and the limit equals their amount,
    # We should increase the next run time, Otherwise the fetch will get stuck at this time forever.
    if len(next_run_ids) == limit:
        next_run_time = (datetime.strptime(next_run_time, DATE_FORMAT) + timedelta(seconds=1)).strftime(DATE_FORMAT)

    return {"last_run_time": next_run_time, "last_run_ids": list(next_run_ids)}


def fetch_events(client: Client, **kwargs) -> tuple[list, dict]:
    """
    Args:
        client (Client): RecordedFuture client to use.
        kwargs: last_run (str), limit (int|str), cursor_mode (str, default 'legacy'),
            previous_last_run (dict, the stored last run object, used for debug diagnostics).

    Returns:
        list: (list) of events that will be created in XSIAM.
        dict: The lastRun object to save for next run.
    """
    limit = int(kwargs.get("limit"))  # type: ignore[arg-type]
    cursor_mode = kwargs.get("cursor_mode") or CURSOR_MODE_LEGACY
    previous_last_run = kwargs.get("previous_last_run")
    if previous_last_run is None:
        previous_last_run = demisto.getLastRun() or {}

    params = {
        "triggered": f"[{kwargs.get('last_run')},]",
        "orderby": "triggered",
        "direction": "asc",
        "limit": limit,
    }
    debug_log(f"cursor_mode={cursor_mode}, previous last run: {json.dumps(previous_last_run)}")
    response = client.get_alerts(params)
    events = response.get("data", [])
    log_response_diagnostics(params, response, events)

    next_run: dict = {}
    if events and DEBUG_PROBE_SECONDS:
        run_seconds_probe(client, events)
    if events:
        next_run = compute_next_run(events, limit, cursor_mode)
        debug_log(f"computed next run ({cursor_mode}): {json.dumps(next_run)}")
        # Show what the other mode would have produced, so a single run tells us whether the modes diverge.
        other_mode = CURSOR_MODE_NEWEST if cursor_mode == CURSOR_MODE_LEGACY else CURSOR_MODE_LEGACY
        debug_log(f"next run if cursor_mode={other_mode}: {json.dumps(compute_next_run(events, limit, other_mode))}")

        # Filter out events that have already been fetched.
        if last_run_event_ids := previous_last_run.get("last_run_ids"):
            demisto.info(f"this is the last_run_event_ids {last_run_event_ids}")
            events_before_filter = len(events)
            events = [event for event in events if event.get("id") not in last_run_event_ids]
            debug_log(f"filtered by last_run_ids: {events_before_filter} -> {len(events)} events")

        # Direct duplicate evidence: how many of the events we are about to send were already sent by the previous run.
        previous_sent_ids = set(previous_last_run.get("debug_sent_ids") or [])
        sent_ids = [event.get("id") for event in events]
        resent_ids = [event_id for event_id in sent_ids if event_id in previous_sent_ids]
        debug_log(
            f"overlap with previous run: {len(resent_ids)} of {len(sent_ids)} events were already sent by the previous run. "
            f"re-sent ids: {json.dumps(resent_ids)}"
        )
        next_run["debug_sent_ids"] = sent_ids
    else:
        debug_log("no events returned, last run will not be updated")

    return events, next_run


""" REQUEST-SHAPE PROBE (XSUP-80326, upload 3) """

V2_ALERT_SEARCH_URL = "https://api.recordedfuture.com/v2/alert/search"
INTERESTING_HEADER_PARTS = ("limit", "rate", "retry", "remaining", "x-", "content-length", "server", "via")


def extract_probe_events(body: Any) -> tuple[list, str]:
    """Returns (events, data_type). The gw endpoint returns data as a list, v2 returns data.results."""
    if not isinstance(body, dict):
        return [], type(body).__name__
    data = body.get("data")
    if isinstance(data, dict):
        return data.get("results") or [], "dict(results)"
    if isinstance(data, list):
        return data, "list"
    return [], type(data).__name__


def probe_event_triggered(event: dict) -> str:
    return (event.get("log") or {}).get("triggered") or event.get("triggered") or ""


def summarize_probe_ids(events: list) -> dict:
    ids = [event.get("id") for event in events]
    if len(ids) <= PROBE_FULL_IDS_MAX:
        return {"ids": ids}
    return {"first_ids": ids[:PROBE_EDGE_IDS], "last_ids": ids[-PROBE_EDGE_IDS:]}


def summarize_raw_probe(name: str, res: requests.Response, include_all_headers: bool) -> dict:
    """Builds a log-friendly summary of a raw probe response."""
    headers = {k: v for k, v in res.headers.items() if "cookie" not in k.lower() and "auth" not in k.lower()}
    if not include_all_headers:
        headers = {k: v for k, v in headers.items() if any(part in k.lower() for part in INTERESTING_HEADER_PARTS)}
    summary: dict[str, Any] = {
        "name": name,
        "url": res.url,
        "status": res.status_code,
        "elapsed_ms": int(res.elapsed.total_seconds() * 1000) if res.elapsed else None,
        "headers": headers,
    }
    try:
        body = res.json()
    except ValueError:
        summary["body_text"] = res.text[:500]
        return summary
    events, data_type = extract_probe_events(body)
    triggered = [probe_event_triggered(event) for event in events]
    summary.update(
        {
            "body_keys": list(body) if isinstance(body, dict) else None,
            "extra_top_level": {k: v for k, v in body.items() if k not in ("data", "counts")} if isinstance(body, dict) else None,
            "data_type": data_type,
            "counts": body.get("counts") if isinstance(body, dict) else None,
            "returned": len(events),
            "order": order_of(triggered),
            "first_triggered": triggered[0] if triggered else None,
            "last_triggered": triggered[-1] if triggered else None,
            "min_triggered": min(triggered) if triggered else None,
            "max_triggered": max(triggered) if triggered else None,
            **summarize_probe_ids(events),
        }
    )
    if res.status_code != 200:
        summary["body_text"] = res.text[:500]
    return summary


def order_of(values: list) -> str:
    if len(values) < 2:
        return "n/a"
    if values == sorted(values):
        return "asc"
    if values == sorted(values, reverse=True):
        return "desc"
    return "unsorted"


def build_request_probe_cases(start: str, end: str) -> list[tuple[str, dict | None, str | None]]:
    """All request shapes to try: (name, params, full_url). Exactly one of params/full_url is set.

    start/end are second-precision UTC strings (start = now-24h, end = now), so the windows hold far more than 50 alerts.
    """
    base: dict[str, Any] = {"triggered": f"[{start},]", "orderby": "triggered", "direction": "asc"}
    start_date, end_date = start[:10], end[:10]
    cases: list[tuple[str, dict | None, str | None]] = [
        # limit: is it honoured below 50, where is the cap, what happens above it
        ("limit_none", dict(base), None),
        *[(f"limit_{n}", {**base, "limit": n}, None) for n in (1, 10, 49, 50, 51, 100, 200, 500, 1000, 1001)],
        # paging: does 'from' (documented in the 2023 Postman collection) move the window
        *[(f"limit_50_from_{n}", {**base, "limit": 50, "from": n}, None) for n in (0, 50, 100)],
        *[(f"limit_10_from_{n}", {**base, "limit": 10, "from": n}, None) for n in (0, 10)],
        ("from_50_no_limit", {**base, "from": 50}, None),
        ("limit_50_offset_50", {**base, "limit": 50, "offset": 50}, None),
        # ordering
        ("desc_limit_50", {**base, "direction": "desc", "limit": 50}, None),
        ("desc_limit_10", {**base, "direction": "desc", "limit": 10}, None),
        ("no_direction_limit_50", {"triggered": base["triggered"], "orderby": "triggered", "limit": 50}, None),
        ("no_orderby_no_direction_limit_50", {"triggered": base["triggered"], "limit": 50}, None),
        ("direction_ASC_upper_limit_50", {**base, "direction": "ASC", "limit": 50}, None),
        # triggered formats
        ("no_triggered_limit_10", {"orderby": "triggered", "direction": "asc", "limit": 10}, None),
        ("triggered_ms_Z_limit_10", {**base, "triggered": f"[{start}.000Z,]", "limit": 10}, None),
        ("triggered_relative_24h_limit_10", {**base, "triggered": "[-24h,]", "limit": 10}, None),
        ("triggered_relative_1h_limit_10", {**base, "triggered": "[-1h,]", "limit": 10}, None),
        ("closed_seconds_limit_10", {**base, "triggered": f"[{start},{end}]", "limit": 10}, None),
        ("closed_Z_limit_10", {**base, "triggered": f"[{start}Z,{end}Z]", "limit": 10}, None),
        ("closed_ms_Z_limit_10", {**base, "triggered": f"[{start}.000Z,{end}.000Z]", "limit": 10}, None),
        ("closed_date_only_limit_10", {**base, "triggered": f"[{start_date},{end_date}]", "limit": 10}, None),
        ("closed_relative_limit_10", {**base, "triggered": "[-24h,-1h]", "limit": 10}, None),
        ("end_only_limit_10", {**base, "triggered": f"[,{end}]", "limit": 10}, None),
        # URL encoding: requests encodes [ , ] - send the same query unencoded
        (
            "unencoded_open_limit_100",
            None,
            f"{BASE_URL}/alert/search?triggered=[{start},]&orderby=triggered&direction=asc&limit=100",
        ),
        (
            "unencoded_closed_limit_10",
            None,
            f"{BASE_URL}/alert/search?triggered=[{start},{end}]&orderby=triggered&direction=asc&limit=10",
        ),
        # Connect API v2 endpoint (the one in the 2023 Postman collection) with the same token
        ("v2_limit_100", None, f"{V2_ALERT_SEARCH_URL}?triggered=[{start},]&orderby=triggered&direction=asc&limit=100"),
        (
            "v2_limit_50_from_50",
            None,
            f"{V2_ALERT_SEARCH_URL}?triggered=[{start},]&orderby=triggered&direction=asc&limit=50&from=50",
        ),
        ("v2_desc_limit_10", None, f"{V2_ALERT_SEARCH_URL}?triggered=[{start},]&orderby=triggered&direction=desc&limit=10"),
    ]
    return cases


def run_probe_case(client: Client, name: str, params: dict | None, full_url: str | None, include_all_headers: bool) -> dict:
    """Runs one probe request. Never raises: errors are returned in the summary."""
    try:
        request_kwargs: dict[str, Any] = {
            "resp_type": "response",
            "ok_codes": PROBE_OK_CODES,
            "retries": 0,
            "timeout": PROBE_REQUEST_TIMEOUT_SECONDS,
        }
        if full_url:
            res = client._call(url_suffix="", full_url=full_url, **request_kwargs)
        else:
            res = client._call(url_suffix="/alert/search", params=params, **request_kwargs)
        summary = summarize_raw_probe(name, res, include_all_headers)
    except Exception as error:
        summary = {"name": name, "error": str(error)[:500]}
    summary["request_params"] = params
    return summary


def ids_of(summary: dict) -> list:
    return summary.get("ids") or []


def evaluate_request_probe(results: dict[str, dict]) -> dict:
    """Turns the probe summaries into direct answers."""

    def returned(name: str):
        return results.get(name, {}).get("returned")

    def total(name: str):
        return (results.get(name, {}).get("counts") or {}).get("total")

    limits = (1, 10, 49, 50, 51, 100, 200, 500, 1000, 1001)
    limit_table = {n: {"returned": returned(f"limit_{n}"), "status": results.get(f"limit_{n}", {}).get("status")} for n in limits}
    page_0, page_50 = set(ids_of(results.get("limit_50_from_0", {}))), set(ids_of(results.get("limit_50_from_50", {})))
    small_0, small_10 = set(ids_of(results.get("limit_10_from_0", {}))), set(ids_of(results.get("limit_10_from_10", {})))
    limit_100_ids = set(ids_of(results.get("limit_100", {})))
    return {
        "window_total": total("limit_50"),
        "limit_table": limit_table,
        "limit_below_50_honoured": returned("limit_10") == 10 and returned("limit_1") == 1,
        "max_returned_seen": max((s.get("returned") or 0) for s in results.values()),
        "from_moves_window_limit_50": bool(page_50) and not (page_0 & page_50),
        "from_moves_window_limit_10": bool(small_10) and not (small_0 & small_10),
        "from_pages_union_equals_limit_100": bool(limit_100_ids) and limit_100_ids == (page_0 | page_50),
        "offset_param_moves_window": bool(ids_of(results.get("limit_50_offset_50", {})))
        and not (page_0 & set(ids_of(results.get("limit_50_offset_50", {})))),
        "asc_order": results.get("limit_50", {}).get("order"),
        "asc_first_last": [results.get("limit_50", {}).get("first_triggered"), results.get("limit_50", {}).get("last_triggered")],
        "desc_order": results.get("desc_limit_50", {}).get("order"),
        "desc_first_last": [
            results.get("desc_limit_50", {}).get("first_triggered"),
            results.get("desc_limit_50", {}).get("last_triggered"),
        ],
        # If asc and desc return the same 50 ids, the API picks the newest 50 and only sorts within them.
        "asc_desc_common_ids": len(set(ids_of(results.get("limit_50", {}))) & set(ids_of(results.get("desc_limit_50", {})))),
        "asc_limit_50_min_max": [
            results.get("limit_50", {}).get("min_triggered"),
            results.get("limit_50", {}).get("max_triggered"),
        ],
        "asc_limit_10_min_max": [
            results.get("limit_10", {}).get("min_triggered"),
            results.get("limit_10", {}).get("max_triggered"),
        ],
        "totals_by_format": {
            name: total(name)
            for name in results
            if name.startswith(("closed", "triggered_", "end_only", "no_triggered", "unencoded", "v2_"))
        },
        "statuses_not_200": {name: s.get("status") or s.get("error") for name, s in results.items() if s.get("status") != 200},
    }


def should_run_request_probe() -> bool:
    if not DEBUG_PROBE_REQUESTS:
        return False
    state = get_integration_context().get(REQUEST_PROBE_CONTEXT_KEY) or {}
    if state.get("version") != DEBUG_REQUEST_PROBE_VERSION:
        return True
    last_run_at = arg_to_datetime(state.get("last_run_at"))
    if not last_run_at:
        return True
    return datetime.now(UTC) - last_run_at >= timedelta(minutes=DEBUG_REQUEST_PROBE_INTERVAL_MINUTES)


def mark_request_probe_ran() -> None:
    integration_context = get_integration_context()
    integration_context[REQUEST_PROBE_CONTEXT_KEY] = {
        "version": DEBUG_REQUEST_PROBE_VERSION,
        "last_run_at": datetime.now(UTC).strftime(SECONDS_FORMAT) + "Z",
    }
    set_integration_context(integration_context)


def run_request_probe(client: Client) -> dict:
    """Runs every request shape once and logs one line per request plus a verdict. Read-only; never raises."""
    now = datetime.now(UTC)
    start = (now - timedelta(hours=24)).strftime(SECONDS_FORMAT)
    end = now.strftime(SECONDS_FORMAT)
    cases = build_request_probe_cases(start, end)
    debug_log(f"request probe {DEBUG_REQUEST_PROBE_VERSION} starting: {len(cases)} requests, start={start} end={end}")
    results: dict[str, dict] = {}
    started = time.monotonic()
    for index, (name, params, full_url) in enumerate(cases):
        if time.monotonic() - started > PROBE_TIME_BUDGET_SECONDS:
            debug_log(f"request probe time budget reached, skipped: {[case[0] for case in cases[index:]]}")
            break
        results[name] = run_probe_case(client, name, params, full_url, include_all_headers=index == 0)
        debug_log(f"request probe case {name}: {json.dumps(results[name], default=str)}")
    verdict = evaluate_request_probe(results)
    debug_log(f"request probe verdict: {json.dumps(verdict, default=str)}")
    return verdict


def maybe_run_request_probe(client: Client) -> None:
    """Runs the request probe when it is due. Any failure is logged and swallowed so the fetch is never affected."""
    try:
        if not should_run_request_probe():
            return
        run_request_probe(client)
        mark_request_probe_ran()
    except Exception as error:
        debug_log(f"request probe failed: {error}")


def get_pending_force_start_time() -> str | None:
    """Returns DEBUG_FORCE_START_TIME (formatted) if it is set and was not applied yet, otherwise None."""
    if not DEBUG_FORCE_START_TIME:
        return None
    if get_integration_context().get(APPLIED_FORCE_START_CONTEXT_KEY) == DEBUG_FORCE_START_TIME:
        debug_log(f"DEBUG_FORCE_START_TIME={DEBUG_FORCE_START_TIME} was already applied, ignoring it")
        return None
    return arg_to_datetime(DEBUG_FORCE_START_TIME).strftime(DATE_FORMAT)  # type: ignore[union-attr]


def mark_force_start_time_applied() -> None:
    """Remembers that DEBUG_FORCE_START_TIME was applied, so later runs do not rewind again."""
    integration_context = get_integration_context()
    integration_context[APPLIED_FORCE_START_CONTEXT_KEY] = DEBUG_FORCE_START_TIME
    set_integration_context(integration_context)
    debug_log(f"DEBUG_FORCE_START_TIME={DEBUG_FORCE_START_TIME} marked as applied")


""" HELPER FUNCTIONS """


def add_time_key_to_events(events: list = None):
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    """
    for event in events or []:
        event["_time"] = demisto.get(event, "log.triggered")


""" MAIN FUNCTION """


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_key = params.get("credentials", {}).get("password")
    headers = {"X-RFToken": api_key}

    demisto.info(f"Command being called is {command}")
    try:
        client = Client(base_url=BASE_URL, headers=headers, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            test_module(client)

        elif command == "recorded-future-get-events":
            events = get_events(client, params=build_get_events_params(args))
            if argToBoolean(args.get("should_push_events", False)):
                add_time_key_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            debug_log(
                f"debug build active: DEBUG_CURSOR_MODE={DEBUG_CURSOR_MODE}, DEBUG_FORCE_START_TIME={DEBUG_FORCE_START_TIME}, "
                f"DEBUG_PROBE_SECONDS={DEBUG_PROBE_SECONDS}, DEBUG_PROBE_REQUESTS={DEBUG_PROBE_REQUESTS} "
                f"({DEBUG_REQUEST_PROBE_VERSION})"
            )
            maybe_run_request_probe(client)
            stored_last_run = demisto.getLastRun() or {}
            last_run = stored_last_run.get("last_run_time")
            if force_start := get_pending_force_start_time():
                debug_log(f"applying one-time rewind to {force_start} (stored last_run_time was {last_run})")
                last_run = force_start
                stored_last_run = {}  # start clean from the rewind time
            if not last_run:
                last_run = arg_to_datetime(params.get("first_fetch", "3 days")).strftime(DATE_FORMAT)  # type: ignore
            events, next_run = fetch_events(
                client=client,
                limit=args.get("limit") or params.get("max_fetch") or 1000,
                last_run=last_run,
                cursor_mode=DEBUG_CURSOR_MODE,
                previous_last_run=stored_last_run,
            )

            add_time_key_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            debug_log(f"sent {len(events)} events to XSIAM")
            if force_start and not next_run:
                # Keep the rewound start time even if the window was empty, so the rewind is not lost.
                next_run = {"last_run_time": force_start, "last_run_ids": []}
            if next_run:
                demisto.setLastRun(next_run)
                debug_log(f"setLastRun: {json.dumps(next_run)}")
            if force_start:
                # Marked only after a successful run, so a failed fetch retries the rewind.
                mark_force_start_time_applied()

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
