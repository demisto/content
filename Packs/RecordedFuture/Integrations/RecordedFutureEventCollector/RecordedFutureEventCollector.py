from CommonServerPython import *
import json
import urllib3
from typing import Any
from collections.abc import Iterator

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
BASE_URL = "https://api.recordedfuture.com/gw/xsiam"
STATUS_TO_RETRY = [500, 501, 502, 503, 504]
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TRIGGERED_FORMAT = "%Y-%m-%dT%H:%M:%S"  # The format of get_triggered() values (no milliseconds).
VENDOR = "Recorded Future"
PRODUCT = "Intelligence Cloud"
# The alert search endpoint silently caps every response at 50 alerts, regardless of the requested limit.
PAGE_SIZE = 50
MAX_FETCH = 1000

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


def get_events(client: Client, args: dict) -> list:
    """Retrieves events using the RecordedFuture API (recorded-future-get-events).

    Debug / verification aid (XSUP-80326): start_time and end_time let you compare the number of alerts in a time
    window with the number of unique alerts in the dataset.
    - The API only honours an open start filter (triggered=[start,]). It silently ignores closed ranges and end-only
      filters (it falls back to its default ~7-day window), so end_time is NOT sent to the API. Instead we page
      until we pass end_time and drop newer alerts here.
    - The API's counts.total is the number of alerts triggered from start_time up to NOW, not up to end_time.

    Args:
        client (Client): RecordedFuture client to use.
        args (dict): The command arguments (limit, start_time, end_time).

    Returns:
        list: The events in the time window (oldest first), up to `limit`.
    """
    limit = min(arg_to_number(args.get("limit"), arg_name="limit") or 10, MAX_FETCH)
    start_dt = arg_to_datetime(args.get("start_time"), arg_name="start_time")
    end_dt = arg_to_datetime(args.get("end_time"), arg_name="end_time")
    start = start_dt.strftime(TRIGGERED_FORMAT) if start_dt else ""
    end = end_dt.strftime(TRIGGERED_FORMAT) if end_dt else ""

    params: dict[str, Any] = {"orderby": "triggered", "direction": "desc"}
    if start:
        params["triggered"] = f"[{start},]"

    alerts: list[dict] = []
    api_total = None
    window_complete = False  # True when we saw every alert up to end_time (or up to now when there is no end_time).
    for page, response in iter_alert_pages(client, params):
        if api_total is None:
            api_total = (response.get("counts") or {}).get("total")
        alerts.extend(page)
        if len(page) < PAGE_SIZE or (end and any(get_triggered(alert) > end for alert in page)):
            window_complete = True
            break
        if len(dedupe_and_sort(alerts, end)) > limit:
            break

    window_alerts = dedupe_and_sort(alerts, end)
    events = window_alerts[:limit]

    window_desc = f"[{start or 'API default (~7 days ago)'}, {end or 'now'}] (UTC, second precision)"
    window_count = str(len(window_alerts)) if window_complete else f"more than {limit} (stopped at the limit)"
    total_desc = "from start_time up to NOW" if start else "in the API default window (~last 7 days) up to NOW"
    summary = {
        "Time window": window_desc,
        "Alerts in window": window_count,
        "Returned": f"{len(events)} (limit {limit})",
        "API counts.total": f"{api_total} - alerts triggered {total_desc}, NOT limited by end_time",
    }
    hr = tableToMarkdown("Recorded Future get-events summary", summary, headers=list(summary))
    if end:
        hr += "\nNote: end_time is applied by the integration, the Recorded Future API does not support an end time.\n"
    hr += tableToMarkdown(name="Events", t=events)
    return_results(CommandResults(readable_output=hr, raw_response=events))

    return events


def dedupe_and_sort(alerts: list[dict], end: str = "") -> list[dict]:
    """Returns the alerts sorted oldest first, without duplicate IDs, and (if given) only those triggered up to `end`.

    Args:
        alerts (list): The raw alerts.
        end (str): Optional inclusive upper bound, in TRIGGERED_FORMAT.

    Returns:
        list: The unique alerts, oldest first.
    """
    unique_alerts: list[dict] = []
    seen_ids: set = set()
    for alert in sorted(alerts, key=get_triggered):
        if end and get_triggered(alert) > end:
            continue
        if (alert_id := alert.get("id")) not in seen_ids:
            seen_ids.add(alert_id)
            unique_alerts.append(alert)
    return unique_alerts


def iter_alert_pages(client: Client, params: dict) -> Iterator[tuple[list[dict], dict]]:
    """Yields /alert/search pages using `from` offset paging with a fixed page size, until a short page.

    The page size is always PAGE_SIZE (the API's hard cap) so `from` always advances in whole pages.
    With direction=desc each page holds the next-oldest alerts, so paging moves forward in time.
    The caller decides when to stop early (by breaking out of the loop).

    Args:
        client (Client): RecordedFuture client to use.
        params (dict): The search params (without limit / from).

    Yields:
        tuple: (the alerts in the page, the full API response).
    """
    offset = 0
    while True:
        response = client.get_alerts({**params, "limit": PAGE_SIZE, "from": offset})
        page = response.get("data") or []
        demisto.debug(f"Fetched {len(page)} alerts (from={offset}, limit={PAGE_SIZE}).")
        yield page, response
        if len(page) < PAGE_SIZE:
            return
        offset += PAGE_SIZE


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


def fetch_alert_pages(client: Client, last_run: str, max_fetch: int) -> list[dict]:
    """Fetch the oldest alerts triggered at or after `last_run`, paging with `from` until `max_fetch` is reached.

    With direction=desc the API returns the *oldest* alerts after the start time (displayed newest-first),
    so paging with `from` moves forward in time and new alerts arriving between pages do not shift the offsets.
    The page size is always PAGE_SIZE (never shrunk for the last page) so `from` always advances in whole pages;
    the caller trims the result to `max_fetch`.

    Args:
        client (Client): RecordedFuture client to use.
        last_run (str): The start time (inclusive) to fetch from.
        max_fetch (int): The number of alerts to collect before stopping.

    Returns:
        list: The raw alerts returned by the API (may contain duplicates across pages, and up to
              PAGE_SIZE - 1 alerts more than `max_fetch`).
    """
    alerts: list[dict] = []
    params = {"triggered": f"[{last_run},]", "orderby": "triggered", "direction": "desc"}
    for page, _ in iter_alert_pages(client, params):
        alerts.extend(page)
        if len(alerts) >= max_fetch:
            break
    return alerts


def fetch_events(client: Client, **kwargs) -> tuple[list, dict]:
    """
    Args:
        client (Client): RecordedFuture client to use.
        limit: The maximum number of events to fetch (capped at MAX_FETCH).
        last_run (str): The time to fetch from (inclusive).

    Returns:
        list: (list) of events that will be created in XSIAM, sorted by trigger time.
        dict: The lastRun object to save for next run (empty if nothing was fetched).
    """
    last_run = str(kwargs.get("last_run"))
    max_fetch = min(arg_to_number(kwargs.get("limit")) or MAX_FETCH, MAX_FETCH)
    last_run_ids = set(demisto.getLastRun().get("last_run_ids") or [])

    alerts = fetch_alert_pages(client, last_run, max_fetch)
    if not alerts:
        return [], {}

    # Sort oldest first, drop duplicates across pages, then keep only the oldest `max_fetch` alerts.
    # The cursor is computed from the kept alerts only, so trimmed (newer) alerts are fetched next run.
    kept = dedupe_and_sort(alerts)[:max_fetch]

    # The cursor is the latest trigger time kept. The API ignores milliseconds, so the next fetch
    # starts from (including) this second, and we keep the IDs triggered at this second to filter them out.
    next_run_time = get_triggered(kept[-1])
    next_run_ids = {alert.get("id") for alert in kept if get_triggered(alert) == next_run_time}
    if next_run_time == last_run.split(".")[0]:
        next_run_ids |= last_run_ids

    # In case all kept alerts were triggered at the same second and the limit was reached,
    # move the cursor forward, otherwise the fetch will get stuck at this second forever.
    if len(kept) >= max_fetch and get_triggered(kept[0]) == next_run_time:
        next_run_time = (datetime.strptime(next_run_time, TRIGGERED_FORMAT) + timedelta(seconds=1)).strftime(TRIGGERED_FORMAT)

    # Remove alerts already sent in the previous round (same trigger second as the previous cursor).
    events = [alert for alert in kept if alert.get("id") not in last_run_ids]

    demisto.debug(f"Fetched {len(alerts)} alerts, kept {len(kept)}, {len(events)} new. Next run time: {next_run_time}.")
    return events, {"last_run_time": next_run_time, "last_run_ids": list(next_run_ids)}


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
            events = get_events(client, args)
            if argToBoolean(args.get("should_push_events", False)):
                add_time_key_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            if not (last_run := demisto.getLastRun().get("last_run_time")):
                last_run = arg_to_datetime(params.get("first_fetch", "3 days")).strftime(DATE_FORMAT)  # type: ignore
            events, next_run = fetch_events(
                client=client, limit=args.get("limit") or params.get("max_fetch") or MAX_FETCH, last_run=last_run
            )

            add_time_key_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            if next_run:
                demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
