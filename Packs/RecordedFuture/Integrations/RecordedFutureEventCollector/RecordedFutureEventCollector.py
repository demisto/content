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
TRIGGERED_FORMAT = "%Y-%m-%dT%H:%M:%S"  # Second precision, the API ignores milliseconds.
VENDOR = "Recorded Future"
PRODUCT = "Intelligence Cloud"
PAGE_SIZE = 50  # The API caps every response at 50 alerts, whatever limit is requested.
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


""" HELPER FUNCTIONS """


def get_triggered(event: dict) -> str:
    """Returns the event's "triggered" time in TRIGGERED_FORMAT (no milliseconds, no "Z")."""
    if event:
        return event.get("log", {}).get("triggered", "").split(".")[0].removesuffix("Z")
    return ""


def parse_limit(value: Any, default: int) -> int:
    """Returns the limit capped at MAX_FETCH, or `default` when empty or 0. Raises on a negative limit."""
    limit = arg_to_number(value, arg_name="limit")
    if not limit:
        return default
    if limit < 1:
        raise ValueError(f"limit must be a positive number, got {limit}.")
    return min(limit, MAX_FETCH)


def to_triggered_format(value: datetime | None) -> str:
    """Returns the datetime in UTC as TRIGGERED_FORMAT, or "" when empty. Naive values are treated as UTC."""
    if not value:
        return ""
    if value.tzinfo:
        value = value.astimezone(timezone.utc)
    return value.strftime(TRIGGERED_FORMAT)


def dedupe_and_sort(alerts: list[dict], end: str = "") -> list[dict]:
    """Returns the alerts oldest first, without duplicate IDs, and only up to `end` (inclusive) when given."""
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
    """Yields (alerts, raw response) per page using `from` paging, until a short page. The caller may stop early.

    The page size is always PAGE_SIZE, so `from` advances in whole pages.
    """
    offset = 0
    while True:
        response = client.get_alerts({**params, "limit": PAGE_SIZE, "from": offset})
        page = response.get("data") or []
        demisto.debug(f"[Pagination] Got {len(page)} alerts (from={offset}, limit={PAGE_SIZE}).")
        yield page, response
        if len(page) < PAGE_SIZE:
            return
        offset += PAGE_SIZE


def add_time_key_to_events(events: list = None):
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    """
    for event in events or []:
        event["_time"] = demisto.get(event, "log.triggered")


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
    """Gets the alerts in a time window (for debugging and verification).

    The API only supports an open start filter (triggered=[start,]), so end_time is applied here and requires
    start_time. The API's counts.total is from start_time up to now.

    Args:
        client (Client): RecordedFuture client to use.
        args (dict): The command arguments (limit, start_time, end_time).

    Returns:
        list: The events in the window, oldest first, up to `limit`.
    """
    limit = parse_limit(args.get("limit"), default=10)
    start = to_triggered_format(arg_to_datetime(args.get("start_time"), arg_name="start_time"))
    end = to_triggered_format(arg_to_datetime(args.get("end_time"), arg_name="end_time"))
    if end and not start:
        raise ValueError("end_time requires start_time.")
    demisto.debug(f"[Get Events] Window [{start or 'API default'}, {end or 'now'}], limit {limit}.")

    params: dict[str, Any] = {"orderby": "triggered", "direction": "desc"}
    if start:
        params["triggered"] = f"[{start},]"

    alerts: list[dict] = []
    api_total = None
    window_complete = False
    for page, response in iter_alert_pages(client, params):
        if api_total is None:
            api_total = (response.get("counts") or {}).get("total")
        alerts.extend(page)
        # The whole window was seen: this is the last page, or the page passes end_time.
        if len(page) < PAGE_SIZE or (end and any(get_triggered(alert) > end for alert in page)):
            window_complete = True
            break
        if len(dedupe_and_sort(alerts, end)) > limit:
            break

    window_alerts = dedupe_and_sort(alerts, end)
    events = window_alerts[:limit]
    demisto.debug(f"[Get Events] {len(window_alerts)} alerts in window, returning {len(events)}, complete={window_complete}.")

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


def fetch_events(client: Client, **kwargs) -> tuple[list, dict]:
    """Fetches the oldest alerts triggered at or after `last_run`, up to `limit`.

    Args:
        client (Client): RecordedFuture client to use.
        limit: The maximum number of events to fetch (capped at MAX_FETCH).
        last_run (str): The time to fetch from (inclusive).

    Returns:
        list: The new events, oldest first.
        dict: The lastRun object for the next run (empty when no alerts were found).
    """
    last_run = str(kwargs.get("last_run"))
    max_fetch = parse_limit(kwargs.get("limit"), default=MAX_FETCH)
    last_run_ids = set(demisto.getLastRun().get("last_run_ids") or [])
    demisto.debug(f"[Fetch] Fetching from {last_run}, limit {max_fetch}, {len(last_run_ids)} IDs from the last run.")

    # direction=desc returns the oldest alerts after the start time. Observed on the live API, not documented.
    params = {"triggered": f"[{last_run},]", "orderby": "triggered", "direction": "desc"}
    alerts: list[dict] = []
    for page, _ in iter_alert_pages(client, params):
        alerts.extend(page)
        if len(alerts) >= max_fetch:
            break
    if not alerts:
        demisto.debug("[Fetch] No alerts found.")
        return [], {}

    # Keep the oldest `max_fetch` unique alerts, the rest are fetched next run.
    kept = dedupe_and_sort(alerts)[:max_fetch]

    # The next run starts at (and includes) the latest kept second, so save the IDs at that second to skip them.
    next_run_time = get_triggered(kept[-1])
    next_run_ids = {alert.get("id") for alert in kept if get_triggered(alert) == next_run_time}
    if next_run_time == last_run.split(".")[0]:
        next_run_ids |= last_run_ids

    # If the limit was reached within a single second, move forward one second, otherwise the fetch gets stuck.
    if len(kept) >= max_fetch and get_triggered(kept[0]) == next_run_time:
        demisto.info(
            f"[Fetch] All {len(kept)} alerts were triggered at {next_run_time} and the limit was reached. "
            "Moving the cursor forward by one second, alerts beyond the limit in this second are skipped."
        )
        next_run_time = (datetime.strptime(next_run_time, TRIGGERED_FORMAT) + timedelta(seconds=1)).strftime(TRIGGERED_FORMAT)

    events = [alert for alert in kept if alert.get("id") not in last_run_ids]

    demisto.debug(f"[Fetch] Fetched {len(alerts)} alerts, kept {len(kept)}, {len(events)} new. Next run time: {next_run_time}.")
    return events, {"last_run_time": next_run_time, "last_run_ids": list(next_run_ids)}


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

    demisto.info(f"[Main] Command being called is {command}")
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
                demisto.debug(f"[Fetch] No last run, first fetch from {last_run}.")
            events, next_run = fetch_events(
                client=client, limit=args.get("limit") or params.get("max_fetch") or MAX_FETCH, last_run=last_run
            )

            add_time_key_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            if next_run:
                demisto.setLastRun(next_run)
                demisto.debug(f"[Fetch] Saved last run: {next_run['last_run_time']} ({len(next_run['last_run_ids'])} IDs).")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
