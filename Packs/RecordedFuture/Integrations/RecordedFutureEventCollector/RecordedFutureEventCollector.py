from CommonServerPython import *
import json
import urllib3
from typing import Any

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


def get_events(client, params: dict) -> list:
    """
        Retrieves events using the RecordedFuture API.
    Args:
        client (Client): RecordedFuture client to use.
        params (dict): The params to send to the API basically contains the limit for example {'limit': '1000'}.

    Returns:
        list: (list) of events that will be created in XSIAM.
    """

    result = client.get_alerts(params)
    events = result.get("data", [])

    hr = tableToMarkdown(name="Test Event", t=events)
    return_results(CommandResults(readable_output=hr, raw_response=events))

    return events


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

    Args:
        client (Client): RecordedFuture client to use.
        last_run (str): The start time (inclusive) to fetch from.
        max_fetch (int): The maximum number of alerts to fetch.

    Returns:
        list: The raw alerts returned by the API (may contain duplicates across pages).
    """
    alerts: list[dict] = []
    offset = 0
    while offset < max_fetch:
        page_limit = min(PAGE_SIZE, max_fetch - offset)
        params = {
            "triggered": f"[{last_run},]",
            "orderby": "triggered",
            "direction": "desc",
            "limit": page_limit,
            "from": offset,
        }
        page = client.get_alerts(params).get("data") or []
        alerts.extend(page)
        offset += len(page)
        demisto.debug(f"Fetched {len(page)} alerts (from={offset - len(page)}, limit={page_limit}).")
        if len(page) < page_limit:
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

    # Remove alerts fetched in the previous round (same trigger second as the cursor) and duplicates across pages.
    events: list[dict] = []
    seen_ids: set = set()
    for alert in sorted(alerts, key=get_triggered):
        alert_id = alert.get("id")
        if alert_id in seen_ids or alert_id in last_run_ids:
            continue
        seen_ids.add(alert_id)
        events.append(alert)

    # The cursor is the latest trigger time fetched. The API ignores milliseconds, so the next fetch
    # starts from (including) this second, and we keep the IDs triggered at this second to filter them out.
    next_run_time = max(get_triggered(alert) for alert in alerts)
    next_run_ids = {alert.get("id") for alert in alerts if get_triggered(alert) == next_run_time}
    if next_run_time == last_run.split(".")[0]:
        next_run_ids |= last_run_ids

    # In case all fetched alerts were triggered at the same second and the limit was reached,
    # move the cursor forward, otherwise the fetch will get stuck at this second forever.
    if len(alerts) >= max_fetch and all(get_triggered(alert) == next_run_time for alert in alerts):
        next_run_time = (datetime.strptime(next_run_time, TRIGGERED_FORMAT) + timedelta(seconds=1)).strftime(TRIGGERED_FORMAT)

    demisto.debug(f"Fetched {len(alerts)} alerts, {len(events)} new. Next run time: {next_run_time}.")
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
            events = get_events(client, params={"limit": args.get("limit", 10)})
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
