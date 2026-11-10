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
VENDOR = "Recorded Future"
PRODUCT = "Intelligence Cloud"

# XSUP-80326 debug build constants
DEBUG_PREFIX = "[XSUP-80326 DEBUG]"
CURSOR_MODE_LEGACY = "legacy"  # original behaviour: cursor taken from events[0]
CURSOR_MODE_NEWEST = "newest"  # candidate fix: cursor taken from the newest event in the response
OVERRIDE_CONTEXT_KEY = "debug_override_last_run_time"

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


def debug_fetch_command(client: Client, args: dict, params: dict) -> CommandResults:
    """Dry run of a fetch round: calls the API exactly like fetch-events, but does not send events or change the last run.

    Args:
        client (Client): RecordedFuture client to use.
        args (dict): start_time (optional, defaults to the stored last_run_time), limit (optional).
        params (dict): The integration parameters.

    Returns:
        CommandResults: The returned events and the next run each cursor mode would compute.
    """
    last_run = demisto.getLastRun() or {}
    if args.get("start_time"):
        start_time = arg_to_datetime(args["start_time"], arg_name="start_time").strftime(DATE_FORMAT)  # type: ignore[union-attr]
    else:
        # Use the stored cursor exactly as fetch-events would send it.
        start_time = last_run.get("last_run_time") or arg_to_datetime(params.get("first_fetch", "3 days")).strftime(  # type: ignore[union-attr]
            DATE_FORMAT
        )
    limit = int(args.get("limit") or params.get("max_fetch") or 1000)

    request_params = {"triggered": f"[{start_time},]", "orderby": "triggered", "direction": "asc", "limit": limit}
    response = client.get_alerts(request_params)
    events = response.get("data", [])
    log_response_diagnostics(request_params, response, events)

    already_fetched_ids = set(last_run.get("last_run_ids") or [])
    previous_sent_ids = set(last_run.get("debug_sent_ids") or [])
    rows = [
        {
            "index": index,
            "id": event.get("id"),
            "triggered": demisto.get(event, "log.triggered"),
            "in_last_run_ids": event.get("id") in already_fetched_ids,
            "sent_by_previous_run": event.get("id") in previous_sent_ids,
        }
        for index, event in enumerate(events)
    ]
    summary: dict[str, Any] = {
        "RequestParams": request_params,
        "ResponseCounts": response.get("counts"),
        "EventsReturned": len(events),
        "ResponseOrder": get_response_order(events),
        "StoredLastRun": last_run,
        "NextRunLegacy": compute_next_run(events, limit, CURSOR_MODE_LEGACY),
        "NextRunNewest": compute_next_run(events, limit, CURSOR_MODE_NEWEST),
    }
    readable = tableToMarkdown("Debug fetch summary (dry run - nothing was sent or saved)", summary) + tableToMarkdown(
        "Events in API order", rows, headers=["index", "id", "triggered", "in_last_run_ids", "sent_by_previous_run"]
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix="RecordedFutureEventCollector.DebugFetch",
        outputs={**summary, "Events": rows},
        raw_response=response,
    )


def debug_get_last_run_command() -> CommandResults:
    """Shows the stored last run and any pending start-time override."""
    last_run = demisto.getLastRun() or {}
    override = get_integration_context().get(OVERRIDE_CONTEXT_KEY)
    outputs = {"LastRun": last_run, "PendingOverrideStartTime": override}
    return CommandResults(
        readable_output=tableToMarkdown("Recorded Future collector last run", outputs),
        outputs_prefix="RecordedFutureEventCollector.LastRun",
        outputs=outputs,
    )


def debug_set_fetch_start_command(args: dict) -> CommandResults:
    """Schedules the next fetch-events run to start from the given time (applied once, then cleared).

    Optional - only needed if we want to re-fetch a past window. The override is stored in the integration context
    because the last run object can only be changed by fetch-events. The next successful fetch-events run uses it
    as its start time, overwrites the last run with its own result, and clears the override.
    """
    start_time = arg_to_datetime(args.get("start_time"), arg_name="start_time", required=True)
    override = start_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]
    integration_context = get_integration_context()
    integration_context[OVERRIDE_CONTEXT_KEY] = override
    set_integration_context(integration_context)
    debug_log(f"next fetch-events run will start from override time {override}")
    return CommandResults(readable_output=f"The next fetch-events run will start from {override} (applied once).")


def get_override_start_time() -> str | None:
    """Returns the pending start-time override, if any."""
    return get_integration_context().get(OVERRIDE_CONTEXT_KEY)


def clear_override_start_time() -> None:
    """Removes the start-time override so it is applied only once."""
    integration_context = get_integration_context()
    if integration_context.pop(OVERRIDE_CONTEXT_KEY, None):
        set_integration_context(integration_context)
        debug_log("start-time override cleared")


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

        elif command == "recorded-future-debug-fetch":
            return_results(debug_fetch_command(client, args, params))

        elif command == "recorded-future-debug-get-last-run":
            return_results(debug_get_last_run_command())

        elif command == "recorded-future-debug-set-fetch-start":
            return_results(debug_set_fetch_start_command(args))

        elif command == "fetch-events":
            stored_last_run = demisto.getLastRun() or {}
            last_run = stored_last_run.get("last_run_time")
            if override := get_override_start_time():
                debug_log(f"applying start-time override {override} (stored last_run_time was {last_run})")
                last_run = override
                stored_last_run = {}  # start clean from the override time
            if not last_run:
                last_run = arg_to_datetime(params.get("first_fetch", "3 days")).strftime(DATE_FORMAT)  # type: ignore
            events, next_run = fetch_events(
                client=client,
                limit=args.get("limit") or params.get("max_fetch") or 1000,
                last_run=last_run,
                cursor_mode=params.get("debug_cursor_mode") or CURSOR_MODE_LEGACY,
                previous_last_run=stored_last_run,
            )

            add_time_key_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            debug_log(f"sent {len(events)} events to XSIAM")
            if override and not next_run:
                # Keep the rewound start time even if the window was empty, so the override is not lost.
                next_run = {"last_run_time": override, "last_run_ids": []}
            if next_run:
                demisto.setLastRun(next_run)
                debug_log(f"setLastRun: {json.dumps(next_run)}")
            if override:
                # Cleared only after a successful run, so a failed fetch retries from the override.
                clear_override_start_time()

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
