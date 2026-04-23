import hashlib
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """

VENDOR = "Menlo"
PRODUCT = "Menlo Security Isolation Platform"

DEFAULT_MAX_EVENTS_PER_FETCH = 5000
MAX_EVENTS_PER_PAGE = 1000  # API hard limit per request
DEFAULT_FIRST_FETCH = "3 hours"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

API_PATH = "/api/rep/v1/fetch/client_select"

# Mapping from UI log type name to API log_type value.
# "safemail" is the name used in the official Menlo Python script; the API body uses "email".
# TODO: Verify that "safemail" is the correct UI label (the official script uses it, but the
#       API docs use "email" as the log_type value). Confirm with Menlo Security.
# TODO: Verify that "isoc" is a valid log_type for this API endpoint. The official Python
#       script help text does not list it, but the Logging API docs mention it as valid.
LOG_TYPE_MAP: dict[str, str] = {
    "web": "web",
    "safemail": "email",
    "audit": "audit",
    "smtp": "smtp",
    "attachment": "attachment",
    "dlp": "dlp",
    "isoc": "isoc",
}

# Mapping from UI log type name to the source_log_type value added to each event.
SOURCE_LOG_TYPE_MAP: dict[str, str] = {
    "web": "web_logs",
    "safemail": "email_logs",
    "audit": "audit_logs",
    "smtp": "smtp_logs",
    "attachment": "attachment_logs",
    "dlp": "dlp_logs",
    "isoc": "isoc_logs",
}

ALL_LOG_TYPES = list(LOG_TYPE_MAP.keys())


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the Menlo Security Logging API.

    Authenticates via an API token passed in the POST body.
    All log fetch requests are POST to /api/rep/v1/fetch/client_select.
    """

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._token = token

    def fetch_log_page(
        self,
        log_type: str,
        start: int,
        end: int,
        limit: int = MAX_EVENTS_PER_PAGE,
        paging_identifiers: dict | None = None,
    ) -> dict:
        """Fetch a single page of logs from the Menlo Security API.

        Args:
            log_type: The API log_type value (e.g. "web", "email", "audit").
            start: UTC start time in seconds since epoch.
            end: UTC end time in seconds since epoch.
            limit: Maximum number of records per page (max 1000).
            paging_identifiers: Pagination state from the previous response.
                                 None or empty dict for the first page.

        Returns:
            dict: The full API response JSON.
        """
        params = {
            "start": start,
            "end": end,
            "limit": limit,
            "format": "json",
        }
        body: dict[str, Any] = {
            "token": self._token,
            "log_type": log_type,
        }
        if paging_identifiers:
            body["pagingIdentifiers"] = paging_identifiers

        return self._http_request(
            method="POST",
            url_suffix=API_PATH,
            params=params,
            json_data=body,
            resp_type="json",
            ok_codes=(200,),
        )


""" HELPER FUNCTIONS """


def epoch_to_timestamp(epoch_seconds: int) -> str:
    """Convert epoch seconds to ISO 8601 timestamp string."""
    return datetime.utcfromtimestamp(epoch_seconds).strftime(DATE_FORMAT)


def timestamp_to_epoch(timestamp: str) -> int:
    """Convert ISO 8601 timestamp string to epoch seconds."""
    dt = arg_to_datetime(timestamp)
    if dt is None:
        raise ValueError(f"Could not parse timestamp: {timestamp!r}")
    return int(dt.timestamp())


def hash_event(event: dict) -> str:
    """Return a stable MD5 hex digest of an event dict.

    Used for cross-cycle dedup: events at the boundary timestamp are hashed
    so the next cycle can identify and skip exact duplicates.
    """
    serialized = json.dumps(event, sort_keys=True, default=str)
    return hashlib.md5(serialized.encode()).hexdigest()  # noqa: S324


def get_boundary_hashes(events: list[dict], boundary_time: str) -> list[str]:
    """Return hashes of all events whose event_time equals boundary_time.

    Iterates backwards (most efficient since boundary events are at the end)
    and stops as soon as a different timestamp is encountered.

    Args:
        events: List of events in ascending time order.
        boundary_time: The event_time of the last (most recent) event.

    Returns:
        list[str]: MD5 hashes of all events at the boundary timestamp.
    """
    hashes: list[str] = []
    for event in reversed(events):
        if event.get("event_time", "") == boundary_time:
            hashes.append(hash_event(event))
        else:
            break
    return hashes


def get_events_for_log_type(
    client: Client,
    log_type_ui: str,
    start_epoch: int,
    end_epoch: int,
    max_events: int,
    enrich: bool = True,
) -> list[dict]:
    """Fetch all events for a single log type, paginating as needed.

    Args:
        client: The Menlo Security API client.
        log_type_ui: The UI log type name (e.g. "web", "safemail").
        start_epoch: Fetch start time as epoch seconds.
        end_epoch: Fetch end time as epoch seconds.
        max_events: Maximum total events to collect for this log type.
        enrich: If True, add _time and source_log_type fields to each event.
                Should be True when sending to XSIAM, False for display-only.

    Returns:
        list[dict]: All collected events, enriched if enrich=True.
    """
    api_log_type = LOG_TYPE_MAP[log_type_ui]
    source_log_type = SOURCE_LOG_TYPE_MAP[log_type_ui]
    events: list[dict] = []
    paging_identifiers: dict | None = None

    while len(events) < max_events:
        remaining = max_events - len(events)
        page_limit = min(MAX_EVENTS_PER_PAGE, remaining)

        demisto.debug(
            f"Fetching {log_type_ui} logs: start={start_epoch}, end={end_epoch}, "
            f"page_limit={page_limit}, paging_identifiers={paging_identifiers}"
        )

        try:
            response = client.fetch_log_page(
                log_type=api_log_type,
                start=start_epoch,
                end=end_epoch,
                limit=page_limit,
                paging_identifiers=paging_identifiers,
            )
        except Exception as e:
            demisto.error(f"Error fetching {log_type_ui} logs: {e}")
            break

        # The API may return an empty 200 response (Content-Length: 0) when there is no data.
        if not response:
            demisto.debug(f"Empty response for {log_type_ui} logs — no data available.")
            break

        result = response.get("result", {})
        page_events = result.get("events", [])

        if not page_events:
            demisto.debug(f"No more events for {log_type_ui} logs.")
            break

        demisto.debug(f"Fetched {len(page_events)} {log_type_ui} events in this page.")

        # Per the API docs, each element in the events list is {"event": {...}}.
        for event in page_events:
            inner = event.get("event", event)  # unwrap the {"event": {...}} envelope
            if enrich:
                event_time_str = inner.get("event_time")
                if event_time_str:
                    try:
                        dt = arg_to_datetime(event_time_str)
                        inner["_time"] = dt.strftime(DATE_FORMAT) if dt else event_time_str
                    except Exception:
                        inner["_time"] = event_time_str
                inner["source_log_type"] = source_log_type
            events.append(inner)

        # Update paging state for the next request.
        paging_identifiers = result.get("pagingIdentifiers") or {}
        if not paging_identifiers:
            demisto.debug(f"No pagingIdentifiers returned — all {log_type_ui} events fetched.")
            break

    demisto.debug(f"Total {log_type_ui} events collected: {len(events)}")
    return events


""" COMMAND FUNCTIONS """


def test_module(client: Client, log_types: list[str]) -> str:
    """Test API connectivity and authentication.

    Fetches a single record for each configured log type for the last 1 hour.
    Returns 'ok' on success, a descriptive error string for known failures,
    or raises an exception for unexpected errors.

    Args:
        client: The Menlo Security API client.
        log_types: List of selected log type UI names.

    Returns:
        str: 'ok' if all configured log types are reachable.
    """
    end_epoch = int(datetime.utcnow().timestamp())
    start_epoch = end_epoch - 3600  # last 1 hour

    types_to_test = log_types if log_types else ALL_LOG_TYPES
    for log_type_ui in types_to_test:
        api_log_type = LOG_TYPE_MAP.get(log_type_ui, log_type_ui)
        demisto.debug(f"Testing connectivity for log type: {log_type_ui}")
        try:
            client.fetch_log_page(
                log_type=api_log_type,
                start=start_epoch,
                end=end_epoch,
                limit=1,
            )
        except Exception as e:
            error_str = str(e)
            if "401" in error_str or "Unauthorized" in error_str:
                return "Authorization Error: make sure the Auth Token is correct and has the Log Export API permission."
            if "403" in error_str or "Forbidden" in error_str:
                return f"Authorization Error: the token does not have permission to access '{log_type_ui}' logs."
            if "ConnectionError" in error_str or "Failed to establish" in error_str:
                return "Connection Error: could not reach the Menlo Security API. Check the Server URL and network connectivity."
            raise e

    return "ok"


def fetch_events(
    client: Client,
    last_run: dict,
    log_types: list[str],
    first_fetch_time: str,
    max_events_per_fetch: int,
) -> tuple[dict, list[dict]]:
    """Fetch events from all selected log types.

    Args:
        client: The Menlo Security API client.
        last_run: The last run dict from demisto.getLastRun().
        log_types: List of selected log type UI names.
        first_fetch_time: Human-readable first fetch time (e.g. "3 days").
        max_events_per_fetch: Maximum events to fetch per log type per cycle.

    Returns:
        tuple[dict, list[dict]]: (next_run dict, list of all events)
    """
    end_dt = datetime.utcnow()
    end_epoch = int(end_dt.timestamp())
    end_timestamp = end_dt.strftime(DATE_FORMAT)

    all_events: list[dict] = []
    next_run: dict = {}

    for log_type_ui in log_types:
        # Determine start time for this log type.
        last_fetch_time = last_run.get(log_type_ui, {}).get("last_fetch_time")
        if last_fetch_time:
            start_epoch = timestamp_to_epoch(last_fetch_time)
            demisto.debug(f"Resuming {log_type_ui} from last fetch time: {last_fetch_time}")
        else:
            first_fetch_dt = arg_to_datetime(first_fetch_time)
            if first_fetch_dt is None:
                raise ValueError(f"Invalid first_fetch_time value: {first_fetch_time!r}")
            start_epoch = int(first_fetch_dt.timestamp())
            demisto.debug(f"First fetch for {log_type_ui}, starting from: {epoch_to_timestamp(start_epoch)}")

        events = get_events_for_log_type(
            client=client,
            log_type_ui=log_type_ui,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            max_events=max_events_per_fetch,
        )

        boundary_hashes: set[str] = set(last_run.get(log_type_ui, {}).get("boundary_hashes", []))
        if last_fetch_time and events and boundary_hashes:
            skip = 0
            for e in events:
                if e.get("event_time", "") == last_fetch_time and hash_event(e) in boundary_hashes:
                    skip += 1
                else:
                    break
            if skip:
                demisto.debug(f"Removed {skip} duplicate {log_type_ui} event(s) with event_time={last_fetch_time!r} (hash match)")
                events = events[skip:]

        all_events.extend(events)

        if events:
            last_event_time = events[-1].get("event_time") or events[-1].get("_time", "")
            next_fetch_time = last_event_time if last_event_time else end_timestamp
            # Compute hashes of all events at the boundary timestamp (iterate backwards,
            # stop at first different timestamp) for dedup in the next cycle.
            next_boundary_hashes = get_boundary_hashes(events, last_event_time)
        else:
            next_fetch_time = end_timestamp
            next_boundary_hashes = []

        demisto.debug(
            f"Next fetch for {log_type_ui} will start from: {next_fetch_time} with {len(next_boundary_hashes)} boundary hash(es)"
        )
        next_run[log_type_ui] = {
            "last_fetch_time": next_fetch_time,
            "boundary_hashes": next_boundary_hashes,
        }

    demisto.debug(f"Total events fetched across all log types: {len(all_events)}")
    return next_run, all_events


def get_events_command(
    client: Client,
    args: dict,
    log_types: list[str],
    max_events_per_fetch: int,
) -> CommandResults:
    """Manual command to fetch and optionally push events.

    Args:
        client: The Menlo Security API client.
        args: Command arguments (start_time, end_time, log_types, limit, should_push_events).
        log_types: Default log types from integration params.
        max_events_per_fetch: Default max events from integration params.

    Returns:
        CommandResults: Human-readable output for display in the War Room.
    """
    start_time_str = args.get("start_time", "1 hour")
    end_time_str = args.get("end_time", "now")
    arg_log_types = argToList(args.get("log_types", "")) or log_types
    limit = arg_to_number(args.get("limit", max_events_per_fetch)) or max_events_per_fetch
    should_push = argToBoolean(args.get("should_push_events", False))

    start_dt = arg_to_datetime(start_time_str)
    end_dt = arg_to_datetime(end_time_str)
    if start_dt is None:
        raise ValueError(f"Invalid start_time value: {start_time_str!r}")
    if end_dt is None:
        raise ValueError(f"Invalid end_time value: {end_time_str!r}")

    start_epoch = int(start_dt.timestamp())
    end_epoch = int(end_dt.timestamp())

    all_events: list[dict] = []
    for log_type_ui in arg_log_types:
        if log_type_ui not in LOG_TYPE_MAP:
            demisto.debug(f"Unknown log type: {log_type_ui}, skipping.")
            continue
        events = get_events_for_log_type(
            client=client,
            log_type_ui=log_type_ui,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            max_events=limit,
            enrich=should_push,  # only enrich (_time, source_log_type) when sending to XSIAM
        )
        all_events.extend(events)

    hr = tableToMarkdown(
        name=f"{VENDOR} - {PRODUCT} Events",
        t=all_events,
        removeNull=True,
    )
    if should_push:
        send_events_to_xsiam(all_events, vendor=VENDOR, product=PRODUCT)

    return CommandResults(readable_output=hr, raw_response=all_events)


""" MAIN FUNCTION """


def main() -> None:
    """Main function — parses params and dispatches commands."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "https://logs.menlosecurity.com").rstrip("/")
    token = params.get("credentials", {}).get("password") or params.get("token", "")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    log_types: list[str] = argToList(params.get("log_types", ",".join(ALL_LOG_TYPES)))
    if not log_types:
        log_types = ALL_LOG_TYPES

    first_fetch_time: str = DEFAULT_FIRST_FETCH
    max_events_per_fetch: int = (
        arg_to_number(params.get("max_events_per_fetch", DEFAULT_MAX_EVENTS_PER_FETCH)) or DEFAULT_MAX_EVENTS_PER_FETCH
    )

    demisto.debug(f"Command being called: {command}")
    demisto.debug(f"Selected log types: {log_types}")

    try:
        client = Client(
            base_url=base_url,
            token=token,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module(client, log_types)
            return_results(result)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Last run: {last_run}")
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                log_types=log_types,
                first_fetch_time=first_fetch_time,
                max_events_per_fetch=max_events_per_fetch,
            )
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Next run set to: {next_run}")

        elif command == "menlo-security-get-events":
            results = get_events_command(
                client=client,
                args=args,
                log_types=log_types,
                max_events_per_fetch=max_events_per_fetch,
            )
            return_results(results)

        else:
            raise NotImplementedError(f"Command {command!r} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
