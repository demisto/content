import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "microsoft"
PRODUCT = "o365_message_trace"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_MAX_FETCH = 5000
DEFAULT_FIRST_FETCH = "3 days"


class Client(BaseClient):
    """Client for the Office 365 Reporting Web Service (Message Trace)."""

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=(username, password))

    def get_message_trace(self, start_date: str, end_date: str, top: int) -> list[dict[str, Any]]:
        """Query the Reporting Web Service for message trace records.

        Args:
            start_date: ISO-8601 start time (inclusive).
            end_date: ISO-8601 end time (inclusive).
            top: Maximum number of records to return.

        Returns:
            A list of message trace event dictionaries.
        """
        params = {
            "$format": "json",
            "$top": top,
            "$filter": f"StartDate eq datetime'{start_date}' and EndDate eq datetime'{end_date}'",
        }
        raw_response = self._http_request(method="GET", url_suffix="/MessageTrace", params=params)
        return raw_response.get("d", {}).get("results", [])


def add_time_field(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add the _time field expected by the XSIAM dataset, derived from Received.

    Args:
        events: Raw message trace events.

    Returns:
        The same events with a normalized _time field added.
    """
    for event in events:
        received = event.get("Received")
        if received:
            event["_time"] = received
    return events


def test_module(client: Client) -> str:
    """Validate connectivity and credentials.

    Args:
        client: Configured API client.

    Returns:
        'ok' on success.
    """
    now = datetime.utcnow()
    start = (now - timedelta(minutes=30)).strftime(DATE_FORMAT)
    end = now.strftime(DATE_FORMAT)
    client.get_message_trace(start_date=start, end_date=end, top=1)
    return "ok"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict[str, Any]], CommandResults]:
    """Manually retrieve message trace events for debugging.

    Args:
        client: Configured API client.
        args: Command arguments (limit, start_date, end_date).

    Returns:
        A tuple of the fetched events and a CommandResults for display.
    """
    limit = arg_to_number(args.get("limit")) or 50
    now = datetime.utcnow()
    end_date = args.get("end_date") or now.strftime(DATE_FORMAT)
    start_date = args.get("start_date") or (now - timedelta(hours=1)).strftime(DATE_FORMAT)

    events = client.get_message_trace(start_date=start_date, end_date=end_date, top=limit)
    events = add_time_field(events)

    human_readable = tableToMarkdown(name="O365 Message Trace Events", t=events)
    results = CommandResults(readable_output=human_readable)
    return events, results


def fetch_events(client: Client, last_run: dict[str, Any], first_fetch: str, max_fetch: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch new message trace events since the last run.

    Args:
        client: Configured API client.
        last_run: The integration's last run object.
        first_fetch: Human-readable first fetch window (e.g., '3 days').
        max_fetch: Maximum number of events to fetch.

    Returns:
        A tuple of the next last_run object and the list of fetched events.
    """
    now = datetime.utcnow()
    end_date = now.strftime(DATE_FORMAT)
    start_date = last_run.get("last_fetch")
    if not start_date:
        first_fetch_dt = dateparser.parse(first_fetch)
        start_date = first_fetch_dt.strftime(DATE_FORMAT) if first_fetch_dt else (now - timedelta(days=3)).strftime(DATE_FORMAT)

    events = client.get_message_trace(start_date=start_date, end_date=end_date, top=max_fetch)
    events = add_time_field(events)

    next_run = {"last_fetch": end_date}
    demisto.debug(f"O365 Message Trace fetched {len(events)} events.")
    return next_run, events


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get("base_url", "").rstrip("/")
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier", "")  # type: ignore[union-attr]
    password = credentials.get("password", "")  # type: ignore[union-attr]
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, username=username, password=password, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))

        elif command == "o365-message-trace-get-events":
            events, results = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(client, last_run, first_fetch, max_fetch)
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
