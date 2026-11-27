import hashlib
import uuid
from datetime import timezone
from typing import Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" CONSTANTS """

VENDOR = "acmedemo"
PRODUCT = "auditlogs"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 1000
DEFAULT_LIMIT = 10
EVENT_STEP = timedelta(minutes=1)
EVENT_ID_NAMESPACE = uuid.UUID("6f1c2b0e-8a3d-4c5e-9b7a-acde00000001")

EVENT_TYPES = ["login", "logout", "file_access", "config_change", "user_created"]
OUTCOMES = ["success", "failure"]
SEVERITIES = ["low", "medium", "high"]
USERS = [
    {"id": "u-1001", "name": "alice", "email": "alice@acmedemo.example.com"},
    {"id": "u-1002", "name": "bob", "email": "bob@acmedemo.example.com"},
    {"id": "u-1003", "name": "carol", "email": "carol@acmedemo.example.com"},
    {"id": "u-1004", "name": "dave", "email": "dave@acmedemo.example.com"},
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "AcmeDemoCLI/2.3.1 (linux; amd64)",
    "python-requests/2.31.0",
]
TARGETS = [
    {"type": "file", "name": "/reports/q3-financials.xlsx"},
    {"type": "setting", "name": "mfa_policy"},
    {"type": "user", "name": "new.hire@acmedemo.example.com"},
    {"type": "application", "name": "acmedemo-console"},
]

""" CLIENT CLASS """


class Client(BaseClient):
    """Demo client that generates deterministic synthetic audit events locally. Never performs network calls."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def generate_events(self, start_time: datetime, end_time: datetime, limit: int) -> list[dict]:
        """Generates up to `limit` events, one per whole minute, in the window (start_time, end_time].

        Args:
            start_time: Exclusive window start.
            end_time: Inclusive window end.
            limit: Maximum number of events to return.

        Returns:
            list[dict]: Events in strictly ascending `created_time` order.
        """
        events: list[dict] = []
        current_time = to_utc(start_time).replace(second=0, microsecond=0) + EVENT_STEP
        end_time = to_utc(end_time)
        while len(events) < limit and current_time <= end_time:
            events.append(build_event(current_time.strftime(DATE_FORMAT), index=0))
            current_time += EVENT_STEP
        return events


""" HELPER FUNCTIONS """


def utc_now() -> datetime:
    """Returns the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def to_utc(date_time: datetime) -> datetime:
    """Normalizes a datetime to a timezone-aware UTC datetime."""
    if date_time.tzinfo is None:
        return date_time.replace(tzinfo=timezone.utc)
    return date_time.astimezone(timezone.utc)


def parse_time(time_str: str) -> datetime:
    """Parses a DATE_FORMAT string into a timezone-aware UTC datetime."""
    return datetime.strptime(time_str, DATE_FORMAT).replace(tzinfo=timezone.utc)


def build_source_ip(seed: int) -> str:
    """Builds a deterministic source IP - mostly IPv4, occasionally IPv6.

    Uses seed bits independent of the event type selection, so every event type can have either IP family.
    """
    if (seed >> 40) % 5 == 0:
        return f"2001:db8:{(seed >> 8) % 65536:x}::{(seed >> 24) % 65536:x}"
    return f"198.51.{(seed >> 8) % 256}.{(seed >> 16) % 254 + 1}"


def build_event(created_time: str, index: int) -> dict:
    """Builds a single deterministic event from its creation time and index."""
    seed = int(hashlib.sha256(f"{created_time}-{index}".encode()).hexdigest(), 16)
    event_type = EVENT_TYPES[seed % len(EVENT_TYPES)]
    outcome = OUTCOMES[(seed >> 4) % len(OUTCOMES)]
    user = dict(USERS[(seed >> 12) % len(USERS)])
    target = dict(TARGETS[(seed >> 20) % len(TARGETS)])
    return {
        "id": str(uuid.uuid5(EVENT_ID_NAMESPACE, f"{created_time}-{index}")),
        "created_time": created_time,
        "event_type": event_type,
        "outcome": outcome,
        "user": user,
        "source_ip": build_source_ip(seed),
        "user_agent": USER_AGENTS[(seed >> 28) % len(USER_AGENTS)],
        "target": target,
        "severity": SEVERITIES[(seed >> 32) % len(SEVERITIES)],
        "message": f"User {user['name']} performed {event_type} on {target['type']} {target['name']} ({outcome})",
    }


def add_time_to_events(events: list[dict]) -> None:
    """Sets the `_time` field of each event to its `created_time`."""
    for event in events:
        event["_time"] = event["created_time"]


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Returns 'ok' when an API key is configured. No network calls are made."""
    if not client.api_key:
        raise DemistoException("API Key is required. Enter any non-empty value in the API Key parameter.")
    return "ok"


def build_next_run(events: list[dict], last_run: dict, start_time: datetime) -> dict:
    """Builds the next last_run from the newest event, or keeps/initializes it when there are no events."""
    if not events:
        return last_run or {"last_fetch_time": start_time.strftime(DATE_FORMAT), "last_ids": []}
    newest_time = events[-1]["created_time"]
    return {
        "last_fetch_time": newest_time,
        "last_ids": [event["id"] for event in events if event["created_time"] == newest_time],
    }


def fetch_events(client: Client, last_run: dict, first_fetch_time: datetime, max_fetch: int) -> tuple[dict, list[dict]]:
    """Fetches new events since the last run, deduplicating events already fetched at the boundary timestamp.

    Returns:
        tuple: The next run dict and the list of new events.
    """
    last_fetch_time = last_run.get("last_fetch_time")
    start_time = parse_time(last_fetch_time) if last_fetch_time else to_utc(first_fetch_time)
    last_ids = set(last_run.get("last_ids") or [])

    events = client.generate_events(start_time=start_time, end_time=utc_now(), limit=max_fetch)
    events = [event for event in events if event["id"] not in last_ids]
    demisto.debug(f"Generated {len(events)} new events since {start_time.strftime(DATE_FORMAT)}.")
    return build_next_run(events, last_run, start_time), events


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict], CommandResults]:
    """Gets events for display, and optionally pushes them to XSIAM."""
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    start_time = arg_to_datetime(args.get("start_time") or DEFAULT_FIRST_FETCH, required=True)
    should_push_events = argToBoolean(args.get("should_push_events", False))

    events = client.generate_events(start_time=start_time, end_time=utc_now(), limit=limit)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(
        "AcmeDemo Audit Events", events, headerTransform=string_to_table_header, removeNull=True
    )
    if should_push_events:
        add_time_to_events(events)
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        return events, CommandResults(readable_output=readable_output)

    return events, CommandResults(
        outputs_prefix="AcmeDemo.Event",
        outputs_key_field="id",
        outputs=events,
        readable_output=readable_output,
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=params.get("url", ""),
            api_key=(params.get("credentials") or {}).get("password", ""),
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
        )
        first_fetch_time = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, required=True)
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

        if command == "test-module":
            return_results(test_module(client))

        elif command == "acmedemo-get-events":
            _, results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            next_run, events = fetch_events(
                client=client,
                last_run=demisto.getLastRun() or {},
                first_fetch_time=first_fetch_time,  # type: ignore[arg-type]
                max_fetch=max_fetch,
            )
            add_time_to_events(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)
            demisto.debug(f"Set next run to {next_run}.")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
