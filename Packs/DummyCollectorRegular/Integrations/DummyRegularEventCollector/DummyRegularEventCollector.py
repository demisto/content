import random
import time
from typing import Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "dummy"
PRODUCT = "collector"
COLLECTOR_SOURCE = "regular"
INTEGRATION_ID = "DummyRegularEventCollector"
PACK_NAME = "DummyCollectorRegular"
GET_EVENTS_COMMAND = "dummy-regular-get-events"

DEFAULT_LIMIT = 5
EVENT_TYPES = ["login", "logout", "file_access", "config_change"]
SEVERITIES = ["low", "medium", "high"]
USERS_POOL_SIZE = 10

""" CLIENT CLASS """


class Client:
    """Generates fake events. No real API calls are made.

    The collector identity (source, integration ID, pack name) is injected so that
    a sibling pack can reuse this code by changing only the module constants.
    """

    def __init__(self, collector_source: str, integration_id: str, pack_name: str) -> None:
        self.collector_source = collector_source
        self.integration_id = integration_id
        self.pack_name = pack_name

    def generate_event(self, event_id: int) -> dict[str, Any]:
        """Generates a single fake event with the given ID."""
        return {
            "id": event_id,
            "collector_source": self.collector_source,
            "integration_id": self.integration_id,
            "pack_name": self.pack_name,
            "event_type": random.choice(EVENT_TYPES),  # noqa: S311
            "severity": random.choice(SEVERITIES),  # noqa: S311
            "user": f"user{random.randint(1, USERS_POOL_SIZE)}@dummy.local",  # noqa: S311
            "source_ip": generate_private_ip(),
            "message": f"[{self.collector_source}] Dummy event #{event_id}",
            "created_time": time.strftime(DATE_FORMAT, time.gmtime()),
        }

    def generate_events(self, last_id: int, limit: int) -> list[dict[str, Any]]:
        """Generates `limit` fake events with IDs continuing from `last_id`."""
        demisto.debug(f"Generating {limit} events starting after id {last_id}.")
        return [self.generate_event(event_id) for event_id in range(last_id + 1, last_id + limit + 1)]


""" HELPER FUNCTIONS """


def generate_private_ip() -> str:
    """Returns a random IPv4 address from the 10.0.0.0/8 private range."""
    octets = [random.randint(0, 255) for _ in range(2)]  # noqa: S311
    return f"10.{octets[0]}.{octets[1]}.{random.randint(1, 254)}"  # noqa: S311


def add_time_to_events(events: list[dict[str, Any]]) -> None:
    """Sets the `_time` key of each event from its `created_time` field."""
    for event in events:
        created_time = arg_to_datetime(arg=event.get("created_time"))
        event["_time"] = created_time.strftime(DATE_FORMAT) if created_time else None


def parse_limit(value: Any) -> int:
    """Parses a positive events limit, falling back to the default."""
    limit = arg_to_number(value) or DEFAULT_LIMIT
    if limit <= 0:
        raise DemistoException(f"The limit must be a positive integer, got {limit}.")
    return limit


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validates that events can be generated. Returns 'ok' on success."""
    client.generate_events(last_id=0, limit=1)
    return "ok"


def fetch_events(client: Client, last_run: dict[str, Any], max_events_per_fetch: int) -> tuple[dict[str, int], list[dict]]:
    """Generates the next batch of events and computes the next run.

    Args:
        client: The dummy client.
        last_run: The last run object, holding `last_id`.
        max_events_per_fetch: Number of events to generate.

    Returns:
        The next run dict and the list of generated events.
    """
    last_id = int(last_run.get("last_id") or 0)
    events = client.generate_events(last_id=last_id, limit=max_events_per_fetch)
    new_last_id = events[-1]["id"] if events else last_id
    demisto.debug(f"Generated {len(events)} events, new last_id is {new_last_id}.")
    return {"last_id": new_last_id}, events


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict], CommandResults]:
    """Generates events for display (and optional push) without affecting the last run."""
    limit = parse_limit(args.get("limit"))
    events = client.generate_events(last_id=0, limit=limit)
    readable_output = tableToMarkdown(name=f"Dummy Events ({COLLECTOR_SOURCE})", t=events, removeNull=True)
    return events, CommandResults(readable_output=readable_output, raw_response=events)


def push_events(events: list[dict[str, Any]]) -> None:
    """Adds `_time` to the events and sends them to XSIAM."""
    add_time_to_events(events)
    demisto.debug(f"Sending {len(events)} events to XSIAM.")
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
    demisto.debug("Sent events to XSIAM successfully.")


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Parses params and runs command functions."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(collector_source=COLLECTOR_SOURCE, integration_id=INTEGRATION_ID, pack_name=PACK_NAME)
        max_events_per_fetch = parse_limit(params.get("max_events_per_fetch"))

        if command == "test-module":
            return_results(test_module(client))

        elif command == GET_EVENTS_COMMAND:
            should_push_events = argToBoolean(args.get("should_push_events", False))
            events, results = get_events_command(client, args)
            return_results(results)
            if should_push_events:
                push_events(events)

        elif command == "fetch-events":
            next_run, events = fetch_events(client, demisto.getLastRun(), max_events_per_fetch)
            push_events(events)
            demisto.setLastRun(next_run)
            demisto.debug(f"Setting next run to {next_run}.")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
