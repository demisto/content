from contextlib import contextmanager
from enum import Enum
from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from dateutil import tz

VENDOR = "proofpoint"
PRODUCT = "email_security"

URL = "wss://{host}/v1/stream?cid={cluster_id}&type={type}&sinceTime={time}"


EVENTS_TO_FETCH = 30
TIMEOUT = 20


class EventType(str, Enum):
    MESSAGE = "message"
    MAILLOG = "maillog"


@contextmanager
def websocket_connections(host: str, cluster_id: str, api_key: str):
    now = datetime.utcnow().isoformat()
    demisto.info("Starting websocket connection")
    extra_headers = {"Authorization": f"Bearer {api_key}"}
    with connect(
        URL.format(host=host, cluster_id=cluster_id, type=EventType.MESSAGE.value, time=now),
        additional_headers=extra_headers,
    ) as message_connection, connect(
        URL.format(host=host, cluster_id=cluster_id, type=EventType.MAILLOG.value, time=now),
        additional_headers=extra_headers,
    ) as maillog_connection:
        yield message_connection, maillog_connection


def fetch_events(event_type: EventType, connection: Connection, events_to_fetch: int, timeout: int) -> list[dict]:
    events: list[dict] = []
    while len(events) < events_to_fetch:
        try:
            event = json.loads(connection.recv(timeout=timeout))
            event_ts = event.get("ts")
            if not event_ts:
                raise DemistoException(f"Event does not contain a timestamp: {event}")
            date = dateparser.parse(event_ts)
            if not date:
                raise DemistoException(f"Failed to parse date: {event_ts}")
            # the `ts` parameter is not always in UTC, so we need to convert it
            event["_time"] = date.astimezone(tz.tzutc()).isoformat()
            events.append(event)
            demisto.debug(f"Received event. length of events from {event_type} is: {len(events)}")
        except TimeoutError:
            demisto.debug(f"Reached the end of time windows to collect events. Collected {len(events)} events from {event_type}")
            break
    return events


def test_module(host: str, cluster_id: str, api_key: str):
    # edit the global variables to make the test module faster
    events_to_fetch = 1
    timeout = 10
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        fetch_events(EventType.MESSAGE, message_connection, events_to_fetch, timeout)
        fetch_events(EventType.MAILLOG, maillog_connection, events_to_fetch, timeout)
        return "ok"


def long_running_execution_command(host: str, cluster_id: str, api_key: str, events_to_fetch: int, timeout: int):
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        demisto.info("Connected to websocket")
        while True:
            message_events = fetch_events(EventType.MESSAGE, message_connection, events_to_fetch, timeout)
            maillog_events = fetch_events(EventType.MAILLOG, maillog_connection, events_to_fetch, timeout)
            demisto.info(f"Adding {len(message_events) + len(maillog_events)} events to XSIAM")
            # Send the events to the XSIAM
            send_events_to_xsiam(message_events + maillog_events, vendor=VENDOR, product=PRODUCT)


def main():
    command = demisto.command()
    params = demisto.params()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    events_to_fetch = params.get("events_to_fetch", EVENTS_TO_FETCH)
    timeout = params.get("fetch_timeout", TIMEOUT)
    if command == "long-running-execution":
        return_results(long_running_execution_command(host, cluster_id, api_key, events_to_fetch, timeout))
    if command == "test-module":
        return_results(test_module(host, cluster_id, api_key))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
