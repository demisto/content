from contextlib import contextmanager
from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from dateutil import tz

VENDOR = "proofpoint"
PRODUCT = "on_demand_email_security"

URL = "wss://{host}/v1/stream?cid={cluster_id}&type={type}&sinceTime={time}"


EVENTS_TO_FETCH = 10


@contextmanager
def websocket_connections(host: str, cluster_id: str, api_key: str):
    now = datetime.utcnow().isoformat()
    demisto.info("Starting websocket connection")
    extra_headers = {"Authorization": f"Bearer {api_key}"}
    with connect(
        URL.format(host=host, cluster_id=cluster_id, type="message", time=now),
        additional_headers=extra_headers,
    ) as message_connection, connect(
        URL.format(host=host, cluster_id=cluster_id, type="maillog", time=now),
        additional_headers=extra_headers,
    ) as maillog_connection:
        yield message_connection, maillog_connection


def fetch_events(connection: Connection) -> list[dict]:
    events: list[dict] = []
    while len(events) < EVENTS_TO_FETCH:
        try:
            event = json.loads(connection.recv(timeout=60))
            event_ts = event.get("ts")
            if not event_ts:
                raise DemistoException(f"Event does not contain a timestamp: {event}")
            date = dateparser.parse(event_ts)
            if not date:
                raise DemistoException(f"Failed to parse date: {event_ts}")
            # the `ts` parameter is not always in UTC, so we need to convert it
            event["_time"] = date.astimezone(tz.tzutc()).isoformat()
            events.append(event)
            demisto.debug(f"Received event. length of events from {connection.remote_address} is: {len(events)}")
        except TimeoutError:
            demisto.debug("Timeout reached when receiving events")
            break
    return events


def test_module(host: str, cluster_id: str, api_key: str):
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        fetch_events(message_connection)
        fetch_events(maillog_connection)
        return "ok"


def long_running_execution_command(host: str, cluster_id: str, api_key: str):
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        demisto.info("Connected to websocket")
        while True:
            message_events = fetch_events(message_connection)
            maillog_events = fetch_events(maillog_connection)
            demisto.info(f"Adding {len(message_events) + len(maillog_events)} events to XSIAM")
            # Send the events to the XSIAM
            send_events_to_xsiam(message_events, vendor=VENDOR, product=PRODUCT)
            send_events_to_xsiam(maillog_events, vendor=VENDOR, product=PRODUCT)


def main():
    command = demisto.command()
    params = demisto.params()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    if command == "long-running-execution":
        long_running_execution_command(host, cluster_id, api_key)
    if command == "test-module":
        test_module(host, cluster_id, api_key)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
