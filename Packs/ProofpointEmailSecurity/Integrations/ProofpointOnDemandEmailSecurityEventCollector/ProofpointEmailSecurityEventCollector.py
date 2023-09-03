from contextlib import contextmanager
from enum import Enum
from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from dateutil import tz

VENDOR = "proofpoint"
PRODUCT = "email_security"

URL = "wss://{host}/v1/stream?cid={cluster_id}&type={type}&sinceTime={time}"


FETCH_INTERVAL_IN_SECONDS = 60
TIMEOUT = 10


class EventType(str, Enum):
    MESSAGE = "message"
    MAILLOG = "maillog"


def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    return datetime.utcnow() > fetch_start_time + timedelta(seconds=fetch_interval)


@contextmanager
def websocket_connections(
    host: str, cluster_id: str, api_key: str, since_time: str | None = None, to_time: str | None = None
):
    url = URL
    if not since_time:
        since_time = datetime.utcnow().isoformat()
    if to_time:
        url += f"&toTime={to_time}"
    demisto.info("Starting websocket connection")
    extra_headers = {"Authorization": f"Bearer {api_key}"}
    with connect(
        url.format(host=host, cluster_id=cluster_id, type=EventType.MESSAGE.value, time=since_time),
        additional_headers=extra_headers,
    ) as message_connection, connect(
        url.format(host=host, cluster_id=cluster_id, type=EventType.MAILLOG.value, time=since_time),
        additional_headers=extra_headers,
    ) as maillog_connection:
        yield message_connection, maillog_connection


def fetch_events(event_type: EventType, connection: Connection, fetch_interval: int) -> list[dict]:
    """
    This function fetches events from the websocket connection for the given event type, for the given fetch interval

    Args:
        event_type (EventType): The event type to fetch (MAILLOG, MESSAGE)
        connection (Connection): the websocket connection to the event type
        fetch_interval (int): the interval of events to fetch, in seconds

    Returns:
        list[dict]: A list of events
    """
    events: list[dict] = []
    fetch_start_time = datetime.utcnow()
    while not is_interval_passed(fetch_start_time, fetch_interval):
        try:
            event = json.loads(connection.recv(timeout=TIMEOUT))
        except TimeoutError:
            # if we didn't receive an event, try again
            continue
        event_ts = event.get("ts")
        if not event_ts:
            # if timestamp is not in the response, use the current time
            event_ts = datetime.utcnow().isoformat()
        date = dateparser.parse(event_ts)
        if not date:
            # if timestamp is not in correct format, use the current time
            date = datetime.utcnow()
        # the `ts` parameter is not always in UTC, so we need to convert it
        event["_time"] = date.astimezone(tz.tzutc()).isoformat()
        event["event_type"] = event_type.value
        events.append(event)
    demisto.debug(f"Fetched {len(events)} events of type {event_type}")
    demisto.debug("The events ids are: " + ", ".join([str(event.get("id", event.get("guid"))) for event in events]))
    return events


def get_events(host: str, cluster_id: str, api_key: str, since_time: str | None, to_time: str | None) -> CommandResults:
    with websocket_connections(host, cluster_id, api_key, since_time, to_time) as (
        message_connection,
        maillog_connection,
    ):
        message_events = fetch_events(EventType.MESSAGE, message_connection, FETCH_INTERVAL_IN_SECONDS)
        maillog_events = fetch_events(EventType.MAILLOG, maillog_connection, FETCH_INTERVAL_IN_SECONDS)
        return CommandResults(
            outputs_prefix="ProopolintEmailSecurityEvents",
            outputs_key_field="id",
            outputs=message_events + maillog_events,
        )


def test_module(host: str, cluster_id: str, api_key: str):
    # set the fetch interval to 10 seconds so we don't get timeout for the test module
    fetch_interval = 10
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        fetch_events(EventType.MESSAGE, message_connection, fetch_interval)
        fetch_events(EventType.MAILLOG, maillog_connection, fetch_interval)
        return "ok"


def long_running_execution_command(host: str, cluster_id: str, api_key: str, fetch_interval: int):
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        demisto.info("Connected to websocket")
        while True:
            message_events = fetch_events(EventType.MESSAGE, message_connection, fetch_interval)
            maillog_events = fetch_events(EventType.MAILLOG, maillog_connection, fetch_interval)
            demisto.info(f"Adding {len(message_events) + len(maillog_events)} events to XSIAM")
            # Send the events to the XSIAM
            send_events_to_xsiam(message_events + maillog_events, vendor=VENDOR, product=PRODUCT)


def main():
    command = demisto.command()
    params = demisto.params()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))
    if command == "long-running-execution":
        return_results(long_running_execution_command(host, cluster_id, api_key, fetch_interval))
    elif command == "test-module":
        return_results(test_module(host, cluster_id, api_key))
    else:
        raise NotImplementedError(f"Command {command} is not implemented.")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
