from contextlib import contextmanager
from enum import Enum
from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from websockets.exceptions import InvalidStatus
from dateutil import tz
import traceback


VENDOR = "proofpoint"
PRODUCT = "email_security"

URL = "{host}/v1/stream?cid={cluster_id}&type={type}&sinceTime={time}"


FETCH_INTERVAL_IN_SECONDS = 60
FETCH_SLEEP = 5


class EventType(str, Enum):
    MESSAGE = "message"
    MAILLOG = "maillog"


def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    """This function checks if the given interval has passed since the given start time

    Args:
        fetch_start_time (datetime): The start time of the interval
        fetch_interval (int): The interval in seconds

    Returns:
        bool: True if the interval has passed, False otherwise
    """
    return fetch_start_time + timedelta(seconds=fetch_interval) < datetime.utcnow()


@contextmanager
def websocket_connections(
    host: str, cluster_id: str, api_key: str, since_time: str | None = None, to_time: str | None = None
):
    demisto.info(
        f"Starting websocket connection to {host} with cluster id: {cluster_id}, sinceTime: {since_time}, toTime: {to_time}")
    url = URL
    if not since_time:
        since_time = datetime.utcnow().isoformat()
    if to_time:
        url += f"&toTime={to_time}"
    extra_headers = {"Authorization": f"Bearer {api_key}"}
    with connect(
        url.format(host=host, cluster_id=cluster_id, type=EventType.MESSAGE.value, time=since_time),
        additional_headers=extra_headers,
    ) as message_connection, connect(
        url.format(host=host, cluster_id=cluster_id, type=EventType.MAILLOG.value, time=since_time),
        additional_headers=extra_headers,
    ) as maillog_connection:
        yield message_connection, maillog_connection


def fetch_events(event_type: EventType, connection: Connection, fetch_interval: int, recv_timeout: int = 10) -> list[dict]:
    """
    This function fetches events from the websocket connection for the given event type, for the given fetch interval

    Args:
        event_type (EventType): The event type to fetch (MAILLOG, MESSAGE)
        connection (Connection): the websocket connection to the event type
        fetch_interval (int): the interval of events to fetch, in seconds
        recv_timeout (int): The timeout for the receive function in the socket connection

    Returns:
        list[dict]: A list of events
    """
    events: list[dict] = []
    event_ids = set()
    fetch_start_time = datetime.utcnow()
    while not is_interval_passed(fetch_start_time, fetch_interval):
        try:
            event = json.loads(connection.recv(timeout=recv_timeout))
        except TimeoutError:
            # if we didn't receive an event for `fetch_interval` seconds, finish fetching
            continue
        event_id = event.get("id", event.get("guid"))
        event_ts = event.get("ts")
        if not event_ts:
            # if timestamp is not in the response, use the current time
            demisto.debug(f"Event {event_id} does not have a timestamp, using current time")
            event_ts = datetime.utcnow().isoformat()
        date = dateparser.parse(event_ts)
        if not date:
            demisto.debug(f"Event {event_id} has an invalid timestamp, using current time")
            # if timestamp is not in correct format, use the current time
            date = datetime.utcnow()
        # the `ts` parameter is not always in UTC, so we need to convert it
        event["_time"] = date.astimezone(tz.tzutc()).isoformat()
        event["event_type"] = event_type.value
        events.append(event)
        event_ids.add(event_id)
    demisto.debug(f"Fetched {len(events)} events of type {event_type.value}")
    demisto.debug("The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))
    return events


def test_module(host: str, cluster_id: str, api_key: str):
    # set the fetch interval to 2 seconds so we don't get timeout for the test module
    fetch_interval = 2
    recv_timeout = 2
    try:
        with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
            fetch_events(EventType.MESSAGE, message_connection, fetch_interval, recv_timeout)
            fetch_events(EventType.MAILLOG, maillog_connection, fetch_interval, recv_timeout)
            return "ok"
    except InvalidStatus as e:
        if e.response.status_code == 401:
            return_error("Authentication failed. Please check the Cluster ID and API key.")


def perform_long_running_loop(message_connection: Connection, maillog_connection: Connection, fetch_interval: int):
    message_events = fetch_events(EventType.MESSAGE, message_connection, fetch_interval)
    maillog_events = fetch_events(EventType.MAILLOG, maillog_connection, fetch_interval)
    # Send the events to the XSIAM, with events from the context
    integration_context = demisto.getIntegrationContext()
    message_events_from_context = integration_context.get("message_events", [])
    message_maillog_from_context = integration_context.get("maillog_events", [])

    message_events.extend(message_events_from_context)
    maillog_events.extend(message_maillog_from_context)
    demisto.info(f"Adding {len(message_events)} Message Events, and {len(maillog_events)} MailLog Events to XSIAM")

    try:
        send_events_to_xsiam(message_events + maillog_events, vendor=VENDOR, product=PRODUCT)
        # clear the context after sending the events
        demisto.setIntegrationContext({})
    except DemistoException:
        demisto.error(f"Failed to send events to XSOAR. Error: {traceback.format_exc()}")
        # save the events to the context so we can send them again in the next execution
        demisto.setIntegrationContext({"message_events": message_events, "maillog_events": maillog_events})


def long_running_execution_command(host: str, cluster_id: str, api_key: str, fetch_interval: int):
    fetch_interval = max(1, fetch_interval // len(EventType))
    with websocket_connections(host, cluster_id, api_key) as (message_connection, maillog_connection):
        demisto.info("Connected to websocket")
        while True:
            perform_long_running_loop(message_connection, maillog_connection, fetch_interval)
            # sleep for a bit to not throttle the CPU
            time.sleep(FETCH_SLEEP)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(host, cluster_id, api_key, fetch_interval))
        elif command == "test-module":
            return_results(test_module(host, cluster_id, api_key))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
