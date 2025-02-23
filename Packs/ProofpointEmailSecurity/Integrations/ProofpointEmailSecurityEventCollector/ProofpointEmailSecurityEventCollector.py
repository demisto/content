from contextlib import ExitStack, contextmanager
from enum import Enum
from functools import partial
import threading

from websockets import Data
from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from websockets.exceptions import InvalidStatus
from dateutil import tz
import ijson
import traceback


VENDOR = "proofpoint"
PRODUCT = "email_security"

URL = "{host}/v1/stream?cid={cluster_id}&type={type}&sinceTime={time}"


FETCH_INTERVAL_IN_SECONDS = 60
FETCH_SLEEP = 5
SERVER_IDLE_TIMEOUT = 300


class EventType(str, Enum):
    MESSAGE = 'message'
    MAILLOG = 'maillog'
    AUDIT = 'audit'


class EventConnection:
    def __init__(self, event_type: EventType, connection: Connection, fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
                 idle_timeout: int = SERVER_IDLE_TIMEOUT - 20):
        self.event_type = event_type
        self.connection = connection
        self.lock = threading.Lock()
        self.idle_timeout = idle_timeout
        self.fetch_interval = fetch_interval

    def recv(self, timeout: float | None = None) -> Data:
        """
        Receive the next message from the connection

        Args:
            timeout (float): Block until timeout seconds have elapsed or a message is received. If None, waits indefinitely.
                             If timeout passes, raises TimeoutError

        Returns:
            Data: Next event received from the connection
        """
        with self.lock:
            event = self.connection.recv(timeout=timeout)
        return event

    def heartbeat(self):
        """
        Heartbeat thread function to periodically send keep-alives to the server.
        For the sake of simplicity and error prevention, keep-alives are sent regardless of the actual connection activity.
        """
        while True:
            with self.lock:
                self.connection.pong()
            time.sleep(self.idle_timeout)


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
        host: str, cluster_id: str, api_key: str, since_time: str | None = None, to_time: str | None = None,
        fetch_interval: int = FETCH_INTERVAL_IN_SECONDS):
    """
    Create a connection for every type of event.

    Args:
        host (str): host URL for the websocket connection.
        cluster_id (str): Proofpoint cluster ID to connect to.
        api_key (str): Proofpoint API key.
        since_time (str): Start time to fetch events from.
        to_time (str): End time for fetch, leave empty for real-time streaming.
        fetch_interval (int): Time between fetch iterations, used for estimating message receive times for idle heartbeat.

    Yields:
        list[EventConnection]: List containing an eventConnection for every event type
    """
    demisto.info(
        f"Starting websocket connection to {host} with cluster id: {cluster_id}, sinceTime: {since_time}, toTime: {to_time}")
    url = URL
    if not since_time:
        since_time = datetime.utcnow().isoformat()
    if to_time:
        url += f"&toTime={to_time}"

    url = partial(url.format, host=host, cluster_id=cluster_id, time=since_time)
    demisto.info(f"Constructed URL: {url}")

    extra_headers = {"Authorization": f"Bearer {api_key}"}
    demisto.info(f"Authorization Header: {extra_headers}")

    with ExitStack() as stack:  # Keep connection contexts for clean up
        connections = []
        for event_type in EventType:
            connection_url = url(type=event_type.value)
            demisto.info(f"Connecting to URL: {connection_url} with headers: {extra_headers}")
            connection = stack.enter_context(connect(connection_url, additional_headers=extra_headers))
            connections.append(EventConnection(
                event_type=event_type,
                connection=connection,
                fetch_interval=fetch_interval,
            ))

        yield connections


def fetch_events(connection: EventConnection, fetch_interval: int, recv_timeout: int = 10) -> list[dict]:
    """
    This function fetches events from the given connection, for the given fetch interval

    Args:
        connection (EventConnection): the connection to the event type
        fetch_interval (int): Total time to keep fetching before stopping
        recv_timeout (int): The timeout for the receive function in the socket connection

    Returns:
        list[dict]: A list of events
    """
    event_type = connection.event_type
    demisto.debug(f'Starting to fetch events of type {event_type.value}')
    events: list[dict] = []
    event_ids = set()
    fetch_start_time = datetime.utcnow()
    while not is_interval_passed(fetch_start_time, fetch_interval):
        try:
            raw_event = connection.recv(timeout=recv_timeout)
            event = next(ijson.items(raw_event, ''))
        except TimeoutError:
            # if we didn't receive an event for `fetch_interval` seconds, finish fetching
            continue
        except ijson.JSONError as e:
            demisto.error(f"Failed to parse JSON: {str(e)}")
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
    # fetch_interval = 2
    # recv_timeout = 2
    # try:
    #     with websocket_connections(host, cluster_id, api_key) as connections:
    #         for connection in connections:
    #             fetch_events(connection, fetch_interval, recv_timeout)
    #         return "ok"
    # except InvalidStatus as e:
    #     if e.response.status_code == 401:
    #         return_error("Authentication failed. Please check the Cluster ID and API key.")
    #     else:
    #         return_error(f"Failed with status code: {e.response.status_code}")
    # except Exception as e:
    #     return_error(f"An unexpected error occurred: {str(e)}")
    return "Test module is expected to fail."


def perform_long_running_loop(connections: list[EventConnection], fetch_interval: int):
    """
    Long running loop iteration function. Fetches events from each connection and sends them to XSIAM.

    Args:
        connections (list[EventConnection]): List of connection objects to fetch events from.
        fetch_interval (int): Fetch time per cycle allocated for each event type in seconds.
    """
    integration_context = demisto.getIntegrationContext()
    events_to_send = []
    for connection in connections:
        events = fetch_events(connection, fetch_interval)
        events.extend(integration_context.get(connection.event_type.value, []))
        integration_context[connection.event_type.value] = events  # update events in context in case of fail
        demisto.debug(f'Adding {len(events)} {connection.event_type.value} Events to XSIAM')
        events_to_send.extend(events)

    # Send the events to the XSIAM, with events from the context
    try:
        send_events_to_xsiam(events_to_send, vendor=VENDOR, product=PRODUCT)
        # clear the context after sending the events
        demisto.setIntegrationContext({})
    except DemistoException:
        demisto.error(f"Failed to send events to XSIAM. Error: {traceback.format_exc()}")
        # save the events to the context so we can send them again in the next execution
        demisto.setIntegrationContext(integration_context)


def long_running_execution_command(host: str, cluster_id: str, api_key: str, fetch_interval: int):
    """
    Performs the long running execution loop.
    Opens a connection to Proofpoints for every event type and fetches events in a loop.
    Heartbeat threads are opened for every connection to send keepalives if the connection is idle for too long.

    Args:
        host (str): host URL for the websocket connection.
        cluster_id (str): Proofpoint cluster ID to connect to.
        api_key (str): Proofpoint API key.
        fetch_interval (int): Total time allocated per fetch cycle.
    """
    with websocket_connections(host, cluster_id, api_key, fetch_interval=fetch_interval) as connections:
        demisto.info("Connected to websocket")
        fetch_interval = max(1, fetch_interval // len(EventType))  # Divide the fetch interval equally among all event types

        # The Proofpoint server will close connections if they are idle for 5 minutes
        # Setting up heartbeat daemon threads to send keep-alives if needed
        for connection in connections:
            threading.Thread(target=connection.heartbeat, daemon=True).start()

        while True:
            perform_long_running_loop(connections, fetch_interval)
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
