from contextlib import ExitStack, contextmanager
from enum import Enum
from functools import partial
from threading import Thread, Lock

from dateutil import tz
from websockets import exceptions
from websockets.sync.client import connect
from websockets.sync.connection import Connection

import demistomock as demisto
from CommonServerPython import *

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
    def __init__(self, event_type: EventType, url: str, headers: dict,
                 fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
                 idle_timeout: int = SERVER_IDLE_TIMEOUT - 20):
        self.event_type = event_type.value
        self.url = url
        self.headers = headers
        self.lock = Lock()
        self.idle_timeout = idle_timeout
        self.fetch_interval = fetch_interval
        self.connection = self.connect()
        self.heartbeat_thread = Thread(target=self.heartbeat, daemon=True)
        self.heartbeat_thread.start()

    def connect(self) -> Connection:
        """
        Establish a new WebSocket connection.
        """
        return connect(self.url, additional_headers=self.headers)

    def recv(self, timeout: float | None = None) -> Any:
        """
        Receive the next message from the connection

        Args:
            timeout (float): Block until timeout seconds have elapsed or a message is received. If None, waits indefinitely.
                             If timeout passes, raises TimeoutError

        Returns:
            Any: Next event received from the connection
        """
        with self.lock:
            event = self.connection.recv(timeout=timeout)
        return event

    def reconnect(self):
        """
        Reconnect logic for the WebSocket connection.
        """
        with self.lock:
            try:
                self.connection = self.connect()
                demisto.info(f"[{self.event_type}] Successfully reconnected to WebSocket")
            except Exception as e:
                demisto.error(f"[{self.event_type}] Reconnection failed: {str(e)} {traceback.format_exc()}")
                raise

    def heartbeat(self):
        """
        Heartbeat thread function to periodically send keep-alives (pong) to the server.
        Keep-alives are sent regardless of the actual connection activity to ensure the connection remains open.
        """
        while True:
            try:
                with self.lock:
                    self.connection.pong()
                demisto.info(f"[{self.event_type}] Sent heartbeat pong")
                time.sleep(self.idle_timeout)
            except exceptions.ConnectionClosedError as e:
                demisto.error(f"[{self.event_type}] Connection closed due to error in thread - {self.event_type}: {str(e)}")
                self.reconnect()
            except exceptions.ConnectionClosedOK:
                demisto.info(f"[{self.event_type}] Connection closed OK in thread - {self.event_type}")
                self.reconnect()
            except Exception as e:
                demisto.error(f"[{self.event_type}] Unexpected error in heartbeat: {str(e)} {traceback.format_exc()}")
                self.reconnect()


def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    """This function checks if the given interval has passed since the given start time

    Args:
        fetch_start_time (datetime): The start time of the interval
        fetch_interval (int): The interval in seconds

    Returns:
        bool: True if the interval has passed, False otherwise
    """
    return fetch_start_time + timedelta(seconds=fetch_interval) < datetime.utcnow()


def set_the_integration_context(key: str, val: Any):
    """Adds a key-value pair to the integration context dictionary.
        If the key already exists in the integration context, the function will overwrite the existing value with the new one.
    """
    cnx = demisto.getIntegrationContext()
    cnx[key] = val
    demisto.setIntegrationContext(cnx)


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
    extra_headers = {"Authorization": f"Bearer {api_key}"}

    try:
        with ExitStack() as stack:  # Keep connection contexts for clean up
            connections = [EventConnection(
                event_type=event_type,
                url=url(type=event_type.value),
                headers=extra_headers,
                fetch_interval=fetch_interval,
            ) for event_type in EventType]

            set_the_integration_context(
                "last_run_results", f"Opened a connection successfully at {datetime.now().astimezone(tz.tzutc())}")

            yield connections
    except Exception as e:
        set_the_integration_context("last_run_results",
                                    f"{str(e)} \n This error happened at {datetime.now().astimezone(tz.tzutc())}")
        raise DemistoException(f"{str(e)}\n")


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
    demisto.debug(f'Starting to fetch events of type {event_type}')
    events: list[dict] = []
    event_ids = set()
    fetch_start_time = datetime.utcnow()
    while not is_interval_passed(fetch_start_time, fetch_interval):
        try:
            event = json.loads(connection.recv(timeout=recv_timeout))
        except TimeoutError:
            demisto.debug(f"Timeout while waiting for the event on {connection.event_type}")
            continue
        except exceptions.ConnectionClosedError:
            demisto.error(f"Connection closed, attempting to reconnect...")
            connection.reconnect()
            continue
        except Exception as e:
            set_the_integration_context("last_run_results",
                                        f"{str(e)} \n This error happened at {datetime.now().astimezone(tz.tzutc())}")
            raise DemistoException(str(e))
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
        event["event_type"] = event_type
        events.append(event)
        event_ids.add(event_id)
    num_events = len(events)
    demisto.debug(f"Fetched {num_events} events of type {event_type}")
    demisto.debug("The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))
    set_the_integration_context("last_run_results",
                                f"Got from connection {num_events} events starting\
                                    at {str(fetch_start_time)} until {datetime.now().astimezone(tz.tzutc())}")

    return events


def test_module(host: str, cluster_id: str, api_key: str):
    raise DemistoException(
        "No test option is available due to API limitations.\
        To verify the configuration, run the proofpoint-es-get-last-run-results command.")


def get_last_run_results_command():
    last_run_results = demisto.getIntegrationContext().get("last_run_results")
    if last_run_results:
        return CommandResults(readable_output=last_run_results)
    else:
        return CommandResults(readable_output="No results from the last run yet, \
            please wait one minute and try running the command again.")


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
        events.extend(integration_context.get(connection.event_type, []))
        integration_context[connection.event_type] = events  # update events in context in case of fail
        demisto.debug(f'Adding {len(events)} {connection.event_type} Events to XSIAM')
        events_to_send.extend(events)

    # Send the events to the XSIAM, with events from the context
    try:
        send_events_to_xsiam(events_to_send, vendor=VENDOR, product=PRODUCT)
        # clear the context after sending the events
        for connection in connections:
            set_the_integration_context(connection.event_type, [])
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
            demisto.info("TESTSTRING")
            return_results(long_running_execution_command(host, cluster_id, api_key, fetch_interval))
        elif command == "test-module":
            return_results(test_module(host, cluster_id, api_key))
        elif command == "proofpoint-es-get-last-run-results":
            return_results(get_last_run_results_command())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
