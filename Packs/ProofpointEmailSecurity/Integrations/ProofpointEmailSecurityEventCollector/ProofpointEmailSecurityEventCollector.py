from contextlib import ExitStack, contextmanager
from functools import partial
from threading import Lock, Thread

import demistomock as demisto
from CommonServerPython import *
from dateutil import tz
from websockets import exceptions
from websockets.sync.client import connect
from websockets.sync.connection import Connection

VENDOR = "proofpoint"
PRODUCT = "email_security"

URL = "{host}/v1/stream?cid={cluster_id}&type={type}"


FETCH_INTERVAL_IN_SECONDS = 60
FETCH_SLEEP = 5
SERVER_IDLE_TIMEOUT = 300


EVENT_TYPES=["message", "maillog", "audit"]


class EventConnection:
    def __init__(
        self,
        event_type: str,
        url: str,
        headers: dict,
        fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
        idle_timeout: int = SERVER_IDLE_TIMEOUT - 20,
    ):
        demisto.info(f"Starting EventConnection of type {event_type}")
        self.event_type = event_type
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

    def reconnect(self):
        """
        Reconnect logic for the WebSocket connection.
        """
        demisto.info(f"In {self.event_type} reconnect, going to reconnect.")
        try:
            self.connection = self.connect()
            demisto.info(f"[{self.event_type}] Successfully reconnected to WebSocket")
        except Exception as e:
            demisto.error(f"[{self.event_type}] Reconnection failed: {e!s} {traceback.format_exc()}")
            raise

    def heartbeat(self):
        """
        Heartbeat thread function to periodically send keep-alives (pong) to the server.
        Keep-alives are sent regardless of the actual connection activity to ensure the connection remains open.
        """
        while True:
            with self.lock:
                try:
                    self.connection.pong()
                    demisto.info(f"[{self.event_type}] Sent heartbeat pong")
                except exceptions.ConnectionClosedError as e:
                    demisto.error(f"[{self.event_type}] Connection closed due to error in thread - {self.event_type}: {e!s}")
                    self.reconnect()
                except exceptions.ConnectionClosedOK:
                    demisto.info(f"[{self.event_type}] Connection closed OK in thread - {self.event_type}")
                    self.reconnect()
                except Exception as e:
                    demisto.error(f"[{self.event_type}] Unexpected error in heartbeat: {e!s} {traceback.format_exc()}")
                    self.reconnect()
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


def set_the_integration_context(key: str, val: Any):
    """Adds a key-value pair to the integration context dictionary.
    If the key already exists in the integration context, the function will overwrite the existing value with the new one.
    """
    cnx = demisto.getIntegrationContext()
    cnx[key] = val
    demisto.setIntegrationContext(cnx)


@contextmanager
def websocket_connections(
    host: str,
    cluster_id: str,
    api_key: str,
    since_time: str | None = None,
    to_time: str | None = None,
    fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
    event_types: list[str] = EVENT_TYPES
):
    """
    Create a connection for every type of event.

    Args:
        host (str): host URL for the websocket connection.
        cluster_id (str): Proofpoint cluster ID to connect to.
        api_key (str): Proofpoint API key.
        since_time (str): Start time to fetch events from.
        to_time (str): End time for fetch, leave empty for real-time streaming.
        fetch_interval (int): Time between fetch iterations, used for estimating message receive times for idle heartbeat.
        event_types: (list[str]): The list of event types to collect.

    Yields:
        list[EventConnection]: List containing an eventConnection for every event type
    """
    demisto.info(
        f"Starting websocket connection to {host} with cluster id: {cluster_id}, sinceTime: {since_time}, toTime: {to_time}"
    )
    url = URL
    if since_time:
        url += f"&sinceTime={since_time}"
    if to_time:
        url += f"&toTime={to_time}"
    url = partial(url.format, host=host, cluster_id=cluster_id)
    extra_headers = {"Authorization": f"Bearer {api_key}"}

    try:
        with ExitStack():  # Keep connection contexts for clean up
            connections = [
                EventConnection(
                    event_type=event_type,
                    url=url(type=event_type),
                    headers=extra_headers,
                    fetch_interval=fetch_interval,
                )
                for event_type in event_types
            ]

            set_the_integration_context(
                "last_run_results", f"Opened a connection successfully at {datetime.now().astimezone(tz.tzutc())}"
            )

            yield connections
    except Exception as e:
        set_the_integration_context(
            "last_run_results", f"{e!s} \n This error happened at {datetime.now().astimezone(tz.tzutc())}"
        )
        raise DemistoException(f"{e!s}\n")


def fetch_events(connection: EventConnection, fetch_interval: int, integration_context: dict,
                 should_skip_sleeping: List[bool]) -> list[dict]:
    """
    This function fetches events from the given connection, for the given fetch interval

    Args:
        connection (EventConnection): the connection to the event type
        fetch_interval (int): Total time to keep fetching before stopping
        integration_context (dict) The integration context dict.
        should_skip_sleeping (List[bool]): a list to update all execution results -
        False if timeout occurred, otherwise will append True.

    Returns:
        list[dict]: A list of events
    """
    event_type = connection.event_type
    demisto.debug(f"Starting to fetch events of type {event_type}")
    events: list[dict] = []
    event_ids = set()
    fetch_start_time = datetime.utcnow()
    demisto.info(f'in {event_type=}, preparing to acquire lock & recv.')
    with connection.lock:
        while not is_interval_passed(fetch_start_time, fetch_interval):
            try:
                event = json.loads(connection.connection.recv(timeout=1))
                event_id = event.get("id", event.get("guid"))
                event_ts = event.get("ts")
                if not event_ts:
                    # if timestamp is not in the response, use the current time
                    demisto.debug(f"Event {event_id} does not have a timestamp, using current time.")
                    event_ts = datetime.utcnow().isoformat()
                date = dateparser.parse(event_ts)
                if not date:
                    demisto.debug(f"Event {event_id} has an invalid timestamp, using current time.")
                    # if timestamp is not in correct format, use the current time
                    date = datetime.utcnow()
                # the `ts` parameter is not always in UTC, so we need to convert it
                event["_time"] = date.astimezone(tz.tzutc()).isoformat()
                event["event_type"] = event_type
                events.append(event)
                event_ids.add(event_id)
            except TimeoutError:
                demisto.debug(f"Timeout while waiting for the event on {connection.event_type}, breaking.")
                break
            except exceptions.ConnectionClosedError:
                demisto.error("Connection closed, attempting to reconnect...")
                connection.reconnect()
                continue
            except Exception as e:
                demisto.error(f"Got general error in fetch_events {e}")
                events.extend(integration_context.get(connection.event_type, []))
                integration_context[connection.event_type] = events  # update events in context in case of fail
                integration_context["last_run_results"] = f"{e!s} \nThe error happened at {datetime.now().astimezone(tz.tzutc())}"
                set_integration_context(integration_context)
                raise DemistoException(str(e))
    demisto.info(f'in {event_type=}, released the lock and finished recv.')
    num_events = len(events)
    last_event_time = None
    if events:
        last_event_time =  events[-1].get("_time")
    demisto.debug(f"Fetched {num_events} events of type {event_type} with {last_event_time=}")
    demisto.debug("The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))
    set_the_integration_context(
        "last_run_results",
        f"Got from connection {num_events} events starting\
                                    at {fetch_start_time!s} until {datetime.now().astimezone(tz.tzutc())}",
    )
    should_skip_sleeping.append(True)
    return events


def test_module(host: str, cluster_id: str, api_key: str):
    raise DemistoException(
        "No test option is available due to API limitations.\
        To verify the configuration, run the proofpoint-es-get-last-run-results command."
    )


def get_last_run_results_command():
    last_run_results = demisto.getIntegrationContext().get("last_run_results")
    if last_run_results:
        return CommandResults(readable_output=last_run_results)
    else:
        return CommandResults(
            readable_output="No results from the last run yet, \
            please wait one minute and try running the command again."
        )


def perform_long_running_loop(connections: list[EventConnection], fetch_interval: int, should_skip_sleeping: List[bool]):
    """
    Long running loop iteration function. Fetches events from each connection and sends them to XSIAM.

    Args:
        connections (list[EventConnection]): List of connection objects to fetch events from.
        fetch_interval (int): Fetch time per cycle allocated for each event type in seconds.
        should_skip_sleeping (List[bool]): a list to update all execution results -
        False if timeout occurred, otherwise will append True.
    """
    integration_context = demisto.getIntegrationContext()
    events_to_send = []
    for connection in connections:
        events = fetch_events(connection, fetch_interval, integration_context, should_skip_sleeping)
        events.extend(integration_context.get(connection.event_type, []))
        integration_context[connection.event_type] = events  # update events in context in case of fail
        demisto.debug(f"Adding {len(events)} {connection.event_type} Events to XSIAM")
        events_to_send.extend(events)
    demisto.info(f"Going to send {len(events_to_send)} events to xsiam.")
    # Send the events to the XSIAM, with events from the context
    try:
        if events_to_send:
            send_events_to_xsiam(events_to_send, vendor=VENDOR, product=PRODUCT)
        else:
            demisto.info("No events to send to xsiam.")
        demisto.info(f"Finished sending {len(events_to_send)} events to xsiam, going to clear context.")
        # clear the context after sending the events
        for connection in connections:
            set_the_integration_context(connection.event_type, [])
    except DemistoException:
        demisto.error(f"Failed to send events to XSIAM. Error: {traceback.format_exc()}")
        # save the events to the context so we can send them again in the next execution
        demisto.setIntegrationContext(integration_context)


def long_running_execution_command(host: str, cluster_id: str, api_key: str, fetch_interval: int, event_types: List[str]):
    """
    Performs the long running execution loop.
    Opens a connection to Proofpoints for every event type and fetches events in a loop.
    Heartbeat threads are opened for every connection to send keepalives if the connection is idle for too long.

    Args:
        host (str): host URL for the websocket connection.
        cluster_id (str): Proofpoint cluster ID to connect to.
        api_key (str): Proofpoint API key.
        fetch_interval (int): Total time allocated per fetch cycle.
        event_types (List[str]): The list of event types to collect.
    """
    support_multithreading()
    demisto.info("starting long running execution.")
    while True:
        try:
            with websocket_connections(host, cluster_id, api_key, fetch_interval=fetch_interval,
                                       event_types=event_types) as connections:
                demisto.info("Connected to websocket")
                fetch_interval = max(1, fetch_interval // len(event_types))  # Divide the fetch interval equally among event types

                while True:
                    should_skip_sleeping: List[bool] = []
                    perform_long_running_loop(connections, fetch_interval, should_skip_sleeping)
                    # sleep for a bit to not throttle the CPU
                    if any(should_skip_sleeping):
                        demisto.info("Finished perform_long_running_loop, should_skip_sleeping evaluated to True.")
                    else:
                        demisto.info("Finished perform_long_running_loop, should_skip_sleeping evaluated to False,  going to"
                                     f"sleep {FETCH_SLEEP} seconds.")
                        time.sleep(FETCH_SLEEP)
                        demisto.info(f"Finished sleeping {FETCH_SLEEP} seconds.")
        except Exception as e:
            err = f"Got an error while running in long running {e}"
            demisto.updateModuleHealth(err, is_error=True)
            demisto.error(err)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))
    event_types = params.get("event_types", EVENT_TYPES)
    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(host, cluster_id, api_key, fetch_interval, event_types))
        elif command == "test-module":
            return_results(test_module(host, cluster_id, api_key))
        elif command == "proofpoint-es-get-last-run-results":
            return_results(get_last_run_results_command())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f"Failed to execute {command} command.\nError:\n{traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
