from contextlib import ExitStack, contextmanager
from functools import partial
from threading import Lock, Thread

import demistomock as demisto
from CommonServerPython import *
from dateutil import tz
from http import HTTPStatus
from websockets import exceptions
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from datetime import datetime, timezone, timedelta

VENDOR = "proofpoint"
PRODUCT = "email_security"

URL = "{host}/v1/stream?cid={cluster_id}&type={type}"


FETCH_INTERVAL_IN_SECONDS = 60
FETCH_SLEEP = 5
SERVER_IDLE_TIMEOUT = 300
MAX_RECONNECT_ATTEMPTS = 5
MAX_BACKOFF_SECONDS = 60
BASE_BACKOFF_SECONDS = 2


EVENT_TYPES = ["message", "maillog", "audit"]
DEFAULT_GET_EVENTS_LIMIT = 10
DATE_FILTER_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
PING_TIMEOUT = 60  # Timeout for keepalive pings in seconds
CLOSE_TIMEOUT = 60  # Timeout for closing the connection in seconds
RECEIVE_TIMEOUT = 1  # Timeout for receiving events in seconds


class EventConnection:
    def __init__(
        self,
        event_type: str,
        url: str,
        headers: dict,
        fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
        idle_timeout: int = SERVER_IDLE_TIMEOUT - 20,
        check_heartbeat: bool = True,
    ):
        demisto.info(f"Starting EventConnection of type {event_type}")
        self.event_type = event_type
        self.url = url
        self.headers = headers
        self.lock = Lock()
        self.idle_timeout = idle_timeout
        self.fetch_interval = fetch_interval
        self.connection = self.connect()
        if check_heartbeat:
            self.heartbeat_thread = Thread(target=self.heartbeat, daemon=True)
            self.heartbeat_thread.start()

    def connect(self) -> Connection:
        """
        Establish a new WebSocket connection.
        """
        return connect(self.url, additional_headers=self.headers, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)

    @property
    def is_to_archive(self) -> bool:
        """
        Check if the connection is to an archive.
        """
        return bool("sinceTime" in self.url and "toTime" in self.url)

    def reconnect(self):
        """
        Reconnect logic for the WebSocket connection using an exponential backoff strategy.
        This handles the HTTP 409 error by delaying the retry to allow the Proofpoint server to clear the session.
        """
        attempt = 0
        while attempt < MAX_RECONNECT_ATTEMPTS:
            attempt += 1
            demisto.info(f"[{self.event_type}] Going to attempt reconnection #{attempt} / {MAX_RECONNECT_ATTEMPTS}.")
            try:
                self.connection = self.connect()
                demisto.info(f"[{self.event_type}] Successfully reconnected to WebSocket after {attempt} attempt(s).")
                return

            except exceptions.InvalidStatus as e:
                # Need to wait if HTTP 409 (Conflict) error was raised because the failed session
                # has not been fully terminated or released by the Proofpoint server
                if e.response.status_code == HTTPStatus.CONFLICT:
                    delay = min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
                    demisto.error(
                        f"[{self.event_type}] Reconnection failed due to session conflict. "
                        f"Waiting {delay} seconds before retrying (Attempt {attempt})."
                    )
                    time.sleep(delay)

                else:
                    demisto.error(f"[{self.event_type}] Connection status error: {e!s}.")
                    raise

            except Exception as e:
                demisto.error(f"[{self.event_type}] General reconnection failure: {e!s}.")
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

    def receive(self, timeout: int = RECEIVE_TIMEOUT) -> dict[str, Any]:
        """Receive a new event from the websocket connection.

        Args:
            timeout (int): Maximum time to wait for a message to be received. Defaults to RECEIVE_TIMEOUT.

        Returns:
            dict[str, Any]: The raw event from the websocket.
        """
        return json.loads(self.connection.recv(timeout=timeout))


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
    event_types: list[str] = EVENT_TYPES,
    write_to_integration_context: bool = True,
    check_heartbeat: bool = True,
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
        write_to_integration_context (bool): Whether to write events to the integration context.
        check_heartbeat (bool): Whether to check for heartbeat messages.

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
                    check_heartbeat=check_heartbeat,
                )
                for event_type in event_types
            ]

            if write_to_integration_context:
                set_the_integration_context(
                    "last_run_results", f"Opened a connection successfully at {datetime.now().astimezone(tz.tzutc())}"
                )

            yield connections
    except Exception as e:
        if write_to_integration_context:
            set_the_integration_context(
                "last_run_results", f"{e!s} \n This error happened at {datetime.now().astimezone(tz.tzutc())}"
            )
        raise DemistoException(f"{e!s}\n")


def fetch_events(
    connection: EventConnection,
    fetch_interval: int,
    integration_context: dict,
    should_skip_sleeping: List[bool],
    write_to_integration_context: bool = True,
) -> list[dict]:
    """
    This function fetches events from the given connection, for the given fetch interval

    Args:
        connection (EventConnection): the connection to the event type
        fetch_interval (int): Total time to keep fetching before stopping
        integration_context (dict) The integration context dict.
        should_skip_sleeping (List[bool]): a list to update all execution results -
        False if timeout occurred, otherwise will append True.
        write_to_integration_context (bool): Whether to write to integration context.

    Returns:
        list[dict]: A list of events
    """
    event_type = connection.event_type
    demisto.debug(f"[{event_type}] Starting to fetch events.")
    events: list[dict] = []
    event_ids = set()  # For deduplication within the *same* fetch cycle only! (Cannot deduplicate all events from the websocket)
    fetch_start_time = datetime.utcnow()

    demisto.info(f"[{event_type}] Preparing to acquire lock & recv.")
    with connection.lock:
        while not is_interval_passed(fetch_start_time, fetch_interval):
            try:
                event = receive_event(connection, timeout=RECEIVE_TIMEOUT)
                event_id = get_event_id(event)
                if event_id in event_ids:
                    demisto.debug(f"[{event_type}] Already fetched {event_id=}. Skipping duplicate.")
                    continue
                event_ids.add(event_id)
                events.append(event)

            except TimeoutError:
                # This exception typically indicates no new events from websocket stream
                demisto.debug(f"[{event_type}] Timeout while waiting for a new event in stream. Breaking.")
                break

            except exceptions.InvalidStatus as e:
                status_code = e.response.status_code
                demisto.error(f"[{event_type}] Invalid status: {status_code}. Starting recovery.")
                recover_after_disconnection(connection, events, event_ids, reconnect=True)
                continue

            except exceptions.ConnectionClosedError:
                demisto.error(f"[{event_type}] Connection closed with error. Starting recovery.")
                recover_after_disconnection(connection, events, event_ids, reconnect=True)
                continue

            except exceptions.ConnectionClosedOK:
                # This exception from archive websocket means event fetching completed successfully
                if connection.is_to_archive:
                    demisto.info(f"[{event_type}] Connection closed with OK status. All archived events were fetched.")
                    break
                demisto.error(f"[{event_type}] Connection closed with OK status. Starting recovery.")
                recover_after_disconnection(connection, events, event_ids, reconnect=True)
                continue

            except Exception as e:
                demisto.error(f"[{event_type}] Got general error in fetch_events. Starting recovery. Error: {e}")
                recover_after_disconnection(connection, events, event_ids, reconnect=False)
                events.extend(integration_context.get(event_type, []))
                integration_context[event_type] = events  # update events in context in case of fail
                integration_context["last_run_results"] = f"{e!s} \nThe error happened at {datetime.now().astimezone(tz.tzutc())}"
                if write_to_integration_context:
                    set_integration_context(integration_context)
                raise DemistoException(str(e))

    demisto.info(f"[{event_type}] Released the lock and finished recv.")
    num_events = len(events)
    last_event_time = events[-1].get("_time") if events else None
    demisto.debug(f"[{event_type}] Fetched {num_events} events with {last_event_time=}")
    demisto.debug(f"[{event_type}] Fetched events IDs: {', '.join([str(event_id) for event_id in event_ids])}.")
    if write_to_integration_context:
        fetch_end_time = datetime.utcnow()
        set_the_integration_context(
            "last_run_results",
            f"Got from connection {num_events} events starting at {fetch_start_time!s} until {fetch_end_time!s}",
        )
    should_skip_sleeping.append(True)
    return events


def get_event_id(event: dict):
    """
    Extracts event ID using either the `id`, `guid`, or `filter.qid` field.
    Used for id-based deduplication and logging.

    Args:
        event (dict): The raw event.

    Returns:
        str: Event ID.
    """
    return event.get("id") or event.get("guid") or event.get("filter", {}).get("qid")


def receive_event(connection: EventConnection, timeout: int = RECEIVE_TIMEOUT) -> dict[str, Any]:
    """
    Processes a single event by parsing its timestamp and adding metadata.

    Args:
        connection (EventConnection): The connection to the event type.
        timeout (int): Maximum time to wait for a message to be received. Defaults to RECEIVE_TIMEOUT.

    Returns:
        dict[str, Any]: The processed event with '_time' and 'event_type' fields.
    """
    event = connection.receive(timeout=timeout)
    event_id = get_event_id(event)
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
    event["event_type"] = connection.event_type
    return event


def receive_events_after_disconnection(connection: EventConnection) -> list[dict]:
    """Receive events after disconnection.

    Args:
        connection (EventConnection): The connection to the event type.

    Returns:
        list[dict]: A list of events received after disconnection.
    """
    events = []
    demisto.info(f"[{connection.event_type}] Trying to receive in-transit events following disconnection.")
    while True:
        try:
            event = receive_event(connection)
            events.append(event)
        except Exception as e:
            demisto.debug(f"[{connection.event_type}] Terminating post-disconnection receive loop after error: {e}")
            break
    demisto.info(f"[{connection.event_type}] Returning {len(events)} in-transit events following disconnection.")
    return events


def recover_after_disconnection(connection: EventConnection, events: list[dict], event_ids: set[str], reconnect: bool = True):
    """Recover after disconnection by attempting to receive in-transit events and (optionally) reconnecting.

    Args:
        connection (EventConnection): The connection to the event type.
        events (list[dict]): The list of events.
        event_ids (set[str]): The set of event ids.
        reconnect (bool, optional): Whether to reconnect. Defaults to True.
    """
    demisto.debug(f"[{connection.event_type}] Recovering after disconnection.")
    in_transit_events = receive_events_after_disconnection(connection)
    for event in in_transit_events:
        event_id = get_event_id(event)
        if event_id in event_ids:
            demisto.debug(f"[{connection.event_type}] Already fetched {event_id=}. Skipping duplicate.")
            continue
        event_ids.add(event_id)
        events.append(event)

    demisto.debug(
        f"[{connection.event_type}] Received {len(in_transit_events)} in-transit events and event ids after disconnection."
    )
    if reconnect:
        demisto.info(f"[{connection.event_type}] Attempting to reconnect after disconnection.")
        connection.reconnect()


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
        demisto.debug(f"[{connection.event_type}] Adding {len(events)} events to XSIAM")
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
    except Exception as e:
        demisto.error(f"Failed to send events to XSIAM. Error: {str(e)},  {traceback.format_exc()}")
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
    demisto.info(f"Starting long running execution. Fetching {event_types=}.")
    while True:
        try:
            with websocket_connections(
                host, cluster_id, api_key, fetch_interval=fetch_interval, event_types=event_types
            ) as connections:
                demisto.info("Connected to websocket")
                fetch_interval = max(1, fetch_interval // len(event_types))  # Divide the fetch interval equally among event types

                while True:
                    should_skip_sleeping: List[bool] = []
                    perform_long_running_loop(connections, fetch_interval, should_skip_sleeping)
                    # sleep for a bit to not throttle the CPU
                    if any(should_skip_sleeping):
                        demisto.info("Finished perform_long_running_loop, should_skip_sleeping evaluated to True.")
                    else:
                        demisto.info(
                            "Finished perform_long_running_loop, should_skip_sleeping evaluated to False,  going to"
                            f"sleep {FETCH_SLEEP} seconds."
                        )
                        time.sleep(FETCH_SLEEP)
                        demisto.info(f"Finished sleeping {FETCH_SLEEP} seconds.")
        except Exception as e:
            err = f"Got an error while running in long running {e}. {traceback.format_exc()}"
            demisto.updateModuleHealth(err, is_error=True)
            demisto.error(err)


def get_events_command(host: str, cluster_id: str, api_key: str, args: dict[str, str]) -> tuple[list, CommandResults]:
    """Implements the `!proofpoint-est-get-events` command.

    Args:
        host (str): The host URL for the websocket connection.
        cluster_id (str): The Proofpoint cluster ID to connect to.
        api_key (str): The Proofpoint API key.
        args (dict[str, str]): The command arguments.

    Returns:
        tuple[list, CommandResults]: The list of events and the command results containing human-readable output.
    """
    event_types = argToList(args.get("event_types")) or EVENT_TYPES
    limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT

    tz_offset = arg_to_number(args.get("timezone_offset")) or 0
    event_tz = timezone(timedelta(hours=tz_offset))

    # `arg_to_datetime` does not return `None` since args are required. Added `type: ignore` to silence type checkers and linters
    since_time = arg_to_datetime(args.get("since_time"), required=True).replace(tzinfo=event_tz).strftime(DATE_FILTER_FORMAT)  # type: ignore[union-attr]
    to_time = arg_to_datetime(args.get("to_time"), required=True).replace(tzinfo=event_tz).strftime(DATE_FILTER_FORMAT)  # type: ignore[union-attr]

    all_events = []
    time_interval = 1 * 60
    demisto.debug(f"Starting to fetch {event_types=}, {since_time=}, {to_time=}")
    with websocket_connections(
        host,
        cluster_id,
        api_key,
        event_types=event_types,
        since_time=since_time,
        to_time=to_time,
        write_to_integration_context=False,
        check_heartbeat=False,
    ) as connections:
        for connection in connections:
            events = fetch_events(
                connection,
                time_interval,
                integration_context={},
                should_skip_sleeping=[],
                write_to_integration_context=False,
            )
            demisto.debug(f"[{connection.event_type}] Got {len(events)} events. Appending up to {limit} events.")
            all_events.extend(events[:limit])

    return all_events, CommandResults(readable_output=tableToMarkdown(f"Events since {since_time} to {to_time}", all_events))


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))
    event_types = argToList(params.get("event_types")) or EVENT_TYPES
    try:
        if command == "long-running-execution":
            if params.get("isFetchEvents", False):
                demisto.debug("Fetching events is enabled for this instance. Starting long running execution.")
                return_results(long_running_execution_command(host, cluster_id, api_key, fetch_interval, event_types))
            else:
                demisto.debug(f"Fetching events is disabled for this instance. Sleeping for {fetch_interval} seconds.")
                time.sleep(fetch_interval)

        elif command == "test-module":
            return_results(test_module(host, cluster_id, api_key))

        elif command == "proofpoint-es-get-last-run-results":
            return_results(get_last_run_results_command())

        elif command == "proofpoint-es-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            events, command_results = get_events_command(host, cluster_id, api_key, args)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)

        elif command == "fetch-events":
            # Return informative error message to prevent errors from appearing in tenant UI§
            demisto.info("Fetching events is done via long running execution.")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f"Failed to execute {command} command.\nError:\n{traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
