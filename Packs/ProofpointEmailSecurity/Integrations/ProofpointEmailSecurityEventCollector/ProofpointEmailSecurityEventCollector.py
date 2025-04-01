import asyncio
from contextlib import asynccontextmanager
from enum import Enum
from functools import partial
from datetime import datetime, timedelta
import traceback
import json

from dateutil import tz, parser as dateparser
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets import connect

import demistomock as demisto
from CommonServerPython import *

VENDOR = "proofpoint"
PRODUCT = "email_security"

URL_TEMPLATE = "{host}/v1/stream?cid={cluster_id}&type={type}&sinceTime={time}"

FETCH_INTERVAL_IN_SECONDS = 60
FETCH_SLEEP = 5
SERVER_IDLE_TIMEOUT = 300
RECONNECT_TIMEOUT = 30  # Timeout for reconnection attempt in seconds


class EventType(str, Enum):
    MESSAGE = 'message'
    MAILLOG = 'maillog'
    AUDIT = 'audit'


class EventConnection:
    def __init__(self, event_type: EventType, url_template: str, headers: dict,
                 fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
                 idle_timeout: int = SERVER_IDLE_TIMEOUT - 20):
        self.event_type = event_type.value
        self.url_template = url_template
        self.headers = [(k, v) for k, v in headers.items()]  # Convert headers to list of tuples
        self.idle_timeout = idle_timeout
        self.fetch_interval = fetch_interval
        self.connection = None

    async def connect(self):
        """
        Establish a new WebSocket connection.
        """
        url = self.url_template
        demisto.info(f"Connecting to URL: {url}")
        try:
            self.connection = await connect(url, additional_headers=self.headers)
            demisto.info(f"Successfully connected to URL: {url}")
        except Exception as e:
            demisto.error(f"Failed to connect to URL: {url}. Error: {str(e)} {traceback.format_exc()}")
            raise

    async def recv(self, timeout: float | None = None) -> Any:
        """
        Receive the next message from the connection

        Args:
            timeout (float): Block until timeout seconds have elapsed or a message is received. If None, waits indefinitely.
                             If timeout passes, raises TimeoutError

        Returns:
            Any: Next event received from the connection
        """
        try:
            return await asyncio.wait_for(self.connection.recv(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("Timeout while waiting for the event")

    async def disconnect(self):
        """
        Disconnect the WebSocket connection.
        """
        try:
            await self.connection.close()
            demisto.info(f"[{self.event_type}] Successfully disconnected from WebSocket")
        except Exception as e:
            demisto.error(f"[{self.event_type}] Disconnection failed: {str(e)} {traceback.format_exc()}")

    async def reconnect(self, new_since_time: str):
        """
        Reconnect logic for the WebSocket connection with a new since_time.
        """
        demisto.info(f"[{self.event_type}] Starting reconnection process with new since_time: {new_since_time}")
        await self.disconnect()
        demisto.info(f"[{self.event_type}] Disconnected successfully. Updating URL template.")
        self.update_url(new_since_time)
        demisto.info(f"[{self.event_type}] URL template updated to: {self.url_template}")

        start_time = time.time()
        while time.time() - start_time < RECONNECT_TIMEOUT:
            try:
                demisto.info(f"[{self.event_type}] Attempting to establish a new connection.")
                await self.connect()
                demisto.info(f"[{self.event_type}] Successfully reconnected to WebSocket")
                return  # Exit the function if connection is successful
            except Exception as e:
                demisto.error(f"[{self.event_type}] Reconnection attempt failed: {str(e)}")
                await asyncio.sleep(5)  # Wait before retrying

        demisto.error(f"[{self.event_type}] Reconnection failed after {RECONNECT_TIMEOUT} seconds. Giving up.")
        raise Exception(f"[{self.event_type}] Reconnection failed after {RECONNECT_TIMEOUT} seconds. Giving up.")

    def update_url(self, new_since_time: str):
        """
        Update the URL template with a new since_time.
        """
        self.url_template = self.url_template.replace(self.url_template.split("sinceTime=")[1].split("&")[0], new_since_time)


def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    """This function checks if the given interval has passed since the given start time

    Args:
        fetch_start_time (datetime): The start time of the interval
        fetch_interval (int): The interval in seconds

    Returns:
        bool: True if the interval has passed, False otherwise
    """
    return fetch_start_time + timedelta(seconds=fetch_interval) < datetime.utcnow()


def set_the_integration_context(context: dict):
    """Sets the integration context."""
    demisto.setIntegrationContext(context)


def update_integration_context(key: str, val: Any):
    """Updates a key-value pair in the integration context dictionary.
    If the key already exists in the integration context, the function will overwrite the existing value with the new one.
    """
    context = demisto.getIntegrationContext()
    context[key] = val
    set_the_integration_context(context)


@asynccontextmanager
async def websocket_connections(host: str, cluster_id: str, api_key: str, since_time: str | None = None, to_time: str | None = None,
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
    demisto.info(f"Starting websocket connection to {host} with cluster id: {cluster_id}, sinceTime: {since_time}, toTime: {to_time}")

    if not since_time:
        since_time = datetime.utcnow().isoformat()
    url_template = partial(URL_TEMPLATE.format, host=host, cluster_id=cluster_id, time=since_time)
    if to_time:
        url_template += f"&toTime={to_time}"

    extra_headers = {"Authorization": f"Bearer {api_key}"}

    try:
        connections = [EventConnection(
            event_type=event_type,
            url_template=url_template(type=event_type.value),
            headers=extra_headers,
            fetch_interval=fetch_interval,
        ) for event_type in EventType]

        await asyncio.gather(*[connection.connect() for connection in connections])

        update_integration_context("last_run_results", f"Opened a connection successfully at {datetime.now().astimezone(tz.tzutc())}")
        yield connections

        await asyncio.gather(*[connection.disconnect() for connection in connections])
    except Exception as e:
        update_integration_context("last_run_results", f"{str(e)} \n This error happened at {datetime.now().astimezone(tz.tzutc())}")
        raise DemistoException(f"{str(e)}\n")


async def fetch_events(connection: EventConnection, fetch_interval: int, recv_timeout: int = 10) -> list[dict]:
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
            event = json.loads(await connection.recv(timeout=recv_timeout))
        except TimeoutError:
            demisto.debug(f"Timeout while waiting for the event on {connection.event_type}")
            continue
        except (ConnectionClosedError, ConnectionClosedOK) as e:
            demisto.info(f"Connection was closed (code 1000 or similar). Attempting to reconnect... Reason: {str(e)}")
            await connection.reconnect(datetime.utcnow().isoformat())
            continue
        except Exception as e:
            update_integration_context("last_run_results", f"{str(e)} \n This error happened at {datetime.now().astimezone(tz.tzutc())}")
            demisto.error(f"Exception while fetching events: {str(e)} {traceback.format_exc()}")
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
    update_integration_context("last_run_results", f"Got from connection {num_events} events starting at {str(fetch_start_time)} until {datetime.now().astimezone(tz.tzutc())}")

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


async def perform_long_running_loop(connections: list[EventConnection], fetch_interval: int):
    """
    Long running loop iteration function. Fetches events from each connection and sends them to XSIAM.

    Args:
        connections (list[EventConnection]): List of connection objects to fetch events from.
        fetch_interval (int): Fetch time per cycle allocated for each event type in seconds.
    """
    integration_context = demisto.getIntegrationContext()
    events_to_send = []
    for connection in connections:
        try:
            events = await fetch_events(connection, fetch_interval)
            events.extend(integration_context.get(connection.event_type, []))
            integration_context[connection.event_type] = events  # update events in context in case of fail
            demisto.debug(f'Adding {len(events)} {connection.event_type} Events to XSIAM')
            events_to_send.extend(events)
        except Exception as e:
            demisto.error(f"Exception while fetching events for {connection.event_type}: {str(e)} {traceback.format_exc()}")

    # Send the events to the XSIAM, with events from the context
    try:
        if events_to_send:
            send_events_to_xsiam(events_to_send, vendor=VENDOR, product=PRODUCT)
            # clear the context after sending the events
            for connection in connections:
                integration_context[connection.event_type] = []
    except DemistoException as e:
        demisto.error(f"Failed to send events to XSIAM. Error: {str(e)} {traceback.format_exc()}")
        # save the events to the context so we can send them again in the next execution
        demisto.setIntegrationContext(integration_context)
        return

    if events_to_send:
        # Update the sinceTime in the integration context for the next fetch
        last_event_time = max(event["_time"] for event in events_to_send)
        demisto.info(f"Updating sinceTime to {last_event_time}")
        integration_context["sinceTime"] = last_event_time
        set_the_integration_context(integration_context)
        for connection in connections:
            demisto.info(f"Reconnecting connection for event type: {connection.event_type}")
            await connection.reconnect(last_event_time)


async def long_running_execution_command(host: str, cluster_id: str, api_key: str, fetch_interval: int):
    """
    Performs the long running execution loop.
    Opens a connection to Proofpoints for every event type and fetches events in a loop.

    Args:
        host (str): host URL for the websocket connection.
        cluster_id (str): Proofpoint cluster ID to connect to.
        api_key (str): Proofpoint API key.
        fetch_interval (int): Total time allocated per fetch cycle.
    """
    since_time = demisto.getIntegrationContext().get("sinceTime")
    async with websocket_connections(host, cluster_id, api_key, since_time=since_time, fetch_interval=fetch_interval) as connections:
        demisto.info("Connected to websocket")
        fetch_interval = max(1, fetch_interval // len(EventType))  # Divide the fetch interval equally among all event types

        while True:
            try:
                await perform_long_running_loop(connections, fetch_interval)
            except Exception as e:
                demisto.error(f"Exception in long running loop: {str(e)} {traceback.format_exc()}")
            # sleep for a bit to not throttle the CPU
            await asyncio.sleep(FETCH_SLEEP)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    host = params.get("host", "")
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))

    try:
        if command == "long-running-execution":
            asyncio.run(long_running_execution_command(host, cluster_id, api_key, fetch_interval))
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
