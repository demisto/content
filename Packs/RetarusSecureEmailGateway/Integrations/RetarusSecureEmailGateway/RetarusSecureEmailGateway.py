import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
from websockets import Data
import websockets
from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection
from websockets.exceptions import InvalidStatus
from dateutil import tz
import traceback
import threading
from contextlib import contextmanager



# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

VENDOR = "Retarus"
PRODUCT = "Secure Email Gateway"
FETCH_INTERVAL_IN_SECONDS = 60
FETCH_SLEEP = 5
SERVER_IDLE_TIMEOUT = 60
DEFAULT_CHANNEL = "default"

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class EventConnection:
    def __init__(self, connection: Connection, fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
                 idle_timeout: int = SERVER_IDLE_TIMEOUT):
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


    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' HELPER FUNCTIONS '''
def push_events(events: list[dict]):
    """
    Push events to XSIAM.
    """
    demisto.debug(f"Pushing {len(events)} to XSIAM")
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"Pushed {len(events)} to XSIAM successfully")
    

@contextmanager
def websocket_connection(url: str, token_id: str, fetch_interval: int, channel: str, verify_ssl: bool):
    extra_headers = {"Authorization": f"Bearer {token_id}"}
    
    context = ssl.create_default_context()
    if not verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    with connect("wss://"+url+f"/email/siem/v1/websocket?channel={channel}", additional_headers=extra_headers) as ws:
        connection = EventConnection(
                connection=ws,
                fetch_interval=fetch_interval
            )
        yield connection

def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:
    """This function checks if the given interval has passed since the given start time

    Args:
        fetch_start_time (datetime): The start time of the interval
        fetch_interval (int): The interval in seconds

    Returns:
        bool: True if the interval has passed, False otherwise
    """
    return fetch_start_time + timedelta(seconds=fetch_interval) < datetime.utcnow()


def perform_long_running_loop(connection: EventConnection, fetch_interval: int):
    integration_context = demisto.getIntegrationContext()
    events_to_send = []
    events = fetch_events(connection, fetch_interval)
    events.extend(integration_context.get("events", []))
    integration_context["events"] = events  # update events in context in case of a failure.
    demisto.debug(f'Adding {len(events)} Events to XSIAM')
    events_to_send.extend(events)
    
    # Send the events to the XSIAM, with events from the context
    # Need to add the option that if we have more then one failure of sending the events to xsiam then we stop fetching. consult with Meital and Dima # TODO
    try:
        send_events_to_xsiam(events_to_send, vendor=VENDOR, product=PRODUCT)
        # clear the context after sending the events
        demisto.setIntegrationContext({})
    except DemistoException:
        demisto.error(f"Failed to send events to XSIAM. Error: {traceback.format_exc()}")
        # save the events to the context so we can send them again in the next execution
        demisto.setIntegrationContext(integration_context)


''' COMMAND FUNCTIONS '''
def long_running_execution_command(url, token_id, fetch_interval, channel, verify_ssl):
    """
    Performs the long running execution loop.
    Opens a connection to Retarus.
    Heartbeat thread is opened for the connection to send keepalives if the connection is idle for too long.

    Args:
        url (str): URL for the websocket connection.
        token_id (str): Retarus token_id to connect to.
        channel (str): channel to connect with.
        fetch_interval (int): Total time allocated per fetch cycle.
    """
    with websocket_connection(url, token_id, fetch_interval, channel, verify_ssl) as connection:
        demisto.info("Connected to websocket")

        # Retarus will keep connections with no traffic open for at most 5 minutes.
        # It is highly recommended that the client sends a PING control frame every 60 seconds to keep the connection open.
        # (sentence taken from Retarus docs)
        # Setting up heartbeat daemon threads to send keep-alives if needed
        threading.Thread(target=connection.heartbeat, daemon=True).start()

        while True:
            perform_long_running_loop(connection, fetch_interval)
            # sleep for a bit to not throttle the CPU
            time.sleep(FETCH_SLEEP)

def test_module(url, token_id):
    if not url:
        raise DemistoException("Missing url parameter.")
    if not token_id:
        raise DemistoException("Missing token id parameter.")
    return 'ok'


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
    events: list[dict] = []
    event_ids = set()
    fetch_start_time = datetime.utcnow()
    demisto.debug(f'Starting to fetch events at {fetch_start_time}')
    while not is_interval_passed(fetch_start_time, fetch_interval):
        try:
            event = json.loads(connection.recv(timeout=recv_timeout))
        except TimeoutError:
            # if we didn't receive an event for `fetch_interval` seconds, finish fetching
            continue
        event_id = None # TODO we don't get an id from Retarus
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
        event["_time"] = date
        event["event_type"] = event.get("type")
        events.append(event)
        event_ids.add(event_id)
    demisto.debug(f"Fetched {len(events)} events")
    demisto.debug("The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))
    return events

''' MAIN FUNCTION '''


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    url = params.get("url", "events.retarus.com")
    token_id = params.get("credentials", {}).get("password", "")
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))
    verify_ssl = argToBoolean(not params.get("insecure", False))
    channel = params.get("channel", DEFAULT_CHANNEL)

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(url, token_id, fetch_interval, channel, verify_ssl))
        elif command == "test-module":
            return_results(test_module(url, token_id))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')




if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
