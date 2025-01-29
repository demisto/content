import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import urllib3
from websockets import Data
from websockets.sync.client import connect
from websockets.sync.connection import Connection
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
LOG_PREFIX = "Retarus-logs"


''' CLIENT CLASS '''


class EventConnection:
    def __init__(self, connection: Connection, fetch_interval: int = FETCH_INTERVAL_IN_SECONDS,
                 idle_timeout: int = SERVER_IDLE_TIMEOUT):  # pragma: no cover
        self.connection = connection
        self.lock = threading.Lock()
        self.idle_timeout = idle_timeout
        self.fetch_interval = fetch_interval

    def recv(self, timeout: float | None = None) -> Data:  # pragma: no cover
        """
        Receive the next message from the connection

        Args:
            timeout (float): Block until timeout seconds have elapsed or a message is received. If None, waits indefinitely.
                             If timeout passes, raises TimeoutError

        Returns:
            Data: Next event received from the connection
        """
        with self.lock:
            demisto.debug("Locked the thread to recv a message")
            event = self.connection.recv(timeout=timeout)
        return event

    def heartbeat(self):  # pragma: no cover
        """
        Heartbeat thread function to periodically send keep-alives to the server.
        For the sake of simplicity and error prevention, keep-alives are sent regardless of the actual connection activity.
        """
        while True:
            with self.lock:
                demisto.debug("Locked the thread to pong the connection")
                self.connection.pong()
            time.sleep(self.idle_timeout)


''' HELPER FUNCTIONS '''


def push_events(events: list[dict]):  # pragma: no cover
    """
    Push events to XSIAM.
    """
    send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
    demisto.debug(f"{LOG_PREFIX} Pushed {len(events)} to XSIAM successfully")


@contextmanager
def websocket_connection(url: str, token_id: str, fetch_interval: int, channel: str, verify_ssl: bool):  # pragma: no cover
    """
    Create a connection to the api.

    Args:
        url (str): host URL for the websocket connection.
        channel (str): Retarus channel to connect through.
        token_id (str): Retarus token id.
        fetch_interval (int): Time between fetch iterations.
        verify_ssl (bool): Whether to verify ssl when connecting.

    Yields:
        EventConnection: eventConnection to receive events from.
    """
    extra_headers = {"Authorization": f"Bearer {token_id}"}

    ssl_context = ssl.create_default_context()
    if not verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    try:
        with connect("wss://" + url + f"/email/siem/v1/websocket?channel={channel}",
                     additional_headers=extra_headers,
                     ssl=ssl_context) as ws:
            connection = EventConnection(
                connection=ws,
                fetch_interval=fetch_interval
            )
            set_the_integration_context(
                "last_run_results", f"Opened a connection successfully at {datetime.now().astimezone(timezone.utc)}")
            yield connection

    except Exception as e:
        set_the_integration_context("last_run_results",
                                    f"{str(e)} \n This error happened at {datetime.now().astimezone(timezone.utc)}")
        raise DemistoException(f"{str(e)}\n")


def set_the_integration_context(key: str, val):  # pragma: no cover
    """Adds a key-value pair to the integration context dictionary.
        If the key already exists in the integration context, the function will overwrite the existing value with the new one.
    """
    cnx = demisto.getIntegrationContext()
    cnx[key] = val
    demisto.setIntegrationContext(cnx)


def is_interval_passed(fetch_start_time: datetime, fetch_interval: int) -> bool:  # pragma: no cover
    """Checks if the specified interval has passed since the given start time.
        This function is used within the fetch_events function to determine if the time to fetch events is over or not.

    Args:
        fetch_start_time (datetime): The start time of the interval
        fetch_interval (int): The interval in seconds

    Returns:
        bool: True if the interval has passed, False otherwise
    """
    is_interval_passed = fetch_start_time + timedelta(seconds=fetch_interval) < datetime.now().astimezone(timezone.utc)
    demisto.debug(f"returning {is_interval_passed=}")
    return is_interval_passed


def perform_long_running_loop(connection: EventConnection, fetch_interval: int):
    """
    Long running loop iteration function. Fetches events from the connection and sends them to XSIAM.

    Args:
        connection (EventConnection): A connection object to fetch events from.
        fetch_interval (int): Fetch time for this fetching events cycle.
    """
    demisto.debug(f"{LOG_PREFIX} starting to fetch events")
    events = fetch_events(connection, fetch_interval)
    demisto.debug(f'{LOG_PREFIX} Adding {len(events)} Events to XSIAM')

    # Send the events to the XSIAM.
    try:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.debug("Sended events to XSIAM successfully")
    except DemistoException:
        demisto.error(f"Failed to send events to XSIAM. Error: {traceback.format_exc()}")


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
        verify_ssl (bool): Whether to verify ssl when opening the connection.
    """
    with websocket_connection(url, token_id, fetch_interval, channel, verify_ssl) as connection:
        demisto.info(f"{LOG_PREFIX} Connected to websocket")

        # Retarus will keep connections with no traffic open for at most 5 minutes.
        # It is highly recommended that the client sends a PING control frame every 60 seconds to keep the connection open.
        # (sentence taken from Retarus API docs)
        # Setting up heartbeat daemon threads to send keep-alives if needed
        threading.Thread(target=connection.heartbeat, daemon=True).start()
        demisto.debug(f"{LOG_PREFIX} Created heartbeat")

        while True:
            perform_long_running_loop(connection, fetch_interval)
            # sleep for a bit to not throttle the CPU
            time.sleep(FETCH_SLEEP)


def test_module():  # pragma: no cover
    raise DemistoException(
        "No test option is available due to API limitations.\
        To verify the configuration, run the retarus-get-last-run-results command and ensure it returns no errors.")


def get_last_run_results_command():
    last_run_results = demisto.getIntegrationContext().get("last_run_results")
    if last_run_results:
        return CommandResults(readable_output=last_run_results)
    else:
        return CommandResults(readable_output="No results from the last run yet. Ensure that a Retarus instance \
            is configured and enabled. If it is, please wait one minute and try running the command again.")


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
    fetch_start_time = datetime.now().astimezone(timezone.utc)
    demisto.debug(f'{LOG_PREFIX} Starting to fetch events at {fetch_start_time}')

    while not is_interval_passed(fetch_start_time, fetch_interval):
        try:
            event = json.loads(connection.recv(timeout=recv_timeout))
        except TimeoutError:
            continue
        except Exception as e:
            set_the_integration_context("last_run_results",
                                        f"{str(e)} \n This error happened at {datetime.now().astimezone(timezone.utc)}")
            raise DemistoException(str(e))

        event_id = event.get("rmxId")
        event_ts = event.get("ts")
        if not event_ts:
            # if timestamp is not in the response, use the current time
            demisto.debug(f"{LOG_PREFIX} Event {event_id} does not have a timestamp, using current time")
            event_ts = datetime.now().isoformat()

        date = dateparser.parse(event_ts)
        if not date:
            demisto.debug(f"{LOG_PREFIX} Event {event_id} has an invalid timestamp, using current time")
            # if timestamp is not in correct format, use the current time
            date = datetime.now()

        event["_time"] = date.astimezone(timezone.utc).isoformat()
        event["SOURCE_LOG_TYPE"] = event.get("type")

        events.append(event)
        event_ids.add(event_id)

    num_events = len(events)
    demisto.debug(f"{LOG_PREFIX} Fetched {num_events} events")
    demisto.debug(f"{LOG_PREFIX} The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))

    set_the_integration_context("last_run_results",
                                f"Got from connection {num_events} events starting\
                                    at {str(fetch_start_time)} untill {datetime.now().astimezone(timezone.utc)}")
    return events


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    url = params["url"]
    token_id = params.get("credentials", {}).get("password", "")
    fetch_interval = arg_to_number(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))
    verify_ssl = argToBoolean(not params.get("insecure", False))
    channel = params.get("channel", DEFAULT_CHANNEL)

    demisto.debug(f"{LOG_PREFIX} command being called is {command}")

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(url, token_id, fetch_interval, channel, verify_ssl))
        elif command == "retarus-get-last-run-results":
            return_results(get_last_run_results_command())
        elif command == "test-module":
            return_results(test_module())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
