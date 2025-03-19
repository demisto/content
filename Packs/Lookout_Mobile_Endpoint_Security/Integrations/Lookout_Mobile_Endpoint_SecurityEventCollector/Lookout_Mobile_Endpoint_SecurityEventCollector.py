import uuid
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

from sseclient import SSEClient


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'lookout_mobile'
PRODUCT = 'endpoint_security'
BASE_URL = 'https://api.lookout.com/'
FETCH_SLEEP = 5
FETCH_INTERVAL_IN_SECONDS = 60
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """
    def __init__(self, base_url: str, verify: bool, proxy: bool, event_type_query: str, app_key: str):
        
        self.event_type_query = event_type_query
        self.app_key = app_key
        self.base_url = base_url
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        
    def refresh_token_request(self):
        """request a new access token"""
        data = {'grant_type': 'client_credentials'}
        headers = {'Authorization': f'Bearer {self.app_key}'}
        response = self._http_request(method="POST", data=data, url_suffix='oauth2/token', headers=headers)
        return response

    def stream_events(self):
        pass


    def get_token(self) -> str:
        """Returns the token, or refreshes it if the time of it was exceeded
        """
        integration_context = demisto.getIntegrationContext()
        if integration_context.get('token_expiration', 0) <= time.time():
            return self.refresh_token()

        return integration_context.get('access_token', '')
            
    def refresh_token(self) -> str:
        """Refreshes the token and updated the integration context
        """
        demisto.debug("MES: refreshing the token")
        response = self.refresh_token_request()
        
        access_token = response.get('access_token')
        token_expiration = response.get('expires_at')
        
        set_the_context('access_token', access_token)
        set_the_context('token_expiration', token_expiration)

        demisto.debug("MES: Updated integration context with new token")
        return access_token

def set_the_context(key: str, val):  # pragma: no cover
    """Adds a key-value pair to the integration context dictionary.
        If the key already exists in the integration context, the function will overwrite the existing value with the new one.
    """
    cnx = demisto.getIntegrationContext()
    cnx[key] = val
    demisto.setIntegrationContext(cnx)

def fetch_events(sse_client: SSEClient, fetch_interval: int, recv_timeout: int = 10) -> list[dict]:
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
    demisto.debug(f'Starting to fetch events at {fetch_start_time}')

    for event in sse_client.events():
        demisto.debug(f'MES: Got event {event}')
        event_id = event.get("id")
        event_created_time = event.get("created_time")
        if not event_created_time:
            # if timestamp is not in the response, use the current time
            demisto.debug(f"Event {event_id} does not have a timestamp, using current time")
            event_created_time = datetime.now().isoformat()

        event["_time"] = event_created_time
        event["SOURCE_LOG_TYPE"] = event.get("type")

        events.append(event)
        event_ids.add(event_id)
        
        if is_interval_passed(fetch_start_time, fetch_interval):
            handle_fetched_events(events, event_ids, event_created_time)

    set_the_context("last_run_results",
                                f"Got from connection {len(events)} events starting\
                                    at {str(fetch_start_time)} until {datetime.now().astimezone(timezone.utc)}")
    return events

def handle_fetched_events(events: list,event_ids: set, last_fetch_time: str):
    demisto.debug(f"Fetched {len(events)} events")
    demisto.debug("The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))
    # Send the events to the XSIAM.
    try:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.debug("Sended events to XSIAM successfully")
        set_the_context('last_fetch_time', last_fetch_time)
    except DemistoException:
        demisto.error(f"Failed to send events to XSIAM. Error: {traceback.format_exc()}")
    
    


''' MAIN FUNCTION '''

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

def get_start_time_for_stream() -> str:
    integration_context = demisto.getIntegrationContext()
    last_fetch_time = integration_context.get('last_fetch_time', '')
    if not last_fetch_time:
        last_fetch_time = datetime.now().isoformat()

    urlencoded_time = urllib.parse.quote(last_fetch_time)

    return urlencoded_time
    

def perform_long_running_loop(client: Client, fetch_interval: int):
    """
    Long running loop iteration function. Fetches events from the connection and sends them to XSIAM.

    Args:
        connection (EventConnection): A connection object to fetch events from.
        fetch_interval (int): Fetch time for this fetching events cycle.
    """
    token_for_stream = client.get_token()
    start_time_for_stream = get_start_time_for_stream()

    headers = {'Accept': 'text/event-stream', 'Authorization': token_for_stream}
    params = {'types': client.event_type_query, 'start_time': start_time_for_stream}
    remove_nulls_from_dictionary(params)
    
    response = requests.get(client.base_url + 'mra/stream/v2/events', stream=True, headers=headers, params=params)
    sse_client = SSEClient(response)
    demisto.debug(f"starting to fetch events from {start_time_for_stream}")
    fetch_events(sse_client, fetch_interval)


def long_running_execution_command(client: Client, fetch_interval: int):
    """
    Performs the long running execution loop.
    Opens a connection to Proofpoints for every event type and fetches events in a loop.
    Heartbeat threads are opened for every connection to send keepalives if the connection is idle for too long.

    Args:
        host (str): host URL for the websocket connection.
    """
    while True:
        try:
            perform_long_running_loop(client, fetch_interval)
            # sleep for a bit to not throttle the CPU
        except Exception as e:
            pass
        time.sleep(FETCH_SLEEP)

def test_module(client):  # pragma: no cover
    client.refresh_token()
    return 'ok'

def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    app_key = params.get("api_key", {}).get("password", "")
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    event_types = params.get('event_types', [])
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))
    
    if 'All' in event_types:
        event_type_query = ''
    else:
        event_type_query = ','.join(event_type.upper() for event_type in event_types)
    client = Client(base_url=BASE_URL, verify=verify, proxy=proxy, event_type_query=event_type_query, app_key=app_key)

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(client, fetch_interval))
        elif command == "test-module":
            return_results(test_module(client))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
