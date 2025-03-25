import demistomock as demisto
from CommonServerPython import *
import urllib3
from requests import Response

from sseclient import SSEClient


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'lookout_mobile'
PRODUCT = 'endpoint_security'
BASE_URL = 'https://api.lookout.com/'
FETCH_SLEEP = 10
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

    def refresh_token_request(self) -> dict:
        """request a new access token"""
        data = {'grant_type': 'client_credentials'}
        headers = {'Authorization': f'Bearer {self.app_key}'}
        response = self._http_request(method="POST", data=data, url_suffix='oauth2/token', headers=headers)
        return response

    def get_token(self) -> str:
        """Returns the token, or refreshes it if the time of it was exceeded
        """
        integration_context = demisto.getIntegrationContext()
        time_now = int(time.time() * 1000)

        if integration_context.get('token_expiration', 0) <= time_now:
            demisto.debug("Refreshing token")
            return self.refresh_token()

        return integration_context.get('access_token', '')

    def refresh_token(self) -> str:
        """Refreshes the token and updated the integration context
        """
        response = self.refresh_token_request()

        access_token = response.get('access_token', '')
        token_expiration = response.get('expires_at', 0)

        set_the_context('access_token', access_token)
        set_the_context('token_expiration', token_expiration)

        demisto.debug("Updated integration context with new token")
        return access_token


def set_the_context(key: str, val):  # pragma: no cover
    """Adds a key-value pair to the integration context dictionary.
        If the key already exists in the integration context, the function will overwrite the existing value with the new one.
    """
    cnx = demisto.getIntegrationContext()
    cnx[key] = val
    demisto.setIntegrationContext(cnx)


def stream_events(sse_client: SSEClient, fetch_interval: int):
    """
    This function fetches events from the given connection, for the given fetch interval

    Args:
        sse_client (SSEClient): the sse client to stream events
        fetch_interval (int): Total time to keep fetching before stopping
    """
    events: list[dict] = []
    event_ids = set()
    events_data = {}

    fetch_start_time = datetime.now().astimezone(timezone.utc)
    demisto.debug(f'Starting to fetch events at {fetch_start_time}')
    for raw_event in sse_client.events():  # this method waits for new server events

        events_data = json.loads(raw_event.data)

        if events_data:
            demisto.debug(f"Got {len(events_data.get('events', {}))} events from API")
            for event in events_data.get('events', {}):

                event["_time"] = event.get("created_time")
                event["SOURCE_LOG_TYPE"] = event.get("type")

                events.append(event)
                event_ids.add(event.get('id'))

        if is_interval_passed(fetch_start_time, fetch_interval) and events:
            handle_fetched_events(events, event_ids, str(raw_event.id))
            events = []
            event_ids.clear()


def handle_fetched_events(events: list, event_ids: set, latest_server_event_id: str):
    """Handles the fetched events in the interval
    """
    demisto.debug(f"Fetched a total of {len(events)} events")
    demisto.debug("The fetched events ids are: " + ", ".join([str(event_id) for event_id in event_ids]))

    try:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        demisto.debug("Sent events to XSIAM successfully")
        set_the_context('last_event_id', latest_server_event_id)
        demisto.debug(f"Updated context with {latest_server_event_id=}")
    except DemistoException as e:
        demisto.error(f"Failed to send events to XSIAM. Error: {str(e)}")


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
    demisto.debug(f"Returning {is_interval_passed=}")
    return is_interval_passed


def get_last_event_id() -> str:
    """Gets the start stream time from the context if exists. If not,returns current time
    """
    integration_context = demisto.getIntegrationContext()
    return integration_context.get('last_event_id', '')


def get_url_for_stream(base_url: str, event_type_query: str, last_event_id: str) -> str:
    """Builds the url for streaming with the url parameters
    """
    url_for_stream = base_url + 'mra/stream/v2/events'
    url_for_stream += f'?type={event_type_query}&id={last_event_id}'
    return url_for_stream


def create_response_object(client: Client) -> Response:
    """Creates the response object with the requests module
    """
    last_event_id = get_last_event_id()
    stream_url = get_url_for_stream(client.base_url, client.event_type_query, last_event_id)
    demisto.debug(f"Streaming from url: {stream_url}")

    token_for_stream = client.get_token()
    demisto.debug("Got token")

    headers = {'Accept': 'text/event-stream', 'Authorization': f'Bearer {token_for_stream}'}
    response = requests.get(stream_url, headers=headers, stream=True, verify=client._verify)
    return response


def perform_long_running_loop(client: Client, fetch_interval: int):
    """
    Long running loop iteration function. Fetches events from the connection and sends them to XSIAM.

    Args:
        connection (EventConnection): A connection object to fetch events from.
        fetch_interval (int): Fetch time for this fetching events cycle.
    """
    response = create_response_object(client)
    sse_client = SSEClient(response)  # type: ignore
    demisto.debug(f'Connected successfully with {response=}')

    stream_events(sse_client, fetch_interval)


def long_running_execution_command(client: Client, fetch_interval: int):
    """
    Performs the long running execution loop.
    Opens a connection to MES and fetches events in a loop.
    """
    while True:
        try:
            perform_long_running_loop(client, fetch_interval)

        except Exception as e:
            demisto.updateModuleHealth(f'Got the following error while trying to stream events: {str(e)}')
        time.sleep(FETCH_SLEEP)  # sleep for a bit to not throttle the CPU


def test_module(client) -> str:  # pragma: no cover
    """Tests the connection to the server
    """
    try:
        client.refresh_token()
    except Exception as e:
        if 'invalid_client' in str(e):
            raise DemistoException('The application key is not valid, make sure to use the correct one.')
        else:
            raise e
    return 'ok'


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    server_url = params.get('server_url', BASE_URL)
    app_key = params.get("app_key", {}).get("password", "")
    proxy = argToBoolean(params.get("proxy", False))
    verify = not argToBoolean(params.get("insecure", False))
    event_types = argToList(params.get('event_types', []))
    fetch_interval = int(params.get("fetch_interval", FETCH_INTERVAL_IN_SECONDS))

    if 'All' in event_types:
        event_type_query = ''
    else:
        event_type_query = ','.join(event_type.upper() for event_type in event_types)
    client = Client(base_url=server_url, verify=verify, proxy=proxy, event_type_query=event_type_query, app_key=app_key)

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(client, fetch_interval))
        elif command == "test-module":
            return_results(test_module(client))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error:\n{str(e)}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
