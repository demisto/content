import uuid
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

import sseclient

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'lookout_mobile'
PRODUCT = 'endpoint_security'
BASE_URL = 'https://api.lookout.com/'
FETCH_SLEEP = 5
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

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    def refresh_token_request(self):
        """request a new access token"""
        data = {'grant_type': 'client_credentials'}
        headers = {'Authorization': f'Bearer {self.app_key}'}
        response = self._http_request(method="POST", data=data, url_suffix='oauth2/token', headers=headers)
        return response

    def stream_events(self):
        pass


    def get_token(self):
        """Returns the token, or refreshes it if the time of it was exceeded
        """
        integration_context = demisto.getIntegrationContext()
        if integration_context.get('token_expiration', 0) <= time.time():
            self.refresh_token()

        return integration_context.get('access_token')
            
    def refresh_token(self):
        """Refreshes the token and updated the integration context
        """
        demisto.debug("MES: refreshing the token")
        response = self.refresh_token_request()
        
        access_token = response.get('access_token')
        token_expiration = response.get('expires_at')

        demisto.setIntegrationContext({'access_token': access_token, 'token_expiration': token_expiration})
        demisto.debug("MES: Updated integration context with new token")


def test_module(client):  # pragma: no cover
    client.refresh_token()
    return 'ok'


def get_events(client: Client, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get('limit', 50)
    from_date = args.get('from_date')
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: dict[str, int],
                 first_fetch_time, alert_status: str | None, max_events_per_fetch: int
                 ) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get('prev_id', None)
    if not prev_id:
        prev_id = 0

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    demisto.debug(f'Fetched event with id: {prev_id + 1}.')

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'prev_id': prev_id + 1}
    demisto.debug(f'Setting next run {next_run}.')
    return next_run, events


''' MAIN FUNCTION '''


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('created_time'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None

def long_running_execution_command(client: Client):
    """
    Performs the long running execution loop.
    Opens a connection to Proofpoints for every event type and fetches events in a loop.
    Heartbeat threads are opened for every connection to send keepalives if the connection is idle for too long.

    Args:
        host (str): host URL for the websocket connection.
    """
    while True:
        perform_long_running_loop(client)
        # sleep for a bit to not throttle the CPU
        time.sleep(FETCH_SLEEP)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    app_key = params.get("api_key", {}).get("password", "")
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    event_types = params.get('event_types', [])
    
    if 'All' in event_types:
        event_type_query = ''
    else:
        event_type_query = 'types=' + ','.join(event_type.upper() for event_type in event_types)
    client = Client(base_url=BASE_URL, verify=verify, proxy=proxy, event_type_query=event_type_query, app_key=app_key)

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(client))
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
