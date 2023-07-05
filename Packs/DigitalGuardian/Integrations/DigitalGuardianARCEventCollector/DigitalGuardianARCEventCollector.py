from CommonServerPython import *
import urllib3
from datetime import datetime
import time
from typing import Any, Dict, Optional

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Digital Guardian'
PRODUCT = 'ARC'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, verify, proxy, auth_url, gateway_url, client_id, client_secret, export_profile,
                 headers=None, base_url=None):
        self.auth_url = auth_url
        self.gateway_url = gateway_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.export_profile = export_profile

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def get_token(self):
        integration_context = get_integration_context()
        token = integration_context.get('token')
        valid_until = integration_context.get('valid_until')
        time_now = int(time.time())
        if token and valid_until:
            if time_now < valid_until:
                # Token is still valid - did not expire yet
                return token
        sec = self.client_secret.get("password")
        response = self._http_request(
            method='POST',
            full_url=f'{self.auth_url}/as/token.oauth2',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=f'client_id={self.client_id}&client_secret={sec}&grant_type=client_credentials',
        )
        integration_context = {
            'token': response.get("access_token"),
            'valid_until': time_now + int(response.get("expires_in")) - 100
        }
        set_integration_context(integration_context)
        return response.get("access_token")

    def get_events(self, days, token):
        headers = {
            'Authorization': 'Bearer ' + token
        }
        sdays = str(days)
        response = self._http_request(
            method='GET',
            full_url=f'{self.gateway_url}/rest/2.0/export_profiles/{self.export_profile}/export?q=dg_time:last_n_days,{sdays}',
            headers=headers,
        )
        return response


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        limit = int(params.get('Number_of_events', 1000))

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            limit=limit,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def get_raw_events(client, days):
    outcome = []
    event_list = []
    token = client.get_token()
    events = client.get_events(
        days=days,
        token=token
    )
    for item in events["fields"]:
        outcome.append(item['name'])
    for item in events["data"]:
        result = dict(zip(outcome, item))
        event_list.append(result)
    event_list.sort(key=lambda item: (item["inc_mtime"], item["dg_guid"]))
    return event_list


def get_events(client, args):
    days = args.get("days")
    event_list = get_raw_events(client, days)
    limit = int(args.get("limit")) if args.get("limit") else None
    if limit:
        event_list = event_list[:limit]
    hr = tableToMarkdown(name='Test Event', t=event_list)
    return event_list, CommandResults(readable_output=hr)


def create_events_for_push(event_list, last_time, id_list, limit):
    index = 0
    event_list_for_push = []
    for event in event_list:
        if last_time:
            if event.get("inc_mtime") < last_time:
                continue
            if event.get("dg_guid") in id_list:
                continue
            if last_time[:10] == event.get("inc_mtime")[:10]:
                id_list.append(event.get("dg_guid"))
            else:
                id_list = [event.get("dg_guid")]
        else:
            id_list = [event.get("dg_guid")]
        event_list_for_push.append(event)
        last_time = event.get("inc_mtime")
        index += 1
        if index == limit:
            break
    return event_list_for_push, last_time, id_list

def fetch_events(client: Client, last_run: dict[str, list], first_fetch_time: int, limit: int):
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        limit (int):

    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    id_list = last_run.get('id_list', [])

    last_time = last_run.get('start_time', None)
    last_time_date = arg_to_datetime(last_time)
    if last_time_date:
        fetch_time = (datetime.now() - last_time_date).days + 1
    else:
        fetch_time = first_fetch_time

    event_list = get_raw_events(client, fetch_time)
    event_list_for_push, time_of_event, id_list = create_events_for_push(event_list, last_time, id_list, limit)

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'start_time': time_of_event, 'id_list': id_list}
    demisto.info(f'Setting next run {next_run}.')
    return next_run, event_list_for_push


''' MAIN FUNCTION '''


def add_time_to_events(events):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('inc_mtime'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None: # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    auth_url = params.get('Auth Server URL')
    gateway_url = params.get('Gateway Base URL')
    client_id = params.get('Client ID')
    client_secret = params.get('Client Secret')
    export_profile = params.get('Export Profile')
    verify_certificate = not params.get('insecure', False)
    next_run = None

    # How much time before the first fetch to retrieve events
    first_fetch_time = params.get('first_fetch', 3)
    proxy = params.get('proxy', False)
    limit = int(params.get('Number_of_events', 1000))

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            verify=verify_certificate,
            proxy=proxy,
            auth_url=auth_url,
            gateway_url=gateway_url,
            client_id=client_id,
            client_secret=client_secret,
            export_profile=export_profile
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_time)
            return_results(result)

        elif command in ('digital-guardian-get-events', 'fetch-events'):
            if command == 'digital-guardian-get-events':
                should_push_events = argToBoolean(args.pop('should_push_events'))
                events, results = get_events(client, args)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun()
                next_run, events = fetch_events(
                    client=client,
                    last_run=last_run,
                    first_fetch_time=first_fetch_time,
                    limit=limit
                )

            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
                if next_run:
                    # saves next_run for the time fetch-events is invoked
                    demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
