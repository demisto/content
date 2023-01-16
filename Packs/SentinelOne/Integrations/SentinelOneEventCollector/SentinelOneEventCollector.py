from CommonServerPython import *
import urllib3
from typing import Dict, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'sentinelone'
PRODUCT = 'xdr'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this SentinelOne implementation, no special attributes defined
    """

    def __init__(self, base_url, verify=True, headers=None, proxy=False, fetch_limit=1000):
        super().__init__(
            base_url=base_url,
            verify=verify,
            headers=headers,
            proxy=proxy
        )
        self.limit = fetch_limit

    def get_activities(self, from_time: datetime | str) -> List:
        """
        Returns SentinelOne activities using the '/activities' API endpoint.
        All the parameters are passed directly to the API as HTTP GET parameters in the request

        Args:
            from_time: Time (the incident was created) to start fetching.

        Returns:
            list: The activities.
        """
        params = {
            'createdAt__gt': from_time,
            'limit': self.limit,
            'sortBy': 'createdAt',
            'sortOrder': 'asc',
        }
        result = self._http_request('GET', url_suffix='/activities', params=params)
        return result.get('data', [])

    def get_threats(self, from_time: datetime | str) -> List:
        """
        Returns SentinelOne threats using the '/threats' API endpoint.
        All the parameters are passed directly to the API as HTTP GET parameters in the request

        Args:
            from_time: Time (the incident was created) to start fetching.

        Returns:
            list: The threats.
        """
        params = {
            'createdAt__gt': from_time,
            'limit': self.limit,
            'sortBy': 'createdAt',
            'sortOrder': 'asc',
        }
        result = self._http_request('GET', url_suffix='/threats', params=params)
        return result.get('data', [])

    def get_alerts(self, from_time: datetime | str) -> List:
        """
        Returns SentinelOne alerts using the '/cloud-detection/alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP GET parameters in the request

        Args:
            from_time: Time (the incident was created) to start fetching.

        Returns:
            list: The alerts.
        """
        params = {
            'limit': self.limit,
            'createdAt__gt': from_time,
            'sortBy': 'alertInfoCreatedAt',
            'sortOrder': 'asc',
        }
        result = self._http_request('GET', url_suffix='/cloud-detection/alerts', params=params)
        return result.get('data', [])


''' HELPER FUNCTIONS '''


def get_events(client: Client, event_type: List,
               from_time: datetime = arg_to_datetime('3 days')) -> List:  # type: ignore
    events = []
    if 'ACTIVITIES' in event_type:
        events.extend(client.get_activities(from_time))
    if 'THREATS' in event_type:
        events.extend(client.get_threats(from_time))
    if 'ALERTS' in event_type:
        events.extend(client.get_alerts(from_time))

    return events


def first_run(from_time: datetime = arg_to_datetime('3 days')) -> Dict:  # type: ignore
    return {
        'last_activity_created': from_time,
        'last_threat_created': from_time,
        'last_alert_created': from_time,
    }


def add_time_key_to_events(events: List[Dict[str, Any]] = None):
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    """
    for event in events:
        if alert_info := event.get('alertInfo'):
            event["_time"] = alert_info.get("createdAt")
        if threat_info := event.get('threatInfo'):
            event["_time"] = threat_info.get("createdAt")
        else:  # Otherwise, it's an activity.
            event["_time"] = event.get("createdAt")


''' COMMAND FUNCTIONS '''


def test_module(client: Client, event_type: List) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): SentinelOne client to use.
        event_type (List): Integration parameters.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        get_events(client, event_type=event_type)
    except Exception as e:
        if 'UNAUTHORIZED' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events_command(client: Client, first_fetch_time: datetime, event_type: List) -> Tuple[List, CommandResults]:
    events = get_events(client, from_time=first_fetch_time, event_type=event_type)
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: Dict[str, datetime | str], event_type: Optional[List]) -> Tuple[Dict, List]:
    """
    Args:
        client (Client): SentinelOne client to use.
        last_run (dict): A dict containing the latest event (for each event type) created time we got from last fetch.
            For example: {'last_activity_created': '2023-01-01T00:00:00', 'last_threat_created': '2023-01-01T00:00:00'}
        event_type (list): Event type to be fetched ['ACTIVITIES', 'THREATS', 'ALERTS']
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    if not event_type:
        event_type = ['ACTIVITIES', 'THREATS', 'ALERTS']

    demisto.info(f'Fetched event of type: {event_type} from time {last_run}.')
    events = []
    if 'ACTIVITIES' in event_type:
        if activities := client.get_activities(last_run['last_activity_created']):
            events.extend(activities)
            last_run['last_activity_created'] = activities[-1].get('createdAt')
    if 'THREATS' in event_type:
        if threats := client.get_threats(last_run['last_threat_created']):
            events.extend(threats)
            last_run['last_threat_created'] = threats[-1].get('threatInfo', {}).get('createdAt')
    if 'ALERTS' in event_type:
        if alerts := client.get_alerts(last_run['last_alert_created']):
            events.extend(alerts)
            last_run['last_alert_created'] = alerts[-1].get('alertInfo', {}).get('createdAt')

    demisto.info(f'Setting next run {last_run}.')
    return last_run, events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('url'), 'web/api/v2.1')
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    fetch_limit = arg_to_number(args.get('limit') or params.get('fetch_limit', 1000))
    proxy = params.get('proxy', False)
    event_type = [event_type.strip() for event_type in params.get('event_type', ['ACTIVITIES', 'THREATS', 'ALERTS'])]

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'ApiToken {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            fetch_limit=fetch_limit
        )

        if command == 'test-module':
            result = test_module(client, event_type)
            return_results(result)

        elif command in (f'{VENDOR}-get-events', 'fetch-events'):
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events = []  # type: List[Dict]
            if command == f'{VENDOR}-get-events':
                events, results = get_events_command(client, first_fetch_time, event_type)  # type: ignore
                return_results(results)

            if command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun() or first_run(first_fetch_time)  # type: ignore
                next_run, events = fetch_events(client=client, last_run=last_run, event_type=event_type)
                demisto.setLastRun(next_run)

            if events and should_push_events:
                add_time_key_to_events(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
