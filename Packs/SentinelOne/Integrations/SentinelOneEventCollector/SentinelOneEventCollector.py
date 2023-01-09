import uuid

from requests import Response

import demistomock as demisto
from CommonServerPython import *
import json
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast

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
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, headers, proxy, fetch_limit=1000):
        super().__init__(
            base_url=base_url,
            verify=verify,
            headers=headers,
            proxy=proxy
        )
        self.limit = fetch_limit

    def get_activities(self, from_time):
        """
        Returns SentinelOne activities using the '/activities' API endpoint.
        All the parameters are passed directly to the API as HTTP GET parameters in the request

        Args:
            from_time: Time (the incident was created) to start fetching.

        Returns:
            list: The activities.
        """
        params = {
            'createdAt__gte': from_time,
            'limit': self.limit,
            'sortBy': 'createdAt',
            'sortOrder': 'asc',
        }
        result = self._http_request('GET', url_suffix='/activities', params=params)
        return result.get('data', [])

    def get_threats(self, from_time):
        """
        Returns SentinelOne threats using the '/threats' API endpoint.
        All the parameters are passed directly to the API as HTTP GET parameters in the request

        Args:
            from_time: Time (the incident was created) to start fetching.

        Returns:
            list: The threats.
        """
        params = {
            'createdAt__gte': from_time,
            'limit': self.limit,
            'sortBy': 'createdAt',
            'sortOrder': 'asc',
        }
        result = self._http_request('GET', url_suffix='/threats', params=params)
        return result.get('data', [])

    def get_alerts(self, from_time):
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
            'createdAt__gte': from_time,
            'sortBy': 'alertInfoCreatedAt',
            'sortOrder': 'asc',
        }
        result = self._http_request('GET', url_suffix='/cloud-detection/alerts', params=params)
        return result.get('data', [])


def test_module(client: Client, event_type) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        event_type (List): Integration parameters.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    first_fetch_time = arg_to_datetime('3 days')

    try:
        if 'ACTIVITIES' in event_type:
            client.get_activities(first_fetch_time)
        if 'THREATS' in event_type:
            client.get_threats(first_fetch_time)
        if 'ALERTS' in event_type:
            client.get_alerts(first_fetch_time)

    except Exception as e:
        if 'UNAUTHORIZED' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client, first_fetch_time, event_type):
    events = []
    if 'ACTIVITIES' in event_type:
        events.extend(client.get_activities(first_fetch_time))
    if 'THREATS' in event_type:
        events.extend(client.get_threats(first_fetch_time))
    if 'ALERTS' in event_type:
        events.extend(client.get_alerts(first_fetch_time))
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: Dict[str, str], event_type: Optional[list]):
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict containing the latest event (for each event type) created time we got from last fetch.
            For example: {'last_activity_created': '2023-01-01T00:00:00', 'last_threat_created': '2023-01-01T00:00:00'}
        event_type (list): Event type to be fetched ['ACTIVITIES', 'THREATS', 'ALERTS']
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    events = []

    demisto.info(f'Fetched event of type: {event_type} from time {last_run}.')
    if 'ACTIVITIES' in event_type:
        if activities := client.get_activities(last_run.get('last_activity_created')):
            events.extend(activities)
            last_run['last_activity_created'] = activities[-1].get('createdAt')
    if 'THREATS' in event_type:
        if threats := client.get_threats(last_run.get('last_threat_created')):
            events.extend(threats)
            last_run['last_threat_created'] = threats[-1].get('threatInfo', {}).get('createdAt')
    if 'ALERTS' in event_type:
        if alerts := client.get_alerts(last_run.get('last_alert_created')):
            events.extend(alerts)
            last_run['last_alert_created'] = alerts[-1].get('createdAt')

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
    base_url = urljoin(params.get('url'), f'web/api/v{params.get("api_version", "2.1")}')
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    fetch_limit = arg_to_number(args.get('limit') or params.get('fetch_limit', 1000))
    assert 0 < fetch_limit < 1001  # Verify fetch_limit is within range 1 - 1000.
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
            fetch_limit=params.get('fetch_limit')
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, event_type)
            return_results(result)

        elif command in (f'{VENDOR}-{PRODUCT}-get-events', 'fetch-events'):
            if command == f'{VENDOR}-{PRODUCT}-get-events':
                should_push_events = argToBoolean(args.get('should_push_events', False))
                events, results = get_events(client, first_fetch_time, event_type)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun() or {
                    'last_activity_created': first_fetch_time,
                    'last_threat_created': first_fetch_time,
                    'last_alert_created': first_fetch_time,
                }  # For the first execution.
                next_run, events = fetch_events(
                    client=client,
                    last_run=last_run,
                    event_type=event_type
                )
                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun(next_run)

            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
