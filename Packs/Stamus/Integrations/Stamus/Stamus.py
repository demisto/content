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
# mocks: is removed by xsoar server
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
#

import urllib3
from datetime import datetime
from typing import Iterable
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'
PAGE_SIZE = 200  # https://xsoar.pan.dev/docs/integrations/fetching-incidents#fetch-limit

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def test_connection(self):
        self._http_request(
            method='GET',
            params={},
            url_suffix='/rest/')

    def get_events(self, _id: str) -> dict[str, Any]:
        """Get all related events with _id that comes from incidents (dbotMirrorId)

        Args:
            _id (str): ID used to get all related events

        Returns:
            dict: dict containing all related events
        """
        return self._http_request(
            method='GET',
            params={},
            url_suffix='/rest/appliances/threat_history_incident/%s/get_events' % _id)

    def get_by_ioc(self, key, value):
        """Get events from Stamus Central Server

        Args:
            ip (str): IP address

        Returns:
            dict: dict containing Host ID informations
        """
        return self._http_request(
            method='GET',
            params={'qfilter': f'{key}:{escape(value)}'},
            url_suffix='/rest/rules/es/events_tail/')

    def get_host_id(self, ip: str) -> dict[str, Any]:
        """Get host id from Stamus Central Server

        Args:
            ip (str): IP address

        Returns:
            dict: dict containing Host ID informations
        """
        return self._http_request(
            method='GET',
            params={},
            url_suffix='/rest/appliances/host_id/%s' % ip)

    def get_incidents(self, timestamp: int) -> Iterable:
        """Get incidents from Stamus Central Server

        Args:
            timestamp (int): start timestamp (epoch in seconds) for the search.

        Returns:
            list: list of kill chains changes
        """
        params = {'timestamp': str(timestamp), 'page_size': PAGE_SIZE}

        response = self._http_request(
            method='GET',
            params=params,
            url_suffix='/rest/appliances/threat_history_incident/')

        for item in response['results']:
            yield item


''' HELPER FUNCTIONS '''


def escape(string):
    return string. \
        replace('=', r'\='). \
        replace('+', r'\+'). \
        replace('-', r'\-'). \
        replace('&', r'\&'). \
        replace('|', r'\|'). \
        replace('!', r'\!'). \
        replace('(', r'\('). \
        replace(')', r'\)'). \
        replace('{', r'\{'). \
        replace('}', r'\}'). \
        replace('[', r'\['). \
        replace(']', r'\]'). \
        replace('^', r'\^'). \
        replace('"', r'\"'). \
        replace('~', r'\~'). \
        replace(':', r'\:'). \
        replace('/', r'\/'). \
        replace('\\', r'\\')


def convert_to_demisto_severity(severity: int) -> int:
    """
    Maps severity to Cortex XSOAR severity.
    Converts stamus alert severity level to Cortex XSOAR incident
    severity (1 to 4) => (Low to CRITICAL).

    Args:
        severity (str): severity as returned from the HelloWorld API.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """
    return {
        1: IncidentSeverity.CRITICAL,
        2: IncidentSeverity.HIGH,
        3: IncidentSeverity.MEDIUM,
        4: IncidentSeverity.LOW,
    }.get(severity, IncidentSeverity.UNKNOWN)


def get_command_results(data: dict[str, Any]) -> CommandResults:
    return CommandResults(
        readable_output=f'## {json.dumps(data)}',
        outputs_prefix='StamusIntegration.Output',
        outputs=data
    )

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)


''' COMMAND FUNCTIONS '''


def fetch_by_ioc(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch events from indicator of compromise
    """
    return get_command_results(client.get_by_ioc(args['key'], args['value'])['results'])


def fetch_events(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch events from an incident ID
    """
    return get_command_results(client.get_events(args['id'])['results'])


def fetch_host_id(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch host_id info from an IP
    """
    return get_command_results(client.get_host_id(args['ip']))


def fetch_incidents(client: Client, timestamp: int) -> tuple[dict[str, int], list[dict]]:
    """Fetch last alerts and build new incident structs
    """

    incidents: list[dict] = []
    next_run = {'timestamp': timestamp}

    for idx, alert in enumerate(client.get_incidents(timestamp)):
        incident = {
            'name': '%s_incident_%s' % (alert['target'], idx),
            # Stamus ID used to get related events
            'dbotMirrorId': str(alert['id']),
            'details': alert['threat_description'],
            'occurred': alert['timestamp'],
            'rawJSON': json.dumps(alert),
            'type': alert['target_type'],
        }
        incidents.append(incident)

        timestamp = int(datetime.strptime(alert['timestamp'], DATE_FORMAT).timestamp())
        if timestamp > next_run['timestamp']:
            next_run['timestamp'] = timestamp

    return next_run, incidents


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        message = 'ok'
        client.test_connection()

    except Exception as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    api_token = params.get('credentials', {}).get('password')
    server_url = params.get('url')
    proxy = params.get('proxy', False)
    verify_certificate = not params.get('insecure', False)

    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    timestamp = int(first_fetch_time.timestamp())
    headers = {'Authorization': f'Token {api_token}'}

    try:
        client = Client(
            base_url=server_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        demisto.debug(f'Command being called is {demisto.command()}')

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            last_fetch = demisto.getLastRun().get('timestamp', None)
            timestamp = timestamp if last_fetch is None else int(last_fetch)

            next_run, incidents = fetch_incidents(
                client=client,
                timestamp=timestamp,
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            # return_results(incidents)

        elif demisto.command() == 'stamus-get-host-id':
            args = demisto.args()
            return_results(fetch_host_id(client, args))

        elif demisto.command() == 'stamus-get-events':
            args = demisto.args()
            return_results(fetch_events(client, args))

        elif demisto.command() == 'stamus-get-by-ioc':
            args = demisto.args()
            return_results(fetch_by_ioc(client, args))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
