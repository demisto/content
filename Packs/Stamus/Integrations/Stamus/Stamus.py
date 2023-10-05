"""Stamus Integration for Cortex XSOAR (aka Demisto)

This is an integration with Stamus Security Platform.
"""
# mocks: is removed by xsoar server
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
#

import urllib3
from datetime import datetime
from collections.abc import Iterable
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'
PAGE_SIZE = 200  # https://xsoar.pan.dev/docs/integrations/fetching-incidents#fetch-limit
ARRAY_ITEMS = ['client_service', 'hostname', 'username', 'http.user_agent', 'tls.ja3', 'ssh.client', 'roles']
ITEM_KEY = {'client_service': 'name', 'hostname': 'host', 'username': 'user', 'http.user_agent': 'agent',
            'tls.ja3': 'hash', 'ssh.client': 'software_version', 'roles': 'name', 'services': 'app_proto'}
FIELDS_SUBSTITUTION = (['http.user_agent', 'http_user_agent'], ['http.user_agent_count', 'http_user_agent_count'],
                       ['tls.ja3', 'tls_ja3'], ['tls.ja3_count', 'tls_ja3_count'], ['ssh.client', 'ssh_client'],
                       ['ssh.client_count', 'ssh_client_count'])
FIELDS_SUBSTITUTION_DICT = {'http.user_agent': 'http_user_agent', 'http.user_agent_count': 'http_user_agent_count',
                            'tls.ja3': 'tls_ja3', 'tls.ja3_count': 'tls_ja3_count', 'ssh.client': 'ssh_client',
                            'ssh.client_count': 'ssh_client_count'}

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
            url_suffix=f'/rest/appliances/threat_history_incident/{_id}/get_events')

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
            url_suffix=f'/rest/appliances/host_id/{ip}')

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

        yield from response.get('results', [])


''' HELPER FUNCTIONS '''


def escape(string):
    '''
    Escape other elasticsearch reserved characters
    '''
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


def get_command_results(data: dict[str, Any], table: str, context: str) -> CommandResults:
    return CommandResults(
        readable_output=table,
        outputs_prefix=f'StamusIntegration.{context}',
        outputs=data
    )

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)


''' COMMAND FUNCTIONS '''


def fetch_by_ioc(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch events from indicator of compromise
    """
    results = client.get_by_ioc(args['indicator_key'], args['indicator_value']).get('results', [])
    table = tableToMarkdown('IOC Matches', results, headers=['timestamp', 'src_ip', 'dest_ip', 'event_type'])
    return get_command_results(results, table, 'IOC')


def fetch_events(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch events from an incident ID
    """
    results = client.get_events(str(args.get('id'))).get('results', [])
    for result in results:
        result['method'] = result.get('alert', {}).get('signature', 'algorithmic detection')
        result['info'] = ""
        if result.get("hostname_info"):
            result['info'] = 'Hostname: %s' % (result.get('hostname_info', {}).get('host', 'unknown'))
        result['asset'] = result.get('stamus', {}).get('asset', 'unknown')
        result['offender'] = result.get('stamus', {}).get('source', 'unknown')
        result['killchain'] = result.get('stamus', {}).get('kill_chain', 'unknown')
    headers = ['timestamp', 'asset', 'offender', 'killchain', 'method', 'info', 'src_ip', 'dest_ip', 'app_proto']
    table = tableToMarkdown('Individual Events List', results, headers=headers)
    return get_command_results(results, table, 'RelatedEvents')


def linearize_host_id(host: dict) -> list:
    """Host Insights structure is nested and this function convert it to
    a suite of events.
    """
    host_info = []
    host_data = host['host_id']
    item_data = {'ip': host['ip']}
    item_data['event_type'] = 'discovery'
    item_data['first_seen'] = host_data['first_seen']
    if 'last_seen' in host_data:
        item_data['last_seen'] = host_data['last_seen']
    if 'net_info' in host_data:
        item_data['net_info'] = host_data['net_info']
    host_services = host_data.get('services')
    if host_services is not None:
        item_data['type'] = 'service'
        for service in host_services:
            for value in service['values']:
                item_data['service'] = value
                item_data['service']['proto'] = service['proto']
                item_data['service']['port'] = service['port']
                item_data['value'] = value['app_proto']
                if '+' in value['first_seen'] and value['first_seen'][-3] != ':':
                    item_data['timestamp'] = value['first_seen'][:-2] + ':' + value['first_seen'][-2:]
                else:
                    item_data['timestamp'] = value['first_seen']
                host_info.append(item_data.copy())
        item_data.pop('service')
    for key in ARRAY_ITEMS:
        if key in host_data:
            item_data['type'] = FIELDS_SUBSTITUTION_DICT.get(key, key)
            for item in host_data[key]:
                if key in FIELDS_SUBSTITUTION_DICT:
                    item_data[FIELDS_SUBSTITUTION_DICT[key]] = item
                else:
                    item_data[key] = item
                item_data['value'] = item[ITEM_KEY[key]]
                item_data['timestamp'] = item['first_seen']
                host_info.append(item_data.copy())
            item_data.pop('timestamp')
            if key in FIELDS_SUBSTITUTION_DICT:
                item_data.pop(FIELDS_SUBSTITUTION_DICT[key])
            else:
                item_data.pop(key)
    return host_info


def fetch_host_id(client: Client, args: dict[str, Any]) -> CommandResults:
    """Fetch host_id info from an IP
    """
    result = client.get_host_id(str(args.get('ip')))
    host_info = linearize_host_id(result)

    table = tableToMarkdown('Host Insight', host_info, headers=['timestamp', 'ip', 'type', 'value'])

    return get_command_results(result, table, 'HostInsights')


def fetch_incidents(client: Client, timestamp: int) -> tuple[dict[str, int], list[dict]]:
    """Fetch last alerts and build new incident structs
    """

    incidents: list[dict] = []
    next_run = {'timestamp': timestamp}

    for idx, alert in enumerate(client.get_incidents(timestamp)):
        incident = {
            'name': f'{alert.get("target")}_incident_{idx}',
            # Stamus ID used to get related events
            'dbotMirrorId': str(alert.get('id')),
            'details': alert.get('threat_description'),
            'occurred': alert.get('timestamp'),
            'rawJSON': json.dumps(alert),
            'type': alert.get('target_type'),
        }
        incidents.append(incident)

        timestamp = int(datetime.strptime(alert['timestamp'], DATE_FORMAT).timestamp())
        if timestamp > next_run['timestamp']:
            next_run['timestamp'] = timestamp + 1

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

    client.test_connection()
    return 'ok'


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    api_token = params.get('credentials', {}).get('password')
    server_url = params.get('url')
    proxy = params.get('proxy', False)
    verify_certificate = not params.get('insecure', False)

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
            first_fetch_time = arg_to_datetime(
                arg=params.get('first_fetch', '3 days'),
                arg_name='First fetch time',
                required=True
            )
            if first_fetch_time is None:
                raise Exception('Invalid first fetch time')

            timestamp = int(first_fetch_time.timestamp())
            last_fetch = demisto.getLastRun().get('timestamp', None)
            timestamp = timestamp if last_fetch is None else int(last_fetch)

            next_run, incidents = fetch_incidents(
                client=client,
                timestamp=timestamp,
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'stamus-get-host-insight':
            return_results(fetch_host_id(client, args))

        elif demisto.command() == 'stamus-get-doc-events':
            return_results(fetch_events(client, args))

        elif demisto.command() == 'stamus-check-ioc':
            return_results(fetch_by_ioc(client, args))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
