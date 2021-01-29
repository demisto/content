import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import traceback
from typing import Any, Dict, Tuple, List

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATE_REG = '[0-9]+-[0-9]+-[0-9]+[0-9]+T[0-9]+:[0-9]+:[0-9]+Z'

''' CLIENT CLASS '''

URL_SUFFIX: Dict[str, str] = {
    'NODES': '/nodes?{}',
    'ELEMENTS': '/elements?{}',
    'VERSIONS': '/versions?{}',
    'TOKEN': '/csrf-token',
    'RULES': '/rules?{}', }

RULES_HUMAN_READABLE_HEADERS: Dict[str, list] = {
    'RULES': ['name', 'id', 'severity', 'elementName', 'type', 'command', 'importedTime', 'modifiedTime'],
    'ELEMENTS': ['id', 'name', 'nodeName', 'ruleName', 'baselineVersionId'],
    'VERSIONS': ['id', 'timeDetected', 'elementName', 'changeType', 'nodeName', 'ruleName'],
    'NODES': ['id', 'name', 'make', 'ipAddresses', 'type', 'lastCheck', 'modifiedTime'],
}


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, verify=False, proxy=False, auth=None):
        headers = {
            "accept": "application/json",
            'content-type': "application/json",
            "X-Requested-With": "required"
        }
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy, auth=auth)
        self.get_session_token()

    def get_session_token(self):
        """
        Get the csrf token for the requests which is added to the headers of the client
        """
        try:
            response = self._http_request(method='GET', url_suffix=URL_SUFFIX['TOKEN'])
            self._headers.update({response['tokenName']: response['tokenValue']})
        except DemistoException as e:
            if 'CSRF Token must only be requested once per session' in str(e) and self._headers.get('CSRFToken'):
                pass
            elif 'Authentication Failed: Invalid user name or password' in str(e):
                raise DemistoException('Authentication Failed: Invalid user name or password')
            else:
                raise DemistoException(e)

    def get_nodes(self, nodes_filter: str):
        """
        :param nodes_filter: (str) contains the filter of the request.
        :return: the result of the http request from the api
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['NODES'].format(nodes_filter))

    def get_rules(self, rules_filter: str):
        """
        :param rules_filter: (str) contains the filter of the request.
        :return: the result of the http request from the api
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['RULES'].format(rules_filter))

    def get_elements(self, elements_filter: str):
        """
        :param elements_filter: (str) contains the filter of the request.
        :return: the result of the http request from the api
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['ELEMENTS'].format(elements_filter))

    def get_versions(self, versions_filter: str):
        """
        :param versions_filter: (str) contains the filter of the request.
        :return: the result of the http request from the api
        """
        demisto.info(f'fileters for version {versions_filter}')
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['VERSIONS'].format(versions_filter))


''' HELPER FUNCTIONS '''


def prepare_time_range(start: str, end: str = ''):
    if not end:
        end = datetime.utcnow().strftime(DATE_FORMAT)
    if not re.search(DATE_REG, start):
        try:
            start = parse_date_range(start, date_format=DATE_FORMAT)[0]
        except Exception:
            raise DemistoException(f"Please insert start time in relative format e.g. '1 day', '2 days' or in "
                                   f"date format {DATE_FORMAT}")
    if not re.search(DATE_REG, end):
        try:
            end = parse_date_range(end, date_format=DATE_FORMAT)[0]
        except Exception:
            raise DemistoException(f"Please insert end time in relative format e.g. '1 day', '2 days' or in "
                                   f"date format {DATE_FORMAT}")

    return start, end


def filter_versions(args: dict) -> str:
    """
    :param args: (dict) args of the command .
    :return: (str) combination of all filter for the command.
    """
    filters = ""
    if args.get('rule_oids'):
        for rule_id in argToList(args.get('rule_oids')):
            filters += f"ruleId={rule_id}&"
    if args.get('rule_names'):
        for rule_name in argToList(args.get('rule_names')):
            filters += f"ruleName={rule_name}&"
    if args.get('node_oids'):
        for node_id in argToList(args.get('node_oids')):
            filters += f"nodeId={node_id}&"
    if args.get('version_oids'):
        for id in argToList(args.get('version_oids')):
            filters += f"id={id}&"
    if args.get('element_oids'):
        for element_id in argToList(args.get('element_oids')):
            filters += f"elementId={element_id}&"
    if args.get('element_names'):
        for element_name in argToList(args.get('element_names')):
            filters += f"elementName={element_name}&"
    if args.get('node_names'):
        for node_label in argToList(args.get('node_names')):
            filters += f"nodeLabel={node_label}&"
    if args.get('version_hashes'):
        for hash in argToList(args.get('version_hashes')):
            filters += f"hash={hash}&"
    if args.get('baseline_version_ids'):
        for baseline_version in argToList(args.get('baseline_version_ids')):
            filters += f"baselineVersion={baseline_version}&"
    if start := args.get('start_detected_time', ''):
        start, end = prepare_time_range(start=start, end=args.get('end_detected_time', ''))
        filters += f"timeDetectedRange={start},{end}&"
    if start := args.get('start_received_time', ''):
        start, end = prepare_time_range(start=start, end=args.get('end_received_time', ''))
        filters += f"timeReceivedRange={start},{end}&"
    if args.get('limit'):
        filters += f"pageLimit={args.get('limit')}&"
    if args.get('start'):
        filters += f"pageStart={args.get('start')}&"
    return filters


def filter_rules(args: dict) -> str:
    """
    :param args: (dict) args of the command .
    :return: (str) combination of all filter for the command.
    """
    filters = ""
    if args.get('rule_oids'):
        for id in argToList(args.get('rule_oids')):
            filters += f"id={id}&"
    if args.get('rule_names'):
        for name in argToList(args.get('rule_names')):
            filters += f"name={name}&"
    if args.get('rule_types'):
        for type in argToList(args.get('rule_types')):
            filters += f"type={type}&"
    if args.get('limit'):
        filters += f"pageLimit={args.get('limit')}&"
    if args.get('start'):
        filters += f"pageStart={args.get('start')}&"
    return filters


def filter_elements(args: dict) -> str:
    """
    :param args: (dict) args of the command .
    :return: (str) combination of all filter for the command.
    """
    filters = ""
    if args.get('element_oids'):
        for id in argToList(args.get('element_oids')):
            filters += f"id={id}&"
    if args.get('element_names'):
        for name in argToList(args.get('element_names')):
            filters += f"name={name}&"
    if args.get('node_oids'):
        for name in argToList(args.get('node_oids')):
            filters += f"nodeId={name}&"
    if args.get('rule_oids'):
        for rule_id in argToList(args.get('rule_oids')):
            filters += f"ruleId={rule_id}&"
    if args.get('baseline_version_ids'):
        for baseline_versionId in argToList(args.get('baseline_version_ids')):
            filters += f"baselineVersionId={baseline_versionId}&"
    if args.get('last_version_id'):
        for last_version_id in argToList(args.get('last_version_id')):
            filters += f"lastVersionId={last_version_id}&"
    if args.get('limit'):
        filters += f"pageLimit={args.get('limit')}&"
    if args.get('start'):
        filters += f"pageStart={args.get('start')}&"
    return filters


def filter_nodes(args: dict) -> str:
    """
    :param args: (dict) args of the command .
    :return: (str) combination of all filter for the command.
    """
    filters = ""
    if args.get('node_oids'):
        for id in argToList(args.get('node_oids')):
            filters += f"id={id}&"
    if args.get('node_ips'):
        for ip_address in argToList(args.get('node_ips')):
            filters += f"ipAddress={ip_address}&"
    if args.get('node_mac_adresses'):
        for mac_address in argToList(args.get('node_mac_adresses')):
            filters += f"macAddress={mac_address}&"
    if args.get('node_names'):
        for ic_name in argToList(args.get('node_names')):
            filters += f"ic_name={ic_name}&"
    if args.get('node_os_names'):
        for make in argToList(args.get('node_os_names')):
            filters += f"make={make}&"
    if args.get('tags'):
        for tag in argToList(args.get('tags')):
            filters += f"tag={tag}&"
    if args.get('limit'):
        filters += f"pageLimit={args.get('limit')}&"
    if args.get('start'):
        filters += f"pageStart={args.get('start')}&"
    return filters


def prepare_fetch(params: dict, first_fetch: str):
    """
    :param params: (dict) args of the command .
    :param first_fetch: (dict) args of the command .
    :return: (str) combination of all filter for the command.
    """
    # check that either ruleid exist or node id for fetch to run
    if not params.get('rule_oids') and not params.get('node_oids'):
        raise DemistoException(
            'Test failed, missing both rule ids and node ids. \n At least one of the above is needed.')

    # set last run
    last_run = demisto.getLastRun().get('lastRun', '')
    if last_run:
        last_fetch = last_run
    else:
        last_fetch = parse_date_range(first_fetch, date_format=DATE_FORMAT)[0]

    # set filter for fetch
    time_now = datetime.utcnow().strftime(DATE_FORMAT)
    params['time_detected_range'] = f'{last_fetch},{time_now}'
    fetch_filter = filter_versions(params)

    return params, fetch_filter, last_fetch


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity and authentication'

    :type client: ``Client``
    :param client: Tripwire client to use

    :type client: ``dict``
    :param params: contains the test modules params.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    if params.get('isFetch'):
        params, fetch_filter, last_fetch = prepare_fetch(params, params.get('first_fetch', ''))
        fetch_incidents(client=client, params=params, max_results=1)

    client.get_nodes("")
    return 'ok'


def versions_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-versions-list command

    :type client: ``Client``
    :param client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    versions_filter = filter_versions(args)
    result = client.get_versions(versions_filter)
    readable_output = tableToMarkdown(
        f'Tripwire Versions list results\nThe number of returned results is: {len(result)}', result, removeNull=True,
        headers=RULES_HUMAN_READABLE_HEADERS['VERSIONS'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Versions',
        outputs_key_field='id',
        outputs=result
    )


def rules_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-rules-list command

    :type client: ``Client``
    :param client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    rules_filter = filter_rules(args)
    result = client.get_rules(rules_filter)
    readable_output = tableToMarkdown(f'Tripwire Rules list results\nThe number of returned results is: {len(result)}',
                                      result, removeNull=True,
                                      headers=RULES_HUMAN_READABLE_HEADERS['RULES'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Rules',
        outputs_key_field='id',
        outputs=result
    )


def nodes_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-nodes-list command

    :type client: ``Client``
    :param client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    node_filter = filter_nodes(args)
    result = client.get_nodes(node_filter)
    readable_output = tableToMarkdown(f'Tripwire Nodes list results\nThe number of returned results is: {len(result)}',
                                      result, removeNull=True,
                                      headers=RULES_HUMAN_READABLE_HEADERS['NODES'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Nodes',
        outputs_key_field='id',
        outputs=result
    )


def elements_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-elements-list command

    :type client: ``Client``
    :param client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    elements_filter = filter_elements(args)
    result = client.get_elements(elements_filter)
    readable_output = tableToMarkdown(
        f'Tripwire Elements list results\nThe number of returned results is: {len(result)}', result, removeNull=True,
        headers=RULES_HUMAN_READABLE_HEADERS['ELEMENTS'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Elements',
        outputs_key_field='id',
        outputs=result
    )


def fetch_incidents(client: Client, max_results: int, params: dict) -> Tuple[Dict[str, str], List[dict]]:
    """
    :type client: ``Client``
    :param client: Tripwire client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type params: ``dict``
    :param params:
        A dict contains the instance params.

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, str]``): Contains the datetime str that will be
                    used in ``last_fetch`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """
    params, fetch_filter, last_fetch = prepare_fetch(params, params.get('first_fetch', ''))

    incidents: List[Dict[str, Any]] = []
    last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)
    # This is necessary for making sure there are no duplicate incidents. The reason for it is as the api returns
    # the versions that occurred from the given time including and this causes duplicates.
    last_fetched_ids = demisto.getLastRun().get('fetched_ids', [])
    alerts = client.get_versions(fetch_filter)
    alerts = alerts[:int(max_results)]
    fetched_ids = []
    for alert in alerts:
        incident_created_time = datetime.strptime(alert.get('timeDetected'), '%Y-%m-%dT%H:%M:%S.000Z')

        if incident_created_time < last_fetch:
            continue

        incident_name = alert.get('id')

        if incident_name in last_fetched_ids:
            continue
        last_fetch = incident_created_time

        incident = {
            'name': f"Element {alert.get('elementName')} version has been changed to: {incident_name}",
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'rawJSON': json.dumps(alert),
        }
        incidents.append(incident)
        fetched_ids.extend([alert.get('id')])

    next_run = {'lastRun': last_fetch.strftime(DATE_FORMAT),
                'fetched_ids': fetched_ids if fetched_ids else last_fetched_ids}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    username = params.get('credentials').get("identifier")
    password = params.get('credentials').get('password')
    base_url = urljoin(params.get('url'), '/api/v1')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth=(username, password))

        command = demisto.command()
        LOG(f'Command being called is {command}')

        commands = {
            "tripwire-versions-list": versions_list_command,
            "tripwire-rules-list": rules_list_command,
            "tripwire-elements-list": elements_list_command,
            "tripwire-nodes-list": nodes_list_command

        }

        if command in commands:
            return_results(commands[command](client, demisto.args()))
        elif command == 'test-module':
            return_results(test_module(client, demisto.params()))
        elif command == 'fetch-incidents':
            max_fetch = params.get('max_fetch', 10)
            next_run, incidents = fetch_incidents(client=client, params=demisto.params(), max_results=max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f'{command} is not an existing Tripwire command')
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
