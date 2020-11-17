import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast, Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''

URL_SUFFIX: Dict[str, str] = {
    'NODES': '/nodes?{}',
    'ELEMENTS': '/elements?{}',
    'VERSIONS': '/versions?{}',
    'TOKEN': '/csrf-token',
    'RULES': '/rules?{}',
    'RULE_RUN_REQUESTS': '/nodes/ruleRunRequests',
}


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
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
        try:
            response = self._http_request(method='GET', url_suffix=URL_SUFFIX['TOKEN'])
            self._headers.update({response['tokenName']: response['tokenValue']})
        except DemistoException as e:
            if 'CSRF Token must only be requested once per session' in str(e) and self._headers.get('CSRFToken'):
                pass
            else:
                raise DemistoException(e)

    def get_nodes(self, nodes_filter: str):
        """
        :return:
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['NODES'].format(nodes_filter))

    def get_rules(self, rules_filter: str):
        """
        :return:
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['RULES'].format(rules_filter))

    def get_elements(self, elements_filter: str):
        """
        :return:
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['ELEMENTS'].format(elements_filter))

    def get_versions(self, versions_filter: str):
        """
        :return:
        """
        return self._http_request(method='GET', url_suffix=URL_SUFFIX['VERSIONS'].format(versions_filter))


''' HELPER FUNCTIONS '''


def filter_version(args):
    filters = ""
    if args.get('rule_oids'):
        filters += f"ruleId={args.get('rule_oids')}&"
    if args.get('rule_names'):
        filters += f"ruleName={args.get('rule_names')}&"
    if args.get('node_oids'):
        filters += f"nodeId={args.get('node_oids')}&"
    if args.get('version_oids'):
        filters += f"id={args.get('version_oids')}&"
    if args.get('element_oids'):
        filters += f"elementId={args.get('element_oids')}&"
    if args.get('element_names'):
        filters += f"elementName={args.get('element_names')}&"
    if args.get('node_names'):
        filters += f"nodeLabel={args.get('node_names')}&"
    if args.get('version_hashes'):
        filters += f"hash={args.get('version_hashes')}&"
    if args.get('baseline_version_ids'):
        filters += f"baselineVersion={args.get('baseline_version_ids')}&"
    if args.get('time_detetcted_range'):
        filters += f"timeDetectedRange={args.get('time_detetcted_range')}&"
    if args.get('time_received_range'):
        filters += f"timeReceivedRange={args.get('time_received_range')}&"
    if args.get('page_limit'):
        filters += f"pageLimit={args.get('page_limit')}&"
    if args.get('page_start'):
        filters += f"pageStart={args.get('page_start')}&"
    return filters


def filter_rules(args):
    filters = ""
    if args.get('rule_oids'):
        filters += f"id={args.get('rule_oids')}&"
    if args.get('rule_names'):
        filters += f"name={args.get('rule_names')}&"
    if args.get('rule_types'):
        filters += f"type={args.get('rule_types')}&"
    if args.get('page_limit'):
        filters += f"pageLimit={args.get('page_limit')}&"
    if args.get('page_start'):
        filters += f"pageStart={args.get('page_start')}&"
    return filters



def filter_elements(args):
    filters = ""
    if args.get('element_oids'):
        filters += f"id={args.get('element_oids')}&"
    if args.get('element_names'):
        filters += f"name={args.get('element_names')}&"
    if args.get('node_oids'):
        filters += f"nodeId={args.get('node_oids')}&"
    if args.get('rule_oids'):
        filters += f"ruleId={args.get('rule_oids')}&"
    if args.get('baseline_version_ids'):
        filters += f"baselineVersionId={args.get('baseline_version_ids')}&"
    if args.get('last_version_id'):
        filters += f"lastVersionId={args.get('last_version_id')}&"
    if args.get('page_limit'):
        filters += f"pageLimit={args.get('page_limit')}&"
    if args.get('page_start'):
        filters += f"pageStart={args.get('page_start')}&"
    return filters


def filter_nodes(args):
    filters = ""
    if args.get('node_oids'):
        filters += f"id={args.get('node_oids')}&"
    if args.get('node_ips'):
        filters += f"ipAddress={args.get('node_ips')}&"
    if args.get('node_mac_adresses'):
         filters += f"macAddress={args.get('rule_types')}&"
    if args.get('node_names'):
        filters += f"ic_name={args.get('node_names')}&"
    if args.get('node_os_names'):
        filters += f"make={args.get('node_os_names')}&"
    if args.get('tags'):
        filters += f"tag={args.get('tags')}&"
    if args.get('page_limit'):
        filters += f"pageLimit={args.get('page_limit')}&"
    if args.get('page_start'):
        filters += f"pageStart={args.get('page_start')}&"
    return filters


def prepare_fetch(params: dict, first_fetch: str):

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
    params['time_received_range'] = f'{last_fetch},{time_now}'
    fetch_filter = filter_version(params)

    return params, fetch_filter, last_fetch


''' COMMAND FUNCTIONS '''


def test_module(client: Client, args) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    if demisto.params().get('isFetch'):
        params, fetch_filter, last_fetch = prepare_fetch(demisto.params(), demisto.params().get('first_fetch'))
        fetch_incidents(client=client, last_fetch=last_fetch, fetch_filter=fetch_filter, max_results=1)

    client.get_nodes("")
    return 'ok'


def versions_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-versions-list command

    :type client: ``Client``
    :param Client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    versions_filter = filter_version(args)
    result = client.get_versions(versions_filter)
    readable_output = tableToMarkdown('Tripwire Versions list results', result, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Versions',
        outputs_key_field='id',
        outputs=result
    )


def rules_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-versions-list command

    :type client: ``Client``
    :param Client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    rules_filter = filter_rules(args)
    result = client.get_rules(rules_filter)
    readable_output = tableToMarkdown('Tripwire Rules list results', result, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Rules',
        outputs_key_field='id',
        outputs=result
    )


def nodes_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-notes-list command

    :type client: ``Client``
    :param Client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    node_filter = filter_nodes(args)
    result = client.get_nodes(node_filter)
    readable_output = tableToMarkdown('Tripwire Nodes list results', result, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Nodes',
        outputs_key_field='id',
        outputs=result
    )


def elements_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """tripwire-elements-list command

    :type client: ``Client``
    :param Client: Tripwire client to use

    :type args: `` Dict[str, Any]``
    :param args:
        all command arguments, passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``
    :rtype: ``CommandResults``
    """
    elements_filter = filter_elements(args)
    result = client.get_elements(elements_filter)
    readable_output = tableToMarkdown('Tripwire Elements list results', result, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Tripwire.Elements',
        outputs_key_field='id',
        outputs=result
    )


def fetch_incidents(client: Client, max_results: int, last_fetch: str, fetch_filter: Optional[str] = ''
                    ) -> Tuple[Dict[str, str], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch_time to determine when to start fetching
    the first time.


    :type client: ``Client``
    :param Client: Tripwire client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch: ``Optional[str]``
    :param first_fetch:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type first_fetch_time: ``Optional[str]``
    :param fetch_filter: If the user entered filters that should be applied on the fetch request.

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    incidents: List[Dict[str, Any]] = []
    last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)
    alerts = client.get_versions(fetch_filter)
    alerts = alerts[:int(max_results)]
    for alert in alerts:
        incident_created_time = datetime.strptime(alert.get('timeDetected'), '%Y-%m-%dT%H:%M:%S.000Z')
        if incident_created_time < last_fetch:
            continue
        incident_name = alert.get('id')
        incident = {
            'name': incident_name,
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'rawJSON': json.dumps(alert),
            }
        incidents.append(incident)
        last_fetch = incident_created_time

    next_run = {'lastRun': last_fetch.strftime(DATE_FORMAT)}
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
            'test-module': test_module,
            "tripwire-versions-list": versions_list_command,
            "tripwire-rules-list": rules_list_command,
            "tripwire-elements-list": elements_list_command,
            "tripwire-nodes-list": nodes_list_command

        }

        if command in commands:
            return_results(commands[command](client, demisto.args()))
        elif command == 'fetch-incidents':
            max_fetch = params.get('max_fetch', 10)
            params, fetch_filter, last_fetch = prepare_fetch(params, params.get('first_fetch'))
            next_run, incidents = fetch_incidents(client=client, last_fetch=last_fetch,
                                                  fetch_filter=fetch_filter, max_results=max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f'{command} is not an existing Tripwire command')
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
