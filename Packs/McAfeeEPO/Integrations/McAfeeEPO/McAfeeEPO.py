
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Any, Dict, Tuple, List, Optional, cast
from datetime import datetime
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''
MAX_INCIDENTS_TO_FETCH = 10


''' CLIENT CLASS '''


class Client(BaseClient):

    def search_alerts(self, alert_types: list, max_results: int, start_time: int) -> str:
        alert_types_filter = ""
        for alert_type in alert_types:
            alert_types_filter += f' (eq EPOEvents.ThreatCategory "{alert_type}")'
        params = {
            ':output': 'json',
            'select': f'(select (top {max_results}) EPOEvents.ServerID EPOEvents.EventTimeLocal '
                      f'EPOEvents.AgentGUID EPOEvents.AnalyzerName EPOEvents.AnalyzerHostName '
                      f'EPOEvents.AnalyzerMAC EPOEvents.ThreatCategory  EPOEvents.ThreatEventID '
                      f'EPOEvents.ThreatSeverity  EPOEvents.ThreatName EPOEvents.ThreatType  '
                      f'EPOEvents.ThreatActionTaken EPOEvents.ThreatHandled EPOEvents.AnalyzerDetectionMethod '
                      f'EPOEvents.SourceIPV4 EPOEvents.TargetIPV4 EPOEvents.TargetHostName EPOEvents.TargetUserName '
                      f'EPOEvents.TargetFileName )',
            'target': 'EPOEvents',
            'where': f'(where (and (or {alert_types_filter}) (newerThan EPOEvents.EventTimeLocal {start_time})))',
            'order': '(order(asc EPOEvents.EventTimeLocal))'
        }
        return self._http_request(
            'get',
            url_suffix='core.executeQuery',
            params=params,
            resp_type='text'
        )

    def epo_help(self, suffix: str) -> str:
        params = {
            ":output": "json"
        }
        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )

    def epo_get_latest_dat(self, dat_url: str) -> str:
        return self._http_request(
            'get',
            full_url=dat_url,
            resp_type='text'
        )

    def epo_get_system_tree_group(self, suffix: str, query: str) -> str:
        params = {
            ":output": "json"
        }
        if query:
            params['searchText'] = query

        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )

    def epo_find_systems(self, suffix: str, group_id: str) -> str:
        params = {
            ":output": "json"
        }
        if group_id:
            params['groupId'] = group_id

        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )

    def epo_get_tables(self, suffix: str, table: str = None) -> str:
        params = {
            ":output": "json"
        }
        if table:
            params['table'] = table

        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )

    def epo_query(self, suffix: str, table: str, columns: str = None, query_filter: str = None,
                  order_by: str = None) -> str:
        params = {
            ":output": "json",
            "target": table
        }
        if columns:
            params['select'] = '(select '+columns+')'
        if query_filter:
            params['where'] = '(where ('+query_filter+'))'
        if order_by:
            params['order'] = order_by

        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )

    def epo_find_policies(self, suffix: str, keyword: str) -> str:
        params = {
            ":output": "json"
        }
        if keyword:
            params['searchText'] = keyword

        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )

    def epo_assign_policy(self, suffix: str, policy_id: str, type_id: str, product_id: str, names: str) -> str:
        params = {
            ":output": "json",
            "objectId": policy_id,
            "typeId": type_id,
            "productId": product_id,
            "names": names
        }

        return self._http_request(
            'get',
            url_suffix=suffix,
            params=params,
            resp_type='text'
        )


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:

    try:
        client.epo_help(suffix='core.help')
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], alert_types: Optional[list]
                    ) -> Tuple[Dict[str, int], List[dict]]:

    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)
    latest_created_time = cast(int, last_fetch)

    incidents = []
    raw_response = None

    try:
        raw_response = client.search_alerts(
            alert_types=alert_types,
            max_results=max_results,
            start_time=last_fetch,
        )
        raw_alerts = json.loads(raw_response[3:])
        alerts = []

        for alert in raw_alerts:
            alert_details = {}
            for key in alert:
                alert_details[key.split('.')[1]] = alert[key]
            alerts.append(alert_details)
        for alert in alerts:
            incident_created_time = int(datetime.strptime(alert.get('EventTimeLocal', '0'), '%Y-%m-%dT%H:%M:%S%z').
                                        timestamp()*1000)
            if last_fetch:
                if incident_created_time <= last_fetch:
                    continue
            incident_name = alert['ThreatName']
            incident = {
                'name': incident_name,
                'occurred': timestamp_to_datestring(incident_created_time),
                'rawJSON': json.dumps(alert)
            }

            incidents.append(incident)

            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

        next_run = {'last_fetch': latest_created_time}
        return next_run, incidents
    except Exception:
        return_error(raw_response)


def epo_help_command(client: Client) -> CommandResults:

    suffix = 'core.help'
    commands = json.loads(client.epo_help(suffix=suffix)[3:])
    commands_help = []
    for command in commands:
        command_dict = {}
        split = command.split(' - ')
        if len(split) == 2:
            command_dict['Command'] = split[0].split(' ')[0]
            command_dict['CommandArguments'] = split[0].split(' ')[1:]
            command_dict['Description'] = split[1]
        else:
            command_dict['Command'] = split[0].split(' ')[0]
            command_dict['CommandArguments'] = split[0].split(' ')[1:]
            command_dict['Description'] = 'No Description'
        commands_help.append(command_dict)
    return CommandResults(
        outputs_prefix='McAfeeEPO.Help',
        outputs_key_field='Command',
        outputs=commands_help,
    )


def epo_get_latest_dat_command(client: Client) -> CommandResults:
    dat_url = 'http://update.nai.com/products/commonupdater/gdeltaavv.ini'

    raw_response = client.epo_get_latest_dat(dat_url=dat_url)
    current_version = {
        'CurrentVersion': raw_response.split('\r\n\r\n')[0].split('CurrentVersion=')[1]
    }

    return CommandResults(
        outputs_prefix='McAfeeEPO.LatestDat',
        outputs_key_field='current_version',
        outputs=current_version,
    )


def epo_get_system_tree_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    suffix = 'system.findGroups'
    query = args.get('query', None)
    groups = json.loads(client.epo_get_system_tree_group(suffix=suffix, query=query)[3:])

    return CommandResults(
        outputs_prefix='McAfeeEPO.SystemGroups',
        outputs_key_field='groupId',
        outputs=groups,
    )


def epo_find_systems_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    suffix = 'epogroup.findSystems'
    group_id = args.get('groupId', None)
    systems = json.loads(client.epo_find_systems(suffix=suffix, group_id=group_id)[3:])
    found_systems = []

    for system in systems:
        system_details = {}
        for key in system:
            system_details[key.split('.')[1]] = system[key]
        found_systems.append(system_details)

    return CommandResults(
        outputs_prefix='McAfeeEPO.Systems',
        outputs_key_field='AgentGUID',
        outputs=found_systems,
    )


def epo_get_tables_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    suffix = 'core.listTables'
    table = args.get('table', None)
    tables = []
    if table:
        try:
            raw_response = json.loads(client.epo_get_tables(suffix=suffix, table=table)[3:])
            tables.append(raw_response)
        except Exception:
            return_error(client.epo_get_tables(suffix=suffix, table=table))
    else:
        raw_responses = json.loads(client.epo_get_tables(suffix=suffix)[3:])
        for response in raw_responses:
            response.pop('columns')
            response.pop('foreignKeys')
            response.pop('relatedTables')
            tables.append(response)

    return CommandResults(
        outputs_prefix='McAfeeEPO.Tables',
        outputs_key_field='target',
        outputs=tables,
    )


def epo_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    suffix = 'core.executeQuery'
    table = args.get('table', None)
    columns = args.get('columns', None)
    query_filter = args.get('query_filter', None)
    order_by = args.get('order_by', None)
    raw_responses = None
    query_results = []

    try:
        raw_responses = client.epo_query(suffix=suffix, table=table, columns=columns,
                                         query_filter=query_filter, order_by=order_by)
        raw_results = json.loads(raw_responses[3:])
        for result in raw_results:
            result_details = {}
            for key in result:
                result_details[key.split('.')[1]] = result[key]
            query_results.append(result_details)
    except Exception:
        return_error(raw_responses)

    return CommandResults(
        outputs_prefix='McAfeeEPO.QueryResults',
        outputs_key_field='TargetCreateTime',
        outputs=query_results,
    )


def epo_fetch_sample_alerts_command(client: Client, alert_types: list, max_results: int, first_fetch_time: int,
                                    last_run: Dict[str, int]) -> CommandResults:

    raw_response = client.search_alerts(
        max_results=max_results,
        start_time=first_fetch_time,
        alert_types=alert_types
    )
    raw_alerts = json.loads(raw_response[3:])
    alerts = []

    for alert in raw_alerts:
        alert_details = {}
        for key in alert:
            alert_details[key.split('.')[1]] = alert[key]
        alerts.append(alert_details)

    return CommandResults(
        outputs_prefix='McAfeeEPO.SampleAlerts',
        outputs_key_field='groupId',
        outputs=alerts,
    )


def epo_find_policies_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    suffix = 'policy.find'
    keyword = args.get('keyword', None)
    policies = json.loads(client.epo_find_policies(suffix=suffix, keyword=keyword)[3:])
    found_policies = []

    for policy in policies:
        policy_details = {}
        for key in policy:
            policy_details[key] = policy[key]
        found_policies.append(policy_details)

    return CommandResults(
        outputs_prefix='McAfeeEPO.Policies',
        outputs_key_field='typeId,objectId',
        outputs=found_policies,
    )


def epo_assign_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    suffix = 'policy.assignToSystem'
    policy_id = args.get('policy_id', None)
    type_id = args.get('type_id', None)
    product_id = args.get('product_id', None)
    endpoints = args.get('endpoints', None)
    groups = args.get('groups', None)
    names = None
    if endpoints and groups:
        names = endpoints + ',' + groups
    elif endpoints:
        names = endpoints
    elif groups:
        names = groups
    else:
        return_error('Please provide either either endpoints or groups to assign a policy to')
    raw_results = json.loads(client.epo_assign_policy(suffix=suffix, policy_id=policy_id, type_id=type_id,
                                                   product_id=product_id, names=names)[3:])
    results = []

    for result in raw_results:
        result_details = {}
        for key in result:
            result_details[key] = result[key]
        results.append(result_details)

    return CommandResults(
        outputs_prefix='McAfeeEPO.PolicyAssignTasks',
        outputs_key_field='id',
        outputs=results,
    )


''' MAIN FUNCTION '''


def main() -> None:

    base_url = urljoin(demisto.params()['url'], '/remote')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    username = demisto.params().get('credentials', {}).get('identifier', '')
    password = demisto.params().get('credentials', {}).get('password', '')
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
    )
    first_fetch_milliseconds = int((datetime.now().timestamp() - first_fetch_time.timestamp())*1000)
    alert_types = demisto.params().get('alert_types', 'av.detect').split(',')
    max_results = arg_to_number(
        arg=demisto.params().get('max_fetch'),
        arg_name='max_fetch',
        required=False
    )
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            auth=(username, password)
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_milliseconds,
                alert_types=alert_types
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'epo-help':
            return_results(epo_help_command(client))
        elif demisto.command() == 'epo-get-latest-dat':
            return_results(epo_get_latest_dat_command(client))
        elif demisto.command() == 'epo-get-system-tree-group':
            return_results(epo_get_system_tree_group_command(client, demisto.args()))
        elif demisto.command() == 'epo-find-systems':
            return_results(epo_find_systems_command(client, demisto.args()))
        elif demisto.command() == 'epo-get-tables':
            return_results(epo_get_tables_command(client, demisto.args()))
        elif demisto.command() == 'epo-query':
            return_results(epo_query_command(client, demisto.args()))
        elif demisto.command() == 'epo-fetch-sample-alerts':
            return_results(epo_fetch_sample_alerts_command(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_milliseconds,
                alert_types=alert_types)
            )
        elif demisto.command() == 'epo-find-policies':
            return_results(epo_find_policies_command(client, demisto.args()))
        elif demisto.command() == 'epo-assign-policy':
            return_results(epo_assign_policy_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
