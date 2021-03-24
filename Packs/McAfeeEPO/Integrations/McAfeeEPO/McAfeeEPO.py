
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''


''' CLIENT CLASS '''


class Client(BaseClient):

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


def epo_help_command(client: Client) -> CommandResults:

    suffix = 'core.help'
    commands = json.loads(client.epo_help(suffix=suffix)[3:])
    commands_dict = {}

    for command in commands:
        split = command.split(' - ')
        if len(split) == 2:
            commands_dict[split[0].split(' ')[0]] = split[1]
        else:
            commands_dict[split[0].split(' ')[0]] = 'No Description'

    return CommandResults(
        outputs_prefix='McAfeeEPO.Help',
        outputs_key_field='',
        outputs=commands_dict,
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
        raw_results = json.loads(client.epo_query(suffix=suffix, table=table, columns=columns,
                                                  query_filter=query_filter, order_by=order_by)[3:])
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


''' MAIN FUNCTION '''


def main() -> None:

    base_url = urljoin(demisto.params()['url'], '/remote')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    username = demisto.params().get('credentials', {}).get('identifier', '')
    password = demisto.params().get('credentials', {}).get('password', '')

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

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
