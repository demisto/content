from CommonServerPython import *
from CommonServerUserPython import *

import requests
import traceback
import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, token: object, partition: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Content-Type': 'application/json',
                        'X-F5-Auth-Token': token}
        self.partition = partition
        self.stats_keys = {
            'activeMemberCnt', 'availableMemberCnt', 'connq.ageEdm', 'connq.ageEma', 'connq.ageHead',
            'connq.ageMax', 'connq.depth', 'connq.serviced', 'connqAll.ageEdm', 'connqAll.ageEma',
            'connqAll.ageHead', 'connqAll.ageMax', 'connqAll.depth', 'connqAll.serviced', 'curPriogrp',
            'curSessions', 'highestPriogrp', 'lowestPriogrp', 'memberCnt', 'monitorRule',
            'status.statusReason'
        }

    def get_pools(self, expand_collection=False, partition=None):

        url_suffix = f'ltm/pool?expandSubcollections={str(expand_collection).lower()}&' \
                     f'$select=membersReference,name,partition,monitor&$filter=partition eq' \
                     f' {partition if partition else self.partition}'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        if str(expand_collection).lower() == 'true':
            pools = []
            for item in response.get('items'):
                if 'items' in item.get('membersReference'):
                    pools.append({
                        'name': item.get('name'),
                        'partition': item.get('partition'),
                        'monitor': item.get('monitor'),
                        'members': item.get('membersReference')['items']
                    })
        else:
            pools = response.get('items')
        return pools

    def get_pool(self, pool, partition=None):
        url_suffix = f'ltm/pool/~{partition if partition else self.partition}~{pool}'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        return response

    def get_pool_members(self, pool, partition=None):
        url_suffix = f'ltm/pool/~{partition if partition else self.partition}~{pool}/members'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        return {
            'name': pool,
            'members': response.get('items')
        }

    def get_nodes(self, partition=None):
        url_suffix = f'ltm/node?$select=name,partition,address,ration,session,state&$filter=partition eq ' \
                     f'{partition if partition else self.partition}'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        return response.get('items')

    def get_node(self, node, partition=None):
        url_suffix = f'ltm/node/~{partition if partition else self.partition}~{node}'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        return response

    def disable_node(self, node, partition=None):
        url_suffix = f'ltm/node/~{partition if partition else self.partition}~{node}'
        response = self._http_request(method='PATCH', url_suffix=url_suffix,
                                      headers=self.headers, json_data={"session": "user-disabled"})
        return response

    def enable_node(self, node, partition=None):
        url_suffix = f'ltm/node/~{partition if partition else self.partition}~{node}'
        response = self._http_request(method='PATCH', url_suffix=url_suffix,
                                      headers=self.headers, json_data={"session": "user-enabled"})
        return response

    def get_pool_member_stats(self, pool, member, partition=None):
        pool_stats = {}
        partition_name = partition if partition else self.partition
        url_suffix = f'ltm/pool/~{partition_name}~{pool}/members/~{partition_name}~{member}/stats'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        member_stats = response.get('entries')[f'https://localhost/mgmt/tm/ltm/pool/~{partition_name}~{pool}/members/'
                                               f'~{partition_name}~{member}/stats']['nestedStats']['entries']

        for key, value in response.get('entries').items():
            raw_stats = value.get('nestedStats')['entries']
            pool_stats = {key: raw_stats[key] for key in raw_stats.keys() & self.stats_keys}

        return {
            'pool': pool,
            'stats': pool_stats,
            'members': [{'name': member, 'stats': member_stats}]
        }

    def get_node_stats(self, node, partition=None):
        url_suffix = f'ltm/node/~{partition if partition else self.partition}~{node}/stats'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        node_stats = (response.get('entries')[f'https://localhost/mgmt/tm/ltm/node/~'
                                              f'{partition if partition else self.partition}~{node}/'
                                              f'stats']['nestedStats']['entries'])
        return {
            'name': node,
            'stats': node_stats
        }


''' HELPER FUNCTIONS '''


def login(server: str, port: str, username: str, password: str, verify_certificate: bool):
    response = requests.post(f'https://{server}:{port}/mgmt/shared/authn/login',
                             verify=verify_certificate,
                             json={'username': username, 'password': password,
                                   'loginProviderName': 'tmos'}).json()
    token = dict_safe_get(response, ['token', 'token'], '', str)
    if not token:
        raise DemistoException(f'Authorization Error: please check your credentials. \n\nError:\n{response}')

    return token


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    try:
        client.get_pools()
    except DemistoException as exception:
        if 'Authorization Required' in str(exception) or 'Authentication failed' in str(exception):
            return_error(f'Authorization Error: please check your credentials.\n\nError:\n{exception}')

        if 'HTTPSConnectionPool' in str(exception):
            return_error(f'Connection Error: please check your server ip address.\n\nError: {exception}')
        raise
    return 'ok'


def ltm_get_pools_command(client, args) -> CommandResults:
    expand_collection = args.get('expand')
    partition = args.get('partition')
    results = client.get_pools(expand_collection=expand_collection, partition=partition)

    return CommandResults(
        outputs_prefix='F5.LTM.Pools',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_pool_command(client, args) -> CommandResults:
    pool = args.get('pool_name')
    partition = args.get('partition')
    results = client.get_pool(pool=pool, partition=partition)

    return CommandResults(
        outputs_prefix='F5.LTM.Pools',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_nodes_command(client, args) -> CommandResults:
    partition = args.get('partition')
    results = client.get_nodes(partition)

    return CommandResults(
        outputs_prefix='F5.LTM.Nodes',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_node_command(client, args) -> CommandResults:
    node = args.get('node_name')
    partition = args.get('partition')
    results = client.get_node(node=node, partition=partition)

    return CommandResults(
        outputs_prefix='F5.LTM.Nodes',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_pool_members_command(client, args) -> CommandResults:
    pool = args.get('pool_name')
    partition = args.get('partition')
    results = client.get_pool_members(pool=pool, partition=partition)
    readable_output = tableToMarkdown('Pool Members:', {
        'name': results.get('name'),
        'members': [member['name'] for member in results.get('members')]
    })

    return CommandResults(
        outputs_prefix='F5.LTM.Pools',
        outputs_key_field='name',
        outputs=results,
        readable_output=readable_output
    )


def ltm_disable_node_command(client, args) -> CommandResults:
    node = args.get('node_name')
    partition = args.get('partition')
    results = client.disable_node(node=node, partition=partition)

    return CommandResults(
        outputs_prefix='F5.LTM.Nodes',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_enable_node_command(client, args) -> CommandResults:
    node = args.get('node_name')
    partition = args.get('partition')
    results = client.enable_node(node=node, partition=partition)

    return CommandResults(
        outputs_prefix='F5.LTM.Nodes',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_pool_member_stats_command(client, args) -> CommandResults:
    pool = args.get('pool_name')
    member = args.get('member_name')
    partition = args.get('partition')
    results = client.get_pool_member_stats(pool=pool, member=member, partition=partition)
    readable_output = tableToMarkdown('Pool Member Stats:', {
        'pool': results.get('pool'),
        'member': [member.get('name') for member in results.get('members')],
        'curConns': [member.get('stats')['serverside.curConns']['value'] for member in results.get('members')]
    })

    return CommandResults(
        outputs_prefix='F5.LTM.Stats',
        outputs_key_field='name',
        outputs=results,
        readable_output=readable_output
    )


def ltm_get_node_stats_command(client, args) -> CommandResults:
    node = args.get('node_name')
    partition = args.get('partition')
    results = client.get_node_stats(node=node, partition=partition)
    readable_output = tableToMarkdown('Node Stats:', {
        'node': results.get('name'),
        'curConns': results.get('stats')['serverside.curConns']['value']
    })
    return CommandResults(
        outputs_prefix='F5.LTM.Nodes',
        outputs_key_field='name',
        outputs=results,
        readable_output=readable_output
    )


def ltm_get_node_by_address_command(client, args):
    partition = args.get('partition')
    ip_address = args.get('ip_address')
    results = client.get_nodes(partition=partition)
    for item in results:
        if item.get('address') == ip_address:
            node = item
            return CommandResults(
                outputs_prefix='F5.LTM.Nodes',
                outputs_key_field='name',
                outputs=node,
            )
    return_error(f'No nodes found matching the address: {ip_address}')
    return None


def ltm_get_pools_by_node_command(client, args) -> CommandResults:
    node = args.get('node_name')
    pools = []
    partition = args.get('partition')
    results = client.get_pools(expand_collection='true', partition=partition)
    for item in results:
        for subitem in item.get('members'):
            if subitem.get('name').split(':')[0] == node:
                pools.append(item.get('name'))
                break
    node_mapping = {
        "name": node,
        "pools": pools
    }
    return CommandResults(
        outputs_prefix='F5.LTM.Nodes',
        outputs_key_field='name',
        outputs=node_mapping,
    )


''' MAIN FUNCTION '''


def main() -> None:
    args = demisto.args()
    params = demisto.params()
    server = params.get('server')
    port = params.get('port', '443')
    verify_certificate = not params.get('insecure', False)
    proxy = not params.get('insecure', False)
    partition = params.get('partition')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    base_url = f'https://{server}:{port}/mgmt/tm/'

    handle_proxy()

    token = login(server, port, username, password, verify_certificate)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            token=token,
            partition=partition,
            use_ssl=verify_certificate,
            use_proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'f5-ltm-get-pools':
            return_results(ltm_get_pools_command(client, args))

        elif demisto.command() == 'f5-ltm-get-pool':
            return_results(ltm_get_pool_command(client, args))

        elif demisto.command() == 'f5-ltm-get-pool-members':
            return_results(ltm_get_pool_members_command(client, args))

        elif demisto.command() == 'f5-ltm-get-nodes':
            return_results(ltm_get_nodes_command(client, args))

        elif demisto.command() == 'f5-ltm-get-node':
            return_results(ltm_get_node_command(client, args))

        elif demisto.command() == 'f5-ltm-disable-node':
            return_results(ltm_disable_node_command(client, args))

        elif demisto.command() == 'f5-ltm-enable-node':
            return_results(ltm_enable_node_command(client, args))

        elif demisto.command() == 'f5-ltm-get-pool-member-stats':
            return_results(ltm_get_pool_member_stats_command(client, args))

        elif demisto.command() == 'f5-ltm-get-node-stats':
            return_results(ltm_get_node_stats_command(client, args))

        elif demisto.command() == 'f5-ltm-get-node-by-address':
            return_results(ltm_get_node_by_address_command(client, args))

        elif demisto.command() == 'f5-ltm-get-pool-by-node':
            return_results(ltm_get_pools_by_node_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
