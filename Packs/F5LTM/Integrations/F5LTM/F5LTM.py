
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any


requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, token: str, partition: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Content-Type': 'application/json',
                        'X-F5-Auth-Token': token}
        self.partition = partition

    def get_pools(self):

        url_suffix = 'ltm/pool'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})

        return response.get('items')

    def get_pool(self, pool):
        url_suffix = f'ltm/pool/~{self.partition}~{pool}'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        return response

    def get_pool_members(self, pool):
        url_suffix = f'ltm/pool/~{self.partition}~{pool}/members'
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params={})
        return {
            'name': pool,
            'members': response.get('items')
        }


''' HELPER FUNCTIONS '''


def login(server: str, port: str, username: str, password: str, verify_certificate: bool) -> str:

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


def ltm_get_pools_command(client) -> CommandResults:
    results = client.get_pools()

    return CommandResults(
        outputs_prefix='F5.LTM.Pools',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_pool_command(client, args) -> CommandResults:
    pool = args.get('pool')
    results = client.get_pool(pool)

    return CommandResults(
        outputs_prefix='F5.LTM.Pools',
        outputs_key_field='name',
        outputs=results,
    )


def ltm_get_pool_members_command(client, args) -> CommandResults:
    pool = args.get('pool')
    results = client.get_pool_members(pool)

    return CommandResults(
        outputs_prefix='F5.LTM.Pools',
        outputs_key_field='name',
        outputs=results,
    )


''' MAIN FUNCTION '''


def main() -> None:
    args = demisto.args()
    server = demisto.params()['server']
    port = demisto.params().get('port', '443')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = not demisto.params().get('insecure', False)
    partition = demisto.params().get('partition')
    username = demisto.params().get('credentials', {}).get('identifier')
    password = demisto.params().get('credentials', {}).get('password')

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
            return_results(ltm_get_pools_command(client))

        elif demisto.command() == 'f5-ltm-get-pool':
            return_results(ltm_get_pool_command(client, args))

        elif demisto.command() == 'f5-ltm-get-pool-members':
            return_results(ltm_get_pool_members_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
