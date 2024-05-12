from demisto_sdk.commands.generate_yml_from_python.yml_metadata_collector import (CommandMetadata, ConfKey, InputArgument,
                                                                                  YMLMetadataCollector, OutputArgument,
                                                                                  ParameterTypes)
from CommonServerPython import BaseClient, CommandResults, datetime

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
BASE_URL_SUFFIX = '/api/v1'
AUTHENTICATION_URL_SUFFIX = '/auth/tokens'
USER_MANAGEMENT_GROUPS_URL_SUFFIX = '/usermgmt/groups/'
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 2000
DEFAULT_LIMIT = 50
'''CLIENT CLASS'''


def handle_pagination(limit, page, page_size=DEFAULT_PAGE_SIZE):
    if page:
        if page_size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return {
            'skip': (page - 1) * page_size,
            'limit': page_size
        }
    elif limit:
        return {
            'skip': 0,
            'limit': limit
        }
    else:
        return {
            'skip': 0,
            'limit': DEFAULT_LIMIT
        }


class CipherTrustClient(BaseClient):
    """ A client class to interact with the Thales CipherTrust API """

    def __init__(self, username: str, password: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        res = self._create_auth_token(username, password)
        self._headers = {'Authorization': f'Bearer {res.get("jwt")}', 'accept': 'application/json'}

    def _create_auth_token(self, username, password):  # todo: before each request to make sure isn't expired?
        return self._http_request(
            method='POST',
            url_suffix=AUTHENTICATION_URL_SUFFIX,
            json_data={
                'grant_type': 'password',
                'username': username,
                'password': password
            }
        )

    def get_groups_list(self, params: dict):
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            params=params
        )


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: CipherTrustClient):
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """
    pass


def groups_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    pass


''' MAIN FUNCTION '''


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get('server_url')
    base_url = urljoin(server_url, BASE_URL_SUFFIX)

    username = params.get('credentials', {}).get('username')
    password = params.get('credentials', {}).get('password')

    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        client = CipherTrustClient(
            username=username,
            password=password,
            base_url=base_url,
            verify=verify,
            proxy=proxy)

        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            return_results(test_module(client))
        if command == 'ciphertrust-group-list':
            return_results(groups_list_command(client=client, args=args))


    except Exception as e:
        msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
        demisto.error(traceback.format_exc())
        return_error(message=msg, error=e)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
