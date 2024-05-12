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

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class to interact with the Thales CipherTrust API """

    def __init__(self, username: str, password: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        res = self._create_auth_token(username, password)
        self._headers = {'Authorization': f'Bearer {res.get("jwt")}', 'accept': 'application/json'}

    def _create_auth_token(self, username, password):  # todo: before each request to make sure isn't expired?
        return self._http_request(
            method='POST',
            url_suffix='/auth/tokens',
            json_data={
                'grant_type': 'password',
                'username': username,
                'password': password
            }
        )


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """Tests connectivity with the client.
    Takes as an argument all client arguments to create a new client
    """


''' MAIN FUNCTION '''


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get('server_url')
    base_url = urljoin(server_url, '/api/v1')

    username = params.get('credentials', {}).get('username')
    password = params.get('credentials', {}).get('password')

    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    try:
        client = Client(
            username=username,
            password=password,
            base_url=base_url,
            verify=verify,
            proxy=proxy)

        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            return_results(test_module(client))


    except Exception as e:
        msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
        demisto.error(traceback.format_exc())
        return_error(message=msg, error=e)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
