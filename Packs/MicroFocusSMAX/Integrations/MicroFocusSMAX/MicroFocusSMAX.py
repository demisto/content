
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, token: object, tenant_id: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Cookie': f'SMAX_AUTH_TOKEN={token}'}
        self.tenant_id = tenant_id

    def get_entity(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}


    def query_entities(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}


''' HELPER FUNCTIONS '''


def login(server: str, tenant:  str, username: str, password: str, verify_certificate: bool):
    response = requests.post(f'https://{server}/auth/authentication-endpoint/authenticate/token??TENANTID={tenant}',
                             verify=verify_certificate,
                             json={'Login': username, 'Password': password})
    token = response.text
    if not token:
        raise DemistoException(f'Authorization Error: please check your credentials. \n\nError:\n{response}')
    return token


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    try:
        client.baseintegration_dummy(dummy=client._headers)
    except DemistoException as exception:
        if 'Authorization Required' in str(exception) or 'Authentication failed' in str(exception):
            return_error(f'Authorization Error: please check your credentials.\n\nError:\n{exception}')

        if 'HTTPSConnectionPool' in str(exception):
            return_error(f'Connection Error: please check your server ip address.\n\nError: {exception}')
        raise
    return 'ok'


def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    args = demisto.args()
    params = demisto.params()
    base_url = params.get('url')
    tenant_id = params.get('tenant_id')
    verify_certificate = not params.get('insecure', False)
    proxy = not params.get('insecure', False)
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    handle_proxy()

    token = login(base_url, tenant_id, username, password, verify_certificate)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            token=token,
            tenant_id=tenant_id,
            use_ssl=verify_certificate,
            use_proxy=proxy
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
