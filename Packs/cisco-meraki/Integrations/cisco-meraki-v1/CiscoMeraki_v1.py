import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Updated Integration to work with Cisco Meraki API v1 Integration for Cortex XSOAR (aka Demisto)

Cisco Documentation: https://developer.cisco.com/meraki/api-v1/

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

America: https://api.meraki.com
Canada: https://api.meraki.ca
China: https://api.meraki.cn
India: https://api.meraki.in
United States FedRamp: https://api.gov-meraki.com

"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
import meraki

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''
BRAND = 'CiscoMeraki-v1'
INTEGRATION_NAME = 'CiscoMeraki'

PARAMS = demisto.params()
USE_SSL = not PARAMS.get('insecure', False)

PROXY = demisto.params().get('proxy')
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# print(PARAMS)

BASE_URI = PARAMS['uri']
# print(BASE_URI)
BASE_URL = f'{BASE_URI}/api/v1'
# print(BASE_URL)

API_KEY = PARAMS['credentials']['password']
# print(API_KEY)

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
        
    dashboard = meraki.DashboardAPI(API_KEY, base_url=BASE_URL, output_log=False, print_console=False, suppress_logging=True)

''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


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

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def get_organizations_command(client: Client) -> CommandResults:

    result = client.dashboard.organizations.getOrganizations()

    return CommandResults(
        outputs_prefix=INTEGRATION_NAME,
        outputs_key_field='id',
        outputs=result,
    )

def get_networks_command(client: Client, orgID: str) -> CommandResults:
        
    result = client.dashboard.organizations.getOrganizationNetworks(orgID)

    return CommandResults(
        outputs_prefix=INTEGRATION_NAME,
        outputs_key_field='id',
        outputs=result,
    )

def get_devices_command(client: Client, orgID: str) -> CommandResults:
        
    result = client.dashboard.organizations.getOrganizationDevices(orgID)

    return CommandResults(
        outputs_prefix=INTEGRATION_NAME,
        outputs_key_field='id',
        outputs=result,
    )

def get_action_batches_command(client: Client, orgID: str) -> CommandResults:
        
    result = client.dashboard.organizations.getOrganizationActionBatches(orgID)

    return CommandResults(
        outputs_prefix=INTEGRATION_NAME,
        outputs_key_field='id',
        outputs=result,
    )

def get_action_batch_command(client: Client, orgID: str, actionID: str) -> CommandResults:
        
    result = client.dashboard.organizations.getOrganizationActionBatch(organizationId=orgID, actionBatchId=actionID)

    return CommandResults(
        outputs_prefix=INTEGRATION_NAME,
        outputs_key_field='id',
        outputs=result,
    )

def get_action_batch_command(client: Client, orgID: str) -> CommandResults:
        
    result = client.dashboard.organizations.createOrganizationActionBatch()

    return CommandResults(
        outputs_prefix=INTEGRATION_NAME,
        outputs_key_field='id',
        outputs=result,
    )





''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {API_KEY}'
        }
        
        client = Client(
            base_url=BASE_URL,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'get-organizations':
            return_results(get_organizations_command(client))            
        elif demisto.command() == 'get-networks':
            return_results(get_networks_command(client, **demisto.args()))
        elif demisto.command() == 'get-devices':
            return_results(get_devices_command(client, **demisto.args()))
        elif demisto.command() == 'get-action-batches':
            return_results(get_action_batches_command(client, **demisto.args()))
        elif demisto.command() == 'get-action-batch':
            return_results(get_action_batch_command(client, **demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        ...
        # return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
