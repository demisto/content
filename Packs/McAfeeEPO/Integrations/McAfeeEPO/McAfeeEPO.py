
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

EPO_SYSTEM_ATTRIBUTE_MAP = {
    'EPOComputerProperties.ComputerName': 'Name',
    'EPOComputerProperties.DomainName': 'Domain',
    'EPOComputerProperties.IPHostName': 'Hostname',
    'EPOComputerProperties.IPAddress': 'IPAddress',
    'EPOComputerProperties.OSType': 'OS',
    'EPOComputerProperties.OSVersion': 'OSVersion',
    'EPOComputerProperties.CPUType': 'Processor',
    'EPOComputerProperties.NumOfCPU': 'Processors',
    'EPOComputerProperties.TotalPhysicalMemory': 'Memory',
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API

    def epo_help(self, dummy: str) -> Dict[str, str]:

        return {"dummy": dummy}

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


def epo_help_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='McAfeeEPO',
        outputs_key_field='',
        outputs=result,
    )

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/remote')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement
        elif demisto.command() == 'epo-help':
            return_results(epo_help_command(client, demisto.args()))
        elif demisto.command() == 'epo-get-latest-dat':
            return_results(epo_get_latest_dat_command(client, demisto.args()))
        elif demisto.command() == 'epo-get-current-dat':
            return_results(epo_get_current_dat_command(client, demisto.args()))
        elif demisto.command() == 'epo-update-client-dat':
            return_results(epo_update_client_dat_command(client, demisto.args()))
        elif demisto.command() == 'epo-update-repository':
            return_results(epo_update_repository_command(client, demisto.args()))
        elif demisto.command() == 'epo-get-system-tree-group':
            return_results(epo_get_system_tree_group_command(client, demisto.args()))
        elif demisto.command() == 'epo-find-systems':
            return_results(epo_find_systems_command(client, demisto.args()))
        elif demisto.command() == 'epo-wakeup-agent':
            return_results(epo_wakeup_agent_command(client, demisto.args()))
        elif demisto.command() == 'epo-apply-tag':
            return_results(epo_apply_tag_command(client, demisto.args()))
        elif demisto.command() == 'epo-clear-tag':
            return_results(epo_clear_tag_command(client, demisto.args()))
        elif demisto.command() == 'epo-get-tables':
            return_results(epo-get-tables_command(client, demisto.args()))
        elif demisto.command() == 'epo-query-table':
            return_results(epo_query_table_command(client, demisto.args()))
        elif demisto.command() == 'epo-get-version':
            return_results(epo_get_version_command(client, demisto.args()))
        elif demisto.command() == 'epo-move-system':
            return_results(epo_move_system_command(client, demisto.args()))
        elif demisto.command() == 'epo-command':
            return_results(epo_command_command(client, demisto.args()))
        elif demisto.command() == 'epo-advanced-command':
            return_results(epo_advanced_command_command(client, demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
