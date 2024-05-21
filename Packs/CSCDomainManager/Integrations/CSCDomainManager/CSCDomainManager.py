import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

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

def csc_domains_list_command(client: Client):
    return



def csc_domains_availability_check_command(client: Client):
    return


def csc_domains_configuration_list_command(client: Client):
    return
        
        
def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    
    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

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
        
        elif demisto.command() == 'csc-domains-list':
            result = csc_domains_list_command(client)
            return_results(result)
        
        elif demisto.command() == 'csc-domains-availability-check':
            result = csc_domains_availability_check_command(client)
            return_results(result)
        
        elif demisto.command() == 'csc-domains-configuration-list':
            result = csc_domains_configuration_list_command(client)
            return_results(result)


    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
