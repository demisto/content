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
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import traceback
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
    def __init__(self, base_url, verify, proxy, headers=None, max_fetch=None):
        self.max_fetch = max_fetch        

        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def kmsat_account_info(self):
        return self._http_request(method='GET', url_suffix='/account', resp_type='json', ok_codes=(200,))
    
    def kmsat_account_risk_score_history(self):
        return self._http_request(method='GET', url_suffix='/account/risk_score_history', resp_type='json',  ok_codes=(200,))


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def get_account_info(client: Client) -> CommandResults:
    response = client.kmsat_account_info()
    return_results(response)
    if response is None:
        raise DemistoException('Translation failed: the response from server did not include `account_info`.', res=response)
    return CommandResults(outputs_prefix='KMSAT_Account_Info_Returned',
                          outputs_key_field='',
                          raw_response=response,
                          readable_output=tableToMarkdown(name='Account_Info', t=response))


def get_account_risk_score_history(client: Client) -> CommandResults:
    response = client.kmsat_account_risk_score_history()
    return_results(response)
    if response is None:
        raise DemistoException('Translation failed: the response from server did not include `risk_score`.', res=response)
    return CommandResults(outputs_prefix='KMSAT_Account_Risk_Score_History_Returned',
                          outputs_key_field='',
                          raw_response=response,
                          readable_output=tableToMarkdown(name='Account_Risk_Score_History', t=response))


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
        client.kmsat_account_info()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set' + str(client._headers)
        else:
            raise e
    return message





''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()    
    demisto.debug(f'Command being called is {command}')
    
    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/v1')

    # verify api key or creds are specified
    if not params.get('apikey') or not (key := params.get('apikey', {}).get('password')):
        raise DemistoException('Missing API Key. Fill in a valid key in the integration configuration.')
    
    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)
    
    try:

        headers: Dict = {
            'Authorization': 'Bearer ' + key,
            'Content-Type': 'application/json'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == 'get-account-info':
            return_results(get_account_info(client, **args))
        elif command == 'get-account-risk-score-history':
            return_results(get_account_risk_score_history(client, **args))            
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
