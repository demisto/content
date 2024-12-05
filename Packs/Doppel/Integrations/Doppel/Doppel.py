import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Doppel for Cortex XSOAR (aka Demisto)

This integration contains features to mirror the alerts from Doppel to create incidents in XSOAR and 
the commands to perform different updates on the alerts

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
    
    def __init__(self, base_url, api_key, verify=True, proxy=False, ok_codes=..., auth=None, timeout=...):
        super().__init__(base_url, verify, proxy, ok_codes, auth, timeout)

        self._headers = dict()
        self._headers["accept"] = "application/json"
        self._headers["x-api-key"] = api_key


    def get_alert(self, id: str, entity: str) -> Dict[str, str]:
        """Return the alert's details when provided the Alert ID or Entity as input

        :type id: ``str``
        :param id: Alert id for which we need to fetch details
        
        :type entity: ``str``
        :param entity: Alert id for which we need to fetch details

        :return: dict as with alert's details
        :rtype: ``dict``
        """
        api_name: str = "alert"
        api_url = f"{self._base_url}/{api_name}?"
        if id:
            api_url = f"{api_url}id={id}"
        elif entity:
            api_url = f"{api_url}id={entity}"
        else:
            message: str = "Please provide id or entity as input"
            demisto.error(message)
            raise DemistoException(message)

        
        response_content = self._http_request(
            method="GET",
            full_url=api_url            
        )
        return response_content


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.password
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


def get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    id: str = args.get('id', None)
    entity: str = args.get('entity', None)
    if not id and not entity:
        raise ValueError('Neither id nor the entity is specified. We need exactly single input for this command')
    if id and entity:
        raise ValueError('Both id and entity is specified. We need exactly single input for this command')
    
    result = client.get_alert(id=id, entity=entity)

    return CommandResults(
        outputs_prefix='Doppel.Alert',
        outputs_key_field='id',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.params().get('credentials', {}).get('api_key')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/v1')

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
        client = Client(
            base_url=base_url,
            api_key=api_key)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'get-alert':
            return_results(get_alert_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
