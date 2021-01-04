"""TOPdesk integration for Cortex XSOAR"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
from typing import Any, Dict, List, Optional
from base64 import b64encode

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INTEGRATION_NAME = 'TOPdesk'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the TOPdesk service API"""

    def get_users(self, users_type: str, start: Optional[int] = None, page_size: Optional[int] = None,
                    query: Optional[str] = None) -> Dict[str, Any]:
        """Get users using the '/persons' or '/operators' API endpoint"""

        if users_type not in ["persons", "operators"]:
            raise ValueError(f"Cannot get users of type {users_type}.\n "
                             f"Only persons or operators are allowed.")

        request_params: Dict[str, Any] = {}
        if start:
            request_params["start"] = start
        if page_size:
            request_params["page_size"] = page_size
        if query:
            request_params["query"] = query

        return self._http_request(
            method='GET',
            url_suffix=f"/{users_type}",
            json_data=request_params
        )


''' COMMAND FUNCTIONS '''


def list_persons_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get customers list from TOPdesk"""

    persons = client.get_userss(users_type="persons",
                                start=args.get('start', None),
                                page_size=args.get('page_size', None),
                                query=args.get('query', None))
    if len(persons) == 0:
        return CommandResults(readable_output='No persons found')

    readable_output = tableToMarkdown('id', persons)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.person',
        outputs_key_field='id',
        outputs=persons
    )


def list_operators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get operators list from TOPdesk"""

    operators = client.get_users(users_type="operators",
                                 start=args.get('start', None),
                                 page_size=args.get('page_size', None),
                                 query=args.get('query', None))
    if len(operators) == 0:
        return CommandResults(readable_output='No operators found')

    readable_output = tableToMarkdown('id', operators)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.operator',
        outputs_key_field='id',
        outputs=operators
    )


def test_module(client: Client) -> str:
    """Test API connectivity and authentication."""
    try:
        client.get_users(users_type="persons")
    except DemistoException as e:
        if 'Error 401' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions."""

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        encoded_credentials = b64encode(bytes(f"{demisto.params().get('username')}:{demisto.params().get('password')}",
                                              encoding='ascii')).decode('ascii')

        headers = {
            'Authorization': f'Basic {encoded_credentials}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'topdesk-persons-list':
            return_results(list_persons_command(client, demisto.args()))

        elif demisto.command() == 'topdesk-operators-list':
            return_results(list_operators_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()