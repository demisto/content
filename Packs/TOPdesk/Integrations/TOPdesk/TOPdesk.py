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

    def get_list(self, endpoint: str):
        """Get entry types using the API endpoint"""

        return self._http_request(
            method='GET',
            url_suffix=f"{endpoint}",
        )


''' HELPER FUNCTIONS '''


def command_with_all_fields_readable_list(results, result_name, output_prefix, outputs_key_field='id') -> CommandResults:
    """Get entry types list from TOPdesk"""

    if len(results) == 0:
        return CommandResults(readable_output=f'No {result_name} found')

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} {result_name}', results)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.{output_prefix}',
        outputs_key_field=outputs_key_field,
        outputs=results
    )


''' COMMAND FUNCTIONS '''


def list_persons_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get persons list from TOPdesk"""

    persons = client.get_users(users_type="persons",
                               start=args.get('start', None),
                               page_size=args.get('page_size', None),
                               query=args.get('query', None))
    if len(persons) == 0:
        return CommandResults(readable_output='No persons found')

    headers = ['id', 'dynamicName', 'phoneNumber', 'mobileNumber', 'fax', 'email',
               'jobTitle', 'department', 'city', 'departmentFree', 'branch', 'location',
               'tasLoginName', 'status', 'clientReferenceNumber']

    readable_persons = []
    for person in persons:
        readable_persons.append({
            'id': person.get('id'),
            'dynamicName': person.get('dynamicName'),
            'phoneNumber': person.get('phoneNumber'),
            'mobileNumber': person.get('mobileNumber'),
            'fax': person.get('fax'),
            'email': person.get('email'),
            'jobTitle': person.get('jobTitle'),
            'department': person.get('department'),
            'city': person.get('city'),
            'departmentFree': person.get('departmentFree'),
            'branch': person.get('branch'),
            'location': person.get('location'),
            'tasLoginName': person.get('tasLoginName'),
            'status': person.get('status'),
            'clientReferenceNumber': person.get('clientReferenceNumber')
        })

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} persons', readable_persons, headers=headers)

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

    headers = ['id', 'dynamicName', 'phoneNumber', 'mobileNumber', 'fax', 'email',
               'jobTitle', 'department', 'city', 'departmentFree', 'branch', 'location',
               'tasLoginName', 'status', 'clientReferenceNumber']

    readable_operators = []
    for operator in operators:
        readable_operators.append({
            'id': operator.get('id'),
            'dynamicName': operator.get('dynamicName'),
            'phoneNumber': operator.get('phoneNumber'),
            'mobileNumber': operator.get('mobileNumber'),
            'fax': operator.get('fax'),
            'email': operator.get('email'),
            'jobTitle': operator.get('jobTitle'),
            'department': operator.get('department'),
            'city': operator.get('city'),
            'departmentFree': operator.get('departmentFree'),
            'branch': operator.get('branch'),
            'location': operator.get('location'),
            'tasLoginName': operator.get('tasLoginName'),
            'status': operator.get('status'),
            'clientReferenceNumber': operator.get('clientReferenceNumber')
        })

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} operators', readable_operators, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.operator',
        outputs_key_field='id',
        outputs=operators
    )


def entry_types_command(client: Client) -> CommandResults:
    """Get entry types list from TOPdesk"""
    entry_types = client.get_list('/incidents/entry_types')
    return command_with_all_fields_readable_list(results=entry_types,
                                                 result_name='entry types',
                                                 output_prefix='entryType',
                                                 outputs_key_field='id')


def call_types_command(client: Client) -> CommandResults:
    """Get call types list from TOPdesk"""
    call_types = client.get_list("/incidents/call_types")
    return command_with_all_fields_readable_list(results=call_types,
                                                 result_name='call types',
                                                 output_prefix='callType',
                                                 outputs_key_field='id')


def categories_command(client: Client) -> CommandResults:
    """Get categories list from TOPdesk"""
    categories = client.get_list("/incidents/categories")
    return command_with_all_fields_readable_list(results=categories,
                                                 result_name='categories',
                                                 output_prefix='category',
                                                 outputs_key_field='id')


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

        elif demisto.command() == 'topdesk-entry-types-list':
            return_results(entry_types_command(client))

        elif demisto.command() == 'topdesk-call-types-list':
            return_results(call_types_command(client))

        elif demisto.command() == 'topdesk-categories-list':
            return_results(categories_command(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()