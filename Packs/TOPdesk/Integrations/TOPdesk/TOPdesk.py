"""TOPdesk integration for Cortex XSOAR"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
from typing import Any, Dict, List, Optional
from dateutil.parser import parse
from base64 import b64encode

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INTEGRATION_NAME = 'TOPdesk'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the TOPdesk service API"""

    def get_list_with_query(self, list_type: str, start: Optional[int] = None, page_size: Optional[int] = None,
                            query: Optional[str] = None) -> Dict[str, Any]:
        """Get list of objects that support start, page_size and query arguments."""

        allowed_list_type = ["persons", "operators", "branches", "incidents"]
        if list_type not in allowed_list_type:
            raise ValueError(f"Cannot get list of type {list_type}.\n "
                             f"Only {allowed_list_type} are allowed.")

        request_params: Dict[str, Any] = {}
        if start:
            request_params["start"] = start
        if page_size:
            request_params["page_size"] = page_size
        if query:
            request_params["query"] = query

        return self._http_request(
            method='GET',
            url_suffix=f"/{list_type}",
            json_data=request_params
        )

    def get_list(self, endpoint: str) -> Dict[str, Any]:
        """Get entry types using the API endpoint"""

        return self._http_request(
            method='GET',
            url_suffix=f"{endpoint}",
        )


''' HELPER FUNCTIONS '''


def command_with_all_fields_readable_list(results: Dict[str, Any],
                                          result_name: str,
                                          output_prefix: str,
                                          outputs_key_field: str = 'id') -> CommandResults:
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

    persons = client.get_list_with_query(list_type="persons",
                                         start=args.get('start', None),
                                         page_size=args.get('page_size', None),
                                         query=args.get('query', None))
    if len(persons) == 0:
        return CommandResults(readable_output='No persons found')

    headers = ['id', 'Compound Name', 'Telephone', 'Job Title', 'Department', 'City',
               'Room']

    # Maybe import settings for this the overview setup ?

    readable_persons = []
    for person in persons:
        readable_person = {
            'id': person.get('id', None),
            'Compound Name': person.get('dynamicName', None),
            'Telephone': person.get('phoneNumber', None),
            'Job Title': person.get('jobTitle', None),
            'Department': person.get('department', None),
            'City': person.get('city', None),
            'Room': None
        }
        if person.get('location', None):
            readable_person['Room'] = person.get('location', None).get('room', None)
        readable_persons.append(readable_person)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} persons', readable_persons, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.person',
        outputs_key_field='id',
        outputs=persons
    )


def list_operators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get operators list from TOPdesk"""

    operators = client.get_list_with_query(list_type="operators",
                                           start=args.get('start', None),
                                           page_size=args.get('page_size', None),
                                           query=args.get('query', None))
    if len(operators) == 0:
        return CommandResults(readable_output='No operators found')

    headers = ['id', 'Compound Name', 'Telephone', 'Mobile Number', 'Job Title', 'Department',
               'City', 'Login Name']

    readable_operators = []
    for operator in operators:
        readable_operators.append({
            'id': operator.get('id', None),
            'Compound Name': operator.get('dynamicName', None),
            'Telephone': operator.get('phoneNumber', None),
            'Mobile Number': operator.get('mobileNumber', None),
            'Job Title': operator.get('jobTitle', None),
            'Department': operator.get('department', None),
            'City': operator.get('city', None),
            'Login Name': operator.get('tasLoginName', None),
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


def subcategories_command(client: Client) -> CommandResults:
    """Get categories list from TOPdesk"""
    subcategories = client.get_list("/incidents/subcategories")

    if len(subcategories) == 0:
        return CommandResults(readable_output=f'No subcategories found')

    subcategories_with_categories = []
    for subcategory in subcategories:
        subcategory_with_category = {"id": subcategory.get("id", None),
                                      "name": subcategory.get("name", None),
                                      "category id": None,
                                      "category name": None}
        if subcategory.get("category", None):
            subcategory_with_category["category id"] = subcategory.get("category", None).get("id", None)
            subcategory_with_category["category name"] = subcategory.get("category", None).get("name", None)

        subcategories_with_categories.append(subcategory_with_category)

    headers = ['id', 'name', 'category id', 'category name']
    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} subcategories',
                                      subcategories_with_categories,
                                      headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.subcategories',
        outputs_key_field='id',
        outputs=subcategories
    )


def branches_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get branches list from TOPdesk"""

    branches = client.get_list_with_query(list_type="branches",
                                          start=args.get('start', None),
                                          page_size=args.get('page_size', None),
                                          query=args.get('query', None))
    if len(branches) == 0:
        return CommandResults(readable_output='No persons found')

    headers = ['id', 'Status', 'Name', 'Specifications', 'Client Reference Number', 'Phone', 'Email',
               'Website', 'Branch Type', 'Head Branch id', 'Head Branch Name', 'Address', 'Postal Address',
               'Contact id', 'Contact Name', 'Account Manager id', 'Account Manager Name', 'Attention Comment',
               'Additional Info']

    readable_branches = []
    for branch in branches:
        readable_branch = {
            'id': branch.get('id', None),
            'Status': branch.get('status', None),
            'Name': branch.get('name', None),
            'Specifications': branch.get('specifications', None),
            'Client Reference Number': branch.get('clientReferenceNumber', None),
            'Phone': branch.get('phone', None),
            'Email': branch.get('email', None),
            'Website': branch.get('website', None),
            'Branch Type': branch.get('branchType', None),
            'Head Branch id': branch.get('headBranch', {}).get('id', None),
            'Head Branch Name': branch.get('headBranch', {}).get('name', None),
            'Address': branch.get('address', {}).get('addressMemo', None),
            'Postal Address': branch.get('postalAddress', {}).get('addressMemo', None),
            'Contact id': branch.get('contact', {}).get('id', None),
            'Contact Name': branch.get('contact', {}).get('name', None),
            'Account Manager id': branch.get('accountManager', {}).get('id', None),
            'Account Manager Name': branch.get('accountManager', {}).get('name', None),
            'Attention Comment': branch.get('attentionComment', None),
            'Additional Info': branch.get('additionalInfo', None)
        }
        readable_branches.append(readable_branch)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} branches', readable_branches, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.branch',
        outputs_key_field='id',
        outputs=branches
    )


def add_filter_to_query(query, filter_name, args):
    if args.get(filter_name, None):
        if query:
            query = f"{query}&"
        query = f"{query}{filter_name}=={args.get(filter_name, None)}"
    return query


def replace_none(value, replacement):
    if value:
        return value
    return replacement


def incidents_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get list of incidents from TOPdesk"""

    if args.get('incident_id', None) or args.get('incident_number', None):
        if args.get('incident_id', None):
            incidents = [client.get_list(f"/incidents/id/{args.get('incident_id', None)}")]

        elif args.get('incident_number', None):
            incidents = [client.get_list(f"/incidents/number/{args.get('incident_number', None)}")]
    else:

        allowed_statuses = [None, 'firstLine', 'secondLine', 'partial']
        if args.get('status', None) not in allowed_statuses:
            raise(ValueError(f"status {args.get('status', None)} id not in "
                             f"the allowed statuses list: {allowed_statuses}"))

        query = args.get('query', None)
        query = add_filter_to_query(query=query,
                                    filter_name="status",
                                    args=args)
        query = add_filter_to_query(query=query,
                                    filter_name="caller_id",
                                    args=args)
        query = add_filter_to_query(query=query,
                                    filter_name="branch_id",
                                    args=args)
        query = add_filter_to_query(query=query,
                                    filter_name="category",
                                    args=args)
        query = add_filter_to_query(query=query,
                                    filter_name="subcategory",
                                    args=args)
        query = add_filter_to_query(query=query,
                                    filter_name="call_type",
                                    args=args)
        query = add_filter_to_query(query=query,
                                    filter_name="entry_type",
                                    args=args)

        incidents = client.get_list_with_query(list_type="incidents",
                                               start=args.get('start', None),
                                               page_size=args.get('page_size', None),
                                               query=query)
    if len(incidents) == 0:
        return CommandResults(readable_output='No incidents found')

    headers = ['id', 'Request', 'Requests', 'Action', 'Attachments', 'Summary', 'Line', 'Progress',
               'Response Target Date', 'Responded', 'Response Date', 'Call Number', 'Caller Name',
               'Customer (Caller)', '\'Budget holder\'', 'Call Type', 'Status', 'Operator', 'Completed',
               'Closed', 'Target Date', 'Impact', 'Category', 'Subcategory', 'SLA Target Date',
               'Operator Group', '(De-)escalation Operator']

    readable_branches = []
    for incident in incidents:
        actions = client.get_list(f"/incidents/id/{incident.get('id', None)}/actions")
        readable_action = ""
        for action in actions:
            pretty_datetime = parse(action.get('entryDate', None)).strftime("%d-%m-%Y %H:%M")
            readable_action = f"{readable_action}\n\n {pretty_datetime}-" \
                              f"{action.get('operator', {}).get('name', None)}:\n{action.get('memoText', None)}"

        readable_branch = {
            'id': incident.get('id', None),
            'Request': incident.get('request', None),
            'Requests': incident.get('requests', None),
            'Action': readable_action,
            'Attachments': incident.get('attachments', None),
            'Line': incident.get('status', None),
            'Response Target Date': incident.get('specifications', None),
            'Responded': incident.get('responded', None),
            'Response Date': incident.get('responseDate', None),
            'Call Number': incident.get('number', None),  # not sure
            'Caller Name': replace_none(incident.get('caller', {}), {}).get('dynamicName', None),
            'Customer (Caller)': replace_none(replace_none(incident.get('caller', {}), {}).get('branch', {}), {}).get('name', None),
            'Call Type': replace_none(incident.get('callType', {}), {}).get('name', None),
            'Status': replace_none(incident.get('processingStatus', {}), {}).get('name', None),
            'Operator': incident.get('operator', None),
            'Completed': incident.get('completed', None),
            'Closed': incident.get('closed', None),
            'Target Date': incident.get('targetDate', None),
            'Impact': replace_none(incident.get('impact', {}), {}).get('name', None),
            'Category': replace_none(incident.get('category', {}), {}).get('name', None),
            'Subcategory': replace_none(incident.get('subcategory', {}), {}).get('name', None),
            'SLA Target Date': replace_none(incident.get('sla', {}), {}).get('targetDate', None),
            'Operator Group': replace_none(incident.get('subcategory', {}), {}).get('name', None),
            '(De-)escalation Operator': replace_none(incident.get('escalationOperator', {}), {}).get('name', None)
        }

        readable_branches.append(readable_branch)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} branches', readable_branches, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.incident',
        outputs_key_field='id',
        outputs=incidents
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

        elif demisto.command() == 'topdesk-entry-types-list':
            return_results(entry_types_command(client))

        elif demisto.command() == 'topdesk-call-types-list':
            return_results(call_types_command(client))

        elif demisto.command() == 'topdesk-categories-list':
            return_results(categories_command(client))

        elif demisto.command() == 'topdesk-subcategories-list':
            return_results(subcategories_command(client))

        elif demisto.command() == 'topdesk-branches-list':
            return_results(branches_command(client, demisto.args()))

        elif demisto.command() == 'topdesk-incidents-list':
            return_results(incidents_list_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()