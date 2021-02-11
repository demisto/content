"""TOPdesk integration for Cortex XSOAR"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import shutil
import urllib3
import traceback
from typing import Any, Dict, List, Optional, Callable
from dateutil.parser import parse
from base64 import b64encode

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INTEGRATION_NAME = 'TOPdesk'
XSOAR_ENTRY_TYPE = 'Automation'  # XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the TOPdesk service API"""

    def get_list_with_query(self, list_type: str, start: Optional[int] = None, page_size: Optional[int] = None,
                            query: Optional[str] = None, modification_date_start: Optional[str] = None,
                            modification_date_end: Optional[str] = None) -> List[Dict[str, Any]]:
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
        if modification_date_start:
            request_params["modification_date_start"] = modification_date_start
        if modification_date_end:
            request_params["modification_date_end"] = modification_date_end

        return self._http_request(
            method='GET',
            url_suffix=f"/{list_type}",
            json_data=request_params
        )

    def get_list(self, endpoint: str) -> List[Dict[str, Any]]:
        """Get entry types using the API endpoint"""

        return self._http_request(
            method='GET',
            url_suffix=f"{endpoint}",
        )

    def create_incident(self, args: Dict[str, Any] = {}) -> Dict[str, Any]:
        """Create incident in TOPdesk"""

        request_params: Dict[str, Any] = {}
        if not args.get("caller", None):
            raise ValueError('Caller must be specified to create incident.')
        if args.get('registered_caller', False):
            request_params['callerLookup'] = {"id": args["caller"]}
        else:
            request_params['caller'] = {"dynamicName": args["caller"]}

        if args.get("entry_type", None):
            request_params["entryType"] = {"name": args["entry_type"]}
        else:
            request_params["entryType"] = {"name": XSOAR_ENTRY_TYPE}
        optional_params = ["status", "description", "request", "action", "action_invisible_for_caller",
                           "call_type", "category", "subcategory", "external_number", "main_incident"]
        if args:
            for optional_param in optional_params:
                if args.get(optional_param, None):
                    request_params[underscoreToCamelCase(optional_param)] = args.get(optional_param, None)

        if args.get("additional_params", None):
            request_params.update(args["additional_params"])

        return self._http_request(
            method='POST',
            url_suffix="/incidents/",
            json_data=request_params
        )

    def update_incident(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident in TOPdesk"""

        request_params: Dict[str, Any] = {}
        if not args.get("id", None) and not args.get("number", None):
            raise ValueError('Either id or number must be specified to update incident.')
        if args.get("id", None):
            endpoint = f"/incidents/id/{args['id']}"
        else:
            endpoint = f"/incidents/number/{args['number']}"

        if args.get("entry_type", None):
            request_params["entryType"] = {"name": args["entry_type"]}
        else:
            request_params["entryType"] = {"name": XSOAR_ENTRY_TYPE}

        optional_params = ["caller", "status", "description", "request", "action",
                           "action_invisible_for_caller", "call_type", "category", "subcategory",
                           "external_number", "main_incident"]
        optional_named_params = ["call_type", "category", "subcategory"]
        if args:
            for optional_param in optional_params:
                if args.get(optional_param, None):
                    if optional_param == "description":
                        request_params["briefDescription"] = args.get(optional_param, None)
                    if optional_param == "caller":
                        if args.get("registered_caller", False):
                            request_params["callerLookup"] = {"id": args[optional_param]}
                        else:
                            request_params["caller"] = {"dynamicName": args[optional_param]}
                    elif optional_param in optional_named_params:
                        request_params[underscoreToCamelCase(optional_param)] = {"name": args[optional_param]}
                    else:
                        request_params[underscoreToCamelCase(optional_param)] = args.get(optional_param, None)

        if args.get("additional_params", None):
            request_params.update(args["additional_params"])

        return self._http_request(
            method='PATCH',
            url_suffix=endpoint,
            json_data=request_params
        )

    def incident_do(self, action: str,
                    incident_id: Optional[str],
                    incident_number: Optional[str]) -> Dict[str, Any]:
        """ """
        allowed_actions = ["escalate", "deescalate", "archive", "unarchive"]
        request_params: Dict[str, Any] = {}
        if action not in allowed_actions:
            raise ValueError(f'Endpoint {action} not in allowed endpoint list: {allowed_actions}')
        if not incident_id and not incident_number:
            raise ValueError('Either id or number must be specified to update incident.')
        if incident_id:
            endpoint = f"/incidents/id/{incident_id}"
            request_params["id"] = incident_id
        else:
            endpoint = f"/incidents/number/{incident_number}"
            request_params["number"] = incident_number

        return self._http_request(
            method='PATCH',
            url_suffix=f"{endpoint}/{action}",
            json_data=request_params
        )

    def attachment_upload(self,
                          incident_id: Optional[str],
                          incident_number: Optional[str],
                          file_entry: str,
                          file_name: str,
                          invisible_for_caller: bool,
                          file_description: str):
        """ """
        if not incident_id and not incident_number:
            raise ValueError('Either id or number must be specified to update incident.')
        if incident_id:
            endpoint = f"/incidents/id/{incident_id}"
        else:
            endpoint = f"/incidents/number/{incident_number}"
        request_params: Dict[str, Any] = {}
        if isinstance(invisible_for_caller, bool):
            request_params["invisibleForCaller"] = invisible_for_caller
        else:
            raise ValueError('invisibleForCaller must be either ture or false')
        if file_description:
            request_params["description"] = file_description

        shutil.copy(demisto.getFilePath(file_entry)['path'], file_name)
        files = {'file': open(file_name, 'rb')}
        response = self._http_request(method='POST',
                                      url_suffix=f"{endpoint}/attachments",
                                      files=files,
                                      json_data=request_params)
        shutil.rmtree(file_name)
        return response


''' HELPER FUNCTIONS '''


def command_with_all_fields_readable_list(results: List[Dict[str, Any]],
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
        return CommandResults(readable_output='No subcategories found')

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


def add_filter_to_query(query: str, filter_name: str, args: Dict[str, Any]) -> str:
    if args.get(filter_name, None):
        if query:
            query = f"{query}&"
        query = f"{query}{filter_name}=={args.get(filter_name, None)}"
    return query


def replace_none(value: Any, replacement: Any) -> Any:
    if value:
        return value
    return replacement


def get_incidents_list(client: Client,
                       args: Dict[str, Any],
                       demisto_params: Dict[str, Any],
                       is_fetch: bool = False) -> List[Dict[str, Any]]:
    if args.get('incident_id', None) or args.get('incident_number', None):
        if args.get('incident_id', None):
            incidents = client.get_list(f"/incidents/id/{args.get('incident_id', None)}")

        elif args.get('incident_number', None):
            incidents = client.get_list(f"/incidents/number/{args.get('incident_number', None)}")
    else:

        allowed_statuses = [None, 'firstLine', 'secondLine', 'partial']
        if args.get('status', None) not in allowed_statuses:
            raise(ValueError(f"status {args.get('status', None)} id not in "
                             f"the allowed statuses list: {allowed_statuses}"))

        query = args.get('query', None)
        filter_arguments = ["status", "caller_id", "branch_id", "category", "subcategory",
                            "call_type", "entry_type"]
        for filter_arg in filter_arguments:
            query = add_filter_to_query(query=query,
                                        filter_name=filter_arg,
                                        args=args)

        if args.get('max_fetch', 10) > 10000:
            # implement pagination properly
            pass
        else:
            page_size = max(args.get('page_size', 0), args.get('max_fetch', 0))
            if page_size == 0:
                page_size = None
            if is_fetch:
                modification_date_start = demisto_params.get('modification_date_start', None)
                modification_date_end = demisto_params.get('modification_date_end', None)
            else:
                modification_date_start = None
                modification_date_end = None
            incidents = client.get_list_with_query(list_type="incidents",
                                                   start=args.get('start', None),
                                                   page_size=page_size,
                                                   query=query,
                                                   modification_date_start=modification_date_start,
                                                   modification_date_end=modification_date_end)

    return incidents


def incidents_to_command_results(client: Client, incidents: List[Dict[str, Any]]) -> CommandResults:
    """Receive Incidents from api and convert to CommandResults"""
    if len(incidents) == 0:
        return CommandResults(readable_output='No incidents found')

    headers = ['id', 'Request', 'Requests', 'Action', 'Attachments', 'Summary', 'Line', 'Progress',
               'Response Target Date', 'Responded', 'Response Date', 'Call Number', 'Caller Name',
               'Customer (Caller)', '\'Budget holder\'', 'Call Type', 'Status', 'Operator', 'Completed',
               'Closed', 'Target Date', 'Impact', 'Category', 'Subcategory', 'SLA Target Date',
               'Operator Group', '(De-)escalation Operator']

    readable_incidents = []
    for incident in incidents:
        try:
            actions = client.get_list(f"/incidents/id/{incident.get('id', None)}/actions")
        except DemistoException as e:
            if "Failed to parse json object from response: b''" in str(e):
                actions = []
            else:
                raise e

        readable_action = ""
        for action in actions:
            pretty_datetime = parse(action.get('entryDate', None)).strftime("%d-%m-%Y %H:%M")
            readable_action = f"{readable_action}\n\n {pretty_datetime}-" \
                              f"{action.get('operator', {}).get('name', None)}:\n{action.get('memoText', None)}"

        readable_incident = {
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
            'Customer (Caller)': replace_none(replace_none(incident.get('caller',
                                                                        {}), {}).get('branch',
                                                                                     {}), {}).get('name', None),
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

        readable_incidents.append(readable_incident)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} incidents', readable_incidents, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.incident',
        outputs_key_field='id',
        outputs=incidents
    )


def incident_func_command(client: Client, args: Dict[str, Any], client_func: Callable, action: str) -> CommandResults:
    """Abstract class for executing client_func and returning TOPdesk incident as a result."""
    response = client_func(args)

    if not response.get('incident', None) and not response.get('id', None):
        raise Exception(f"Recieved Error when {action} incident in TOPdesk:\n{response}")

    incident = response.get('incident', response)
    return incidents_to_command_results(client, [incident])


def attachment_upload_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Upload attachment to certain incident in TOPdesk"""
    file_entry = args.get('file_entry', None)
    if not file_entry:
        raise Exception("Found no file entry.")

    file_name = demisto.dt(demisto.context(), "File(val.EntryID=='" + file_entry + "').Name")
    if not file_name:  # in case of info file
        file_name = demisto.dt(demisto.context(), "InfoFile(val.EntryID=='" + file_entry + "').Name")
    if not file_name:
        raise ValueError(f"Could not fine file in entry with entry_id: {file_entry}")
    file_name = file_name[0] if isinstance(file_name, list) else file_name  # If few files

    response = client.attachment_upload(incident_id=args.get('incident_id', None),
                                        incident_number=args.get('incident_number', None),
                                        file_entry=file_entry,
                                        file_name=file_name,
                                        invisible_for_caller=args.get('invisibleForCaller', None),
                                        file_description=args.get('file_description', None))

    if not response.get("attachment", None):
        raise Exception(f"Failed uploading file: {response}")

    headers = ['id', 'fileName', 'downloadUrl', 'size', 'description',
               'invisibleForCaller', 'entryDate', 'operator']
    readable_attachment = [{
        'id': response["attachment"].get('id', None),
        'fileName': response["attachment"].get('fileName', None),
        'downloadUrl': response["attachment"].get('downloadUrl', None),
        'size': response["attachment"].get('size', None),
        'description': response["attachment"].get('description', None),
        'invisibleForCaller': response["attachment"].get('invisibleForCaller', None),
        'entryDate': response["attachment"].get('entryDate', None),
        'operator': response["attachment"].get('operator', None),
    }]

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} operators', readable_attachment, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.incident',
        outputs_key_field='id',  # Not sure this will update the right path. Needs checking.
        outputs=response["attachment"]
    )


def fetch_incidents(client: Client, args: Dict[str, Any], demisto_params: Dict[str, Any]) -> None:
    """Fetches incidents from TOPdesk."""

    first_fetch_datetime = arg_to_datetime(
        arg=demisto_params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', None)
    if not last_fetch:
        if first_fetch_datetime:
            last_fetch = first_fetch_datetime.timestamp()
        else:
            raise Exception("Could not find last fetch time.")

    latest_created_time = last_fetch
    incidents: List[Dict[str, Any]] = []
    topdesk_incidents = get_incidents_list(client=client,
                                           args=args,
                                           demisto_params=demisto_params,
                                           is_fetch=True)

    for topdesk_incident in topdesk_incidents:
        creation_datetime = arg_to_datetime(topdesk_incident.get('creationDate', '0'))
        if creation_datetime:
            incident_created_time = creation_datetime.timestamp()
        else:
            incident_created_time = int(last_fetch)
        if int(last_fetch) < int(incident_created_time):
            labels: List[Dict[str, Any]] = []
            for topdesk_incident_field, topdesk_incident_value in topdesk_incident.items():
                if isinstance(topdesk_incident_value, str):
                    labels.append({
                        'type': topdesk_incident_field,
                        'value': topdesk_incident_value
                    })
                else:
                    labels.append({
                        'type': topdesk_incident_field,
                        'value': json.dumps(topdesk_incident_value)
                    })

            incidents.append({
                'name': f"TOPdesk incident {topdesk_incident['number']}",
                'details': json.dumps(topdesk_incident),
                'occurred': timestamp_to_datestring(incident_created_time),
                'rawJSON': json.dumps(topdesk_incident),
                'labels': labels
            })
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time
    demisto.setLastRun({'last_fetch': latest_created_time})
    demisto.incidents(incidents)


def test_module(client: Client, demisto_params: Dict[str, Any]) -> str:
    """Test API connectivity and authentication."""
    try:
        if demisto_params.get('isFetch'):
            get_incidents_list(client, {}, demisto_params)
        else:
            client.get_list("/incidents/call_types")
    except DemistoException as e:
        if 'Error 401' in str(e):
            return 'Authorization Error: make sure username and password are correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions."""

    # get the service API url
    demisto_params = demisto.params()
    base_url = urljoin(demisto_params['url'], '/api')
    verify_certificate = not demisto_params.get('insecure', False)
    proxy = demisto_params.get('proxy', False)

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
            result = test_module(client, demisto_params)
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
            return_results(incidents_to_command_results(client, get_incidents_list(client,
                                                                                   demisto.args(),
                                                                                   demisto_params)))

        elif demisto.command() == 'topdesk-incident-create':
            args = demisto.args()
            try:
                args['registered_caller'] = True
                return_results(incident_func_command(client=client,
                                                     args=demisto.args(),
                                                     client_func=client.create_incident,
                                                     action="creating"))
            except Exception as e:
                if "'callerLookup.id' cannot be parsed" in str(e):
                    args['registered_caller'] = False
                    return_results(incident_func_command(client=client,
                                                         args=demisto.args(),
                                                         client_func=client.create_incident,
                                                         action="creating"))
                else:
                    raise e

        elif demisto.command() == 'topdesk-incident-update':
            args = demisto.args()
            try:
                args['registered_caller'] = True
                return_results(incident_func_command(client=client,
                                                     args=demisto.args(),
                                                     client_func=client.update_incident,
                                                     action="updating"))
            except Exception as e:
                if "'callerLookup.id' cannot be parsed" in str(e):
                    args['registered_caller'] = False
                    return_results(incident_func_command(client=client,
                                                         args=demisto.args(),
                                                         client_func=client.update_incident,
                                                         action="updating"))
                else:
                    raise e
        elif demisto.command() == 'topdesk-incident-escalate':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="escalate",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None))]))
        elif demisto.command() == 'topdesk-incident-deescalate':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="deescalate",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None))]))
        elif demisto.command() == 'topdesk-incident-archive':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="archive",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None))]))
        elif demisto.command() == 'topdesk-incident-unarchive':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="unarchive",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None))]))
        elif demisto.command() == 'topdesk-incident-attachment-upload':
            return_results(attachment_upload_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client, demisto.args(), demisto_params)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
