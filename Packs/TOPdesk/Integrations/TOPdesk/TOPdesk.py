"""TOPdesk integration for Cortex XSOAR"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import os
import math
import shutil
import urllib3
import traceback
import dateparser

from typing import Any, Dict, List, Optional, Callable, Tuple
from base64 import b64encode

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INTEGRATION_NAME = 'TOPdesk'
XSOAR_ENTRY_TYPE = 'Automation'  # XSOAR
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_API_PAGE_SIZE = 10000

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

        url_suffix = f"/{list_type}"
        inline_parameters = False
        request_params: Dict[str, Any] = {}
        if start:
            url_suffix = f"{url_suffix}?start={start}"
            inline_parameters = True
        if page_size:
            if inline_parameters:
                url_suffix = f"{url_suffix}&page_size={page_size}"
            else:
                url_suffix = f"{url_suffix}?page_size={page_size}"
                inline_parameters = True
        if query:
            if inline_parameters:
                url_suffix = f"{url_suffix}&query={query}"
            else:
                url_suffix = f"{url_suffix}?query={query}"
        if modification_date_start:
            request_params["modification_date_start"] = modification_date_start
        if modification_date_end:
            request_params["modification_date_end"] = modification_date_end

        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_params
        )

    def get_list(self, endpoint: str) -> List[Dict[str, Any]]:
        """Get entry types using the API endpoint"""

        return self._http_request(
            method='GET',
            url_suffix=f"{endpoint}",
        )

    def get_single_endpoint(self, endpoint: str) -> Dict[str, Any]:
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
                    incident_number: Optional[str],
                    reason_id: Optional[str]) -> Dict[str, Any]:
        """ """
        allowed_actions = ["escalate", "deescalate", "archive", "unarchive"]
        request_params: Dict[str, Any] = {}
        if action not in allowed_actions:
            raise ValueError(f'Endpoint {action} not in allowed endpoint list: {allowed_actions}')
        if not incident_id and not incident_number:
            raise ValueError('Either id or number must be specified to update incident.')
        if incident_id:
            endpoint = f"/incidents/id/{incident_id}"
        else:
            endpoint = f"/incidents/number/{incident_number}"

        if reason_id:
            request_params["id"] = reason_id

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
                          invisible_for_caller: Optional[bool],
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
        if file_description:
            request_params["description"] = file_description

        shutil.copyfile(demisto.getFilePath(file_entry)['path'], file_name)
        try:
            files = {'file': open(file_name, 'rb')}
            response = self._http_request(method='POST',
                                          url_suffix=f"{endpoint}/attachments",
                                          files=files,
                                          json_data=request_params)
        except Exception as e:
            os.remove(file_name)
            raise e
        return response


''' HELPER FUNCTIONS '''


def command_with_all_fields_readable_list(results: List[Dict[str, Any]],
                                          result_name: str,
                                          output_prefix: str,
                                          outputs_key_field: str = 'id') -> CommandResults:
    """Get entry types list from TOPdesk"""

    if len(results) == 0:
        return CommandResults(readable_output=f'No {result_name} found')

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} {result_name}', results, removeNull=True)

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
               'Branch Name', 'Room']

    readable_persons = []
    for person in persons:
        readable_person = {
            'id': person.get('id', None),
            'Compound Name': person.get('dynamicName', None),
            'Telephone': person.get('phoneNumber', None),
            'Job Title': person.get('jobTitle', None),
            'Department': person.get('department', None),
            'City': person.get('city', None),
            'Branch Name': replace_none(person.get('branch', {}), {}).get('name', None),
            'Room': None
        }
        if person.get('location', None):
            readable_person['Room'] = person.get('location', None).get('room', None)
        readable_persons.append(readable_person)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} persons',
                                      readable_persons,
                                      headers=headers,
                                      removeNull=True)

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

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} operators',
                                      readable_operators,
                                      headers=headers,
                                      removeNull=True)

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
                                      headers=headers,
                                      removeNull=True)

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
        return CommandResults(readable_output='No branches found')

    headers = ['id', 'Status', 'Name', 'Phone', 'Website', 'Address']

    readable_branches = []
    for branch in branches:
        readable_branch = {
            'id': branch.get('id', None),
            'Status': branch.get('status', None),
            'Name': branch.get('name', None),
            'Phone': branch.get('phone', None),
            'Website': branch.get('website', None),
            'Address': branch.get('address', {}).get('addressMemo', None)
        }
        readable_branches.append(readable_branch)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} branches',
                                      readable_branches,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.branch',
        outputs_key_field='id',
        outputs=branches
    )


def add_filter_to_query(query: Optional[str], filter_name: str, args: Dict[str, Any]) -> Optional[str]:
    if args.get(filter_name, None):
        if query:
            query = f"{query}&"
        else:
            query = ''
        query = f"{query}{filter_name}=={args.get(filter_name, None)}"
    return query


def replace_none(value: Any, replacement: Any) -> Any:
    if value:
        return value
    return replacement


def get_incidents_with_pagination(client: Client,
                                  max_fetch: int,
                                  query: str,
                                  modification_date_start: str,
                                  modification_date_end: str) -> List[Dict[str, Any]]:
    incidents = []
    max_incidents = int(max_fetch)
    number_of_requests = math.ceil(max_incidents / MAX_API_PAGE_SIZE)
    if max_incidents < MAX_API_PAGE_SIZE:
        page_size = max_incidents
    else:
        page_size = MAX_API_PAGE_SIZE
    start = 0
    for index in range(number_of_requests):
        incidents += client.get_list_with_query(list_type="incidents",
                                                start=start,
                                                page_size=page_size,
                                                query=query,
                                                modification_date_start=modification_date_start,
                                                modification_date_end=modification_date_end)
        start += page_size
    return incidents


def get_incidents_list(client: Client,
                       incident_number: str = None,
                       incident_id: str = None,
                       modification_date_start: str = None,
                       modification_date_end: str = None,
                       query: str = None,
                       page_size: int = None,
                       start: int = None,
                       args: Dict[str, Any] = {}) -> List[Dict[str, Any]]:
    if incident_id or incident_number:
        if incident_id:
            incidents = [client.get_single_endpoint(f"/incidents/id/{incident_id}")]
        else:
            incidents = [client.get_single_endpoint(f"/incidents/number/{incident_number}")]
    else:
        allowed_statuses = [None, 'firstLine', 'secondLine', 'partial']
        if args.get('status', None) not in allowed_statuses:
            raise(ValueError(f"status {args.get('status', None)} id not in "
                             f"the allowed statuses list: {allowed_statuses}"))
        else:
            filter_arguments = ["status", "caller_id", "branch_id", "category", "subcategory",
                                "call_type", "entry_type"]
            for filter_arg in filter_arguments:
                query = add_filter_to_query(query=query,
                                            filter_name=filter_arg,
                                            args=args)
            incidents = client.get_list_with_query(list_type="incidents",
                                                   start=start,
                                                   page_size=page_size,
                                                   query=query,
                                                   modification_date_start=modification_date_start,
                                                   modification_date_end=modification_date_end)

    return incidents


def incidents_to_command_results(client: Client, incidents: List[Dict[str, Any]]) -> CommandResults:
    """Receive Incidents from api and convert to CommandResults"""
    if len(incidents) == 0:
        return CommandResults(readable_output='No incidents found')

    headers = ['id', 'Number', 'Request', 'Line', 'Actions', 'Caller Name', 'Status', 'Operator', 'Priority']

    readable_incidents = []
    for incident in incidents:
        readable_incident = {
            'id': incident.get('id', None),
            'Number': incident.get('number', None),
            'Request': incident.get('request', None),
            'Line': incident.get('status', None),
            'Caller Name': replace_none(incident.get('caller', {}), {}).get('dynamicName', None),
            'Status': replace_none(incident.get('processingStatus', {}), {}).get('name', None),
            'Operator': replace_none(incident.get('operator', {}), {}).get('name', None),
            'Priority': incident.get('priority', None)
        }

        readable_incidents.append(readable_incident)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} incidents', readable_incidents,
                                      headers=headers,
                                      removeNull=True)

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
    file_entry = args.get('file', None)
    if not file_entry:
        raise Exception("Found no file entry.")

    file_name = demisto.dt(demisto.context(), "File(val.EntryID=='" + file_entry + "').Name")
    if not file_name:  # in case of info file
        file_name = demisto.dt(demisto.context(), "InfoFile(val.EntryID=='" + file_entry + "').Name")
    if not file_name:
        raise ValueError(f"Could not fine file in entry with entry_id: {file_entry}")
    file_name = file_name[0] if isinstance(file_name, list) else file_name  # If few files

    invisible_for_caller_str = args.get('invisible_for_caller', None)
    if not invisible_for_caller_str:
        raise ValueError('invisible_for_caller must be either ture or false')
    if invisible_for_caller_str.lower() in ['true', 't', 'yes', 'y', '1']:
        invisible_for_caller = True
    else:
        invisible_for_caller = False

    response = client.attachment_upload(incident_id=args.get('id', None),
                                        incident_number=args.get('number', None),
                                        file_entry=file_entry,
                                        file_name=file_name,
                                        invisible_for_caller=invisible_for_caller,
                                        file_description=args.get('file_description', None))

    if not response.get("downloadUrl", None):
        raise Exception(f"Failed uploading file: {response}")

    headers = ['id', 'fileName', 'downloadUrl', 'size', 'description',
               'invisibleForCaller', 'entryDate', 'operator']
    readable_attachment: List[Dict[str, Any]] = [{}]
    for header in headers:
        readable_attachment[0][header] = response.get(header, None)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} attachment',
                                      readable_attachment,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.attachment',
        outputs_key_field='id',  # Not sure this will update the right path. Needs checking.
        outputs=response
    )


def get_incidents_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    return incidents_to_command_results(client,
                                        get_incidents_list(client=client,
                                                           incident_number=args.get('incident_number', None),
                                                           incident_id=args.get('incident_id', None),
                                                           query=args.get('query', None),
                                                           page_size=args.get('page_size', None),
                                                           start=args.get('start', None),
                                                           args=args))


def fetch_incidents(client: Client,
                    last_run: Dict[str, Any],
                    demisto_params: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Fetches incidents from TOPdesk."""

    first_fetch_datetime = dateparser.parse(demisto_params.get('first_fetch', '3 days'))
    last_fetch = last_run.get('last_fetch', None)  # TODO: Always returns None for some reason.

    if not last_fetch:
        if first_fetch_datetime:
            last_fetch_datetime = first_fetch_datetime
        else:
            raise Exception("Could not find last fetch time.")
    else:
        last_fetch_datetime = dateparser.parse(last_fetch)

    latest_created_time = last_fetch_datetime
    incidents: List[Dict[str, Any]] = []

    topdesk_incidents = get_incidents_with_pagination(client=client,
                                                      max_fetch=int(demisto_params.get('max_fetch', 10)),
                                                      query=demisto_params.get('query', None),
                                                      modification_date_start=demisto_params.get(
                                                          'modification_date_start', None),
                                                      modification_date_end=demisto_params.get(
                                                          'modification_date_end', None))

    for topdesk_incident in topdesk_incidents:
        if topdesk_incident.get('creationDate', None):
            creation_datetime = dateparser.parse(topdesk_incident['creationDate'])
            incident_created_time = creation_datetime
        else:
            incident_created_time = last_fetch_datetime
        if int(last_fetch_datetime.timestamp()) < int(incident_created_time.timestamp()):
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
                'occurred': incident_created_time.strftime(DATE_FORMAT),
                'rawJSON': json.dumps(topdesk_incident),
                'labels': labels
            })
        if latest_created_time.timestamp() < incident_created_time.timestamp():
            latest_created_time = incident_created_time

    return {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}, incidents


def test_module(client: Client, demisto_last_run: Dict[str, Any], demisto_params: Dict[str, Any]) -> str:
    """Test API connectivity and authentication."""
    try:
        if demisto_params.get('isFetch'):
            fetch_incidents(client=client,
                            last_run=demisto_last_run,
                            demisto_params=demisto_params)
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
            result = test_module(client, demisto.getLastRun(), demisto_params)
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
            return_results(get_incidents_list_command(client, demisto.args()))

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
                                                                                                               None),
                                                                            reason_id=demisto.args().get("reason_id",
                                                                                                         None))]))
        elif demisto.command() == 'topdesk-incident-deescalate':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="deescalate",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None),
                                                                            reason_id=demisto.args().get("reason_id",
                                                                                                         None))]))
        elif demisto.command() == 'topdesk-incident-archive':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="archive",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None),
                                                                            reason_id=demisto.args().get("reason_id",
                                                                                                         None))]))
        elif demisto.command() == 'topdesk-incident-unarchive':
            return_results(incidents_to_command_results(client,
                                                        [client.incident_do(action="unarchive",
                                                                            incident_id=demisto.args().get("id", None),
                                                                            incident_number=demisto.args().get("number",
                                                                                                               None),
                                                                            reason_id=None)]))
        elif demisto.command() == 'topdesk-incident-attachment-upload':
            return_results(attachment_upload_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            last_fetch, incidents = fetch_incidents(client=client,
                                                    last_run=demisto.getLastRun(),
                                                    demisto_params=demisto_params)
            demisto.setLastRun(last_fetch)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
