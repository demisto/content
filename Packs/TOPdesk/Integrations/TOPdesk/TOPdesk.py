import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""TOPdesk integration for Cortex XSOAR"""


import math
import os
import shutil
import traceback
from distutils.version import LooseVersion
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

INTEGRATION_NAME = 'TOPdesk'
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DATE_FORMAT_FULL = "%Y-%m-%dT%H:%M:%S.%f%z"
MAX_API_PAGE_SIZE = 10000
FIRST_REST_API_VERSION_WITH_NEW_QUERY = "3.4.0"

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the TOPdesk service API"""

    def __init__(self, base_url, verify, auth):
        super().__init__(base_url=base_url, verify=verify, auth=auth)
        self._proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        self.rest_api_new_query = self.rest_api_supports_new_query()

    def rest_api_supports_new_query(self) -> bool:
        """Initialize which query type is supported by requesting the TOPdeskRestAPI version.

        Return True if the version supports new FIQL type query and False otherwise.
        """
        try:
            rest_api_version = LooseVersion(self.get_single_endpoint("/version")["version"])

        except DemistoException as e:
            if 'Error 401' in str(e):
                raise DemistoException('Authorization Error: make sure username and password are correctly set')
            if '[404] - Not Found' in str(e):
                raise DemistoException('Page Not Found: make sure the url is correctly set')
            else:
                raise e

        if rest_api_version >= LooseVersion(FIRST_REST_API_VERSION_WITH_NEW_QUERY):
            return True
        return False

    def get_list_with_query(self, list_type: str, start: Optional[int] = None, page_size: Optional[int] = None,
                            query: Optional[str] = None, modification_date_start: Optional[str] = None,
                            modification_date_end: Optional[str] = None, creation_date_start: Optional[str] = None,
                            creation_date_end: Optional[str] = None, fields: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of objects that support start, page_size and query arguments.

        Args:
            list_type: "persons"/ "operators"/ "branches"/ "incidents"
            start: The offset at which to start listing the incidents at, default is 0.
            page_size: The amount of incidents to be returned per request, default is 10.
            query: Filter the incidents by this FIQL query.
            modification_date_start: Retrieve only incidents with modification date greater or equal to
                this day 00:00:00, using time zone of the logged in user or operator. <yyyy-mm-dd>
            modification_date_end: Retrieve only incidents with modification date smaller or equal to
                this day 23:59:59, using time zone of the logged in user or operator. <yyyy-mm-dd>
            creation_date_start: Retrieve only incidents with creation date greater or equal to
                this day 00:00:00, using time zone of the logged in user or operator. <yyyy-mm-dd>
            creation_date_end: Retrieve only incidents with creation date smaller or equal to
                this day 00:00:00, using time zone of the logged in user or operator. <yyyy-mm-dd>
            fields: Option to select fields for persons, branches and incidents.

        Return List of requested objects.
        """

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

        if list_type == "incidents":
            new_query = self.rest_api_new_query

        else:
            new_query = True

        if fields:
            qfield = "fields"
            if list_type == "persons" or list_type == "branches":
                qfield = "$" + qfield

            if inline_parameters:
                url_suffix = f"{url_suffix}&{qfield}={fields}"
            else:
                url_suffix = f"{url_suffix}?{qfield}={fields}"
                inline_parameters = True

        query = self.convert_query_types(query, new_query)

        url_suffix = self.add_query_to_request(query, url_suffix, new_query, inline_parameters)

        if modification_date_start:
            request_params["modification_date_start"] = modification_date_start

        if modification_date_end:
            request_params["modification_date_end"] = modification_date_end

        if creation_date_start:
            request_params["creation_date_start"] = creation_date_start

        if creation_date_end:
            request_params["creation_date_end"] = creation_date_end

        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            json_data=request_params
        )

    def get_list(self, endpoint: str) -> List[Dict[str, Any]]:
        """Get list of objects using the API endpoint."""

        return self._http_request(
            method='GET',
            url_suffix=f"{endpoint}",
        )

    def get_single_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """Get an object using the API endpoint."""

        return self._http_request(
            method='GET',
            url_suffix=f"{endpoint}",
        )

    def create_incident(self, args: Dict[str, Any] = {}) -> Dict[str, Any]:
        """Create incident in TOPdesk.

        Args:
            args: The args for creating. Caller must be specified to create incident.

        Return the new incident on success or the API error otherwise.
        """

        if not args.get("caller", None):
            raise ValueError('Caller must be specified to create incident.')

        request_params = prepare_touch_request_params(args)

        return self._http_request(
            method='POST',
            url_suffix="/incidents/",
            json_data=request_params
        )

    def update_incident(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident in TOPdesk.

        Args:
            args: The args for updating. Either id or number must be specified to update incident.

        Return the updated incident on success or the API error otherwise.
        """

        if not args.get("id", None) and not args.get("number", None):
            raise ValueError('Either id or number must be specified to update incident.')

        if args.get("id", None):
            endpoint = f"/incidents/id/{args['id']}"
        else:
            endpoint = f"/incidents/number/{args['number']}"

        request_params = prepare_touch_request_params(args)

        return self._http_request(
            method='PUT',
            url_suffix=endpoint,
            json_data=request_params
        )

    def incident_do(self, action: str, incident_id: Optional[str], incident_number: Optional[str],
                    reason_id: Optional[str]) -> Dict[str, Any]:
        """Preform action on TOPdesk incident with specified reason_id if needed.
        This function implements "escalate"/ "deescalate"/ "archive"/ "unarchive" commands.

        Args:
            action: "escalate"/ "deescalate"/ "archive"/ "unarchive"
            incident_id: The incident id to preform the action on.
            incident_number: The incident number to preform the action on.
                If both id and number are specified, id will be used.
            reason_id: The reason id for the specified action.

        Return the updated incident on success or the API error otherwise.
        """
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
            method='PUT',
            url_suffix=f"{endpoint}/{action}",
            json_data=request_params
        )

    def attachment_upload(self, incident_id: Optional[str], incident_number: Optional[str], file_entry: str,
                          file_name: str, invisible_for_caller: bool, file_description: Optional[str]):
        """Upload an attachment from file_entry to TOPdesk incident.

        Args:
            incident_id: The incident id to upload attachment to.
            incident_number: The incident number to upload attachment to.
                If both id and number are specified, id will be used.
            file_entry: The file entry id indicating the attachment to upload
            file_name: The file name to upload.
            invisible_for_caller: Whether the attachment will be visible for the caller or not.
            file_description: Description of the file to upload. Will be uploaded alongside.

        Return attachment response from API.
        """
        if not incident_id and not incident_number:
            raise ValueError('Either id or number must be specified to update incident.')

        if incident_id:
            endpoint = f"/incidents/id/{incident_id}"
        else:
            endpoint = f"/incidents/number/{incident_number}"

        request_params: Dict[str, Any] = {}
        request_params["invisibleForCaller"] = invisible_for_caller
        if file_description:
            request_params["description"] = file_description

        shutil.copyfile(demisto.getFilePath(file_entry)['path'], file_name)
        try:
            with open(file_name, 'rb') as file_obj:
                files = {'file': file_obj}
                response = self._http_request(method='POST',
                                              url_suffix=f"{endpoint}/attachments",
                                              files=files,
                                              data=request_params)
        except Exception as e:
            os.remove(file_name)
            raise e
        os.remove(file_name)
        return response

    def list_attachments(self, incident_id: Optional[str], incident_number: Optional[str]) -> List[Dict[str, Any]]:
        """List attachments of a given incident.

        Args:
            incident_id: The incident id to list attachments of.
            incident_number: The incident number to list attachments of.
                If both id and number are specified, id will be used.

        Return list of attachments of the incident.
        """
        if not incident_id and not incident_number:
            raise ValueError('Either id or number must be specified to update incident.')

        if incident_id:
            attachments = self.get_list(f"/incidents/id/{incident_id}/attachments")

        else:
            attachments = self.get_list(f"/incidents/number/{incident_number}/attachments")

        return attachments

    def list_actions(self, incident_id: Optional[str], incident_number: Optional[str]) -> List[Dict[str, Any]]:
        """List actions of a given incident.

        Args:
            incident_id: The incident id to list actions of.
            incident_number: The incident number to list actions of.
                If both id and number are specified, id will be used.

        Return list of actions of the incident.
        """
        if not incident_id and not incident_number:
            raise ValueError('Either id or number must be specified to update incident.')

        if incident_id:
            actions = self.get_list(f"/incidents/id/{incident_id}/actions")

        else:
            actions = self.get_list(f"/incidents/number/{incident_number}/actions")
        return actions

    @staticmethod
    def add_filter_to_query(query: Optional[str], filter_name: str, filter_arg: str,
                            use_new_query: bool = True) -> Optional[str]:
        """Enhance query to include filter argument. Consider the supported query type.

        Args:
            query: The current query in use. (e.g. id==some-id)
            filter_name: The filter name to add (e.g. email)
            filter_arg: The filter argument to add (e.g. my@email.com)
            use_new_query: Whether to use FIQL query or not.

        Return the joined query with the argument (e.g. id==some-id&email==my@email.com)
        """
        if filter_name and filter_arg:
            if query:
                query = f"{query}&"
            else:
                query = ''

            if use_new_query:
                query = f"{query}{filter_name}=={filter_arg}"
            else:
                query = f"{query}{filter_name}={filter_arg}"

        return query

    @staticmethod
    def add_query_to_request(query: Optional[str], url_suffix: str, new_query: bool,
                             inline_parameters: bool) -> str:
        """Add the inline query parameter to the url suffix of a request.
        Consider the supported query type.

        Args:
             query: The query argument to add to the url suffix (e.g. id==3)
             url_suffix: The existing url suffix (e.g. /persons?start=2)
             new_query: Whether to use FIQL query or add parameters inline.
             inline_parameters: Whether there are already other inline parameters in the url.

        Return the reconstructed url_suffix containing the query.
        """
        if query:
            if new_query:
                query = f"query={query}"

            if inline_parameters:
                url_suffix = f"{url_suffix}&{query}"

            else:
                url_suffix = f"{url_suffix}?{query}"

        return url_suffix

    @staticmethod
    def convert_query_types(current_query: Optional[str], to_new_query: bool) -> Optional[str]:
        """Convert inline params to FIQL query and otherwise

        Args:
            current_query: The current query, must be in the for.
            to_new_query: Wether to convert to FIQL query or inline parameters.

        Return the new reconstructed query.
        """
        if not current_query:
            return None
        query_args = re.split("&", current_query)
        new_query_args = []
        for query_arg in query_args:
            query_arg_list = re.split("=", query_arg)
            if '' in query_arg_list:
                query_arg_list.remove('')

            if len(query_arg_list) > 3:
                raise ValueError('Invalid query, make sure it is in the right format')

            if not to_new_query and len(query_arg_list) != 2:
                raise ValueError(f'Invalid query, older {INTEGRATION_NAME} versions only support filtering with =')

            if to_new_query and len(query_arg_list) == 2 and query_arg_list[0][-1] != '!':
                new_query_args.append('=='.join(query_arg_list))

            else:
                new_query_args.append('='.join(query_arg_list))

        return '&'.join(new_query_args)


''' HELPER FUNCTIONS '''


def trim_results_by_limit(results: List[Any], limit: Union[int, str] = 100) -> List[Any]:
    """Trim list of results so only a limited number is returned.

    Args:
        results: The list of results.
        limit: The upper limit of the results to return. If limit is set to -1 all results will be returned.

    Return the trimmed results.
    """
    if int(limit) == -1:
        return results
    return results[:int(limit)]


def attachments_to_command_results(client: Client, attachments: List[Dict[str, Any]], incident_id: Optional[str],
                                   incident_number: Optional[str]) -> CommandResults:
    """Transform raw attachments to CommandResults.

    Args:
        client: The client from which to take the base_url for clickable links.
        attachments: The raw attachments list from the API
        incident_id: The incident id of the attachments.
        incident_number: The incident number of the attachments.

    Return CommandResults of attachments.
    """
    headers = ['Id', 'FileName', 'DownloadUrl', 'Size', 'Description', 'InvisibleForCaller', 'EntryDate', 'Operator']
    capitalized_attachments = capitalize_for_outputs(attachments)
    for capitalized_attachment in capitalized_attachments:
        full_url = '/api'.join([client._base_url.split('/api')[0],
                                capitalized_attachment['DownloadUrl'].split('/api')[1]])
        capitalized_attachment['DownloadUrl'] = full_url

    incident_identifier = incident_number if incident_number else incident_id
    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} attachment of incident {incident_identifier}",
                                      capitalized_attachments,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Attachment',
        outputs_key_field='Id',
        outputs=capitalized_attachments,
        raw_response=attachments
    )


def actions_to_command_results(client: Client, actions: List[Dict[str, Any]], incident_id: Optional[str],
                               incident_number: Optional[str]) -> CommandResults:
    """Transform raw actions to CommandResults.

    Args:
        client: The client from which to take the base_url for clickable links.
        actions: The raw actions list from the API
        incident_id: The incident id of the actions.
        incident_number: The incident number of the actions.

    Return CommandResults of actions.
    """
    headers = ['Id', 'Memotext', 'Flag', 'InvisibleForCaller', 'EntryDate', 'Operator', 'Person']
    capitalized_actions = capitalize_for_outputs(actions)

    incident_identifier = incident_number if incident_number else incident_id
    readable_output = tableToMarkdown(f"{INTEGRATION_NAME} action of incident {incident_identifier}",
                                      capitalized_actions,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Action',
        outputs_key_field='Id',
        outputs=capitalized_actions,
        raw_response=actions
    )


def prepare_touch_request_params(args: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare request parameters for incident-create and incident-update commands.
    Convert snake_case and specific names of command to halfCamelizedCase and API names.

    Args should contain arguments as specified in the documentation:
      https://developers.topdesk.com/documentation/index.html#api-Incident-CreateIncident

    Return a request body dictionary ready for sending.
    """
    request_params: Dict[str, Any] = {}
    if args.get("entry_type", None):
        request_params["entryType"] = {"name": args["entry_type"]}

    optional_params = ["caller", "status", "description", "request", "action",
                       "action_invisible_for_caller", "call_type", "category", "subcategory",
                       "external_number", "main_incident"]
    optional_named_params = ["call_type", "category", "subcategory"]
    if args:
        for optional_param in optional_params:
            if args.get(optional_param, None):
                if optional_param == "description":
                    request_params["briefDescription"] = args.get(optional_param, None)

                elif optional_param == "caller":
                    if args.get("registered_caller", False):
                        request_params["callerLookup"] = {"id": args[optional_param]}
                    else:
                        request_params["caller"] = {"dynamicName": args[optional_param]}

                elif optional_param in optional_named_params:
                    request_params[half_camelize(optional_param)] = {"name": args[optional_param]}

                else:
                    request_params[half_camelize(optional_param)] = args.get(optional_param, None)

    if args.get("additional_params", None):
        request_params.update(json.loads(args["additional_params"]))

    return request_params


def half_camelize(s: str, delimiter: str = '_') -> str:
    """Convert an underscore separated string to camel case with first word not capitalized.
        hello_world -> helloWorld
    Args:
        s: The string to convert
        delimiter: The delimiter of the snake_case (e.g. snake-case => delimiter == '-')

    Return the converted halfCamelized string.
    """
    components = s.split(delimiter)
    return f"{components[0]}{''.join(x.title() for x in components[1:])}"


def capitalize(word: str):
    """Capitalize the first letter of the word while keeping the rest as it is."""
    return word[:1].upper() + word[1:]


def capitalize_for_outputs(outputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Capitalize for XSOAR readable outputs.

    Args:
        outputs: XSOAR raw_outputs object.

    Return same object with capitalized field names.
    """
    capitalized_outputs: List[Dict[str, Any]] = []
    for output in outputs:
        capitalized_output: Dict[str, Any] = {}
        for field, value in output.items():
            if isinstance(value, str) or isinstance(value, bool):
                capitalized_output[capitalize(field)] = value
            elif isinstance(value, dict):
                capitalized_output[capitalize(field)] = {}
                for sub_field, sub_value in value.items():
                    if isinstance(sub_value, str) or isinstance(value, bool):
                        capitalized_output[capitalize(field)][capitalize(sub_field)] = sub_value
                    elif isinstance(sub_value, dict):
                        capitalized_output[capitalize(field)][capitalize(sub_field)] = {}
                        for sub_sub_field, sub_sub_value in sub_value.items():
                            capitalized_output[capitalize(field)][capitalize(sub_field)][capitalize(sub_sub_field)] = \
                                sub_sub_value  # Support up to dict[x: dict[y: dict]]
        capitalized_outputs.append(capitalized_output)

    return capitalized_outputs


def command_with_all_fields_readable_list(results: List[Dict[str, Any]], result_name: str, output_prefix: str,
                                          outputs_key_field: str = 'id') -> CommandResults:
    """Return CommandResults with all the fields.

    Args:
        results: The command results extracted from the API response.
        result_name: Result table name. (e.g. Archiving Reasons)
        output_prefix: The output_prefix used in context data (e.g. ArchiveReason)
        outputs_key_field: Key field for the CommandResults (e.g. id)

    Return CommandResults with all fields in results and readable_output.
    """

    if len(results) == 0:
        return CommandResults(readable_output=f'No {result_name} found')

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} {result_name}', capitalize_for_outputs(results),
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.{output_prefix}',
        outputs_key_field=outputs_key_field,
        outputs=capitalize_for_outputs(results),
        raw_response=results
    )


def get_incidents_with_pagination(client: Client, max_fetch: int, query: str,
                                  modification_date_start: Optional[str] = None,
                                  modification_date_end: Optional[str] = None,
                                  creation_date_start: Optional[str] = None,
                                  creation_date_end: Optional[str] = None,
                                  fields: Optional[str] = None) -> List[Dict[str, Any]]:
    """Implement pagination for fetching incidents.

    Args:
        client: The client from which to make the requests.
        max_fetch: Maximum number of incidents to fetch.
        query: A filter query for the incidents to fetch.
        modification_date_start: The start modification date from which to fetch.
        modification_date_end: The end modification date from which to fetch.
        creation_date_start: The start creation date from which to fetch.
        creation_date_end: The end creation date from which to fetch.
        fields: Option to select fields for persons, branches and incidents.


    Return all incidents fetched.
    """
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
                                                modification_date_end=modification_date_end,
                                                creation_date_start=creation_date_start,
                                                creation_date_end=creation_date_end,
                                                fields=fields)
        start += page_size
    return incidents


def get_incidents_list(client: Client, modification_date_start: str = None, modification_date_end: str = None,
                       args: Dict[str, Any] = {}) -> List[Dict[str, Any]]:
    """Get list of incidents from TOPdesk.

    Args:
        client: The client from which to make the requests.
        modification_date_start: The start date from which to fetch.
        modification_date_end: The end date from which to fetch.
        args: might contain new style query or other old style arguments.

    Return list of incidents got from the API.
    """
    if args.get('incident_id', None):
        incidents = [client.get_single_endpoint(f"/incidents/id/{args.get('incident_id')}")]
    elif args.get('incident_number', None):
        incidents = [client.get_single_endpoint(f"/incidents/number/{args.get('incident_number')}")]
    else:
        allowed_statuses = [None, 'firstLine', 'secondLine', 'partial']
        if args.get('status', None) not in allowed_statuses:
            raise (ValueError(f"status {args.get('status', None)} id not in "
                              f"the allowed statuses list: {allowed_statuses}"))
        else:
            filter_arguments: Dict[str, Any] = {"status": "status",
                                                "caller_id": "caller",
                                                "branch_id": "branch",
                                                "category": "category",
                                                "subcategory": "subcategory",
                                                "call_type": "callType",
                                                "entry_type": "entryType"}
            old_query_not_allowed_filters = ["category", "subcategory", "call_type", "entry_type"]

            query = args.get('query', None)
            for filter_arg in filter_arguments.keys():
                if not client.rest_api_new_query:
                    if args.get(filter_arg, None) and filter_arg in old_query_not_allowed_filters:
                        raise KeyError(f"Filtering via {filter_arg} is not supported in older TOPdeskRestApi versions.")

                query = client.add_filter_to_query(query=query,
                                                   filter_name=filter_arguments.get(filter_arg, None),
                                                   filter_arg=args.get(filter_arg, None),
                                                   use_new_query=client.rest_api_new_query)
            incidents = client.get_list_with_query(list_type="incidents",
                                                   start=args.get('start', None),
                                                   page_size=args.get('page_size', None),
                                                   query=query,
                                                   modification_date_start=modification_date_start,
                                                   modification_date_end=modification_date_end,
                                                   fields=args.get('fields', None))

    return incidents


def incidents_to_command_results(client: Client, incidents: List[Dict[str, Any]]) -> CommandResults:
    """Receive incidents from api and convert to CommandResults.

    Args:
        client: The client from which to take the base_url for clickable links.
        incidents: The raw incidents list from the API

    Return CommandResults of Incidents.
    """
    if len(incidents) == 0:
        return CommandResults(readable_output='No incidents found')

    headers = ['Id', 'Number', 'Request', 'Line', 'Actions', 'CallerName', 'Status', 'Operator', 'Priority',
               'LinkToTOPdesk']

    readable_incidents = []
    for incident in incidents:
        readable_incident = {
            'Id': incident.get('id', None),
            'Number': incident.get('number', None),
            'Request': incident.get('request', None),
            'Line': incident.get('status', None),
            'CallerName': incident.get('caller', {}).get('dynamicName', None) if incident.get('caller') else None,
            'Status':
                incident.get('processingStatus', {}).get('name', None) if incident.get('processingStatus') else None,
            'Operator': incident.get('operator', {}).get('name', None) if incident.get('operator') else None,
            'Priority': incident.get('priority', None),
            'LinkToTOPdesk': f"[Open Incident in TOPdesk]({client._base_url.split('/api')[0]}"
                             f"/public/ssp/content/detail/incident?unid={incident.get('id', None)})"
        }
        readable_incidents.append(readable_incident)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} incidents', readable_incidents,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Incident',
        outputs_key_field='Id',
        outputs=capitalize_for_outputs(incidents),
        raw_response=incidents
    )


def incident_func_command(client: Client, args: Dict[str, Any], client_func: Callable, action: str) -> CommandResults:
    """Abstract class for executing client_func and returning TOPdesk incident as a result.

    Args:
        client: The client from which to take the base_url for clickable links.
        args: the arguments to send to the client_func.
        client_func: The client function to be called to execute the command.
        action: Readable string of the command to indicate the errors better.

    Return CommandResults of list of single incident response.
    """
    response = client_func(args)

    if not response.get('id', None):
        raise Exception(f"Recieved Error when {action} incident in TOPdesk:\n{response}")

    return incidents_to_command_results(client, [response])


''' COMMAND FUNCTIONS '''
''' List Commands '''


def list_persons_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get persons list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the persons command.

    Return CommadResults of list of persons.
    """

    persons = client.get_list_with_query(list_type="persons",
                                         start=args.get('start', None),
                                         page_size=args.get('page_size', None),
                                         query=args.get('query', None),
                                         fields=args.get('fields', None))
    if len(persons) == 0:
        return CommandResults(readable_output='No persons found')

    headers = ['Id', 'Name', 'Telephone', 'JobTitle', 'Department', 'City',
               'BranchName', 'Room']

    readable_persons = []
    for person in persons:
        readable_person = {
            'Id': person.get('id', None),
            'Name': person.get('dynamicName', None),
            'Telephone': person.get('phoneNumber', None),
            'JobTitle': person.get('jobTitle', None),
            'Department': person.get('department', None),
            'City': person.get('city', None),
            'BranchName': person.get('branch', {}).get('name', None) if person.get('branch') else None,
            'Room': person.get('location', {}).get('room', None) if person.get('location') else None
        }

        readable_persons.append(readable_person)

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} persons',
                                      readable_persons,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Person',
        outputs_key_field='Id',
        outputs=capitalize_for_outputs(persons),
        raw_response=persons
    )


def list_operators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get operators list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the operators command.

    Return CommandResults of list of operators.
    """

    operators = client.get_list_with_query(list_type="operators",
                                           start=args.get('start', None),
                                           page_size=args.get('page_size', None),
                                           query=args.get('query', None))
    if len(operators) == 0:
        return CommandResults(readable_output='No operators found')

    headers = ['Id', 'Name', 'Telephone', 'JobTitle', 'Department',
               'City', 'BranchName', 'LoginName']

    readable_operators = []
    for operator in operators:
        readable_operators.append({
            'Id': operator.get('id', None),
            'Name': operator.get('dynamicName', None),
            'Telephone': operator.get('phoneNumber', None),
            'JobTitle': operator.get('jobTitle', None),
            'Department': operator.get('department', None),
            'City': operator.get('city', None),
            'BranchName': operator.get('branch', {}).get('name', None) if operator.get('branch') else None,
            'LoginName': operator.get('tasLoginName', None),
        })

    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} operators',
                                      readable_operators,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Operator',
        outputs_key_field='Id',
        outputs=capitalize_for_outputs(operators),
        raw_response=operators
    )


def entry_types_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get entry types list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of EntryType."""
    entry_types = client.get_list('/incidents/entry_types')
    entry_types = trim_results_by_limit(entry_types, args.get('limit', 100))

    return command_with_all_fields_readable_list(results=entry_types,
                                                 result_name='entry types',
                                                 output_prefix='EntryType',
                                                 outputs_key_field='Id')


def call_types_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get call types list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of CallType."""

    call_types = client.get_list("/incidents/call_types")
    call_types = trim_results_by_limit(call_types, args.get('limit', 100))

    return command_with_all_fields_readable_list(results=call_types,
                                                 result_name='call types',
                                                 output_prefix='CallType',
                                                 outputs_key_field='Id')


def categories_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get categories list from TOPdesk

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of Category."""

    categories = client.get_list("/incidents/categories")
    categories = trim_results_by_limit(categories, args.get('limit', 100))

    return command_with_all_fields_readable_list(results=categories,
                                                 result_name='categories',
                                                 output_prefix='Category',
                                                 outputs_key_field='Id')


def escalation_reasons_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get escalation reasons list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of EscalationReason."""
    escalation_reasons = client.get_list("/incidents/escalation-reasons")
    escalation_reasons = trim_results_by_limit(escalation_reasons, args.get('limit', 100))

    return command_with_all_fields_readable_list(results=escalation_reasons,
                                                 result_name='escalation reasons',
                                                 output_prefix='EscalationReason',
                                                 outputs_key_field='Id')


def deescalation_reasons_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str]:
    """Get deescalation reasons list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of DeescalationReason."""
    try:
        deescalation_reasons = client.get_list("/incidents/deescalation-reasons")
        deescalation_reasons = trim_results_by_limit(deescalation_reasons, args.get('limit', 100))

    except DemistoException as e:
        if '[404] - Not Found' in str(e):
            return 'Page Not Found: make sure deescalation feature is enabled in TOPdesk.'

    return command_with_all_fields_readable_list(results=deescalation_reasons,
                                                 result_name='deescalation reasons',
                                                 output_prefix='DeescalationReason',
                                                 outputs_key_field='Id')


def archiving_reasons_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get archiving reasons list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of ArchiveReason."""

    archiving_reasons = client.get_list("/archiving-reasons")
    archiving_reasons = trim_results_by_limit(archiving_reasons, args.get('limit', 100))

    return command_with_all_fields_readable_list(results=archiving_reasons,
                                                 result_name='archiving reasons',
                                                 output_prefix='ArchiveReason',
                                                 outputs_key_field='Id')


def subcategories_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get subcategories list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of subcategories."""

    subcategories = client.get_list("/incidents/subcategories")

    if len(subcategories) == 0:
        return CommandResults(readable_output='No subcategories found')

    subcategories = trim_results_by_limit(subcategories, args.get('limit', 100))

    subcategories_with_categories = []
    for subcategory in subcategories:
        subcategory_with_category = {"Id": subcategory.get("id", None),
                                     "Name": subcategory.get("name", None),
                                     "CategoryId": None,
                                     "CategoryName": None}
        if subcategory.get("category", None):
            subcategory_with_category["CategoryId"] = subcategory.get("category", None).get("id", None)
            subcategory_with_category["CategoryName"] = subcategory.get("category", None).get("name", None)

        subcategories_with_categories.append(subcategory_with_category)

    headers = ['Id', 'Name', 'CategoryId', 'CategoryName']
    readable_output = tableToMarkdown(f'{INTEGRATION_NAME} subcategories',
                                      subcategories_with_categories,
                                      headers=headers,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_NAME}.Subcategory',
        outputs_key_field='Id',
        outputs=capitalize_for_outputs(subcategories),
        raw_response=subcategories
    )


def list_attachments_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get attachments list from TOPdesk incident.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of attachments."""
    attachments = client.list_attachments(incident_id=args.get('incident_id', None),
                                          incident_number=args.get('incident_number', None))

    if len(attachments) == 0:
        return CommandResults(readable_output='No attachments found')

    attachments = trim_results_by_limit(attachments, args.get('limit', 100))
    return attachments_to_command_results(client, attachments, args.get('incident_id', None),
                                          args.get('incident_number', None))


def list_actions_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get actions list from TOPdesk incident.

    Args:
        client: The client to preform command on.
        args: The arguments of the command, specifically 'limit' will be used.

    Return CommadResults of list of attachments."""
    actions = client.list_actions(incident_id=args.get('incident_id', None),
                                  incident_number=args.get('incident_number', None))

    if len(actions) == 0:
        return CommandResults(readable_output='No actions found')

    actions = trim_results_by_limit(actions, args.get('limit', 100))
    return actions_to_command_results(client, actions, args.get('incident_id', None),
                                      args.get('incident_number', None))


def branches_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get branches list from TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the branches command.

    Return CommadResults of list of branches.
    """

    branches = client.get_list_with_query(list_type="branches",
                                          start=args.get('start', None),
                                          page_size=args.get('page_size', None),
                                          query=args.get('query', None),
                                          fields=args.get('fields', None))
    if len(branches) == 0:
        return CommandResults(readable_output='No branches found')

    headers = ['Id', 'Status', 'Name', 'Phone', 'Website', 'Address']

    readable_branches = []
    for branch in branches:
        readable_branch = {
            'Id': branch.get('id', None),
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
        outputs_prefix=f'{INTEGRATION_NAME}.Branch',
        outputs_key_field='Id',
        outputs=capitalize_for_outputs(branches),
        raw_response=branches
    )


def get_incidents_list_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str]:
    """Parse arguments and return incidents list as CommandResults.

    Args:
        client: The client to preform command on.
        args: The arguments of the incidents_list command.

    Return CommadResults of list of incidents.
    """

    try:
        command_results = incidents_to_command_results(client, get_incidents_list(client=client, args=args))
        return command_results
    except Exception as e:
        if 'Error parsing query' in str(e):
            return 'Error parsing query: make sure you are using the right query type.'
        else:
            raise e


def incident_touch_command(client: Client, args: Dict[str, Any], client_func: Callable, action: str) -> CommandResults:
    """This function implements incident_create and incident_update commands.

    Try setting caller as a reqistered caller. If caller is not registered, set the caller argument as caller name.
    A registered caller is one that has a TOPdesk account that can be linked to the call.

    Args:
        client: The client from which to take the base_url for clickable links.
        args: The arguments of the command.
        client_func: The client function to be called.
        action: Readable string for better errors (e.g. 'update')

    Return CommandResults with the renewed/new incident.
    """

    try:
        args['registered_caller'] = True  # Try to link a caller id to the incident.
        return incident_func_command(client=client,
                                     args=args,
                                     client_func=client_func,
                                     action=action)
    except Exception as e:
        if "'callerLookup.id' cannot be parsed" in str(e):  # If couldn't find a caller with the provided id.
            args['registered_caller'] = False  # Create incident with an unregistered caller name.
            return incident_func_command(client=client,
                                         args=args,
                                         client_func=client_func,
                                         action=action)
        else:
            raise e


def incident_do_command(client: Client, args: Dict[str, Any], action: str) -> CommandResults:
    """Preform an action on an incident and return it as CommandResults.

    Args:
        client: The client to preform command on.
        args: The arguments of the incidents_list command.
        action: The action to preform on the incident: "escalate"/"deescalate"/"archive"/"unarchive"

    Return the incident as CommandResult.
    """

    return incidents_to_command_results(client,
                                        [client.incident_do(action=action,
                                                            incident_id=args.get("id", None),
                                                            incident_number=args.get("number", None),
                                                            reason_id=args.get(f"{action}_reason_id", None))])


def attachment_upload_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Upload attachment to certain incident in TOPdesk.

    Args:
        client: The client to preform command on.
        args: The arguments of the attachment upload command. Should contain either id or number
            indicating the incident and a file entry id indicating the attachment to upload.

    Return the uploaded attachment as CommandResults.
    """

    file_entry = args.get('file')
    file_name = demisto.dt(demisto.context(), f"File(val.EntryID=='{file_entry}').Name")
    if not file_name:  # in case of info file
        file_name = demisto.dt(demisto.context(), f"InfoFile(val.EntryID=='{file_entry}').Name")

    if not file_name:
        raise ValueError(f"Could not fine file in entry with entry_id: {file_entry}")

    if isinstance(file_name, list):  # If few files
        if args.get('file_name', None) and args.get('file_name') in file_name:
            file_name = args.get('file_name')
        else:
            file_name = file_name[0]

    invisible_for_caller = bool(args.get('invisible_for_caller', False))

    response = client.attachment_upload(incident_id=args.get('id', None),
                                        incident_number=args.get('number', None),
                                        file_entry=str(file_entry),
                                        file_name=str(file_name),
                                        invisible_for_caller=invisible_for_caller,
                                        file_description=args.get('file_description', None))

    if not response.get("downloadUrl", None):
        raise Exception(f"Failed uploading file: {response}")

    return attachments_to_command_results(client, [response], args.get('incident_id', None),
                                          args.get('incident_number', None))


''' FETCH & MIRRORING COMMANDS'''


def fetch_incidents(client: Client,
                    last_run: Dict[str, Any],
                    demisto_params: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Fetches incidents from TOPdesk.

    Args:
        client: The client to preform command on.
        last_run: Dict indicating the last fetch time (e.g. {'last_fetch': 2020-03-10T06:32:36.000000+0000})
        demisto_params: Demisto configuration of fetch_incidents.

    Return (updated dict indicating the last fetch time, incidents)
    """

    first_fetch_datetime = dateparser.parse(demisto_params.get('first_fetch', '3 days'))
    last_fetch = last_run.get('last_fetch', None)

    if not last_fetch:
        if first_fetch_datetime:
            last_fetch_datetime = first_fetch_datetime
        else:
            raise Exception("Could not find last fetch time.")
    else:
        last_fetch_datetime = dateparser.parse(last_fetch)

    latest_created_time = last_fetch_datetime
    incidents: List[Dict[str, Any]] = []

    creation_date_start = last_fetch_datetime.strftime("<%Y-%m-%d>")

    topdesk_incidents = get_incidents_with_pagination(client=client,
                                                      max_fetch=int(demisto_params.get('max_fetch', 10)),
                                                      query=demisto_params.get('fetch_query', None),
                                                      creation_date_start=creation_date_start)

    for topdesk_incident in topdesk_incidents:
        if topdesk_incident.get('creationDate', None):
            creation_datetime = dateparser.parse(topdesk_incident['creationDate'])
            incident_created_time = creation_datetime
        else:
            incident_created_time = last_fetch_datetime
        if float(last_fetch_datetime.timestamp()) < float(incident_created_time.timestamp()):

            incident = {
                'name': f"TOPdesk incident {topdesk_incident['number']}",
                'details': json.dumps(topdesk_incident),
                'occurred': incident_created_time.strftime(DATE_FORMAT),
                'rawJSON': json.dumps(topdesk_incident)}

            if incident not in incidents:  # Do not fetch duplicates
                incidents.append(incident)

        if float(latest_created_time.timestamp()) < float(incident_created_time.timestamp()):
            latest_created_time = incident_created_time

    return {'last_fetch': latest_created_time.strftime(DATE_FORMAT_FULL)}, incidents


def test_module(client: Client, demisto_last_run: Dict[str, Any], demisto_params: Dict[str, Any]) -> str:
    """Test API connectivity and authentication.
    Use fetch incidents for testing if the integration supports it.

    Args:
        client: The client to try to connect to.
        demisto_last_run: Last run of fetch_incidents.
        demisto_params: Demisto configuration, will be used in case of fetching incidents.

    Returns 'ok' on success and an error message otherwise.
    """

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
        if '[404] - Not Found' in str(e):
            return 'Page Not Found: make sure the url is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions."""

    # get the service API url
    demisto_params = demisto.params()
    base_url = urljoin(demisto_params.get('url'), '/api')
    verify_certificate = not demisto_params.get('insecure', False)
    credentials = demisto_params.get('credentials')

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(credentials.get('identifier'), credentials.get('password')))

        if demisto.command() == 'test-module':
            result = test_module(client, demisto.getLastRun(), demisto_params)
            return_results(result)

        elif demisto.command() == 'topdesk-persons-list':
            return_results(list_persons_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-operators-list':
            return_results(list_operators_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-entry-types-list':
            return_results(entry_types_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-call-types-list':
            return_results(call_types_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-categories-list':
            return_results(categories_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-escalation-reasons-list':
            return_results(escalation_reasons_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-deescalation-reasons-list':
            return_results(deescalation_reasons_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-archiving-reasons-list':
            return_results(archiving_reasons_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-subcategories-list':
            return_results(subcategories_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-branches-list':
            return_results(branches_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-incidents-list':
            return_results(get_incidents_list_command(client, demisto.args()))
        elif demisto.command() == 'topdesk-incident-attachments-list':
            return_results(list_attachments_command(client, demisto.args()))

        elif demisto.command() == 'topdesk-incident-create':
            return_results(incident_touch_command(client=client,
                                                  args=demisto.args(),
                                                  client_func=client.create_incident,
                                                  action="creating"))
        elif demisto.command() == 'topdesk-incident-update':
            return_results(incident_touch_command(client=client,
                                                  args=demisto.args(),
                                                  client_func=client.update_incident,
                                                  action="updating"))

        elif demisto.command() == 'topdesk-incident-escalate':
            return_results(incident_do_command(client, demisto.args(), "escalate"))
        elif demisto.command() == 'topdesk-incident-deescalate':
            return_results(incident_do_command(client, demisto.args(), "deescalate"))
        elif demisto.command() == 'topdesk-incident-archive':
            return_results(incident_do_command(client, demisto.args(), "archive"))
        elif demisto.command() == 'topdesk-incident-unarchive':
            return_results(incident_do_command(client, demisto.args(), "unarchive"))

        elif demisto.command() == 'topdesk-incident-attachment-upload':
            return_results(attachment_upload_command(client, demisto.args()))

        elif demisto.command() == 'topdesk-incident-actions-list':
            return_results(list_actions_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            last_fetch, incidents = fetch_incidents(client=client,
                                                    last_run=demisto.getLastRun(),
                                                    demisto_params=demisto_params)
            demisto.setLastRun(last_fetch)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f"command {demisto.command()} does not exist in {INTEGRATION_NAME} integration")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
