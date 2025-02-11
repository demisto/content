import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Tuple, Dict, List, Any
from _collections import defaultdict
import urllib3
import ast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
API_VERSION = '/api/v3/'

OAUTH = {
    'United States': 'https://accounts.zoho.com/oauth/v2/token',
    'Europe': 'https://accounts.zoho.eu/oauth/v2/token',
    'India': 'https://accounts.zoho.in/oauth/v2/token',
    'China': 'https://accounts.zoho.cn/oauth/v2/token',
    'Australia': 'https://accounts.zoho.com.au/oauth/v2/token',
}

REQUEST_FIELDS = ['subject', 'description', 'request_type', 'impact', 'status', 'mode', 'level', 'urgency', 'priority',
                  'service_category', 'requester', 'assets', 'site', 'group', 'technician', 'category', 'subcategory',
                  'item', 'email_ids_to_notify', 'is_fcr', 'resources', 'udf_fields', 'update_reason']
FIELDS_WITH_NAME = ['request_type', 'impact', 'status', 'mode', 'level', 'urgency', 'priority', 'service_category',
                    'requester', 'site', 'group', 'technician', 'category', 'subcategory', 'item']
FIELDS_TO_IGNORE = ['has_draft', 'cancel_flag_comments']
HUMAN_READABLE_FIELDS = ['CreatedTime', 'Id', 'Requester', 'Technician', 'Status', 'Subject']
FIELDS_WITH_TIME = ['created_time', 'deleted_on', 'due_by_time', 'first_response_due_by_time', 'responded_time',
                    'resolved_time', 'completed_time', 'assigned_time', 'last_updated_time', 'submitted_on']

SERVER_URL = {
    'United States': 'https://sdpondemand.manageengine.com',
    'Europe': 'https://sdpondemand.manageengine.eu',
    'India': 'https://sdpondemand.manageengine.in',
    'China': 'https://servicedeskplus.cn',
    'Australia': 'https://servicedeskplus.net.au',
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, client_id: str = None, client_secret: str = None,
                 refresh_token: str = None, technician_key: str = None, fetch_time: str = '7 days',
                 fetch_status: list = None, fetch_limit: int = 50, fetch_filter: str = '', on_premise: bool = False,
                 oauth_url: str = ''):
        if fetch_status is None:
            fetch_status = []
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.technician_key = technician_key
        self.fetch_time = fetch_time
        self.fetch_status = fetch_status
        self.fetch_limit = fetch_limit
        self.fetch_filter = fetch_filter
        self.on_premise = on_premise
        self.oauth_url = oauth_url
        if on_premise:
            super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={
                'Accept': 'application/v3+json',
                'TECHNICIAN_KEY': technician_key
            })
        else:
            super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={
                'Accept': 'application/v3+json'
            })

            if self.refresh_token:
                self.get_access_token()  # Add a valid access token to the headers

    def get_access_token(self):
        """
        Gets an access token that was previously created if it is still valid, else, generates a new access token from
        the client id, client secret and refresh token
        """
        previous_token = demisto.getIntegrationContext()
        # Check if there is an existing valid access token
        if previous_token.get('access_token') and previous_token.get('expiry_time') > date_to_timestamp(datetime.now()):
            access_token = previous_token.get('access_token')
        else:
            params = {
                'refresh_token': self.refresh_token,
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            try:
                res = self.http_request('POST', url_suffix='', full_url=self.oauth_url, params=params)
                if 'error' in res:
                    return_error(
                        f'Error occurred while creating an access token. Please check the Client ID, Client Secret '
                        f'and Refresh Token.\n{res}')
                if res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format='%Y-%m-%dT%H:%M:%S')
                    expiry_time += res.get('expires_in') * 1000 - 10
                    new_token = {
                        'access_token': res.get('access_token'),
                        'expiry_time': expiry_time
                    }
                    demisto.setIntegrationContext(new_token)
                    access_token = res.get('access_token')
            except Exception as e:
                return_error(f'Error occurred while creating an access token. Please check the Client ID, Client Secret'
                             f' and Refresh Token.\n\n{e.args[0]}')
        self._headers.update({
            'Authorization': 'Bearer ' + access_token
        })

    def http_request(self, method, url_suffix, full_url=None, params=None):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            res = self._http_request(method, url_suffix, full_url=full_url, resp_type='response', ok_codes=ok_codes,
                                     params=params)
            if res.status_code in [200, 201]:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)

            if res.status_code in [401]:
                if not self.on_premise and demisto.getIntegrationContext().get('expiry_time', 0)\
                        <= date_to_timestamp(datetime.now()):
                    self.get_access_token()
                    return self.http_request(method, url_suffix, full_url=full_url, params=params)
                try:
                    err_msg = f'Unauthorized request - check domain location and the given credentials \n{str(res.json())}'
                except ValueError:
                    err_msg = f'Unauthorized request - check domain location and the given credentials -\n{str(res)}'
                raise DemistoException(err_msg)

        except Exception as e:
            if 'SSL Certificate Verification Failed' in e.args[0]:
                return_error('SSL Certificate Verification Failed - try selecting \'Trust any certificate\' '
                             'checkbox in the integration configuration.')
            raise DemistoException(e.args[0])

    def get_requests(self, request_id: str = None, params: dict = None):
        if request_id:
            return self.http_request(method='GET', url_suffix=f'requests/{request_id}')
        else:
            return self.http_request(method='GET', url_suffix='requests', params=params)


def create_output(request: dict) -> dict:
    """
    Creates the output for the context and human readable from the response of an http_request

    Args:
        request: A single request dict returned from the http_request

    Returns:
        A dictionary containing all valid fields in the request
    """
    output = {}
    for field in request.keys():
        value = request.get(field, None)
        if value not in [None, {}, []] and field not in FIELDS_TO_IGNORE:
            output[string_to_context_key(field)] = value
            if field in FIELDS_WITH_TIME:
                output[string_to_context_key(field)] = \
                    timestamp_to_datestring(request.get(field, {}).get('value'))

    if output.get('Status'):
        output['Status'] = request.get('status', {}).get('name')
    return output


def args_to_query(args: dict) -> dict:
    """
    Converts the given demisto.args into the format required for the http request

    Args:
        args: The arguments for the current command.

    Returns:
        A dictionary containing all valid valid query field that were passed in the args, converted into the format
        required for the http_request.
    """
    request_fields: Dict[str, Any] = {}
    for field in REQUEST_FIELDS:
        value = args.get(field, None)
        if value:
            if field == 'udf_fields':
                request_fields[field] = f"{create_udf_field(value)}"
            elif field not in FIELDS_WITH_NAME or (value[0] == '{' and value[-1] == '}'):  # if the second condition
                # holds the user entered an object as the field value and not only the name of the field. For more
                # information please refer to the `service-desk-plus-request-create` command in the README.
                request_fields[field] = value
            else:
                request_fields[field] = {
                    'name': value
                }
    return {
        'request': request_fields
    }


def create_udf_field(udf_input: str):
    """
    Converts the given string with udf keys and values to a valid dictionary for the query.

    Args:
        udf_input: the string representing the udf values as given by the user.

    Returns:
        A dictionary where every key is the udf_field key and the value given by the user.
    """
    if not udf_input:
        return {}
    try:
        if udf_input[0] == '{' and udf_input[-1] == '}':  # check if the user entered a dict as the value
            return ast.literal_eval(udf_input)

        fields = udf_input.split(',')
        udf_dict = {}
        for field in fields:
            if field:
                field_key_value = field.split(':')
                if field_key_value[0] and field_key_value[1]:
                    udf_dict[field_key_value[0]] = field_key_value[1]
                else:
                    raise Exception('Invalid input')
        return udf_dict
    except Exception:
        raise Exception('Illegal udf fields format. Input format should be a string of key and value separated by : '
                        'Multiple key;value pairs can be given, separated with a comma')


def create_modify_linked_input_data(linked_requests_id: list, comment: str) -> dict:
    """
    Returning the input_data dictionary that should be used to link/unlink the requests were passed.

    Args:
         linked_requests_id: the requests that should be linked/unlinked with/from the given base request
         comment: the comment that should be added when linking requests (optional)

     Returns:
         A dictionary containing the input_data parameter that should be used for linking/un-linking the requests.
    """
    all_linked_requests = []
    for request_id in linked_requests_id:
        linked_request: Dict[str, Any] = {
            'linked_request': {
                'id': request_id
            }
        }
        if comment:
            linked_request['comments'] = comment
        all_linked_requests.append(linked_request)
    return {
        'link_requests': all_linked_requests
    }


def create_human_readable(output: dict) -> dict:
    """
    Converts the output of a command to a human readable output

    Args:
        output: the output that should be converted to the human readable representation

    Returns:
        dict: the dictionary that represents the human readable output
    """
    hr = {}
    for field in HUMAN_READABLE_FIELDS:
        if output.get(field):
            hr[field] = output.get(field)
            if field in ['Technician', 'Requester']:
                hr[field] = output.get(field, {}).get('name')
    return hr


def resolution_human_readable(output: dict) -> dict:
    """
    Creates the human readable dictionary from the output of the resolution of the request

    Args:
        output: The resolution output that was created for the called request

    Returns:
        A dictionary containing all the valid fields in the resolution output
    """
    hr = {}
    for key in output.keys():
        if key == 'SubmittedBy':
            hr['SubmittedBy'] = output.get('SubmittedBy', {}).get('name', '')
        else:
            hr[key] = output.get(key, '')
    return hr


def create_requests_list_info(start_index, row_count, search_fields, filter_by):
    """
    Returning the list_info dictionary that should be used to filter the requests that are being returned.

    Args:
         start_index: the index of the first request that should be returned
         row_count: the number of requests that should be returned
         search_fields: search for specific fields in the requests
         filter_by: the filter by which to filter the returned requests

     Returns:
         A dictionary containing the list_info parameter that should be used for filtering the requests.

    """
    list_info = {}
    if start_index is not None:
        list_info['start_index'] = start_index
    if row_count is not None:
        list_info['row_count'] = row_count
    if search_fields:
        list_info['search_fields'] = search_fields
    if filter_by:
        list_info['filter_by'] = filter_by
    list_info['sort_field'] = 'created_time'
    list_info['sort_order'] = 'asc'
    return {
        'list_info': list_info
    }


def create_fetch_list_info(time_from: str, time_to: str, status: list, fetch_filter: str, fetch_limit: int) -> dict:
    """
    Returning the list_info dictionary that should be used to filter the requests that are being fetched
    The requests that will be returned when using this list_info are all requests created between 'time_from' and
    'time_to' (inclusive) and are with the given status, in ascending order of creation time.

    Args:
         time_from: the time from which requests should be fetched
         time_to: the time until which requests should be fetched
         status: the status of the requests that should be fetched
         fetch_filter: a string representing all the field according to which the results that are being fetched should
                       be filtered. Multiple fields, separated with a comma, can be used to filter. Every field should
                       be in the following format: 'field-name condition field-value' where condition is the condition
                       that this field should satisfy, for example 'is', 'is not', 'greater than' etc.
         fetch_limit: the maximal number of requests that should be returned.

     Returns:
         A dictionary containing the list_info parameter that should be used for filtering the requests.

    """
    list_info = {}
    try:
        search_criteria = [{
            'field': 'created_time',
            'values': [f'{time_from}', f'{time_to}'],
            'condition': 'between'
        }]
        if fetch_filter:
            filters = ast.literal_eval(fetch_filter)
            if isinstance(filters, dict):
                query: Dict[str, Any] = {
                    'field': filters.get('field'),
                    'condition': filters.get('condition'),
                    'values': filters.get('values', '').split(','),
                    'logical_operator': filters.get('logical_operator', 'AND')
                }
                if filters.get('logical_operator') == 'OR':
                    raise Exception('Only "AND" is allowed as a logical_operator')
                search_criteria.append(query)
            else:
                for filter in filters:
                    query = {
                        'field': filter.get('field'),
                        'condition': filter.get('condition'),
                        'values': filter.get('values', '').split(','),
                        'logical_operator': filter.get('logical_operator', 'AND')
                    }
                    if filter.get('logical_operator') == 'OR':
                        raise Exception('Only "AND" is allowed as a logical_operator')
                    search_criteria.append(query)
        else:
            if status:
                query = {
                    'field': 'status.name',
                    'values': status,
                    'condition': 'is',
                    'logical_operator': 'AND'
                }
                search_criteria.append(query)

        list_info = {
            'search_criteria': search_criteria,
            'sort_field': 'created_time',
            'sort_order': 'asc',
            'row_count': fetch_limit
        }
    except Exception as e:
        return_error(f'Invalid input format for fetch query. Please see detailed information (?) for valid fetch query '
                     f'format.\n{e.args[0]}')
    return {
        'list_info': list_info
    }


# Command functions:
def list_requests_command(client: Client, args: dict):
    """
    Get the details of requests. The returned requests can be filtered by a single request id or by input_data param.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id', None)
    start_index = args.get('start_index', None)
    row_count = args.get('page_size', None)
    search_fields = args.get('search_fields', None)
    filter_by = args.get('filter_by', None)
    list_info = create_requests_list_info(start_index, row_count, search_fields, filter_by)
    params = {
        'input_data': f'{list_info}'
    }
    result = client.get_requests(request_id, params)

    output = []
    hr = []
    context: dict = defaultdict(list)
    if request_id:
        requests = [result.get('request', [])]
    else:
        requests = result.get('requests', [])
    for request in requests:
        request_output = create_output(request)
        output.append(request_output)
        hr.append(create_human_readable(request_output))

    context['ServiceDeskPlus(val.ID===obj.ID)'] = {
        'Request': output
    }
    markdown = tableToMarkdown('Requests', t=hr)
    return markdown, context, result


def delete_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Delete the request(s) with the given request_id

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id', '')
    requests_list = request_id.split(',')
    result = {}
    for request in requests_list:
        result = client.http_request('DELETE', url_suffix=f'requests/{request}')
    hr = f'### Successfully deleted request(s) {requests_list}'
    return hr, {}, result


def create_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Create a new request with the given args

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    query = args_to_query(args)
    params = {
        'input_data': f'{query}'
    }
    result = client.http_request('POST', url_suffix='requests', params=params)
    request = result.get('request', None)

    output = {}
    context: dict = defaultdict(list)
    if request:
        output = create_output(request)
    hr = create_human_readable(output)
    markdown = tableToMarkdown('Service Desk Plus request was successfully created', t=hr)
    context['ServiceDeskPlus(val.ID===obj.ID)'] = {
        'Request': output
    }
    return markdown, context, result


def update_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Updates an existing request with the given args

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    query = args_to_query(args)
    params = {
        'input_data': f'{query}'
    }
    request_id = args.get('request_id')
    result = client.http_request('PUT', url_suffix=f'requests/{request_id}', params=params)
    request = result.get('request', None)
    output = {}
    context: dict = defaultdict(list)
    if request:
        output = create_output(request)

    hr = create_human_readable(output)
    markdown = tableToMarkdown('Service Desk Plus request was successfully updated', t=hr)
    context['ServiceDeskPlus(val.ID===obj.ID)'] = {
        'Request': output
    }
    return markdown, context, result


def assign_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Assigns the given request to the given technician/group

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    query = args_to_query(args)
    params = {
        'input_data': f'{query}'
    }
    request_id = args.get('request_id')
    result = client.http_request('PUT', url_suffix=f'requests/{request_id}/_assign', params=params)
    markdown = f'### Service Desk Plus request {request_id} was successfully assigned'
    return markdown, {}, result


def pickup_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Picks up the given request to the current technician

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    result = client.http_request('PUT', url_suffix=f'requests/{request_id}/pickup')
    markdown = f'### Service Desk Plus request {request_id} was successfully picked up'
    return markdown, {}, result


def linked_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Lists all the requests that are linked to the given request.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    result = client.http_request('GET', url_suffix=f'requests/{request_id}/link_requests')

    linked_requests = result.get('link_requests', [])
    context: dict = defaultdict(list)
    output = []

    for request in linked_requests:
        request_output = create_output(request)
        output.append(request_output)

    markdown = tableToMarkdown(f'Linked requests to request {request_id}', t=output, removeNull=True)
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = {
        'LinkRequests': output
    }
    return markdown, context, result


def modify_linked_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Links/Un-links the given request with all the other requests that where passed as arguments.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    action = args.get('action')
    linked_requests_id = args.get('linked_requests_id', '').split(',')
    comment = args.get('comment', '')
    input_data = create_modify_linked_input_data(linked_requests_id, comment)
    params = {
        'input_data': f'{input_data}'
    }
    if action == 'Link':
        result = client.http_request('POST', url_suffix=f'requests/{request_id}/link_requests', params=params)
    else:
        result = client.http_request('DELETE', url_suffix=f'requests/{request_id}/link_requests', params=params)
    markdown = f"## {result.get('response_status', {}).get('messages')[0].get('message')}"
    return markdown, {}, result


def add_resolution_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Adds the resolution to the given request

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    resolution_content = args.get('resolution_content')
    add_to_linked_requests = args.get('add_to_linked_requests') if args.get('add_to_linked_requests') else 'false'
    query = {
        'resolution': {
            'content': resolution_content,
            'add_to_linked_requests': add_to_linked_requests
        }
    }
    params = {
        'input_data': f'{query}'
    }
    result = client.http_request('POST', url_suffix=f'requests/{request_id}/resolutions', params=params)

    if add_to_linked_requests == 'true':
        markdown = f'### Resolution was successfully added to {request_id} and the linked requests'
    else:
        markdown = f'### Resolution was successfully added to {request_id}'

    return markdown, {}, result


def get_resolutions_list_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Gets the resolution of the given request

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    result = client.http_request('GET', url_suffix=f'requests/{request_id}/resolutions')

    context: dict = defaultdict(list)
    output = create_output(result.get('resolution', {}))
    hr = {}
    if output:
        context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = {
            'Resolution': output
        }
        hr = resolution_human_readable(output)
    markdown = tableToMarkdown(f'Resolution of request {request_id}', t=hr)
    return markdown, context, result


def close_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Close the request with the given request_id with comments and resolution defined by the user.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    closure_info: Dict[str, Any] = {
        "requester_ack_resolution": args.get('requester_ack_resolution', 'false'),
        "requester_ack_comments": args.get('requester_ack_comments', ''),
        "closure_comments": args.get('closure_comments', ''),
    }
    if args.get('closure_code'):
        closure_info["closure_code"] = {'name': args.get('closure_code')}
    input_data = {
        "request": {
            "closure_info": closure_info
        }
    }
    params = {
        'input_data': f'{input_data}'
    }
    result = client.http_request('PUT', url_suffix=f'requests/{request_id}/_close', params=params)
    hr = f'### Successfully closed request {request_id}'
    return hr, {}, result


def fetch_incidents(client: Client, test_command: bool = False) -> list:
    date_format = '%Y-%m-%dT%H:%M:%S'
    last_run = {}
    if not test_command:
        last_run = demisto.getLastRun()

    if not last_run:  # if first time running
        try:
            new_last_run = {
                'time': date_to_timestamp(parse_date_range(client.fetch_time, date_format=date_format, utc=False)[0])
            }
        except Exception as e:
            return_error(f'Invalid fetch time range.\n{e.args[0]}')
    else:
        new_last_run = last_run
    demisto_incidents: List = list()
    time_from = new_last_run.get('time')
    time_to = date_to_timestamp(datetime.now(), date_format=date_format)
    list_info = create_fetch_list_info(str(time_from), str(time_to), client.fetch_status, client.fetch_filter,
                                       client.fetch_limit + 1)
    params = {
        'input_data': f'{list_info}'
    }

    # Get incidents from Service Desk Plus
    demisto.info(f'Fetching ServiceDeskPlus incidents. with the query params: {str(params)}')

    incidents = client.get_requests(params=params).get('requests', [])

    if incidents:
        count = 0
        last_run_id = last_run.get('id', '0')
        last_incident_id = last_run.get('id', '0')
        cur_time = new_last_run.get('time', 0)
        incident_creation_time = new_last_run.get('time', 0)

        for incident in incidents:
            if count >= client.fetch_limit:
                break
            # Prevent fetching twice the same incident - the last incident that was fetched in the last run, will be the
            # first incident in the returned incidents from the API call this time.
            if incident.get('id') == last_run_id:
                continue
            incident_creation_time = int(incident.get('created_time', {}).get('value'))
            if incident_creation_time >= cur_time:
                demisto_incidents.append({
                    'name': f'{incident.get("subject")} - {incident.get("id")}',
                    'occurred': timestamp_to_datestring(incident_creation_time),
                    'rawJSON': json.dumps(incident)
                })
                count += 1
                last_incident_id = incident.get('id')

        if demisto_incidents:
            new_last_run.update({
                'time': incident_creation_time,
                'id': last_incident_id
            })

    if not demisto_incidents:
        new_last_run.update({
            'time': time_to
        })

    if not test_command:
        demisto.setLastRun(new_last_run)
    return demisto_incidents


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    If 'Fetches incidents' is checked in the instance configurations, this function checks that the entered parameters
    are valid.

    Args:
        client: Service Desk Plus client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    if not client.on_premise and not client.refresh_token:
        return_error('Please enter a refresh token (see detailed instruction (?) for more information)')
    try:
        client.http_request('GET', 'requests')
        params: dict = demisto.params()

        if params.get('isFetch'):
            fetch_incidents(client, test_command=True)
        return 'ok'

    except Exception as e:
        raise e


def generate_refresh_token(client: Client, args: Dict) -> Tuple[str, dict, Any]:
    """
    Creates for the user the refresh token for the app, given the code the user got when defining the scopes of the app.

    Args:
        client: Service Desk Plus client
        args: demisto.args() containing the code

    Returns:
        If the code is valid and the Refresh Token was generated successfully, the function displays the refresh token
        for the user in the war room.
    """
    if client.on_premise:
        return_error("The command 'service-desk-plus-generate-refresh-token' can not be executed on on-premise.")
    code = args.get('code')
    params = {
        'code': code,
        'grant_type': 'authorization_code',
        'client_id': client.client_id,
        'client_secret': client.client_secret
    }
    res = client.http_request('POST', url_suffix='', full_url=OAUTH, params=params)
    if res.get('refresh_token'):
        hr = f'### Refresh Token: {res.get("refresh_token")}\n Please paste the Refresh Token in the instance ' \
             f'configuration and save it for future use.'
    elif res.get('error'):
        hr = f'### Error: {res.get("error")}'
    else:
        hr = res
    return hr, {}, None


def main():
    params = demisto.params()
    server_url = params.get('server_url')
    technician_key = params.get('credentials_technician_key', {}).get(
        'password') or params.get('technician_key')
    client_id = params.get('credentials_client', {}).get('identifier') or params.get('client_id')
    client_secret = params.get('credentials_client', {}).get('password') or params.get('client_secret')
    refresh_token = params.get('credentials_refresh_token', {}).get('password') or params.get('refresh_token')
    if server_url == 'On-Premise':
        client = Client(url=params.get('server_url_on_premise') + API_VERSION,
                        use_ssl=not params.get('insecure', False),
                        use_proxy=params.get('proxy', False),
                        technician_key=technician_key,
                        fetch_time=params.get('first_fetch') if params.get('first_fetch') else '7 days',
                        fetch_status=params.get('fetch_status'),
                        fetch_limit=int(params.get('max_fetch')) if params.get('max_fetch') else 50,
                        fetch_filter=params.get('fetch_filter') if params.get('fetch_filter') else '',
                        on_premise=True)
    else:
        server_url = SERVER_URL[params.get('server_url')]
        oauth_url = OAUTH[params.get('server_url')]
        client = Client(url=server_url + API_VERSION,
                        oauth_url=oauth_url,
                        use_ssl=not params.get('insecure', False),
                        use_proxy=params.get('proxy', False),
                        client_id=client_id,
                        client_secret=client_secret,
                        refresh_token=refresh_token,
                        fetch_time=params.get('fetch_time') if params.get('fetch_time') else '7 days',
                        fetch_status=params.get('fetch_status'),
                        fetch_limit=int(params.get('fetch_limit')) if params.get('fetch_limit') else 50,
                        fetch_filter=params.get('fetch_filter') if params.get('fetch_filter') else '')

    commands = {
        'service-desk-plus-generate-refresh-token': generate_refresh_token,
        'service-desk-plus-requests-list': list_requests_command,
        'service-desk-plus-request-delete': delete_request_command,
        'service-desk-plus-request-create': create_request_command,
        'service-desk-plus-request-update': update_request_command,
        'service-desk-plus-request-assign': assign_request_command,
        'service-desk-plus-request-pickup': pickup_request_command,
        'service-desk-plus-request-close': close_request_command,
        'service-desk-plus-linked-request-list': linked_request_command,
        'service-desk-plus-link-request-modify': modify_linked_request_command,
        'service-desk-plus-request-resolution-add': add_resolution_command,
        'service-desk-plus-request-resolutions-list': get_resolutions_list_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command == "fetch-incidents":
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
