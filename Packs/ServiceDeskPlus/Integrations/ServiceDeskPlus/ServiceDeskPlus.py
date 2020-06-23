import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Tuple, Dict, List, Any
from _collections import defaultdict
import requests
import ast

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
API_VERSION = '/api/v3/'
OAUTH = 'https://accounts.zoho.com/oauth/v2/token'

REQUEST_FIELDS = ['subject', 'description', 'request_type', 'impact', 'status', 'mode', 'level', 'urgency', 'priority',
                  'service_category', 'requester', 'assets', 'site', 'group', 'technician', 'category', 'subcategory',
                  'item', 'email_ids_to_notify', 'is_fcr', 'resources', 'udf_fields']
FIELDS_WITH_NAME = ['request_type', 'impact', 'status', 'mode', 'level', 'urgency', 'priority', 'service_category',
                    'requester', 'site', 'group', 'technician', 'category', 'subcategory', 'item']
FIELDS_TO_IGNORE = ['has_draft', 'cancel_flag_comments']

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

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, client_id: str, client_secret: str,
                 refresh_token: str = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/v3+json'})
        if self.refresh_token:
            self.update_access_token()  # Add a valid access token to the headers
            self.access_token_refreshed = False  # todo: remove

    def update_access_token(self):
        """
        Generates an access token from the client id, client secret and refresh token
        """
        params = {
            'refresh_token': self.refresh_token,
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        res = self.http_request('POST', url_suffix='', full_url=OAUTH, params=params)
        if res.get('access_token'):
            self._headers.update({'Authorization': 'Bearer ' + res.get('access_token')})
            self.access_token_refreshed = True

    def http_request(self, method, url_suffix, full_url=None, params=None):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            res = self._http_request(method, url_suffix, full_url=full_url, resp_type='response', ok_codes=ok_codes,
                                     params=params)
            if res.status_code in [200, 201]:
                self.access_token_refreshed = False  # todo: remove

                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)

            if res.status_code in [401]:
                # if the access token hasn't been refreshed, refresh it and run the command again
                if not self.access_token_refreshed:  # todo: remove
                    self.update_access_token()
                    return self.http_request(method, url_suffix, full_url=full_url, params=params)
                try:
                    err_msg = f'Unauthorized request - check domain location and the given credentials \n{str(res.json())}'
                except ValueError:
                    err_msg = f'Unauthorized request - check domain location and the given credentials -\n{str(res)}'
                raise DemistoException(err_msg)

        except Exception as e:  # todo: remove the text in the error
            raise DemistoException('FAILS HERE ' + e.args[0])

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
    if output.get('Status'):
        output['Status'] = request.get('status', {}).get('name')
    if output.get('CreatedTime'):
        output['CreatedTime'] = timestamp_to_datestring(request.get('created_time', {}).get('value'))
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
    request_fields = {}
    for field in REQUEST_FIELDS:
        value = args.get(field, None)
        if value:
            if field not in FIELDS_WITH_NAME or 'name' in value:
                request_fields[field] = value
            else:
                request_fields[field] = {'name': value}
    return {'request': request_fields}


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
        linked_request = {
            'linked_request': {
                'id': request_id
            }
        }
        if comment:
            linked_request['comments'] = comment
        all_linked_requests.append(linked_request)
    return {'link_requests': all_linked_requests}


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
    row_count = args.get('row_count', None)
    search_fields = args.get('search_fields', None)
    filter_by = args.get('filter_by', None)
    list_info = create_list_info(start_index, row_count, search_fields, filter_by)
    params = {'input_data': f'{list_info}'}
    result = client.get_requests(request_id, params)
    output = []
    context: dict = defaultdict(list)

    if request_id:
        requests = [result.get('request', [])]
    else:
        requests = result.get('requests', [])
    for request in requests:
        request_output = create_output(request)
        output.append(request_output)
    context['ServiceDeskPlus(val.ID===obj.ID)'] = {'Request': output}
    markdown = tableToMarkdown(f'Requests', t=output)
    return markdown, context, result


def delete_request_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Delete the request with the given request_id

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    result = client.http_request('DELETE', url_suffix=f'requests/{request_id}')
    hr = f'### Successfully deleted request {request_id}'
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
    params = {'input_data': f'{query}'}
    result = client.http_request('POST', url_suffix='requests', params=params)
    request = result.get('request', None)
    output = {}
    context: dict = defaultdict(list)
    if request:
        output = create_output(request)

    markdown = tableToMarkdown('Service Desk Plus request was successfully created', t=output)
    context['ServiceDeskPlus(val.ID===obj.ID)'] = {'Request': output}
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
    params = {'input_data': f'{query}'}
    request_id = args.get('request_id')
    result = client.http_request('PUT', url_suffix=f'requests/{request_id}', params=params)
    request = result.get('request', None)
    output = {}
    context: dict = defaultdict(list)
    if request:
        output = create_output(request)

    markdown = tableToMarkdown('Service Desk Plus request was successfully updated', t=output)
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = {'Request': output}
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
    params = {'input_data': f'{query}'}
    request_id = args.get('request_id')
    result = client.http_request('PUT', url_suffix=f'requests/{request_id}/assign', params=params)
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
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = {'LinkRequests': output}
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
    linked_requests_id = args.get('linked_requests_id').split(',')
    comment = args.get('comment')
    input_data = create_modify_linked_input_data(linked_requests_id, comment)
    params = {'input_data': f'{input_data}'}
    if action == 'Link':
        result = client.http_request('POST', url_suffix=f'requests/{request_id}/link_requests', params=params)
    else:
        result = client.http_request('DELETE', url_suffix=f'requests/{request_id}/link_requests', params=params)
    markdown = f"## {result.get('response_status').get('messages')[0].get('message')}"
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
    resolution_content = args.get('resolution_content', '')
    add_to_linked_requests = args.get('add_to_linked_requests', 'false')
    query = {'resolution': {'content': resolution_content, 'add_to_linked_requests': add_to_linked_requests}}
    params = {'input_data': f'{query}'}
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
    output = result.get('resolution', {})
    markdown = tableToMarkdown(f'Resolution of request {request_id}', t=output)
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = {'Resolution': output}
    return markdown, context, result


def create_list_info(start_index, row_count, search_fields, filter_by):
    list_info = {}
    if start_index is not None:
        list_info['start_index'] = start_index
    if row_count is not None:
        list_info['row_count'] = row_count
    if search_fields:
        list_info['search_fields'] = search_fields
    if filter_by:
        list_info['filter_by'] = filter_by
    return {'list_info': list_info}


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, status: str, fetch_filter: str) -> list:
    date_format = '%Y-%m-%dT%H:%M:%S'
    last_run = demisto.getLastRun()
    if not last_run:  # if first time running
        new_last_run = {'time': date_to_timestamp(parse_date_range(fetch_time, date_format=date_format, utc=False)[0])}
    else:
        new_last_run = last_run
    demisto_incidents: List = list()
    time_from = new_last_run.get('time')
    time_to = date_to_timestamp(datetime.now(), date_format=date_format)
    list_info = create_fetch_list_info(str(time_from), str(time_to), status, fetch_filter)
    params = {'input_data': f'{list_info}'}

    # Get incidents from Service Desk Plus
    demisto.debug(f'Fetching Service Desk Plus requests. From: '
                  f'{timestamp_to_datestring(time_from, date_format=date_format)}. To: '
                  f'{timestamp_to_datestring(time_to, date_format=date_format)}\n'
                  f'last run id: {new_last_run.get("id", 0)}\n')
    incidents = client.get_requests(params=params).get('requests', [])

    if incidents:
        count = 0
        last_incident_id = last_run.get('id', '0')

        # Prevent fetching twice the same incident (the last that was previously fetched and the current first)
        first_incident = incidents[0]
        if first_incident.get('id') == last_incident_id:
            incidents = incidents[1:]

        for incident in incidents:
            if count < fetch_limit:
                demisto_incidents.append({
                    'name': f'{incident.get("subject")} - {incident.get("id")}',  # todo: check if id is necessary
                    'occurred': timestamp_to_datestring(incident.get('created_time', {}).get('value')),
                    'rawJSON': json.dumps(incident)
                })
                count += 1
                last_incident_id = incident.get('id')

        if demisto_incidents:
            last_incident_time = date_to_timestamp(demisto_incidents[-1].get('occurred').split('.')[0])
            new_last_run.update({'time': last_incident_time, 'id': last_incident_id})

    if not demisto_incidents:
        new_last_run.update({'time': time_to})
    demisto.setLastRun(new_last_run)
    return demisto_incidents


def create_fetch_list_info(time_from: str, time_to: str, status: str, fetch_filter: str) -> dict:
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

     Returns:
         A dictionary containing the list_info parameter that should be used for filtering the requests.

    """
    try:
        search_criteria = [{'field': 'created_time', 'values': [f'{time_from}', f'{time_to}'], 'condition': 'between'}]
        if fetch_filter:
            filters = ast.literal_eval(fetch_filter)
            if isinstance(filters, dict):
                query = {
                    'field': filters.get('field'),
                    'condition': filters.get('condition'),
                    'values': filters.get('values', '').split(','),
                    'logical_operator': filters.get('logical_operator', 'AND')
                }
                search_criteria.append(query)
            else:
                for filter in filters:
                    query = {
                        'field': filter.get('field'),
                        'condition': filter.get('condition'),
                        'values': filter.get('values', '').split(','),
                        'logical_operator': filter.get('logical_operator', 'AND')
                    }
                    search_criteria.append(query)
        else:
            query = {'field': 'status.name', 'values': status.split(','), 'condition': 'is', 'logical_operator': 'AND'}
            search_criteria.append(query)

        list_info = {
            'search_criteria': search_criteria,
            'sort_field': 'created_time',
            'sort_order': 'asc'
        }
        return {'list_info': list_info}
    except:
        return_error('Invalid input format. Please follow instructions for correct filter format.')


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
    if not client.refresh_token:
        return_error('Please enter a refresh token (see detailed instruction (?) for more information)')
    try:
        client.http_request('GET', 'requests')

        params: dict = demisto.params()

        if params.get('isFetch'):
            fetch_time = params.get('fetch_time', '1 day')
            fetch_status = params.get('fetch_status', 'Open')
            fetch_filter = params.get('fetch_filter')

            date_format = '%Y-%m-%dT%H:%M:%S'
            time_from = date_to_timestamp(parse_date_range(fetch_time, date_format=date_format, utc=False)[0])
            time_to = date_to_timestamp(datetime.now(), date_format=date_format)
            list_info = create_fetch_list_info(str(time_from), str(time_to), fetch_status, fetch_filter)
            params = {'input_data': f'{list_info}'}
            try:
                client.get_requests(params=params).get('requests', [])
            except Exception as e:
                if 'Error in API call' in e.args[0]:
                    raise DemistoException(f'Invalid input format. Please see instructions for correct filter format.'
                                           f'\n\n{e.args[0]}')
                raise e
        return 'ok'

    except Exception as e:
        raise e


def generate_refresh_token(client: Client, args: Dict) -> Tuple[str, dict, any]:
    """
    Creates for the user the refresh token for the app, given the code the user got when defining the scopes of the app.

    Args:
        client: Service Desk Plus client
        args: demisto.args() containing the code

    Returns:
        If the code is valid and the Refresh Token was generated successfully, the function displays the refresh token
        for the user in the war room.
    """
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
    else:
        hr = res
    return hr, {}, None


def main():
    params = demisto.params()
    server_url = SERVER_URL[params.get('server_url')]

    client = Client(url=server_url+API_VERSION,
                    use_ssl=not params.get('insecure', False),
                    use_proxy=params.get('proxy', False),
                    client_id=params.get('client_id'),
                    client_secret=params.get('client_secret'),
                    refresh_token=params.get('refresh_token'))

    commands = {
        'service-desk-plus-generate-refresh-token': generate_refresh_token,
        'service-desk-plus-requests-list': list_requests_command,
        'service-desk-plus-request-delete': delete_request_command,
        'service-desk-plus-request-create': create_request_command,
        'service-desk-plus-request-update': update_request_command,
        'service-desk-plus-request-assign': assign_request_command,
        'service-desk-plus-request-pickup': pickup_request_command,
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
            fetch_time = params.get('fetch_time', '1 day')
            fetch_limit = params.get('fetch_limit', 10)
            fetch_status = params.get('fetch_status', 'Open')
            fetch_filter = params.get('fetch_filter')
            incidents = fetch_incidents(client, fetch_time=fetch_time, fetch_limit=int(fetch_limit),
                                        status=fetch_status, fetch_filter=fetch_filter)
            demisto.incidents(incidents)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        # raise e
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
