import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Tuple, Dict, Any
from _collections import defaultdict
import requests
import hashlib

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
SERVER_URL = 'https://sdpondemand.manageengine.com'
VERSION = '/api/v3/'

REQUEST_FIELDS = ['subject', 'description', 'request_type', 'impact', 'status', 'mode', 'level', 'urgency', 'priority',
                  'service_category', 'requester', 'assets', 'site', 'group', 'technician', 'category', 'subcategory',
                  'item', 'email_ids_to_notify', 'is_fcr', 'resources', 'udf_fields']
FIELDS_WITH_NAME = ['request_type', 'impact', 'status', 'mode', 'level', 'urgency', 'priority', 'service_category',
                    'requester', 'site', 'group', 'technician', 'category', 'subcategory', 'item']


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, access_token: str):
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/v3+json',
                                                                        'Authorization': 'Bearer ' + access_token})

    def http_request(self, method, url_suffix, params=None):
        ok_codes = (200, 201, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            # print(url_suffix)
            # print(params)
            res = self._http_request(method, url_suffix, resp_type='response', ok_codes=ok_codes, params=params)
            if res.status_code in [200, 201]:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)

            if res.status_code in [401]:
                try:
                    err_msg = f'Check server URL and access token \n{str(res.json())}'
                except ValueError:
                    err_msg = 'Unauthorized request - check server URL and access token -\n' + str(res)
                raise DemistoException(err_msg)

        except Exception as e:  # todo: change the exception handling
            if '<requests.exceptions.ConnectionError>' in e.args[0]:  # todo: check if this error happens
                raise DemistoException('Connection error - Verify that the server URL parameter is correct and that '
                                       'you have access to the server from your host.\n')
            raise Exception('fails here ' + e.args[0])

    def get_requests(self, request_id: str = None, params: dict = None):
        if request_id:
            return self.http_request(method='GET', url_suffix=f'requests/{request_id}')
        else:
            return self.http_request(method='GET', url_suffix='requests', params=params)

    def ip_report(self, ip: str) -> dict:
        if not is_ip_valid(ip):
            raise DemistoException('The given IP was invalid')
        return self.http_request('GET', f'/ip/{ip}')

    def domain_report(self, domain: str) -> dict:
        return self.http_request('GET', f'/hostname/{domain}')


def create_output(request: dict) -> dict:
    """
    Creates the output for the context and human readable from the response of an http_request

    Args:
        request: The request dict returned from the http_request

    Returns:
        A dictionary containing all valid fields in the request
    """
    output = {}
    for field in REQUEST_FIELDS:
        value = request.get(field, None)
        if value:
            output[string_to_context_key(field)] = value
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
    requests = result.get('requests', [])
    output = []
    context: dict = defaultdict(list)
    for request in requests:
        output.append(create_output(request))
    print(output)
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = output
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
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = output
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
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = output
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
    output = {'link_requests': linked_requests}

    markdown = tableToMarkdown(f'Linked requests to request {request_id}', t=linked_requests)
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = output
    return markdown, context, result


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
    Gets the resolution to the given request

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
    context['ServiceDeskPlus.Request(val.ID===obj.ID)'] = output
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


def test_module(client=None):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Service Desk Plus client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    params = {
        "input_data": '{"list_info": {"row_count":1, "start_index":1, "search_fields":{"subject":"upgrade to catalina","display_id":1, "requester.email_id":"akrupnik@paloaltonetworks.com"}}}'}
    # todo: after adding fetch-incidents, test it here
    try:
        client.http_request('GET', 'requests')
        return 'ok'
    except Exception as e:
        raise e


def main():
    params = demisto.params()
    server_url = params.get('server_url') if params.get('server_url') else SERVER_URL

    client = Client(url=server_url + VERSION,
                    use_ssl=not params.get('insecure', False),
                    use_proxy=params.get('proxy', False),
                    access_token=params.get('access_token'))

    commands = {
        'service-desk-plus-requests-list': list_requests_command,
        'service-desk-plus-request-delete': delete_request_command,
        'service-desk-plus-request-create': create_request_command,
        'service-desk-plus-request-update': update_request_command,
        'service-desk-plus-request-assign': assign_request_command,
        'service-desk-plus-request-pickup': pickup_request_command,
        'service-desk-plus-linked-request-list': linked_request_command,
        'service-desk-plus-request-resolution-add': add_resolution_command,
        'service-desk-plus-request-resolutions-list': get_resolutions_list_command
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        # raise e
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
