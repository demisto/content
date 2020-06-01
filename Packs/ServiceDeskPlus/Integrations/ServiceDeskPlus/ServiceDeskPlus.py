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


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, access_token: str):
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/v3+json',
                                                                        'Authorization': 'Bearer ' + access_token})

    def http_request(self, method, url_suffix, params=None):
        ok_codes = (200, 401)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient
        try:
            print(url_suffix)
            print(params)
            res = self._http_request(method, url_suffix, resp_type='response', ok_codes=ok_codes, params=params)
            if res.status_code == 200:
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

        except Exception as e:
            if '<requests.exceptions.ConnectionError>' in e.args[0]:  # todo: check if this error happens
                raise DemistoException('Connection error - Verify that the server URL parameter is correct and that '
                                       'you have access to the server from your host.\n')
            raise e

    def get_requests(self, request_id: str = None, params: dict = None):
        if request_id:
            print(request_id, type(request_id))
            return self.http_request(method='GET', url_suffix=f'requests/{request_id}')
        else:
            return self.http_request(method='GET', url_suffix='requests', params=params)

    def ip_report(self, ip: str) -> dict:
        if not is_ip_valid(ip):
            raise DemistoException('The given IP was invalid')
        return self.http_request('GET', f'/ip/{ip}')

    def domain_report(self, domain: str) -> dict:
        return self.http_request('GET', f'/hostname/{domain}')


def get_requests_command(client: Client, args: dict):
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
    input_data = {'input_data': f'{list_info}'}
    print(client.get_requests(request_id, input_data))


def delete_request_command(client: Client, args: dict):
    """
    Delete the request with the given request_id

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    request_id = args.get('request_id')
    print(client.http_request('DELETE', url_suffix=f'requests/{request_id}'))


def create_list_info(start_index, row_count, search_fields, filter_by):
    list_info = {}
    if start_index is not None:
        list_info['start_index'] = start_index
    if row_count is not None:  # checking 'if row_count' will cause skipping when row_count = 0
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
        'service-desk-plus-requests-list': get_requests_command,
        'service-desk-plus-request-delete': delete_request_command
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
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
