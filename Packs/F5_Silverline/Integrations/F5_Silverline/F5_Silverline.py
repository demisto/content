import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
BASE_URL = "/api/v1/ip_lists"
TABLE_HEADERS_GET_OBJECTS = ['ID', 'IP', 'Expires At', 'List Target', 'Created At', 'Updated At']
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, headers: dict, proxy: bool):
        """
        Client for CyberInt RESTful API.

        Args:
            base_url (str): URL to access when getting alerts.
            access_token (str): Access token for authentication.
            verify_ssl (bool): specifies whether to verify the SSL certificate or not.
            proxy (bool): specifies if to use XSOAR proxy settings.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._headers = headers

    def request_ip_objects(self, body: dict, method: str, url_suffix: str, params: dict, resp_type='json') -> Dict:
        """Returns a
        """
        return self._http_request(method=method, json_data=body, url_suffix=url_suffix, params=params,
                                  headers=self._headers, resp_type=resp_type)


def test_module(client: Client) -> str:
    """
    """
    try:
        client.request_ip_objects(body={}, method='GET', url_suffix='denylist/ip_objects', params={})
        message = 'ok'
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def paging_args_to_params(page_size, page_number):
    params = {}
    try:
        page_size = int(page_size)
        page_number = int(page_number)
    except ValueError:
        raise ValueError("page_number and page_size should be numbers")

    params['page[size]'] = page_size
    params['page[number]'] = page_number
    return params


def add_ip_objects_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    # TODO handle the bad_actor list_type
    list_type = args.get('list_type')
    list_target = args.get('list_target', 'proxy')
    ip_address = args.get('IP')
    mask = args.get('mask', '32')
    duration = args.get('duration', 0)
    note = args.get('note', "")
    tags = argToList(args.get('tags', []))
    url_suffix = f'{list_type}/ip_objects'

    body = {"list_target": list_target, "data": {"id": "", "type": "ip_objects",
                                                 "attributes": {"mask": mask, "ip": ip_address, "duration": duration},
                                                 "meta": {"note": note, "tags": tags}}}
    human_readable = f"IP object with IP address: {ip_address} created successfully."

    client.request_ip_objects(body=body, method='POST', url_suffix=url_suffix, params={}, resp_type='content')
    return CommandResults(readable_output=human_readable)


def delete_ip_objects_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    # TODO handle the bad_actor list_type
    list_type = args.get('list_type')
    object_id = args.get('object_id')
    url_suffix = f'{list_type}/ip_objects/{object_id}'

    client.request_ip_objects(body={}, method='DELETE', url_suffix=url_suffix, params={}, resp_type='content')
    human_readable = f"IP object with ID: {object_id} deleted successfully."
    return CommandResults(readable_output=human_readable)


def get_ip_objects_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    # TODO handle the bad_actor list_type
    list_type = args.get('list_type')
    object_ids = argToList(args.get('object_id'))
    page_number = args.get('page_number')
    page_size = args.get('page_size')
    url_suffix = f'{list_type}/ip_objects'
    params = {}
    is_paging = False
    if page_number and page_size:
        params = paging_args_to_params(page_size, page_number)
        is_paging = True

    if not object_ids:
        response = client.request_ip_objects(body={}, method='GET', url_suffix=url_suffix, params=params)
        outputs = [response]
        human_results = parse_results_for_specific_ip_object(response)

    else:
        human_results, outputs = get_ip_objects_by_ids(client, object_ids, list_type, params)

    human_readable = tableToMarkdown('F5 Silverline IP Objects', human_results, TABLE_HEADERS_GET_OBJECTS,
                                     removeNull=True)

    if not human_results and is_paging:
        human_readable = "No results were found. Please try to run the command without page_number and page_size to " \
                         "get all the data."

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='F5Silverline.IPObjectList',
        outputs_key_field='id',
        outputs=outputs
    )


def get_ip_objects_by_ids(client, object_ids, list_type, params):
    human_results = []
    outputs = []
    for object_id in object_ids:
        url_suffix = f'{list_type}/ip_objects'
        url_suffix = '/'.join([url_suffix, object_id])
        res = client.request_ip_objects(body={}, method='GET', url_suffix=url_suffix, params=params)
        human_results.append(parse_results_for_specific_ip_object(res)[0])
        outputs.append(res.get('data'))
    return human_results, outputs


def parse_results_for_specific_ip_object(results: Dict):
    parsed_results = []
    results_data = results.get('data')
    if isinstance(results_data, dict):
        results_data = [results_data]
    for data in results_data:
        if data:
            parsed_results.append({
                'ID': data.get('id'),
                'IP': data.get('attributes').get('ip'),
                'Expires At': data.get('attributes').get('expires_at'),
                'List Target': data.get('attributes').get('list_target'),
                'Created At': data.get('meta').get('created_at'),
                'Updated At': data.get('meta').get('updated_at')
            })
    return parsed_results


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    access_token = params.get('token')
    base_url = urljoin(params.get('url'), BASE_URL)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {"X-Authorization-Token": access_token, "Content-Type": 'application/json'}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'f5-silverline-ip-objects-list':
            return_results(get_ip_objects_list_command(client, demisto.args()))

        elif demisto.command() == 'f5-silverline-ip-object-add':
            return_results(add_ip_objects_command(client, demisto.args()))

        elif demisto.command() == 'f5-silverline-ip-object-delete':
            return_results(delete_ip_objects_command(client, demisto.args()))


    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
