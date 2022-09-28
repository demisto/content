from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa

import requests
from typing import Dict


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_SUFFIX = '/products/DEMO/features/'
EDIT_FIELDS = 'id,reference_num,name,description,workflow_status,created_at'
DEFAULT_FIELDS = {'reference_num', 'name', 'id', 'created_at'}
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, headers: dict, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self._headers = headers

    def get_features(self, feature_name: str, fields: str, from_date: str, page: str, per_page: str) -> Dict:
        """
        Retrieves a list of features from AHA
        Args:
            feature_name: str if given it will fetch the feature specified. if not will fetch all features.
            fields: str optional feature fields to retrive from service
            from_date: str format: YYYY-MM-DD get feature created after from_date
            page: str pagination specify the number of the page
            per_page: str pagination specify the number of maximum features per page.
        """
        headers = self._headers
        url_suffix = f'{URL_SUFFIX}{feature_name}?updated_since={from_date}&fields={fields}&page={page}&per_page={per_page}'
        response = self._http_request(method='GET',
                                      url_suffix=url_suffix,
                                      headers=headers, resp_type='json')
        return response

    def edit_feature(self, feature_name: str, fields: Dict) -> Dict:
        """
        Updates fields in a feature from AHA
        Args:
            feature_name: str feature to update
            fields: Dict fields to update
        """
        name = fields.get("name")
        desc = fields.get("description")
        status = fields.get("status")
        payload = {"feature": {"name": name, "description": desc,
                   "workflow_status": {"name": status}}}
        demisto.debug(f"payload: {payload}")
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{feature_name}?fields={EDIT_FIELDS}",
                                      headers=headers, resp_type='json', data=json.dumps(payload))

        return response

    ''' HELPER FUNCTIONS'''


def parse_features(response: dict, fields: set) -> List:
    res_list: List = []
    for res in response:
        curr = parse_feature(res, fields=fields)
        res_list.extend(curr)
    return res_list


def parse_feature(response: dict, fields: set = DEFAULT_FIELDS) -> List:
    ret_dict: Dict = {}
    for curr in fields:
        demisto.info(f"curr: {curr}")
        if curr == 'description':
            ret_dict[curr] = response.get(curr, {}).get('body')
        elif curr == 'workflow_status':
            ret_dict[curr] = response.get(curr, {}).get('name')
        else:
            ret_dict[curr] = response.get(curr, '')
    return [ret_dict]


def string_to_set(fields_as_string: str) -> Set[str]:
    fields_lst = fields_as_string.split(',')
    out_set: Set[str] = set()
    for curr in fields_lst:
        curr = curr.strip()
        out_set.add(curr)
    return out_set


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"""

    message: str = ''
    try:
        result = client.get_features('', set(), '2020-01-01', page='1', per_page='1')
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_features(client: Client, from_date: str, feature_name: str = '',
                 fields: set = set(), page: str = '1', per_page: str = '30') -> CommandResults:
    message: List = []
    req_fields = ','.join(DEFAULT_FIELDS.union(fields))
    try:
        response = client.get_features(feature_name=feature_name, fields=req_fields,
                                       from_date=from_date, page=page, per_page=per_page)
        if response:
            message = parse_features(response['features'], DEFAULT_FIELDS.union(
                fields)) if 'features' in response else parse_feature(response['feature'], DEFAULT_FIELDS.union(fields))
            human_readable = tableToMarkdown('Aha! get features',
                                             message,
                                             removeNull=True)
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message.append('Authorization Error: make sure API Key is correctly set')
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.Feature',
        outputs_key_field='id',
        outputs=message,
        raw_response=response,
        readable_output=human_readable
    )
    return command_results


def edit_feature(client: Client, feature_name: str, fields: Dict) -> CommandResults:
    message: List = []
    try:
        response = client.edit_feature(feature_name=feature_name, fields=fields)
        if response:
            message = parse_feature(response['feature'], fields=string_to_set(EDIT_FIELDS))
            human_readable = tableToMarkdown('Aha! edit feature',
                                             message,
                                             removeNull=True)
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = ['Authorization Error: make sure API Key is correctly set']
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.Feature',
        outputs_key_field='id',
        outputs=message,
        readable_output=human_readable,
        raw_response=response
    )
    return command_results


''' MAIN FUNCTION '''


def main() -> None:

    api_key = demisto.params().get('api_key', {}).get('password', {})
    base_url = urljoin(demisto.params()['url'], '/api/v1')
    proxy = demisto.params().get('proxy', False)
    verify = not demisto.params().get('insecure', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {'Authorization': f"Bearer {api_key}"}
        client = Client(
            headers=headers,
            base_url=base_url,
            proxy=proxy,
            verify=verify)
        command = demisto.command()
        args = demisto.args()

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'aha-get-features':
            from_date = args.get('from_date', '2020-01-01')
            feature_name = args.get('feature_name', '')
            fields_as_string = args.get('fields', '')
            fields = string_to_set(fields_as_string)
            page = args.get('page', '1')
            per_page = args.get('per_page', '30')
            command_result = get_features(client, from_date=from_date, feature_name=feature_name, fields=fields, page=page,
                                          per_page=per_page)
            return_results(command_result)
        elif command == 'aha-edit-feature':
            feature_name = args.get('feature_name', '')
            edit_fields = json.loads(args.get('fields', {}))
            command_result = edit_feature(client, feature_name=feature_name, fields=edit_fields)
            return_results(command_result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
