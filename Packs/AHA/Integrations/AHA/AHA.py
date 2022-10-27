from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]  # pylint: disable=no-member

''' CONSTANTS '''
REPLACE = 'replace'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_SUFFIX_PATTERN = f'/products/{REPLACE}/features/'
EDIT_FIELDS = ['id', 'reference_num', 'name', 'description', 'workflow_status', 'created_at']
DEFAULT_FIELDS = ['reference_num', 'name', 'id', 'created_at']

''' CLIENT CLASS '''


class Client(BaseClient):
    url = ''

    def __init__(self,
                 headers: dict,
                 base_url: str,
                 proxy: bool,
                 verify: bool,
                 url: str):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self.url = url
        self._headers['Content-Type'] = 'application/json'

    def get_features(self,
                     feature_name: str,
                     fields: str,
                     from_date: str,
                     page: str,
                     per_page: str) -> Dict:
        """
        Retrieves a list of features from AHA
        Args:
            feature_name: str if given it will fetch the feature specified. if not, it will fetch all features.
            fields: str optional feature fields to retrive from the service.
            from_date: str format: YYYY-MM-DD get features created after from_date.
            page: str pagination specify the number of the page.
            per_page: str pagination specify the maximum number of features per page.
        """
        headers = self._headers
        params = {
            'updated_since': from_date,
            'fields': fields,
            'page': page,
            'per_page': per_page,
        }
        return self._http_request(method='GET',
                                  url_suffix=f'{self.url}{feature_name}',
                                  headers=headers, params=params, resp_type='json')

    def edit_feature(self, feature_name: str, fields: Dict) -> Dict:
        """
        Updates fields in a feature from AHA
        Args:
            feature_name: str feature to update
            fields: Dict fields to update
        """
        payload = extract_payload(fields=fields)
        demisto.debug(f'Edit feature payload: {payload}')
        fields = ','.join(EDIT_FIELDS)
        return self._http_request(method='PUT', url_suffix=f'{self.url}{feature_name}?fields={fields}',
                                  resp_type='json', json_data=payload)


''' HELPER FUNCTIONS'''


def extract_payload(fields: Dict):
    payload: Dict = {'feature': {}}
    for field in fields:
        feature = payload.get('feature', {})
        if field == 'status':
            workflow_status = {'name': fields[field]}
            feature['workflow_status'] = workflow_status
        else:
            feature[field] = fields[field]
    return payload


def parse_features(features: dict, fields: List) -> List:
    res_list = []
    for res in features:
        curr = parse_feature(res, fields=fields)
        res_list.extend(curr)
    demisto.debug(f'Parsed response fields: {res_list}')
    return res_list


def parse_feature(feature: dict, fields: List = DEFAULT_FIELDS) -> List:
    ret_dict = {}
    for curr in fields:
        if curr == 'description':
            ret_dict[curr] = feature.get(curr, {}).get('body')
        elif curr == 'workflow_status':
            ret_dict[curr] = feature.get(curr, {}).get('name')
        else:
            ret_dict[curr] = feature.get(curr, '')
    return [ret_dict]


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"""

    message: str = ''
    try:
        result = client.get_features('', '', '2020-01-01', page='1', per_page='1')
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure that the API Key is setup correctly.'
        else:
            raise e
    return message


def get_features(client: Client,
                 from_date: str,
                 feature_name: str = '',
                 fields: List = [],
                 page: str = '1',
                 per_page: str = '30') -> CommandResults:
    message: List = []
    req_fields = ','.join(DEFAULT_FIELDS + fields)
    response = client.get_features(feature_name=feature_name, fields=req_fields,
                                   from_date=from_date, page=page, per_page=per_page)
    if response:
        if 'features' in response:
            message = parse_features(response['features'], DEFAULT_FIELDS + fields)
        else:
            message = parse_feature(response['feature'], DEFAULT_FIELDS + fields)
        human_readable = tableToMarkdown('Aha! get features',
                                         message,
                                         removeNull=True)
    return CommandResults(
        outputs_prefix='AHA.Feature',
        outputs_key_field='id',
        outputs=message,
        raw_response=response,
        readable_output=human_readable
    )


def edit_feature(client: Client,
                 feature_name: str,
                 fields: Dict) -> CommandResults:
    message: List = []
    response = client.edit_feature(feature_name=feature_name, fields=fields)
    if response:
        message = parse_feature(response['feature'], fields=EDIT_FIELDS)
        human_readable = tableToMarkdown('Aha! edit feature',
                                         message,
                                         removeNull=True)
    return CommandResults(
        outputs_prefix='AHA.Feature',
        outputs_key_field='id',
        outputs=message,
        readable_output=human_readable,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    base_url = urljoin(params['url'], '/api/v1')
    project_name = params.get('project_name', {})
    url = URL_SUFFIX_PATTERN.replace(REPLACE, project_name)
    api_key = params.get('api_key', {}).get('password', {})
    proxy = params.get('proxy', False)
    verify = not params.get('insecure', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {'Authorization': f'Bearer {api_key}'}
        client = Client(
            headers=headers,
            base_url=base_url,
            proxy=proxy,
            verify=verify,
            url=url)
        command = demisto.command()
        args = demisto.args()

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'aha-get-features':
            from_date = args.get('from_date', '2020-01-01')
            feature_name = args.get('feature_name', '')
            fields = argToList(args.get('fields', ''))
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
