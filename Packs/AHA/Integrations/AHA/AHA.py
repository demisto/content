from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa

import requests
from typing import Dict


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_SUFFIX = '/products/DEMO/features/'
RESPONSE_FIELDS = 'reference_num,name,description,workflow_status'
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, headers: dict, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self._headers = headers

    def get_features(self, feature_name: str, from_date: str) -> Dict:
        """
        Retrieves a list of features from AHA
        Args:
            feature_name: str if given it will fetch the feature specified. if not will fetch all features.
            from_date: str format: YYYY-MM-DD
        """
        headers = self._headers
        response = self._http_request(method='GET',
                                      url_suffix=f'{URL_SUFFIX}{feature_name}?updated_since={from_date}&fields={RESPONSE_FIELDS}',
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
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{feature_name}?fields={RESPONSE_FIELDS}",
                                      headers=headers, resp_type='json', data=json.dumps(payload))

        return response

    ''' HELPER FUNCTIONS'''


def parse_features_response(response) -> dict:
    output: dict = {}
    if type(response) is list:
        for res in response:
            output.update(parse_feature_response(res))
    else:
        output = parse_feature_response(response=response)
    return output


def parse_feature_response(response: dict) -> dict:
    return {'Feature Name': response.get('name'), 'Id': response.get('id'),
            'Reference Number': response.get('reference_num'), 'Description': response.get('description'),
            'Status': response.get('workflow_status').get('name')}


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"""

    message: str = ''
    try:
        result = client.get_features('', '2020-01-01')
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

# TODO remove all paloalto mail from yml file


def parse_features(response: dict) -> dict:
    res_dict: dict = {}
    for res in response:
        curr = parse_feature(res)
        res_dict[curr['Reference Number']] = curr
    return res_dict


def parse_feature(response: dict) -> dict:
    return {'Feature Name': response.get('name'), 'Id': response.get('id'),
            'Reference Number': response.get('reference_num'), 'Description': response.get('description').get('body'),
            'Status': response.get('workflow_status').get('name')}


def get_features(client: Client, from_date: str, feature_name: str = '') -> CommandResults:
    message: Dict = {}
    try:
        response = client.get_features(feature_name=feature_name, from_date=from_date)
        if response:
            message = parse_features(response['features']) if 'features' in response else parse_feature(response['feature'])
            human_readable = tableToMarkdown('Aha! get features',
                                             message,
                                             removeNull=True)
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.Features',
        outputs_key_field='id',
        outputs=message,
        raw_response=response,
        readable_output=human_readable
    )
    return command_results


def edit_feature(client: Client, feature_name: str, fields: Dict) -> CommandResults:
    message: str = ''
    try:
        response = client.edit_feature(feature_name=feature_name, fields=fields)
        if response:
            message = parse_feature_response(response['feature'])
            human_readable = tableToMarkdown('Aha! edit feature',
                                             message,
                                             removeNull=True)
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.Edit',
        outputs_key_field='id',
        outputs=message,
        readable_output=human_readable,
        raw_response=response
    )
    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('api_key')

    # get the service API url
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
            command_result = get_features(client, from_date=from_date, feature_name=feature_name)
            return_results(command_result)
        elif command == 'aha-edit-feature':
            feature_name = args.get('feature_name', '')
            fields = json.loads(args.get('fields', {}))
            command_result = edit_feature(client, feature_name=feature_name, fields=fields)
            return_results(command_result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
