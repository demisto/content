from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa

import requests
from typing import Dict


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_SUFFIX = '/products/DEMO/features/'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, headers: dict, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self._headers = headers

    def get_features(self, from_date: str = "2020-01-01") -> Dict:
        """
        Retrieves a list of features from AHA
        Args:
            from_date: str format: YYYY-MM-DD
        """
        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f"{URL_SUFFIX}?updated_since={from_date}", headers=headers,
                                      resp_type='json')
        return response

    def get_feature(self, feature_name: str, fields_list: Optional[List]) -> Dict:
        """
        Retrieves a specific feature from AHA
        Args:
            feature_name: str
        """
        headers = self._headers
        url_suffix = f"{URL_SUFFIX}{feature_name}"
        if fields_list:
            fields = ",".join(fields_list)
            url_suffix = f"{url_suffix}?fields={fields}"
        response = self._http_request(method='GET', url_suffix=url_suffix, headers=headers,
                                      resp_type='json')
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
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{feature_name}", headers=headers,
                                      resp_type='json', data=json.dumps(payload))

        return response

    def close_feature(self, feature_name: str) -> Dict:
        """
        Sets a Aha! feature status to Closed
        Args:
            feature_name: str feature staus to close
        """
        payload = '{"feature":{"workflow_status": {"name": "Closed" }}}'
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{feature_name}", headers=headers,
                                      resp_type='json', data=payload)
        return response


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"""

    message: str = ''
    try:
        result = client.get_features()
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_features(client: Client, from_date: str) -> CommandResults:
    message: str = ''
    try:
        result = client.get_features(from_date=from_date)
        if result:
            message = result['features']
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.ActionStatus',
        outputs_key_field='',
        outputs=message,
        raw_response=message
    )
    return command_results


def get_feature(client: Client, feature_name: str, fields_list: Optional[List] = None) -> CommandResults:
    message: str = ''
    try:
        result = client.get_feature(feature_name=feature_name, fields_list=fields_list)
        if result:
            message = result['feature']
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.ActionStatus',
        outputs_key_field='',
        outputs=message,
        raw_response=message
    )
    return command_results


def edit_feature(client: Client, feature_name: str, fields: Dict) -> CommandResults:
    message: str = ''
    try:
        result = client.edit_feature(feature_name=feature_name, fields=fields)
        if result:
            message = result['feature']
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.ActionStatus',
        outputs_key_field='',
        outputs=message,
        raw_response=message
    )
    return command_results


def close_feature(client: Client, feature_name: str) -> CommandResults:
    message: str = ''
    try:
        result = client.close_feature(feature_name=feature_name)
        if result:
            message = result['feature']
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix='AHA.ActionStatus',
        outputs_key_field='',
        outputs=message,
        raw_response=message
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
            command_result = get_features(client, from_date=from_date)
            return_results(command_result)
        elif command == 'aha-get-feature':
            feature_name = args.get('feature_name', '')
            command_result = get_feature(client, feature_name=feature_name)
            return_results(command_result)
        elif command == 'aha-edit-feature':
            feature_name = args.get('feature_name', '')
            fields = json.loads(args.get('fields', {}))
            command_result = edit_feature(client, feature_name=feature_name, fields=fields)
            return_results(command_result)
        elif command == 'aha-close-feature':
            feature_name = args.get('feature_name', '')
            command_result = close_feature(client, feature_name=feature_name)
            return_results(command_result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
