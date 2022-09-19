# import demistomock as demisto
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

    def list_features(self, fromDate: str = "2020-01-01") -> Dict:
        """
        Retrieves a list of features from AHA
        Args:
        """
        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f"{URL_SUFFIX}?updated_since={fromDate}", headers=headers,
                                      resp_type='json')
        return response

    def get_feature(self, featureName: str, fieldsList: Optional[List]) -> Dict:
        """
        Retrieves a specific feature from AHA
        Args:
        featureName: str
        """
        headers = self._headers
        url_suffix = f"{URL_SUFFIX}{featureName}"
        if fieldsList:
            fields = ",".join(fieldsList)
            url_suffix = f"{url_suffix}?fields={fields}"
        response = self._http_request(method='GET', url_suffix=url_suffix, headers=headers,
                                      resp_type='json')
        return response

    def update_feature(self, featureName: str, fields: Dict) -> Dict:
        """
        Updates fields in a feature from AHA
        Args:
        featureName: str feature to update
        fields: Dict fields to update
        """
        name = fields.get("name")
        desc = fields.get("description")
        status = fields.get("status")
        payload = {"feature": {"name": name, "description": desc,
                   "workflow_status": {"name": status}}}
        demisto.info(f"DANF payload: {payload}")
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{featureName}", headers=headers,
                                      resp_type='json', data=json.dumps(payload))

        return response


    def close_feature(self, featureName: str) -> Dict:
        """
        Sets a Aha! feature status to Closed
        Args:
        featureName: str feature staus to close
        """
        payload = '{"feature":{"workflow_status": {"name": "Closed" }}}'
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{featureName}", headers=headers,
                                      resp_type='json', data=payload)
        return response


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"""

    message: str = ''
    try:
        result = client.list_features()
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_all_features(client: Client, fromDate: str) -> CommandResults:
    message: str = ''
    try:
        result = client.list_features(fromDate=fromDate)
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


def get_feature(client: Client, featureName: str, fieldsList: Optional[List] = None) -> CommandResults:
    message: str = ''
    try:
        result = client.get_feature(featureName=featureName, fieldsList=fieldsList)
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


def edit_feature(client: Client, featureName: str, fields: Dict) -> CommandResults:
    message: str = ''
    try:
        result = client.update_feature(featureName=featureName, fields=fields)
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


def close_feature(client: Client, featureName: str) -> CommandResults:
    message: str = ''
    try:
        result = client.close_feature(featureName=featureName)
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

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    # verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)
    verify = not demisto.params().get('insecure', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {'Authorization': f"Bearer {api_key}"}
    # def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool):

        client = Client(
            headers=headers,
            base_url=base_url,
            proxy=proxy,
            verify=verify)
        command = demisto.command()
        args = demisto.args()

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == 'get-all-features':
            fromDate = args.get('fromDate', '2020-01-01')
            commandResult = get_all_features(client, fromDate=fromDate)
            return_results(commandResult)
        elif command == 'get-feature':
            featureName = args.get('featureName', '')
            commandResult = get_feature(client, featureName=featureName)
            return_results(commandResult)
        elif command == 'edit-feature':
            featureName = args.get('featureName', '')
            fields = json.loads(args.get('fields', {}))
            demisto.info(f"DANF \nfeatureName:{featureName}\n fields:{fields}")
            commandResult = edit_feature(client, featureName=featureName, fields=fields)
            return_results(commandResult)
        elif command == 'close-feature':
            featureName = args.get('featureName', '')
            commandResult = close_feature(client, featureName=featureName)
            return_results(commandResult)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
