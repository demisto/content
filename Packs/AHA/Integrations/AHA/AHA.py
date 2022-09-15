# import demistomock as demisto
from dataclasses import dataclass
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, headers: dict, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self._headers = headers

    def list_features(self, fromDate="2020-01-01") -> Dict:
        """
        Retrieves a list of features from AHA
        Args:
        """
        headers = self._headers
        response = self._http_request(method='GET', url_suffix=f"{URL_SUFFIX}?updated_since={fromDate}", headers=headers,
                                      resp_type='json')
        return response

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """
        Updates fields in a feature from AHA
        Args:
        featureName: str feature to update
        fields: Dict fields to update
        """
        payload = '{"feature":<replace>}'.replace("<replace>", json.dumps(fields))
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        response = self._http_request(method='PUT', url_suffix=f"{URL_SUFFIX}{featureName}", headers=headers,
                                      resp_type='json', data=payload)

        return {"dummy": dummy}
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

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


    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
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

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

def get_feature(client: Client, featureName: str) -> str:
    message: str = ''
    try:
        result = client.get_feature(featureName=featureName)
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def edit_feature(client: Client, featureName: str, data: str) -> str:
    message: str = ''
    try:
        result = client.update_feature()
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO implement
def delete_feature(client: Client) -> str:
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

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)
    verify = not demisto.params().get('insecure', False)
    fromDate = demisto.params().get('fromDate', '2020-01-01')
    featureName = demisto.params().get('featureName', '')
    data = demisto.params().get()('fields', '')
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

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'get-all-features':
            result = get_all_features(client, fromDate=fromDate)
            return_results(result)
        elif demisto.command() == 'get-feature':
            result = get_feature(client, featureName=featureName)
            return_results(result)
        elif demisto.command() == 'edit-feature':
            result = edit_feature(client, featureName=featureName, data=data)
            return_results(result)
        elif demisto.command() == 'delete-feature':
            result = delete_feature(client)
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
