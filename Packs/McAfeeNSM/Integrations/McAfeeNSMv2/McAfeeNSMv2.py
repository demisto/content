
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any
import base64

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url: str, auth: tuple, headers: Dict, proxy: bool = False, verify: bool = True):
        self.url = url
        self.headers = headers
        super().__init__(base_url=url, verify=verify, proxy=proxy, auth=auth, headers=headers)

    def get_session_request(self, encoded_str: str) -> Dict:
        """ Gets a session from the API.
            Args:
                encoded_str: str - The string that contains username:password in base64
            Returns:
                A dictionary with the session details.
        """
        url_suffix = '/sdkapi/session'
        self.headers['NSM-SDK-API'] = encoded_str
        return self._http_request(method='GET', url_suffix=url_suffix)


''' HELPER FUNCTIONS '''


def encode_to_base64(str_to_convert: str) -> str:
    b = base64.b64encode(bytes(str_to_convert, 'utf-8'))  # bytes
    base64_str = b.decode('utf-8')  # convert bytes to string
    return base64_str


''' COMMAND FUNCTIONS '''


def test_module(client: Client, encoded_str: str) -> str:
    """ Test the connection to McAfee NSM.
    Args:
        client: A McAfeeNSM client.
        encoded_str: str - The string that contains username:password in base64
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_session_request(encoded_str)
        return 'ok'
    except DemistoException as e:
        raise Exception(e.message)


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    url = demisto.params().get('url')
    user_name = demisto.params().get('credentials', {}).get('identifier', "")
    password = demisto.params().get('credentials', {}).get('password', "")
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    auth = (user_name, password)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        client = Client(url=url, auth=auth, headers=headers, proxy=proxy, verify=verify_certificate)
        user_name_n_password_encoded = encode_to_base64(f'{user_name}:{password}')

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, user_name_n_password_encoded)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
