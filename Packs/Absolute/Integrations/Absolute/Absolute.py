import hashlib

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from urllib.parse import urlparse
import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

ABSOLUTE_URL_TO_API_URL = {
    'https://cc.absolute.com': 'https://api.absolute.com',
    'https://cc.us.absolute.com': 'https://api.us.absolute.com',
    'https://cc.eu2.absolute.com': 'https://api.eu2.absolute.com',
}
INTEGRATION = "Absolute"
STRING_TO_SIGN_ALGORITHM = "ABS1-HMAC-SHA-256"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, token_id: str, secret_key: str, verify: bool, headers: dict, proxy: bool):
        """
        Client to use in the Absolute integration. Overrides BaseClient.

        Args:
            base_url (str): URL to access when doing a http request.
            token_id (str): The Absolute token id
            secret_key (str): User's Absolute secret key
            verify (bool): Whether to check for SSL certificate validity.
            proxy (bool): Whether the client should use proxies.
            headers (dict): Headers to set when doing a http request.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._api_url = None
        self._base_url = base_url
        self._token_id = token_id
        self._secret_key = secret_key
        self._headers = headers

    def validate_absolute_api_url(self):
        if self._base_url not in ABSOLUTE_URL_TO_API_URL.keys():
            DemistoException(f"{INTEGRATION} Error: The Absolute server url {self._base_url} in not a valid url.")
        self._api_url = ABSOLUTE_URL_TO_API_URL[self._base_url]

    def prepare_request_for_api(self, method: str, canonical_uri: str, query_string: str, payload: str):
        """
        The Absolute v2 API requires following 5 steps in order to properly authorize the API request.
        We must follow the steps:
        1. Create a canonical request
        2. Create a signing string
        3. Create a signing key
        4. Create a signature
        5. Add the authorization header

        For more info https://www.absolute.com/media/2221/abt-api-working-with-absolute.pdf
        """
        canonical_req = self.create_canonical_request(method, canonical_uri, query_string, payload)

    def create_canonical_request(self, method: str, canonical_uri: str, query_string: str, payload: str) -> str:
        """
        The canonical request should look like (for example):

        GET
        /v2/reporting/devices
        %24filter=substringof%28%2760001%27%2C%20esn%29%20eq%20true
        host:api.absolute.com
        content-type:application/json
        x-abs-date:20170926T172213Z
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        canonical_request = [method, canonical_uri, self.prepare_query_string_for_canonical_request(query_string),
                             self.prepare_canonical_headers(), self.prepare_canonical_hash_payload(payload)]
        return "\n".join(canonical_request)

    def prepare_query_string_for_canonical_request(self, query_string: str) -> str:
        """
        Query is given as a string represents the filter query. For example,
        query_string = "$top=10 $skip=20"
        1. Splitting into a list (by space as a separator).
        2. Sorting arguments in ascending order; for example, 'A' is before 'a'.
        3. URI encode the parameter name and value using URI generic syntax.
        4. Reassembling the list into a string.
        """
        if not query_string:
            return ""
        query_list = query_string.split()
        query_list.sort()
        encoded_query_list = [urllib.parse.quote(query.encode('utf-8'), safe='=') for query in query_list]
        return '&'.join(encoded_query_list)

    def prepare_canonical_headers(self) -> str:
        canonical_headers = ""
        for header, value in self._headers.items():
            canonical_headers += f'{header.lower()}:{value.strip()}\n'
        return canonical_headers

    def prepare_canonical_hash_payload(self, payload) -> str:
        """
        According to the API we should do:
        Hash the entire body using SHA-256 algorithm, HexEncode, and apply lowercase
        If there is no payload, use an empty string
        """
        if not payload:
            return ""
        return hashlib.sha256(payload).hexdigest().lower()

    def create_signing_string(self):
        """
        The signing string should look like (for example):

        ABS1-HMAC-SHA-256
        20170926T172032Z
        20170926/cadc/abs1
        63f83d2c7139b6119d4954e6766ce90871e41334c3f29b6d64201639d273fa19
        """
        requested_date_time = date_to_timestamp(datetime.now(), DATE_FORMAT)


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

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

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


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()

    base_url = urljoin(params.get('url'), '/v2')
    token_id = params.get('token')
    secret_key = params.get('secret_key', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
