import sys
from datetime import datetime, timedelta

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR"
TOKEN_TYPE = "Bearer"


class Client(BaseClient):
    def __init__(self, proxy: bool, verify: bool, base_url: str, client_id: str, client_secret: str):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = ""
        self.headers = {}

    def generate_new_access_token(self):
        body = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        return self._http_request(
            method='POST',
            url_suffix="oauth",
            json_data=body
        )

    def save_access_token_to_context(self, auth_response):
        access_token_expiration_in_seconds = auth_response.get("expires_in")
        if access_token_expiration_in_seconds and isinstance(auth_response.get("expires_in"), int):
            access_token_expiration_datetime = datetime.now() + timedelta(seconds=access_token_expiration_in_seconds)
            context = {"access_token": self.access_token, "expires_in": access_token_expiration_datetime}
            set_integration_context(context)
            demisto.debug(
                f"New access token that expires in : {expires_in.strftime(DATE_FORMAT)} w"
                f"as set to integration_context.")
        else:
            return_error(f"HPEArubaClearpass error: Got an invalid access token "
                         f"expiration time from the API: {access_token_expiration_in_seconds} "
                         f"from type: {type(access_token_expiration_in_seconds)}")

    def login(self):
        integration_context = get_integration_context()
        access_token_expiration = integration_context.get('expires_in')
        access_token = integration_context.get('access_token')
        is_context_has_access_token = access_token and access_token_expiration
        if is_context_has_access_token and access_token_expiration > datetime.now():
            self.set_request_headers()
            return

        # if the access is expired or not exist, generate a new one
        auth_response = self.generate_new_access_token()
        access_token = auth_response.get("access_token")
        if access_token:
            self.access_token = access_token
            self.save_access_token_to_context(auth_response)
            self.set_request_headers()
        else:
            return_error("HPE Aruba Clearpass error: The client credentials are invalid.")

    def set_request_headers(self):
        """
        Setting the headers for the future HTTP requests.
        The headers should be: {Authorization: Bearer <access_token>}
        """
        authorization_header_value = f"{TOKEN_TYPE} {self.access_token}"
        self.headers = {"Authorization": authorization_header_value}


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
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


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


def main() -> None:
    params = demisto.params()
    base_url = urljoin(params['url'], '/api')
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(proxy=proxy, verify=verify_certificate, base_url=base_url, client_id=client_id,
                    client_secret=client_secret)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client.login()
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
