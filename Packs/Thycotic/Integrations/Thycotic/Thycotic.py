import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# import json
import requests
# import dateparser
# import time
# from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, server_url: str, username: str, password: str, max_fetch: int):
        super().__init__(base_url=server_url)
        self._username = username
        self._password = password
        self._max_fetch = max_fetch
        self._token = self._generate_token()
        self._headers = {'Authorization': self._token, 'Content-Type': 'application/json'}

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            "username": self._username,
            "password": self._password,
            "grant_type": "password"
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        return "Bearer " + (self._http_request("POST", "/oauth2/token", headers=headers, data=body)).get('access_token')

    def getToken(self):
        return self._token

    def getPasswordById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + secret_id + "/fields/password"
        return self._http_request("GET", url_suffix)

    def getUsernameById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + secret_id + "/fields/username"
        return self._http_request("GET", url_suffix)


def test_module(client: Client,) -> str:
    if client._token == '':
        raise Exception('Dont access token')

    return 'ok'


def authenticate_token_command(client):
    token = client.getToken()

    return CommandResults(
        readable_output=f'Access token for current session: {token}',
        outputs_prefix='Thycotic.authenticate',
        outputs_key_field='token',
        raw_response=token,
        outputs=token
    )


def secret_password_get_command(client, secret_id: str = ''):
    secret_password = client.getPasswordById(secret_id)

    return CommandResults(
        readable_output=f"Retrieved password by ID {secret_id} {secret_password}",
        outputs_prefix='Thycotic.secret',
        outputs_key_field="secret_password",
        raw_response=secret_password,
        outputs=secret_password
    )


def secret_username_get_command(client, secret_id: str = ''):
    secret_username = client.getUsernameById(secret_id)

    return CommandResults(
        readable_output=f"Retrieved username by ID {secret_id} {secret_username}",
        outputs_prefix='Thycotic.secret',
        outputs_key_field="secret_username",
        raw_response=secret_username,
        outputs=secret_username
    )


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    url = demisto.params().get('url')

    max_fetch = demisto.params()['max_fetch']
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(server_url=url, username=username, password=password, max_fetch=int(max_fetch))

        if demisto.command() == 'thycotic-authenticate-token':
            return_results(authenticate_token_command(client))

        elif demisto.command() == 'thycotic-secret-password-get':
            return_results(secret_password_get_command(client, **demisto.args()))

        elif demisto.command() == 'thycotic-secret-username-get':
            return_results(secret_username_get_command(client, **demisto.args()))

        elif demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
