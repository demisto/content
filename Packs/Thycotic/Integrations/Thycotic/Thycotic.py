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
        return "Bearer " + (self._http_request("POST", "/oauth2/token", headers=headers, data=body))['access_token']

    def getToken(self):
        return self._token

    def getPasswordById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + secret_id + "/fields/password"
        return self._http_request("GET", url_suffix)

    def getUsernameById(self, secret_id: str) -> str:
        url_suffix = "/api/v1/secrets/" + secret_id + "/fields/username"
        return self._http_request("GET", url_suffix)

#    def list_incidents(self):
#        return [
#            {
#                'incident_id': 1,
#                'description': 'Thycotic incident 1',
#                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
#            },
#            {
#                'incident_id': 2,
#                'description': 'Thycotic incident 2',
#                'created_time': datetime.utcnow().strftime(DATE_FORMAT)
#            }
#        ]


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


# def fetch_incidents(client, last_run, first_fetch_time):
#    last_fetch = last_run.get('last_fetch')
#
#   # Handle first time fetch
#    if last_fetch is None:
#        last_fetch, _ = dateparser.parse(first_fetch_time)
#    else:
#        last_fetch = dateparser.parse(last_fetch)
#
#    latest_created_time = last_fetch
#    incidents = []
#    items = client.list_incidents()
#    for item in items:
#        incident_created_time = dateparser.parse(item['created_time'])
#        incident = {
#            'name': item['description'],
#            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
#            'rawJSON': json.dumps(item)
#        }
#
#        incidents.append(incident)
#
#        # Update last run and add incident if the incident is newer than last fetch
#        if incident_created_time > latest_created_time:
#            latest_created_time = incident_created_time
#
#    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
#    return next_run, incidents


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    url = demisto.params()['url']

#    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
#    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()
    max_fetch = demisto.params()['max_fetch']

#    proxy = demisto.params().get('proxy', False)

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

#         elif demisto.command() == 'fetch-incidents':
#            # Set and define the fetch incidents command to run after activated via integration settings.
#            next_run, incidents = fetch_incidents(
#                client=client,
#                last_run=demisto.getLastRun(),
#                first_fetch_time=first_fetch_time)
#
#            demisto.setLastRun(next_run)
#            demisto.incidents(incidents)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
