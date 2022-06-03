"""Cisco Umbrella Reporting v2 Integration for Cortex XSOAR (aka Demisto)
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    def __init__(self, base_url, verify, headers, proxy, org_id):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy, ok_codes=(200))
        self.org_id = org_id

    def get_summary(self, start: str = '', end: str = '') -> Dict[str, str]:
        """Returns a summary of top identities, destinations, URLs, categories, threats, threat types, events
        and IPs being observed in your environment within a specific timeframe.
        """
        if start == '' and end == '':
            uri = f'{self._base_url}/organizations/{self.org_id}/summary'
        else:
            uri = f'{self._base_url}/organizations/{self.org_id}/summary?from={start}&to={end}'
        response = self._http_request('GET', uri)
        response_data = response.get('data', {})
        return response_data

    def list_top_threats(self, start: str = '', end: str = '') -> List[Dict]:
        """Returns a List of top threats within timeframe based on both DNS and
        Proxy data.
        """
        if start == '' and end == '':
            uri = f'{self._base_url}/organizations/{self.org_id}/top-threats'
        else:
            uri = f'{self._base_url}/organizations/{self.org_id}/top-threats?from={start}&to={end}'
        response = self._http_request('GET', uri)
        response_data = response.get('data', {})
        return response_data


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

    try:
        client.get_summary()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_summary_command(client: Client, args: dict) -> CommandResults:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    """
    start = args.get('start', '')
    end = args.get('end', '')
    response = client.get_summary(start=start, end=end)
    readable_output = tableToMarkdown(t=response, name='Summary', headers=['object', 'count'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='UmbrellaReporting.Summary',
        outputs_key_field='object',
        outputs=response
    )


def list_top_threats_command(client: Client, args: dict) -> CommandResults:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    """
    start = args.get('start', '')
    end = args.get('end', '')
    response = client.list_top_threats(start=start, end=end)
    readable_output = tableToMarkdown(t=response, name='Top Threats', headers=['threat', 'threat_type', 'count'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='UmbrellaReporting.TopThreats',
        outputs_key_field='threat',
        outputs=response
    )


class UmbrellaAuthAPI:
    def __init__(self, url, ident, secret):
        self.url = url
        self.ident = ident
        self.secret = secret
        self.token = None

    def get_access_token(self):
        auth = HTTPBasicAuth(self.ident, self.secret)
        client = BackendApplicationClient(client_id=self.ident)
        oauth = OAuth2Session(client=client)
        self.token = oauth.fetch_token(token_url=self.url, auth=auth)
        return self.token


''' MAIN FUNCTION '''


def main() -> None:
    token_url = demisto.params().get('token_url')
    org_id = demisto.params().get('orgId')

    api_key = demisto.params().get('apiKey')
    api_secret = demisto.params().get('apiSecret')

    base_url = demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    commands = {
        'umbrella-get-summary': get_summary_command,
        'umbrella-list-top-threats': list_top_threats_command,
    }

    try:

        product_auth = UmbrellaAuthAPI(token_url, api_key, api_secret)
        access_token = product_auth.get_access_token()["access_token"]
        headers: Dict = {
            "Authorization": f"Bearer {access_token}"
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            org_id=org_id)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
