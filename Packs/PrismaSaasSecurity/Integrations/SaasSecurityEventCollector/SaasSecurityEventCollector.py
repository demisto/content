import time

import requests

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import traceback
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SAAS_SECURITY_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
TOKEN_LIFE_TIME = 117

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Saas Security server url.
    :param client_id (str): client ID.
    :param client_secret (str): client secret.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        :return: The http response
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        return super()._http_request(*args, headers=headers, retries=5, status_list_to_retry=[204], **kwargs)

    def get_access_token(self):
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

       :return: Access token that will be added to authorization header.
       :rtype: str
       """
        now = datetime.now()
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        time_issued = integration_context.get('time_issued')

        if access_token and get_passed_mins(now, time_issued) < TOKEN_LIFE_TIME:
            return access_token

        # there's no token or it is expired
        access_token = self.get_token_request()
        integration_context = {'access_token': access_token, 'time_issued': date_to_timestamp(now) / 1000}
        set_integration_context(integration_context)
        return access_token

    def get_token_request(self):
        """
        Sends request to retrieve token.

       :return: Access token.
       :rtype: str
        """
        base64_encoded_creds = b64_encode(f'{self.client_id}:{self.client_secret}')
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded; charset=ISO-8859-1',
            'Authorization': f'Basic {base64_encoded_creds}',
        }
        params = {
            'grant_type': 'client_credentials',
            'scope': 'api_access',
        }
        token_response = self._http_request('POST', url_suffix='/oauth/token', params=params, headers=headers)
        return token_response.get('access_token')

    def get_events_request(self):
        url_suffix = '/api/v1/log_events'
        return self.http_request('GET', url_suffix=url_suffix, resp_type='response')


''' HELPER FUNCTIONS '''


def get_passed_mins(start_time, end_time_str, tz=None):
    """
    Calculates the amount of minutes passed between 2 dates.
    :param start_time: Start time in datetime
    :param end_time_str: End time in str

    :return: The passed minutes.
    :rtype: int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str, tz)
    return time_delta.seconds / 60


''' COMMAND FUNCTIONS '''


def test_module(client):
    response = client.get_events_request()
    if response.status_code in (200, 204):
        return 'ok'


def get_events_command(client: Client) -> list:
    events = []
    res = client.get_events_request()
    if res.status_code == 200:
        events.append(res.json())
    else:
        while res.status_code == 204:
            response = client.get_events_request()
            demisto.debug(f'This is the response status code - {response.status_code}')
            if response.status_code == 200:
                events.append(response.json())
                break
    return events


def main() -> None:
    params = demisto.params()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            results = test_module(client)
            return_outputs(results)

        elif command in ('saas-security-get-events', 'fetch-events'):
            events = get_events_command(client)
            if command == 'saas-security-get-events':
                if events:
                    command_results = CommandResults(
                        readable_output=tableToMarkdown('SaaS Security Logs', events, headerTransform=pascalToSpace),
                        raw_response=events,
                    )
                else:
                    command_results = 'No logs were found.'
                return_results(command_results)

            send_events_to_xsiam(events=events, vendor='Palo Alto', product='saas-security')
    except Exception as e:
        raise Exception(f'Error in Palo Alto Saas Security Event Collector Integration [{e}]')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
