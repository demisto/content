import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
from bs4 import BeautifulSoup as bs
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '11.5.6'
VENDOR = 'CyberArk'
PRODUCT = 'EPM'

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, username, password, verify=True, proxy=False, **kwargs):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.username = username
        self.password = password
        self.application_id = kwargs.get('application_id')
        self.authentication_url = kwargs.get('authentication_url')
        self.application_url = kwargs.get('application_url')
        if self.authentication_url and self.application_url:
            self.auth_to_cyber_ark()
        else:
            ...

    def get_session_token(self):
        # Reference: https://developer.okta.com/docs/reference/api/authn/#primary-authentication
        data = {
            "username": self.username,
            "password": self.password,
        }
        result = self._http_request('POST', full_url=self.authentication_url, json_data=data)
        return result.get('sessionToken')

    def get_saml_response(self):
        # Reference: https://devforum.okta.com/t/how-to-get-saml-assertion-through-an-api/24580
        full_url = f'{self.application_url}?onetimetoken={self.get_session_token()}'
        result = self._http_request('POST', full_url=full_url, resp_type='response')
        soup = bs(result.text, features='html.parser')
        saml_response = soup.find("input", {'name': 'SAMLResponse'}).get('value')
        return saml_response

    def auth_to_cyber_ark(self):
        # Reference: https://docs.cyberark.com/EPM/Latest/en/Content/WebServices/SAMLAuthentication.htm
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'SAMLResponse': self.get_saml_response()
        }
        result = self._http_request('POST', headers=headers, data=data)
        if result.get('IsPasswordExpired'):
            return_error('CyberArk is reporting that the user password is expired. Terminating script.')
            raise
        self._base_url = urljoin(result.get('ManagerURL'), '/EPM/API/')
        self._headers['Authorization'] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_set_list(self) -> dict:
        return self._http_request('GET', url_suffix='Sets')

    def get_policy_audits(self, set_id: str) -> dict:
        return self._http_request('POST', url_suffix=f'Sets/{set_id}/policyaudits/search')

    def get_admin_audits(self) -> dict:
        return self._http_request('GET', url_suffix=f'Account/AdminAudit')

    def get_events(self, set_id: str) -> dict:
        return self._http_request('POST', url_suffix=f'Sets/{set_id}/Events/Search')


""" HELPER FUNCTIONS """


def get_set_ids_by_set_names(client: Client) -> list[str]:
    """
    Gets a list of set names and returns a list of set IDs.
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        (list) A list of IDs associated with the names.
    """
    set_names = argToList(demisto.params().get('set_name'))
    context_set_items = get_integration_context().get('set_items', {})

    if context_set_items.keys() != set(set_names):
        result = client.get_set_list()
        context_set_items = {
            set_item.get('Name'): set_item.get('Id')
            for set_item in result.get('Sets', [])
            if set_item.get('Name') in set_names
        }
        set_integration_context({'set_items': context_set_items})

    return list(context_set_items.values())


def get_policy_audits(client: Client) -> list:
    """
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        (list) A list of policy audits associated with a list of set names.
    """
    policy_audits = []
    for set_id in get_set_ids_by_set_names(client):
        events = client.get_policy_audits(set_id).get('events')
        policy_audits.extend(events)
    return policy_audits


def get_admin_audits(client: Client) -> list:
    """
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        (list) A list of admin audits.
    """
    return client.get_admin_audits().get('events')


def get_detailed_events(client: Client):
    """
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        (list) A list of detailed events associated with a list of set names.
    """
    detailed_events = []
    for set_id in get_set_ids_by_set_names(client):
        events = client.get_events(set_id).get('events')
        detailed_events.extend(events)
    return detailed_events


""" COMMAND FUNCTIONS """


def fetch_events(client: Client, max_fetch: int = 5000) -> list:
    """ Fetches 3 types of events from CyberArkEPM
        - policy_audits
        - admin_audits
        - events
    Args:
        client (Client): CyberArkEPM client to use.
        max_fetch (int): The max events to return per fetch default is 5000
    Return:
        (list) A list of events to push to XSIAM
    """
    last_run = demisto.getLastRun()
    demisto.debug(f'Start fetching last run: {last_run}')

    events = get_policy_audits(client) + get_admin_audits(client) + get_detailed_events(client)
    next_run = {}

    demisto.setLastRun(next_run)
    demisto.info(f'Sending len{len(events)} to XSIAM. updated_next_run={next_run}.')

    return events


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    if len(fetch_events(client=client, max_fetch=5)) == 5:
        return 'ok'


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()

    # Parse parameters
    # base_url = urljoin(params.get('url'), f'/EPM/{API_VERSION}')
    base_url = params.get('url')
    application_id = params.get('application_id')
    authentication_url = params.get('authentication_url')
    application_url = params.get('application_url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch', '5000'))

    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=verify_certificate,
            proxy=proxy,
            application_id=application_id,
            authentication_url=authentication_url,
            application_url=application_url,
        )

        get_admin_audits(client)
        result = get_policy_audits(client) + get_detailed_events(client)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-events':
            events = fetch_events(client, max_fetch)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
