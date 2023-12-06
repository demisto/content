import datetime
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
from dateutil import parser
from bs4 import BeautifulSoup as bs
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
MAX_LIMIT = 1000
ADMIN_AUDITS_MAX_LIMIT = 500
MAX_FETCH = 5000
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

    def get_policy_audits(self, set_id: str, from_date: str = '', limit: int = MAX_LIMIT) -> dict:
        url_suffix = f'Sets/{set_id}/policyaudits/search?sortDir=asc&limit={min(limit, MAX_LIMIT)}'
        data = assign_params(filter=f'arrivalTime GE {from_date}')
        return self._http_request('POST', url_suffix=url_suffix, json_data=data)

    def get_admin_audits(self, set_id: str, from_date: str = '', limit: int = ADMIN_AUDITS_MAX_LIMIT) -> dict:
        url_suffix = f'Sets/{set_id}/AdminAudit?datefrom={from_date}&limit={min(limit, ADMIN_AUDITS_MAX_LIMIT)}'
        return self._http_request('GET', url_suffix=url_suffix)

    def get_events(self, set_id: str, from_date: str = '', limit: int = MAX_LIMIT) -> dict:
        url_suffix = f'Sets/{set_id}/Events/Search?sortDir=asc&limit={min(limit, MAX_LIMIT)}'
        data = assign_params(filter=f'arrivalTime GE {from_date}')
        return self._http_request('POST', url_suffix=url_suffix, json_data=data)


""" HELPER FUNCTIONS """


def prepare_datetime(date_time: datetime | str, increase: bool = False) -> str:
    if isinstance(date_time, str):
        date_time = parser.parse(date_time, ignoretz=True)
    if increase:
        date_time += timedelta(milliseconds=1)
    date_time_str = date_time.isoformat(timespec="milliseconds")
    return f'{date_time_str}Z'


def get_set_ids_by_set_names(client: Client) -> list[str]:
    """
    Gets a list of set names and returns a list of set IDs.
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        (dict) A dict of {set_id: events (list events associated with a list of set names)}.
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


def get_policy_audits(client: Client, set_ids_with_from_date: dict, limit: int) -> dict[str, list]:
    """
    Args:
        client (Client): CyberArkEPM client to use.
        set_ids_with_from_date (dict): A dict of set_ids and dates form where to get the events. {'123': '01-02-2023T23:20:50Z'}.
        limit (int): The sum of events to get.
    Returns:
        (dict) A dict of {set_id: events (list events associated with a list of set names)}.
    """
    policy_audits = {}

    for set_id, from_date in set_ids_with_from_date.items():
        result = client.get_policy_audits(set_id, from_date.get('policy_audits'), limit)
        policy_audits[set_id] = result.get('events')
        total_events = result.get('filteredCount')

        while len(policy_audits[set_id]) < total_events and len(policy_audits[set_id]) < limit:
            latest_event_date = policy_audits[set_id][-1].get('arrivalTime')
            result = client.get_policy_audits(set_id, prepare_datetime(latest_event_date, increase=True), limit)
            policy_audits[set_id].extend(result.get('events'))

        policy_audits[set_id] = policy_audits[set_id][:limit]

    return policy_audits


def get_admin_audits(client: Client, set_ids_with_from_date: dict, limit: int) -> dict[str, list]:
    """
    Args:
        client (Client): CyberArkEPM client to use.
        set_ids_with_from_date (dict): A dict of set_ids and dates form where to get the events. {'123': '01-02-2023T23:20:50Z'}.
        limit (int): The sum of events to get.
    Returns:
        (dict) A dict of {set_id: events (list events associated with a list of set names)}.
    """
    admin_audits = {}

    for set_id, from_date in set_ids_with_from_date.items():
        result = client.get_admin_audits(set_id, from_date.get('admin_audits'), limit)
        admin_audits[set_id] = result.get('AdminAudits')
        total_events = result.get('TotalCount')

        while len(admin_audits[set_id]) < total_events and len(admin_audits[set_id]) < limit:
            latest_event_date = max(parser.parse(event.get('EventTime'), ignoretz=True) for event in result.get('AdminAudits'))
            result = client.get_admin_audits(set_id, prepare_datetime(latest_event_date, increase=True), limit)
            admin_audits[set_id].extend(result.get('AdminAudits'))

        admin_audits[set_id] = admin_audits[set_id][:limit]

    return admin_audits


def get_detailed_events(client: Client, set_ids_with_from_date: dict, limit: int) -> dict[str, list]:
    """
    Args:
        client (Client): CyberArkEPM client to use.
        set_ids_with_from_date (dict): A dict of set_ids and dates form where to get the events. {'123': '01-02-2023T23:20:50Z'}.
        limit (int): The sum of events to get.
    Returns:
        (dict) A dict of {set_id: events (list events associated with a list of set names)}.
    """
    detailed_events = {}

    for set_id, from_date in set_ids_with_from_date.items():
        result = client.get_events(set_id, from_date.get('detailed_events'), limit)
        detailed_events[set_id] = result.get('events')
        total_events = result.get('filteredCount')

        while len(detailed_events[set_id]) < total_events and len(detailed_events[set_id]) < limit:
            latest_event_date = result.get('events')[-1].get('arrivalTime')
            result = client.get_policy_audits(set_id, prepare_datetime(latest_event_date, increase=True), limit)
            detailed_events[set_id].extend(result.get('events'))

        detailed_events[set_id] = detailed_events[set_id][:limit]

    return detailed_events


""" COMMAND FUNCTIONS """


def fetch_events(client: Client, max_fetch: int = MAX_FETCH) -> list:
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
    events = []
    next_run = {}
    set_ids = get_set_ids_by_set_names(client)

    if not (last_run := demisto.getLastRun()):
        demisto.debug('First fetch....')
        now = (datetime.now() - timedelta(weeks=50))
        last_run = {
            set_id: {
                'policy_audits': prepare_datetime(now),
                'admin_audits': prepare_datetime(now),
                'detailed_events': prepare_datetime(now),
            } for set_id in set_ids
        }

    demisto.debug(f'Start fetching last run: {last_run}')

    for set_id, policy_audits in get_policy_audits(client, last_run, max_fetch).items():
        if policy_audits:
            events.extend(policy_audits)
            latest_event_date = policy_audits[-1]['arrivalTime']
            if next_run.get(set_id):
                next_run[set_id].update({'policy_audits': prepare_datetime(latest_event_date, increase=True)})
            else:
                next_run[set_id] = {'policy_audits': prepare_datetime(latest_event_date, increase=True)}
        else:
            next_run[set_id] = {'policy_audits': last_run[set_id]['policy_audits']}
    for set_id, admin_audits in get_admin_audits(client, last_run, max_fetch).items():
        if admin_audits:
            events.extend(admin_audits)
            latest_event_date = max(parser.parse(event.get('EventTime'), ignoretz=True) for event in admin_audits)
            if next_run.get(set_id):
                next_run[set_id].update({'admin_audits': prepare_datetime(latest_event_date, increase=True)})
            else:
                next_run[set_id] = {'admin_audits': prepare_datetime(latest_event_date, increase=True)}
        else:
            next_run[set_id] = {'admin_audits': last_run[set_id]['admin_audits']}
    for set_id, detailed_events in get_detailed_events(client, last_run, max_fetch).items():
        if detailed_events:
            events.extend(detailed_events)
            latest_event_date = detailed_events[-1]['arrivalTime']
            if next_run.get(set_id):
                next_run[set_id].update({'detailed_events': prepare_datetime(latest_event_date)})
            else:
                next_run[set_id] = {'detailed_events': prepare_datetime(latest_event_date)}
        else:
            next_run[set_id] = {'detailed_events': last_run[set_id]['detailed_events']}

    demisto.setLastRun(last_run)
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
    fetch_events(client=client, max_fetch=5)
    return 'ok'


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()

    # Parse parameters
    base_url = params.get('url')
    application_id = params.get('application_id')
    authentication_url = params.get('authentication_url')
    application_url = params.get('application_url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = max(arg_to_number(params.get('max_fetch', MAX_FETCH)), 1)

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
