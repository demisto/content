import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from dateutil import parser
from bs4 import BeautifulSoup
from itertools import chain
from collections.abc import Callable


""" CONSTANTS """

MAX_LIMIT = 1000
ADMIN_AUDITS_MAX_LIMIT = 500
DEFAULT_LIMIT = 250
MAX_FETCH = 5000
VENDOR = 'CyberArk'
PRODUCT = 'EPM'
XSIAM_EVENT_TYPE = {
    'policy_audits': 'policy audit raw event details',
    'admin_audits': 'set admin audit data',
    'detailed_events': 'detailed raw',
}

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, username, password, application_id, authentication_url=None, application_url=None,
                 verify=True, proxy=False, policy_audits_event_type=None, raw_events_event_type=None):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.username = username
        self.password = password
        self.application_id = application_id
        self.authentication_url = authentication_url
        self.application_url = application_url
        if self.authentication_url and self.application_url:
            self.saml_auth_to_cyber_ark()
        else:
            self.epm_auth_to_cyber_ark()
        self.policy_audits_event_type = policy_audits_event_type
        self.raw_events_event_type = raw_events_event_type

    def epm_auth_to_cyber_ark(self):  # pragma: no cover
        data = {
            "Username": self.username,
            "Password": self.password,
            "ApplicationID": self.application_id or "CyberArkXSOAR",
        }
        result = self._http_request('POST', url_suffix='/EPM/API/Auth/EPM/Logon', json_data=data)
        if result.get('IsPasswordExpired'):
            return_error('CyberArk is reporting that the user password is expired. Terminating script.')
        self._base_url = urljoin(result.get('ManagerURL'), '/EPM/API/')
        self._headers['Authorization'] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_session_token(self) -> str:  # pragma: no cover
        # Reference: https://developer.okta.com/docs/reference/api/authn/#primary-authentication
        data = {
            "username": self.username,
            "password": self.password,
        }
        result = self._http_request('POST', full_url=self.authentication_url, json_data=data)
        demisto.debug(f"result is: {result}")
        if result.get("status", "") != "SUCCESS":
            raise DemistoException(f"Retrieving Okta session token returned status: {result.get('status')},"
                                   f" Check your Okta credentials and make sure the user is not blocked by a role.")
        return result.get('sessionToken')

    def get_saml_response(self) -> str:  # pragma: no cover
        # Reference: https://devforum.okta.com/t/how-to-get-saml-assertion-through-an-api/24580
        full_url = f'{self.application_url}?onetimetoken={self.get_session_token()}'
        result = self._http_request('POST', full_url=full_url, resp_type='response')
        soup = BeautifulSoup(result.text, features='html.parser')
        saml_response = soup.find("input", {'name': 'SAMLResponse'}).get('value')

        return saml_response

    def saml_auth_to_cyber_ark(self):  # pragma: no cover
        # Reference: https://docs.cyberark.com/EPM/Latest/en/Content/WebServices/SAMLAuthentication.htm
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'SAMLResponse': self.get_saml_response()
        }
        result = self._http_request('POST', url_suffix='/SAML/Logon', headers=headers, data=data)
        if result.get('IsPasswordExpired'):
            return_error('CyberArk is reporting that the user password is expired. Terminating script.')
        self._base_url = urljoin(result.get('ManagerURL'), '/EPM/API/')
        self._headers['Authorization'] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_set_list(self) -> dict:
        return self._http_request('GET', url_suffix='Sets')

    def get_admin_audits(self, set_id: str, from_date: str = '', limit: int = ADMIN_AUDITS_MAX_LIMIT) -> dict:
        url_suffix = f'Sets/{set_id}/AdminAudit?dateFrom={from_date}&limit={min(limit, ADMIN_AUDITS_MAX_LIMIT)}'
        return self._http_request('GET', url_suffix=url_suffix)

    def get_policy_audits(self, set_id: str, from_date: str = '', limit: int = MAX_LIMIT, next_cursor: str = 'start') -> dict:
        url_suffix = f'Sets/{set_id}/policyaudits/search?nextCursor={next_cursor}&limit={min(limit, MAX_LIMIT)}'
        filter_params = f'arrivalTime GE {from_date}'
        if self.policy_audits_event_type:
            filter_params += f' AND eventType IN {",".join(self.policy_audits_event_type)}'
        data = assign_params(
            filter=filter_params,
        )
        return self._http_request('POST', url_suffix=url_suffix, json_data=data)

    def get_events(self, set_id: str, from_date: str = '', limit: int = MAX_LIMIT, next_cursor: str = 'start') -> dict:
        url_suffix = f'Sets/{set_id}/Events/Search?nextCursor={next_cursor}&limit={min(limit, MAX_LIMIT)}'
        filter_params = f'arrivalTime GE {from_date}'
        if self.raw_events_event_type:
            filter_params += f' AND eventType IN {",".join(self.raw_events_event_type)}'
        data = assign_params(
            filter=filter_params,
        )
        return self._http_request('POST', url_suffix=url_suffix, json_data=data)


""" HELPER FUNCTIONS """


def create_last_run(set_ids: list, from_date: str) -> dict:
    """
    Gets a list of set_ids and a datetime presentation in str.
    Args:
        set_ids (Any): A datetime presentation in str or as a datetime object.
        from_date (bool): either to increase the datetime with a millisecond (useful for next fetch).
    Returns:
        (dict) A dict with a set_id as a key and a dict with the event type (admin_audits, policy_audits, detailed_events)
            as a key and a dict with `from_date` (from which date the get the event) and `next_cursor` (for the next_fetch)
            for example {
                '123': {
                    'admin_audits': {'from_date': '01-02-2023T23:20:50Z'},
                    'policy_audits': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': 'start'},
                    'detailed_events': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': 'start'},
                }
                '456': {
                    'admin_audits': {'from_date': '01-02-2023T23:20:50Z'},
                    'policy_audits': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': 'start'},
                    'detailed_events': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': 'start'},
                }
            }
    """
    return {
        set_id: {
            'admin_audits': {'from_date': from_date},
            'policy_audits': {'from_date': from_date, 'next_cursor': 'start'},
            'detailed_events': {'from_date': from_date, 'next_cursor': 'start'},
        } for set_id in set_ids
    }


def prepare_datetime(date_time: Any, increase: bool = False) -> str:
    """
    Gets a datetime (string or datetime object) and returns a str in ISO format with milliseconds and Z suffix.
    Args:
        date_time (Any): A datetime presentation in str or as a datetime object.
        increase (bool): either to increase the datetime with a millisecond (useful for next fetch).
    Returns:
        (str) A datetime presentation in str with milliseconds and Z suffix. 01-02-2023T23:20:50.123Z.
    """
    if isinstance(date_time, str):
        date_time = parser.parse(date_time, ignoretz=True)
    if increase:
        date_time += timedelta(milliseconds=1)
    date_time_str = date_time.isoformat(timespec="milliseconds")
    return f'{date_time_str}Z'


def prepare_next_run(set_id: str, event_type: str, last_run: dict, last_fetch: dict):      # pragma: nocover
    """
    Gets a list of events and adds the `_time` and the `eventTypeXsiam` keys.
    Args:
        set_id (str): The set_id that the events are related with.
        event_type (str): The evnet type, (possible values: policy_audits, detailed_events).
        last_run (dict): The last run information should be updated with the last fetch information.
        last_fetch (dict): The last fetch information.
    """
    events = last_fetch.get('events')
    next_cursor = last_fetch.get('next_cursor')

    last_run[set_id][event_type]['next_cursor'] = next_cursor
    if last_fetch.get('next_cursor') == 'start':
        latest_event = max(events, key=lambda x: parser.parse(x.get('_time'), ignoretz=True))  # type: ignore
        from_date_next_fetch = prepare_datetime(latest_event.get('_time'), increase=True)  # type: ignore
        last_run[set_id][event_type]['from_date'] = from_date_next_fetch


def add_fields_to_events(events: list, date_field: str, event_type: str):
    """
    Gets a list of events and adds the `_time` and the `eventTypeXsiam` keys.
    Args:
        events (list): A list of events.
        date_field (str): The date field from which the _time field is taken.
        event_type (str): The event type to set in the eventTypeXsiam field.
    """
    for event in events:
        event['_time'] = event.get(date_field)
        event['source_log_type'] = XSIAM_EVENT_TYPE.get(event_type)


def get_set_ids_by_set_names(client: Client, set_names: list) -> list[str]:
    """
    Gets a list of set names and returns a list of set IDs.
    Args:
        client (Client): CyberArkEPM client to use.
        set_names (list): A list of set names configured in the integration instance.
    Returns:
        (dict) A dict of {set_id: events (list events associated with a list of set names)}.
    """
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


def get_admin_audits(client: Client, last_run_per_id: dict, limit: int) -> dict[str, list]:     # pragma: nocover
    """
    Args:
        client (Client): CyberArkEPM client to use.
        last_run_per_id (dict): A dict of set_ids and dates form where to get the events. {'123': '01-02-2023T23:20:50Z'}.
        limit (int): The maximum events to get.
    Returns:
        (dict) A dict of {set_id: events (list events associated with a list of set names)}.
    """
    admin_audits = {}

    for set_id, last_run in last_run_per_id.items():
        result = client.get_admin_audits(set_id, last_run.get('admin_audits', {}).get('from_date'), limit)
        admin_audits[set_id] = result.get('AdminAudits', [])
        total_events = arg_to_number(result.get('TotalCount', 0))

        while len(admin_audits[set_id]) < total_events and len(admin_audits[set_id]) < limit:  # type: ignore
            latest_event_date = admin_audits[set_id][-1].get('EventTime')
            result = client.get_admin_audits(set_id, prepare_datetime(latest_event_date, increase=True), limit)
            admin_audits[set_id].extend(result.get('AdminAudits', []))

        add_fields_to_events(admin_audits[set_id], 'EventTime', 'admin_audits')

    return admin_audits


def get_events(client_function: Callable, event_type: str, last_run_per_id: dict, limit: int) -> dict[str, dict[str, str | list]]:
    """
    Args:
        client_function (callable): CyberArkEPM client function to use to get the events.
        event_type (str): The events type to fetch.
        last_run_per_id (dict): A dict of set_ids and a dict of dates and next_cursor from where to get the events.
            {'123': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': '123465'}}.
        limit (int): The maximum events to get.
    Returns:
        (dict) A dict of {'set_id': {'events' [list events associated with a list of set names], 'next_cursor': '123456'}}.
    """
    events: dict[str, dict[str, str | list]] = {}

    for set_id, last_run in last_run_per_id.items():
        events[set_id] = {}
        from_date = last_run.get(event_type).get('from_date')
        next_cursor = last_run.get(event_type).get('next_cursor')

        results = client_function(set_id, from_date, limit, next_cursor)
        events[set_id]['events'] = results.get('events', [])

        while (next_cursor := results.get('nextCursor')) and len(events[set_id]['events']) < limit:
            results = client_function(set_id, from_date, limit, next_cursor)
            events[set_id]['events'].extend(results.get('events', []))  # type: ignore

        add_fields_to_events(events[set_id]['events'], 'arrivalTime', event_type)  # type: ignore
        events[set_id]['next_cursor'] = next_cursor or 'start'

    return events


""" COMMAND FUNCTIONS """


def get_events_command(client: Client, event_type: str, last_run: dict, limit: int) -> tuple[list, CommandResults]:
    if event_type == 'admin_audits':
        results = get_admin_audits(client, last_run, limit)  # type: ignore
        events_list = list(chain(*results.values()))
    else:
        if event_type == 'policy_audits':
            results = get_events(client.get_policy_audits, 'policy_audits', last_run, limit)  # type: ignore
        if event_type == 'detailed_events':
            results = get_events(client.get_events, 'detailed_events', last_run, limit)  # type: ignore
        events_list_of_lists = [value.get('events', []) for value in results.values()]  # type: ignore
        events_list = list(chain(*events_list_of_lists))

    human_readable = tableToMarkdown(string_to_table_header(event_type), events_list)

    return events_list, CommandResults(readable_output=human_readable, raw_response=events_list)


def fetch_events(client: Client, last_run: dict, max_fetch: int = MAX_FETCH,
                 enable_admin_audits: bool = False) -> tuple[list, dict]:
    """ Fetches 3 types of events from CyberArkEPM
        - admin_audits
        - policy_audits
        - events
    Args:
        client (Client): CyberArkEPM client to use.
        last_run (dict): The last run information.
        max_fetch (int): The max events to return per fetch default is 250.
        enable_admin_audits (bool): Whether to fetch admin audits events. Defaults is False.
    Return:
        (list, dict) A list of events to push to XSIAM, A dict with information for next fetch.
    """
    events: list = []
    demisto.info(f'Start fetching last run: {last_run}')

    if enable_admin_audits:
        for set_id, admin_audits in get_admin_audits(client, last_run, max_fetch).items():
            if admin_audits:
                last_run[set_id]['admin_audits']['from_date'] = prepare_datetime(admin_audits[-1].get('EventTime'), increase=True)
                events.extend(admin_audits)

    for set_id, policy_audits_last_run in get_events(client.get_policy_audits, 'policy_audits', last_run, max_fetch).items():
        if policy_audits := policy_audits_last_run.get('events', []):
            prepare_next_run(set_id, 'policy_audits', last_run, policy_audits_last_run)
            events.extend(policy_audits)

    for set_id, detailed_events_last_run in get_events(client.get_events, 'detailed_events', last_run, max_fetch).items():
        if detailed_events := detailed_events_last_run.get('events', []):
            prepare_next_run(set_id, 'detailed_events', last_run, detailed_events_last_run)
            events.extend(detailed_events)

    demisto.info(f'Sending len {len(events)} to XSIAM. updated_next_run={last_run}.')

    return events, last_run


def test_module(client: Client, last_run: dict) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): CyberArkEPM client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    fetch_events(client=client, last_run=last_run, max_fetch=5)
    return 'ok'


""" MAIN FUNCTION """


def main():  # pragma: no cover
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    # Parse parameters
    base_url = params.get('url')
    application_id = params.get('application_id')
    authentication_url = params.get('authentication_url')
    application_url = params.get('application_url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    set_names = argToList(params.get('set_name'))
    enable_admin_audits = argToBoolean(params.get('enable_admin_audits', False))
    policy_audits_event_type = argToList(params.get('policy_audits_event_type'))
    raw_events_event_type = argToList(params.get('raw_events_event_type'))
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(args.get('limit') or params.get('max_fetch') or DEFAULT_LIMIT)
    max_limit = arg_to_number(args.get('limit', 5))

    if not 0 < max_fetch <= MAX_FETCH:  # type: ignore
        demisto.debug(f'`max_fetch` is not in the correct value, setting it to {DEFAULT_LIMIT}.')
        max_fetch = DEFAULT_LIMIT

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
            policy_audits_event_type=policy_audits_event_type,
            raw_events_event_type=raw_events_event_type,
        )

        set_ids = get_set_ids_by_set_names(client, set_names)
        if command != 'fetch-events' or not demisto.getLastRun():
            from_date = args.get('from_date') or datetime.now() - timedelta(hours=3)
            last_run = create_last_run(set_ids, prepare_datetime(from_date))
        else:
            last_run = demisto.getLastRun()

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, last_run)
            return_results(result)

        elif command == 'cyberarkepm-get-admin-audits':
            events, command_result = get_events_command(client, 'admin_audits', last_run, max_limit)  # type: ignore
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        elif command == 'cyberarkepm-get-policy-audits':
            events, command_result = get_events_command(client, 'policy_audits', last_run, max_limit)  # type: ignore
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        elif command == 'cyberarkepm-get-events':
            events, command_result = get_events_command(client, 'detailed_events', last_run, max_limit)  # type: ignore
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        elif command in 'fetch-events':
            events, next_run = fetch_events(client, last_run, max_fetch, enable_admin_audits)  # type: ignore
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
