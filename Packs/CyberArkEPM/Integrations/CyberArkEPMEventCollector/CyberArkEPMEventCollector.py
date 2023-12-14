import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from dateutil import parser
from bs4 import BeautifulSoup
from itertools import chain


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
    def __init__(self, base_url, username, password, application_id, authentication_url, application_url,
                 verify=True, proxy=False):
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
        elif self.application_id:
            self.epm_auth_to_cyber_ark()
        else:
            return_error('Either the application id or the authentication url and application url is required to authenticate')
            raise

    def epm_auth_to_cyber_ark(self):
        data = {
            "Username": self.username,
            "Password": self.password,
            "ApplicationID": self.application_id,
        }
        result = self._http_request('POST', url_suffix='/EPM/API/Auth/EPM/Logon', data=data)
        if result.get('IsPasswordExpired'):
            return_error('CyberArk is reporting that the user password is expired. Terminating script.')
            raise
        self._base_url = urljoin(result.get('ManagerURL'), '/EPM/API/')
        self._headers['Authorization'] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_session_token(self) -> str:
        # Reference: https://developer.okta.com/docs/reference/api/authn/#primary-authentication
        data = {
            "username": self.username,
            "password": self.password,
        }
        result = self._http_request('POST', full_url=self.authentication_url, json_data=data)
        return result.get('sessionToken')

    def get_saml_response(self) -> str:
        # Reference: https://devforum.okta.com/t/how-to-get-saml-assertion-through-an-api/24580
        full_url = f'{self.application_url}?onetimetoken={self.get_session_token()}'
        result = self._http_request('POST', full_url=full_url, resp_type='response')
        soup = BeautifulSoup(result.text, features='html.parser')
        saml_response = soup.find("input", {'name': 'SAMLResponse'}).get('value')
        return saml_response

    def saml_auth_to_cyber_ark(self):
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
            raise
        self._base_url = urljoin(result.get('ManagerURL'), '/EPM/API/')
        self._headers['Authorization'] = f"basic {result.get('EPMAuthenticationResult')}"

    def get_set_list(self) -> dict:
        return self._http_request('GET', url_suffix='Sets')

    def get_admin_audits(self, set_id: str, from_date: str = '', limit: int = ADMIN_AUDITS_MAX_LIMIT) -> dict:
        url_suffix = f'Sets/{set_id}/AdminAudit?dateFrom={from_date}&limit={min(limit, ADMIN_AUDITS_MAX_LIMIT)}'
        return self._http_request('GET', url_suffix=url_suffix)

    def get_policy_audits(self, set_id: str, from_date: str = '', limit: int = MAX_LIMIT, next_cursor: str = 'start') -> dict:
        url_suffix = f'Sets/{set_id}/policyaudits/search?nextCursor={next_cursor}&limit={min(limit, MAX_LIMIT)}'
        data = assign_params(filter=f'arrivalTime GE {from_date}')
        return self._http_request('POST', url_suffix=url_suffix, json_data=data)

    def get_events(self, set_id: str, from_date: str = '', limit: int = MAX_LIMIT, next_cursor: str = 'start') -> dict:
        url_suffix = f'Sets/{set_id}/Events/Search?nextCursor={next_cursor}&limit={min(limit, MAX_LIMIT)}'
        data = assign_params(filter=f'arrivalTime GE {from_date}')
        return self._http_request('POST', url_suffix=url_suffix, json_data=data)


""" HELPER FUNCTIONS """


def create_last_run(set_ids: list, from_date: str) -> dict:
    return {
        set_id: {
            'admin_audits': {'from_date': from_date},
            'policy_audits': {'from_date': from_date, 'next_cursor': 'start'},
            'detailed_events': {'from_date': from_date, 'next_cursor': 'start'},
        } for set_id in set_ids
    }


def prepare_datetime(date_time: Any, increase: bool = False) -> str:
    if isinstance(date_time, str):
        date_time = parser.parse(date_time, ignoretz=True)
    if increase:
        date_time += timedelta(milliseconds=1)
    date_time_str = date_time.isoformat(timespec="milliseconds")
    return f'{date_time_str}Z'


def add_fields_to_events(events: list, date_field: str, event_type: str):
    for event in events:
        event['_time'] = event.get(date_field)
        event['eventTypeXsiam'] = XSIAM_EVENT_TYPE.get(event_type)


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


def get_admin_audits(client: Client, last_run_per_id: dict, limit: int) -> dict[str, list]:
    """
    Args:
        client (Client): CyberArkEPM client to use.
        last_run_per_id (dict): A dict of set_ids and dates form where to get the events. {'123': '01-02-2023T23:20:50Z'}.
        limit (int): The sum of events to get.
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


def get_policy_audits(client: Client, last_run_per_id: dict, limit: int) -> dict[str, dict[str, Any]]:
    """
    Args:
        client (Client): CyberArkEPM client to use.
        last_run_per_id (dict): A dict of set_ids and dates or next_cursor from where to get the events.
            {'123': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': '123465'}}.
        limit (int): The sum of events to get.
    Returns:
        (dict) A dict of {'set_id': {'events' [list events associated with a list of set names], 'next_cursor': '123456'}}.
    """
    policy_audits: dict[str, dict[str, str | list]] = {}

    for set_id, last_run in last_run_per_id.items():
        policy_audits[set_id] = {'events': [], 'next_cursor': ''}
        from_date = last_run.get('policy_audits').get('from_date')
        next_cursor = last_run.get('policy_audits').get('next_cursor')

        results = client.get_policy_audits(set_id, from_date, limit, next_cursor)
        policy_audits[set_id]['events'] = results.get('events', [])

        while (next_cursor := results.get('nextCursor')) and len(policy_audits[set_id]['events']) < limit:
            results = client.get_policy_audits(set_id, from_date, limit,  next_cursor)
            policy_audits[set_id]['events'].extend(results.get('events', []))

        add_fields_to_events(policy_audits[set_id]['events'], 'arrivalTime', 'policy_audits')
        policy_audits[set_id]['next_cursor'] = next_cursor or 'start'

    return policy_audits


def get_detailed_events(client: Client, last_run_per_id: dict, limit: int) -> dict[str, dict[str, Any]]:
    """
    Args:
        client (Client): CyberArkEPM client to use.
        last_run_per_id (dict): A dict of set_ids and dates or next_cursor from where to get the events.
            {'123': {'from_date': '01-02-2023T23:20:50Z', 'next_cursor': '123465'}}.
        limit (int): The sum of events to get.
    Returns:
        (dict) A dict of {'set_id': {'events' [list events associated with a list of set names], 'next_cursor': '123456'}}.
    """
    detailed_events: dict[str, dict[str, str | list]] = {}

    for set_id, last_run in last_run_per_id.items():
        detailed_events[set_id] = {'events': [], 'next_cursor': ''}
        from_date = last_run.get('detailed_events').get('from_date')
        next_cursor = last_run.get('detailed_events').get('next_cursor')

        results = client.get_events(set_id, from_date, limit, next_cursor)
        detailed_events[set_id]['events'] = results.get('events', [])

        while (next_cursor := results.get('nextCursor')) and len(detailed_events[set_id]['events']) < limit:
            results = client.get_events(set_id, from_date, limit,  next_cursor)
            detailed_events[set_id]['events'].extend(results.get('events', []))

        add_fields_to_events(detailed_events[set_id]['events'], 'arrivalTime', 'detailed_events')
        detailed_events[set_id]['next_cursor'] = next_cursor or 'start'

    return detailed_events


""" COMMAND FUNCTIONS """


def get_admin_audits_command(client: Client, last_run: dict, args: dict) -> tuple[list, CommandResults]:
    limit = arg_to_number(args.get('limit', 5))

    results = get_admin_audits(client, last_run, limit)  # type: ignore
    events_list = list(chain(*results.values()))
    human_readable = tableToMarkdown('Admin Audits', events_list)

    return events_list, CommandResults(readable_output=human_readable, raw_response=events_list)


def get_policy_audits_command(client: Client, last_run: dict, args: dict) -> tuple[list, CommandResults]:
    limit = arg_to_number(args.get('limit', 5))

    results = get_policy_audits(client, last_run, limit)  # type: ignore
    events_list_of_lists = [value.get('events') for value in results.values()]
    events_list = list(chain(*events_list_of_lists))
    human_readable = tableToMarkdown('Policy Audits', events_list)

    return events_list, CommandResults(readable_output=human_readable, raw_response=events_list)


def get_detailed_events_command(client: Client, last_run: dict, args: dict) -> tuple[list, CommandResults]:
    limit = arg_to_number(args.get('limit', 5))

    results = get_detailed_events(client, last_run, limit)  # type: ignore
    events_list_of_lists = [value.get('events') for value in results.values()]
    events_list = list(chain(*events_list_of_lists))
    human_readable = tableToMarkdown('Events', events_list)

    return events_list, CommandResults(readable_output=human_readable, raw_response=events_list)


def fetch_events(client: Client, last_run: dict, max_fetch: int = MAX_FETCH) -> tuple[list, dict]:
    """ Fetches 3 types of events from CyberArkEPM
        - admin_audits
        - policy_audits
        - events
    Args:
        client (Client): CyberArkEPM client to use.
        last_run (dict): The last run
        max_fetch (int): The max events to return per fetch default is 5000
    Return:
        (list) A list of events to push to XSIAM
    """
    events: list = []
    demisto.info(f'Start fetching last run: {last_run}')

    for set_id, admin_audits in get_admin_audits(client, last_run, max_fetch).items():
        if admin_audits:
            last_run[set_id]['admin_audits']['from_date'] = prepare_datetime(admin_audits[-1].get('EventTime'), increase=True)
            events.extend(admin_audits)

    for set_id, policy_audits_last_run in get_policy_audits(client, last_run, max_fetch).items():
        if policy_audits := policy_audits_last_run.get('events'):
            last_run[set_id]['policy_audits']['next_cursor'] = policy_audits_last_run.get('next_cursor')
            if policy_audits_last_run.get('next_cursor') == 'start':
                latest_event = max(policy_audits, key=lambda x: parser.parse(x.get('_time'), ignoretz=True))
                last_run[set_id]['policy_audits']['from_date'] = prepare_datetime(latest_event.get('_time'), increase=True)
            events.extend(policy_audits)

    for set_id, detailed_events_last_run in get_detailed_events(client, last_run, max_fetch).items():
        if detailed_events := detailed_events_last_run.get('events'):
            last_run[set_id]['detailed_events']['next_cursor'] = detailed_events_last_run.get('next_cursor')
            if detailed_events_last_run.get('next_cursor') == 'start':
                latest_event = max(detailed_events, key=lambda x: parser.parse(x.get('_time'), ignoretz=True))
                last_run[set_id]['detailed_events']['from_date'] = prepare_datetime(latest_event.get('_time'), increase=True)
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
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(args.get('limit') or params.get('max_fetch') or DEFAULT_LIMIT)

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
            events, command_result = get_admin_audits_command(client, last_run, args)
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        elif command == 'cyberarkepm-get-policy-audits':
            events, command_result = get_policy_audits_command(client, last_run, args)
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        elif command == 'cyberarkepm-get-events':
            events, command_result = get_detailed_events_command(client, last_run, args)
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(command_result)

        elif command in 'fetch-events':
            events, next_run = fetch_events(client, last_run, max_fetch)  # type: ignore
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
