import demistomock as demisto
from CommonServerPython import *
import urllib3
from datetime import datetime, timedelta

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'aruba'
PRODUCT = 'central'
MAX_GET_AUDIT_LIMIT = 100  # Maximum limit accepted by get audit events API
MAX_AUDIT_API_REQS = 10
MAX_GET_EVENTS_LIMIT = 1000  # Maximum limit accepted by get events API
MAX_EVENT_API_REQS = 5
AUDIT_TS = 'ts'
NETWORKING_TS = 'timestamp'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the Aruba Central API
    """

    def __init__(self, base_url, client_id, client_secret, user_name, user_password, customer_id, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_name = user_name
        self.user_password = user_password
        self.customer_id = customer_id

    def get_access_token(self):
        """
         Get access token for Aruba Central API.
         If one exists in the integration context and is not expired, returns it.
         Otherwise, refreshes the access token using the refresh token and returns the new token.

         Returns:
             Valid access token to the Aruba Central API.
        """
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        expiry_time = integration_context.get('expiry_time', 0)
        refresh_token = integration_context.get('refresh_token')

        if access_token and expiry_time > int(datetime.now().timestamp()):
            demisto.debug('Returning cached access token')
            return access_token
        elif isinstance(refresh_token, str):
            demisto.debug('Refreshing access token.')
            access_token, refresh_token, validity_duration = self.refresh_access_token(refresh_token)
        else:
            demisto.debug('Acquiring new access token via oauth.')
            access_token, refresh_token, validity_duration = self.oauth_sequence()

        integration_context.update({
            'access_token': access_token,
            'expiry_time': int(datetime.now().timestamp()) + validity_duration,
            'refresh_token': refresh_token
        })
        set_integration_context(integration_context)

        return access_token

    def refresh_access_token(self, refresh_token: str):
        """
        Refreshes the access token using the provided refresh token.

        Args:
            refresh_token (str): Refresh token to be used

        Returns:
            access_token (str): The new access token.
            refresh_token (str): The next refresh token.
            expires_in (int): The validity duration of the new access token in seconds.
        """
        headers = {'Content-Type': 'application/json'}
        params = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        token_resp = self._http_request(
            method='POST',
            url_suffix='/oauth2/token',
            headers=headers,
            params=params,
        )
        return token_resp['access_token'], token_resp['refresh_token'], token_resp['expires_in']

    def oauth_sequence(self):
        """
        Performs the full OAuth sequence to obtain an access token for the Aruba Central API.

        Returns:
            access_token (str): The access token.
            refresh_token (str): The next refresh token.
            validity_duration (int): The validity duration of the access token in seconds.
        """
        csrf_token, session = self.request_login()
        auth_code = self.request_auth_code(csrf_token, session)
        return self.request_access_token(auth_code)

    def request_login(self) -> tuple[str, str]:
        """
        Perform login step in oauth sequence

        Returns:
            csrf_token (str): CSRF token obtained from the login request
            session (str): Session object obtained from login request
        """
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        params = {
            'client_id': self.client_id,
        }
        json_data = {
            'username': self.user_name,
            'password': self.user_password,
        }
        response: requests.Response = self._http_request(
            method='POST',
            url_suffix='/oauth2/authorize/central/api/login',
            headers=headers,
            params=params,
            json_data=json_data,
            resp_type='response',
        )
        csrf_token = response.cookies.get('csrftoken')
        session = response.cookies.get('session')
        if not csrf_token or not session:
            raise DemistoException('Failed to acquire CSRF token and session from login request, check the credentials are valid')
        demisto.debug(f'Login request response: {csrf_token=}, {session=}')
        return csrf_token, session

    def request_auth_code(self, csrf_token: str, session: str) -> str:
        """
        Perform auth code request step in oauth sequence

        Args:
            csfr_token (str): CSRF token obtained from the login request
            session (str): Session object obtained from login request

        Returns:
            auth_code (str): Authorization code obtained from the auth code request
        """
        headers = {
            'Content-Type': 'application/json',
            'X-CSFR-Token': csrf_token,
            'Cookie': f'session={session}',
        }
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'scope': 'read',
        }
        json_data = {
            'customer_id': self.customer_id,
        }
        response = self._http_request(
            method='POST',
            url_suffix='/oauth2/authorize/central/api',
            headers=headers,
            params=params,
            json_data=json_data,
        )
        demisto.debug(f'Auth code request response: {response}')
        return response.get('auth_code')

    def request_access_token(self, auth_code: str) -> tuple[str, str, int]:
        """
        Perform access token request step in oauth sequence

        Args:
            auth_code (str): Authorization code obtained from the auth code request

        Returns:
            access_token (str): The access token obtained from the request
            refresh_token (str): The refresh token obtained from the request
            validity_duration (int): The validity duration of the access token in seconds
        """
        headers = {
            'Content-Type': 'application/json',
        }
        json_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': auth_code,
        }
        response = self._http_request(
            method='POST',
            url_suffix='/oauth2/token',
            headers=headers,
            json_data=json_data,
        )
        demisto.debug(f'Access token request response: {response}')
        return response.get('access_token'), response.get('refresh_token'), response.get('expires_in')

    def http_request(self, method: str, url_suffix: str = '', params: dict = {}):
        """
        Make an http request to the Aruba Central API with the provided parameters.

        Args:
            method (str): HTTP method to use (e.g., 'GET', 'POST')
            url_suffix (str): Suffix to be appended to the base URL
            params (dict): Query parameters to be included in the request

        Returns:
            Response from the Aruba Central API
        """
        headers = {
            'accept': 'application/json',
            'authorization': f'Bearer {self.get_access_token()}',
        }

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            headers=headers,
        )

    def fetch_audit_events(self, start_time: int, end_time: int, amount_to_fetch: int):
        """
        Fetch audit events from Aruba Central API.

        Args:
            start_time (int): Unix timestamp in seconds for the start time of the events to fetch
            end_time (int): Unix timestamp in seconds for the end time of the events to fetch
            amount_to_fetch (int): Amount of events to fetch

        Returns:
            events (list): list of audit events
        """
        if amount_to_fetch > MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT:
            demisto.debug('API requests required to satisfy limit exceeded maximum allowed. Fetching up to the allowed max.')
            amount_to_fetch = MAX_AUDIT_API_REQS * MAX_GET_AUDIT_LIMIT
        events = []
        offset = 0

        demisto.debug(f'{amount_to_fetch=}')
        while amount_to_fetch > 0:
            fetch_size = min(amount_to_fetch, MAX_GET_AUDIT_LIMIT)
            response = self.http_request(
                method='GET',
                url_suffix='/auditlogs/v1/events',
                params={
                    'limit': fetch_size,
                    'offset': offset,
                    'start_time': start_time,
                    'end_time': end_time,
                }
            )

            events.extend(response.get('events', []))
            amount_to_fetch -= fetch_size
            offset += fetch_size
            if not response.get('remaining_records'):
                break

        return events

    def fetch_networking_events(self, start_time: int, end_time: int, amount_to_fetch: int):
        """
        Fetch networking events from Aruba Central API.

        Args:
            start_time (int): Unix timestamp in seconds indicating the start of the fetch window
            end_time (int): Unix timestamp in seconds indicating the end of the fetch window
            amount_to_fetch (int): Amount of events to fetch

        Returns:
            events (list): list of networking events
        """
        if amount_to_fetch > MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT:
            demisto.debug('API requests required to satisfy limit exceeded maximum allowed. Fetching up to the allowed max.')
            amount_to_fetch = MAX_EVENT_API_REQS * MAX_GET_EVENTS_LIMIT
        events = []
        offset = 0

        demisto.debug(f'{amount_to_fetch=}')
        while amount_to_fetch > 0:
            fetch_size = min(amount_to_fetch, MAX_GET_EVENTS_LIMIT)
            response = self.http_request(
                method='GET',
                url_suffix='/monitoring/v2/events',
                params={
                    'limit': fetch_size,
                    'offset': offset,
                    'from_timestamp': start_time,
                    'to_timestamp': end_time,
                    'calculate_total': True,
                }
            )

            events.extend(response.get('events', []))
            amount_to_fetch -= fetch_size
            offset += fetch_size
            if response.get('count') == response.get('total'):  # Got all records for this time frame
                break

        return events


def test_module(client: Client, first_fetch_time: int, fetch_networking_events: bool) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Aruba Central client to use.
        first_fetch_time(str): The first fetch time as configured in the integration params.
        fetch_networking_events (bool): Whether to fetch networking events, as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            num_audit_events_to_fetch=1,
            fetch_networking_events=fetch_networking_events,
            num_networking_events_to_fetch=1,
        )

    except Exception as e:
        if 'Forbidden' in str(e) or 'UNAUTHORIZED' in str(e):
            return 'Authorization Error: make sure credentials are correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, fetch_networking_events: bool, args: dict) -> tuple[List[Dict],
                                                                                   List[Dict] | None, List[CommandResults]]:
    """
    Get events from the Aruba Central API.

    Args:
        client (Client): Aruba Central client to use.
        fetch_networking_events (bool): Whether to fetch networking events, as configured in the integration params.
        args (dict): command arguments.

    Returns:
        audit_events (list[dict]): List of audit events fetched from Aruba Central API.
        networking_events (list[dict] | None): List of networking events fetched from Aruba Central API
        results (list[CommandResults]): List of CommandResults objects to be returned to the war-room.
    """
    limit = arg_to_number(args.get('limit'))
    audit_limit = limit or MAX_GET_AUDIT_LIMIT
    networking_limit = limit or MAX_GET_EVENTS_LIMIT
    if 'from_date' in args:
        start_time = date_to_timestamp(args.get('from_date'))
    else:
        start_time = int((datetime.now() - timedelta(hours=3)).timestamp())

    demisto.debug(f'Running get_events with {start_time=}')
    _, audit_events, networking_events = fetch_events(
        client=client,
        last_run={},
        first_fetch_time=start_time,
        num_audit_events_to_fetch=audit_limit,
        fetch_networking_events=fetch_networking_events,
        num_networking_events_to_fetch=networking_limit,
    )
    audit_hr = tableToMarkdown(name='Audit Events', t=audit_events)
    results = [CommandResults(readable_output=audit_hr)]
    if fetch_networking_events:
        networking_hr = tableToMarkdown(name='Networking Events', t=networking_events)
        results.append(CommandResults(readable_output=networking_hr))

    return audit_events, networking_events, results


def fetch_events(client: Client,
                 last_run: dict[str, str],
                 first_fetch_time: int,
                 num_audit_events_to_fetch: int,
                 fetch_networking_events: bool,
                 num_networking_events_to_fetch: int,
                 ) -> tuple[dict, list[dict], list[dict] | None]:
    """
    Args:
        client (Client): Aruba Central client to use.
        last_run (dict): A dict with a key containing the end time of the last successful fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            seconds on when to start fetching events.
        num_audit_events_to_fetch (int): number of audit events to fetch.
        fetch_networking_events (bool): whether to fetch networking events in addition to audit events.
        num_networking_events_to_fetch (int): number of networking events to fetch.
    Returns:
        next_run(dict): Dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        audit_events(list): List of fetched audit events.
        networking_events(list): List of fetched networking events.
    """
    start_time = date_to_timestamp(last_run['last_fetch_time'],
                                   DATE_FORMAT) if 'last_fetch_time' in last_run else first_fetch_time
    end_time = int(datetime.now().timestamp())
    demisto.debug(f'Fetching {num_audit_events_to_fetch} audit events from {start_time} to {end_time}.')
    audit_events = client.fetch_audit_events(start_time=start_time, end_time=end_time, amount_to_fetch=num_audit_events_to_fetch)
    demisto.debug(f'Got {len(audit_events)} audit events.')
    networking_events = None
    if fetch_networking_events:
        demisto.debug(f'Fetching {num_networking_events_to_fetch} networking events from {start_time} to {end_time}.')
        networking_events = client.fetch_networking_events(start_time=start_time, end_time=end_time,
                                                           amount_to_fetch=num_networking_events_to_fetch)
        demisto.debug(f'Got {len(networking_events)} networking events.')

    next_run = {'last_fetch_time': timestamp_to_datestring(end_time, DATE_FORMAT)}
    demisto.debug(f'Returning {next_run=}.')
    return next_run, audit_events, networking_events


''' MAIN FUNCTION '''


def add_time_to_events(events: List[Dict] | None, time_arg: str):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get(time_arg))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    user_name = params.get('user', {}).get('identifier')
    user_password = params.get('user', {}).get('password')
    customer_id = params.get('customer_id', {}).get('password')
    base_url = params.get('url', '')
    fetch_networking_events = params.get('fetch_networking_events', False)
    max_audit_events_per_fetch = arg_to_number(params.get('max_audit_events_per_fetch')) or MAX_GET_AUDIT_LIMIT
    max_networking_events_per_fetch = arg_to_number(params.get('max_networking_events_per_fetch')) or MAX_GET_EVENTS_LIMIT
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    first_fetch_time = int(datetime.now().timestamp())

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            user_name=user_name,
            user_password=user_password,
            customer_id=customer_id,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client,
                                 first_fetch_time=first_fetch_time,
                                 fetch_networking_events=fetch_networking_events)
            return_results(result)

        elif command == 'aruba-central-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            audit_events, networking_events, results = get_events(client, fetch_networking_events, args)
            return_results(results)

            if should_push_events:
                add_time_to_events(audit_events, AUDIT_TS)
                send_events_to_xsiam(
                    audit_events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

                if networking_events:
                    add_time_to_events(networking_events, NETWORKING_TS)
                    send_events_to_xsiam(
                        networking_events,
                        vendor=VENDOR,
                        product=f'{PRODUCT}_network_events',
                    )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, audit_events, networking_events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                num_audit_events_to_fetch=max_audit_events_per_fetch,
                fetch_networking_events=fetch_networking_events,
                num_networking_events_to_fetch=max_networking_events_per_fetch,
            )

            add_time_to_events(audit_events, AUDIT_TS)
            send_events_to_xsiam(
                audit_events,
                vendor=VENDOR,
                product=PRODUCT
            )

            if networking_events:
                add_time_to_events(networking_events, NETWORKING_TS)
                send_events_to_xsiam(
                    networking_events,
                    vendor=VENDOR,
                    product=f'{PRODUCT}_network_events',
                )

            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
