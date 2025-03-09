import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'google'
PRODUCT = 'apigee'
DEFAULT_LIMIT = 25000
MILLISECOENDS_CONVERT = 1000
ACCESS_TOKEN_STR = 'access_token'
TOKEN_INITIATE_TIME_STR = 'token_initiate_time'
TOKEN_EXPIRATION_SECONDS_STR = 'token_expiration_seconds'
REFRESH_TOKEN_STR = 'refresh_token'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    :param base_url (str): Saas Security server url.
    :param username (str): Username.
    :param password (str): Password.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    :param org_name (str): the organization name
    :param zone (str): the zone name
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool,
                 org_name: str, zone: str, **kwargs):
        self.username = username
        self.password = password
        self.org_name = org_name
        self.zone = zone

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]

    def get_access_token(self) -> str:
        """
       Obtains access and refresh token from server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new access token are obtained and stored in the integration context.

        Returns:
            str: the access token.
       """
        current_time = time.time()
        integration_context = get_integration_context()
        access_token = integration_context.get(ACCESS_TOKEN_STR)
        token_initiate_time = integration_context.get(TOKEN_INITIATE_TIME_STR, current_time)
        token_expiration_seconds = integration_context.get(TOKEN_EXPIRATION_SECONDS_STR, 0)
        refresh_token = integration_context.get(REFRESH_TOKEN_STR, '')

        if access_token and Client.is_token_valid(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds),
            current_time=current_time
        ):
            return access_token
        # There's no token or it is expired
        access_token, token_expiration_seconds, refresh_token = self.get_token_request(refresh_token)
        integration_context = {
            ACCESS_TOKEN_STR: access_token,
            TOKEN_EXPIRATION_SECONDS_STR: token_expiration_seconds,
            TOKEN_INITIATE_TIME_STR: current_time,
            REFRESH_TOKEN_STR: refresh_token,
        }
        set_integration_context(context=integration_context)
        demisto.info('successfully updated access token')

        return access_token

    def get_token_request(self, refresh_token: str = '') -> tuple[str, str, str]:
        """
        Sends request to retrieve token.

       Returns:
           tuple[str, str]: token and its expiration date
        """
        grant_type = REFRESH_TOKEN_STR if refresh_token else 'password'
        data = {
            'grant_type': grant_type
        }
        if refresh_token:
            data[REFRESH_TOKEN_STR] = refresh_token
        else:
            data['username'] = self.username
            data['password'] = self.password
        # hard-coded value that the API requires in the header.
        # https://docs.apigee.com/api-platform/system-administration/management-api-tokens
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
            'Accept': 'application/json;charset=utf-8',
            'Authorization': 'Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0',
        }
        zone = f'{self.zone}.' if self.zone else ''
        url = f'https://{zone}login.apigee.com/oauth/token'
        token_response = self._http_request('POST', full_url=url, url_suffix='/oauth/token', data=data, headers=headers)
        return token_response.get(ACCESS_TOKEN_STR), token_response.get('expires_in'), token_response.get(REFRESH_TOKEN_STR)

    @staticmethod
    def is_token_valid(token_initiate_time: float, token_expiration_seconds: float, current_time: float) -> bool:
        """
        Check whether a token has expired. A token is considered expired if it reached its expiration date in
        seconds minus a minute.

        for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

        300.0001 - 240 < 120 - 60

        Args:
            token_initiate_time (float): the time in which the token was initiated in seconds.
            token_expiration_seconds (float): the time in which the token should be expired in seconds.
            current_time (float): the current time in seconds

        Returns:
            bool: True if token is valid, False if not.
        """
        return current_time - token_initiate_time < token_expiration_seconds - 60

    def get_logs(self, from_time: int, to_time: int) -> List[Dict[str, Any]]:
        """
        Gets the logs from Apigee

        Args:
            from_time (int): the start time of the logs to retrive
            to_time (int): the end time of the logs to retrive

        Returns:
            List[Dict[str, Any]]: the logs from Apigee
        """
        demisto.debug(f'get_logs {from_time=} {to_time=}')
        res = self.http_request(
            method='GET',
            url_suffix=f'/v1/audits/organizations/{self.org_name}',
            params={'startTime': from_time, 'endTime': to_time, 'expand': True}
        )
        return res


def handle_dedup(logs: List[Dict[str, Any]], events_amount: float, last_timestamp: float) -> None:
    """
    Delete duplicated logs
    Args:
        logs (List[Dict[str,Any]]): the logs from the API
        events_amount (float): the amount of events that happend at the same time as the last fetch timestamp
        last_timestamp (float): the timestamp of the last fetch
    """
    for event in reversed(logs):
        if event.get('timeStamp') == last_timestamp and events_amount > 0:
            events_amount -= 1
            logs.pop()
        else:
            break


def create_events(logs: List[Dict[str, Any]], limit: int, to_time: int) -> tuple[List[Dict[str, Any]], Dict[str, float]]:
    """
    Create a list with the requested length
    Args:
        logs (List[Dict[str,Any]]): the logs from the API
        limit (int): the amount of logs to return.
        to_time (int): the current time in seconds

    Returns:
        Tuple:
            List: A list containing the events.
            List: A dict containing the time of the last run and the amount of events of this time
    """
    # The new logs are at the start of the list, we want to get the oldest relevant logs
    start_list = 0 if len(logs) <= limit else -limit
    events = logs[start_list:]
    time_stamp = events[0].get('timeStamp') if events else 0
    if len(events) == limit:
        to_time = time_stamp  # type: ignore[assignment]
    # could be less than limit and still same
    events_count = 0
    if time_stamp == to_time:
        events_count = sum(event.get('timeStamp') == time_stamp for event in events)
    return events, {'last_fetch_timestamp': to_time, 'last_fetch_events_amount': events_count}


def search_events(client, last_run: Dict[str, float], limit: int) -> tuple[List[Dict[str, Any]], Dict[str, float]]:
    """
    Return the relevant logs
    Args:
        client (Client): client to interact with the service API
        last_run (Dict): A list containing the time of the last run and the amount of events of this time
        limit: (int): the amount of logs to return.
    Returns:
        Tuple:
            List: A list containing the events.
            List: A dict containing the time of the last run and the amount of events of this time
    """
    demisto.debug(f'search_events {last_run=}')
    to_time = int(time.time()) * MILLISECOENDS_CONVERT
    last_fetch = last_run.get('last_fetch_timestamp', to_time)
    logs_response = client.get_logs(last_fetch, to_time)
    logs = logs_response.get('auditRecord', [])
    if not logs:
        return [], {'last_fetch_timestamp': to_time, 'last_fetch_events_amount': 0}

    events_amount = last_run.get('last_fetch_events_amount', 0)
    handle_dedup(logs, events_amount, last_fetch)
    return create_events(logs, limit, to_time)


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): client to interact with the service API
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        search_events(client, last_run={}, limit=DEFAULT_LIMIT)

    except Exception as e:
        if 'usergrid' in str(e):
            return 'Authorization Error: make sure username is correctly set'
        elif 'Invalid Credentials' in str(e):
            return 'Authorization Error: make sure password and organization name are correctly set'
        elif 'signupX' in str(e):
            return 'Authorization Error: make sure zone is correctly set'
        raise e

    return 'ok'


def get_events_command(client: Client, args: dict, max_fetch: int = DEFAULT_LIMIT) -> tuple[List[Dict], CommandResults]:
    """
    Get fetched events
    Args:
        client (Client): client to interact with the service API
        args (dict): function arguments
        max_fetch (int): the amount of logs to get.

    Returns:
         Tuple:
            List: A list containing the events.
            CommandResults: A readable obtaining the events and raw response of the logs
    """
    last_run = {}
    limit = arg_to_number(args.get('limit')) or max_fetch
    from_date = arg_to_datetime(args.get('from_date'))
    if from_date:
        last_run = {'last_fetch_timestamp': int(from_date.timestamp()) * 1000}
    events, _ = search_events(client, last_run, limit)  # type: ignore[arg-type]
    if events:
        hr = tableToMarkdown(name='Audit Logs', t=events)
    else:
        hr = tableToMarkdown(name='There are no log', t=events)
    return events, CommandResults(readable_output=hr, raw_response=events)


def fetch_events(client: Client, last_run: Dict[str, float], limit: int) -> tuple[Dict[str, float], List[Dict]]:
    """
    Fetch events
    Args:
        client (Client): client to interact with the service API
        last_run (dict): A list containing the time of the last run and the amount of events of this time
        limit (int): the amount of logs to fetch.
    Returns:
        Dict: A dict containing the time of the last run and the amount of events of this time
        List: list of events that will be created in XSIAM.
    """
    events, next_fetch = search_events(client, last_run, limit)
    demisto.debug(f'fetch_events: {next_fetch=}')
    return next_fetch, events


''' MAIN FUNCTION '''


def add_time_and_type_to_event(events: List[Dict] = []):
    """
    Adds _time and source_log_type keys to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    """
    for event in events:
        create_time = arg_to_datetime(arg=event.get('timeStamp'), is_utc=True)
        event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None
        event['source_log_type'] = 'audit'


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    username = params['credentials']['identifier']
    password = params['credentials']['password']
    org_name = params.get('org_name', '')
    zone = params.get('zone', '')
    base_url = params.get('url', '')
    proxy = params.get("proxy", False)
    verify_certificate = not params.get('insecure', False)

    demisto.debug(f'Command being called is {command}')
    try:
        max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_LIMIT

        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy,
                        org_name=org_name, zone=zone, username=username, password=password)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'google-apigee-get-events':
            events, results = get_events_command(client, args, max_fetch)
            return_results(results)
            if argToBoolean(args.get('should_push_events')):
                add_time_and_type_to_event(events)
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                limit=max_fetch
            )

            add_time_and_type_to_event(events)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
