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
DEFAULT_LIMIT = 5000
MILLISECOENDS_CONVERT = 1000

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
    :param limit (int): the maximum logs to return per fetch call
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool,
                 org_name: str, zone: str, limit: int = DEFAULT_LIMIT, **kwargs):
        self.username = username
        self.password = password
        self.org_name = org_name
        self.max_fetch = limit
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
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        token_initiate_time = integration_context.get('token_initiate_time')
        token_expiration_seconds = integration_context.get('token_expiration_seconds')

        if access_token and Client.is_token_valid(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token
        # TODO: add refresh to token?
        # There's no token or it is expired
        access_token, token_expiration_seconds = self.get_token_request()
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.info('successfully updated access token')
        set_integration_context(context=integration_context)

        return access_token

    def get_token_request(self) -> tuple[str, str]:
        """
        Sends request to retrieve token.

       Returns:
           tuple[str, str]: token and its expiration date
        """
        data = {
            'username': self.username,
            'password': self.password,
            'grant_type': 'password'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
            'Accept': 'application/json;charset=utf-8',
            'Authorization': 'Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0'

        }
        zone = f'{self.zone}.' if self.zone else ''
        url = f'https://{zone}login.apigee.com/oauth/token'
        token_response = self._http_request('POST', full_url=url, url_suffix='/oauth/token', data=data, headers=headers)
        return token_response.get('access_token'), token_response.get('expires_in')

    @staticmethod
    def is_token_valid(token_initiate_time: float, token_expiration_seconds: float) -> bool:
        """
        Check whether a token has expired. A token is considered expired if it reached its expiration date in
        seconds minus a minute.

        for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

        300.0001 - 240 < 120 - 60

        Args:
            token_initiate_time (float): the time in which the token was initiated in seconds.
            token_expiration_seconds (float): the time in which the token should be expired in seconds.

        Returns:
            bool: True if token has expired, False if not.
        """
        return time.time() - token_initiate_time < token_expiration_seconds - 60

    def get_logs(self, from_date, to_time: int) -> Any:
        res = self.http_request(
            method='GET',
            url_suffix=f'/v1/audits/organizations/{self.org_name}',
            params={'startTime': from_date, 'endTime': to_time, 'expand': True}
        )
        return res


def search_events(client, last_run: Dict[str, float]) -> tuple[List[Dict[str, Any]], Dict[str, float]]:
    """
    Searches for logs using the '/<url_suffix>' API endpoint.
    Note: it seems that this API use timestamp as ID (we still handle duplicate timestamp situation)
    Args:
        client (Client): client to interact with the service API
        last_run (Dict): A list containing the time of the last run and the amount of events of this time
        limit: int, the limit of the results to return. (is received only in zoom-get-events command)
    Returns:
        Tuple:
            List: A list containing the events.
            List: A dict containing the time of the last run and the amount of events of this time
    """
    last_fetch = last_run.get('last_fetch')
    to_time = int(time.time()) * MILLISECOENDS_CONVERT
    events_count = 0
    logs_response = client.get_logs(last_fetch, to_time)
    logs = logs_response.get('auditRecord', [])
    if not logs:
        return [], {'last_fetch': to_time, 'events_amount': events_count}
    events_amount = last_run.get('events_amount', 0)
    for event in reversed(logs):
        if event.get('timeStamp') == last_fetch and events_amount > 0:
            events_amount -= 1
            logs.pop()
        else:
            break
    limit = 0 if len(logs) <= client.max_fetch else -client.max_fetch
    events = logs[limit:]
    time_stamp = events[1].get('timeStamp') if events else 0
    if len(events) == client.max_fetch:
        to_time = time_stamp
    # could be less than limit and still same
    if time_stamp == to_time:
        events_count = sum(1 for event in events if event.get('timeStamp') == time_stamp)
    return events, {'last_fetch': to_time, 'events_amount': events_count}


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): client to interact with the service API
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.g
    """

    try:
        from_time = int(time.time() * MILLISECOENDS_CONVERT) - 10000
        search_events(client, last_run={'last_fetch': from_time})

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    """
    get fetched events
    Args:
        client (Client): client to interact with the service API
        args (dict): function arguments

    Returns:
         Tuple:
            List: A list containing the events.
            CommandResults: A readable ontaining the events and raw response of the logs
    """
    from_date = arg_to_number(args.get('from_date')) or int(time.time() * MILLISECOENDS_CONVERT)
    events, _ = search_events(client, {'last_fetch': from_date})
    hr = tableToMarkdown(name='Audit Logs', t=events)
    return events, CommandResults(readable_output=hr, raw_response=events)


def fetch_events(client: Client, last_run: Dict[str, float]) -> tuple[Dict[str, float], List[Dict]]:
    """
    Args:
        client (Client): client to interact with the service API
        last_run (dict): A list containing the time of the last run and the amount of events of this time
    Returns:
        Dict: A dict containing the time of the last run and the amount of events of this time
        List: list of events that will be created in XSIAM.
    """
    events, next_fetch = search_events(client, last_run)
    demisto.debug(f'fetch: {next_fetch}')
    return next_fetch, events


''' MAIN FUNCTION '''


def call_send_events_to_xsiam(events: List[Dict] = []):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    """
    for event in events:
        create_time = arg_to_datetime(arg=event.get('timeStamp'), is_utc=True)
        event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    username = params['client']['identifier']
    password = params['client']['password']
    org_name = params.get('org_name', '')
    zone = params.get('zone', '')
    base_url = params.get('url', '')
    proxy = params.get("proxy", False)
    verify_certificate = not params.get('insecure', False)

    demisto.debug(f'Command being called is {command}')
    try:
        limit = arg_to_number(params.get('limit')) or DEFAULT_LIMIT

        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy,
                        org_name=org_name, zone=zone, username=username, password=password, limit=limit)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'google-apigee-get-events':
            events, results = get_events(client, demisto.args())
            return_results(results)
            should_push_events = argToBoolean(args.get('should_push_events'))
            if should_push_events:
                call_send_events_to_xsiam(events)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
            )

            call_send_events_to_xsiam(events)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
