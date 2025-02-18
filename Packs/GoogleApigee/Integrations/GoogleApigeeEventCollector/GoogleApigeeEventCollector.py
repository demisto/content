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
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool,
                 org_name: str, zone: str, api_limit=DEFAULT_LIMIT, **kwargs):
        self.username = username
        self.password = password
        self.org_name = org_name
        self.api_limit = api_limit
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
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

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
        url = f'https://{self.zone}.login.apigee.com/oauth/token'
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

    def search_events(self, max_fetch: int, last_fetch_time: float = 0) -> tuple[List[Dict[str, Any]], Dict[str, float]]:
        """
        Searches for logs using the '/<url_suffix>' API endpoint.
        Args:
            last_time: datetime, The datetime of the last event fetched.
            limit: int, the limit of the results to return. (is received only in zoom-get-events command)
        Returns:
            Tuple:
                str: The time of the latest event fetched.
                List: A list containing the events.
        """
        # add comment - timestamp is id
        # last_fetch, last_timestamp and how many
        from_time = last_fetch_time
        to_time = int(time.time())
        events = []
        logs_response = self.get_logs(from_time, to_time)
        logs = logs_response.get('auditRecord', [])
        events = logs[:max_fetch + 1]
        if not events:
            return events, {'last_run': to_time}

        if len(logs) >= max_fetch:
            next_fetch_time = logs[max_fetch].get('timeStamp')
            for i in range(max_fetch, 0, -1):
                if events[i].get('timeStamp') == next_fetch_time:
                    events.pop()
                else:
                    break
        else:
            next_fetch_time = to_time

        return events, {'last_run': next_fetch_time}


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.g
    """

    try:
        from_time = time.time() - 10000
        client.search_events(max_fetch=DEFAULT_LIMIT, last_fetch_time=from_time)

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get('limit', DEFAULT_LIMIT)
    from_date = arg_to_number(args.get('from_date')) or time.time()
    events, _ = client.search_events(limit, int(from_date))
    hr = tableToMarkdown(name='Audit Logs', t=events)
    return events, CommandResults(readable_output=hr, raw_response=events)


def fetch_events(client: Client, last_run: Dict[str, float], max_events_per_fetch: int
                 ) -> tuple[Dict[str, float], List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    from_time = last_run.get('last_run', 0)
    demisto.info(f"looking for backward events from:{from_time}")
    events, next_fetch_time = client.search_events(max_events_per_fetch, from_time)

    return next_fetch_time, events


''' MAIN FUNCTION '''


def call_send_events_to_xsiam(events: List[Dict] = []):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    for event in events:
        create_time = arg_to_datetime(arg=event.get('timeStamp'), is_utc=True)
        event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None
    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

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
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_LIMIT

        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy,
                        org_name=org_name, zone=zone, username=username, password=password)

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
                max_events_per_fetch=max_fetch,
            )

            call_send_events_to_xsiam(events)
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
