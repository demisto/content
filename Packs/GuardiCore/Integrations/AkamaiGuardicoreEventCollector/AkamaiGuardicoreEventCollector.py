import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any, Dict, Optional

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'akamai'
PRODUCT = 'guardicore'
INTEGRATION_NAME = 'Akamai GuardiCore Event Collector'

''' CLIENT CLASS '''

class Client(BaseClient):
    """
       Client for GuardiCoreV2

       Args:
          username (str): The GuardiCore username for API access.
          password (str): The GuardiCore password for API access.
          base_url (str): The GuardiCore API server URL.
    """

    def __init__(self, proxy: bool, verify: bool, base_url: str, username: str,
                 password: str):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.username = username
        self.password = password
        self.base_url = base_url
        self.access_token = ""
        self._headers = {}

    def login(self):
        integration_context = get_integration_context()

        if self._is_access_token_valid(integration_context):
            access_token = integration_context.get('access_token')
            self._save_access_token(access_token)
        else:
            demisto.debug(
                f"{INTEGRATION_NAME} - Generating a new token (old one isn't valid anymore).")
            self.generate_new_token()

    def _save_access_token(self, access_token: str):
        self.access_token = access_token
        self._headers = {
            "Authorization": f'bearer {access_token}'}

    def _is_access_token_valid(self, integration_context: dict) -> bool:
        access_token_expiration = integration_context.get('expires_in')
        access_token = integration_context.get('access_token')
        demisto.debug(
            f'{INTEGRATION_NAME} - Checking if context has valid access token...'
            + f'expiration: {access_token_expiration}, access_token: {access_token}')
        if access_token and access_token_expiration:
            access_token_expiration_datetime = datetime.strptime(
                access_token_expiration, DATE_FORMAT)
            return access_token_expiration_datetime > datetime.now()
        return False

    def generate_new_token(self):
        token = self.authenticate()
        self.save_jwt_token(token)
        self._save_access_token(token)

    def save_jwt_token(self, access_token: str):
        expiration = get_jwt_expiration(access_token)
        expiration_timestamp = datetime.fromtimestamp(expiration)
        context = {"access_token": access_token,
                   "expires_in": expiration_timestamp.strftime(DATE_FORMAT)}
        set_integration_context(context)
        demisto.debug(
            f"New access token that expires in : {expiration_timestamp.strftime(DATE_FORMAT)}"
            f" was set to integration_context.")

    def authenticate(self):
        body = {
            'username': self.username,
            'password': self.password
        }
        new_token = self._http_request(
            method='POST',
            url_suffix='/authenticate',
            json_data=body)

        if not new_token or not new_token.get('access_token'):
            raise DemistoException(
                f"{INTEGRATION_NAME} error: The client credentials are invalid.")

        new_token = new_token.get('access_token')
        return new_token

    def get_events(self, start_time, end_time, limit, offset) -> List[Dict[str, Any]]:
        """
        Get events from Guardicore API using the modelbreaches endpoint and the start and end time.
        """
        params = {
            "from_time": start_time,
            "to_time": end_time,
            "limit": limit,
            "offset": offset
        }
        print(params)
        data = self._http_request(
            method='GET',
            url_suffix=f'/incidents',
            params=params
        )
        return data['objects']


def get_jwt_expiration(token: str):
    if "." not in token:
        return 0
    jwt_token = base64.b64decode(token.split(".")[1] + '==')
    jwt_token = json.loads(jwt_token)
    return jwt_token.get("exp")


def generate_new_token(self):
    token = self.authenticate()
    self.save_jwt_token(token)
    self._save_access_token(token)


def test_module(client: Client, params: Dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Gurdicore client to use.
        params (Dict): Integration parameters.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.login()

    except Exception as e:
        if 'UNAUTHORIZED' in str(e):
            return 'Authorization Error: make sure the username and password are correctly set'
        else:
            raise e

    return 'ok'


def add_time_to_events(events):
    """ Adds the _time key to the events.

    Args:
        events: list[dict] - list of events to add the _time key to.

    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            event['_time'] = event.get('start_time')


def get_events(client, args):
    """
       Gets events from Guardicore API.
    """
    start_time = date_to_timestamp(
        arg_to_datetime(args.get('from_date', '1 second ago')))
    end_time = date_to_timestamp(
        arg_to_datetime(args.get('to_time'))) if "to_time" in args else int(datetime.now().timestamp() * 1000)
    limit = arg_to_number(args.get("limit", 1000))
    offset = int(args.get('offset', 0))
    events = client.get_events(start_time, end_time, limit, offset)
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, params: dict, last_run: dict) -> List[dict]:
    """
       Fetches events from Guardicore API.
    """
    start_time = date_to_timestamp(arg_to_datetime(last_run.get('from_ts', '1 second')))
    end_time = int(datetime.now().timestamp() * 1000)
    demisto.debug(f'Getting events from: {timestamp_to_datestring(start_time)}, till: {timestamp_to_datestring(end_time)}')
    offset = arg_to_number(last_run.get('offset')) or 0
    limit = arg_to_number(params.get('max_events_per_fetch')) or 1000

    retrieve_events = client.get_events(start_time, end_time, limit, offset)
    demisto.debug(f'Fetched {len(retrieve_events)} events.')

    demisto.setLastRun(
        {'from_ts': end_time} if len(retrieve_events) < limit else {'from_ts': start_time, 'offset': offset + limit}
    )

    return retrieve_events

''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    base_url = urljoin(params.get('url'), '/api/v3.0')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get("proxy", False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(username=username, password=password,
                        base_url=base_url, proxy=proxy, verify=(not verify_certificate))
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        client.login()
        if command == f'{PRODUCT}-get-events':
            should_push_events = argToBoolean(args.get('should_push_events', False))
            events, results = get_events(client, args)  # type: ignore
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun() or {}
            events = fetch_events(
                client,
                params,
                last_run
            )
            add_time_to_events(events)

            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()