import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

VENDOR = 'Bitwarden'
PRODUCT = 'Password Manager'

DEFAULT_MAX_FETCH = 500
DEFAULT_FIRST_FETCH = '3 days'
DEFAULT_STARTTIME = 10
DEFAULT_ENDTIME = 10
DEFAULT_LIMIT = 10
MINUTES_BEFORE_TOKEN_EXPIRED = 2

AUTHENTICATION_FULL_URL = 'https://identity.bitwarden.com/connect/token'


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token = self.login(client_id, client_secret)

    def login(self, client_id: str, client_secret: str) -> str:
        integration_context = get_integration_context()
        demisto.log(f"{integration_context=}")
        if token := integration_context.get('token'):
            expires_date = integration_context.get('expires')
            if expires_date and not self.is_token_expired(expires_date):
                demisto.log(f"Token is valid: {expires_date=}, {token=}")
                return token

        json_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'client_credentials',
            'scope': 'api.organization'
        }
        return self.create_new_token(json_data)

    def is_token_expired(self, expires_date: str) -> bool:
        utc_now = get_current_time()
        expires_datetime = arg_to_datetime(expires_date)
        return utc_now > expires_datetime

    def create_new_token(self, json_data: dict) -> str:
        access_token_obj = self._http_request(
            method='POST',
            full_url=AUTHENTICATION_FULL_URL,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=json_data
        )

        new_access_token = access_token_obj.get('access_token', '')
        expire_in = arg_to_number(access_token_obj.get('expires_in')) or 1
        self.store_token_in_context(new_access_token, expire_in)

        demisto.log(f"Created new token: {new_access_token=}, {expire_in=}")
        return new_access_token

    def store_token_in_context(self, token: str, expire_in: int) -> None:

        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        set_integration_context(context={
            'token': token,
            'expires': str(expire_date)
        })

    def get_events(self, start_time: datetime = None, end_time: datetime = None, limit: int = DEFAULT_MAX_FETCH) -> List[Dict[
        str, Any]]:
        # params = {'starttime': start_time, 'endtime': end_time, 'expandenums': "true", 'includeacknowledged': "true",
        #           'minimal': "false", 'includebreachurl': "true"}
        # params = {'starttime': start_time.strftime("%H:%M:%S"), 'endtime': end_time.strftime("%H:%M:%S")}

        headers = {
            'Authorization': f'Bearer {self.token}'
        }

        res = self._http_request(
            method='GET',
            url_suffix='/public/events',
            headers=headers,
            # params=params
        )

        return res.get('data')


def test_module(client: Client, first_fetch_time: int) -> str:
    demisto.log("in test module")
    try:
        retrieve_events, last_run = fetch_events(client, max_fetch=1, last_run={}, start_time=first_fetch_time,
                                                 end_time=convert_to_timestamp(datetime.now()))
        demisto.log(f"{retrieve_events=}")
    except DemistoException as e:
        raise e

    return 'ok'


def convert_to_timestamp(date: datetime | None) -> int:
    """Converts datetime to timestamp"""
    if date:
        if isinstance(date, datetime):
            return int(date.timestamp())
        elif isinstance(date, int):
            return int(date)
    return 0


def filter_events(events: List[Dict[str, Any]], last_fetched_pid: int, max_fetch: int) -> List[Dict[str, Any]]:
    """Filters events by ascending pbid and max_fetch"""
    for index, event in enumerate(events):
        if event.get('pbid', 0) > last_fetched_pid:
            return events[index:index + max_fetch]
    return []


def fetch_events(client: Client, max_fetch: int, last_run: Dict[str, Any], start_time: int, end_time: int):
    fetching_start_time = demisto.getLastRun() if demisto.getLastRun() else start_time
    retrieve_events = client.get_events(fetching_start_time, end_time)
    retrieve_events = filter_events(retrieve_events, int(last_run.get('last_fetch_itemId', 0)), max_fetch)
    if retrieve_events:
        # extracting last fetch time and last fetched events.
        last_fetch_time = retrieve_events[-1].get('date')
        last_fetched_itemId = retrieve_events[-1].get('itemId')
        demisto.debug(f'Setting last run to itemId: {last_fetched_itemId} time:{timestamp_to_datestring(last_fetch_time)}')
        last_run = {'last_fetch_time': retrieve_events[-1].get('date'),
                    'last_fetch_itemId': last_fetched_itemId}
    return retrieve_events, last_run


def get_events_command(client: Client, args: Dict[str, Any]) -> tuple[List[Dict[str, Any]], CommandResults]:
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    start_time = None
    end_time = None
    events = client.get_events(start_time=start_time, end_time=end_time, limit=limit)
    if events:
        return events, CommandResults(
            readable_output=tableToMarkdown("Open Incidents", events),
            raw_response=events
        )
    return [], CommandResults(readable_output='No events found')


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions

    :return:
    :rtype:
    """
    print("in main")
    demisto_params = demisto.params()
    base_url = demisto_params.get('url', 'https://api.bitwarden.com')
    client_id = demisto_params.get('credentials', {}).get('identifier')
    client_secret = demisto_params.get('credentials', {}).get('password')
    max_events_per_fetch = arg_to_number(demisto_params.get('max_fetch')) or DEFAULT_MAX_FETCH
    first_fetch_time_timestamp = convert_to_timestamp(arg_to_datetime(demisto_params.get('first_fetch', DEFAULT_FIRST_FETCH)))
    verify_certificate = not demisto_params.get('insecure', False)
    proxy = demisto_params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            client_id=client_id,
            client_secret=client_secret,
            proxy=proxy)
        args = demisto.args()
        if command == 'test-module':
            return_results(test_module(client, first_fetch_time_timestamp))
        elif command == 'bitwarden-get-events':  # rename with bitwarden
            events, results = get_events_command(client=client, args={})
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
        elif demisto.command() == 'fetch-events':
            last_run = demisto.getLastRun()
            events, new_last_run = fetch_events(client=client,
                                                max_fetch=max_events_per_fetch,
                                                start_time=first_fetch_time_timestamp,
                                                end_time=int(datetime.now().timestamp()),
                                                last_run=last_run)
            if events:
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)  # type: ignore
                if new_last_run:
                    demisto.setLastRun(new_last_run)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            return_error('Authorization Error: make sure API Key is correctly set')
        else:
            return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
