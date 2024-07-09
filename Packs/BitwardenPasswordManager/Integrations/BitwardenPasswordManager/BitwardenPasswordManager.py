import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

VENDOR = 'Bitwarden'
PRODUCT = 'Password Manager'

DEFAULT_MAX_FETCH = 500
DEFAULT_FIRST_FETCH = '2024-07-01T14:16:34Z'
MINUTES_BEFORE_TOKEN_EXPIRED = 2

AUTHENTICATION_FULL_URL = 'https://identity.bitwarden.com/connect/token'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.token = self.login(client_id, client_secret)

    def login(self, client_id: str, client_secret: str) -> str:
        integration_context = get_integration_context()
        if token := integration_context.get('token'):
            expires_date = integration_context.get('expires')
            if expires_date and not self.is_token_expired(expires_date):
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

        return new_access_token

    def store_token_in_context(self, token: str, expire_in: int) -> None:
        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        set_integration_context(context={
            'token': token,
            'expires': str(expire_date)
        })

    def get_events(self, start_date: str = '', continuation_token: str = '') -> dict:
        if continuation_token:
            params = {'continuationToken': continuation_token}
        else:
            start_date = start_date[:-1] + '.00'
            params = {
                'start': start_date,
                'end': (get_current_time() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-4]
            }

        headers = {'Authorization': f'Bearer {self.token}'}

        res = self._http_request(
            method='GET',
            url_suffix='/public/events',
            headers=headers,
            params=params
        )

        return res


def test_module(client: Client) -> str:
    event, _ = fetch_events(client, max_fetch=1)
    if not event:
        raise ValueError('failed to fetch events')

    return 'ok'


def get_events_command(client: Client, start_date_str: str, max_fetch: int) -> tuple:
    events, _ = fetch_events(client=client, max_fetch=max_fetch, start_date_str=start_date_str)
    if events:
        events = events[:max_fetch]
        return events, CommandResults(readable_output=tableToMarkdown('Bitwarden Events', events),
                                      raw_response=events)

    return [], CommandResults(readable_output='No events found')


def fetch_events(client: Client, max_fetch: int, start_date_str: str = DEFAULT_FIRST_FETCH) -> tuple:
    last_run = demisto.getLastRun()
    demisto.debug(f'{last_run=}')
    continuation_token = last_run.get('continuationToken', '')
    events: List[dict] = []
    has_next = True
    while has_next:
        has_next = False
        if len(events) >= max_fetch:
            break
        start_date = last_run.get('last_fetch', '') if last_run.get('last_fetch', '') else start_date_str
        response = client.get_events(start_date=start_date, continuation_token=continuation_token)

        if continuation_token := response.get('continuationToken'):
            has_next = True
        events.extend(response.get('data'))

    if continuation_token:
        demisto.debug(
            f'Bitwarden - Fetched {len(events)} which is the maximum or greater then the number of events.'
            f' Will keep the fetching in the next fetch.')
        created = start_date_str or last_run.get('last_fetch') or (
            (get_current_time() - timedelta(minutes=1)).strftime(DATE_FORMAT))
        new_last_run = {'continuationToken': continuation_token, 'last_fetch': created, 'nextTrigger': '0'}
    else:
        # If there is no continuation token, the last fetch date will be the max end date of the fetched events.
        new_last_fetch_date = max([dt for dt in (arg_to_datetime(event.get('date'), DATE_FORMAT)
                                                 for event in events) if dt is not None]).strftime(
            DATE_FORMAT) if events else get_current_time()
        new_last_run = {'last_fetch': new_last_fetch_date}
        demisto.debug(f'Bitwarden - Fetched {len(events)} events')

    for event in events:
        event['_time'] = event.get('date')

    return events, new_last_run


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions

    :return:
    :rtype:
    """
    demisto_params = demisto.params()
    base_url = demisto_params.get('url', 'https://api.bitwarden.com')
    client_id = demisto_params.get('credentials', {}).get('identifier')
    client_secret = demisto_params.get('credentials', {}).get('password')
    max_events_per_fetch = arg_to_number(demisto_params.get('max_fetch_events')) or DEFAULT_MAX_FETCH
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
        if args.get('start'):
            start_date = arg_to_datetime(args.get('start'))
            start_date_str = start_date.strftime(DATE_FORMAT)
        else:
            start_date_str = DEFAULT_FIRST_FETCH
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'bitwarden-get-events':
            events, results = get_events_command(client=client, start_date_str=start_date_str, max_fetch=max_events_per_fetch)
            return_results(results)
            if argToBoolean(args.get('should_push_events')):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
        elif demisto.command() == 'fetch-events':
            events, new_last_run = fetch_events(client=client, max_fetch=max_events_per_fetch, start_date_str=start_date_str)
            if events:
                if new_last_run:
                    demisto.debug(f'{new_last_run=}')
                    demisto.setLastRun(new_last_run)
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)


    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
