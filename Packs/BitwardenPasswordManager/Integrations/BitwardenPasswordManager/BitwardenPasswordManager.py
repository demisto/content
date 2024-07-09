import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import hashlib

VENDOR = 'Bitwarden'
PRODUCT = 'Password Manager'

DEFAULT_MAX_FETCH = 500
SECONDS_BEFORE_TOKEN_EXPIRED = 120
AUTHENTICATION_FULL_URL = 'https://identity.bitwarden.com/connect/token'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

default_first_fetch_datetime_object = get_current_time() - timedelta(minutes=1)
DEFAULT_FIRST_FETCH = default_first_fetch_datetime_object.strftime(
    '%Y-%m-%dT%H:%M:%S.') + f'{default_first_fetch_datetime_object.microsecond // 10000:02d}'


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
        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(seconds=SECONDS_BEFORE_TOKEN_EXPIRED)
        set_integration_context(context={
            'token': token,
            'expires': str(expire_date)
        })

    def get_events(self, start_date: str = '', continuation_token: str = '') -> dict:
        end_date_datetime_object = get_current_time() + timedelta(days=1)
        end_date = end_date_datetime_object.strftime(
            '%Y-%m-%dT%H:%M:%S.') + f'{end_date_datetime_object.microsecond // 10000:02d}'

        params = {
            'start': start_date,
            'end': end_date
        }

        if continuation_token:
            params['continuationToken'] = continuation_token

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


def get_events_command(client: Client, start_date_arg: str, max_fetch: int) -> tuple:
    events, _ = fetch_events(client=client, max_fetch=max_fetch, start_date_str=start_date_arg)
    if events:
        events = events[:max_fetch]
        return events, CommandResults(readable_output=tableToMarkdown('Bitwarden Events', events),
                                      raw_response=events)

    return [], CommandResults(readable_output='No events found')


def fetch_events(client: Client, max_fetch: int, start_date_str: str = DEFAULT_FIRST_FETCH) -> tuple[
    List[Dict[str, Any]], Dict[str, Any]]:
    last_run = demisto.getLastRun()
    events, continuation_token = get_events(client, max_fetch, start_date_str, last_run)
    unique_events = get_unique_events(events, last_run)
    latest_events = filter_events(events=events, latest=True)
    hash_latest_events = hash_events(latest_events)
    if continuation_token:
        demisto.debug(
            f'Bitwarden - Fetched {len(unique_events)} which is the maximum or greater then the number of events.'
            f' Will keep the fetching in the next fetch.')
        created = start_date_str or last_run.get('last_fetch') or (
            (get_current_time() - timedelta(minutes=1)).strftime(DATE_FORMAT))
        new_last_run = {'continuationToken': continuation_token, 'last_fetch': created, 'nextTrigger': '0',
                        'hashed_latest_events': hash_latest_events}
    else:
        # If there is no continuation token, the last fetch date will be the max end date of the fetched events.
        new_last_fetch_date = max([dt for dt in (arg_to_datetime(event.get('date'), DATE_FORMAT)
                                                 for event in unique_events) if dt is not None]).strftime(
            DATE_FORMAT) if unique_events else get_current_time()
        new_last_run = {'last_fetch': new_last_fetch_date, 'hashed_latest_events': hash_latest_events}
        demisto.debug(f'Bitwarden - Fetched {len(unique_events)} events')

    for event in unique_events:
        event['_time'] = event.get('date')

    return unique_events, new_last_run


def get_events(client: Client, max_fetch: int, start_date_str: str, last_run: Dict[str, Any]) -> tuple[List[Dict[str, Any]], str]:
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
    return events, continuation_token


def get_unique_events(events: List[Dict[str, Any]], last_run: Dict[str, Any]) -> List[Dict[str, Any]]:
    if hashed_latest_events := last_run.get('hashed_latest_events'):
        recent_events = filter_events(events=events, latest=False)
        hashed_recent_events = hash_events(recent_events)
        should_be_removed_events = []
        for hashed_recent_event in hashed_recent_events:
            if list(hashed_recent_event.keys())[0] in hashed_latest_events:
                should_be_removed_events.append(list(hashed_recent_event.values())[0])

        events_to_remove_set = {tuple(event.items()) for event in should_be_removed_events}
        unique_events = [event for event in events if tuple(event.items()) not in events_to_remove_set]
        return unique_events
    return events


def filter_events(events: List[Dict[str, Any]], latest: bool) -> List[Dict[str, Any]]:
    sorted_events = sorted(events, key=lambda x: x['date'])
    if latest:
        date = sorted_events[-1]['date']
    else:
        date = sorted_events[0]['date']
    filtered_events = [event for event in sorted_events if event['date'] == date]

    return filtered_events


def hash_events(events: List[Dict[str, Any]]) -> List[Dict[str, Dict[str, Any]]]:
    hashed_events = []
    for event in events:
        for key, value in event.items():
            if value is None:
                event[key] = "null"

        event_str = json.dumps(event, sort_keys=True)
        event_hash_object = hashlib.sha256(event_str.encode()).hexdigest()
        hashed_events.append({event_hash_object: event})

    return hashed_events


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
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'bitwarden-get-events':
            events, results = get_events_command(client=client, start_date_arg=args.get('start'), max_fetch=max_events_per_fetch)
            return_results(results)
            if argToBoolean(args.get('should_push_events')):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
        elif demisto.command() == 'fetch-events':
            events, new_last_run = fetch_events(client=client, max_fetch=max_events_per_fetch)
            if events:
                demisto.setLastRun({'last_fetch': new_last_run.get('last_fetch')})
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)


    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
