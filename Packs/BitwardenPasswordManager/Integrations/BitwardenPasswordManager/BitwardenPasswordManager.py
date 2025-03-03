import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import hashlib

VENDOR = 'Bitwarden'
PRODUCT = 'Password Manager'

DEFAULT_MAX_FETCH = 500
SECONDS_BEFORE_TOKEN_EXPIRED = 120
AUTHENTICATION_FULL_URL = 'https://identity.bitwarden.com/connect/token'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
DEFAULT_FIRST_FETCH = (get_current_time() - timedelta(minutes=1)).strftime(DATE_FORMAT)
DEFAULT_END_DATE = (get_current_time() + timedelta(days=1)).strftime(DATE_FORMAT)


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

    def get_events(self, start_date: str = '', end_date: str = '', continuation_token: str = '') -> dict:
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
    fetch_events(client, max_fetch=1)
    return 'ok'


def get_events_command(client: Client, args: Dict[str, Any]) -> tuple:
    limit = args.get('limit', DEFAULT_MAX_FETCH)
    start = args.get('start', DEFAULT_FIRST_FETCH)
    end = args.get('end', DEFAULT_END_DATE)
    events, _ = fetch_events(client=client, max_fetch=limit, dates={'start': start, 'end': end})
    if events:
        events = events[:limit]
        return events, CommandResults(readable_output=tableToMarkdown('Bitwarden Events', events),
                                      raw_response=events)

    return [], CommandResults(readable_output='No events found')


def fetch_events(client: Client, max_fetch: int,
                 dates: Dict[str, Any] = {'start': DEFAULT_FIRST_FETCH, 'end': DEFAULT_END_DATE}) -> tuple[
        List[Dict[str, Any]], Dict[str, Any]]:
    """ Fetches events from the API using the provided client.
    Args:
        - client (Client): The client object used to make API requests.
        - max_fetch (int): The maximum number of events to fetch.
        - dates (Dict[str, Any], optional): A dictionary containing the start and end dates for the events.
            The default values are set to DEFAULT_FIRST_FETCH for the start date and DEFAULT_END_DATE for the end date.

    Returns:
        - tuple[List[Dict[str, Any]], Dict[str, Any]]: A tuple containing a list of fetched events and a last_run object.
            - The list of events contains dictionaries with event information.
            - The last_run object contains the new last fetch date and, if there is a continuationToken, nextTrigger is set to 0.

    Additional Functionality:
        - The function calls the get_events_with_pagination function, which internally calls client.get_events to fetch events
            from the API.
        - The function checks whether the events fetched in the most recent request are identical to the oldest events fetched in
            the subsequent request. This check is implemented to prevent duplicate events from being included in the fetched
            results.
    """
    last_run = demisto.getLastRun()
    events, continuation_token = get_events_with_pagination(client, max_fetch, dates, last_run)
    if not events:
        return [], last_run
    unique_events = get_unique_events(events, last_run)
    recent_events = filter_events(events=events, oldest=False)
    hashed_recent_events = hash_events(recent_events)
    if continuation_token:
        demisto.debug(
            f'Bitwarden - Fetched {len(unique_events)} which is the maximum or greater then the number of events.'
            f' Will keep the fetching in the next fetch.')
        last_fetch_date = unique_events[0].get('date', '').split('Z')[0]
        split_string = last_fetch_date.split('.')
        formatted_datetime = split_string[0] + '.' + split_string[1][:-4].ljust(3, '0')
        new_last_run = {'continuationToken': continuation_token, 'last_fetch': formatted_datetime, 'nextTrigger': '0',
                        'hashed_recent_events': hashed_recent_events}
    else:
        # If there is no continuation token, the last fetch date will be the max end date of the fetched events.
        new_last_fetch_date = max([dt for dt in (arg_to_datetime(event.get('date'), DATE_FORMAT)
                                                 for event in unique_events) if dt is not None]).strftime(
            DATE_FORMAT) if unique_events else get_current_time()
        new_last_run = {'last_fetch': new_last_fetch_date, 'hashed_recent_events': hashed_recent_events}
        demisto.debug(f'Bitwarden - Fetched {len(unique_events)} events')

    for event in unique_events:
        event['_time'] = event.get('date')

    return unique_events, new_last_run


def get_events_with_pagination(client: Client, max_fetch: int, dates: Dict[str, Any], last_run: Dict[str, Any]) -> tuple[
        List[Dict[str, Any]], str]:
    continuation_token = last_run.get('continuationToken', '')
    events: List[dict] = []
    has_next = True
    while has_next:
        has_next = False
        if len(events) >= max_fetch:
            break
        start_date = last_run.get('last_fetch', '') if last_run.get('last_fetch', '') else dates.get('start', DEFAULT_FIRST_FETCH)
        response = client.get_events(start_date=start_date, end_date=dates.get('end', DEFAULT_END_DATE),
                                     continuation_token=continuation_token)
        if continuation_token := response.get('continuationToken'):
            has_next = True
        events.extend(response.get('data', []))

    return events, continuation_token


def get_unique_events(events: List[Dict[str, Any]], last_run: Dict[str, Any]) -> List[Dict[str, Any]]:
    if last_fetched_hashed_recent_events := last_run.get('hashed_recent_events'):
        oldest_events = filter_events(events=events, oldest=True)
        hashed_oldest_events = hash_events(oldest_events)
        should_be_removed_events = []
        for hashed_oldest_event, oldest_event in hashed_oldest_events.items():
            if hashed_oldest_event in list(last_fetched_hashed_recent_events.keys()):
                should_be_removed_events.append(oldest_event)

        events_to_remove_set = {tuple(event.items()) for event in should_be_removed_events}
        unique_events = [event for event in events if tuple(event.items()) not in events_to_remove_set]
        return unique_events
    return events


def filter_events(events: List[Dict[str, Any]], oldest: bool) -> List[Dict[str, Any]]:
    sorted_events = sorted(events, key=lambda x: x['date'])
    date = sorted_events[0]['date'] if oldest else sorted_events[-1]['date']
    filtered_events = [event for event in sorted_events if event['date'] == date]

    return filtered_events


def hash_events(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    hashed_events = {}
    for event in events:
        event_str = json.dumps(event, sort_keys=True)
        event_hash_object = hashlib.sha256(event_str.encode()).hexdigest()
        hashed_events[event_hash_object] = event

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
            events, results = get_events_command(client=client, args=args)
            return_results(results)
            if argToBoolean(args.get('should_push_events', False)):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
        elif demisto.command() == 'fetch-events':
            events, new_last_run = fetch_events(client=client, max_fetch=max_events_per_fetch)
            if events:
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun({'last_fetch': new_last_run.get('last_fetch')})

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
