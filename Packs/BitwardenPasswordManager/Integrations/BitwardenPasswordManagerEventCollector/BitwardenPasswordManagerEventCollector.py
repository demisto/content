import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

VENDOR = 'Bitwarden'
PRODUCT = 'Password Manager'

DEFAULT_MAX_FETCH = 500
DEFAULT_FIRST_FETCH = '3 days'
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
                demisto.log(f"Token is valid: {expires_date=}")  # TODO: Remove this line
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

        demisto.log(f"Created new token: {expire_in=}")  # TODO: Remove this line
        return new_access_token

    def store_token_in_context(self, token: str, expire_in: int) -> None:
        expire_date = get_current_time() + timedelta(seconds=expire_in) - timedelta(minutes=MINUTES_BEFORE_TOKEN_EXPIRED)
        demisto.log(f"{expire_date=}")  # TODO: Remove this line
        set_integration_context(context={
            'token': token,
            'expires': str(expire_date)
        })

    def get_events(self, start_date: str = "", continuation_token: str = "") -> dict:
        params = {
            'start': start_date,
            'continuationToken': continuation_token
        }

        headers = {
            'Authorization': f'Bearer {self.token}'
        }

        res = self._http_request(
            method='GET',
            url_suffix='/public/events',
            headers=headers,
            params=params
        )

        return res


def test_module(client: Client) -> str:
    try:
        retrieve_events, last_run = fetch_events(client, max_fetch=1)
    except DemistoException as e:
        raise e

    return 'ok'


def get_events_command(client: Client, start_date_str: str, max_fetch: int) -> tuple:
    events, _ = fetch_events(client=client, max_fetch=max_fetch, start_date_str=start_date_str)
    if events:
        events = events[:max_fetch]
        return events, CommandResults(readable_output=tableToMarkdown("Bitwarden Events", events),
                                      raw_response=events)

    return [], CommandResults(readable_output='No events found')


def fetch_events(client: Client, max_fetch: int, start_date_str: str = "") -> tuple:
    events, next_run = get_events(client, start_date_str, max_fetch)

    if 'continuationToken' in next_run:
        next_run["nextTrigger"] = "0"

    for event in events:
        event['_time'] = event.get('date')

    return events, next_run


def get_events(client: Client, start_date: str, max_fetch: int) -> tuple:
    last_run = demisto.getLastRun()
    continuation_token = last_run.get("continuationToken", "")
    demisto.log(f"{continuation_token=}")  # TODO: Remove this line
    events: List[dict] = []
    has_next = True
    while has_next:
        has_next = False
        if len(events) >= max_fetch:
            break
        response = client.get_events(start_date=start_date, continuation_token=continuation_token)

        if continuation_token := response.get("continuationToken"):
            has_next = True
        events.extend(response.get('data'))

    events = events[:max_fetch]
    created, current_date = calculate_fetch_dates(start_date, last_run=last_run)  # TODO: Check whats is it
    if continuation_token:
        demisto.debug(
            f"Bitwarden - Fetched {len(events)} which is the maximum number of events."
            f" Will keep the fetching in the next fetch.")
        new_last_run_with_continuation_token = {"continuationToken": continuation_token, "last_fetch": created}
        demisto.log(f"{new_last_run_with_continuation_token=}")  # TODO: Check whats is it
        return events, new_last_run_with_continuation_token
    # If there is no continuation token, the last fetch date will be the max end date of the fetched events.
    new_last_fetch_date = max([dt for dt in (arg_to_datetime(event.get("date"), DATE_FORMAT)
                                             for event in events) if dt is not None]).strftime(
        DATE_FORMAT) if events else current_date
    new_last_run_without_continuation_token = {"last_fetch": new_last_fetch_date}
    demisto.debug(f"Bitwarden - Fetched {len(events)} events")
    demisto.log(f"{new_last_run_without_continuation_token=}")  # TODO: Check whats is it
    return events, new_last_run_without_continuation_token


def validate_start_date(start_date_str: str):
    if start_date := arg_to_datetime(start_date_str):
        start_date_str = start_date.strftime(DATE_FORMAT)
    if not start_date:
        raise ValueError("The start date is missing or it is invalid. Please provide valid date.")
    return start_date_str


def calculate_fetch_dates(start_date: str, last_run: dict) -> tuple:
    now_utc_time = get_current_time()
    # argument > last run > current time
    start_date = start_date or last_run.get('last_fetch') or (
        (now_utc_time - timedelta(minutes=1)).strftime(DATE_FORMAT))
    # argument > current time
    return start_date


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
            valid_start_date = validate_start_date(args.get('start'))
            events, results = get_events_command(client=client, start_date_str=valid_start_date, max_fetch=max_events_per_fetch)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
        elif demisto.command() == 'fetch-events':
            events, new_last_run = fetch_events(client=client, max_fetch=max_events_per_fetch)
            if events:
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                if new_last_run:
                    demisto.setLastRun(new_last_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
