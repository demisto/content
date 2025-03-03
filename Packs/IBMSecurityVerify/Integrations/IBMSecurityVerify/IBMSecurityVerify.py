import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'ibm'
PRODUCT = 'security verify'
TOKEN_EXPIRY_BUFFER = timedelta(minutes=1)
MIN_FETCH = 1
MAX_FETCH = 50_000
MAX_EVENTS_API_CALL = 10_000


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret

        self._authenticate()

    def _authenticate(self):
        """
        Authenticates by validating or obtaining a new access token.

        Sets the authorization header with the valid access token.
        """
        token_data = demisto.getIntegrationContext()

        if not self._is_token_valid(token_data):
            token_data = self._get_new_token()
            demisto.setIntegrationContext(token_data)

        access_token = token_data["access_token"]
        self._headers = {"Authorization": f"Bearer {access_token}"}

    def _is_token_valid(self, token_data) -> bool:
        """
        Checks if the access token is valid and not expired.

        Args:
            token_data (dict): Token data with 'access_token' and 'expiry_time_utc'.

        Returns:
            bool: True if valid, False otherwise.
        """
        access_token = token_data.get("access_token")
        expiry_time_str = token_data.get("expiry_time_utc")
        if not access_token or not expiry_time_str:
            return False

        current_time_utc = datetime.now(timezone.utc)
        expiry_time_utc = datetime.fromisoformat(expiry_time_str)
        return current_time_utc < (expiry_time_utc - TOKEN_EXPIRY_BUFFER)

    def _get_new_token(self):
        """
        Retrieves a new access token using client credentials and calculates its expiration time.
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

        response = self._http_request(
            method="POST",
            url_suffix="/endpoint/default/token",
            data=data,
        )

        new_token = response.get('access_token')
        expires_in = response.get("expires_in")
        current_time_utc = datetime.now(timezone.utc)
        expiry_time_utc = current_time_utc + timedelta(seconds=expires_in)

        token_data = {"access_token": new_token, "expiry_time_utc": expiry_time_utc.isoformat()}
        return token_data

    def search_events(self, limit: int, sort_order: str, last_item: dict = {}) -> tuple[dict[str, str], list]:
        """
        Searches and returns a list of events based on the specified criteria.

        """
        params = {
            'size': limit,
            'range_type': 'indexed_at',
            'all_events': 'yes',
            'sort_order': sort_order,
            'after_time': last_item.get("last_time"),
            'after_id': last_item.get("last_id")
        }

        response = self._http_request(
            method="GET",
            url_suffix="events",
            params=params,
        )
        response_events = response.get("response", {}).get("events", {})
        events_list = response_events.get("events", [])
        search_after = response_events.get("search_after", {})
        return search_after, events_list


def test_module(client: Client, params) -> str:
    """
    'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    if argToBoolean(params.get('isFetchEvents')):
        max_limit_validation(arg_to_number(params.get('max_fetch')))

    args = {"limit": 1}
    get_events_command(client, args)

    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list[dict], str]:
    """
    Retrieves events using the client based on the provided arguments.
    """

    last_id = args.get("last_id")
    last_time = args.get("last_time")
    last_item = {"last_id": last_id, "last_time": last_time}
    if bool(last_id) != bool(last_time):
        raise DemistoException("Both 'last_id' and 'last_time' must be provided together or not at all.")

    limit = arg_to_number(args.get("limit")) or MAX_EVENTS_API_CALL
    sort_order = args.get("sort_order", "desc").lower()
    if limit > MAX_EVENTS_API_CALL or limit < MIN_FETCH:
        raise DemistoException(f"The maximum number of events per fetch should be between {MIN_FETCH} - {MAX_EVENTS_API_CALL}")

    _, events = client.search_events(limit=limit, sort_order=sort_order, last_item=last_item)
    hr = tableToMarkdown(f"{VENDOR.title()} - {PRODUCT.title()} Events:", format_record_keys(events))
    return events, hr


def fetch_events(client: Client, last_run: dict[str, str], limit: int) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from the client starting from the last known event.

    Args:
        client (Client): The client object used to communicate with the event source.
        last_run (dict): A dictionary containing the last run information, including 'last_time' and 'last_id'.
        limit (int): The maximum number of events to fetch.

    Returns:
        tuple: A tuple containing the updated last run information and a list of events.
    """
    max_limit_validation(limit)
    last_time = last_run.get("last_time")
    last_id = last_run.get("last_id")

    if not last_time or not last_id:  # If this is a first run
        demisto.debug('Last run data is missing. Fetching initial last_run.')

        search_after, first_event = client.search_events(limit=1, sort_order="desc")
        if not first_event:
            demisto.debug('No events found in the initial fetch.')
            return {}, []

        last_run = {
            "last_time": search_after.get("time", ""),
            "last_id": search_after.get("id", "")
        }
        demisto.debug(f'Initial last_run set to: {last_run}')

    collected_events: list[dict] = []
    while len(collected_events) < limit:
        limit_for_request = min(limit - len(collected_events), MAX_EVENTS_API_CALL)
        search_after, events = client.search_events(
            limit=limit_for_request,
            sort_order="asc",
            last_item=last_run
        )
        if not events:
            break

        demisto.debug(f'Got {len(events)} events from api')
        last_run = {
            "last_time": search_after.get("time", ""),  # Contains the 'indexed_at' of the last event
            "last_id": search_after.get("id", "")
        }
        collected_events.extend(events)

    demisto.debug(f'Sum fetched {len(collected_events)} new events')
    return last_run, collected_events


''' HELPER FUNCTIONS '''


def format_record_keys(dict_list):
    new_list = []
    for input_dict in dict_list:
        new_dict = {}
        for key, value in input_dict.items():
            new_key = key.replace('_', ' ').title()
            new_dict[new_key] = value
        new_list.append(new_dict)
    return new_list


def add_time_to_events(events: list[dict]):
    """
    Adds the _time key to the events.
    Args:
        events: list[dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(event["time"])
            event["_time"] = create_time.strftime(DATE_FORMAT)  # type: ignore[union-attr]


def max_limit_validation(limit):
    """
    Validates if the limit is within the allowed range.
    """
    if limit > MAX_FETCH or limit < MIN_FETCH:
        raise DemistoException(f"The maximum number of events per fetch should be between {MIN_FETCH} - {MAX_FETCH}")


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = urljoin(params.get('url'), '/v1.0')
    credentials = params.get('credentials', {})
    client_id = credentials.get('identifier')
    client_secret = credentials.get('password')
    limit_fetch = arg_to_number(params.get('max_fetch')) or MAX_EVENTS_API_CALL
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client, params))

        elif command == 'ibm-security-verify-get-events':
            events, hr = get_events_command(client, args)
            return_results(CommandResults(readable_output=hr))

            should_push_events = argToBoolean(args.get('should_push_events'))
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            demisto.debug(f'Last_run before the fetch: {last_run}')
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                limit=limit_fetch,
            )

            add_time_to_events(events)
            send_events_to_xsiam(
                events=events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.debug(f'last_run after the fetch {last_run}')
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
