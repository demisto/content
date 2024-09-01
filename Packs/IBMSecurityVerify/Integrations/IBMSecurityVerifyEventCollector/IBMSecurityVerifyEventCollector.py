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
DEFAULT_LIMIT_COMMAND = 1_000
DEFAULT_LIMIT_FETCH = 10_000
MAX_LIMIT = 50_000
MIN_LIMIT = 1
# TODO: print
# print(f"{demisto.params()=}")
# print(f"{demisto.args()=}")

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret

        self._authenticate()

    def _authenticate(self):
        """
        """
        token_data = demisto.getIntegrationContext()

        if not self._is_token_valid(token_data):
            token_data = self._get_new_token()
            demisto.setIntegrationContext(token_data)

        access_token = token_data["access_token"]
        self._headers = {"Authorization": f"Bearer {access_token}"}

    def _is_token_valid(self, token_data):
        """
        Checks if the current token is valid and not expired with a security buffer.
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
        Fetches a new token from the Exabeam API and updates the integration context.
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

    def _max_limit_validation(self, limit):
        if limit > MAX_LIMIT or limit < MIN_LIMIT:
            raise DemistoException(f"The maximum number of events per fetch should be between 1 - {MAX_LIMIT}")

    def search_events(self, limit: int, sort_order: str, last_item: dict = {}) -> list:
        """

        """
        self._max_limit_validation(limit)
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
        events = response.get("response", {}).get("events", {}).get("events", [])
        return events


def test_module(client: Client) -> str:
    """
    'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    args = {"limit": 1}
    get_events_command(client, args)
    return "ok"


def get_events_command(client: Client, args: dict) -> list[dict]:
    last_id = args.get("last_id")
    last_time = args.get("last_time")
    last_item = {"last_id": last_id, "last_time": last_time}
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT_COMMAND
    sort_order = args.get("sort_order", "desc").lower()

    events = client.search_events(limit=limit, sort_order=sort_order, last_item=last_item)
    return events


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
    last_time = last_run.get("last_time")
    last_id = last_run.get("last_id")

    if not last_time or not last_id:
        demisto.debug('Last run data is missing. Fetching initial last_run.')

        first_event = client.search_events(limit=1, sort_order="desc")
        if not first_event:
            demisto.debug('No events found in the initial fetch.')
            return {}, []

        last_run = {
            "last_time": first_event[0].get("indexed_at"),
            "last_id": first_event[0].get("id")
        }
        demisto.debug(f'Initial last_run set to: {last_run}')

    events = client.search_events(
        limit=limit,
        sort_order="asc",
        last_item=last_run
    )
    demisto.debug(f'Fetched {len(events)} new events')
    if events:
        last_run = {
            "last_time": events[-1].get("indexed_at"),
            "last_id": events[-1].get("id")
        }
    return last_run, events


''' MAIN FUNCTION '''


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
    limit = arg_to_number(params.get('max_fetch')) or DEFAULT_LIMIT_FETCH
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
            return_results(test_module(client))

        elif command == 'ibm-security-verify-get-events':
            events = get_events_command(client, args)
            return_results(CommandResults(readable_output=tableToMarkdown(f"{VENDOR.title()} Events:", events)))

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
                limit=limit,
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
