import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'ibm'
PRODUCT = 'security verify'
TOKEN_EXPIRY_BUFFER = timedelta(minutes=5)
DEFAULT_TEST = 1_000
DEFAULT_FETCH = 10_000
MAX_FETCH = 50_000
MIN_FETCH = 1

# print(f"{demisto.params()=}")
# print(f"{demisto.args()=}")


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        # self._max_fetch_validation()

        self._authenticate()

    def _authenticate(self):
        """
        """
        token_data = demisto.getIntegrationContext()

        if not self._is_token_valid(token_data):
            token_data = self._get_new_token()
            demisto.setIntegrationContext(token_data)

        self.access_token = token_data["access_token"]

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

    def search_events(self, limit: int, last_item: Optional[dict] = None) -> Dict:
        """

        """
        params = {
            'size': limit,
            'range_type': 'indexed_at',
            'all_events': 'yes',
            'sort_order': 'asc',
        }
        if last_item:
            params["after_time"] = last_item["last_time"]
            params["after_id"] = last_item["last_id"]

        headers = {
            "Authorization": f"Bearer {self.access_token}",
        }

        response = self._http_request(
            method="GET",
            url_suffix="events",
            params=params,
            headers=headers
        )
        return response

    def _max_fetch_validation(self):
        if self.max_fetch > MAX_FETCH or self.max_fetch < MIN_FETCH:
            raise DemistoException(f"The maximum number of events per fetch should be between 1 - {MAX_FETCH}")


def test_module(client: Client) -> str:
    """
    ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        get_events(client, {})

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    last_id = args.get("last_id")
    last_time = args.get("last_time")
    last_item = {"last_id": last_id, "last_time": last_time}
    limit = arg_to_number(args.get("limit")) or DEFAULT_TEST

    response = client.search_events(limit, last_item)
    events = response.get("response", {}).get("events", {}).get("events", [])

    return events


# def fetch_events(client: Client, last_run: dict[str, int],
#                  first_fetch_time, alert_status: str | None, max_events_per_fetch: int
#                  ) -> tuple[Dict, List[Dict]]:
#     """
# f events that will be created in XSIAM.
#     """
#     prev_id = last_run.get('prev_id', None)
#     if not prev_id:
#         prev_id = 0

#     events = client.search_events(
#         prev_id=prev_id,
#         alert_status=alert_status,
#         limit=max_events_per_fetch,
#         from_date=first_fetch_time,
#     )
#     demisto.debug(f'Fetched event with id: {prev_id + 1}.')

#     # Save the next_run as a dict with the last_fetch key to be stored
#     next_run = {'prev_id': prev_id + 1}
#     demisto.debug(f'Setting next run {next_run}.')
#     return next_run, events


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
    max_fetch = arg_to_number(params.get('max_fetch')) or DEFAULT_FETCH
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    # first_fetch_time = datetime.now().isoformat()

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
            events = get_events(client, args)
            return_results(events)

            should_push_events = argToBoolean(args.get('should_push_events'))
            if should_push_events:
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            pass
        # max_fetch
            # last_run = demisto.getLastRun()
            # next_run, events = fetch_events(
            #     client=client,
            #     last_run=last_run,
            #     first_fetch_time=first_fetch_time,
            #     alert_status=alert_status,
            #     max_events_per_fetch=max_fetch,
            # )

            # send_events_to_xsiam(
            #     events,
            #     vendor=VENDOR,
            #     product=PRODUCT
            # )
            # demisto.setLastRun( next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
