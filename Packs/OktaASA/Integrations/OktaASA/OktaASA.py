import demistomock as demisto
from CommonServerPython import *
import urllib3
import pytz

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Okta'
PRODUCT = 'ASA'
INTEGRATION_NAME = "Okta ASA"
# Note: True life time of token is actually 60 mins - we take minutes of 58 minutes.
TOKEN_LIFE_TIME_SECONDS = 3480

''' CLIENT CLASS '''


class OktaASAClient(BaseClient):
    """Client class to interact with the Okta ASA Audit Events API"""

    def __init__(
        self,
        key_id: str,
        key_secret: str,
        base_url: str,
        verify=True,
        proxy=False,
    ):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.key_id = key_id
        self.key_secret = key_secret

    def get_token_request(self) -> dict:
        """Gets request token.

        Args:
            self (OktaASAClient): Okta ASA Client.

        Returns:
            dict: The refresh token response.
        """
        body = {
            'key_id': self.key_id,
            'key_secret': self.key_secret
        }
        # response expires_at time is UTC time.
        token_response: dict = self._http_request('POST', '/service_token', json_data=body,
                                                  headers={"Content-Type": "application/json"})
        # We don't need to save the team name
        token_response.pop("team_name", None)
        return token_response

    def get_audit_events_request(self, params: dict) -> list:
        """Gets audit events request.

        Args:
            self (OktaASAClient): Okta ASA Client.
            params (Dict): Request parameters.

        Returns:
            list: A list of events.
        """
        events_response: list = self._http_request('GET', '/auditsV2', params=params).get("list", [])

        return events_response

    def execute_audit_events_request(self, offset: Optional[str], count: Optional[int],
                                     descending: Optional[bool], prev: Optional[bool]) -> list:
        """Gets audit events request.

        Args:
            self (OktaASAClient): Okta ASA Client.
            offset (str): The UUID of an object used as an offset for pagination.
            count (int): Controls the number of objects listed per page
            descending (bool): If 'true', the most recent results are listed first
            prev (bool): Controls the direction of paging

        Returns:
            Dict: The response.
        """

        params = assign_params(offset=offset, count=count, descending=descending, prev=prev)
        self.is_token_refresh_required()
        try:
            events_response = self.get_audit_events_request(params)
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 401 and "Authentication token expired" in e.res.text:
                self.is_token_refresh_required(hard=True)
                demisto.debug(f"{INTEGRATION_NAME}: Hard refresh token")
                events_response = self.get_audit_events_request(params)
            else:
                raise e
        return events_response

    def is_token_refresh_required(self, hard=False) -> None:
        """Checks if token refresh required and return the token.

            Args:
                self (OktaASAClient): Okta ASA Client.
                hard (bool): Refresh the token regardless of the expiration time.
            Returns:
                Dict: The response.
        """
        integration_context: dict = demisto.getIntegrationContext()
        token_response: dict = {}

        if integration_context:
            current_time = datetime.now(pytz.utc)
            expires_at_token = integration_context.get("expires_at", str(get_current_time()))
            is_token_expired_bool = is_token_expired(expires_at_token) or hard
            demisto.debug(
                f"{INTEGRATION_NAME}: is_token_expired {is_token_expired_bool=},"
                f"{current_time.strftime(DATE_FORMAT)=}, {expires_at_token=}")
            token_response = (self.get_token_request()
                              if is_token_expired_bool
                              else integration_context)
        else:
            token_response = self.get_token_request()
        demisto.setIntegrationContext(token_response)
        token = token_response.get("bearer_token", "")
        self._headers = {'Authorization': f'Bearer {token}'}

    def search_events(
        self, limit: Optional[int] = 10000, offset: str | None = None
    ) -> tuple[List[Dict], Optional[str], Optional[str]]:
        """
        Searches for Okta ASA events using the '/auditsV2' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            limit (int): limit.
            offset (str): The UUID of an object used as an offset for pagination.

        Returns:
            List[Dict]: events
            str: id for last run
        """
        results: List[Dict] = []
        descending = False
        returned_offset = offset
        returned_timestamp = None
        # We are limited to 1000 results per request, count > 1000 does not work.
        count = min(limit, 1000) if limit else 1000
        while limit and len(results) < limit:
            descending = bool(not returned_offset)
            events = self.execute_audit_events_request(
                offset=returned_offset, count=count, descending=descending, prev=None
            )
            if not events:
                break
            event_offset = events[0] if descending else events[len(events) - 1]
            returned_offset = event_offset.get("id")
            results.extend(events)
            count = min(limit - len(results), 1000)
        if results:
            list_last_index = len(results) - 1
            demisto.debug(f"{INTEGRATION_NAME}: will return {len(results)} events")
            returned_timestamp = results[list_last_index].get("timestamp")

        return results, returned_offset, returned_timestamp


'''HELPER FUNCTIONS'''


def is_token_expired(expires_date: str) -> bool:
    """Checks if token is expired.

        Args:
            self (OktaASAClient): Okta ASA Client.
            expires_date (str): The expiration date.
        Returns:
            bool: is the token expired.
    """
    current_utc_time = datetime.now(pytz.utc)
    expires_datetime_date = dateparser.parse(expires_date, settings={'TIMEZONE': 'UTC'}) or current_utc_time
    expires_datetime_date = expires_datetime_date - timedelta(hours=0, minutes=3)
    expires_datetime: datetime = arg_to_datetime(expires_date) or current_utc_time
    return current_utc_time > expires_datetime


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('timestamp'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


'''COMMAND FUNCTIONS'''


def test_module(client: OktaASAClient) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (OktaASAClient): OktaASAClient client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        fetch_events_command(
            client=client,
            last_run={},
            max_audit_events_per_fetch=1,
            is_fetch_events=True
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events_command(client: OktaASAClient, args: dict) -> tuple[List[Dict], CommandResults]:
    """
        Gets audit events from Audits Events endpoint.

        Args:
            self (OktaASAClient): Okta ASA Client.
            args (dict): A dictionary containing the command arguments.

        Returns:
            List[Dict]: list of events.
            CommandResults: command results containing Audits Events.
    """

    max_audit_events_per_fetch = arg_to_number(args.get('limit')) or 50
    events, _, _ = client.search_events(
        limit=max_audit_events_per_fetch,
        offset=None,
    )
    hr = tableToMarkdown(name='Audits Events', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events_command(client: OktaASAClient, last_run: dict[str, str],
                         max_audit_events_per_fetch: Optional[int], is_fetch_events: bool = False
                         ) -> tuple[dict[str, str], List[Dict]]:
    """
    Args:
        client (OktaASAClient): OktaASAClient client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        max_audit_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    if is_fetch_events:
        events, offset, timestamp = client.search_events(
            limit=max_audit_events_per_fetch,
            offset=last_run.get("offset") if last_run else None,
        )
        # Save the next_run as a dict with the last_fetch key to be stored
        next_run: dict = {"offset": offset, "timestamp": timestamp} if offset else last_run
    else:
        events = []
        next_run = last_run
    demisto.debug(f'{INTEGRATION_NAME}: Setting next run {next_run}.')
    return next_run, events


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key_id = params.get('api_key_id', {}).get('password')
    api_key_secret = params.get('api_key_secret', {}).get('password')
    team_name = params.get('team_name')
    base_url = urljoin(params.get('url'), f'/v1/teams/{team_name}')
    verify_certificate = not params.get('insecure', False)
    max_audit_events_per_fetch = arg_to_number(params.get('max_audit_events_per_fetch', "10000"))
    proxy = params.get('proxy', False)
    is_fetch_events = argToBoolean(params.get('isFetchEvents', False))

    demisto.debug(f'{INTEGRATION_NAME}: Command being called is {command}')
    try:
        client = OktaASAClient(
            key_id=api_key_id,
            key_secret=api_key_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'okta-asa-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            events, results = get_events_command(client, demisto.args())
            return_results(results)
            if should_push_events:
                add_time_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events_command(
                client=client,
                last_run=last_run,
                max_audit_events_per_fetch=max_audit_events_per_fetch,
                is_fetch_events=is_fetch_events
            )

            add_time_to_events(events)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
