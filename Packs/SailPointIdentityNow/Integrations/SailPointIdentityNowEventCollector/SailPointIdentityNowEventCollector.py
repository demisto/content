from datetime import datetime, timedelta
import demistomock as demisto
from CommonServerPython import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'sailpoint'
PRODUCT = 'identitynow'
# Default lookback is 1 hour from current time
DEFAULT_LOOKBACK = (datetime.now() - timedelta(hours=1)).strftime(DATE_FORMAT)

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, client_id: str, client_secret: str, base_url: str, proxy: bool, verify: bool, token: str | None = None):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = token

        try:
            demisto.debug('in Client - Getting token.')
            self.token = self.get_token()
            self.headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.token}'
            }
        except Exception as e:
            raise Exception(f'Failed to get token. Error: {str(e)}')

    def generate_token(self) -> str:
        """
        Generates an OAuth 2.0 token using client credentials.
        Returns:
            str: token
        """
        demisto.debug('in generate_token - starting to generate token.')
        resp = self._http_request(
            method='POST',
            url_suffix="oauth/token",
            data={
                'grant_type': 'client_credentials',
            },
            auth=(self.client_id, self.client_secret)
        )

        token = resp.get('access_token')
        now_timestamp = arg_to_datetime('now').timestamp()  # type:ignore
        expiration_time = now_timestamp + resp.get('expires_in')
        demisto.debug(f'in generate_token - Generated token that expires at: {expiration_time}.')
        integration_context = get_integration_context()
        integration_context.update({'token': token})
        # Subtract 60 seconds from the expiration time to make sure the token is still valid
        integration_context.update({'expires': expiration_time - 60})
        demisto.debug(f'in generate_token - Updated integration context to be {integration_context}.')
        set_integration_context(integration_context)

        return token

    def get_token(self) -> str:
        """
        Obtains token from integration context if available and still valid.
        After expiration, new token are generated and stored in the integration context.
        Returns:
            str: token that will be added to authorization header.
        """
        demisto.debug('in get_token - starting to get token.')
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        valid_until = integration_context.get('expires')

        now_timestamp = arg_to_datetime('now').timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until and now_timestamp < valid_until:
            demisto.debug(f'in get_token - Using existing token that expires at: {valid_until}.')
            return token

        # else generate a token and update the integration context accordingly
        token = self.generate_token()
        demisto.debug('in get_token - Generated new token.')

        return token

    def search_events(self, prev_id: str, from_date: str, limit: int | None = None) -> List[Dict]:
        """
        Searches for events in SailPoint IdentityNow
        Args:
            prev_id: The id of the last event fetched
            from_date: The date from which to fetch events
            limit: Maximum number of events to fetch
        Returns:
            List of events
        """
        query = {"indices": ["events"],
                 "queryType": "SAILPOINT",
                 "queryVersion": "5.2",
                 "query":
                 {"query": f"type:* AND created: [{from_date} TO now]"},
                 "timeZone": "America/Los_Angeles",
                 "sort": ["+id"],
                 "searchAfter": [prev_id]
                 }
        url_suffix = f'/v3/search?limit={limit}' if limit else '/v3/search'
        demisto.debug(f'in search_events - Searching for events with query: {query}.')
        return self._http_request(method='POST', url_suffix=url_suffix, data=query)


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    Args:
        client: Client object with the API client
    Returns:
        'ok' if test passed, anything else will fail the test
    """

    try:
        fetch_events(
            client=client,
            last_run={},
            max_events_per_fetch=1,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, limit: int, from_date: str, from_id: str = '0') -> tuple[List[Dict], CommandResults]:
    """
    Gets events from the SailPoint IdentityNow API
    Args:
        client: Client object with the API client
        limit: Maximum number of events to fetch
        from_date: The date from which to get events
        from_id: The ID of an event from which to start to get events from
    Returns:
        List of events and CommandResults object
    """
    events = client.search_events(
        prev_id=from_id,
        from_date=from_date,
        limit=limit,
    )
    demisto.debug(f'in get_events - Fetched {len(events)} events.')
    demisto.debug(f'in get events - First event: {events[0]}' if events else 'No events fetched.')
    hr = tableToMarkdown(name='Test Events', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: dict[str, str],
                 max_events_per_fetch: int
                 ) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from the SailPoint IdentityNow API
    Args:
        client: Client object with the API client
        last_run: Dict containing the last run data
        max_events_per_fetch: Maximum number of events to fetch per call
    Returns:
        Tuple with the next run data and the list of events fetched
    """

    all_events = []
    formatted_now = datetime.now().strftime(DATE_FORMAT)
    while max_events_per_fetch > 0:
        demisto.debug(f'in fetch_events - Fetching events with max_events_per_fetch: {max_events_per_fetch}.')
        events = client.search_events(
            prev_id=last_run.get('prev_id', "0"),
            from_date=last_run.get('prev_date', formatted_now),
            limit=max_events_per_fetch,
        )
        demisto.debug(f'in fetch_events - Fetched {len(events)} events.')
        demisto.debug(f'in fetch_events - First event: {events[0]}' if events else 'No events fetched.')
        if not events:
            demisto.debug('in fetch_events - No more events to fetch.')
            break
        last_fetched_event = events[-1]
        last_fetched_id = last_fetched_event['id']
        last_fetched_creation_date = last_fetched_event['created']
        demisto.debug(f'Fetched event with id: {last_fetched_id} and creation date: {last_fetched_creation_date}.')

        last_run = {'prev_id': last_fetched_id, 'prev_date': last_fetched_creation_date}
        max_events_per_fetch -= len(events)
        all_events.extend(events)

    next_run = {'prev_id': last_fetched_id, 'prev_date': last_fetched_creation_date}
    demisto.debug(f'Setting next run {next_run}.')
    return next_run, all_events


''' MAIN FUNCTION '''


def add_time_and_status_to_events(events: List[Dict] | None) -> None:
    """
    Adds _time and _ENTRY_STATUS fields to events
    Args:
        events: List of events
    Returns:
        None
    """
    if events:
        for event in events:
            created = event.get('created')
            if created:
                created = datetime.fromisoformat(created)

            modified = event.get('modified')
            if modified:
                modified = datetime.fromisoformat(modified)

            if created and modified and modified > created:
                event['_time'] = modified.strftime(DATE_FORMAT)
                event["_ENTRY_STATUS"] = "modified"
            elif created:
                event['_time'] = created.strftime(DATE_FORMAT)
                event["_ENTRY_STATUS"] = "new"


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    base_url = params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_events_per_fetch = arg_to_number(params.get('max_events_per_fetch')) or 50000

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)
        demisto.debug("finished initializing client, starting execution")

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'identitynow-get-events':
            limit = arg_to_number(args.get('limit')) or 50
            should_push_events = argToBoolean(args.get('should_push_events'))
            time_to_start = arg_to_datetime(args.get('from_date'))
            formatted_time_to_start = time_to_start.strftime(DATE_FORMAT) if time_to_start else DEFAULT_LOOKBACK
            id_to_start = args.get('from_id') or '0'
            events, results = get_events(client, limit, from_date=formatted_time_to_start, from_id=id_to_start)
            return_results(results)
            if should_push_events:
                add_time_and_status_to_events(events)
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_and_status_to_events(events)
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
