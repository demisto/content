from datetime import datetime
import demistomock as demisto
from CommonServerPython import *
import urllib3
from dateutil import parser

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = 'sailpoint'
PRODUCT = 'identitynow'
CURRENT_TIME_STR = datetime.now().strftime(DATE_FORMAT)

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
        demisto.debug(f'Generated token that expires at: {expiration_time}.')
        integration_context = get_integration_context()
        integration_context.update({'token': token})
        # Subtract 60 seconds from the expiration time to make sure the token is still valid
        integration_context.update({'expires': expiration_time - 60})
        set_integration_context(integration_context)

        return token

    def get_token(self) -> str:
        """
        Obtains token from integration context if available and still valid.
        After expiration, new token are generated and stored in the integration context.
        Returns:
            str: token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        token = integration_context.get('token', '')
        valid_until = integration_context.get('expires')

        now_timestamp = arg_to_datetime('now').timestamp()  # type:ignore
        # if there is a key and valid_until, and the current time is smaller than the valid until
        # return the current token
        if token and valid_until and now_timestamp < valid_until:
            demisto.debug(f'Using existing token that expires at: {valid_until}.')
            return token

        # else generate a token and update the integration context accordingly
        token = self.generate_token()
        demisto.debug('Generated a new token.')

        return token

    def search_events(self, from_date: str, limit: int, prev_id: str | None = None) -> List[Dict]:
        """
        Searches for events in SailPoint IdentityNow
        Args:
            from_date: The date from which to fetch events
            limit: Maximum number of events to fetch
            prev_id: The id of the last event fetched
        Returns:
            List of events
        """
        query: Dict = {
            "indices": ["events"],
            "queryType": "SAILPOINT",
            "queryVersion": "5.2",
            "sort": ["+created"] if not prev_id else ["+id"],
        }
        if prev_id:
            query["query"] = {"query": "type:* "}
            query["searchAfter"] = [prev_id]
        else:
            query["query"] = {"query": f"type:* AND created: [{from_date} TO now]"}
            query["timeZone"] = "GMT"

        url_suffix = f'/v3/search?limit={limit}'
        demisto.debug(f'Searching for events with query: {query}.')
        return self._http_request(method='POST', headers=self.headers, url_suffix=url_suffix, data=json.dumps(query))


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
            limit=1,
            last_run={},
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, from_date: str, from_id: str | None, limit: int = 50) -> tuple[List[Dict], CommandResults]:
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
        limit=limit
    )
    demisto.debug(f'Got {len(events)} events.')
    hr = tableToMarkdown(name='Test Events', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client,
                 limit: int, last_run: dict) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from the SailPoint IdentityNow API
    Args:
        client: Client object with the API client
        last_run: Dict containing the last run data
        limit: Maximum number of events to fetch per call
    Returns:
        Tuple with the next run data and the list of events fetched
    """
    # currently the API fails fetching events by id, so we are fetching by date only.
    # Once the issue is resolved, we just need to uncomment the commented lines,
    # and remove the dedup function and last_fetched_ids from everywhere..
    demisto.debug(f'Starting fetch_events with last_run: {last_run}.')
    # last_fetched_id = last_run.get('prev_id')
    last_fetched_creation_date = last_run.get('prev_date', CURRENT_TIME_STR)
    last_fetched_ids: list = last_run.get('last_fetched_ids', [])

    all_events = []
    remaining_events_to_fetch = limit
    # since we allow the user to set the limit to 50,000, but the API only allows 10000 events per call
    # we need to make multiple calls to the API to fetch all the events
    while remaining_events_to_fetch > 0:
        current_batch_to_fetch = min(remaining_events_to_fetch, 10000)
        demisto.debug(f'trying to fetch {current_batch_to_fetch} events.')

        events = client.search_events(
            # prev_id=last_fetched_id
            from_date=last_fetched_creation_date,
            limit=current_batch_to_fetch
        )
        demisto.debug(f'Successfully fetched {len(events)} events in this cycle.')
        if not events:
            demisto.debug('No events fetched. Exiting the loop.')
        events = dedup_events(events, last_fetched_ids)
        if events:
            last_fetched_event = events[-1]
            last_fetched_id = last_fetched_event['id']
            last_fetched_creation_date = last_fetched_event['created']
            demisto.debug(
                f'information of the last event in this cycle: id: {last_fetched_id}, created: {last_fetched_creation_date}.')
            remaining_events_to_fetch -= len(events)
            demisto.debug(f'{remaining_events_to_fetch} events are left to fetch in the next calls.')
            last_fetched_ids = get_last_fetched_ids(events)
            all_events.extend(events)
        else:
            # to avoid infinite loop, if no events are fetched, or all events are duplicates, exit the loop
            break
    # next_run = {'prev_id': last_fetched_id, 'prev_date': last_fetched_creation_date}
    next_run = {'prev_date': last_fetched_creation_date, 'last_fetched_ids': last_fetched_ids}
    demisto.debug(f'Done fetching. Sum of all events: {len(all_events)}, the next run is {next_run}.')
    return next_run, all_events


''' HELPER FUNCTIONS '''


def dedup_events(events: List[Dict], last_fetched_ids: list) -> List[Dict]:
    """
    Dedupes the events fetched based on the last fetched ids and creation date.
    This process is based on the assumption that the events are sorted by creation date.

    Args:
        events: List of events.
        last_fetched_ids: List of the last fetched ids.
    Returns:
        List of deduped events.
    """
    if not last_fetched_ids:
        demisto.debug("No last fetched ids. Skipping deduping.")
        return events

    demisto.debug(f"Starting deduping. Number of events before deduping: {len(events)}, last fetched ids: {last_fetched_ids}")

    last_fetched_ids_set = set(last_fetched_ids)
    deduped_events = [event for event in events if event['id'] not in last_fetched_ids_set]

    demisto.debug(f"Done deduping. Number of events after deduping: {len(deduped_events)}")
    return deduped_events


def get_last_fetched_ids(events: List[Dict]) -> List[str]:
    """
    Gets the ids of the last fetched events
    Args:
        events: List of events, assumed to be sorted ASC by creation date
    Returns:
        List of the last fetched ids
    """
    last_creation_date = events[-1]['created']
    return [event['id'] for event in events if event['created'] == last_creation_date]


def add_time_and_status_to_events(events: List[Dict]) -> None:
    """
    Adds _time and _ENTRY_STATUS fields to events
    Args:
        events: List of events
    Returns:
        None
    """
    for event in events:
        created = event['created']
        created = parser.parse(created)

        modified = event.get('modified')
        if modified:
            modified = parser.parse(modified)

        is_modified = created and modified and modified > created
        event['_time'] = modified.strftime(DATE_FORMAT) if is_modified else created.strftime(DATE_FORMAT)
        event["_ENTRY_STATUS"] = "modified" if is_modified else "new"


''' MAIN FUNCTION '''


def main() -> None:     # pragma: no cover
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
    fetch_limit = arg_to_number(params.get('limit')) or 50000

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'identitynow-get-events':
            limit = arg_to_number(args.get('limit', 50)) or 50
            should_push_events = argToBoolean(args.get('should_push_events', False))
            time_to_start = arg_to_datetime(args.get('from_date'))
            formatted_time_to_start = time_to_start.strftime(DATE_FORMAT) if time_to_start else CURRENT_TIME_STR
            id_to_start = args.get('from_id')
            if not (id_to_start or time_to_start) or (id_to_start and time_to_start):
                raise DemistoException("Please provide either from_id or from_date.")
            events, results = get_events(client, from_date=formatted_time_to_start,
                                         from_id=id_to_start, limit=limit)
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
                limit=fetch_limit,
                last_run=last_run,
            )

            add_time_and_status_to_events(events)
            demisto.debug(f'Sending {len(events)} events to Xsiam.')
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(next_run)
            demisto.debug(f'Next run is set to: {next_run}.')
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
