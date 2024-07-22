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
DEFAULT_NOW = datetime.now().strftime(DATE_FORMAT)

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

    def search_events(self, prev_id: str| None, from_date: str, limit: int, filter_by_time: bool) -> List[Dict]:
        """
        Searches for events in SailPoint IdentityNow
        Args:
            prev_id: The id of the last event fetched
            from_date: The date from which to fetch events
            limit: Maximum number of events to fetch
        Returns:
            List of events
        """
        if not prev_id:
            demisto.debug("No ID provided, using timestamp" )
            field_to_sort_by = "created" if filter_by_time else "id"
            demisto.debug(f"{field_to_sort_by =}")
            query = {"indices": ["events"],
                    "queryType": "SAILPOINT",
                    "queryVersion": "5.2",
                    "query":
                    {"query": f"type:* AND created: [{from_date} TO now]"},
                    "timeZone": "GMT",
                    "sort": ["+" + field_to_sort_by],
                    }
        else:
             query = {"indices": ["events"],
                    "queryType": "SAILPOINT",
                    "queryVersion": "5.2",
                    "query":
                    {"query": "type:* "},
                    "sort": ["+id"],
                    "searchAfter": [prev_id]
                    }

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


def get_events(client: Client, from_date: str, from_id: str| None, limit: int = 50,
               filter_by_time: bool =False) -> tuple[List[Dict], CommandResults]:
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
        filter_by_time= filter_by_time
    )
    demisto.debug(f'Fetched {len(events)} events.')
    hr = tableToMarkdown(name='Test Events', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client,
                 limit: int, last_run: dict[str, str],
                 filter_by_time: bool = False
                 ) -> tuple[Dict, List[Dict]]:
    """
    Fetches events from the SailPoint IdentityNow API
    Args:
        client: Client object with the API client
        last_run: Dict containing the last run data
        limit: Maximum number of events to fetch per call
    Returns:
        Tuple with the next run data and the list of events fetched
    """
    demisto.debug(f'last_run: {last_run}.')
    last_fetched_id = last_run.get('prev_id')
    last_fetched_creation_date = last_run.get('prev_date', DEFAULT_NOW)
    last_fetched_ids = last_run.get('last_fetched_ids', [])

    all_events = []
    remaining_events_to_fetch = limit
    # since we allow the user to set the limit to 50,000, but the API only allows 10000 events per call
    # we need to make multiple calls to the API to fetch all the events
    while remaining_events_to_fetch > 0:
        current_batch_to_fetch = min(remaining_events_to_fetch, 10000)
        demisto.debug(f'trying to fetch {current_batch_to_fetch} events.')

        events = client.search_events(
            prev_id=last_fetched_id if not filter_by_time else None,
            from_date= last_fetched_creation_date,
            limit=current_batch_to_fetch,
            filter_by_time = filter_by_time
        )
        demisto.debug(f'Successfully fetched {len(events)} events in this cycle.')
        events = dedup(events =events, last_run=last_run)
        if events:
            last_fetched_event = events[-1]
            last_fetched_id = last_fetched_event['id']
            last_fetched_creation_date = last_fetched_event['created']
            demisto.debug(f"last event = {last_fetched_event}")
            demisto.debug(f'information of the last event in this cycle: id: {last_fetched_id}, created: {last_fetched_creation_date}.')
            remaining_events_to_fetch -= len(events)
            demisto.debug(f'{remaining_events_to_fetch} events are left to fetch in the next calls.')
            last_fetched_ids = get_last_fetched_ids(events, last_fetched_creation_date)
            all_events.extend(events)
        else:
            #to avoid infinite loop, if no events are fetched, or all events are duplicates, exit the loop
            break

    last_fetched_ids = get_last_fetched_ids(all_events, last_fetched_creation_date)
    next_run = {'prev_id': last_fetched_id, 'prev_date': last_fetched_creation_date, 'last_fetched_ids': last_fetched_ids}
    demisto.debug(f'Done fetching. Sum of all events: {len(all_events)}, the next run is {next_run}.')
    return next_run, all_events


''' HELPER FUNCTIONS '''


def dedup(events: List[Dict], last_run: Dict) -> List[Dict]:
    last_creation_date = last_run.get('prev_date')
    last_fetched_ids = last_run.get('last_fetched_ids', [])
    demisto.debug(f"Starting deduping. {len(events)=} {last_creation_date=} {last_fetched_ids=}")

    if not last_creation_date or not last_fetched_ids:
        demisto.debug("Last run is missing data, skipping deduping.")
        return events

    for event in events:
        if event['created'] != last_creation_date:
            demisto.debug(f"Done deduping. Number of events after deduping: {len(events)}")
            return events
        if event['id'] in last_fetched_ids:
            events.remove(event)
            demisto.debug(f"Removed event with id: {event['id']}")
    demisto.debug(f"Done deduping. Number of events after deduping: {len(events)}")
    return events


def get_last_fetched_ids(events: List[Dict],last_creation_date) -> List[str]:
    list_of_ids = []
    for event in reversed(events):
        if event['created'] != last_creation_date:
            return list_of_ids
        else:
            list_of_ids.append(event['id'])
    return list_of_ids


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
                created = parser.parse(created)

            modified = event.get('modified')
            if modified:
                modified = parser.parse(modified)
            if created and modified and modified > created:
                event['_time'] = modified.strftime(DATE_FORMAT)
                event["_ENTRY_STATUS"] = "modified"
            elif created:
                event['_time'] = created.strftime(DATE_FORMAT)
                event["_ENTRY_STATUS"] = "new"


''' MAIN FUNCTION '''


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
    limit = arg_to_number(params.get('limit')) or 50000
    filter_by_time = argToBoolean(params.get('filter_by_time', False))

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
            limit = arg_to_number(args.get('limit', 50))
            should_push_events = argToBoolean(args.get('should_push_events', False))
            time_to_start = arg_to_datetime(args.get('from_date'))
            formatted_time_to_start = time_to_start.strftime(DATE_FORMAT) if time_to_start else DEFAULT_NOW
            id_to_start = args.get('from_id')
            if not (id_to_start or time_to_start):
                raise DemistoException("Either from_id or from_date must be provided.")
            if id_to_start and time_to_start:
                raise DemistoException("Both from_id and from_date cannot be provided.")
            events, results = get_events(client,from_date=formatted_time_to_start,
                                         from_id=id_to_start, limit=limit)   # type:ignore
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
                limit=limit,
                last_run=last_run,
                filter_by_time = filter_by_time
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

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
