import uuid
import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'sailpoint'
PRODUCT = 'identitynow'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """
    def __init__(self, client_id: str, client_secret: str, base_url: str, proxy: bool, verify: bool, token: str|None =None):
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
        """
        url = urljoin(self._base_url, "oauth/token")
        resp = self._http_request(
            method='POST',
            url_suffix=url,
            data={
                'client_id': self.client_id,
                'grant_type': 'client_credentials',
                'client_secret': self.client_secret
            },
            headers = {"scope": "sp:scope:all"}
        )

        token = resp.get('access_token')
        now_timestamp = arg_to_datetime('now').timestamp()  # type:ignore
        expiration_time = now_timestamp + resp.get('expires_in')

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
            return token

        # else generate a token and update the integration context accordingly
        token = self.generate_token()

        return token
    
    

    def search_events(self, prev_id: int, limit: int, from_date: str | None = None) -> List[Dict]:  # noqa: E501
        """
        """
        query = {"indices": ["events"],
        "queryType": "SAILPOINT",
        "queryVersion": "5.2",
        "query":
        { "query": "type:*" }
        }
        return self._http_request(method='POST', url_suffix='/v3/search', data=query)



def test_module(client: Client, first_fetch_time: str) -> str:
    """
    """

    try:
        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get('limit') or 50
    from_date = args.get('from_date')
    events = client.search_events(
        prev_id=0,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: dict[str, int],
                 first_fetch_time, max_events_per_fetch: int
                 ) -> tuple[Dict, List[Dict]]:
    """
    """
    prev_id = last_run.get('prev_id', None)
    if not prev_id:
        prev_id = 0

    events = client.search_events(
        prev_id=prev_id,
        limit=max_events_per_fetch,
        from_date=first_fetch_time,
    )
    demisto.debug(f'Fetched event with id: {prev_id + 1}.')

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'prev_id': prev_id + 1}
    demisto.debug(f'Setting next run {next_run}.')
    return next_run, events


''' MAIN FUNCTION '''


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
            create_time = arg_to_datetime(arg=event.get('created_time'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def main() -> None:  # pragma: no cover
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

    # How much time before the first fetch to retrieve events
    first_fetch_time = datetime.now().isoformat()
    max_events_per_fetch = params.get('max_events_per_fetch') or 50000

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_time)
            return_results(result)

        elif command == 'identitynow-get-events':
            should_push_events = argToBoolean(args.pop('should_push_events'))
            events, results = get_events(client, args=args)
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
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                max_events_per_fetch=max_events_per_fetch,
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
