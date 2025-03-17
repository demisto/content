import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
from typing import Any, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

VENDOR = 'runzero'
PRODUCT = 'runzero'
DEFAULT_LIMIT = "1000"

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any business logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url, verify, proxy, client_secret, client_id):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        data = {
            'client_secret': client_secret,
            'client_id': client_id,
            'grant_type': 'client_credentials',
        }
        self.data = data

    def get_api_token(self):
        """
        Get api token for RunZero account API requests.
        """
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        try:
            api_token_res = self._http_request(
                method='POST',
                url_suffix='/account/api/token',
                headers=headers,
                data=self.data,
            )
        except Exception as e:
            if 'Forbidden' in str(e):
                raise DemistoException('Authorization Error: make sure API Key is correctly set')
            else:
                raise e
        return api_token_res.get('access_token', '')

    def http_request(self, method: str, url_suffix: str, params: dict):
        api_token = self.get_api_token()

        headers = {
            'Authorization': f'Bearer {api_token}'
        }

        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            headers=headers,
        )

    def fetch_system_event_logs(self, search_query: str) -> list:
        """
        Searches for RunZero system event logs using the '/account/events.json' API endpoint.
        search_query parameter is passed directly to the API as HTTP POST parameter in the request

        Args:
            search_query (str): Query to search for. Using the created_at:>epoch_time to filter results.

        Returns:
            list: list of RunZero system event logs as dicts.
        """
        request_params: dict[str, str] = {"search": search_query}

        return self.http_request(
            method='GET',
            url_suffix='/account/events.json',
            params=request_params,
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): RunZeroEventCollector client to use.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    fetch_events(
        client=client,
        max_results=1,
        last_run={},
        first_fetch_time=first_fetch_time
    )

    return 'ok'


def sort_events(events: list) -> list:
    return sorted(events, key=lambda x: x['created_at'])


def get_events_command(
    client: Client, query_string: str, limit: int
) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Gets all the events from the RunZero API for each log type.
    Args:
        client (Client): RunZero client to use.
        limit: int, the limit of the results to return per log_type.
    Returns:
        list: A list containing the events
        CommandResults: A CommandResults object that contains the events in a table format.
    """
    events: list[dict] = []
    hr = ''
    temp_events = client.fetch_system_event_logs(query_string)
    temp_events = sort_events(temp_events)
    limited_events = temp_events[:limit]
    if limited_events:
        hr += tableToMarkdown(name='Events', t=limited_events)
        for event in limited_events:
            event = add_time_to_event(event)
            events.append(event)
    else:
        hr = 'No events found.'

    return events, CommandResults(readable_output=hr)


def add_time_to_event(event: dict):
    event_created_time = int(event.get('created_at', '0'))
    event_created_time_ms = event_created_time * 1000
    event['_time'] = timestamp_to_datestring(event_created_time_ms)
    return event


def fetch_events(client: Client, max_results: int, last_run: dict[str, int],
                 first_fetch_time: int | None) -> tuple[dict[str, int], list[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that events are fetched only onces and no events are missed.
    By default it's invoked by XSIAM every minute. It will use last_run to save the timestamp of the last event it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): RunZero client to use.
        max_results (int): Maximum numbers of events per fetch.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """

    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)

    events: list[dict[str, Any]] = []
    search_query = f'created_at:>{latest_created_time}'
    temp_events = client.fetch_system_event_logs(
        search_query=search_query
    )
    temp_events = sort_events(events=temp_events)
    limited_events = temp_events[:max_results]

    for event in limited_events:
        event_created_time = int(event.get('created_at', '0'))

        if last_fetch:
            if event_created_time <= last_fetch:
                continue

        events.append(add_time_to_event(event))
        # Update last run and add event if the event is newer than last fetch
        if event_created_time > latest_created_time:
            latest_created_time = event_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client_id = params.get('client_id', '')
    client_secret = params.get('client_secret', {}).get('password', '')
    base_url = urljoin(params.get('url'), '/api/v1.0')
    verify_certificate = not params.get('insecure', False)
    try:
        first_fetch_time = arg_to_datetime(
            arg=params.get('first_fetch', '3 days'),
            arg_name='First fetch time',
            required=True
        )
        first_fetch_epoch_time = int(first_fetch_time.timestamp()) if first_fetch_time else None  # type: ignore

        if not first_fetch_epoch_time:
            raise DemistoException('Did not set first_fetch_time.')

        proxy = params.get('proxy', False)
        demisto.debug(f'Command being called is {command}')

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            client_secret=client_secret,
            client_id=client_id,
        )

        if command == 'test-module':
            result = test_module(client, first_fetch_epoch_time)
            return_results(result)

        elif command == 'runzero-get-events':
            events, results = get_events_command(
                client, query_string=f'created_at:>{first_fetch_epoch_time}',
                limit=arg_to_number(args.get("limit", DEFAULT_LIMIT))  # type: ignore
            )
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

        elif command == 'fetch-events':
            max_results = arg_to_number(arg=params.get('max_fetch'))

            next_run, events = fetch_events(
                client=client,
                max_results=max_results,  # type: ignore
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_epoch_time
            )

            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
