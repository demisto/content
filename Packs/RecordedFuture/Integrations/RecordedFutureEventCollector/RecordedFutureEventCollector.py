from CommonServerPython import *
import json
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
BASE_URL = 'https://api.recordedfuture.com/v2'
STATUS_TO_RETRY = [500, 501, 502, 503, 504]
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Recorded Future'
PRODUCT = 'Intelligence Cloud'

''' CLIENT CLASS '''


class Client(BaseClient):

    def _call(self, url_suffix, **kwargs):
        request_kwargs = {
            'method': 'get',
            'url_suffix': url_suffix,
            'timeout': 90,
            'retries': 3,
            'status_list_to_retry': STATUS_TO_RETRY,
        }
        request_kwargs.update(kwargs)

        return self._http_request(**request_kwargs)

    def whoami(self) -> dict[str, Any]:
        """Check whoami."""
        return self._call(url_suffix='/info/whoami')

    def get_alerts(self, params: dict = None) -> dict[str, Any]:
        """Get alerts."""
        return self._call(url_suffix='/alert/search', params=params)


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.whoami()
        return_results('ok')
    except Exception as err:
        message = str(err)
        try:
            error = json.loads(str(err).split('\n')[1])
            if 'fail' in error.get('result', dict()).get('status', ''):
                message = error.get('result', dict())['message']
        except Exception:
            message = (
                'Unknown error. Please verify that the API'
                f' URL and Token are correctly configured. RAW Error: {err}'
            )
        raise DemistoException(f'Failed due to - {message}')


def get_events(client, params: dict) -> list:
    result = client.get_alerts(params)
    events = result.get('data', {}).get('results', [])

    hr = tableToMarkdown(name='Test Event', t=events)
    return_results(CommandResults(
        readable_output=hr,
        raw_response=events
    ))

    return events


def fetch_events(client: Client, **kwargs) -> list:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.

    Returns:
        list: (list) of events that will be created in XSIAM.
    """
    params = {
        'triggered': f'[{kwargs.get("last_run")}, ]',
        'orderby': 'triggered',
        'direction': 'desc',
        'limit': kwargs.get('limit')
    }
    response = client.get_alerts(params)

    if events := response.get('data', {}).get('results'):
        last_run_event_ids = demisto.getLastRun().get('last_run_ids', set())
        if last_run_event_ids:
            events = list(filter(lambda x: x.get('id') not in last_run_event_ids, events))

        # Get the latest triggered time to start fetching the next round from this time.
        next_run_time = events[-1].get('triggered')
        # We need the IDs of the events with the same trigger time as the latest,
        # So that we can remove them in the next fetch, Since we are fetching from this time.
        next_run_event_ids = {event.get('id') for event in events if event.get('triggered') == next_run_time}

        # In case all events were triggered at the same time and the limit equals their amount,
        # We should increase the next run time, Otherwise the fetch will get stuck at this time forever.
        if len(next_run_event_ids) == len(events) == int(kwargs.get('limit')):
            next_run_time = (dateparser.parse(next_run_time) + timedelta(seconds=1)).strftime(DATE_FORMAT)

        demisto.setLastRun({'last_run_time': next_run_time, 'last_run_ids': next_run_event_ids})

        return events


''' HELPER FUNCTIONS '''


def add_time_key_to_events(events: list = None):
    """
    Adds the _time key to the events.
    Args:
        events: list, the events to add the time key to.
    """
    for event in events or []:
        event["_time"] = event.get("triggered")


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('credentials', {}).get('password')
    headers = {'X-RFToken': api_key}
    limit = args.get('limit') or params.get('limit') or 1000

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=BASE_URL,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            test_module(client)

        if command == 'recorded-future-get-events':
            events = get_events(client, params={'limit': limit})

        if command == 'fetch-events':
            last_run = demisto.getLastRun().get('last_run_time') or arg_to_datetime(params.get('first_fetch', '3 days'))
            events = fetch_events(
                client=client,
                last_run=last_run,
                limit=limit
            )

        if command == 'fetch-events' or argToBoolean(args.get('should_push_events')):
            add_time_key_to_events(events)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
