import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Dict, List, Optional

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'NetBox'
PRODUCT = 'IRM'

LOG_TYPES = ['journal-entries', 'object-changes']


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url: str, headers: dict, verify: bool, proxy: bool, limit: int):
        self.limit = limit
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def http_request(self, url_suffix=None, full_url=None, params=None):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            full_url=full_url,
            params=params
        )

    def search_events(self, prev_ids={}, ordering=''):
        """
        Searches for NetBox alerts using the '/<log_type>' API endpoint for log_type in LOG_TYPES.
        All the parameters are passed directly to the API as HTTP POST parameters in the request
        Args:
            prev_id: dict of previous ids that was fetched fot each log_type.
            ordering: boll, if is True this will return the data starting with the oldest, otherwise, the opposite.
        Returns:
            dict: the next event
        """
        next_ids = {}
        results: List[Dict] = []

        for log_type in LOG_TYPES:
            result: List[Dict] = []
            next_page = True

            params = {
                'limit': self.limit,
                'ordering': ordering,
                'id__gt': prev_ids.get(log_type, 0)
            }

            while next_page and len(result) < self.limit:
                full_url = next_page if type(next_page) == str else ''
                response = self.http_request(url_suffix=f'/{log_type}', full_url=full_url, params=params)

                result += response.get('results', [])

                next_page = response.get('next')
                params['limit'] = self.limit - len(result)

            results += result

            if result:
                next_ids[log_type] = result[-1]['id']

        return next_ids, results

    def get_first_fetch_ids(self, first_fetch_time):
        """
        Sets the first fetch ids for each log type.
        Args:
            first_fetch_time: int, the first fetch time.
        """
        next_run: Dict[str, int] = {}

        # get the first journal-entries id
        first_fetch_time_strftime = dateparser.parse(str(first_fetch_time)).strftime(DATE_FORMAT)

        next_page = True
        while next_page:
            full_url = next_page if type(next_page) == str else ''
            response = self.http_request(url_suffix='/journal-entries', full_url=full_url,
                                         params={'limit': 100, 'ordering': 'created',
                                                 'last_updated__gte': first_fetch_time_strftime})

            next_page = response.get('next')
            results = response.get('results', [])

            for result in results:
                created = int(arg_to_datetime(result['created']).timestamp())  # type: ignore
                if created >= first_fetch_time:
                    next_run['journal-entries'] = result['id']
                    next_page = False
                    break

        # get the first object-changes id
        if next_run.get('journal-entries'):
            first_object_changes = self.http_request(url_suffix='/object-changes',
                                                     params={'ordering': 'time', 'limit': 1,
                                                             'changed_object_id': next_run['journal-entries']})
            next_run['object-changes'] = first_object_changes.get('results', [{}])[0].get('id')

        return next_run


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.limit = 1
        client.search_events()

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client):
    _, events = client.search_events()
    if events:
        hr = tableToMarkdown(name='Journal-entries and Object-changes Events',
                             t=events, headers=(events[0] | events[-1]).keys())
    else:
        hr = 'No events found.'

    return events, hr


def fetch_events(client: Client, last_run: Dict[str, int],
                 first_fetch_time: Optional[int]
                 ):
    """
    Args:
        client (Client): NetBox client to use.
        last_run (dict): A dict with a keys containing the latest events ids we got from last fetch for each log type.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    if not last_run:
        last_run = client.get_first_fetch_ids(first_fetch_time)
        if not last_run:
            return {}, []

    next_run, events = client.search_events(
        ordering='id',
        prev_ids=last_run,
    )
    demisto.info(f'Fetched events with ids: {", ".join(f"{log_type}: {id_}" for log_type, id_ in last_run.items())}')

    # Save the next_run as a dict with the last_fetch key to be stored
    demisto.info(f'Setting next run with ids: {", ".join(f"{log_type}: {id_+1}" for log_type, id_ in next_run.items())}.')
    return next_run, events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get('credentials', {}).get('password')
    base_url = urljoin(params.get('url'), '/api/extras')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch', 1000))
    limit = arg_to_number(args.get('limit'))

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Token {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            limit=limit or max_fetch)  # type: ignore

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in ('netbox-get-events', 'fetch-events'):
            if command == 'netbox-get-events':
                should_push_events = argToBoolean(args.get('should_push_events'))
                events, results = get_events(client)
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun()
                next_run, events = fetch_events(
                    client=client,
                    last_run=last_run,
                    first_fetch_time=first_fetch_timestamp
                )
                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun(next_run)

            if should_push_events:
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
