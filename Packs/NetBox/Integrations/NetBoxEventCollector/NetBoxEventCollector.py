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
DEFAULT_LIMIT = 1000

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """
    def http_request(self, url_suffix=None, full_url=None, params=None):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            full_url=full_url,
            params=params
        )

    def search_events(self, url_suffix, limit=DEFAULT_LIMIT, prev_id=0, ordering=''):
        """
        Searches for NetBox alerts using the '/<log_type>' API endpoint for log_type in LOG_TYPES.
        All the parameters are passed directly to the API as HTTP POST parameters in the request
        Args:
            limit: int, the limit of the results to return per log_type.
            prev_id: dict of previous ids that was fetched fot each log_type.
            ordering: boll, if is True this will return the data starting with the oldest, otherwise, the opposite.
        Returns:
            dict: A dict containing the next_run
            list: A list containing the events
        """
        next_id = prev_id
        results: List[Dict] = []

        next_page = True
        params = {
            'limit': limit,
            'ordering': ordering,
            'id__gte': next_id,
        }

        while next_page and len(results) < limit:
            full_url = next_page if type(next_page) == str else ''
            response = self.http_request(url_suffix=url_suffix, full_url=full_url, params=params)

            results += response.get('results', [])

            next_page = response.get('next')
            params['limit'] = limit - len(results)

            if results:
                next_id = results[-1]['id'] + 1

        return next_id, results

    def get_first_fetch_id(self, url_suffix, params):
        """
        Sets the first fetch ids for each log type.
        Args:
            first_fetch_time: int, the first fetch time in timestamp.
        """
        first_log = self.http_request(url_suffix=url_suffix, params={'ordering': 'id', 'limit': 1} | params)
        try:
            next_run = first_log.get('results', [{}])[0].get('id')
        except IndexError:
            next_run = None

        return next_run


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): NetBox client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        client.search_events(url_suffix=LOG_TYPES[0], limit=1)

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, limit: int):
    events: List[Dict] = []
    hr = ''
    for log_type in LOG_TYPES:
        _, events_ = client.search_events(url_suffix=log_type, limit=limit)
        if events_:
            hr += tableToMarkdown(name=f'{log_type} Events', t=events_)
            events += events_
        else:
            hr = f'No events found for {log_type}.'

    return events, hr


def fetch_events(client: Client, max_fetch: int, last_run: Dict[str, int],
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
    # In the first fetch, get the ids for the first fetch time
    first_fetch_time_strftime = dateparser.parse(str(first_fetch_time)).strftime(DATE_FORMAT)  # type: ignore
    params = {'journal-entries': {'created_after': first_fetch_time_strftime},
              'object-changes': {'time_after': first_fetch_time_strftime}}
    for log_type in LOG_TYPES:
        if last_run.get(log_type) is None:
            last_run[log_type] = client.get_first_fetch_id(url_suffix=log_type,
                                                           params=params[log_type])

    next_run = last_run.copy()
    events = []

    for log_type in LOG_TYPES:
        if last_run[log_type] is None:
            continue
        next_run[log_type], events_ = client.search_events(url_suffix=log_type,
                                                           limit=max_fetch,
                                                           ordering='id',
                                                           prev_id=last_run[log_type])
        events += events_

    demisto.info(f'Fetched events with ids: {", ".join(f"{log_type}: {id_}" for log_type, id_ in last_run.items())}.')

    # Save the next_run as a dict with the last_fetch key to be stored
    demisto.info(f'Setting next run with ids: {", ".join(f"{log_type}: {id_}" for log_type, id_ in next_run.items())}.')
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
    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_LIMIT))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))

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
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in ('netbox-get-events', 'fetch-events'):
            if command == 'netbox-get-events':
                should_push_events = argToBoolean(args.get('should_push_events'))
                events, results = get_events(client, limit=limit)  # type: ignore
                return_results(results)

            else:  # command == 'fetch-events':
                should_push_events = True
                last_run = demisto.getLastRun()
                next_run, events = fetch_events(
                    client=client,
                    max_fetch=max_fetch,  # type: ignore
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
