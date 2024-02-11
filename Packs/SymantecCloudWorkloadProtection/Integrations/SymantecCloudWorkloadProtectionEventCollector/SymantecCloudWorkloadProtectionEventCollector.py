import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'symantec'
PRODUCT = 'cwp'

''' CLIENT CLASS '''

# TODO add token mechanism, 401 = Token expired
# DESCENDING = Newer first


class Client(BaseClient):

    credentials: dict = {}
    max_events_per_fetch: int = 0

    def _http_request(
        self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
        params=None, data=None, files=None, timeout=None, resp_type='json', ok_codes=None,
        return_empty_response=False, retries=0, status_list_to_retry=None, backoff_factor=5,
        raise_on_redirect=False, raise_on_status=False, error_handler=None, empty_valid_codes=None,
        params_parser=None, **kwargs
    ):
        res = super()._http_request(
            method, url_suffix, full_url, headers, auth, json_data, params, data, files, timeout,
            'response', ok_codes, return_empty_response, retries, status_list_to_retry, backoff_factor,
            raise_on_redirect, raise_on_status, error_handler, empty_valid_codes, params_parser, **kwargs
        )
        if res.status_code == 401:
            self.get_new_token()
            res = super()._http_request(
                method, url_suffix, full_url, headers, auth, json_data, params, data, files, timeout,
                'response', ok_codes, return_empty_response, retries, status_list_to_retry, backoff_factor,
                raise_on_redirect, raise_on_status, error_handler, empty_valid_codes, params_parser, **kwargs
            )
        return res.json()
    
    def get_new_token(self):
        pass

    @classmethod
    def from_params(
        cls, url: str, credentials: dict, customer_id: str,
        domain_id: str, max_events_per_fetch: str, insecure: bool,
        proxy: bool, **_
    ):
        client = cls(
            base_url=url,
            verify=(not insecure),
            proxy=proxy,
            headers={
                'content-type': 'application/json',
                'Authorization': 'Bearer {token}',
                'x-epmp-customer-id': customer_id,
                'x-epmp-domain-id': domain_id,
            },
        )
        client.credentials = {
            'client_id': credentials['identifier'],
            'client_secret': credentials['password']
        }
        client.max_events_per_fetch = arg_to_number(max_events_per_fetch) or 0
        return client

    def search_events(self):
        ...

    def search_alerts(self):
        ...


def test_module(client: Client) -> str:

    try:
        alert_status = params.get('alert_status', None)

        fetch_events(
            client=client,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
            max_events_per_fetch=1,
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def get_events(client: Client, alert_status: str, args: dict) -> tuple[List[Dict], CommandResults]:
    limit = args.get('limit', 50)
    from_date = args.get('from_date')
    events = client.search_events(
        prev_id=0,
        alert_status=alert_status,
        limit=limit,
        from_date=from_date,
    )
    hr = tableToMarkdown(name='Test Event', t=events)
    return events, CommandResults(readable_output=hr)


def fetch_events(client: Client, last_run: dict[str, int],
                 first_fetch_time, alert_status: str | None, max_events_per_fetch: int
                 ) -> tuple[Dict, List[Dict]]:
    """
    Args:
        client (Client): HelloWorld client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time: If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """
    prev_id = last_run.get('prev_id', None)
    if not prev_id:
        prev_id = 0

    events = client.search_events(
        prev_id=prev_id,
        alert_status=alert_status,
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

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client.from_params(**demisto.params())

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(
                client=client,
                last_run=last_run,
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                max_events_per_fetch=max_events_per_fetch,
            )

            add_time_to_events(events)
            send_events_to_xsiam(
                events,
                vendor=VENDOR,
                product=PRODUCT
            )
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
