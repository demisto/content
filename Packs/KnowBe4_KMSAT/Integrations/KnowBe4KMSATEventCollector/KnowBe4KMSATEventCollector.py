from datetime import date
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_EVENTS_PER_REQUEST = 100

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the KnowBe4 KMSAT platform, and does not contain any XSOAR logic.

    :param base_url (str): Saas Security server url.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    :param headers (dict[str, str]): the requests header.
    """
    @logger
    def __init__(self, base_url: str, verify: bool = False, proxy: bool = False, headers: dict[str, str] = {}):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.headers = headers

    def http_request(self, method: str = 'GET', params: dict = None, url_suffix: str = '',
                     resp_type: str = 'response', ok_codes: list[int] = [200]):
        """
        Overrides Base client request function.

        :return: The http response
        """
        # token = self.get_access_token()
        return super()._http_request(headers=self.headers, method=method, params=params,
                                     url_suffix=url_suffix, resp_type=resp_type, ok_codes=ok_codes)  # type: ignore[misc]

    def get_events_request(self, params: dict = None):
        return self.http_request(
            method='GET',
            url_suffix='/events',
            resp_type='response',
            ok_codes=[200, 204],
            params=params
        )


''' HELPER FUNCTIONS '''


def validate_limit(limit: Optional[int]):
    """
    Validate that the limit/max fetch is a number divisible by the MAX_EVENTS_PER_REQUEST (100) and that it is not
    a negative number.
    """
    if limit:
        if limit % MAX_EVENTS_PER_REQUEST != 0:
            raise DemistoException(f'fetch limit parameter should be divisible by {MAX_EVENTS_PER_REQUEST}')

        if limit <= 0:
            raise DemistoException('fetch limit parameter cannot be negative number or zero')


def eliminate_duplicated_events(fetched_events: list[dict], last_run: dict):
    """
    create a new list out of a given a list that include only events that occurred after that latest event from previous run.

    Args:
        fetched_events (list[dict]): the list of the fetched events.
        last_run (date): the occurred time of the lastest event for previous run.

    Returns:
        list: A list containing only events that occurred after the last run.
    """
    last_run_time = last_run.get('latest_event_time', datetime.now())
    return [event for event in fetched_events if event.get('occurred_date', datetime.now()) > last_run_time]


def check_if_last_run_reached(last_run: dict, earliest_fetched_event: dict[str, Any]):
    """
    Compare the latest event from previous fetch interval with the latest event in the page from the current fetch interval
    To check if the latest event was reached.

    Args:
        earliest_fetched_event (dict): the earliest event from the current fetch interval.
        last_run (date): the occurred time of the lastest event for previous run.

    Returns:
        list: A list containing only events that occurred after the last run.
    """
    last_run_time = last_run.get('latest_event_time', datetime.now())
    return last_run_time >= earliest_fetched_event.get('occurred_date', datetime.now())


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, first_fetch_time: Optional[datetime],
                 last_run: dict[str, date] = None) -> tuple[List[Dict], dict[str, date]]:
    """
    Fetches events from the KnowBe4_KMSAT queue.
    """
    query_params = {'page': 1, 'per_page': 100}
    events: List[Dict] = []
    if not last_run:
        last_run = {}
    #  if max fetch is None, all events will be fetched until there aren't anymore in the queue (until we get 204)
    while True:
        response = client.get_events_request(params=query_params)
        # if response.status_code == 204:  # if we got 204, it means there aren't events in the queue, hence breaking.
        #     break
        fetched_events = response.json().get('data') or []
        demisto.info(f'fetched events length: ({len(fetched_events)})')
        demisto.debug(f'fetched events: ({fetched_events})')
        events.extend(eliminate_duplicated_events(fetched_events, last_run))
        is_last_run_reached = check_if_last_run_reached(last_run, events[-1])
        if not response.get('meta', {}).get('next_page') or is_last_run_reached:
            break
        else:
            query_params['page'] = response.get('meta', {}).get('next_page', 1)
    new_last_run: dict[str, date] = {'latest_event_time': events[0].get('occurred_date')}
    demisto.info(f'Done fetching {len(events)} events, Setting new_last_run = {new_last_run}.')
    return events, new_last_run


def test_module(client: Client) -> str:
    """
    Testing we have a valid connection to Saas-Security.
    """
    client.get_events_request()
    return 'ok'


def get_events_command(client: Client, args: Dict, max_fetch: Optional[int], vendor: str,
                       product: str) -> Union[str, CommandResults]:
    """
    Fetches events from the saas-security queue and return them to the war-room.
    in case should_push_events is set to True, they will be also sent to XSIAM.
    """
    should_push_events = argToBoolean(args.get('should_push_events'))

    if events := fetch_events_from_saas_security(client=client, max_fetch=max_fetch):
        if should_push_events:
            send_events_to_xsiam(events=events, vendor=vendor, product=product)
        return CommandResults(
            readable_output=tableToMarkdown(
                'SaaS Security Logs',
                events,
                headers=['log_type', 'item_type', 'item_name', 'timestamp', 'serial'],
                headerTransform=underscoreToCamelCase,
                removeNull=True
            ),
            raw_response=events,
            outputs=events,
            outputs_key_field=['timestamp', 'log_type', 'item_name', 'item_type'],
            outputs_prefix='SaasSecurity.Event'
        )
    return 'No events were found.'


def fetch_events_from_saas_security(client: Client, max_fetch: Optional[int] = None) -> List[Dict]:
    """
    Fetches events from the saas-security queue.
    """
    events: List[Dict] = []
    under_max_fetch = True

    #  if max fetch is None, all events will be fetched until there aren't anymore in the queue (until we get 204)
    while under_max_fetch:
        response = client.get_events_request()
        if response.status_code == 204:  # if we got 204, it means there aren't events in the queue, hence breaking.
            break
        fetched_events = response.json().get('events') or []
        demisto.info(f'fetched events length: ({len(fetched_events)})')
        demisto.debug(f'fetched events: ({fetched_events})')
        events.extend(fetched_events)
        if max_fetch:
            under_max_fetch = len(events) < max_fetch

    return events


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    base_url: str = params['url'].rstrip('/')
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    first_fetch_time = arg_to_datetime(params.get('first_fetch', '3 days'))
    max_fetch = arg_to_number(args.get('limit') or params.get('max_fetch'))
    validate_limit(max_fetch)
    proxy = demisto.params().get('proxy', False)
    vendor, product = params.get('vendor'), params.get('product')
    headers = {'Authorization': f'Bearer {api_key}'}

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            events, last_run = fetch_events(client=client, first_fetch_time=first_fetch_time, last_run=last_run)
            send_events_to_xsiam(
                events,
                vendor=vendor,
                product=product
            )
            demisto.setLastRun(last_run)
        elif command == 'kms-get-events':
            return_results(get_events_command(
                client=client, args=args, max_fetch=max_fetch, vendor=vendor, product=product)
            )
        else:
            raise ValueError(f'Command {command} is not implemented in this integration')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
