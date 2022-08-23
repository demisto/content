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
    def __init__(self, base_url: str, verify: bool, proxy: bool, headers: dict[str, str]):
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


def eliminate_duplicated_events(fetched_events: list[dict], last_run: date):
    """
    create a new list out of a given a list that include only events that occurred after that latest event from previous run.

    Args:
        fetched_events (list[dict]): the list of the fetched events.
        last_run (date): the occurred time of the lastest event for previous run.

    Returns:
        list: A list containing only events that occurred after the last run.
    """
    return [event for event in fetched_events if event.get('occurred_time', datetime.now()) > last_run]


def check_if_last_run_reached(last_run: date, earliest_fetched_event: dict[str, Any]):
    """
    Compare the latest event from previous fetch interval with the latest event in the page from the current fetch interval
    To check if the latest event was reached.

    Args:
        earliest_fetched_event (dict): the earliest event from the current fetch interval.
        last_run (date): the occurred time of the lastest event for previous run.

    Returns:
        list: A list containing only events that occurred after the last run.
    """
    return last_run <= earliest_fetched_event.get('occurred_date', datetime.now())


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, first_fetch_time: Optional[datetime],
                 last_run: dict[str, date] = None) -> tuple[List[Dict], dict[str, date]]:
    """
    Fetches events from the KnowBe4_KMSAT queue.
    """
    query_params = {'page': 1, 'per_page': 100}
    events: List[Dict] = []
    if last_run:
        #  if max fetch is None, all events will be fetched until there aren't anymore in the queue (until we get 204)
        while True:
            response = client.get_events_request(params=query_params)
            # if response.status_code == 204:  # if we got 204, it means there aren't events in the queue, hence breaking.
            #     break
            fetched_events = response.json().get('data') or []
            demisto.info(f'fetched events length: ({len(fetched_events)})')
            demisto.debug(f'fetched events: ({fetched_events})')
            events.extend(eliminate_duplicated_events(fetched_events, last_run.get('latest_event_time', datetime.now())))
            is_last_run_reached = check_if_last_run_reached(last_run.get('latest_event_time', datetime.now()), events[0])
            if not response.get('meta', {}).get('next_page') or is_last_run_reached:
                break
            else:
                query_params['page'] = response.get('meta', {}).get('next_page', 1)

    else:
        a = 5
        # to do: implement a mechanism to collect events from all days between first fetch and current date
    new_last_run: dict[str, date] = {'latest_event_time': events[0].get('occurred_date')}
    demisto.info(f'Done fetching {len(events)} events, Setting new_last_run = {new_last_run}.')
    return events, new_last_run


def test_module(client: Client) -> str:
    """
    Testing we have a valid connection to Saas-Security.
    """
    client.get_events_request()
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()

    base_url: str = params['url'].rstrip('/')
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    first_fetch_time = arg_to_datetime(params.get('first_fetch', '3 days'))
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
        else:
            raise ValueError(f'Command {command} is not implemented in this integration')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
