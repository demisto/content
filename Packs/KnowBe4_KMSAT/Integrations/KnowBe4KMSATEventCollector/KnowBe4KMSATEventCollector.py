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


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, first_fetch_time: Optional[datetime], max_fetch: Optional[int] = None,
                 last_run: dict[str, int] = None) -> tuple[List[Dict], dict[str, int]]:
    """
    Fetches events from the KnowBe4_KMSAT queue.
    """
    if last_run:
        query_params = last_run if last_run else {'page': 0}
        query_params['per_page'] = 100
        events: List[Dict] = []
        under_max_fetch = True
        page = 0
        #  if max fetch is None, all events will be fetched until there aren't anymore in the queue (until we get 204)
        while under_max_fetch:
            response = client.get_events_request(params=query_params)
            if response.status_code == 204:  # if we got 204, it means there aren't events in the queue, hence breaking.
                break
            fetched_events = response.json().get('data') or []
            demisto.info(f'fetched events length: ({len(fetched_events)})')
            demisto.debug(f'fetched events: ({fetched_events})')
            events.extend(fetched_events)
            page = response.get('meta').get('current_page')
            query_params['page'] = page + 1
            if max_fetch:
                under_max_fetch = len(events) < max_fetch

        
    else:
        first_fetch_time = p
    new_last_run: dict[str, int] = {'page': page + 1} if page else {'page': 0}
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
    args = demisto.args()

    base_url: str = params['url'].rstrip('/')
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    first_fetch_time = arg_to_datetime(params.get('first_fetch', '3 days'))
    fetch_limit = arg_to_number(args.get('limit') or params.get('fetch_limit', '1000'))
    validate_limit(fetch_limit)
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
            events, last_run = fetch_events(client=client, first_fetch_time=first_fetch_time,
                                            max_fetch=fetch_limit, last_run=last_run)
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
