import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date

import urllib3
from CommonServerUserPython import *  # noqa

from typing import Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'knowbe4'
PRODUCT = 'kmsat'

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

    def get_events_request(self, params: dict = None):  # pragma: no cover
        try:
            return self.http_request(
                method='GET',
                url_suffix='/events',
                resp_type='response',
                ok_codes=[200, 204],
                params=params
            )
        except Exception as e:
            if 'Limit Exceeded' in str(e):
                raise DemistoException("You've reached the daily api-call limit for your key.\n"
                                       "Please wait for tomorrow to reset your calls limit or upgrade your key.")
            else:
                raise DemistoException(str(e))


''' HELPER FUNCTIONS '''


def eliminate_duplicated_events(fetched_events: list[dict], last_run: dict[str, date]):
    """
    create a new list out of a given a list that include only events that occurred after that latest event from previous run.

    Args:
        fetched_events (list[dict]): the list of the fetched events.
        last_run (dict[str, date]): the occurred time of the lastest event for previous run.

    Returns:
        list: A list containing only events that occurred after the last run.
    """
    last_run_time = last_run.get('latest_event_time')
    return [event for event in fetched_events if parse_date_string(event.get('occurred_date')) > last_run_time]


def check_if_last_run_reached(last_run: dict[str, date], earliest_fetched_event: dict[str, Any]):
    """
    Compare the latest event from previous fetch interval with the latest event in the page from the current fetch interval
    To check if the latest event was reached.

    Args:
        earliest_fetched_event (dict): the earliest event from the current fetch interval.
        last_run (dict[str, date]): the occurred time of the lastest event for previous run.

    Returns:
        list: A list containing only events that occurred after the last run.
    """
    last_run_time = last_run.get('latest_event_time')
    return last_run_time >= parse_date_string(earliest_fetched_event.get('occurred_date'))


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, first_fetch_time: Optional[datetime] = datetime.now(),
                 last_run: dict[str, date] = {}) -> tuple[List[Dict], dict[str, date]]:
    """
    Fetches events from the KnowBe4_KMSAT queue.
    """
    query_params = {'page': 1, 'per_page': 100}
    events: List[Dict] = []
    if not last_run and first_fetch_time:
        last_run['latest_event_time'] = first_fetch_time
    elif type(last_run.get('latest_event_time')) is str:
        last_run['latest_event_time'] = parse_date_string(last_run.get('latest_event_time'))
    while True:
        response = client.get_events_request(params=query_params).json()
        fetched_events = response.get('data') or []
        if not fetched_events:
            demisto.debug("no events fetched from the api at all")
            break
        demisto.info(f'fetched events length: ({len(fetched_events)})')
        demisto.debug(f'fetched events: ({fetched_events})')
        is_last_run_reached = check_if_last_run_reached(last_run, fetched_events[-1])
        if not response.get('meta', {}).get('next_page') or is_last_run_reached:
            events.extend(eliminate_duplicated_events(fetched_events, last_run))
            break
        else:
            events.extend(fetched_events)
            query_params['page'] = response.get('meta', {}).get('next_page', 1)
    new_last_run_obj: dict = \
        {'latest_event_time': events[0].get('occurred_date') if events else datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)}
    demisto.info(f'Done fetching {len(events)} events, Setting new_last_run = {new_last_run_obj}.')
    return events, new_last_run_obj


def test_module(client: Client) -> str:
    """
    Testing we have a valid connection to Saas-Security.
    """
    try:
        client.get_events_request()
        return 'ok'
    except Exception as e:
        if 'Limit Exceeded' in str(e):
            raise DemistoException("You've reached the daily api-call limit for your key.\n"
                                   "Please wait for tomorrow to reset your calls limit or upgrade your key.")
        elif "Internal Server Error" in str(e):
            raise DemistoException("Please make sure you've entered a valid api-key and chose the right server url.")
        else:
            raise DemistoException(str(e))


def get_events_command(client: Client, args: Dict, vendor: str, product: str) -> Union[str, CommandResults]:
    """
    Fetches events from the KnowBe4-KMSAT queue and return them to the war-room.
    in case should_push_events is set to True, they will be also sent to XSIAM.
    """
    should_push_events = argToBoolean(args.get('should_push_events'))
    params = {'per_page': 100}
    args.pop('should_push_events')
    params.update(args)
    response = client.get_events_request(params)
    events: List[Dict] = response.json().get('data') or []
    if events:
        if should_push_events:
            send_events_to_xsiam(events=events, vendor=vendor, product=product)
        return CommandResults(
            readable_output=tableToMarkdown(
                'KnowBe4 KMSAT Logs',
                events,
                # headers=['log_type', 'item_type', 'item_name', 'timestamp', 'serial'],
                headerTransform=underscoreToCamelCase,
                removeNull=True
            ),
            raw_response=events,
            outputs=events,
            # outputs_key_field=['timestamp', 'log_type', 'item_name', 'item_type'],
            outputs_prefix='KMSat.Event'
        )
    return CommandResults(readable_output='No events were found.')


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    base_url: str = params['url'].rstrip('/')
    api_key = params.get('credentials', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    first_fetch_time = arg_to_datetime(params.get('first_fetch', '1 day'))
    proxy = demisto.params().get('proxy', False)
    vendor = VENDOR
    product = PRODUCT
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
                client=client, args=args, vendor=vendor, product=product)
            )
        else:
            raise ValueError(f'Command {command} is not implemented in this integration')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
