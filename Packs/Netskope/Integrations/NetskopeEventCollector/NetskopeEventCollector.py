import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

ALL_SUPPORTED_EVENT_TYPES = ['audit', 'page', 'network', 'application', 'alert']
MAX_EVENTS_PAGE_SIZE = 10000
MAX_SKIP = 50000

EXECUTION_TIMEOUT_SECONDS = 190 # 3:30 minutes
EVENT_LOGGER = {}

# Netskope response constants
WAIT_TIME = 'wait_time'     # Wait time between queries
RATELIMIT_REMAINING = "ratelimit-remaining"     # Rate limit remaining
RATELIMIT_RESET = "ratelimit-reset"     # Rate limit RESET value is in seconds

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client for Netskope RESTful API.

    Args:
        base_url (str): The base URL of Netskope.
        token (str): The token to authenticate against Netskope API.
        validate_certificate (bool): Specifies whether to verify the SSL certificate or not.
        proxy (bool): Specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, api_version: str, validate_certificate: bool, proxy: bool):
        super().__init__(base_url, verify=validate_certificate, proxy=proxy)
        if api_version == 'v1':
            self._session.params['token'] = token  # type: ignore
        else:
            self._headers = {'Netskope-Api-Token': token}

    def perform_data_export(self, endpoint, _type, index_name, operation):
        url_suffix = f'events/dataexport/{endpoint}/{_type}'
        params = {
            'index': index_name,
            'operation': operation
        }
        response = self._http_request(method='GET', url_suffix=url_suffix, params=params, resp_type='response', retries=10)
        honor_rate_limiting(headers=response.headers, endpoint=url_suffix)
        return response.json()


''' HELPER FUNCTIONS '''


def honor_rate_limiting(headers, endpoint):
    """
    Identify the response headers carrying the rate limiting value.
    If the rate limit remaining for this endpoint is 0 then wait for the rate limit reset time before sending the response to the
    client.
    """
    try:
        if remaining := headers.get(RATELIMIT_REMAINING):
            demisto.debug(f'Remaining rate limit is: {remaining}')
            if int(remaining) <= 0:
                demisto.debug(f'Rate limiting reached for the endpoint: {endpoint}')
                if to_sleep := headers.get(RATELIMIT_RESET):
                    demisto.debug(f'Going to sleep for {to_sleep} seconds to avoid rate limit error')
                    time.sleep(int(to_sleep))
                else:
                    # if the RESET value does not exist in the header then
                    # sleep for default 1 second as the rate limit remaining is 0
                    demisto.debug(f'Did not find a rate limit reset value, going to sleep for 1 second to avoid rate limit error')
                    time.sleep(1)

            elif 'alerts' in endpoint:
                demisto.debug(f'Sleeping for 1 seconds between alerts')
                time.sleep(1)

    except ValueError as ve:
        logging.error("Value error when honoring the rate limiting wait time {} {}".format(headers, str(ve)))


def populate_parsing_rule_fields(event: dict, event_type: str):
    event['source_log_event'] = event_type
    try:
        event['_time'] = timestamp_to_datestring(event['timestamp'] * 1000, is_utc=True)
    except TypeError:
        # modeling rule will default on ingestion time if _time is missing
        pass


def dedup_by_id(last_run: dict, results: list, event_type: str, limit: int):
    """
    Dedup mechanism for the fetch to check both event id and timestamp (since timestamp can be duplicate)
    Args:
        last_run: Last run.
        results: List of the events from the api.
        event_type: the event type.
        limit: the number of events to return.

    Returns:
        - list of events to send to XSIAM.
        - The new last_run (dictionary with the relevant timestamps and the events ids)

    """
    last_run_ids = set(last_run.get(f'{event_type}-ids', []))
    new_events = []
    new_events_ids = []
    new_last_run = {}

    # Sorting the list to Ascending order according to the timestamp (old one first)
    sorted_list = list(reversed(results))
    for event in sorted_list[:limit]:
        event_timestamp = event.get('timestamp')
        event_id = event.get('_id')
        event['event_id'] = event_id

        # The event we are looking at has the same timestamp as previously fetched events
        if event_timestamp == last_run[event_type]:
            if event_id not in last_run_ids:
                new_events.append(event)
                last_run_ids.add(event_id)

        # The event has a timestamp we have not yet fetched meaning it is a new event
        else:
            new_events.append(event)
            new_events_ids.append(event_id)
            # Since the event has a timestamp newer than the saved one, we will update the last run to the
            # current event time
            new_last_run[event_type] = event_timestamp

        # If we have received events with a newer time (new_event_ids list) we save them,
        # otherwise we save the list that include the old ids together with the new event ids.
        new_last_run[f'{event_type}-ids'] = new_events_ids or last_run_ids

    demisto.debug(f'Setting new last run - {new_last_run}')
    return new_events, new_last_run


''' COMMAND FUNCTIONS '''


def test_module(client: Client, api_version: str, last_run: dict, max_fetch: int) -> str:
    fetch_events_command(client, api_version, last_run, max_fetch=max_fetch, is_command=True)
    return 'ok'


def get_all_events_v2(client: Client, last_run: dict, limit: int, api_version: str, is_command: bool) -> Tuple[list, dict]:
    # We add the instance name to the index so several instances could run in parallel without effecting eachother
    if limit is None:
        limit = MAX_EVENTS_PAGE_SIZE

    all_types_events_result = []

    start_time = datetime.utcnow()
    for event_type in ALL_SUPPORTED_EVENT_TYPES:

        events, time_out = handle_data_export_single_event_type(client=client, event_type=event_type, last_run=last_run,
                                                                limit=limit, start_time=start_time)
        all_types_events_result.extend(prepare_events(events, event_type))
        if time_out:
            demisto.warning('Timeout reached, stopped pulling events')
            break

    last_run['v2']['operation'] = 'next'
    return all_types_events_result, last_run


def get_events_command(client: Client, args: Dict[str, Any], last_run: dict, api_version: str,
                       is_command: bool) -> Tuple[CommandResults, list]:
    limit = arg_to_number(args.get('limit')) or 50
    events, _ = fetch_events_command(client=client, api_version=api_version, last_run=last_run, max_fetch=limit,
                                     is_command=is_command)
    # events, _ = get_all_events_v1(client, last_run, api_version=api_version, limit=limit, is_command=is_command)

    for event in events:
        event['timestamp'] = timestamp_to_datestring(event['timestamp'] * 1000)

    readable_output = tableToMarkdown('Events List:', events,
                                      removeNull=True,
                                      headers=['_id', 'timestamp', 'type', 'access_method', 'app', 'traffic_type'],
                                      headerTransform=string_to_table_header)

    results = CommandResults(outputs_prefix='Netskope.Event',
                             outputs_key_field='_id',
                             outputs=events,
                             readable_output=readable_output,
                             raw_response=events)

    return results, events


def fetch_events_command(client, api_version, last_run, max_fetch, is_command):  # pragma: no cover
    if api_version == 'v1':
        events, new_last_run = get_all_events_v1(client, last_run=last_run, limit=max_fetch, api_version=api_version,
                                                 is_command=is_command)
    else:
        events, new_last_run = get_all_events_v2(client, last_run=last_run, limit=max_fetch, api_version=api_version,
                                                 is_command=is_command)

    return events, new_last_run


''' MAIN FUNCTION '''
original_func = split_data_to_chunks


# TODO handle in common server python
def split_data_to_chunks(data, target_chunk_size = None):
    return original_func(data, target_chunk_size=2 ** 20 * 5)


def main() -> None:  # pragma: no cover
    demisto.debug('some line\n some new line')
    params = demisto.params()

    url = params.get('url')
    api_version = params.get('api_version')
    token = params.get('credentials', {}).get('password')
    base_url = urljoin(url, f'/api/{api_version}/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    first_fetch = params.get('first_fetch')
    max_fetch = arg_to_number(params.get('max_fetch', 1000))
    vendor, product = params.get('vendor', 'netskope'), params.get('product', 'netskope_dev_2')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(base_url, token, api_version, verify_certificate, proxy)
        first_fetch = int(arg_to_datetime(first_fetch).timestamp())  # type: ignore[union-attr]

        last_run = demisto.getLastRun()
        demisto.debug(f'Running with the following last_run - {last_run}')
        if api_version == 'v1':
            for event_type in ALL_SUPPORTED_EVENT_TYPES:
                # First Fetch
                if not last_run.get(event_type):
                    last_run_id_key = f'{event_type}-ids'
                    last_run[event_type] = first_fetch
                    last_run[last_run_id_key] = last_run.get(last_run_id_key, [])
                    demisto.debug(f'V1 First Fetch - Initialize last run - {last_run}')
        else:
            if not last_run.get('v2', {}).get('operation'):
                last_run['v2'] = {'operation': first_fetch}
                demisto.debug(f'V2 First Fetch - Initialize last run - {last_run}')

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, api_version, last_run, max_fetch=MAX_EVENTS_PAGE_SIZE)  # type: ignore[arg-type]
            return_results(result)

        elif demisto.command() == 'netskope-get-events':
            results, events = get_events_command(client, demisto.args(), last_run, api_version, is_command=True)

            if argToBoolean(demisto.args().get('should_push_events', 'true')):
                send_events_to_xsiam(events=events, vendor=vendor, product=product)  # type: ignore
            return_results(results)

        elif demisto.command() == 'fetch-events':
            start = datetime.utcnow()
            demisto.debug(f'Sending request with last run {last_run}')
            events, new_last_run = fetch_events_command(client, api_version, last_run, max_fetch, is_command=False)
            demisto.debug(f'sending {len(events)} to xsiam')
            send_events_to_xsiam(events=events, vendor=vendor, product=product)
            demisto.debug(f'Setting the last_run to: {new_last_run}')

            end = datetime.utcnow()
            demisto.debug(f'Handled {len(events)} total events in {(end - start).seconds} seconds')
            demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        # TODO: Add resend
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
