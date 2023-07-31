import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

ALL_SUPPORTED_EVENT_TYPES = ['application', 'alert', 'page', 'audit', 'network']
# ALL_SUPPORTED_ALERT_TYPES_v2 = ['policy', 'compromisedcredential', 'ctep', 'dlp', 'malsite', 'malware', 'quarantine',
MAX_EVENTS_PAGE_SIZE = 10000
MAX_SKIP = 50000

EXECUTION_TIMEOUT_SECONDS = 190  # 3:30 minutes
EVENT_LOGGER = {}

# Netskope response constants
WAIT_TIME = 'wait_time'  # Wait time between queries
RATELIMIT_REMAINING = "ratelimit-remaining"  # Rate limit remaining
RATELIMIT_RESET = "ratelimit-reset"  # Rate limit RESET value is in seconds

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

    def __init__(self, base_url: str, token: str, validate_certificate: bool, proxy: bool):
        self.fetch_status: dict = {event_type: False for event_type in ALL_SUPPORTED_EVENT_TYPES}

        headers = {'Netskope-Api-Token': token}
        super().__init__(base_url, verify=validate_certificate, proxy=proxy, headers=headers)

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


def prepare_events(events: list, event_type: str) -> list:
    for event in events:
        populate_parsing_rule_fields(event, event_type)
        event_id = event.get('_id')
        event['event_id'] = event_id

    return events

def print_event_statistics_logs(events: list, event_type: str):
    demisto.debug(f'__[{event_type}]__ - Total events fetched this round: {len(events)}')
    if events:
        event_times = f'__[{event_type}]__ - First event: {events[0].get("timestamp")} __[{event_type}]__ - Last event: {events[-1].get("timestamp")}'
        demisto.debug(event_times)


def is_execution_time_exceeded(start_time: datetime) -> bool:
    end_time = datetime.utcnow()
    secs_from_beginning = (end_time - start_time).seconds
    demisto.debug(f'Execution length so far is {secs_from_beginning} secs')

    return secs_from_beginning > EXECUTION_TIMEOUT_SECONDS


def handle_data_export_single_event_type(client: Client, event_type: str, operation: str, limit: int, start_time: datetime):
    instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')
    wait_time = 0
    events = []
    index_name = f'xsoar_collector_{instance_name}_{event_type}'

    while len(events) < limit:

        # If the execution exceeded the timeout we will break
        if is_execution_time_exceeded(start_time=start_time):
            return events, True

        # Wait time between queries
        if wait_time:
            demisto.debug(f'Going to sleep between queries, wait_time is {wait_time} seconds')
            time.sleep(wait_time)
        else:
            demisto.debug(f'No wait time received, going to sleep for 1 second')
            time.sleep(1)

        response = client.perform_data_export('events', event_type, index_name, operation)

        results = response.get('result', [])
        demisto.debug(f'The number of received events - {len(results)}')
        operation = 'next'

        # The API responds with the time we should wait between requests, the server needs this time to prepare the next response.
        # It will be used to sleep in the beginning of the next iteration
        wait_time = arg_to_number(response.get(WAIT_TIME, 5))
        demisto.debug(f'Wait time is {wait_time} seconds')

        events.extend(results)
        print_event_statistics_logs(events=events, event_type=event_type)

        if not results or len(results) < MAX_EVENTS_PAGE_SIZE:
            break

    # We mark this event type as successfully fetched
    client.fetch_status[event_type] = True
    return events, False


def setup_last_run(last_run_dict: dict, first_fetch: str) -> dict:
    for event_type in ALL_SUPPORTED_EVENT_TYPES:
        if not last_run_dict.get(event_type, {}).get('operation'):
            last_run_dict[event_type] = {'operation': first_fetch}

    demisto.debug(f'Initialize last run to - {last_run_dict}')

    return last_run_dict


def get_all_events(client: Client, last_run: dict, limit: int, is_command: bool) -> Tuple[list, dict]:
    # We add the instance name to the index so several instances could run in parallel without effecting each other
    if limit is None:
        limit = MAX_EVENTS_PAGE_SIZE

    all_types_events_result = []
    start_time = datetime.utcnow()
    for event_type in ALL_SUPPORTED_EVENT_TYPES:
        event_type_operation = last_run.get(event_type).get('operation')

        events, time_out = handle_data_export_single_event_type(client=client, event_type=event_type,
                                                                operation=event_type_operation, limit=limit,
                                                                start_time=start_time)
        all_types_events_result.extend(prepare_events(events, event_type))
        last_run[event_type] = {'operation': 'next'}

        if time_out:
            demisto.warning('Timeout reached, stopped pulling events')
            break

    return all_types_events_result, last_run


''' COMMAND FUNCTIONS '''


def test_module(client: Client, last_run: dict, max_fetch: int) -> str:
    fetch_events_command(client, last_run, max_fetch=max_fetch, is_command=True)
    return 'ok'


def get_events_command(client: Client, args: Dict[str, Any], last_run: dict, is_command: bool) -> Tuple[CommandResults, list]:
    limit = arg_to_number(args.get('limit')) or 50
    events, _ = fetch_events_command(client=client, last_run=last_run, max_fetch=limit, is_command=is_command)

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


def fetch_events_command(client, last_run, max_fetch, is_command):  # pragma: no cover
    events, new_last_run = get_all_events(client, last_run=last_run, limit=max_fetch, is_command=is_command)
    return events, new_last_run


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    try:
        params = demisto.params()

        url = params.get('url')
        token = params.get('credentials', {}).get('password')
        base_url = urljoin(url, f'/api/v2/')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        first_fetch = params.get('first_fetch')
        max_fetch = arg_to_number(params.get('max_fetch', 1000))
        vendor, product = params.get('vendor', 'netskope'), params.get('product', 'netskope_dev_2')
        command_name = demisto.command()
        demisto.debug(f'Command being called is {command_name}')

        client = Client(base_url, token, verify_certificate, proxy)
        first_fetch = int(arg_to_datetime(first_fetch).timestamp())  # type: ignore[union-attr]
        last_run = setup_last_run(demisto.getLastRun(), first_fetch)
        demisto.debug(f'Running with the following last_run - {last_run}')

        events = []
        new_last_run = {}
        if command_name == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, last_run, max_fetch=MAX_EVENTS_PAGE_SIZE)  # type: ignore[arg-type]
            return_results(result)

        elif command_name == 'netskope-get-events':
            results, events = get_events_command(client, demisto.args(), last_run, is_command=True)
            if argToBoolean(demisto.args().get('should_push_events', 'true')):
                send_events_to_xsiam(events=events, vendor=vendor, product=product)  # type: ignore
            return_results(results)

        elif command_name == 'fetch-events':
            # We have this try-finally block for fetch events where wrapping up should be done if errors occur
            try:
                start = datetime.utcnow()
                demisto.debug(f'Sending request with last run {last_run}')
                events, new_last_run = fetch_events_command(client, last_run, max_fetch, is_command=False)
            finally:
                demisto.debug(f'sending {len(events)} to xsiam')
                send_events_to_xsiam(events=events, vendor=vendor, product=product)

                for event_type, status, in client.fetch_status.items():
                    if not status:
                        new_last_run[event_type] = {'operation': 'resend'}
                demisto.debug(f'Setting the last_run to: {new_last_run}')

                end = datetime.utcnow()
                demisto.debug(f'Handled {len(events)} total events in {(end - start).seconds} seconds')
                demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command_name} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
