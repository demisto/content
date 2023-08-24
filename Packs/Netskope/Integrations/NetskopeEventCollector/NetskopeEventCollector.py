import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

ALL_SUPPORTED_EVENT_TYPES = ['application', 'alert', 'page', 'audit', 'network']
MAX_EVENTS_PAGE_SIZE = 10000
MAX_SKIP = 50000

EXECUTION_TIMEOUT_SECONDS = 190  # 3:30 minutes

# Netskope response constants
WAIT_TIME = 'wait_time'  # Wait time between queries
RATE_LIMIT_REMAINING = "ratelimit-remaining"  # Rate limit remaining
RATE_LIMIT_RESET = "ratelimit-reset"  # Rate limit RESET value is in seconds

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

    def perform_data_export(self, endpoint: str, _type: str, index_name: str, operation: str):
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
        if RATE_LIMIT_REMAINING in headers:
            remaining = headers.get(RATE_LIMIT_REMAINING)
            demisto.debug(f'Remaining rate limit is: {remaining}')
            if int(remaining) <= 0:
                demisto.debug(f'Rate limiting reached for the endpoint: {endpoint}')
                if to_sleep := headers.get(RATE_LIMIT_RESET):
                    demisto.debug(f'Going to sleep for {to_sleep} seconds to avoid rate limit error')
                    time.sleep(int(to_sleep))
                else:
                    # if the RESET value does not exist in the header then
                    # sleep for default 1 second as the rate limit remaining is 0
                    demisto.debug('Did not find a rate limit reset value, going to sleep for 1 second to avoid rate limit error')
                    time.sleep(1)

    except ValueError as ve:
        logging.error("Value error when honoring the rate limiting wait time {} {}".format(headers, str(ve)))


def populate_parsing_rule_fields(event: dict, event_type: str):
    """
    Handles the source_log_event and _time fields.
    Sets the source_log_event to the given event type and _time to the time taken from the timestamp field

    Args:
        event (dict): the event to edit
        event_type (str): the event type tp set in the source_log_event field
    """
    event['source_log_event'] = event_type
    try:
        event['_time'] = timestamp_to_datestring(event['timestamp'] * 1000, is_utc=True)
    except TypeError:
        # modeling rule will default on ingestion time if _time is missing
        pass


def prepare_events(events: list, event_type: str) -> list:
    """
    Iterates over a list of given events and add/modify special fields like event_id, _time and source_log_event.

    Args:
        events (list): list of events to modify.
        event_type (str): the type of events given in the list.

    Returns:
        list: the list of modified events
    """
    for event in events:
        populate_parsing_rule_fields(event, event_type)
        event_id = event.get('_id')
        event['event_id'] = event_id

    return events


def print_event_statistics_logs(events: list, event_type: str):
    """
    Helper function for debugging purposes.
    This function is responsible to print statistics about pulled events, like the amount of pulled events and the first event and
    last event times.

    Args:
        events (list): list of events.
        event_type (str): the type of events given in the list.
    """
    demisto.debug(f'__[{event_type}]__ - Total events fetched this round: {len(events)}')
    if events:
        event_times = f'__[{event_type}]__ - First event: {events[0].get("timestamp")} __[{event_type}]__ - Last event: ' \
                      f'{events[-1].get("timestamp")}'
        demisto.debug(event_times)


def is_execution_time_exceeded(start_time: datetime) -> bool:
    """
    Checks if the execution time so far exceeded the timeout limit.

    Args:
        start_time (datetime): the time when the execution started.

    Returns:
        bool: true, if execution passed timeout settings, false otherwise.
    """
    end_time = datetime.utcnow()
    secs_from_beginning = (end_time - start_time).seconds
    demisto.debug(f'Execution length so far is {secs_from_beginning} secs')

    return secs_from_beginning > EXECUTION_TIMEOUT_SECONDS


def setup_last_run(last_run_dict: dict) -> dict:
    """
    Setting the last_tun object with the right operation to be used throughout the integration run.

    Args:
        last_run_dict (dict): The dictionary of the last run to be configured

    Returns:
        dict: the modified last run dictionary with the needed operation
    """
    first_fetch = int(arg_to_datetime('now').timestamp())  # type: ignore[union-attr]
    for event_type in ALL_SUPPORTED_EVENT_TYPES:
        if not last_run_dict.get(event_type, {}).get('operation'):
            last_run_dict[event_type] = {'operation': first_fetch}

    demisto.debug(f'Initialize last run to - {last_run_dict}')

    return last_run_dict


def handle_data_export_single_event_type(client: Client, event_type: str, operation: str, limit: int,
                                         execution_start_time: datetime) -> tuple[list, bool]:
    """
    Pulls events per each given event type. Each event type receives a dedicated index name that is constructed using the event
    type and the integration instance name. The function keeps pulling events as long as the limit was not exceeded.
    - First thing it validates is that execution time of the entire run was not exceeded.
    - Then it checks if we need to wait some time before making another call to the same endpoint by checking the wait_time value
        received in the previous response.
    - The operation variable marks the next operation to perform on this endpoint (besides the first fetch it is always 'next')
    - After it is done pulling, it marks this event type as successfully done in the 'fetch_status' dictionary.

    Args:
        client (Client): The Netskope client.
        event_type (str): The type of event to pull.
        operation (str): The operation to perform. Can be 'next' or a timestamp string.
        limit (int): The limit which after we stop pulling.
        execution_start_time (datetime): The time when we started running the fetch mechanism.

    Return:
        list: The list of events pulled for the given event type.
        bool: Was execution timeout reached.
    """
    wait_time: int = 0
    events: list[dict] = []
    # We use the instance name to allow multiple instances in parallel without causing a collision in index names
    instance_name = demisto.callingContext.get('context', {}).get('IntegrationInstance')
    index_name = f'xsoar_collector_{instance_name}_{event_type}'

    while len(events) < limit:

        # If the execution exceeded the timeout we will break
        if is_execution_time_exceeded(start_time=execution_start_time):
            return events, True

        # Wait time between queries
        if wait_time:
            demisto.debug(f'Going to sleep between queries, wait_time is {wait_time} seconds')
            time.sleep(wait_time)   # pylint: disable=E9003
        else:
            demisto.debug('No wait time received, going to sleep for 1 second')
            time.sleep(1)

        response = client.perform_data_export('events', event_type, index_name, operation)

        results = response.get('result', [])
        demisto.debug(f'The number of received events - {len(results)}')
        operation = 'next'

        # The API responds with the time we should wait between requests, the server needs this time to prepare the next response.
        # It will be used to sleep in the beginning of the next iteration
        wait_time = arg_to_number(response.get(WAIT_TIME, 5)) or 5
        demisto.debug(f'Wait time is {wait_time} seconds')

        events.extend(results)

        if not results or len(results) < MAX_EVENTS_PAGE_SIZE:
            break

    print_event_statistics_logs(events=events, event_type=event_type)
    # We mark this event type as successfully fetched
    client.fetch_status[event_type] = True
    return events, False


def get_all_events(client: Client, last_run: dict, limit: int = MAX_EVENTS_PAGE_SIZE) -> Tuple[list, dict]:
    """
    Iterates over all supported event types and call the handle data export logic. Once each event type is done the operation for
    next run is set to 'next'.

    Args:
        client (Client): The Netskope client.
        last_run (dict): The execution last run dict where the relevant operations are stored.
        limit (int): The limit which after we stop pulling.

    Returns:
        list: The accumulated list of all events.
        dict: The updated last_run object.
    """

    all_types_events_result = []
    execution_start_time = datetime.utcnow()
    for event_type in ALL_SUPPORTED_EVENT_TYPES:
        event_type_operation = last_run.get(event_type, {}).get('operation')

        events, time_out = handle_data_export_single_event_type(client=client, event_type=event_type,
                                                                operation=event_type_operation, limit=limit,
                                                                execution_start_time=execution_start_time)
        all_types_events_result.extend(prepare_events(events, event_type))
        last_run[event_type] = {'operation': 'next'}

        if time_out:
            demisto.info('Timeout reached, stopped pulling events')
            break

    return all_types_events_result, last_run


''' COMMAND FUNCTIONS '''


def test_module(client: Client, last_run: dict, max_fetch: int) -> str:
    get_all_events(client, last_run, limit=max_fetch)
    return 'ok'


def get_events_command(client: Client, args: Dict[str, Any], last_run: dict) -> Tuple[CommandResults, list]:
    limit = arg_to_number(args.get('limit')) or MAX_EVENTS_PAGE_SIZE
    events, _ = get_all_events(client=client, last_run=last_run, limit=limit)

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


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    try:
        params = demisto.params()

        url = params.get('url')
        token = params.get('credentials', {}).get('password')
        base_url = urljoin(url, '/api/v2/')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        max_fetch: int = arg_to_number(params.get('max_fetch')) or 10000
        vendor, product = params.get('vendor', 'netskope'), params.get('product', 'netskope')
        command_name = demisto.command()
        demisto.debug(f'Command being called is {command_name}')

        client = Client(base_url, token, verify_certificate, proxy)
        last_run = setup_last_run(demisto.getLastRun())
        demisto.debug(f'Running with the following last_run - {last_run}')

        events: list[dict] = []
        new_last_run: dict = {}
        if command_name == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, last_run, max_fetch=MAX_EVENTS_PAGE_SIZE)  # type: ignore[arg-type]
            return_results(result)

        elif command_name == 'netskope-get-events':
            results, events = get_events_command(client, demisto.args(), last_run)
            if argToBoolean(demisto.args().get('should_push_events', 'true')):
                send_events_to_xsiam(events=events, vendor=vendor, product=product)  # type: ignore
            return_results(results)

        elif command_name == 'fetch-events':
            # We have this try-finally block for fetch events where wrapping up should be done if errors occur
            start = datetime.utcnow()
            try:
                demisto.debug(f'Sending request with last run {last_run}')
                events, new_last_run = get_all_events(client, last_run, max_fetch)
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
