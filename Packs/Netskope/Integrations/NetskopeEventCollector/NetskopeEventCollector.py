from typing import Any

import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

ALL_SUPPORTED_EVENT_TYPES = ['application', 'alert', 'page', 'audit', 'network', 'incident']
MAX_EVENTS_PAGE_SIZE = 10000
MAX_SKIP = 50000
EXECUTION_TIMEOUT_SECONDS = 190  # 3:30 minutes
POC = True

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

    def __init__(self, base_url: str, token: str, validate_certificate: bool, proxy: bool, event_types_to_fetch: list[str]):
        self.fetch_status: dict = {event_type: False for event_type in event_types_to_fetch}
        self.event_types_to_fetch: list[str] = event_types_to_fetch

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

    def poc_fetch_events(self, type: str, params: dict):
        url_suffix = f"events/data/{type}"
        response = self._http_request(method="GET", url_suffix=url_suffix, params=params, resp_type="response", retries=10)
        # honor_rate_limiting(headers=response.headers, endpoint=url_suffix)
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
        logging.error(f"Value error when honoring the rate limiting wait time {headers} {str(ve)}")


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

def poc_prepare_events(events: list, event_type: str, last_run: dict, epoch_starttime: str) -> list[Any]:
    """
    - Iterates over a list of given events and add/modify special fields like event_id, _time and source_log_event.
    - sort results by _creation_timestamp key
    - dedup with IDs from previous fetch, if available
    - get max epoch from fetch events

    Args:
        events (list): list of events to modify.
        event_type (str): the type of events given in the list.

    Returns:
        list: the list of modified events
    """
    last_fetch_ids = set(last_run.get(event_type, {}).get("last_fetch_ids", []))

    deduped_events = []
    max_epoch = epoch_starttime

    for event in events:
        if (event_id := str(event.get("_id"))) not in last_fetch_ids:
            populate_parsing_rule_fields(event, event_type)
            event["event_id"] = event_id
            deduped_events.append(event)
            max_epoch = max(max_epoch, str(event.get("_creation_timestamp", "")))

    last_run.setdefault(event_type, {})
    last_run[event_type]["last_fetch_ids"] = [event["event_id"] for event in deduped_events]
    last_run[event_type]["last_fetch_max_epoch"] = max_epoch

    return deduped_events

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


def remove_unsupported_event_types(last_run_dict: dict, event_types_to_fetch: list):
    keys_to_remove = []

    for key in last_run_dict:
        if (key in ALL_SUPPORTED_EVENT_TYPES) and (key not in event_types_to_fetch):
            keys_to_remove.append(key)

    for key in keys_to_remove:
        last_run_dict.pop(key, None)


def setup_last_run(last_run_dict: dict, event_types_to_fetch: list[str]) -> dict:
    """
    Setting the last_tun object with the right operation to be used throughout the integration run.

    Args:
        last_run_dict (dict): The dictionary of the last run to be configured

    Returns:
        dict: the modified last run dictionary with the needed operation
    """
    remove_unsupported_event_types(last_run_dict, event_types_to_fetch)
    first_fetch = int(arg_to_datetime('now').timestamp())  # type: ignore[union-attr]
    for event_type in event_types_to_fetch:
        if not last_run_dict.get(event_type, {}).get('operation'):
            last_run_dict[event_type] = {'operation': first_fetch}

    demisto.debug(f'Initialize last run to - {last_run_dict}')

    return last_run_dict


def handle_data_export_single_event_type(client: Client, event_type: str, operation: str, limit: int,
                                         execution_start_time: datetime, all_event_types: list) -> bool:
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
            return True

        # Wait time between queries
        if wait_time:
            demisto.debug(f'Going to sleep between queries, wait_time is {wait_time} seconds')
            time.sleep(wait_time)  # pylint: disable=E9003
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

        all_event_types.extend(prepare_events(results, event_type))

        if not results or len(results) < MAX_EVENTS_PAGE_SIZE:
            break

    print_event_statistics_logs(events=events, event_type=event_type)
    # We mark this event type as successfully fetched
    client.fetch_status[event_type] = True
    return False


def get_all_events(client: Client, last_run: dict, all_event_types: list, limit: int = MAX_EVENTS_PAGE_SIZE) -> dict:
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

    execution_start_time = datetime.utcnow()
    for event_type in client.event_types_to_fetch:
        event_type_operation = last_run.get(event_type, {}).get('operation')

        time_out = handle_data_export_single_event_type(client=client, event_type=event_type,
                                                        operation=event_type_operation, limit=limit,
                                                        execution_start_time=execution_start_time,
                                                        all_event_types=all_event_types)
        last_run[event_type] = {'operation': 'next'}

        if time_out:
            demisto.info('Timeout reached, stopped pulling events')
            break

    return last_run


def poc_get_all_events(client: Client, last_run: dict, all_event_types: list, limit: int = MAX_EVENTS_PAGE_SIZE) -> dict:
    """
    Iterates over all supported event types and call the handle event fetch logic.

    Endpoint: /api/v2/events/data/
    Docs: https://www.postman.com/netskope-tech-alliances/netskope-rest-api/request/zknja6y/get-network-events-generated-by-netskope



    Example HTTP request:
    <baseUrl>/api/v2/events/data/network?offset=0&starttime=1707466628&endtime=1739089028&query=_creation_timestamp gte 1739058516

    Args:
        client (Client): The Netskope client.
        last_run (dict): The execution last run dict where the relevant operations are stored.
        limit (int): The limit which after we stop pulling.

    Returns:
        list: The accumulated list of all events.
        dict: The updated last_run object.
    """
    remove_unsupported_event_types(last_run, client.event_types_to_fetch)
    epoch_current_time = str(int(arg_to_datetime("now").timestamp()))  # type: ignore[union-attr]

    for event_type in client.event_types_to_fetch:
        # event_type_operation = last_run.get(event_type, {}).get('operation')
        epoch_starttime = last_run.get(event_type, {}).get("last_fetch_max_epoch", "") or str(
            object=int(arg_to_datetime("1 Month").timestamp())  # type: ignore[union-attr]
        )
        query = f"_creation_timestamp gte {epoch_starttime}"  # TODO: add some sorting by '_creation_timestamp' key
        params = assign_params(limit=limit, offset=0, starttime=epoch_starttime, endtime=epoch_current_time, query=query)

        response = client.poc_fetch_events(event_type, params)
        results = response.get("result", [])
        demisto.debug(f"The number of received events - {len(results)}")

        deduped_events = poc_prepare_events(results, event_type, last_run, epoch_starttime)
        all_event_types.extend(deduped_events)

    return last_run


''' COMMAND FUNCTIONS '''


def test_module(client: Client, last_run: dict, max_fetch: int) -> str:
    get_all_events(client, last_run, limit=max_fetch, all_event_types=[])
    return 'ok'


def get_events_command(client: Client, args: dict[str, Any], last_run: dict, events: list) -> tuple[CommandResults, list]:
    limit = arg_to_number(args.get('limit')) or MAX_EVENTS_PAGE_SIZE
    _ = get_all_events(client=client, last_run=last_run, limit=limit, all_event_types=events)

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


def handle_event_types_to_fetch(event_types_to_fetch) -> list[str]:
    """ Handle event_types_to_fetch parameter.
        Transform the event_types_to_fetch parameter into a pythonic list with lowercase values.
    """
    return argToList(
        arg=event_types_to_fetch if event_types_to_fetch else ALL_SUPPORTED_EVENT_TYPES,
        transform=lambda x: x.lower(),
    )


def next_trigger_time(num_of_events, max_fetch, new_last_run):
    """Check wether to add the next trigger key to the next_run dict based on number of fetched events.

    Args:
        num_of_events (int): The number of events fetched.
        max_fetch (int): The maximum fetch limit.
        new_last_run (dict): the next_run to update
    """
    if num_of_events > (max_fetch / 2):
        new_last_run['nextTrigger'] = '0'
    else:
        new_last_run.pop('nextTrigger', None)


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
        event_types_to_fetch = handle_event_types_to_fetch(params.get('event_types_to_fetch'))
        demisto.debug(f'Event types that will be fetched in this instance: {event_types_to_fetch}')
        command_name = demisto.command()
        demisto.debug(f'Command being called is {command_name}')

        client = Client(base_url, token, verify_certificate, proxy, event_types_to_fetch)

        if POC:
            last_run = demisto.getLastRun()
        else:
            last_run = setup_last_run(demisto.getLastRun(), event_types_to_fetch)
        demisto.debug(f'Running with the following last_run - {last_run}')

        all_event_types: list[dict] = []
        new_last_run: dict = {}
        if command_name == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, last_run, max_fetch=MAX_EVENTS_PAGE_SIZE)  # type: ignore[arg-type]
            return_results(result)

        elif command_name == 'netskope-get-events':
            results, events = get_events_command(client, demisto.args(), last_run, events=[])
            if argToBoolean(demisto.args().get('should_push_events', 'true')):
                send_events_to_xsiam(events=events, vendor=vendor, product=product,
                                     chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT)  # type: ignore
            return_results(results)

        elif command_name == 'fetch-events':
            if POC:
                start = datetime.utcnow()
                demisto.debug('Starting fetch with "/api/v2/events/data/" endpoint')
                new_last_run = poc_get_all_events(
                    client=client, last_run=last_run, limit=max_fetch, all_event_types=all_event_types
                )
                end = datetime.utcnow()

                demisto.debug(f"Handled {len(all_event_types)} total events in {(end - start).seconds} seconds")
                next_trigger_time(len(all_event_types), max_fetch, new_last_run)
                demisto.debug(f"Setting the last_run to: {new_last_run}")
                demisto.setLastRun(new_last_run)


            else:
                # We have this try-finally block for fetch events where wrapping up should be done if errors occur
                start = datetime.utcnow()
                try:
                    demisto.debug(f"Sending request with last run {last_run}")
                    new_last_run = get_all_events(
                        client=client, last_run=last_run, limit=max_fetch, all_event_types=all_event_types
                    )
                    send_events_to_xsiam(
                        events=all_event_types, vendor=vendor, product=product, chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT
                    )
                finally:
                    demisto.debug(f"sending {len(all_event_types)} to xsiam")
                    send_events_to_xsiam(
                        events=all_event_types, vendor=vendor, product=product, chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT
                    )

                    for (
                        event_type,
                        status,
                    ) in client.fetch_status.items():
                        if not status:
                            new_last_run[event_type] = {"operation": "resend"}

                    end = datetime.utcnow()

                    demisto.debug(f"Handled {len(all_event_types)} total events in {(end - start).seconds} seconds")
                    next_trigger_time(len(all_event_types), max_fetch, new_last_run)
                    demisto.debug(f"Setting the last_run to: {new_last_run}")
                    demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        last_run = new_last_run if new_last_run else demisto.getLastRun()
        last_run.pop('nextTrigger', None)
        demisto.setLastRun(last_run)
        demisto.debug(f'last run after removing nextTrigger {last_run}')
        return_error(f'Failed to execute {command_name} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
