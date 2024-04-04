import demistomock as demisto
from CommonServerPython import *
import hashlib

NUM_OF_RETRIES = 3
BACKOFF_FACTOR = 1.0
API_VERSION = 'v2'
MAX_EVENTS_PER_TYPE = 50000
PAGE_SIZE = 10000
MAX_AUDIT_API_COUNT = 10000
ALERT_TIME_FIELD = 'latestTimestampUsecs'
AUDIT_LOGS_TIME_FIELD = 'timestampUsecs'


class EventType:
    """
    Class used to as Enum for the Cohesity event type
    """
    alert = 'Alert'
    audit_log = 'Audit Log'


class Client(BaseClient):
    """
    Client class to interact with Cohesity Helios.
    """

    def get_alerts(self, fetch_start_timestamp: int, fetch_end_timestamp: int) -> dict:
        request_params = {
            'startDateUsecs': fetch_start_timestamp,
            'endDateUsecs': fetch_end_timestamp
        }
        res = self._http_request(  # type: ignore
            method='GET',
            url_suffix='/mcm/alerts',
            params=request_params,
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            resp_type='response'
        )
        # In case there are no results the API returns 'null' which parsed into None object by response.json().
        try:
            json_res = res.json() or {}
        except ValueError as exception:
            raise DemistoException(f'Failed to parse response into json object. Response: {res.content}', exception, res)

        return json_res

    def get_audit_logs(self, start_time: int, end_time: int) -> dict:
        request_params = {
            'startTimeUsecs': start_time,
            'endTimeUsecs': end_time,
            'count': MAX_AUDIT_API_COUNT
        }

        return self._http_request(
            method='GET',
            url_suffix='/mcm/audit-logs',
            params=request_params,
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
        )


''' HELPER FUNCTIONS '''


def adjust_and_dedup_elements(new_elements: list[dict], existing_element_ids: list[str], time_field_name: str) -> list[dict]:
    """
    Filter out all the elements from the new_elements list that their ID does not appear in the existing_element_ids list.
    The new elements also get their '_time' foeld set.
    Args:
        new_elements (list[dict]): The list of elements to filter.
        existing_element_ids (list[str]): The list of IDs to remove.
        time_field_name (str): The name of the field containing the time info.

    Return:
         list[dict]: a subset of new_elements that their ID did not appear in existing_element_ids.
    """
    filtered_list: list = []
    for element in new_elements:
        if element.get('id') not in existing_element_ids:
            try:
                element['_time'] = timestamp_to_datestring(element.get(time_field_name) / 1000)  # type: ignore[operator]

            except TypeError as e:
                # modeling rule will default on ingestion time if _time is missing
                demisto.error(f'Could not parse _time field, for event {element}: {e}')

            filtered_list.append(element)
    return filtered_list


def get_earliest_event_ids_with_the_same_time(events: list, time_field: str) -> list[str]:
    """
    Upon receiving a descending list of events, returns the ID(s) of the events that were the earliest.
    Args:
        events (list): DESCENDING list of alerts.
        time_field (str): The field name in the event to use for comparison.
    Return:
        list[str]: list of element IDs that are the earliest.
    """
    earliest_event_fetched_ids = []
    if events:
        #  Last event is necessarily the earliest as teh list is descending
        earliest_event_fetched_timestamp = arg_to_number(events[-1].get(time_field))
        for event in reversed(events):
            # Once we found an event which i newer than the earliest event we know we have saved all the events that had the same
            # timestamp.
            if arg_to_number(event.get(time_field)) > earliest_event_fetched_timestamp:  # type: ignore[operator]
                break
            # Audit logs don't have an ID, so we create it from the other fields
            event_id = event.get('id') if event.get('id') else hash_fields_to_create_id(event)
            earliest_event_fetched_ids.append(event_id)

    return earliest_event_fetched_ids


def hash_fields_to_create_id(event: dict) -> str:
    """
    create a hash value for a given event based on its properties. This is used to create an ID to the Audit Log events that has
    no IDs.
    Args:
        event (dict): Audit Log event

    Return:
        str: hash created from the event properties
    """
    string = ''
    for val in event.values():
        string += str(val)
    _id = hashlib.sha256(str.encode(string)).hexdigest()
    return _id


def fetch_events_per_type(client: Client, event_type: str, fetch_start_timestamp: int, fetch_end_timestamp: int) -> list[dict]:
    """
    Given the event type to pull and the relevant start and end time, call the relevant function to pull the given event type.
    Args:
        client (Client): the client to use for the API calls.
        event_type (EventType): the event type we want to pull.
        fetch_start_timestamp (int): The start time to pull events from.
        fetch_end_timestamp (int): The end time to pull events to.

    Return:
        List: the list of pulled events (Audit Logs | Alerts)
    """
    demisto.debug(f'Pulling {event_type}s with {fetch_start_timestamp=}, {fetch_end_timestamp=}')
    if event_type == EventType.alert:
        event_pulling_function = client.get_alerts
        data_field = 'alertsList'

    elif event_type == EventType.audit_log:
        event_pulling_function = client.get_audit_logs  # type: ignore[assignment]
        data_field = 'auditLogs'
    else:
        raise DemistoException(f'Event Type: {event_type} is not supported by the integration')

    try:
        res = event_pulling_function(fetch_start_timestamp, fetch_end_timestamp)
        events = res.get(data_field, [])
        if event_type == EventType.alert:
            # The API returns alerts with no specific order in each response, but we prefer DESCENDING order since the API will
            # always return the LATEST PAGE_SIZE alerts that matched the query and not the EARLIEST PAGE_SIZE alerts.
            events.sort(key=lambda alert: alert.get(ALERT_TIME_FIELD), reverse=True)

    except DemistoException as e:
        if 'Unauthorized' in e.message:
            raise DemistoException('Unauthorized - API key is invalid')
        raise e

    return events


def fetch_events_loop(client: Client, event_type: str, cache: dict, max_fetch: int) -> tuple[list, dict, bool]:
    """
    This is the main loop to retrieve events, it is called twice - once for each event type (Audit Log, Alert).
    For each API response we check for duplicates and add the '_time' field.
    There are 3 different cases the code is able to handle:
        # 1: API returns fewer events than page_size on the first request - no need for additional iteration, all we need is to
            save last event timestamp with an increase of 1 micro sec to be used in the next fetch-events-execution.
        # 2: There are more than page_size events but there are less than max_fetch events - In this case as the events are
            returned in descending order in both APIs ,we first make sure to save the newest event timestamp to be used in the
            next fetch-events-execution. Then we perform similar calls where each time we update the fetch_end_timestamp is set
            the EARLIEST timestamp received in the previous response.
        # 3: There are more than max_fetch events - This means that we will have to iterate backwards from the original end time
            in multiple fetch executions. Thus, in addition to what we do in case 2 we also save in cache the earliest timestamp
            we fetched to continue in the next execution.
    """
    demisto.debug(f'Starting fetch_events for event_type={event_type}s')
    time_field_name = ALERT_TIME_FIELD if event_type == EventType.alert else AUDIT_LOGS_TIME_FIELD

    ids_for_dedup = cache.get('ids_for_dedup', [])
    fetch_start_timestamp = cache.get('next_start_timestamp') or \
        int(arg_to_datetime('1 min').timestamp() * 1000000)  # type: ignore[union-attr]
    fetch_end_timestamp = cache.get('next_end_timestamp') or \
        int(arg_to_datetime('Now').timestamp() * 1000000)  # type: ignore[union-attr]

    # The latest_event_fetched_timestamp acts like a pointer to the newest event we ever fetched.
    latest_fetched_event_timestamp = cache.get('latest_event_fetched_timestamp')
    aggregated_events: list = []
    temp_events: list = []
    while len(aggregated_events) < max_fetch:
        temp_events = fetch_events_per_type(client, event_type, fetch_start_timestamp, fetch_end_timestamp)
        demisto.debug(f'Number of events before de-duping {len(temp_events)}:\n{temp_events}')
        deduped_events = adjust_and_dedup_elements(temp_events, ids_for_dedup, time_field_name)
        demisto.debug(f'Number of events after de-duping {len(deduped_events)}:{deduped_events}')
        if not deduped_events:
            break
        aggregated_events.extend(deduped_events)
        # The fetch_end_timestamp variable is used as the next end timestamp and acts like an index marking the earliest alert
        # pulled so far (alerts are returned in descending order) in cases where we need to perform several calls in the same
        # round. In cases where we have not reached the user limit we will pass it on to the next fetch-events execution.
        fetch_end_timestamp = deduped_events[-1].get(time_field_name)
        ids_for_dedup = get_earliest_event_ids_with_the_same_time(deduped_events, time_field_name)
        demisto.debug(f'Saved {len(ids_for_dedup)} alert IDs for de-duplication in next iteration')
        # This means we know there are no more events to pull using the current fetch_start_timestamp and fetch_end_timestamp.
        if len(temp_events) < PAGE_SIZE:
            demisto.debug(f'Received {len(temp_events)} events, which is less than {PAGE_SIZE=}')
            break

    # We only update latest_fetched_event_timestamp if it is empty, o/w it means we are still fetch past events.
    if not latest_fetched_event_timestamp:
        latest_fetched_event_timestamp = aggregated_events[0].get(time_field_name) + 1 if aggregated_events else \
            fetch_end_timestamp  # type: ignore[operator]
        demisto.debug(f'latest_fetched_event_timestamp is empty, setting it to \'{latest_fetched_event_timestamp}\'')

    in_progress_pagination: bool = False
    # In case the last events list has less than PAGE_SIZE events we know there are no more events to pull using the current
    # fetch_start_timestamp and fetch_end_timestamp, so next round is basically a new search. In that case we will:
    #   1. Update the next_start_timestamp to latest_event_fetched_timestamp
    #   2. Update ids_for_dedup with the latest_fetched_events_ids
    #   3. clear the next_end_timestamp, latest_fetched_event_timestamp and latest_fetched_events_ids
    if len(temp_events) < PAGE_SIZE:
        next_start_timestamp = latest_fetched_event_timestamp
        next_end_timestamp = ''
        latest_fetched_event_timestamp = ''
        ids_for_dedup = []
        demisto.debug(f'Last events list has {len(temp_events)} events, which is less than {PAGE_SIZE=}, setting '
                      f'{next_start_timestamp=}')

    # If we exited the loop and the last list of pulled events is not smaller than PAGE_SIZE (the first if condition)
    # it must mean that len(events) == PAGE_SIZE, and that we have reached the user limit, implying we are missing more events to
    # pull from the original window. In that case we will keep the next_start_timestamp as is (fetch_start_timestamp) and will
    # update the next_end_timestamp to fetch_end_timestamp (the oldest alert fetched). We will also save the list of
    # ids_for_dedup to be used in the next round
    else:
        in_progress_pagination = True
        next_start_timestamp = fetch_start_timestamp
        next_end_timestamp = fetch_end_timestamp    # type: ignore[assignment]
        demisto.debug(f'Last events list has {len(temp_events)} events. The aggregated events list has {len(aggregated_events)} '
                      f'events which should equal to {max_fetch=}. This means we are missing more events.')

    new_cache = {
        'ids_for_dedup': ids_for_dedup,
        'next_start_timestamp': next_start_timestamp,
        'next_end_timestamp': next_end_timestamp,
        'latest_event_fetched_timestamp': latest_fetched_event_timestamp,
    }

    demisto.debug(f'Returning {len(aggregated_events)=} events, and a new {new_cache=}')
    return aggregated_events, new_cache, in_progress_pagination


''' COMMAND FUNCTIONS '''


def test_module_command(client, max_fetch):
    fetch_events_command(client, {}, max_fetch)
    return 'ok'


def fetch_events_command(client: Client, last_run: dict, max_fetch: int):
    audit_logs, audit_cache, in_progress_pagination_audit_log = fetch_events_loop(client, EventType.audit_log,
                                                                                  last_run.get('audit_cache', {}), max_fetch)
    last_run['audit_cache'] = audit_cache
    alerts, alerts_cache, in_progress_pagination_alert = fetch_events_loop(client, EventType.alert,
                                                                           last_run.get('alert_cache', {}), max_fetch)
    last_run['alert_cache'] = alerts_cache
    if in_progress_pagination_audit_log or in_progress_pagination_alert:
        last_run["nextTrigger"] = '0'

    return alerts + audit_logs, last_run


def get_events_command(client: Client, args: dict):
    start_time = int(arg_to_datetime(args.get('start_time')).timestamp() * 1000000)  # type: ignore[union-attr]
    end_time = int(arg_to_datetime(args.get('end_time'), 'now').timestamp() * 1000000)   # type: ignore[union-attr]
    raw_audit_logs = client.get_audit_logs(start_time, end_time)
    raw_alerts = client.get_alerts(start_time, end_time)
    events = raw_audit_logs.get('auditLogs', []) + raw_alerts.get('alertsList', [])
    if argToBoolean(args.get('should_push_events')):
        send_events_to_xsiam(events=events, vendor='cohesity', product='helios')
    return CommandResults(readable_output=tableToMarkdown('Events returned from Cohesity Helios', t=events),
                          raw_response=raw_audit_logs.get('auditLogs', []) + raw_alerts.get('alertsList', []))


def main() -> None:
    """main function, parses params and runs command functions

    """

    params = demisto.params()
    # Get API key for authentication.
    api_key = params.get('api_key', {}).get('password')

    # Get helios service API url.
    base_url = urljoin(params.get('url'), API_VERSION)
    max_fetch: int = min(arg_to_number(params.get('max_fetch', MAX_EVENTS_PER_TYPE)),
                         MAX_EVENTS_PER_TYPE)  # type: ignore[assignment, type-var]
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        # Prepare client and set authentication headers.
        headers: dict = {
            'apikey': api_key,
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module_command(client, max_fetch)
            return_results(result)
        if command == 'cohesity-helios-get-events':
            args = demisto.args()
            return_results(get_events_command(client, args))

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            demisto.debug(f'{last_run=}')
            events, new_last_run = fetch_events_command(client, last_run, max_fetch)
            send_events_to_xsiam(events=events, vendor='cohesity', product='helios')
            demisto.setLastRun(new_last_run)
            demisto.debug(f'{new_last_run=}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
