import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
import hashlib

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

AUDIT = 'audit'
NETWORK_ACTIVITIES = 'network_activities'
ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
VALID_EVENT_TITLES = ['Audit', 'Network Activities']
VENDOR = 'ZeroNetworks'
PRODUCT = 'Segment'
FIRST_FETCH = 'one minute'
MAX_CALLS_FOR_LOG_TYPE = {AUDIT: 10000, NETWORK_ACTIVITIES: 400}
URL = {AUDIT: '/audit', NETWORK_ACTIVITIES: '/activities/network'}


''' CLIENT CLASS '''


class Client(BaseClient):
    API_VERSION = "/api/v1"

    def __init__(self, server_url: str, proxy: bool, verify: bool, headers: dict):
        super().__init__(
            base_url=urljoin(server_url, self.API_VERSION),
            verify=verify,
            proxy=proxy,
            headers=headers
        )

    def search_events(self, limit: int, cursor: int, log_type: str, filters=None) -> dict[str, Any]:
        """
        Search for events based on given parameters.

        Args:
            limit (int): Maximum number of events to return.
            cursor (int): The starting point for fetching events.
            log_type (str): Type of logs to fetch (e.g., network activities).
            filters (Optional[dict[str, Any]]): Filters to apply when fetching events. Defaults to None.

        Returns:
            Dict[str, Any]: A dictionary containing the search results.
        """
        if log_type == NETWORK_ACTIVITIES:
            params = remove_empty_elements({"_limit": limit, "order": "asc", "_cursor": cursor, "_filters": filters})
        else:
            params = remove_empty_elements({"_limit": limit, "order": "asc", "_cursor": cursor})

        return self._http_request(
            method="GET",
            url_suffix=URL[log_type],
            params=params,
        )


''' HELPER FUNCTIONS '''


def handle_log_types(event_types_to_fetch: list) -> list:
    """
    Args:
        event_types_to_fetch (list of str): A list of event type titles to be converted to log types.

    Raises:
        InvalidEventTypeError: If any of the event type titles are not found in the titles_to_types mapping.

    Returns:
        list: A list of log types corresponding to the provided event type titles.
              The list contains log types that have a matching title in the titles_to_types mapping.
              If an event type title is not found, an exception is raised.
    """
    log_types = []
    titles_to_types = {'Audit': AUDIT, 'Network Activities': NETWORK_ACTIVITIES}
    for type_title in event_types_to_fetch:
        if log_type := titles_to_types.get(type_title):
            log_types.append(log_type)
        else:
            raise DemistoException(
                f"'{type_title}' is not valid event type, please select from the following list: {VALID_EVENT_TITLES}")

    return log_types


def initialize_start_timestamp(last_run: dict[str, Any], log_type: str) -> int:
    """
    Initialize the start timestamp for fetching logs based on provided parameters.

    Args:
        last_run (dict[str, Any]): Dictionary containing the last fetch timestamps for different log types.
        log_type (str): Type of log for which to initialize the start timestamp.
        arg_from (Optional[int]): A specific start timestamp to use. Defaults to None.

    Returns:
        int: The start timestamp for fetching logs.
    """
    start_timestamp = last_run.get(log_type, {}).get("last_fetch")
    if not start_timestamp:
        start_date = dateparser.parse(FIRST_FETCH).strftime(ISO_8601_FORMAT)  # type: ignore[union-attr]
        start_timestamp = date_to_timestamp(start_date, ISO_8601_FORMAT)

    return start_timestamp


def get_max_results_and_limit(params: dict[str, Any], log_type: str, args={}) -> tuple[int, int]:
    """
    Determine the maximum number of results and the limit for fetching logs based on input parameters.

    Args:
        params (dict[str, Any]): Dictionary of parameters including the maximum fetch limit.
        log_type (str): Type of log for which to determine the limits.

    Returns:
        Tuple[int, int]: A tuple containing:
            - max_results (int): The maximum number of results to fetch.
            - limit (int): The limit for fetching results, adjusted to be at least 20.
    """
    max_results_for_log_type = {AUDIT: 10000, NETWORK_ACTIVITIES: 2000}
    max_fetch_param_name = {AUDIT: 'max_fetch_audit', NETWORK_ACTIVITIES: 'max_fetch_network'}
    max_results = arg_to_number(args.get(max_fetch_param_name[log_type])) \
        or arg_to_number(params.get(max_fetch_param_name[log_type])) or max_results_for_log_type[log_type]
    limit = min(max_results, MAX_CALLS_FOR_LOG_TYPE[log_type])
    if limit < 20:
        limit = 20

    return max_results, limit


def update_last_run(last_run: dict[str, Any], log_type: str, last_event_time: int, previous_ids: list) -> dict:
    """
    Update the last run details for a specific log type.

    Args:
        last_run (dict[str, Any]): Dictionary containing the last run details for different log types.
        log_type (str): Type of log to update.
        last_event_time (int): Timestamp of the last event fetched.
        previous_ids (list): List of IDs from the previous fetch to track.

    Returns:
        Dict[str, Any]: Updated dictionary containing the last run details.
    """
    last_run[log_type] = {
        "last_fetch": last_event_time,
        "previous_ids": previous_ids
    }
    return last_run


def create_id(event: dict, log_type: str) -> str:
    """
    Create a unique ID for an event based on its log type.

    Args:
        event (dict): Dictionary containing event details.
        log_type (str): Type of log to determine how to generate the ID (e.g., audit or network activities).

    Returns:
        str: A unique ID generated for the event, represented as a SHA-256 hash.
    """
    timestamp = event.get("timestamp")
    if log_type == AUDIT:
        reported_object_id = event.get("reportedObjectId", "")
        performed_by_name = event.get("performedBy", {}).get("id", "")
        combined_string = f"{timestamp}-{reported_object_id}-{performed_by_name}"

    elif log_type == NETWORK_ACTIVITIES:
        src_asset_id = event.get("src", {}).get("assetId", "")
        dst_asset_id = event.get("dst", {}).get("assetId", "")
        combined_string = f"{timestamp}-{src_asset_id}-{dst_asset_id}"
    else:
        combined_string = ""
        demisto.debug(f"{log_type=} didn't match any condition. {combined_string=}")

    hash_object = hashlib.sha256(combined_string.encode())
    return hash_object.hexdigest()


def process_events(events: list, previous_ids: list, last_event_time: int, max_results: int, num_results: int,
                   log_type: str) -> tuple[list, list, int]:
    """
    Process a list of events to filter out new ones and update tracking information.

    Args:
        events (list): List of event dictionaries to process.
        previous_ids (list): List of IDs from previously processed events.
        last_event_time (int): Timestamp of the last event processed.
        max_results (int): Maximum number of results to process.
        num_results (int): Current number of results processed.
        log_type (str): Type of log to determine how to process the events.

    Returns:
        new_events (list): List of newly processed events.
        updated_previous_ids (list): Updated list of IDs from previously processed events.
        updated_last_event_time (int): Updated timestamp of the last event processed.
    """
    new_events = []
    for event in events:
        event_id = create_id(event, log_type)
        if num_results == max_results:
            break

        if event_id not in previous_ids:
            event['_time'] = event.get('timestamp')
            event['source_log_type'] = log_type
            new_events.append(event)
            event_timestamp = event.get("timestamp")
            num_results += 1
            if int(event_timestamp) > last_event_time:
                previous_ids = [event_id]
                last_event_time = event_timestamp

            # Adding the event ID when the event time is equal to the last received event
            elif int(event_timestamp) == last_event_time:
                previous_ids.append(event_id)

    return new_events, previous_ids, last_event_time


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, last_run: dict, start_timestamp: int, log_type: str,
                 filters: list, max_results: int, limit: int) -> tuple[dict, list]:
    """
    Fetches events from ZeroNetworks API by log type.

    Args:
        client (Client): The client instance used to interact with the ZeroNetworks API.
        last_run (dict): Dictionary containing the last run information, including previously processed event IDs and timestamps.
        start_timestamp (int): Timestamp to start fetching events from.
        log_type (str): The type of log to fetch, used to determine how to process the events and set limits.
        filters (list): List of filters to apply to the event search.

    Returns:
        last_run (dict): Updated dictionary with the latest information on processed events and timestamps.
        collected_events (list): List of newly fetched and processed events.
    """
    cursor = last_event_time = start_timestamp
    collected_events: list = []
    previous_ids = last_run.get(log_type, {}).get("previous_ids", [])

    while len(collected_events) < max_results:
        demisto.debug(f"Fetching events for {log_type=} with {cursor=} and {limit=}")
        response = client.search_events(limit, cursor=cursor, log_type=log_type, filters=filters)

        if not response:
            demisto.debug("No response received from client.")
            break

        events = response.get('items', [])
        scroll_cursor = response.get('scrollCursor')
        if scroll_cursor:
            cursor = int(scroll_cursor)

        if not events:
            demisto.debug("No events found in response.")
            break

        new_events, previous_ids, last_event_time = process_events(events, previous_ids, last_event_time, max_results,
                                                                   len(collected_events), log_type)

        # If no new events are returned from process_events, but there are existing events:
        # It indicates that all events might be within the range of previously processed IDs.
        # This situation can occur if the cursor is initialized to the timestamp of the last event,
        # resulting in some of the events returned being from before the current processing period.
        # To handle this, we adjust the limit to fetch new events, unless the number of events is less than the limit,
        # which implies there are no more new events to retrieve.
        if not new_events:
            demisto.debug("No new events returned from process_events.")
            if len(events) < limit:
                demisto.debug("Number of events is less than the limit; breaking out of the loop.")
                break

            limit += limit

        collected_events.extend(new_events)

    last_run = update_last_run(last_run, log_type, last_event_time, previous_ids)
    demisto.debug(
        f"Updated last_run for {log_type=} with {last_event_time=} and previous_ids {previous_ids=}")

    return last_run, collected_events


def get_events(client: Client, args: dict, last_run: dict, params: dict, log_types: list) -> tuple[list, CommandResults]:
    """
    Fetch events from the Zero Networks Segment API and format the results.

    Args:
        client (Client): The client instance used to interact with the API.
        args (dict): Dictionary of arguments, potentially including a "from_date" for filtering.
        last_run (dict): Dictionary of the last run details to determine the starting point for fetching events.
        params (dict): Additional parameters to pass to the event fetching function.

    Returns:
        events (list): List of fetched events.
        CommandResults: An object containing the formatted results for output.
    """
    types_to_titles = {AUDIT: 'Audit', NETWORK_ACTIVITIES: 'Network Activities'}
    all_events: list = []
    filters = params.get("network_activity_filters", [])
    hr = ""
    for log_type in log_types:
        if arg_from := args.get("from_date"):
            start_timestamp = date_to_timestamp(arg_from, ISO_8601_FORMAT)
        else:
            start_timestamp = initialize_start_timestamp(last_run, log_type)

        max_results, limit = get_max_results_and_limit(params, log_type, args)
        last_run, collected_events = fetch_events(client, last_run, start_timestamp,
                                                  log_type, filters, max_results, limit)
        hr += tableToMarkdown(name=f'{types_to_titles[log_type]} Events', t=collected_events)
        all_events.extend(collected_events)

    return all_events, CommandResults(readable_output=hr)


def fetch_all_events(client: Client, params: dict, last_run: dict, log_types: list) -> tuple[dict, list]:
    """
    Fetch events from various log types and aggregate the results.

    Args:
        client (Client): The client instance used to interact with the event source.
        params (dict): Dictionary of parameters, including network activity filters and settings for fetching events.
        last_run (dict): Dictionary of the last run details used to determine the starting point for fetching events.

    Returns:
        last_run (dict): Updated dictionary with new timestamps for each log type.
        all_events (list): List of all collected events from different log types.
    """
    all_events: list = []
    filters = params.get("network_activity_filters", [])
    for log_type in log_types:
        start_timestamp = initialize_start_timestamp(last_run, log_type)
        max_results, limit = get_max_results_and_limit(params, log_type)
        last_run, collected_events = fetch_events(client, last_run, start_timestamp,
                                                  log_type, filters, max_results, limit)
        all_events.extend(collected_events)

    return last_run, all_events


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): ZeroNetworks client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        start_timestamp = initialize_start_timestamp({}, "")
        client.search_events(limit=1, cursor=start_timestamp, log_type=AUDIT)
    except Exception as e:
        if 'Unauthorized' in str(e):
            return 'Authorization Error: make sure the API Key is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """
    Main function for parsing parameters and executing command functions.
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('credentials', {}).get('password')
    server_url = urljoin(params.get('url'))
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = params.get('proxy', False)
    should_push_events = argToBoolean(args.get('should_push_events', False))
    event_types_to_fetch = argToList(params.get('event_types_to_fetch', []))
    log_types = handle_log_types(event_types_to_fetch)
    isFetch = params.get('isFetchEvents')
    if isFetch and not log_types:
        raise DemistoException("At least one event type must be specified for fetching.")

    demisto.debug(f'Event types that will be fetched in this instance: {log_types}')

    filters = params.get('network_activity_filters', '')
    if 'network_activities' in log_types and not filters:
        raise DemistoException(
            "Using network_activity_filters is required when fetching network events, to limit the number of events.")

    demisto.debug(f'Command being called is {command}')
    try:
        headers: dict = {'accept': 'application/json', 'Authorization': api_key}

        client = Client(
            server_url=server_url,
            proxy=proxy,
            verify=verify_certificate,
            headers=headers)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'zero-networks-segment-get-events':
            last_run = demisto.getLastRun()
            events, results = get_events(client, args, last_run, params, log_types)  # type: ignore
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_all_events(client, params, last_run, log_types)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

# Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
