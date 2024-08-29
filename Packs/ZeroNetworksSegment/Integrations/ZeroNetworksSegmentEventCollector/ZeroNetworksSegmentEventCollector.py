import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
import hashlib

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

VENDOR = 'ZeroNetworks'
PRODUCT = 'Segment'
FIRST_FETCH = 'one minute'
MAX_RESULTS_FOR_LOG_TYPE = {'audit': 10000, 'network_activities': 2000}
MAX_CALLS_FOR_LOG_TYPE = {'audit': 10000, 'network_activities': 400}
URL = {'audit': '/audit', 'network_activities': '/activities/network'}
MAX_FETCH_PARAM_NAME = {'audit': 'max_fetch_audit', 'network_activities': 'max_fetch_network'}
AUDIT_TYPE = 'audit'
NETWORK_ACTIVITIES_TYPE = 'network_activities'
TYPES_TO_TITLES = {'audit': 'Audit', 'network_activities': 'Network Activities'}
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
        Get a list of events.
        Args:
            start_date (str, optional): Fetch events that are newer than given time.
                Defaults to None.
            limit (int, optional): Maximum number of events to return.
                Defaults to None.
            offset (int, optional): Item number to start looking from.
                Defaults to None.
        Returns:
            Dict[str, Any]: A list of events.
        """
        if log_type == NETWORK_ACTIVITIES_TYPE:
            params = remove_empty_elements({"_limit": limit, "order": "asc", "_cursor": cursor, "_filters": filters})
        else:
            params = remove_empty_elements({"_limit": limit, "order": "asc", "_cursor": cursor})

        return self._http_request(
            method="GET",
            url_suffix=URL[log_type],
            params=params,
            headers=self._headers
        )


''' HELPER FUNCTIONS '''


def get_log_types(params: dict) -> list:
    log_types = [AUDIT_TYPE]
    is_fetch_network = argToBoolean(params.get("isFetchNetwork", False))
    if is_fetch_network:
        log_types.append(NETWORK_ACTIVITIES_TYPE)

    return log_types


def initialize_start_timestamp(last_run: dict[str, Any], log_type: str, arg_from=None) -> int:
    if arg_from:
        return arg_from

    start_timestamp = last_run.get(log_type, {}).get("last_fetch")
    if not start_timestamp:
        start_date = dateparser.parse(FIRST_FETCH).strftime(ISO_8601_FORMAT)  # type: ignore[union-attr]
        start_timestamp = date_to_timestamp(start_date, ISO_8601_FORMAT)

    return start_timestamp


def get_max_results_and_limit(params: dict[str, Any], log_type: str) -> tuple[int, int]:
    max_results = arg_to_number(params.get(MAX_FETCH_PARAM_NAME[log_type])) or MAX_RESULTS_FOR_LOG_TYPE[log_type]
    limit = min(max_results, MAX_CALLS_FOR_LOG_TYPE[log_type])
    if limit < 20:
        limit = 20

    return max_results, limit


def update_last_run(last_run: dict[str, Any], log_type: str, last_event_time: int, previous_ids: list) -> dict:
    last_run[log_type] = {
        "last_fetch": last_event_time,
        "previous_ids": previous_ids
    }
    return last_run


def create_id(event: dict, log_type: str) -> str:
    timestamp = event.get("timestamp")
    if log_type == AUDIT_TYPE:
        reported_object_id = event.get("reportedObjectId", "")
        performed_by_name = event.get("performed_by", {}).get("id", "")
        combined_string = f"{timestamp}-{reported_object_id}-{performed_by_name}"
    if log_type == NETWORK_ACTIVITIES_TYPE:
        src_asset_id = event.get("src", {}).get("assetId", "")
        dst_asset_id = event.get("dst", {}).get("assetId", "")
        combined_string = f"{timestamp}-{src_asset_id}-{dst_asset_id}"

    hash_object = hashlib.sha256(combined_string.encode())
    return hash_object.hexdigest()


def process_events(events: list, previous_ids: list, last_event_time: int, max_results: int, num_results: int,
                   log_type: str) -> tuple[list, list, int]:
    new_events = []
    for event in events:
        event_id = create_id(event, log_type)
        if num_results == max_results:
            break

        if event_id not in previous_ids:
            event['_TIME'] = timestamp_to_datestring(event.get('timestamp'), is_utc=True)
            event['source_log_type'] = log_type
            new_events.append(event)
            event_timestamp = event.get("timestamp")
            num_results += 1
            if int(event_timestamp) > last_event_time:
                demisto.debug('updating the last run')
                previous_ids = [event_id]
                last_event_time = event_timestamp

            # Adding the event ID when the event time is equal to the last received event
            elif int(event_timestamp) == last_event_time:
                demisto.debug('adding id to the "new_previous_ids"')
                previous_ids.append(event_id)

    return new_events, previous_ids, last_event_time


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, params: dict, last_run: dict, arg_from=None) -> tuple[dict, list, dict]:
    """
       Fetches audit logs from ZeroNetworks API.
    """
    log_types = get_log_types(params)
    all_events: list = []
    events_split_to_log_type: dict = {}
    filters = params.get("network_activity_filters", [])
    for log_type in log_types:
        start_timestamp = initialize_start_timestamp(last_run, log_type, arg_from)
        cursor = start_timestamp
        last_event_time = start_timestamp
        collected_events: list = []
        max_results, limit = get_max_results_and_limit(params, log_type)
        previous_ids = last_run.get(log_type, {}).get("previous_ids", [])

        while len(collected_events) < max_results:
            response = client.search_events(limit, cursor=cursor, log_type=log_type, filters=filters)

            if not response:
                break

            events = response.get('items', [])
            scroll_cursor = response.get('scrollCursor')
            if scroll_cursor:
                cursor = int(scroll_cursor)

            if not events:
                break

            new_events, previous_ids, last_event_time = process_events(events, previous_ids, last_event_time, max_results,
                                                                       len(collected_events), log_type)

            if not new_events:
                if len(events) < limit:
                    break

                limit += limit

            collected_events.extend(new_events)

        last_run = update_last_run(last_run, log_type, last_event_time, previous_ids)
        all_events.extend(collected_events)
        events_split_to_log_type[log_type] = collected_events

    return last_run, all_events, events_split_to_log_type


def get_events(client: Client, args: dict, last_run: dict, params: dict) -> tuple[list, CommandResults]:
    """
       Gets events from Zero Networks Segment API.
    """
    if arg_from := args.get("from_date"):
        arg_from = date_to_timestamp(arg_from, ISO_8601_FORMAT)

    last_run, events, events_split_to_log_type = fetch_events(client=client, params=params, last_run=last_run, arg_from=arg_from)
    final_hr = ""
    for log_type in events_split_to_log_type:
        final_hr += tableToMarkdown(name=f'{TYPES_TO_TITLES[log_type]} Events', t=events_split_to_log_type[log_type])

    return events, CommandResults(readable_output=final_hr)


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): ZeroNetworks client to use.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        start_date = dateparser.parse(FIRST_FETCH).strftime(ISO_8601_FORMAT)  # type: ignore[union-attr]
        start_timestamp = date_to_timestamp(start_date, ISO_8601_FORMAT)
        client.search_events(limit=1, cursor=start_timestamp, log_type=AUDIT_TYPE)
    except Exception as e:
        if 'Unauthorized' in str(e):
            return 'Authorization Error: make sure the API Key is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()

    command = demisto.command()
    api_key = params.get('credentials', {}).get('password')
    server_url = urljoin(params.get('url'))
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = params.get('proxy', False)
    should_push_events = argToBoolean(args.get('should_push_events', False))
    fetch_network = argToBoolean(params.get('isFetchNetwork', 'False'))
    filters = params.get('network_activity_filters', '')
    if fetch_network and not filters:
        return_error("Using filters is required to limit the number of events.")

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
            events, results = get_events(client, args, last_run, params)  # type: ignore
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun() or {}
            next_run, events, _ = fetch_events(client, params, last_run)
            demisto.setLastRun(next_run)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
