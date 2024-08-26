import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
import urllib.parse

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

VENDOR = 'ZeroNetworks'
PRODUCT = 'Segment'
FIRST_FETCH = 'one minute'
MAX_RESULTS_FOR_LOG_TYPE = {'audit': 10000, 'network_activities': 2000}
MAX_CALLS_FOR_LOG_TYPE = {'audit': 10000, 'network_activities': 400}
URL = {'audit': '/audit', 'network_activities': 'activities/network'}
MAX_FETCH_PARAM_NAME = {'audit': 'max_fetch_audit', 'network_activities': 'max_fetch_network'}
AUDIT_TYPE = 'audit'
NETWORK_ACTIVITIES_TYPE = 'network_activities'

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

    def search_events(self, limit, cursor, log_type, filters=None) -> dict[str, Any]:
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


def process_events(events: list, previous_ids: set, last_event_time: int, max_results: int, num_results: int, log_type: str):
    new_events = []
    for event in events:
        event_id = event.get('id')
        if num_results == max_results:
            break

        if event_id not in previous_ids:
            event['_TIME'] = timestamp_to_datestring(event.get('timestamp'), is_utc=True)
            event['source_log_type'] = log_type
            new_events.append(event)
            event_timestamp = event.get("timestamp")
            num_results += 1
            if event_timestamp > last_event_time:
                demisto.debug('updating the last run')
                previous_ids = {event_id}
                last_event_time = event_timestamp

            # Adding the event ID when the event time is equal to the last received event
            elif event_timestamp == last_event_time:
                demisto.debug('adding id to the "new_previous_ids"')
                previous_ids.add(event_id)

    return new_events, previous_ids, last_event_time, num_results


def get_log_types(params):
    log_types = [AUDIT_TYPE]
    is_fetch_network = argToBoolean(params.get("isFetchNetwork", False))
    if is_fetch_network:
        log_types.append(NETWORK_ACTIVITIES_TYPE)

    return log_types


def initialize_start_timestamp(last_run: dict[str, Any], log_type: str) -> int:
    start_timestamp = last_run.get(log_type, {}).get("last_fetch")
    if not start_timestamp:
        start_date = dateparser.parse(FIRST_FETCH).strftime(ISO_8601_FORMAT)  # type: ignore[union-attr]
        start_timestamp = date_to_timestamp(start_date, ISO_8601_FORMAT)
    return start_timestamp


def get_max_results_and_limit(params: dict[str, Any], log_type: str) -> tuple[int, int]:
    max_results = arg_to_number(params.get(MAX_FETCH_PARAM_NAME[log_type])) or MAX_RESULTS_FOR_LOG_TYPE[log_type]
    limit = min(max_results, MAX_CALLS_FOR_LOG_TYPE[log_type])
    return max_results, limit


def prepare_filters(params: dict[str, Any]) -> str:
    filters = params.get("network_activity_filters", [])
    url_encoded = urllib.parse.quote(filters)
    url_encoded_str_with_quotes = url_encoded.replace('%22', '"')
    return url_encoded_str_with_quotes


def update_last_run(last_run: dict[str, Any], log_type: str, last_event_time: int, previous_ids: set):
    last_run[log_type] = {
        "last_fetch": last_event_time,
        "previous_ids": previous_ids
    }
    return last_run


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, params: dict, last_run: dict):
    """
       Fetches audit logs from ZeroNetworks API.
    """
    log_types = get_log_types(params)

    for log_type in log_types:
        start_timestamp = initialize_start_timestamp(last_run, log_type)
        cursor: int = start_timestamp
        last_event_time = start_timestamp
        collected_events: list = []
        max_results, limit = get_max_results_and_limit(params, log_type)
        previous_ids = last_run.get(log_type, {}).get("previous_ids", {})
        num_results = 0

        filters = prepare_filters(params) if log_type == NETWORK_ACTIVITIES_TYPE else None

        while len(collected_events) < max_results:
            response = client.search_events(limit, cursor=cursor, log_type=log_type, filters=filters)

            if not response:
                break

            events = response.get('items', [])
            cursor = int(response.get('scrollCursor', ''))

            if not events:
                break

            new_events, previous_ids, last_event_time, num_results = process_events(events, previous_ids, last_event_time,
                                                                                    max_results, num_results, log_type)

            if not new_events:
                break

            collected_events.extend(new_events)

        last_run = update_last_run(last_run, log_type, last_event_time, previous_ids)

    return last_run, collected_events


def test_module(client: Client, params) -> str:
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
        fetch_events(client, params, {})
    except Exception as e:
        if 'Unauthorized' in str(e):
            return 'Authorization Error: make sure the Client ID and API Key are correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()

    command = demisto.command()
    api_key = params.get('api_key', '')
    server_url = urljoin(params.get('url'))
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        headers: dict = {'Authorization': api_key}

        client = Client(
            server_url=server_url,
            proxy=proxy,
            verify=verify_certificate,
            headers=headers)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))

        # elif command == 'zero-networks-get-events':
        #     events, results = get_events(client, args)  # type: ignore
        #     return_results(results)
        #     if should_push_events:
        #         send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(client, params, last_run)
            demisto.setLastRun(next_run)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
