import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

VENDOR = 'ZeroNetworks'
PRODUCT = 'Segment'
FIRST_FETCH = 'one minute'
MAX_LIMIT = 10000
LOG_TYPE = ['audit', 'network_activities']

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

    def search_events(self, limit, cursor) -> dict[str, Any]:
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
        params = remove_empty_elements({"_limit": limit, "order": "asc", "_cursor": cursor})

        return self._http_request(
            method="GET",
            url_suffix="/audit",
            params=params,
        )


''' HELPER FUNCTIONS '''


def process_events(events: list, previous_ids: set, last_event_time: int, max_results: int, num_results: int):
    new_events = []
    for event in events:
        event_id = event.get('id')
        if num_results == max_results:
            break
        
        if event_id not in previous_ids:
            event['_TIME'] = timestamp_to_datestring(event.get('timestamp'), is_utc=True)
            event['source_log_type'] = 'audit'
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


''' COMMAND FUNCTIONS '''


def fetch_events(client: Client, params: dict, last_run: dict):
    """
       Fetches audit logs from ZeroNetworks API.
    """
    start_timestamp = last_run.get("last_fetch")
    if not start_timestamp:
        start_date = dateparser.parse(FIRST_FETCH).strftime(ISO_8601_FORMAT)   # type: ignore[union-attr]
        start_timestamp = date_to_timestamp(start_date, ISO_8601_FORMAT)

    cursor = start_timestamp
    last_event_time = start_timestamp
    collected_events: list = []
    max_results: int = arg_to_number(params.get('max_results')) or MAX_LIMIT
    previous_ids = last_run.get('previous_ids', ())
    num_results = 0
    while len(collected_events) < max_results:
        response = client.search_events(limit=min(max_results, MAX_LIMIT), cursor=cursor)

        if not response:
            break

        events = response.get('items', [])
        cursor = response.get('scrollCursor')

        if not events:
            break

        new_events, previous_ids, last_event_time, num_results = process_events(events, previous_ids, last_event_time,
                                                                                max_results, num_results)

        if not new_events:
            break

        collected_events.extend(new_events)

    last_run = {
        "last_fetch": last_event_time,
        "previous_ids": previous_ids
    }

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
    is_fetch_network = params.get('isFetchNetwork', False)

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

        # elif command == 'cisco-amp-get-events':
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
