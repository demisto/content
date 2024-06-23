import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

VENDOR = 'cisco'
PRODUCT = 'secure endpoint'
INTEGRATION_NAME = 'Cisco AMP Event Collector'

FIRST_FETCH = 'one hour'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
       Client for Cisco AMP

       Args:
          client_id (str): The Cisco AMP client_id for API access.
          api_key (str): The Cisco AMP api_key for API access.
          server_url (str): The Cisco AMP API server URL.
    """
    API_VERSION = "v1"

    def __init__(self, proxy: bool, verify: bool, server_url: str, client_id: str, api_key: str):
        super().__init__(
            base_url=urljoin(server_url, self.API_VERSION),
            verify=verify,
            proxy=proxy,
            auth=(client_id, api_key),
        )

    def get_events(self, start_date: str = None, limit: int = None, offset: int = None) -> dict[str, Any]:
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
        params = remove_empty_elements({
            "start_date": start_date,
            "limit": limit,
            "offset": offset,
        })

        return self._http_request(
            method="GET",
            url_suffix="/events",
            params=params,
        )


def test_module(client: Client, params) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): CiscoAMP client to use.
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


def get_events(client, args):
    """
       Gets events from Guardicore API.
    """

    _, events = fetch_events(client=client, params=args, last_run={'last_fetch': args.get('from_date', FIRST_FETCH)})
    hr = tableToMarkdown(name='Events', t=events)
    return events, CommandResults(readable_output=hr)


def get_earliest_events(client, start_date, offset=0):
    # A loop of fetching earliest events,
    while True:
        response = client.get_events(start_date=start_date, limit=500, offset=offset)
        # Check if there are more pages to fetch
        if "next" not in response["metadata"]["links"]:
            break
        total_results = response.get('metadata', {}).get('results', {}).get('total')
        if not total_results:
            raise Exception('wrong response returned')
        offset = total_results - 500

    # Reverses the list of events so that the list is in ascending order
    # so that the earliest event will be the first in the list
    events = response.get("data")
    events.reverse()
    return events


def iterate_events(events, max_events_per_fetch, previous_ids, last_fetch_timestamp):

    # Copy the previous_ids list to manage the events list suspected of being duplicates for the next fetch
    new_previous_ids = previous_ids.copy()
    filtered_events: list[dict[str, Any]] = []
    for event in events:
        # Break once the maximum number of filtered_events has been achieved.
        if len(filtered_events) >= max_events_per_fetch:
            demisto.debug('We reached the "max_events_per_fetch" requested by the user')
            break

        # Skip if the event ID has been fetched already.
        if (event_id := str(event.get("id"))) in previous_ids:
            demisto.debug(f'skipping {event_id} as it was appear in previous_ids, which means it was already fetched')
            continue

        event_timestamp = arg_to_number(event.get('timestamp') * 1000, required=True, arg_name='event.timestamp')

        event.update({'_time': timestamp_to_datestring(event_timestamp, is_utc=True)})
        filtered_events.append(event)

        # Update the latest event time that was fetched.
        # And accordingly initializing the list of `previous_ids`
        # to the ids that belong to the time of the last event received
        if event_timestamp > last_fetch_timestamp:
            demisto.debug('updating the last run')
            new_previous_ids = {event_id}
            last_fetch_timestamp = event_timestamp

        # Adding the event ID when the event time is equal to the last received event
        elif event_timestamp == last_fetch_timestamp:
            demisto.debug('adding id to the "new_previous_ids"')
            new_previous_ids.add(event_id)

    last_run = {
        "last_fetch": timestamp_to_datestring(last_fetch_timestamp, is_utc=True),
        "previous_ids": list(new_previous_ids),
    }

    return last_run, filtered_events


def fetch_events(client: Client, params: dict, last_run: dict):
    """
       Fetches events from CiscoAMP API.
    """
    max_events_per_fetch = arg_to_number(params.get('max_events_per_fetch')) or 1000
    filtered_events = []
    while max_events_per_fetch:
        demisto.debug(f'{last_run=}')
        start_date = last_run.get("last_fetch")
        if start_date:
            start_date = dateparser.parse(start_date).strftime(ISO_8601_FORMAT)   # type: ignore[union-attr]
        else:
            start_date = dateparser.parse(FIRST_FETCH).strftime(ISO_8601_FORMAT)   # type: ignore[union-attr]
        last_fetch_timestamp = date_to_timestamp(start_date, ISO_8601_FORMAT)
        demisto.debug(f'Getting events from: {start_date}')

        # The list of event ids that are suspected of being duplicates
        previous_ids = set(last_run.get("previous_ids", []))

        events = get_earliest_events(client, start_date)
        demisto.debug(f'Received {len(events)} events from request')
        last_run, events = iterate_events(events, max_events_per_fetch, previous_ids, last_fetch_timestamp)
        demisto.debug(f'Remained {len(events)} after filtering')

        filtered_events += events

        if not events:
            break
        max_events_per_fetch -= len(filtered_events)

    demisto.debug(f'Fetched {len(filtered_events)} events.')
    return last_run, filtered_events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client_id = params.get('credentials').get('identifier')
    api_key = params.get('credentials').get('password')
    server_url = urljoin(params.get('url'))
    verify_certificate = not argToBoolean(params.get('insecure', False))
    proxy = params.get("proxy", False)
    should_push_events = argToBoolean(args.get('should_push_events', False))

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(client_id=client_id, api_key=api_key,
                        server_url=server_url, proxy=proxy, verify=verify_certificate)
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))

        elif command == 'cisco-amp-get-events':
            events, results = get_events(client, args)  # type: ignore
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun() or {}
            next_run, events = fetch_events(client, params, last_run)
            demisto.setLastRun(next_run)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
