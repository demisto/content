import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from datetime import datetime

urllib3.disable_warnings()


''' CONSTANTS '''

VENDOR = 'Proofpoint'
PRODUCT = 'Isolation'
DEFAULT_FETCH_LIMIT = 50000
ITEMS_PER_PAGE = 10000
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
# last_run = {}

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url, verify: bool, api_key: str) -> None:
        self.api_key = api_key
        super().__init__(base_url=base_url, verify=verify)

    def get_events(self, start_date: str, end_date: str) -> dict:
        """
        Gets events from the specified start date to the end date using the API.

        Args:
            start_date (str): The start date for the data retrieval in YYYY-MM-DD format.
            end_date (str): The end date for the data retrieval in YYYY-MM-DD format.

        Returns:
            dict: The API response containing the usage data events.
        """
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/v2/reporting/usage-data?key={self.api_key}&pageSize={ITEMS_PER_PAGE}"
                       f"&from={start_date}&to={end_date}",
        )
        return results


''' HELPER FUNCTIONS '''


def get_and_parse_date(event: dict) -> str | None:
    """
    Parses the date string from an event dictionary and formats it according to the specified date format.

    Args:
        event (dict): A dictionary containing event data.

    Returns:
        str: The formatted date string if parsing is successful.

    Raises:
        ValueError: If the 'date' value in the event dictionary is invalid or cannot be parsed.
    """
    date_str = event.get('date')
    try:
        start = parse_date_string(date_str, DATE_FORMAT)
        return start.strftime(DATE_FORMAT)
    except ValueError:
        raise ValueError('Invalid date format')


def sort_events_by_date(events: list) -> list:
    """
    Sorts a list of events by their date in ascending order.

    Args:
        events (list): A list of dictionaries.

    Returns:
        list: The sorted list of events based on the 'date' field.
    """
    return sorted(events, key=lambda x: datetime.strptime(x['date'], '%Y-%m-%dT%H:%M:%S.%f%z'))


def add_time_to_event(event: dict) -> None:
    """
    Adds a '_TIME' field to an event dictionary, using the value from the 'date' field.

    Args:
        event (dict): A dictionary containing event data.
    """
    event['_TIME'] = event.get('date')


def hash_user_name_and_url(event: dict) -> str:
    """
    Generates a hash-like string by concatenating the 'url' and 'userName' fields from an event dictionary.

    Args:
        event (dict): A dictionary containing event data.

    Returns:
        str: A string in the format '<url>&<userName>'.
    """
    url = event.get('url', "")
    user_id = event.get('userName', "")
    return f'{url}&{user_id}'


def remove_duplicate_events(start_date, ids: set, events: list) -> None:
    """
    Removes duplicate events from a list of events based on a set of unique identifiers and a specified start date.

    Args:
        start_date (str): The date to check against, in the same format as the event dates.
        ids (set): A set of hashed identifiers for detecting duplicates.
        events (list): A list of event dictionaries to process.
    """
    events_copy = events.copy()
    for event in events_copy:
        current_date = get_and_parse_date(event)
        if current_date != start_date:
            break
        hashed_id = hash_user_name_and_url(event)
        if hashed_id in ids:
            events.remove(event)


def initialize_args_to_get_events(args: dict) -> tuple:
    """
    Initializes the arguments required to fetch events.

    Args:
        args (dict): A dictionary containing the input arguments for fetching events.

    Returns:
        tuple: A tuple containing: start (str), end (str), ids (set)
    """
    start = args.get('start_date')
    end = args.get('end_date')
    ids: set = set()

    return start, end, ids


def initialize_args_to_fetch_events() -> tuple:
    """
    Initializes the arguments required to fetch events based on the last run.

    Returns:
        tuple: A tuple containing start (str), end (str), ids (set).
    """
    # global last_run
    last_run = demisto.getLastRun() or {}
    start = last_run.get('start_date')
    # start = "2025-01-09T11:27:08"
    ids = set(last_run.get('ids', []))
    end = get_current_time().strftime(DATE_FORMAT)
    return start, end, ids


def get_and_reorganize_events(client: Client, start: str, end: str, ids: set) -> list:
    """
    Fetches events, sorts them by date, and removes duplicates.

    Args:
        client (Client): The client to fetch events from.
        start (str): The start date for fetching events.
        end (str): The end date for fetching events.
        ids (set): A set of already processed event IDs to filter out duplicates.

    Returns:
        list: A list of sorted and deduplicated events.
    """
    events: list = client.get_events(start, end).get('data', [])
    events = sort_events_by_date(events)
    remove_duplicate_events(start, ids, events)
    return events


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests the connection to the service by attempting to fetch events within a date range.

    Args:
        client (Client): The client object used to interact with the service.

    Returns:
        str: 'ok' if the connection is successful. If an authorization error occurs, an appropriate error message is returned.
    """
    try:
        client.get_events(start_date="2024-12-01", end_date="2024-12-02")
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_events(client: Client, fetch_limit: int, get_events_args: dict = None) -> tuple[list, dict]:
    output: list = []

    if get_events_args:  # handle get_event command
        start, end, ids = initialize_args_to_get_events(get_events_args)
    else:  # handle fetch_events case
        start, end, ids = initialize_args_to_fetch_events()
        if not start:
            # start = get_current_time().strftime(DATE_FORMAT)
            start = "2025-01-01T11:27:08"
            new_last_run = {'start_date': start, 'ids': []}
            return output, new_last_run

    current_start_date = start
    while True:
        events = get_and_reorganize_events(client, start, end, ids)
        if not events:
            break

        for event in events:
            add_time_to_event(event)
            output.append(event)
            start = get_and_parse_date(event)

            if start != current_start_date:
                current_start_date = start
                ids = set()
            hashed_id = hash_user_name_and_url(event)
            ids.add(hashed_id)

            if len(output) >= fetch_limit:
                new_last_run = {'start_date': start, 'ids': list(ids)}
                return output, new_last_run

    new_last_run = {'start_date': start, 'ids': list(ids)}
    return output, new_last_run


def get_events(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Fetches events within the specified date range and returns them.

    Args:
        client (Client): The client to fetch events from.
        args (dict): A dictionary containing the start and end dates for the query.

    Returns:
        list: A list of events fetched within the specified date range.
    """
    start_date = args.get('start_date')
    end_date = args.get('end_date')
    limit: int = arg_to_number(args.get('limit', DEFAULT_FETCH_LIMIT))

    output, _ = fetch_events(client, limit, {"start_date": start_date, "end_date": end_date})

    filtered_events = []
    for event in output:
        filtered_event = {'User ID': event.get('userId'),
                          'User Name': event.get('userName'),
                          'URL': event.get('url'),
                          'Date': event.get('date')
                          }
        filtered_events.append(filtered_event)

    human_readable = tableToMarkdown(name='Proofpoint Isolation Events', t=filtered_events, removeNull=True)
    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix='ProofpointIsolationEventCollector',
    )
    return output, command_results


''' MAIN FUNCTION '''


def main() -> None: # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        base_url = params.get('base_url')
        verify = not params.get('insecure', False)
        api_key = params.get('credentials').get('password')
        fetch_limit = arg_to_number(params.get('max_events_per_fetch')) or DEFAULT_FETCH_LIMIT

        client = Client(
            base_url=base_url,
            verify=verify,
            api_key=api_key
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'fetch-events':
            # while True:
            events, new_last_run_dict = fetch_events(client, fetch_limit)
            demisto.setLastRun(new_last_run_dict)
            # global last_run
            # last_run = new_last_run_dict
            demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')
            if events:
                demisto.debug(f'Sending {len(events)} events to Cortex XSIAM')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
        elif command == 'proofpoint-isolation-get-events':
            events, command_results = get_events(client, args)
            if events and argToBoolean(args.get('should_push_events')):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
