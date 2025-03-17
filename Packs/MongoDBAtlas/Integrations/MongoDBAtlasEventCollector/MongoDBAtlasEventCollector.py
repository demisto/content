from datetime import datetime

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
from requests.auth import HTTPDigestAuth

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
VENDOR = 'MongoDB'
PRODUCT = 'Atlas'
DEFAULT_FETCH_LIMIT = 2500
ITEMS_PER_PAGE = 500

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url, verify: bool, group_id: str, private_key: str = "", public_key: str = "") -> None:
        self.group_id = group_id
        auth = HTTPDigestAuth(public_key, private_key)
        headers = {
            'Accept': "application/vnd.atlas.2023-02-01+json"
        }
        super().__init__(base_url=base_url, verify=verify, headers=headers, auth=auth)

    def get_alerts_request(self, page_num: int = None, items_per_page: int = ITEMS_PER_PAGE) -> dict:
        """
        Fetch a paginated list of alerts from the service API.

        Args:
            page_num (int): The page number to retrieve.
            items_per_page (int): The number of alerts to retrieve per page.

        Returns:
            dict: A dictionary containing the paginated list of alerts and metadata such as total count.
        """
        params = assign_params(pageNum=page_num, itemsPerPage=items_per_page)
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/atlas/v2/groups/{self.group_id}/alerts",
            params=params
        )
        return results

    def get_events_request(self, page_num: int = None, items_per_page: int = ITEMS_PER_PAGE, min_date: str = None) -> dict:
        """
        Fetch a paginated list of events from the service API.

        Args:
            page_num (int): The page number to retrieve.
            items_per_page (int): The number of events to retrieve per page.
            min_date (str): The minimum date to retrieve.

        Returns:
            dict: A dictionary containing the paginated list of events and metadata such as total count.
        """
        params = assign_params(pageNum=page_num, itemsPerPage=items_per_page, minDate=min_date)
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/atlas/v2/groups/{self.group_id}/events",
            params=params
        )
        return results

    def get_response_from_page_link(self, page_link: str) -> dict:
        """
        Sends an HTTP GET request to fetch data using `page_link`.

        Args:
            page_link (str): The full URL to the specific data page to fetch.

        Returns:
            The API response containing the data retrieved from the provided page link.
        """
        results = self._http_request(
            method="GET",
            full_url=page_link
        )
        return results

    def get_events_first_run(self, fetch_limit: int) -> list:
        """
        Fetches events from multiple pages, ensuring that the total number of fetched events does not exceed the specified
        `fetch_limit`.

        Args:
            fetch_limit (int): The maximum number of events to fetch.

        Returns:
            list: A list of events, truncated to the `fetch_limit` if necessary.
        """
        results: List[dict] = []
        items_per_page = min(fetch_limit, ITEMS_PER_PAGE)
        page_num = 1

        while len(results) < fetch_limit:
            page_results = self.get_events_request(page_num=page_num, items_per_page=items_per_page).get('results')
            if not page_results:
                break

            results.extend(page_results)

            if len(results) >= fetch_limit:
                return results[:fetch_limit]

            items_per_page = min(fetch_limit - len(results), ITEMS_PER_PAGE)
            page_num += 1

        return results


''' HELPER FUNCTIONS '''


################ ALERTS AND EVENTS FUNCTIONS ################


def add_entry_status_field(event: dict) -> None:
    """
    Adds a _ENTRY_STATUS field to an event by checking the event status.

    Args:
        event (dict): The event.
    """
    updated_str: str = str(event.get('updated'))
    created_str: str = str(event.get('created'))

    updated = datetime.strptime(updated_str, DATE_FORMAT)
    created = datetime.strptime(created_str, DATE_FORMAT)

    if updated == created:
        event['_ENTRY_STATUS'] = 'new'
    elif updated > created:
        event['_ENTRY_STATUS'] = 'updated'


def get_page_url(links: list, page_type: str) -> str:
    """
    Retrieves the URL for the next or previous page from a list of links.

    Args:
        links (list): A list of dictionaries, each representing a link with "rel" and "href" keys.
        page_type (str): The type of the page, can be 'next', 'previous' or 'self'.
    Returns:
        str or empty string: The URL for the next or previous page if found, otherwise None.
    """
    for link in links:
        if link.get("rel") == page_type:
            return link.get("href")
    return ""


def add_time_field(event: dict) -> None:
    """
    Adds a `_time` field to an event based on its updated or created time.

    Args:
        event (dict): The event dictionary to add the `_time` field to. If the event has an 'updated' time,
         `_time` will be set to this value; otherwise, it will default to the 'created' time.
    """
    if event.get('updated'):
        event['_time'] = event.get('updated')
    else:
        event['_time'] = event.get('created')


def enrich_event(event: dict, event_type: str) -> None:
    """
    Enriches each event with additional information based on its type.

    Args:
        event (dict): The event dictionary to enrich.
        event_type (str): The type of event ('alerts' or 'events').
    """
    event['source_log_type'] = event_type
    add_time_field(event)
    if event_type == 'alerts':
        add_entry_status_field(event)


################ ALERTS FUNCTIONS ################


def remove_alerts_by_ids(alerts: list, ids: list) -> list:
    """
    Removes alerts from a list based on specified IDs.

    Args:
        alerts (list): A list of alert dictionaries, each containing an "id" key.
        ids (list): A list of IDs to be removed from the alerts list.

    Returns:
        list: A filtered list of alerts excluding any alerts with IDs in the provided ids list.
    """
    results = []
    for alert in alerts:
        if alert.get('id') not in ids:
            results.append(alert)
    return results


def create_last_run_dict_for_alerts(links: list, last_page_alerts_ids: list) -> dict:
    """
    Updates the last_run dictionary with the current page's self URL and event IDs.

    Args:
        links (list): Current page links for pagination.
        last_page_alerts_ids (list): IDs of alerts on the last processed page.

    Returns:
        dict: Updated last_run dictionary.
    """
    return {
        'page_link': get_page_url(links, page_type='self'),
        'last_page_alerts_ids': last_page_alerts_ids
    }


def fetch_alerts_command(client: Client, fetch_limit: int, last_run: dict) -> tuple[list, dict]:
    """
    Fetches alerts until fetch_limit is reached, or no more alerts are available.

    Args:
        client (Client): MongoDBAtlasEventCollector client.
        fetch_limit: The maximum number of alerts to fetch.
        last_run (dict): Dictionary containing data from the previous run.

    Returns:
        - The list containing all fetched events.
        - The object to save for the next run.
    """

    demisto.debug('Start to fetch alerts')
    page_link = last_run.get('page_link', "")

    if page_link:
        demisto.debug(f'Getting a response from page {page_link}')
        response = client.get_response_from_page_link(page_link)
    else:
        demisto.debug('Initialize the first page')
        response = client.get_alerts_request(page_num=1, items_per_page=ITEMS_PER_PAGE)

    links = response.get('links', [])
    results = response.get('results', [])

    last_page_alerts_ids = last_run.get('last_page_alerts_ids', [])

    alerts = remove_alerts_by_ids(results, last_page_alerts_ids)
    demisto.debug(f'Those are the events ids from the last run {last_page_alerts_ids}')
    output = []

    while True:
        for alert in alerts:
            enrich_event(alert, event_type='alerts')
            output.append(alert)
            last_page_alerts_ids.append(alert.get('id'))

            if len(output) >= fetch_limit:
                last_run_new_dict = create_last_run_dict_for_alerts(links, last_page_alerts_ids)
                demisto.debug(f'The limit is reached. Amount of fetched alerts is {len(output)}')
                return output, last_run_new_dict

        next_url = get_page_url(links, page_type="next")
        if next_url:
            response = client.get_response_from_page_link(next_url)
            alerts = response.get('results', [])
            links = response.get('links', [])
            last_page_alerts_ids.clear()
        else:
            break

    demisto.debug(f'No more pages left to fetch. Total alerts fetched: {len(output)}')
    last_run_new_dict = create_last_run_dict_for_alerts(links, last_page_alerts_ids)
    return output, last_run_new_dict


################ EVENTS FUNCTIONS ################


def get_latest_date(date1: str, date2: str) -> str:
    """
    Compares two dates and returns the latest one.

    Args:
        date1 (str): The first date in string format.
        date2 (str): The second date in string format.

    Returns:
        str: The latest date in string format.
    """
    if not date1:
        return date2
    if not date2:
        return date1

    dt1 = datetime.strptime(date1, DATE_FORMAT)
    dt2 = datetime.strptime(date2, DATE_FORMAT)

    return date1 if dt1 >= dt2 else date2


def get_last_page_of_events(client: Client, results: dict) -> dict:
    """
    Iterates through paginated event data, following "next" links provided in the API response until it reaches the last page.

    Args:
        client (Client): The API client instance used to retrieve the event data.
        results (dict): The initial response dictionary containing event data and pagination links.

    Returns:
        dict: The final page of events retrieved from the API.
    """
    links = results.get('links', [])
    next_url = get_page_url(links, page_type="next")
    last_response = results

    while next_url:
        last_response = client.get_response_from_page_link(next_url)
        links = last_response.get('links')
        next_url = get_page_url(links, page_type='next')

    return last_response


def save_events_ids_with_specific_created_date(events: list, created_date: str) -> list:
    """
    Filters event IDs by a given creation date.

    Args:
        events (list): List of event dictionaries with "id" and "created" date fields.
        created_date (str): Target creation date to filter by.

    Returns:
        list: IDs of events matching the specified creation date.
    """
    results = []
    for event in events:
        if event.get('created') == created_date:
            results.append(event.get('id'))
    return results


def create_last_run_dict_for_events(output: list, new_min_time: str) -> dict:
    """
    Creates a dictionary to store the last run information for events.

    Args:
        output (list): List of event dictionaries.
        new_min_time (str): The minimum time to filter events by.

    Returns:
        dict: A dictionary with `min_time` and `events_with_created_min_time` keys.
    """
    events_with_created_min_time = save_events_ids_with_specific_created_date(output, new_min_time)
    return {'min_time': new_min_time,
            'events_with_created_min_time': events_with_created_min_time
            }


def first_time_fetching_events(client: Client, fetch_limit: int) -> tuple[list, str]:
    """
    Fetches and enriches the first batch of events, returning them with the minimum creation time.

    Args:
        client (Client): The client instance used to retrieve events.
        fetch_limit (int): The maximum number of events to retrieve.

    Returns:
        tuple: A tuple containing:
            - results (list): A list of event dictionaries.
            - new_min_time (str): The creation time of the latest fetched event.
    """
    results = client.get_events_first_run(fetch_limit)
    for event in results:
        enrich_event(event, event_type='events')
    last_fetched_event = results[0] if results else None
    new_min_time = last_fetched_event.get('created') if last_fetched_event else None
    return results, new_min_time  # type: ignore[return-value]


def fetch_events_command(client: Client, fetch_limit: int, last_run: dict) -> tuple[list, dict]:
    """
    Fetches events until fetch_limit is reached, or no more events are available.

    Args:
        client (Client): MongoDBAtlasEventCollector client.
        fetch_limit (int): The maximum number of events to fetch.
        last_run (dict): Dictionary containing data from the previous run.

    Returns:
        - The list containing all fetched events.
        - The object to save for the next run.
    """
    min_date = last_run.get('min_time')
    events_with_created_min_time = last_run.get('events_with_created_min_time') or []

    if not min_date:  # first time fetching events
        output, new_min_time = first_time_fetching_events(client, fetch_limit)
        new_last_run_obj = create_last_run_dict_for_events(output, new_min_time)
        return output, new_last_run_obj

    demisto.debug(f'Start to fetch events with {min_date}')

    results: dict = client.get_events_request(min_date=min_date)
    response = get_last_page_of_events(client, results)
    links = response.get('links', [])
    events = response.get('results', [])

    output = []
    new_min_date = min_date

    while True:
        for event in reversed(events):
            event_id = event.get('id')
            if event_id in events_with_created_min_time:
                continue

            enrich_event(event, 'events')
            output.append(event)
            new_min_date = get_latest_date(new_min_date, event.get('created'))

            if len(output) >= fetch_limit:
                demisto.debug(f'Fetch limit reached. Total events fetched: {len(output)}')
                new_last_run_obj = create_last_run_dict_for_events(output, new_min_date)
                return output, new_last_run_obj

        previous_page = get_page_url(links, page_type='previous')
        if previous_page:
            response = client.get_response_from_page_link(previous_page)
            events = response.get('results', [])
            links = response.get('links', [])
        else:
            break

    demisto.debug(f'No more events left to fetch. Total events fetched: {len(output)}')
    new_last_run_obj = create_last_run_dict_for_events(output, new_min_date)
    return output, new_last_run_obj


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: MongoDB Atlas client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    fetch_events_command(client=client, fetch_limit=1, last_run={})
    return 'ok'


def fetch_events(client: Client, fetch_limit: int) -> tuple[list, dict]:
    last_run = demisto.getLastRun()

    alerts_output, last_run_alerts = fetch_alerts_command(client, fetch_limit, last_run)
    events_output, last_run_events = fetch_events_command(client, fetch_limit, last_run)

    last_run_new_obj = {**last_run_alerts, **last_run_events}
    return (alerts_output + events_output), last_run_new_obj


def get_events(client: Client, args) -> tuple[list, CommandResults]:
    fetch_limit = int(args.get('limit'))

    output, _ = fetch_events(client, fetch_limit)

    filtered_events = []
    for event in output:
        filtered_event = {'ID': event.get('id'),
                          'Event Type': event.get('source_log_type'),
                          'Time': event.get('_time'),
                          'Created': event.get('created')
                          }
        filtered_events.append(filtered_event)

    human_readable = tableToMarkdown(name='MongoDB Atlas Events', t=filtered_events, removeNull=True)
    command_results = CommandResults(
        readable_output=human_readable,
        outputs=output,
        outputs_prefix='MongoDBAtlasEventCollector',
    )
    return output, command_results


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f'MongoDB Command being called is {demisto.command()}')
    try:
        credentials = params.get('credentials', {})
        public_key = credentials.get('identifier')
        private_key = credentials.get('password')
        group_id = params.get('group_id')

        base_url = params.get('url')
        verify = not params.get('insecure', False)
        fetch_limit = arg_to_number(params.get('max_events_per_fetch')) or DEFAULT_FETCH_LIMIT

        client = Client(
            base_url=base_url,
            verify=verify,
            public_key=public_key,
            private_key=private_key,
            group_id=group_id
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'mongo-db-atlas-get-events':
            events, command_results = get_events(client, args)
            if events and argToBoolean(args.get('should_push_events')):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        elif command == 'fetch-events':
            events, last_run_new_obj = fetch_events(client, fetch_limit)
            if events:
                demisto.debug(f'Sending {len(events)} events to Cortex XSIAM')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(last_run_new_obj)
                demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
