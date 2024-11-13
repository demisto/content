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
MAX_NUMBER_OF_PAGES = 5
# last_run = {}

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with the service API
    """

    def __init__(self, base_url, verify: bool, group_id: str, private_key: str = "", public_key: str = ""):
        self.group_id = group_id
        auth = HTTPDigestAuth(public_key, private_key)
        headers = {
            'Accept': "application/vnd.atlas.2023-02-01+json"
        }
        super().__init__(base_url=base_url, verify=verify, headers=headers, auth=auth)

    def get_alerts_with_page_num(self, page_num, items_per_page):
        """
        Fetch a paginated list of alerts from the service API.

        Args:
            page_num (int): The page number to retrieve.
            items_per_page (int): The number of alerts to retrieve per page.

        Returns:
            dict: A dictionary containing the paginated list of alerts and metadata such as total count.
        """
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/atlas/v2/groups/{self.group_id}/alerts?pageNum={page_num}&itemsPerPage={items_per_page}",
        )
        return results

    def get_events_with_page_num(self, page_num, items_per_page):
        """
        Fetch a paginated list of events from the service API.

        Args:
            page_num (int): The page number to retrieve.
            items_per_page (int): The number of events to retrieve per page.

        Returns:
            dict: A dictionary containing the paginated list of events and metadata such as total count.
        """
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/atlas/v2/groups/{self.group_id}/events?pageNum={page_num}&itemsPerPage={items_per_page}",
        )
        return results

    def get_response_from_page_link(self, page_link: str):
        """
        Sends an HTTP GET request to fetch data using `page_link`.

        Args:
            page_link (str): The URL to the specific page of data to fetch.

        Returns:
            The API response containing the data retrieved from the provided page link.
        """
        results = self._http_request(
            method="GET",
            full_url=page_link
        )
        return results

    def get_events_with_min_time(self, min_time: str):
        """
        Sends an HTTP GET request to fetch events from the server that occurred after
        the provided `min_time`, using it as a filter.

        Args:
            min_time (str): The minimum time, specifying the earliest event time to include.

        Returns:
            The API response containing the events that match the specified time filter.
        """
        results = self._http_request(
            method="GET",
            url_suffix=f"/api/atlas/v2/groups/{self.group_id}/events?minDate={min_time}",
        )
        return results

    def first_time_fetch_alerts(self):
        """
        Initiates the first-time retrieval of alerts by fetching a single page of alerts,
        with a maximum of 500 alerts in that page.

        Returns:
            A response object containing the first page of alerts.
        """
        # TODO to change items_per_page=500
        return self.get_alerts_with_page_num(page_num=1, items_per_page=10)

    def get_events_first_five_pages(self, fetch_limit: int):
        """
        Fetches events from up to 5 pages, ensuring that the total number of fetched events does not exceed the specified
        `fetch_limit`.

        Args:
            fetch_limit (int): The maximum number of events to fetch.

        Returns:
            list: A list of events, truncated to the `fetch_limit` if necessary.
        """
        # TODO to change items_per_page=500 + unittest
        results = []
        items_per_page = min(fetch_limit, 50)

        for page_num in range(1, MAX_NUMBER_OF_PAGES + 1):
            page_results = self.get_events_with_page_num(page_num=page_num, items_per_page=items_per_page).get('results')
            results.extend(page_results)

            if len(results) >= fetch_limit:
                return results[:fetch_limit]

            items_per_page = min(fetch_limit - len(results), 50)

        return results


''' HELPER FUNCTIONS '''


################ ALERTS AND EVENTS FUNCTIONS ################

def add_entry_status_field(event: dict):
    """
    Adds a _entry_status field to an event by checking the event status.

    Args:
        event (dict): The event.
    """
    updated_str: str = str(event.get('updated'))
    created_str: str = str(event.get('created'))

    updated = datetime.strptime(updated_str, DATE_FORMAT)
    created = datetime.strptime(created_str, DATE_FORMAT)

    if updated == created:
        event['_entry_status'] = 'new'
    elif updated > created:
        event['_entry_status'] = 'updated'


def get_next_url(links: list):
    """
    Retrieves the URL for the next page from a list of links.

    Args:
        links (list): A list of dictionaries, each representing a link with "rel" and "href" keys.

    Returns:
        str or empty string: The URL for the next page if found, otherwise None.
    """
    for link in links:
        if link.get("rel") == "next":
            return link.get("href")
    return ""


def get_self_url(links: list):
    """
    Retrieves the self-referential URL from a list of links.

    Args:
        links (list): A list of dictionaries, each representing a link with "rel" and "href" keys.

    Returns:
        str or empty string: The self URL if found, otherwise None.
    """
    for link in links:
        if link.get("rel") == "self":
            return link.get("href")
    return ""


def add_time_field(event: dict):
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


def enrich_event(event: dict, event_type: str):
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


def remove_alerts_by_ids(alerts: list, ids: list):
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


def get_page_from_last_run_for_alerts(client: Client, page_link: str):
    """
    Retrieves alerts based on the last fetched page link or performs an initial fetch.

    Args:
        client (Client): MongoDB Atlas client.
        page_link (str): The URL of the last fetched page, if available.

    Returns:
        dict: The API response containing alerts data.
    """
    if page_link:
        demisto.debug(f'Getting a response from page {page_link}')
        response = client.get_response_from_page_link(page_link)
    else:
        demisto.debug('Initialize the first page')
        response = client.first_time_fetch_alerts()
    return response


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
        'page_link': get_self_url(links),
        'last_page_alerts_ids': last_page_alerts_ids
    }


def fetch_alert_type(client: Client, fetch_limit: int, last_run: dict):
    """
    Fetches alerts until fetch_limit is reached, or no more alerts are available.

    Args:
        client (Client): MongoDBAtlas client.
        fetch_limit: The maximum number of alerts to fetch.
        last_run (dict): Dictionary containing data from the previous run.

    Returns:
        A list containing all fetched alerts.
    """

    demisto.debug('Start to fetch alerts')
    page_link = last_run.get('page_link', "")
    response = get_page_from_last_run_for_alerts(client, page_link)  # get the last page or get the first page
    links = response.get('links')
    results = response.get('results')

    last_page_alerts_ids = last_run.get('last_page_alerts_ids', [])

    events = remove_alerts_by_ids(results, last_page_alerts_ids)
    demisto.debug(f'Those are the events ids from the last run {last_page_alerts_ids}')
    current_fetched_events_amount = 0
    output = []

    while current_fetched_events_amount < fetch_limit:
        for event in events:
            enrich_event(event, 'alerts')
            output.append(event)
            last_page_alerts_ids.append(event.get('id'))
            current_fetched_events_amount += 1

            demisto.debug(f'Fetched alerts ID {event.get("id")} from type alerts')

            if current_fetched_events_amount == fetch_limit:
                last_run_new_dict = create_last_run_dict_for_alerts(links, last_page_alerts_ids)
                demisto.debug(f'The limit is reached. Amount of fetched alerts is {len(output)}')
                return output, last_run_new_dict

        next_url = get_next_url(links)
        if next_url:
            response = client.get_response_from_page_link(next_url)
            events = response.get('results')
            links = response.get('links')
            last_page_alerts_ids.clear()
        else:
            break

    demisto.debug(f'No more pages left to fetch. Total alerts fetched: {len(output)}')
    last_run_new_dict = create_last_run_dict_for_alerts(links, last_page_alerts_ids)
    return output, last_run_new_dict


################ EVENTS FUNCTIONS ################


def get_previous_page(links: list) -> str | None:
    """
    Finds and returns the URL of the previous page from a list of link dictionaries.

    Args:
        links (list): A list of dictionaries representing links, where each dictionary contains "rel" and "href" keys.

    Returns:
        str or None: The URL of the previous page if found, otherwise None.
    """
    for link in links:
        if link.get("rel") == "previous":
            return link.get("href")
    return None


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


def add_second_to_date(date: str) -> str:
    # TODO if not used - to delete
    date_plus_one_second = datetime.strptime(date, DATE_FORMAT) + timedelta(seconds=1)
    return date_plus_one_second.strftime(DATE_FORMAT)


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
    next_url = get_next_url(links)
    last_response = results

    while next_url:
        last_response = client.get_response_from_page_link(next_url)
        links = last_response.get('links')
        next_url = get_next_url(links)

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


def get_page_with_min_time_for_events(client: Client, min_time, fetch_limit) -> dict:
    """
    If `min_time` is provided, fetches events from that timestamp onward.
    If None, fetches events from the beginning.

    Args:
        client (Client): The API client for fetching events.
        min_time: The timestamp to fetch from, or None to start from the beginning.
        fetch_limit:
    Returns:
        dict: A dictionary of events from the specified time.
    """
    if min_time:
        results = client.get_events_with_min_time(min_time)
    else:
        results = client.get_events_first_five_pages(fetch_limit)
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


def first_time_fetching_events(client: Client, fetch_limit: int):
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
    results = client.get_events_first_five_pages(fetch_limit)
    for event in results:
        enrich_event(event, event_type='events')
    last_fetched_event = results[0] if results else None
    new_min_time = last_fetched_event.get('created') if last_fetched_event else None
    return results, new_min_time


def fetch_event_type(client: Client, fetch_limit: int, last_run: dict) -> tuple[list, dict]:
    """
    Fetches events until fetch_limit is reached, or no more events are available.

    Args:
        client (Client): MongoDBAtlas client.
        fetch_limit (int): The maximum number of events to fetch.
        last_run (dict): Dictionary containing data from the previous run.

    Returns:
        A list containing all fetched events.
    """
    min_time = last_run.get('min_time')
    events_with_created_min_time = last_run.get('events_with_created_min_time') or []

    demisto.debug(f'Start to fetch events with {min_time}')

    if min_time:
        results = client.get_events_with_min_time(min_time)
    else:  # first time fetching events
        results, new_min_time = first_time_fetching_events(client, fetch_limit)
        new_last_run_obj = create_last_run_dict_for_events(results, new_min_time)
        return results, new_last_run_obj

    response = get_last_page_of_events(client, results)
    links = response.get('links', [])
    events = response.get('results', [])

    current_fetched_events_amount = 0
    output = []
    new_min_time = min_time

    while current_fetched_events_amount < fetch_limit:
        for event in reversed(events):  # ignore
            event_id = event.get('id')
            if event_id in events_with_created_min_time:
                continue

            enrich_event(event, 'events')
            output.append(event)
            current_fetched_events_amount += 1
            new_min_time = get_latest_date(new_min_time, event.get('created'))

            demisto.debug(f'Fetched event ID {event_id} from type "events"')

            if current_fetched_events_amount == fetch_limit:
                demisto.debug(f'Fetch limit reached. Total events fetched: {len(output)}')
                new_last_run_obj = create_last_run_dict_for_events(output, new_min_time)
                return output, new_last_run_obj

        previous_page = get_previous_page(links)
        if previous_page:
            response = client.get_response_from_page_link(previous_page)
            events = response.get('results', [])
            links = response.get('links', [])
        else:
            break

    demisto.debug(f'No more events left to fetch. Total events fetched: {len(output)}')
    new_last_run_obj = create_last_run_dict_for_events(output, new_min_time)
    return output, new_last_run_obj


''' COMMAND FUNCTIONS '''


def test_module(client: Client, fetch_limit) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: MongoDB Atlas client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    message: str = ''
    if int(fetch_limit) < 1 or int(fetch_limit) > 2500:
        message = 'Invalid maximum number of events per fetch, should be between 1 and 2500.'
        return_error(message)
    else:
        try:
            client.get_alerts_with_page_num(page_num=1, items_per_page=10)
            message = 'ok'
        except DemistoException as e:
            if 'Forbidden' in str(e) or 'Authorization' in str(e):
                message = 'Authorization Error: make sure private key and public key are correctly set'
            else:
                raise e
    return message


def fetch_events(client: Client, fetch_limit: int):
    last_run = demisto.getLastRun()
    # global last_run

    alerts_output, last_run_alerts = fetch_alert_type(client, fetch_limit, last_run)
    events_output, last_run_events = fetch_event_type(client, fetch_limit, last_run)

    last_run_new_obj = {**last_run_alerts, **last_run_events}
    return (alerts_output + events_output), last_run_new_obj


def get_events(client: Client, args):
    fetch_limit = int(args.get('limit'))

    last_run = demisto.getLastRun()

    alerts_output, _ = fetch_alert_type(client, fetch_limit, last_run)
    events_output, _ = fetch_event_type(client, fetch_limit, last_run)

    output = alerts_output + events_output
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
        raw_response=output
    )
    return output, command_results


''' MAIN FUNCTION '''


def main() -> None: # pragma: no cover
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f'MongoDB Command being called is {demisto.command()}')
    try:
        public_key = params.get('public_key', {}).get('password')
        private_key = params.get('private_key', {}).get('password')
        group_id = params.get('group_id')

        base_url = params.get('url')
        verify = not params.get('insecure', False)
        fetch_limit = params.get('max_events_per_fetch', 2500)

        client = Client(
            base_url=base_url,
            verify=verify,
            public_key=public_key,
            private_key=private_key,
            group_id=group_id
        )

        if command == 'test-module':
            result = test_module(client, fetch_limit)
            return_results(result)
        elif command == 'mongo-db-atlas-get-events':
            events, command_results = get_events(client, args)
            if events and argToBoolean(args.get('should_push_events')):
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            return_results(command_results)
        elif command == 'fetch-events':
            # while True:
            events, last_run_new_obj = fetch_events(client, int(fetch_limit))
            # global last_run
            # last_run = last_run_new_obj
            if events:
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(last_run_new_obj)
                demisto.debug(f'Successfully saved last_run= {demisto.getLastRun()}')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
