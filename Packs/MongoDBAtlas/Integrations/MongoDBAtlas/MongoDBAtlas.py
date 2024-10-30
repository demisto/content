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
last_run = {}

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
    
    def get_alerts(self, page_num, items_per_page):
        """
        Fetch a paginated list of alerts from the service API.
        
        Args:
            page_num (int): The page number to retrieve.
            items_per_page (int): The number of alerts to retrieve per page.
            
        Returns:
            dict: A dictionary containing the paginated list of alerts and metadata such as total count.
        """
        try:
            results = self._http_request(
                method="GET",
                url_suffix=f"/api/atlas/v2/groups/{self.group_id}/alerts?pageNum={page_num}&itemsPerPage={items_per_page}",
                # url_suffix=f"/api/atlas/v2/groups/{self.group_id}/alerts"
            )
        except Exception as e:
            demisto.debug(f'This is the error from get_alerts client function {e}')
            raise e
        
        return results

    def get_events(self, page_num, items_per_page):
        """
        Fetch a paginated list of events from the service API.

        Args:
            page_num (int): The page number to retrieve.
            items_per_page (int): The number of events to retrieve per page.

        Returns:
            dict: A dictionary containing the paginated list of events and metadata such as total count.
        """
        try:
            results = self._http_request(
                method="GET",
                url_suffix=f"/api/atlas/v2/groups/{self.group_id}/events?pageNum={page_num}&itemsPerPage={items_per_page}",
            )
            return results
        except Exception as e:
            demisto.debug(f'This is the error from get_events client function {e}')
            raise e
    
    def get_response_from_page_link(self, page_link: str):
        try:
            page_link = page_link[len(self._base_url):]
            results = self._http_request(
                method="GET",
                url_suffix=page_link
            )
            return results
        except Exception as e:
            demisto.debug(f'This is the error from get_response_from_page_link client function {e}')
            raise e
        
    def first_time_fetch_events(self, event_type: str):
        if event_type == 'alerts':
            demisto.debug('This is event from type alert')
            return self.get_alerts(page_num=1, items_per_page=10)
        elif event_type == 'events':
            demisto.debug('This is event from type event')
            return self.get_events(page_num=1, items_per_page=10)
        return None
        
        
''' HELPER FUNCTIONS '''

def add_entry_status_field(event: dict):
    """
    Adds a _ENTRY_STATUS field to an event by checking the event status.

    Args:
        event (dict): The event.
    """
    updated = datetime.strptime(event.get('updated'), DATE_FORMAT)
    created = datetime.strptime(event.get('created'), DATE_FORMAT)
    if updated == created:
        event['_ENTRY_STATUS'] = 'new'
    elif updated > created:
        event['_ENTRY_STATUS'] = 'updated'

def remove_events_by_ids(events: list, ids: list):
    """
    Removes events from a list based on specified IDs.

    Args:
        events (list): A list of event dictionaries, each containing an "id" key.
        ids (list): A list of IDs to be removed from the events list.

    Returns:
        list: A filtered list of events excluding any events with IDs in the provided ids list.
    """
    return [event for event in events if event["id"] not in ids]

def get_next_url(links: list):
    """
    Retrieves the URL for the next page from a list of links.

    Args:
        links (list): A list of dictionaries, each representing a link with "rel" and "href" keys.

    Returns:
        str or None: The URL for the next page if found, otherwise None.
    """
    for link in links:
        if link.get("rel") == "next":
            return link.get("href")
    return None

def get_self_url(links):
    """
    Retrieves the self-referential URL from a list of links.

    Args:
        links (list): A list of dictionaries, each representing a link with "rel" and "href" keys.

    Returns:
        str or None: The self URL if found, otherwise None.
    """
    for link in links:
        if link.get("rel") == "self":
            return link.get("href")
    return None

def get_page_from_last_run(client: Client, page_link: str, event_type: str):
    """
    Retrieves events based on the last fetched page link or performs an initial fetch.

    Args:
        client (Client): MongoDB Atlas client.
        page_link (str): The URL of the last fetched page, if available.
        event_type (str): The type of events to fetch if starting from the first page.

    Returns:
        dict: The API response containing events data.
    """
    if page_link:
        demisto.debug('Enter the first if')
        response = client.get_response_from_page_link(page_link)
    else:
        demisto.debug('Enter the else')
        response = client.first_time_fetch_events(event_type)
    demisto.debug(f'This is the response {response}')
    return response

def update_last_run_with_self_url(links, last_page_events_ids):
    """
    Updates the last_run dictionary with the current page's self URL and event IDs.

    Args:
        links (list): Current page links for pagination.
        last_page_events_ids (list): IDs of events on the last processed page.

    Returns:
        dict: Updated last_run dictionary.
    """
    return {
        'page_link': get_self_url(links),
        'last_page_events_ids': last_page_events_ids
    }
    
def enrich_event(event, event_type):
    """
    Enriches each event with additional information based on its type.

    Args:
        event (dict): The event dictionary to enrich.
        event_type (str): The type of event ('alerts' or 'events').
    """
    event['source_log_type'] = event_type
    if event_type == 'alerts':
        add_entry_status_field(event)

def fetch_events_by_type(client: Client, fetch_limit: int, last_run: dict, event_type: str):
    """
    Fetches events or alerts until fetch_limit is reached, or no more events are available.
    
    Args:
        client (Client): MongoDBAtlas client.
        fetch_limit: The maximum number of events to fetch.
        last_run (dict): Dictionary containing data from the previous run.
        event_type: The event type, can be 'alerts' or 'events'.
        
    Returns:
        A list containing all fetched events or alerts.
    """
    
    response = get_page_from_last_run(client, last_run.get('page_link'), event_type) #get the last page or get the first page
    links = response.get('links')
    results = response.get('results')
    
    last_page_events_ids = last_run.get('last_page_events_ids', [])
    events = remove_events_by_ids(results, last_page_events_ids)
    
    current_fetched_events_amount = 0
    output = []
    
    while current_fetched_events_amount <= fetch_limit:
        for event in events:
            #running on the current page
            enrich_event(event, event_type)
            output.append(event)
            demisto.debug(f'This is the event that is appended {event}')
            last_page_events_ids.append(event.get('id'))
            current_fetched_events_amount += 1
            
            if current_fetched_events_amount == fetch_limit:
                #the limit is reached, save the current page and the ids.
                last_run_new_dict = update_last_run_with_self_url(links, last_page_events_ids)
                demisto.debug(f'This is the output of fetch_events {output}, the limit is reached')
                return output, last_run_new_dict
            
        next_url = get_next_url(links)
        if next_url:
            #change to the next page and start again
            response = client.get_response_from_page_link(next_url)
            events = response.get('results')
            links = response.get('links')
            last_page_events_ids.clear()
        else:
            #no more pages left, exit the loop
            demisto.debug(f'This is the output of fetch_events {output}, there is no pages left')
            break
            
    
    demisto.debug(f'This is the output of fetch_events {output}')
    last_run_new_dict = update_last_run_with_self_url(links, last_page_events_ids)
    return output, last_run_new_dict

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: MongoDB Atlas client

    Returns:
        'ok' if test passed, anything else will fail the test
    """

    message: str = ''
    try:
        client.get_alerts(page_num=1, items_per_page=1)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure private key and public key are correctly set'
        else:
            raise e
    return message

def fetch_events(client: Client, fetch_limit: int):
    #run every min and return all the new events from the last run
    demisto.debug('Enter the fetch_events function')
    last_run = demisto.getLastRun()
    # global last_run
    last_run_alerts = last_run.get('alerts', {})
    last_run_events = last_run.get('events', {})
    
    demisto.debug('Getting the alerts')
    alerts_output, last_run_alerts = fetch_events_by_type(client, fetch_limit, last_run_alerts, 'alerts')
    demisto.debug(f'Those are the alerts {alerts_output}')
    
    events_output, last_run_events = fetch_events_by_type(client, fetch_limit, last_run_events, 'events')
    demisto.debug(f'Those are the events {alerts_output}')
    
    last_run_new_obj = ({'alerts': last_run_alerts,
                        'events': last_run_events
                        })
    # last_run = ({'alerts': last_run_alerts,
    #                 'events': last_run_events
    #                  })
    demisto.debug(f'This is the final output for fetch_events {alerts_output + events_output}')
    return (alerts_output + events_output), last_run_new_obj

def get_events(client: Client):
    #suppose to run fetch_events with some PageNum
    pass

    
''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
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
        proxy = params.get('proxy', False)
        fetch_limit = int(params.get('max_events_per_fetch', 2500))
        
        client = Client (
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
            return_results(get_events(client, demisto.args()))
        elif command == 'fetch-events':
            # while True:
            demisto.debug('fetch_events is starting')
            events, last_run_new_obj = fetch_events(client,fetch_limit)
            if events:
                demisto.debug('Sending events to the send_events_to_xsiam function')
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                demisto.setLastRun(last_run_new_obj)
                demisto.debug('fetch-events command is done')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
