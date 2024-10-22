import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
from requests.auth import HTTPDigestAuth

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

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
            )
        except Exception as e:
            pass
        
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
        except Exception as e:
            pass
        
        return results

''' HELPER FUNCTIONS '''

def sort_list_by_created_field(data: list):
    """
    Sort a list of JSON objects by the 'created' field, which contains the event or alert's creation date.
    
    Args:
        data: the list of JSON objects.
        
    Returns:
        The sorted list.
    """
    return sorted(data, key=lambda x: datetime.strptime(x["created"], DATE_FORMAT))

def fetch_events_type(fetch_limit: int):
    pass

def fetch_alerts_type(fetch_limit: int):
    pass

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

def get_events(client: Client):
    #suppose to run fetch_events with some PageNum
    pass

def fetch_events(client: Client, fetch_limit: int):
    #run every min and return all the new events from the last run
    
    #fetch_events_type
    #fetch_alerts_type
    #concatenate the arrays
    
    #Algorithm for fetch:
    
    #initialize if not exists:
        #current_page = 1
        #fetched_events = 0 - total number of fetched events at the moment
        #last_page_amount_of_fetched_events = 0 - the number of fetched events from the last page
        
    #current_fetched_events = 0
    #output = []
    #items_per_page = 500 #the maximum the api can get
    
    #while current_fetched_events < fetch_limit:
      #response = client.get_alerts(current_page, items_per_page)
      #events = response.get('results')
      #total_count = response.get('totalCount')
      
      #sorted_list = sort_list_by_created_field(events)
      #if fetched_events >= total_count: return output
      
      #start = last_page_amount_of_fetched_events
      #for each event in events[start:]:
        #append to output
        #current_fetched_events += 1
        #fetched_events += 1
        
        #if current_fetched_events == fetch_limit:
            #save current_fetched_events+1 as last_page_amount_of_fetched_events
            #save fetched_events
            #save current_page
            #return output
            
      #current_fetched_events = 0
      #current_page += 1
    
    #return output
    
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

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        public_key = params.get('public_key', {}).get('password')
        private_key = params.get('private_key', {}).get('password')
        group_id = params.get('group_id')

        base_url = params.get('url')
        verify = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        fetch_limit = int(params.get('number_of_events_per_fetch', 2500))
        
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
            return_results(fetch_events(client,fetch_limit))


    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
