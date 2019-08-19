import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Setting global params, initiation in main() function
TOKEN: str = ''
SERVER: str = ''
USE_SSL: bool = False
FETCH_TIME: str = ''
BASE_URL: str = ''
HEADERS: dict = dict()
PROXIES: dict or None = None

''' HELPER FUNCTIONS '''


def http_request(method: str, url_suffix: str, params: dict = None, data: dict = None, proxies: list = None,
                 headers: dict = None):
    """

    Args:
        method: Method to use: ['GET', 'POST', 'PUT', 'DELETE']
        url_suffix: suffix to add to SERVER param
        params: dict to use in url query
        data: body of request
        proxies: list of proxies to use
        headers: dict of headers

    Returns:

    """
    # A wrapper for requests lib to send our requests and handle requests and responses better
    err_msg = 'Error in API call to Example Integration [{}] - {}'
    if proxies is None:
        proxies = PROXIES
    if headers is None:
        headers = HEADERS

    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers,
        proxies=proxies
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error(err_msg.format(res.status_code, res.reason))
    try:
        return res.json()
    except ValueError as e:
        return_error(err_msg.format(res.status_code, res.reason), error=str(e))


def item_to_incident(item: dict):
    incident: dict = dict()
    # Incident Title
    incident['name'] = f'Example Incident: {item.get("name")}'
    # Incident occurrence time, usually item creation date in service
    incident['occurred'] = item.get('createdDate')
    # The raw response from the service, providing full info regarding the item
    incident['rawJSON'] = json.dumps(item)
    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', 'items/samples')


def get_items_command():
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Init main vars
    context: dict = dict()
    context_entries: list = list()
    title: str = ''
    # Get arguments from user
    item_ids: list = argToList(demisto.args().get('item_ids', []))
    is_active: bool = demisto.args().get('is_active') == 'true'
    limit: int = int(demisto.args().get('limit', 10))
    # Make request and get raw response
    raw_response: list = get_items_request(item_ids, is_active)
    # Parse response into context & content entries
    if raw_response:
        if limit:
            raw_response = raw_response[:limit]
        title = 'Example - Getting Items Details'

        context_entries = [
            {
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'CreatedDate': item.get('createdDate')
            } for item in raw_response
        ]

        context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries
    # Creating human readable for War room
    human_readable = tableToMarkdown(title, context_entries, removeNull=True)
    # Return data to Demisto
    return_outputs(human_readable, context, raw_response)


def get_items_request(item_ids: list, is_active: bool):
    """

    Args:
        item_ids:
        is_active:

    Returns:
        Dict: response data
    """
    # The service endpoint to request from
    endpoint_url: str = 'items'
    # Dictionary of params for the request
    params = {
        'ids': item_ids,
        'isActive': is_active
    }
    # Send a request using our http_request wrapper
    response = http_request('GET', endpoint_url, params)
    # Check if response contains errors
    if response.get('errors'):
        return_error(response.get('errors'))
    # Check if response contains any data to parse
    if 'data' in response:
        return response.get('data')
    # If neither was found, return back empty results
    return {}


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    incidents = []
    items = get_items_request()
    for item in items:
        incident = item_to_incident(item)
        incident_date = date_to_timestamp(incident['occurred'], '%Y-%m-%dT%H:%M:%S.%fZ')
        # Update last run and add incident if the incident is newer than last fetch
        if incident_date > last_fetch:
            last_fetch = incident_date
            incidents.append(incident)

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))


def main():
    global TOKEN, SERVER, USE_SSL, FETCH_TIME, BASE_URL, HEADERS, PROXIES
    TOKEN = demisto.params().get('api_key')
    # Remove trailing slash to prevent wrong URL path to service
    SERVER = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    # Should we use SSL
    USE_SSL = not demisto.params().get('insecure', False)
    # How many time before the first fetch to retrieve incidents
    FETCH_TIME = demisto.params().get('fetch_time', '3 days')
    # Service base URL
    BASE_URL = SERVER + '/api/v2.0/'
    # Headers to be sent in requests
    HEADERS = {
        'Authorization': f'Bearer {TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    # Remove proxy if not set to true in params
    PROXIES = handle_proxy()

    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            fetch_incidents()
        elif demisto.command() == 'example-get-items':
            # An example command
            get_items_command()

    # Log exceptions
    except Exception as e:
        return_error(error=e)


if __name__ == '__builtin__':
    main()
