import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Any, Dict
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Setting global params, initiation in main() function
TOKEN: str = ''
SERVER: str = ''
USE_SSL: bool = False
BASE_URL: str = ''
HEADERS: dict = dict()
PROXIES: dict or None = None

''' HELPER FUNCTIONS '''


def http_request(method: str, url_suffix: str, params: dict = None, data: dict = None, proxies: list = None,
                 headers: dict = None):
    """Basic HTTP Request wrapper

    Args:
        method: Method to use: ['GET', 'POST', 'PUT', 'DELETE']
        url_suffix: suffix to add to SERVER param
        params: dict to use in url query
        data: body of request
        proxies: list of proxies to use
        headers: dict of headers

    Returns:
        Response.json
    """
    # A wrapper for requests lib to send our requests and handle requests and responses better
    err_msg = 'Error in API call to CaseManagement Integration [{}] - {}'
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


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', 'items/samples')


def get_ticket_command():
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: dict = dict()
    # Get arguments from user
    ticket_id: str = demisto.args().get('ticket_id')
    # Make request and get raw response
    ticket: dict = get_ticket_request(ticket_id)
    # Parse response into context & content entries
    if ticket:
        title = 'CaseManagement - Getting Ticket Details'

        context_entry = {
            'ID': ticket.get('id'),
            'Description': ticket.get('description'),
            'Name': ticket.get('name'),
            'CreatedDate': ticket.get('createdDate')
        }

        context['CaseManagement.Event(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry, removeNull=True)
        # Return data to Demisto
        return_outputs(human_readable, context, ticket)
    else:
        return_error(f'CaseManagement: Could not find get ID: {ticket_id}')


def get_ticket_request(ticket_id: str) -> Dict:
    """

    Args:
        ticket_id: ID of ticket to get

    Returns:
        Dict: response data
    """
    # The service endpoint to request from
    suffix: str = 'ticket'
    # Dictionary of params for the request
    params = {
        'ticket_id': ticket_id
    }
    # Send a request using our http_request wrapper
    response = http_request('GET', suffix, params)
    # Check if response contains any data to parse
    if 'results' in response:
        return response.get('results')
    # If neither was found, return back empty results
    return {}


def list_tickets_command():
    pass


def create_ticket_command():
    pass


def close_ticket_command():
    pass


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))


def assign_ticket_command():
    pass


def main():
    # Declare global parameters
    global TOKEN, SERVER, USE_SSL, BASE_URL, HEADERS, PROXIES
    TOKEN = demisto.params().get('api_key')
    # Remove trailing slash to prevent wrong URL path to service
    SERVER = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    # Should we use SSL
    USE_SSL = not demisto.params().get('insecure', False)
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
    command: str = demisto.command()
    try:
        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif command == 'case-management-get-ticket':
            # An CaseManagement command, fully structured command
            get_ticket_command()
        elif command == 'case-management-list-tickets':
            list_tickets_command()
        elif command == 'case-management-create-ticket':
            create_ticket_command()
        elif command == 'case-management-close-ticket':
            close_ticket_command()
        elif command == 'case-managment-assign-ticket':
            assign_ticket_command()
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in CaseManagement Integration [{e}]'
        return_error(err_msg, error=str(e))


if __name__ == '__builtin__':
    main()
