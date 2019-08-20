import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Union
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
# Setting global params, initiation in main() function
USERNAME: str = ''
PASSWORD: str = ''
SERVER: str = ''
USE_SSL: bool = False
BASE_URL: str = ''
HEADERS: dict = dict()
PROXIES: Union[dict, None] = None

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
        Response.json()
    """
    # A wrapper for requests lib to send our requests and handle requests and responses better
    err_msg = 'Error in API call to AuthenticationExample Integration [{}] - {}'
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
        proxies=proxies,
        auth=(USERNAME, PASSWORD)
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


def fetch_credentials():
    """Uses to fetch credentials into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_credentials
    """
    # Get credentials from api
    raw_response = http_request('GET', 'credentials')
    # Creates credentials entry
    credentials = [{
        'user': credential.get('username'),
        'password': credential.get('password'),
        'name': credential.get('name')
    } for credential in raw_response]
    demisto.credentials(credentials)


def lock_account(account: str) -> str:
    """Gets events from given ids

    Args:
        account: account to lock

    Returns:
        str: locked account
    """
    # The service endpoint to request from
    suffix: str = 'account/lock'
    # Dictionary of params for the request
    params = {
        'account': account
    }
    # Send a request using our http_request wrapper
    response = http_request('PUT', suffix, params)
    # Check if response contains any data to parse
    return response.get('account_locked')


def lock_account_command():
    """
    Gets details about a raw_response using IDs or some other filters
    """
    # Initialize main vars
    context: dict = dict()
    # Get arguments from user
    account_to_lock: str = demisto.args().get('account_id')
    # Make request and get raw response
    locked_account: str = lock_account(account_to_lock)
    # Parse response into context & content entries
    if locked_account == account_to_lock:
        title = f'AuthenticationExample - Account {locked_account} has been locked.'

        context_entry = {
            'IsLocked': True,
            'ID': account_to_lock
        }

        context['AuthenticationExample.Account(val.ID && val.ID === obj.ID)'] = context_entry
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return_outputs(human_readable, context)
    else:
        return_error(f'AuthenticationExample - Could not lock account {account_to_lock}')


def lock_vault_command():
    pass


def reset_account_command():
    pass


def close_event_command():
    pass


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))


def main():
    # Declare global parameters
    global USERNAME, PASSWORD, SERVER, USE_SSL, BASE_URL, HEADERS, PROXIES
    USERNAME = demisto.params().get('authorization', {}).get('identifier')
    PASSWORD = demisto.params().get('authorization', {}).get('password')
    # Remove trailing slash to prevent wrong URL path to service
    SERVER = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    # Should we use SSL
    USE_SSL = not demisto.params().get('insecure', False)
    # Service base URL
    BASE_URL = SERVER + '/api/v2.0/'
    # Headers to be sent in requests
    HEADERS = {
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
        elif command == 'fetch-credentials':
            # Set and define the fetch credentials command to run after activated via integration settings.
            fetch_credentials()
        elif command == 'authentication-example-lock-account':
            # An AuthenticationExample command, fully structured command
            lock_account_command()
        elif command == 'authentication-example-lock-vault':
            lock_vault_command()
        elif command == 'authentication-example-reset-account':
            reset_account_command()
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in AuthenticationExample Integration [{e}]'
        return_error(err_msg, error=str(e))


if __name__ == '__builtin__':
    main()
