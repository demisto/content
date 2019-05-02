import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse as parsedate

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

PARAMS = demisto.params()
USERNAME = PARAMS.get('credentials').get('identifier')
PASSWORD = PARAMS.get('credentials').get('password')
# Remove trailing slash to prevent wrong URL path to service
BASE_URL = PARAMS.get('url', '').strip().rstrip('/')
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
AUTH = ''
LAST_JWT_FETCH = None
# Default JWT validity time set in Forescout Web API
JWT_VALIDITY_TIME = timedelta(minutes=5)


''' HELPER FUNCTIONS '''


def login():
    if not LAST_JWT_FETCH or datetime.now(timezone.utc) >= LAST_JWT_FETCH + JWT_VALIDITY_TIME:
        url_suffix = '/api/login'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        params = {'username': USERNAME, 'password': PASSWORD}
        response = http_request('POST', url_suffix, headers=headers, params=params)
        fetch_time = parsedate(response.headers.get('Date', ''))
        AUTH = response.text
        LAST_JWT_FETCH = fetch_time


def http_request(method, url_suffix, full_url=None, headers=None, auth=None, params=None, data=None, files=None):
    """
    A wrapper for requests lib to send our requests and handle requests
    and responses better

    Parameters
    ----------
    method : str
        HTTP method, e.g. 'GET', 'POST' ... etc.
    url_suffix : str
        API endpoint.
    full_url : str
        Bypasses the use of BASE_URL + url_suffix. Useful if there is a need to
        make a request to an address outside of the scope of the integration
        API.
    headers : dict
        Headers to send in the request.
    auth : tuple
        Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    params : dict
        URL parameters.
    data : dict
        Data to be sent in a 'POST' request.
    files : dict
        File data to be sent in a 'POST' request.

    Returns
    -------
    dict
        Response JSON from having made the request.
    """
    try:
        address = full_url if full_url else BASE_URL + url_suffix
        res = requests.request(
            method,
            address,
            verify=USE_SSL,
            params=params,
            data=data,
            files=files,
            headers=headers,
            auth=auth
        )

        # Handle error responses gracefully
        if 300 <= res.status_code < 200:
            err_msg = 'Error in Forescout Integration API call [{}] - {}'.format(res.status_code, res.reason)
            try:
                res_json = res.json()
                if res_json.get('error'):
                    err_msg += '\n{}'.format(res_json.get('message'))
                return_error(err_msg)
            except json.decoder.JSONDecodeError:
                return_error(err_msg)

        return res.json()

    except json.decoder.JSONDecodeError:
        if res.text != '':
            return res
        else:
            return return_error('No contents in the response.')
    except requests.exceptions.ConnectionError:
        err_msg = 'Connection Error - Check that the Server URL parameter is correct.'
        return_error(err_msg)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = http_request('GET', 'items/samples')


def get_items_command():
    """
    Gets details about a items using IDs or some other filters
    """
    # Init main vars
    headers = []
    contents = []
    context = {}
    context_entries = []
    title = ''
    # Get arguments from user
    item_ids = argToList(demisto.args().get('item_ids', []))
    is_active = bool(strtobool(demisto.args().get('is_active', 'false')))
    limit = int(demisto.args().get('limit', 10))
    # Make request and get raw response
    items = get_items_request(item_ids, is_active)
    # Parse response into context & content entries
    if items:
        if limit:
            items = items[:limit]
        title = 'Example - Getting Items Details'

        for item in items:
            contents.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'Created Date': item.get('createdDate')
            })
            context_entries.append({
                'ID': item.get('id'),
                'Description': item.get('description'),
                'Name': item.get('name'),
                'CreatedDate': item.get('createdDate')
            })

        context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_items_request(item_ids, is_active):
    # The service endpoint to request from
    endpoint_url = 'items'
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


def get_host():
    pass


def get_host_command():
    pass


def get_hosts():
    pass


def get_hosts_command():
    pass


def get_hostfields():
    pass


def get_hostfields_command():
    pass


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'forescout-get-host': get_host_command,
    'forescout-get-hosts': get_hosts_command,
    'forescout-get-hostfields': get_hostfields_command
}

''' EXECUTION '''


def main():
    """Main execution block"""

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        cmd_name = demisto.command()
        LOG('Command being called is {}'.format((cmd_name)))

        if cmd_name in COMMANDS.keys():
            COMMANDS[cmd_name]()

    # Log exceptions
    except Exception as e:
        LOG(str(e))
        LOG.print_log()
        raise


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
