import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
API_KEY = PARAMS.get('api_key')
# Remove trailing slash to prevent wrong URL path to service
SERVER = 'https://autofocus.paloaltonetworks.com'
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
PROXY = PARAMS.get('proxy')
# Service base URL
BASE_URL = SERVER + '/api/v1.0'
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json'
}

''' HELPER FUNCTIONS '''


def parse_response(resp, err_operation):
    try:
        # Handle error responses gracefully
        res_json = resp.json()
        resp.raise_for_status()
        return res_json
    except requests.exceptions.HTTPError:
        err_msg = f'{err_operation}: {res_json.get("message")}'
        return return_error(err_msg)
    except Exception as e:
        err_msg = f'{err_operation}: {e}'
        return return_error(err_msg)


def http_request(url_suffix, method='POST', params=None, data=None, err_operation=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    return parse_response(res, err_operation)


def doSearch(search_object, data, err_operation=None):
    path = 'samples/search' if search_object == 'samples' else 'sessions/search'
    result = http_request(path, data=data, err_operation=err_operation)


''' COMMANDS'''


def test_module():
    """
    Performs basic get request to get item samples
    """
    data = {
        'query': {
            'operator': 'all',
            'children': [
                {
                    'field': 'sample.malware',
                    'operator': 'is',
                    'value': 1
                }
            ]
        },
        'size': 1,
        'from': 0,
        'scope': 'public'
    }
    doSearch('samples', data, err_operation='Test module failed')
    return


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    # Remove proxy if not set to true in params
    handle_proxy()
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'example-get-items':
        # An example command
        a = 5

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
