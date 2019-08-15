import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Token ' + TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    url = SERVER + url_suffix
    LOG(f'firedrill is attempting {method} request sent to {url} with params:\n{json.dumps(params, indent=4)}')
    res = requests.request(
        method,
        url,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        return_error(f'Error in API call to Example Integration [{res.status_code}] - {res.reason}')
    # TODO: Add graceful handling of various expected issues (Such as wrong URL and wrong creds)
    return res.json()


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = http_request('GET', 'items/samples')


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            test_module()
            demisto.results('ok')
        else:
            return_error(f'Command {command} is not supported.')
    except Exception as e:
        message = f'Unexpected error: {str(e)}, traceback: {traceback.format_exc()}'
        return_error(message)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
