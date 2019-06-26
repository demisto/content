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

# USERNAME = demisto.params().get('credentials').get('identifier')
# PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/xapi/v1/'
# Headers to be sent in requests
TENANT_ID = '11'
APPLICATION_ID = 'Demisto'
HEADERS = {
    'tenantid': TENANT_ID,
    'applicationid': APPLICATION_ID,
    # 'Authorization': 'Token ' + TOKEN + ':' + USERNAME + PASSWORD,
    # 'Content-Type': 'application/json',
    # 'Accept': 'application/json'
}
# Remove proxy if not set to true in params
handle_proxy()

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, test=False, params=None, data=None, operation=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix if not test else url_suffix,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=HEADERS
        )
    except requests.exceptions.ConnectionError:
        return_error(f'Invalid server address')
    return parse_http_response(res, operation, test)


def parse_http_response(resp, operation, test=False):
    try:
        resp.raise_for_status()
        return resp.json() if not test else resp.text
    # except requests.exceptions.HTTPError as err:
    # Handle error responses gracefully
    except Exception as err:
        return_error(f'Error in {operation}: {err}')


# def item_to_incident(item):
#     incident = {}
#     # Incident Title
#     incident['name'] = 'Example Incident: ' + item.get('name')
#     # Incident occurrence time, usually item creation date in service
#     incident['occurred'] = item.get('createdDate')
#     # The raw response from the service, providing full info regarding the item
#     incident['rawJSON'] = json.dumps(item)
#     return incident
#


def health_check():
    path = f'{SERVER}/xapi/health-check'
    server_status = http_request('GET', path, test=True)
    if server_status == '"Ok"':
        return
    else:
        return_error(f'Server health-check failed. Status returned was: {server_status} ')


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module_command():
    health_check()
    return

    # demisto.results({
    #     'Type': entryTypes['note'],
    #     'ContentsFormat': formats['json'],
    #     'Contents': contents,
    #     'ReadableContentsFormat': formats['markdown'],
    #     'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
    #     'EntryContext': context
    # })


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module_command()
        demisto.results('ok')
    # elif demisto.command() == 'traps-get-endpoint-by-id':
    #     # An example command
    #     get_items_command()

# Log exceptions
except Exception as e:
    LOG(e)
    LOG.print_log()
