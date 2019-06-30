import inspect

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

OUTPUTS = {
    'get_endpoint_by_id': {
        'ID': 'guid',
        'Name': 'name',
        'Domain': 'domain',
        'Platform': 'platform',
        'Status': 'status',
        'IP': 'ip',
        'ComputerSid': 'computerSid',
        'IsCompromised': 'compromised',
        'OsVersion': 'osVersion',
        'OsProductType': 'osProductType',
        'OsProductName': 'osProductName',
        'Is64': 'is64',
        'LastSeen': 'lastSeen',
        'LastUser': 'lastUser'
    }

}

# OUTPUT_EXCEPTIONS

''' HELPER FUNCTIONS '''


def create_output(data, type='context'):
    new_data = {}
    for key, val in data.items():
        new_key = ''
        if type == 'context':
            new_key = string_to_context_key(key)
        elif type == 'md':
            new_key = string_to_table_header(key)
        new_data[new_key] = val
    return new_data


def http_request(method, url_suffix, test=False, params=None, data=None, operation_err=None):
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
    except requests.exceptions.ConnectionError as err:
        return_error(f'Error connecting to Traps server check your connection and you server address')
    return parse_http_response(res, operation_err, test)


def parse_http_response(resp, operation_err_message, test=False):
    try:
        resp.raise_for_status()
        return resp.json() if not test else resp.text
    # Handle error responses gracefully
    except requests.exceptions.HTTPError as err:
        try:
            err_message = resp.json().get('message')
        except Exception as err:
            return_error(f'{operation_err_message}: {err}')


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


def parse_data_from_responce(endpoint_data):
    new_endpoint_data = {}  # type: dict
    operation_name = inspect.stack()[1].function  # Get the caller function mame
    outputs_obj = OUTPUTS[operation_name]
    for key, val in outputs_obj.items():
        new_endpoint_data[key] = endpoint_data.get(val)

    return new_endpoint_data


def get_endpoint_by_id(endpoint_id):
    path = f'agents/{endpoint_id}'
    endpoint_data = http_request('GET', path, operation_err=f'Get endpoint {endpoint_id} failed ')
    return parse_data_from_responce(endpoint_data), endpoint_data


def endpoint_files_retrieve(endpoint_id):
    path = f'agents/{endpoint_id}/files-retrieve'
    endpoint_data = http_request('POST', path, operation_err=f'Endpoint {endpoint_id} file retrieve failed ')


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module_command():
    health_check()
    return


def get_endpoint_by_id_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    endpoint_data, raw_data = get_endpoint_by_id(endpoint_id)
    # endpoint = {'Name': endpoint_data.get('name'),
    #             'Data': createContext(endpoint_data, keyTransform=string_to_context_key())}
    md = tableToMarkdown(f'Endpoint {endpoint_id} data:', endpoint_data, headerTransform=pascalToSpace)
    context = {'Traps.Endpoint(val.Data.ID == obj.Data.ID)': createContext(endpoint_data)}
    return_outputs(md, context, raw_response=raw_data)


def endpoint_files_retrieve_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    endpoint_files_retrieve(endpoint_id)


# def traps_endpoint_isolate_command():


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module_command()
        demisto.results('ok')
    elif demisto.command() == 'traps-get-endpoint-by-id':
        get_endpoint_by_id_command()
    elif demisto.command() == 'traps-endpoint-files-retrieve':
        endpoint_files_retrieve_command()
    # elif demisto.command() == 'traps-endpoint-isolate':
    #     traps_endpoint_isolate_command()

# Log exceptions
except Exception as e:
    LOG(e)
    LOG.print_log()
