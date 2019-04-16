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

BASE_URL = "https://www.googleapis.com/bigquery/v2/"
QUERY_URL = "projects/{0}/queries"


USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('unsecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/v2.0/'
# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Token ' + TOKEN + ':' + USERNAME + PASSWORD,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''

def represents_int(string_var):
    if '.' in string_var:
        return False
    if string_var[0] in ('-', '+'):
        return string_var[1:].isdigit()
    return string_var.isdigit()

def represents_bool(string_var):
    return string_var.lower() == 'false' or string_var.lower() == 'true'


def validate_args_for_query_request(max_results, timeout_ms, dry_run, use_query_cache, use_legacy_sql, parameter_mode):
    if not represents_int(max_results):
        return_error("Error: max_results must have an integer value.")
    if not represents_int(timeout_ms):
        return_error("Error: timeout_ms must have an integer value.")
    if not represents_bool(dry_run):
        return_error("Error: dry_run must have a boolean value.")
    if not represents_bool(use_query_cache):
        return_error("Error: use_query_cache must have a boolean value.")
    if not represents_bool(use_legacy_sql):
        return_error("Error: use_legacy_sql must have a boolean value.")
    if not (parameter_mode.lower() == 'positional' or parameter_mode.lower() == 'named'):
        return_error("Error: parameter_mode must have a value of 'positional' or 'named'.")


def build_default_dataset_data_dict(default_dataset_json_arg):
    default_dataset_data_dict = {
        'datasetId': default_dataset_json_arg['dataset_id']
    }
    if 'project_id' in default_dataset_json_arg:
        default_dataset_data_dict['projectId'] = default_dataset_json_arg['project_id']
    return default_dataset_data_dict


def build_parameter_type_data(parameter_type_data):




def build_param_data_dict(param_data):
    param_data_dict = {
        'name': param_data.get('name', None),
        'parameterType': build_parameter_type_data(param_data.get('parameter_type'))

    }
    return param_data_dict


def build_query_parameters_data(query_parameters):
    query_params_data = []
    for param in query_parameters:
        param_data = build_param_data_dict(param)
        query_params_data.append(param_data)
    return query_params_data


def build_query_request_data(query, max_results, default_dataset, timeout_ms, dry_run, use_query_cache, use_legacy_sql, parameter_mode, query_parameters, location):
    # currently treating parameterMode as optional
    validate_args_for_query_request(max_results, timeout_ms, dry_run, use_query_cache, use_legacy_sql, parameter_mode)
    data_for_query_request = {
        "kind": "bigquery#queryRequest",
        'query': query,
        # if max_results is None does bool(dry_run) get computed before? I don't think so
        'maxResults': int(max_results) if max_results else None,
        'defaultDataset': build_default_dataset_data_dict(default_dataset) if default_dataset else None,
        'timeoutMs': int(timeout_ms) if timeout_ms else None,
        'dryRun': bool(dry_run) if dry_run else None,
        'useQueryCache': bool(use_query_cache) if use_query_cache else None,
        'useLegacySql': bool(use_legacy_sql) if use_legacy_sql else None,
        'queryParameters': build_query_parameters_data(query_parameters) if query_parameters else None,
        'location': location,
    }

    if parameter_mode:
        data_for_query_request['parameterMode'] = 'POSITIONAL' if (parameter_mode.lower() == 'positional') else 'NAMED';

    data_for_query_request = {key: value for key, value in data_for_query_request.items() if value is not None}
    return data_for_query_request



def http_request(method, url_suffix, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

    return res.json()


def item_to_incident(item):
    incident = {}
    # Incident Title
    incident['name'] = 'Example Incident: ' + item.get('name')
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

    demisto.setLastRun({'time' : last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

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
except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise
