from distutils.util import strtobool
from typing import Dict

import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = None
# # Remove trailing slash to prevent wrong URL path to service
# SERVER = demisto.params()['url'][:-1] \
#     if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = 'https://api.zerofox.com/1.0' # disable-secrets-detection
# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Token {}'.format(TOKEN),
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


def get_authorization_token():
    context: Dict = demisto.getIntegrationContext()
    # if context is a dict so it must have a token inside - because token is the first thing added to the context
    if isinstance(context, Dict):
        return
    endpoint: str = '/api-token-auth/'
    demisto.info(USERNAME)
    demisto.info(PASSWORD)
    data_for_request: Dict = {
        'username': USERNAME,
        'password': PASSWORD
    }
    request_response = http_request('POST', endpoint, data=data_for_request, headers=None)
    global TOKEN
    TOKEN = request_response.get('token')
    demisto.setIntegrationContext({'auth_token': TOKEN})

def http_request(method: str, url_suffix: str, params: Dict = None, data: Dict = None, headers: Dict = HEADERS):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        err_msg: str = f'Error in ZeroFox Integration API call [{res.status_code}] -ggg {res.reason}\n'
        try:
            res_json = res.json()
            if 'error' in res_json:
                err_msg += res_json.get('error')
            else:
                err_msg += res_json
        except ValueError:
            pass
        finally:
            return_error(err_msg)
    else:
        try:
            res_json = res.json()
            return res_json
        except ValueError:
            return 'Success Message'


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

def close_alert(args={}):
    alert_id: int = args.get('alert_id')
    endpoint: str = f'/alerts/{alert_id}/close/'
    response_content = http_request('POST', endpoint)
    return response_content


def close_alert_command():
    args = demisto.args()
    response_content = close_alert(args) # ???
    alert_id: int = demisto.args('alert_id')
    success_msg: str = f'Alert: {alert_id} has been closed successfully.'
    demisto.results(success_msg)


def alert_request_takedown(args={}):
    alert_id: int = args.get('alert_id')
    endpoint: str = f'/alerts/{alert_id}/request_takedown/'
    response_content = http_request('POST', endpoint)
    return response_content

def alert_request_takedown_command():
    args = demisto.args()
    response_content = close_alert(args)
    alert_id: int = demisto.args('alert_id')
    success_msg: str = f'Alert: {alert_id} has been taken down successfully.'
    demisto.results(success_msg)


def alert_user_assignment(args={}):
    alert_id: int = args.get('alert_id')
    endpoint: str = f'/alerts/{alert_id}/assign/'
    subject_email: str = args.get('subject_email')
    subject_name: str = args.get('subject_name')
    request_body: Dict = {
        'subject_email': subject_email,
        'subject': subject_name
    }
    response_content = http_request('POST', endpoint, data=request_body)
    return response_content

def alert_user_assignment_command():
    args = demisto.args()
    response_content = alert_user_assignment(args)
    alert_id: int = demisto.args('alert_id')
    subject_name: str = demisto.args('subject_name')
    success_msg: str = f'User: {subject_name} has been assigned to Alert: {alert_id} successfully.'
    demisto.results(success_msg)


def modify_alert_tags(args={}):
    endpoint: str = '/alerttagchangeset/'
    alert_id: int = args.get('alert_id')
    addition: bool = args.get('addition')
    tags_list_name: str = 'added' if addition else 'removed'
    tags_list: list = args.get('tags').split(',')
    request_body: Dict = {
        'changes': [
            {
                f'{tags_list_name}': tags_list,
                'alert': alert_id
            }
        ]
    }
    response_content = http_request('POST', endpoint, data=request_body)
    return response_content

def modify_alert_tags_command():
    args = demisto.args()
    response_content = modify_alert_tags(args)
    alert_tags_changeset_id: str = response_content.get('uuid')
    human_readable: str = 'Changes were successfully made.'
    outputs: Dict = {'ZeroFox.Alert.ChangeUUID': alert_tags_changeset_id}
    return_outputs(human_readable, outputs, response_content)


def get_alert(args={}):
    alert_id: int = args.get('alert_id')
    endpoint: str = f'/alerts/{alert_id}/'
    response_content = http_request('GET', endpoint)
    return response_content

def get_alert_command():
    args = demisto.args()
    response_content = get_alert(args)
    # TODO.



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

''' EXECUTION '''

def main():
    LOG('Command being called is %s' % (demisto.command()))
    try:
        demisto.info(USERNAME)
        demisto.info(PASSWORD)
        get_authorization_token()
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
        elif demisto.command() == 'zerofox-get-alert':
            get_alert_command()
        elif demisto.command() == 'zerofox-alert-user-assignment':
            alert_user_assignment_command()
        elif demisto.command() == 'zerofox-close-alert':
            close_alert_command()

    # Log exceptions
    except Exception as e:
        LOG(e.message)
        LOG.print_log()
        raise

# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
