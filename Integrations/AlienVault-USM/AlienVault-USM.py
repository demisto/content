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

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
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


''' HELPER FUNCTIONS '''


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

    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    handle_proxy()
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
    LOG(e.message)
    LOG.print_log()
    raise


# ''' IMPORTS '''
# import requests
#
# import demistomock as demisto
# from CommonServerPython import *
#
# ''' GLOBAL VARS '''
# CLIENT_ID = demisto.params().get('clientid')
# SECRET = demisto.params().get('secret')
# HOST = demisto.params().get('host')
#
#
# API_VERSION = '2.0'
# URL = HOST + '/api/' + API_VERSION
#
#
# def get_token():
#     basicauth_credentials = (CLIENT_ID, SECRET)
#
#     try:
#         response = requests.post(URL + '/oauth/token?grant_type=client_credentials',
#                                  params={'grant_type': 'client_credentials'},
#                                  auth=basicauth_credentials)
#     except Exception:
#         raise Exception('request failed')
#
#     if response.status_code == 200:
#         res = json.loads(response.text)
#         return res['access_token']
#
#
# def parse_alarm(alarm_data):
#     return {
#         'Alarm.ID': alarm_data['uuid'],
#         'Alarm.Priority': alarm_data['priority_label'],
#         'Alarm.DestinationAsset': alarm_data['destinations'][0]['address'],
#         'Alarm.RuleAttackId': alarm_data['rule_attack_id'],
#         'Alarm.RuleAttackTactic': alarm_data['rule_attack_tactic'][0],
#         'Alarm.RuleAttackTechnique': alarm_data['rule_attack_technique'],
#         "Alarm.Sensor": alarm_data['events'][0]['received_from'],
#         'Alarm.Source.IpAddress': alarm_data['destinations'][0]['address'],
#         'Alarm.Source.Organization': alarm_data['sources'][0]['organisation'],
#         'Alarm.Source.Country': alarm_data['sources'][0]['country'],
#         'Alarm.Destination.IpAddress': alarm_data['destinations'][0]['address'],
#         'Alarm.Destination.FQDN': alarm_data['destinations'][0]['fqdn']
#     }
#
#
# def parse_alarms(alarms_data):
#     alarms = []
#     for alarm in alarms_data['_embedded']['alarms']:
#         tmp = {
#             'Alarm.ID': alarm['uuid'],
#             'Alarm.Priority': alarm['priority_label'],
#             'Alarm.DestinationAsset': alarm['events'][0]['message']['destination_address'],
#             'Alarm.RuleAttackId': alarm['rule_attack_id'],
#             'Alarm.RuleAttackTactic': alarm['rule_attack_tactic'][0],
#             'Alarm.RuleAttackTechnique': alarm['rule_attack_technique'],
#             "Alarm.Sensor": alarm['events'][0]['message']['received_from'],
#             'Alarm.Source.IpAddress': alarm['events'][0]['message']['source_address'],
#             'Alarm.Source.Organization': alarm['events'][0]['message']['source_organisation'],
#             'Alarm.Source.Country': alarm['events'][0]['message']['source_country'],
#             'Alarm.Destination.IpAddress': alarm['events'][0]['message']['destination_address'],
#             'Alarm.Destination.FQDN': alarm['events'][0]['message']['destination_fqdn'],
#         }
#         alarms.append(tmp)
#
#     return alarms
#
#
# def get_alarm_by_id(alarm_id):
#     auth_token = get_token()
#     hed = {'Authorization': 'Bearer ' + auth_token}
#     url = URL + '/alarms/' + alarm_id
#
#     try:
#         response = requests.get(url, headers=hed)
#     except Exception:
#         raise Exception('request failed')
#
#     if response.status_code == 401:
#         raise Exception('invalid token')
#
#     if response.status_code == 404:
#         raise Exception('alarm could not be found')
#
#     if response.status_code == 200:
#         res = json.loads(response.text)
#
#         alarm_context = parse_alarm(res)
#
#         print alarm_context
#     return alarm_context
#
#
# def get_alarms():
#     auth_token = get_token()
#     hed = {'Authorization': 'Bearer ' + auth_token}
#     url = URL + '/alarms/'
#
#     try:
#         response = requests.get(url, headers=hed)
#     except Exception:
#         raise Exception('request failed')
#
#     if response.status_code == 401:
#         raise Exception('invalid token')
#
#     if response.status_code == 404:
#         raise Exception('alarm could not be found')
#
#     if response.status_code == 200:
#         res = json.loads(response.text)
#
#         alarm_context = parse_alarms(res)
#
#         print alarm_context
#     return alarm_context
#
#
# get_alarm_by_id('d8689007-30b1-ae32-f4b2-f5f2b553ac14')
# get_alarms()
#
# sys.exit(0)