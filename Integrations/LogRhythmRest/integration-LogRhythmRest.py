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


TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
BASE_URL = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']

# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')

# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Bearer ' + TOKEN
}


''' HELPER FUNCTIONS '''

def fix_template(template, data):
    for key in data:
        template = template.replace('{{' + key + '}}', data[key])
    return template

def http_request(method, url_suffix, data=None):

    res = requests.request(
        method,
        BASE_URL + '/' + url_suffix,
        headers = HEADERS,
        verify=False,
        data=data
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        raise Exception('Error in API call to {}, status code: {}, reason: {}'.format(BASE_URL + '/' + url_suffix, res.status_code, res.json()['message']))

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
    hosts = http_request('GET', 'lr-admin-api/hosts?entity=Primary Site')
    return hosts

def add_host(dataArgs):

    template = '{' + \
    '	"entity": {' + \
    '		"id": {{entity_id}},' + \
    '		"name": "{{entity_name}}"' + \
    '	},' +  \
    '	"name": "{{name}}",' + \
    '	"shortDesc": "{{short-desc}}",' +  \
    '	"longDesc": "{{long-desc}}",' +  \
    '	"riskLevel": "{{risk-level}}",' +  \
    '	"threatLevel": "{{threat-level}}",' + \
    '	"threatLevelComments": "{{threat-level-comments}}",' + \
    '	"recordStatusName": "{{record-status-name}}",' +  \
    '	"hostZone": "{{host-zone}}",' +  \
    '	"os": "{{os}}",' +  \
    '	"useEventlogCredentials": {{use-eventlog-credentials}},' + \
    '	"osType": "{{os-type}}"' +  \
    '}'

    data = fix_template(template, dataArgs)

    res = http_request('POST', 'lr-admin-api/hosts/',data)
    return res

def get_hosts(dataArgs):
    res = http_request('GET', 'lr-admin-api/hosts?entity=' + dataArgs['entity_name'])

    context = {}
    context['Logrhythm.Hosts(val.Name && val.Name === obj.Name)'] = res
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Hosts', res),
        'EntryContext': context
    })

    return res

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
    elif demisto.command() == 'add-host':
        add_host(demisto.args())
        demisto.results('ok')
    elif demisto.command() == 'get-hosts-by-entity':
        get_hosts(demisto.args())
        demisto.results('ok')
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
except Exception, e:
    raise
