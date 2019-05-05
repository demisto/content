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
SERVER = (demisto.params()['url'][:-1]
          if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url'])
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time').strip()
# Service base URL
BASE_URL = SERVER + '/api/v1'
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}


''' HELPER FUNCTIONS '''


def http_request(method, path, params=None, data=None):
    """
    Sends an HTTP request using the provided arguments
    :param method: HTTP method
    :param path: URL path
    :param params: URL query params
    :param data: Request body
    :return: JSON response
    """
    params = params if params is not None else {}
    data = data if data is not None else {}
    res = None

    try:
        res = requests.request(
            method,
            BASE_URL + path,
            auth=(USERNAME, PASSWORD),
            verify=USE_SSL,
            params=params,
            data=json.dumps(data, sort_keys=True),
            headers=HEADERS)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects, requests.exceptions.RequestException) as e:
        return_error('Could not connect to PhishLabs IOC Feed: {}'.format(str(e)))

    if res.status_code < 200 or res.status_code > 300:
        status = res.status_code
        message = res.reason
        details = ''
        try:
            error_json = res.json()
            message = error_json.get('statusMessage')
            details = error_json.get('message')
        except Exception:
            pass
        return_error('Error in API call to PhishLabs IOC API, status code: {}, reason: {}, details: {}'
                     .format(status, message, details))

    try:
        return res.json()
    except Exception:
        return_error('Failed parsing the response from PhishLabs IOC API: {}'.format(res.content))


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


def get_global_feed_command():
    """
    Gets the global feed data using the provided arguments
    """
    indicator_headers = ['ID', 'Indicator', 'CreatedAt', 'FalsePositive']
    attribute_headers = ['Name', 'Value', 'CreatedAt']
    contents = []
    context = {}
    indicator_type = ''
    since = demisto.args().get('since')
    limit = demisto.args().get('limit')
    indicator = demisto.args().get('indicator_type')
    offset = demisto.args().get('offset')
    remove_protocol = demisto.args().get('remove_protocol')
    remove_query = demisto.args().get('remove_query')

    feed = get_global_feed_request(since, limit, indicator, offset, remove_protocol, remove_query)
    if feed and feed.get('data'):
        results = feed['data']
        if limit:
            results = results[:limit]
        title = 'Example - Getting Items Details'

        for result in results:
            contents.append({
                'ID': result.get('id'),
                'Indicator': result.get('description'),
                'CreatedAt': result.get('name'),
                'FalsePositive': result.get('createdDate')
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


def get_global_feed_request(since, limit, indicator, offset, remove_protocol, remove_query):
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
    items = get_global_feed_request()
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
handle_proxy()
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
        get_global_feed_command()

# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
