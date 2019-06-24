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

# Remove trailing slash to prevent wrong URL path to service
API_URL = demisto.params()['url'].rstrip('/')

# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

THRESHOLD = demisto.params().get('threshold')

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
}


''' HELPER FUNCTIONS '''


def http_request(method, command, data=None):
    url = f'{API_URL}/{command}/'
    demisto.info(f'{method} {url}')
    res = requests.request(method,
                           url,
                           verify=USE_SSL,
                           data=data,
                           headers=HEADERS)

    if res.status_code != 200:
        raise Exception(f'Error in API call {url} [{res.status_code}] - {res.reason}')

    return res


def query_url_information(url):
    return http_request('POST',
                         'https://urlhaus-api.abuse.ch/v1/url/',  # disable-secrets-detection
                        f'url={url}')


def query_host_information(host):
    return http_request('POST',
                                'https://urlhaus-api.abuse.ch/v1/host/',  # disable-secrets-detection
                        f'host={host}')


def query_payload_information(hash_type, hash):
    return http_request('POST',
                                'https://urlhaus-api.abuse.ch/v1/payload/',  # disable-secrets-detection
                        f'{hash_type}_hash={hash}')


def query_tag_information(tag):
    return http_request('POST',
                                'https://urlhaus-api.abuse.ch/v1/tag/',  # disable-secrets-detection
                        f'tag={tag}')


def query_signature_information(signature):
    return http_request('POST',
                                'https://urlhaus-api.abuse.ch/v1/signature/',  # disable-secrets-detection
                        f'signature={signature}')

def download_malware_sample(sha256, dest):
    res = requests.get(f'https://urlhaus-api.abuse.ch/v1/download/{sha256}/')# disable-secrets-detection
    with open(dest, 'wb') as malware_sample:
        malware_sample.write(res.content)



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
    http_request('POST', 'url')


# def get_items_command():
#     """
#     Gets details about a items using IDs or some other filters
#     """
#     # Init main vars
#     headers = []
#     contents = []
#     context = {}
#     context_entries = []
#     title = ''
#     # Get arguments from user
#     item_ids = argToList(demisto.args().get('item_ids', []))
#     is_active = bool(strtobool(demisto.args().get('is_active', 'false')))
#     limit = int(demisto.args().get('limit', 10))
#     # Make request and get raw response
#     items = get_items_request(item_ids, is_active)
#     # Parse response into context & content entries
#     if items:
#         if limit:
#             items = items[:limit]
#         title = 'Example - Getting Items Details'
#
#         for item in items:
#             contents.append({
#                 'ID': item.get('id'),
#                 'Description': item.get('description'),
#                 'Name': item.get('name'),
#                 'Created Date': item.get('createdDate')
#             })
#             context_entries.append({
#                 'ID': item.get('id'),
#                 'Description': item.get('description'),
#                 'Name': item.get('name'),
#                 'CreatedDate': item.get('createdDate')
#             })
#
#         context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries
#
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': contents,
#         'ReadableContentsFormat': formats['markdown'],
#         'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
#         'EntryContext': context
#     })
#
#
# def get_items_request(item_ids, is_active):
#     # The service endpoint to request from
#     endpoint_url = 'items'
#     # Dictionary of params for the request
#     params = {
#         'ids': item_ids,
#         'isActive': is_active
#     }
#     # Send a request using our http_request wrapper
#     response = http_request('GET', endpoint_url, params)
#     # Check if response contains errors
#     if response.get('errors'):
#         return_error(response.get('errors'))
#     # Check if response contains any data to parse
#     if 'data' in response:
#         return response.get('data')
#     # If neither was found, return back empty results
#     return {}
#
#
# def fetch_incidents():
#     last_run = demisto.getLastRun()
#     # Get the last fetch time, if exists
#     last_fetch = last_run.get('time')
#
#     # Handle first time fetch, fetch incidents retroactively
#     if last_fetch is None:
#         last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)
#
#     incidents = []
#     items = get_items_request()
#     for item in items:
#         incident = item_to_incident(item)
#         incident_date = date_to_timestamp(incident['occurred'], '%Y-%m-%dT%H:%M:%S.%fZ')
#         # Update last run and add incident if the incident is newer than last fetch
#         if incident_date > last_fetch:
#             last_fetch = incident_date
#             incidents.append(incident)
#
#     demisto.setLastRun({'time' : last_fetch})
#     demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

#print(query_url_information('http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/'))
#print(query_host_information('vektorex.com'))
#print(query_payload_information('md5', '12c8aec5766ac3e6f26f2505e2f4a8f2'))
#print(query_tag_information('Retefe'))
#print(query_signature_information('Gozi'))
#print(download_malware_sample('254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b', 'here.zip'))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
