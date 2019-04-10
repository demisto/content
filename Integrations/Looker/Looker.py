import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
SESSION_VALIDITY_THRESHOLD = timedelta(minutes=5)
CLIENT_ID = demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('client_secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) \
    else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('unsecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/api/3.0/'
# Request headers (preparation)
HEADERS = {}

handle_proxy()


''' HELPER FUNCTIONS '''


def verify_url(url):
    # validate url parameter format, extract port
    try:
        server, port = url.rsplit(':', 1)
        assert 0 < int(port) < 65536

    except (ValueError, AssertionError):
        return_error("Incorrect URL format. Use the following format: https://example.looker.com:19999\n"
                     "The default port for Looker API is 19999.")


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
        raise requests.exceptions.HTTPError('Error in API call to Looker [%d] - %s' % (res.status_code, res.reason))

    return res.json()


def get_new_token():
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response_json = http_request('POST', 'login', data=data)

    return {
        'token': response_json['access_token'],
        'expires': datetime.utcnow() + timedelta(seconds=int(response_json['expires_in']))
    }


def get_session_token():
    global HEADERS
    ic = demisto.getIntegrationContext()
    if CLIENT_ID not in ic or 'expires' not in ic[CLIENT_ID] \
            or ic[CLIENT_ID]['expires'] + SESSION_VALIDITY_THRESHOLD > datetime.utcnow():
        ic[CLIENT_ID] = get_new_token()
    if demisto.command() != 'test-module':
        demisto.setIntegrationContext(ic)

    HEADERS['Authorization'] = 'token {}'.format(ic[CLIENT_ID]['token'])


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to check connectivity and authentication
    """
    http_request('GET', 'user')


def run_query_command():
    # Get arguments from user
    query_id = demisto.args()['query_id']
    result_format = demisto.args()['result_format']
    limit = int(demisto.args().get('limit', 10))
    # Make request and get raw response
    contents = run_query_request(query_id, result_format)
    # Parse response into context & content entries
    context = {
        'Looker.Query(val.ID && val.ID === obj.ID)': {
            'ID': query_id,
            'Results': contents
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Results for query #{query_id}', contents, removeNull=True),
        'EntryContext': context
    })


def run_query_request(query_id, result_format):
    # The service endpoint to request from
    endpoint_url = f'/queries/{query_id}/run/{result_format}'
    # Send a request using our http_request wrapper
    return http_request('GET', endpoint_url)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))
verify_url(SERVER)
try:
    get_session_token()
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'looker-run-query':
        # An example command
        run_query_command()

# Log exceptions
except Exception as e:
    LOG(e)
    LOG(traceback.format_exc())
    LOG.print_log()
    raise
