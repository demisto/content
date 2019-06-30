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

SERVICE_PRINCIPAL = demisto.params().get('credentials').get('identifier')
SECRET = demisto.params().get('credentials').get('password')

# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
API_VERSION = demisto.params().get('api_version')
BASE_URL = SERVER + '/' + API_VERSION + '/siem'


VERIFY_CERTIFICATE = not demisto.params().get('insecure', False)

# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')

THREAT_STATUS = argToList(demisto.params().get('threat_status'))

THREAT_TYPE = argToList(demisto.params().get('threat_type'))

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    full_url = BASE_URL + url_suffix

    res = requests.request(
        method,
        full_url,
        verify=VERIFY_CERTIFICATE,
        params=params,
        json=data,
        auth=(SERVICE_PRINCIPAL, SECRET)
    )

    if res.status_code not in [200, 204]:
        raise ValueError('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

    try:
        return res.json()
    except:
        raise ValueError("Failed to parse http response to JSON format. Original response body: \n{}".format(res.text))


def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = get_events()

    # test was successful
    demisto.results('ok')


def get_events(interval=None, since_time=None, since_seconds=None, threat_type=None, threat_status=None,
               event_type_filter=None):

    if not interval and not since_time and not since_seconds:
        raise ValueError("Required to pass interval or sinceTime or sinceSeconds.")

    query_params = {}
    if interval:
        query_params["interval"] = interval

    if since_time:
        query_params["sinceTime"] = since_time

    if since_seconds:
        query_params["sinceSeconds"] = since_seconds

    if threat_status:
        query_params["threatStatus"] = threat_status

    if threat_type:
        query_params["threatType"] = threat_type

    url_route = {
        "All": "/all",
        "Issues": "/issues",
        "Blocked Clicks": "/clicks/blocked",
        "Permitted Clicks": "/clicks/permitted",
        "Blocked Messages": "/messages/blocked",
        "Delivered Messages": "/messages/delivered"
    }[event_type_filter]

    events = http_request("GET", url_route, params=query_params)

    return events


def get_events_command():
    interval = demisto.args().get("interval")
    threat_type = argToList(demisto.args().get("threatType"))
    threat_status = demisto.args().get("threatStatus")
    since_time = demisto.args().get("sinceTime")
    since_seconds = demisto.args().get("sinceSeconds")
    event_type_filter = demisto.args().get("eventTypes")

    raw_events = get_events(interval, since_time, since_seconds, threat_type, threat_status, event_type_filter)

    return_outputs(
        readable_output=tableToMarkdown("Proofpoint Events", raw_events),
        outputs={
            'Proofpoint.MessagesDelivered': raw_events.get("messagesDelivered"),
            'Proofpoint.MessagesBlocked': raw_events.get("messagesBlocked"),
            'Proofpoint.ClicksBlocked': raw_events.get("clicksBlocked"),
            'Proofpoint.ClicksPermitted': raw_events.get("clicksPermitted")
        },
        raw_response=raw_events
    )


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        # date format 2016-05-01T12:00:00Z
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format="%Y-%m-%dT%H:%M:%SZ", utc=True)

    incidents = []
    raw_events = get_events()

    for raw_event in raw_events.get("clicksBlocked", []):
        """
        var event = events.messagesDelivered[i];
        event.type = 'messages delivered';
        var incident = {
            name: 'Proofpoint - Message Delivered - ' + event.GUID,
            rawJSON: JSON.stringify(event)
        };
        """
        raw_event["type"] = "clicks blocked"
        event_guid = raw_events.get("GUID", "")
        incident = {
            "name": "Proofpoint - Message Delivered - {}".format(event_guid),
            "rawJSON": json.dumps(raw_event)
        }



    demisto.setLastRun({'last_fetch': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'proofpoint-get-events':
        get_events_command()

# Log exceptions
except Exception as e:
    return_error(str(e))
