import json
import time

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()

baseURL = demisto.params()['url']
apiKey = demisto.params()['apikey']
applicationKey = demisto.params()['applicationkey']
HEADERS = {
    "Accept": "application/json",
    "DD-API-KEY": apiKey,
    "DD-APPLICATION-KEY": applicationKey
}

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

VERIFY = True
if demisto.params()['insecure']:
    VERIFY = False


def http_request(method, url_suffix, params=None, DATA=None):
    res = requests.request(method, baseURL + url_suffix, params=params, headers=HEADERS, data=DATA, verify=VERIFY)
    if res.status_code >= 400:
        try:
            json_res = res.json()
            if json_res.get('errors') is None:
                return_error('Error in API call to the DataDog Integration [%d] - %s' % (res.status_code, res.reason))
            else:
                error_code = json_res.get('errors')[0]
                return_error('Error: {}'.format(error_code))
        except ValueError:
            return_error('Error in API call to DataDog Integration [%d] - %s' % (res.status_code, res.reason))
    if res.status_code == 204:
        return res
    else:
        try:
            json_res = res.json()
        except Exception as e:
            return_error("Unable to parse result - " + str(e))
        return res.json()


def get_event():
    PARAMS = demisto.args()
    res = http_request('GET', '/api/v1/events', params=PARAMS)
    if res.get('events'):
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'EntryContext': {'dataDog.events': res['events']},
            'Contents': res['events'],
            'HumanReadable': tableToMarkdown("Events", res['events'], ["id", "title", "alert_type", "date_happened", "priority", "url"])})
    else:
        demisto.results("No events returned")


def get_single_event():
    res = http_request('GET', '/api/v1/events/' + str(demisto.args()['id']))
    if res.get('event'):
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'EntryContext': {'dataDog.event': res['event']},
            'Contents': res['event'],
            'HumanReadable': tableToMarkdown("Details of Event ID: " + str(demisto.args()['id']), res['event'], ["id", "title", "alert_type", "date_happened", "priority", "url"])})
    else:
        demisto.results("No event with id %s found" % (str(demisto.args()['id'])))


def get_incidents():
    res = http_request('GET', '/api/v2/incidents')
    if res.get('data'):
        incidentList = []
        incidentDetails = {}
        for items in res['data']:
            incidentDetails = flattenRow(items['attributes'])
            incidentDetails['id'] = items['id']
            incidentDetails['type'] = items['type']
            incidentList.append(incidentDetails)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'EntryContext': {'dataDog.incidents': incidentList},
            'Contents': incidentList,
            'HumanReadable': tableToMarkdown("Incidents", incidentList, ["id", "title", "created", "severity", "state"])})
    else:
        demisto.results("No incidents returned")


def get_single_incident():
    res = http_request('GET', '/api/v2/incidents/' + str(demisto.args()['id']))
    if res.get('data'):
        incidentDetails = {}
        incidentDetails = flattenRow(res['data']['attributes'])
        incidentDetails['id'] = res['data']['id']
        incidentDetails['type'] = res['data']['type']
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'EntryContext': {'dataDog.incident': incidentDetails},
            'Contents': incidentDetails,
            'HumanReadable': tableToMarkdown("Details of Incident ID: " + str(demisto.args()['id']), incidentDetails, ["id", "title", "created", "severity", "state"])})
    else:
        demisto.results("No incidents with id %s found" % (str(demisto.args()['id'])))


def list_hosts():
    PARAMS = demisto.args()
    res = http_request('GET', '/api/v1/hosts', params=PARAMS)
    if res.get('host_list'):
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'EntryContext': {'dataDog.hosts': res['host_list']},
            'Contents': res['host_list'],
            'HumanReadable': tableToMarkdown("List of Hosts", res['host_list'], ["id", "name", "host_name"])})
    else:
        demisto.results("No events returned")


def list_host_action(action):
    if action == 'mute':
        # If the end time is in the past no error is returned and the host is not muted. Results returned are the same.
        data = {
            "message": str(demisto.args()['message']),
            "end": int(demisto.args()['end'])
        }
        res = http_request('POST', '/api/v1/host/' + str(demisto.args()['hostname']) + '/mute', DATA=data)
    else:
        res = http_request('POST', '/api/v1/host/' + str(demisto.args()['hostname']) + '/unmute')
    if res.get('action'):
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'HumanReadable': tableToMarkdown("Action Result", res)})
    else:
        demisto.results("No hosts affected")


def get_users():
    if demisto.args():
        PARAMS = demisto.args()
    else:
        PARAMS = None
    res = http_request('GET', '/api/v2/users', params=PARAMS)
    if res.get('data'):
        userList = []
        userDetails = {}
        for items in res['data']:
            userDetails = flattenRow(items['attributes'])
            userDetails['id'] = items['id']
            userDetails['type'] = items['type']
            userList.append(userDetails)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'EntryContext': {'dataDog.users': userList},
            'Contents': userList,
            'HumanReadable': tableToMarkdown("Users", userList, ["id", "name", "email", "status"])})
    else:
        demisto.results("No users returned")


def list_active_metrics():
    PARAMS = demisto.args()
    res = http_request('GET', '/api/v1/metrics', params=PARAMS)
    if res.get('metrics'):
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res['metrics'],
            'HumanReadable': tableToMarkdown("Metrics", res['metrics'], ["Metrics"])})
    else:
        demisto.results("No metrics returned")


def submit_metics():
    data = {
        "series": [{
            "host": str(demisto.args()['host']),
            "interval": int(demisto.args()['interval']),
            "type": str(demisto.args()['type']),
            "metric": str(demisto.args()['metric']),
            "points": [[str(demisto.args()['pointTimeStamp']), str(demisto.args()['pointValue'])]]
        }]
    }
    res = http_request('POST', '/api/v1/series', DATA=json.dumps(data))
    if res.get("status"):
        if res['status'] == "ok":
            demisto.results("Metrics updated successfully")
        else:
            demisto.results("Metrics update failed")


def fetch_incidents():
    now = round(time.time())
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        # if this is the first run, fetch events for the last 3 hours
        startTime = now - 10800
    else:
        startTime = last_fetch
    latest_created_time = startTime
    PARAMS = {
        "start": str(startTime),
        "end": str(now),
        "priority": demisto.params()['incidentPriority'],
        "unaggregated": True
    }
    res = http_request('GET', '/api/v1/events', params=PARAMS)
    if res.get('events'):
        incidents = []
        for event in res['events']:
            incident_created_time = int(event.get('date_happened', '0'))
            incident_created_time_ms = incident_created_time * 1000
            incident = {
                "name": event['title'],
                "occurred": timestamp_to_datestring(incident_created_time_ms),
                "rawJSON": json.dumps(event)
            }
            if incident_created_time > latest_created_time:
                incidents.append(incident)
                latest_created_time = incident_created_time
        next_run = {'last_fetch': latest_created_time}
        return next_run, incidents
    else:
        next_run = {'last_fetch': startTime}
        return next_run, []


def test_module():
    try:
        http_request('GET', '/api/v1/validate')
    except Exception as e:
        demisto.results('API Call failed - ' + str(e))
    demisto.results('ok')


# Main functions
if demisto.command() == 'test-module':
    test_module()
elif demisto.command() == 'dd-get-events':
    get_event()
elif demisto.command() == 'dd-get-event-id':
    get_single_event()
elif demisto.command() == 'dd-get-incidents':
    get_incidents()
elif demisto.command() == 'dd-get-incident-id':
    get_single_incident()
elif demisto.command() == 'dd-list-hosts':
    list_hosts()
elif demisto.command() == 'dd-mute-host':
    list_host_action("mute")
elif demisto.command() == 'dd-unmute-host':
    list_host_action("unmmute")
elif demisto.command() == 'dd-get-users':
    get_users()
elif demisto.command() == 'dd-get-active-metrics-list':
    list_active_metrics()
elif demisto.command() == 'dd-submit-metics':
    submit_metics()
elif demisto.command() == 'fetch-incidents':
    next_run, incidents = fetch_incidents()
    demisto.setLastRun(next_run)
    demisto.incidents(incidents)
