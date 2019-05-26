import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import random
import string
from datetime import datetime, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
BASE_URL = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) \
    else demisto.params()['url']

CLUSTER_ID = demisto.params().get('cluster-id')

# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Bearer ' + TOKEN
}

HOSTS_HEADERS = ["id", "name", "entity", "os", "hostStatus", "location", "riskLevel", "threatLevel", "dateUpdated",
                 "hostZone"]
LOGS_HEASERS = ["Level", "Computer", "Channel", "Keywords", "EventData"]

''' HELPER FUNCTIONS '''


def fix_hosts_response(hosts):
    for item in hosts:
        location_val = str(item.get('location'))
        if location_val == '{u\'id\': -1}':
            item['location'] = 'NA'

        item['hostStatus'] = item.pop('recordStatusName')
    return hosts


def get_time_frame(time_frame, start_arg, end_arg):
    start = datetime.now()
    end = datetime.now()

    if time_frame == 'Today':
        start = datetime(end.year, end.month, end.day)
    elif time_frame == 'Last2Days':
        start = end - timedelta(days=2)
    elif time_frame == 'LastWeek':
        start = end - timedelta(days=7)
    elif time_frame == 'LastMonth':
        start = end - timedelta(days=30)
    elif time_frame == 'Custom':
        if not start_arg:
            return_error('start-date argument is missing')
        if not end_arg:
            return_error('end-date argument is missing')
        start = datetime.strptime(start_arg, '%Y-%m-%d')
        end = datetime.strptime(end_arg, '%Y-%m-%d')

    return start, end


def http_request(method, url_suffix, data=None, headers=HEADERS):
    try:
        res = requests.request(
            method,
            BASE_URL + '/' + url_suffix,
            headers=headers,
            verify=False,
            data=data
        )
    except Exception as e:
        return_error(e)

    # Handle error responses gracefully
    if res.headers['Content-Type'] != 'application/json':
        return_error('invalid url or port: ' + BASE_URL)

    if res.status_code not in {200, 201, 207}:
        return_error(
            'Error in API call to {}, status code: {}, reason: {}'.format(BASE_URL + '/' + url_suffix, res.status_code,
                                                                          res.json()['message']))

    return res.json()


def get_host_by_id(host_id):
    res = http_request('GET', 'lr-admin-api/hosts/' + host_id)
    return fix_hosts_response([res])


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    http_request('GET', 'lr-admin-api/hosts')
    demisto.results('ok')


def add_host(dataArgs):
    data = {
        "id": -1,
        "entity": {
            "id": dataArgs.get('entity-id'),
            "name": dataArgs.get('entity-name')
        },
        "name": dataArgs.get('name'),
        "shortDesc": dataArgs.get('short-description'),
        "longDesc": dataArgs.get('long-description'),
        "riskLevel": dataArgs.get('risk-level'),
        "threatLevel": dataArgs.get('threat-level'),
        "threatLevelComments": dataArgs.get('threat-level-comments'),
        "recordStatusName": dataArgs.get('host-status'),
        "hostZone": dataArgs.get('host-zone'),
        "os": dataArgs.get('os'),
        "useEventlogCredentials": dataArgs.get('use-eventlog-credentials'),
        "osType": dataArgs.get('os-type')
    }

    res = http_request('POST', 'lr-admin-api/hosts/', json.dumps(data))
    return_outputs(readable_output=dataArgs.get('name') + " added successfully to " + dataArgs.get('entity-name'),
                   outputs=None, raw_response=res)


def get_hosts(dataArgs):
    res = http_request('GET', 'lr-admin-api/hosts?entity=' + dataArgs['entity-name'] + '&count=' + dataArgs['count'])
    res = fix_hosts_response(res)
    context = createContext(res, removeNull=True)
    human_readable = tableToMarkdown('Hosts for ' + dataArgs.get('entity-name'), res, HOSTS_HEADERS)
    outputs = {'Logrhythm.Hosts(val.Name && val.id === obj.id)': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def change_status(dataArgs):
    data = [{
        "hostId": int(dataArgs.get('host-id')),
        "status": dataArgs.get('status')
    }]

    res = http_request('PUT', 'lr-admin-api/hosts/status', json.dumps(data))

    host_info = get_host_by_id(dataArgs.get('host-id'))
    context = createContext(host_info, removeNull=True)
    outputs = {'Logrhythm.Hosts(val.id === obj.id)': context}
    return_outputs(readable_output='Status updated to ' + dataArgs.get('status'), outputs=outputs, raw_response=res)


def execute_query(dataArgs):
    req_id = ''.join(random.choice(string.ascii_letters) for x in range(8))
    start, end = get_time_frame(dataArgs.get('time-frame'), dataArgs.get('start-date'), dataArgs.get('end-date'))
    delta = end - start
    dates = []

    for i in range(delta.days + 1):
        dates.append((start + timedelta(days=i)).strftime("logs-%Y-%m-%d"))

    data = {
        "indices": dates,
        "searchType": "DFS_QUERY_THEN_FETCH",
        "source": {
            "size": dataArgs.get('page-size'),
            "query": {
                "query_string": {
                    "default_field": "logMessage",
                    "query": dataArgs.get('keyword')
                }
            },
            "stored_fields": "logMessage",
            "sort": [
                {
                    "normalDate": {
                        "order": "asc"
                    }
                }
            ]
        }
    }

    headers = HEADERS
    headers['Content-Type'] = 'application/json'
    headers['Request-Id'] = req_id
    headers['Request-Origin-Date'] = str(datetime.now())
    headers['x-gateway-route-to-tag'] = CLUSTER_ID

    res = http_request('POST', 'lr-legacy-search-api/esquery', json.dumps(data), headers)
    logs = res['hits']['hits']
    logs_response = []

    xml_ns = './/{http://schemas.microsoft.com/win/2004/08/events/event}'

    for log in logs:
        message = str(log['fields']['logMessage'])
        message = message[:-2][3:]

        try:
            root = ET.fromstring(message)

            log_item = {
                "EventID": str(root.find(xml_ns + 'EventID').text),  # type: ignore
                "Level": str(root.find(xml_ns + 'Level').text),  # type: ignore
                "Task": str(root.find(xml_ns + 'Task').text),  # type: ignore
                "Opcode": str(root.find(xml_ns + 'Opcode').text),  # type: ignore
                "Keywords": str(root.find(xml_ns + 'Keywords').text),  # type: ignore
                "Channel": str(root.find(xml_ns + 'Channel').text),  # type: ignore
                "Computer": str(root.find(xml_ns + 'Computer').text),  # type: ignore
                "EventData": str(root.find(xml_ns + 'EventData').text)  # type: ignore
                .replace('\\r\\n', '\n').replace('\\t', '\t')
            }
            logs_response.append(log_item)
        except Exception:
            continue

    context = createContext(logs_response, removeNull=True)
    human_readable = tableToMarkdown('logs results', logs_response, LOGS_HEASERS)
    outputs = {'Logrhythm.logs': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=logs_response)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
    elif demisto.command() == 'lr-add-host':
        add_host(demisto.args())
    elif demisto.command() == 'lr-get-hosts-by-entity':
        get_hosts(demisto.args())
    elif demisto.command() == 'lr-execute-query':
        execute_query(demisto.args())
    elif demisto.command() == 'lr-update-alarm-status':
        change_status(demisto.args())
except Exception as e:
    raise
