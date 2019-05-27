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
BASE_URL = demisto.params()['url'].strip('/')
INSECURE = demisto.params().get('insecure')
CLUSTER_ID = demisto.params().get('cluster-id')

# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Bearer ' + TOKEN
}

HOSTS_HEADERS = ["ID", "Name", "EntityId", "EntityName", "OS", "Status", "Location", "RiskLevel", "ThreatLevel",
                 "ThreatLevelComments", "DateUpdated", "HostZone"]
LOGS_HEADERS = ["Level", "Computer", "Channel", "Keywords", "EventData"]

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
            verify=INSECURE,
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


def update_hosts_keys(hosts):
    new_hosts = []
    for host in hosts:
        tmp_host = {
            'EntityId': host.get('entity').get('id'),
            'EntityName': host.get('entity').get('name'),
            'OS': host.get('os'),
            'ThreatLevel': host.get('threatLevel'),
            'UseEventlogCredentials': host.get('useEventlogCredentials'),
            'Name': host.get('name'),
            'DateUpdated': host.get('dateUpdated'),
            'HostZone': host.get('hostZone'),
            'RiskLevel': host.get('riskLevel'),
            'Location': host.get('location'),
            'Status': host.get('hostStatus'),
            'ThreatLevelComments': host.get('threatLevelComments'),
            'ID': host.get('id'),
            'OSType': host.get('osType')
        }
        new_hosts.append(tmp_host)
    return new_hosts


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    http_request('GET', 'lr-admin-api/hosts')
    demisto.results('ok')


def add_host(data_args):
    data = {
        "id": -1,
        "entity": {
            "id": int(data_args.get('entity-id')),
            "name": data_args.get('entity-name')
        },
        "name": data_args.get('name'),
        "shortDesc": data_args.get('short-description'),
        "longDesc": data_args.get('long-description'),
        "riskLevel": data_args.get('risk-level'),
        "threatLevel": data_args.get('threat-level'),
        "threatLevelComments": data_args.get('threat-level-comments'),
        "recordStatusName": data_args.get('host-status'),
        "hostZone": data_args.get('host-zone'),
        "os": data_args.get('os'),
        "useEventlogCredentials": bool(data_args.get('use-eventlog-credentials')),
        "osType": data_args.get('os-type')
    }

    res = http_request('POST', 'lr-admin-api/hosts/', json.dumps(data))
    res = fix_hosts_response([res])
    context = createContext(update_hosts_keys(res), removeNull=True)
    outputs = {'Logrhythm.Host(val.ID === obj.ID)': context}
    return_outputs(readable_output=data_args.get('name') + " added successfully to " + data_args.get('entity-name'),
                   outputs=outputs, raw_response=res)


def get_hosts(data_args):
    res = http_request('GET', 'lr-admin-api/hosts?entity=' + data_args['entity-name'] + '&count=' + data_args['count'])
    res = fix_hosts_response(res)
    res = update_hosts_keys(res)
    context = createContext(res, removeNull=True)
    human_readable = tableToMarkdown('Hosts for ' + data_args.get('entity-name'), res, HOSTS_HEADERS)
    outputs = {'Logrhythm.Host(val.Name && val.ID === obj.ID)': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def change_status(data_args):
    data = [{
        "hostId": int(data_args.get('host-id')),
        "status": data_args.get('status')
    }]

    res = http_request('PUT', 'lr-admin-api/hosts/status', json.dumps(data))

    host_info = get_host_by_id(data_args.get('host-id'))
    context = createContext(update_hosts_keys(host_info), removeNull=True)
    outputs = {'Logrhythm.Host(val.ID === obj.ID)': context}
    return_outputs(readable_output='Status updated to ' + data_args.get('status'), outputs=outputs, raw_response=res)


def execute_query(data_args):
    #generate random string for request id
    req_id = ''.join(random.choice(string.ascii_letters) for x in range(8))
    start, end = get_time_frame(data_args.get('time-frame'), data_args.get('start-date'), data_args.get('end-date'))
    delta = end - start
    dates = []

    for i in range(delta.days + 1):
        dates.append((start + timedelta(days=i)).strftime("logs-%Y-%m-%d"))

    data = {
        "indices": dates,
        "searchType": "DFS_QUERY_THEN_FETCH",
        "source": {
            "size": data_args.get('page-size'),
            "query": {
                "query_string": {
                    "default_field": "logMessage",
                    "query": data_args.get('keyword')
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

    headers = dict(HEADERS)
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
        message = message[3:-2]

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
    human_readable = tableToMarkdown('logs results', logs_response, LOGS_HEADERS)
    outputs = {'Logrhythm.Log': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=logs_response)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is %s' % (demisto.command()))

    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        elif demisto.command() == 'lr-add-host':
            add_host(demisto.args())
        elif demisto.command() == 'lr-get-hosts-by-entity':
            get_hosts(demisto.args())
        elif demisto.command() == 'lr-execute-query':
            execute_query(demisto.args())
        elif demisto.command() == 'lr-update-host-status':
            change_status(demisto.args())
    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
