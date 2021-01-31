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

TOKEN = demisto.params().get('token', '')
BASE_URL = demisto.params().get('url', '').strip('/')
INSECURE = not demisto.params().get('insecure')
CLUSTER_ID = demisto.params().get('cluster-id')

# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Bearer ' + TOKEN,
    'Content-Type': 'application/json',
}

HOSTS_HEADERS = ["ID", "Name", "EntityId", "EntityName", "OS", "Status", "Location", "RiskLevel", "ThreatLevel",
                 "ThreatLevelComments", "DateUpdated", "HostZone"]
LOGS_HEADERS = ["Level", "Computer", "Channel", "Keywords", "EventData"]
PERSON_HEADERS = ["ID", "HostStatus", "IsAPIPerson", "FirstName", "LastName", "UserID", "UserLogin", "DateUpdated"]
NETWORK_HEADERS = ["ID", "BeganIP", "EndIP", "HostStatus", "Name", "RiskLevel", "EntityId", "EntityName", "Location",
                   "ThreatLevel", "DateUpdated", "HostZone"]
ALARM_SUMMARY_HEADERS = ["PIFType", "DrillDownSummaryLogs"]

PIF_TYPES = {
    "1": "Direction",
    "2": "Priority",
    "3": "Normal Message Date",
    "4": "First Normal Message Date",
    "5": "Last Normal Message Date",
    "6": "Count",
    "7": "MessageDate",
    "8": "Entity",
    "9": "Log Source",
    "10": "Log Source Host",
    "11": "Log Source Type",
    "12": "Log Class Type",
    "13": "Log Class",
    "14": "Common Event",
    "15": "MPE Rule",
    "16": "Source",
    "17": "Destination",
    "18": "Service",
    "19": "Known Host",
    "20": "Known Host (Origin)",
    "21": "Known Host (Impacted)",
    "22": "Known Service",
    "23": "IP",
    "24": "IP Address (Origin)",
    "25": "IP Address (Impacted)",
    "26": "Host Name",
    "27": "Host Name (Origin)",
    "28": "Host Name (Impacted)",
    "29": "Port (Origin)",
    "30": "Port (Impacted)",
    "31": "Protocol",
    "32": "User (Origin)",
    "33": "User (Impacted)",
    "34": "Sender",
    "35": "Recipient",
    "36": "Subject",
    "37": "Object",
    "38": "Vendor Message ID",
    "39": "Vendor Message Name",
    "40": "Bytes In",
    "41": "Bytes Out",
    "42": "Items In",
    "43": "Items Out",
    "44": "Duration",
    "45": "Time Start",
    "46": "Time End",
    "47": "Process",
    "48": "Amount",
    "49": "Quantity",
    "50": "Rate",
    "51": "Size",
    "52": "Domain (Impacted)",
    "53": "Group",
    "54": "URL",
    "55": "Session",
    "56": "Sequence",
    "57": "Network (Origin)",
    "58": "Network (Impacted)",
    "59": "Location (Origin)",
    "60": "Country (Origin)",
    "61": "Region (Origin)",
    "62": "City (Origin)",
    "63": "Location (Impacted)",
    "64": "Country (Impacted)",
    "65": "Region (Impacted)",
    "66": "City (Impacted)",
    "67": "Entity (Origin)",
    "68": "Entity (Impacted)",
    "69": "Zone (Origin)",
    "70": "Zone (Impacted)",
    "72": "Zone",
    "73": "User",
    "74": "Address",
    "75": "MAC",
    "76": "NATIP",
    "77": "Interface",
    "78": "NATPort",
    "79": "Entity (Impacted or Origin)",
    "80": "RootEntity",
    "100": "Message",
    "200": "MediatorMsgID",
    "201": "MARCMsgID",
    "1040": "MAC (Origin)",
    "1041": "MAC (Impacted)",
    "1042": "NATIP (Origin)",
    "1043": "NATIP (Impacted)",
    "1044": "Interface (Origin)",
    "1045": "Interface (Impacted)",
    "1046": "PID",
    "1047": "Severity",
    "1048": "Version",
    "1049": "Command",
    "1050": "ObjectName",
    "1051": "NATPort (Origin)",
    "1052": "NATPort (Impacted)",
    "1053": "Domain (Origin)",
    "1054": "Hash",
    "1055": "Policy",
    "1056": "Vendor Info",
    "1057": "Result",
    "1058": "Object Type",
    "1059": "CVE",
    "1060": "UserAgent",
    "1061": "Parent Process Id",
    "1062": "Parent Process Name",
    "1063": "Parent Process Path",
    "1064": "Serial Number",
    "1065": "Reason",
    "1066": "Status",
    "1067": "Threat Id",
    "1068": "Threat Name",
    "1069": "Session Type",
    "1070": "Action",
    "1071": "Response Code",
    "1072": "User (Origin) Identity ID",
    "1073": "User (Impacted) Identity ID",
    "1074": "Sender Identity ID",
    "1075": "Recipient Identity ID",
    "1076": "User (Origin) Identity",
    "1077": "User (Impacted) Identity",
    "1078": "Sender Identity",
    "1079": "Recipient Identity",
    "1080": "User (Origin) Identity Domain",
    "1081": "User (Impacted) Identity Domain",
    "1082": "Sender Identity Domain",
    "1083": "Recipient Identity Domain",
    "1084": "User (Origin) Identity Company",
    "1085": "User (Impacted) Identity Company",
    "1086": "Sender Identity Company",
    "1087": "Recipient Identity Company",
    "1088": "User (Origin) Identity Department",
    "1089": "User (Impacted) Identity Department",
    "1090": "Sender Identity Department",
    "1091": "Recipient Identity Department",
    "1092": "User (Origin) Identity Title",
    "1093": "User (Impacted) Identity Title",
    "1094": "Sender Identity Title",
    "1095": "Recipient Identity Title",
    "10001": "Source Or Destination",
    "10002": "Port (Origin or Impacted)",
    "10003": "Network (Origin or Impacted)",
    "10004": "Location (Origin or Impacted)",
    "10005": "Country (Origin or Impacted)",
    "10006": "Region (Origin or Impacted)",
    "10007": "City (Origin or Impacted)",
    "10008": "Bytes In/Out",
    "10009": "Items In/Out"
}

ALARM_STATUS = {
    "0": "Waiting",
    "1": "In queue",
    "2": "Sent to SvcHost",
    "3": "Queued for retry",
    "4": "Completed",
}

''' HELPER FUNCTIONS '''


def fix_date_values(item):
    date_keys = ['normalDateMin', 'normalDate', 'normalMsgDateMax', 'logDate']

    for key in date_keys:
        if item.get(key):
            item[key] = datetime.fromtimestamp(item.get(key) / 1000.0).\
                strftime('%Y-%m-%d %H:%M:%S')


def fix_location_value(items):
    for item in items:
        location_val = str(item.get('location'))
        if location_val == '{u\'id\': -1}':
            item['location'] = 'NA'

    return items


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
    if res.headers.get('Content-Type') != 'application/json':
        return_error('invalid url or port: ' + BASE_URL)

    if res.status_code == 404:
        if res.json().get('message'):
            return_error(res.json().get('message'))
        else:
            return_error('No data returned')

    if res.status_code not in {200, 201, 202, 207}:
        return_error(
            'Error in API call to {}, status code: {}, reason: {}'.format(BASE_URL + '/' + url_suffix, res.status_code,
                                                                          res.json()['message']))

    return res.json()


def get_host_by_id(host_id):
    res = http_request('GET', 'lr-admin-api/hosts/' + host_id)
    return fix_location_value([res])


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
            'Status': host.get('recordStatusName'),
            'ThreatLevelComments': host.get('threatLevelComments'),
            'ID': host.get('id'),
            'OSType': host.get('osType')
        }
        new_hosts.append(tmp_host)
    return new_hosts


def update_networks_keys(networks):
    new_networks = []

    for network in networks:
        tmp_network = {
            'EndIP': network.get('eip'),
            'HostStatus': network.get('recordStatusName'),
            'Name': network.get('name'),
            'RiskLevel': network.get('riskLevel'),
            'EntityId': network.get('entity').get('id'),
            'EntityName': network.get('entity').get('name'),
            'Location': network.get('location'),
            'ThreatLevel': network.get('threatLevel'),
            'DateUpdated': network.get('dateUpdated'),
            'HostZone': network.get('hostZone'),
            'ID': network.get('id'),
            'BeganIP': network.get('bip')
        }
        new_networks.append(tmp_network)
    return new_networks


def update_persons_keys(persons):
    new_persons = []

    for person in persons:
        tmp_person = {
            'ID': person.get('id'),
            'DateUpdated': person.get('dateUpdated'),
            'HostStatus': person.get('recordStatusName'),
            'LastName': person.get('lastName'),
            'FirstName': person.get('firstName'),
            'IsAPIPerson': person.get('isAPIPerson'),
            'UserID': person.get('user').get('id'),
            'UserLogin': person.get('user').get('login')
        }
        new_persons.append(tmp_person)
    return new_persons


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
    res = fix_location_value([res])
    context = createContext(update_hosts_keys(res), removeNull=True)
    outputs = {'Logrhythm.Host(val.ID === obj.ID)': context}
    return_outputs(readable_output=data_args.get('name') + " added successfully to " + data_args.get('entity-name'),
                   outputs=outputs, raw_response=res)


def get_hosts_by_entity(data_args):
    res = http_request('GET', 'lr-admin-api/hosts?entity=' + data_args['entity-name'] + '&count=' + data_args['count'])
    res = fix_location_value(res)
    res = update_hosts_keys(res)
    context = createContext(res, removeNull=True)
    human_readable = tableToMarkdown('Hosts for ' + data_args.get('entity-name'), res, HOSTS_HEADERS)
    outputs = {'Logrhythm.Host(val.Name && val.ID === obj.ID)': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_hosts(data_args):
    id = data_args.get('host-id')
    if id:
        res = get_host_by_id(id)
    else:
        res = http_request('GET', 'lr-admin-api/hosts?count=' + data_args['count'])

    res = fix_location_value(res)
    res = update_hosts_keys(res)
    context = createContext(res, removeNull=True)
    human_readable = tableToMarkdown('Hosts information:', res, HOSTS_HEADERS)
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
    # generate random string for request id
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


def get_persons(data_args):
    id = data_args.get('person-id')
    if id:
        res = [http_request('GET', 'lr-admin-api/persons/' + id)]
    else:
        res = http_request('GET', 'lr-admin-api/persons?count=' + data_args['count'])
    res = update_persons_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Person(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Persons information', context, PERSON_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_networks(data_args):
    id = data_args.get('network-id')
    if id:
        res = [http_request('GET', 'lr-admin-api/networks/' + id)]
    else:
        res = http_request('GET', 'lr-admin-api/networks?count=' + data_args['count'])
    res = fix_location_value(res)
    res = update_networks_keys(res)
    context = createContext(res, removeNull=True)
    outputs = {'Logrhythm.Network(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Networks information', context, NETWORK_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_alarm_data(data_args):
    id = data_args.get('alarm-id')
    res = http_request('GET', 'lr-drilldown-cache-api/drilldown/' + id)

    alarm_data = res['Data']['DrillDownResults']
    alarm_summaries = res['Data']['DrillDownResults']['RuleBlocks']
    del alarm_data['RuleBlocks']
    aie_message = xml2json(str(alarm_data.get('AIEMsgXml'))).replace('\"@', '\"')
    alarm_data['AIEMsgXml'] = json.loads(aie_message).get('aie')
    alarm_data['Status'] = ALARM_STATUS[str(alarm_data['Status'])]
    alarm_data['ID'] = alarm_data['AlarmID']
    del alarm_data['AlarmID']

    dds_summaries = []
    for block in alarm_summaries:
        for item in block['DDSummaries']:
            item['PIFType'] = PIF_TYPES[str(item['PIFType'])]
            m = re.findall(r'"field": "(([^"]|\\")*)"', item['DrillDownSummaryLogs'])
            fields = [k[0] for k in m]
            item['DrillDownSummaryLogs'] = ", ".join(fields)
            del item['DefaultValue']
            dds_summaries.append(item)

    alarm_data['Summary'] = dds_summaries

    context = createContext(alarm_data, removeNull=True)
    outputs = {'Logrhythm.Alarm(val.ID === obj.ID)': context}

    del alarm_data['AIEMsgXml']
    del alarm_data['Summary']
    human_readable = tableToMarkdown('Alarm information for alarm id ' + id, alarm_data) + tableToMarkdown(
        'Alarm summaries', dds_summaries, ALARM_SUMMARY_HEADERS)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_alarm_events(data_args):
    id = data_args.get('alarm-id')
    count = int(data_args.get('count'))
    fields = data_args.get('fields')
    show_log_message = data_args.get('get-log-message') == 'True'

    res = http_request('GET', 'lr-drilldown-cache-api/drilldown/' + id)
    res = res['Data']['DrillDownResults']['RuleBlocks']

    events = []

    for block in res:
        if not block.get('DrillDownLogs'):
            continue
        logs = json.loads(block['DrillDownLogs'])
        for log in logs:
            fix_date_values(log)
            if not show_log_message:
                del log['logMessage']
            events.append((log))

    events = events[:count]
    human_readable = tableToMarkdown('Events information for alarm ' + id, events)

    if fields:
        fields = string.split(fields, ',')
        for event in events:
            for key in event.keys():
                if key not in fields:
                    del event[key]

    ec = {"ID": int(id), "Event": events}
    context = createContext(ec, removeNull=True)
    outputs = {'Logrhythm.Alarm(val.ID === obj.ID)': context}

    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


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
            get_hosts_by_entity(demisto.args())
        elif demisto.command() == 'lr-get-hosts':
            get_hosts(demisto.args())
        elif demisto.command() == 'lr-execute-query':
            execute_query(demisto.args())
        elif demisto.command() == 'lr-update-host-status':
            change_status(demisto.args())
        elif demisto.command() == 'lr-get-persons':
            get_persons(demisto.args())
        elif demisto.command() == 'lr-get-networks':
            get_networks(demisto.args())
        elif demisto.command() == 'lr-get-alarm-data':
            get_alarm_data(demisto.args())
        elif demisto.command() == 'lr-get-alarm-events':
            get_alarm_events(demisto.args())
    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
