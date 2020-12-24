
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import os
import ast
import json
import urllib3
import urllib.parse
from dateutil.parser import parse
from typing import Any
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' GLOBALS/PARAMS '''
FETCH_TIME = demisto.params().get('fetch_time')
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

PROCESS_TEXT = 'Process information for process with PTID'
PARENT_PROCESS_TEXT = 'Parent process for process with PTID'
PROCESS_CHILDREN_TEXT = 'Children for process with PTID'

# The commands below won't work unless the connection passed in `connection_name` argument is active.
COMMANDS_DEPEND_ON_CONNECTIVITY = [
    'tanium-tr-list-snapshots-by-connection',
    'tanium-tr-create-snapshot',
    'tanium-tr-list-events-by-connection',
    'tanium-tr-get-process-info',
    'tanium-tr-get-events-by-process',
    'tanium-tr-get-process-children',
    'tanium-tr-get-parent-process',
    'tanium-tr-get-parent-process-tree',
    'tanium-tr-get-process-tree',
    'tanium-tr-create-evidence',
    'tanium-tr-request-file-download',
    'tanium-tr-list-files-in-directory',
    'tanium-tr-get-file-info',
    'tanium-tr-delete-file-from-endpoint',
    'tanium-tr-get-process-timeline',
]
DEPENDENT_COMMANDS_ERROR_MSG = '\nPlease verify that the connection you have specified is active.'


class Client(BaseClient):
    def __init__(self, base_url, username, password, **kwargs):
        self.username = username
        self.password = password
        self.session = ''
        super(Client, self).__init__(base_url, **kwargs)

    def do_request(self, method, url_suffix, data=None, params=None, resp_type='json'):
        if not self.session:
            self.update_session()
        res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                 params=params, resp_type='response', ok_codes=(200, 201, 202, 204, 400, 403, 404))

        # if session expired
        if res.status_code == 403:
            self.update_session()
            res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                     params=params, ok_codes=(200, 400, 404))
            return res

        if res.status_code == 404 or res.status_code == 400:
            if res.content:
                raise requests.HTTPError(str(res.content))
            if res.reason:
                raise requests.HTTPError(str(res.reason))
            raise requests.HTTPError(res.json().get('text'))

        if resp_type == 'json':
            try:
                return res.json()
            except json.JSONDecodeError:
                return res.content
        if resp_type == 'text':
            return res.text, res.headers.get('Content-Disposition')
        if resp_type == 'content':
            return res.content, res.headers.get('Content-Disposition')

        return res

    def update_session(self):
        body = {
            'username': self.username,
            'password': self.password
        }

        res = self._http_request('GET', '/api/v2/session/login', json_data=body, ok_codes=(200,))

        self.session = res.get('data').get('session')
        return self.session

    def login(self):
        return self.update_session()


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_process_timeline_item(raw_item, category_name, limit, offset):
    timeline_item = []
    for category in raw_item:
        if category['name'].lower() == category_name.lower():
            sorted_timeline_dates = sorted(category['details'].keys())
            from_idx = min(offset, len(sorted_timeline_dates))
            to_idx = min(offset + limit, len(sorted_timeline_dates))
            for i in range(from_idx, to_idx):
                current_date = sorted_timeline_dates[i]
                events_in_current_date = category['details'][current_date]
                timeline_item.append({
                    'Date': timestamp_to_datestring(sorted_timeline_dates[i], date_format='%Y-%m-%d %H:%M:%S.%f'),
                    'Category': category_name,
                    'Event': events_in_current_date
                })

    return timeline_item


def try_parse_integer(int_to_parse: Any) -> int:
    """
    Tries to parse an integer.
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        res = 10000
    return res


def path_join(base, file_name):
    if '\\' in base:
        if not base.endswith('\\'):
            return base + '\\' + file_name
        return base + file_name
    elif '/' in base:
        if not base.endswith('/'):
            return base + '/' + file_name
        return base + file_name
    return file_name


def evidence_type_number_to_name(num: int) -> str:
    """
    Transforms evidence type number to it's corresponding name
    :param num: The evidence type number
    :return: The string name of the evidence type
    """
    name: str = str()
    supported_types = ['Network', 'Process', 'File', 'Registry', 'Security', 'Image', 'DNS']
    try:
        name = supported_types[num - 1]
    except IndexError:
        name = 'Unknown'
    finally:
        return name


def get_evidence_item(raw_item):
    evidence_item = {
        'ID': raw_item.get('id'),
        'CreatedAt': raw_item.get('created'),
        'UpdatedAt': raw_item.get('lastModified'),
        'User': raw_item.get('user'),
        'ConnectionName': raw_item.get('host'),
        'Type': evidence_type_number_to_name(try_parse_integer(raw_item.get('type'))),
        'ProcessTableId': raw_item.get('sId'),
        'Timestamp': raw_item.get('sTimestamp'),
        'Summary': raw_item.get('summary'),
        'Comments': raw_item.get('comments'),
        'Tags': raw_item.get('tags'),
        'Deleted': False
    }
    return {key: val for key, val in evidence_item.items() if val is not None}


def get_process_tree_item(raw_item, level):
    tree_item = {
        'ID': raw_item.get('id'),
        'PTID': raw_item.get('ptid'),
        'PID': raw_item.get('pid'),
        'Name': raw_item.get('name'),
        'Parent': raw_item.get('parent'),
        'Children': raw_item.get('children')
    }

    human_readable = tree_item.copy()
    del human_readable['Children']

    children = tree_item.get('Children')
    if children and level == 1:
        human_readable['ChildrenCount'] = len(children)
    if not children and level == 1:
        human_readable['ChildrenCount'] = 0
    elif children and level == 0:
        human_readable_arr = []
        output_arr = []
        for item in children:
            tree_output, human_readable_res = get_process_tree_item(item, level + 1)
            human_readable_arr.append(human_readable_res)
            output_arr.append(tree_output)

        human_readable['Children'] = human_readable_arr
        tree_item['Children'] = output_arr

    return tree_item, human_readable


def get_process_event_item(raw_event):
    return {
        'ID': raw_event.get('id'),
        'Detail': raw_event.get('detail'),
        'Operation': raw_event.get('operation'),
        'Timestamp': raw_event.get('timestamp'),
        'Type': raw_event.get('type')
    }


def get_process_item(raw_process):
    return {
        'CreateTime': raw_process.get('create_time'),
        'Domain': raw_process.get('domain'),
        'ExitCode': raw_process.get('exit_code'),
        'ProcessCommandLine': raw_process.get('process_command_line'),
        'ProcessID': raw_process.get('process_id'),
        'ProcessName': raw_process.get('process_name'),
        'ProcessTableId': raw_process.get('process_table_id'),
        'SID': raw_process.get('sid'),
        'Username': raw_process.get('username')
    }


def get_event_header(event_type):
    if event_type == "combined":
        headers = ['ID', 'Type', 'ProcessName', 'Detail', 'Timestamp', 'Operation']

    elif event_type == "file":
        headers = ['ID', 'Type', 'File', 'Timestamp', 'Domain', 'ProcessTableID', 'ProcessID', 'ProcessName',
                   'Username']

    elif event_type == "network":
        headers = ['ID', 'Type', 'Timestamp', 'Domain', 'ProcessTableID', 'ProcessID', 'ProcessName', 'Username',
                   'Operation', 'DestinationAddress', 'DestinationPort', 'SourceAddress', 'SourcePort']

    elif event_type == "registry":
        headers = ['ID', 'Type', 'Timestamp', 'Domain', 'ProcessTableID', 'ProcessID', 'ProcessName', 'Username',
                   'KeyPath', 'ValueName']

    elif event_type == "process":
        headers = ['Domain', 'Type', 'ProcessTableID', 'ProcessCommandLine', 'ProcessID', 'ProcessName', 'ExitCode',
                   'SID', 'Username', 'CreationTime', 'EndTime']

    elif event_type == "driver":
        headers = ['ID', 'Type', 'Timestamp', 'ProcessTableID', 'SID', 'Hashes', 'ImageLoaded', 'Signature', 'Signed',
                   'EventID', 'EventOpcode', 'EventRecordID', 'EventTaskID']

    elif event_type == "security":
        headers = ['ID', 'Type', 'Timestamp', 'EventID', 'EventTaskName', 'ProcessTableID']

    elif event_type == "dns":
        headers = ['ID', 'Type', 'Timestamp', 'Domain', 'ProcessTableID', 'ProcessID', 'ProcessName', 'Username',
                   'Operation', 'Query', 'Response']

    else:  # if event_type == "image"
        headers = ['ID', 'Type', 'Timestamp', 'ImagePath', 'ProcessTableID', 'ProcessID', 'ProcessName', 'Username',
                   'Hash', 'Signature']
    return headers


def get_event_item(raw_event, event_type):
    event = {
        'ID': raw_event.get('id'),
        'Domain': raw_event.get('domain'),
        'File': raw_event.get('file'),
        'Operation': raw_event.get('operation'),
        'ProcessID': raw_event.get('process_id'),
        'ProcessName': raw_event.get('process_name'),
        'ProcessTableID': raw_event.get('process_table_id'),
        'Timestamp': raw_event.get('timestamp'),
        'Username': raw_event.get('username'),
        'DestinationAddress': raw_event.get('destination_addr'),
        'DestinationPort': raw_event.get('destination_port'),
        'SourceAddress': raw_event.get('source_addr'),
        'SourcePort': raw_event.get('source_port'),
        'KeyPath': raw_event.get('key_path'),
        'ValueName': raw_event.get('value_name'),
        'CreationTime': raw_event.get('create_time'),
        'EndTime': raw_event.get('end_time'),
        'ExitCode': raw_event.get('exit_code'),
        'ProcessCommandLine': raw_event.get('process_command_line'),
        'ProcessHash': raw_event.get('process_hash'),
        'SID': raw_event.get('sid'),
        'Hashes': raw_event.get('Hashes'),
        'ImageLoaded': raw_event.get('ImageLoaded'),
        'Signature': raw_event.get('Signature'),
        'Signed': raw_event.get('Signed'),
        'EventID': raw_event.get('event_id'),
        'EventOpcode': raw_event.get('event_opcode'),
        'EventRecordID': raw_event.get('event_record_id'),
        'EventTaskID': raw_event.get('event_task_id'),
        'EventTaskName': raw_event.get('event_task_name'),
        'Query': raw_event.get('query'),
        'Response': raw_event.get('response')
    }

    if event_type == 'security':
        event['Property'] = [{k.title(): v for k, v in prop.items()}
                             for prop in raw_event.get('properties')]

    if event_type == 'combined':
        event['Type'] = raw_event.get('type')
    else:
        event['Type'] = event_type.upper() if event_type in ['dns', 'sid'] else event_type.title()

    # remove empty values from the event item
    return {k: v for k, v in event.items() if v is not None}


def get_file_item(file, con_name, dir_path='', full_path=''):
    file_item = {
        'ConnectionName': con_name,
        'Created': timestamp_to_datestring(file.get('created'), '%Y-%m-%d %H:%M:%S'),
        'Path': file.get('file-path'),
        'IsDirectory': file.get('is-directory'),
        'LastModified': timestamp_to_datestring(file.get('last-modified'), '%Y-%m-%d %H:%M:%S'),
        'Permissions': file.get('permissions'),
        'Size': file.get('size'),
        'Deleted': False
    }
    if not file_item['Path']:
        file_item['Path'] = full_path
    else:
        file_item['Path'] = path_join(dir_path, file_item['Path'])

    return {key: val for key, val in file_item.items() if val is not None}


def get_file_download_item(file):
    return {
        'ID': file.get('id'),
        'Host': file.get('host'),
        'Path': file.get('path'),
        'SPath': file.get('spath'),
        'Hash': file.get('hash'),
        'Size': file.get('size'),
        'Created': file.get('created'),
        'CreatedBy': file.get('created_by'),
        'CreatedByProc': file.get('created_by_proc'),
        'LastModified': file.get('last_modified'),
        'LastModifiedBy': file.get('last_modified_by'),
        'LastModifiedByProc': file.get('last_modified_by_proc'),
        'Downloaded': file.get('downloaded'),
        'Comments': file.get('comments'),
        'Tags': file.get('tags'),
        'Deleted': False
    }


def get_label_item(label):
    return {
        'ID': label.get('id'),
        'Name': label.get('name'),
        'Description': label.get('description'),
        'IndicatorCount': label.get('indicatorCount'),
        'SignalCount': label.get('signalCount'),
        'CreatedAt': label.get('createdAt'),
        'UpdatedAt': label.get('updatedAt')}


def get_connection_item(connection):
    info = connection.get('info')
    return {
        'Name': connection.get('name'),
        'State': info.get('state'),
        'CreateTime': info.get('createTime'),
        'DST': info.get('dst'),
        'DestinationType': info.get('dstType'),
        'Remote': info.get('remote'),
        'OSName': connection.get('osName'),
        'Deleted': False
    }


def get_local_snapshot_items(raw_snapshots, limit, offset, conn_name):
    snapshots = []
    host_snapshots = raw_snapshots.get(conn_name, {})
    snapshot_keys = sorted(host_snapshots)
    from_idx = min(offset, len(snapshot_keys))
    to_idx = min(offset + limit, len(snapshot_keys))

    for key in snapshot_keys[from_idx:to_idx]:
        snapshots.append({
            'ConnectionName': conn_name,
            'FileName': key,
            'Deleted': False
        })

    return snapshots


def get_snapshot_items(raw_snapshots, limit, offset, conn_name):
    snapshots = []
    host_snapshots = raw_snapshots.get(conn_name, {})
    snapshot_keys = sorted(host_snapshots)
    from_idx = min(offset, len(snapshot_keys))
    to_idx = min(offset + limit, len(snapshot_keys))

    for key in snapshot_keys[from_idx:to_idx]:
        snapshots.append({
            'ConnectionName': conn_name,
            'ID': key,
            'Started': host_snapshots[key].get('started', ''),
            'State': host_snapshots[key].get('state', ''),
            'Error': host_snapshots[key].get('error', ''),
            'Deleted': False
        })

    return snapshots


def get_intel_doc_item(intel_doc):
    return {
        'ID': intel_doc.get('id'),
        'Name': intel_doc.get('name'),
        'Description': intel_doc.get('description'),
        'AlertCount': intel_doc.get('alertCount'),
        'UnresolvedAlertCount': intel_doc.get('unresolvedAlertCount'),
        'CreatedAt': intel_doc.get('createdAt'),
        'UpdatedAt': intel_doc.get('updatedAt'),
        'LabelIds': intel_doc.get('labelIds')}


def get_alert_item(alert):
    return {
        'ID': alert.get('id'),
        'AlertedAt': alert.get('alertedAt'),
        'ComputerIpAddress': alert.get('computerIpAddress'),
        'ComputerName': alert.get('computerName'),
        'CreatedAt': alert.get('createdAt'),
        'GUID': alert.get('guid'),
        'IntelDocId': alert.get('intelDocId'),
        'Priority': alert.get('priority'),
        'Severity': alert.get('severity'),
        'State': alert.get('state').title(),
        'Type': alert.get('type'),
        'UpdatedAt': alert.get('updatedAt')}


def alarm_to_incident(client, alarm):
    intel_doc_id = alarm.get('intelDocId', '')
    host = alarm.get('computerName', '')
    details = alarm.get('details')

    if details:
        details = json.loads(alarm['details'])
        alarm['details'] = details

    intel_doc = ''
    if intel_doc_id:
        raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}')
        intel_doc = raw_response.get('name')

    return {
        'name': f'{host} found {intel_doc}',
        'occurred': alarm.get('alertedAt'),
        'rawJSON': json.dumps(alarm)}


def state_params_suffix(alerts_states_to_retrieve):
    valid_alert_states = ['unresolved', 'inprogress', 'resolved', 'suppressed']

    for state in alerts_states_to_retrieve:
        if state.lower() not in valid_alert_states:
            raise ValueError(f'Invalid state \'{state}\' in filter_alerts_by_state parameter.'
                             f'Possible values are \'unresolved\', \'inprogress\', \'resolved\' or \'suppressed\'.')

    return '&'.join(['state=' + state.lower() for state in alerts_states_to_retrieve])


def validate_connection_name(client, arg_input, skip=False):
    """ Tanium API's connection-name parameter is case sensitive - this function queries for the user input
    and returns the precise string to use in the API, or raises a ValueError if doesn't exist.

    Args:
        client: (Client) the client class object.
        arg_input: (str) the user input for a command's connection name argument.
        skip: (bool) Whether to skipping validation

    Returns:
        (str) The precise connection name.

    """
    if arg_input.startswith('local-') or skip:  # don't check snapshots
        return arg_input
    if is_ip_valid(arg_input):
        # if input is IP, try with the format a-b-c-d first because it will replace the IP with the real connection name
        # and prevents the user from using the IP - which we prefer because that way the connections list won't contain
        # the IP with "timeout" state (it doesn't happen in Tanium UI).
        ip_input = arg_input.replace('.', '-')
        results = client.do_request('GET', f'/plugin/products/trace/computers?name={ip_input}')
        if results and len(results) == 1:
            return results[0]
    results = client.do_request('GET', f'/plugin/products/trace/computers?name={arg_input}')
    if results and len(results) == 1 and results[0].lower() == arg_input.lower():
        return results[0]
    raise ValueError('The specified connection name does not exist.')


def test_module(client, data_args):
    if client.login():
        return demisto.results('ok')
    raise ValueError('Test Tanium integration failed - please check your username and password')


def get_intel_doc(client, data_args):
    id_ = data_args.get('intel-doc-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{id_}')
    intel_doc = get_intel_doc_item(raw_response)

    context = createContext(intel_doc, removeNull=True)
    outputs = {'Tanium.IntelDoc(val.ID && val.ID === obj.ID)': context}

    intel_doc['LabelIds'] = str(intel_doc['LabelIds']).strip('[]')
    headers = ['ID', 'Name', 'Description', 'Type', 'AlertCount', 'UnresolvedAlertCount', 'CreatedAt', 'UpdatedAt',
               'LabelIds']
    human_readable = tableToMarkdown('Intel Doc information', intel_doc, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_intel_docs(client, data_args):
    limit = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/intels/', params={'limit': limit})

    intel_docs = []
    for item in raw_response:
        intel_doc = get_intel_doc_item(item)
        intel_docs.append(intel_doc)

    context = createContext(intel_docs, removeNull=True)
    outputs = {'Tanium.IntelDoc(val.ID && val.ID === obj.ID)': context}

    for item in intel_docs:
        item['LabelIds'] = str(item['LabelIds']).strip('[]')

    headers = ['ID', 'Name', 'Description', 'Type', 'AlertCount', 'UnresolvedAlertCount', 'CreatedAt', 'UpdatedAt',
               'LabelIds']
    human_readable = tableToMarkdown('Intel docs', intel_docs, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_alerts(client, data_args):
    limit = int(data_args.get('limit'))
    offset = data_args.get('offset')
    ip_address = data_args.get('computer-ip-address')
    computer_name = data_args.get('computer-name')
    scan_config_id = data_args.get('scan-config-id')
    intel_doc_id = data_args.get('intel-doc-id')
    severity = data_args.get('severity')
    priority = data_args.get('priority')
    type_ = data_args.get('type')
    state = data_args.get('state')

    params = {'type': type_,
              'priority': priority,
              'severity': severity,
              'intelDocId': intel_doc_id,
              'scanConfigId': scan_config_id,
              'computerName': computer_name,
              'computerIpAddress': ip_address,
              'limit': limit,
              'offset': offset}
    if state:
        params['state'] = state.lower()

    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/alerts/', params=params)

    alerts = []
    for item in raw_response:
        alert = get_alert_item(item)
        alerts.append(alert)

    context = createContext(alerts, removeNull=True)
    headers = ['ID', 'Type', 'Severity', 'Priority', 'AlertedAt', 'CreatedAt', 'UpdatedAt', 'ComputerIpAddress',
               'ComputerName', 'GUID', 'State', 'IntelDocId']
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Alerts', alerts, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_alert(client, data_args):
    alert_id = data_args.get('alert-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/alerts/{alert_id}')
    alert = get_alert_item(raw_response)

    context = createContext(alert, removeNull=True)
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Name', 'Type', 'Severity', 'Priority', 'AlertedAt', 'CreatedAt', 'UpdatedAt', 'ComputerIpAddress',
               'ComputerName', 'GUID', 'State', 'IntelDocId']
    human_readable = tableToMarkdown('Alert information', alert, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def alert_update_state(client, data_args):
    alert_id = data_args.get('alert-id')
    state = data_args.get('state')

    body = {"state": state.lower()}
    raw_response = client.do_request('PUT', f'/plugin/products/detect3/api/v1/alerts/{alert_id}', data=body)
    alert = get_alert_item(raw_response)

    context = createContext(alert, removeNull=True)
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Name', 'Type', 'Severity', 'Priority', 'AlertedAt', 'CreatedAt', 'UpdatedAt', 'ComputerIpAddress',
               'ComputerName', 'GUID', 'State', 'IntelDocId']
    human_readable = tableToMarkdown(f'Alert state updated to {state}', alert, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_snapshots(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    conn_name = data_args.get('connection-name')

    raw_response = client.do_request('GET', '/plugin/products/trace/snapshots/')
    snapshots = get_snapshot_items(raw_response, limit, offset, conn_name)
    context = createContext(snapshots, removeNull=True)
    headers = ['ID', 'ConnectionName', 'State', 'Started', 'Error']
    outputs = {'Tanium.Snapshot(val.ID === obj.ID && val.ConnectionName === obj.ConnectionName)': context}
    human_readable = tableToMarkdown(f'Snapshots for connection {conn_name}', snapshots, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def create_snapshot(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    client.do_request('POST', f'/plugin/products/trace/conns/{con_name}/snapshots', resp_type='content')
    return f"Initiated snapshot creation request for {con_name}.", {}, {}


def delete_snapshot(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    snapshot_id = data_args.get('snapshot-id')
    client.do_request('DELETE', f'/plugin/products/trace/conns/{con_name}/snapshots/{snapshot_id}', resp_type='content')
    context = {
        'ConnectionName': con_name,
        'ID': snapshot_id,
        'Deleted': True
    }
    outputs = {'Tanium.Snapshot(val.ID === obj.ID && val.ConnectionName === obj.ConnectionName)': context}
    return f"Snapshot {snapshot_id} deleted successfully.", outputs, {}


def get_local_snapshots(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    conn_name = data_args.get('connection-name')
    raw_response = client.do_request('GET', '/plugin/products/trace/locals/')
    snapshots = get_local_snapshot_items(raw_response, limit, offset, conn_name)
    context = createContext(snapshots, removeNull=True)
    outputs = {
        'Tanium.LocalSnapshot(val.FileName === obj.FileName && val.ConnectionName === obj.ConnectionName)': context
    }
    headers = ['FileName', 'ConnectionName']
    human_readable = tableToMarkdown(f'Local snapshots for connection {conn_name}', snapshots, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def delete_local_snapshot(client, data_args):
    connection_name = data_args.get('connection-name')
    file_name = data_args.get('file-name')
    client.do_request('DELETE', f'/plugin/products/trace/locals/{connection_name}/{file_name}', resp_type='content')
    context = {
        'FileName': file_name,
        'Deleted': True
    }
    outputs = {'Tanium.LocalSnapshot(val.FileName === obj.FileName)': context}
    return f"Local snapshot {file_name} of connection {connection_name} was deleted successfully.", outputs, {}


def get_connections(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    raw_response = client.do_request('GET', '/plugin/products/trace/conns')
    connections = []

    from_idx = min(offset, len(raw_response))
    to_idx = min(offset + limit, len(raw_response))

    for conn in raw_response[from_idx:to_idx]:
        connections.append(get_connection_item(conn))

    context = createContext(connections, removeNull=True)
    outputs = {'Tanium.Connection(val.Name && val.Name === obj.Name)': context}
    headers = ['Name', 'State', 'Remote', 'CreateTime', 'DST', 'DestinationType', 'OSName']
    human_readable = tableToMarkdown('Connections', connections, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_connection(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    raw_response = client.do_request('GET', '/plugin/products/trace/conns')
    connection_raw_response: dict = {}
    found = False
    for conn in raw_response:
        if conn.get('name') and conn['name'] == conn_name:
            connection_raw_response = conn
            found = True
            break

    if not found:  # Should not get here
        return 'Connection not found.', {}, {}

    connection = get_connection_item(connection_raw_response)

    context = createContext(connection, removeNull=True)
    outputs = {'Tanium.Connection(val.Name && val.Name === obj.Name)': context}
    headers = ['Name', 'State', 'Remote', 'CreateTime', 'DST', 'DestinationType', 'OSName']
    human_readable = tableToMarkdown('Connection information', connection, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, connection_raw_response


def create_connection(client, data_args):
    remote = bool(data_args.get('remote'))
    dst_type = data_args.get('destination-type')
    dst = validate_connection_name(client, data_args.get('destination'),
                                   argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    conn_timeout = data_args.get('connection-timeout')

    body = {
        "remote": remote,
        "dst": dst,
        "dstType": dst_type,
        "connTimeout": conn_timeout}

    if conn_timeout:
        body['connTimeout'] = int(data_args.get('connection-timeout'))

    client.do_request('POST', '/plugin/products/trace/conns/', data=body, resp_type='content')
    return f"Initiated connection request to {dst}.", {}, {}


def delete_connection(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    client.do_request('DELETE', '/plugin/products/trace/conns/{conn_name}', resp_type='text')
    context = {
        'Name': conn_name,
        'Deleted': True
    }
    outputs = {'Tanium.Connection(val.Name && val.Name === obj.Name)': context}
    return f"Connection {conn_name} deleted successfully.", outputs, {}


def get_labels(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/labels/')

    from_idx = min(offset, len(raw_response))
    to_idx = min(offset + limit, len(raw_response))

    labels = []
    for item in raw_response[from_idx:to_idx]:
        label = get_label_item(item)
        labels.append(label)

    context = createContext(labels, removeNull=True)
    outputs = {'Tanium.Label(val.ID && val.ID === obj.ID)': context}
    headers = ['Name', 'Description', 'ID', 'IndicatorCount', 'SignalCount', 'CreatedAt', 'UpdatedAt']
    human_readable = tableToMarkdown('Labels', labels, headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_label(client, data_args):
    label_id = data_args.get('label-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/labels/{label_id}')
    label = get_label_item(raw_response)

    context = createContext(label, removeNull=True)
    outputs = {'Tanium.Label(val.ID && val.ID === obj.ID)': context}
    headers = ['Name', 'Description', 'ID', 'IndicatorCount', 'SignalCount', 'CreatedAt', 'UpdatedAt']
    human_readable = tableToMarkdown('Label information', label, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_file_downloads(client, data_args):
    data_args = {key: val for key, val in data_args.items() if val is not None}
    raw_response = client.do_request('GET', '/plugin/products/trace/filedownloads/', params=data_args)

    files = []
    for item in raw_response:
        file = get_file_download_item(item)
        files.append(file)

    context = createContext(files, removeNull=True)
    outputs = {'Tanium.FileDownload(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Host', 'Path', 'Hash', 'Downloaded', 'Size', 'Created', 'CreatedBy', 'CreatedByProc',
               'LastModified', 'LastModifiedBy', 'LastModifiedByProc', 'SPath', 'Comments', 'Tags']
    human_readable = tableToMarkdown('File downloads', files, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_downloaded_file(client, data_args):
    file_id = data_args.get('file-id')
    file_content, content_desc = client.do_request('GET', f'/plugin/products/trace/filedownloads/{file_id}',
                                                   resp_type='content')

    filename = re.findall(r"filename\*=UTF-8\'\'(.+)", content_desc)[0]

    demisto.results(fileResult(filename, file_content))


def filter_to_tanium_api_syntax(filter_str):
    filter_dict = {}
    try:
        if filter_str:
            filter_expressions = ast.literal_eval(filter_str)
            for i, expression in enumerate(filter_expressions):
                filter_dict['f' + str(i)] = expression[0]
                filter_dict['o' + str(i)] = expression[1]
                filter_dict['v' + str(i)] = expression[2]
        return filter_dict
    except IndexError:
        raise ValueError('Invalid filter argument.')


def get_events_by_connection(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    connection = validate_connection_name(client, data_args.get('connection-name'),
                                          argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    sort = data_args.get('sort')
    fields = data_args.get('fields')
    event_type = data_args.get('event-type').lower()
    filter_dict = filter_to_tanium_api_syntax(data_args.get('filter'))
    match = data_args.get('match')

    params = {
        'limit': limit,
        'offset': offset,
        'sort': sort,
        'fields': fields,
        'match': match
    }

    if filter_dict:
        g1 = ','.join([str(i) for i in range(len(filter_dict) // 3)])  # A weird param that must be passed
        params['gm1'] = match
        params['g1'] = g1
        params.update(filter_dict)

    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{connection}/{event_type}/events/',
                                     params=params)

    events = []
    for item in raw_response:
        event = get_event_item(item, event_type)
        events.append(event)

    context = createContext(events, removeNull=True)
    outputs = {'TaniumEvent(val.ID === obj.ID)': context}
    headers = get_event_header(event_type)
    human_readable = tableToMarkdown(f'Events for {connection}', events, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_file_download_info(client, data_args):
    if not data_args.get('path') and not data_args.get('id'):
        raise ValueError('At least one of the arguments `path` or `id` must be set.')

    data_args = {key: val for key, val in data_args.items() if val is not None}

    raw_response = client.do_request('GET', '/plugin/products/trace/filedownloads/', params=data_args)
    if not raw_response:
        raise ValueError('File download does not exist.')

    file = get_file_download_item(raw_response[0])
    context = createContext(file, removeNull=True)
    outputs = {'Tanium.FileDownload(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Host', 'Path', 'Hash', 'Downloaded', 'Size', 'Created', 'CreatedBy', 'CreatedByProc',
               'LastModified', 'LastModifiedBy', 'LastModifiedByProc', 'SPath', 'Comments', 'Tags']
    human_readable = tableToMarkdown(f'File download metadata for file `{file["Path"]}`', file, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_process_info(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/processes/{ptid}')
    process = get_process_item(raw_response)

    context = createContext(process, removeNull=True)
    outputs = {'Tanium.Process(val.ProcessID && val.ProcessID === obj.ProcessID)': context}
    headers = ['ProcessID', 'ProcessName', 'ProcessCommandLine', 'ProcessTableId', 'SID', 'Username', 'Domain',
               'ExitCode', 'CreateTime']
    human_readable = tableToMarkdown(f'{PROCESS_TEXT} {ptid}', process, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_events_by_process(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/processevents/{ptid}',
                                     params={'limit': limit, 'offset': offset})

    events = []
    for item in raw_response:
        event = get_process_event_item(item)
        events.append(event)

    context = createContext(events, removeNull=True)
    outputs = {'Tanium.ProcessEvent(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Detail', 'Type', 'Timestamp', 'Operation']
    human_readable = tableToMarkdown(f'Events for process {ptid}', events, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_process_children(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/processtrees/{ptid}/children')

    children = []
    children_human_readable = []
    for item in raw_response:
        child, readable_output = get_process_tree_item(item, 1)
        children.append(child)
        children_human_readable.append(readable_output)

    context = createContext(children, removeNull=True)
    outputs = {'Tanium.ProcessChildren(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Name', 'PID', 'PTID', 'Parent', 'Children', 'ChildrenCount']
    human_readable = tableToMarkdown(f'{PROCESS_CHILDREN_TEXT} {ptid}', children_human_readable, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_parent_process(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/parentprocesses/{ptid}')
    process = get_process_item(raw_response)

    context = createContext(process, removeNull=True)
    outputs = {'Tanium.ParentProcess(val.ProcessID && val.ProcessID === obj.ProcessID)': context}
    headers = ['ProcessID', 'ProcessName', 'ProcessCommandLine', 'ProcessTableId', 'SID', 'Username', 'Domain',
               'ExitCode', 'CreateTime']
    human_readable = tableToMarkdown(f'{PROCESS_TEXT} {ptid}', process, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_parent_process_tree(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/parentprocesstrees/{ptid}')

    if not raw_response:
        raise ValueError('Failed to parse tanium-tr-get-parent-process-tree response.')

    tree, readable_output = get_process_tree_item(raw_response[0], 0)

    children_item = readable_output.get('Children')

    headers = ['ID', 'Name', 'PID', 'PTID', 'Parent', 'Children', 'ChildrenCount']
    if children_item:
        process_tree = readable_output.copy()
        del process_tree['Children']
        headers = ['ID', 'Name', 'PID', 'PTID', 'Parent', 'Children', 'ChildrenCount']

        human_readable = tableToMarkdown(f'{PARENT_PROCESS_TEXT} {ptid}', process_tree, headers=headers,
                                         headerTransform=pascalToSpace, removeNull=True)
        human_readable += tableToMarkdown('Processes with the same parent', children_item, headers=headers,
                                          headerTransform=pascalToSpace, removeNull=True)
    else:
        human_readable = tableToMarkdown(f'{PARENT_PROCESS_TEXT} {ptid}', readable_output, headers=headers,
                                         headerTransform=pascalToSpace, removeNull=True)

    context = createContext(tree, removeNull=True)
    outputs = {'Tanium.ParentProcessTree(val.ID && val.ID === obj.ID)': context}

    return human_readable, outputs, raw_response


def get_process_tree(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/processtrees/{ptid}')

    if not raw_response:
        raise ValueError('Failed to parse tanium-tr-get-process-tree response.')

    tree, readable_output = get_process_tree_item(raw_response[0], 0)
    headers = ['ID', 'Name', 'PID', 'PTID', 'Parent', 'Children', 'ChildrenCount']

    children_item = readable_output.get('Children')

    if children_item:
        process_tree = readable_output.copy()
        del process_tree['Children']
        human_readable = tableToMarkdown(f'Process information for process with PTID {ptid}', process_tree,
                                         headers=headers, headerTransform=pascalToSpace, removeNull=True)
        human_readable += tableToMarkdown(f'{PROCESS_CHILDREN_TEXT} {ptid}', children_item,
                                          headers=headers, headerTransform=pascalToSpace, removeNull=True)
    else:
        human_readable = tableToMarkdown(f'{PROCESS_TEXT} {ptid}', readable_output,
                                         headers=headers, headerTransform=pascalToSpace, removeNull=True)

    context = createContext(tree, removeNull=True)
    outputs = {'Tanium.ProcessTree(val.ID && val.ID === obj.ID)': context}

    return human_readable, outputs, raw_response


def list_evidence(client, data_args):
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))
    sort = data_args.get('sort')
    params = {
        'sort': sort,
        'limit': limit,
        'offset': offset
    }
    raw_response = client.do_request('GET', '/plugin/products/trace/evidence', params=params)

    evidences = []
    for item in raw_response:
        evidence = get_evidence_item(item)
        evidences.append(evidence)

    context = createContext(evidences, removeNull=True)
    outputs = {'Tanium.Evidence(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Timestamp', 'ConnectionName', 'User', 'Summary', 'Type', 'CreatedAt', 'UpdatedAt',
               'ProcessTableId', 'Comments', 'Tags']
    human_readable = tableToMarkdown('Evidence list', evidences, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_evidence(client, data_args):
    evidence_id = data_args.get('evidence-id')
    raw_response = client.do_request('GET', f'/plugin/products/trace/evidence/{evidence_id}')
    if not raw_response:
        raise DemistoException(f'Evidence {evidence_id} was not found.')
    evidence = get_evidence_item(raw_response)

    context = createContext(evidence, removeNull=True)
    outputs = {'Tanium.Evidence(val.ID && val.ID === obj.ID)': context}
    headers = ['ID', 'Timestamp', 'Host', 'User', 'Summary', 'ConntectionID', 'Type', 'CreatedAt', 'UpdatedAt',
               'ProcessTableId', 'Comments', 'Tags']
    human_readable = tableToMarkdown('Label information', evidence, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def create_evidence(client, data_args):
    conn_name = validate_connection_name(client, data_args.get('connection-name'),
                                         argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')

    params = {'match': 'all', 'f1': 'process_table_id', 'o1': 'eq', 'v1': ptid}
    process_data = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}/process/events', params=params)

    if not process_data:
        raise ValueError('Invalid connection-name or ptid.')

    data = {
        'host': conn_name,
        'user': client.username,
        'data': process_data[0],
        'connId': conn_name,
        'type': 'ProcessEvent',
        'sTimestamp': process_data[0].get('create_time'),
        'sId': ptid
    }

    client.do_request('POST', '/plugin/products/trace/evidence', data=data, resp_type='content')
    return "Evidence have been created.", {}, {}


def delete_evidence(client, data_args):
    evidence_id = data_args.get('evidence-id')
    client.do_request('DELETE', f'/plugin/products/trace/evidence/{evidence_id}', resp_type='content')
    context = {
        'ID': int(evidence_id),
        'Deleted': True
    }
    outputs = {'Tanium.Evidence(val.ID === obj.ID)': context}
    return f"Evidence {evidence_id} has been deleted successfully.", outputs, {}


def request_file_download(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    path = data_args.get('path')

    # context object will help us to verify the request has succeed in the download file playbook.
    context = {
        'ConnectionName': con_name,
        'Path': path,
        'Downloaded': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    }
    outputs = {'Tanium.FileDownload(val.Path === obj.Path && val.ConnectionName === obj.ConnectionName)': context}

    data = {
        'path': path,
        'connId': con_name
    }
    client.do_request('POST', '/plugin/products/trace/filedownloads', data=data, resp_type='text')
    filename = os.path.basename(path)
    return f"Download request of file {filename} has been sent successfully.", outputs, {}


def get_file_download_request_status(client, data_args):
    downloaded = str(data_args.get('request-date')).replace('T', ' ')
    host = data_args.get('connection-name')
    path = data_args.get('path')

    params = {'downloaded>': downloaded}
    if host:
        params['host'] = host
    if path:
        params['path'] = path

    raw_response = client.do_request('GET', '/plugin/products/trace/filedownloads', params=params)
    if raw_response:
        file_id = raw_response[0].get('id')
        status = 'Completed'
        downloaded = raw_response[0].get('downloaded')
        path = path if path else raw_response[0].get('path')
        host = host if host else raw_response[0].get('host')
    else:
        file_id = None
        status = 'Not found'

    file_download_request = {
        'ID': file_id,
        'ConnectionName': host,
        'Path': path,
        'Status': status,
        'Downloaded': downloaded
    }

    context = createContext(file_download_request, removeNull=True)
    outputs = {'Tanium.FileDownload(val.Path === obj.Path && val.ConnectionName === obj.ConnectionName)': context}
    headers = ['ID', 'ConnectionName', 'Status', 'Path', 'Downloaded']
    human_readable = tableToMarkdown('File download request status', file_download_request,
                                     headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def delete_file_download(client, data_args):
    file_id = data_args.get('file-id')
    client.do_request('DELETE', f'/plugin/products/trace/filedownloads/{file_id}', resp_type='text')
    context = {
        'ID': int(file_id),
        'Deleted': True
    }
    outputs = {'Tanium.FileDownload(val.ID && val.ID === obj.ID)': context}
    return f"Delete request of file with ID {file_id} has been sent successfully.", outputs, {}


def list_files_in_dir(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    dir_path_name = data_args.get('path')
    dir_path = urllib.parse.quote(dir_path_name, safe='')
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))

    raw_response = client.do_request('GET', f'/plugin/products/trace/filedownloads/{con_name}/list/{dir_path}')

    files = []
    from_idx = min(offset, len(raw_response))
    to_idx = min(offset + limit, len(raw_response))

    for file in raw_response[from_idx:to_idx]:
        files.append(get_file_item(file, con_name, dir_path_name))

    context = createContext(files, removeNull=True)
    outputs = {'Tanium.File(val.Path === obj.Path && val.ConnectionName === obj.ConnectionName)': context}
    headers = ['Path', 'Size', 'Created', 'LastModified', 'Permissions', 'IsDirectory']
    human_readable = tableToMarkdown(f'Files in directory `{dir_path_name}`', files,
                                     headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def get_file_info(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    path_name = data_args.get('path')
    path = urllib.parse.quote(path_name, safe='')

    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{con_name}/fileinfo/{path}')
    file_info = get_file_item(raw_response, con_name, full_path=path_name)

    context = createContext(file_info, removeNull=True)
    outputs = {'Tanium.File(val.Path === obj.Path && val.ConnectionName === obj.ConnectionName)': context}
    headers = ['Path', 'ConnectionName', 'Size', 'Created', 'LastModified', 'Permissions', 'IsDirectory']
    human_readable = tableToMarkdown(f'Information for file `{path_name}`', file_info,
                                     headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def delete_file_from_endpoint(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    path = urllib.parse.quote(data_args.get('path'))
    client.do_request('DELETE', f'/plugin/products/trace/filedownloads/{con_name}/{path}', resp_type='text')
    context = {
        'Path': data_args.get('path').replace("\\", "/"),
        'ConnectionName': con_name,
        'Deleted': True
    }
    outputs = {'Tanium.File(val.Path === obj.Path && val.ConnectionName === obj.ConnectionName)': context}
    return f"Delete request of file {path} from endpoint {con_name} has been sent successfully.", outputs, {}


def get_process_timeline(client, data_args):
    con_name = validate_connection_name(client, data_args.get('connection-name'),
                                        argToBoolean(data_args.get('skip_conn_name_validation', 'False')))
    ptid = data_args.get('ptid')
    category = data_args.get('category')
    limit = int(data_args.get('limit'))
    offset = int(data_args.get('offset'))

    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{con_name}/eprocesstimelines/{ptid}')
    timeline = get_process_timeline_item(raw_response, category, limit, offset)

    context = createContext(timeline, removeNull=True)
    outputs = {'Tanium.ProcessTimeline(val.ProcessTableID && val.ProcessTableID === obj.ProcessTableID)': context}
    headers = ['Date', 'Event', 'Category']
    human_readable = tableToMarkdown(f'Timeline data for process with PTID `{ptid}`', timeline,
                                     headers=headers, headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


def fetch_incidents(client, alerts_states_to_retrieve):
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
    # Get the last fetch time and data if it exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format=DATE_FORMAT)

    last_fetch = parse(last_fetch)
    current_fetch = last_fetch

    url_suffix = '/plugin/products/detect3/api/v1/alerts?' + state_params_suffix(alerts_states_to_retrieve)

    raw_response = client.do_request('GET', url_suffix)

    # convert the data/events to demisto incidents
    incidents = []
    for alarm in raw_response:
        incident = alarm_to_incident(client, alarm)
        temp_date = parse(incident.get('occurred'))

        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date + timedelta(seconds=1)

        # avoid duplication due to weak time query
        if temp_date > current_fetch:
            incidents.append(incident)

    demisto.setLastRun({'time': datetime.strftime(last_fetch, DATE_FORMAT)})
    return demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')

    # Remove trailing slash to prevent wrong URL path to service
    server = params['url'].strip('/')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)

    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()
    client = Client(server, username, password, verify=use_ssl)
    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'tanium-tr-get-intel-doc-by-id': get_intel_doc,
        'tanium-tr-list-intel-docs': get_intel_docs,
        'tanium-tr-list-alerts': get_alerts,
        'tanium-tr-get-alert-by-id': get_alert,
        'tanium-tr-alert-update-state': alert_update_state,
        'tanium-tr-list-snapshots-by-connection': get_snapshots,
        'tanium-tr-create-snapshot': create_snapshot,
        'tanium-tr-delete-snapshot': delete_snapshot,
        'tanium-tr-list-local-snapshots-by-connection': get_local_snapshots,
        'tanium-tr-delete-local-snapshot': delete_local_snapshot,
        'tanium-tr-list-connections': get_connections,
        'tanium-tr-get-connection-by-name': get_connection,
        'tanium-tr-create-connection': create_connection,
        'tanium-tr-delete-connection': delete_connection,
        'tanium-tr-list-labels': get_labels,
        'tanium-tr-get-label-by-id': get_label,
        'tanium-tr-list-events-by-connection': get_events_by_connection,
        'tanium-tr-get-process-info': get_process_info,
        'tanium-tr-get-events-by-process': get_events_by_process,
        'tanium-tr-get-process-children': get_process_children,
        'tanium-tr-get-parent-process': get_parent_process,
        'tanium-tr-get-parent-process-tree': get_parent_process_tree,
        'tanium-tr-get-process-tree': get_process_tree,
        'tanium-tr-list-evidence': list_evidence,
        'tanium-tr-get-evidence-by-id': get_evidence,
        'tanium-tr-create-evidence': create_evidence,
        'tanium-tr-delete-evidence': delete_evidence,
        'tanium-tr-list-file-downloads': get_file_downloads,
        'tanium-tr-get-file-download-info': get_file_download_info,
        'tanium-tr-request-file-download': request_file_download,
        'tanium-tr-get-download-file-request-status': get_file_download_request_status,
        'tanium-tr-delete-file-download': delete_file_download,
        'tanium-tr-list-files-in-directory': list_files_in_dir,
        'tanium-tr-get-file-info': get_file_info,
        'tanium-tr-delete-file-from-endpoint': delete_file_from_endpoint,
        'tanium-tr-get-process-timeline': get_process_timeline
    }

    try:
        if command == 'fetch-incidents':
            alerts_states_to_retrieve = demisto.params().get('filter_alerts_by_state')
            return fetch_incidents(client, alerts_states_to_retrieve)
        if command == 'tanium-tr-get-downloaded-file':
            return get_downloaded_file(client, demisto.args())

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    except Exception as e:
        import traceback
        if command == 'fetch-incidents':
            LOG(traceback.format_exc())
            LOG.print_log()
            raise

        else:
            error_msg = str(e)
            if command in COMMANDS_DEPEND_ON_CONNECTIVITY:
                error_msg += DEPENDENT_COMMANDS_ERROR_MSG
            return_error('Error in Tanium Threat Response Integration: {}'.format(error_msg), traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
