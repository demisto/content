
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' GLOBALS/PARAMS '''
FETCH_TIME = demisto.params().get('fetch_time')
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

ALERT_TYPE_FROM_REQUEST = {'unresolved': 'Unresolved', 'inprogress': 'In Progress', 'ignored': 'Ignored', 'resolved': 'Resolved'}
ALERT_TYPE_TO_REQUEST = {'Unresolved': 'unresolved', 'In Progress': 'inprogress', 'Ignored': 'ignored', 'Resolved': 'resolved'}


class Client(BaseClient):
    def __init__(self, base_url, username, password, domain, **kwargs):
        self.username = username
        self.password = password
        self.domain = domain
        self.session = ''
        super(Client, self).__init__(base_url, **kwargs)

    def do_request(self, method, url_suffix, data=None, params=None, resp_type='json'):
        if not self.session:
            self.update_session()

        res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                 params=params, resp_type='response', ok_codes=(200, 202, 204, 400, 403, 404))

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
            return res.json()
        if resp_type == 'text':
            return res.text
        if resp_type == 'content':
            return res.content

    def update_session(self):
        body = {
            'username': self.username,
            'domain': self.domain,
            'password': self.password
        }

        res = self._http_request('GET', '/api/v2/session/login', json_data=body, ok_codes=(200,))

        self.session = res.get('data').get('session')
        return self.session

    def login(self):
        return self.update_session()

    def alarm_to_incident(self, alarm):
        intel_doc_id = alarm.get('intelDocId', '')
        host = alarm.get('computerName', '')
        details = alarm.get('details')

        if details:
            details = json.loads(alarm['details'])
            alarm['details'] = details

        intel_doc = ''
        if intel_doc_id:
            raw_response = self.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}')
            intel_doc = raw_response.get('name')

        return {
            'name': f'{host} found {intel_doc}',
            'occurred': alarm.get('alertedAt'),
            'rawJSON': json.dumps(alarm)}

    def get_intel_doc_item(self, intel_doc):
        return {
            'ID': intel_doc.get('id'),
            'Name': intel_doc.get('name'),
            'Description': intel_doc.get('description'),
            'AlertCount': intel_doc.get('alertCount'),
            'UnresolvedAlertCount': intel_doc.get('unresolvedAlertCount'),
            'CreatedAt': intel_doc.get('createdAt'),
            'UpdatedAt': intel_doc.get('updatedAt'),
            'LabelIds': intel_doc.get('labelIds')}

    def get_alert_item(self, alert):
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
            'State': ALERT_TYPE_FROM_REQUEST[alert.get('state')],
            'Type': alert.get('type'),
            'UpdatedAt': alert.get('updatedAt')}

    def get_snapshot_items(self, raw_snapshots, limit):
        snapshots = []
        count = 0

        for host in raw_snapshots.items():
            for key in host[1].items():
                snapshots.append({
                    'DirectoryName': host[0],
                    'FileName': key[0],
                    'Started': key[1].get('started', ''),
                    'State': key[1].get('state', ''),
                    'Error': key[1].get('error', ''),
                })
                count += 1
                if count == limit:
                    return snapshots

        return snapshots

    def get_local_snapshot_items(self, raw_snapshots, limit):
        snapshots = []
        count = 0

        for host in raw_snapshots.items():
            for snapshot in host[1]:
                snapshots.append({
                    'DirectoryName': host[0],
                    'FileName': snapshot
                })
                count += 1
                if count == limit:
                    return snapshots

        return snapshots

    def get_connection_item(self, connection, name):
        return {
            'Name': name,
            'State': connection.get('state'),
            'CreateTime': connection.get('createTime'),
            'DST': connection.get('dst'),
            'Remote': connection.get('remote')}

    def get_label_item(self, label):
        return {
            'ID': label.get('id'),
            'Name': label.get('name'),
            'Description': label.get('description'),
            'IndicatorCount': label.get('indicatorCount'),
            'SignalCount': label.get('signalCount'),
            'CreatedAt': label.get('createdAt'),
            'UpdatedAt': label.get('updatedAt')}


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client, data_args):
    if client.login():
        return demisto.results('ok')
    raise ValueError('Test Tanium integration failed - please check your username and password')


def get_intel_doc(client, data_args):
    id_ = data_args.get('intel-doc-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{id_}')
    intel_doc = client.get_intel_doc_item(raw_response)

    context = createContext(intel_doc, removeNull=True)
    outputs = {'Tanium.IntelDoc(val.ID && val.ID === obj.ID)': context}

    intel_doc['LabelIds'] = str(intel_doc['LabelIds']).strip('[]')
    human_readable = tableToMarkdown('Intel Doc information', intel_doc)
    return human_readable, outputs, raw_response


def get_intel_docs(client, data_args):
    limit = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/intels/', params={'limit': limit})

    intel_docs = []
    for item in raw_response:
        intel_doc = client.get_intel_doc_item(item)
        intel_docs.append(intel_doc)

    context = createContext(intel_docs, removeNull=True)
    outputs = {'Tanium.IntelDoc(val.ID && val.ID === obj.ID)': context}

    for item in intel_docs:
        item['LabelIds'] = str(item['LabelIds']).strip('[]')

    human_readable = tableToMarkdown('Intel docs', intel_docs)
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
        params['state'] = ALERT_TYPE_TO_REQUEST[state]

    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/alerts/', params=params)

    alerts = []
    for item in raw_response:
        alert = client.get_alert_item(item)
        alerts.append(alert)

    context = createContext(alerts, removeNull=True)
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Alerts', alerts)
    return human_readable, outputs, raw_response


def get_alert(client, data_args):
    alert_id = data_args.get('alert-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/alerts/{alert_id}')
    alert = client.get_alert_item(raw_response)

    context = createContext(alert, removeNull=True)
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Alert information', alert)
    return human_readable, outputs, raw_response


def alert_update_state(client, data_args):
    alert_id = data_args.get('alert-id')
    state = data_args.get('state')

    body = {"state": ALERT_TYPE_TO_REQUEST[state]}
    raw_response = client.do_request('PUT', f'/plugin/products/detect3/api/v1/alerts/{alert_id}', data=body)
    alert = client.get_alert_item(raw_response)

    context = createContext(alert, removeNull=True)
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown(f'Alert state updated to {state}', alert)
    return human_readable, outputs, raw_response


def get_snapshots(client, data_args):
    limit = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/trace/snapshots/')
    snapshots = client.get_snapshot_items(raw_response, limit)
    context = createContext(snapshots, removeNull=True)
    outputs = {'Tanium.Snapshot(val.FileName && val.FileName === obj.FileName)': context}
    human_readable = tableToMarkdown('Snapshots', snapshots)
    return human_readable, outputs, raw_response


def create_snapshot(client, data_args):
    con_id = data_args.get('connection-id')
    client.do_request('POST', f'/plugin/products/trace/conns/{con_id}/snapshots', resp_type='content')
    return f"Initiated snapshot creation request for {con_id}.", {}, {}


def delete_snapshot(client, data_args):
    con_id = data_args.get('connection-id')
    snapshot_id = data_args.get('snapshot-id')
    client.do_request('DELETE', f'/plugin/products/trace/conns/{con_id}/snapshots/{snapshot_id}', resp_type='content')
    return f"Snapshot {snapshot_id} deleted successfully.", {}, {}


def get_local_snapshots(client, data_args):
    limit = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/trace/locals/')
    snapshots = client.get_local_snapshot_items(raw_response, limit)
    context = createContext(snapshots, removeNull=True)
    outputs = {'Tanium.LocalSnapshot.DirectoryName(val.FileName && val.FileName === obj.FileName)': context}
    human_readable = tableToMarkdown('Local snapshots', snapshots)
    return human_readable, outputs, raw_response


def delete_local_snapshot(client, data_args):
    directory_name = data_args.get('directory-name')
    file_name = data_args.get('file-name')
    client.do_request('DELETE', f'/plugin/products/trace/locals/{directory_name}/{file_name}', resp_type='content')
    return f"Local snapshot from Directory {directory_name} and File {file_name} is deleted successfully.", {}, {}


def get_connections(client, data_args):
    limit = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/trace/conns')
    connections = []

    for conn in raw_response[:limit]:
        connections.append(client.get_connection_item(conn.get('info'), conn.get('name')))

    context = createContext(connections, removeNull=True)
    outputs = {'Tanium.Connection(val.Name && val.Name === obj.Name)': context}
    human_readable = tableToMarkdown('Connections', connections)
    return human_readable, outputs, raw_response


def get_connection(client, data_args):
    conn_name = data_args.get('connection-name')
    raw_response = client.do_request('GET', f'/plugin/products/trace/conns/{conn_name}')
    connection = client.get_connection_item(raw_response, conn_name)

    context = createContext(connection, removeNull=True)
    outputs = {'Tanium.Connection(val.Name && val.Name === obj.Name)': context}
    human_readable = tableToMarkdown('Connection details', connection)
    return human_readable, outputs, raw_response


def create_connection(client, data_args):
    remote = bool(data_args.get('remote'))
    dst_type = data_args.get('destination-type')
    dst = data_args.get('destination')
    conn_timeout = data_args.get('connection-timeout')

    body = {
        "remote": remote,
        "dst": dst,
        "dstType": dst_type,
        "connTimeout": conn_timeout}

    if conn_timeout:
        body['connTimeout'] = int(data_args.get('connection-timeout'))

    client.do_request('POST', f'/plugin/products/trace/conns/', data=body, resp_type='content')
    return f"Initiated connection request to {dst}.", {}, {}


def delete_connection(client, data_args):
    conn_id = data_args.get('connection-id')
    client.do_request('DELETE', f'/plugin/products/trace/conns/{conn_id}', resp_type='text')
    return f"Connection {conn_id} deleted successfully.", {}, {}


def get_labels(client, data_args):
    limit = int(data_args.get('limit'))
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/labels/', params={'limit': limit})

    labels = []
    for item in raw_response:
        label = client.get_label_item(item)
        labels.append(label)

    context = createContext(labels, removeNull=True)
    outputs = {'Tanium.Label(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Labels', labels)
    return human_readable, outputs, raw_response


def get_label(client, data_args):
    label_id = data_args.get('label-id')
    raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/labels/{label_id}')
    label = client.get_label_item(raw_response)

    context = createContext(label, removeNull=True)
    outputs = {'Tanium.Label(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Label details', label)
    return human_readable, outputs, raw_response


def fetch_incidents(client):
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

    last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)
    current_fetch = last_fetch
    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/alerts')

    # convert the data/events to demisto incidents
    incidents = []
    for alarm in raw_response:
        incident = client.alarm_to_incident(alarm)
        temp_date = datetime.strptime(incident.get('occurred'), DATE_FORMAT)

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
    domain = params.get('domain')
    # Remove trailing slash to prevent wrong URL path to service
    server = params['url'].strip('/')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)

    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()
    client = Client(server, username, password, domain, verify=use_ssl)
    demisto.info(f'Command being called is {command}')

    commands = {
        f'test-module': test_module,
        f'tanium-tr-get-intel-doc-by-id': get_intel_doc,
        f'tanium-tr-list-intel-docs': get_intel_docs,
        f'tanium-tr-list-alerts': get_alerts,
        f'tanium-tr-get-alert-by-id': get_alert,
        f'tanium-tr-alert-update-state': alert_update_state,
        f'tanium-tr-list-snapshots': get_snapshots,
        f'tanium-tr-create-snapshot': create_snapshot,
        f'tanium-tr-delete-snapshot': delete_snapshot,
        f'tanium-tr-list-local-snapshots': get_local_snapshots,
        f'tanium-tr-delete-local-snapshot': delete_local_snapshot,
        f'tanium-tr-list-connections': get_connections,
        f'tanium-tr-get-connection-by-name': get_connection,
        f'tanium-tr-create-connection': create_connection,
        f'tanium-tr-delete-connection': delete_connection,
        f'tanium-tr-list-labels': get_labels,
        f'tanium-tr-get-label-by-id': get_label
    }

    try:
        if command == 'fetch-incidents':
            return fetch_incidents(client)

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        # Log exceptions
    except Exception as e:
        err_msg = f'Error in Tanium v2 Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
