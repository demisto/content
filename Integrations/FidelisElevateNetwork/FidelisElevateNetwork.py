import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import json
import shutil
import requests
import random
import urllib
# disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS / PARAMS '''
IS_FETCH = demisto.params().get('isFetch')
SERVER_URL = demisto.params().get('server_url', '')
CREDENTIALS = demisto.params().get('credentials')
INSECURE = demisto.params().get('unsecure')
PROXY = demisto.params().get('proxy')
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
SESSION_ID = None
ALERT_UUID_REGEX = re.compile('[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}')


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, files=None, is_json=True):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    headers = {}  # type: Dict[str, str]
    if SESSION_ID is not None:
        headers['x-uid'] = SESSION_ID
    if files is None:
        headers['Content-Type'] = 'application/json'

    res = requests.request(
        method,
        SERVER_URL + url_suffix,
        data=None if data is None else json.dumps(data),
        headers=headers,
        params=params,
        files=files,
        verify=not INSECURE,
    )
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        if res.status_code == 500:
            try:
                error = res.json().get('detailMessage', res.content)

            except:  # noqa
                error = res.content

            raise Exception('Error in API call to Fidelis Integration [%d] - %s' % (res.status_code, error))
        else:
            raise Exception('Error in API call to Fidelis Integration [%d] - %s' % (res.status_code, res.reason))

    if is_json:
        try:
            return res.json()

        except ValueError:
            return_error('failed to parse json object from response: {}'.format(res.content))

    else:
        return res.content


@logger
def login():
    global SESSION_ID

    data = {
        'user': CREDENTIALS.get('identifier'),
        'password': CREDENTIALS.get('password')
    }

    if SESSION_ID is None:
        url = '/j/rest/v1/access/login/json/'
        try:
            res = http_request('POST', url, data=data)
            if res.get('error') is not None:
                raise requests.HTTPError('Failed to login: {}'.format(res['error']))
            SESSION_ID = res.get('uid')
        except requests.exceptions.RequestException as e:  # noqa
            return_error('Demisto has encounter a connection error, '
                         'please check the server_url and credentials parameters')


def logout():
    global SESSION_ID
    if SESSION_ID is not None:
        try:
            url = '/j/rest/v1/access/logout/{}/'.format(SESSION_ID)
            http_request('GET', url)
            SESSION_ID = None

        except:  # noqa
            pass


def generate_pagination():
    return {
        'getLast': False,
        'page': 1,
        'referenceTime': '',
        'size': 200,
        'supportPaging': True,
    }


def get_ioc_filter(ioc):
    if re.match(ipv4Regex, ioc):
        return {'simple': {'column': 'ANY_IP', 'operator': '=', 'value': ioc}}
    elif md5Regex.match(ioc):
        return {'simple': {'column': 'MD5', 'operator': '=', 'value': ioc}}
    elif sha256Regex.match(ioc):
        return {'simple': {'column': 'SHA256', 'operator': '=', 'value': ioc}}
    elif sha1Regex.match(ioc):
        return {'simple': {'column': 'SHA1_HASH', 'operator': '=', 'value': ioc}}
    elif ALERT_UUID_REGEX.match(ioc):
        return {'simple': {'column': 'UUID', 'operator': '=', 'value': ioc}}
    else:
        return {'simple': {'column': 'ANY_STRING', 'operator': '=~', 'value': ioc}}


def to_fidelis_time_format(t):
    if isinstance(t, STRING_TYPES):
        try:
            t = datetime.strptime(t, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            t = datetime.strptime(t, '%Y-%m-%dT%H:%M:%S')

    return datetime.strftime(t, '%Y-%m-%d %H:%M:%S')


def generate_time_settings(time_frame=None, start_time=None, end_time=None):
    # default value
    settings = {
        'from': '',
        'to': '',
        'key': 'all',
        'value': '',
    }

    if time_frame is None:
        return settings
    elif time_frame in ['Today', 'Yesterday']:
        settings['key'] = time_frame.lower()
    elif 'Last' in time_frame:
        settings['key'] = 'last'
        if time_frame == 'Last 7 Days':
            settings['value'] = '7:00:00:00'
        elif time_frame == 'Last 30 Days':
            settings['value'] = '30:00:00:00'
        elif time_frame == 'Last Hour':
            settings['value'] = '1:00:00'
        elif time_frame == 'Last 24 Hours':
            settings['value'] = '24:00:00'
        elif time_frame == 'Last 48 Hours':
            settings['value'] = '48:00:00'
        else:
            raise ValueError('Could not parse time frame: {}'.format(time_frame))

    elif time_frame == 'Custom':
        settings['key'] = 'custom'
        if start_time is None and end_time is None:
            raise ValueError('invalid custom time frame: need to specify one of start_time, end_time')
        if start_time is not None:
            settings['from'] = to_fidelis_time_format(start_time)
        if end_time is not None:
            settings['to'] = to_fidelis_time_format(end_time)

    return settings


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_alert_command():
    args = demisto.args()
    alert_id = args['alert_id']

    alert = get_alert(alert_id)

    output = {
        'ID': alert['alertId'],
        'ThreatScore': alert['fidelisScore'],
        'Time': alert['time'],
        'RuleID': alert['ruleId'],
        'RuleName': alert['rule'],
        'Summary': alert['summary'],
        'PolicyName': alert['policy'],
        'Severity': alert['severity'],
        'Protocol': alert['protocol'],
        'Type': alert['alertType'],
        'AlertUUID': alert['alertUUID'],
        'AssignedUser': alert['ticket']['assignedUserId'] if alert['ticket'] is not None else None,
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': alert,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Alert {}'.format(alert_id), output, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_alert(alert_id):
    return http_request('GET', '/j/rest/v1/alert/info/{}/'.format(alert_id))


def delete_alert_command():
    args = demisto.args()
    alert_id = args['alert_id'].split(',')

    delete_alert(alert_id)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': '\n'.join('Alert ({}) deleted successfully!'.format(_id) for _id in alert_id),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join('Alert ({}) deleted successfully!'.format(_id) for _id in alert_id),
    })


@logger
def delete_alert(alert_id):
    data = {
        'type': 'byAlertID',
        'alertIds': alert_id,
    }
    result = http_request('POST', '/j/rest/v1/alert/delete/', data=data)

    return result


def get_malware_data_command():
    args = demisto.args()
    alert_id = args['alert_id']

    result = get_malware_data(alert_id)

    output = {
        'ID': alert_id,
        'Malware': {
            'Name': result['malwareName'],
            'Behavior': result['malwareBehavior'],
            'Description': result['malwareDescription'],
            'DetailName': result['malwareDetailName'],
            'Platform': result['malwarePlatform'],
            'Type': result['malwareType'],
            'Variant': result['malwareVariant'],
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Alert {} Malware:'.format(alert_id), result, headerTransform=pascalToSpace),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_malware_data(alert_id):
    result = http_request('GET', '/j/rest/v1/alert/malware/{}/'.format(alert_id))

    return result


def get_alert_pcap_command():
    args = demisto.args()
    alert_id = args['alert_id']

    results = get_alert_pcap(alert_id)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('<INSERT TITLE HERE>', results),
    })


@logger
def get_alert_pcap(alert_id):
    # result = http_request('GET', '/j/rest/v1/alert/pcap/{}/'.format(alert_id), is_json=False)
    # return result
    raise NotImplementedError()


def get_alert_report_command():
    args = demisto.args()
    alert_id = int(args['alert_id'])

    pdf_content = get_alert_report(alert_id)

    demisto.results(fileResult(
        'Alert_Details_{}.pdf'.format(alert_id),
        pdf_content,
        file_type=entryTypes['entryInfoFile']
    ))


@logger
def get_alert_report(alert_id):
    result = http_request(
        'GET',
        '/j/rest/v1/alert/export/alertdetails/pdf',
        params={'alertIds': alert_id},
        is_json=False)

    return result


def sandbox_upload_command():
    args = demisto.args()
    upload_item = args['upload_item']

    results = sandbox_upload(upload_item)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('<INSERT TITLE HERE>', results),
        # 'EntryContext': create_context([indicator]),
    })


@logger
def sandbox_upload(upload_item):
    raise NotImplementedError()


def list_alerts_command():
    args = demisto.args()
    time_frame = args.get('time_frame')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    severity = args.get('severity')
    _type = args.get('type')
    threat_score = args.get('threat_score')
    ioc = args.get('ioc')

    results = list_alerts(time_frame=time_frame, start_time=start_time, end_time=end_time, severity=severity,
                          _type=_type, threat_score=threat_score, ioc=ioc)
    output = [{
        'ID': alert['ALERT_ID'],
        'Time': alert['ALERT_TIME'],
        'Summary': alert['SUMMARY'],
        'Severity': alert['SEVERITY'],
        'Type': alert['ALERT_TYPE'],
    } for alert in results]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Found {} Alerts:'.format(len(output)), output),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def list_alerts(time_frame=None, start_time=None, end_time=None, severity=None, _type=None,
                threat_score=None, ioc=None, additional_columns=None):
    columns = additional_columns if additional_columns is not None else []

    filters = [{'simple': {'column': 'ACTION', 'operator': '=', 'value': 'alert'}}]
    if severity is not None:
        filters.append({'simple': {'column': 'SEVERITY', 'operator': 'IN', 'value': severity}})
    if _type is not None:
        filters.append({'simple': {'column': 'ALERT_TYPE', 'operator': 'IN', 'value': _type}})
    if threat_score is not None:
        filters.append({'simple': {'column': 'FIDELIS_SCORE', 'operator': '>', 'value': threat_score}})
    if ioc is not None:
        filters.append(get_ioc_filter(ioc))

    data = {
        'columns': columns + ['ALERT_ID', 'ALERT_TIME', 'SUMMARY', 'SEVERITY', 'ALERT_TYPE', ],
        'filter': {
            'composite': {
                'logic': 'and',
                'filters': filters,
            }
        },
        'order': [{'column': 'ALERT_TIME', 'direction': 'DESC'}],
        'pagination': generate_pagination(),
        'timeSettings': generate_time_settings(time_frame, start_time, end_time)
    }
    res = http_request('POST', '/j/rest/v1/alert/search/', data=data)

    return res['aaData']


def list_alerts_by_ip_request(time_frame=None, start_time=None, end_time=None, src_ip=None, dest_ip=None):

    filters = []
    if src_ip is not None:
        filters.append({'simple': {'column': 'SRC_IP', 'operator': 'IN', 'value': src_ip}})
    if dest_ip is not None:
        filters.append({'simple': {'column': 'DEST_IP', 'operator': 'IN', 'value': dest_ip}})

    data = {
        'commandPosts': [],
        'filter': {
            'composite': {
                'logic': 'or',
                'filters': filters
            }
        },
        'order': [
            {
                'column': 'ALERT_TIME',
                'direction': 'DESC'
            }
        ],
        'pagination': {
            'page': 1,
            'size': 100
        },
        'columns': ['ALERT_TIME', 'UUID', 'ALERT_ID', 'DISTRIBUTED_ALERT_ID', 'USER_RATING', 'HOST_IP', 'ASSET_ID',
                    'ALERT_TYPE', 'DEST_COUNTRY_NAME', 'SRC_COUNTRY_NAME', 'DEST_IP', 'SRC_IP'],

        'timeSettings': generate_time_settings(time_frame, start_time, end_time)
    }

    res = http_request('POST', '/j/rest/v1/alert/search/', data=data)
    return res['aaData']


def list_alerts_by_ip():
    """
    List alerts by the source IP or destination IP
    """
    args = demisto.args()
    time_frame = args.get('time_frame')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    src_ip = args.get('src_ip')
    dest_ip = args.get('dest_ip')
    headers = ['Time', 'AlertUUID', 'ID', 'DistributedAlertID', 'UserRating', 'HostIP', 'AssetID',
               'Type', 'DestinationCountry', 'SourceCountry', 'DestinationIP', 'SourceIP']
    results = list_alerts_by_ip_request(time_frame=time_frame, start_time=start_time, end_time=end_time, src_ip=src_ip,
                                        dest_ip=dest_ip)
    output = [{
        'ID': alert.get('ALERT_ID'),
        'Time': alert.get('ALERT_TIME'),
        'AlertUUID': alert.get('UUID'),
        'DistributedAlertID': alert.get('DISTRIBUTED_ALERT_ID'),
        'Type': alert.get('ALERT_TYPE'),
        'UserRating': alert.get('USER_RATING'),
        'HostIP': alert.get('HOST_IP'),
        'AssetID': alert.get('ASSET_ID'),
        'DestinationCountry': alert.get('DEST_COUNTRY_NAME'),
        'SourceCountry': alert.get('SRC_COUNTRY_NAME'),
        'DestinationIP': alert.get('DEST_IP'),
        'SourceIP': alert.get('SRC_IP')
    } for alert in results]

    context = {
        'Fidelis.Alert(val.ID && val.ID == obj.ID)': output
    }

    return_outputs(tableToMarkdown('Found {} Alerts:'.format(len(output)), output, headers), context, results)


def get_alert_by_uuid():

    alert_uuid = demisto.args().get('alert_uuid')

    results = list_alerts(ioc=alert_uuid)

    output = [{
        'ID': alert['ALERT_ID'],
        'Time': alert['ALERT_TIME'],
        'Summary': alert['SUMMARY'],
        'Severity': alert['SEVERITY'],
        'Type': alert['ALERT_TYPE']
    } for alert in results]

    context = {
        'Fidelis.Alert(val.ID && val.ID == obj.ID)': output
    }

    return_outputs(tableToMarkdown('Found {} Alerts:'.format(len(output)), output), context, results)


def upload_pcap_command():
    args = demisto.args()
    component_ip = args['component_ip']
    entry_id = args['entry_id']

    upload_pcap(component_ip, entry_id)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'Pcap file uploaded successfully.',
    })


@logger
def upload_pcap(component_ip, entry_id):
    file_info = demisto.getFilePath(entry_id)
    shutil.copy(file_info['path'], file_info['name'])

    try:
        with open(file_info['name'], 'rb') as f:
            http_request('POST', '/j/rest/policy/pcap/upload/{}/'.format(component_ip),
                         files={'uploadFile': f}, is_json=False)
    finally:
        shutil.rmtree(file_info['name'], ignore_errors=True)


def run_pcap_command():
    args = demisto.args()
    component_ip = args['component_ip']
    file_names = args['files'].split(',')

    run_pcap(component_ip, file_names)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'Pcap file run submitted.',
    })


@logger
def run_pcap(component_ip, file_names):
    data = {
        'component': component_ip,
        'files': file_names
    }
    res = http_request('POST', '/j/rest/policy/pcap/run/', data=data)  # noqa


def list_pcap_components_command():
    results = list_pcap_components()
    output = [{
        'IP': r['ip'],
        'Name': r['name'],
    } for r in results]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('PCAP Components', output, headers=['Name', 'IP']),
        'EntryContext': {'Fidelis.Component(val.Name && val.Name == obj.Name)': output},
    })


@logger
def list_pcap_components():
    res = http_request('GET', '/j/rest/policy/pcap/components/')

    return res


def list_metadata_request(time_frame=None, start_time=None, end_time=None, client_ip=None, server_ip=None,
                          request_direction=None):

    filters = []
    if client_ip is not None:
        filters.append({'simple': {'column': 'ClientIP', 'operator': '=', 'value': client_ip}})
    if server_ip is not None:
        filters.append({'simple': {'column': 'ServerIP', 'operator': '=', 'value': server_ip}})
    if request_direction is not None:
        filters.append({'simple': {'column': 'Direction', 'operator': '=', 'value': request_direction}})
    search_id = str([random.randint(1, 9) for _ in range(8)])

    data = {
        'collectors': [],
        'action': 'new',
        'allCollectors': True,
        'timeSettings': generate_time_settings(time_frame, start_time, end_time),
        'displaySettings': {
            'pageSize': 1000,
            'currentPage': 1,
            'pageNavigation': "",
            'sorting': {
                'column': 'Timestamp',
                'sortingOrder': 'D'
            }
        },
        'dataSettings': {
            'composite': {
                'logic': 'and',
                'filters': filters
            }
        },
        'searchId': search_id
    }
    res = http_request('POST', '/j/rest/metadata/search/', data=data)

    return res.get('aaData')


def list_metadata():

    args = demisto.args()
    time_frame = args.get('time_frame')
    start_time = args.get('start_time')
    end_time = args.get('end_time')
    client_ip = args.get('client_ip')
    server_ip = args.get('server_ip')
    request_direction = args.get('request_direction')

    data = []
    event_context = []

    results = list_metadata_request(time_frame=time_frame, start_time=start_time, end_time=end_time,
                                    client_ip=client_ip, server_ip=server_ip, request_direction=request_direction)
    for event in results:
        data.append({
            'Timestamp': event.get('Timestamp'),
            'ServerIP': event.get('ServerIP'),
            'ServerPort': event.get('ServerPort'),
            'ClientIP': event.get('ClientIP'),
            'ClientPort': event.get('ClientPort')
        })

        event_context.append({
            'Timestamp': event.get('Timestamp'),
            'ServerIP': event.get('ServerIP'),
            'ServerPort': event.get('ServerPort'),
            'ServerCountry': event.get('ServerCountry'),
            'ClientIP': event.get('ClientIP'),
            'ClientPort': event.get('ClientPort'),
            'ClientCountry': event.get('ClientCountry'),
            'Type': event.get('Type'),
            'SensorUUID': event.get('SensorUUID'),
            'SessionStart': event.get('SessionStart'),
            'SessionDuration': event.get('SessionDuration'),
            'Protocol': event.get('Protocol'),
            'URL': event.get('URL'),
            'RequestDirection': event.get('RequestDirection'),
            'UserAgent': event.get('UserAgent'),
            'FileName': event.get('FileName'),
            'FileType': event.get('FileType'),
            'FileSize': event.get('FileSize'),
            'MD5': event.get('MD5'),
            'SHA256': event.get('SHA256'),
            'MalwareName': event.get('MalwareName'),
            'MalwareType': event.get('MalwareType'),
            'MalwareSeverity': event.get('MalwareSeverity'),
            'PcapFilename': event.get('PcapFilename'),
            'PcapTimestamp': event.get('PcapTimestamp')

        })
    context = {
        'Fidelis.Metadata(val.ID && val.ID == obj.ID)': event_context
    }

    return_outputs(tableToMarkdown('Found {} Metadata:'.format(len(data)), data), context, results)


def request_dpath(alert_id):

    res = http_request('GET', '/j/rest/v1/alert/dpath/{}/'.format(alert_id))
    dpath = res.get('decodingPaths')[0]
    link_path = dpath.get('linkPath')
    encoded_path = urllib.quote(link_path)
    return encoded_path


def download_malware_file_request(alert_id):

    dpath = request_dpath(alert_id)
    query_params = {
        'uid': SESSION_ID,
        'alert_id': alert_id,
        'type': '1',
        'params': dpath
    }
    res = http_request(
        'GET',
        '/query/tcpses_getfile.cgi',
        params=query_params,
        is_json=False)

    return res


def download_malware_file():
    """
    Download specific malware from the alert
    """
    alert_id = demisto.args().get('alert_id')
    file_name = request_dpath(alert_id)
    decoded_file_name = urllib.unquote(file_name)
    results = download_malware_file_request(alert_id)

    demisto.results(fileResult(
        decoded_file_name + '.zip',
        results,
        file_type=entryTypes['file']))


def download_pcap_request(alert_id):

    query_params = {
        'uid': SESSION_ID,
        'alert_id': alert_id,
        'commandpost': '127.0.0.1',
    }

    results = http_request(
        'GET',
        '/e.cgi',
        params=query_params,
        is_json=False
    )

    return results


def download_pcap_file():
    """
    Download PCAP from an alert
    """
    alert_id = demisto.args().get('alert_id')

    results = download_pcap_request(alert_id)
    demisto.results(fileResult(
        'Alert ID_' + alert_id + '.pcap',
        results,
        file_type=entryTypes['file']))


def test_integration():
    # the login is executed in the switch panel code
    if IS_FETCH:
        # just check the correctness of the parameter
        parse_date_range(FETCH_TIME)
    list_pcap_components()
    demisto.results('ok')


def fetch_incidents():
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format='%Y-%m-%dT%H:%M:%S')

    latest = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%S')

    demisto.debug('getting alarms since {}'.format(last_fetch))
    incidents = []
    items = list_alerts(time_frame='Custom', start_time=last_fetch)
    demisto.debug('got {} new alarms'.format(len(items)))
    for item in items:
        incident_date = datetime.strptime(item['ALERT_TIME'], '%Y-%m-%d %H:%M:%S')
        incident = {
            'Type': 'Fidelis',
            'name': '{} {}'.format(item['ALERT_ID'], item['SUMMARY']),
            'occurred': incident_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item),
        }
        latest = max(latest, incident_date)
        incidents.append(incident)

    if latest != last_fetch:
        last_fetch = (latest + timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%S')
        demisto.setLastRun({'time': last_fetch})

    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    try:
        handle_proxy()
        command = demisto.command()
        LOG('Command being called is {}'.format(command))
        login()
        if command == 'test-module':
            test_integration()
        elif command == 'fetch-incidents':
            fetch_incidents()

        elif command == 'fidelis-get-alert':
            get_alert_command()

        elif command == 'fidelis-delete-alert':
            delete_alert_command()

        elif command == 'fidelis-get-malware-data':
            get_malware_data_command()

        elif command == 'fidelis-get-alert-pcap':
            get_alert_pcap_command()

        elif command == 'fidelis-get-alert-report':
            get_alert_report_command()

        elif command == 'fidelis-sandbox-upload':
            sandbox_upload_command()

        elif command == 'fidelis-list-alerts':
            list_alerts_command()

        elif command == 'fidelis-upload-pcap':
            upload_pcap_command()

        elif command == 'fidelis-run-pcap':
            run_pcap_command()

        elif command == 'fidelis-list-pcap-components':
            list_pcap_components_command()
        elif command == 'fidelis-get-alert-by-uuid':
            get_alert_by_uuid()
        elif command == 'fidelis-list-metadata':
            list_metadata()
        elif command == 'fidelis-list-alerts-by-ip':
            list_alerts_by_ip()
        elif command == 'fidelis-download-malware-file':
            download_malware_file()
        elif command == 'fidelis-download-pcap-file':
            download_pcap_file()

    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)))

    finally:
        logout()


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
