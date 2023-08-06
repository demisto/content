import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

from CommonServerUserPython import *
import urllib3
from urllib.parse import unquote
''' IMPORTS '''
import json
import shutil
import requests
import random


# disable insecure warnings
urllib3.disable_warnings()

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


def capitalize_first_letter(raw_dict):
    parsed_dict = {}
    for key in list(raw_dict.keys()):
        cap_key = key[0].capitalize() + key[1:]
        parsed_dict[cap_key] = raw_dict[key]

    return parsed_dict


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

            raise Exception(f'Error in API call to Fidelis Integration {res.status_code} - {error}')
        else:
            raise Exception(f'Error in API call to Fidelis Integration {res.status_code} - {res.reason}')

    if is_json:
        try:
            return res.json()

        except ValueError:
            return_error(f'failed to parse json object from response: {str(res.content)}')

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
                raise requests.HTTPError(f'Failed to login: {res.get("error")}')
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
            t = datetime.strptime(str(t), '%Y-%m-%dT%H:%M:%SZ')
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
            raise ValueError(f'Could not parse time frame: {time_frame}')

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


def update_alertstatus_command():
    status_to_explicit_score = {
        'False Positive': 1,
        'Not Interesting': 2,
        'Interesting': 3,
        'Actionable': 4
    }
    args = demisto.args()
    alert_id = args['alert_id']
    status = args['status']

    data = {
        'alertIds': [alert_id],
        'explicitScore': status_to_explicit_score[status]
    }

    raw_res = update_alertstatus(data)
    return_outputs(f"Alert {alert_id} has been updated to {status.capitalize()} status", {}, raw_res)


@logger
def update_alertstatus(data):
    url = '/j/rest/v1/alert/feedback/'

    return http_request('PUT', url, data=data)


def get_alert_dpath_command():
    args = demisto.args()
    alert_id = args['alert_id']

    result = get_alert_dpath(alert_id)
    context_result = capitalize_first_letter(result)

    output = {
        'ID': alert_id,
        'DecodingPath': context_result
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Alert {alert_id}', context_result, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_alert_dpath(alert_id):
    result = http_request('GET', f'/j/rest/v1/alert/dpath/{alert_id}/')

    return result


def alert_ef_submission_command():
    args = demisto.args()

    alert_id = args['alert_id']

    result = alert_ef_submission(alert_id)
    context_result = capitalize_first_letter(result)

    output = {
        'ID': alert_id,
        'ExecutionForensics': context_result
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Alert {alert_id}', context_result, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def alert_ef_submission(alert_id):
    result = http_request('GET', f'/j/rest/v1/alert/efsubmit/{alert_id}/')

    return result


def add_alert_comment_command():
    args = demisto.args()
    alert_id = args['alert_id']
    comment = args['comment']

    data = {
        'type': "byAlertID",
        'alertIds': [alert_id],
        'comment': comment
    }

    add_alert_comment(alert_id, data)
    return_outputs(f"Added this comment: {comment}\n To alert ID: {alert_id}", {}, {})


@logger
def add_alert_comment(alert_id, data):
    url = '/j/rest/v1/alert/mgmt/'
    http_request('PUT', url, data=data)


def manage_alert_label_command():
    args = demisto.args()
    alert_id = args['alert_id']
    label = args['label']
    action = args['action']

    label_action = {
        'Add': 'LABEL_ADD',
        'Remove': 'LABEL_REMOVE'
    }

    data = {
        'type': "byAlertID",
        'alertIds': [alert_id],
        'labels': [label],
        'labelAction': label_action[action],
    }

    bad_res = manage_alert_label(data)
    if bad_res and action == 'Add':
        return_error(f"Was not able to add the label {label} to alert {alert_id}")

    elif bad_res and action == 'Remove':
        return_error(f"Was not able to remove the label {label} to alert {alert_id}")

    else:
        return_outputs(f"Assigned label: {label} to alert {alert_id}", {}, {})


@logger
def manage_alert_label(data):
    url = '/j/rest/v1/alert/mgmt/'
    res = http_request('PUT', url, data=data)
    if res.get('Console') == 'OK':
        return 0

    else:
        return 1


def manage_alert_assignuser_command():
    args = demisto.args()
    conclusion_id = args['conclusion_id']
    assign_user = args['assign_user']
    comment = args.get('comment')

    data = {
        'alertIds': [f'Console-{conclusion_id}'],
        'assignToUser': assign_user,
        'searchParams': None,
        'byId': True,
        'purgeEvents': False,
        'resolution': None,
        'comment': comment,
        'labels': None,
        'rating': None,
        'status': 'OPEN',
        'action': "ASSIGN",
    }

    raw_response = manage_alert_assignuser(data)
    entry_context = {
        'AssignedUser': assign_user,
        'ConclusionID': conclusion_id
    }

    return_outputs(f"Assigned User: {assign_user} to alert with conclusion ID {conclusion_id}",
                   {'Fidelis.Alert(val.ConclusionID && val.ConclusionID == obj.ConclusionID)': entry_context}, raw_response)


def manage_alert_assignuser(data):
    url = '/j/rest/v2/alert/mgmt/'
    raw_res = http_request('POST', url, data=data)
    return raw_res


def manage_alert_closealert_command():
    args = demisto.args()
    conclusion_id = args['conclusion_id']
    comment = args.get('comment')
    resolution = args['resolution']

    data = {
        'alertIds': [f'Console-{conclusion_id}'],
        # This field is not used by Fidelis when closing alerts / So setting it doesn't matter
        'searchParams': None,
        'byId': True,
        'purgeEvents': False,
        'resolution': resolution,
        'comment': comment,
        'labels': None,
        'rating': None,
        'status': 'CLOSED',
        'action': "STATUS",
    }

    raw_response = manage_alert_closealert(data)

    return_outputs("Closed alert conclusion ID {}".format(conclusion_id), {}, raw_response)


@logger
def manage_alert_closealert(data):
    url = '/j/rest/v2/alert/mgmt/'
    raw_res = http_request('POST', url, data=data)
    return raw_res


def get_alert_sessiondata_command():
    args = demisto.args()
    alert_id = args['alert_id']

    result = get_alert_sessiondata(alert_id)
    context_result = capitalize_first_letter(result)

    # The API has typos built in "serverDomaniName" - should be ServerDomainName,
    # clientDomaniName - should be ClientDomainName,
    if context_result.get('ServerDomaniName'):
        context_result['ServerDomainName'] = context_result['ServerDomaniName']
        del context_result['ServerDomaniName']

    else:
        context_result['ServerDomainName'] = None

    if context_result.get('ClientDomaniClient'):
        context_result['ClientDomainName'] = context_result.get('ClientDomaniClient')
        del context_result['ClientDomaniClient']

    else:
        context_result['ClientDomainName'] = None

    output = {
        'ID': alert_id,
        'SessionData': context_result
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Alert {alert_id}', context_result, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_alert_sessiondata(alert_id):
    result = http_request('GET', f'/j/rest/v2/event/sessiondata/{alert_id}/')

    return result


def get_alert_ef_command():
    args = demisto.args()
    alert_id = args['alert_id']

    result = get_alert_ef(alert_id)
    context_result = capitalize_first_letter(result)
    output = {
        'ID': alert_id,
        'ExecutionForensics': context_result
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(f'Alert {alert_id}', context_result, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_alert_ef(alert_id):
    result = http_request('GET', f'/j/rest/v1/alert/ef/{alert_id}/')

    return result


def get_alert_forensictext_command():
    args = demisto.args()
    alert_id = args['alert_id']

    result = get_alert_forensictext(alert_id)
    output = {
        'ID': alert_id,
        'ForensicText': result

    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': str(result),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
        'HumanReadable': f'Alert {alert_id}\nForensic Text: {result}'
    })


@logger
def get_alert_forensictext(alert_id):
    headers = {}  # type: Dict[str, str]
    if SESSION_ID is not None:
        headers['x-uid'] = SESSION_ID
    headers['Content-Type'] = 'application/json'

    res = requests.request(
        method='GET',
        url=SERVER_URL + f'/j/rest/v1/alert/file/forensic/text/{alert_id}/',
        data=None,
        headers=headers,
        params=None,
        files=None,
        verify=not INSECURE,
    )

    return res.text


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
        'HumanReadable': tableToMarkdown(f'Alert {alert_id}', output, headerTransform=pascalToSpace,
                                         removeNull=True),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_alert(alert_id):
    return http_request('GET', f'/j/rest/v1/alert/info/{alert_id}/')


def delete_alert_command():
    args = demisto.args()
    alert_id = args['alert_id'].split(',')

    delete_alert(alert_id)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': '\n'.join(f'Alert ({_id}) deleted successfully!' for _id in alert_id),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': '\n'.join(f'Alert ({_id}) deleted successfully!' for _id in alert_id),
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
        'HumanReadable': tableToMarkdown(f'Alert {alert_id} Malware:', result, headerTransform=pascalToSpace),
        'EntryContext': {
            'Fidelis.Alert(val.ID && val.ID == obj.ID)': output,
        },
    })


@logger
def get_malware_data(alert_id):
    result = http_request('GET', f'/j/rest/v1/alert/malware/{alert_id}/')

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
        f'Alert_Details_{alert_id}.pdf',
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
    raise NotImplementedError("The command is not implemented and could only be done manually through Fidelis.")


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
        'HumanReadable': tableToMarkdown(f'Found {len(output)} Alerts:', output),
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

    return_outputs(tableToMarkdown(f'Found {len(output)} Alerts:', output, headers), context, results)


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

    return_outputs(tableToMarkdown(f'Found {len(output)} Alerts:', output), context, results)


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
            http_request('POST', f'/j/rest/policy/pcap/upload/{component_ip}/',
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
    http_request('POST', '/j/rest/policy/pcap/run/', data=data)  # noqa


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

    return_outputs(tableToMarkdown(f'Found {len(data)} Metadata:', data), context, results)


def request_dpath(alert_id):
    res = http_request('GET', f'/j/rest/v1/alert/dpath/{alert_id}/')
    if res.get('decodingPaths'):
        dpath = res.get('decodingPaths')[0]
        link_path = dpath.get('linkPath')
    else:
        raise Exception('Could not find the file path.')

    return link_path


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

    if not file_name:
        return_outputs("No File Found", {}, {})

    else:
        decoded_file_name = unquote(file_name)
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

    demisto.debug(f'getting alarms since {last_fetch}')
    incidents = []
    items = list_alerts(time_frame='Custom', start_time=last_fetch)
    demisto.debug(f'got {len(items)} new alarms')
    for item in items:
        incident_date = datetime.strptime(item['ALERT_TIME'], '%Y-%m-%d %H:%M:%S')
        incident = {
            'Type': 'Fidelis',
            'name': f'{item["ALERT_ID"].encode("utf-8")} {item["SUMMARY"].encode("utf-8")}',
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
        demisto.debug('Command being called is {}'.format(command))
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

        elif command == 'fidelis-get-alert-session-data':
            get_alert_sessiondata_command()

        elif command == 'fidelis-get-alert-execution-forensics':
            get_alert_ef_command()

        elif command == 'fidelis-get-alert-forensic-text':
            get_alert_forensictext_command()

        elif command == 'fidelis-get-alert-decoding-path':
            get_alert_dpath_command()

        elif command == 'fidelis-update-alert-status':
            update_alertstatus_command()

        elif command == 'fidelis-alert-execution-forensics-submission':
            alert_ef_submission_command()

        elif command == 'fidelis-add-alert-comment':
            add_alert_comment_command()

        elif command == 'fidelis-assign-user-to-alert':
            manage_alert_assignuser_command()

        elif command == 'fidelis-close-alert':
            manage_alert_closealert_command()

        elif command == 'fidelis-manage-alert-label':
            manage_alert_label_command()

    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)))

    finally:
        logout()


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
