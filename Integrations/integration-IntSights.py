import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import json
import base64
from datetime import datetime

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = demisto.getParam('server')
if URL[-1] != '/':
    URL += '/'

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

VALIDATE_CERT = not demisto.params().get('insecure', True)

id_and_api_key = demisto.getParam('credentials')['identifier'] + ':' + demisto.getParam('credentials')['password']
encoded_auth_key = base64.b64encode(id_and_api_key.encode("utf-8"))
mssp_account_id = demisto.getParam('mssp_sub_account_id')

HEADERS = {'Authorization': 'Basic ' + encoded_auth_key, 'Content-Type': 'application/json',
           'Account-Id': demisto.getParam('credentials')['identifier']}

# Change the Account-Id to the sub account id, so all actions will be on the sub account.
if mssp_account_id:
    HEADERS['Account-Id'] = mssp_account_id

IOC_TYPE_TO_DBOT_TYPE = {
    'IpAddresses': 'ip',
    'Urls': 'url',
    'Domains': 'domain',
    'Hashes': 'hash'
}


def req(method, path, json_data=None, params=None):
    """
    Send the request to IntSights and return the JSON response
    """
    r = requests.request(method, URL + path, headers=HEADERS, json=json_data, params=params, verify=VALIDATE_CERT)
    if r.status_code < 200 or r.status_code > 299:
        if not (r.text == 'SeverityNotChanged' or r.text == 'TagExist' or r.text == 'IocBlocklistStatusNotChanged'):
            return_error('Error in API call to IntSights service %s - [%d] %s' % (path, r.status_code, r.text))
    return r


def convert_iso_string_to_python_date(date_in_iso_format):
    iso_format = "%Y-%m-%dT%H:%M:%S"
    date_in_python_format = datetime.strptime(date_in_iso_format, iso_format)
    return date_in_python_format


def convert_python_date_to_unix_millisecond(python_date_object):
    timestamp_in_unix_millisecond = date_to_timestamp(python_date_object, 'datetime.datetime')
    return timestamp_in_unix_millisecond


def increase_iso_by_x_days(date_in_iso_format, num_of_days):
    iso_format = "%Y-%m-%dT%H:%M:%S"
    date_in_python_format = convert_iso_string_to_python_date(date_in_iso_format)
    new_date_in_python_format = date_in_python_format + timedelta(days=int(num_of_days))
    new_date_in_iso_format = new_date_in_python_format.isoformat()
    return new_date_in_iso_format


def remove_milliseconds_from_iso(date_in_iso_format):
    date_parts_arr = date_in_iso_format.split('.')
    date_in_iso_without_milliseconds = date_parts_arr[0]
    return date_in_iso_without_milliseconds


def increase_timestamp_by_x_days(date_in_unix_ms_timestamp, num_of_days):
    date_in_iso = timestamp_to_datestring(date_in_unix_ms_timestamp)
    date_in_iso_without_ms = remove_milliseconds_from_iso(date_in_iso)
    date_in_iso_plus_x_days = increase_iso_by_x_days(date_in_iso_without_ms, num_of_days)
    timestamp_in_unix_ms_plus_x_days = date_to_timestamp(date_in_iso_plus_x_days)
    return timestamp_in_unix_ms_plus_x_days


def update_params_with_end_and_start_date(params, oldest_day_to_search_in_unix_timestamp, now_date_in_unix_timestamp):
    params['foundDateFrom'] = oldest_day_to_search_in_unix_timestamp
    params['foundDateTo'] = now_date_in_unix_timestamp
    params['sourceDateFrom'] = oldest_day_to_search_in_unix_timestamp
    params['sourceDateTo'] = now_date_in_unix_timestamp


def update_params_with_delta_arg(params, time_delta_in_days_int):
    now_date_in_iso = datetime.utcnow().isoformat()
    now_date_in_iso_without_ms = remove_milliseconds_from_iso(now_date_in_iso)
    now_date_in_unix_timestamp = date_to_timestamp(now_date_in_iso_without_ms)
    oldest_day_to_search_in_unix_timestamp = increase_timestamp_by_x_days(now_date_in_unix_timestamp,
                                                                          -1 * time_delta_in_days_int)
    update_params_with_end_and_start_date(params, oldest_day_to_search_in_unix_timestamp, now_date_in_unix_timestamp)
    del params['time-delta']


def update_params_dict_according_to_delta_arg(params, time_delta_in_days_int):
    if 'foundDateFrom' in params or 'foundDateTo' in params:
        demisto.debug(
            "ERROR in get_alerts() - can't use found-date-to or found-date-from arguments with time-delta argument")
        return_error("Error: can't assign delta when assigned both found-date-to or found-date-from")
    else:
        update_params_with_delta_arg(params, time_delta_in_days_int)
    return params


def handle_filters():
    """
    Apply filters to alert list
    """
    argsConversion = {
        'alert-type': 'alertType',
        'source-type': 'sourceType',
        'network-type': 'networkType',
        'source-date-from': 'sourceDateFrom',
        'source-date-to': 'sourceDateTo',
        'found-date-from': 'foundDateFrom',
        'found-date-to': 'foundDateTo',
        'is-flagged': 'isFlagged',
        'is-closed': 'isClosed',
        'source-ID': 'sourceId',
        'first-seen-from': 'firstSeenFrom',
        'first-seen-to': 'firstSeenTo',
        'last-seen-from': 'lastSeenFrom',
        'last-seen-to': 'lastSeenTo',
        'value': 'iocValue',
    }
    params = {}
    for k in demisto.args():
        if demisto.getArg(k):
            params[argsConversion.get(k) or k] = demisto.getArg(k)
    if demisto.getArg('time-delta'):
        time_delta_in_days = demisto.getArg('time-delta')
        update_params_dict_according_to_delta_arg(params, int(time_delta_in_days))
    return params


def get_alerts_helper(params):
    demisto.info("Executing get_alerts")
    resp = req('GET', 'public/v1/data/alerts/alerts-list', params=params)
    if resp.status_code == 204:
        r = []
    else:
        r = resp.json()

    alerts_HR = []
    alerts_ctx = []
    for alert_id in r:
        alert_informationHR, alert_informationCtx = get_alert_by_id_helper(alert_id)
        alerts_HR.append(alert_informationHR)
        alerts_ctx.append(alert_informationCtx)
    return alerts_HR, alerts_ctx


def extract_mail(replies):
    mails = []
    for reply in replies:
        mails.append(reply.get('Email'))

    return '\n'.join(mails)


def extract_remediation(remidiations):
    remdies = []
    string_format = "{0} - Status: {1}"
    for remdy in remidiations:
        remdies.append(string_format.format(remdy.get('Value'), remdy.get('Status')))

    return '\n'.join(remdies)


def hash_identifier(hash_val):
    if md5Regex.match(hash_val):
        return 'MD5'
    elif sha1Regex.match(hash_val):
        return 'SHA1'
    elif sha256Regex.match(hash_val):
        return 'SHA256'
    return 'Unknown'


def extract_tags(tags):
    pretty_tags = []
    string_format = "ID: {0} - Name: {1}"
    for tag in tags:
        pretty_tags.append(string_format.format(tag.get('_id'), tag.get('Name')))
    return pretty_tags


def get_alerts():
    """
    Gets all alerts and returns as a list.
    """
    alerts_HR, alerts_ctx = get_alerts_helper(handle_filters())

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': alerts_ctx},
        'Contents': alerts_ctx,
        'HumanReadable': tableToMarkdown('IntSights Alerts', alerts_HR,
                                         ['ID', 'Severity', 'Type', 'FoundDate', 'SourceType', 'SourceURL',
                                          'SourceEmail', 'SourceNetworkType', 'IsClosed', 'IsFlagged', 'Images', 'Tags',
                                          'Description', 'Title', 'TakedownStatus', 'SubType'], removeNull=False),
        'ContentsFormat': formats['json']
    })


def alert_to_readable(r, parse_tags):
    """
    Convert alert to readable format
    """

    readable = {
        'ID': demisto.get(r, '_id'),
        'Severity': demisto.get(r, 'Details.Severity'),
        'Type': demisto.get(r, 'Details.Type'),
        'FoundDate': demisto.get(r, 'FoundDate'),
        'SourceType': demisto.get(r, 'Details.Source.Type'),
        'SourceURL': demisto.get(r, 'Details.Source.URL'),
        'SourceEmail': demisto.get(r, 'Details.Source.Email'),
        'SourceNetworkType': demisto.get(r, 'Details.Source.NetworkType'),
        'IsClosed': demisto.get(r, 'IsClosed'),
        'IsFlagged': demisto.get(r, 'IsFlagged'),
        'Assets': demisto.get(r, 'Assets'),
        'Images': demisto.get(r, 'Details.Images'),
        'Description': demisto.get(r, 'Details.Description'),
        'Title': demisto.get(r, 'Details.Title'),
        'TakedownStatus': demisto.get(r, 'TakedownStatus'),
        'SubType': demisto.get(r, 'Details.SubType')
    }

    tags = demisto.get(r, 'Details.Tags')
    if parse_tags:
        readable['Tags'] = extract_tags(tags)
    else:
        readable['Tag'] = []
        for tag in tags:
            readable['Tag'].append({'ID': tag.get('_id'), 'Name': tag.get('Name')})

    return readable


def get_alert_by_id_helper(alert_id):
    """
    Helper for getting details by ID
    """
    r = req('GET', 'public/v1/data/alerts/get-complete-alert/' + alert_id).json()
    return alert_to_readable(r, True), alert_to_readable(r, False)


def get_alert_by_id():
    """
    Get alert details by id
    """
    alert_id = demisto.getArg('alert-id')
    activity_hr, activity_ctx = get_alert_by_id_helper(alert_id)
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': activity_ctx},
        'Contents': activity_hr,
        'HumanReadable': tableToMarkdown('IntSights Alert Details', [activity_hr],
                                         ['ID', 'Severity', 'Type', 'FoundDate', 'SourceType', 'SourceURL',
                                          'SourceEmail', 'SourceNetworkType', 'IsClosed', 'IsFlagged', 'Images', 'Tags',
                                          'Description', 'Title', 'TakedownStatus', 'SubType']),
        'ContentsFormat': formats['json']
    })


def get_alert_image():
    """
    Retrieves the alert image by image_id
    """
    image_id = demisto.getArg('image-id')
    r = req('GET', 'public/v1/data/alerts/alert-image/' + image_id)
    demisto.results(fileResult(image_id + '-image.jpeg', r.content))


def ask_analyst():
    """
    Send question to an analyst about the requested alert
    """
    alert_id = demisto.getArg('alert-id')
    question = demisto.getArg('question')
    r = req('POST', 'public/v1/data/alerts/ask-the-analyst/' + alert_id, json_data={'Question': question})
    question_details = {'ID': alert_id, 'Question': question}
    demisto.results(
        {
            'Type': entryTypes['note'],
            'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': question_details},
            'Contents': question_details,
            'HumanReadable': tableToMarkdown(
                'IntSights Ask the Analyst: Your question has been successfully sent to an analyst about the requested alert',
                [question_details], ['ID', 'Question']),
            'ContentsFormat': formats['json']
        }
    )


def get_alert_activity():
    """
    Retrieves the alert activity by alert-id
    """
    alert_id = demisto.getArg('alert-id')
    r = req('GET', 'public/v1/data/alerts/activity-log/' + alert_id).json()
    activities = []

    human_readables = []
    alert = {'ID': alert_id, 'Activities': []}
    for k in r:
        alert['Activities'].append({
            'ID': demisto.get(k, '_id'),
            'Type': demisto.get(k, 'Type'),
            'Initiator': demisto.get(k, 'Initiator'),
            'CreatedDate': demisto.get(k, 'CreatedDate'),
            'UpdateDate': demisto.get(k, 'UpdateDate'),
            'RemediationBlocklistUpdate': demisto.get(k, 'AdditionalInformation.RemediationBlocklistUpdate'),
            'AskTheAnalyst': {'Replies': demisto.get(k, 'AdditionalInformation.AskTheAnalyst.Replies')},
            'Mail': {'Replies': demisto.get(k, 'AdditionalInformation.Mail.Replies')},
            'ReadBy': demisto.get(k, 'ReadBy')
        })
        human_readables.append({
            'ID': demisto.get(k, '_id'),
            'Type': demisto.get(k, 'Type'),
            'Initiator': demisto.get(k, 'Initiator'),
            'CreatedDate': demisto.get(k, 'CreatedDate'),
            'UpdateDate': demisto.get(k, 'UpdateDate'),
            'RemediationBlocklistUpdate': extract_remediation(
                demisto.get(k, 'AdditionalInformation.RemediationBlocklistUpdate')),
            'AskTheAnalyst': {'Replies': demisto.get(k, 'AdditionalInformation.AskTheAnalyst.Replies')},
            'Mail': extract_mail(demisto.get(k, 'AdditionalInformation.Mail.Replies')),
            'ReadBy': demisto.get(k, 'ReadBy')
        })
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': alert},
        'Contents': r,
        'HumanReadable': tableToMarkdown('IntSights Alert Activity Log', human_readables,
                                         ['ID', 'Type', 'Initiator', 'CreatedDate', 'UpdateDate',
                                          'RemediationBlocklistUpdate', 'AskTheAnalyst', 'Mail', 'ReadBy']),
        'ContentsFormat': formats['json']
    })


def change_severity():
    """
    Change severity of an alert
    """
    alert_id = demisto.getArg('alert-id')
    severity = demisto.getArg('severity')
    r = req('PATCH', 'public/v1/data/alerts/change-severity/' + alert_id, json_data={'Severity': severity})
    severity_details = {'ID': alert_id, 'Severity': severity}
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': severity_details},
        'Contents': severity_details,
        'HumanReadable': tableToMarkdown(
            'IntSights Update Alert Severity: The Alert severity has been successfully updated.', [severity_details],
            ['ID', 'Severity']),
        'ContentsFormat': formats['json']
    })


def get_assignee_id(assignee_email):
    r = req('GET', 'public/v1/account/users-details')
    r = r.json()
    for user in r:
        if assignee_email == user.get('Email', ''):
            return user.get('_id')

    raise Exception('user not found')


def assign_alert():
    """
    Assign alert to an Assignee ID
    """
    alert_id = demisto.getArg('alert-id')
    assignee_email = demisto.getArg('assignee-email')
    is_mssp = demisto.getArg('is-mssp-optional')
    assignee_id = get_assignee_id(assignee_email)
    assign_details = {'ID': alert_id, 'Assignees.AssigneeID': assignee_id}

    url = 'public/v1/data/alerts/assign-alert/' + alert_id
    if is_mssp:
        url += '?IsMssp=' + is_mssp
    r = req('PATCH', url, json_data={'AssigneeID': assignee_id})
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': assign_details},
        'Contents': assign_details,
        'HumanReadable': tableToMarkdown(
            'IntSights Assign Alert: The Alert has been successfully assigned to assigneeID', [assign_details],
            ['ID', 'Assignees.AssigneeID']),
        'ContentsFormat': formats['json']
    })


def unassign_alert():
    """
    Unassign an alert
    """
    alert_id = demisto.getArg('alert-id')
    r = req('PATCH', 'public/v1/data/alerts/unassign-alert/' + alert_id)
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': {'ID': alert_id}},
        'Contents': {'ID': alert_id},
        'HumanReadable': 'Alert id: ' + alert_id + ' successfully unassigned',
        'ContentsFormat': formats['json']
    })


def close_alert():
    """
    Close an alert
    """
    alert_id = demisto.getArg('alert-id')
    reason = demisto.getArg('reason')
    free_text = demisto.getArg('free-text')
    is_hidden = demisto.getArg('is-hidden')
    rate = demisto.getArg('rate')
    close_details = {'ID': alert_id, 'Close Reason': reason, 'Closed FreeText': free_text, 'Closed Rate': rate,
                     'IsHidden': is_hidden}
    close_details_context = {'ID': alert_id, 'Closed': {'Reason': reason, 'FreeText': free_text, 'Rate': rate},
                             'IsHidden': is_hidden}
    url = 'public/v1/data/alerts/close-alert/' + alert_id
    json_data = {'Reason': reason}

    if free_text:
        json_data['FreeText'] = free_text
    if free_text:
        json_data['IsHidden'] = is_hidden
    if free_text:
        json_data['Rate'] = rate

    r = req('PATCH', url, json_data)
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': close_details},
        'Contents': close_details_context,
        'HumanReadable': tableToMarkdown('IntSights Close Alert: The Alert has successfully been closed.',
                                         [close_details],
                                         ['ID', 'Close Reason', 'Closed FreeText', 'Closed Rate', 'IsHidden']),
        'ContentsFormat': formats['json']
    })


def send_mail():
    """
    Send email with the alert details and a question
    """
    alert_id = demisto.getArg('alert-id')
    emails = argToList(demisto.getArg('emails'))
    content = demisto.getArg('content')
    r = req('POST', 'public/v1/data/alerts/send-mail/' + alert_id, {'Emails': emails, 'Content': content})
    ec = {
        'ID': alert_id,
        'EmailID': emails,
        'Question': content
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': ec},
        'Contents': ec,
        'HumanReadable': 'Email with content (' + content + ') sent to emails',
        'ContentsFormat': formats['json']
    })


def get_tag_id(alert_id, tag_name):
    res = req('GET', 'public/v1/data/alerts/get-complete-alert/' + alert_id)
    res = res.json()

    details = res.get('Details', {})
    tags = details.get('Tags', [])
    for tag in tags:
        if tag.get('Name', '') == tag_name:
            return tag.get('_id', '')

    return 'Not found'


def add_tag():
    """
    Adds a tag to the alert
    """
    alert_id = demisto.getArg('alert-id')
    tag_name = demisto.getArg('tag-name')
    r = req('PATCH', 'public/v1/data/alerts/add-tag/' + alert_id, json_data={'TagName': tag_name})
    tag_info = {
        'TagName': tag_name,
        'ID': get_tag_id(alert_id, tag_name)
    }
    ec = {
        'ID': alert_id,
        'Tags': tag_info
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': ec},
        'Contents': ec,
        'HumanReadable': 'Tag (' + tag_name + ') added to alert id: ' + alert_id,
        'ContentsFormat': formats['json']
    })


def remove_tag():
    """
    Removes a tag from an alert
    """
    alert_id = demisto.getArg('alert-id')
    tag_id = demisto.getArg('tag-id')
    r = req('PATCH', 'public/v1/data/alerts/remove-tag/' + alert_id, json_data={'TagID': tag_id})
    ec = {
        'ID': alert_id,
        'Tags': {'ID': tag_id}
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': ec},
        'Contents': ec,
        'HumanReadable': 'Tag id: ' + tag_id + ' removed from alert id: ' + alert_id,
        'ContentsFormat': formats['json']
    })


def add_comment():
    """
    Adds a comment to an alert
    """
    alert_id = demisto.getArg('alert-id')
    comment = demisto.getArg('comment')
    r = req('PATCH', 'public/v1/data/alerts/add-comment/' + alert_id, json_data={'Comment': comment})
    ec = {
        'ID': alert_id,
        'Comment': comment
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': ec},
        'Contents': ec,
        'HumanReadable': 'Succesfully added comment "' + comment + '" to alert id: ' + alert_id,
        'ContentsFormat': formats['json']
    })


def IOC_to_readable(r):
    """
    Convert IOC to readable format
    """
    ioc_context = {
        'ID': demisto.get(r, '_id'),
        'SourceID': demisto.get(r, 'SourceID'),
        'AccountID': demisto.get(r, 'AccountID'),
        'Type': demisto.get(r, 'Type'),
        'Value': demisto.get(r, 'Value'),
        'FirstSeen': demisto.get(r, 'FirstSeen'),
        'LastSeen': demisto.get(r, 'LastSeen'),
        'Domain': demisto.get(r, 'Domain'),
        'Status': demisto.get(r, 'Status'),
        'Severity': demisto.get(r, 'Severity'),
        'SourceName': demisto.get(r, 'Source.Name'),
        'SourceConfidence': demisto.get(r, 'Source.Confidence'),
        'Flags': {'IsInAlexa': demisto.get(r, 'Flags.IsInAlexa')},
        'Enrichment': {
            'Status': demisto.get(r, 'Enrichment.Status'),
            'Data': demisto.get(r, 'Enrichment.Data'),
            'Date': demisto.get(r, 'Enrichment.Data')  # Backwards compatability issue
        }
    }
    ioc_readable = {
        'ID': demisto.get(r, '_id'),
        'SourceID': demisto.get(r, 'SourceID'),
        'AccountID': demisto.get(r, 'AccountID'),
        'Type': demisto.get(r, 'Type'),
        'Value': demisto.get(r, 'Value'),
        'FirstSeen': demisto.get(r, 'FirstSeen'),
        'LastSeen': demisto.get(r, 'LastSeen'),
        'Domain': demisto.get(r, 'Domain'),
        'Status': demisto.get(r, 'Status'),
        'Severity': demisto.get(r, 'Severity').get('Value'),
        'SourceName': demisto.get(r, 'Source.Name'),
        'SourceConfidence': demisto.get(r, 'Source.Confidence'),
        'IsInAlexa': demisto.get(r, 'Flags.IsInAlexa'),
        'Enrichment Status': demisto.get(r, 'Enrichment.Status'),
        'Enrichment Data': demisto.get(r, 'Enrichment.Data')
    }
    dbot_score = {
        'Indicator': ioc_context['Value'],
        'Type': IOC_TYPE_TO_DBOT_TYPE[ioc_context['Type']],
        'Vendor': 'IntSights',
        'Score': translate_severity(ioc_readable['Severity'])
    }
    malicious_dict = {
        'Vendor': 'IntSights',
        'Description': 'IntSights severity level is High'
    }
    domain = {}
    if ioc_context['Domain']:
        domain['Name'] = ioc_context['Domain']
        if translate_severity(ioc_readable['Severity']) == 3:
            domain['Malicious'] = malicious_dict

    ip_info = {}
    if ioc_context['Type'] == 'IpAddresses':
        ip_info['Address'] = ioc_context['Value']
        if translate_severity(ioc_readable['Severity']) == 3:
            ip_info['Malicious'] = malicious_dict

    url_info = {}
    if ioc_context['Type'] == 'Urls':
        url_info['Data'] = ioc_context['Value']
        if translate_severity(ioc_readable['Severity']) == 3:
            url_info['Malicious'] = malicious_dict

    hash_info = {}
    if ioc_context['Type'] == 'Hashes':
        hash_info['Name'] = ioc_context['Value']
        hash_info[hash_identifier(ioc_context['Value'])] = ioc_context['Value']
        if translate_severity(ioc_readable['Severity']) == 3:
            hash_info['Malicious'] = malicious_dict

    return ioc_context, ioc_readable, dbot_score, domain, ip_info, url_info, hash_info


def search_for_IOC():
    """
    Search for IOC by value
    """
    value = demisto.getArg('value')
    r = req('GET', 'public/v1/iocs/ioc-by-value', params=handle_filters())

    if r.status_code != 204:
        r = r.json()
        ioc_context, ioc_readable, dbot_score, domain, ip_info, url_info, hash_info = IOC_to_readable(r)

        demisto.results(
            {
                'Type': entryTypes['note'],
                'EntryContext': {
                    'IntSights.Iocs(val.ID === obj.ID)': ioc_context,
                    'DBotScore': dbot_score,
                    'Domain': domain,
                    'IP': ip_info,
                    'URL': url_info,
                    'File': hash_info
                },
                'Contents': r,
                'HumanReadable': tableToMarkdown('IOC Information', [ioc_readable],
                                                 ['ID', 'SourceID', 'AccountID', 'Type', 'Value', 'FirstSeen',
                                                  'LastSeen', 'Domain', 'Status', 'Severity', 'SourceName',
                                                  'SourceConfidence', 'IsInAlexa', 'Enrichment Status',
                                                  'Enrichment Data']),
                'ContentsFormat': formats['json']
            }
        )
    else:
        results_for_no_content('IOC Information')


def results_for_no_content(cmd_name):
    demisto.results(
        {
            'Type': entryTypes['note'],
            'EntryContext': {'IntSights': {}},
            'Contents': {},
            'HumanReadable': '### {} \n\n Could not get any results.'.format(cmd_name),
            'ContentsFormat': formats['json']
        }
    )


def translate_severity(sev):
    """
    Translate alert severity to demisto
    """
    if sev == 'High' or sev == 'Medium':
        return 3
    elif sev == 'Low':
        return 2
    return 0


def fetch_incidents():
    """
    Fetch incidents for Demisto
    """
    now = int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds() * 1000)
    lastRunObject = demisto.getLastRun()
    lastRun = lastRunObject and lastRunObject['time']
    if not lastRun:
        lastRun = now - 24 * 60 * 60 * 1000
    demisto.args()['found-date-from'] = lastRun
    if not demisto.getLastRun():
        demisto.args()['is-closed'] = False

    demisto.args()['alert-type'] = demisto.getParam('type')
    alerts_HR, alerts_ctx = get_alerts_helper(handle_filters())
    incidents = []
    for alert in alerts_ctx:
        incidents.append({
            'name': alert['Type'] + ' - ' + alert['ID'],
            'occurred': alert['FoundDate'],
            'severity': translate_severity(alert['Severity']),
            'rawJSON': json.dumps(alert)
        })
    demisto.incidents(incidents)
    demisto.setLastRun({'time': now})


def get_iocs():
    """
    Gets all IOCs with the given filters
    """
    r = req('GET', 'public/v1/iocs/complete-iocs-list', params=handle_filters()).json()
    domains = []
    ip_infos = []
    url_infos = []
    hash_infos = []
    dbot_scores = []
    iocs_context = []
    iocs_readable = []
    for k in r:
        ioc_context, ioc_readable, dbot_score, domain, ip_info, url_info, hash_info = IOC_to_readable(k)
        iocs_context.append(ioc_context)
        iocs_readable.append(ioc_readable)
        dbot_scores.append(dbot_score)
        domains.append(domain)
        ip_infos.append(ip_info)
        url_infos.append(url_info)
        hash_infos.append(hash_info)
    demisto.results(
        {
            'Type': entryTypes['note'],
            'EntryContext': {
                'IntSights.Iocs': iocs_context,
                'DBotScore': dbot_scores,
                'Domain': domains,
                'IP': ip_infos,
                'URL': url_info,
                'File': hash_info
            },
            'Contents': r,
            'HumanReadable': tableToMarkdown('IOC Information', iocs_readable,
                                             ['ID', 'SourceID', 'AccountID', 'Type', 'Value', 'FirstSeen', 'LastSeen',
                                              'Domain', 'Status', 'Severity', 'SourceName', 'SourceConfidence',
                                              'IsInAlexa', 'Enrichment Status', 'Enrichment Data']),
            'ContentsFormat': formats['json']
        }
    )


def takedown_request():
    """
    Request alert takedown
    """
    alert_id = demisto.getArg('alert-id')
    r = req('PATCH', 'public/v1/data/alerts/takedown-request/' + alert_id)
    ec = {
        'ID': alert_id,
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': ec},
        'Contents': ec,
        'HumanReadable': '### IntSights Alert Takedown\n' + 'The Alert Takedown request has been sent successfully for ' + str(
            alert_id),
        'ContentsFormat': formats['json']
    })


def get_alert_takedown_status():
    """
    Get an alert's takedown status
    """
    alert_id = demisto.getArg('alert-id')
    r = req('GET', 'public/v1/data/alerts/takedown-status/' + alert_id)
    ec = {
        'ID': alert_id,
        'TakedownStatus': r.text
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': ec},
        'Contents': ec,
        'HumanReadable': tableToMarkdown('IntSights Alert Takedown Status', [ec], ['ID', 'TakedownStatus']),
        'ContentsFormat': formats['json']
    })


def update_ioc_blocklist_status():
    alert_id = demisto.getArg('alert-id')
    types = argToList(demisto.getArg('type'))
    values = argToList(demisto.getArg('value'))
    statuses = argToList(demisto.getArg('blocklist-status'))
    if len(types) != len(values) or len(types) != len(statuses):
        return_error('The lists must be of equal length. For each IOC, provide an entry in each list.')
    data = []
    for i in range(len(types)):
        data.append({
            'Type': types[i],
            'Value': values[i],
            'BlocklistStatus': statuses[i]
        })
    r = req('PATCH', 'public/v1/data/alerts/change-iocs-blocklist-status/' + alert_id, json_data={'Iocs': data})
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': {'ID': alert_id, 'Status': statuses}},
        'Contents': {'ID': alert_id, 'Status': statuses},
        'HumanReadable': tableToMarkdown('IntSights Update IOC BlockList Status for ' + alert_id, data,
                                         ['BlocklistStatus']),
        'ContentsFormat': formats['json']
    })


def get_ioc_blocklist_status():
    alert_id = demisto.getArg('alert-id')
    r = req('GET', 'public/v1/data/alerts/blocklist-status/' + alert_id).json()
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {
            'IntSights.Alerts(val.ID === obj.ID)': {'ID': alert_id, 'Status': [s.get('Status') for s in r]}},
        'Contents': r,
        'HumanReadable': tableToMarkdown('IntSights Blocklist Status for ' + alert_id, r, ['Status']),
        'ContentsFormat': formats['json']
    })




def get_mssp_sub_accounts():
    account_id = demisto.getParam('credentials')['identifier']
    accounts = req('GET', 'public/v1/mssp/customers').json()
    if not accounts:
        return_error("intsights-mssp-get-sub-accounts failed to return data.")

    # Fix accounts _id keys
    for account in accounts:
        account["ID"] = account["_id"]
        del account["_id"]

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.MsspAccounts(val.ID === obj.ID)': accounts},
        'HumanReadable': tableToMarkdown('IntSights MSSP accounts for ' + account_id, [a for a in accounts],
                                         ["ID", 'CompanyName', "Status"]),
        'Contents': accounts,
        'ContentsFormat': formats['json']
    })


def test_mssp():
    account_id = demisto.getParam('credentials')['identifier']

    # Check if mssp_sub_account_id is full or not
    if not mssp_account_id:
        return_error('Please insert an mssp sub account id, before preforming this action.')

    # Check if account exsits
    HEADERS['Account-Id'] = account_id
    accounts = req('GET', 'public/v1/mssp/customers').json()
    if not accounts:
        return_error("intsights-mssp-test failed to fetch sub accounts.")

    account_ids = [i["_id"] for i in accounts]
    if mssp_account_id not in account_ids:
        demisto.log("[DEBUG] - MSSP sub accounts:" + str(accounts))
        return_error('Sub account id ({}) is not part of this mssp account'.format(mssp_account_id))

    if len(accounts) < 2:
        return_error('Current MSSP Account has only one sub account, please test with 2 or more.')

    # Call account 1 with /public/v1/account/used-assets after update of account-id in the header
    account_1 = account_ids[0]
    HEADERS['Account-Id'] = account_1
    account_1_ua = req('GET', 'public/v1/account/used-assets').text

    # Call account 2 and check the difference
    account_2 = account_ids[1]
    HEADERS['Account-Id'] = account_2
    account_2_ua = req('GET', 'public/v1/account/used-assets').text

    if account_1_ua == "" and account_2_ua == "":
        return_error("intsights-mssp-test failed fetching sub accounts (both are empty entries).")

    if account_1_ua == account_2_ua:
        demisto.log("[DEBUG] - MSSP Sub account results ({}={})".format(str(account_1_ua), str(account_2_ua)))
        return_error("MSSP test failed, sub accounts are not different.")

    accounts[0].update(json.loads(account_1_ua))
    accounts[1].update(json.loads(account_2_ua))

    # Fix accounts _id keys
    for account in accounts:
        account["ID"] = account["_id"]
        del account["_id"]

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.MsspAccounts(val.ID === obj.ID)': accounts},
        'HumanReadable': tableToMarkdown('IntSights MSSP accounts used assets ' + account_id, [a for a in accounts],
                                         ["ID", 'CompanyName', "Status", "AssetsLimit", "AssetsCount"]),
        'Contents': accounts,
        'ContentsFormat': formats['json']
    })

    # Restore the header
    HEADERS['Account-Id'] = mssp_account_id


if demisto.command() == 'test-module':
    req('GET', 'public/v1/api/version')
    demisto.results('ok')
elif demisto.command() == 'intsights-mssp-get-sub-accounts':
    get_mssp_sub_accounts()
elif demisto.command() == 'intsights-mssp-test':
    test_mssp()
elif demisto.command() == 'intsights-get-alerts':
    get_alerts()
elif demisto.command() == 'intsights-get-alert-image':
    get_alert_image()
elif demisto.command() == 'intsights-get-alert-activities':
    get_alert_activity()
elif demisto.command() == 'intsights-assign-alert':
    assign_alert()
elif demisto.command() == 'intsights-unassign-alert':
    unassign_alert()
elif demisto.command() == 'intsights-send-mail':
    send_mail()
elif demisto.command() == 'intsights-ask-the-analyst':
    ask_analyst()
elif demisto.command() == 'intsights-add-tag-to-alert':
    add_tag()
elif demisto.command() == 'intsights-remove-tag-from-alert':
    remove_tag()
elif demisto.command() == 'intsights-add-comment-to-alert':
    add_comment()
elif demisto.command() == 'intsights-update-alert-severity':
    change_severity()
elif demisto.command() == 'intsights-get-alert-by-id':
    get_alert_by_id()
elif demisto.command() == 'intsights-get-ioc-by-value':
    search_for_IOC()
elif demisto.command() == 'intsights-get-iocs':
    get_iocs()
elif demisto.command() == 'intsights-alert-takedown-request':
    takedown_request()
elif demisto.command() == 'fetch-incidents':
    fetch_incidents()
elif demisto.command() == 'intsights-get-alert-takedown-status':
    get_alert_takedown_status()
elif demisto.command() == 'intsights-get-ioc-blocklist-status':
    get_ioc_blocklist_status()
elif demisto.command() == 'intsights-update-ioc-blocklist-status':
    update_ioc_blocklist_status()
elif demisto.command() == 'intsights-close-alert':
    close_alert()
else:
    return_error('Unrecognized command: ' + demisto.command())
