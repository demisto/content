from CommonServerPython import *

reload(sys)
sys.setdefaultencoding('utf-8')  # pylint: disable=E1101

requests.packages.urllib3.disable_warnings()

URL = demisto.getParam('server')
if URL[-1] != '/':
    URL += '/'

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

VALIDATE_CERT = not demisto.params().get('insecure', True)

ID_AND_API_KEY = demisto.getParam('credentials')['identifier'] + ':' + demisto.getParam('credentials')['password']
ENCODED_AUTH_KEY = base64.b64encode(ID_AND_API_KEY.encode("utf-8"))
MSSP_ACCOUNT_ID = demisto.getParam('mssp_sub_account_id')

HEADERS = {'Authorization': 'Basic {}'.format(ENCODED_AUTH_KEY.decode()), 'Content-Type': 'application/json',
           'Account-Id': demisto.getParam('credentials')['identifier']}

# Change the Account-Id to the sub account id, so all actions will be on the sub account.
if MSSP_ACCOUNT_ID:
    HEADERS['Account-Id'] = MSSP_ACCOUNT_ID

IOC_TYPE_TO_DBOT_TYPE = {
    'IpAddresses': 'ip',
    'Urls': 'url',
    'Domains': 'domain',
    'Hashes': 'hash'
}

DEFAULT_TIME_RANGE = '1 day'
SEVERITY_LEVEL = {
    'All': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3
}


def http_request(method, path, json_data=None, params=None, json_response=False):
    """
    Send the request to IntSights and return the JSON response
    """
    try:
        response = requests.request(method, URL + path, headers=HEADERS, json=json_data,
                                    params=params, verify=VALIDATE_CERT)
    except requests.exceptions.SSLError:
        raise Exception('Connection error in the API call to IntSights.\nCheck your not secure parameter.')
    except requests.ConnectionError:
        raise Exception('Connection error in the API call to IntSights.\nCheck your Server URL parameter.')

    if response.status_code < 200 or response.status_code > 299:
        if not (response.text == 'SeverityNotChanged' or response.text == 'TagExist'
                or response.text == 'IocBlocklistStatusNotChanged'):
            return_error('Error in API call to IntSights service %s - [%d] %s' %
                         (path, response.status_code, response.text))

    if response.status_code == 204:
        return []  # type: ignore

    if json_response:
        try:
            return response.json()
        except ValueError:
            raise Exception('Error in API call to IntSights service - check your configured URL address')

    return response


def convert_iso_string_to_python_date(date_in_iso_format):
    iso_format = "%Y-%m-%dT%H:%M:%S"
    date_in_python_format = datetime.strptime(date_in_iso_format, iso_format)
    return date_in_python_format


def convert_python_date_to_unix_millisecond(python_date_object):
    timestamp_in_unix_millisecond = date_to_timestamp(python_date_object, 'datetime.datetime')
    return timestamp_in_unix_millisecond


def increase_iso_by_x_days(date_in_iso_format, num_of_days):
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


def handle_filters(found_date_from=None):
    """
    Apply filters to alert list
    """
    args_camel_case = {
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
    for key in demisto.args():
        if demisto.getArg(key):
            params[args_camel_case.get(key) or key] = demisto.getArg(key)
    if demisto.getArg('time-delta'):
        time_delta_in_days = demisto.getArg('time-delta')
        update_params_dict_according_to_delta_arg(params, int(time_delta_in_days))
    elif found_date_from:
        params['foundDateFrom'] = found_date_from
    return params


def get_alerts_helper(params):
    demisto.info("Executing get_alerts with params: {}".format(params))
    response = http_request('GET', 'public/v1/data/alerts/alerts-list', params=params, json_response=True)

    alerts_human_readable = []
    alerts_context = []
    for alert_id in response:
        alert_human_readable, alert_context = get_alert_by_id_helper(alert_id)
        alerts_human_readable.append(alert_human_readable)
        alerts_context.append(alert_context)
    return alerts_human_readable, alerts_context


def extract_mail(replies):
    if not replies:
        return ''
    mails = []
    for reply in replies:
        mails.append(reply.get('Email'))

    return '\n'.join(mails)


def extract_remediation(remidiations):
    if not remidiations:
        return ''
    remedies = []
    string_format = "{0} - Status: {1}"
    for remedy in remidiations:
        remedies.append(string_format.format(remedy.get('Value'), remedy.get('Status')))

    return '\n'.join(remedies)


def hash_identifier(hash_val):
    if md5Regex.match(hash_val):
        return 'MD5'
    if sha1Regex.match(hash_val):
        return 'SHA1'
    if sha256Regex.match(hash_val):
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
    alerts_human_readable, alerts_context = get_alerts_helper(handle_filters())
    headers = ['ID', 'Severity', 'Type', 'FoundDate', 'SourceType', 'SourceURL',
               'SourceEmail', 'SourceNetworkType', 'IsClosed', 'Closed', 'IsFlagged', 'Images', 'Tags',
               'Description', 'Title', 'TakedownStatus', 'SubType']
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': alerts_context},
        'Contents': alerts_context,
        'HumanReadable': tableToMarkdown('IntSights Alerts', alerts_human_readable, headers=headers, removeNull=False),
        'ContentsFormat': formats['json']
    })


def alert_to_readable(alert, parse_tags):
    """
    Convert alert to readable format
    """

    is_closed = demisto.get(alert, 'IsClosed')
    if is_closed is None:
        is_closed = demisto.get(alert, 'Closed.IsClosed')

    readable = {
        'ID': demisto.get(alert, '_id'),
        'Severity': demisto.get(alert, 'Details.Severity'),
        'Type': demisto.get(alert, 'Details.Type'),
        'FoundDate': demisto.get(alert, 'FoundDate'),
        'SourceType': demisto.get(alert, 'Details.Source.Type'),
        'SourceURL': demisto.get(alert, 'Details.Source.URL'),
        'SourceEmail': demisto.get(alert, 'Details.Source.Email'),
        'SourceNetworkType': demisto.get(alert, 'Details.Source.NetworkType'),
        'IsClosed': is_closed,
        'IsFlagged': demisto.get(alert, 'IsFlagged'),
        'Assets': demisto.get(alert, 'Assets'),
        'Images': demisto.get(alert, 'Details.Images'),
        'Description': demisto.get(alert, 'Details.Description'),
        'Title': demisto.get(alert, 'Details.Title'),
        'TakedownStatus': demisto.get(alert, 'TakedownStatus'),
        'SubType': demisto.get(alert, 'Details.SubType'),
    }

    tags = demisto.get(alert, 'Details.Tags')
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
    response = http_request('GET', 'public/v1/data/alerts/get-complete-alert/' + alert_id, json_response=True)
    return alert_to_readable(response, True), alert_to_readable(response, False)


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
                                          'SourceEmail', 'SourceNetworkType', 'IsClosed', 'IsFlagged',
                                          'Images', 'Tags', 'Description', 'Title', 'TakedownStatus', 'SubType']),
        'ContentsFormat': formats['json']
    })


def get_alert_image():
    """
    Retrieves the alert image by image_id
    """
    image_id = demisto.getArg('image-id')
    response = http_request('GET', 'public/v1/data/alerts/alert-image/' + image_id)
    demisto.results(fileResult(image_id + '-image.jpeg', response.content))


def ask_analyst():
    """
    Send question to an analyst about the requested alert
    """
    alert_id = demisto.getArg('alert-id')
    question = demisto.getArg('question')
    http_request('POST', 'public/v1/data/alerts/ask-the-analyst/' + alert_id, json_data={'Question': question})
    question_details = {'ID': alert_id, 'Question': question}
    title = 'IntSights Ask the Analyst: ' \
            'Your question has been successfully sent to an analyst about the requested alert'
    demisto.results(
        {
            'Type': entryTypes['note'],
            'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': question_details},
            'Contents': question_details,
            'HumanReadable': tableToMarkdown(title, [question_details], ['ID', 'Question']),
            'ContentsFormat': formats['json']
        }
    )


def get_alert_activity():
    """
    Retrieves the alert activity by alert-id
    """
    alert_id = demisto.getArg('alert-id')
    response = http_request('GET', 'public/v1/data/alerts/activity-log/' + alert_id, json_response=True)

    alert = {'ID': alert_id, 'Activities': []}
    if not response:
        demisto.results({
            'Type': entryTypes['note'],
            'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': alert},
            'Contents': response,
            'HumanReadable': 'Alert {} does not have activities.'.format(alert_id),
            'ContentsFormat': formats['json']
        })
    else:
        human_readable_arr = []
        for activity in response:
            alert['Activities'].append({
                'ID': demisto.get(activity, '_id'),
                'Type': demisto.get(activity, 'Type'),
                'Initiator': demisto.get(activity, 'Initiator'),
                'CreatedDate': demisto.get(activity, 'CreatedDate'),
                'UpdateDate': demisto.get(activity, 'UpdateDate'),
                'RemediationBlocklistUpdate': demisto.get(activity, 'AdditionalInformation.RemediationBlocklistUpdate'),
                'AskTheAnalyst': {'Replies': demisto.get(activity, 'AdditionalInformation.AskTheAnalyst.Replies')},
                'Mail': {'Replies': demisto.get(activity, 'AdditionalInformation.Mail.Replies')},
                'ReadBy': demisto.get(activity, 'ReadBy')
            })
            human_readable_arr.append({
                'ID': demisto.get(activity, '_id'),
                'Type': demisto.get(activity, 'Type'),
                'Initiator': demisto.get(activity, 'Initiator'),
                'CreatedDate': demisto.get(activity, 'CreatedDate'),
                'UpdateDate': demisto.get(activity, 'UpdateDate'),
                'RemediationBlocklistUpdate': extract_remediation(
                    demisto.get(activity, 'AdditionalInformation.RemediationBlocklistUpdate'))
                if demisto.get(activity, 'AdditionalInformation') else '',
                'AskTheAnalyst': {'Replies': demisto.get(activity, 'AdditionalInformation.AskTheAnalyst.Replies')},
                'Mail': extract_mail(
                    demisto.get(activity, 'AdditionalInformation.Mail.Replies'))
                if demisto.get(activity, 'AdditionalInformation.Mail') else '',
                'ReadBy': demisto.get(activity, 'ReadBy')
            })

        headers = ['ID', 'Type', 'Initiator', 'CreatedDate', 'UpdateDate',
                   'RemediationBlocklistUpdate', 'AskTheAnalyst', 'Mail', 'ReadBy']
        human_readable = tableToMarkdown('IntSights Alert {} Activity Log'.format(alert_id),
                                         t=human_readable_arr, headers=headers),

        demisto.results({
            'Type': entryTypes['note'],
            'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': alert},
            'Contents': response,
            'HumanReadable': human_readable,
            'ContentsFormat': formats['json']
        })


def change_severity():
    """
    Change severity of an alert
    """
    alert_id = demisto.getArg('alert-id')
    severity = demisto.getArg('severity')
    http_request('PATCH', 'public/v1/data/alerts/change-severity/' + alert_id, json_data={'Severity': severity})
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
    response = http_request('GET', 'public/v1/account/users-details', json_response=True)
    for user in response:
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
    http_request('PATCH', url, json_data={'AssigneeID': assignee_id})
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
    http_request('PATCH', 'public/v1/data/alerts/unassign-alert/' + alert_id)
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
    is_hidden = demisto.getArg('is-hidden') == 'True'
    rate = demisto.getArg('rate')
    close_details = {'ID': alert_id, 'Close Reason': reason, 'Closed FreeText': free_text, 'Closed Rate': rate,
                     'IsHidden': is_hidden}
    close_details_context = {'ID': alert_id, 'Closed': {'Reason': reason, 'FreeText': free_text, 'Rate': rate},
                             'IsHidden': is_hidden}
    url = 'public/v1/data/alerts/close-alert/' + alert_id
    json_data = {'Reason': reason}

    if free_text:
        json_data['FreeText'] = free_text
    if is_hidden:
        json_data['IsHidden'] = is_hidden
    if rate:
        json_data['Rate'] = rate

    http_request('PATCH', url, json_data)
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
    http_request('POST', 'public/v1/data/alerts/send-mail/' + alert_id, {'Emails': emails, 'Content': content})
    context = {
        'ID': alert_id,
        'EmailID': emails,
        'Question': content
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': context},
        'Contents': context,
        'HumanReadable': 'Email with content (' + content + ') sent to emails',
        'ContentsFormat': formats['json']
    })


def get_tag_id(alert_id, tag_name):
    response = http_request('GET', 'public/v1/data/alerts/get-complete-alert/' + alert_id, json_response=True)

    details = response.get('Details', {})
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
    http_request('PATCH', 'public/v1/data/alerts/add-tag/' + alert_id, json_data={'TagName': tag_name})
    tag_info = {
        'TagName': tag_name,
        'ID': get_tag_id(alert_id, tag_name)
    }
    context = {
        'ID': alert_id,
        'Tags': tag_info
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': context},
        'Contents': context,
        'HumanReadable': 'Tag (' + tag_name + ') added to alert id: ' + alert_id,
        'ContentsFormat': formats['json']
    })


def remove_tag():
    """
    Removes a tag from an alert
    """
    alert_id = demisto.getArg('alert-id')
    tag_id = demisto.getArg('tag-id')
    http_request('PATCH', 'public/v1/data/alerts/remove-tag/' + alert_id, json_data={'TagID': tag_id})
    context = {
        'ID': alert_id,
        'Tags': {'ID': tag_id}
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': context},
        'Contents': context,
        'HumanReadable': 'Tag id: ' + tag_id + ' removed from alert id: ' + alert_id,
        'ContentsFormat': formats['json']
    })


def add_comment():
    """
    Adds a comment to an alert
    """
    alert_id = demisto.getArg('alert-id')
    comment = demisto.getArg('comment')
    http_request('PATCH', 'public/v1/data/alerts/add-comment/' + alert_id, json_data={'Comment': comment})
    context = {
        'ID': alert_id,
        'Comment': comment
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': context},
        'Contents': context,
        'HumanReadable': 'Succesfully added comment "' + comment + '" to alert id: ' + alert_id,
        'ContentsFormat': formats['json']
    })


def ioc_to_readable(ioc_data):
    """
    Convert IOC to readable format
    """
    ioc_context = {
        'ID': demisto.get(ioc_data, '_id'),
        'SourceID': demisto.get(ioc_data, 'SourceID'),
        'AccountID': demisto.get(ioc_data, 'AccountID'),
        'Type': demisto.get(ioc_data, 'Type'),
        'Value': demisto.get(ioc_data, 'Value'),
        'FirstSeen': demisto.get(ioc_data, 'FirstSeen'),
        'LastSeen': demisto.get(ioc_data, 'LastSeen'),
        'Domain': demisto.get(ioc_data, 'Domain'),
        'Status': demisto.get(ioc_data, 'Status'),
        'Severity': demisto.get(ioc_data, 'Severity'),
        'SourceName': demisto.get(ioc_data, 'Source.Name'),
        'SourceConfidence': demisto.get(ioc_data, 'Source.Confidence'),
        'Flags': {'IsInAlexa': demisto.get(ioc_data, 'Flags.IsInAlexa')},
        'Enrichment': {
            'Status': demisto.get(ioc_data, 'Enrichment.Status'),
            'Data': demisto.get(ioc_data, 'Enrichment.Data'),
            'Date': demisto.get(ioc_data, 'Enrichment.Data')  # Backwards compatibility issue
        }
    }
    ioc_readable = {
        'ID': demisto.get(ioc_data, '_id'),
        'SourceID': demisto.get(ioc_data, 'SourceID'),
        'AccountID': demisto.get(ioc_data, 'AccountID'),
        'Type': demisto.get(ioc_data, 'Type'),
        'Value': demisto.get(ioc_data, 'Value'),
        'FirstSeen': demisto.get(ioc_data, 'FirstSeen'),
        'LastSeen': demisto.get(ioc_data, 'LastSeen'),
        'Domain': demisto.get(ioc_data, 'Domain'),
        'Status': demisto.get(ioc_data, 'Status'),
        'Severity': demisto.get(ioc_data, 'Severity').get('Value'),
        'SourceName': demisto.get(ioc_data, 'Source.Name'),
        'SourceConfidence': demisto.get(ioc_data, 'Source.Confidence'),
        'IsInAlexa': demisto.get(ioc_data, 'Flags.IsInAlexa'),
        'Enrichment Status': demisto.get(ioc_data, 'Enrichment.Status'),
        'Enrichment Data': demisto.get(ioc_data, 'Enrichment.Data')
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


def search_for_ioc():
    """
    Search for IOC by value
    """
    response = http_request('GET', 'public/v1/iocs/ioc-by-value', params=handle_filters(), json_response=True)

    if response:
        ioc_context, ioc_readable, dbot_score, domain, ip_info, url_info, hash_info = ioc_to_readable(response)

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
                'Contents': response,
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
    if sev in ['Medium', 'High']:
        return 3
    if sev == 'Low':
        return 2
    return 0


def fetch_incidents():
    """
    Fetch incidents for Demisto
    """
    now = int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds() * 1000)
    last_run = demisto.getLastRun()
    demisto.info("IntSight fetch last run time is: {}".format(str(last_run)))
    if not last_run or 'time' not in last_run:
        fetch_delta, _ = parse_date_range(demisto.params().get('fetch_delta', DEFAULT_TIME_RANGE), to_timestamp=True)
    else:
        fetch_delta = last_run.get('time')

    alert_type = demisto.getParam('type')
    min_severity_level = demisto.params().get('severity_level', 'All')
    if min_severity_level not in SEVERITY_LEVEL:
        raise Exception("Minimum Alert severity level to fetch incidents incidents from, allowed values are: All,"
                        " Low, Medium, High. (Setting to All will fetch all incidents)")

    _, alerts_context = get_alerts_helper(handle_filters(fetch_delta))
    incidents = []
    for alert in alerts_context:
        if SEVERITY_LEVEL[min_severity_level] <= SEVERITY_LEVEL[alert.get('Severity', 'Low')]:
            if not alert_type or alert_type.lower() == alert.get('Type', '').lower():
                incidents.append({
                    'name': '{type} - {id}'.format(type=alert.get('Type', 'Type not found'), id=alert.get('ID')),
                    'occurred': alert.get('FoundDate'),
                    'severity': translate_severity(alert.get('Severity')),
                    'rawJSON': json.dumps(alert)
                })
    demisto.incidents(incidents)
    demisto.setLastRun({'time': now})


def get_iocs():
    """
    Gets all IOCs with the given filters
    """
    response = http_request('GET', 'public/v1/iocs/complete-iocs-list', params=handle_filters(), json_response=True)
    domains = []
    ip_infos = []
    url_infos = []
    hash_infos = []
    dbot_scores = []
    iocs_context = []
    iocs_readable = []

    for indicator in response:
        ioc_context, ioc_readable, dbot_score, domain, ip_info, url_info, hash_info = ioc_to_readable(indicator)
        iocs_context.append(ioc_context)
        iocs_readable.append(ioc_readable)
        dbot_scores.append(dbot_score)
        domains.append(domain)
        ip_infos.append(ip_info)
        url_infos.append(url_info)
        hash_infos.append(hash_info)

    headers = ['ID', 'SourceID', 'AccountID', 'Type', 'Value', 'FirstSeen', 'LastSeen',
               'Domain', 'Status', 'Severity', 'SourceName', 'SourceConfidence',
               'IsInAlexa', 'Enrichment Status', 'Enrichment Data']
    demisto.results(
        {
            'Type': entryTypes['note'],
            'EntryContext': {
                'IntSights.Iocs': iocs_context,
                'DBotScore': dbot_scores,
                'Domain': domains,
                'IP': ip_infos,
                'URL': url_infos,
                'File': hash_infos
            },
            'Contents': response,
            'HumanReadable': tableToMarkdown('IOC Information', t=iocs_readable, headers=headers),
            'ContentsFormat': formats['json']
        }
    )


def takedown_request():
    """
    Request alert takedown
    """
    alert_id = demisto.getArg('alert-id')
    http_request('PATCH', 'public/v1/data/alerts/takedown-request/' + alert_id)
    context = {
        'ID': alert_id,
    }
    human_readable = '### IntSights Alert Takedown\n' \
                     'The Alert Takedown request has been sent successfully for {}'.format(str(alert_id))
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': context},
        'Contents': context,
        'HumanReadable': human_readable,
        'ContentsFormat': formats['json']
    })


def get_alert_takedown_status():
    """
    Get an alert's takedown status
    """
    alert_id = demisto.getArg('alert-id')
    response = http_request('GET', 'public/v1/data/alerts/takedown-status/' + alert_id)
    context = {
        'ID': alert_id,
        'TakedownStatus': response.text
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.Alerts(val.ID === obj.ID)': context},
        'Contents': context,
        'HumanReadable': tableToMarkdown('IntSights Alert Takedown Status', [context], ['ID', 'TakedownStatus']),
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
    for count, type_ in enumerate(types):
        data.append({
            'Type': type_,
            'Value': values[count],
            'BlocklistStatus': statuses[count]
        })
    http_request('PATCH', 'public/v1/data/alerts/change-iocs-blocklist-status/' + alert_id, json_data={'Iocs': data})
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
    response = http_request('GET', 'public/v1/data/alerts/blocklist-status/' + alert_id, json_response=True)
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {
            'IntSights.Alerts(val.ID === obj.ID)': {'ID': alert_id, 'Status': [ioc.get('Status') for ioc in response]}},
        'Contents': response,
        'HumanReadable': tableToMarkdown('IntSights Blocklist Status for ' + alert_id, response, ['Status']),
        'ContentsFormat': formats['json']
    })


def get_mssp_sub_accounts():
    account_id = demisto.getParam('credentials')['identifier']
    accounts = http_request('GET', 'public/v1/mssp/customers', json_response=True)
    if not accounts:
        return_error("intsights-mssp-get-sub-accounts failed to return data.")

    # Fix accounts _id keys
    for account in accounts:
        account["ID"] = account["_id"]
        del account["_id"]

    if len(accounts) < 1:
        return_error('Current MSSP Account has no sub accounts.')

    account_ids = [i["ID"] for i in accounts]
    if MSSP_ACCOUNT_ID not in account_ids:
        demisto.log("[DEBUG] - MSSP sub accounts:" + str(accounts))
        return_error('Entered sub account id ({}) is not part of this mssp account'.format(MSSP_ACCOUNT_ID))

    for i, account in enumerate(account_ids):
        # Call account
        HEADERS['Account-Id'] = account
        account_ua = http_request('GET', 'public/v1/account/used-assets', json_response=True)

        if not account_ua:
            continue

        accounts[i].update(account_ua)

    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'IntSights.MsspAccount(val.ID === obj.ID)': accounts},
        'HumanReadable': tableToMarkdown('IntSights MSSP accounts used assets ' + account_id, accounts,
                                         ["ID", 'CompanyName', "Status", "AssetsLimit", "AssetsCount"]),
        'Contents': accounts,
        'ContentsFormat': formats['json']
    })

    # Restore the header
    HEADERS['Account-Id'] = MSSP_ACCOUNT_ID


def test_module():
    http_request('GET', 'public/v1/api/version')
    if demisto.params().get('isFetch'):
        min_severity_level = demisto.params().get('severity_level', 'All')
        if min_severity_level not in SEVERITY_LEVEL:
            return_error("Minimum Alert severity level to fetch incidents incidents from, allowed values are: "
                         "All, Low, Medium, High. (Setting to All will fetch all incidents)")

    demisto.results('ok')


try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'intsights-mssp-get-sub-accounts':
        get_mssp_sub_accounts()
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
        search_for_ioc()
    elif demisto.command() == 'intsights-get-iocs':
        get_iocs()
    elif demisto.command() == 'intsights-alert-takedown-request':
        takedown_request()
    elif demisto.command() == 'intsights-get-alert-takedown-status':
        get_alert_takedown_status()
    elif demisto.command() == 'intsights-get-ioc-blocklist-status':
        get_ioc_blocklist_status()
    elif demisto.command() == 'intsights-update-ioc-blocklist-status':
        update_ioc_blocklist_status()
    elif demisto.command() == 'intsights-close-alert':
        close_alert()
    else:
        raise Exception('Unrecognized command: ' + demisto.command())
except Exception as err:
    return_error(str(err))
