import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
import json
import re
import base64
import time

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' PREREQUISITES '''


def load_server_url():
    """
    Cleans and loads the server url from the configuration
    """
    url = demisto.params().get('baseUrl')
    url = re.sub('/[\/]+$/', '', url)
    url = re.sub('\/$', '', url)
    return url


''' GLOBALS '''
USERNAME = demisto.params().get('username')
PASSWORD = demisto.params().get('password')
USE_SSL = not demisto.params().get('unsecure')
BASE_URL = load_server_url()
LOGIN_HEADERS = {
    'Accept': 'application/vnd.ve.v1.0+json',
    'Content-Type': 'application/json',
    'VE-SDK-API': base64.b64encode(USERNAME + ':' + PASSWORD)
}
HEARTBEAT_HEADERS = {
    'Accept': 'application/vnd.ve.v1.0+json',
    'Content-Type': 'application/json'
}
API_HEADERS = None

''' HELPERS '''


def get_session_credentials():
    result = http_request('php/session.php', 'get', LOGIN_HEADERS)
    if result:
        return result['results']


@logger
def heart_beat():
    return http_request('php/heartbeat.php', 'get', API_HEADERS, HEARTBEAT_HEADERS)


def get_headers():
    sess = get_session_credentials()
    return {
        'Accept': 'application/vnd.ve.v1.0+json',
        'VE-SDK-API': base64.b64encode(sess['session'] + ':' + sess['userId'])
    }


def http_request(uri, method, headers={}, body={}, params={}, files={}):
    """
    Makes an API call with the supplied uri, method, headers, body
    """
    LOG('running request with url=%s' % uri)
    url = '%s/%s' % (BASE_URL, uri)
    res = requests.request(
        method,
        url,
        headers=headers,
        data=body,
        verify=USE_SSL,
        params=params,
        files=files
    )
    if res.status_code < 200 or res.status_code >= 300:
        if res.status_code == 401:
            return_error('Request Failed with status: 401 Unauthorized - Invalid Username or Password')
        elif res.status_code == 415:
            return_error('Request Failed with status: 415 - Invalid accept header or content type header')
        else:
            return_error('Request Failed with status: ' + str(res.status_code) + '. Reason is: ' + str(res.reason))
    result = res.content

    if not uri.startswith('php/showreport.php?'):
        # parsing the int as string is vital for long taskId/jobId that round up by json.loads
        try:
            result = json.loads(result, parse_int=str)
        except ValueError:
            LOG('result is: %s' % result)
            return_error('Response Parsing failed')
        if 'success' in result:  # type: ignore
            if result['success'] == 'false':  # type: ignore
                return_error('ATD Api call to ' + uri + ' failed. Reason is: ' + str(res.reason))
    return result


def prettify_current_user_res(current_user):
    pretty_current_user = {
        'APIVersion': current_user['apiVersion'],
        'IsAdmin': 'True' if current_user['isAdmin'] == '1' else 'False',
        'SessionId': current_user['session'],
        'UserId': current_user['userId']
    }
    return pretty_current_user


def prettify_list_users_res(users):
    if len(users) > 0:
        pretty_users = []
    else:
        return ''

    for i in range(len(users)):
        user = users[i]
        pretty_users.append({
            'FullName': user['fullName'],
            'UserId': user['idx'],
            'LoginId': user['loginId'],
            'UserType': user['userType']
        })

    return pretty_users


def prettify_list_profiles_res(profiles):
    pretty_profiles = []
    for i in range(len(profiles)):
        pretty_profiles.append({
            'Name': profiles[i]['name'],
            'AnalyzerProfileId': profiles[i]['vmProfileid'],
            'Description': profiles[i]['vmDesc'],
            'Sandbox': 'True' if profiles[i]['sandbox'] == 1 else 'False',
            'Internet': 'True' if profiles[i]['internet'] == 1 else 'False',
            'LocalBlackList': 'True' if profiles[i]['locBlackList'] == 1 else 'False'
        })
    return pretty_profiles


def prettify_task_status_by_taskId_res(task_status):
    pretty_task_status = {
        'taskId': task_status['taskid'],
        'jobId': task_status['jobid'],
        'status': task_status['status'],
        'filename': task_status['filename'],
        'MD5': task_status['md5'],
        'submitTime': task_status['submitTime']
    }
    return pretty_task_status


def prettify_file_upload_res(file_upload_res):
    pretty_file_upload = {
        'taskId': file_upload_res['results'][0]['taskId'],
        'jobId': file_upload_res['subId'],
        'messageId': file_upload_res['results'][0]['messageId'],
        'url': file_upload_res['results'][0]['url'],
        'srcIp': file_upload_res['results'][0]['srcIp'],
        'destIp': file_upload_res['results'][0]['destIp'],
        'MD5': file_upload_res['results'][0]['md5'],
        'SHA1': file_upload_res['results'][0]['sha1'],
        'SHA256': file_upload_res['results'][0]['sha256'],
    }
    return pretty_file_upload


''' FUNCTIONS '''


def test_get_session():
    get_session()


@logger
def get_session():
    result = http_request('php/session.php', 'get', LOGIN_HEADERS)
    return result


def get_session_command():
    result = get_session()
    result = result['results']
    md = tableToMarkdown('ATD Current User', prettify_current_user_res(result),
                         ['APIVersion', 'IsAdmin', 'SessionId', 'UserId'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'ATD.Session(val.SessionId == obj.SessionId)': prettify_current_user_res(result)
        }
    })


@logger
def list_users(user_type):
    user_type = user_type if user_type else 'STAND_ALONE'
    result = http_request('php/briefUserList.php?userType=' + user_type, 'get', API_HEADERS)
    users = result['results']
    return users


def list_users_command():
    users = list_users(demisto.args()['userType'])

    pretty_users = prettify_list_users_res(users)
    md = tableToMarkdown(
        'ATD User List',
        pretty_users,
        ['FullName', 'UserId', 'LoginId', 'UserType']
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': users,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'ATD.Users(val.UserId == obj.UserId)': pretty_users,
        }
    })


@logger
def list_profiles():
    result = http_request('php/vmprofiles.php', 'get', API_HEADERS)
    return result['results']


def list_profiles_command():
    result = list_profiles()

    md = tableToMarkdown(
        'ATD Analyzers Profile List', prettify_list_profiles_res(result),
        ['Name', 'AnalyzerProfileId', 'Description',
         'Sandbox', 'Internet', 'LocalBlackList'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'ATD.ListAnalyzerProfiles(val.AnalyzerProfileId == obj.AnalyzerProfileId)': prettify_list_profiles_res(
                result)
        }
    })


@logger
def check_task_status_by_taskId(task_ids):
    result = {}  # type: dict
    multiple_results = []
    tasks = []

    for i in range(len(task_ids)):
        request_suffix = 'iTaskId=' + str(task_ids[i])
        result = http_request('php/samplestatus.php?' + request_suffix, 'get', API_HEADERS)

        # when you use TaskID, you get results in res.results
        tasks.append(prettify_task_status_by_taskId_res(result['results']))
        multiple_results.append(result['results'])

    status = result['results']['status']  # backward compatibility
    return {
        'status': status,
        'tasks': tasks,
        'multipleResults': multiple_results
    }


@logger
def check_task_status_by_jobId(job_ids):
    taskIds = []
    for i in range(len(job_ids)):
        result = http_request('php/getTaskIdList.php?jobId=' + job_ids[i], 'get', API_HEADERS)
        task_id = result['result']['taskIdList']
        taskIds.append(task_id)
    return check_task_status_by_taskId(taskIds)


def check_task_status_command():
    result = {}  # type: dict
    args = demisto.args()

    if ('jobId' not in args and 'taskId' not in args) or ('jobId' in args and 'taskId' in args):
        return_error('You must specify one (and only one) of the following: jobId, taskId.')

    if 'jobId' in args:
        ids = argToList(args['jobId'])
        result = check_task_status_by_jobId(ids)

    elif 'taskId' in args:
        ids = argToList(args['taskId'])
        result = check_task_status_by_taskId(ids)

    md = tableToMarkdown(
        'ATD Sandbox Task Status',
        result['tasks'],
        (result['tasks'][0]).keys()
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result['multipleResults'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'ATD.status': result['status'],  # backward compatibility
            'ATD.Task(val.taskId == obj.taskId)': result['tasks']
        }
    })


@logger
def get_taskIds(job_ids):
    results = []
    for i in range(len(job_ids)):
        result = http_request('php/getTaskIdList.php?jobId=' + str(job_ids[i]), 'get', API_HEADERS)
        results.append(result)
    return results


def get_taskIds_command():
    job_ids = argToList(demisto.args()['jobId'])
    results = get_taskIds(job_ids)

    multiple_md = []
    ec = []
    for i in range(len(results)):
        multiple_md.append({
            'taskId': results[i]['result']['taskIdList'],
            'jobId': job_ids[i]
        })
        ec.append({
            'taskId': results[i]['result']['taskIdList'],
            'jobId': job_ids[i]
        })

    md = tableToMarkdown('ATD TaskIds and JobIds List', multiple_md, ['taskId', 'jobId'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'ATD.Task(val.jobId == obj.jobId)': ec
        }
    })


@logger
def file_upload_raw(body, file_entry_id, filename_to_upload):
    uri = 'php/fileupload.php'
    if len(filename_to_upload) == 0:  # first priority for the file name is user's argument
        # second priority for the file name is the file name in the context
        filenameDq = demisto.dt(demisto.context(), 'File(val=val.EntryID=="' + file_entry_id + '")=val.Name')
        if filenameDq and filenameDq[0]:
            filename_to_upload = filenameDq
        else:
            filename_to_upload = file_entry_id  # last priority for the file name is demisto's entryID

    with open(demisto.getFilePath(file_entry_id)['path'], 'rb') as f:
        file_up = {'amas_filename': f}
        res = http_request(
            uri,
            'post',
            API_HEADERS,
            body,
            '',
            files=file_up,
        )

    if not res['success']:
        return_error('Failed to upload sample due to: ' + res['errorMessage'])
    return res


def url_upload_raw(body):
    uri = 'php/fileupload.php'
    res = http_request(
        uri,
        'post',
        API_HEADERS,
        body
    )

    if not res['success']:
        return_error('Failed to upload sample due to: ' + res['errorMessage'])
    return res


def file_upload(submit_type, sample, vm_profile_list,
                skip_task_id=None, analyze_again=None, x_mode=None, message_id=None,
                file_priority_q=None, src_ip=None, dest_ip=None, file_name=None):
    body = {}  # type: dict
    body['data'] = {}
    data = {}  # type: dict
    data['data'] = {}
    # Add missing prefix to url
    if submit_type != 0:
        if not sample.startswith('http://') and not sample.startswith('https://'):
            if sample.startswith('www.'):
                sample = "http://" + sample
            else:
                sample = "http://www." + sample  # disable-secrets-detection

    data['data']['vmProfileList'] = vm_profile_list
    data['data']['submitType'] = submit_type
    data['data']['messageId'] = message_id
    data['data']['srcIp'] = src_ip
    data['data']['destIp'] = dest_ip
    data['data']['url'] = '' if submit_type == 0 else sample
    data['data']['skipTaskId'] = int(skip_task_id) if skip_task_id else None
    data['data']['analyzeAgain'] = analyze_again
    data['data']['xMode'] = x_mode
    data['data']['filePriorityQ'] = file_priority_q if file_priority_q else 'run_now'

    body['data'] = json.dumps(data)
    file = sample if submit_type == 0 else ''
    filename_to_upload = file_name if (submit_type == 0 and file_name) else ''
    if submit_type == 0:
        result_obj = file_upload_raw(body, file, filename_to_upload)
    elif submit_type == 1:
        result_obj = url_upload_raw(body)
    return {
        'taskId': result_obj['results'][0]['taskId'],
        'resultObj': result_obj
    }


def file_upload_command():
    args = demisto.args()

    if ('entryID' in args and 'url' in args) or ('entryID' not in args and 'url' not in args):
        return_error('You must submit one and only one of the following: url, entryID')
    if ('entryID' in args and args['submitType'] != '0') or ('url' in args and args['submitType'] != '1'):
        return_error(
            'In order to detonate a file submitType must be 0 and an entryID of a file must be given.\n'
            'In order to detonate a url submitType must be 1 and a url must be given.')

    sample = args['entryID'] if 'entryID' in args else args['url']
    vm_profile_list = int(args['vmProfileList']) if 'vmProfileList' in args else None
    analyze_again = int(args['analyze_again']) if 'analyze_again' in args else None
    skip_task_id = int(args['skip_task_id']) if 'skip_task_id' in args else None
    x_mode = int(args['x_mode']) if 'x_mode' in args else None
    message_id = args['messageId'] if 'messageId' in args else None
    file_priority_q = args['file_priority_q'] if 'file_priority_q' in args else None
    src_ip = args['src_ip'] if 'src_ip' in args else None
    dest_ip = args['dest_ip'] if 'dest_ip' in args else None
    file_name = args['file_name'] if 'file_name' in args else None

    result = file_upload(int(args['submitType']), sample, vm_profile_list,
                         skip_task_id, analyze_again, x_mode, message_id, file_priority_q,
                         src_ip, dest_ip, file_name)
    md = tableToMarkdown('ATD sandbox sample submission', prettify_file_upload_res(result['resultObj']),
                         ['taskId', 'jobId', 'messageId', 'url', 'dest_ip', 'src_ip', 'MD5', 'SHA1', 'SHA256'],
                         removeNull=True)

    upload_file_output = {
        'ATD.Task(val.taskId == obj.taskId)': prettify_file_upload_res(result['resultObj']),
        'ATD.taskId': result['taskId']  # backward compatibility
    }
    if 'url' in args:
        upload_file_output[outputPaths['url']] = sample

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result['resultObj'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': upload_file_output
    })


def build_report_context(report_summary, upload_data, status, threshold, task_id):
    context = {}  # type: dict
    if report_summary and report_summary['Subject']:
        subject = report_summary['Subject']
        context = {
            'DBotScore': {
                'Vendor': 'McAfee Advanced Threat Defense',
                'Score': 0
            }
        }

        if 'FileType' in subject:
            context['DBotScore']['Indicator'] = subject['md5']
            context['DBotScore']['Type'] = 'hash'
            # default threshold for McAfee ATD is 3
            if report_summary['Verdict']['Severity'] > threshold:
                context['DBotScore']['Score'] = 3
                if subject['Type'] == 'application/url':
                    context['URL(val.Name == obj.Data)'] = {
                        'Type': subject['Type'],
                        'MD5': subject['md5'],
                        'SHA1': subject['sha-1'],
                        'SHA256': subject['sha-256'],
                        'Size': subject['size'],
                        'Name': subject['Name'],
                        'Malicious': {
                            'Vendor': 'McAfee Advanced Threat Defense',
                            'Description': 'Severity: ' + report_summary['Verdict']['Severity']
                        }
                    }
                else:
                    context['File(val.MD5 == obj.MD5)'] = {
                        'Type': subject['Type'],
                        'MD5': subject['md5'],
                        'SHA1': subject['sha-1'],
                        'SHA256': subject['sha-256'],
                        'Size': subject['size'],
                        'Name': subject['Name'],
                        'Malicious': {
                            'Vendor': 'McAfee Advanced Threat Defense',
                            'Description': 'Severity: ' + report_summary['Verdict']['Severity']
                        }
                    }
            else:
                context['DBotScore']['Score'] = 1

        else:  # detonation did not return any data
            # retrieve submission url by the task ID, if exist
            submission_dt = demisto.dt(demisto.context(), 'ATD.Task(val.taskId === "{}")'.format(task_id))
            if isinstance(submission_dt, list):
                submission = submission_dt[0]
            else:
                submission = submission_dt
            if isinstance(submission, dict):
                if submission.get('url') and len(str(submission.get('url'))) > 0:
                    context['DBotScore']['Type'] = 'application/url'
                    context['DBotScore']['Indicator'] = submission.get('url')
                else:  # if does not exist, submission is a file
                    if submission.get('SHA256') and len(str(submission.get('SHA256'))) > 0:
                        context['DBotScore']['Indicator'] = submission.get('SHA256')
                        context['DBotScore']['Type'] = 'hash'
                    elif submission.get('SHA1') and len(str(submission.get('SHA1'))) > 0:
                        context['DBotScore']['Indicator'] = submission.get('SHA1')
                        context['DBotScore']['Type'] = 'hash'

        context['IP'] = {}
        if 'Ips' in report_summary:
            ip_addresses = []
            for i in range(len(report_summary['Ips'])):
                ip_addresses.append(report_summary['Ips'][i]['Ipv4'])
            context['IP']['Address'] = ip_addresses

        if upload_data:
            context['ATD'] = {}
            context['ATD']['Task(val.taskId == obj.taskId)'] = {
                'status': status,
                'taskId': upload_data['taskId'],
                'jobId': upload_data['subId'] if 'subId' in upload_data else None,
                'messageId': upload_data['messageId'],
                'url': upload_data['url'],
                'srcIp': upload_data['srcIp'],
                'destIp': upload_data['destIp'],
                'MD5': upload_data['md5'],
                'SHA1': upload_data['sha1'],
                'SHA256': upload_data['sha256'],
                'Report': {
                    'Attachments': report_summary['Attachments'] if 'Attachment' in report_summary else None,
                    'Environment': report_summary['Environment'] if 'Environment' in report_summary else None,
                    'Ips': report_summary['Ips'] if 'Ips' in report_summary else None,
                    'Verdict': report_summary['Verdict'] if 'Verdict' in report_summary else None,
                    'Data': report_summary['Data'] if 'Data' in report_summary else None,
                    'Selectors': report_summary['Selectors'] if 'Selectors' in report_summary else None
                }
            }
    return context


@logger
def get_report(uri_suffix, task_id, report_type, upload_data, status, threshold):
    json_res = http_request('php/showreport.php?' + uri_suffix + '&iType=json', 'get', API_HEADERS)
    if not json_res:
        return_error(
            'You cannot download this report because you do not have the same permissions'
            ' as the user that uploaded the submission to McAfee ATD.\n'
            'Make sure you have the same permissions as the user that uploaded the submissions.'
            ' Admin users have full permissions.')
    json_res = json.loads(json_res)
    summary = json_res['Summary']
    summary['VerdictDescription'] = summary['Verdict']['Description']
    summary['VerdictSeverity'] = summary['Verdict']['Severity']
    ec = build_report_context(summary, upload_data, status, threshold, task_id)
    json_res_string = json.dumps(json_res)
    if report_type == 'json':
        md = tableToMarkdown('McAfee ATD Sandbox Report', summary, summary.keys(), None, True)
        return {
            'content': json_res_string,
            'md': md,
            'ec': ec
        }

    res = http_request('php/showreport.php?' + uri_suffix + '&iType=' + report_type, 'get', API_HEADERS)

    if report_type == 'pdf' or report_type == 'zip':
        filename = str(task_id) + '.' + report_type
        return {
            'content': res,
            'filename': filename,
            'ec': ec
        }

    if report_type == 'sample':
        return {
            'content': res,
            'filename': task_id + '.zip',
            'ec': ec
        }
    return res


def get_report_command():
    uri_suffix = job_or_taskId()
    args = demisto.args()
    report_type = args['type'] if 'type' in args else 'pdf'
    threshold = args['threshold']

    filename = args['jobId'] if 'jobId' in args else args['taskId']

    return_report(uri_suffix, filename, report_type, '', '', threshold)


def job_or_taskId():
    args = demisto.args()
    if ('jobId' not in args and 'taskId' not in args) or ('jobId' in args and 'taskId' in args):
        return_error('You must specify one (and only one) of the following: jobId, taskId.')

    if 'jobId' in args:
        uri_suffix = 'jobId=' + str(args['jobId'])
    else:
        uri_suffix = 'iTaskId=' + str(args['taskId'])

    return uri_suffix


def detonate(submit_type, sample, timeout, report_type, threshold, file_name):
    result = file_upload(submit_type, sample, file_name)
    task_id = result['taskId']
    upload_data = result['resultObj']['results'][0]

    timeout = int(timeout)
    while 0 < timeout:
        status = str(check_task_status_by_taskId([task_id])['status'])
        if status == 'Completed':
            uri_suffix = 'iTaskId=' + str(task_id)
            return_report(uri_suffix, task_id, report_type, upload_data, status, threshold)
            sys.exit(0)
        time.sleep(1)
        timeout -= 1

    return_error("Timeout due to no answer after " + demisto.args()['timeout']
                 + "seconds. Check the status using '!atd-check-status' in a while"
                 " and if 'completed' execute '!atd-get-report'.")


def return_report(uri_suffix, task_id, report_type, upload_data, status, threshold):
    current_status = check_task_status_by_taskId([task_id])['status']
    if current_status != 'Completed':
        demisto.results('Please wait in order to download the report, the sample is still being analyzed.')
    else:
        res = get_report(uri_suffix, task_id, report_type, upload_data, status, threshold)

        if report_type == 'json':
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': res['content'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': res['md'],
                'EntryContext': res['ec']
            })

        elif report_type == 'pdf' or report_type == 'zip':
            file_type = entryTypes['entryInfoFile']
            result = fileResult(res['filename'], res['content'],
                                file_type)  # will be saved under 'InfoFile' in the context.
            result['EntryContext'] = res['ec']
            demisto.results(result)

        elif report_type == 'sample':
            # used to retrieve a sample from McAfee ATD to demisto
            file_type = entryTypes['file']
            result = fileResult(res['filename'], res['content'],
                                file_type)  # will be saved under 'File' in the context, can be farther investigated.
            demisto.results(result)

        else:
            demisto.results(res)


@logger
def logout():
    http_request('/php/session.php', 'delete', API_HEADERS)


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))
    global API_HEADERS
    API_HEADERS = get_headers()

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            test_get_session()
            demisto.results('ok')

        elif demisto.command() == 'atd-login':
            get_session_command()

        elif demisto.command() == 'atd-list-analyzer-profiles':
            list_profiles_command()

        elif demisto.command() == 'atd-list-user':
            list_users_command()

        elif demisto.command() == 'atd-check-status':
            check_task_status_command()

        elif demisto.command() == 'atd-get-task-ids':
            get_taskIds_command()

        elif demisto.command() == 'atd-file-upload':
            file_upload_command()

        elif demisto.command() == 'atd-get-report':
            get_report_command()

        elif demisto.command() == 'detonate-file':  # deprecated, please use 'ATD - Detonate File' playbook
            detonate(0, demisto.args().get('upload'), demisto.args().get('timeout'), demisto.args().get('format'),
                     demisto.args().get('threshold'), demisto.args().get('fileName'))
            # submit type for regular file is 0

        elif demisto.command() == 'detonate-url':  # deprecated, please use 'Detonate URL - McAfee ATD_python' playbook
            detonate(1, demisto.args().get('url'), demisto.args().get('timeout'), demisto.args().get('format'),
                     demisto.args().get('threshold'), demisto.args().get('fileName'))
            # submit type for url submission is 1

        # elif demisto.command() == 'detonate-file-remote':
        # return detonate(3, args.url, args.timeout, args.format, args.threshold);
        # submit type for url-download is 3

    except Exception, ex:
        return_error(ex)

    finally:
        LOG.print_log()
        logout()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
