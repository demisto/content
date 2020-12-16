import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import re
import base64
import time
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' PREREQUISITES '''


def load_server_url():
    """
    Cleans and loads the server url from the configuration
    """
    url = demisto.params().get('baseUrl')
    url = re.sub(r'/[/]+$/', '', url)
    url = re.sub(r'/$', '', url)
    return url


''' GLOBALS '''
SUBMIT_TYPE_WITH_FILE = [0, 2]
SUBMIT_TYPE_WITH_URL = [1, 3]
SUBMIT_TYPE_WITH_FILE_STR = ['0', '2']
VALID_SUBMIT_TYPE = ['0', '1', '2', '3']

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
    if not result:
        return_error('Failed getting session credentials.')
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


def http_request(uri, method, headers=None, body=None, params=None, files=None):
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
            return_error(
                'Request Failed with status: 401 Unauthorized - Invalid Username or Password')
        elif res.status_code == 415:
            return_error(
                'Request Failed with status: 415 - Invalid accept header or content type header')
        else:
            return_error(
                'Request Failed with status: ' + str(res.status_code)
                + '. Reason is: ' + str(res.reason))
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
    if users:
        pretty_users = []
    else:
        return ''

    for user in users:
        pretty_users.append({
            'FullName': user['fullName'],
            'UserId': user['idx'],
            'LoginId': user['loginId'],
            'UserType': user['userType']
        })

    return pretty_users


def prettify_list_profiles_res(profiles):
    pretty_profiles = []
    for profile in profiles:
        pretty_profiles.append({
            'Name': profile['name'],
            'AnalyzerProfileId': profile['vmProfileid'],
            'Description': profile['vmDesc'],
            'Sandbox': 'True' if profile['sandbox'] == 1 else 'False',
            'Internet': 'True' if profile['internet'] == 1 else 'False',
            'LocalBlackList': 'True' if profile['locBlackList'] == 1 else 'False'
        })
    return pretty_profiles


def prettify_task_status_by_task_id(task_status):
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
    human_readable = tableToMarkdown('ATD Current User', prettify_current_user_res(result),
                                     ['APIVersion', 'IsAdmin', 'SessionId', 'UserId'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
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
    human_readable = tableToMarkdown(
        'ATD User List',
        pretty_users,
        ['FullName', 'UserId', 'LoginId', 'UserType']
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': users,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
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

    human_readable = tableToMarkdown(
        'ATD Analyzers Profile List', prettify_list_profiles_res(result),
        ['Name', 'AnalyzerProfileId', 'Description',
         'Sandbox', 'Internet', 'LocalBlackList'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'ATD.ListAnalyzerProfiles(val.AnalyzerProfileId == obj.AnalyzerProfileId)':
                prettify_list_profiles_res(result)
        }
    })


@logger
def check_task_status_by_task_id(task_ids):
    result = {}  # type: dict
    multiple_results = []
    tasks = []

    for task_id in task_ids:
        request_suffix = 'iTaskId=' + str(task_id)
        result = http_request('php/samplestatus.php?' + request_suffix, 'get', API_HEADERS)

        # when you use TaskID, you get results in res.results
        tasks.append(prettify_task_status_by_task_id(result['results']))
        multiple_results.append(result['results'])

    status = result['results']['status']  # backward compatibility
    return {
        'status': status,
        'tasks': tasks,
        'multipleResults': multiple_results
    }


@logger
def check_task_status_by_job_id(job_ids):
    task_ids = []
    for job_id in job_ids:
        result = http_request('php/getTaskIdList.php?jobId=' + job_id, 'get', API_HEADERS)
        task_id = argToList(result['result']['taskIdList'])
        task_ids.extend(task_id)
    return check_task_status_by_task_id(task_ids)


def check_task_status_command():
    result = {}  # type: dict
    args = demisto.args()

    if ('jobId' not in args and 'taskId' not in args) or ('jobId' in args and 'taskId' in args):
        return_error('You must specify one (and only one) of the following: jobId, taskId.')

    if 'jobId' in args:
        ids = argToList(args['jobId'])
        result = check_task_status_by_job_id(ids)

    elif 'taskId' in args:
        ids = argToList(args['taskId'])
        result = check_task_status_by_task_id(ids)

    human_readable = tableToMarkdown(
        'ATD Sandbox Task Status',
        result['tasks'],
        (result['tasks'][0]).keys()
    )

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result['multipleResults'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'ATD.status': result['status'],  # backward compatibility
            'ATD.Task(val.taskId == obj.taskId)': result['tasks']
        }
    })


@logger
def get_task_ids(job_ids):
    results = []
    for job_id in job_ids:
        result = http_request('php/getTaskIdList.php?jobId=' + str(job_id), 'get', API_HEADERS)
        results.append(result)
    return results


def get_task_ids_command():
    job_ids = argToList(demisto.args()['jobId'])
    results = get_task_ids(job_ids)

    multiple_human_readable = []
    entry_context = []
    for i, result in enumerate(results):
        multiple_human_readable.append({
            'taskId': result['result']['taskIdList'],
            'jobId': job_ids[i]
        })
        entry_context.append({
            'taskId': result['result']['taskIdList'],
            'jobId': job_ids[i]
        })

    human_readable = tableToMarkdown(
        'ATD TaskIds and JobIds List', multiple_human_readable, ['taskId', 'jobId'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            'ATD.Task(val.jobId == obj.jobId)': entry_context
        }
    })


@logger
def file_upload_raw(body, file_entry_id, filename_to_upload):
    uri = 'php/fileupload.php'
    if not filename_to_upload:  # first priority for the file name is user's argument
        # second priority for the file name is the file name in the context
        filename_dq = demisto.dt(
            demisto.context(), 'File(val=val.EntryID=="' + file_entry_id + '")=val.Name')
        if filename_dq and filename_dq[0]:
            filename_to_upload = filename_dq
        else:
            # last priority for the file name is demisto's entryID
            filename_to_upload = file_entry_id

    with open(demisto.getFilePath(file_entry_id)['path'], 'rb') as file_to_upload:
        file_up = {'amas_filename': file_to_upload}
        result = http_request(
            uri,
            'post',
            API_HEADERS,
            body,
            '',
            files=file_up,
        )

    if not result['success']:
        return_error('Failed to upload sample due to: ' + result['errorMessage'])
    return result


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


def add_prefix_to_given_url(url):
    """
        Args:
            url (str) : the given url argument

        Returns:
            the given url argument with a prefix of http://
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        if url.startswith('www.'):
            url = "http://" + url
        else:
            url = "http://www." + url  # disable-secrets-detection
    return url


def file_upload(submit_type, sample, vm_profile_list,
                skip_task_id=None, analyze_again=None, x_mode=None, message_id=None,
                file_priority_q=None, src_ip=None, dest_ip=None, file_name=None, given_url=None):
    body = {}  # type: dict
    body['data'] = {}
    data = {}  # type: dict
    data['data'] = {}
    # Add missing prefix to url
    if submit_type in SUBMIT_TYPE_WITH_URL:
        sample = add_prefix_to_given_url(sample)
    elif submit_type == 2:
        given_url = add_prefix_to_given_url(given_url)

    data['data']['vmProfileList'] = vm_profile_list
    data['data']['submitType'] = submit_type
    data['data']['messageId'] = message_id
    data['data']['srcIp'] = src_ip
    data['data']['destIp'] = dest_ip
    data['data']['url'] = get_url_entry_by_submit_type(submit_type, given_url, sample)
    data['data']['skipTaskId'] = skip_task_id
    data['data']['analyzeAgain'] = analyze_again
    data['data']['xMode'] = x_mode
    data['data']['filePriorityQ'] = file_priority_q if file_priority_q else 'run_now'

    body['data'] = json.dumps(data)
    file_entry_id = sample if submit_type in SUBMIT_TYPE_WITH_FILE else ''
    filename_to_upload = file_name if (submit_type in SUBMIT_TYPE_WITH_FILE and file_name) else ''
    if submit_type in SUBMIT_TYPE_WITH_FILE:
        result_obj = file_upload_raw(body, file_entry_id, filename_to_upload)
    elif submit_type in SUBMIT_TYPE_WITH_URL:
        result_obj = url_upload_raw(body)
    return {
        'taskId': result_obj['results'][0]['taskId'],
        'resultObj': result_obj
    }


def get_url_entry_by_submit_type(submit_type, given_url, sample):
    """
        Args:
            submit_type (int) : SubmitType argument (can be one of those: 0,1,2,3)
            given_url (str) : a url if SubmitType arg is 2, None otherwise.
            sample (str) : a url (if SubmitType is 1 or 3 ) or a file entry id (if SubmitType is 0 or 2)

        Returns:
            url entry value (str)

    """
    if submit_type == 0:
        return ''
    elif submit_type == 2:
        return given_url
    else:
        return sample


def handling_errors_with_file_upload_command(args):
    """
        Args:
            args (dict) : file upload command arguments
        Returns:
            returns error if one of the given arguments does not fit the command's structure

    """
    # in case submitType is not one of : 0,1,2,3
    if args['submitType'] not in VALID_SUBMIT_TYPE:
        return_error('This is not a valid submitType. Should be one of : 0, 1, 2, 3')
    # in case submitType is 2 but not both arguments (entryID and url) were given
    if ('entryID' not in args or 'url' not in args) and args['submitType'] == '2':
        return_error('When submitType is 2 You must submit both url and entryID')
    # in case submitType is one of [0,1,3] and both arguments (entryID and url) were given
    if ('entryID' in args and 'url' in args and args['submitType'] != '2') \
            or ('entryID' not in args and 'url' not in args):
        return_error('You must submit one and only one of the following: url, entryID')
    # in case one of those happened :
    # 1. submitType is 1 or 3 and entryID was given (should not be given)
    # 2. submitType is 0 and url was given
    if ('entryID' in args and args['submitType'] not in SUBMIT_TYPE_WITH_FILE_STR) or \
            ('url' in args and args['submitType'] == '0'):
        return_error(
            'In order to detonate a file submitType must be 0'
            ' and an entryID of a file must be given.\n'
            'In order to detonate a url submitType must be 1 or 3'
            ' and a url must be given.'
            'In order to submit file with a url submitType must be 2'
            ' and both entryID and a url must be given.')


def file_upload_command():
    args = demisto.args()
    handling_errors_with_file_upload_command(args)
    if args['submitType'] == '2':
        # should have both entryID and url
        given_url = args.get('url', "")
        sample = args.get('entryID', "")
    else:
        given_url = ""
        sample = args['entryID'] if 'entryID' in args else args.get('url', "")
    vm_profile_list = int(args['vmProfileList']) if 'vmProfileList' in args else None
    analyze_again = int(args['analyzeAgain']) if 'analyzeAgain' in args else None
    skip_task_id = int(args['skipTaskId']) if 'skipTaskId' in args else 0
    x_mode = int(args['xMode']) if 'xMode' in args else None
    message_id = args['messageId'] if 'messageId' in args else None
    file_priority_q = args['filePriorityQ'] if 'filePriorityQ' in args else None
    src_ip = args['srcIp'] if 'srcIp' in args else None
    dest_ip = args['dstIp'] if 'dstIp' in args else None
    file_name = args['fileName'] if 'fileName' in args else None

    result = file_upload(int(args['submitType']), sample, vm_profile_list,
                         skip_task_id, analyze_again, x_mode, message_id, file_priority_q,
                         src_ip, dest_ip, file_name, given_url)
    human_readable = tableToMarkdown(
        'ATD sandbox sample submission', prettify_file_upload_res(result['resultObj']),
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
        'HumanReadable': human_readable,
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
            submission_dt = demisto.dt(
                demisto.context(), 'ATD.Task(val.taskId === "{}")'.format(task_id))
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
    entry_context = build_report_context(summary, upload_data, status, threshold, task_id)
    json_res_string = json.dumps(json_res)
    if report_type == 'json':
        human_readable = tableToMarkdown(
            'McAfee ATD Sandbox Report', summary, summary.keys(), None, removeNull=True)
        return {
            'content': json_res_string,
            'md': human_readable,
            'ec': entry_context
        }

    result = http_request(
        'php/showreport.php?' + uri_suffix + '&iType=' + report_type, 'get', API_HEADERS)

    if report_type == 'pdf' or report_type == 'zip':
        filename = str(task_id) + '.' + report_type
        return {
            'content': result,
            'filename': filename,
            'ec': entry_context
        }

    if report_type == 'sample':
        return {
            'content': result,
            'filename': task_id + '.zip',
            'ec': entry_context
        }
    return result


def get_report_command():
    uri_suffix = job_or_task_id()
    args = demisto.args()
    report_type = args['type'] if 'type' in args else 'pdf'
    threshold = args['threshold']

    filename = args['jobId'] if 'jobId' in args else args['taskId']

    return_report(uri_suffix, filename, report_type, '', '', threshold)


def job_or_task_id():
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
    while timeout > 0:
        status = str(check_task_status_by_task_id([task_id])['status'])
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
    current_status = check_task_status_by_task_id([task_id])['status']
    if current_status != 'Completed':
        demisto.results(
            'Please wait in order to download the report, the sample is still being analyzed.')
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
            # will be saved under 'File' in the context, can be farther investigated.
            result = fileResult(res['filename'], res['content'], file_type)
            demisto.results(result)

        else:
            demisto.results(res)


@logger
def logout():
    http_request('/php/session.php', 'delete', API_HEADERS)


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))
    handle_proxy()  # Remove proxy if not set to true in params
    global API_HEADERS
    API_HEADERS = get_headers()

    try:
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
            get_task_ids_command()

        elif demisto.command() == 'atd-file-upload':
            file_upload_command()

        elif demisto.command() == 'atd-get-report':
            get_report_command()

        # deprecated, please use 'ATD - Detonate File' playbook
        elif demisto.command() == 'detonate-file':
            detonate(
                0, demisto.args().get('upload'), demisto.args().get('timeout'),
                demisto.args().get('format'), demisto.args().get('threshold'),
                demisto.args().get('fileName'))
            # submit type for regular file is 0

        # deprecated, please use 'Detonate URL - McAfee ATD_python' playbook
        elif demisto.command() == 'detonate-url':
            detonate(
                1, demisto.args().get('url'), demisto.args().get('timeout'),
                demisto.args().get('format'), demisto.args().get('threshold'),
                demisto.args().get('fileName'))
            # submit type for url submission is 1

        # elif demisto.command() == 'detonate-file-remote':
        # return detonate(3, args.url, args.timeout, args.format, args.threshold);
        # submit type for url-download is 3

    except Exception as ex:
        return_error(ex)

    finally:
        LOG.print_log()
        logout()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
