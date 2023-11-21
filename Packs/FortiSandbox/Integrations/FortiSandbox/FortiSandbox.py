import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""IMPORTS"""

import base64
import hashlib
import json
import os

import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""HELPER FUNCTIONS"""


def _handle_post(post_url, data):
    try:
        USE_SSL = demisto.params().get('secure')
        res = requests.post(post_url, data=json.dumps(data), verify=USE_SSL)
        return res

    except ConnectionError:
        return_error("Something went wrong with the POST Request. Please check task inputs\n " + res.text)


def _file_entry(data, name):
    decoded_data = base64.b64decode(data)
    return fileResult(name, decoded_data)


def _parse_results(response_data):
    returned_data = json.loads(response_data.text)
    if 'result' in returned_data and 'data' in returned_data['result']:
        data = returned_data['result']['data']
        result_object = {
            'Type': entryTypes['note'],
            'Contents': json.dumps(data),
            'ContentsFormat': formats['json'],
            'HumanReadable': tableToMarkdown('', data, removeNull=False),
            'ReadableContentsFormat': formats['markdown']
        }

    else:
        result_object = {
            'Type': entryTypes['note'],
            'Contents': response_data.text,
            'ContentsFormat': formats['text']
        }

    return result_object


""" COMMAND FUNCTIONS """


def login(username, password, base_url):
    url_suffix = '/sys/login/user'
    payload = {
        "method": "exec",
        "params": [
            {
                'url': url_suffix,
                'data': [{
                    'user': username,
                    'passwd': password
                }]
            }
        ],
        "ver": "2.0",
        "id": 1
    }

    return _handle_post(base_url + "/jsonrpc", payload)


def logout(session, base_url):
    url_suffix = "/sys/logout"
    payload = {
        "method": "exec",
        "params": [
            {
                'url': url_suffix
            }
        ],
        "session": session,
        "ver": "2.0",
        "id": 2
    }

    return _handle_post(base_url + "/jsonrpc", payload)


def get_sha_file_rating(session, base_url, ctype):
    url_suffix = "/scan/result/filerating"
    checksum = demisto.args().get('checksum')
    payload = {
        "method": "get",
        "params": [
            {
                'url': url_suffix,
                'checksum': checksum,
                'ctype': ctype
            }
        ],
        "session": session,
        "ver": "2.1",
        "id": 13
    }

    return _handle_post(base_url + "/jsonrpc", payload)


def get_url_rating(session, base_url):
    url_suffix = "/scan/result/urlrating"
    urls = demisto.args().get('url')
    address = urls.split(",")
    payload = {
        "method": "get",
        "params": [
            {
                'url': url_suffix,
                'address': address
            }
        ],
        "session": session,
        "ver": "2.4",
        "id": 14
    }

    return _handle_post(base_url + "/jsonrpc", payload)


def get_file_verdict(session, base_url):
    url_suffix = "/scan/result/file"
    checksum = demisto.args().get('checksum')
    checksum_type = demisto.args().get('checksum_type')
    payload = {
        "method": "get",
        "params": [
            {
                'url': url_suffix,
                'checksum': checksum,
                'ctype': checksum_type
            }
        ],
        "session": session,
        "ver": "2.1",
        "id": 10
    }

    return _handle_post(base_url + "/jsonrpc", payload)


def upload_file_on_demand(session, base_url):
    """File Processing"""
    upload = demisto.args().get('file_entry_id')
    file_path = demisto.getFilePath(upload)['path']
    file_name = demisto.getFilePath(upload)['name']
    file_sha256 = ""
    if 'sha256' in demisto.args():
        file_sha256 = demisto.args().get('sha256')

    try:
        file_handler = open(file_path, 'rb')
        fname = os.path.basename(file_handler.name)
        encoded_file_name = base64.b64encode(fname.encode())
        file_data = file_handler.read()
        encoded_file_data = base64.encodebytes(file_data)
        file_handler.seek(0, os.SEEK_END)
        file_size = file_handler.tell()
        file_handler.close()

    except Exception:
        raise Exception('Failed to prepare file for upload.')

    if int(file_size) >= 200000000:
        # Max File Size is 20M, hence the check.
        return_error("File too big to upload to the Sandbox, limit is 20MB")

    """File Upload"""
    url_suffix = "/alert/ondemand/submit-file"
    payload = {
        "method": "set",
        "params": [
            {
                "file": encoded_file_data.decode('utf-8'),
                "filename": encoded_file_name.decode('utf-8'),
                "archive_password": demisto.args().get("archive_password"),
                "overwrite_vm_list": demisto.args().get("vm_csv_list"),  # WIN7X86VM,WINXPVM
                "skip_steps": demisto.args().get("skip_steps"),
                # Do not use this parameter if no step to skip. 1 = Skip AV, 2= Skip Cloud, 4= Skip sandboxing,
                # 8= Skip Static Scan.
                "url": url_suffix,
                "type": "file",
                "timeout": "3600",
                # "malpkg":"0"
                # (Optional) set the value as "1" to require to add the sample to malware package if it satisfy the
                # malware critia. By default, the value is "0".
            }
        ],
        "session": session,
        "ver": "2.5",
        "id": 11
    }

    return _handle_post(base_url + "/jsonrpc", payload), file_name, file_sha256


def upload_urls(session, base_url):
    """URL File Processing"""

    csv_urls = demisto.args().get("urls")
    file_name = "urls_for_upload_" + str(time.time())
    sha256_hash = hashlib.sha256()

    with open(file_name, 'w+') as urlfile:
        for url in csv_urls.split(","):
            urlfile.write(url + "\n")

    """URL File Upload"""
    with open(file_name, 'rb') as file_handler:
        file_data = file_handler.read()
        encoded_file_data = base64.encodebytes(file_data)
        fname = os.path.basename(file_handler.name)
        encoded_file_name = base64.b64encode(fname.encode())
        for byte_block in iter(lambda: file_handler.read(4096), b""):
            sha256_hash.update(byte_block)
        file_sha256 = sha256_hash.hexdigest()

    url_suffix = "/alert/ondemand/submit-file"
    payload = {
        "method": "set",
        "params": [
            {
                "file": encoded_file_data.decode('utf-8'),
                "filename": encoded_file_name.decode('utf-8'),
                "url": url_suffix,
                "type": "url",
                "timeout": "1200"
            }
        ],
        "session": session,
        "ver": "2.2",
        "id": 12
    }

    return _handle_post(base_url + "/jsonrpc", payload), fname, file_sha256


def query_job_verdict(session, base_url):
    url_suffix = "/scan/result/job"
    jid = demisto.args().get("job_id")
    payload = {
        "method": "get",
        "params": [
            {
                "url": url_suffix,
                "jid": jid
            }
        ],
        "session": session,
        "ver": "2.1",
        "id": 15
    }

    return _handle_post(base_url + "/jsonrpc", payload), jid


def get_jobid_from_submissionid(session, base_url):
    url_suffix = "/scan/result/get-jobs-of-submission"
    submission_id = demisto.args().get("submission_id")
    payload = {
        "method": "get",
        "params": [
            {
                "url": url_suffix,
                "sid": submission_id
            }
        ],
        "session": session,
        "ver": "2.0",
        "id": 17
    }

    return _handle_post(base_url + "/jsonrpc", payload), submission_id


def get_pdf_report(session, base_url):
    url_suffix = "/scan/result/get-pdf-report"
    query_type = demisto.args().get("query_type")
    query_value = demisto.args().get("query_value")

    file_sha256 = ""
    if query_type == 'sha256':
        file_sha256 = query_value

    payload = {
        "method": "get",
        "params": [
            {
                "url": url_suffix,
                "qtype": query_type,
                "qval": query_value
            }
        ],
        "session": session,
        "ver": "2.5",
        "id": 50
    }

    return _handle_post(base_url + "/jsonrpc", payload), file_sha256


def main():
    """Parse and Validate Integration Params"""

    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    base_url = demisto.params()['server'][:-1] if (demisto.params()['server'] and demisto.params()
                                                   ['server'].endswith('/')) else demisto.params()['server']
    log_in = json.loads(login(username, password, base_url).text)
    session = log_in['session']

    """Commands Switch Panel"""

    if demisto.command() == 'test-module':
        """ This is the call made when pressing the integration test button """

        login_resp = json.loads(login(username, password, base_url).text)
        if login_resp['result']['status']['message'] == "OK" and int(login_resp['result']['status']['code']) == 0:
            logout(login_resp['session'], base_url)
            demisto.results('ok')
        else:
            demisto.results(login_resp)

    elif demisto.command() == 'fortisandbox-simple-file-rating-sha256':
        """Query file's rating through its SHA-256 checksum if data exists [Simplified]"""
        result = get_sha_file_rating(session, base_url, "sha256")
        demisto.results(_parse_results(result))

    elif demisto.command() == 'fortisandbox-simple-file-rating-sha1':
        """Query file's rating through its SHA-1 checksum if data exists [Simplified]"""
        result = get_sha_file_rating(session, base_url, "sha1")
        demisto.results(_parse_results(result))

    elif demisto.command() == 'fortisandbox-url-rating':
        """Query URL Rating if data exists"""
        result = get_url_rating(session, base_url)
        demisto.results(result.text)
        # demisto.results(_parse_results(result))

    elif demisto.command() == 'fortisandbox-get-file-verdict-detailed':
        """Query file's verdict through its checksum."""
        result = get_file_verdict(session, base_url)
        returned_data = json.loads(result.text)
        if 'result' in returned_data and 'data' in returned_data['result']:
            data = returned_data['result']['data']
            result_object = {
                'Type': entryTypes['note'],
                'Contents': json.dumps(data),
                'ContentsFormat': formats['json']
            }

        else:
            result_object = {
                'Type': entryTypes['note'],
                'Contents': json.dumps(returned_data),
                'ContentsFormat': formats['text']
            }
        demisto.results(result_object)

    elif demisto.command() == 'fortisandbox-upload-file':
        """Upload file (on-demand submit)"""
        result, file_name, file_sha256 = upload_file_on_demand(session, base_url)
        submission = json.loads(result.text)
        if 'result' in submission and 'data' in submission['result']:
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': submission,
                'ContentsFormat': formats['text'],
                'EntryContext': {'FortiSandbox.Upload': {
                    'SubmissionId': submission["result"]["data"].get("sid"),
                    'FileName': file_name,
                    'SHA256': file_sha256,
                    'Status': 'Starting'
                }
                }
            })
        demisto.results(_parse_results(result))

    elif demisto.command() == 'fortisandbox-upload-urls':
        """Upload CSV seperated URLs for scanning"""
        result, file_name, file_sha256 = upload_urls(session, base_url)
        submission = json.loads(result.text)
        if 'result' in submission and 'data' in submission['result']:
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': submission,
                'ContentsFormat': formats['text'],
                'EntryContext': {'FortiSandbox.Upload': {
                    'SubmissionId': submission["result"]["data"].get("sid"),
                    'FileName': file_name,
                    'SHA256': file_sha256,
                    'Status': 'Starting'
                }
                }
            })
        demisto.results(_parse_results(result))

    elif demisto.command() == 'fortisandbox-jobid-from-submission':
        """Get Job IDs from an uploaded Submission"""
        # demisto.results("Starting JobID from Submission ID")
        submission_result, submission_id = get_jobid_from_submissionid(session, base_url)
        json_results = submission_result.json()

        if 'result' in json_results and 'data' in json_results['result']:
            # demisto.results("Results and data exists")
            jids = json_results["result"]["data"].get("jids")
            str_jids = [str(one_job_id) for one_job_id in jids]
            if "," in submission_id:
                demisto.results("Multiple submissions detected, waiting for polling to complete")
                sys.exit(0)
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': "Job IDs:" + ",".join(str_jids),
                'EntryContext': {'FortiSandbox.Upload(val.SubmissionId && val.SubmissionId == obj.SubmissionId)': {
                    'SubmissionId': submission_id,
                    'Status': 'In-Progress' if len(jids) > 0 else 'Starting',
                    'JobIds': str_jids
                }
                }
            })

    elif demisto.command() == 'fortisandbox-query-job-verdict':
        """Query job's verdict detail through its job id."""
        api_result, jid = query_job_verdict(session, base_url)
        verdict = json.loads(api_result.text)
        if 'data' in verdict['result']:
            file_sha256 = verdict['result']['data'].get("sha256")
            fpn = verdict['result']['data'].get("false_positive_negative")
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': 'Scan Finished, Rating is ' + verdict['result']['data'].get("rating"),
                'ContentsFormat': formats['text'],
                'IgnoreAutoExtract': True,
                'EntryContext': {'FortiSandbox.Upload(val.SHA256 && val.SHA256 == obj.SHA256)': {
                    'SHA256': file_sha256,
                    'Virus_ID': verdict['result']['data'].get("vid"),
                    'Rating': verdict['result']['data'].get("rating"),
                    'Infected_OS': verdict['result']['data'].get("infected_os"),
                    'Detection_OS': verdict['result']['data'].get("detection_os"),
                    'Score': verdict['result']['data'].get("score"),
                    'Untrusted': verdict['result']['data'].get("untrusted"),
                    'Malware_Name': verdict['result']['data'].get("malware_name"),
                    'Category': verdict['result']['data'].get("category"),
                    'Rating_Source': verdict['result']['data'].get("rating_source"),
                    'Detail_URL': verdict['result']['data'].get("detail_url"),
                    'Start_TS': verdict['result']['data'].get("start_ts"),
                    'Finish_TS': verdict['result']['data'].get("finish_ts"),
                    'FP_Or_FN': "False Positive" if fpn == 1 else "False Negative" if fpn == 2 else "N/A",
                    'Status': 'Done',
                    'JobIds': str(jid)
                }
                }
            })
        else:
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': 'Scan in Progress',
                'ContentsFormat': formats['text'],
                'EntryContext': {'FortiSandbox.Upload': {
                    'JobIds': str(jid),
                    'Status': 'In-Progress'
                }
                }
            })

        demisto.results(_parse_results(api_result))

    elif demisto.command() == 'fortisandbox-get-pdf-report':
        """Get PDF Report of the Scan"""
        result, file_sha256 = get_pdf_report(session, base_url)
        report = json.loads(result.text)
        if 'data' in report['result']:
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': 'Scan Finished, Report Available',
                'ContentsFormat': formats['text'],
                'EntryContext': {'FortiSandbox.Upload(val.SHA256 && val.SHA256 == obj.SHA256)': {
                    'SHA256': file_sha256,
                    'Status': 'Done'}
                }
            })
            demisto.results(_file_entry(report['result']['data']['report'], report['result']['data']['report_name']))

    else:
        demisto.results("No Command Specified")

    """ Clean-up Actions """

    logout(session, base_url)  # Log Out
    session = ""  # purge session variable


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
