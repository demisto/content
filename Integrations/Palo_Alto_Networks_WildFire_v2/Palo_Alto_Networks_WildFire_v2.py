import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import requests
import shutil

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
URL = demisto.getParam('server')
TOKEN = demisto.getParam('token')
USE_SSL = not demisto.params().get('insecure', False)
FILE_TYPE_SUPPRESS_ERROR = demisto.getParam('suppress_file_type_error')
DEFAULT_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
MULTIPART_HEADERS = {'Content-Type': "multipart/form-data; boundary=upload_boundry"}

if URL and not URL.endswith('/publicapi'):
    if URL[-1] != '/':
        URL += '/'
    URL += 'publicapi'

URL_DICT = {
    'verdict': '/get/verdict',
    'verdicts': '/get/verdicts',
    'upload_file': '/submit/file',
    'upload_url': '/submit/link',
    'upload_file_url': '/submit/url',
    'report': '/get/report',
    'sample': '/get/sample'
}

ERROR_DICT = {
    '401': 'Unauthorized, API key invalid',
    '404': 'Not Found, The report was not found',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}

VERDICTS_DICT = {
    '0': 'benign',
    '1': 'malware',
    '2': 'grayware',
    '4': 'phishing',
    '-100': 'pending, the sample exists, but there is currently no verdict',
    '-101': 'error',
    '-102': 'unknown, cannot find sample record in the database',
    '-103': 'invalid hash value'
}

VERDICTS_TO_DBOTSCORE = {
    '0': 1,
    '1': 3,
    '2': 2,
    '4': 3,
    '-100': 0,
    '-101': 0,
    '-102': 0,
    '-103': 0
}

''' HELPER FUNCTIONS '''


def http_request(url, method, headers=None, body=None, params=None, files=None):
    LOG('running request with url=%s' % url)
    result = requests.request(
        method,
        url,
        headers=headers,
        data=body,
        verify=USE_SSL,
        params=params,
        files=files
    )

    if str(result.reason) == 'Not Found':
        # sample not found
        if url.find(URL_DICT["sample"]) != -1:
            demisto.results(
                'Sample was not found. '
                'Please note that grayware and benign samples are available for 14 days only. '
                'For more info contact your wildfire representative.')
            sys.exit(0)
        # report not found
        if url.find(URL_DICT["report"]) != -1:
            demisto.results('Report not found.')
            sys.exit(0)

    if result.status_code < 200 or result.status_code >= 300:
        if str(result.status_code) in ERROR_DICT:
            if result.status_code == 418 and FILE_TYPE_SUPPRESS_ERROR:
                demisto.results({
                    'Type': 11,
                    'Contents': f'Request Failed with status: {result.status_code}'
                                f' Reason is: {ERROR_DICT[str(result.status_code)]}',
                    'ContentsFormat': formats['text']
                })
                sys.exit(0)
            else:
                return_error(f'Request Failed with status: {result.status_code}'
                             f' Reason is: {ERROR_DICT[str(result.status_code)]}')
        else:
            return_error(f'Request Failed with status: {result.status_code} Reason is: {result.reason}')
    if result.text.find("Forbidden. (403)") != -1:
        return_error('Request Forbidden - 403, check SERVER URL and API Key')

    if result.headers['Content-Type'] == 'application/octet-stream':
        return result
    else:
        try:
            json_res = json.loads(xml2json(result.text))
            return json_res
        except Exception:
            return_error(f'Failed to parse response to json. response: {result.text}')


def prettify_upload(upload_body):
    pretty_upload = {
        'MD5': upload_body["md5"],
        'SHA256': upload_body["sha256"],
        'Status': 'Pending'
    }
    if 'filetype' in upload_body:
        pretty_upload["FileType"] = upload_body["filetype"]
    if 'size' in upload_body:
        pretty_upload["Size"] = upload_body["size"]
    if 'url' in upload_body:
        pretty_upload["URL"] = upload_body["url"]

    return pretty_upload


def prettify_report_entry(file_info):
    pretty_report = {
        'MD5': file_info["md5"],
        'SHA256': file_info["sha256"],
        'Status': 'Completed'
    }
    if 'filetype' in file_info:
        pretty_report["FileType"] = file_info["filetype"]
    if 'size' in file_info:
        pretty_report["Size"] = file_info["size"]
    if 'url' in file_info:
        pretty_report["URL"] = file_info["url"]

    return pretty_report


def prettify_verdict(verdict_data):
    pretty_verdict = {}

    if 'md5' in verdict_data:
        pretty_verdict["MD5"] = verdict_data["md5"]
    if 'sha256' in verdict_data:
        pretty_verdict["SHA256"] = verdict_data["sha256"]

    pretty_verdict["Verdict"] = verdict_data["verdict"]
    pretty_verdict["VerdictDescription"] = VERDICTS_DICT[verdict_data["verdict"]]

    return pretty_verdict


def create_dbot_score_from_verdict(pretty_verdict):
    if 'SHA256' not in pretty_verdict and 'MD5' not in pretty_verdict:
        return_error('Hash is missing in WildFire verdict.')
    if pretty_verdict["Verdict"] not in VERDICTS_TO_DBOTSCORE:
        return_error('This hash verdict is not mapped to a DBotScore. Contact Demisto support for more information.')
    dbot_score = {
        'Indicator': pretty_verdict["SHA256"] if 'SHA256' in pretty_verdict else pretty_verdict["MD5"],
        'Type': 'hash',
        'Vendor': 'WildFire',
        'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict["Verdict"]]
    }
    return dbot_score


def prettify_verdicts(verdicts_data):
    pretty_verdicts_arr = []

    for verdict_data in verdicts_data:
        pretty_verdict = {}
        if 'md5' in verdict_data:
            pretty_verdict["MD5"] = verdict_data["md5"]
        if 'sha256' in verdict_data:
            pretty_verdict["SHA256"] = verdict_data["sha256"]

        pretty_verdict["Verdict"] = verdict_data["verdict"]
        pretty_verdict["VerdictDescription"] = VERDICTS_DICT[verdict_data["verdict"]]

        pretty_verdicts_arr.append(pretty_verdict)

    return pretty_verdicts_arr


def create_dbot_score_from_verdicts(pretty_verdicts):
    dbot_score_arr = []

    for pretty_verdict in pretty_verdicts:

        if 'SHA256' not in pretty_verdict and 'MD5' not in pretty_verdict:
            return_error('Hash is missing in WildFire verdict.')
        if pretty_verdict["Verdict"] not in VERDICTS_TO_DBOTSCORE:
            return_error(
                'This hash verdict is not mapped to a DBotScore. Contact Demisto support for more information.')

        dbot_score = {
            'Indicator': pretty_verdict["SHA256"] if "SHA256" in pretty_verdict else pretty_verdict["MD5"],
            'Type': 'hash',
            'Vendor': 'WildFire',
            'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict["Verdict"]]
        }
        dbot_score_arr.append(dbot_score)

    return dbot_score_arr


def create_upload_entry(upload_body, title, result):
    pretty_upload_body = prettify_upload(upload_body)
    md = tableToMarkdown(title, pretty_upload_body, removeNull=True)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            "WildFire.Report(val.SHA256 == obj.SHA256 || val.MD5 == obj.MD5)": pretty_upload_body
        }
    })


def hash_args_handler(sha256=None, md5=None):
    # hash argument used in wildfire-report, wildfire-verdict commands
    inputs = argToList(sha256) if sha256 else argToList(md5)
    for element in inputs:
        if sha256Regex.match(element) or md5Regex.match(element):
            continue
        else:
            return_error('Invalid hash. Only SHA256 and MD5 are supported.')

    return inputs


def file_args_handler(file=None, sha256=None, md5=None):
    # file/md5/sha256 are used in file command
    if (file and not md5 and not sha256) or (not file and md5 and not sha256) or (not file and md5 and not sha256):
        if file:
            inputs = argToList(file)
        elif md5:
            inputs = argToList(md5)
        else:
            inputs = argToList(sha256)

        for element in inputs:
            if sha256Regex.match(element) or md5Regex.match(element) or sha1Regex.match(element):
                continue
            else:
                return_error('Invalid hash. Only SHA256 and MD5 are supported.')

        return inputs

    else:
        return_error('Specify exactly 1 of the following arguments: file, sha256, md5.')


def hash_list_to_file(hash_list):
    file_path = demisto.uniqueFile()
    with open(file_path, 'w') as f:
        f.write("\n".join(hash_list))

    return [file_path]


''' COMMANDS '''


def test_module():
    if wildfire_upload_url('https://www.demisto.com')[1]:
        demisto.results('ok')


@logger
def wildfire_upload_file(upload):
    upload_file_uri = URL + URL_DICT["upload_file"]
    body = {'apikey': TOKEN}

    file_path = demisto.getFilePath(upload)['path']
    file_name = demisto.getFilePath(upload)['name']

    try:
        shutil.copy(file_path, file_name)
    except Exception:
        return_error('Failed to prepare file for upload.')

    try:
        with open(file_name, 'rb') as f:
            result = http_request(
                upload_file_uri,
                'POST',
                body=body,
                files={'file': f}
            )
    finally:
        shutil.rmtree(file_name, ignore_errors=True)

    upload_file_data = result["wildfire"]["upload-file-info"]

    return result, upload_file_data


def wildfire_upload_file_command():
    uploads = argToList(demisto.args().get('upload'))
    for upload in uploads:
        result, upload_file_data = wildfire_upload_file(upload)
        create_upload_entry(upload_file_data, 'WildFire Upload File', result)


@logger
def wildfire_upload_file_url(upload):
    upload_file_url_uri = URL + URL_DICT["upload_file_url"]
    body = f'''--upload_boundry
Content-Disposition: form-data; name="apikey"

{TOKEN}
--upload_boundry
Content-Disposition: form-data; name="url"

{upload}
--upload_boundry--'''

    result = http_request(
        upload_file_url_uri,
        'POST',
        headers=MULTIPART_HEADERS,
        body=body
    )

    upload_file_url_data = result["wildfire"]["upload-file-info"]

    return result, upload_file_url_data


def wildfire_upload_file_url_command():
    uploads = argToList(demisto.args().get('upload'))
    for upload in uploads:
        result, upload_file_url_data = wildfire_upload_file_url(upload)
        create_upload_entry(upload_file_url_data, 'WildFire Upload File URL', result)


@logger
def wildfire_upload_url(upload):
    upload_url_uri = URL + URL_DICT["upload_url"]
    body = '''--upload_boundry
Content-Disposition: form-data; name="apikey"

{apikey}
--upload_boundry
Content-Disposition: form-data; name="link"

{link}
--upload_boundry--'''.format(apikey=TOKEN, link=upload)

    result = http_request(
        upload_url_uri,
        'POST',
        headers=MULTIPART_HEADERS,
        body=body
    )

    upload_url_data = result["wildfire"]["submit-link-info"]

    return result, upload_url_data


def wildfire_upload_url_command():
    uploads = argToList(demisto.args().get('upload'))
    for upload in uploads:
        result, upload_url_data = wildfire_upload_url(upload)
        create_upload_entry(upload_url_data, 'WildFire Upload URL', result)


@logger
def wildfire_get_verdict(file_hash):
    get_verdict_uri = URL + URL_DICT["verdict"]
    body = 'apikey=' + TOKEN + '&hash=' + file_hash

    result = http_request(get_verdict_uri, 'POST', headers=DEFAULT_HEADERS, body=body)
    verdict_data = result["wildfire"]["get-verdict-info"]

    return result, verdict_data


def wildfire_get_verdict_command():
    inputs = hash_args_handler(demisto.args().get('hash'))
    for element in inputs:
        result, verdict_data = wildfire_get_verdict(element)

        pretty_verdict = prettify_verdict(verdict_data)
        md = tableToMarkdown('WildFire Verdict', pretty_verdict, removeNull=True)

        dbot_score = create_dbot_score_from_verdict(pretty_verdict)
        ec = {
            "WildFire.Verdicts(val.SHA256 == obj.SHA256 || val.MD5 == obj.MD5)": pretty_verdict,
            "DBotScore": dbot_score
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': result,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })


@logger
def wildfire_get_verdicts(file_path):
    get_verdicts_uri = URL + URL_DICT["verdicts"]
    body = {'apikey': TOKEN}

    try:
        with open(file_path, 'rb') as f:
            result = http_request(
                get_verdicts_uri,
                'POST',
                body=body,
                files={'file': f}
            )
    finally:
        shutil.rmtree(file_path, ignore_errors=True)

    verdicts_data = result["wildfire"]["get-verdict-info"]

    return result, verdicts_data


def wildfire_get_verdicts_command():
    if ('EntryID' in demisto.args() and 'hash_list' in demisto.args()) or (
            'EntryID' not in demisto.args() and 'hash_list' not in demisto.args()):
        return_error('Specify exactly 1 of the following arguments: EntryID, hash_list.')

    if 'EntryID' in demisto.args():
        inputs = argToList(demisto.args().get('EntryID'))
        paths = [demisto.getFilePath(element)['path'] for element in inputs]

    else:
        paths = hash_list_to_file(argToList(demisto.args().get('hash_list')))

    for file_path in paths:
        result, verdicts_data = wildfire_get_verdicts(file_path)

        pretty_verdicts = prettify_verdicts(verdicts_data)
        md = tableToMarkdown('WildFire Verdicts', pretty_verdicts, removeNull=True)

        dbot_score = create_dbot_score_from_verdicts(pretty_verdicts)
        ec = {
            "WildFire.Verdicts(val.SHA256 == obj.SHA256 || val.MD5 == obj.MD5)": pretty_verdicts,
            "DBotScore": dbot_score
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': result,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })


def create_report(file_hash, reports, file_info, format_='xml', verbose=False):
    udp_ip = []
    udp_port = []
    tcp_ip = []
    tcp_port = []
    dns_query = []
    dns_response = []
    evidence_md5 = []
    evidence_text = []

    # When only one report is in response, it's returned as a single json object and not a list.
    if not isinstance(reports, list):
        reports = [reports]

    for report in reports:
        if 'network' in report and report["network"]:
            if 'UDP' in report["network"]:
                if '-ip' in report["network"]["UDP"]:
                    udp_ip.append(report["network"]["UDP"]["-ip"])
                if '-port' in report["network"]["UDP"]:
                    udp_port.append(report["network"]["UDP"]["-port"])
            if 'TCP' in report["network"]:
                if '-ip' in report["network"]["TCP"]:
                    tcp_ip.append(report["network"]["TCP"]["-ip"])
                if '-port' in report["network"]["TCP"]:
                    tcp_port.append(report["network"]["TCP"]['-port'])
            if 'dns' in report["network"]:
                for dns_obj in report["network"]["dns"]:
                    if '-query' in dns_obj:
                        dns_query.append(dns_obj['-query'])
                    if '-response' in dns_obj:
                        dns_response.append(dns_obj['-response'])

        if 'evidence' in report and report["evidence"]:
            if 'file' in report["evidence"]:
                if isinstance(report["evidence"]["file"], dict) and 'entry' in report["evidence"]["file"]:
                    if '-md5' in report["evidence"]["file"]["entry"]:
                        evidence_md5.append(report["evidence"]["file"]["entry"]["-md5"])
                    if '-text' in report["evidence"]["file"]["entry"]:
                        evidence_text.append(report["evidence"]["file"]["entry"]["-text"])

    outputs = {
        'Status': 'Success',
        'SHA256': file_info["sha256"]
    }

    if len(udp_ip) > 0 or len(udp_port) > 0 or len(tcp_ip) > 0 or len(tcp_port) > 0 or dns_query or dns_response:

        outputs["Network"] = {}

        if len(udp_ip) > 0 or len(udp_port) > 0:
            outputs["Network"]["UDP"] = {}
            if len(udp_ip) > 0:
                outputs["Network"]["UDP"]["IP"] = udp_ip
            if len(udp_port) > 0:
                outputs["Network"]["UDP"]["Port"] = udp_port

        if len(tcp_ip) > 0 or len(tcp_port) > 0:
            outputs["Network"]["TCP"] = {}
            if len(tcp_ip) > 0:
                outputs["Network"]["TCP."]["IP"] = tcp_ip
            if len(tcp_port) > 0:
                outputs["Network"]["TCP"]["Port"] = tcp_port

        if len(dns_query) > 0 or len(dns_response) > 0:
            outputs["Network"]["DNS"] = {}
            if len(dns_query) > 0:
                outputs["Network"]["DNS"]["Query"] = dns_query
            if len(dns_response) > 0:
                outputs["Network"]["DNS"]["Response"] = dns_response

    if len(evidence_md5) > 0 or len(evidence_text) > 0:
        outputs["Evidence"] = {}
        if len(evidence_md5) > 0:
            outputs["Evidence"]["md5"] = evidence_md5
        if len(evidence_text) > 0:
            outputs["Evidence"]["Text"] = evidence_text

    ec = {}
    ec["DBotScore"] = {
        'Indicator': file_hash,
        'Type': 'hash',
        'Vendor': 'WildFire',
        'Score': 0
    }
    ec["WildFire.Report(val.SHA256 === obj.SHA256)"] = outputs

    if file_info:
        if file_info["malware"] == 'yes':
            ec["DBotScore"]["Score"] = 3
            ec[outputPaths['file']] = {
                'Type': file_info["filetype"],
                'MD5': file_info["md5"],
                'SHA1': file_info["sha1"],
                'SHA256': file_info["sha256"],
                'Size': file_info["size"],
                'Name': file_info["filename"] if 'filename' in file_info else None,
                'Malicious': {'Vendor': 'WildFire'}
            }
        else:
            ec["DBotScore"]["Score"] = 1
    if format_ == 'pdf':
        get_report_uri = URL + URL_DICT["report"]
        params = {
            'apikey': TOKEN,
            'format': 'pdf',
            'hash': file_hash
        }

        res_pdf = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params)

        file_name = 'wildfire_report_' + file_hash + '.pdf'
        file_type = entryTypes['entryInfoFile']
        result = fileResult(file_name, res_pdf.content,
                            file_type)  # will be saved under 'InfoFile' in the context.
        result['EntryContext'] = ec

        demisto.results(result)

    else:
        md = tableToMarkdown('WildFire Report', prettify_report_entry(file_info))
        if verbose:
            for report in reports:
                if isinstance(report, dict):
                    md += tableToMarkdown('Report ', report, list(report), removeNull=True)

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': reports,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })


@logger
def wildfire_get_report(file_hash):
    get_report_uri = URL + URL_DICT["report"]
    params = {
        'apikey': TOKEN,
        'format': 'xml',
        'hash': file_hash
    }

    json_res = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params)

    if not json_res:
        demisto.results('Report not found')
        sys.exit(0)

    task_info = json_res["wildfire"].get('task_info', None)
    reports = task_info.get('report', None) if task_info else None
    file_info = json_res["wildfire"].get('file_info', None)

    if not reports or not file_info:
        demisto.results('The sample is still being analyzed. Please wait to download the report')
        sys.exit(0)
    return file_hash, reports, file_info


def wildfire_get_report_command():
    if 'sha256' in demisto.args():
        sha256 = demisto.args().get('sha256', None)
    elif 'hash' in demisto.args():
        sha256 = demisto.args().get('hash', None)
    else:
        sha256 = None
    md5 = demisto.args().get('md5', None)
    inputs = hash_args_handler(sha256, md5)

    verbose = demisto.args().get('verbose', 'false').lower() == 'true'
    format_ = demisto.args().get('format', 'xml')
    for element in inputs:
        file_hash, report, file_info = wildfire_get_report(element)
        create_report(file_hash, report, file_info, format_, verbose)


def wildfire_file_command():
    inputs = file_args_handler(demisto.args().get('file'), demisto.args().get('md5'), demisto.args().get('sha256'))
    for element in inputs:
        if sha1Regex.match(element):
            demisto.results({
                'Type': 11,
                'Contents': 'WildFire file hash reputation supports only MD5, SHA256 hashes',
                'ContentsFormat': formats['text']
            })
        else:
            file_hash, report, file_info = wildfire_get_report(element)
            create_report(file_hash, report, file_info, 'xml', False)


def wildfire_get_sample(file_hash):
    get_report_uri = URL + URL_DICT["sample"]
    params = {
        'apikey': TOKEN,
        'hash': file_hash
    }

    result = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params)
    return result


def wildfire_get_sample_command():
    if 'sha256' or 'hash' in demisto.args():
        sha256 = demisto.args().get('sha256', None)
    else:
        sha256 = None
    md5 = demisto.args().get('md5', None)
    inputs = hash_args_handler(sha256, md5)

    for element in inputs:
        result = wildfire_get_sample(element)

        headers_string = str(result.headers)
        file_name = headers_string.split("filename=", 1)[1]

        # will be saved under 'File' in the context, can be farther investigated.
        file_entry = fileResult(file_name, result.content)

        demisto.results(file_entry)


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))

    try:
        # Remove proxy if not set to true in params
        handle_proxy()

        if demisto.command() == 'test-module':
            test_module()

        elif demisto.command() == 'wildfire-upload':
            wildfire_upload_file_command()

        elif demisto.command() in ['wildfire-upload-file-remote', 'wildfire-upload-file-url']:
            wildfire_upload_file_url_command()

        elif demisto.command() == 'wildfire-upload-url':
            wildfire_upload_url_command()

        elif demisto.command() == 'wildfire-report':
            wildfire_get_report_command()

        elif demisto.command() == 'file':
            wildfire_file_command()

        elif demisto.command() == 'wildfire-get-sample':
            wildfire_get_sample_command()

        elif demisto.command() == 'wildfire-get-verdict':
            wildfire_get_verdict_command()

        elif demisto.command() == 'wildfire-get-verdicts':
            wildfire_get_verdicts_command()

    except Exception as ex:
        return_error(str(ex))

    finally:
        LOG.print_log()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
