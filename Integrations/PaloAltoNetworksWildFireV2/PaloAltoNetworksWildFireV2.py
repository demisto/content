import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import requests
from base64 import b64encode
import re

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
URL = demisto.getParam('server')
TOKEN = demisto.getParam('token')
USE_SSL = not demisto.params().get('insecure', False)
DEFAULT_HEADERS = {'Content-Type': ['application/x-www-form-urlencoded']}
 
URL_DICT = {
    'verdict': '/get/verdict',
    'verdicts': '/get/verdicts',
    'upload_file': '/submit/file',
    'upload_url': '/submit/link',
    'upload_file_url': '/submit/url',
    'report': '/get/report'
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


def http_request(uri, method, headers={}, body={}, params={}, files={}):
    """
    Makes an API call with the supplied uri, method, headers, body
    """
    LOG('running request with url=%s' % uri)
    url = '%s/%s' % (URL, uri)
    result = requests.request(
        method,
        url,
        headers=headers,
        data=body,
        verify=USE_SSL,
        params=params,
        files=files
    )

    if result.status_code < 200 or result.status_code >= 300:
        if result.status_code in ERROR_DICT:
            return_error('Request Failed with status: ' + str(result.status_code) + '. Reason is: ' + ERROR_DICT[
                result.status_code])
        else:
            return_error('Request Failed with status: ' + str(result.status_code) + '. Reason is: ' + str(result.reason))

    return result.content


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
        if verdict_data["md5"]:
            pretty_verdict["MD5"] = verdict_data["md5"]
        if verdict_data["sha256"]:
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
    md = tableToMarkdown(title, upload_body)
    return {
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            "WildFire.Report(val.SHA256 == obj.SHA256 || val.MD5 == obj.MD5)": prettify_upload(upload_body)
        }
    }


def create_report_entry(body, title, result, verbose, reports, ec):
    md = tableToMarkdown(title, body, body.keys())

    if verbose:
        for report in reports:
            md += tableToMarkdown('Report ', report, report.keys())

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def hash_args_handler(sha256 = None, md5 = None):
    # hash argument used in wildfire-report, wildfire-verdict commands
    inputs = argToList(sha256) if sha256 else argToList(md5)
    for input in inputs:
        if sha256Regex.match(input) or md5Regex.test(input):
            continue
        else:
            return_error('Invalid hash. Only SHA256 and MD5 are supported.')

    return inputs


def file_args_handler(file = None, sha256 = None, md5 = None):
    # file/md5/sha256 are used in file command
    if (file and not md5 and not sha256) or (not file and md5 and not sha256) or (not file and md5 and not sha256):
        if file:
            inputs = argToList(file)
        elif md5:
            inputs = argToList(md5)
        else:
            inputs = argToList(sha256)

        for input in inputs:
            if sha1Regex.match(input):  # validate hash is not sha1
                demisto.results('SHA1')
            elif sha256Regex.match(input) or md5Regex.test(input):
                continue
            else:
                return_error('Invalid hash. Only SHA256 and MD5 are supported.')

        return inputs

    else:
        return_error('Specify exactly 1 of the following arguments: file, sha256, md5.')


''' COMMANDS '''
def test_module():
    test_url = URL + URL_DICT["report"]
    test_result = http_request(
        test_url,
        {'Method': 'POST',
         'Body': 'apikey=' + TOKEN + '&format=xml&hash=7f638f13d0797ef9b1a393808dc93b94',
         'Headers': DEFAULT_HEADERS}
    )

    if test_result["status_code"] == 200:
        demisto.results('ok')


@logger
def wildfire_upload_file(upload):
    upload_file_uri = URL + URL_DICT["upload_file"]
    body = {
        'apikey': TOKEN,
        'file': upload
    }

    result = http_request(upload_file_uri, DEFAULT_HEADERS, upload, body)
    upload_file_data = result["wildfire"]["upload-file-info"]

    return result, upload_file_data


def wildfire_upload_file_command():
    uploads = argToList(demisto.args(['upload']))
    for upload in uploads:
        result, upload_file_data = wildfire_upload_file(upload)
        create_upload_entry(upload_file_data, 'WildFire Upload File', result)


@logger
def wildfire_upload_file_url(upload):
    upload_file_url_uri = URL + URL_DICT["upload_file_url"]
    body = {
        'apikey': TOKEN,
        'file': upload
    }

    result = http_request(upload_file_url_uri, DEFAULT_HEADERS, upload, body)
    upload_file_url_data = result["wildfire"]["upload-file-info"]

    return result, upload_file_url_data


def wildfire_upload_file_url_command():
    uploads = argToList(demisto.args(['upload']))
    for upload in uploads:
        result, upload_file_url_data = wildfire_upload_file_url(upload)
        create_upload_entry(upload_file_url_data, 'WildFire Upload File URL', result)


@logger
def wildfire_upload_url(upload):
    upload_url_uri = URL + URL_DICT["upload_url"]
    body = {
        'apikey': TOKEN,
        'link': upload
    }

    result = http_request(upload_url_uri, DEFAULT_HEADERS, '', body);
    upload_url_data = result["wildfire"]["submit-link-info"]

    return result, upload_url_data


def wildfire_upload_url_command():
    uploads = argToList(demisto.args(['upload']))
    for upload in uploads:
        result, upload_url_data = wildfire_upload_url(upload)
        create_upload_entry(upload_url_data, 'WildFire Upload URL', result)


@logger
def wildfire_get_verdict(hash):
    get_verdict_uri = URL + URL_DICT["verdict"]
    body = 'apikey=' + TOKEN + '&hash=' + hash;

    result = http_request(get_verdict_uri, body, DEFAULT_HEADERS);

    jres = json.loads(result["body"])
    verdict_data = jres["wildfire"]["get-verdict-info"]

    return jres, verdict_data


def wildfire_get_verdict_command():
    inputs = hash_args_handler(demisto.args(['hash']))
    for input in inputs:
        jres, verdict_data = wildfire_get_verdict(input)

        pretty_verdict = prettify_verdict(verdict_data)
        md = tableToMarkdown('WildFire Verdict', pretty_verdict)

        dbot_score = create_dbot_score_from_verdict(pretty_verdict)
        ec = {
            "WildFire.Verdicts(val.SHA256 == obj.SHA256 || val.MD5 == obj.MD5)": pretty_verdict,
            "DBotScore(val.Indicator == obj.Indicator)": dbot_score
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': jres,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })


@logger
def wildfire_get_verdicts(entry_id):
    get_verdicts_uri = URL + URL_DICT["verdicts"]
    body = {'apikey': TOKEN}

    result = http_request(get_verdicts_uri, DEFAULT_HEADERS, entry_id, body)
    verdicts_data = result["wildfire"]["get-verdict-info"]

    return result, verdicts_data


def wildfire_get_verdicts_command():
    inputs = argToList(demisto.args(['EntryID']))
    for input in inputs:
        result, verdicts_data = wildfire_get_verdicts(input)
        
        pretty_verdicts = prettify_verdicts(verdicts_data)
        md = tableToMarkdown('WildFire Verdicts', pretty_verdicts);

        dbot_score = create_dbot_score_from_verdicts(pretty_verdicts)
        ec = {
            "WildFire.Verdicts(val.SHA256 == obj.SHA256 || val.MD5 == obj.MD5)": pretty_verdicts,
            "DBotScore(val.Indicator == obj.Indicator)": dbot_score
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': result,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })


def create_report(report_response, format, verbose):
    reportUrl = URL + URL_DICT.report;
    var
    result = reportResponse.result;
    var
    report = reportResponse.report;
    var
    file_info = reportResponse.info;
    var
    hash = reportResponse.hash;

    udp_ip = [];
    udp_port = [];
    tcp_ip = [];
    tcp_port = [];
    dns_query = [];
    dns_response = [];
    evidence_md5 = [];
    evidence_text = [];

    for (var i = 0; i < report.length; i++) {
    if ('network' in report[i]) {
    if (report[i].network) {
    if ('UDP' in report[i].network) {
    if ('-ip' in report[i].network.UDP) {
    udp_ip.push(report[i].network.UDP['-ip']);
    }
    if ('-port' in report[i].network.UDP) {
    udp_port.push(report[i].network.UDP['-port']);
    }
    }
    if ('TCP' in report[i].network) {
    if ('-ip' in report[i].network.TCP) {
    tcp_ip.push(report[i].network.TCP['-ip']);
    }
    if ('-port' in report[i].network.TCP) {
    tcp_port.push(report[i].network.TCP['-port']);
    }
    }
    if ('dns' in report[i].network) {
    for (var j = 0; j < report[i].network.dns.length; j++) {
    if ('-query' in report[i].network.dns[j]) {
    dns_query.push(report[i].network.dns[j]['-query']);
    }
    if ('-response' in report[i].network.dns[j]) {
    dns_response.push(report[i].network.dns[j]['-response']);
    }
    }
    }
    }
    }
    if ('evidence' in report[i]) {
    if ('file' in report[i].evidence) {
    if (typeof report[i].evidence.file == 'object' & & 'entry' in report[i].evidence.file) {
    if ('-md5' in report[i].evidence.file.entry) {
    evidence_md5.push(report[i].evidence.file.entry['-md5']);
    }
    if (typeof report[i].evidence.file == 'object' & & '-text' in report[i].evidence.file.entry) {
    evidence_text.push(report[i].evidence.file.entry['-text']);
    }
    }
    }
    }
    }

    var
    context = {
        DBotScore: {Indicator: hash, Type: 'hash', Vendor: 'WildFire', Score: 0}
    };

    var
    outputs = {
        'Status': 'Success',
        'SHA256': reportResponse.info.sha256,
    };

    if (udp_ip.length | | udp_port.length | | tcp_ip.length | | tcp_port.length | | dns_query | | dns_response) {

    outputs.Network = {};

    if (udp_ip.length | | udp_port.length) {
    outputs.Network.UDP = {};
    if (udp_ip.length) {
    outputs.Network.UDP.IP = udp_ip;
    }
    if (udp_port.length) {
    outputs.Network.UDP.Port = udp_port;
    }
    }
    if (tcp_ip.length | | tcp_port.length) {
    outputs.Network.TCP = {};
    if (tcp_ip.length) {
    outputs.Network.TCP.IP = tcp_ip;
    }
    if (tcp_port.length) {
    outputs.Network.TCP.Port = tcp_port;
    }
    }
    if (dns_query.length | | dns_response.length) {
    outputs.Network.DNS = {};
    if (dns_query.length) {
    outputs.Network.DNS.Query = dns_query;
    }
    if (dns_response.length) {
    outputs.Network.DNS.Response = dns_response;
    }
    }
    }

    if (evidence_md5.length | | evidence_text.length) {
    outputs.Evidence = {};
    if (evidence_md5.length) {
    outputs.Evidence.md5 = evidence_md5;
    }
    if (evidence_text.length) {
    outputs.Evidence.Text = evidence_text;
    }
    }

    context["WildFire.Report(val.SHA256 === obj.SHA256)"] = outputs;

    if (file_info) {
    if (file_info.malware == = 'yes') {
    context.DBotScore.Score = 3;
    addMalicious(context, outputPaths.file, {
    Type: file_info.filetype,
          MD5: file_info.md5,
    SHA1: file_info.sha1,
    SHA256: file_info.sha256,
    Size: file_info.size,
    Name: file_info.filename,
    Malicious: {Vendor: 'WildFire'}
    });
    } else {
        context.DBotScore.Score = 1;
    }
    }
    if (format === 'pdf'){
    var bodyPDF = 'apikey=' + TOKEN + '&format=pdf&hash=' + hash;
    var resPDF = sendRequest(reportUrl, bodyPDF, DEFAULT_HEADERS).Bytes;
    var currentTime = new Date();
    var fileName = command + '_at_' + currentTime.getTime();
    return {
        Type: 9,
        FileID: saveFile(resPDF),
        File: fileName,
        Contents: fileName,
        EntryContext: context
    };
    }
    else {
    create_report_entry(file_info, 'WildFire Report', result, verbose, report, context)


@logger
def wildfire_get_report(hash):
    get_report_uri = URL + URL_DICT["report"]
    body_xml = 'apikey=' + TOKEN + '&format=xml&hash=' + hash

    res_xml = http_request(get_report_uri, body_xml, DEFAULT_HEADERS)

    if not res_xml:
        'Report not found'
    res_xml_body = res_xml["body"]
    else if not res_xml_body:
        return 'No results yet'

    jres = json.loads(res_xml_body)
    report = jres["wildfire"]["task_info.report"]
    file_info = jres["wildfire"]["file_info"]
    if not report or not file_info:
        return 'No results yet'

    return hash, jres, report, file_info


def wildfire_get_report_command():
    if 'sha256' or 'hash' in demisto.args():
        sha256 = demisto.args(["sha256"]) if 'sha256' in demisto.args() else demisto.args(["hash"])
    else:
        sha256 = None
    md5 = demisto.args(["md5"]) if "md5" in demisto.args(["md5"]) else None
    inputs = hash_args_handler(sha256, md5)
    for input in inputs:
        hash, jres, report, file_info = wildfire_get_report(input)
        create_report(hash, jres, report, file_info)


''' EXECUTION '''
LOG('command is %s' % (demisto.command(),))

try:
    # Remove proxy if not set to true in params
    handle_proxy()

    if demisto.command() == 'test-module':
        test_module()

    elif demisto.command() == 'wildfire-upload':
        wildfire_upload_file_command()

    elif demisto.command() in ['wildfire-upload-dile-remote', 'wildfire-upload-file-url']:
        wildfire_upload_file_url_command()

    elif demisto.command() == 'wildfire-upload-url':
        wildfire_upload_url_command()

    elif demisto.command() == 'wildfire-report':
        wildfire_get_report_command()

    elif demisto.command() == 'file':
        file_command()

    elif demisto.command() == 'wildfire-get-verdict':
        wildfire_get_verdict_command()

    elif demisto.command() == 'wildfire-get-verdicts':
        wildfire_get_verdicts_command()


except Exception as ex:
    return_error(str(ex))

finally:
    LOG.print_log()