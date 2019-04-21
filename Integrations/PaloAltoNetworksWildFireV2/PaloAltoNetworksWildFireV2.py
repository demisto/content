import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import requests
from base64 import b64encode

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
URL = demisto.getParam('server')
TOKEN = demisto.getParam('token')
USE_SSL = not demisto.params().get('insecure', False)
DEFAULT_HEADERS = {'Content-Type': ['application/x-www-form-urlencoded']}

handle_proxy()

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
            return_error('Request Failed with status: ' + str(res.status_code) + '. Reason is: ' + ERROR_DICT[
                result.status_code])
        else:
            return_error('Request Failed with status: ' + str(res.status_code) + '. Reason is: ' + str(res.reason))

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


def create_entry(body, title, result, verbose, reports, ec):
    md = tableToMarkdown(title, body, body.keys())

    if verbose:
        for report in reports:
            md += tableToMarkdown('Report ', report, report.keys())

    return {
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    }


def hash_args_handler(md5, hash, file):
    if file:
        if MD5_REGEX.test(file) SHA256_REGEX.test(file:
            return [file];
        else:
        return_error('Invalid hash. Only SHA256 and MD5 are supported.')

    else:
        inputs = md5? argToList(md5): argToList(hash);
        for (i = 0; i < inputs.length; i++):
            if (SHA256_REGEX.test(inputs[i]) | | MD5_REGEX.test(inputs[i]))
                continue;
            else:
                return_error('Invalid hash. Only SHA256 and MD5 are supported.')

    return inputs;

''' COMMANDS '''

function
uploadFile(upload)
{
    uri = URL + URL_DICT.upload;
var
body = {
    'apikey': TOKEN,
    'file': upload
};
var
result = sendMultipartRequest(uri, DEFAULT_HEADERS, upload, body);
var
uploadData = dq(result, 'wildfire.upload-file-info');
var
returnObj = {
    res: result,
    data: uploadData
};
return returnObj;
}


function
getVerdicts(EntryID)
{
uri = URL + URL_DICT.verdicts;
var
body = {'apikey': TOKEN};
var
result = sendMultipartRequest(uri, DEFAULT_HEADERS, EntryID, body);

var
verdictsData = dq(result, 'wildfire.get-verdict-info');

var
prettyVerdicts = prettifyVerdicts(verdictsData);
var
md = tableToMarkdown('WildFire Verdicts', prettyVerdicts);

var
dbotScore = createDBotScoreFromVerdicts(prettyVerdicts);
var
ec = {
    "WildFire.Verdicts(val.SHA256 === obj.SHA256 || val.MD5 === obj.MD5)": prettyVerdicts,
    "DBotScore(val.Indicator === obj.Indicator)": dbotScore
};

return {
    Type: entryTypes.note,
    Contents: result,
    ContentsFormat: formats.json,
    HumanReadable: md,
    ReadableContentsFormat: formats.markdown,
    EntryContext: ec
};
}


function
getVerdict(hash)
{
var
uri = URL + URL_DICT.verdict;

var
body = 'apikey=' + TOKEN + '&hash=' + hash;
var
result = sendRequest(uri, body, DEFAULT_HEADERS);
var
jres = JSON.parse(x2j(result.Body));

var
verdictData = dq(jres, 'wildfire.get-verdict-info');

var
prettyVerdict = prettifyVerdict(verdictData);
var
md = tableToMarkdown('WildFire Verdict', prettyVerdict);

var
dbotScore = createDBotScoreFromVerdict(prettyVerdict);
var
ec = {
    "WildFire.Verdicts(val.SHA256 === obj.SHA256 || val.MD5 === obj.MD5)": prettyVerdict,
    "DBotScore(val.Indicator === obj.Indicator)": dbotScore
};

return {
    Type: entryTypes.note,
    Contents: jres,
    ContentsFormat: formats.json,
    HumanReadable: md,
    ReadableContentsFormat: formats.markdown,
    EntryContext: ec
};
}


function
uploadFileRemote(upload)
{
var
uri = URL + URL_DICT.remoteFile;

var
body = {
    apikey: TOKEN,
    url: upload
};
var
result = sendMultipartRequest(uri, DEFAULT_HEADERS, '', body);

var
uploadData = dq(result, 'wildfire.upload-file-info');

var
returnObj = {
    res: result,
    data: uploadData
};
return returnObj;
}


function
uploadUrl(upload)
{
var
uri = URL + URL_DICT.uploadUrl;

var
body = {
    apikey: TOKEN,
    link: upload
};
var
result = sendMultipartRequest(uri, DEFAULT_HEADERS, '', body);

var
uploadData = dq(result, 'wildfire.submit-link-info');

var
returnObj = {
    res: result,
    data: uploadData
};
return returnObj;
}


function
getReport(hash)
{
var
reportUrl = URL + URL_DICT.report;

var
bodyXML = 'apikey=' + TOKEN + '&format=xml&hash=' + hash;
var
resXML = sendRequest(reportUrl, bodyXML, DEFAULT_HEADERS);

if (!resXML){
return {error: 'Report not found'};
}
var
resXMLBody = resXML.Body;
if (!resXMLBody)
{
return {error: 'No results yet'};
}

var
result = JSON.parse(x2j(resXMLBody));
var
report = dq(result, 'wildfire.task_info.report');
var
file_info = dq(result, 'wildfire.file_info');
if (!report | | !file_info)
{
return {error: 'No results yet'};
}

var
returnObj = {
hash: hash,
result: result,
report: report,
info: file_info
};
return returnObj;
}


function
createReport(reportResponse, format, verbose)
{
var
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
return createEntry(file_info, 'WildFire Report', result, verbose, report, context);
}
}


function
detonate(type, upload, format, delay, timeout, verbose)
{
    var
uploadData;
if (type === 'file')
{
uploadData = uploadFile(upload).data;
} else { // type is remote
file
uploadData = uploadFileRemote(upload).data;
}
var
sha = uploadData.sha256;
delayTime = parseInt(delay);
timeOut = parseInt(timeout);
var
waitTime = delayTime;
wait(delayTime);

while (waitTime < timeOut) {
var reportResponse = getReport(undefined, sha);
if (reportResponse.result) {
return createReport(reportResponse, format, verbose);
} else {
waitTime = waitTime + delayTime;
wait(delayTime);
}
}
throw('Timeout due to no answer after ' + timeOut + ' seconds.');
}


switch(command)
{
    case
'test-module': // This is the
call
made
when
pressing
the
integration
test
button. \
    testUrl = URL + URL_DICT.report;
var
res = http(
    testUrl,
    {
Method: 'POST',
Body: 'apikey=' + TOKEN + '&format=xml&hash=7f638f13d0797ef9b1a393808dc93b94',
Headers: DEFAULT_HEADERS
},
params.insecure,
params.proxy
);
if (res.StatusCode === 200) {
return 'ok';
}
else {
return 'Something went wrong.\n Status code: ' + res.StatusCode + '\nBody: ' + JSON.stringify(res) + '.';
}
break;

case
'wildfire-upload':
inputs = argToList(args.upload);
entries = [];
for (i=0; i < inputs.length; i++) {
    var response = uploadFile(inputs[i]);
var uploadData = response.data;
var result = response.res;
entries.push(createUploadEntry(uploadData, 'WildFire Upload File', result));
}
return entries;

case
'wildfire-upload-file-remote': // deprecated
case
'wildfire-upload-file-url':
var
response = uploadFileRemote(args.upload);
var
uploadData = response.data;
var
result = response.res;
return createUploadEntry(uploadData, 'WildFire Upload File URL', result);

// case
'wildfire-upload-url':
// inputs = argToList(args.upload);
// entries = [];
// for (i=0; i < inputs.length; i++) {
                                     // var response = uploadUrl(inputs[i]);
// var uploadData = response.data;
// var result = response.res;
// entries.push(createUploadEntry(uploadData, 'WildFire Upload URL', result));
//}
// return entries;

case
'file':
case
'wildfire-report':
var
inputs = hashArgsHandler(args.md5, args.hash, args.file);
entries = [];
for (i=0; i < inputs.length; i++) {
    var reportResponse = getReport(inputs[i]);
if (reportResponse.error){
return reportResponse.error;
}
entries.push(createReport(reportResponse, args.format, args.verbose));
}
return entries;

case
'wildfire-get-verdict':
var
inputs = hashArgsHandler('', args.hash, '');
var
entries = [];
for (i=0; i < inputs.length; i++) {
    var entry = getVerdict(inputs[i]);
entries.push(entry);
}
return entries;

case
'wildfire-get-verdicts':
var
inputs = argToList(args.EntryID);
var
entries = [];
for (i=0; i < inputs.length; i++) {
    var entry = getVerdicts(inputs[i]);
entries.push(entry);
}
return entries;

case
'detonate-file': // deprecated, please
use
WildFire
Detonate
playbook
return detonate('file', args.upload, args.format, args.delay, args.timeout, args.verbose);

case
'detonate-file-remote': // deprecated, please
use
WildFire
Detonate
playbook
return detonate('remoteFile', args.upload, args.format, args.delay, args.timeout);
}
