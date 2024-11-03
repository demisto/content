import demistomock as demisto
from CommonServerPython import *
'''IMPORTS'''
import requests
import base64
import urllib3

urllib3.disable_warnings()

'''INTEGRATION PARAMS'''
API_TOKEN = demisto.params().get('apitoken')
URL_BASE = demisto.params().get('url')
USE_PROXY = demisto.params().get('proxy', False)
UNSECURE = not demisto.params().get('insecure', False)

'''CONSTANTS'''
READ_BINARY_MODE = 'rb'
SLASH = '/'
SCAN_FILE_URL = 'direct/scan/file/'
GET_FILE_VERDICT_URL = 'direct/verdict/?hash={}'
TOKEN_PREFIX = 'Bearer'  # guardrails-disable-line
RESPONSE_CODE_OK = 200
STATUS_IN_PROGRESS = 'IN_PROGRESS'
STATUS_DONE = 'DONE'
AUTH_HEADERS = {
    'Authorization': f"{TOKEN_PREFIX} {API_TOKEN}"
}

VERDICT_SCANNING = 'Scanning'
VERDICT_MALICIOUS = 'Malicious'
VERDICT_APPROVED = 'Approved'
VERDICT_ERROR = 'Error'
VERDICT_BENIGN = 'Benign'
VERDICT_TIMEOUT = 'Timeout'
SCAN_ONGOING = 'Still scanning...'

BITDAM_COMMAND_PREFIX = 'bitdam'
DBOTSCORE_UNKNOWN = 0
DBOTSCORE_CLEAN = 1
DBOTSCORE_MALICIOUS = 3

'''HANDLE PROXY'''
handle_proxy()


'''HELPER FUNCTIONS'''


def get_file_bytes(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    with open(file_path, READ_BINARY_MODE) as fopen:
        bytes = fopen.read()
    return base64.b64encode(bytes)


def get_url_base_with_trailing_slash():
    '''
    Returns the intergation's base url parameter, making sure it contains an trailing slash
    '''
    url_base = URL_BASE
    return url_base if url_base.endswith(SLASH) else url_base + SLASH


def build_json_response(content, context, human_readable):
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': content,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(human_readable, content),
        'EntryContext': context
    }


def get_file_name(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    return get_file_path_res["name"]


def verdict_to_dbotscore(verdict):
    if verdict == VERDICT_APPROVED:
        return DBOTSCORE_CLEAN
    elif verdict == VERDICT_MALICIOUS:
        return DBOTSCORE_MALICIOUS
    elif verdict == VERDICT_SCANNING:
        return DBOTSCORE_UNKNOWN
    else:
        return DBOTSCORE_UNKNOWN


'''API_IMPL'''


def scan_file():
    response = scan_file_command()
    returned_sha1 = parse_scan_file_response(response)
    # Build demisto reponse
    response_content = {'SHA1': returned_sha1}
    response_context = {'BitDam': {'FileScan': {'SHA1': returned_sha1}}}
    return build_json_response(response_content, response_context, "File was submitted successfully")


def scan_file_command():
    # Get data to build the request
    entry_id = demisto.args().get('entryId')
    file_name = get_file_name(entry_id)
    file_bytes = get_file_bytes(entry_id)
    json_data = {'file_name': file_name,
                 'file_data_base64': base64.b64encode(file_bytes)}
    raw_json = json.dumps(json_data, ensure_ascii=False)
    url = f"{get_url_base_with_trailing_slash()}{SCAN_FILE_URL}"

    # Send the HTTP request
    response = requests.post(url, data=raw_json, headers=AUTH_HEADERS, verify=UNSECURE)
    return response


def parse_scan_file_response(response):
    # Parse response
    if response.status_code != RESPONSE_CODE_OK:
        raise Exception(f"Scan file failed. Response code -{str(response.status_code)}, Data- '{response.content}'")
    response_json = json.loads(response.content)
    if 'sha1' not in response_json:
        raise Exception(
            f"Scan file failed. Bad response json - {response.content}")
    returned_sha1 = response_json['sha1']
    return returned_sha1


def get_file_verdict():
    identifier_value = demisto.args().get('idValue')
    response = get_file_verdict_command(identifier_value)
    verdict, status = parse_get_file_verdict_response(response)
    response_content = {'STATUS': status,
                        'VERDICT': verdict,
                        'ID': identifier_value}
    context = {}
    context['BitDam.Analysis(val.ID && val.ID == obj.ID)'] = {
        'Status': status,
        'Verdict': verdict,
        'ID': identifier_value
    }

    if verdict == VERDICT_MALICIOUS:
        context[outputPaths['file']] = {'SHA1': identifier_value}
        context[outputPaths['file']]['Malicious'] = {
            'Vendor': 'BitDam',
            'Description': 'Process whitelist inconsistency by bitdam-get-file-verdict',
            'Name': identifier_value
        }

    dbotscore = verdict_to_dbotscore(verdict)
    if dbotscore:
        context[outputPaths['dbotscore']] = {
            'Indicator': identifier_value,
            'Type': 'File',
                    'Vendor': 'BitDam',
                    'Score': dbotscore
        }
    response_context = context
    return build_json_response(response_content, response_context,
                               "Get file verdict was performed successfully")


def parse_get_file_verdict_response(response):
    # Parse results
    if response.status_code != RESPONSE_CODE_OK:
        raise Exception(f"Get file verdict failed. Response code -{str(response.status_code)}, Data- '{response.content}'")
    response_json = json.loads(response.content)
    status = ''
    verdict = ''
    if 'scan_data' not in response_json or 'verdict' not in response_json['scan_data']:
        raise Exception(f"Get file verdict failed. Unknown response schema. Data- '{response.content}'")

    verdict = response_json['scan_data']['verdict']
    if verdict == SCAN_ONGOING or verdict == VERDICT_SCANNING:
        # Still in progress
        verdict = VERDICT_SCANNING
        status = STATUS_IN_PROGRESS
    else:
        status = STATUS_DONE

    return verdict, status


def get_file_verdict_command(identifier_value):
    # Get data to build the request
    scan_file_relative_url_formatted = GET_FILE_VERDICT_URL.format(identifier_value)

    url = f"{get_url_base_with_trailing_slash()}{scan_file_relative_url_formatted}"
    # Send the request
    response = requests.get(url, headers=AUTH_HEADERS, verify=UNSECURE)
    return response


def upload_test_file_to_scan():
    d = {
        "file_name": "demisto.txt",
        "file_data_base64": 'ZGVtaXN0bw=='
    }
    url = f"{get_url_base_with_trailing_slash()}{SCAN_FILE_URL}"
    response = requests.post(url, headers=AUTH_HEADERS, json=d, verify=UNSECURE)
    return response


def test_module():
    response = upload_test_file_to_scan()
    if response.status_code == RESPONSE_CODE_OK:
        return True
    raise Exception(f"Status code - {str(response.status_code)}, Error- '{response.content}'")


'''COMMAND_CLASIFIER'''
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        if test_module():
            demisto.results('ok')
        sys.exit(0)
    elif demisto.command() == 'bitdam-upload-file':
        demisto.results(scan_file())
    elif demisto.command() == 'bitdam-get-verdict':
        demisto.results(get_file_verdict())
except Exception as e:
    LOG(e)
    return_error(f"Error: {str(e)}")
