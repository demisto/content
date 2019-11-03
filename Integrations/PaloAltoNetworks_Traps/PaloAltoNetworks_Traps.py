''' IMPORTS '''
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests
import copy
import jwt

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS['url'][:-1] \
    if (PARAMS['url'] and PARAMS['url'].endswith('/')) else PARAMS['url']
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
# Service base URL
BASE_URL = SERVER + '/xapi/v1/'
APPLICATION_ID = PARAMS.get('application_id')
PRIVATE_KEY = PARAMS.get('private_key')
# Headers to be sent in requests
REQUEST_HEADERS = {
    'Content-Type': 'application/json'
}

OUTPUTS = {
    'get_endpoint_by_id': {
        'ID': 'guid',
        'Name': 'name',
        'Domain': 'domain',
        'Platform': 'platform',
        'Status': 'status',
        'IP': 'ip',
        'ComputerSid': 'computerSid',
        'IsCompromised': 'compromised',
        'OsVersion': 'osVersion',
        'OsProductType': 'osProductType',
        'OsProductName': 'osProductName',
        'Is64': 'is64',
        'LastSeen': 'lastSeen',
        'LastUser': 'lastUser'
    },
    'endpoint_files_retrieve': {
        'OperationID': 'operationId'
    },
    'endpoint_isolate': {
        'OperationID': 'operationId'
    },
    'endpoint_scan': {
        'OperationID': 'operationId'
    },
    'event_bulk_update_status': {
        'EventID': 'eventGuid'
    },
    'hashes_blacklist_status': {
        'SHA256': 'hash',
        'BlacklistStatus': 'status'
    },
    'event_quarantine_result': {
        'SHA256': 'fileHash',
        'FilePath': 'filePath'
    },
    'endpoint_scan_result': {
        'FileScanned': 'filesScanned',
        'FilesFailed': 'filesFailed',
        'MalwareFound': 'malwareFound'
    }
}

# OUTPUT_EXCEPTIONS

''' HELPER FUNCTIONS '''


def create_headers(with_auth):
    headers = copy.deepcopy(REQUEST_HEADERS)
    if with_auth:
        token = generate_auth_token().decode('utf-8')
        headers['Authorization'] = f'Bearer {token}'
    return headers


def http_request(method, url_suffix, plain_url=False, params=None, data=None, operation_err=None, parse_response=True,
                 with_auth=True):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix if not plain_url else url_suffix,
            verify=USE_SSL,
            params=params,
            data=json.dumps(data) if data else data,
            headers=create_headers(with_auth),
        )
    except requests.exceptions.ConnectionError:
        return_error(f'Error connecting to Traps server. Please check your connection and you server address')
    if parse_response:
        res = extract_and_validate_http_response(res, operation_err, plain_url)
    return res


def extract_and_validate_http_response(resp, operation_err_message, test=False):
    try:
        resp.raise_for_status()
        return resp.json() if not test else resp.content
    except requests.exceptions.HTTPError:
        try:
            err_message = resp.json().get('message')
        except Exception:
            try:
                err_obj = json.loads(xml2json(resp.text))
                err_message = demisto.get(err_obj, 'Error.Message')
            except Exception:
                err_message = f'Could not parse error'
        return_error(f'{operation_err_message}: \n{err_message}')


def health_check():
    path = f'{SERVER}/xapi/health-check'
    server_status = http_request('GET', path, plain_url=True).decode('utf-8')
    if server_status == '"Ok"':
        return
    else:
        return_error(f'Server health-check failed. Status returned was: {server_status}')


def generate_auth_token():
    key = PRIVATE_KEY
    data = {'appId': APPLICATION_ID}
    token = jwt.encode(data, key, algorithm='RS256')
    return token


def parse_data_from_response(resp_obj, operation_name=None):
    new_data_obj = {}  # type: dict
    outputs_obj = OUTPUTS[operation_name]
    for key, val in outputs_obj.items():
        new_data_obj[key] = resp_obj.get(val)

    return new_data_obj


def get_endpoint_by_id(endpoint_id):
    path = f'agents/{endpoint_id}'
    endpoint_data = http_request('GET', path, operation_err=f'Get endpoint {endpoint_id} failed')
    return parse_data_from_response(endpoint_data, 'get_endpoint_by_id'), endpoint_data


def endpoint_files_retrieve(endpoint_id, file_name, event_id):
    path = f'agents/{endpoint_id}/files-retrieve'
    data = {
        'incidentId': event_id,
        'files': [
            {
                "path": file_name
            }
        ]
    }
    resp = http_request('POST', path, data=data,
                        operation_err=f'Files retrieve command on endpoint {endpoint_id} failed')
    operation_obj = parse_data_from_response(resp, 'endpoint_files_retrieve')
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'files-retrieve'
    })
    return operation_obj


def endpoint_scan(endpoint_id):
    path = f'agents/{endpoint_id}/scan'
    resp = http_request('POST', path, operation_err=f'Scanning endpoint: {endpoint_id} failed')
    operation_obj = parse_data_from_response(resp, 'endpoint_scan')
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'endpoint-scan'
    })
    return operation_obj


def endpoint_scan_result(operation_id):
    status, additional_data = sam_operation(operation_id, f'Could not get scan results')
    scan_data = parse_data_from_response(additional_data.get('scanData'),
                                         'endpoint_scan_result') if additional_data else {}
    scan_data['Status'] = status
    scan_data['OperationID'] = operation_id
    return scan_data


def update_event_status(event_ids, status):
    path = f'events/status'
    data = {
        "guids": event_ids,
        "status": status
    }
    resp = http_request('PATCH', path, data=data, operation_err=f'Update events {event_ids} status failed')
    return resp


def update_event_comment(event_id, comment):
    path = f'events/{event_id}/comment'
    data = {
        "comment": comment
    }
    http_request('POST', path, data=data, operation_err=f'Update event: {event_id} comment failed')
    return


def event_update_status_and_command(event_id, status, comment):
    if not status and not comment:
        return_error('Please add a status or a comment. Neither was given')
    if status:
        resp = update_event_status([event_id], status)
        if resp.get('failed'):
            return_error(f'Update status for event: {event_id} has failed')
    if comment:
        update_event_comment(event_id, comment)
    return


def event_bulk_update_status(event_ids, status):
    ids_obj = update_event_status(event_ids, status)
    # maybe should be changed to a separate function
    results = {
        'UpdateSuccess': list(
            map(lambda id_obj: parse_data_from_response(id_obj, 'event_bulk_update_status'), ids_obj.get('succeeded'))),
        'UpdateFail': list(
            map(lambda id_obj: parse_data_from_response(id_obj, 'event_bulk_update_status'), ids_obj.get('failed'))),
        'UpdateIgnored': list(
            map(lambda id_obj: parse_data_from_response(id_obj, 'event_bulk_update_status'), ids_obj.get('ignored')))
    }
    return results


def hash_blacklist(hash_id):
    path = f'hashes/{hash_id}/blacklist'
    result = http_request('POST', path, operation_err=f'Failed to blacklist {hash_id}')
    return result.get('status')


def remove_hash_from_blacklist(hash_id):
    path = f'hashes/{hash_id}/blacklist-remove'
    result = http_request('POST', path, operation_err=f'Failed to remove {hash_id} from blacklist')
    return result.get('status')


# TODO: Check if needed error message.
def hashes_blacklist_status(hash_ids):
    path = f'hashes/blacklist-status'
    data = {
        'hashes': hash_ids
    }
    ids_obj = http_request('POST', path, data=data, operation_err='Failed to get hashes status')
    result = list(map(lambda id_obj: parse_data_from_response(id_obj, 'hashes_blacklist_status'), ids_obj))
    return result


def event_quarantine(event_id):
    path = f'events/{event_id}/quarantine'
    resp = http_request('POST', path, operation_err=f'Quarantine event {event_id} failed')
    message_ids = resp.get('operationId').get('samMessageIds')
    operations = []
    for op_id in message_ids:
        operations.append({
            'EventID': event_id,
            'Type': 'event-quarantine',
            'OperationID': op_id
        })
    return operations


def endpoint_isolate(endpoint_id):
    path = f'agents/{endpoint_id}/isolate'
    resp = http_request('POST', path, operation_err=f'Isolation of endpoint: {endpoint_id} failed')
    operation_obj = parse_data_from_response(resp, 'endpoint_isolate')
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'endpoint-isolate'
    })
    return operation_obj


def sam_operation(operation_id, operation_err):
    """
    This functions invokes an API call to the sam operation endpoint on Traps server to get the operation status and/or
    results.
    :param operation_id: the operation on which to get the status/results
    :param operation_err: The error to return in case of a failure (changes according to the command fired.)
    :return:
        status: the status of the operation.
        additional_data: additional data regarding the operation (like scan results)
    """
    path = f'sam/operations/{operation_id}'
    result = http_request('GET', path, operation_err=operation_err)
    if result.get('summaryData').get('incompatible'):
        return_error(f'{operation_err} incompatible operation')
    if result.get('summaryData').get('samExists'):
        return 'ignored', None
    for status_obj in result.get('statuses'):
        if status_obj.get('count') > 0:
            return status_obj.get('status'), result.get('additionalData')
    return_error(f'{operation_err}: Could not retrieve status')


def endpoint_isolate_status(operation_id):
    status, _ = sam_operation(operation_id, f'Could not get endpoint isolate status')
    return {'Status': status, 'OperationID': operation_id}


def event_quarantine_result(operation_id):
    status, additional_data = sam_operation(operation_id, f'Could not get event quarantine status')
    quarantine_data = parse_data_from_response(additional_data.get('quarantineData'),
                                               'event_quarantine_result') if additional_data else {}
    quarantine_data['Status'] = status
    quarantine_data['OperationID'] = operation_id
    return quarantine_data


def endpoint_files_retrieve_result(operation_id):
    status, additional_data = sam_operation(operation_id, f'Failed to get file retrieve results')
    if status == 'finished':
        file_info = additional_data.get('uploadData')
        file_name = file_info.get('fileName')
        url = file_info.get('downloadUrl')
        data = http_request('GET', url, plain_url=True, operation_err=f'Unable to download file.', with_auth=False)
        demisto.results(fileResult(filename=file_name, data=data))
    return {'Status': status, 'OperationID': operation_id}


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module_command():
    health_check()
    res = http_request('GET', 'agents/1', parse_response=False)
    if res.status_code == 403:
        return_error(f'Error connecting to server. Check your Application ID and Private key')
    return


def get_endpoint_by_id_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    endpoint_data, raw_data = get_endpoint_by_id(endpoint_id)
    md = tableToMarkdown(f'Endpoint {endpoint_id} data:', endpoint_data, headerTransform=pascalToSpace)
    context = {'Traps.Endpoint(val.ID == obj.ID)': createContext(endpoint_data)}
    return_outputs(md, context, raw_response=raw_data)


def endpoint_files_retrieve_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    file_name = args.get('file_name')
    event_id = args.get('event_id')
    operation_obj = endpoint_files_retrieve(endpoint_id, file_name, event_id)
    md = tableToMarkdown(f'Files retrieve command on endpoint: {endpoint_id} received', operation_obj,
                         headerTransform=pascalToSpace)
    context = {'Traps.FileRetrieve(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(md, context)


def endpoint_files_retrieve_result_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = endpoint_files_retrieve_result(operation_id)
    md = f'### File retrieval status is: {status_obj.get("Status")}'
    context = {'Traps.FileRetrieveResult(val.OperationID == obj.OperationID)': status_obj}
    return_outputs(md, context)


def endpoint_scan_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    operation_obj = endpoint_scan(endpoint_id)
    md = tableToMarkdown(f'Scan command on endpoint: {endpoint_id} received', operation_obj,
                         headerTransform=pascalToSpace)
    context = {'Traps.Scan(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(md, context)


def endpoint_scan_result_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = endpoint_scan_result(operation_id)
    context = {f'Traps.ScanResult(val.OperationID == obj.OperationID)': status_obj}
    md = tableToMarkdown(f'Status of scan operation: {operation_id}', status_obj, headerTransform=pascalToSpace)
    return_outputs(md, context)


def event_update_command():
    args = demisto.args()
    event_id = args.get('event_id')
    status = args.get('status')
    comment = args.get('comment')
    event_update_status_and_command(event_id, status, comment)
    md = f'### Event: {event_id} was updated'
    md += f'\n##### New status: {status}' if status else ''
    md += f'\n##### New comment: {comment}' if comment else ''
    return_outputs(md, None)


def event_bulk_update_status_command():
    args = demisto.args()
    event_ids = argToList(args.get('event_ids'))
    status = args.get('status')
    results = event_bulk_update_status(event_ids, status)
    md = tableToMarkdown('Successfully updated', results.get('UpdateSuccess'), headerTransform=pascalToSpace)
    md += tableToMarkdown('Failed to update', results.get('UpdateFail'), headerTransform=pascalToSpace)
    md += tableToMarkdown('Ignored', results.get('UpdateIgnored'), headerTransform=pascalToSpace)
    return_outputs(md, {})


def event_quarantine_command():
    args = demisto.args()
    event_id = args.get('event_id')
    operations = event_quarantine(event_id)
    md = tableToMarkdown(f'Quarantine command on event: {event_id} received', operations,
                         headerTransform=pascalToSpace)
    context = {'Traps.Quarantine(val.OperationID == obj.OperationID)': operations}
    return_outputs(md, context)


def event_quarantine_result_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = event_quarantine_result(operation_id)
    context = {f'Traps.QuarantineResult(val.OperationID == obj.OperationID)': status_obj}
    md = tableToMarkdown(f'Status of quarantine operation: {operation_id}', status_obj, headerTransform=pascalToSpace)
    return_outputs(md, context)


def hash_blacklist_command():
    args = demisto.args()
    hash_id = args.get('hash_id')
    status = hash_blacklist(hash_id)
    context = {}  # type: dict
    if status == 'success':
        md = f'#### Successfully blacklisted: {hash_id}'
        status_obj = {
            'SHA256': hash_id,
            'BlacklistStatus': 'blacklisted'
        }
        context = {'Traps.File(val.SHA256 == obj.SHA256)': status_obj}

    elif status == 'ignore':
        md = f'#### Hash: {hash_id} already appears in blacklist'
    else:
        md = f'#### Failed to blacklist: {hash_id}'
    return_outputs(md, context)


def hash_blacklist_remove_command():
    args = demisto.args()
    hash_id = args.get('hash_id')
    status = remove_hash_from_blacklist(hash_id)
    context = {}  # type: dict
    if status == 'success':
        md = f'#### Successfully removed {hash_id} from blacklist'
        status_obj = {
            'SHA256': hash_id,
            'BlacklistStatus': 'none'
        }
        context = {'Traps.File(val.SHA256 == obj.SHA256)': status_obj}
    else:
        md = f'#### Failed to remove {hash_id} from blacklist:'

    return_outputs(md, context)


def hashes_blacklist_status_command():
    args = demisto.args()
    hash_ids = args.get('hash_ids').split(',')
    ids_obj = hashes_blacklist_status(hash_ids)
    md = tableToMarkdown('Hashes status:', ids_obj, headerTransform=pascalToSpace)
    context = {'Traps.File(val.SHA256 == obj.SHA256)': ids_obj}
    return_outputs(md, context)


def endpoint_isolate_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    operation_obj = endpoint_isolate(endpoint_id)
    md = tableToMarkdown(f'Isolate command on endpoint {endpoint_id} received', operation_obj,
                         headerTransform=pascalToSpace)
    context = {'Traps.Isolate(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(md, context)


def endpoint_isolate_status_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    isolate_status = endpoint_isolate_status(operation_id)
    md = f'### Isolate status is: {isolate_status.get("Status")}'
    context = {f'Traps.IsolateResult(val.OperationID == obj.OperationID)': isolate_status}
    return_outputs(md, context)


def main():
    # Remove proxy if not set to true in params
    handle_proxy()

    ''' COMMANDS MANAGER / SWITCH PANEL '''

    LOG('Command being called is %s' % (demisto.command()))

    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module_command()
            demisto.results('ok')
        elif demisto.command() == 'traps-get-endpoint-by-id':
            get_endpoint_by_id_command()
        elif demisto.command() == 'traps-endpoint-files-retrieve':
            endpoint_files_retrieve_command()
        elif demisto.command() == 'traps-endpoint-files-retrieve-result':
            endpoint_files_retrieve_result_command()
        elif demisto.command() == 'traps-endpoint-scan':
            endpoint_scan_command()
        elif demisto.command() == 'traps-endpoint-scan-result':
            endpoint_scan_result_command()
        elif demisto.command() == 'traps-event-update':
            event_update_command()
        elif demisto.command() == 'traps-event-bulk-update-status':
            event_bulk_update_status_command()
        elif demisto.command() == 'traps-hash-blacklist':
            hash_blacklist_command()
        elif demisto.command() == 'traps-hash-blacklist-remove':
            hash_blacklist_remove_command()
        elif demisto.command() == 'traps-hashes-blacklist-status':
            hashes_blacklist_status_command()
        elif demisto.command() == 'traps-event-quarantine':
            event_quarantine_command()
        elif demisto.command() == 'traps-event-quarantine-result':
            event_quarantine_result_command()
        elif demisto.command() == 'traps-endpoint-isolate':
            endpoint_isolate_command()
        elif demisto.command() == 'traps-endpoint-isolate-status':
            endpoint_isolate_status_command()
    # Log exceptions
    except Exception as e:
        return_error(e)


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
