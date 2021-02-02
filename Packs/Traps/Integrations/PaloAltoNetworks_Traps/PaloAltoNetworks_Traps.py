import copy

import urllib3
import jwt

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

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
        'ScanStatus': 'scanStatus',
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

# comment for test
def create_headers(with_auth):
    """Create headers for the http_request

    Args:
        with_auth: True

    Returns:
        Headers.
    """
    headers = copy.deepcopy(REQUEST_HEADERS)
    if with_auth:
        token = generate_auth_token().decode('utf-8')
        headers['Authorization'] = f'Bearer {token}'
    return headers


def extract_and_validate_http_response(response, operation_err_message, test=False):
    """

    Args:
        response: raw response
        operation_err_message: error message to present in case of error
        test: boolean value, true if test

    Returns:
        Error if response is faulty.
    """
    try:
        response.raise_for_status()
        return response.json() if not test else response.content
    except requests.exceptions.HTTPError:
        try:
            err_message = response.json().get('message')
        except Exception:
            try:
                err_obj = json.loads(xml2json(response.text))
                err_message = demisto.get(err_obj, 'Error.Message')
            except Exception:
                err_message = 'Could not parse error'
        return_error(f'{operation_err_message}: \n{err_message}')


def http_request(method, url_suffix, plain_url=False, params=None, data=None, operation_err=None, parse_response=True,
                 with_auth=True):
    """Generic http call to Traps

    Args:
        method: request method.
        url_suffix: URL suffix.
        plain_url: full URL.
        params: request params.
        data: request data.
        operation_err: operation error to log the user.
        parse_response: boolean value, if parsing the response is needed.
        with_auth: boolean value, do we need to authenticate the request.

    Returns:
        Result from the API.
    """
    try:
        result = requests.request(
            method,
            BASE_URL + url_suffix if not plain_url else url_suffix,
            verify=USE_SSL,
            params=params,
            data=json.dumps(data) if data else data,
            headers=create_headers(with_auth),
        )
    except requests.exceptions.ConnectionError:
        return_error('Error connecting to Traps server. Please check your connection and you server address')
    if parse_response:
        result = extract_and_validate_http_response(result, operation_err, plain_url)
    return result


def health_check():
    """Performs basic health check on the server.

    Returns:
        Error if not ok.
    """
    path = f'{SERVER}/xapi/health-check'
    server_status = http_request('GET', path, plain_url=True).decode('utf-8')
    if server_status == '"Ok"':
        return
    raise Exception(f'Server health-check failed. Status returned was: {server_status}')


def generate_auth_token():
    """Generate a token using jwt.

    Returns:
        token.
    """
    key = PRIVATE_KEY
    data = {'appId': APPLICATION_ID}
    token = jwt.encode(data, key, algorithm='RS256')
    return token


def parse_data_from_response(resp_obj, operation_name=None):
    """Response raw data.

    Args:
        resp_obj: raw_data.
        operation_name: operation name.

    Returns:
        parsed data.
    """
    new_data_obj = {}  # type: dict
    outputs_obj = OUTPUTS[operation_name]
    for key, val in outputs_obj.items():
        if val in resp_obj:
            new_data_obj[key] = resp_obj.get(val)

    return new_data_obj


def get_endpoint_by_id(endpoint_id):
    """Get endpoint data by sending a GET request.

    Args:
        endpoint_id: endpoint ID.

    Returns:
        endpoint data.
    """
    path = f'agents/{endpoint_id}'
    endpoint_data = http_request('GET', path, operation_err=f'Get endpoint {endpoint_id} failed')
    return parse_data_from_response(endpoint_data, 'get_endpoint_by_id'), endpoint_data


def endpoint_files_retrieve(endpoint_id, file_name, event_id):
    """Retrieve a file from the endpoint by sending a POST request.

    Args:
        endpoint_id: endpoint ID.
        file_name: File name.
        event_id: Event ID.

    Returns:
        Operation data.
    """
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
    """Initiate a scan on an endpoint by sending a POST request.

    Args:
        endpoint_id: endpoint ID.

    Returns:
        Operation data.
    """
    path = f'agents/{endpoint_id}/scan'
    response = http_request('POST', path, operation_err=f'Scanning endpoint: {endpoint_id} failed')
    operation_obj = parse_data_from_response(response, 'endpoint_scan')
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'endpoint-scan'
    })
    return operation_obj, response


def endpoint_scan_result(operation_id):
    """Initiate the SAM operation for retrieving the scan result.

    Args:
        operation_id: operation ID.

    Returns:
        scan data.
    """
    status, additional_data = sam_operation(operation_id, 'Could not get scan results')
    scan_data = parse_data_from_response(additional_data.get('scanData'),
                                         'endpoint_scan_result') if additional_data else {}
    scan_data['Status'] = status
    scan_data['OperationID'] = operation_id
    return scan_data


def update_event_status(event_ids, status):
    """Update event or events status by sending a POST request.

    Args:
        event_ids: event IDs.
        status: status.

    Returns:
        API response.
    """
    path = 'events/status'
    data = {
        "guids": event_ids,
        "status": status
    }
    response = http_request('PATCH', path, data=data, operation_err=f'Update events {event_ids} status failed')
    return response


def update_event_comment(event_id, comment):
    """Update event comment by sending a POST request.

    Args:
        event_id: event ID.
        comment: comment.
    """
    path = f'events/{event_id}/comment'
    data = {
        "comment": comment
    }
    http_request('POST', path, data=data, operation_err=f'Update event: {event_id} comment failed')


def event_update(event_id, status, comment):
    """Initiate update of an event.

    Args:
        event_id: event ID.
        status: status.
        comment: comment.

    Returns:
        Error if not successful.
    """
    if not status and not comment:
        raise Exception('Please add a status or a comment. Neither was given.')
    if status:
        response = update_event_status([event_id], status)
        if response.get('failed'):
            raise Exception(f'Update status for event: {event_id} has failed.')
    if comment:
        update_event_comment(event_id, comment)


def event_bulk_update_status(event_ids, status):
    """Initiate update of events statuses.

    Args:
        event_ids: event IDs.
        status: status.

    Returns:
        Update statuses.
    """
    ids_obj = update_event_status(event_ids, status)
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
    """Add hash to a blacklist by sending a POST request.

    Args:
        hash_id: Hash.

    Returns:
        status.
    """
    path = f'hashes/{hash_id}/blacklist'
    result = http_request('POST', path, operation_err=f'Failed to blacklist {hash_id}')
    return result.get('status')


def remove_hash_from_blacklist(hash_id):
    """Remove hash to a blacklist by sending a POST request.

    Args:
        hash_id: Hash.

    Returns:
        status.
    """
    path = f'hashes/{hash_id}/blacklist-remove'
    result = http_request('POST', path, operation_err=f'Failed to remove {hash_id} from blacklist')
    return result.get('status')


def hashes_blacklist_status(hash_ids):
    """Get hashes blacklisting status by sending a POST request.

    Args:
        hash_ids: Hashes.

    Returns:
        Hashes and blacklisting data.
    """
    path = 'hashes/blacklist-status'
    data = {
        'hashes': hash_ids
    }
    ids_obj = http_request('POST', path, data=data, operation_err='Failed to get hashes status')
    result = list(map(lambda id_obj: parse_data_from_response(id_obj, 'hashes_blacklist_status'), ids_obj))
    return result


def event_quarantine(event_id):
    """Quarantine an event by sending a POST request.

    Args:
        event_id: event ID.

    Returns:
        Data regarding the event and the quarantine operation.
    """
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
    """Isolate an endpoint by sending a POST request.

    Args:
        endpoint_id: endpoint ID.

    Returns:
        Data regarding the endpoint and the isolation operation.
    """
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
    summary_data = result.get('summaryData')
    if summary_data and (summary_data.get('incompatible') or summary_data.get('samExists')):
        if operation_err == 'Could not get scan results':  # Get scan result
            requested_scans = int(summary_data.get('requested', 0))
            incompatible_scans = int(summary_data.get('incompatible', 0))
            sam_exists_scans = int(summary_data.get('samExists', 0))
            if requested_scans <= incompatible_scans + sam_exists_scans:
                raise Exception(f'{operation_err}.\nRequested scans number: {requested_scans}.\n'
                                f'Incompatible scans number: {requested_scans}.\n'
                                f'Sam exists scans number: {sam_exists_scans}.')
        raise Exception(f'{operation_err}')
    if result.get('summaryData').get('samExists'):
        return 'ignored', None
    for status_obj in result.get('statuses'):
        if status_obj.get('count') > 0:
            return status_obj.get('status'), result.get('additionalData')
    raise Exception(f'{operation_err}: Could not retrieve status')


def endpoint_isolate_status(operation_id):
    """Initiate the SAM operation for endpoint isolation status.

    Args:
        operation_id: operation ID.

    Returns:
        endpoint status, operation ID
    """
    status, _ = sam_operation(operation_id, 'Could not get endpoint isolate status')
    return {'Status': status, 'OperationID': operation_id}


def event_quarantine_result(operation_id):
    """Initiate the SAM operation for quarantine result.

    Args:
        operation_id: operation ID.

    Returns:
        quarantine data.
    """
    status, additional_data = sam_operation(operation_id, 'Could not get event quarantine status')
    quarantine_data = parse_data_from_response(additional_data.get('quarantineData'),
                                               'event_quarantine_result') if additional_data else {}
    quarantine_data['Status'] = status
    quarantine_data['OperationID'] = operation_id
    return quarantine_data


def endpoint_files_retrieve_result(operation_id):
    """Initiate the SAM operation for file retrieving.

    Args:
        operation_id: operation ID.

    Returns:
        file as an entry, status, operation_id.
    """
    status, additional_data = sam_operation(operation_id, 'Failed to get file retrieve results')
    if status == 'finished':
        file_info = additional_data.get('uploadData')
        file_name = file_info.get('fileName')
        url = file_info.get('downloadUrl')
        data = http_request('GET', url, plain_url=True, operation_err='Unable to download file.', with_auth=False)
        demisto.results(fileResult(filename=file_name, data=data))
    return {'Status': status, 'OperationID': operation_id}


def test_module_command():
    """Performs basic GET request to check if the API is reachable and authentication is successful.

    Returns:
        ok if successful.
    """
    health_check()
    result = http_request('GET', 'agents/1', parse_response=False)
    if result.status_code == 403:
        raise Exception('Error connecting to server. Check your Application ID and Private key')
    demisto.results('ok')


def get_endpoint_by_id_command():
    """Get endpoint data.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    endpoint_data, raw_data = get_endpoint_by_id(endpoint_id)
    human_readable = tableToMarkdown(f'Endpoint {endpoint_id} data:', endpoint_data, headerTransform=pascalToSpace)
    context = {'Traps.Endpoint(val.ID == obj.ID)': createContext(endpoint_data)}
    return_outputs(human_readable, context, raw_response=raw_data)


def endpoint_files_retrieve_command():
    """Initiate retrieving of files from an endpoint.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    file_name = args.get('file_name')
    event_id = args.get('event_id')
    operation_obj = endpoint_files_retrieve(endpoint_id, file_name, event_id)
    human_readable = tableToMarkdown(f'Files retrieve command on endpoint: {endpoint_id} received', operation_obj,
                                     headerTransform=pascalToSpace)
    context = {'Traps.FileRetrieve(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(human_readable, context, operation_obj)


def endpoint_files_retrieve_result_command():
    """Retrieve files from an endpoint result.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = endpoint_files_retrieve_result(operation_id)
    human_readable = f'### File retrieval status is: {status_obj.get("Status")}'
    context = {'Traps.FileRetrieveResult(val.OperationID == obj.OperationID)': status_obj}
    return_outputs(human_readable, context)


def endpoint_scan_command():
    """Initiate scan on an endpoint.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')

    # check that running a scan is possible
    _, raw_data = get_endpoint_by_id(endpoint_id)
    scan_status = raw_data.get('scanStatus')
    if scan_status and scan_status in ['pending', 'in_progress']:
        raise Exception(f'Could not initiate a scan on the endpoint {endpoint_id}'
                        f' because endpoint scan status is {scan_status}.')

    operation_obj, raw_data = endpoint_scan(endpoint_id)
    human_readable = tableToMarkdown(f'Scan command on endpoint: {endpoint_id} received', operation_obj,
                                     headerTransform=pascalToSpace)
    context = {'Traps.Scan(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(human_readable, context, raw_data)


def endpoint_scan_result_command():
    """Retrieve endpoint scan results.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = endpoint_scan_result(operation_id)
    context = {'Traps.ScanResult(val.OperationID == obj.OperationID)': status_obj}
    human_readable = tableToMarkdown(f'Status of scan operation: {operation_id}', status_obj,
                                     headerTransform=pascalToSpace)
    return_outputs(human_readable, context, status_obj)


def event_update_command():
    """Update an event.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    event_id = args.get('event_id')
    status = args.get('status')
    comment = args.get('comment')
    event_update(event_id, status, comment)
    human_readable = f'### Event: {event_id} was updated'
    human_readable += f'\n##### New status: {status}' if status else ''
    human_readable += f'\n##### New comment: {comment}' if comment else ''
    return_outputs(human_readable, None, {})


def event_bulk_update_status_command():
    """Update events.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    event_ids = argToList(args.get('event_ids'))
    status = args.get('status')
    results = event_bulk_update_status(event_ids, status)
    human_readable = tableToMarkdown('Successfully updated', results.get('UpdateSuccess'),
                                     headerTransform=pascalToSpace)
    human_readable += tableToMarkdown('Failed to update', results.get('UpdateFail'), headerTransform=pascalToSpace)
    human_readable += tableToMarkdown('Ignored', results.get('UpdateIgnored'), headerTransform=pascalToSpace)
    return_outputs(human_readable, {}, {})


def event_quarantine_command():
    """Quarantine an event.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    event_id = args.get('event_id')
    operations = event_quarantine(event_id)
    human_readable = tableToMarkdown(f'Quarantine command on event: {event_id} received', operations,
                                     headerTransform=pascalToSpace)
    context = {'Traps.Quarantine(val.OperationID == obj.OperationID)': operations}
    return_outputs(human_readable, context, operations)


def event_quarantine_result_command():
    """Check quarantine event status.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = event_quarantine_result(operation_id)
    context = {'Traps.QuarantineResult(val.OperationID == obj.OperationID)': status_obj}
    human_readable = tableToMarkdown(f'Status of quarantine operation: {operation_id}',
                                     status_obj, headerTransform=pascalToSpace)
    return_outputs(human_readable, context, status_obj)


def hash_blacklist_command():
    """Add a hash to a blacklist.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    hash_id = args.get('hash_id')
    status = hash_blacklist(hash_id)
    context = {}  # type: dict
    if status == 'success':
        human_readable = f'#### Successfully blacklisted: {hash_id}'
        status_obj = {
            'SHA256': hash_id,
            'BlacklistStatus': 'blacklisted'
        }
        context = {'Traps.File(val.SHA256 == obj.SHA256)': status_obj}

    elif status == 'ignore':
        human_readable = f'#### Hash: {hash_id} already appears in blacklist'
    else:
        human_readable = f'#### Failed to blacklist: {hash_id}'
    return_outputs(human_readable, context, status)


def hash_blacklist_remove_command():
    """Remove a hash from blacklist.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    hash_id = args.get('hash_id')
    status = remove_hash_from_blacklist(hash_id)
    context = {}  # type: dict
    if status == 'success':
        human_readable = f'#### Successfully removed {hash_id} from blacklist'
        status_obj = {
            'SHA256': hash_id,
            'BlacklistStatus': 'none'
        }
        context = {'Traps.File(val.SHA256 == obj.SHA256)': status_obj}
    else:
        human_readable = f'#### Failed to remove {hash_id} from blacklist:'

    return_outputs(human_readable, context, status)


def hashes_blacklist_status_command():
    """Check hash blacklist status.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    hash_ids = args.get('hash_ids').split(',')
    ids_obj = hashes_blacklist_status(hash_ids)
    human_readable = tableToMarkdown('Hashes status:', ids_obj, headerTransform=pascalToSpace)
    context = {'Traps.File(val.SHA256 == obj.SHA256)': ids_obj}
    return_outputs(human_readable, context, ids_obj)


def endpoint_isolate_command():
    """Isolate an endpoint.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    operation_obj = endpoint_isolate(endpoint_id)
    human_readable = tableToMarkdown(f'Isolate command on endpoint {endpoint_id} received', operation_obj,
                                     headerTransform=pascalToSpace)
    context = {'Traps.Isolate(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(human_readable, context, operation_obj)


def endpoint_isolate_status_command():
    """Check endpoint isolation status.

    Returns:
        Demisto Outputs.
    """
    args = demisto.args()
    operation_id = args.get('operation_id')
    isolate_status = endpoint_isolate_status(operation_id)
    human_readable = f'### Isolate status is: {isolate_status.get("Status")}'
    context = {'Traps.IsolateResult(val.OperationID == obj.OperationID)': isolate_status}
    return_outputs(human_readable, context, isolate_status)


def main():
    """
    Initiate integration command
    """
    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}.')
    try:
        if command == 'test-module':
            test_module_command()
        elif command == 'traps-get-endpoint-by-id':
            get_endpoint_by_id_command()
        elif command == 'traps-endpoint-files-retrieve':
            endpoint_files_retrieve_command()
        elif command == 'traps-endpoint-files-retrieve-result':
            endpoint_files_retrieve_result_command()
        elif command == 'traps-endpoint-scan':
            endpoint_scan_command()
        elif command == 'traps-endpoint-scan-result':
            endpoint_scan_result_command()
        elif command == 'traps-event-update':
            event_update_command()
        elif command == 'traps-event-bulk-update-status':
            event_bulk_update_status_command()
        elif command == 'traps-hash-blacklist':
            hash_blacklist_command()
        elif command == 'traps-hash-blacklist-remove':
            hash_blacklist_remove_command()
        elif command == 'traps-hashes-blacklist-status':
            hashes_blacklist_status_command()
        elif command == 'traps-event-quarantine':
            event_quarantine_command()
        elif command == 'traps-event-quarantine-result':
            event_quarantine_result_command()
        elif command == 'traps-endpoint-isolate':
            endpoint_isolate_command()
        elif command == 'traps-endpoint-isolate-status':
            endpoint_isolate_status_command()
        else:
            raise NotImplementedError(f'Command {command} was not implemented.')
    except Exception as err:
        return_error(err)


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
