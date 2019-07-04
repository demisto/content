import inspect

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

# USERNAME = demisto.params().get('credentials').get('identifier')
# PASSWORD = demisto.params().get('credentials').get('password')
TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Service base URL
BASE_URL = SERVER + '/xapi/v1/'
# Headers to be sent in requests
TENANT_ID = '11'
APPLICATION_ID = 'Demisto'
HEADERS = {
    'Content-Type': 'application/json',
    'tenantid': TENANT_ID,
    'applicationid': APPLICATION_ID
}
# Remove proxy if not set to true in params
handle_proxy()

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
    'traps_endpoint_scan': {
        'OperationID': 'operationId'
    },
    'event_bulk_update_status': {
        'EventID': 'eventGuid'
    },
    'hashes_blacklist_status': {
        'HashID': 'hash',
        'BlacklistStatus': 'status'
    },
    'event_quarantine_status': {
        'FileHash': 'fileHash',
        'FilePath': 'filePath'
    }

}

# OUTPUT_EXCEPTIONS

''' HELPER FUNCTIONS '''


# def create_output(data, type='context'):
#     new_data = {}
#     for key, val in data.items():
#         new_key = ''
#         if type == 'context':
#             new_key = string_to_context_key(key)
#         elif type == 'md':
#             new_key = string_to_table_header(key)
#         new_data[new_key] = val
#     return new_data


def http_request(method, url_suffix, plain_url=False, params=None, data=None, operation_err=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix if not plain_url else url_suffix,
            verify=USE_SSL,
            params=params,
            data=json.dumps(data) if data else data,
            headers=HEADERS,
        )
    except requests.exceptions.ConnectionError as err:
        return_error(f'Error connecting to Traps server check your connection and you server address')
    return parse_http_response(res, operation_err, plain_url)


def parse_http_response(resp, operation_err_message, test=False):
    try:
        resp.raise_for_status()
        return resp.json() if not test else resp.content
    except requests.exceptions.HTTPError:
        try:
            err_message = resp.json().get('message')
        except Exception as err:
            err_message = err
        return_error(f'{operation_err_message}: \n{err_message}')


# def item_to_incident(item):
#     incident = {}
#     # Incident Title
#     incident['name'] = 'Example Incident: ' + item.get('name')
#     # Incident occurrence time, usually item creation date in service
#     incident['occurred'] = item.get('createdDate')
#     # The raw response from the service, providing full info regarding the item
#     incident['rawJSON'] = json.dumps(item)
#     return incident
#


def health_check():
    path = f'{SERVER}/xapi/health-check'
    server_status = http_request('GET', path, plain_url=True)
    if server_status == '"Ok"':
        return
    else:
        return_error(f'Server health-check failed. Status returned was: {server_status}')


def parse_data_from_response(resp_obj, operation_name=None):
    new_data_obj = {}  # type: dict
    operation_name = operation_name if operation_name else inspect.stack()[1].function  # Get the caller function mame
    outputs_obj = OUTPUTS[operation_name]
    for key, val in outputs_obj.items():
        new_data_obj[key] = resp_obj.get(val)

    return new_data_obj


def get_endpoint_by_id(endpoint_id):
    path = f'agents/{endpoint_id}'
    endpoint_data = http_request('GET', path, operation_err=f'Get endpoint {endpoint_id} failed')
    return parse_data_from_response(endpoint_data), endpoint_data


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
    operation_obj = parse_data_from_response(resp)
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'files-retrieve'
    })
    return operation_obj


def endpoint_scan(endpoint_id):
    path = f'agents/{endpoint_id}/scan'
    resp = http_request('POST', path, operation_err=f'Scanning endpoint: {endpoint_id} failed')
    operation_obj = parse_data_from_response(resp)
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'endpoint-scan'
    })
    return operation_obj


def update_event_status(event_ids, status):
    path = f'events/status'
    data = {
        "guids": event_ids,
        "status": status
    }
    resp = http_request('PATCH', path, data=data, operation_err=f'Update events status failed for: {event_ids}')
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


# def parse_ids(id_list):
#     new_list = []  # type: list
#     for id_obj in id_list:
#         new_list.append(parse_data_from_response(id_obj))
#     return new_list


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


def hashes_blacklist_status(hash_ids):
    path = f'hashes/blacklist-status'
    data = {
        'hashes': hash_ids
    }
    ids_obj = http_request('POST', path, data=data)
    result = list(map(lambda id_obj: parse_data_from_response(id_obj, 'hashes_blacklist_status'), ids_obj))
    return result


def event_quarantine(event_id):
    path = f'events/{event_id}/quarantine'
    resp = http_request('POST', path, operation_err=f'Quarantine event {event_id} failed')
    resp = {
        "operationId": {
            "samMessageIds": [
                "90eb5bf99d9311e997c606493deb1400",
                "90eb5bf99d9311e997c606493deb1401",
                "90eb5bf99d9311e997c606493deb1410",
                "90eb5bf99d9311e997c606493deb1411"
            ]
        }
    }
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
    # resp = http_request('POST', path, operation_err=f'Isolation of endpoint: {endpoint_id} failed')
    resp = {
        "operationId": "ac3f7f0f9cca11e9ad0b06493deb1492"
    }
    operation_obj = parse_data_from_response(resp)
    operation_obj.update({
        'EndpointID': endpoint_id,
        'Type': 'endpoint-isolate'
    })
    return operation_obj


def sam_operation(operation_id, operation_err):
    path = f'sam/operations/{operation_id}'
    result = http_request('GET', path, operation_err=operation_err)
    if result.get('summaryData').get('incompatible'):
        return_error(f'{operation_err} incompatible operation')
    if result.get('summaryData').get('samExists'):
        return_error(f'{operation_err} incompatible operation')
    for status_obj in result.get('statuses'):
        if status_obj.get('count') > 0:
            return status_obj.get('status'), result.get('additionalData')


def endpoint_isolate_status(operation_id):
    status, _ = sam_operation(operation_id, f'Could not get endpoint isolate status')
    return {'Status': status}


def event_quarantine_status(operation_id):
    status, additional_data = sam_operation(operation_id, f'Could not get event quarantine status')
    quarantine_data = parse_data_from_response(additional_data.get('quarantineData'))
    quarantine_data['Status'] = status
    return quarantine_data

# 15a8bb669e3211e9b66f06493deb1492

def endpoint_files_retrieve_result(operation_id):
    status, additional_data = sam_operation(operation_id, f'Failed to get file retrieve results')
    if status == 'finished':
        file_info = additional_data.get('uploadData')
        file_name = file_info.get('fileName')
        url = file_info.get('downloadUrl')
        # url = "https://demisto-agent-uploads-40.s3.us-west-2.amazonaws.com/sam%3Ac33cf8881313db8d3e1ad8979d698faeb9d590aac7d8c059f29ff5b3841746a0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIA4FSZU6GK3NMOF4UQ%2F20190704%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20190704T071746Z&X-Amz-Expires=604200&X-Amz-Security-Token=AgoJb3JpZ2luX2VjEJ%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLXdlc3QtMiJIMEYCIQDnkL3cgzgW0xSG0L6uFub3%2BWs6AdAoqCFLMZnYDNlcewIhAOqRuD0mJltKxMGmCt2xfHB2lYNsYyLkMnjQZOax2p2bKuMDCOj%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMODM2NjMyODk5OTg5Igw8hoUgNZyoXUb9L2gqtwOJG9m9drhgzm5q4gNAwtMds3QDSD1s3558ZLC1B1Iqb44ajoFCrzkIU9xYUU5%2B239J7dYm6F%2Fn8dTTty3fYbrktvGZBMnyZfVcqloTJswXlik9sFgrx43tGQ8SbYwk0hjeBm%2BTzkaWh%2FohEllLk5PMX1NiQnijRlu6stxlUwvBkmWj9vIiJGdxCKT0bUw1TH1UfUrRBBz2hEz2qvcNkkclpP5im2Xb%2BrwwU%2BHe9098Uy93ZkiM%2Fxmw2AqpWp3pYLad3tLCVSA6A4b3Oklmnoe4J6CN6LHDjepumZapstmmpCeyqTMWBs%2B%2B%2BQQrN9VHabiZiQBbzZt05LSRTPvRG71%2FQAkQTJoU75muSfv5Fh93t4NbvOx9XrbbnRUX8k9jk11NDHGPVuidjGcafxz8aX8CbPxDEbMNgA3V7N4XjJsiB8SV%2B71n%2FvT%2BJenX7VNEQrqpMx52kDOVrPiLxrjOiiikTDrahfzMDfBJwli7NTnWTd7x8%2FR1hnZ9TNJusiulsN1wPMkYfIzL4FXkj%2F7x6GGryZH6JX0F12viQxG9i6P5sJ62%2FYZ0Xr01GmfDNfa0%2BSWIlkxVdx4UMNu29ugFOrMBGD%2FfbH2N2hvZmxMm2fnMewPFpwNmlH%2FHL51mdQvofrptU%2F7H8ea9ScWDFPKVsvGUKIODY7z%2F2w0Ag9DJzsRSxqUV6iRpmGHOv1rDca7UVUtFs8yPTUiNJAd39kwnyBZkkdQ%2FGHQxGGJcIQ7zOqWRhaSNQ5ov%2F9InMGUmncjX%2BPAiyKDFB%2FjpopMP0RPNL3ivHPlwKdgoXEMOubWT6RR7uJfUMLeKupbrpBcAau6g25poMqQ%3D&X-Amz-Signature=a0228494af45875d07ee97bf044bc1e32e9a7a9a5f86a6bed83438b184c0aa6c&X-Amz-SignedHeaders=host"
        data = http_request('GET', url, plain_url=True)
        demisto.results(fileResult(filename=file_name, data=data))
    return status


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module_command():
    health_check()
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
    context = {'Traps.Operation(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(md, context)


def endpoint_files_retrieve_result_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    status = endpoint_files_retrieve_result(operation_id)
    md = f'### File retrieval status is: {status}'
    context = {'Traps.Operation'}
    return_outputs(md, context)


def endpoint_scan_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    operation_obj = endpoint_scan(endpoint_id)
    md = tableToMarkdown(f'Scan command on endpoint: {endpoint_id} received', operation_obj,
                         headerTransform=pascalToSpace)
    context = {'Traps.Operation(val.OperationID == obj.OperationID)': operation_obj}
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
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': md,
        'HumanReadable': md
    })


def event_bulk_update_status_command():
    args = demisto.args()
    event_ids = args.get('event_ids').split(',')
    status = args.get('status')
    results = event_bulk_update_status(event_ids, status)
    md = tableToMarkdown('Successfully updated', results.get('UpdateSuccess'), headerTransform=pascalToSpace)
    md += tableToMarkdown('Failed to update', results.get('UpdateFail'), headerTransform=pascalToSpace)
    md += tableToMarkdown('Ignored', results.get('UpdateIgnored'), headerTransform=pascalToSpace)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': md,
        'HumanReadable': md
    })


def event_quarantine_command():
    args = demisto.args()
    event_id = args.get('event_id')
    operations = event_quarantine(event_id)
    md = tableToMarkdown(f'Quarantine command on event: {event_id} received', operations,
                         headerTransform=pascalToSpace)
    context = {'Traps.Operation(val.OperationID == obj.OperationID)': operations}
    return_outputs(md, context)


def event_quarantine_status_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    status_obj = event_quarantine_status(operation_id)
    # curr_context_obj = demisto.dt(demisto.context(), f'Traps.Operation.Quarantine(val.OperationID == "{operation_id}")')
    # status_obj.update(curr_context_obj)
    # print(status_obj)
    # print(curr_context_obj)
    # sys.exit(0)
    context = {f'Traps.Operation(val.OperationID == obj.OperationID)': status_obj}
    md = tableToMarkdown(f'Status of quarantine operation: {operation_id}', status_obj, headerTransform=pascalToSpace)
    return_outputs(md, context)


def hash_blacklist_command():
    args = demisto.args()
    hash_id = args.get('hash_id')
    status = hash_blacklist(hash_id)
    if status == 'success':
        md = f'#### Successfully blacklisted: {hash_id}'
    elif status == 'ignore':
        md = f'#### Hash: {hash_id} already appears in blacklist'
    else:
        md = f'#### Failed to blacklist: {hash_id}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': md,
        'HumanReadable': md
    })


def hash_blacklist_remove_command():
    args = demisto.args()
    hash_id = args.get('hash_id')
    status = remove_hash_from_blacklist(hash_id)
    md = f'#### Successfully removed {hash_id} from blacklist' if status == 'success' \
        else f'#### Failed to remove {hash_id} from blacklist:'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': md,
        'HumanReadable': md
    })


def hashes_blacklist_status_command():
    args = demisto.args()
    hash_ids = args.get('hash_ids').split(',')
    ids_obj = hashes_blacklist_status(hash_ids)
    md = tableToMarkdown('Hashes status:', ids_obj, headerTransform=pascalToSpace)
    context = {'Traps.Hash(val.HashID == obj.HashID)': ids_obj}
    return_outputs(md, context)


def endpoint_isolate_command():
    args = demisto.args()
    endpoint_id = args.get('endpoint_id')
    operation_obj = endpoint_isolate(endpoint_id)
    md = tableToMarkdown(f'Isolate command on endpoint {endpoint_id} received', operation_obj,
                         headerTransform=pascalToSpace)
    context = {'Traps.Operation(val.OperationID == obj.OperationID)': operation_obj}
    return_outputs(md, context)


def endpoint_isolate_status_command():
    args = demisto.args()
    operation_id = args.get('operation_id')
    isolate_status = endpoint_isolate_status(operation_id)
    md = f'### Isolate status is: {isolate_status.get("status")}'
    context = {f'Traps.Operation.Isolate.'}


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
    elif demisto.command() == 'traps-event-quarantine-status':
        event_quarantine_status_command()
    elif demisto.command() == 'traps-endpoint-isolate':
        endpoint_isolate_command()
    elif demisto.command() == 'traps-endpoint-isolate-status':
        endpoint_isolate_status_command()


# Log exceptions
except Exception as e:
    LOG(e)
    LOG.print_log()
    demisto.results(e)
