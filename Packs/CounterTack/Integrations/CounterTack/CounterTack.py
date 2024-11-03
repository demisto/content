import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import urllib3
import os.path

# Disable insecure warnings
urllib3.disable_warnings()

# remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SERVER_URL = demisto.params().get('server')[:-1] if demisto.params().get('server').endswith('/') else \
    demisto.params().get('server')
FETCH_TIME = demisto.params().get('fetch_time', '3 days').strip()
FETCH_NOTIFICATIONS = demisto.params().get('fetch_notifications')
FETCH_BEHAVIORS = demisto.params().get('fetch_behviors')

# Should we use SSL
USE_SSL = not demisto.params().get('unsecure', False)
# Service base URL
BASE_PATH = f'{SERVER_URL}/api/v2/'
# Headers to be sent in requests
DEFAULT_HEADERS = {
    'Content-Type': 'application/json'
}


def http_request(method, suffix_url, headers=DEFAULT_HEADERS, body=None):
    """
    returns the http request

    """
    url = BASE_PATH + suffix_url

    response = requests.request(
        method,
        url,
        auth=(USERNAME, PASSWORD),
        headers=headers,
        verify=USE_SSL,
        data=body
    )
    # handle request failure
    if response.status_code not in {200}:
        message = parse_error_response(response)
        return_error(f'Error in API call to CounterTack with status code {response.status_code}\n{message}')

    try:
        response = response.json()
    except Exception:
        return_error(response.content)

    return response


def parse_error_response(response):
    try:
        res = response.json()
        msg = res.get('message')
        if res.get('details') is not None and res.get('details')[0].get('message') is not None:
            msg = msg + "\n" + json.dumps(res.get('details')[0])
    except Exception:
        return response.text
    return msg


"""

ENDPOINTS

"""


def get_endpoints_request():
    """
    This request returns a collection of endpoints.
    """
    suffix_url = 'endpoints'
    response = http_request('GET', suffix_url)
    return response


def get_endpoints():
    """
    Returns the information on existing endpoints
    """
    data = []
    endpoint_standards = []
    endpoints = get_endpoints_request()
    for endpoint in endpoints:
        data.append({
            'Id': endpoint.get('id'),
            'Name': endpoint.get('name'),
            'OS': endpoint.get('product_name'),
            'IP': endpoint.get('ips'),
            'Status': endpoint.get('status'),
            'Threat': endpoint.get('threat')
        })
        endpoint_standards.append({
            'Id': endpoint.get('id'),
            'IPAddress': endpoint.get('ips'),
            'Domain': endpoint.get('domain'),
            'MACAddress': endpoint.get('mac'),
            'OS': endpoint.get('product_name'),
            'OSVersion': endpoint.get('driver_version'),
            'Model': endpoint.get('current_profile'),
            'Memory': endpoint.get('memory'),
            'Processors': endpoint.get('num_cpus')
        })

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(endpoints,
                                                                           keyTransform=underscoreToCamelCase),
        'Endpoint': endpoint_standards
    }

    headers = ['OS', 'Name', 'Threat', 'Status', 'Id', 'IP']
    entry = {
        'Type': entryTypes['note'],
        'Contents': endpoints,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'CounterTack Endpoints', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def get_endpoint_request(endpoint_id):
    """
    Request for a specific endpoint
    """
    suffix_url = 'endpoints/' + endpoint_id

    response = http_request('GET', suffix_url)

    return response


def get_endpoint():
    """
    Get the information for the requested endpoint

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint

    returns:
        The information about the specified endpoint
    """
    endpoint_id = demisto.args().get('endpoint_id')

    response = get_endpoint_request(endpoint_id)

    content = {
        'OS': response.get('product_name'),
        'Domain': response.get('domain'),
        'IP': response.get('ip'),
        'Threat': response.get('threat'),
        'MaxImpact': response.get('max_impact'),
        'TenantID': response.get('tenant'),
        'IsQuarantined': response.get('is_quarantined'),
        'Profile': response.get('current_profile'),
        'Cluster_hosts': response.get('cluster_hosts'),
        'Status': response.get('status'),
        'Tags': response.get('tags')
    }

    endpoint_standards = {
        'Id': response.get('id'),
        'IPAddress': response.get('ips'),
        'Domain': response.get('domain'),
        'MACAddress': response.get('mac'),
        'OS': response.get('product_name'),
        'OSVersion': response.get('driver_version'),
        'Model': response.get('current_profile'),
        'Memory': response.get('memory'),
        'Processors': response.get('num_cpus')
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(response,
                                                                           keyTransform=underscoreToCamelCase),
        'Endpoint': endpoint_standards
    }

    headers = ['OS', 'Domain', 'IP', 'Threat', 'MaxImpact', 'TenantID', 'IsQuarantined',
               'Profile', 'Tags', 'Cluster_Hosts', 'Status']
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'CounterTack Endpoint information:', content, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


"""
ENDPOINTS TAGS
"""


def endpoint_tags_request(endpoint_id):
    """
    This request retrieves tags from specified endpoint
    """

    suffix_url = 'endpoints/' + endpoint_id + '/tags'

    response = http_request('GET', suffix_url)
    return response


def get_endpoint_tags():
    """
    Get the tags for the specified endpoint

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    """
    endpoint_id = demisto.args().get('endpoint_id')
    response = endpoint_tags_request(endpoint_id)

    response = {
        'tags': response
    }

    tags_context = {
        'Id': endpoint_id,
        'tags': response
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(tags_context,
                                                                           keyTransform=underscoreToCamelCase)
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('CounterTack tags for the specified endpoint:', response, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def add_tags_request(endpoint_id, body):
    """
    The request adds tags to specified endpoint

    The request gets the endpoint ID and the tags the user wants to add.
    """
    suffix_url = 'endpoints/' + endpoint_id + '/tags'

    response = http_request('POST', suffix_url, body=json.dumps(body))
    return response


def add_tags():
    """
    The command add tags for the specified endpoint.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (array) body
        The tags to add to the endpoint
    """

    endpoint_id = demisto.args().get('endpoint_id')
    body = argToList(demisto.args().get('tags'))

    response = add_tags_request(endpoint_id, body)
    response = endpoint_tags_request(endpoint_id)

    response = {
        'tags': response,
        'Id': endpoint_id
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(response, keyTransform=underscoreToCamelCase)
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Endpoint tags were added successfully", response),
        'EntryContext': context
    }
    demisto.results(entry)


def delete_tags_request(endpoint_id, body):
    """
    This request deletes specific tags from specified endpoint.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (array) body
        The tags to delete from the endpoint
    """

    suffix_url = 'endpoints/' + endpoint_id + '/tags'

    response = http_request('DELETE', suffix_url, body=json.dumps(body))
    return response


def delete_tags():
    """
    The command deletes tags for the specified endpoint.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (array) body
        The tags to delete from the endpoint
    """

    endpoint_id = demisto.args().get('endpoint_id')
    body = argToList(demisto.args().get('tags'))

    response = delete_tags_request(endpoint_id, body)
    response = endpoint_tags_request(endpoint_id)

    response = {
        'tags': response,
        'Id': endpoint_id
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(response, keyTransform=underscoreToCamelCase)
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'Endpoint tags were deleted successfully', response),
        'EntryContext': context
    }
    demisto.results(entry)


"""
ENDPOINTS COMMANDS
"""


def endpoint_quarantine_request(endpoint_id, body):
    """
    Request to quarantine a specified endpoint

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (string) type
        The type of the command: quarantine
    """

    suffix_url = 'endpoints/' + endpoint_id + '/commands'
    response = http_request('POST', suffix_url, body=json.dumps(body))

    return response


def endpoint_quarantine():
    """
    Prevents an endpoint(s) from any network communication, but maintains a connection to the Sentinel Cluster
    and addresses defined in the Global Whitelist.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (string) type
        The type of the command: quarantine
    """

    endpoint_id = demisto.args().get('endpoint_id')
    body = {
        'type': 'quarantine'
    }
    response = endpoint_quarantine_request(endpoint_id, body)
    quarantine_response = get_endpoint_request(endpoint_id)
    quarantine_context = {
        'Id': endpoint_id,
        'is_quarantine': quarantine_response.get('is_quarantined')
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(quarantine_context,
                                                                           keyTransform=underscoreToCamelCase)
    }

    data = {
        'Id': response.get('id'),
        'user name': response.get('username'),
        'request time': response.get('request_time'),
        'endpoint ID': response.get('endpoint_ids'),
        'command name': response.get('command_name'),
        'status': response.get('status'),
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': quarantine_context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('The command has been applied successfully:', data, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def disable_quarantine():
    """
    Allows a previously quarantined endpoint to communicate with the network.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (string) type
        The type of the command: lift_quarantine

    """
    endpoint_id = demisto.args().get('endpoint_id')
    body = {
        'type': 'lift_quarantine'
    }
    response = endpoint_quarantine_request(endpoint_id, body)
    quarantine_response = get_endpoint_request(endpoint_id)

    quarantine_context = {
        'Id': endpoint_id,
        'is_quarantine': quarantine_response.get('is_quarantined')
    }

    data = {
        'Id': response.get('id'),
        'user name': response.get('username'),
        'request time': response.get('request_time'),
        'endpoint ID': response.get('endpoint_ids'),
        'command name': response.get('command_name'),
        'status': response.get('status'),
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(quarantine_context,
                                                                           keyTransform=underscoreToCamelCase)
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': quarantine_context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('The command has been applied successfully:', data, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def file_extract_request(endpoint_id, body):
    """
    Request for extracting file from specified endpoint
    """

    suffix_url = 'endpoints/' + endpoint_id + '/commands'

    response = http_request('POST', suffix_url, body=json.dumps(body))
    return response


def extract_file():
    """
    Enables an API consumer to extract the file in addition to some file metadata.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (string) body
        The type of the command: extract file and the file path
    """
    endpoint_id = demisto.args().get('endpoint_id')
    paths = argToList(demisto.args().get('file_path'))
    body = {
        'type': 'extract_files',
        'paths': paths
    }

    response = file_extract_request(endpoint_id, body)
    data = {
        'Id': response.get('id'),
        'User Name': response.get('username'),
        'Request Time': response.get('request_time'),
        'Endpoint ID': response.get('endpoint_ids'),
        'Command Name': response.get('command_name'),
        'Command Arguments': response.get('command_arg'),
        'Status': response.get('status'),
    }

    context = {
        'CounterTack.File(val.Id && val.Id === obj.Id)': createContext(response, keyTransform=underscoreToCamelCase)
    }
    headers = ['Id', 'User Name', 'Request Time', 'Endpoint ID', 'Command Name', 'Command Arguments', 'Status']
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'The file has been extracted successfully:', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def delete_file_request(endpoint_id, body):
    """
    Deletes a file from the specified endpoint
    """

    suffix_url = 'endpoints/' + endpoint_id + '/commands'

    response = http_request('POST', suffix_url, body=json.dumps(body))
    return response


def delete_file():
    """
    Deletes a file from the specified endpoint

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (string) body
        The type of the command: delete_file and the file path
    """
    endpoint_id = demisto.args().get('endpoint_id')
    path = demisto.args().get('file_path')
    body = {
        'type': 'delete_file',
        'path': path
    }

    delete_file_request(endpoint_id, body)

    demisto.results('The file has been deleted successfully')


def kill_process_request(endpoint_id, body):
    """
    Reqquest to terminates all instances of the process identified in the command.

    """
    suffix_url = 'endpoints/' + endpoint_id + '/commands'

    response = http_request('POST', suffix_url, body=json.dumps(body))
    return response


def kill_process():
    """
    Terminates all instances of the process identified in the command.
    Processes can be identified by the PID or process name.

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    demisto parameter: (string) process_id
        The ID of the process to terminate
    demisto parameter: (string) process_name
        The name of the process to terminate

    """

    endpoint_id = demisto.args().get('endpoint_id')
    pid = demisto.args().get('process_id')
    name = demisto.args().get('process_name')
    if not pid and not name:
        return_error('Please provide either process_id or process_name')
    body = {
        'type': 'kill_process',
        'pid': pid,
        'name': name
    }

    response = kill_process_request(endpoint_id, body)

    data = {
        'Id': response.get('id'),
        'User Name': response.get('username'),
        'Request Time': response.get('request_time'),
        'Endpoint ID': response.get('endpoint_ids'),
        'Command Name': response.get('command_name'),
        'Status': response.get('status'),
    }

    context = {
        'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(response,
                                                                           keyTransform=underscoreToCamelCase,
                                                                           removeNull=True)
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'The process has been terminated', data, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


"""
ENDPOINT FILES

"""


def file_request():
    """
    This request retrieves all extracted files for all endpoints on the cluster
    """

    suffix_url = 'endpoints/files'

    response = http_request('GET', suffix_url)
    return response


def get_all_files():

    data = []
    files_standards = []

    files = file_request()
    for file in files:
        data.append({
            'Id': file.get('id'),
            'user': file.get('user'),
            'endpoint_id': file.get('endpoint_id'),
            'path': file.get('path'),
            'extraction_time': file.get('extraction_time'),
            'Status': file.get('status')
        })

        files_standards.append({
            'Size': file.get('size'),
            'MD5': file.get('md5'),
            'SHA256': file.get('sha256'),
            'SSDeep': file.get('ssdeep'),
            'Path': file.get('path')
        })

    context = {
        'CounterTack.File(val.Id && val.Id === obj.Id)': createContext(files, keyTransform=underscoreToCamelCase),
        outputPaths['file']: files_standards
    }

    headers = ['Status', 'Id', 'path', 'endpoint_id', 'extraction_time', 'user']
    entry = {
        'Type': entryTypes['note'],
        'Contents': files,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'CounterTack Endpoints Files', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def endpoint_files_request(endpoint_id):
    """
    This request returns all extracted files from specified endpoint
    """

    suffix_url = 'endpoints/' + endpoint_id + '/files'

    response = http_request('GET', suffix_url)
    return response


def get_endpoint_files():
    """
    Returns extracted files from specific endpoint

    demisto parameter: (string) endpoint_id
        The unique ID of the endpoint
    """

    endpoint_id = demisto.args().get('endpoint_id')
    data = []
    files_standards = []

    files = endpoint_files_request(endpoint_id)
    for file in files:
        data.append({
            'Id': file.get('id'),
            'User': file.get('user'),
            'EndpointId': file.get('endpoint_id'),
            'Path': file.get('path'),
            'ExtractionTime': file.get('extraction_time'),
            'Status': file.get('status')
        })
        files_standards.append({
            'Size': file.get('size'),
            'MD5': file.get('md5'),
            'SHA256': file.get('sha256'),
            'SSDeep': file.get('ssdeep'),
            'Path': file.get('path')
        })
    context = {
        'CounterTack.File(val.Id && val.Id === obj.Id)': createContext(files, keyTransform=underscoreToCamelCase),
        outputPaths['file']: files_standards
    }

    headers = ['Status', 'Id', 'path', 'endpoint_id', 'extraction_time', 'user']
    entry = {
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(
            'The extracted files from the endpoint:', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def file_information_request(file_id):
    """
    request specific file information
    """
    suffix_url = 'endpoints/files/' + file_id
    response = http_request('GET', suffix_url)

    return response


def get_file_information():
    """
    Get the information of a specific file

    demisto parameter: (string) file_id
        The unique ID of the extracted file
    """
    context = {}
    files_standards = []
    file_id = demisto.args().get('file_id')
    response = file_information_request(file_id)

    data = {
        'endpoint_name': response.get('endpoint_name'),
        'path': response.get('path'),
        'size': response.get('size'),
        'extraction_time': response.get('extraction_time'),
        'status': response.get('status')
    }

    files_standards.append({
        'Size': response.get('size'),
        'MD5': response.get('md5'),
        'SHA256': response.get('sha256'),
        'SSDeep': response.get('ssdeep'),
        'Path': response.get('path')
    })

    context['CounterTack.File(val.Id && val.Id === obj.Id)'] = createContext(response,
                                                                             keyTransform=underscoreToCamelCase)
    context[outputPaths['file']] = files_standards
    headers = ['endpoint_name', 'path', 'size', 'status', 'extraction_time']
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('CounterTack File Information:', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def download_file_request(file_id):

    # This request downloads an extracted file.

    suffix_url = 'downloads/extractedfiles/' + file_id
    response = http_request('GET', suffix_url)
    return response


def download_file():
    """
    Download an extracted file in a ZIP format.

    demisto parameter: (string) file_id
        The unique ID of the extracted file
    """

    file_id = demisto.args().get('file_id')
    response = download_file_request(file_id)

    demisto.results(fileResult(file_id + '.zip', response.content))


"""

BEHAVIORS

"""


def get_behaviors_request():
    """
    This request retrieves information on a collection of behaviors.
    """
    suffix_url = 'behaviors'

    response = http_request('GET', suffix_url)
    return response


def get_behaviors():
    """
    retrieve information on a collection of behaviors.
    """
    data = []
    behaviors = get_behaviors_request()
    for behavior in behaviors:
        data.append({
            'Id': behavior.get('id'),
            'Name': behavior.get('name'),
            'Type': behavior.get('type'),
            'ImpactLevel': behavior.get('impact_level'),
            'lastReported': behavior.get('last_reported'),
            'EndpointId': behavior.get('endpoint_id')
        })

    context = {
        'CounterTack.Behavior(val.Id && val.Id === obj.Id)': createContext(behaviors,
                                                                           keyTransform=underscoreToCamelCase)
    }
    headers = ['Name', 'Id', 'Type', 'ImpactLevel', 'EndpointId', 'lastReported']
    entry = {
        'Type': entryTypes['note'],
        'Contents': behaviors,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('CounterTack Endpoints Behaviors', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


def get_behavior_request(behavior_id):
    """
    Request for getting specified behvior
    """
    suffix_url = 'behaviors/' + behavior_id

    response = http_request('GET', suffix_url)
    return response


def get_behavior():
    """
    Get behavior information

    demisto parameter: behavior_id(string)
        The unique ID of the behvior

    """

    behavior_id = demisto.args().get('behavior_id')
    response = get_behavior_request(behavior_id)

    data = {
        'Id': response.get('id'),
        'Name': response.get('name'),
        'ImpactLevel': response.get('impact_level'),
        'LastActive': response.get('last_active'),
        'EventCount': response.get('event_count'),
        'MaxImpact': response.get('max_impact'),
        'EndpointId': response.get('endpoint_id'),
        'Type': response.get('type'),
    }

    context = {
        'CounterTack.Behavior(val.Id && val.Id === obj.Id)': createContext(response, keyTransform=underscoreToCamelCase)
    }
    headers = ['Name', 'Id', 'ImpactLevel', 'MaxImpact', 'EventCount', 'Type', 'EndpointId', 'LastActive']
    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('CounterTack Behavior information', data, headers, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


"""
BEHAVIORS TAGS
"""


def behaviour_add_tags_request(behaviour_id, body):
    """
    The request adds tags to specified behaviour
    """
    suffix_url = 'behaviors/' + behaviour_id + '/tags'
    response = http_request('POST', suffix_url, body=json.dumps(body))
    return response


def add_behavior_tags():
    """
    Add specific tags to specified behavior

    demisto parameter: (string) behavior_id
        The unique ID of the behavior

    demisto parameter: (Array) Body.
        The tags to add to the behavior. seperate the tags with comma
    """
    behaviour_id = demisto.args().get('behaviour_id')
    body = argToList(demisto.args().get('tags'))

    response = behaviour_add_tags_request(behaviour_id, body)
    behavior_tags = get_behavior_request(behaviour_id)

    response = {
        'tags': behavior_tags.get('tags'),
        'Id': behaviour_id
    }

    context = {
        'CounterTack.Behavior(val.Id && val.Id === obj.Id)': createContext(response, keyTransform=underscoreToCamelCase)
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Behavior tags were added successfully', response),
        'EntryContext': context
    }
    demisto.results(entry)


def delete_tags_behavior_request(behaviour_id, body):

    suffix_url = 'behaviors/' + behaviour_id + '/tags'
    response = http_request('DELETE', suffix_url, body=json.dumps(body))
    return response


def delete_behavior_tags():
    """
    Delete specific tags from behavior

    demisto parameter: (string) behavior_id
        The unique ID of the behavior

    demisto parameter: (Array) Body.
        The tags to delete from the behavior. seperate the tags with comma

    """
    behaviour_id = demisto.args().get('behaviour_id')
    body = argToList(demisto.args().get('tags'))

    response = delete_tags_behavior_request(behaviour_id, body)
    response = get_behavior_request(behaviour_id)

    response = {
        'tags': response.get('tags'),
        'Id': behaviour_id
    }

    context = {
        'CounterTack.Behavior(val.Id && val.Id === obj.Id)': createContext(response, keyTransform=underscoreToCamelCase)
    }

    entry = {
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Endpoint tags were deleted successfully', response, removeNull=True),
        'EntryContext': context
    }
    demisto.results(entry)


"""
SEARCH
"""


def search_endpoints_request(exp):
    """
    Request for endpoints search using CQL expression

    """
    suffix_url = 'search/endpoints' + exp
    response = http_request('GET', suffix_url)

    return response


def search_behaviors_request(exp):
    """
    Request for endpoints search using CQL expression

    """
    suffix_url = 'search/behaviors' + exp
    response = http_request('GET', suffix_url)

    return response


def search_events_request(exp):
    """
    Request for events search using CQL expression

    """
    suffix_url = 'search/events' + exp
    response = http_request('GET', suffix_url)

    return response


def search_events():
    """
    Request for events search using CQL expression
    demisto parameter: (dict) expression
        The CQL expression to be used for the search
    """

    data = []
    expression = demisto.args().get('expression')
    exp = '?expression=' + expression
    events = search_events_request(exp)
    if events.get('results'):
        results = events.get('results')
        results_lst = list()
        for i in range(len(results)):
            results_lst.append({k.replace('events.', ''): v for k, v in results[i].items()})
        events['results'] = results_lst
        for event in events.get('results'):
            data.append({
                'Id': event.get('id'),
                'Events Action': event.get('action'),
                'Events Impact': event.get('impact'),
                'Events EndpointID': event.get('endpoint_id'),
                'Event Type': event.get('event_type'),
                'Collected time': event.get('time_stamp'),
                'Source process PID': event.get('source_process_pid'),
                'Source process name': event.get('source_process_name')
            })

        context = {
            'CounterTack.Event(val.Id && val.Id === obj.Id)': createContext(results_lst,
                                                                            keyTransform=underscoreToCamelCase,
                                                                            removeNull=True)
        }
        headers = ['ID', 'Event Type', 'Events Action', 'Events EndpointID', 'Events Impact',
                   'Collected time', 'Source process PID', 'Source process name']
        entry = {
            'Type': entryTypes['note'],
            'Contents': results_lst,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Results of the events search', data, headers, removeNull=True),
            'EntryContext': context
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def search_endpoints():
    """
    Request for endpoints search using CQL expression
    demisto parameter: (dict) expression
        The CQL expression to be used for the search
    """

    data = []
    endpoint_standards = []
    expression = demisto.args().get('expression')
    exp = '?expression=' + expression
    endpoints = search_endpoints_request(exp)
    if endpoints.get('results'):
        results = endpoints.get('results')
        results_lst = list()
        for i in range(len(results)):
            results_lst.append({k.replace('endpoints.', ''): v for k, v in results[i].items()})
        endpoints['results'] = results_lst
        for endpoint in endpoints.get('results'):
            data.append({
                'Id': endpoint.get('id'),
                'Name': endpoint.get('name'),
                'OS': endpoint.get('product_name'),
                'IP': endpoint.get('ips'),
                'Status': endpoint.get('status'),
                'Threat': endpoint.get('threat')
            })
            endpoint_standards.append({
                'Id': endpoint.get('id'),
                'IPAddress': endpoint.get('ips'),
                'Domain': endpoint.get('domain'),
                'MACAddress': endpoint.get('mac'),
                'OS': endpoint.get('product_name'),
                'OSVersion': endpoint.get('driver_version'),
                'Model': endpoint.get('current_profile'),
                'Memory': endpoint.get('memory'),
                'Processors': endpoint.get('num_cpus')
            })
        context = {
            'CounterTack.Endpoint(val.Id && val.Id === obj.Id)': createContext(results_lst,
                                                                               keyTransform=underscoreToCamelCase,
                                                                               removeNull=True),
            'Endpoint': endpoint_standards
        }

        headers = ['Status', 'Name', 'Id', 'OS', 'Events Impact', 'Threat', 'IP']
        entry = {
            'Type': entryTypes['note'],
            'Contents': results_lst,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Results of the endpoints search', data, headers, removeNull=True),
            'EntryContext': context
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def search_behaviors():
    """
    Request for behaviors search using CQL expression
    demisto parameter: (dict) expression
        The CQL expression to be used for the search
    """

    data = []
    expression = demisto.args().get('expression')
    exp = '?expression=' + expression
    behaviors = search_behaviors_request(exp)
    if behaviors.get('results'):
        results = behaviors.get('results')
        results_lst = list()
        for i in range(len(results)):
            results_lst.append({k.replace('behaviors.', ''): v for k, v in results[i].items()})
        behaviors['results'] = results_lst
        for behavior in behaviors.get('results'):
            data.append({
                'Id': behavior.get('id'),
                'Name': behavior.get('name'),
                'Type': behavior.get('type'),
                'Impact_Level': behavior.get('impact_level'),
                'lastReported': behavior.get('last_reported'),
                'EndpointID': behavior.get('endpoint_id')
            })

        context = {
            'CounterTack.Behavior(val.Id && val.Id === obj.Id)': createContext(results_lst,
                                                                               keyTransform=underscoreToCamelCase,
                                                                               removeNull=True)
        }
        headers = ['Name', 'Type', 'Impact_Level', 'Id', 'EndpointID', 'lastReported']
        entry = {
            'Type': entryTypes['note'],
            'Contents': results_lst,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Results of the behaviors search', data, headers, removeNull=True),
            'EntryContext': context
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


def hashes_search_request(exp):
    """
    Request for Hashed search using CQL expression

    """
    suffix_url = 'search/hashes' + exp
    response = http_request('GET', suffix_url)

    return response


def search_hashes():
    """
    Request for hashes search using CQL expression
    demisto parameter: (dict) expression
        The CQL expression to be used for the search
    """
    data = []
    file_standards = []
    expression = demisto.args().get('expression')
    exp = '?expression=' + expression
    hashes = hashes_search_request(exp)
    if hashes.get('results'):
        results = hashes.get('results')
        results_lst = list()
        for i in range(len(results)):
            results_lst.append({k.replace('hashes.', ''): v for k, v in results[i].items()})
        hashes['results'] = results_lst
        for hash_type in hashes.get('results'):
            file_hash_type = hash_type.get('type', '').upper()
            if file_hash_type == 'SSDEEP':
                file_hash_type = 'SSDeep'
            hash_id = hash_type.get('id')
            data.append({
                file_hash_type: hash_id,
                'Type': file_hash_type,
                'Impact': hash_type.get('impact'),
                'VT report location': hash_type.get('vt_report_location'),
                'AV Coverage': hash_type.get('av_coverage')
            })

            if file_hash_type:
                file_standards.append({
                    file_hash_type: hash_id
                })

        context = {
            'CounterTack.Hash(val.hash_id && val.hash_id === obj.hash_id)': createContext(data),
            outputPaths['file']: file_standards
        }

        entry = {
            'Type': entryTypes['note'],
            'Contents': results_lst,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Results of the hashes search:', data, removeNull=True),
            'EntryContext': context
        }
        demisto.results(entry)
    else:
        demisto.results('No results found')


"""

FETCH INCIDENTS

"""


def search_notifications_request(params=''):
    """
    Request for notifications search using CQL expression

    """
    suffix_url = 'search/notifications?expression=' + params
    response = http_request('GET', suffix_url)

    return response


def fetch_behaviors_request(params=''):
    """
    Request for behaviors search using CQL expression

    """
    suffix_url = 'search/behaviors?expression=' + params
    response = http_request('GET', suffix_url)

    return response


def fetch_incidents():
    incidents = []
    last_run = demisto.getLastRun()

    if last_run and last_run['time_stamp']:
        last_update_time = last_run['time_stamp']
    else:
        # In first run
        last_update_time, _ = parse_date_range(FETCH_TIME, date_format='%Y-%m-%dT%H:%M:%S.%f'[:-3])

    max_timestamp = last_update_time
    if FETCH_BEHAVIORS:
        params = 'behaviors.time_stamp>' + last_update_time
        behaviors = fetch_behaviors_request(params)

        for behavior in behaviors.get('results'):
            incident = behavior_to_incident(behavior)
            # 0 corresponds to never triggered
            time_stamp = behavior.get('behaviors.time_stamp')[:-5]  # comapre time_stamp
            if time_stamp > max_timestamp:
                max_timestamp = time_stamp
            incidents.append(incident)

    if FETCH_NOTIFICATIONS:
        params = 'notifications.time_stamp>' + last_update_time
        notifications = search_notifications_request(params)

        for notification in notifications.get('results'):
            incident = notifications_to_incidents(notification)
            time_stamp = notification.get('notifications.time_stamp')[:-5]

            if time_stamp > max_timestamp:
                max_timestamp = time_stamp
            incidents.append(incident)

    demisto.setLastRun({
        'time_stamp': max_timestamp
    })

    demisto.incidents(incidents)


def behavior_to_incident(behavior):
    incident = {}
    incident['name'] = 'CounterTack Behavior - ' + behavior.get('behaviors.name')
    incident['rawJSON'] = json.dumps(behavior)
    return incident


def notifications_to_incidents(notification):
    incident = {}
    incident['name'] = 'CounterTack Notification - ' + notification.get('notifications.message')
    incident['rawJSON'] = json.dumps(notification)
    return incident


"""

EXECUTION

"""

command = demisto.command()
LOG(f'Running command "{command}"')
try:
    if command == 'test-module':
        get_endpoints_request()
        demisto.results('ok')
    elif command == 'fetch-incidents':
        fetch_incidents()
    elif command == 'countertack-get-endpoints':
        get_endpoints()
    elif command == 'countertack-get-endpoint':
        get_endpoint()
    elif command == 'countertack-get-endpoint-tags':
        get_endpoint_tags()
    elif command == 'countertack-add-tags':
        add_tags()
    elif command == 'countertack-delete-tags':
        delete_tags()
    elif command == 'countertack-endpoint-quarantine':
        endpoint_quarantine()
    elif command == 'countertack-disable-quarantine':
        disable_quarantine()
    elif command == 'countertack-extract-file':
        extract_file()
    elif command == 'countertack-delete-file':
        delete_file()
    elif command == 'countertack-get-all-files':
        get_all_files()
    elif command == 'countertack-get-endpoint-files':
        get_endpoint_files()
    elif command == 'countertack-get-file-information':
        get_file_information()
    elif command == 'countertack-download-file':
        download_file()
    elif command == 'countertack-get-behaviors':
        get_behaviors()
    elif command == 'countertack-get-behavior':
        get_behavior()
    elif command == 'countertack-add-behavior-tags':
        add_behavior_tags()
    elif command == 'countertack-delete-behavior-tags':
        delete_behavior_tags()
    elif command == 'countertack-search-events':
        search_events()
    elif command == 'countertack-search-hashes':
        search_hashes()
    elif command == 'countertack-search-endpoints':
        search_endpoints()
    elif command == 'countertack-search-behaviors':
        search_behaviors()
    elif command == 'countertack-kill-process':
        kill_process()
except Exception as e:
    return_error(e)
    LOG(e)
