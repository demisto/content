import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params().get('url') and demisto.params()['url'].endswith('/')) \
    else demisto.params().get('url')
BASE_URL = f'{SERVER}/api/bit9platform/v1'
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
CB_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
CB_NO_MS_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
INCIDENTS_PER_FETCH = int(demisto.params().get('incidents_per_fetch', 15))
# Headers to be sent in requests
HEADERS = {
    'X-Auth-Token': TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}


''' HUMAN READABLE HEADERS '''


APPROVAL_REQUEST_HEADERS = [
    'ID',
    'FileName',
    'Status',
    'DateCreated',
    'Platform'
]


COMPUTER_HEADERS = [
    'ID',
    'Hostname',
    'IPAddress',
    'MACAddress',
    'OSVersion',
    'Processor',
    'Processors',
    'Model'
]


CONNECTOR_HEADERS = [
    'ID',
    'AnalysisName',
    'Enabled',
    'AnalysisEnabled',
    'AnalysisTargets',
    'CanAnalyze',
    'ConnectorVersion'
]


EVENT_HEADERS = [
    'ID',
    'Type',
    'SubType',
    'Severity',
    'Description'
]


FILE_ANALYSIS_HEADERS = [
    'ID',
    'PathName',
    'Priority',
    'FileCatalogId',
    'ComputerID',
    'DateCreated',
    'DateModified',
    'CreatedBy'
]


FILE_CATALOG_HEADERS = [
    'ID',
    'Name',
    'Type',
    'Extension',
    'Path',
    'Size'
    'ProductName',
    'Publisher',
    'Company'
]


FILE_INSTANCE_HEADERS = [
    'ID',
    'Name',
    'Path',
    'ComputerID',
    'CatalogID'
]


FILE_RULE_HEADERS = [
    'ID',
    'Name',
    'Description',
    'PolicyIDs',
    'FileState',
    'CatalogID',
    'Hash',
    'ReportOnly'
]


FILE_UPLOAD_HEADERS = [
    'ID',
    'PathName',
    'UploadPath',
    'UploadStatus',
    'DateCreated',
    'DateModified',
    'UploadedFileSize',
    'ComputerId',
    'Priority',
    'CreatedBy'
]

POLICY_HEADERS = [
    'ID',
    'Name',
    'PackageName',
    'Description',
    'EnforcementLevel'
]

PUBLISHER_HEADERS = [
    'ID',
    'Name',
    'Description',
    'Reputation',
    'State',
    'SignedCertificatesCount',
    'SignedFilesCount'
]

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=HEADERS, safe=False, parse_json=True):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: HTTP method for the request.

        :type url_suffix: ``str``
        :param url_suffix: The suffix of the URL (endpoint)

        :type params: ``dict``
        :param params: The URL params to be passed.

        :type data: ``dict``
        :param data: The body data of the request.

        :type headers: ``dict``
        :param headers: Request headers

        :type safe: ``bool``
        :param safe: If set to true will return None in case of error

        :return: Returns the http request response json
        :rtype: ``dict`` or ``str``
    """
    url = BASE_URL + url_suffix
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            json=data,
            headers=headers,
        )
    except requests.exceptions.RequestException as e:
        LOG(str(e))
        return_error('Error in connection to the server. Please make sure you entered the URL correctly.')
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        if safe:
            return None
        elif res.status_code == 401:
            reason = 'Unauthorized. Please check your API token'
        else:
            try:
                reason = res.json()
            except ValueError:
                reason = res.reason
        return_error(f'Error in API call status code: {res.status_code}, reason: {reason}')
    if parse_json:
        return res.json()
    return res.content


def remove_prefix(prefix, full_str):
    """
    Removes prefix from beginning of full_str if found
    :param prefix: Prefix to remove from full_str
    :param full_str: String to have its prefix removed
    :return: full_str without the provided prefix
    """
    if full_str.startswith(prefix):
        return full_str[len(prefix):]
    return full_str


def event_severity_to_dbot_score(severity):
    """
        Converts an severity int to DBot score representation
        Event severity. Can be one of:
        2 = Critical    -> 3
        3 = Error       -> 0
        4 = Warning     -> 2
        5 = Notice      -> 2
        6 = Info        -> 0
        7 = Debug       -> 0

        :type severity: ``int``
        :param severity: Int representation of a severity

        :return: DBot score representation of the severity
        :rtype ``int``
    """
    severity = int(severity)
    if severity == 2:
        return 3
    elif severity in (4, 5):
        return 2
    return 0


def cbp_date_to_timestamp(date):
    """
    Converts a date in carbon black's format to timestamp
    :param date: Date string in cbp date format
    :return: Timestamp of the given date
    """
    try:
        ts = date_to_timestamp(date, date_format=CB_TIME_FORMAT)
    except ValueError:
        ts = date_to_timestamp(date, date_format=CB_NO_MS_TIME_FORMAT)
    return ts


def event_to_incident(event):
    """
        Creates an incident of a detection.

        :type event: ``dict``
        :param event: Single event object

        :return: Incident representation of an event
        :rtype ``dict``
    """
    incident = {
        'name': event.get('description'),
        'occurred': str(event.get('timestamp')),
        'rawJSON': json.dumps(event),
        'severity': event_severity_to_dbot_score(event.get('severity'))
    }
    return incident


def remove_keys_with_empty_value(dict_with_params):
    """
    Removes from dict keys with empty values
    :param dict_with_params: dict to remove empty keys from
    :return: dict without any empty fields
    """
    return {k: v for k, v in dict_with_params.items() if v}


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', '/computer?limit=-1')


def search_file_catalog_command():
    """
    Searches for file catalog
    :return: EntryObject of the file catalog
    """
    args = demisto.args()
    raw_catalogs = search_file_catalog(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                       args.get('group'), args.get('fileName'), args.get('fileType'),
                                       args.get('computerId'), args.get('threat'), args.get('fileState'),
                                       args.get('hash'))
    headers = args.get('headers', FILE_CATALOG_HEADERS)
    catalogs = []
    for catalog in raw_catalogs:
        catalogs.append({
            'Size': catalog.get('fileSize'),
            'Path': catalog.get('pathName'),
            'SHA1': catalog.get('sha1'),
            'SHA256': catalog.get('sha256'),
            'MD5': catalog.get('md5'),
            'Name': catalog.get('fileName'),
            'Type': catalog.get('fileType'),
            'ProductName': catalog.get('productName'),
            'ID': catalog.get('id'),
            'Publisher': catalog.get('publisher'),
            'Company': catalog.get('company'),
            'Extension': catalog.get('fileExtension')
        })
    hr_title = "CarbonBlack Protect File Catalog Search"
    hr = tableToMarkdown(hr_title, catalogs, headers, removeNull=True, headerTransform=pascalToSpace)
    catalogs = {'File(val.SHA1 === obj.SHA1)': catalogs} if catalogs else None
    return_outputs(hr, catalogs, raw_catalogs)


@logger
def search_file_catalog(q=None, limit=None, offset=None, sort=None, group=None, file_name=None, file_type=None,
                        computer_id=None, threat=None, file_state=None, hash_value=None):
    """
    Sends the request for file catalog, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the catalogs to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param file_name: Name of the file under which this unique hash was first seen
    :param file_type: Type of the file
    :param computer_id: Id of computer where this file was first seen
    :param threat: Threat of this file
    :param file_state: File state of this hash
    :param hash_value: Hash of the file
    :return: File catalog response json
    """

    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if file_name:
        url_params['q'].append(f'fileName:{file_name}')
    if file_type:
        url_params['q'].append(f'fileType:{file_type}')
    if computer_id:
        url_params['q'].append(f'computerId:{computer_id}')
    if threat:
        url_params['q'].append(f'threat:{file_catalog_threat_to_int(threat)}')
    if file_state:
        url_params['q'].append(f'fileState:{file_catalog_file_state_to_int(file_state)}')
    if hash_value:
        hash_type = get_hash_type(hash_value)
        if hash_type != 'Unknown':
            url_params['q'].append(f'{hash_type}:{hash_value}')

    return http_request('GET', '/fileCatalog', params=url_params)


@logger
def file_catalog_threat_to_int(threat):
    """
    Threat of this file. Can be one of:
    -1=Unknown
    0=Clean
    50=Potential risk
    100=Malicious
    :param threat:
    :return:
    """
    threat_dict = {
        'Unknown': -1,
        'Clean': 0,
        'Potential risk': 50,
        'Malicious': 100
    }
    return threat_dict.get(threat, threat)


@logger
def file_catalog_file_state_to_int(file_state):
    """
    File state of this hash. Can be one of:
    1=Unapproved
    2=Approved
    3=Banned
    4=Approved by Policy
    5=Banned by Policy
    :param file_state: String value of file state
    :return:
    """
    file_state_dict = {
        'Unapproved': 1,
        'Approved': 2,
        'Banned': 3,
        'Approved by Policy': 4,
        'Banned by Policy': 5
    }
    return file_state_dict.get(file_state, file_state)


def search_computer_command():
    """
    Searches for file catalog
    :return: EntryObject of the computer
    """
    args = demisto.args()
    raw_computers = search_computer(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                    args.get('group'), args.get('name'), args.get('ipAddress'), args.get('macAddress'))
    headers = args.get('headers', COMPUTER_HEADERS)
    computers = []
    for computer in raw_computers:
        computers.append({
            'Memory': computer.get('memorySize'),
            'Processors': computer.get('processorCount'),
            'Processor': computer.get('processorModel'),
            'OS': computer.get('osShortName'),
            'OSVersion': computer.get('osName'),
            'MACAddress': computer.get('macAddress'),
            'Model': computer.get('machineModel'),
            'IPAddress': computer.get('ipAddress'),
            'Hostname': computer.get('name'),
            'ID': computer.get('id')
        })
    hr_title = "CarbonBlack Protect Computer Search"
    hr = tableToMarkdown(hr_title, computers, headers, removeNull=True, headerTransform=pascalToSpace)
    computers = {'Endpoint(val.ID === obj.ID)': computers} if computers else None
    return_outputs(hr, computers, raw_computers)


@logger
def search_computer(q=None, limit=None, offset=None, sort=None, group=None, name=None, ip_address=None, mac=None):
    """
    Sends the request for file catalog, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the computers to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param name: Computer name
    :param ip_address: Last known IP address of this computer
    :param mac: MAC address of adapter used to connect to the CB Protection Server
    :return: Computer response json
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if name:
        url_params['q'].append(f'name:{name}')
    if ip_address:
        url_params['q'].append(f'ipAddress:{ip_address}')
    if mac:
        url_params['q'].append(f'macAddress:{mac}')

    return http_request('GET', '/Computer', params=url_params)


def update_computer_command():
    """
    Updates computer
    :return: EntryObject of the computer
    """
    args = demisto.args()
    raw_computers = update_computer(
        args.get('id'),
        args.get('name'),
        args.get('computerTag'),
        args.get('description'),
        args.get('policyId'),
        args.get('automaticPolicy'),
        args.get('localApproval'),
        args.get('refreshFlags'),
        args.get('prioritized'),
        args.get('debugLevel'),
        args.get('kernelDebugLevel'),
        args.get('debugFlags'),
        args.get('debugDuration'),
        args.get('cCLevel'),
        args.get('cCFlags'),
        args.get('forceUpgrade'),
        args.get('template'),
    )
    computers = {
        'Memory': raw_computers.get('memorySize'),
        'Processors': raw_computers.get('processorCount'),
        'Processor': raw_computers.get('processorModel'),
        'OS': raw_computers.get('osShortName'),
        'OSVersion': raw_computers.get('osName'),
        'MACAddress': raw_computers.get('macAddress'),
        'Model': raw_computers.get('machineModel'),
        'IPAddress': raw_computers.get('ipAddress'),
        'Hostname': raw_computers.get('name'),
        'ID': raw_computers.get('id')
    }
    hr = tableToMarkdown('CarbonBlack Protect computer updated successfully', computers, COMPUTER_HEADERS)
    return_outputs(hr, {'Endpoint(val.ID === obj.ID)': computers}, raw_computers)


@logger
def update_computer(id, name, computer_tag, description, policy_id, automatic_policy, local_approval, refresh_flags,
                    prioritized, debug_level, kernel_debug_level, debug_flags, debug_duration, cclevel, ccflags,
                    force_upgrade, template):
    """
    Update computer

    :param id: id of computer
    :param name: name of computer
    :param computer_tag: computer tag of computer
    :param description: description of computer
    :param policy_id: policy id of the computer
    :param automatic_policy: automatic policy flag
    :param local_approval: local approval flag
    :param refresh_flags: refresh flags
    :param prioritized: Is prioritized
    :param debug_level: debug level of computer
    :param kernel_debug_level: kernel debug level of computer
    :param debug_flags: debug flags
    :param debug_duration: debug duration of computer
    :param cclevel: cache consistency check level set for agent
    :param ccflags: cache consistency check flags set for agent
    :param force_upgrade: True if upgrade is forced for this computer
    :param template: True if computer is a template
    :return: Result json of the request
    """
    body_params = {
        'id': id,
        'name': name,
        'computerTag': computer_tag,
        'description': description,
        'policyId': policy_id,
        'automaticPolicy': automatic_policy,
        'localApproval': local_approval,
        'refreshFlags': refresh_flags,
        'prioritized': prioritized,
        'debugLevel': debug_level,
        'kernelDebugLevel': kernel_debug_level,
        'debugFlags': debug_flags,
        'debugDuration': debug_duration,
        'cCLevel': cclevel,
        'cCFlags': ccflags,
        'forceUpgrade': force_upgrade,
        'template': template,
    }
    body_params = remove_keys_with_empty_value(body_params)

    return http_request('POST', '/computer', data=body_params)


def get_computer_command():
    """
    Gets the requested computer
    :return: EntryObject of the file catalog
    """
    args = demisto.args()
    id = args.get('id')
    raw_computer = get_computer(id)
    computer = {
        'Memory': raw_computer.get('memorySize'),
        'Processors': raw_computer.get('processorCount'),
        'Processor': raw_computer.get('processorModel'),
        'OS': raw_computer.get('osShortName'),
        'OSVersion': raw_computer.get('osName'),
        'MACAddress': raw_computer.get('macAddress'),
        'Model': raw_computer.get('machineModel'),
        'IPAddress': raw_computer.get('ipAddress'),
        'Hostname': raw_computer.get('name'),
        'ID': raw_computer.get('id')
    }
    headers = args.get('headers', COMPUTER_HEADERS)
    hr_title = f'CarbonBlack Protect Computer Get for {id}'
    hr = tableToMarkdown(hr_title, computer, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_computer = {'Endpoint(val.ID === obj.ID)': computer} if computer else None
    return_outputs(hr, entry_context_computer, raw_computer)


@logger
def get_computer(id):
    """
    Sends get computer request
    :param id: Computer ID
    :return: Result json of the request
    """
    url = f'/Computer/{id}'
    return http_request('GET', url)


def search_file_instance_command():
    """
    Searches for file instance
    :return: EntryObject of the file instance
    """
    args = demisto.args()
    raw_files = search_file_instance(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                     args.get('group'), args.get('computerId'), args.get('fileName'))
    headers = args.get('headers', FILE_INSTANCE_HEADERS)
    files = []
    if raw_files:
        for file in raw_files:
            files.append({
                'CatalogID': file.get('fileCatalogId'),
                'ComputerID': file.get('computerId'),
                'ID': file.get('id'),
                'Name': file.get('fileName'),
                'Path': file.get('pathName')
            })
    hr_title = "CarbonBlack Protect File Instance Search"
    hr = tableToMarkdown(hr_title, files, headers, removeNull=True, headerTransform=pascalToSpace)
    files = {'CBP.FileInstance(val.ID === obj.ID)': files} if files else None
    return_outputs(hr, files, raw_files)


@logger
def search_file_instance(q=None, limit=None, offset=None, sort=None, group=None, computer_id=None, file_name=None):
    """
    Sends the request for file instance, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param computer_id: Id of computer associated with this fileInstance
    :param file_name: Name of the file on the agent
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if computer_id:
        url_params['q'].append(f'computerId:{computer_id}')
    if file_name:
        url_params['q'].append(f'fileName:{file_name}')

    return http_request('GET', '/fileInstance', params=url_params)


def search_event_command():
    """
    Searches for file instance
    :return: EntryObject of the file instance
    """
    args = demisto.args()
    raw_events = search_event(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                              args.get('group'), args.get('type'), args.get('computerId'), args.get('ipAddress'),
                              args.get('fileName'), args.get('severity'), args.get('userName'),
                              args.get('fileCatalogId'))
    hr_events = []
    events = []
    if raw_events:
        for event in raw_events:
            event_json = {
                'FilePath': event.get('pathName'),
                'Param1': event.get('param1'),
                'Param2': event.get('param2'),
                'Param3': event.get('param3'),
                'SubTypeName': event.get('subtypeName'),
                'ComputerName': event.get('computerName'),
                'FileName': event.get('fileName'),
                'RuleName': event.get('ruleName'),
                'ProcessFileCatalogID': event.get('processFileCatalogId'),
                'StringID': event.get('stringId'),
                'IPAddress': event.get('ipAddress'),
                'PolicyID': event.get('policyId'),
                'Timestamp': event.get('timestamp'),
                'Username': event.get('userName'),
                'ComputerID': event.get('computerId'),
                'ProcessFileName': event.get('processFileName'),
                'IndicatorName': event.get('indicatorName'),
                'SubType': event.get('subtype'),
                'Type': event.get('type'),
                'ID': event.get('id'),
                'Description': event.get('description'),
                'Severity': event.get('severity'),
                'CommandLine': event.get('commandLine'),
                'ProcessPathName': event.get('processPathName')
            }
            events.append(event_json)
            hr_event_json = dict(event_json)
            hr_event_json['Type'] = event_type_to_string(hr_event_json['Type'])
            hr_event_json['Severity'] = event_severity_to_string(hr_event_json['Severity'])
            hr_events.append(hr_event_json)
    headers = args.get('headers', EVENT_HEADERS)
    hr_title = "CarbonBlack Protect Event Search"
    hr = tableToMarkdown(hr_title, hr_events, headers, removeNull=True, headerTransform=pascalToSpace)
    events = {'CBP.Event(val.ID === obj.ID)': events} if events else None
    return_outputs(hr, events, raw_events)


@logger
def search_event(q=None, limit=None, offset=None, sort=None, group=None, e_type=None, computer_id=None, ip_address=None,
                 file_name=None, severity=None, user_name=None, file_catalog_id=None):
    """
    Sends the request for file instance, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param e_type: Event type
    :param computer_id: Id of computer associated with this event
    :param ip_address: IP address associated with this event
    :param file_name: Name of the file associated with this event
    :param severity: Event severity
    :param user_name: User name associated with this event
    :param file_catalog_id: Id of fileCatalog entry associated with this fileRule
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if e_type:
        url_params['q'].append(f'type:{event_type_to_int(e_type)}')
    if computer_id:
        url_params['q'].append(f'computerId:{computer_id}')
    if ip_address:
        url_params['q'].append(f'ipAddress:{ip_address}')
    if file_name:
        url_params['q'].append(f'fileName:{file_name}')
    if severity:
        url_params['q'].append(f'severity:{event_severity_to_int(severity)}')
    if user_name:
        url_params['q'].append(f'userName:{user_name}')
    if file_catalog_id:
        url_params['q'].append(f'fileCatalogId:{file_catalog_id}')

    return http_request('GET', '/event', params=url_params)


@logger
def event_type_to_int(e_type):
    """
    Returns type of the event in int format
    :param e_type: event type in string or int format
    :return: type of the event in int format
    """
    type_dict = {
        'Server Management': 0,
        'Session Management': 1,
        'Computer Management': 2,
        'Policy Management': 3,
        'Policy Enforcement': 4,
        'Discovery': 5,
        'General Management': 6,
        'Internal Events': 8
    }
    return type_dict.get(e_type, e_type)


@logger
def event_severity_to_int(severity):
    """
    Return severity value in int
    :param severity: severity in string or int
    :return: severity value in int
    """
    severity_dict = {
        'Critical': 2,
        'Error': 3,
        'Warning': 4,
        'Notice': 5,
        'Info': 6,
        'Debug': 7
    }
    return severity_dict.get(severity, severity)


@logger
def event_type_to_string(e_type):
    """
    Returns event type as string
    :param e_type: Event type in int
    :return: event type as string
    """
    type_dict = {
        0: 'Server Management',
        1: 'Session Management',
        2: 'Computer Management',
        3: 'Policy Management',
        4: 'Policy Enforcement',
        5: 'Discovery',
        6: 'General Management',
        8: 'Internal Events'
    }
    return type_dict.get(e_type, e_type)


@logger
def event_severity_to_string(severity):
    """
    Returns event severity as string
    :param severity: Severity of the event
    :return: event severity as string
    """
    severity_dict = {
        2: 'Critical',
        3: 'Error',
        4: 'Warning',
        5: 'Notice',
        6: 'Info',
        7: 'Debug'
    }
    return severity_dict.get(severity, severity)


def search_approval_request_command():
    """
    Searches for approval requests
    :return: EntryObject of the approval requests
    """
    args = demisto.args()
    raw_approval_requests = search_approval(args.get('query'), args.get('limit'), args.get('offset'),
                                            args.get('sort'), args.get('group'))
    hr_approval_requests = []
    approval_requests = []
    if raw_approval_requests:
        for approval_request in raw_approval_requests:
            approval_request_output = {
                'ID': approval_request.get('id'),
                'Resolution': approval_request.get('resolution'),
                'Status': approval_request.get('status'),
                'ResolutionComments': approval_request.get('resolutionComments'),
                'FileCatalogID': approval_request.get('fileCatalogId'),
                'ComputerID': approval_request.get('computerId'),
                'ComputerName': approval_request.get('computerName'),
                'DateCreated': approval_request.get('dateCreated'),
                'CreatedBy': approval_request.get('createdBy'),
                'EnforcementLevel': approval_request.get('enforcementLevel'),
                'RequestorEmail': approval_request.get('requestorEmail'),
                'Priority': approval_request.get('priority'),
                'FileName': approval_request.get('fileName'),
                'PathName': approval_request.get('pathName'),
                'Process': approval_request.get('process'),
                'Platform': approval_request.get('platform')
            }
            approval_requests.append(approval_request_output)
            # handle human readable output
            hr_approval_request = dict(approval_request_output)
            hr_approval_request['Resolution'] = approval_request_resolution_to_string(hr_approval_request['Resolution'])
            hr_approval_request['Status'] = approval_request_status_to_string(hr_approval_request['Status'])
            hr_approval_requests.append(hr_approval_request)
    headers = args.get('headers', APPROVAL_REQUEST_HEADERS)
    hr_title = "CarbonBlack Protect Approval Request Search"
    hr = tableToMarkdown(hr_title, hr_approval_requests, headers, removeNull=True, headerTransform=pascalToSpace)
    approval_requests = {'CBP.ApprovalRequest(val.ID === obj.ID)': approval_requests} if approval_requests else None
    return_outputs(hr, approval_requests, raw_approval_requests)


@logger
def search_approval(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for approval request, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group
    }
    if q:
        # handle multi condition queries in the following formats: a&b
        q = q.split('&')
        url_params['q'] = q

    return http_request('GET', '/approvalRequest', params=url_params)


@logger
def approval_request_resolution_to_string(resolution):
    """
    Converts resolution as integer to string
    Based on https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#approvalrequest
    :param resolution: int that describes resolution [0-7]
    :return: string representation of the resolution (fallback: returns resolution)
    """
    resolution_dict = {
        0: 'Not Resolved',
        1: 'Rejected',
        2: 'Resolved - Approved',
        3: 'Resolved - Rule Change',
        4: 'Resolved - Installer',
        5: 'Resolved - Updated',
        6: 'Resolved - Publisher',
        7: 'Resolved - Other'
    }
    return resolution_dict.get(resolution, resolution)


@logger
def approval_request_status_to_string(status):
    """
    Converts status as integer to string
    Based on https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#approvalrequest
    :param status: int that describes status [1-4]
    :return: string representation of the status (fallback: returns status)
    """
    status_dict = {
        1: 'New',
        2: 'Open',
        3: 'Closed',
        4: 'Escalated'
    }
    return status_dict.get(status, status)


def search_file_rule_command():
    """
    Searches for file rules
    :return: EntryObject of the file rules
    """
    args = demisto.args()
    raw_file_rules = search_file_rule(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                      args.get('group'), args.get('fileCatalogId'), args.get('name'),
                                      args.get('fileState'), args.get('sourceType'), args.get('hash'),
                                      args.get('fileName'))
    hr_file_rules = []
    file_rules = []
    if raw_file_rules:
        for file_rule in raw_file_rules:
            file_rule_output = {
                'ID': file_rule.get('id'),
                'CatalogID': file_rule.get('fileCatalogId'),
                'Description': file_rule.get('description'),
                'FileState': file_rule.get('fileState'),
                'Hash': file_rule.get('hash'),
                'Name': file_rule.get('name'),
                'PolicyIDs': file_rule.get('policyIds'),
                'ReportOnly': file_rule.get('reportOnly')
            }
            file_rules.append(file_rule_output)
            hr_file_rule_output = dict(file_rule_output)
            hr_file_rule_output['FileState'] = file_rule_file_state_to_string(hr_file_rule_output['FileState'])
            hr_file_rules.append(hr_file_rule_output)
    headers = args.get('headers', FILE_RULE_HEADERS)
    hr_title = "CarbonBlack Protect File Rule Search"
    hr = tableToMarkdown(hr_title, hr_file_rules, headers, removeNull=True, headerTransform=pascalToSpace)
    file_rules = {'CBP.FileRule(val.ID === obj.ID)': file_rules} if file_rules else None
    return_outputs(hr, file_rules, raw_file_rules)


@logger
def search_file_rule(q=None, limit=None, offset=None, sort=None, group=None, file_catalog_id=None, name=None,
                     file_state=None, source_type=None, hash_value=None, file_name=None):
    """
    Sends the request for file rule, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param file_catalog_id: Id of fileCatalog entry associated with this fileRule
    :param name: Name of this rule
    :param file_state: File state for this
    :param source_type: Mechanism that created this rule
    :param hash_value: Hash associated with this rule
    :param file_name: File name associated with this rule
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if file_catalog_id:
        url_params['q'].append(f'fileCatalogId:{file_catalog_id}')
    if name:
        url_params['q'].append(f'name:{name}')
    if file_state:
        url_params['q'].append(f'fileState:{file_rule_file_state_to_int(file_state)}')
    if source_type:
        url_params['q'].append(f'sourceType:{file_rule_source_type_to_int(source_type)}')
    if hash_value:
        url_params['q'].append(f'hash:{hash_value}')
    if file_name:
        url_params['q'].append(f'fileName:{file_name}')

    return http_request('GET', '/fileRule', params=url_params)


@logger
def file_rule_file_state_to_int(file_state):
    """
    Returns file rule file state in int format
    :param file_state: File state of a file rule
    :return: file rule file state in int format
    """
    state_dict = {
        'Unapproved': 1,
        'Approved': 2,
        'Banned': 3
    }
    return state_dict.get(file_state, file_state)


@logger
def file_rule_source_type_to_int(e_type):
    """
    Returns type of the event in int format
    :param e_type: event type in string or int format
    :return: type of the event in int format
    """
    type_dict = {
        'Manual': 1,
        'Trusted Directory': 2,
        'Reputation': 3,
        'Imported': 4,
        'External (API)': 5,
        'Event Rule': 6,
        'Application Template': 7,
        'Unified Management': 8
    }
    return type_dict.get(e_type, e_type)


@logger
def file_rule_file_state_to_string(state):
    """
    Converts state as integer to string
    Based on https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#filerule
    :param state: int that describes state [1-3]
    :return: string representation of the state (fallback: returns state)
    """
    file_state_dict = {
        1: 'Unapproved',
        2: 'Approved',
        3: 'Banned'
    }
    return file_state_dict.get(state, state)


def get_file_rule_command():
    """
    Gets the requested file rule
    :return: EntryObject of the file catalog
    """
    args = demisto.args()
    id = args.get('id')
    raw_file_rule = get_file_rule(id)
    file_rule = {
        'ID': raw_file_rule.get('id'),
        'CatalogID': raw_file_rule.get('fileCatalogId'),
        'Description': raw_file_rule.get('description'),
        'FileState': raw_file_rule.get('fileState'),
        'Hash': raw_file_rule.get('hash'),
        'Name': raw_file_rule.get('name'),
        'PolicyIDs': raw_file_rule.get('policyIds'),
        'ReportOnly': raw_file_rule.get('reportOnly')
    }
    hr_file_rule = dict(file_rule)
    hr_file_rule['FileState'] = file_rule_file_state_to_string(hr_file_rule['FileState'])
    headers = args.get('headers', FILE_RULE_HEADERS)
    hr_title = f'CarbonBlack Protect File Rule Get for {id}'
    hr = tableToMarkdown(hr_title, hr_file_rule, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_file_rule = {'CBP.FileRule(val.ID === obj.ID)': file_rule} if file_rule else None
    return_outputs(hr, entry_context_file_rule, raw_file_rule)


@logger
def get_file_rule(id):
    """
    Sends get file rule request
    :param id: File rule ID
    :return: Result json of the request
    """
    url = f'/fileRule/{id}'
    return http_request('GET', url)


def delete_file_rule_command():
    """
    Deletes the requested file rule
    :return: EntryObject of the file catalog
    """
    args = demisto.args()
    id = args.get('id')
    delete_file_rule(id)
    hr = f"File Result {id} deleted successfully"
    demisto.results(hr)


@logger
def delete_file_rule(id):
    """
    Sends delete file rule request
    :param id: File rule ID
    :return: Result of the request
    """
    url = BASE_URL + f'/fileRule/{id}'
    res = requests.request(
        'DELETE',
        url,
        verify=USE_SSL,
        headers=HEADERS
    )
    return res


def update_file_rule_command():
    """
    Creates or update a file rule
    :return: Entry object of the created file analysis
    """
    args = demisto.args()
    raw_file_rule = update_file_rule(
        args.get('hash'),
        args.get('fileState'),
        args.get('id'),
        args.get('fileCatalogId'),
        args.get('name'),
        args.get('description'),
        args.get('reportOnly'),
        args.get('reputationApprovalsEnabled'),
        args.get('forceInstaller'),
        args.get('forceNotInstaller'),
        args.get('policyIds'),
        args.get('platformFlags'),
    )
    file_rule = {
        'ID': raw_file_rule.get('id'),
        'CatalogID': raw_file_rule.get('fileCatalogId'),
        'Description': raw_file_rule.get('description'),
        'FileState': raw_file_rule.get('fileState'),
        'Hash': raw_file_rule.get('hash'),
        'Name': raw_file_rule.get('name'),
        'PolicyIDs': raw_file_rule.get('policyIds'),
        'ReportOnly': raw_file_rule.get('reportOnly')
    }
    hr_file_rule = dict(file_rule)
    hr_file_rule['FileState'] = file_rule_file_state_to_string(hr_file_rule['FileState'])
    hr = tableToMarkdown('CarbonBlack Protect File Rule Updated successfully', hr_file_rule, FILE_RULE_HEADERS,
                         removeNull=True, headerTransform=pascalToSpace)
    return_outputs(hr, {'CBP.FileRule(val.ID === obj.ID)': file_rule}, raw_file_rule)


@logger
def update_file_rule(hash, file_state, id, file_catalog_id, name, description, report_only,
                     reputation_approvals_enabled, force_installer, force_not_installer, policy_ids, platform_flags):
    """
    Update file rule
    :param hash: hash of file rule
    :param file_state: File state of this hash
    :param id: id of the file rule
    :param file_catalog_id: file catlog id
    :param name: name of the file rule
    :param description: description
    :param report_only: True if this has a report-only ban
    :param reputation_approvals_enabled: True if reputation approvals are enabled for this file
    :param force_installer: True if this file is forced to act as installer
    :param force_not_installer: True if this file is forced to act as ‘not installer'
    :param policy_ids: List of IDs of policies where this rule applies.
    :param platform_flags: Set of platform flags where this file rule will be valid
    :return: Result json of the request
    """
    body_params = {
        'hash': hash,
        'fileState': file_state,
        'id': id,
        'fileCatalogId': file_catalog_id,
        'name': name,
        'description': description,
        'reportOnly': report_only,
        'reputationApprovalsEnabled': reputation_approvals_enabled,
        'forceInstaller': force_installer,
        'forceNotInstaller': force_not_installer,
        'policyIds': policy_ids,
        'platformFlags': platform_flags
    }
    body_params = remove_keys_with_empty_value(body_params)

    return http_request('POST', '/fileRule', data=body_params)


def search_policy_command():
    """
    Searches for policy
    :return: EntryObject of the policies
    """
    args = demisto.args()
    raw_policy = search_policy(args.get('query'), args.get('limit'), args.get('offset'),
                               args.get('sort'), args.get('group'),
                               args.get('enforcementLevel'), args.get('disconnectedEnforcementLevel'))
    hr_policies = []
    policies = []
    if raw_policy:
        for policy in raw_policy:
            policy_ec = {
                'ReadOnly': policy.get('readOnly'),
                'EnforcementLevel': policy.get('enforcementLevel'),
                'ReputationEnabled': policy.get('reputationEnabled'),
                'AtEnforcementComputers': policy.get('atEnforcementComputers'),
                'Automatic': policy.get('automatic'),
                'Name': policy.get('name'),
                'FileTrackingEnabled': policy.get('fileTrackingEnabled'),
                'ConnectedComputers': policy.get('connectedComputers'),
                'PackageName': policy.get('packageName'),
                'AllowAgentUpgrades': policy.get('allowAgentUpgrades'),
                'TotalComputers': policy.get('totalComputers'),
                'LoadAgentInSafeMode': policy.get('loadAgentInSafeMode'),
                'AutomaticApprovalsOnTransition': policy.get('automaticApprovalsOnTransition'),
                'ID': policy.get('id'),
                'Description': policy.get('description'),
                'DisconnectedEnforcementLevel': policy.get('disconnectedEnforcementLevel')
            }
            policies.append(policy_ec)
            hr_policy = dict(policy_ec)
            hr_policy['EnforcementLevel'] = policy_enforcement_lvl_to_string(hr_policy['EnforcementLevel'])
            hr_policies.append(hr_policy)
    headers = args.get('headers', POLICY_HEADERS)
    hr_title = "CarbonBlack Protect Policy Search"
    hr = tableToMarkdown(hr_title, hr_policies, headers, removeNull=True, headerTransform=pascalToSpace)
    policies = {'CBP.Policy(val.ID === obj.ID)': policies} if policies else None
    return_outputs(hr, policies, raw_policy)


@logger
def search_policy(q=None, limit=None, offset=None, sort=None, group=None, enf_lvl=None, dc_enf_lvl=None):
    """
    Sends the request for search policy, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param enf_lvl: Target enforcement level
    :param dc_enf_lvl: Target enforcement level for disconnected computers
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if enf_lvl:
        url_params['q'].append(f'enforcementLevel:{policy_enforcement_lvl_to_int(enf_lvl)}')
    if dc_enf_lvl:
        url_params['q'].append(f'disconnectedEnforcementLevel:{policy_enforcement_lvl_to_int(dc_enf_lvl)}')

    demisto.info(url_params)

    return http_request('GET', '/policy', params=url_params)


@logger
def policy_enforcement_lvl_to_int(enf_lvl):
    """
    Returns enforcement level in int
    :param enf_lvl: enforcement level string
    :return: enforcement level in int
    """
    enf_dict = {
        'High (Block Unapproved)': 20,
        'Medium (Prompt Unapproved)': 30,
        'Low (Monitor Unapproved)': 40,
        'None (Visibility)': 60,
        'None (Disabled)': 80
    }
    return enf_dict.get(enf_lvl, enf_lvl)


@logger
def policy_enforcement_lvl_to_string(enf_lvl):
    """
    Returns enforcement level in string
    :param enf_lvl: enforcement level int
    :return: enforcement level string
    """
    enf_dict = {
        20: 'High (Block Unapproved)',
        30: 'Medium (Prompt Unapproved)',
        40: 'Low (Monitor Unapproved)',
        60: 'None (Visibility)',
        80: 'None (Disabled)'
    }

    return enf_dict.get(enf_lvl, enf_lvl)


def search_server_config_command():
    """
    Searches for server config
    :return: EntryObject of the server configurations
    """
    args = demisto.args()
    raw_server_configs = search_server_config(args.get('query'), args.get('limit'), args.get('offset'),
                                              args.get('sort'), args.get('group'))
    server_configs = []
    if raw_server_configs:
        for server_config in raw_server_configs:
            server_configs.append({
                'ID': server_config.get('id'),
                'Value': server_config.get('value'),
                'Name': server_config.get('name')
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect Server Config Search"
    hr = tableToMarkdown(hr_title, server_configs, headers, removeNull=True, headerTransform=pascalToSpace)
    server_configs = {'CBP.ServerConfig(val.ID === obj.ID)': server_configs} if server_configs else None
    return_outputs(hr, server_configs, raw_server_configs)


@logger
def search_server_config(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file rule, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group
    }
    if q:
        # handle multi condition queries in the following formats: a&b
        q = q.split('&')
        url_params['q'] = q

    return http_request('GET', '/serverConfig', params=url_params)


@logger
def publisher_state_to_string(state):
    """
    Converts state as integer to string
    Based on https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#publisher
    :param state: int that describes state [1-5]
    :return: string representation of the state (fallback: returns state)
    """
    publisher_state_dict = {
        1: 'Unapproved',
        2: 'Approved',
        3: 'Banned',
        4: 'Approved By Policy',
        5: 'Banned By Policy'
    }
    return publisher_state_dict.get(state, state)


@logger
def publisher_reputation_to_string(reputation):
    """
    Converts reputation as integer to string
    Based on https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#publisher
    :param reputation: int that describes reputation [0-3]
    :return: string representation of the reputation (fallback: returns reputation)
    """
    publisher_reputation_dict = {
        0: 'Not trusted (Unknown)',
        1: 'Low',
        2: 'Medium',
        3: 'High'
    }
    return publisher_reputation_dict.get(reputation, reputation)


def search_publisher_command():
    """
    Searches for publisher
    :return: EntryObject of the publishers
    """
    args = demisto.args()
    raw_publishers = search_publisher(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                      args.get('group'), args.get('name'), args.get('publisherReputation'),
                                      args.get('publisherState'))
    hr_publishers = []
    publishers = []
    if raw_publishers:
        for publisher in raw_publishers:
            publisher_output = {
                'Description': publisher.get('description'),
                'ID': publisher.get('id'),
                'Name': publisher.get('name'),
                'Reputation': publisher.get('publisherReputation'),
                'SignedCertificatesCount': publisher.get('signedCertificateCount'),
                'SignedFilesCount': publisher.get('signedFilesCount'),
                'State': publisher.get('publisherState')
            }
            publishers.append(publisher_output)
            hr_publisher_output = dict(publisher_output)
            hr_publisher_output['State'] = publisher_state_to_string(hr_publisher_output['State'])
            hr_publisher_output['Reputation'] = publisher_reputation_to_string(hr_publisher_output['Reputation'])
            hr_publishers.append(hr_publisher_output)
    headers = args.get('headers', PUBLISHER_HEADERS)
    hr_title = "CarbonBlack Protect Publisher Search"
    hr = tableToMarkdown(hr_title, hr_publishers, headers, removeNull=True, headerTransform=pascalToSpace)
    publishers = {'CBP.Publisher(val.ID === obj.ID)': publishers} if publishers else None
    return_outputs(hr, publishers, raw_publishers)


@logger
def search_publisher(q=None, limit=None, offset=None, sort=None, group=None, name=None, reputation=None, state=None):
    """
    Sends the request for publisher, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file instances to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param name: Subject name of leaf certificate for this publisher
    :param reputation: Reputation of this publisher
    :param state: State for this publisher
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if name:
        url_params['q'].append(f'name:{name}')
    if reputation:
        url_params['q'].append(f'publisherReputation:{publisher_reputation_to_int(reputation)}')
    if state:
        url_params['q'].append(f'publisherState:{publisher_state_to_int(state)}')

    return http_request('GET', '/publisher', params=url_params)


@logger
def publisher_reputation_to_int(reputation):
    """
    Returns the publisher reputation as an int
    :param reputation: reputation of the publisher
    :return: publisher reputation as a string
    """
    reputation_dict = {
        'Not trusted (Unknown)': 0,
        'Low': 1,
        'Medium': 2,
        'High': 3
    }
    return reputation_dict.get(reputation, reputation)


@logger
def publisher_state_to_int(state):
    state_dict = {
        'Unapproved': 1,
        'Approved': 2,
        'Banned': 3,
        'Approved By Policy': 4,
        'Banned By Policy': 5
    }
    return state_dict.get(state, state)


def get_file_analysis_command():
    """
    Gets the requested file analysis
    :return: EntryObject of the file analysis
    """
    args = demisto.args()
    id = args.get('id')
    raw_file_analysis = get_file_analysis(id)
    # if got here, then get_file_analysis returned a result, so we can assume it'll have a valid fileCatalogId
    raw_file_rule = search_file_catalog(q=f"id:{raw_file_analysis.get('fileCatalogId')}")[0]
    cbp_ec_key = 'CBP.FileAnalysis(val.ID === obj.ID)'
    ec = create_file_analysis_result(raw_file_analysis, raw_file_rule, cbp_ec_key)
    hr_title = f'CarbonBlack Protect Get File Analysis for {id}'
    hr = tableToMarkdown(hr_title, ec[cbp_ec_key], FILE_ANALYSIS_HEADERS,
                         removeNull=True, headerTransform=pascalToSpace)
    return_outputs(hr, ec, raw_file_analysis)


@logger
def get_file_analysis(id):
    """
    Sends get file analysis
    :param id: File analysis ID
    :return: Result json of the request
    """
    url = f'/fileAnalysis/{id}'
    return http_request('GET', url)


@logger
def create_file_analysis_result(raw_file_analysis, raw_file_rule, cbp_ec_key):
    result = {
        cbp_ec_key: {
            'Priority': raw_file_analysis.get('priority'),
            'FileName': raw_file_analysis.get('fileName'),
            'PathName': raw_file_analysis.get('pathName'),
            'ComputerId': raw_file_analysis.get('computerId'),
            'DateModified': raw_file_analysis.get('dateModified'),
            'ID': raw_file_analysis.get('id'),
            'FileCatalogId': raw_file_analysis.get('fileCatalogId'),
            'DateCreated': raw_file_analysis.get('dateCreated'),
            'CreatedBy': raw_file_analysis.get('createdBy')
        },
        outputPaths['file']: {
            'FileCatalogId': raw_file_analysis.get('fileCatalogId'),
            'Name': raw_file_analysis.get('fileName'),
            'PathName': raw_file_analysis.get('pathName'),
            'SHA1': raw_file_rule.get('sha1'),
            'SHA256': raw_file_rule.get('sha256'),
            'MD5': raw_file_rule.get('md5')
        },
        'DBotScore': [
            {
                'Indicator': raw_file_rule.get('md5'),
                'Type': 'hash',
                'Vendor': 'Carbon Black Protection',
                'Score': raw_file_analysis.get('analysisResult', 0)  # cb scoring as the same as dbot scoring
            },
            {
                'Indicator': raw_file_rule.get('sha1'),
                'Type': 'hash',
                'Vendor': 'Carbon Black Protection',
                'Score': raw_file_analysis.get('analysisResult', 0)  # cb scoring as the same as dbot scoring
            },
            {
                'Indicator': raw_file_rule.get('sha256'),
                'Type': 'hash',
                'Vendor': 'Carbon Black Protection',
                'Score': raw_file_analysis.get('analysisResult', 0)  # cb scoring as the same as dbot scoring
            }
        ]
    }
    # analysisResult == 3 -> Malicious
    if int(raw_file_analysis.get('analysisResult', 0)) == 3:
        result[outputPaths['file']].update({  # type: ignore
            'Malicious': {
                'Vendor': 'Carbon Black Protection',
                'Description': 'Carbon Black Protection found this file to be malicious.'
            }
        })
    return result


def update_file_analysis_command():
    """
    Creates or update a file analysis
    :return: Entry object of the created file analysis
    """
    args = demisto.args()
    raw_file_analysis = update_file_analysis(
        args.get('fileCatalogId'),
        args.get('connectorId'),
        args.get('computerId'),
        args.get('priority'),
        args.get('analysisStatus'),
        args.get('analysisTarget'),
        args.get('id')
    )
    file_analysis = {
        'Priority': raw_file_analysis.get('priority'),
        'FileName': raw_file_analysis.get('fileName'),
        'PathName': raw_file_analysis.get('pathName'),
        'ComputerId': raw_file_analysis.get('computerId'),
        'DateModified': raw_file_analysis.get('dateModified'),
        'ID': raw_file_analysis.get('id'),
        'FileCatalogId': raw_file_analysis.get('fileCatalogId'),
        'DateCreated': raw_file_analysis.get('dateCreated'),
        'CreatedBy': raw_file_analysis.get('createdBy')
    }
    hr = tableToMarkdown('CarbonBlack Protect File Analysis Created successfully', file_analysis, FILE_ANALYSIS_HEADERS)
    return_outputs(hr, {'CBP.FileAnalysis(val.ID === obj.ID)': file_analysis}, raw_file_analysis)


@logger
def update_file_analysis(file_catalog_id, connector_id, computer_id, priority, analysis_status, analysis_target, id):
    """
    Update file analysis
    :param file_catalog_id: catalog id
    :param connector_id: connector id
    :param computer_id: computer id
    :param priority: priority of the file analysis
    :param analysis_status: status of the analysis
    :param analysis_target: target of the analysis
    :param id: id of the file analysis
    :return: Result json of the request
    """
    body_params = {
        'fileCatalogId': file_catalog_id,
        'connectorId': connector_id,
        'computerId': computer_id,
        'priority': priority,
        'analysisStatus': analysis_status,
        'analysisTarget': analysis_target,
        'id': id
    }
    body_params = remove_keys_with_empty_value(body_params)

    return http_request('POST', '/fileAnalysis', data=body_params)


def update_file_upload_command():
    """
    Creates or update a file upload
    :return: Entry object of the created file upload
    """
    args = demisto.args()
    raw_file_upload = update_file_upload(
        args.get('fileCatalogId'),
        args.get('computerId'),
        args.get('priority'),
        args.get('uploadStatus'),
        args.get('id')
    )
    file_upload = {
        'Priority': raw_file_upload.get('priority'),
        'FileName': raw_file_upload.get('fileName'),
        'UploadPath': raw_file_upload.get('uploadPath'),
        'ComputerId': raw_file_upload.get('computerId'),
        'DateModified': raw_file_upload.get('dateModified'),
        'ID': raw_file_upload.get('id'),
        'FileCatalogId': raw_file_upload.get('fileCatalogId'),
        'DateCreated': raw_file_upload.get('dateCreated'),
        'CreatedBy': raw_file_upload.get('createdBy'),
        'PathName': raw_file_upload.get('pathName'),
        'UploadStatus': raw_file_upload.get('uploadStatus'),
        'UploadedFileSize': raw_file_upload.get('uploadedFileSize'),
    }
    hr_file_upload = dict(file_upload)
    hr_file_upload['UploadStatus'] = file_upload_status_to_string(hr_file_upload['UploadStatus'])
    hr = tableToMarkdown('CarbonBlack Protect File Upload Created successfully', hr_file_upload, FILE_UPLOAD_HEADERS)
    return_outputs(hr, {'CBP.FileUpload(val.ID === obj.ID)': file_upload}, raw_file_upload)


@logger
def update_file_upload(file_catalog_id, computer_id, priority, analysis_status, id):
    """
    Update file upload
    :param file_catalog_id: catalog id
    :param computer_id: computer id
    :param priority: priority of file upload
    :param analysis_status: analysis status
    :param id: id of file upload
    :return: Result json of the request
    """
    body_params = {
        'fileCatalogId': file_catalog_id,
        'computerId': computer_id,
        'priority': priority,
        'uploadStatus': analysis_status,
        'id': id
    }
    body_params = remove_keys_with_empty_value(body_params)

    return http_request('POST', '/fileUpload', data=body_params)


@logger
def file_upload_status_to_string(status):
    """
    Converts status as integer to string
    Based on https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#fileupload
    :param status: int that describes state [0-6]
    :return: string representation of the status (fallback: returns status)
    """
    file_status_dict = {
        0: 'Queued',
        1: 'Initiated',
        2: 'Uploading',
        3: 'Completed',
        4: 'Error',
        5: 'Cancelled',
        6: 'Deleted'
    }
    return file_status_dict.get(status, status)


def download_file_upload_command():
    """
    Downloads file upload
    :return: File result of file upload
    """
    id = demisto.args().get('id')
    file_upload = get_file_upload(id)
    raw_res = download_file_upload(id)
    demisto.results(fileResult(file_upload.get('fileName', 'cb_uploaded_file'), raw_res))


@logger
def download_file_upload(id):
    """
    Downloads file upload from server
    :param id: ID of the requested file upload
    :return: File upload binary file
    """
    url = f'/fileUpload/{id}'
    params = {
        'downloadFile': 'true'
    }
    return http_request('GET', url, params=params, parse_json=False)


def search_file_upload_command():
    """
    Searches for file upload
    :return: EntryObject of the file upload
    """
    args = demisto.args()
    raw_file_uploads = search_file_upload(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                          args.get('group'), args.get('computerId'), args.get('fileCatalogId'),
                                          args.get('fileName'), args.get('uploadStatus'))
    hr_file_uploads = []
    file_uploads = []
    if raw_file_uploads:
        for file_upload in raw_file_uploads:
            file_upload_output = {
                'Priority': file_upload.get('priority'),
                'FileName': file_upload.get('fileName'),
                'UploadPath': file_upload.get('uploadPath'),
                'ComputerId': file_upload.get('computerId'),
                'DateModified': file_upload.get('dateModified'),
                'ID': file_upload.get('id'),
                'FileCatalogId': file_upload.get('fileCatalogId'),
                'DateCreated': file_upload.get('dateCreated'),
                'CreatedBy': file_upload.get('createdBy'),
                'PathName': file_upload.get('pathName'),
                'UploadStatus': file_upload.get('uploadStatus'),
                'UploadedFileSize': file_upload.get('uploadedFileSize'),
            }
            file_uploads.append(file_upload_output)
            hr_file_upload = dict(file_upload_output)
            hr_file_upload['UploadStatus'] = file_upload_status_to_string(hr_file_upload['UploadStatus'])
            hr_file_uploads.append(hr_file_upload)
    headers = args.get('headers', FILE_UPLOAD_HEADERS)
    hr_title = "CarbonBlack Protect File Upload Search"
    hr = tableToMarkdown(hr_title, hr_file_uploads, headers, removeNull=True, headerTransform=pascalToSpace)
    file_uploads = {'CBP.FileUpload(val.ID === obj.ID)': file_uploads} if file_uploads else None
    return_outputs(hr, file_uploads, raw_file_uploads)


@logger
def search_file_upload(q=None, limit=None, offset=None, sort=None, group=None, computer_id=None, file_catalog_id=None,
                       file_name=None, upload_status=None):
    """
    Sends the request for file upload, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file uploads to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param computer_id: Id of computer entry associated with this analysis
    :param file_catalog_id: Id of fileCatalog entry associated with this upload
    :param file_name: Name of the file where file exists on the endpoint
    :param upload_status: Status of upload
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if computer_id:
        url_params['q'].append(f'computerId:{computer_id}')
    if file_catalog_id:
        url_params['q'].append(f'fileCatalogId:{file_catalog_id}')
    if file_name:
        url_params['q'].append(f'fileName:{file_name}')
    if upload_status:
        url_params['q'].append(f'uploadStatus:{file_upload_status_to_int(upload_status)}')

    return http_request('GET', '/fileUpload', params=url_params)


@logger
def file_upload_status_to_int(upload_status):
    """
    Returns the upload status in int
    :param upload_status: Upload status string
    """
    status_dict = {
        'Queued': 0,
        'Initiated': 1,
        'Uploading': 2,
        'Completed': 3,
        'Error': 4,
        'Cancelled': 5,
        'Deleted': 6
    }

    return status_dict.get(upload_status, upload_status)


def search_file_analysis_command():
    """
    Searches for file analysis
    :return: EntryObject of the file analysis
    """
    args = demisto.args()
    raw_file_analysis = search_file_analysis(args.get('query'), args.get('limit'), args.get('offset'), args.get('sort'),
                                             args.get('group'), args.get('fileCatalogId'), args.get('connectorId'),
                                             args.get('fileName'), args.get('analysisStatus'),
                                             args.get('analysisResult'))
    file_analysis = []
    if raw_file_analysis:
        for analysis in raw_file_analysis:
            file_analysis.append({
                'Priority': analysis.get('priority'),
                'FileName': analysis.get('fileName'),
                'PathName': analysis.get('pathName'),
                'ComputerId': analysis.get('computerId'),
                'DateModified': analysis.get('dateModified'),
                'ID': analysis.get('id'),
                'FileCatalogId': analysis.get('fileCatalogId'),
                'DateCreated': analysis.get('dateCreated'),
                'CreatedBy': analysis.get('createdBy')
            })
    headers = args.get('headers', FILE_ANALYSIS_HEADERS)
    hr_title = "CarbonBlack Protect File Analysis Search"
    hr = tableToMarkdown(hr_title, file_analysis, headers, removeNull=True, headerTransform=pascalToSpace)
    file_analysis = {'CBP.FileAnalysis(val.ID === obj.ID)': file_analysis} if file_analysis else None
    return_outputs(hr, file_analysis, raw_file_analysis)


@logger
def search_file_analysis(q=None, limit=None, offset=None, sort=None, group=None, file_catalog_id=None,
                         connector_id=None, file_name=None, status=None, result=None):
    """
    Sends the request for file analysis, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file analysis to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :param file_catalog_id: Id of fileCatalog entry associated with this analysis
    :param connector_id: Id of connector associated with this analysis
    :param file_name: Name of the file where file exists on the endpoint
    :param status: Status of analysis
    :param result: Result of the analysis
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group,
        "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
    }
    if file_catalog_id:
        url_params['q'].append(f'fileCatalogId:{file_catalog_id}')
    if connector_id:
        url_params['q'].append(f'connectorId:{connector_id}')
    if file_name:
        url_params['q'].append(f'fileName:{file_name}')
    if status:
        url_params['q'].append(f'analysisStatus:{file_analysis_status_to_int(status)}')
    if result:
        url_params['q'].append(f'analysisResult:{file_analysis_result_to_int(result)}')

    return http_request('GET', '/fileAnalysis', params=url_params)


@logger
def file_analysis_status_to_int(status):
    status_dict = {
        'scheduled': 0,
        'submitted (file is sent for analysis)': 1,
        'processed (file is processed but results are not available yet)': 2,
        'analyzed (file is processed and results are available)': 3,
        'error': 4,
        'cancelled': 5
    }
    return status_dict.get(status, status)


@logger
def file_analysis_result_to_int(result):
    result_dict = {
        'Not yet available': 0,
        'File is clean': 1,
        'File is a potential threat': 2,
        'File is malicious': 3
    }
    return result_dict.get(result, result)


def get_file_upload_command():
    """
    Gets the requested file upload
    :return: EntryObject of the file upload
    """
    args = demisto.args()
    id = args.get('id')
    raw_file_upload = get_file_upload(id)
    file_upload = {
        'Priority': raw_file_upload.get('priority'),
        'FileName': raw_file_upload.get('fileName'),
        'UploadPath': raw_file_upload.get('uploadPath'),
        'ComputerId': raw_file_upload.get('computerId'),
        'DateModified': raw_file_upload.get('dateModified'),
        'ID': raw_file_upload.get('id'),
        'FileCatalogId': raw_file_upload.get('fileCatalogId'),
        'DateCreated': raw_file_upload.get('dateCreated'),
        'CreatedBy': raw_file_upload.get('createdBy'),
        'PathName': raw_file_upload.get('pathName'),
        'UploadStatus': raw_file_upload.get('uploadStatus'),
        'UploadedFileSize': raw_file_upload.get('uploadedFileSize'),
    }
    headers = args.get('headers', FILE_UPLOAD_HEADERS)
    hr_file_upload = dict(file_upload)
    hr_file_upload['UploadStatus'] = file_upload_status_to_string(hr_file_upload['UploadStatus'])
    hr_title = f'CarbonBlack Protect File Upload Get for {id}'
    hr = tableToMarkdown(hr_title, hr_file_upload, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_file_upload = {'CBP.FileUpload(val.ID === obj.ID)': file_upload} if file_upload else None
    return_outputs(hr, entry_context_file_upload, raw_file_upload)


@logger
def get_file_upload(id):
    """
    Sends get file upload request
    :param id: File upload ID
    :return: Result json of the request
    """
    url = f'/fileUpload/{id}'
    return http_request('GET', url)


def get_connector_command():
    """
    Gets the requested connector
    :return: EntryObject of the connector
    """
    args = demisto.args()
    id = args.get('id')
    raw_connector = get_connector(id)
    connector = {
        'AnalysisEnabled': raw_connector.get('analysisEnabled'),
        'AnalysisName': raw_connector.get('analysisName'),
        'AnalysisTargets': raw_connector.get('analysisTargets'),
        'CanAnalyze': raw_connector.get('canAnalyze'),
        'ConnectorVersion': raw_connector.get('connectorVersion'),
        'Enabled': raw_connector.get('enabled'),
        'ID': raw_connector.get('id')
    }
    headers = args.get('headers', CONNECTOR_HEADERS)
    hr_title = f'CarbonBlack Protect Connector Get for {id}'
    hr = tableToMarkdown(hr_title, connector, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_connector = {'CBP.Connector(val.ID === obj.ID)': connector} if connector else None
    return_outputs(hr, entry_context_connector, raw_connector)


@logger
def get_connector(id):
    """
    Sends get connector request
    :param id: Connector ID
    :return: Result json of the request
    """
    url = f'/connector/{id}'
    return http_request('GET', url)


def search_connector_command():
    """
    Searches for connectors
    :return: EntryObject of the connectors
    """
    args = demisto.args()
    raw_connectors = search_connector(args.get('query'), args.get('limit'), args.get('offset'),
                                      args.get('sort'), args.get('group'))
    connectors = []
    if raw_connectors:
        for connector in raw_connectors:
            connectors.append({
                'AnalysisEnabled': connector.get('analysisEnabled'),
                'AnalysisName': connector.get('analysisName'),
                'AnalysisTargets': connector.get('analysisTargets'),
                'CanAnalyze': connector.get('canAnalyze'),
                'ConnectorVersion': connector.get('connectorVersion'),
                'Enabled': connector.get('enabled'),
                'ID': connector.get('id')
            })
    headers = args.get('headers', CONNECTOR_HEADERS)
    hr_title = "CarbonBlack Protect Connector Search"
    hr = tableToMarkdown(hr_title, connectors, headers, removeNull=True, headerTransform=pascalToSpace)
    connectors = {'CBP.Connector(val.ID === obj.ID)': connectors} if connectors else None
    return_outputs(hr, connectors, raw_connectors)


@logger
def search_connector(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file analysis, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file analysis to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    """
    url_params = {
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "group": group
    }
    if q:
        # handle multi condition queries in the following formats: a&b
        q = q.split('&')
        url_params['q'] = q

    return http_request('GET', '/connector', params=url_params)


def resolve_approval_request_command():
    """
    Updates an existing approval request
    :return: EntryObject of the approval request
    """
    args = demisto.args()
    raw_res = resolve_approval_request(
        args.get('id'),
        args.get('resolution'),
        args.get('requestorEmail'),
        args.get('resolutionComments'),
        args.get('status')
    )
    approval_request = {
        'ID': raw_res.get('id'),
        'Resolution': raw_res.get('resolution'),
        'Status': raw_res.get('status'),
        'ResolutionComments': raw_res.get('resolutionComments')
    }
    hr_approval_request = dict(approval_request)
    hr_approval_request['Status'] = approval_request_status_to_string(hr_approval_request['Status'])
    hr_approval_request['Resolution'] = approval_request_resolution_to_string(hr_approval_request['Resolution'])
    hr = tableToMarkdown('CarbonBlack Protect Approval Request Updated successfully', hr_approval_request)
    return_outputs(hr, {'CBP.ApprovalRequest(val.ID === obj.ID)': approval_request}, raw_res)


@logger
def resolve_approval_request(id, resolution, requestor_email=None, res_comments=None, status=None):
    """
    Update file analysis
    :param id: apporval request id
    :param resolution: apporval request resolution
    :param requestor_email: apporval request requestor email
    :param res_comments: apporval request resolution comments
    :param status: apporval request status
    :return: Result json of the request
    """
    body_params = {
        'id': id,
        'resolution': resolution,
        'requestorEmail': requestor_email,
        'resolutionComments': res_comments,
        'status': status
    }
    body_params = remove_keys_with_empty_value(body_params)
    return http_request('POST', '/approvalRequest', data=body_params)


def fetch_incidents():
    """
        Fetches incident using the events API
        :return: Fetched events in incident format
    """
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('first_event_time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, date_format=CB_TIME_FORMAT)
    last_fetch_timestamp = cbp_date_to_timestamp(last_fetch)
    query = f"timestamp>{last_fetch}"
    user_query = demisto.params().get('fetch_query')
    if user_query:
        # Add user's query to default query
        query = f'{query}&{user_query}'
    events = search_event(q=query, limit=INCIDENTS_PER_FETCH)
    incidents = []
    if events:
        for event in events:
            incident = event_to_incident(event)
            incident_date = incident['occurred']
            incident_date_timestamp = cbp_date_to_timestamp(incident_date)
            # Update last run and add incident if the incident is newer than last fetch
            if incident_date_timestamp > last_fetch_timestamp:
                last_fetch = incident_date
            incidents.append(incident)
        demisto.setLastRun({'first_event_time': last_fetch})
    return incidents


''' COMMANDS MANAGER / SWITCH PANEL '''


# main added for unit tests
def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')
    # should raise error in case of issue
    if command == 'fetch-incidents':
        demisto.incidents(fetch_incidents())
    else:
        try:
            if command == 'test-module':
                # This is the call made when pressing the integration test button.
                test_module()
                demisto.results('ok')
            elif command == 'cbp-fileCatalog-search':
                search_file_catalog_command()
            elif command == 'cbp-computer-search':
                search_computer_command()
            elif command == 'cbp-computer-update':
                update_computer_command()
            elif command == 'cbp-fileInstance-search':
                search_file_instance_command()
            elif command == 'cbp-event-search':
                search_event_command()
            elif command == 'cbp-approvalRequest-search':
                search_approval_request_command()
            elif command == 'cbp-fileRule-search':
                search_file_rule_command()
            elif command == 'cbp-fileRule-get':
                get_file_rule_command()
            elif command == 'cbp-fileRule-delete':
                delete_file_rule_command()
            elif command in ('cbp-fileRule-update', 'cbp-fileRule-createOrUpdate'):
                update_file_rule_command()
            elif command == 'cbp-policy-search':
                search_policy_command()
            elif command == 'cbp-serverConfig-search':
                search_server_config_command()
            elif command == 'cbp-publisher-search':
                search_publisher_command()
            elif command == 'cbp-fileAnalysis-search':
                search_file_analysis_command()
            elif command == 'cbp-fileAnalysis-get':
                get_file_analysis_command()
            elif command == 'cbp-fileAnalysis-createOrUpdate':
                update_file_analysis_command()
            elif command == 'cbp-fileUpload-createOrUpdate':
                update_file_upload_command()
            elif command == 'cbp-fileUpload-download':
                download_file_upload_command()
            elif command == 'cbp-fileUpload-search':
                search_file_upload_command()
            elif command == 'cbp-fileUpload-get':
                get_file_upload_command()
            elif command == 'cbp-computer-get':
                get_computer_command()
            elif command == 'cbp-connector-get':
                get_connector_command()
            elif command == 'cbp-connector-search':
                search_connector_command()
            elif command == 'cbp-approvalRequest-resolve':
                resolve_approval_request_command()
            else:
                return_error(f"Command {command} is not supported.")
        # Log exceptions
        except Exception as e:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
