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
INCIDENTS_PER_FETCH = int(demisto.params().get('max_incidents_per_fetch', 15))
# Headers to be sent in requests
HEADERS = {
    'X-Auth-Token': TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    os.environ.pop('HTTP_PROXY', None)
    os.environ.pop('HTTPS_PROXY', None)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


''' OUTPUT KEY DICTIONARY '''


APPROVAL_REQUEST_TRANS_DICT = {
    'id': 'ID',
    'resolution': 'Resolution',
    'status': 'Status',
    'resolutionComments': 'ResolutionComments',
    'fileCatalogId': 'FileCatalogID',
    'computerId': 'ComputerID',
    'computerName': 'ComputerName',
    'dateCreated': 'DateCreated',
    'createdBy': 'CreatedBy',
    'enforcementLevel': 'EnforcementLevel',
    'requestorEmail': 'RequestorEmail',
    'priority': 'Priority',
    'fileName': 'FileName',
    'pathName': 'PathName',
    'process': 'Process',
    'platform': 'Platform'
}

APPROVAL_REQUEST_RESOLVE_TRANS_DICT = {
    'id': 'ID',
    'resolution': 'Resolution',
    'status': 'Status',
    'resolutionComments': 'ResolutionComments'
}

COMPUTER_TRANS_DICT = {
    'memorySize': 'Memory',
    'processorCount': 'Processors',
    'processorModel': 'Processor',
    'osShortName': 'OS',
    'osName': 'OSVersion',
    'macAddress': 'MACAddress',
    'machineModel': 'Model',
    'ipAddress': 'IPAddress',
    'name': 'Hostname',
    'id': 'ID'
}

CONNECTOR_TRANS_DICT = {
    'analysisEnabled': 'AnalysisEnabled',
    'analysisName': 'AnalysisName',
    'analysisTargets': 'AnalysisTargets',
    'canAnalyze': 'CanAnalyze',
    'connectorVersion': 'ConnectorVersion',
    'enabled': 'Enabled',
    'id': 'ID'
}

EVENT_TRANS_DICT = {
    'pathName': 'FilePath',
    'param1': 'Param1',
    'param2': 'Param2',
    'param3': 'Param3',
    'subtypeName': 'SubTypeName',
    'computerName': 'ComputerName',
    'fileName': 'FileName',
    'ruleName': 'RuleName',
    'processFileCatalogId': 'ProcessFileCatalogID',
    'stringId': 'StringID',
    'ipAddress': 'IPAddress',
    'policyId': 'PolicyID',
    'timestamp': 'Timestamp',
    'userName': 'Username',
    'computerId': 'ComputerID',
    'processFileName': 'ProcessFileName',
    'indicatorName': 'IndicatorName',
    'subtype': 'SubType',
    'type': 'Type',
    'id': 'ID',
    'description': 'Description',
    'severity': 'Severity',
    'commandLine': 'CommandLine',
    'processPathName': 'ProcessPathName'
}

FILE_ANALYSIS_TRANS_DICT = {
    'priority': 'Priority',
    'fileName': 'FileName',
    'pathName': 'PathName',
    'computerId': 'ComputerId',
    'dateModified': 'DateModified',
    'id': 'ID',
    'fileCatalogId': 'FileCatalogId',
    'dateCreated': 'DateCreated',
    'createdBy': 'CreatedBy'
}

FILE_ANALYSIS_FILE_OUTPUT_TRANS_DICT = {
    'fileCatalogId': 'FileCatalogId',
    'fileName': 'Name',
    'Malicious': 'Malicious',  # This key will be added manually if file is malicious
    'pathName': 'PathName',
}

FILE_CATALOG_TRANS_DICT = {
    'fileSize': 'Size',
    'pathName': 'Path',
    'sha1': 'SHA1',
    'sha256': 'SHA256',
    'md5': 'MD5',
    'fileName': 'Name',
    'fileType': 'Type',
    'productName': 'ProductName',
    'id': 'ID',
    'publisher': 'Publisher',
    'company': 'Company',
    'fileExtension': 'Extension'
}

FILE_INSTANCE_TRANS_DICT = {
    'fileCatalogId': 'CatalogID',
    'computerId': 'ComputerID',
    'id': 'ID',
    'fileName': 'Name',
    'pathName': 'Path'
}

FILE_UPLOAD_TRANS_DICT = {
    'priority': 'Priority',
    'fileName': 'FileName',
    'uploadPath': 'UploadPath',
    'computerId': 'ComputerId',
    'dateModified': 'DateModified',
    'id': 'ID',
    'fileCatalogId': 'FileCatalogId',
    'dateCreated': 'DateCreated',
    'createdBy': 'CreatedBy',
    'pathName': 'PathName',
    'uploadStatus': 'UploadStatus',
    'uploadedFileSize': 'UploadedFileSize',
}

FILE_RULE_TRANS_DICT = {
    'id': 'ID',
    'fileCatalogId': 'CatalogID',
    'description': 'Description',
    'fileState': 'FileState',
    'hash': 'Hash',
    'name': 'Name',
    'policyIds': 'PolicyIDs',
    'reportOnly': 'ReportOnly'
}

POLICY_TRANS_DICT = {
    'readOnly': 'ReadOnly',
    'enforcementLevel': 'EnforcementLevel',
    'reputationEnabled': 'ReputationEnabled',
    'atEnforcementComputers': 'AtEnforcementComputers',
    'automatic': 'Automatic',
    'name': 'Name',
    'fileTrackingEnabled': 'FileTrackingEnabled',
    'connectedComputers': 'ConnectedComputers',
    'packageName': 'PackageName',
    'allowAgentUpgrades': 'AllowAgentUpgrades',
    'totalComputers': 'TotalComputers',
    'loadAgentInSafeMode': 'LoadAgentInSafeMode',
    'automaticApprovalsOnTransition': 'AutomaticApprovalsOnTransition',
    'id': 'ID',
    'description': 'Description',
    'disconnectedEnforcementLevel': 'DisconnectedEnforcementLevel'
}

PUBLISHER_TRANS_DICT = {
    'description': 'Description',
    'id': 'ID',
    'name': 'Name',
    'publisherReputation': 'Reputation',
    'signedCertificateCount': 'SignedCertificatesCount',
    'signedFilesCount': 'SignedFilesCount',
    'publisherState': 'State'
}

SERVER_CONFIG_DICT = {
    'id': 'ID',
    'value': 'Value',
    'name': 'Name'
}

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
        'name': 'CBP Event ID: ' + str(event.get('id')),
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
    raw_catalogs = search_file_catalog(args.get('query'), args.get('limit'), args.get('offset'),
                                       args.get('sort'), args.get('group'))
    headers = args.get('headers')
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
    demisto.results(return_outputs(hr, catalogs, raw_catalogs))


@logger
def search_file_catalog(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file catalog, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the catalogs to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :return: File catalog response json
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

    return http_request('GET', '/fileCatalog', params=url_params)


def search_computer_command():
    """
    Searches for file catalog
    :return: EntryObject of the computer
    """
    args = demisto.args()
    raw_computers = search_computer(args.get('query'), args.get('limit'), args.get('offset'),
                                    args.get('sort'), args.get('group'))
    headers = args.get('headers')
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
    demisto.results(return_outputs(hr, computers, raw_computers))


@logger
def search_computer(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file catalog, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the computers to be fetched
    :param sort: Sort argument for request
    :param group: Group argument for request
    :return: Computer response json
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
    hr = tableToMarkdown('CarbonBlack Protect computer updated successfully', computers)
    demisto.results(return_outputs(hr, {'Endpoint(val.ID === obj.ID)': computers}, raw_computers))


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
    headers = args.get('headers')
    hr_title = f'CarbonBlack Protect Computer Get for {id}'
    hr = tableToMarkdown(hr_title, computer, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_computer = {'Endpoint(val.ID === obj.ID)': computer} if computer else None
    demisto.results(return_outputs(hr, entry_context_computer, raw_computer))


@logger
def get_computer(id):
    """
    Sends get computer request
    :param id: Computer ID
    :return: Result json of the request
    """
    url = '/Computer/{}'.format(id)
    return http_request('GET', url)


def search_file_instance_command():
    """
    Searches for file instance
    :return: EntryObject of the file instance
    """
    args = demisto.args()
    raw_files = search_file_instance(args.get('query'), args.get('limit'), args.get('offset'),
                                     args.get('sort'), args.get('group'))
    headers = args.get('headers')
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
    demisto.results(return_outputs(hr, files, raw_files))


@logger
def search_file_instance(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file instance, and returns the result json
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

    return http_request('GET', '/fileInstance', params=url_params)


def search_event_command():
    """
    Searches for file instance
    :return: EntryObject of the file instance
    """
    args = demisto.args()
    raw_events = search_event(args.get('query'), args.get('limit'), args.get('offset'),
                              args.get('sort'), args.get('group'))
    events = []
    if raw_events:
        for event in raw_events:
            events.append({
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
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect Event Search"
    hr = tableToMarkdown(hr_title, events, headers, removeNull=True, headerTransform=pascalToSpace)
    events = {'CBP.Event(val.ID === obj.ID)': events} if events else None
    demisto.results(return_outputs(hr, events, raw_events))


@logger
def search_event(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file instance, and returns the result json
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

    return http_request('GET', '/event', params=url_params)


def search_approval_request_command():
    """
    Searches for approval requests
    :return: EntryObject of the approval requests
    """
    args = demisto.args()
    raw_approval_requests = search_approval(args.get('query'), args.get('limit'), args.get('offset'),
                                            args.get('sort'), args.get('group'))
    approval_requests = []
    if raw_approval_requests:
        for approval_request in raw_approval_requests:
            approval_requests.append({
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
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect Approval Request Search"
    hr = tableToMarkdown(hr_title, approval_requests, headers, removeNull=True, headerTransform=pascalToSpace)
    approval_requests = {'CBP.ApprovalRequest(val.ID === obj.ID)': approval_requests} if approval_requests else None
    demisto.results(return_outputs(hr, approval_requests, raw_approval_requests))


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


def search_file_rule_command():
    """
    Searches for file rules
    :return: EntryObject of the file rules
    """
    args = demisto.args()
    raw_file_rules = search_file_rule(args.get('query'), args.get('limit'), args.get('offset'),
                                      args.get('sort'), args.get('group'))
    file_rules = []
    if raw_file_rules:
        for file_rule in raw_file_rules:
            file_rules.append({
                'ID': file_rule.get('id'),
                'CatalogID': file_rule.get('fileCatalogId'),
                'Description': file_rule.get('description'),
                'FileState': file_rule.get('fileState'),
                'Hash': file_rule.get('hash'),
                'Name': file_rule.get('name'),
                'PolicyIDs': file_rule.get('policyIds'),
                'ReportOnly': file_rule.get('reportOnly')
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect File Rule Search"
    hr = tableToMarkdown(hr_title, file_rules, headers, removeNull=True, headerTransform=pascalToSpace)
    file_rules = {'CBP.FileRule(val.ID === obj.ID)': file_rules} if file_rules else None
    demisto.results(return_outputs(hr, file_rules, raw_file_rules))


@logger
def search_file_rule(q=None, limit=None, offset=None, sort=None, group=None):
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

    return http_request('GET', '/fileRule', params=url_params)


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
    headers = args.get('headers')
    hr_title = f'CarbonBlack Protect File Rule Get for {id}'
    hr = tableToMarkdown(hr_title, file_rule, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_file_rule = {'CBP.FileRule(val.ID === obj.ID)': file_rule} if file_rule else None
    demisto.results(return_outputs(hr, entry_context_file_rule, raw_file_rule))


@logger
def get_file_rule(id):
    """
    Sends get file rule request
    :param id: File rule ID
    :return: Result json of the request
    """
    url = '/fileRule/{}'.format(id)
    return http_request('GET', url)


def delete_file_rule_command():
    """
    Deletes the requested file rule
    :return: EntryObject of the file catalog
    """
    args = demisto.args()
    id = args.get('id')
    delete_file_rule(id)
    hr = "File Result {} deleted successfully".format(id)
    demisto.results(hr)


@logger
def delete_file_rule(id):
    """
    Sends delete file rule request
    :param id: File rule ID
    :return: Result of the request
    """
    url = BASE_URL + '/fileRule/{}'.format(id)
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
    hr = tableToMarkdown('CarbonBlack Protect File Rule Updated successfully', file_rule,
                         removeNull=True, headerTransform=pascalToSpace)
    demisto.results(return_outputs(hr, {'CBP.FileRule(val.ID === obj.ID)': file_rule}, raw_file_rule))


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
                               args.get('sort'), args.get('group'))
    policies = []
    if raw_policy:
        for policy in raw_policy:
            policies.append({
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
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect Policy Search"
    hr = tableToMarkdown(hr_title, policies, headers, removeNull=True, headerTransform=pascalToSpace)
    policies = {'CBP.Policy(val.ID === obj.ID)': policies} if policies else None
    demisto.results(return_outputs(hr, policies, raw_policy))


@logger
def search_policy(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for search policy, and returns the result json
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

    return http_request('GET', '/policy', params=url_params)


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
    demisto.results(return_outputs(hr, server_configs, raw_server_configs))


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


def search_publisher_command():
    """
    Searches for publisher
    :return: EntryObject of the publishers
    """
    args = demisto.args()
    raw_publishers = search_publisher(args.get('query'), args.get('limit'), args.get('offset'),
                                      args.get('sort'), args.get('group'))
    publishers = []
    if raw_publishers:
        for publisher in raw_publishers:
            publishers.append({
                'Description': publisher.get('description'),
                'ID': publisher.get('id'),
                'Name': publisher.get('name'),
                'Reputation': publisher.get('publisherReputation'),
                'SignedCertificatesCount': publisher.get('signedCertificateCount'),
                'SignedFilesCount': publisher.get('signedFilesCount'),
                'State': publisher.get('publisherState')
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect Publisher Search"
    hr = tableToMarkdown(hr_title, publishers, headers, removeNull=True, headerTransform=pascalToSpace)
    publishers = {'CBP.Publisher(val.ID === obj.ID)': publishers} if publishers else None
    demisto.results(return_outputs(hr, publishers, raw_publishers))


@logger
def search_publisher(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for publisher, and returns the result json
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

    return http_request('GET', '/publisher', params=url_params)


def get_file_analysis_command():
    """
    Gets the requested file analysis
    :return: EntryObject of the file analysis
    """
    args = demisto.args()
    id = args.get('id')
    raw_res = get_file_analysis(id)
    cbp_ec_key = 'CBP.FileAnalysis(val.ID === obj.ID)'
    ec = {
        cbp_ec_key: {
            'Priority': raw_res.get('priority'),
            'FileName': raw_res.get('fileName'),
            'PathName': raw_res.get('pathName'),
            'ComputerId': raw_res.get('computerId'),
            'DateModified': raw_res.get('dateModified'),
            'ID': raw_res.get('id'),
            'FileCatalogId': raw_res.get('fileCatalogId'),
            'DateCreated': raw_res.get('dateCreated'),
            'CreatedBy': raw_res.get('createdBy')
        },
        # File doesn't have dt since the api doesn't return hashes
        'File': {
            'FileCatalogId': raw_res.get('fileCatalogId'),
            'Name': raw_res.get('fileName'),
            'PathName': raw_res.get('pathName'),
        }
    }
    # analysisResult == 3 -> Malicious
    if int(raw_res.get('analysisResult', 0)) == 3:
        ec['File'].update({
            'Malicious': {
                'Vendor': 'Carbon Black Protection',
                'Description': 'Carbon Black Protection found this file to be malicious.'
            }
        })
    hr = tableToMarkdown(
        'CarbonBlack Protect Get File Analysis for {}'.format(id),
        ec[cbp_ec_key],
        removeNull=True,
        headerTransform=pascalToSpace
    )
    demisto.results(return_outputs(hr, ec, raw_res))


@logger
def get_file_analysis(id):
    """
    Sends get file analysis
    :param id: File analysis ID
    :return: Result json of the request
    """
    url = '/fileAnalysis/{}'.format(id)
    return http_request('GET', url)


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
    hr = tableToMarkdown('CarbonBlack Protect File Analysis Created successfully', file_analysis)
    demisto.results(return_outputs(hr, {'CBP.FileAnalysis(val.ID === obj.ID)': file_analysis}, raw_file_analysis))


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
    hr = tableToMarkdown('CarbonBlack Protect File Upload Created successfully', file_upload)
    demisto.results(return_outputs(hr, {'CBP.FileUpload(val.ID === obj.ID)': file_upload}, raw_file_upload))


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
    url = '/fileUpload/{}'.format(id)
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
    raw_file_uploads = search_file_upload(args.get('query'), args.get('limit'), args.get('offset'),
                                          args.get('sort'), args.get('group'))
    file_uploads = []
    if raw_file_uploads:
        for file_upload in raw_file_uploads:
            file_uploads.append({
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
            })
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect File Upload Search"
    hr = tableToMarkdown(hr_title, file_uploads, headers, removeNull=True, headerTransform=pascalToSpace)
    file_uploads = {'CBP.FileUpload(val.ID === obj.ID)': file_uploads} if file_uploads else None
    demisto.results(return_outputs(hr, file_uploads, raw_file_uploads))


@logger
def search_file_upload(q=None, limit=None, offset=None, sort=None, group=None):
    """
    Sends the request for file upload, and returns the result json
    :param q: Query to be executed
    :param limit: Limit on the amount of results to be fetched
    :param offset: Offset of the file uploads to be fetched
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

    return http_request('GET', '/fileUpload', params=url_params)


def search_file_analysis_command():
    """
    Searches for file analysis
    :return: EntryObject of the file analysis
    """
    args = demisto.args()
    raw_file_analysis = search_file_analysis(args.get('query'), args.get('limit'), args.get('offset'),
                                             args.get('sort'), args.get('group'))
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
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect File Analysis Search"
    hr = tableToMarkdown(hr_title, file_analysis, headers, removeNull=True, headerTransform=pascalToSpace)
    file_analysis = {'CBP.FileAnalysis(val.ID === obj.ID)': file_analysis} if file_analysis else None
    demisto.results(return_outputs(hr, file_analysis, raw_file_analysis))


@logger
def search_file_analysis(q=None, limit=None, offset=None, sort=None, group=None):
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

    return http_request('GET', '/fileAnalysis', params=url_params)


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
    headers = args.get('headers')
    hr_title = f'CarbonBlack Protect File Upload Get for {id}'
    hr = tableToMarkdown(hr_title, file_upload, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_file_upload = {'CBP.FileUpload(val.ID === obj.ID)': file_upload} if file_upload else None
    demisto.results(return_outputs(hr, entry_context_file_upload, raw_file_upload))


@logger
def get_file_upload(id):
    """
    Sends get file upload request
    :param id: File upload ID
    :return: Result json of the request
    """
    url = '/fileUpload/{}'.format(id)
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
    headers = args.get('headers')
    hr_title = f'CarbonBlack Protect Connector Get for {id}'
    hr = tableToMarkdown(hr_title, connector, headers, removeNull=True, headerTransform=pascalToSpace)
    entry_context_connector = {'CBP.Connector(val.ID === obj.ID)': connector} if connector else None
    demisto.results(return_outputs(hr, entry_context_connector, raw_connector))


@logger
def get_connector(id):
    """
    Sends get connector request
    :param id: Connector ID
    :return: Result json of the request
    """
    url = '/connector/{}'.format(id)
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
    headers = args.get('headers')
    hr_title = "CarbonBlack Protect Connector Search"
    hr = tableToMarkdown(hr_title, connectors, headers, removeNull=True, headerTransform=pascalToSpace)
    connectors = {'CBP.Connector(val.ID === obj.ID)': connectors} if connectors else None
    demisto.results(return_outputs(hr, connectors, raw_connectors))


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
    raw_res = resolve_approval_request(args)
    ec = {
        'id': 'ID',
        'resolution': 'Resolution',
        'status': 'Status',
        'resolutionComments': 'ResolutionComments'
    }
    hr = tableToMarkdown('CarbonBlack Protect Approval Request Updated successfully', ec)
    demisto.results(return_outputs(hr, {'CBP.ApprovalRequest(val.ID === obj.ID)': ec}, raw_res))


@logger
def resolve_approval_request(body_params):
    """
    Update file analysis
    :param body_params: URL parameters for the request
    :return: Result json of the request
    """
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
    query = "timestamp>{time}".format(time=last_fetch)
    user_query = demisto.params().get('fetch_query')
    if user_query:
        # Add user's query to default query
        query = '{timestamp_query}&{user_query}'.format(timestamp_query=query, user_query=user_query)
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


def main():
    LOG('Command being called is {}'.format(demisto.command()))

    # should raise error in case of issue
    if demisto.command() == 'fetch-incidents':
        demisto.incidents(fetch_incidents())

    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif demisto.command() == 'cbp-fileCatalog-search':
            search_file_catalog_command()
        elif demisto.command() == 'cbp-computer-search':
            search_computer_command()
        elif demisto.command() == 'cbp-computer-update':
            update_computer_command()
        elif demisto.command() == 'cbp-fileInstance-search':
            search_file_instance_command()
        elif demisto.command() == 'cbp-event-search':
            search_event_command()
        elif demisto.command() == 'cbp-approvalRequest-search':
            search_approval_request_command()
        elif demisto.command() == 'cbp-fileRule-search':
            search_file_rule_command()
        elif demisto.command() == 'cbp-fileRule-get':
            get_file_rule_command()
        elif demisto.command() == 'cbp-fileRule-delete':
            delete_file_rule_command()
        elif demisto.command() == 'cbp-fileRule-update':
            update_file_rule_command()
        elif demisto.command() == 'cbp-policy-search':
            search_policy_command()
        elif demisto.command() == 'cbp-serverConfig-search':
            search_server_config_command()
        elif demisto.command() == 'cbp-publisher-search':
            search_publisher_command()
        elif demisto.command() == 'cbp-fileAnalysis-search':
            search_file_analysis_command()
        elif demisto.command() == 'cbp-fileAnalysis-get':
            get_file_analysis_command()
        elif demisto.command() == 'cbp-fileAnalysis-createOrUpdate':
            update_file_analysis_command()
        elif demisto.command() == 'cbp-fileUpload-createOrUpdate':
            update_file_upload_command()
        elif demisto.command() == 'cbp-fileUpload-download':
            download_file_upload_command()
        elif demisto.command() == 'cbp-fileUpload-search':
            search_file_upload_command()
        elif demisto.command() == 'cbp-fileUpload-get':
            get_file_upload_command()
        elif demisto.command() == 'cbp-computer-get':
            get_computer_command()
        elif demisto.command() == 'cbp-connector-get':
            get_connector_command()
        elif demisto.command() == 'cbp-connector-search':
            search_connector_command()
        elif demisto.command() == 'cbp-approvalRequest-resolve':
            resolve_approval_request_command()
        else:
            return_error("Command {} is not supported.".format(demisto.command()))
    # Log exceptions
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
