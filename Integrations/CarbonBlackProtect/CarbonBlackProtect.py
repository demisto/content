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
BASE_URL = SERVER + '/api/bit9platform/v1'
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
CB_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
CB_NO_MS_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
INCIDENTS_PER_FETCH = int(demisto.params().get('max_incidents_per_fetch', 15))
# Service base URL
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

        :type data: ``str``
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
            data=data,
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


def create_entry_object(contents='', ec=None, hr=''):
    """
        Creates an entry object

        :type contents: ``dict``
        :param contents: Raw response to output

        :type ec: ``dict``
        :param ec: Entry context of the entry object

        :type hr: ``str``
        :param hr: Human readable

        :return: Entry object
        :rtype: ``dict``
    """
    res = {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }
    return res


def get_trasnformed_dict(old_dict, transformation_dict):
    """
        Returns a dictionary with the same values as old_dict, with the correlating key:value in transformation_dict

        :type old_dict: ``dict``
        :param old_dict: Old dictionary to pull values from

        :type transformation_dict: ``dict``
        :param transformation_dict: Transformation dictionary that contains oldkeys:newkeys

        :return Transformed dictionart (according to transformation_dict values)
        :rtype ``dict``
    """
    new_dict = {}
    for k in list(old_dict.keys()):
        if k in transformation_dict:
            new_dict[transformation_dict[k]] = old_dict[k]
    return new_dict


def generic_search_command(search_function, trans_dict, hr_title, ec_key):
    """
    Searches for an item from search_function.

    :param search_function: Function to call search endpoint
    :param trans_dict: Transformation dict for result
    :param hr_title: Title of human readable
    :param ec_key: Entry Context key
    :return: EntryObject of the item
    """
    args = demisto.args()
    url_params = {
        "limit": args.get('limit'),
        "offset": args.get('offset'),
        "sort": args.get('sort'),
        "group": args.get('group')
    }
    q = args.get('query')
    if isinstance(q, str):
        # handle multi condition queries in the following formats: 1) a&b, 2) a&q=b
        q = list(map(lambda x: remove_prefix('=q', x), q.split('&')))
        url_params['q'] = q
    headers = args.get('headers')
    raw_res = search_function(url_params)
    ec = []
    for entry in raw_res:
        ec.append(get_trasnformed_dict(entry, trans_dict))
    hr = tableToMarkdown(hr_title, ec, headers, removeNull=True, headerTransform=pascalToSpace)
    ec = {ec_key: ec} if ec else None
    demisto.results(create_entry_object(raw_res, ec, hr))


def generic_get_command(get_function, trans_dict, hr_title, ec_key):
    """
    Gets an item from get_function as an entry object.

    :param get_function: Function to call get endpoint
    :param trans_dict: Transformation dict for result
    :param hr_title: Title of human readable
    :param ec_key: Entry Context key
    :return: EntryObject of the item
    """
    args = demisto.args()
    id = args.get('id')
    headers = args.get('headers')
    raw_res = get_function(id)
    ec = get_trasnformed_dict(raw_res, trans_dict)
    hr = tableToMarkdown(hr_title, ec, headers, removeNull=True, headerTransform=pascalToSpace)
    ec = {ec_key: ec} if ec else None
    demisto.results(create_entry_object(raw_res, ec, hr))


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
    generic_search_command(
        search_function=search_file_catalog,
        trans_dict=FILE_CATALOG_TRANS_DICT,
        hr_title='CarbonBlack Protect File Catalog Search',
        ec_key='File(val.SHA1 === obj.SHA1)'
    )


def search_file_catalog(url_params):
    """
    Sends the request for file catalog, and returns the result json
    :param url_params: url parameters for the request
    :return: File catalog response json
    """
    return http_request('GET', '/fileCatalog', params=url_params)


def search_computer_command():
    """
    Searches for file catalog
    :return: EntryObject of the computer
    """
    generic_search_command(
        search_function=search_computer,
        trans_dict=COMPUTER_TRANS_DICT,
        hr_title='CarbonBlack Protect Computer Search',
        ec_key='Endpoint(val.ID === obj.ID)'
    )


def search_computer(url_params):
    """
    Sends the request for computer, and returns the result json
    :param url_params: url parameters for the request
    :return: Computer response json
    """
    return http_request('GET', '/Computer', params=url_params)


def update_computer_command():
    """
    Updates computer
    :return: EntryObject of the computer
    """
    args = demisto.args()
    raw_res = update_computer(args)
    ec = get_trasnformed_dict(raw_res, COMPUTER_TRANS_DICT)
    hr = tableToMarkdown('CarbonBlack Protect computer updated successfully', ec)
    demisto.results(create_entry_object(raw_res, {'Endpoint(val.ID === obj.ID)': ec}, hr))


def update_computer(body_params):
    """
    Update computer
    :param body_params: URL parameters for the request
    :return: Result json of the request
    """
    return http_request('POST', '/computer', data=json.dumps(body_params))


def get_computer_command():
    """
    Gets the requested computer
    :return: EntryObject of the file catalog
    """
    generic_get_command(
        get_function=get_computer,
        trans_dict=COMPUTER_TRANS_DICT,
        hr_title='CarbonBlack Protect Computer Get for {}'.format(demisto.args().get('id')),
        ec_key='Endpoint(val.ID === obj.ID)'
    )


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
    generic_search_command(
        search_function=search_file_instance,
        trans_dict=FILE_INSTANCE_TRANS_DICT,
        hr_title='CarbonBlack Protect File Instance Search',
        ec_key='CBP.FileInstance(val.ID === obj.ID)'
    )


def search_file_instance(url_params):
    """
    Sends the request for file instance, and returns the result json
    :param url_params: url parameters for the request
    :return: File instance response json
    """
    return http_request('GET', '/fileInstance', params=url_params)


def search_event_command():
    """
    Searches for file instance
    :return: EntryObject of the file instance
    """
    generic_search_command(
        search_function=search_event,
        trans_dict=EVENT_TRANS_DICT,
        hr_title='CarbonBlack Protect Event Search',
        ec_key='CBP.Event(val.ID === obj.ID)'
    )


def search_event(url_params):
    """
    Sends the request for file instance, and returns the result json
    :param url_params: url parameters for the request
    :return: File instance response json
    """
    return http_request('GET', '/event', params=url_params)


def search_approval_request_command():
    """
    Searches for approval requests
    :return: EntryObject of the approval requests
    """
    generic_search_command(
        search_function=search_approval_request,
        trans_dict=APPROVAL_REQUEST_TRANS_DICT,
        hr_title='CarbonBlack Protect Approval Request Search',
        ec_key='CBP.ApprovalRequest(val.ID === obj.ID)'
    )


def search_approval_request(url_params):
    """
    Sends the request for approval request, and returns the result json
    :param url_params: url parameters for the request
    :return: Approval request response json
    """
    return http_request('GET', '/approvalRequest', params=url_params)


def search_file_rule_command():
    """
    Searches for file rules
    :return: EntryObject of the file rules
    """
    generic_search_command(
        search_function=search_file_rule,
        trans_dict=FILE_RULE_TRANS_DICT,
        hr_title='CarbonBlack Protect File Rule Search',
        ec_key='CBP.FileRule(val.ID === obj.ID)'
    )


def search_file_rule(url_params):
    """
    Sends the request for file rule, and returns the result json
    :param url_params: url parameters for the request
    :return: File rule response json
    """
    return http_request('GET', '/fileRule', params=url_params)


def get_file_rule_command():
    """
    Gets the requested file rule
    :return: EntryObject of the file catalog
    """
    generic_get_command(
        get_function=get_file_rule,
        trans_dict=FILE_RULE_TRANS_DICT,
        hr_title='CarbonBlack Protect File Rule Get for {}'.format(demisto.args().get('id')),
        ec_key='CBP.FileRule(val.ID === obj.ID)'
    )


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


def delete_file_rule(id):
    """
    Sends delete file rule request
    :param id: File rule ID
    :return: Result of the request
    """
    url = SERVER + '/fileRule/{}'.format(id)
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
    body_params = {
        'hash': args.get('hash'),
        'fileState': args.get('fileState'),
        'id': args.get('id'),
        'fileCatalogId': args.get('fileCatalogId'),
        'name': args.get('name'),
        'description': args.get('description'),
        'reportOnly': args.get('reportOnly'),
        'reputationApprovalsEnabled': args.get('reputationApprovalsEnabled'),
        'forceInstaller': args.get('forceInstaller'),
        'forceNotInstaller': args.get('forceNotInstaller'),
        'policyIds': args.get('policyIds'),
        'platformFlags': args.get('platformFlags'),
    }
    raw_res = update_file_rule(body_params)
    ec = get_trasnformed_dict(raw_res, FILE_RULE_TRANS_DICT)
    hr = tableToMarkdown('CarbonBlack Protect File Rule Updated successfully', ec)
    demisto.results(create_entry_object(raw_res, {'CBP.FileRule(val.ID === obj.ID)': ec}, hr))


def update_file_rule(body_params):
    """
    Update file rule
    :param body_params: URL parameters for the request
    :return: Result json of the request
    """
    return http_request('POST', '/fileRule', data=json.dumps(body_params))


def search_policy_command():
    """
    Searches for policy
    :return: EntryObject of the policies
    """
    generic_search_command(
        search_function=search_policy,
        trans_dict=POLICY_TRANS_DICT,
        hr_title='CarbonBlack Protect Policy Search',
        ec_key='CBP.Policy(val.ID === obj.ID)'
    )


def search_policy(url_params):
    """
    Sends the request for file rule, and returns the result json
    :param url_params: url parameters for the request
    :return: File rule response json
    """
    return http_request('GET', '/policy', params=url_params)


def search_server_config_command():
    """
    Searches for server config
    :return: EntryObject of the server configurations
    """
    generic_search_command(
        search_function=search_server_config,
        trans_dict=SERVER_CONFIG_DICT,
        hr_title='CarbonBlack Protect Server Config Search',
        ec_key='CBP.ServerConfig(val.ID === obj.ID)'
    )


def search_server_config(url_params):
    """
    Sends the request for server confing, and returns the result json
    :param url_params: url parameters for the request
    :return: Server config response json
    """
    return http_request('GET', '/serverConfig', params=url_params)


def search_publisher_command():
    """
    Searches for publisher
    :return: EntryObject of the publishers
    """
    generic_search_command(
        search_function=search_publisher,
        trans_dict=PUBLISHER_TRANS_DICT,
        hr_title='CarbonBlack Protect Publisher Search',
        ec_key='CBP.Publisher(val.ID === obj.ID)'
    )


def search_publisher(url_params):
    """
    Sends the request for publisher, and returns the result json
    :param url_params: url parameters for the request
    :return: Publisher response json
    """
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
        cbp_ec_key: get_trasnformed_dict(raw_res, FILE_ANALYSIS_TRANS_DICT),
        # File doesn't have dt since the api doesn't return hashes
        'File': get_trasnformed_dict(raw_res, FILE_ANALYSIS_FILE_OUTPUT_TRANS_DICT)
    }
    hr = tableToMarkdown(
        'CarbonBlack Protect Get File Analysis for {}'.format(id),
        ec[cbp_ec_key],
        removeNull=True,
        headerTransform=pascalToSpace
    )
    demisto.results(create_entry_object(raw_res, ec, hr))


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
    raw_res = update_file_analysis(args)
    ec = get_trasnformed_dict(raw_res, FILE_ANALYSIS_TRANS_DICT)
    hr = tableToMarkdown('CarbonBlack Protect File Analysis Created successfully', ec)
    demisto.results(create_entry_object(raw_res, {'CBP.FileAnalysis(val.ID === obj.ID)': ec}, hr))


def update_file_analysis(body_params):
    """
    Update file analysis
    :param body_params: URL parameters for the request
    :return: Result json of the request
    """
    return http_request('POST', '/fileAnalysis', data=json.dumps(body_params))


def update_file_upload_command():
    """
    Creates or update a file upload
    :return: Entry object of the created file upload
    """
    args = demisto.args()
    raw_res = update_file_upload(args)
    ec = get_trasnformed_dict(raw_res, FILE_UPLOAD_TRANS_DICT)
    hr = tableToMarkdown('CarbonBlack Protect File Upload Created successfully', ec)
    demisto.results(create_entry_object(raw_res, {'CBP.FileUpload(val.ID === obj.ID)': ec}, hr))


def update_file_upload(body_params):
    """
    Update file upload
    :param body_params: URL parameters for the request
    :return: Result json of the request
    """
    return http_request('POST', '/fileUpload', data=json.dumps(body_params))


def download_file_upload_command():
    """
    Downloads file upload
    :return: File result of file upload
    """
    id = demisto.args().get('id')
    file_upload = get_file_upload(id)
    raw_res = download_file_upload(id)
    demisto.results(fileResult(file_upload.get('fileName', 'cb_uploaded_file'), raw_res))


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
    generic_search_command(
        search_function=search_file_upload,
        trans_dict=FILE_UPLOAD_TRANS_DICT,
        hr_title='CarbonBlack Protect File Upload Search',
        ec_key='CBP.FileUpload(val.ID === obj.ID)'
    )


def search_file_upload(url_params):
    """
    Sends the request for file upload, and returns the result json
    :param url_params: url parameters for the request
    :return: File upload response json
    """
    return http_request('GET', '/fileUpload', params=url_params)


def search_file_analysis_command():
    """
    Searches for file analysis
    :return: EntryObject of the file analysis
    """
    generic_search_command(
        search_function=search_file_analysis,
        trans_dict=FILE_ANALYSIS_TRANS_DICT,
        hr_title='CarbonBlack Protect File Analysis Search',
        ec_key='CBP.FileAnalysis(val.ID === obj.ID)'
    )


def search_file_analysis(url_params):
    """
    Sends the request for file analysis, and returns the result json
    :param url_params: url parameters for the request
    :return: File analysis response json
    """
    return http_request('GET', '/fileAnalysis', params=url_params)


def get_file_upload_command():
    """
    Gets the requested file upload
    :return: EntryObject of the file upload
    """
    generic_get_command(
        get_function=get_file_upload,
        trans_dict=FILE_UPLOAD_TRANS_DICT,
        hr_title='CarbonBlack Protect File Upload Get for {}'.format(demisto.args().get('id')),
        ec_key='CBP.FileUpload(val.ID === obj.ID)'
    )


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
    Gets the requested file upload
    :return: EntryObject of the file upload
    """
    generic_get_command(
        get_function=get_connector,
        trans_dict=CONNECTOR_TRANS_DICT,
        hr_title='CarbonBlack Protect Connector Get for {}'.format(demisto.args().get('id')),
        ec_key='CBP.Connector(val.ID === obj.ID)'
    )


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
    Searches for file analysis
    :return: EntryObject of the file analysis
    """
    generic_search_command(
        search_function=search_connector,
        trans_dict=CONNECTOR_TRANS_DICT,
        hr_title='CarbonBlack Protect Connector Search',
        ec_key='CBP.Connector(val.ID === obj.ID)'
    )


def search_connector(url_params):
    """
    Sends the request for file analysis, and returns the result json
    :param url_params: url parameters for the request
    :return: File analysis response json
    """
    return http_request('GET', '/connector', params=url_params)


def resolve_approval_request_command():
    """
    Updates an existing approval request
    :return: EntryObject of the approval request
    """
    args = demisto.args()
    raw_res = update_file_upload(args)
    ec = get_trasnformed_dict(raw_res, APPROVAL_REQUEST_RESOLVE_TRANS_DICT)
    hr = tableToMarkdown('CarbonBlack Protect Approval Request Updated successfully', ec)
    demisto.results(create_entry_object(raw_res, {'CBP.ApprovalRequest(val.ID === obj.ID)': ec}, hr))


def resolve_approval_request(body_params):
    """
    Update file analysis
    :param body_params: URL parameters for the request
    :return: Result json of the request
    """
    return http_request('POST', '/approvalRequest', data=json.dumps(body_params))


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
    user_query = demisto.params().get('fetch_query')
    event_url_params = {
        'q': "timestamp>{time}".format(time=last_fetch),
        'limit': INCIDENTS_PER_FETCH
    }
    if user_query:
        # Add user's query to default query
        event_url_params['q'] = '{timestamp_query}&{user_query}'.format(timestamp_query=event_url_params['q'],
                                                                        user_query=user_query)
    events = search_event(event_url_params)
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
