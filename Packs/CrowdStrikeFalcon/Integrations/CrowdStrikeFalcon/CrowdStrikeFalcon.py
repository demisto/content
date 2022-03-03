import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import requests
import base64
import email
import hashlib
from typing import List, Callable
from dateutil.parser import parse
from typing import Dict, Tuple, Any, Optional, Union
from threading import Timer

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
INTEGRATION_NAME = 'CrowdStrike Falcon'
CLIENT_ID = demisto.params().get('client_id')
SECRET = demisto.params().get('secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else \
    demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
BYTE_CREDS = '{name}:{password}'.format(name=CLIENT_ID, password=SECRET).encode('utf-8')
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Basic {}'.format(base64.b64encode(BYTE_CREDS).decode())
}
# Note: True life time of token is actually 30 mins
TOKEN_LIFE_TIME = 28
INCIDENTS_PER_FETCH = int(demisto.params().get('incidents_per_fetch', 15))
# Remove proxy if not set to true in params
handle_proxy()

''' KEY DICTIONARY '''

DETECTIONS_BASE_KEY_MAP = {
    'device.hostname': 'System',
    'device.cid': 'CustomerID',
    'hostinfo.domain': 'MachineDomain',
    'detection_id': 'ID',
    'created_timestamp': 'ProcessStartTime',
    'max_severity': 'MaxSeverity',
    'show_in_ui': 'ShowInUi',
    'status': 'Status',
    'first_behavior': 'FirstBehavior',
    'last_behavior': 'LastBehavior',
    'max_confidence': 'MaxConfidence',
}

DETECTIONS_BEHAVIORS_KEY_MAP = {
    'filename': 'FileName',
    'scenario': 'Scenario',
    'md5': 'MD5',
    'sha256': 'SHA256',
    'ioc_type': 'IOCType',
    'ioc_value': 'IOCValue',
    'cmdline': 'CommandLine',
    'user_name': 'UserName',
    'behavior_id': 'ID',
    'alleged_filetype': 'AllegedFiletype',
    'confidence': 'Confidence',
    'description': 'Description',
    'display_name': 'DisplayName',
    'filepath': 'Filepath',
    'parent_md5': 'ParentMD5',
    'parent_sha256': 'ParentSHA256',
    'pattern_disposition': 'PatternDisposition',
    'pattern_disposition_details': 'PatternDispositionDetails',
    'tactic': 'Tactic',
    'tactic_id': 'TacticID',
    'technique': 'Technique',
    'technique_id': 'TechniqueId',
}

IOC_KEY_MAP = {
    'type': 'Type',
    'value': 'Value',
    'policy': 'Policy',
    'source': 'Source',
    'share_level': 'ShareLevel',
    'expiration': 'Expiration',
    'description': 'Description',
    'created_on': 'CreatedTime',
    'created_by': 'CreatedBy',
    'modified_on': 'ModifiedTime',
    'modified_by': 'ModifiedBy',
    'id': 'ID',
    'platforms': 'Platforms',
    'action': 'Action',
    'severity': 'Severity',
    'tags': 'Tags',
}

IOC_HEADERS = ['ID', 'Action', 'Severity', 'Type', 'Value', 'Expiration', 'CreatedBy', 'CreatedTime', 'Description',
               'ModifiedBy', 'ModifiedTime', 'Platforms', 'Policy', 'ShareLevel', 'Source', 'Tags']

IOC_DEVICE_COUNT_MAP = {
    'id': 'ID',
    'type': 'Type',
    'value': 'Value',
    'device_count': 'DeviceCount'
}

SEARCH_DEVICE_KEY_MAP = {
    'device_id': 'ID',
    'external_ip': 'ExternalIP',
    'local_ip': 'LocalIP',
    'hostname': 'Hostname',
    'os_version': 'OS',
    'mac_address': 'MacAddress',
    'first_seen': 'FirstSeen',
    'last_seen': 'LastSeen',
    'status': 'Status',
}

ENDPOINT_KEY_MAP = {
    'device_id': 'ID',
    'local_ip': 'IPAddress',
    'os_version': 'OS',
    'hostname': 'Hostname',
    'status': 'Status',
}

''' SPLIT KEY DICTIONARY '''

"""
    Pattern:
    {
        'Path': 'Path to item',
        'NewKey': 'Value of output key',
        'Delim': 'Delimiter char',
        'Index': Split Array Index
    }
"""
DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP = [
    {
        'Path': 'parent_details.parent_process_graph_id',
        'NewKey': 'SensorID',
        'Delim': ':',
        'Index': 1
    },
    {
        'Path': 'parent_details.parent_process_graph_id',
        'NewKey': 'ParentProcessID',
        'Delim': ':',
        'Index': 2
    },
    {
        'Path': 'triggering_process_graph_id',
        'NewKey': 'ProcessID',
        'Delim': ':',
        'Index': 2
    },
]

HOST_GROUP_HEADERS = ['id', 'name', 'group_type', 'description', 'assignment_rule',
                      'created_by', 'created_timestamp',
                      'modified_by', 'modified_timestamp']

STATUS_TEXT_TO_NUM = {'New': "20",
                      'Reopened': "25",
                      'In Progress': "30",
                      'Closed': "40"}

STATUS_NUM_TO_TEXT = {20: 'New',
                      25: 'Reopened',
                      30: 'In Progress',
                      40: 'Closed'}

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, files=None, headers=HEADERS, safe=False,
                 get_token_flag=True, no_json=False, json=None, status_code=None):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.

        :param json: JSON body
        :type json ``dict`` or ``list``

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
        :param safe: If set to true will return None in case of http error

        :type get_token_flag: ``bool``
        :param get_token_flag: If set to True will call get_token()

        :type no_json: ``bool``
        :param no_json: If set to true will not parse the content and will return the raw response object for successful
        response

        :type status_code: ``int``
        :param: status_code: The request codes to accept as OK.

        :return: Returns the http request response json
        :rtype: ``dict``
    """
    if get_token_flag:
        token = get_token()
        headers['Authorization'] = 'Bearer {}'.format(token)
    url = SERVER + url_suffix
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=headers,
            files=files,
            json=json,
        )
    except requests.exceptions.RequestException as e:
        return_error(f'Error in connection to the server. Please make sure you entered the URL correctly.'
                     f' Exception is {str(e)}.')
    try:
        valid_status_codes = {200, 201, 202, 204}
        # Handling a case when we want to return an entry for 404 status code.
        if status_code:
            valid_status_codes.add(status_code)
        if res.status_code not in valid_status_codes:
            res_json = res.json()
            reason = res.reason
            resources = res_json.get('resources', {})
            if resources:
                if isinstance(resources, list):
                    reason += f'\n{str(resources)}'
                else:
                    for host_id, resource in resources.items():
                        errors = resource.get('errors', [])
                        if errors:
                            error_message = errors[0].get('message')
                            reason += f'\nHost ID {host_id} - {error_message}'
            elif res_json.get('errors'):
                errors = res_json.get('errors', [])
                for error in errors:
                    reason += f"\n{error.get('message')}"
            err_msg = 'Error in API call to CrowdStrike Falcon: code: {code} - reason: {reason}'.format(
                code=res.status_code,
                reason=reason
            )
            # try to create a new token
            if res.status_code == 403 and get_token_flag:
                LOG(err_msg)
                token = get_token(new_token=True)
                headers['Authorization'] = 'Bearer {}'.format(token)
                return http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    data=data,
                    headers=headers,
                    files=files,
                    json=json,
                    safe=safe,
                    get_token_flag=False,
                    status_code=status_code,
                    no_json=no_json,
                )
            elif safe:
                return None
            return_error(err_msg)
        return res if no_json else res.json()
    except ValueError as exception:
        raise ValueError(
            f'Failed to parse json object from response: {exception} - {res.content}')  # type: ignore[str-bytes-safe]


def create_entry_object(contents: Union[List[Any], Dict[str, Any]] = {}, ec: Union[List[Any], Dict[str, Any]] = None,
                        hr: str = ''):
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
    return {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }


def detection_to_incident(detection):
    """
        Creates an incident of a detection.

        :type detection: ``dict``
        :param detection: Single detection object

        :return: Incident representation of a detection
        :rtype ``dict``
    """
    incident = {
        'name': 'Detection ID: ' + str(detection.get('detection_id')),
        'occurred': str(detection.get('created_timestamp')),
        'rawJSON': json.dumps(detection),
        'severity': severity_string_to_int(detection.get('max_severity_displayname'))
    }
    return incident


def incident_to_incident_context(incident):
    """
            Creates an incident context of a incident.

            :type incident: ``dict``
            :param incident: Single detection object

            :return: Incident context representation of a incident
            :rtype ``dict``
        """
    incident_id = str(incident.get('incident_id'))
    incident_context = {
        'name': f'Incident ID: {incident_id}',
        'occurred': str(incident.get('start')),
        'rawJSON': json.dumps(incident)
    }
    return incident_context


def severity_string_to_int(severity):
    """
        Converts a severity string to DBot score representation

        :type severity: ``str``
        :param severity: String representation of a severity

        :return: DBot score representation of the severity
        :rtype ``int``
    """
    if severity in ('Critical', 'High'):
        return 3
    elif severity in ('Medium', 'Low'):
        return 2
    return 0


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


def extract_transformed_dict_with_split(old_dict, transformation_dict_arr):
    """
        Extracts new values out of old_dict using a json structure of:
        {'Path': 'Path to item', 'NewKey': 'Value of output key', 'Delim': 'Delimiter char', 'Index': Split Array Index}
    """
    new_dict = {}
    for trans_dict in transformation_dict_arr:
        try:
            val = demisto.get(old_dict, trans_dict['Path'])
            if 'split' in dir(val):
                i = trans_dict['Index']
                new_dict[trans_dict['NewKey']] = val.split(trans_dict['Delim'])[i]
        except Exception as ex:
            LOG('Error {exception} with: {tdict}'.format(exception=ex, tdict=trans_dict))
    return new_dict


def get_passed_mins(start_time, end_time_str):
    """
        Returns the time passed in mins
        :param start_time: Start time in datetime
        :param end_time_str: End time in str
        :return: The passed mins in int
    """
    time_delta = start_time - datetime.fromtimestamp(end_time_str)
    return time_delta.seconds / 60


def handle_response_errors(raw_res: dict, err_msg: str = None):
    """
    Raise exception if raw_res is empty or contains errors
    """
    if not err_msg:
        err_msg = "The server was unable to return a result, please run the command again."
    if not raw_res:
        raise DemistoException(err_msg)
    if raw_res.get('errors'):
        raise DemistoException(raw_res.get('errors'))
    return


def create_json_iocs_list(
        ioc_type: str,
        iocs_value: List[str],
        action: str,
        platforms: List[str],
        severity: Optional[str] = None,
        source: Optional[str] = None,
        description: Optional[str] = None,
        expiration: Optional[str] = None,
        applied_globally: Optional[bool] = None,
        host_groups: Optional[List[str]] = None,
        tags: Optional[List[str]] = None) -> List[dict]:
    """
    Get a list of iocs values and create a list of Json objects with the iocs data.
    This function is used for uploading multiple indicator with same arguments with different values.
    :param ioc_type: The type of the indicator.
    :param iocs_value: List of the indicator.
    :param action: Action to take when a host observes the custom IOC.
    :param platforms: The platforms that the indicator applies to.
    :param severity: The severity level to apply to this indicator.
    :param source: The source where this indicator originated.
    :param description: A meaningful description of the indicator.
    :param expiration: The date on which the indicator will become inactive.
    :param applied_globally: Whether the indicator is applied globally.
    :param host_groups: List of host group IDs that the indicator applies to.
    :param tags: List of tags to apply to the indicator.

    """
    iocs_list = []
    for ioc_value in iocs_value:
        iocs_list.append(assign_params(
            type=ioc_type,
            value=ioc_value,
            action=action,
            platforms=platforms,
            severity=severity,
            source=source,
            description=description,
            expiration=expiration,
            applied_globally=applied_globally,
            host_groups=host_groups,
            tags=tags,
        ))

    return iocs_list


''' COMMAND SPECIFIC FUNCTIONS '''


def init_rtr_single_session(host_id: str) -> str:
    """
        Start a session with single host.
        :param host_id: Host agent ID to initialize a RTR session on.
        :return: The session ID to execute the command on
    """
    endpoint_url = '/real-time-response/entities/sessions/v1'
    body = json.dumps({
        'device_id': host_id
    })
    response = http_request('POST', endpoint_url, data=body)
    resources = response.get('resources')
    if resources and isinstance(resources, list) and isinstance(resources[0], dict):
        session_id = resources[0].get('session_id')
        if isinstance(session_id, str):
            return session_id
    raise ValueError('No session id found in the response')


def init_rtr_batch_session(host_ids: list) -> str:
    """
        Start a session with one or more hosts
        :param host_ids: List of host agent ID’s to initialize a RTR session on.
        :return: The session batch ID to execute the command on
    """
    endpoint_url = '/real-time-response/combined/batch-init-session/v1'
    body = json.dumps({
        'host_ids': host_ids
    })
    response = http_request('POST', endpoint_url, data=body)
    return response.get('batch_id')


def refresh_session(host_id: str) -> Dict:
    """
        Refresh a session timeout on a single host.
        :param host_id: Host agent ID to run RTR command on.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/refresh-session/v1'

    body = json.dumps({
        'device_id': host_id
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def batch_refresh_session(batch_id: str) -> None:
    """
        Batch refresh a RTR session on multiple hosts.
        :param batch_id:  Batch ID to execute the command on.
    """
    demisto.debug('Starting session refresh')
    endpoint_url = '/real-time-response/combined/batch-refresh-session/v1'

    body = json.dumps({
        'batch_id': batch_id
    })
    response = http_request('POST', endpoint_url, data=body)
    demisto.debug(f'Refresh session response: {response}')
    demisto.debug('Finished session refresh')


def run_batch_read_cmd(batch_id: str, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with read access
        :param batch_id:  Batch ID to execute the command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-command/v1'

    body = json.dumps({
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def run_batch_write_cmd(batch_id: str, command_type: str, full_command: str, optional_hosts: list = None) -> Dict:
    """
        Sends RTR command scope with write access
        :param batch_id:  Batch ID to execute the command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :param optional_hosts: The hosts ids to run the command on.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-active-responder-command/v1'

    default_body = {
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    }
    if optional_hosts:
        default_body['optional_hosts'] = optional_hosts  # type:ignore

    body = json.dumps(default_body)
    response = http_request('POST', endpoint_url, data=body)
    return response


def run_batch_admin_cmd(batch_id: str, command_type: str, full_command: str, timeout: int = 30,
                        optional_hosts: list = None) -> Dict:
    """
        Sends RTR command scope with write access
        :param batch_id:  Batch ID to execute the command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :param timeout: Timeout for how long to wait for the request in seconds.
        :param optional_hosts: The hosts ids to run the command on.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-admin-command/v1'

    params = {
        'timeout': timeout
    }

    default_body = {
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    }
    if optional_hosts:
        default_body['optional_hosts'] = optional_hosts  # type:ignore

    body = json.dumps(default_body)
    response = http_request('POST', endpoint_url, data=body, params=params)
    return response


def run_batch_get_cmd(host_ids: list, file_path: str, optional_hosts: list = None, timeout: int = None,
                      timeout_duration: str = None) -> Dict:
    """
        Batch executes `get` command across hosts to retrieve files.
        After this call is made `/real-time-response/combined/batch-get-command/v1` is used to query for the results.

      :param host_ids: List of host agent ID’s to run RTR command on.
      :param file_path: Full path to the file that is to be retrieved from each host in the batch.
      :param optional_hosts: List of a subset of hosts we want to run the command on.
                             If this list is supplied, only these hosts will receive the command.
      :param timeout: Timeout for how long to wait for the request in seconds
      :param timeout_duration: Timeout duration for for how long to wait for the request in duration syntax
      :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-get-command/v1'
    batch_id = init_rtr_batch_session(host_ids)

    body = assign_params(batch_id=batch_id, file_path=file_path, optional_hosts=optional_hosts)
    params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
    response = http_request('POST', endpoint_url, data=json.dumps(body), params=params)
    return response


def status_get_cmd(request_id: str, timeout: int = None, timeout_duration: str = None) -> Dict:
    """
        Retrieves the status of the specified batch get command. Will return successful files when they are finished processing.

      :param request_id: ID to the request of `get` command.
      :param timeout: Timeout for how long to wait for the request in seconds
      :param timeout_duration: Timeout duration for how long to wait for the request in duration syntax
      :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-get-command/v1'

    params = assign_params(timeout=timeout, timeout_duration=timeout_duration, batch_get_cmd_req_id=request_id)
    response = http_request('GET', endpoint_url, params=params)
    return response


def run_single_read_cmd(host_id: str, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with read access
        :param host_id: Host agent ID to run RTR command on.
        :param command_type: Active-Responder command type we are going to execute, for example: get or cp.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/command/v1'
    session_id = init_rtr_single_session(host_id)

    body = json.dumps({
        'base_command': command_type,
        'command_string': full_command,
        'session_id': session_id
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def run_single_write_cmd(host_id: str, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with write access
        :param host_id: Host agent ID to run RTR command on.
        :param command_type: Active-Responder command type we are going to execute, for example: get or cp.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/active-responder-command/v1'
    session_id = init_rtr_single_session(host_id)
    body = json.dumps({
        'base_command': command_type,
        'command_string': full_command,
        'session_id': session_id
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def run_single_admin_cmd(host_id: str, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with admin access
        :param host_id: Host agent ID to run RTR command on.
        :param command_type: Active-Responder command type we are going to execute, for example: get or cp.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/admin-command/v1'
    session_id = init_rtr_single_session(host_id)

    body = json.dumps({
        'base_command': command_type,
        'command_string': full_command,
        'session_id': session_id
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def status_read_cmd(request_id: str, sequence_id: Optional[int]) -> Dict:
    """
        Get status of an executed command with read access on a single host.

        :param request_id: Cloud Request ID of the executed command to query
        :param sequence_id: Sequence ID that we want to retrieve. Command responses are chunked across sequences
    """
    endpoint_url = '/real-time-response/entities/command/v1'

    params = {
        'cloud_request_id': request_id,
        'sequence_id': sequence_id or 0
    }

    response = http_request('GET', endpoint_url, params=params)
    return response


def status_write_cmd(request_id: str, sequence_id: Optional[int]) -> Dict:
    """
        Get status of an executed command with write access on a single host.

        :param request_id: Cloud Request ID of the executed command to query
        :param sequence_id: Sequence ID that we want to retrieve. Command responses are chunked across sequences
    """
    endpoint_url = '/real-time-response/entities/active-responder-command/v1'

    params = {
        'cloud_request_id': request_id,
        'sequence_id': sequence_id or 0
    }

    response = http_request('GET', endpoint_url, params=params)
    return response


def status_admin_cmd(request_id: str, sequence_id: Optional[int]) -> Dict:
    """
        Get status of an executed command with admin access on a single host.

        :param request_id: Cloud Request ID of the executed command to query
        :param sequence_id: Sequence ID that we want to retrieve. Command responses are chunked across sequences
    """
    endpoint_url = '/real-time-response/entities/admin-command/v1'

    params = {
        'cloud_request_id': request_id,
        'sequence_id': sequence_id or 0
    }

    response = http_request('GET', endpoint_url, params=params)
    return response


def list_host_files(host_id: str) -> Dict:
    """
        Get a list of files for the specified RTR session on a host.
        :param host_id: Host agent ID to run RTR command on.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/file/v1'
    session_id = init_rtr_single_session(host_id)

    params = {
        'session_id': session_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def upload_script(name: str, permission_type: str, content: str, entry_id: str) -> Dict:
    """
        Uploads a script by either given content or file
        :param name: Script name to upload
        :param permission_type: Permissions type of script to upload
        :param content: PowerShell script content
        :param entry_id: Script file to upload
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    body: Dict[str, Tuple[Any, Any]] = {
        'name': (None, name),
        'permission_type': (None, permission_type)
    }
    temp_file = None
    try:
        if content:
            body['content'] = (None, content)
        else:  # entry_id was provided
            file_ = demisto.getFilePath(entry_id)
            file_name = file_.get('name')  # pylint: disable=E1101
            temp_file = open(file_.get('path'), 'rb')  # pylint: disable=E1101
            body['file'] = (file_name, temp_file)

        headers = {
            'Authorization': HEADERS['Authorization'],
            'Accept': 'application/json'
        }

        response = http_request('POST', endpoint_url, files=body, headers=headers)

        return response
    finally:
        if temp_file:
            temp_file.close()


def get_script(script_id: list) -> Dict:
    """
        Retrieves a script given its ID
        :param script_id: ID of script to get
        :return: Response JSON which contains errors (if exist) and retrieved resource
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    params = {
        'ids': script_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def delete_script(script_id: str) -> Dict:
    """
        Deletes a script given its ID
        :param script_id: ID of script to delete
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    params = {
        'ids': script_id
    }
    response = http_request('DELETE', endpoint_url, params=params)
    return response


def list_scripts() -> Dict:
    """
        Retrieves list of scripts
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    response = http_request('GET', endpoint_url)
    return response


def get_extracted_file(host_id: str, sha256: str, filename: str = None):
    """
        Get RTR extracted file contents for specified session and sha256.
        :param host_id: The host agent ID to initialize the RTR session on.
        :param sha256: Extracted SHA256
        :param filename: Filename to use for the archive name and the file within the archive.
    """
    endpoint_url = '/real-time-response/entities/extracted-file-contents/v1'
    session_id = init_rtr_single_session(host_id)
    params = {
        'session_id': session_id,
        'sha256': sha256
    }
    if filename:
        params['filename'] = filename

    response = http_request('GET', endpoint_url, params=params, no_json=True)
    return response


def upload_file(entry_id: str, description: str) -> Tuple:
    """
        Uploads a file given entry ID
        :param entry_id: The entry ID of the file to upload
        :param description: String description of file to upload
        :return: Response JSON which contains errors (if exist) and how many resources were affected and the file name
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    temp_file = None
    try:
        file_ = demisto.getFilePath(entry_id)
        file_name = file_.get('name')  # pylint: disable=E1101
        temp_file = open(file_.get('path'), 'rb')  # pylint: disable=E1101
        body = {
            'name': (None, file_name),
            'description': (None, description),
            'file': (file_name, temp_file)
        }
        headers = {
            'Authorization': HEADERS['Authorization'],
            'Accept': 'application/json'
        }
        response = http_request('POST', endpoint_url, files=body, headers=headers)
        return response, file_name
    finally:
        if temp_file:
            temp_file.close()


def delete_file(file_id: str) -> Dict:
    """
        Delete a put-file based on the ID given
        :param file_id: ID of file to delete
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    params = {
        'ids': file_id
    }
    response = http_request('DELETE', endpoint_url, params=params)
    return response


def get_file(file_id: list) -> Dict:
    """
        Get put-files based on the ID's given
        :param file_id: ID of file to get
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    params = {
        'ids': file_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def list_files() -> Dict:
    """
        Get a list of put-file ID's that are available to the user for the put command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    response = http_request('GET', endpoint_url)
    return response


def get_token(new_token=False):
    """
        Retrieves the token from the server if it's expired and updates the global HEADERS to include it

        :param new_token: If set to True will generate a new token regardless of time passed

        :rtype: ``str``
        :return: Token
    """
    now = datetime.now()
    ctx = demisto.getIntegrationContext()
    if ctx and not new_token:
        passed_mins = get_passed_mins(now, ctx.get('time'))
        if passed_mins >= TOKEN_LIFE_TIME:
            # token expired
            auth_token = get_token_request()
            demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
        else:
            # token hasn't expired
            auth_token = ctx.get('auth_token')
    else:
        # there is no token
        auth_token = get_token_request()
        demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
    return auth_token


def get_token_request():
    """
        Sends token request

        :rtype ``str``
        :return: Access token
    """
    body = {
        'client_id': CLIENT_ID,
        'client_secret': SECRET
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    token_res = http_request('POST', '/oauth2/token', data=body, headers=headers, safe=True,
                             get_token_flag=False)
    if not token_res:
        err_msg = 'Authorization Error: User has no authorization to create a token. Please make sure you entered the' \
                  ' credentials correctly.'
        raise Exception(err_msg)
    return token_res.get('access_token')


def get_detections(last_behavior_time=None, behavior_id=None, filter_arg=None):
    """
        Sends detections request. The function will ignore the arguments passed according to priority:
        filter_arg > behavior_id > last_behavior_time

        :param last_behavior_time: 3rd priority. The last behavior time of results will be greater than this value
        :param behavior_id: 2nd priority. The result will only contain the detections with matching behavior id
        :param filter_arg: 1st priority. The result will be filtered using this argument.
        :return: Response json of the get detection endpoint (IDs of the detections)
    """
    endpoint_url = '/detects/queries/detects/v1'
    params = {
        'sort': 'first_behavior.asc'
    }
    if filter_arg:
        params['filter'] = filter_arg
    elif behavior_id:
        params['filter'] = "behaviors.behavior_id:'{0}'".format(behavior_id)
    elif last_behavior_time:
        params['filter'] = "first_behavior:>'{0}'".format(last_behavior_time)

    response = http_request('GET', endpoint_url, params)
    return response


def get_fetch_detections(last_created_timestamp=None, filter_arg=None, offset: int = 0):
    """ Sends detection request, based on the created_timestamp field. Used for fetch-incidents
    Args:
        last_created_timestamp: last created timestamp of the results will be greater than this value.
        filter_arg: The result will be filtered using this argument.
    Returns:
        Response json of the get detection endpoint (IDs of the detections)
    """
    endpoint_url = '/detects/queries/detects/v1'
    params = {
        'sort': 'first_behavior.asc',
        'offset': offset,
        'limit': INCIDENTS_PER_FETCH
    }
    if filter_arg:
        params['filter'] = filter_arg

    elif last_created_timestamp:
        params['filter'] = "created_timestamp:>'{0}'".format(last_created_timestamp)

    response = http_request('GET', endpoint_url, params)

    return response


def get_detections_entities(detections_ids):
    """
        Sends detection entities request
        :param detections_ids: IDs of the requested detections.
        :return: Response json of the get detection entities endpoint (detection objects)
    """
    ids_json = {'ids': detections_ids}
    if detections_ids:
        response = http_request(
            'POST',
            '/detects/entities/summaries/GET/v1',
            data=json.dumps(ids_json)
        )
        return response
    return detections_ids


def get_incidents_ids(last_created_timestamp=None, filter_arg=None, offset: int = 0):
    get_incidents_endpoint = '/incidents/queries/incidents/v1'
    params = {
        'sort': 'start.asc',
        'offset': offset,
        'limit': INCIDENTS_PER_FETCH
    }
    if filter_arg:
        params['filter'] = filter_arg

    elif last_created_timestamp:
        params['filter'] = "start:>'{0}'".format(last_created_timestamp)

    response = http_request('GET', get_incidents_endpoint, params)

    return response


def get_incidents_entities(incidents_ids):
    ids_json = {'ids': incidents_ids}
    response = http_request(
        'POST',
        '/incidents/entities/incidents/GET/v1',
        data=json.dumps(ids_json)
    )
    return response


def upload_ioc(ioc_type, value, policy=None, expiration_days=None,
               share_level=None, description=None, source=None):
    """
    Create a new IOC (or replace an existing one)
    """
    payload = assign_params(
        type=ioc_type,
        value=value,
        policy=policy,
        share_level=share_level,
        expiration_days=expiration_days,
        source=source,
        description=description,
    )

    return http_request('POST', '/indicators/entities/iocs/v1', json=[payload])


def update_ioc(ioc_type, value, policy=None, expiration_days=None,
               share_level=None, description=None, source=None):
    """
    Update an existing IOC
    """
    body = assign_params(
        type=ioc_type,
        value=value,
        policy=policy,
        share_level=share_level,
        expiration_days=expiration_days,
        source=source,
        description=description,
    )
    params = assign_params(
        type=ioc_type,
        value=value
    )

    return http_request('PATCH', '/indicators/entities/iocs/v1', json=body, params=params)


def search_iocs(types=None, values=None, policies=None, sources=None, expiration_from=None,
                expiration_to=None, limit=None, share_levels=None, ids=None, sort=None, offset=None):
    """
    :param types: A list of indicator types. Separate multiple types by comma.
    :param values: Comma-separated list of indicator values
    :param policies: Comma-separated list of indicator policies
    :param sources: Comma-separated list of IOC sources
    :param expiration_from: Start of date range to search (YYYY-MM-DD format).
    :param expiration_to: End of date range to search (YYYY-MM-DD format).
    :param share_levels: A list of share levels. Only red is supported.
    :param limit: The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100.
    :param sort: The order of the results. Format
    :param offset: The offset to begin the list from
    """
    if not ids:
        payload = assign_params(
            types=argToList(types),
            values=argToList(values),
            policies=argToList(policies),
            sources=argToList(sources),
            share_levels=argToList(share_levels),
            sort=sort,
            offset=offset,
            limit=limit or '50',
        )
        if expiration_from:
            payload['from.expiration_timestamp'] = expiration_from
        if expiration_to:
            payload['to.expiration_timestamp'] = expiration_to

        ids = http_request('GET', '/indicators/queries/iocs/v1', payload).get('resources')
        if not ids:
            return None
    else:
        ids = str(ids)
    payload = {
        'ids': ids
    }
    return http_request('GET', '/indicators/entities/iocs/v1', params=payload)


def enrich_ioc_dict_with_ids(ioc_dict):
    """
        Enriches the provided ioc_dict with IOC ID
        :param ioc_dict: IOC dict transformed using the SEARCH_IOC_KEY_MAP
        :return: ioc_dict with its ID key:value updated
    """
    for ioc in ioc_dict:
        ioc['ID'] = '{type}:{val}'.format(type=ioc.get('Type'), val=ioc.get('Value'))
    return ioc_dict


def delete_ioc(ioc_type, value):
    """
    Delete an IOC
    """
    payload = assign_params(
        type=ioc_type,
        value=value
    )
    return http_request('DELETE', '/indicators/entities/iocs/v1', payload)


def search_custom_iocs(
    types: Optional[Union[list, str]] = None,
    values: Optional[Union[list, str]] = None,
    sources: Optional[Union[list, str]] = None,
    expiration: Optional[str] = None,
    limit: str = '50',
    sort: Optional[str] = None,
    offset: Optional[str] = None,
) -> dict:
    """
    :param types: A list of indicator types. Separate multiple types by comma.
    :param values: Comma-separated list of indicator values
    :param sources: Comma-separated list of IOC sources
    :param expiration: The date on which the indicator will become inactive. (YYYY-MM-DD format).
    :param limit: The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100.
    :param sort: The order of the results. Format
    :param offset: The offset to begin the list from
    """
    filter_list = []
    if types:
        filter_list.append(f'type:{types}')
    if values:
        filter_list.append(f'value:{values}')
    if sources:
        filter_list.append(f'source:{sources}')
    if expiration:
        filter_list.append(f'expiration:"{expiration}"')

    params = {
        'filter': '+'.join(filter_list),
        'sort': sort,
        'offset': offset,
        'limit': limit,
    }

    return http_request('GET', '/iocs/combined/indicator/v1', params=params)


def get_custom_ioc(ioc_id: str) -> dict:
    params = {'ids': ioc_id}
    return http_request('GET', '/iocs/entities/indicators/v1', params=params)


def update_custom_ioc(
    ioc_id: str,
    action: Optional[str] = None,
    platforms: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    description: Optional[str] = None,
    expiration: Optional[str] = None,
) -> dict:
    """
    Update an IOC
    """
    payload = {
        'indicators': [{
            'id': ioc_id,
        } | assign_params(
            action=action,
            platforms=platforms,
            severity=severity,
            source=source,
            description=description,
            expiration=expiration,
        )]
    }

    return http_request('PATCH', '/iocs/entities/indicators/v1', json=payload)


def delete_custom_ioc(ids: str) -> dict:
    """
    Delete an IOC
    """
    params = {'ids': ids}
    return http_request('DELETE', '/iocs/entities/indicators/v1', params=params)


def get_ioc_device_count(ioc_type, value):
    """
    Gets the devices that encountered the IOC
    """
    payload = assign_params(
        type=ioc_type,
        value=value
    )
    response = http_request('GET', '/indicators/aggregates/devices-count/v1', payload, status_code=404)
    errors = response.get('errors', [])
    for error in errors:
        if error.get('code') == 404:
            return f'No results found for {ioc_type} - {value}'
    return response


def get_process_details(ids):
    """
    Get given processes details
    """
    payload = assign_params(ids=ids)
    return http_request('GET', '/processes/entities/processes/v1', payload)


def get_proccesses_ran_on(ioc_type, value, device_id):
    """
    Get processes ids that ran on the given device_id that encountered the ioc
    """
    payload = assign_params(
        type=ioc_type,
        value=value,
        device_id=device_id
    )
    return http_request('GET', '/indicators/queries/processes/v1', payload)


def search_device():
    """
        Searches for devices using the argument provided by the command execution. Returns empty
        result of no device was found
        :return: Search device response json
    """
    args = demisto.args()
    input_arg_dict = {
        'device_id': str(args.get('ids', '')).split(','),
        'status': str(args.get('status', '')).split(','),
        'hostname': str(args.get('hostname', '')).split(','),
        'platform_name': str(args.get('platform_name', '')).split(','),
        'site_name': str(args.get('site_name', '')).split(',')
    }
    url_filter = '{}'.format(str(args.get('filter', '')))
    for k, arg in input_arg_dict.items():
        if arg:
            if type(arg) is list:
                arg_filter = ''
                for arg_elem in arg:
                    if arg_elem:
                        first_arg = '{filter},{inp_arg}'.format(filter=arg_filter, inp_arg=k) if arg_filter else k
                        arg_filter = "{first}:'{second}'".format(first=first_arg, second=arg_elem)
                if arg_filter:
                    url_filter = "{url_filter}{arg_filter}".format(url_filter=url_filter + '+' if url_filter else '',
                                                                   arg_filter=arg_filter)
            else:
                # All args should be a list. this is a fallback
                url_filter = "{url_filter}+{inp_arg}:'{arg_val}'".format(url_filter=url_filter, inp_arg=k, arg_val=arg)
    raw_res = http_request('GET', '/devices/queries/devices/v1', params={'filter': url_filter})
    device_ids = raw_res.get('resources')
    if not device_ids:
        return None
    return http_request('GET', '/devices/entities/devices/v1', params={'ids': device_ids})


def behavior_to_entry_context(behavior):
    """
        Transforms a behavior to entry context representation
        :param behavior: Behavior dict in the format of crowdstrike's API response
        :return: Behavior in entry context representation
    """
    raw_entry = get_trasnformed_dict(behavior, DETECTIONS_BEHAVIORS_KEY_MAP)
    raw_entry.update(extract_transformed_dict_with_split(behavior, DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP))
    return raw_entry


def get_username_uuid(username: str):
    """
    Obtain CrowdStrike user’s UUId by email.
    :param username: Username to get UUID of.
    :return: The user UUID
    """
    response = http_request('GET', '/users/queries/user-uuids-by-email/v1', params={'uid': username})
    resources: list = response.get('resources', [])
    if not resources:
        raise ValueError(f'User {username} was not found')
    return resources[0]


def resolve_detection(ids, status, assigned_to_uuid, show_in_ui, comment):
    """
        Sends a resolve detection request
        :param ids: Single or multiple ids in an array string format
        :param status: New status of the detection
        :param assigned_to_uuid: uuid to assign the detection to
        :param show_in_ui: Boolean flag in string format (true/false)
        :param comment: Optional comment to add to the detection
        :return: Resolve detection response json
    """
    payload = {
        'ids': ids
    }
    if status:
        payload['status'] = status
    if assigned_to_uuid:
        payload['assigned_to_uuid'] = assigned_to_uuid
    if show_in_ui:
        payload['show_in_ui'] = show_in_ui
    if comment:
        payload['comment'] = comment
    # We do this so show_in_ui value won't contain ""
    data = json.dumps(payload).replace('"show_in_ui": "false"', '"show_in_ui": false').replace('"show_in_ui": "true"',
                                                                                               '"show_in_ui": true')
    return http_request('PATCH', '/detects/entities/detects/v2', data=data)


def contain_host(ids):
    """
        Contains host(s) with matching ids
        :param ids: IDs of host to contain
        :return: Contain host response json
    """
    payload = {
        'ids': ids
    }
    data = json.dumps(payload)
    params = {
        'action_name': 'contain'
    }
    return http_request('POST', '/devices/entities/devices-actions/v2', data=data, params=params)


def lift_host_containment(ids):
    """
        Lifts off containment from host(s) with matchind ids
        :param ids: IDs of host to lift off containment from
        :return: Lift off containment response json
    """
    payload = {
        'ids': ids
    }
    data = json.dumps(payload)
    params = {
        'action_name': 'lift_containment'
    }
    return http_request('POST', '/devices/entities/devices-actions/v2', data=data, params=params)


def timestamp_length_equalization(timestamp1, timestamp2):
    """
        Makes sure the timestamps are of the same length.
    Args:
        timestamp1: First timestamp to compare.
        timestamp2: Second timestamp to compare.
    Returns:
        the two timestamps in the same length (the longer one)
    """
    diff_len = len(str(timestamp1)) - len(str(timestamp2))

    # no difference in length
    if diff_len == 0:
        return int(timestamp1), int(timestamp2)

    # length of timestamp1 > timestamp2
    if diff_len > 0:
        ten_times = pow(10, diff_len)
        timestamp2 = int(timestamp2) * ten_times

    # length of timestamp2 > timestamp1
    else:
        ten_times = pow(10, diff_len * -1)
        timestamp1 = int(timestamp1) * ten_times

    return int(timestamp1), int(timestamp2)


def change_host_group(is_post: bool,
                      host_group_id: Optional[str] = None,
                      name: Optional[str] = None,
                      group_type: Optional[str] = None,
                      description: Optional[str] = None,
                      assignment_rule: Optional[str] = None) -> Dict:
    method = 'POST' if is_post else 'PATCH'
    data = {'resources': [{
        'id': host_group_id,
        "name": name,
        "description": description,
        "group_type": group_type,
        "assignment_rule": assignment_rule
    }]}
    response = http_request(method=method,
                            url_suffix='/devices/entities/host-groups/v1',
                            json=data)
    return response


def change_host_group_members(action_name: str,
                              host_group_id: str,
                              host_ids: List[str]) -> Dict:
    allowed_actions = {'add-hosts', 'remove-hosts'}
    if action_name not in allowed_actions:
        raise DemistoException(f'CrowdStrike Falcon error: action name should be in {allowed_actions}')
    data = {'action_parameters': [{'name': 'filter',
                                   'value': f"(device_id:{str(host_ids)})"}],
            'ids': [host_group_id]}
    response = http_request(method='POST',
                            url_suffix='/devices/entities/host-group-actions/v1',
                            params={'action_name': action_name},
                            json=data)
    return response


def host_group_members(filter: Optional[str],
                       host_group_id: Optional[str],
                       limit: Optional[str],
                       offset: Optional[str]):
    params = {'id': host_group_id,
              'filter': filter,
              'offset': offset,
              'limit': limit}
    response = http_request(method='GET',
                            url_suffix='/devices/combined/host-group-members/v1',
                            params=params)
    return response


def resolve_incident(ids: List[str], status: str):
    if status not in STATUS_TEXT_TO_NUM:
        raise DemistoException(f'CrowdStrike Falcon Error: '
                               f'Status given is {status} and it is not in {STATUS_TEXT_TO_NUM.keys()}')
    data = {
        "action_parameters": [
            {
                "name": "update_status",
                "value": STATUS_TEXT_TO_NUM[status]
            }
        ],
        "ids": ids
    }
    http_request(method='POST',
                 url_suffix='/incidents/entities/incident-actions/v1',
                 json=data)


def list_host_groups(filter: Optional[str], limit: Optional[str], offset: Optional[str]) -> Dict:
    params = {'filter': filter,
              'offset': offset,
              'limit': limit}
    response = http_request(method='GET',
                            url_suffix='/devices/combined/host-groups/v1',
                            params=params)
    return response


def delete_host_groups(host_group_ids: List[str]) -> Dict:
    params = {'ids': host_group_ids}
    response = http_request(method='DELETE',
                            url_suffix='/devices/entities/host-groups/v1',
                            params=params)
    return response


def upload_batch_custom_ioc(ioc_batch: List[dict]) -> dict:
    """
    Upload a list of IOC
    """
    payload = {
        'indicators': ioc_batch
    }

    return http_request('POST', '/iocs/entities/indicators/v1', json=payload)


''' COMMANDS FUNCTIONS '''


def get_fetch_times_and_offset(incident_type):
    last_run = demisto.getLastRun()
    last_fetch_time = last_run.get(f'first_behavior_{incident_type}_time')
    offset = last_run.get(f'{incident_type}_offset', 0)
    if not last_fetch_time:
        last_fetch_time, _ = parse_date_range(FETCH_TIME, date_format='%Y-%m-%dT%H:%M:%SZ')
    prev_fetch = last_fetch_time
    last_fetch_timestamp = int(parse(last_fetch_time).timestamp() * 1000)
    return last_fetch_time, offset, prev_fetch, last_fetch_timestamp


def fetch_incidents():
    incidents = []  # type:List
    current_fetch_info = demisto.getLastRun()
    fetch_incidents_or_detections = demisto.params().get('fetch_incidents_or_detections')

    if 'Detections' in fetch_incidents_or_detections:
        incident_type = 'detection'
        last_fetch_time, offset, prev_fetch, last_fetch_timestamp = get_fetch_times_and_offset(incident_type)

        fetch_query = demisto.params().get('fetch_query')
        if fetch_query:
            fetch_query = "created_timestamp:>'{time}'+{query}".format(time=last_fetch_time, query=fetch_query)
            detections_ids = demisto.get(get_fetch_detections(filter_arg=fetch_query, offset=offset), 'resources')
        else:
            detections_ids = demisto.get(get_fetch_detections(last_created_timestamp=last_fetch_time, offset=offset),
                                         'resources')

        if detections_ids:
            raw_res = get_detections_entities(detections_ids)

            if "resources" in raw_res:
                for detection in demisto.get(raw_res, "resources"):
                    detection['incident_type'] = incident_type
                    incident = detection_to_incident(detection)
                    incident_date = incident['occurred']

                    incident_date_timestamp = int(parse(incident_date).timestamp() * 1000)

                    # make sure that the two timestamps are in the same length
                    if len(str(incident_date_timestamp)) != len(str(last_fetch_timestamp)):
                        incident_date_timestamp, last_fetch_timestamp = timestamp_length_equalization(
                            incident_date_timestamp, last_fetch_timestamp)

                    # Update last run and add incident if the incident is newer than last fetch
                    if incident_date_timestamp > last_fetch_timestamp:
                        last_fetch_time = incident_date
                        last_fetch_timestamp = incident_date_timestamp

                    incidents.append(incident)

            if len(incidents) == INCIDENTS_PER_FETCH:
                current_fetch_info['first_behavior_detection_time'] = prev_fetch
                current_fetch_info['detection_offset'] = offset + INCIDENTS_PER_FETCH
            else:
                current_fetch_info['first_behavior_detection_time'] = last_fetch_time
                current_fetch_info['detection_offset'] = 0

    if 'Incidents' in fetch_incidents_or_detections:
        incident_type = 'incident'

        last_fetch_time, offset, prev_fetch, last_fetch_timestamp = get_fetch_times_and_offset(incident_type)
        last_run = demisto.getLastRun()
        last_incident_fetched = last_run.get('last_fetched_incident')
        new_last_incident_fetched = ''

        fetch_query = demisto.params().get('incidents_fetch_query')

        if fetch_query:
            fetch_query = "start:>'{time}'+{query}".format(time=last_fetch_time, query=fetch_query)
            incidents_ids = demisto.get(get_incidents_ids(filter_arg=fetch_query, offset=offset), 'resources')

        else:
            incidents_ids = demisto.get(get_incidents_ids(last_created_timestamp=last_fetch_time, offset=offset),
                                        'resources')

        if incidents_ids:
            raw_res = get_incidents_entities(incidents_ids)
            if "resources" in raw_res:
                for incident in demisto.get(raw_res, "resources"):
                    incident['incident_type'] = incident_type
                    incident_to_context = incident_to_incident_context(incident)
                    incident_date = incident_to_context['occurred']

                    incident_date_timestamp = int(parse(incident_date).timestamp() * 1000)

                    # make sure that the two timestamps are in the same length
                    if len(str(incident_date_timestamp)) != len(str(last_fetch_timestamp)):
                        incident_date_timestamp, last_fetch_timestamp = timestamp_length_equalization(
                            incident_date_timestamp, last_fetch_timestamp)

                    # Update last run and add incident if the incident is newer than last fetch
                    if incident_date_timestamp > last_fetch_timestamp:
                        last_fetch_time = incident_date
                        last_fetch_timestamp = incident_date_timestamp
                        new_last_incident_fetched = incident.get('incident_id')

                    if last_incident_fetched != incident.get('incident_id'):
                        incidents.append(incident_to_context)

            if len(incidents) == INCIDENTS_PER_FETCH:
                current_fetch_info['first_behavior_incident_time'] = prev_fetch
                current_fetch_info['incident_offset'] = offset + INCIDENTS_PER_FETCH
                current_fetch_info['last_fetched_incident'] = new_last_incident_fetched
            else:
                current_fetch_info['first_behavior_incident_time'] = last_fetch_time
                current_fetch_info['incident_offset'] = 0
                current_fetch_info['last_fetched_incident'] = new_last_incident_fetched

    demisto.setLastRun(current_fetch_info)
    return incidents


def upload_ioc_command(ioc_type=None, value=None, policy=None, expiration_days=None,
                       share_level=None, description=None, source=None):
    """
    :param ioc_type: The type of the indicator:
    :param policy :The policy to enact when the value is detected on a host.
    :param share_level: The level at which the indicator will be shared.
    :param expiration_days: This represents the days the indicator should be valid for.
    :param source: The source where this indicator originated.
    :param description: A meaningful description of the indicator.
    :param value: The string representation of the indicator.
    """
    raw_res = upload_ioc(ioc_type, value, policy, expiration_days, share_level, description, source)
    handle_response_errors(raw_res)
    iocs = search_iocs(ids=f"{ioc_type}:{value}").get('resources')
    if not iocs:
        raise DemistoException("Failed to create IOC. Please try again.")
    ec = [get_trasnformed_dict(iocs[0], IOC_KEY_MAP)]
    enrich_ioc_dict_with_ids(ec)
    return create_entry_object(contents=raw_res, ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
                               hr=tableToMarkdown('Custom IOC was created successfully', ec))


def update_ioc_command(ioc_type=None, value=None, policy=None, expiration_days=None,
                       share_level=None, description=None, source=None):
    """
    :param ioc_type: The type of the indicator:
    :param policy :The policy to enact when the value is detected on a host.
    :param share_level: The level at which the indicator will be shared.
    :param expiration_days: This represents the days the indicator should be valid for.
    :param source: The source where this indicator originated.
    :param description: A meaningful description of the indicator.
    :param value: The string representation of the indicator.
    """
    raw_res = update_ioc(ioc_type, value, policy, expiration_days, share_level, description, source)
    handle_response_errors(raw_res)
    iocs = search_iocs(ids=f"{ioc_type}:{value}").get('resources')
    ec = [get_trasnformed_dict(iocs[0], IOC_KEY_MAP)]
    enrich_ioc_dict_with_ids(ec)
    return create_entry_object(contents=raw_res, ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
                               hr=tableToMarkdown('Custom IOC was created successfully', ec))


def search_iocs_command(types=None, values=None, policies=None, sources=None, from_expiration_date=None,
                        to_expiration_date=None, share_levels=None, limit=None, sort=None, offset=None):
    """
    :param types: A list of indicator types. Separate multiple types by comma.
    :param values: Comma-separated list of indicator values
    :param policies: Comma-separated list of indicator policies
    :param sources: Comma-separated list of IOC sources
    :param from_expiration_date: Start of date range to search (YYYY-MM-DD format).
    :param to_expiration_date: End of date range to search (YYYY-MM-DD format).
    :param share_levels: A list of share levels. Only red is supported.
    :param limit: The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100.
    :param sort: The order of the results. Format
    :param offset: The offset to begin the list from
    """
    raw_res = search_iocs(types=types, values=values, policies=policies, sources=sources, sort=sort, offset=offset,
                          expiration_from=from_expiration_date, expiration_to=to_expiration_date,
                          share_levels=share_levels, limit=limit)
    if not raw_res:
        return create_entry_object(hr='Could not find any Indicators of Compromise.')
    handle_response_errors(raw_res)
    iocs = raw_res.get('resources')
    ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP) for ioc in iocs]
    enrich_ioc_dict_with_ids(ec)
    return create_entry_object(contents=raw_res, ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
                               hr=tableToMarkdown('Indicators of Compromise', ec))


def get_ioc_command(ioc_type: str, value: str):
    """
    :param ioc_type: The type of the indicator
    :param value: The IOC value to retrieve
    """
    raw_res = search_iocs(ids=f"{ioc_type}:{value}")
    handle_response_errors(raw_res, 'Could not find any Indicators of Compromise.')
    iocs = raw_res.get('resources')
    ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP) for ioc in iocs]
    enrich_ioc_dict_with_ids(ec)
    return create_entry_object(contents=raw_res, ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
                               hr=tableToMarkdown('Indicator of Compromise', ec))


def delete_ioc_command(ioc_type, value):
    """
    :param ioc_type: The type of the indicator
    :param value: The IOC value to delete
    """
    raw_res = delete_ioc(ioc_type, value)
    handle_response_errors(raw_res, "The server has not confirmed deletion, please manually confirm deletion.")
    ids = f"{ioc_type}:{value}"
    return create_entry_object(contents=raw_res, hr=f"Custom IOC {ids} was successfully deleted.")


def search_custom_iocs_command(
    types: Optional[Union[list, str]] = None,
    values: Optional[Union[list, str]] = None,
    sources: Optional[Union[list, str]] = None,
    expiration: Optional[str] = None,
    limit: str = '50',
    sort: Optional[str] = None,
    offset: Optional[str] = None,
) -> dict:
    """
    :param types: A list of indicator types. Separate multiple types by comma.
    :param values: Comma-separated list of indicator values
    :param sources: Comma-separated list of IOC sources
    :param expiration: The date on which the indicator will become inactive. (YYYY-MM-DD format).
    :param limit: The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100.
    :param sort: The order of the results. Format
    :param offset: The offset to begin the list from
    """
    raw_res = search_custom_iocs(
        types=argToList(types),
        values=argToList(values),
        sources=argToList(sources),
        sort=sort,
        offset=offset,
        expiration=expiration,
        limit=limit,
    )
    iocs = raw_res.get('resources')
    if not iocs:
        return create_entry_object(hr='Could not find any Indicators of Compromise.')
    handle_response_errors(raw_res)
    ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP) for ioc in iocs]
    return create_entry_object(
        contents=raw_res,
        ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
        hr=tableToMarkdown('Indicators of Compromise', ec, headers=IOC_HEADERS),
    )


def get_custom_ioc_command(
    ioc_type: Optional[str] = None,
    value: Optional[str] = None,
    ioc_id: Optional[str] = None,
) -> dict:
    """
    :param ioc_type: IOC type
    :param value: IOC value
    :param ioc_id: IOC ID
    """

    if not ioc_id and not (ioc_type and value):
        raise ValueError('Either ioc_id or ioc_type and value must be provided.')

    if ioc_id:
        raw_res = get_custom_ioc(ioc_id)
    else:
        raw_res = search_custom_iocs(
            types=argToList(ioc_type),
            values=argToList(value),
        )

    iocs = raw_res.get('resources')
    handle_response_errors(raw_res)
    if not iocs:
        return create_entry_object(hr='Could not find any Indicators of Compromise.')
    ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP) for ioc in iocs]
    return create_entry_object(
        contents=raw_res,
        ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
        hr=tableToMarkdown('Indicator of Compromise', ec, headers=IOC_HEADERS),
    )


def upload_custom_ioc_command(
        ioc_type: str,
        value: str,
        action: str,
        platforms: str,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        description: Optional[str] = None,
        expiration: Optional[str] = None,
        applied_globally: Optional[bool] = None,
        host_groups: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
) -> List[dict]:
    """
    :param ioc_type: The type of the indicator.
    :param value: The string representation of the indicator.
    :param action: Action to take when a host observes the custom IOC.
    :param platforms: The platforms that the indicator applies to.
    :param severity: The severity level to apply to this indicator.
    :param source: The source where this indicator originated.
    :param description: A meaningful description of the indicator.
    :param expiration: The date on which the indicator will become inactive.
    :param applied_globally: Whether the indicator is applied globally.
    :param host_groups: List of host group IDs that the indicator applies to.
    :param tags: List of tags to apply to the indicator.

    """
    if action in {'prevent', 'detect'} and not severity:
        raise ValueError(f'Severity is required for action {action}.')
    value = argToList(value)
    applied_globally = argToBoolean(applied_globally) if applied_globally else None
    host_groups = argToList(host_groups)
    tags = argToList(tags)
    platforms = argToList(platforms)

    iocs_json_batch = create_json_iocs_list(ioc_type, value, action, platforms, severity, source, description,
                                            expiration, applied_globally, host_groups, tags)
    raw_res = upload_batch_custom_ioc(ioc_batch=iocs_json_batch)
    handle_response_errors(raw_res)
    iocs = raw_res.get('resources', [])

    entry_objects_list = []
    for ioc in iocs:
        ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP)]
        entry_objects_list.append(create_entry_object(
            contents=raw_res,
            ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
            hr=tableToMarkdown(f"Custom IOC {ioc['value']} was created successfully", ec),
        ))
    return entry_objects_list


def update_custom_ioc_command(
    ioc_id: str,
    action: Optional[str] = None,
    platforms: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    description: Optional[str] = None,
    expiration: Optional[str] = None,
) -> dict:
    """
    :param ioc_id: The ID of the indicator to update.
    :param action: Action to take when a host observes the custom IOC.
    :param platforms: The platforms that the indicator applies to.
    :param severity: The severity level to apply to this indicator.
    :param source: The source where this indicator originated.
    :param description: A meaningful description of the indicator.
    :param expiration: The date on which the indicator will become inactive.
    """

    raw_res = update_custom_ioc(
        ioc_id,
        action,
        argToList(platforms),
        severity,
        source,
        description,
        expiration,
    )
    handle_response_errors(raw_res)
    iocs = raw_res.get('resources', [])
    ec = [get_trasnformed_dict(iocs[0], IOC_KEY_MAP)]
    return create_entry_object(
        contents=raw_res,
        ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
        hr=tableToMarkdown('Custom IOC was updated successfully', ec),
    )


def delete_custom_ioc_command(ioc_id: str) -> dict:
    """
    :param ioc_id: The ID of indicator to delete.
    """
    raw_res = delete_custom_ioc(ioc_id)
    handle_response_errors(raw_res, "The server has not confirmed deletion, please manually confirm deletion.")
    return create_entry_object(contents=raw_res, hr=f"Custom IOC {ioc_id} was successfully deleted.")


def get_ioc_device_count_command(ioc_type: str, value: str):
    """
    :param ioc_type: The type of the indicator
    :param value: The IOC value
    """
    raw_res = get_ioc_device_count(ioc_type, value)
    if 'No results found for' in raw_res:
        return raw_res
    else:
        handle_response_errors(raw_res)
        device_count_res = raw_res.get('resources')
        ioc_id = f"{ioc_type}:{value}"
        if not device_count_res:
            return create_entry_object(raw_res, hr=f"Could not find any devices the IOC **{ioc_id}** was detected in.")
        context = [get_trasnformed_dict(device_count, IOC_DEVICE_COUNT_MAP) for device_count in device_count_res]
        hr = f'Indicator of Compromise **{ioc_id}** device count: **{device_count_res[0].get("device_count")}**'
        return create_entry_object(contents=raw_res, ec={'CrowdStrike.IOC(val.ID === obj.ID)': context}, hr=hr)


def get_process_details_command(ids: str):
    """
    :param ids: proccess ids
    """
    ids = argToList(ids)
    raw_res = get_process_details(ids)
    handle_response_errors(raw_res)
    proc = raw_res.get('resources')
    if not proc:
        return create_entry_object(raw_res, hr="Could not find any searched processes.")
    proc_hr_ids = str(ids)[1:-1].replace('\'', '')
    title = f"Details for process{'es' if len(ids) > 1 else ''}: {proc_hr_ids}."
    return create_entry_object(contents=raw_res, hr=tableToMarkdown(title, proc),
                               ec={'CrowdStrike.Process(val.process_id === obj.process_id)': proc})


def get_proccesses_ran_on_command(ioc_type, value, device_id):
    """
    :param device_id: Device id the IOC ran on
    :param ioc_type: The type of the indicator
    :param value: The IOC value
    """
    raw_res = get_proccesses_ran_on(ioc_type, value, device_id)
    handle_response_errors(raw_res)
    proc_ids = raw_res.get('resources')
    ioc_id = f"{ioc_type}:{value}"
    if not proc_ids:
        return create_entry_object(raw_res, hr=f"Could not find any processes associated with the IOC **{ioc_id}**.")
    context = {'ID': ioc_id, 'Type': ioc_type, 'Value': value, 'Process': {'DeviceID': device_id, 'ID': proc_ids}}
    hr = tableToMarkdown(f"Processes with custom IOC {ioc_id} on device {device_id}.", proc_ids, headers="Process ID")
    return create_entry_object(contents=raw_res, hr=hr, ec={'CrowdStrike.IOC(val.ID === obj.ID)': context})


def search_device_command():
    """
        Searches for a device
        :return: EntryObject of search device command
    """
    raw_res = search_device()
    if not raw_res:
        return create_entry_object(hr='Could not find any devices.')
    devices = raw_res.get('resources')

    command_results = []
    for single_device in devices:
        status, is_isolated = generate_status_fields(single_device.get('status'))
        endpoint = Common.Endpoint(
            id=single_device.get('device_id'),
            hostname=single_device.get('hostname'),
            ip_address=single_device.get('local_ip'),
            os=single_device.get('platform_name'),
            os_version=single_device.get('os_version'),
            status=status,
            is_isolated=is_isolated,
            mac_address=single_device.get('mac_address'),
            vendor=INTEGRATION_NAME)

        entry = get_trasnformed_dict(single_device, SEARCH_DEVICE_KEY_MAP)
        headers = ['ID', 'Hostname', 'OS', 'MacAddress', 'LocalIP', 'ExternalIP', 'FirstSeen', 'LastSeen', 'Status']

        command_results.append(CommandResults(
            outputs_prefix='CrowdStrike.Device',
            outputs_key_field='ID',
            outputs=entry,
            readable_output=tableToMarkdown('Devices', entry, headers=headers, headerTransform=pascalToSpace),
            raw_response=raw_res,
            indicator=endpoint,
        ))

    return command_results


def search_device_by_ip(raw_res, ip_address):
    devices = raw_res.get('resources')
    filtered_devices = []
    for single_device in devices:
        if single_device.get('local_ip') == ip_address:
            filtered_devices.append(single_device)

    if filtered_devices:
        raw_res['resources'] = filtered_devices
    else:
        raw_res = None
    return raw_res


def generate_status_fields(endpoint_status):
    status = ''
    is_isolated = ''

    if endpoint_status.lower() == 'normal':
        status = 'Online'
    elif endpoint_status == 'containment_pending':
        is_isolated = 'Pending isolation'
    elif endpoint_status == 'contained':
        is_isolated = 'Yes'
    elif endpoint_status == 'lift_containment_pending':
        is_isolated = 'Pending unisolation'
    else:
        raise DemistoException(f'Error: Unknown endpoint status was given: {endpoint_status}')
    return status, is_isolated


def generate_endpoint_by_contex_standard(devices):
    standard_endpoints = []
    for single_device in devices:
        status, is_isolated = generate_status_fields(single_device.get('status'))
        endpoint = Common.Endpoint(
            id=single_device.get('device_id'),
            hostname=single_device.get('hostname'),
            ip_address=single_device.get('local_ip'),
            os=single_device.get('platform_name'),
            os_version=single_device.get('os_version'),
            status=status,
            is_isolated=is_isolated,
            mac_address=single_device.get('mac_address'),
            vendor=INTEGRATION_NAME)
        standard_endpoints.append(endpoint)
    return standard_endpoints


def get_endpoint_command():
    args = demisto.args()
    if 'id' in args.keys():
        args['ids'] = args.get('id', '')

    # handles the search by id or by hostname
    raw_res = search_device()

    if ip := args.get('ip') and raw_res:
        # there is no option to filter by ip in an api call, therefore we would filter the devices in the code
        raw_res = search_device_by_ip(raw_res, ip)

    if not ip and not args.get('id') and not args.get('hostname'):
        # in order not to return all the devices
        return create_entry_object(hr='Please add a filter argument - ip, hostname or id.')

    if not raw_res:
        return create_entry_object(hr='Could not find any devices.')
    devices = raw_res.get('resources')

    standard_endpoints = generate_endpoint_by_contex_standard(devices)

    command_results = []
    for endpoint in standard_endpoints:
        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        hr = tableToMarkdown('CrowdStrike Falcon Endpoint', endpoint_context)

        command_results.append(CommandResults(
            readable_output=hr,
            raw_response=raw_res,
            indicator=endpoint
        ))
    return command_results


def get_behavior_command():
    """
        Gets a behavior by ID
        :return: EntryObject of get behavior command
    """
    behavior_id = demisto.args().get('behavior_id')
    detections_ids = demisto.get(get_detections(behavior_id=behavior_id), 'resources')
    raw_res = get_detections_entities(detections_ids)
    entries = []
    if "resources" in raw_res:
        for resource in demisto.get(raw_res, "resources"):
            for behavior in demisto.get(resource, 'behaviors'):
                entries.append(behavior_to_entry_context(behavior))
    hr = tableToMarkdown('Behavior ID: {}'.format(behavior_id), entries, headerTransform=pascalToSpace)
    # no dt since behavior vary by more than their ID
    ec = {'CrowdStrike.Behavior': entries}
    return create_entry_object(contents=raw_res, ec=ec, hr=hr)


def search_detections_command():
    """
        Searches for a detection
        :return: EntryObject of search detections command
    """
    d_args = demisto.args()
    detections_ids = argToList(d_args.get('ids'))
    extended_data = argToBoolean(d_args.get('extended_data', False))
    if not detections_ids:
        filter_arg = d_args.get('filter')
        if not filter_arg:
            return_error('Command Error: Please provide at least one argument.')
        detections_ids = get_detections(filter_arg=filter_arg).get('resources')
    raw_res = get_detections_entities(detections_ids)
    entries = []
    headers = ['ID', 'Status', 'System', 'ProcessStartTime', 'CustomerID', 'MaxSeverity']
    if "resources" in raw_res:
        for detection in demisto.get(raw_res, "resources"):
            detection_entry = {}

            for path, new_key in DETECTIONS_BASE_KEY_MAP.items():
                detection_entry[new_key] = demisto.get(detection, path)
            behaviors = []

            for behavior in demisto.get(detection, 'behaviors'):
                behaviors.append(behavior_to_entry_context(behavior))
            detection_entry['Behavior'] = behaviors

            if extended_data:
                detection_entry['Device'] = demisto.get(detection, 'device')
                detection_entry['BehaviorsProcessed'] = demisto.get(detection, 'behaviors_processed')

            entries.append(detection_entry)

    hr = tableToMarkdown('Detections Found:', entries, headers=headers, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(readable_output=hr,
                          outputs=entries,
                          outputs_key_field='ID',
                          outputs_prefix='CrowdStrike.Detection',
                          raw_response=raw_res)


def resolve_detection_command():
    """
        Resolves single or multiple detections
        :return: EntryObject of resolve detection command
    """
    args = demisto.args()
    ids = argToList(args.get('ids'))
    username = args.get('username')
    assigned_to_uuid = args.get('assigned_to_uuid')
    comment = args.get('comment')
    if username and assigned_to_uuid:
        raise ValueError('Only one of the arguments assigned_to_uuid or username should be provided, not both.')
    if username:
        assigned_to_uuid = get_username_uuid(username)

    status = args.get('status')
    show_in_ui = args.get('show_in_ui')
    if not (username or assigned_to_uuid or comment or status or show_in_ui):
        raise DemistoException("Please provide at least one argument to resolve the detection with.")
    raw_res = resolve_detection(ids, status, assigned_to_uuid, show_in_ui, comment)
    args.pop('ids')
    hr = "Detection {0} updated\n".format(str(ids)[1:-1])
    hr += 'With the following values:\n'
    for k, arg in args.items():
        hr += '\t{name}:{val}\n'.format(name=k, val=arg)
    return create_entry_object(contents=raw_res, hr=hr)


def contain_host_command():
    """
        Contains hosts with user arg ids
        :return: EntryObject of contain host command
    """
    ids = argToList(demisto.args().get('ids'))
    raw_res = contain_host(ids)
    hr = "Host {} contained".format(str(ids)[1:-1])
    return create_entry_object(contents=raw_res, hr=hr)


def lift_host_containment_command():
    """
        Lifts containment off a host
        :return: EntryObject of lift host containment
    """
    ids = argToList(demisto.args().get('ids'))
    raw_res = lift_host_containment(ids)
    hr = "Containment has been lift off host {}".format(str(ids)[1:-1])
    return create_entry_object(contents=raw_res, hr=hr)


def run_command():
    args = demisto.args()
    host_ids = argToList(args.get('host_ids'))
    command_type = args.get('command_type')
    full_command = args.get('full_command')
    scope = args.get('scope', 'read')
    target = args.get('target', 'batch')

    output = []

    if target == 'batch':
        batch_id = init_rtr_batch_session(host_ids)
        timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
        timer.start()
        try:
            if scope == 'read':
                response = run_batch_read_cmd(batch_id, command_type, full_command)
            elif scope == 'write':
                response = run_batch_write_cmd(batch_id, command_type, full_command)
            else:  # scope = admin
                response = run_batch_admin_cmd(batch_id, command_type, full_command)
        finally:
            timer.cancel()

        resources: dict = response.get('combined', {}).get('resources', {})

        for _, resource in resources.items():
            errors = resource.get('errors', [])
            if errors:
                error_message = errors[0].get('message', '')
                if not error_message:
                    error_message = f'Could not run command\n{errors}'
                return_error(error_message)
            output.append({
                'HostID': resource.get('aid'),
                'SessionID': resource.get('session_id'),
                'Stdout': resource.get('stdout'),
                'Stderr': resource.get('stderr'),
                'BaseCommand': resource.get('base_command'),
                'Command': full_command
            })

        human_readable = tableToMarkdown(f'Command {full_command} results', output, removeNull=True)
        entry_context_batch = {
            'CrowdStrike': {
                'Command': output
            }
        }
        return create_entry_object(contents=response, ec=entry_context_batch, hr=human_readable)
    else:  # target = 'single'
        responses = []
        for host_id in host_ids:
            if scope == 'read':
                response1 = run_single_read_cmd(host_id, command_type, full_command)
            elif scope == 'write':
                response1 = run_single_write_cmd(host_id, command_type, full_command)
            else:  # scope = admin
                response1 = run_single_admin_cmd(host_id, command_type, full_command)
            responses.append(response1)

            for resource in response1.get('resources', []):
                errors = resource.get('errors', [])
                if errors:
                    error_message = errors[0].get('message', '')
                    if not error_message:
                        error_message = f'Could not run command\n{errors}'
                    return_error(error_message)
                output.append({
                    'HostID': host_id,
                    'TaskID': resource.get('cloud_request_id'),
                    'SessionID': resource.get('session_id'),
                    'BaseCommand': command_type,
                    'Command': full_command,
                    'Complete': False,
                    'NextSequenceID': 0
                })

        human_readable = tableToMarkdown(f'Command {full_command} results', output, removeNull=True)
        entry_context_single = {
            'CrowdStrike.Command(val.TaskID === obj.TaskID)': output
        }
        return create_entry_object(contents=responses, ec=entry_context_single, hr=human_readable)


def upload_script_command():
    args = demisto.args()
    name = args.get('name')
    permission_type = args.get('permission_type', 'private')
    content = args.get('content')
    entry_id = args.get('entry_id')

    if content and entry_id:
        raise ValueError('Only one of the arguments entry_id or content should be provided, not both.')
    elif not content and not entry_id:
        raise ValueError('One of the arguments entry_id or content must be provided, none given.')

    response = upload_script(name, permission_type, content, entry_id)

    return create_entry_object(contents=response, hr='The script was uploaded successfully')


def get_script_command():
    script_id = argToList(demisto.args().get('script_id'))

    response = get_script(script_id)

    resources: list = response.get('resources', [])
    if resources and isinstance(resources, list):
        resource = resources[0]
        script = {
            'ID': resource.get('id'),
            'CreatedBy': resource.get('created_by'),
            'CreatedTime': resource.get('created_timestamp'),
            'Description': resource.get('description'),
            'ModifiedBy': resource.get('modified_by'),
            'ModifiedTime': resource.get('modified_timestamp'),
            'Name': resource.get('name'),
            'Permission': resource.get('permission_type'),
            'SHA256': resource.get('sha256'),
            'RunAttemptCount': resource.get('run_attempt_count'),
            'RunSuccessCount': resource.get('run_success_count'),
            'WriteAccess': resource.get('write_access')
        }

        human_readable = tableToMarkdown(f'CrowdStrike Falcon script {script_id}', script)

        entry_context = {
            'CrowdStrike.Script(val.ID === obj.ID)': script
        }

        script_content = resource.get('content')
        if script_content:
            demisto.results(
                fileResult(
                    f"{resource.get('name', 'script')}.ps1",
                    script_content
                )
            )

        return create_entry_object(contents=response, ec=entry_context, hr=human_readable)
    else:
        return 'No script found.'


def delete_script_command():
    script_id = demisto.args().get('script_id')

    response = delete_script(script_id)

    return create_entry_object(contents=response, hr=f'Script {script_id} was deleted successfully')


def list_scripts_command():
    response = list_scripts()

    resources: list = response.get('resources', [])

    scripts = []

    for resource in resources:
        scripts.append({
            'ID': resource.get('id'),
            'CreatedBy': resource.get('created_by'),
            'CreatedTime': resource.get('created_timestamp'),
            'Description': resource.get('description'),
            'ModifiedBy': resource.get('modified_by'),
            'ModifiedTime': resource.get('modified_timestamp'),
            'Name': resource.get('name'),
            'Permission': resource.get('permission_type'),
            'SHA256': resource.get('sha256'),
            'RunAttemptCount': resource.get('run_attempt_count'),
            'RunSuccessCount': resource.get('run_success_count'),
            'Platform': resource.get('platform'),
            'WriteAccess': resource.get('write_access')
        })

    human_readable = tableToMarkdown('CrowdStrike Falcon scripts', scripts)

    entry_context = {
        'CrowdStrike.Script(val.ID === obj.ID)': scripts
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def upload_file_command():
    entry_id = demisto.args().get('entry_id')
    description = demisto.args().get('description', 'File uploaded from Demisto')

    response, file_name = upload_file(entry_id, description)

    return create_entry_object(contents=response, hr='File was uploaded successfully')


def delete_file_command():
    file_id = demisto.args().get('file_id')

    response = delete_file(file_id)

    return create_entry_object(contents=response, hr=f'File {file_id} was deleted successfully')


def get_file_command():
    file_id = argToList(demisto.args().get('file_id'))

    response = get_file(file_id)

    resources: list = response.get('resources', [])
    if resources and isinstance(resources, list):
        # will always be a list of one resource
        resource = resources[0]
        file_ = {
            'ID': resource.get('id'),
            'CreatedBy': resource.get('created_by'),
            'CreatedTime': resource.get('created_timestamp'),
            'Description': resource.get('description'),
            'Type': resource.get('file_type'),
            'ModifiedBy': resource.get('modified_by'),
            'ModifiedTime': resource.get('modified_timestamp'),
            'Name': resource.get('name'),
            'Permission': resource.get('permission_type'),
            'SHA256': resource.get('sha256'),
        }
        file_standard_context = {
            'Type': resource.get('file_type'),
            'Name': resource.get('name'),
            'SHA256': resource.get('sha256'),
            'Size': resource.get('size'),
        }

        human_readable = tableToMarkdown(f'CrowdStrike Falcon file {file_id}', file_)

        entry_context = {
            'CrowdStrike.File(val.ID === obj.ID)': file_,
            outputPaths['file']: file_standard_context
        }

        file_content = resource.get('content')
        if file_content:
            demisto.results(
                fileResult(
                    resource.get('name'),
                    file_content
                )
            )

        return create_entry_object(contents=response, ec=entry_context, hr=human_readable)
    else:
        return 'No file found.'


def list_files_command():
    response = list_files()

    resources: list = response.get('resources', [])

    files_output = []
    file_standard_context = []

    for resource in resources:
        files_output.append({
            'ID': resource.get('id'),
            'CreatedBy': resource.get('created_by'),
            'CreatedTime': resource.get('created_timestamp'),
            'Description': resource.get('description'),
            'Type': resource.get('file_type'),
            'ModifiedBy': resource.get('modified_by'),
            'ModifiedTime': resource.get('modified_timestamp'),
            'Name': resource.get('name'),
            'Permission': resource.get('permission_type'),
            'SHA256': resource.get('sha256'),
        })
        file_standard_context.append({
            'Type': resource.get('file_type'),
            'Name': resource.get('name'),
            'SHA256': resource.get('sha256'),
            'Size': resource.get('size'),
        })

    human_readable = tableToMarkdown('CrowdStrike Falcon files', files_output)

    entry_context = {
        'CrowdStrike.File(val.ID === obj.ID)': files_output,
        outputPaths['file']: file_standard_context
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def run_script_command():
    args = demisto.args()
    script_name = args.get('script_name')
    raw = args.get('raw')
    host_ids = argToList(args.get('host_ids'))
    try:
        timeout = int(args.get('timeout', 30))
    except ValueError as e:
        demisto.error(str(e))
        raise ValueError('Timeout argument should be an integer, for example: 30')

    if script_name and raw:
        raise ValueError('Only one of the arguments script_name or raw should be provided, not both.')
    elif not script_name and not raw:
        raise ValueError('One of the arguments script_name or raw must be provided, none given.')
    elif script_name:
        full_command = f'runscript -CloudFile={script_name}'
    elif raw:
        full_command = f'runscript -Raw=```{raw}```'
    full_command += f' -Timeout={timeout}'

    command_type = 'runscript'

    batch_id = init_rtr_batch_session(host_ids)
    timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
    timer.start()
    try:
        response = run_batch_admin_cmd(batch_id, command_type, full_command, timeout)
    finally:
        timer.cancel()

    resources: dict = response.get('combined', {}).get('resources', {})

    output = []

    for _, resource in resources.items():
        errors = resource.get('errors', [])
        if errors:
            error_message = errors[0].get('message', '')
            if not error_message:
                error_message = f'Could not run command\n{errors}'
            return_error(error_message)
        full_command = full_command.replace('`', '')
        output.append({
            'HostID': resource.get('aid'),
            'SessionID': resource.get('session_id'),
            'Stdout': resource.get('stdout'),
            'Stderr': resource.get('stderr'),
            'BaseCommand': resource.get('base_command'),
            'Command': full_command
        })

    human_readable = tableToMarkdown(f'Command {full_command} results', output)
    entry_context = {
        'CrowdStrike': {
            'Command': output
        }
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def run_get_command(is_polling=False):
    request_ids_for_polling = []
    args = demisto.args()
    host_ids = argToList(args.get('host_ids'))
    file_path = args.get('file_path')
    optional_hosts = argToList(args.get('optional_hosts'))
    timeout = args.get('timeout')
    timeout_duration = args.get('timeout_duration')

    timeout = timeout and int(timeout)
    response = run_batch_get_cmd(host_ids, file_path, optional_hosts, timeout, timeout_duration)

    resources: dict = response.get('combined', {}).get('resources', {})

    output = []

    for _, resource in resources.items():
        errors = resource.get('errors', [])
        if errors:
            error_message = errors[0].get('message', '')
            if not error_message:
                error_message = f'Could not get command\n{errors}'
            return_error(error_message)
        output.append({
            'HostID': resource.get('aid'),
            'Stdout': resource.get('stdout'),
            'Stderr': resource.get('stderr'),
            'BaseCommand': resource.get('base_command'),
            'TaskID': resource.get('task_id'),
            'GetRequestID': response.get('batch_get_cmd_req_id'),
            'Complete': resource.get('complete') or False,
            'FilePath': file_path
        })
        request_ids_for_polling.append(
            {'RequestID': response.get('batch_get_cmd_req_id'),
             'HostID': resource.get('aid'), })

    if is_polling:
        return request_ids_for_polling

    human_readable = tableToMarkdown(f'Get command has requested for a file {file_path}', output)
    entry_context = {
        'CrowdStrike.Command(val.TaskID === obj.TaskID)': output
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def status_get_command(args, is_polling=False):
    request_ids_for_polling = {}
    request_ids = argToList(args.get('request_ids'))
    timeout = args.get('timeout')
    timeout_duration = args.get('timeout_duration')

    timeout = timeout and int(timeout)

    responses = []
    files_output = []
    file_standard_context = []

    sha256 = ""  # Used for the polling. When this isn't empty it indicates that the status is "ready".
    for request_id in request_ids:
        response = status_get_cmd(request_id, timeout, timeout_duration)
        responses.append(response)

        resources: dict = response.get('resources', {})

        for host_id, resource in resources.items():
            errors = resource.get('errors', [])
            if errors:
                error_message = errors[0].get('message', '')
                if not error_message:
                    error_message = f'Could not get command\n{errors}'
                return_error(error_message)
            files_output.append({
                'ID': resource.get('id'),
                'TaskID': resource.get('cloud_request_id'),
                'CreatedAt': resource.get('created_at'),
                'DeletedAt': resource.get('deleted_at'),
                'UpdatedAt': resource.get('updated_at'),
                'Name': resource.get('name'),
                'Size': resource.get('size'),
                'SHA256': resource.get('sha256')
            })
            file_standard_context.append({
                'Name': resource.get('name'),
                'SHA256': resource.get('sha256'),
                'Size': resource.get('size'),
            })
            sha256 = resource.get('sha256', '')
            request_ids_for_polling[host_id] = {'SHA256': sha256}

    if is_polling:
        args['SHA256'] = sha256
        return request_ids_for_polling, args

    human_readable = tableToMarkdown('CrowdStrike Falcon files', files_output)
    entry_context = {
        'CrowdStrike.File(val.ID === obj.ID || val.TaskID === obj.TaskID)': files_output,
        outputPaths['file']: file_standard_context
    }
    if len(responses) == 1:
        return create_entry_object(contents=responses[0], ec=entry_context, hr=human_readable)
    else:
        return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def status_command():
    args = demisto.args()
    request_id = args.get('request_id')
    sequence_id = args.get('sequence_id')
    scope = args.get('scope', 'read')

    sequence_id = None if sequence_id is None else int(sequence_id)

    if scope == 'read':
        response = status_read_cmd(request_id, sequence_id)
    elif scope == 'write':
        response = status_write_cmd(request_id, sequence_id)
    else:  # scope = admin
        response = status_admin_cmd(request_id, sequence_id)

    resources: list = response.get('resources', [])

    output = []

    for resource in resources:
        errors = resource.get('errors', [])
        if errors:
            error_message = errors[0].get('message', '')
            if not error_message:
                error_message = f'Could not run command\n{errors}'
            return_error(error_message)

        sequence_id = int(resource.get('sequence_id', 0))
        output.append({
            'Complete': resource.get('complete') or False,
            'Stdout': resource.get('stdout'),
            'Stderr': resource.get('stderr'),
            'BaseCommand': resource.get('base_command'),
            'TaskID': resource.get('task_id'),
            'SequenceID': sequence_id,
            'NextSequenceID': sequence_id + 1
        })

    human_readable = tableToMarkdown('Command status results', output, removeNull=True)
    entry_context = {
        'CrowdStrike.Command(val.TaskID === obj.TaskID)': output
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def get_extracted_file_command(args):
    host_id = args.get('host_id')
    sha256 = args.get('sha256')
    filename = args.get('filename')

    response = get_extracted_file(host_id, sha256, filename)

    # save an extracted file
    content_type = response.headers.get('Content-Type', '').lower()
    if content_type == 'application/x-7z-compressed':
        content_disposition = response.headers.get('Content-Disposition', '').lower()
        if content_disposition:
            filename = email.message_from_string(f'Content-Disposition: {content_disposition}\n\n').get_filename()

        if not filename:
            sha256 = sha256 or hashlib.sha256(response.content).hexdigest()
            filename = sha256.lower() + '.7z'

        return fileResult(filename, response.content)

    return_error('An extracted file is missing in the response')


def list_host_files_command():
    args = demisto.args()
    host_id = args.get('host_id')

    response = list_host_files(host_id)
    resources: list = response.get('resources', [])

    files_output = []
    file_standard_context = []
    command_output = []

    for resource in resources:
        errors = resource.get('errors', [])
        if errors:
            error_message = errors[0].get('message', '')
            if not error_message:
                error_message = f'Could not run command\n{errors}'
            return_error(error_message)
        command_output.append({
            'HostID': host_id,
            'TaskID': resource.get('cloud_request_id'),
            'SessionID': resource.get('session_id')
        })
        files_output.append({
            'ID': resource.get('id'),
            'CreatedAt': resource.get('created_at'),
            'DeletedAt': resource.get('deleted_at'),
            'UpdatedAt': resource.get('updated_at'),
            'Name': resource.get('name'),
            'SHA256': resource.get('sha256'),
            'Size': resource.get('size'),
            'Stdout': resource.get('stdout'),
            'Stderr': resource.get('stderr')
        })
        file_standard_context.append({
            'Name': resource.get('name'),
            'SHA256': resource.get('sha256'),
            'Size': resource.get('size'),
        })

    if files_output:
        human_readable = tableToMarkdown('CrowdStrike Falcon files', files_output)
    else:
        human_readable = 'No result found'

    entry_context = {
        'CrowdStrike.Command(val.TaskID === obj.TaskID)': command_output,
        'CrowdStrike.File(val.ID === obj.ID)': files_output,
        outputPaths['file']: file_standard_context
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def refresh_session_command():
    args = demisto.args()
    host_id = args.get('host_id')

    response = refresh_session(host_id)
    resources: list = response.get('resources', [])

    session_id = None
    for resource in resources:
        errors = resource.get('errors', [])
        if errors:
            error_message = errors[0].get('message', '')
            if not error_message:
                error_message = f'Could not run command\n{errors}'
            return_error(error_message)
        session_id = resource.get('session_id')

    return create_entry_object(contents=response, hr=f'CrowdStrike Session Refreshed: {session_id}')


def build_error_message(raw_res):
    if raw_res.get('errors'):
        error_data = raw_res.get('errors')[0]
    else:
        error_data = {"code": 'None', "message": 'something got wrong, please try again'}
    error_code = error_data.get('code')
    error_message = error_data.get('message')
    return f'Error: error code: {error_code}, error_message: {error_message}.'


def validate_response(raw_res):
    return 'resources' in raw_res.keys()


def get_indicator_device_id():
    args = demisto.args()
    ioc_type = args.get('type')
    ioc_value = args.get('value')
    params = assign_params(
        type=ioc_type,
        value=ioc_value
    )
    raw_res = http_request('GET', '/indicators/queries/devices/v1', params=params, status_code=404)
    errors = raw_res.get('errors', [])
    for error in errors:
        if error.get('code') == 404:
            return f'No results found for {ioc_type} - {ioc_value}'
    context_output = ''
    if validate_response(raw_res):
        context_output = raw_res.get('resources')
    else:
        error_message = build_error_message(raw_res)
        return_error(error_message)
    ioc_id = f"{ioc_type}:{ioc_value}"
    readable_output = tableToMarkdown(f"Devices that encountered the IOC {ioc_id}", context_output, headers='Device ID')
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CrowdStrike.DeviceID',
        outputs_key_field='DeviceID',
        outputs=context_output,
        raw_response=raw_res
    )


def detections_to_human_readable(detections):
    detections_readable_outputs = []
    for detection in detections:
        readable_output = assign_params(status=detection.get('status'),
                                        max_severity=detection.get('max_severity_displayname'),
                                        detection_id=detection.get('detection_id'),
                                        created_time=detection.get('created_timestamp'))
        detections_readable_outputs.append(readable_output)
    headers = ['detection_id', 'created_time', 'status', 'max_severity']
    human_readable = tableToMarkdown('CrowdStrike Detections', detections_readable_outputs, headers, removeNull=True)
    return human_readable


def list_detection_summaries_command():
    args = demisto.args()
    fetch_query = args.get('fetch_query')

    args_ids = args.get('ids')
    if args_ids:
        detections_ids = argToList(args_ids)
    elif fetch_query:
        fetch_query = "{query}".format(query=fetch_query)
        detections_ids = demisto.get(get_fetch_detections(filter_arg=fetch_query), 'resources')
    else:
        detections_ids = demisto.get(get_fetch_detections(), 'resources')
    detections_response_data = get_detections_entities(detections_ids)
    detections = [resource for resource in detections_response_data.get('resources')]
    detections_human_readable = detections_to_human_readable(detections)

    return CommandResults(
        readable_output=detections_human_readable,
        outputs_prefix='CrowdStrike.Detections',
        outputs_key_field='detection_id',
        outputs=detections
    )


def incidents_to_human_readable(incidents):
    incidents_readable_outputs = []
    for incident in incidents:
        readable_output = assign_params(description=incident.get('description'), state=incident.get('state'),
                                        name=incident.get('name'), tags=incident.get('tags'),
                                        incident_id=incident.get('incident_id'), created_time=incident.get('created'),
                                        status=STATUS_NUM_TO_TEXT.get(incident.get('status')))
        incidents_readable_outputs.append(readable_output)
    headers = ['incident_id', 'created_time', 'name', 'description', 'status', 'state', 'tags']
    human_readable = tableToMarkdown('CrowdStrike Incidents', incidents_readable_outputs, headers, removeNull=True)
    return human_readable


def list_incident_summaries_command():
    args = demisto.args()
    fetch_query = args.get('fetch_query')

    args_ids = args.get('ids')
    if args_ids:
        ids = argToList(args_ids)
    else:
        if fetch_query:
            fetch_query = "{query}".format(query=fetch_query)
            incidents_ids = get_incidents_ids(filter_arg=fetch_query)
        else:
            incidents_ids = get_incidents_ids()
        handle_response_errors(incidents_ids)
        ids = incidents_ids.get('resources')
    if not ids:
        return CommandResults(readable_output='No incidents were found.')
    incidents_response_data = get_incidents_entities(ids)
    incidents = [resource for resource in incidents_response_data.get('resources')]
    incidents_human_readable = incidents_to_human_readable(incidents)
    return CommandResults(
        readable_output=incidents_human_readable,
        outputs_prefix='CrowdStrike.Incidents',
        outputs_key_field='incident_id',
        outputs=incidents
    )


def create_host_group_command(name: str,
                              group_type: str = None,
                              description: str = None,
                              assignment_rule: str = None) -> CommandResults:
    response = change_host_group(is_post=True,
                                 name=name,
                                 group_type=group_type,
                                 description=description,
                                 assignment_rule=assignment_rule)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def update_host_group_command(host_group_id: str,
                              name: Optional[str] = None,
                              description: Optional[str] = None,
                              assignment_rule: Optional[str] = None) -> CommandResults:
    response = change_host_group(is_post=False,
                                 host_group_id=host_group_id,
                                 name=name,
                                 description=description,
                                 assignment_rule=assignment_rule)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def list_host_group_members_command(host_group_id: Optional[str] = None,
                                    filter: Optional[str] = None,
                                    offset: Optional[str] = None,
                                    limit: Optional[str] = None) -> CommandResults:
    response = host_group_members(filter, host_group_id, limit, offset)
    devices = response.get('resources')
    if not devices:
        return CommandResults(readable_output='No hosts are found',
                              raw_response=response)
    headers = list(SEARCH_DEVICE_KEY_MAP.values())
    outputs = [get_trasnformed_dict(single_device, SEARCH_DEVICE_KEY_MAP) for single_device in devices]
    return CommandResults(
        outputs_prefix='CrowdStrike.Device',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Devices', outputs, headers=headers, headerTransform=pascalToSpace),
        raw_response=response
    )


def add_host_group_members_command(host_group_id: str, host_ids: List[str]) -> CommandResults:
    response = change_host_group_members(action_name='add-hosts',
                                         host_group_id=host_group_id,
                                         host_ids=host_ids)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def remove_host_group_members_command(host_group_id: str, host_ids: List[str]) -> CommandResults:
    response = change_host_group_members(action_name='remove-hosts',
                                         host_group_id=host_group_id,
                                         host_ids=host_ids)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def resolve_incident_command(ids: List[str], status: str):
    resolve_incident(ids, status)
    readable = '\n'.join([f'{incident_id} changed successfully to {status}' for incident_id in ids])
    return CommandResults(readable_output=readable)


def list_host_groups_command(filter: Optional[str] = None, offset: Optional[str] = None, limit: Optional[str] = None) \
        -> CommandResults:
    response = list_host_groups(filter, limit, offset)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def delete_host_groups_command(host_group_ids: List[str]) -> CommandResults:
    response = delete_host_groups(host_group_ids)
    deleted_ids = response.get('resources')
    readable = '\n'.join([f'Host groups {host_group_id} deleted successfully' for host_group_id in deleted_ids]) \
        if deleted_ids else f'Host groups {host_group_ids} are not deleted'
    return CommandResults(readable_output=readable,
                          raw_response=response)


def upload_batch_custom_ioc_command(
        multiple_indicators_json: str = None,
) -> List[dict]:
    """
    :param multiple_indicators_json: A JSON object with list of CS Falcon indicators to upload.

    """
    batch_json = safe_load_json(multiple_indicators_json)
    raw_res = upload_batch_custom_ioc(batch_json)
    handle_response_errors(raw_res)
    iocs = raw_res.get('resources', [])
    entry_objects_list = []
    for ioc in iocs:
        ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP)]
        entry_objects_list.append(create_entry_object(
            contents=raw_res,
            ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
            hr=tableToMarkdown(f"Custom IOC {ioc['value']} was created successfully", ec),
        ))
    return entry_objects_list


def test_module():
    try:
        get_token(new_token=True)
    except ValueError:
        return 'Connection Error: The URL or The API key you entered is probably incorrect, please try again.'
    if demisto.params().get('isFetch'):
        try:
            fetch_incidents()
        except ValueError:
            return 'Error: Something is wrong with the filters you entered for the fetch incident, please try again.'
    return 'ok'


def rtr_kill_process_command(args: dict) -> CommandResults:
    host_id = args.get('host_id')
    process_ids = remove_duplicates_from_list_arg(args, 'process_ids')
    command_type = "kill"
    raw_response = []
    host_ids = [host_id]
    batch_id = init_rtr_batch_session(host_ids)
    outputs = []

    for process_id in process_ids:
        full_command = f"{command_type} {process_id}"
        response = execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command)
        outputs.extend(parse_rtr_command_response(response, host_ids, process_id=process_id))
        raw_response.append(response)

    human_readable = tableToMarkdown(
        f'{INTEGRATION_NAME} {command_type} command on host {host_id}:', outputs, headers=["ProcessID", "Error"])
    human_readable += get_human_readable_for_failed_command(outputs, process_ids, "ProcessID")
    return CommandResults(raw_response=raw_response, readable_output=human_readable, outputs=outputs,
                          outputs_prefix="CrowdStrike.Command.kill", outputs_key_field="ProcessID")


def get_human_readable_for_failed_command(outputs, required_elements, element_id):
    failed_elements = {}
    for output in outputs:
        if output.get('Error') != 'Success':
            failed_elements[output.get(element_id)] = output.get('Error')
    return add_error_message(failed_hosts=failed_elements, all_requested_hosts=required_elements)


def parse_rtr_command_response(response, host_ids, process_id=None) -> list:
    outputs = []
    resources: dict = response.get('combined', {}).get('resources', {})

    for host_id, host_data in resources.items():
        current_error = ""
        errors = host_data.get('errors')  # API errors
        stderr = host_data.get('stderr')  # host command error (as path does not exist and more)
        command_failed_with_error = errors or stderr  # API errors are "stronger" that host stderr
        if command_failed_with_error:
            if errors:
                current_error = errors[0].get('message', '')
            elif stderr:
                current_error = stderr
        outputs_data = {'HostID': host_id, 'Error': current_error if current_error else "Success", }
        if process_id:
            outputs_data.update({'ProcessID': process_id})

        outputs.append(outputs_data)

    found_host_ids = {host.get('HostID') for host in outputs}
    not_found_host_ids = set(host_ids) - found_host_ids

    for not_found_host in not_found_host_ids:
        outputs.append({
            'HostID': not_found_host,
            'Error': "The host ID was not found.",
        })
    return outputs


def match_remove_command_for_os(operating_system, file_path):
    if operating_system == 'Windows':
        return f'rm {file_path} --force'
    elif operating_system == 'Linux' or operating_system == 'Mac':
        return f'rm {file_path} -r -d'
    else:
        return ""


def rtr_remove_file_command(args: dict) -> CommandResults:
    file_path = args.get('file_path')
    host_ids = remove_duplicates_from_list_arg(args, 'host_ids')
    operating_system = args.get('os')
    full_command = match_remove_command_for_os(operating_system, file_path)
    command_type = "rm"

    batch_id = init_rtr_batch_session(host_ids)
    response = execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, host_ids)
    outputs = parse_rtr_command_response(response, host_ids)
    human_readable = tableToMarkdown(
        f'{INTEGRATION_NAME} {command_type} over the file: {file_path}', outputs, headers=["HostID", "Error"])
    human_readable += get_human_readable_for_failed_command(outputs, host_ids, "HostID")
    return CommandResults(raw_response=response, readable_output=human_readable, outputs=outputs,
                          outputs_prefix="CrowdStrike.Command.rm", outputs_key_field="HostID")


def execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, host_ids=None):
    """
    Executes a timer for keeping the session refreshed
    """
    timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
    timer.start()
    try:
        response = run_batch_write_cmd(batch_id, command_type=command_type, full_command=full_command,
                                       optional_hosts=host_ids)
    finally:
        timer.cancel()
    return response


def execute_run_batch_admin_cmd_with_timer(batch_id, command_type, full_command, host_ids=None):
    timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
    timer.start()
    try:
        response = run_batch_admin_cmd(batch_id, command_type=command_type, full_command=full_command,
                                       optional_hosts=host_ids)
    finally:
        timer.cancel()
    return response


def rtr_general_command_on_hosts(host_ids: list, command: str, full_command: str, get_session_function: Callable,
                                 write_to_context=True) -> \
        list[CommandResults, dict]:  # type:ignore
    """
    General function to run RTR commands depending on the given command.
    """
    batch_id = init_rtr_batch_session(host_ids)
    response = get_session_function(batch_id, command_type=command, full_command=full_command,
                                    host_ids=host_ids)  # type:ignore
    output, file, not_found_hosts = parse_rtr_stdout_response(host_ids, response, command)

    human_readable = tableToMarkdown(
        f'{INTEGRATION_NAME} {command} command on host {host_ids[0]}:', output, headers="Stdout")
    human_readable += add_error_message(not_found_hosts, host_ids)

    if write_to_context:
        outputs = {"Filename": file[0].get('File')}
        return [CommandResults(raw_response=response, readable_output=human_readable, outputs=outputs,
                               outputs_prefix=f"CrowdStrike.Command.{command}",
                               outputs_key_field="Filename"), file]

    return [CommandResults(raw_response=response, readable_output=human_readable), file]


def parse_rtr_stdout_response(host_ids, response, command, file_name_suffix=""):
    resources: dict = response.get('combined', {}).get('resources', {})
    outputs = []
    files = []

    for host_id, resource in resources.items():
        current_error = ""
        errors = resource.get('errors')
        stderr = resource.get('stderr')
        command_failed_with_error = errors or stderr
        if command_failed_with_error:
            if errors:
                current_error = errors[0].get('message', '')
            elif stderr:
                current_error = stderr
            return_error(current_error)
        stdout = resource.get('stdout', "")
        file_name = f"{command}-{host_id}{file_name_suffix}"
        outputs.append({'Stdout': stdout, "FileName": file_name})
        files.append(fileResult(file_name, stdout))

    not_found_hosts = set(host_ids) - resources.keys()
    return outputs, files, not_found_hosts


def rtr_read_registry_keys_command(args: dict):
    host_ids = remove_duplicates_from_list_arg(args, 'host_ids')
    registry_keys = remove_duplicates_from_list_arg(args, 'registry_keys')
    command_type = "reg"
    raw_response = []
    batch_id = init_rtr_batch_session(host_ids)
    outputs = []
    files = []
    not_found_hosts = set()

    for registry_key in registry_keys:
        full_command = f"{command_type} query {registry_key}"
        response = execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, host_ids=host_ids)
        output, file, not_found_host = parse_rtr_stdout_response(host_ids, response, command_type,
                                                                 file_name_suffix=registry_key)
        not_found_hosts.update(not_found_host)
        outputs.extend(output)
        files.append(file)
        raw_response.append(response)

    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} {command_type} command on hosts {host_ids}:', outputs)
    human_readable += add_error_message(not_found_hosts, host_ids)
    return [CommandResults(raw_response=raw_response, readable_output=human_readable), files]


def add_error_message(failed_hosts, all_requested_hosts):
    human_readable = ""
    if failed_hosts:
        if len(all_requested_hosts) == len(failed_hosts):
            raise DemistoException(f"{INTEGRATION_NAME} The command was failed with the errors: {failed_hosts}")
        human_readable = "Note: you don't see the following IDs in the results as the request was failed " \
                         "for them. \n"
        for host_id in failed_hosts:
            human_readable += f'ID {host_id} failed as it was not found. \n'
    return human_readable


def rtr_polling_retrieve_file_command(args: dict):
    """
    This function is generically handling the polling flow.
    In this case, the polling flow is:
    1. run the "cs-falcon-run-get-command" command to get the request id.
    2. run the "cs-falcon-status-get-command" command to get the status of the first "get" command by the request id.
    2.1 start polling - wait for the 2nd step to be finished (when we get at least sha256 one time).
    3. run the "cs-falcon-get-extracted-file" command to get the extracted file.
    Args:
        args: the arguments required to the command being called, under cmd
    Returns:
        The return value is:
        1. All the extracted files.
        2. A list of dictionaries. Each dict includes a host id and a file name.
    """
    cmd = "cs-falcon-rtr-retrieve-file"
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 60))

    if 'hosts_and_requests_ids' not in args:
        # this is the very first time we call the polling function. We don't wont to call this function more that
        # one time, so we store that arg between the different runs
        args['hosts_and_requests_ids'] = run_get_command(is_polling=True)  # run the first command to retrieve file

    # we are here after we ran the cs-falcon-run-get-command command at the current run or in previous
    if not args.get('SHA256'):
        # this means that we don't have status yet (i.e we didn't get sha256)
        hosts_and_requests_ids = args.pop('hosts_and_requests_ids')
        args['request_ids'] = [res.get('RequestID') for res in hosts_and_requests_ids]
        get_status_response, args = status_get_command(args, is_polling=True)

        if args.get('SHA256'):
            # the status is ready, we can get the extracted files
            args.pop('SHA256')
            return rtr_get_extracted_file(get_status_response, args.get('fileName'))  # type:ignore

        else:
            # we should call the polling on status, cause the status is not ready
            args['hosts_and_requests_ids'] = hosts_and_requests_ids
            args.pop('request_ids')
            args.pop('SHA256')
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval_in_secs,
                args=args,
                timeout_in_seconds=600)
            command_results = CommandResults(scheduled_command=scheduled_command,
                                             readable_output="Waiting for the polling execution")
            return command_results


def rtr_get_extracted_file(args_to_get_files: dict, file_name: str):
    files = []
    outputs_data = []

    for host_id, values in args_to_get_files.items():
        arg = {'host_id': host_id, 'sha256': values.get('SHA256'), 'filename': file_name}
        file = get_extracted_file_command(arg)
        files.append(file)
        outputs_data.append(
            {'HostID': arg.get('host_id'),
             'FileName': file.get('File')
             })
    return [CommandResults(readable_output="CrowdStrike Falcon files", outputs=outputs_data,
                           outputs_prefix="CrowdStrike.File"), files]


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is {}'.format(demisto.command()))


def main():
    command = demisto.command()
    args = demisto.args()
    try:
        if command == 'test-module':
            result = test_module()
            return_results(result)
        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents())

        elif command in ('cs-device-ran-on', 'cs-falcon-device-ran-on'):
            return_results(get_indicator_device_id())
        elif demisto.command() == 'cs-falcon-search-device':
            return_results(search_device_command())
        elif command == 'cs-falcon-get-behavior':
            demisto.results(get_behavior_command())
        elif command == 'cs-falcon-search-detection':
            return_results(search_detections_command())
        elif command == 'cs-falcon-resolve-detection':
            demisto.results(resolve_detection_command())
        elif command == 'cs-falcon-contain-host':
            demisto.results(contain_host_command())
        elif command == 'cs-falcon-lift-host-containment':
            demisto.results(lift_host_containment_command())
        elif command == 'cs-falcon-run-command':
            demisto.results(run_command())
        elif command == 'cs-falcon-upload-script':
            demisto.results(upload_script_command())
        elif command == 'cs-falcon-get-script':
            demisto.results(get_script_command())
        elif command == 'cs-falcon-delete-script':
            demisto.results(delete_script_command())
        elif command == 'cs-falcon-list-scripts':
            demisto.results(list_scripts_command())
        elif command == 'cs-falcon-upload-file':
            demisto.results(upload_file_command())
        elif command == 'cs-falcon-delete-file':
            demisto.results(delete_file_command())
        elif command == 'cs-falcon-get-file':
            demisto.results(get_file_command())
        elif command == 'cs-falcon-list-files':
            demisto.results(list_files_command())
        elif command == 'cs-falcon-run-script':
            demisto.results(run_script_command())
        elif command == 'cs-falcon-run-get-command':
            demisto.results(run_get_command())
        elif command == 'cs-falcon-status-get-command':
            demisto.results(status_get_command(demisto.args()))
        elif command == 'cs-falcon-status-command':
            demisto.results(status_command())
        elif command == 'cs-falcon-get-extracted-file':
            demisto.results(get_extracted_file_command(demisto.args()))
        elif command == 'cs-falcon-list-host-files':
            demisto.results(list_host_files_command())
        elif command == 'cs-falcon-refresh-session':
            demisto.results(refresh_session_command())
        elif command == 'cs-falcon-list-detection-summaries':
            return_results(list_detection_summaries_command())
        elif command == 'cs-falcon-list-incident-summaries':
            return_results(list_incident_summaries_command())
        elif command == 'cs-falcon-search-iocs':
            return_results(search_iocs_command(**args))
        elif command == 'cs-falcon-get-ioc':
            return_results(get_ioc_command(ioc_type=args.get('type'), value=args.get('value')))
        elif command == 'cs-falcon-upload-ioc':
            return_results(upload_ioc_command(**args))
        elif command == 'cs-falcon-update-ioc':
            return_results(update_ioc_command(**args))
        elif command == 'cs-falcon-delete-ioc':
            return_results(delete_ioc_command(ioc_type=args.get('type'), value=args.get('value')))
        elif command == 'cs-falcon-search-custom-iocs':
            return_results(search_custom_iocs_command(**args))
        elif command == 'cs-falcon-get-custom-ioc':
            return_results(get_custom_ioc_command(
                ioc_type=args.get('type'), value=args.get('value'), ioc_id=args.get('ioc_id')))
        elif command == 'cs-falcon-upload-custom-ioc':
            return_results(upload_custom_ioc_command(**args))
        elif command == 'cs-falcon-update-custom-ioc':
            return_results(update_custom_ioc_command(**args))
        elif command == 'cs-falcon-delete-custom-ioc':
            return_results(delete_custom_ioc_command(ioc_id=args.get('ioc_id')))
        elif command == 'cs-falcon-device-count-ioc':
            return_results(get_ioc_device_count_command(ioc_type=args.get('type'), value=args.get('value')))
        elif command == 'cs-falcon-process-details':
            return_results(get_process_details_command(**args))
        elif command == 'cs-falcon-processes-ran-on':
            return_results(
                get_proccesses_ran_on_command(
                    ioc_type=args.get('type'),
                    value=args.get('value'),
                    device_id=args.get('device_id')
                )
            )
        elif command == 'endpoint':
            return_results(get_endpoint_command())
        elif command == 'cs-falcon-create-host-group':
            return_results(create_host_group_command(**args))
        elif command == 'cs-falcon-update-host-group':
            return_results(update_host_group_command(**args))
        elif command == 'cs-falcon-list-host-groups':
            return_results(list_host_groups_command(**args))
        elif command == 'cs-falcon-delete-host-groups':
            return_results(delete_host_groups_command(host_group_ids=argToList(args.get('host_group_id'))))
        elif command == 'cs-falcon-list-host-group-members':
            return_results(list_host_group_members_command(**args))
        elif command == 'cs-falcon-add-host-group-members':
            return_results(add_host_group_members_command(host_group_id=args.get('host_group_id'),
                                                          host_ids=argToList(args.get('host_ids'))))
        elif command == 'cs-falcon-remove-host-group-members':
            return_results(remove_host_group_members_command(host_group_id=args.get('host_group_id'),
                                                             host_ids=argToList(args.get('host_ids'))))
        elif command == 'cs-falcon-resolve-incident':
            return_results(resolve_incident_command(status=args.get('status'),
                                                    ids=argToList(args.get('ids'))))
        elif command == 'cs-falcon-batch-upload-custom-ioc':
            return_results(upload_batch_custom_ioc_command(**args))

        elif command == 'cs-falcon-rtr-kill-process':
            return_results(rtr_kill_process_command(args))

        elif command == 'cs-falcon-rtr-remove-file':
            return_results(rtr_remove_file_command(args))

        elif command == 'cs-falcon-rtr-list-processes':
            host_id = args.get('host_id')
            return_results(
                rtr_general_command_on_hosts([host_id], "ps", "ps", execute_run_batch_write_cmd_with_timer, True))

        elif command == 'cs-falcon-rtr-list-network-stats':
            host_id = args.get('host_id')
            return_results(
                rtr_general_command_on_hosts([host_id], "netstat", "netstat", execute_run_batch_write_cmd_with_timer,
                                             True))

        elif command == 'cs-falcon-rtr-read-registry':
            return_results(rtr_read_registry_keys_command(args))

        elif command == 'cs-falcon-rtr-list-scheduled-tasks':
            full_command = f'runscript -Raw=```schtasks /query /fo LIST /v```'  # noqa: F541
            host_ids = argToList(args.get('host_ids'))
            return_results(rtr_general_command_on_hosts(host_ids, "runscript", full_command,
                                                        execute_run_batch_admin_cmd_with_timer))

        elif command == 'cs-falcon-rtr-retrieve-file':
            return_results(rtr_polling_retrieve_file_command(args))

        else:
            raise NotImplementedError(f'CrowdStrike Falcon error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
