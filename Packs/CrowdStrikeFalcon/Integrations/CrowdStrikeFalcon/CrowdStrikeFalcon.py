import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import requests
import base64
import email
import hashlib
from typing import List
from dateutil.parser import parse
from typing import Dict, Tuple, Any, Optional, Union

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

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
    'status': 'Status'
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
}

SEARCH_IOC_KEY_MAP = {
    'type': 'Type',
    'value': 'Value',
    'policy': 'Policy',
    'source': 'Source',
    'share_level': 'ShareLevel',
    'expiration_timestamp': 'Expiration',
    'description': 'Description',
    'created_timestamp': 'CreatedTime',
    'created_by': 'CreatedBy',
    'modified_timestamp': 'ModifiedTime',
    'modified_by': 'ModifiedBy'
}

SEARCH_DEVICE_KEY_MAP = {
    'device_id': 'ID',
    'external_ip': 'ExternalIP',
    'local_ip': 'LocalIP',
    'hostname': 'Hostname',
    'os_version': 'OS',
    'mac_address': 'MacAddress',
    'first_seen': 'FirstSeen',
    'last_seen': 'LastSeen'
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

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, files=None, headers=HEADERS, safe=False,
                 get_token_flag=True, no_json=False):
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
        :param safe: If set to true will return None in case of http error

        :type get_token_flag: ``bool``
        :param get_token_flag: If set to True will call get_token()

        :type no_json: ``bool``
        :param no_json: If set to true will not parse the content and will return the raw response object for successful response

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
            files=files
        )
    except requests.exceptions.RequestException:
        return_error('Error in connection to the server. Please make sure you entered the URL correctly.')
    try:
        if res.status_code not in {200, 201, 202, 204}:
            res_json = res.json()
            reason = res.reason
            resources = res_json.get('resources', {})
            if resources:
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
                return http_request(method, url_suffix, params, data, headers, safe, get_token_flag=False)
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
    incident_hosts = incident.get('hosts')[0]
    incident_context = {
        'name': f'Incident ID: {incident_id}',
        'occurred': incident_hosts.get('modified_timestamp'),
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


def run_batch_read_cmd(host_ids: list, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with read access
        :param host_ids: List of host agent ID’s to run RTR command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-command/v1'
    batch_id = init_rtr_batch_session(host_ids)
    body = json.dumps({
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def run_batch_write_cmd(host_ids: list, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with write access
        :param host_ids: List of host agent ID’s to run RTR command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-active-responder-command/v1'
    batch_id = init_rtr_batch_session(host_ids)
    body = json.dumps({
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, data=body)
    return response


def run_batch_admin_cmd(host_ids: list, command_type: str, full_command: str) -> Dict:
    """
        Sends RTR command scope with write access
        :param host_ids: List of host agent ID’s to run RTR command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-admin-command/v1'
    batch_id = init_rtr_batch_session(host_ids)

    body = json.dumps({
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, data=body)
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
      :param timeout_duration: Timeout duration for for how long to wait for the request in duration syntax
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
        'Authorization': HEADERS['Authorization']
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
        'sort': 'modified_timestamp.asc',
        'offset': offset,
        'limit': INCIDENTS_PER_FETCH
    }
    if filter_arg:
        params['filter'] = filter_arg

    elif last_created_timestamp:
        params['filter'] = "modified_timestamp:>'{0}'".format(last_created_timestamp)

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


def create_ioc():
    """
        UNTESTED - Creates an IoC
        :return: Response json of create IoC request
    """
    args = demisto.args()
    input_args = {}
    # req args:
    input_args['type'] = args['ioc_type']
    input_args['value'] = args['ioc_value']
    input_args['policy'] = args['policy']
    # opt args:
    input_args['expiration_days'] = args.get('expiration_days')
    input_args['source'] = args.get('source')
    input_args['description'] = args.get('description')

    payload = {k: str(v) for k, v in input_args.items() if v}
    headers = {'Authorization': HEADERS['Authorization']}
    return http_request('POST', '/indicators/entities/iocs/v1', params=payload, headers=headers)


def search_iocs():
    """
        UNTESTED IN OAUTH 2- Searches an IoC
        :return: IoCs that were found in the search
    """
    args = demisto.args()
    ids = args.get('ids')
    if not ids:
        search_args = {
            'types': str(args.get('ioc_types', '')).split(','),
            'values': str(args.get('ioc_values', '')).split(','),
            'policies': str(args.get('policy', '')),
            'sources': str(args.get('sources', '')).split(','),
            'from.expiration_timestamp': str(args.get('expiration_from', '')),
            'to.expiration_timestamp': str(args.get('expiration_to', '')),
            'limit': str(args.get('limit', 50))
        }
        payload = {}
        for k, arg in search_args.items():
            if type(arg) is list:
                if arg[0]:
                    payload[k] = arg
            elif arg:
                payload[k] = arg
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
        Enriches the provided ioc_dict with IoC ID
        :param ioc_dict: IoC dict transformed using the SEARCH_IOC_KEY_MAP
        :return: ioc_dict with its ID key:value updated
    """
    for ioc in ioc_dict:
        ioc['ID'] = '{type}:{val}'.format(type=ioc.get('Type'), val=ioc.get('Value'))
    return ioc_dict


def delete_ioc():
    """
        UNTESTED - Sends a delete IoC request
        :return: Response json of delete IoC
    """
    ids = str(demisto.args().get('ids'))
    payload = {
        'ids': ids
    }
    return http_request('DELETE', '/indicators/entities/iocs/v1', payload)


def update_iocs():
    """
        UNTESTED - Updates the values one or more IoC
        :return: Response json of update IoC request
    """
    args = demisto.args()
    input_args = {
        'ids': args.get('ids'),
        'policy': args.get('policy', ''),
        'expiration_days': args.get('expiration_days', ''),
        'source': args.get('source'),
        'description': args.get('description')
    }
    payload = {k: str(v) for k, v in input_args.items() if v}
    headers = {'Authorization': HEADERS['Authorization']}
    return http_request('PATCH', '/indicators/entities/iocs/v1', params=payload, headers=headers)


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
    """
        Fetches incident using the detections API
        :return: Fetched detections in incident format
    """
    incidents = []  # type:List

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
                raw_res['type'] = "detections"
                for detection in demisto.get(raw_res, "resources"):
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
                demisto.setLastRun({'first_behavior_detection_time': prev_fetch,
                                    'detection_offset': offset + INCIDENTS_PER_FETCH})
            else:
                demisto.setLastRun({'first_behavior_detection_time': last_fetch_time})

    if 'Incidents' in fetch_incidents_or_detections:
        incident_type = 'incident'

        last_fetch_time, offset, prev_fetch, last_fetch_timestamp = get_fetch_times_and_offset(incident_type)

        fetch_query = demisto.params().get('fetch_query')

        if fetch_query:
            fetch_query = "modified_timestamp:>'{time}'+{query}".format(time=last_fetch_time, query=fetch_query)
            incidents_ids = demisto.get(get_incidents_ids(filter_arg=fetch_query, offset=offset), 'resources')

        else:
            incidents_ids = demisto.get(get_incidents_ids(last_created_timestamp=last_fetch_time, offset=offset),
                                        'resources')

        if incidents_ids:
            raw_res = get_incidents_entities(incidents_ids)
            if "resources" in raw_res:
                raw_res['type'] = "incidents"
                for incident in demisto.get(raw_res, "resources"):
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

                    incidents.append(incident_to_context)

            if len(incidents) == INCIDENTS_PER_FETCH:
                demisto.setLastRun({'first_behavior_incident_time': prev_fetch,
                                    'incident_offset': offset + INCIDENTS_PER_FETCH})
            else:
                demisto.setLastRun({'first_behavior_incident_time': last_fetch_time})
    return incidents


def create_ioc_command():
    """
        UNTESTED - Creates an IoC
        :return: EntryObject of create IoC command
    """
    raw_res = create_ioc()
    return create_entry_object(contents=raw_res, hr="Custom IoC was created successfully.")


def search_iocs_command():
    """
        UNTESTED IN OAUTH 2 - Searches for an ioc
        :return: EntryObject of search IoC command
    """
    raw_res = search_iocs()
    if not raw_res:
        return create_entry_object(hr='Could not find any Indicators of Compromise.')
    iocs = raw_res.get('resources')
    ec = [get_trasnformed_dict(ioc, SEARCH_IOC_KEY_MAP) for ioc in iocs]
    enrich_ioc_dict_with_ids(ec)
    return create_entry_object(contents=raw_res, ec={'CrowdStrike.IoC(val.ID === obj.ID)': ec},
                               hr=tableToMarkdown('Indicators of Compromise', ec))


def delete_iocs_command():
    """
        UNTESTED - Deletes an IoC
        :return: EntryObject of delete IoC command
    """
    raw_res = delete_ioc()
    ids = demisto.args().get('ids')
    return create_entry_object(contents=raw_res, hr="Custom IoC {0} successfully deleted.".format(ids))


def update_iocs_command():
    """
        UNTESTED - Updates an IoC
        :return: EntryObject of update IoC command
    """
    raw_res = update_iocs()
    ids = demisto.args().get('ids')
    return create_entry_object(contents=raw_res, hr="Custom IoC {0} successfully updated.".format(ids))


def search_device_command():
    """
        Searches for a device
        :return: EntryObject of search device command
    """
    raw_res = search_device()
    if not raw_res:
        return create_entry_object(hr='Could not find any devices.')
    devices = raw_res.get('resources')
    entries = [get_trasnformed_dict(device, SEARCH_DEVICE_KEY_MAP) for device in devices]
    headers = ['ID', 'Hostname', 'OS', 'MacAddress', 'LocalIP', 'ExternalIP', 'FirstSeen', 'LastSeen']
    hr = tableToMarkdown('Devices', entries, headers=headers, headerTransform=pascalToSpace)
    ec = {'CrowdStrike.Device(val.ID === obj.ID)': entries}
    return create_entry_object(contents=raw_res, ec=ec, hr=hr)


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
            entries.append(detection_entry)
    hr = tableToMarkdown('Detections Found:', entries, headers=headers, removeNull=True, headerTransform=pascalToSpace)
    ec = {'CrowdStrike.Detection(val.ID === obj.ID)': entries}
    return create_entry_object(contents=raw_res, ec=ec, hr=hr)


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
        if scope == 'read':
            response = run_batch_read_cmd(host_ids, command_type, full_command)
        elif scope == 'write':
            response = run_batch_write_cmd(host_ids, command_type, full_command)
        else:  # scope = admin
            response = run_batch_admin_cmd(host_ids, command_type, full_command)

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

    if script_name and raw:
        raise ValueError('Only one of the arguments script_name or raw should be provided, not both.')
    elif not script_name and not raw:
        raise ValueError('One of the arguments script_name or raw must be provided, none given.')
    elif script_name:
        full_command = f'runscript -CloudFile={script_name}'
    elif raw:
        full_command = f'runscript -Raw=```{raw}```'

    command_type = 'runscript'

    response = run_batch_admin_cmd(host_ids, command_type, full_command)

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


def run_get_command():
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

    human_readable = tableToMarkdown(f'Get command has requested for a file {file_path}', output)
    entry_context = {
        'CrowdStrike.Command(val.TaskID === obj.TaskID)': output
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def status_get_command():
    args = demisto.args()
    request_ids = argToList(args.get('request_ids'))
    timeout = args.get('timeout')
    timeout_duration = args.get('timeout_duration')

    timeout = timeout and int(timeout)

    responses = []
    files_output = []
    file_standard_context = []

    for request_id in request_ids:
        response = status_get_cmd(request_id, timeout, timeout_duration)
        responses.append(response)

        resources: dict = response.get('resources', {})

        for _, resource in resources.items():
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


def get_extracted_file_command():
    args = demisto.args()
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


def build_url_filter_for_device_id(args):
    indicator_type = args.get('type')
    indicator_value = args.get('value')
    url_filter = f'/indicators/queries/devices/v1?type={indicator_type}&value={indicator_value}'
    return url_filter


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
    url_filter = build_url_filter_for_device_id(args)
    raw_res = http_request('GET', url_filter)
    context_output = ''
    if validate_response(raw_res):
        context_output = raw_res.get('resources')
    else:
        error_message = build_error_message(raw_res)
        return_error(error_message)
    return CommandResults(
        readable_output=context_output,
        outputs_prefix='CrowdStrike.DeviceID',
        outputs_key_field='DeviceID',
        outputs=context_output
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
    fetch_query = demisto.args().get('fetch_query')

    if fetch_query:
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
                                        incident_id=incident.get('incident_id'), created_time=incident.get('created'))
        incidents_readable_outputs.append(readable_output)
    headers = ['incident_id', 'created_time', 'name', 'description', 'state', 'tags']
    human_readable = tableToMarkdown('CrowdStrike Incidents', incidents_readable_outputs, headers, removeNull=True)
    return human_readable


def list_incident_summaries_command():
    fetch_query = demisto.args().get('fetch_query')

    if fetch_query:
        fetch_query = "{query}".format(query=fetch_query)
        incidents_ids = get_incidents_ids(filter_arg=fetch_query)
    else:
        incidents_ids = get_incidents_ids()
    incidents_response_data = get_incidents_entities(incidents_ids)
    incidents = [resource for resource in incidents_response_data.get('resources')]
    incidents_human_readable = detections_to_human_readable(incidents)
    return CommandResults(
        readable_output=incidents_human_readable,
        outputs_prefix='CrowdStrike.Incidents',
        outputs_key_field='incident_id',
        outputs=incidents
    )


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


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is {}'.format(demisto.command()))

    # should raise error in case of issue
    if demisto.command() == 'fetch-incidents':
        demisto.incidents(fetch_incidents())

    try:
        if demisto.command() == 'test-module':
            result = test_module()
            return_results(result)

            get_token(new_token=True)
            demisto.results('ok')
        elif demisto.command() == 'cs-device-ran-on':
            return_results(get_indicator_device_id())
        elif demisto.command() == 'cs-falcon-search-device':
            demisto.results(search_device_command())
        elif demisto.command() == 'cs-falcon-get-behavior':
            demisto.results(get_behavior_command())
        elif demisto.command() == 'cs-falcon-search-detection':
            demisto.results(search_detections_command())
        elif demisto.command() == 'cs-falcon-resolve-detection':
            demisto.results(resolve_detection_command())
        elif demisto.command() == 'cs-falcon-contain-host':
            demisto.results(contain_host_command())
        elif demisto.command() == 'cs-falcon-lift-host-containment':
            demisto.results(lift_host_containment_command())
        elif demisto.command() == 'cs-falcon-run-command':
            demisto.results(run_command())
        elif demisto.command() == 'cs-falcon-upload-script':
            demisto.results(upload_script_command())
        elif demisto.command() == 'cs-falcon-get-script':
            demisto.results(get_script_command())
        elif demisto.command() == 'cs-falcon-delete-script':
            demisto.results(delete_script_command())
        elif demisto.command() == 'cs-falcon-list-scripts':
            demisto.results(list_scripts_command())
        elif demisto.command() == 'cs-falcon-upload-file':
            demisto.results(upload_file_command())
        elif demisto.command() == 'cs-falcon-delete-file':
            demisto.results(delete_file_command())
        elif demisto.command() == 'cs-falcon-get-file':
            demisto.results(get_file_command())
        elif demisto.command() == 'cs-falcon-list-files':
            demisto.results(list_files_command())
        elif demisto.command() == 'cs-falcon-run-script':
            demisto.results(run_script_command())
        elif demisto.command() == 'cs-falcon-run-get-command':
            demisto.results(run_get_command())
        elif demisto.command() == 'cs-falcon-status-get-command':
            demisto.results(status_get_command())
        elif demisto.command() == 'cs-falcon-status-command':
            demisto.results(status_command())
        elif demisto.command() == 'cs-falcon-get-extracted-file':
            demisto.results(get_extracted_file_command())
        elif demisto.command() == 'cs-falcon-list-host-files':
            demisto.results(list_host_files_command())
        elif demisto.command() == 'cs-falcon-refresh-session':
            demisto.results(refresh_session_command())
        elif demisto.command() == 'cs-falcon-list-detection-summaries':
            return_results(list_detection_summaries_command())
        elif demisto.command() == 'cs-falcon-list-incident-summaries':
            return_results(list_incident_summaries_command())
        # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
