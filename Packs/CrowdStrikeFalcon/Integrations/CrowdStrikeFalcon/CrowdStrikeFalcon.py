import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import base64
import email
import hashlib
import json
from enum import Enum
from threading import Timer
from collections.abc import Callable
from typing import Any
import requests
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
# Disable insecure warnings
import urllib3
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
INTEGRATION_NAME = 'CrowdStrike Falcon'
IDP_DETECTION = "IDP detection"
CLIENT_ID = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('client_id')
SECRET = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else \
    demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
BYTE_CREDS = f'{CLIENT_ID}:{SECRET}'.encode()
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Basic {base64.b64encode(BYTE_CREDS).decode()}'
}
# Note: True life time of token is actually 30 mins
TOKEN_LIFE_TIME = 28
INCIDENTS_PER_FETCH = int(demisto.params().get('incidents_per_fetch', 15))
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
IDP_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DEFAULT_TIMEOUT = 30
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

SEARCH_DEVICE_VERBOSE_KEY_MAP = {
    'agent_load_flags': 'AgentLoadFlags',
    'agent_local_time': 'AgentLocalTime',
    'agent_version': 'AgentVersion',
    'bios_manufacturer': 'BiosManufacturer',
    'bios_version': 'BiosVersion',
    'cid': 'CID',
    'config_id_base': 'ConfigIdBase',
    'config_id_build': 'ConfigIdBuild',
    'config_id_platform': 'ConfigIdPlatform',
    'connection_ip': 'ConnectionIp',
    'connection_mac_address': 'ConnectionMacAddress',
    'cpu_signature': 'CpuSignature',
    'default_gateway_ip': 'DefaultGatewayIP',
    'device_id': 'ID',
    'device_policies': 'DevicePolicies',
    'external_ip': 'ExternalIP',
    'first_seen': 'FirstSeen',
    'group_hash': 'GroupHash',
    'group_name': 'GroupName',
    'group_names': 'GroupNames',
    'groups': 'Groups',
    'hostname': 'Hostname',
    'kernel_version': 'KernelVersion',
    'last_seen': 'LastSeen',
    'local_ip': 'LocalIP',
    'mac_address': 'MacAddress',
    'major_version': 'MajorVersion',
    'meta': 'Meta',
    'minor_version': 'MinorVersion',
    'modified_timestamp': 'ModifiedTimestamp',
    'os_version': 'OS',
    'platform_id': 'PlatformID',
    'platform_name': 'PlatformName',
    'policies': 'Policies',
    'product_type_desc': 'ProductTypeDesc',
    'provision_status': 'ProvisionStatus',
    'reduced_functionality_mode': 'ReducedFunctionalityMode',
    'serial_number': 'SerialNumber',
    'status': 'Status',
    'system_manufacturer': 'SystemManufacturer',
    'system_product_name': 'SystemProductName',
    'tags': 'Tags'
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

''' MIRRORING DICTIONARIES & PARAMS '''

DETECTION_STATUS = {'new', 'in_progress', 'true_positive', 'false_positive', 'ignored', 'closed', 'reopened'}
IDP_DETECTION_STATUS = {'new', 'in_progress', 'closed', 'reopened'}

CS_FALCON_DETECTION_OUTGOING_ARGS = {'status': f'Updated detection status, one of {"/".join(DETECTION_STATUS)}'}

CS_FALCON_INCIDENT_OUTGOING_ARGS = {'tag': 'A tag that have been added or removed from the incident',
                                    'status': f'Updated incident status, one of {"/".join(STATUS_TEXT_TO_NUM.keys())}'}

CS_FALCON_DETECTION_INCOMING_ARGS = ['status', 'severity', 'behaviors.tactic', 'behaviors.scenario', 'behaviors.objective',
                                     'behaviors.technique', 'device.hostname']

CS_FALCON_INCIDENT_INCOMING_ARGS = ['state', 'status', 'tactics', 'techniques', 'objectives', 'tags', 'hosts.hostname']

MIRROR_DIRECTION_DICT = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

HOST_STATUS_DICT = {
    'online': 'Online',
    'offline': 'Offline',
    'unknown': 'Unknown'
}


CPU_UTILITY_INT_TO_STR_KEY_MAP = {
    1: 'Lowest',
    2: 'Low',
    3: 'Medium',
    4: 'High',
    5: 'Highest',
}
CPU_UTILITY_STR_TO_INT_KEY_MAP = {
    value: key for key, value in CPU_UTILITY_INT_TO_STR_KEY_MAP.items()}


SCHEDULE_INTERVAL_STR_TO_INT = {
    'never': 0,
    'daily': 1,
    'weekly': 7,
    'every other week': 14,
    'every four weeks': 28,
    'monthly': 30,
}


class IncidentType(Enum):
    INCIDENT = 'inc'
    DETECTION = 'ldt'
    IDP_DETECTION = ':ind:'


MIRROR_DIRECTION = MIRROR_DIRECTION_DICT.get(demisto.params().get('mirror_direction'))
INTEGRATION_INSTANCE = demisto.integrationInstance()


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, files=None, headers=HEADERS, safe=False,
                 get_token_flag=True, no_json=False, json=None, status_code=None, timeout=None):
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

        :type timeout: ``float``
        :param: timeout: The timeout for the request.

        :return: Returns the http request response json
        :rtype: ``dict``
    """
    if get_token_flag:
        token = get_token()
        headers['Authorization'] = f'Bearer {token}'
    url = SERVER + url_suffix

    headers['User-Agent'] = 'PANW-XSOAR'

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
            timeout=timeout,
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
            if res.status_code in (401, 403) and get_token_flag:
                LOG(err_msg)
                token = get_token(new_token=True)
                headers['Authorization'] = f'Bearer {token}'
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
                    timeout=timeout,
                )
            elif safe:
                return None
            raise DemistoException(err_msg)
        return res if no_json else res.json()
    except ValueError as exception:
        raise ValueError(
            f'Failed to parse json object from response: {exception} - {res.content}')  # type: ignore[str-bytes-safe]


def create_relationships(cve: dict) -> list:
    """
        creates relationships between the cve and each actor from 'actors' field
        : args: cve contains the cve id and the actors field if it is exists.
        : return: a list of relationships by type THREAT_ACTOR.
    """
    list_with_actors_field = []
    if not cve.get('actors'):
        return []
    for actor in cve.get('actors', {}):
        list_with_actors_field.append(actor)
    relationships_list: list[EntityRelationship] = []
    # need to create entity
    for entity_b in list_with_actors_field:
        relationships_list.append(EntityRelationship(entity_a=cve.get('id'),
                                                     entity_a_type=FeedIndicatorType.CVE,
                                                     name=EntityRelationship.Relationships.TARGETED_BY,
                                                     entity_b=entity_b,
                                                     entity_b_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                     brand=INTEGRATION_NAME,
                                                     reverse_name=EntityRelationship.Relationships.TARGETS))

    return relationships_list


def create_dbot_Score(cve: dict, reliability: str) -> Common.DBotScore:
    """
        Creates DBotScore CVE indicator, for get_cve_command.
    """
    return Common.DBotScore(indicator=cve.get('id'),
                            indicator_type=DBotScoreType.CVE,
                            integration_name=INTEGRATION_NAME,
                            score=Common.DBotScore.NONE,
                            reliability=reliability)


def create_publications(cve: dict) -> list:
    """
        Creates publications list from CVE, while using get_cve_command.
    """
    publications = []
    if cve.get('references'):
        for reference in cve.get('references', {}):
            publications.append(Common.Publications(title='references', link=reference))
    if cve.get('vendor_advisory'):
        for vendor_advisory in cve.get('vendor_advisory', {}):
            publications.append(Common.Publications(title='vendor_advisory', link=vendor_advisory))
    return publications


def build_query_params(query_params: dict) -> str:
    """
        Gets a dict of {property: value} and return a string to use as a query param in the requests of exclusion entities.
        For example: {'name': 'test', 'os_name': 'WINDOWS'} => '?name=test+os_name=WINDOWS'

        Args:
            query_params: dict of exclusion property: value.
        Returns:
            String to use as a query param in the requests of exclusion.
    """
    query = ''

    for key, value in query_params.items():
        if query:
            query += '+'
        query += f"{key}:'{value}'"

    return query


''' API FUNCTIONS '''


def create_entry_object(contents: list[Any] | dict[str, Any] = {}, ec: list[Any] | dict[str, Any] | None = None,
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


def add_mirroring_fields(incident: dict):
    """
        Updates the given incident to hold the needed mirroring fields.
    """
    incident['mirror_direction'] = MIRROR_DIRECTION
    incident['mirror_instance'] = INTEGRATION_INSTANCE


def detection_to_incident(detection):
    """
        Creates an incident of a detection.

        :type detection: ``dict``
        :param detection: Single detection object

        :return: Incident representation of a detection
        :rtype ``dict``
    """
    add_mirroring_fields(detection)

    incident = {
        'name': 'Detection ID: ' + str(detection.get('detection_id')),
        'occurred': str(detection.get('first_behavior')),
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
    add_mirroring_fields(incident)
    if incident.get('status'):
        incident['status'] = STATUS_NUM_TO_TEXT.get(incident.get('status'))

    incident_id = str(incident.get('incident_id'))
    incident_context = {
        'name': f'Incident ID: {incident_id}',
        'occurred': str(incident.get('start')),
        'rawJSON': json.dumps(incident)
    }
    return incident_context


def idp_detection_to_incident_context(idp_detection):
    """
            Creates an incident context of an IDP detection.

            :type idp_detection: ``dict``
            :param idp_detection: Single IDP detection object

            :return: Incident context representation of an IDP detection.
            :rtype ``dict``
        """
    add_mirroring_fields(idp_detection)
    if status := idp_detection.get('status'):
        idp_detection['status'] = status

    incident_context = {
        'name': f'IDP Detection ID: {idp_detection.get("composite_id")}',
        'occurred': idp_detection.get('start_time'),
        'last_updated': idp_detection.get('updated_timestamp'),
        'rawJSON': json.dumps(idp_detection)
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
            LOG(f'Error {ex} with: {trans_dict}')
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


def handle_response_errors(raw_res: dict, err_msg: str | None = None):
    """
    Raise exception if raw_res is empty or contains errors
    """
    if not err_msg:
        err_msg = "The server was unable to return a result, please run the command again."
    if not raw_res:
        raise DemistoException(err_msg)
    if raw_res.get('errors'):
        raise DemistoException(raw_res.get('errors'))


def create_json_iocs_list(
        ioc_type: str,
        iocs_value: list[str],
        action: str,
        platforms: list[str],
        severity: str | None = None,
        source: str | None = None,
        description: str | None = None,
        expiration: str | None = None,
        applied_globally: bool | None = None,
        host_groups: list[str] | None = None,
        tags: list[str] | None = None) -> list[dict]:
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


def init_rtr_single_session(host_id: str, queue_offline: bool = False) -> str:
    """
        Start a session with single host.
        :param host_id: Host agent ID to initialize a RTR session on.
        :return: The session ID to execute the command on
    """
    endpoint_url = '/real-time-response/entities/sessions/v1'
    body = json.dumps({
        'device_id': host_id,
        'queue_offline': queue_offline
    })
    response = http_request('POST', endpoint_url, data=body)
    resources = response.get('resources')
    if resources and isinstance(resources, list) and isinstance(resources[0], dict):
        session_id = resources[0].get('session_id')
        if isinstance(session_id, str):
            return session_id
    raise ValueError('No session id found in the response')


def init_rtr_batch_session(host_ids: list, offline=False) -> str:
    """
        Start a session with one or more hosts
        :param host_ids: List of host agent ID’s to initialize a RTR session on.
        :return: The session batch ID to execute the command on
    """
    endpoint_url = '/real-time-response/combined/batch-init-session/v1'
    body = json.dumps({
        'host_ids': host_ids,
        'queue_offline': offline
    })
    response = http_request('POST', endpoint_url, data=body)
    return response.get('batch_id')


def refresh_session(host_id: str) -> dict:
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


def run_batch_read_cmd(batch_id: str, command_type: str, full_command: str, timeout: int = 30) -> dict:
    """
        Sends RTR command scope with read access
        :param batch_id:  Batch ID to execute the command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :param timeout: The timeout for the request.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-command/v1'

    body = json.dumps({
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    })
    params = {
        'timeout': timeout
    }
    response = http_request('POST', endpoint_url, data=body, params=params, timeout=timeout)
    return response


def run_batch_write_cmd(batch_id: str, command_type: str, full_command: str, optional_hosts: list | None = None,
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
        Sends RTR command scope with write access
        :param batch_id:  Batch ID to execute the command on.
        :param command_type: Read-only command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
        :param optional_hosts: The hosts ids to run the command on.
        :param timeout: The timeout for the request.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-active-responder-command/v1'

    default_body = {
        'base_command': command_type,
        'batch_id': batch_id,
        'command_string': full_command
    }
    params = {
        'timeout': timeout if timeout else DEFAULT_TIMEOUT
    }
    if optional_hosts:
        default_body['optional_hosts'] = optional_hosts  # type:ignore

    body = json.dumps(default_body)
    response = http_request('POST', endpoint_url, data=body, timeout=timeout, params=params)
    return response


def run_batch_admin_cmd(batch_id: str, command_type: str, full_command: str, timeout: int = 30,
                        optional_hosts: list | None = None) -> dict:
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
    response = http_request('POST', endpoint_url, data=body, params=params, timeout=timeout)
    return response


def run_batch_get_cmd(host_ids: list, file_path: str, optional_hosts: list | None = None, timeout: int | None = None,
                      timeout_duration: str | None = None, offline: bool = False) -> dict:
    """
        Batch executes `get` command across hosts to retrieve files.
        After this call is made `/real-time-response/combined/batch-get-command/v1` is used to query for the results.

      :param host_ids: List of host agent ID’s to run RTR command on.
      :param file_path: Full path to the file that is to be retrieved from each host in the batch.
      :param optional_hosts: List of a subset of hosts we want to run the command on.
                             If this list is supplied, only these hosts will receive the command.
      :param timeout: Timeout for how long to wait for the request in seconds
      :param timeout_duration: Timeout duration for for how long to wait for the request in duration syntax
      :param offline: Whether the command will run against an offline-queued session for execution when the host comes online.
      :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/combined/batch-get-command/v1'
    batch_id = init_rtr_batch_session(host_ids, offline)

    body = assign_params(batch_id=batch_id, file_path=f'"{file_path}"', optional_hosts=optional_hosts)
    params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
    response = http_request('POST', endpoint_url, data=json.dumps(body), params=params)
    return response


def status_get_cmd(request_id: str, timeout: int | None = None, timeout_duration: str | None = None) -> dict:
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


def run_single_read_cmd(host_id: str, command_type: str, full_command: str, queue_offline: bool,
                        timeout: int = 30) -> dict:
    """
        Sends RTR command scope with read access
        :param host_id: Host agent ID to run RTR command on.
        :param command_type: Active-Responder command type we are going to execute, for example: get or cp.
        :param full_command: Full command string for the command.
        :param queue_offline: Whether the command will run against an offline-queued session and be queued for execution
                              when the host comes online.  # noqa: E501
        :param timeout: The timeout for the request.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/command/v1'
    session_id = init_rtr_single_session(host_id, queue_offline)

    body = json.dumps({
        'base_command': command_type,
        'command_string': full_command,
        'session_id': session_id
    })
    params = {
        'timeout': timeout
    }
    response = http_request('POST', endpoint_url, data=body, timeout=timeout, params=params)
    return response


def run_single_write_cmd(host_id: str, command_type: str, full_command: str, queue_offline: bool,
                         timeout: int = 30) -> dict:
    """
        Sends RTR command scope with write access
        :param host_id: Host agent ID to run RTR command on.
        :param command_type: Active-Responder command type we are going to execute, for example: get or cp.
        :param full_command: Full command string for the command.
        :param queue_offline: Whether the command will run against an offline-queued session and be queued for execution
                              when the host comes online.  # noqa: E501
        :param timeout: The timeout for the request.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/active-responder-command/v1'
    session_id = init_rtr_single_session(host_id, queue_offline)
    body = json.dumps({
        'base_command': command_type,
        'command_string': full_command,
        'session_id': session_id
    })
    params = {
        'timeout': timeout
    }
    response = http_request('POST', endpoint_url, data=body, timeout=timeout, params=params)
    return response


def run_single_admin_cmd(host_id: str, command_type: str, full_command: str, queue_offline: bool,
                         timeout: int = 30) -> dict:
    """
        Sends RTR command scope with admin access
        :param host_id: Host agent ID to run RTR command on.
        :param command_type: Active-Responder command type we are going to execute, for example: get or cp.
        :param full_command: Full command string for the command.
        :param queue_offline: Whether the command will run against an offline-queued session and be queued for execution
                              when the host comes online.  # noqa: E501
        :param timeout: The timeout for the request.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/admin-command/v1'
    session_id = init_rtr_single_session(host_id, queue_offline)

    body = json.dumps({
        'base_command': command_type,
        'command_string': full_command,
        'session_id': session_id
    })
    params = {
        'timeout': timeout
    }
    response = http_request('POST', endpoint_url, data=body, timeout=timeout, params=params)
    return response


def status_read_cmd(request_id: str, sequence_id: int | None) -> dict:
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


def status_write_cmd(request_id: str, sequence_id: int | None) -> dict:
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


def status_admin_cmd(request_id: str, sequence_id: int | None) -> dict:
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


def list_host_files(host_id: str, session_id: str | None = None) -> dict:
    """
        Get a list of files for the specified RTR session on a host.
        :param host_id: Host agent ID to run RTR command on.
        :param session_id: optional session_id for the command, if not provided a new session_id will generate
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/file/v2'
    if not session_id:
        session_id = init_rtr_single_session(host_id)

    params = {
        'session_id': session_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def upload_script(name: str, permission_type: str, content: str, entry_id: str) -> dict:
    """
        Uploads a script by either given content or file
        :param name: Script name to upload
        :param permission_type: Permissions type of script to upload
        :param content: PowerShell script content
        :param entry_id: Script file to upload
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    body: dict[str, tuple[Any, Any]] = {
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


def get_script(script_id: list) -> dict:
    """
        Retrieves a script given its ID
        :param script_id: ID of script to get
        :return: Response JSON which contains errors (if exist) and retrieved resource
    """
    endpoint_url = '/real-time-response/entities/scripts/v2'
    params = {
        'ids': script_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def delete_script(script_id: str) -> dict:
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


def list_scripts() -> dict:
    """
        Retrieves list of scripts
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/scripts/v2'
    response = http_request('GET', endpoint_url)
    return response


def get_extracted_file(host_id: str, sha256: str, filename: str | None = None, timeout=None):
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

    response = http_request('GET', endpoint_url, params=params, no_json=True, timeout=timeout)
    return response


def upload_file(entry_id: str, description: str) -> tuple:
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


def delete_file(file_id: str) -> dict:
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


def get_file(file_id: list) -> dict:
    """
        Get put-files based on the ID's given
        :param file_id: ID of file to get
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/put-files/v2'
    params = {
        'ids': file_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def list_files() -> dict:
    """
        Get a list of put-file ID's that are available to the user for the put command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/put-files/v2'
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
        params['filter'] = f"behaviors.behavior_id:'{behavior_id}'"
    elif last_behavior_time:
        params['filter'] = f"first_behavior:>'{last_behavior_time}'"

    response = http_request('GET', endpoint_url, params)
    return response


def get_fetch_detections(last_created_timestamp=None, filter_arg=None, offset: int = 0, last_updated_timestamp=None,
                         has_limit=True, limit: int = INCIDENTS_PER_FETCH):
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
    }
    if has_limit:
        params['limit'] = limit

    if filter_arg:
        params['filter'] = filter_arg
    elif last_created_timestamp:
        params['filter'] = f"first_behavior:>'{last_created_timestamp}'"
    elif last_updated_timestamp:
        params['filter'] = f"date_updated:>'{last_updated_timestamp}'"

    response = http_request('GET', endpoint_url, params)
    demisto.debug(f"CrowdStrikeFalconMsg: Getting detections from {endpoint_url} with {params=}. {response=}")
    return response


def get_detections_entities(detections_ids: list):
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


def get_incidents_ids(last_created_timestamp=None, filter_arg=None, offset: int = 0, last_updated_timestamp=None, has_limit=True,
                      limit=INCIDENTS_PER_FETCH):
    get_incidents_endpoint = '/incidents/queries/incidents/v1'
    params = {
        'sort': 'start.asc',
        'offset': offset,
    }
    if has_limit:
        params['limit'] = limit

    if filter_arg:
        params['filter'] = filter_arg
    elif last_created_timestamp:
        params['filter'] = f"start:>'{last_created_timestamp}'"
    elif last_updated_timestamp:
        params['filter'] = f"modified_timestamp:>'{last_updated_timestamp}'"

    response = http_request('GET', get_incidents_endpoint, params)

    return response


def get_idp_detections_ids(filter_arg=None, offset: int = 0, limit=INCIDENTS_PER_FETCH):
    """
        Send a request to retrieve IDP detections IDs.

        :type filter_arg: ``str``
        :param filter_arg: The filter to add to the query.
        :type offset: ``int``
        :param offset: The offset for the query.
        :type limit: ``int``
        :param limit: limit of idp detections to retrieve each request.

        :return: The response.
        :rtype ``dict``
    """
    params = {
        'sort': 'created_timestamp.asc',
        'offset': offset,
        'filter': filter_arg
    }
    if limit:
        params['limit'] = limit

    response = http_request('GET', '/alerts/queries/alerts/v1', params)
    return response


def get_incidents_entities(incidents_ids: list):
    ids_json = {'ids': incidents_ids}
    response = http_request(
        'POST',
        '/incidents/entities/incidents/GET/v1',
        data=json.dumps(ids_json)
    )
    return response


def get_idp_detection_entities(incidents_ids: list):
    """
        Send a request to retrieve IDP detection entities.

        :type incidents_ids: ``list``
        :param incidents_ids: The list of ids to search their entities.

        :return: The response.
        :rtype ``dict``
    """
    return http_request(
        'POST',
        '/alerts/entities/alerts/v1',
        data=json.dumps({'ids': incidents_ids})
    )


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
        types: list | str | None = None,
        values: list | str | None = None,
        sources: list | str | None = None,
        expiration: str | None = None,
        limit: str = '50',
        sort: str | None = None,
        offset: str | None = None,
        after: str | None = None,
) -> dict:
    """
    :param types: A list of indicator types. Separate multiple types by comma.
    :param values: Comma-separated list of indicator values
    :param sources: Comma-separated list of IOC sources
    :param expiration: The date on which the indicator will become inactive. (YYYY-MM-DD format).
    :param limit: The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100.
    :param sort: The order of the results. Format
    :param offset: The offset to begin the list from
    :param after: A pagination token used with the limit parameter to manage pagination of results.
                  On your first request, don't provide an 'after' token. On subsequent requests, provide
                  the 'after' token from the previous response to continue from that place in the results.
                  To access more than 10k indicators, use the 'after' parameter instead of 'offset'.
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
        'after': after,
    }

    return http_request('GET', '/iocs/combined/indicator/v1', params=params)


def get_custom_ioc(ioc_id: str) -> dict:
    params = {'ids': ioc_id}
    return http_request('GET', '/iocs/entities/indicators/v1', params=params)


def update_custom_ioc(
        ioc_id: str,
        action: str | None = None,
        platforms: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        description: str | None = None,
        expiration: str | None = None,
) -> dict:
    """
    Update an IOC
    """
    payload = {
        'indicators': [{'id': ioc_id, } | assign_params(
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


def search_device(filter_operator='AND'):
    """
        Searches for devices using the argument provided by the command execution. Returns empty
        result if no device was found

        :param: filter_operator: the operator that should be used between filters, default is 'AND'
        :param: exact_hostname: Whether to return exact hostname

        :return: Search device response json
    """
    args = demisto.args()
    input_arg_dict = {
        'device_id': str(args.get('ids', '')).split(','),
        'status': str(args.get('status', '')).split(','),
        'hostname': str(args.get('hostname', '')).split(','),
        'platform_name': str(args.get('platform_name', '')).split(','),
        'site_name': str(args.get('site_name', '')).split(','),
        'local_ip': str(args.get('ip', '')).split(',')
    }
    url_filter = '{}'.format(str(args.get('filter', '')))
    op = ',' if filter_operator == 'OR' else '+'
    # In Falcon Query Language, '+' stands for AND and ',' for OR
    # (https://falcon.crowdstrike.com/documentation/45/falcon-query-language-fql)

    for k, arg in input_arg_dict.items():
        if arg:
            if type(arg) is list:
                arg_filter = ''
                for arg_elem in arg:
                    if arg_elem:
                        first_arg = f'{arg_filter},{k}' if arg_filter else k
                        arg_filter = f"{first_arg}:'{arg_elem}'"
                if arg_filter:
                    url_filter = "{url_filter}{arg_filter}".format(url_filter=url_filter + op if url_filter else '',
                                                                   arg_filter=arg_filter)
            else:
                # All args should be a list. this is a fallback
                url_filter = "{url_filter}{operator}{inp_arg}:'{arg_val}'".format(url_filter=url_filter, operator=op,
                                                                                  inp_arg=k, arg_val=arg)
    raw_res = http_request('GET', '/devices/queries/devices/v1', params={'filter': url_filter})
    device_ids = raw_res.get('resources')
    if not device_ids:
        return None
    demisto.debug(f"number of devices returned from the api call is: {len(device_ids)}")
    return http_request('GET', '/devices/entities/devices/v2', params={'ids': device_ids})


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


def resolve_idp_detection(ids, status):
    """
        Send a request to update IDP detection status.
        :type ids: ``list``
        :param ids: The list of ids to update.
        :type status: ``str``
        :param status: The new status to set.
        :return: The response.
        :rtype ``dict``
    """
    data = {
        "action_parameters": [{"name": "update_status", "value": status}],
        "ids": ids
    }
    return http_request('PATCH', '/alerts/entities/alerts/v2', data=json.dumps(data))


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
                      host_group_id: str | None = None,
                      name: str | None = None,
                      group_type: str | None = None,
                      description: str | None = None,
                      assignment_rule: str | None = None) -> dict:
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
                              host_ids: list[str]) -> dict:
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


def host_group_members(filter: str | None,
                       host_group_id: str | None,
                       limit: str | None,
                       offset: str | None):
    params = {'id': host_group_id,
              'filter': filter,
              'offset': offset,
              'limit': limit}
    response = http_request(method='GET',
                            url_suffix='/devices/combined/host-group-members/v1',
                            params=params)
    return response


def resolve_incident(ids: list[str], status: str):
    if status not in STATUS_TEXT_TO_NUM:
        raise DemistoException(f'CrowdStrike Falcon Error: '
                               f'Status given is {status} and it is not in {STATUS_TEXT_TO_NUM.keys()}')
    return update_incident_request(ids, STATUS_TEXT_TO_NUM[status], 'update_status')


def update_incident_comment(ids: list[str], comment: str):
    return update_incident_request(ids, comment, 'add_comment')


def update_incident_request(ids: list[str], value: str, action_name: str):
    data = {
        "action_parameters": [
            {
                "name": action_name,
                "value": value
            }
        ],
        "ids": ids
    }
    return http_request(method='POST',
                        url_suffix='/incidents/entities/incident-actions/v1',
                        json=data)


def update_detection_request(ids: list[str], status: str) -> dict:
    if status not in DETECTION_STATUS:
        raise DemistoException(f'CrowdStrike Falcon Error: '
                               f'Status given is {status} and it is not in {DETECTION_STATUS}')
    return resolve_detection(ids=ids, status=status, assigned_to_uuid=None, show_in_ui=None, comment=None)


def update_idp_detection_request(ids: list[str], status: str) -> dict:
    """
        Manage the status to send to update to for IDP detections.
        :type ids: ``list``
        :param ids: The list of ids to update.
        :type status: ``str``
        :param status: The new status to set.
        :return: The response.
        :rtype ``dict``
    """
    if status not in IDP_DETECTION_STATUS:
        raise DemistoException(f'CrowdStrike Falcon Error: '
                               f'Status given is {status} and it is not in {IDP_DETECTION_STATUS}')
    return resolve_idp_detection(ids=ids, status=status)


def list_host_groups(filter: str | None, limit: str | None, offset: str | None) -> dict:
    params = {'filter': filter,
              'offset': offset,
              'limit': limit}
    response = http_request(method='GET',
                            url_suffix='/devices/combined/host-groups/v1',
                            params=params)
    return response


def delete_host_groups(host_group_ids: list[str]) -> dict:
    params = {'ids': host_group_ids}
    response = http_request(method='DELETE',
                            url_suffix='/devices/entities/host-groups/v1',
                            params=params)
    return response


def upload_batch_custom_ioc(ioc_batch: list[dict], timeout: float | None = None) -> dict:
    """
    Upload a list of IOC
    """
    payload = {
        'indicators': ioc_batch
    }

    return http_request('POST', '/iocs/entities/indicators/v1', json=payload, timeout=timeout)


def get_behaviors_by_incident(incident_id: str, params: dict | None = None) -> dict:
    return http_request('GET', f'/incidents/queries/behaviors/v1?filter=incident_id:"{incident_id}"', params=params)


def get_detections_by_behaviors(behaviors_id):
    try:
        body = {'ids': behaviors_id}
        return http_request('POST', '/incidents/entities/behaviors/GET/v1', json=body)
    except Exception as e:
        demisto.error(f'Error occurred when trying to get detections by behaviors: {str(e)}')
        return {}


def create_exclusion(exclusion_type: str, body: dict) -> dict:
    """
        Creates an exclusions based on a given json object.

        Args:
            exclusion_type: The exclusion type can be either ml (machine learning) or IOA`.
            exclusion_ids: A dict contains the exclusion data.
        Returns:
            Info about the created exclusion.
    """
    return http_request(method='POST', url_suffix=f'/policy/entities/{exclusion_type}-exclusions/v1', json=body)


def update_exclusion(exclusion_type: str, body: dict) -> dict:
    """
        Updates an exclusions based on its ID and a given json object.

        Args:
            exclusion_type: The exclusion type can be either ml (machine learning) or IOA`.
            exclusion_ids: A dict contains the exclusion data.
        Returns:
            Info about the updated exclusion.
    """
    return http_request('PATCH', f'/policy/entities/{exclusion_type}-exclusions/v1', json=body)


def delete_exclusion(exclusion_type: str, exclusion_ids: list) -> dict:
    """
        Deletes an exclusions based on its ID.

        Args:
            exclusion_type: The exclusion type can be either ml (machine learning) or IOA`.
            exclusion_ids: A list of exclusion IDs to delete.
        Returns:
            Info about the deleted exclusion.
    """
    return http_request(method='DELETE',
                        url_suffix=f'/policy/entities/{exclusion_type}-exclusions/v1{"?ids=" + "&ids=".join(exclusion_ids)}')


def get_exclusions(exclusion_type: str, filter_query: str | None, params: dict) -> dict:
    """
        Returns IDs of exclusions that match the filter / value

        Args:
            exclusion_type: The exclusion type can be either ml (machine learning) or IOA`.
            filter_query: Custom filter, For example `value:'<value>'`.
            params: API query params (sort, limit, offset).
        Returns:
            List of exclusion IDs.
    """
    return http_request(method='GET', url_suffix=f'/policy/queries/{exclusion_type}-exclusions/v1',
                        params=assign_params(filter=filter_query, **params))


def get_exclusion_entities(exclusion_type: str, exclusion_ids: list) -> dict:
    """
        Returns the exclusions based on a list of IDs.

        Args:
            exclusion_type: The exclusion type can be either ml (machine learning) or IOA`.
            exclusion_ids: A list of exclusion IDs to retrieve.
        Returns:
            List of exclusions.
    """
    return http_request(method='GET',
                        url_suffix=f'/policy/entities/{exclusion_type}-exclusions/v1{"?ids=" + "&ids=".join(exclusion_ids)}')


def list_quarantined_files_id(files_filter: dict | None, query: dict, pagination: dict) -> dict:
    """
        Returns the files ID's that match the filter / value.

        Args:
            files_filter: The exclusion type can be either ml (machine learning) or IOA`.
            query: The exclusion type can be either ml (machine learning) or IOA`.
            pagination: API query params for pagination (limit, offset).
        Returns:
            list: List of exclusions.
    """

    return http_request(method='GET', url_suffix='/quarantine/queries/quarantined-files/v1',
                        params=assign_params(filter=files_filter, q=build_query_params(query), **pagination))


def list_quarantined_files(ids: list) -> dict:
    """
        Returns the file's metadata based a list of IDs.

        Args:
            ids: A list of the IDs of the files.
        Returns:
            A list contains metadata about the files.
    """
    return http_request(method='POST', url_suffix='/quarantine/entities/quarantined-files/GET/v1', json={'ids': ids})


def apply_quarantined_files_action(body: dict) -> dict:
    """
        Applies action to quarantined files.

        Args:
            body: The request body with the parameters to update.
        Returns:
            A list contains metadata about the updated files.
    """
    return http_request(method='PATCH', url_suffix='/quarantine/entities/quarantined-files/v1', json=body)


''' MIRRORING COMMANDS '''


def get_remote_data_command(args: dict[str, Any]):
    """
    get-remote-data command: Returns an updated remote incident or detection.
    Args:
        args:
            id: incident or detection id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contain the incident or detection data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id

    mirrored_data = {}
    entries: list = []
    try:
        demisto.debug(f'Performing get-remote-data command with incident or detection id: {remote_incident_id} '
                      f'and last_update: {remote_args.last_update}')
        incident_type = find_incident_type(remote_incident_id)
        if incident_type == IncidentType.INCIDENT:
            mirrored_data, updated_object = get_remote_incident_data(remote_incident_id)
            if updated_object:
                demisto.debug(f'Update incident {remote_incident_id} with fields: {updated_object}')
                set_xsoar_incident_entries(updated_object, entries, remote_incident_id)  # sets in place

        elif incident_type == IncidentType.DETECTION:
            mirrored_data, updated_object = get_remote_detection_data(remote_incident_id)
            if updated_object:
                demisto.debug(f'Update detection {remote_incident_id} with fields: {updated_object}')
                set_xsoar_detection_entries(updated_object, entries, remote_incident_id)  # sets in place

        elif incident_type == IncidentType.IDP_DETECTION:
            mirrored_data, updated_object = get_remote_idp_detection_data(remote_incident_id)
            if updated_object:
                demisto.debug(f'Update IDP detection {remote_incident_id} with fields: {updated_object}')
                set_xsoar_idp_detection_entries(updated_object, entries, remote_incident_id)  # sets in place

        else:
            # this is here as prints can disrupt mirroring
            raise Exception(f'Executed get-remote-data command with undefined id: {remote_incident_id}')

        if not updated_object:
            demisto.debug(f'No delta was found for detection {remote_incident_id}.')
        return GetRemoteDataResponse(mirrored_object=updated_object, entries=entries)

    except Exception as e:
        demisto.debug(f"Error in CrowdStrike Falcon incoming mirror for incident or detection: {remote_incident_id}\n"
                      f"Error message: {str(e)}")

        if not mirrored_data:
            mirrored_data = {'id': remote_incident_id}
        mirrored_data['in_mirror_error'] = str(e)

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=[])


def find_incident_type(remote_incident_id: str):
    if remote_incident_id[0:3] == IncidentType.INCIDENT.value:
        return IncidentType.INCIDENT
    if remote_incident_id[0:3] == IncidentType.DETECTION.value:
        return IncidentType.DETECTION
    if IncidentType.IDP_DETECTION.value in remote_incident_id:
        return IncidentType.IDP_DETECTION
    return None


def get_remote_incident_data(remote_incident_id: str):
    """
    Called every time get-remote-data command runs on an incident.
    Gets the relevant incident entity from the remote system (CrowdStrike Falcon). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = get_incidents_entities([remote_incident_id]).get('resources', [])  # a list with one dict in it
    mirrored_data = mirrored_data_list[0]

    if 'status' in mirrored_data:
        mirrored_data['status'] = STATUS_NUM_TO_TEXT.get(int(str(mirrored_data.get('status'))))

    updated_object: dict[str, Any] = {'incident_type': 'incident'}
    set_updated_object(updated_object, mirrored_data, CS_FALCON_INCIDENT_INCOMING_ARGS)
    return mirrored_data, updated_object


def get_remote_detection_data(remote_incident_id: str):
    """
    Called every time get-remote-data command runs on an detection.
    Gets the relevant detection entity from the remote system (CrowdStrike Falcon). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = get_detections_entities([remote_incident_id]).get('resources', [])  # a list with one dict in it
    mirrored_data = mirrored_data_list[0]

    mirrored_data['severity'] = severity_string_to_int(mirrored_data.get('max_severity_displayname'))

    updated_object: dict[str, Any] = {'incident_type': 'detection'}
    set_updated_object(updated_object, mirrored_data, CS_FALCON_DETECTION_INCOMING_ARGS)
    return mirrored_data, updated_object


def get_remote_idp_detection_data(remote_incident_id):
    """
        Gets the relevant IDP detection entity from the remote system (CrowdStrike Falcon).

        :type remote_incident_id: ``str``
        :param remote_incident_id: The incident id to return its information.

        :return: The IDP detection entity.
        :rtype ``dict``
        :return: The object with the updated fields.
        :rtype ``dict``
    """
    mirrored_data_list = get_idp_detection_entities([remote_incident_id]).get('resources', [])  # a list with one dict in it
    mirrored_data = mirrored_data_list[0]

    if 'status' in mirrored_data:
        mirrored_data['status'] = mirrored_data.get('status')

    updated_object: dict[str, Any] = {'incident_type': IDP_DETECTION}
    set_updated_object(updated_object, mirrored_data, ['status'])
    return mirrored_data, updated_object


def set_xsoar_incident_entries(updated_object: dict[str, Any], entries: list, remote_incident_id: str):
    if demisto.params().get('close_incident'):
        if updated_object.get('status') == 'Closed':
            close_in_xsoar(entries, remote_incident_id, 'Incident')
        elif updated_object.get('status') in (set(STATUS_TEXT_TO_NUM.keys()) - {'Closed'}):
            reopen_in_xsoar(entries, remote_incident_id, 'Incident')


def set_xsoar_detection_entries(updated_object: dict[str, Any], entries: list, remote_detection_id: str):
    if demisto.params().get('close_incident'):
        if updated_object.get('status') == 'closed':
            close_in_xsoar(entries, remote_detection_id, 'Detection')
        elif updated_object.get('status') in (set(DETECTION_STATUS) - {'closed'}):
            reopen_in_xsoar(entries, remote_detection_id, 'Detection')


def set_xsoar_idp_detection_entries(updated_object: dict[str, Any], entries: list, remote_idp_detection_id: str):
    """
        Send the updated object to the relevant status handler

        :type updated_object: ``dict``
        :param updated_object: The updated object.
        :type entries: ``list``
        :param entries: The list of entries to add the new entry into.
        :type remote_idp_detection_id: ``str``
        :param remote_idp_detection_id: the remote idp detection id

        :return: The response.
        :rtype ``dict``
    """
    if demisto.params().get('close_incident'):
        if updated_object.get('status') == 'closed':
            close_in_xsoar(entries, remote_idp_detection_id, IDP_DETECTION)
        elif updated_object.get('status') in (set(IDP_DETECTION_STATUS) - {'closed'}):
            reopen_in_xsoar(entries, remote_idp_detection_id, IDP_DETECTION)


def close_in_xsoar(entries: list, remote_incident_id: str, incident_type_name: str):
    demisto.debug(f'{incident_type_name} is closed: {remote_incident_id}')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentClose': True,
            'closeReason': f'{incident_type_name} was closed on CrowdStrike Falcon'
        },
        'ContentsFormat': EntryFormat.JSON
    })


def reopen_in_xsoar(entries: list, remote_incident_id: str, incident_type_name: str):
    demisto.debug(f'{incident_type_name} is reopened: {remote_incident_id}')
    entries.append({
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    })


def set_updated_object(updated_object: dict[str, Any], mirrored_data: dict[str, Any], mirroring_fields: list[str]):
    """
    Sets the updated object (in place) for the incident or detection we want to mirror in, from the mirrored data, according to
    the mirroring fields. In the mirrored data, the mirroring fields might be nested in a dict or in a dict inside a list (if so,
    their name will have a dot in it).
    Note that the fields that we mirror right now may have only one dot in them, so we only deal with this case.

    :param updated_object: The dictionary to set its values, so it will hold the fields we want to mirror in, with their values.
    :param mirrored_data: The data of the incident or detection we want to mirror in.
    :param mirroring_fields: The mirroring fields that we want to mirror in, given according to whether we want to mirror an
        incident or a detection.
    """
    for field in mirroring_fields:
        if mirrored_data.get(field):
            updated_object[field] = mirrored_data.get(field)

        # if the field is not in mirrored_data, it might be a nested field - that has a . in its name
        elif '.' in field:
            field_name_parts = field.split('.')
            nested_mirrored_data = mirrored_data.get(field_name_parts[0])

            if isinstance(nested_mirrored_data, list):
                # if it is a list, it should hold a dictionary in it because it is a json structure
                for nested_field in nested_mirrored_data:
                    if nested_field.get(field_name_parts[1]):
                        updated_object[field] = nested_field.get(field_name_parts[1])
                        # finding the field in the first time it is satisfying
                        break
            elif isinstance(nested_mirrored_data, dict) and nested_mirrored_data.get(field_name_parts[1]):
                updated_object[field] = nested_mirrored_data.get(field_name_parts[1])


def get_modified_remote_data_command(args: dict[str, Any]):
    """
    Gets the modified remote incidents and detections IDs.
    Args:
        args:
            last_update: the last time we retrieved modified incidents and detections.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the retrieved incidents and detections IDs.
    """
    remote_args = GetModifiedRemoteDataArgs(args)

    last_update_utc = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})  # convert to utc format
    assert last_update_utc is not None, f"could not parse{remote_args.last_update}"
    last_update_timestamp = last_update_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    demisto.debug(f'Remote arguments last_update in UTC is {last_update_timestamp}')

    modified_ids_to_mirror = []

    raw_incidents = get_incidents_ids(last_updated_timestamp=last_update_timestamp, has_limit=False).get('resources', [])
    for incident_id in raw_incidents:
        modified_ids_to_mirror.append(str(incident_id))

    raw_detections = get_fetch_detections(last_updated_timestamp=last_update_timestamp, has_limit=False).get('resources', [])
    for detection_id in raw_detections:
        modified_ids_to_mirror.append(str(detection_id))
    last_update_timestamp_idp_detections = last_update_utc.strftime(IDP_DATE_FORMAT)
    raw_idp_detections = get_idp_detections_ids(filter_arg=f"updated_timestamp:>'{last_update_timestamp_idp_detections}'"
                                                "+product:'idp'").get('resources', [])
    for raw_idp_detection in raw_idp_detections:
        modified_ids_to_mirror.append(str(raw_idp_detection))

    demisto.debug(f'All ids to mirror in are: {modified_ids_to_mirror}')
    return GetModifiedRemoteDataResponse(modified_ids_to_mirror)


def update_remote_system_command(args: dict[str, Any]) -> str:
    """
    Mirrors out local changes to the remote system.
    Args:
        args: A dictionary containing the data regarding a modified incident, including: data, entries, incident_changed,
         remote_incident_id, inc_status, delta

    Returns:
        The remote incident id that was modified. This is important when the incident is newly created remotely.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    remote_incident_id = parsed_args.remote_incident_id
    demisto.debug(f'Got the following data {parsed_args.data}, and delta {delta} for the following {remote_incident_id=}.')
    if delta:
        demisto.debug(f'Got the following delta keys {list(delta.keys())}.')

    try:
        incident_type = find_incident_type(remote_incident_id)
        if parsed_args.incident_changed:
            if incident_type == IncidentType.INCIDENT:
                result = update_remote_incident(delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'Incident updated successfully. Result: {result}')

            elif incident_type == IncidentType.DETECTION:
                result = update_remote_detection(delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'Detection updated successfully. Result: {result}')

            elif incident_type == IncidentType.IDP_DETECTION:
                result = update_remote_idp_detection(delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'IDP Detection updated successfully. Result: {result}')

            else:
                raise Exception(f'Executed update-remote-system command with undefined id: {remote_incident_id}')

        else:
            demisto.debug(f"Skipping updating remote incident or detection {remote_incident_id} as it didn't change.")

    except Exception as e:
        demisto.error(f'Error in CrowdStrike Falcon outgoing mirror for incident or detection {remote_incident_id}. '
                      f'Error message: {str(e)}')

    return remote_incident_id


def close_in_cs_falcon(delta: dict[str, Any]) -> bool:
    """
    Closing in the remote system should happen only when both:
        1. The user asked for it
        2. One of the closing fields appears in the delta

    The second is mandatory so we will not send a closing request at all of the mirroring requests that happen after closing an
    incident (in case where the incident is updated so there is a delta, but it is not the status that was changed).
    """
    closing_fields = {'closeReason', 'closingUserId', 'closeNotes'}
    return demisto.params().get('close_in_cs_falcon') and any(field in delta for field in closing_fields)


def update_remote_detection(delta, inc_status: IncidentStatus, detection_id: str) -> str:
    if inc_status == IncidentStatus.DONE and close_in_cs_falcon(delta):
        demisto.debug(f'Closing detection with remote ID {detection_id} in remote system.')
        return str(update_detection_request([detection_id], 'closed'))

    # status field in CS Falcon is mapped to State field in XSOAR
    elif 'status' in delta:
        demisto.debug(f'Detection with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_detection_request([detection_id], delta.get('status')))

    return ''


def update_remote_idp_detection(delta, inc_status: IncidentStatus, detection_id: str) -> str:
    """
        Sends the request the request to update the relevant IDP detection entity.

        :type delta: ``dict``
        :param delta: The modified fields.
        :type inc_status: ``IncidentStatus``
        :param inc_status: The IDP detection status.
        :type detection_id: ``str``
        :param detection_id: The IDP detection ID to update.
    """
    if inc_status == IncidentStatus.DONE and close_in_cs_falcon(delta):
        demisto.debug(f'Closing IDP detection with remote ID {detection_id} in remote system.')
        return str(update_idp_detection_request([detection_id], 'closed'))

    # status field in CS Falcon is mapped to State field in XSOAR
    elif 'status' in delta:
        demisto.debug(f'Detection with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_idp_detection_request([detection_id], delta.get('status')))

    return ''


def update_remote_incident(delta: dict[str, Any], inc_status: IncidentStatus, incident_id: str) -> str:
    result = ''
    result += update_remote_incident_tags(delta, incident_id)
    result += update_remote_incident_status(delta, inc_status, incident_id)
    return result


def update_remote_incident_status(delta, inc_status: IncidentStatus, incident_id: str) -> str:
    if inc_status == IncidentStatus.DONE and close_in_cs_falcon(delta):
        demisto.debug(f'Closing incident with remote ID {incident_id} in remote system.')
        return str(resolve_incident([incident_id], 'Closed'))

    # status field in CS Falcon is mapped to Source Status field in XSOAR. Don't confuse with state field
    elif 'status' in delta:
        demisto.debug(f'Incident with remote ID {incident_id} status will change to "{delta.get("status")}" in remote system.')
        return str(resolve_incident([incident_id], delta.get('status')))

    return ''


def update_remote_incident_tags(delta, incident_id: str) -> str:
    result = ''
    if 'tag' in delta:
        current_tags = set(delta.get('tag'))
        prev_tags = get_previous_tags(incident_id)
        demisto.debug(f'Current tags in XSOAR are {current_tags}, and in remote system {prev_tags}.')

        result += remote_incident_handle_tags(prev_tags - current_tags, 'delete_tag', incident_id)
        result += remote_incident_handle_tags(current_tags - prev_tags, 'add_tag', incident_id)

    return result


def get_previous_tags(remote_incident_id: str):
    incidents_entities = get_incidents_entities([remote_incident_id]).get('resources', [])  # a list with one dict in it
    return set(incidents_entities[0].get('tags', ''))


def remote_incident_handle_tags(tags: Set, request: str, incident_id: str) -> str:
    result = ''
    for tag in tags:
        demisto.debug(f'{request} will be requested for incident with remote ID {incident_id} and tag "{tag}" in remote system.')
        result += str(update_incident_request([incident_id], tag, request))
    return result


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
        Returns the list of fields to map in outgoing mirroring, for incidents and detections.
    """
    mapping_response = GetMappingFieldsResponse()

    incident_type_scheme = SchemeTypeMapping(type_name='CrowdStrike Falcon Incident')
    for argument, description in CS_FALCON_INCIDENT_OUTGOING_ARGS.items():
        incident_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(incident_type_scheme)

    detection_type_scheme = SchemeTypeMapping(type_name='CrowdStrike Falcon Detection')
    for argument, description in CS_FALCON_DETECTION_OUTGOING_ARGS.items():
        detection_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(detection_type_scheme)

    return mapping_response


''' COMMANDS FUNCTIONS '''


def migrate_last_run(last_run: dict[str, str] | list[dict]) -> list[dict]:
    """This function migrated from old last run object to new last run object

    Args:
        last_run (dict[str, str]): Old last run object.

    Returns:
        list[dict]: New last run object.
    """
    if isinstance(last_run, list):
        for last_run_type in last_run:
            last_run_type.pop("offset", None)
        return last_run
    else:
        updated_last_run_detections: dict[str, str | None] = {}
        if (detection_time := last_run.get('first_behavior_detection_time')) and \
                (detection_time_date := dateparser.parse(detection_time)):
            updated_last_run_detections['time'] = detection_time_date.strftime(DATE_FORMAT)

        updated_last_run_incidents: dict[str, str | None] = {}
        if (incident_time := last_run.get('first_behavior_incident_time')) and \
                (incident_time_date := dateparser.parse(incident_time)):
            updated_last_run_incidents['time'] = incident_time_date.strftime(DATE_FORMAT)

        return [updated_last_run_detections, updated_last_run_incidents, {}]


def sort_incidents_summaries_by_ids_order(ids_order, full_incidents, id_field):
    """ sort incidents list by the order that ids_order list has

    Args:
        ids_order: list of ids
        full_incidents: list of incidents
        id_field: name of the id field
    Returns:
        list[dict]: New last run object.
    """
    incidents_by_id = {i[id_field]: i for i in full_incidents}
    incidents = [incidents_by_id[i] for i in ids_order]
    return incidents


def fetch_incidents():
    incidents: list = []
    detections: list = []
    idp_detections: list = []
    last_run = demisto.getLastRun()
    demisto.debug(f'CrowdStrikeFalconMsg: Current last run object is {last_run}')
    if not last_run:
        last_run = [{}, {}, {}]
    last_run = migrate_last_run(last_run)
    current_fetch_info_detections: dict = last_run[0]
    current_fetch_info_incidents: dict = last_run[1]
    current_fetch_info_idp_detections: dict = {} if len(last_run) < 3 else last_run[2]
    fetch_incidents_or_detections = demisto.params().get('fetch_incidents_or_detections', "")
    look_back = int(demisto.params().get('look_back', 0))
    fetch_limit = INCIDENTS_PER_FETCH

    demisto.debug(f"CrowdstrikeFalconMsg: Starting fetch incidents with {fetch_incidents_or_detections}")

    if 'Detections' in fetch_incidents_or_detections or "Endpoint Detection" in fetch_incidents_or_detections:
        start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=current_fetch_info_detections,
                                                                    first_fetch=FETCH_TIME,
                                                                    look_back=look_back,
                                                                    date_format=DATE_FORMAT)
        fetch_limit = current_fetch_info_detections.get('limit') or INCIDENTS_PER_FETCH
        incident_type = 'detection'
        fetch_query = demisto.params().get('fetch_query')
        if fetch_query:
            fetch_query = f"first_behavior:>'{start_fetch_time}'+{fetch_query}"
            detections_ids = demisto.get(get_fetch_detections(filter_arg=fetch_query, limit=fetch_limit), 'resources')
        else:
            detections_ids = demisto.get(get_fetch_detections(last_created_timestamp=start_fetch_time, limit=fetch_limit),
                                         'resources')

        raw_res = get_detections_entities(detections_ids)

        if raw_res is not None and "resources" in raw_res:
            full_detections = demisto.get(raw_res, "resources")
            sorted_detections = sort_incidents_summaries_by_ids_order(ids_order=detections_ids,
                                                                      full_incidents=full_detections,
                                                                      id_field='detection_id')
            for detection in sorted_detections:
                detection['incident_type'] = incident_type
                demisto.debug(
                    f"CrowdStrikeFalconMsg: Detection {detection['detection_id']} "
                    f"was fetched which was created in {detection['first_behavior']}")
                incident = detection_to_incident(detection)

                detections.append(incident)

        detections = filter_incidents_by_duplicates_and_limit(incidents_res=detections,
                                                              last_run=current_fetch_info_detections,
                                                              fetch_limit=INCIDENTS_PER_FETCH, id_field='name')

        for detection in detections:
            occurred = dateparser.parse(detection["occurred"])
            if occurred:
                detection["occurred"] = occurred.strftime(DATE_FORMAT)
                demisto.debug(f"CrowdStrikeFalconMsg: Detection {detection['name']} occurred at {detection['occurred']}")
        updated_last_run = update_last_run_object(last_run=current_fetch_info_detections, incidents=detections,
                                                  fetch_limit=INCIDENTS_PER_FETCH,
                                                  start_fetch_time=start_fetch_time, end_fetch_time=end_fetch_time,
                                                  look_back=look_back,
                                                  created_time_field='occurred', id_field='name', date_format=DATE_FORMAT)
        demisto.debug(f"updated last run is {updated_last_run}")
        current_fetch_info_detections = updated_last_run

    if 'Incidents' in fetch_incidents_or_detections or "Endpoint Incident" in fetch_incidents_or_detections:
        start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=current_fetch_info_incidents,
                                                                    first_fetch=FETCH_TIME,
                                                                    look_back=look_back,
                                                                    date_format=DATE_FORMAT)
        fetch_limit = current_fetch_info_incidents.get('limit') or INCIDENTS_PER_FETCH

        incident_type = 'incident'

        fetch_query = demisto.params().get('incidents_fetch_query')

        if fetch_query:
            fetch_query = f"start:>'{start_fetch_time}'+{fetch_query}"
            incidents_ids = demisto.get(get_incidents_ids(filter_arg=fetch_query, limit=fetch_limit), 'resources')

        else:
            incidents_ids = demisto.get(get_incidents_ids(last_created_timestamp=start_fetch_time, limit=fetch_limit),
                                        'resources')
        if incidents_ids:
            raw_res = get_incidents_entities(incidents_ids)
            if raw_res is not None and "resources" in raw_res:
                full_incidents = demisto.get(raw_res, "resources")
                sorted_incidents = sort_incidents_summaries_by_ids_order(ids_order=incidents_ids,
                                                                         full_incidents=full_incidents,
                                                                         id_field='incident_id')
                for incident in sorted_incidents:
                    incident['incident_type'] = incident_type
                    incident_to_context = incident_to_incident_context(incident)
                    incidents.append(incident_to_context)

        incidents = filter_incidents_by_duplicates_and_limit(incidents_res=incidents, last_run=current_fetch_info_incidents,
                                                             fetch_limit=INCIDENTS_PER_FETCH, id_field='name')
        for incident in incidents:
            occurred = dateparser.parse(incident["occurred"])
            if occurred:
                incident["occurred"] = occurred.strftime(DATE_FORMAT)
                demisto.debug(f"CrowdStrikeFalconMsg: Incident {incident['name']} occurred at {incident['occurred']}")
        updated_last_run = update_last_run_object(last_run=current_fetch_info_incidents, incidents=incidents,
                                                  fetch_limit=INCIDENTS_PER_FETCH,
                                                  start_fetch_time=start_fetch_time, end_fetch_time=end_fetch_time,
                                                  look_back=look_back,
                                                  created_time_field='occurred', id_field='name', date_format=DATE_FORMAT)
        current_fetch_info_incidents = updated_last_run

    if "IDP Detection" in fetch_incidents_or_detections:
        start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=current_fetch_info_idp_detections,
                                                                    first_fetch=FETCH_TIME,
                                                                    look_back=look_back,
                                                                    date_format=IDP_DATE_FORMAT)
        fetch_limit = current_fetch_info_idp_detections.get('limit') or INCIDENTS_PER_FETCH
        fetch_query = demisto.params().get('idp_detections_fetch_query', "")
        filter = f"product:'idp'+created_timestamp:>'{start_fetch_time}'"

        if fetch_query:
            filter += f"+{fetch_query}"
        idp_detections_ids = demisto.get(get_idp_detections_ids(filter_arg=filter, limit=fetch_limit), 'resources')
        if idp_detections_ids:
            raw_res = get_idp_detection_entities(idp_detections_ids)
            if "resources" in raw_res:
                full_detections = demisto.get(raw_res, "resources")
                sorted_detections = sort_incidents_summaries_by_ids_order(ids_order=idp_detections_ids,
                                                                          full_incidents=full_detections,
                                                                          id_field='composite_id')
                for idp_detection in sorted_detections:
                    idp_detection['incident_type'] = IDP_DETECTION
                    idp_detection_to_context = idp_detection_to_incident_context(idp_detection)
                    idp_detections.append(idp_detection_to_context)

            idp_detections = filter_incidents_by_duplicates_and_limit(incidents_res=idp_detections,
                                                                      last_run=current_fetch_info_idp_detections,
                                                                      fetch_limit=INCIDENTS_PER_FETCH, id_field='name')
            updated_last_run = update_last_run_object(last_run=current_fetch_info_idp_detections, incidents=idp_detections,
                                                      fetch_limit=fetch_limit,
                                                      start_fetch_time=start_fetch_time, end_fetch_time=end_fetch_time,
                                                      look_back=look_back,
                                                      created_time_field='occurred', id_field='name', date_format=IDP_DATE_FORMAT)
            current_fetch_info_idp_detections = updated_last_run
            demisto.debug(f"CrowdstrikeFalconMsg: Ending fetch idp_detections. Fetched {len(idp_detections)}")

    demisto.setLastRun([current_fetch_info_detections, current_fetch_info_incidents, current_fetch_info_idp_detections])
    return incidents + detections + idp_detections


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
        types: list | str | None = None,
        values: list | str | None = None,
        sources: list | str | None = None,
        expiration: str | None = None,
        limit: str = '50',
        sort: str | None = None,
        offset: str | None = None,
        next_page_token: str | None = None,
) -> list[dict]:
    """
    :param types: A list of indicator types. Separate multiple types by comma.
    :param values: Comma-separated list of indicator values
    :param sources: Comma-separated list of IOC sources
    :param expiration: The date on which the indicator will become inactive. (YYYY-MM-DD format).
    :param limit: The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 100.
    :param sort: The order of the results. Format
    :param offset: The offset to begin the list from
    :param next_page_token: A pagination token used with the limit parameter to manage pagination of results.
                  On your first request, don't provide an 'after' token. On subsequent requests, provide
                  the 'after' token from the previous response to continue from that place in the results.
                  To access more than 10k indicators, use the 'after' parameter instead of 'offset'.
    """
    raw_res = search_custom_iocs(
        types=argToList(types),
        values=argToList(values),
        sources=argToList(sources),
        sort=sort,
        offset=offset,
        expiration=expiration,
        limit=limit,
        after=next_page_token,
    )
    iocs = raw_res.get('resources')
    meta = raw_res.get('meta')
    pagination_token = meta['pagination'].get('after') if meta else None
    if not iocs:
        return create_entry_object(hr='Could not find any Indicators of Compromise.')
    handle_response_errors(raw_res)
    entry_objects_list = []
    ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP) for ioc in iocs]
    entry_objects_list.append(create_entry_object(
        contents=raw_res,
        ec={'CrowdStrike.IOC(val.ID === obj.ID)': ec},
        hr=tableToMarkdown('Indicators of Compromise', ec, headers=IOC_HEADERS),
    ))
    entry_objects_list.append(create_entry_object(
        contents=raw_res,
        ec={'CrowdStrike.NextPageToken': pagination_token},
        hr=tableToMarkdown('Pagination Info', pagination_token, headers=['Next Page Token']),
    ))
    return entry_objects_list


def get_custom_ioc_command(
        ioc_type: str | None = None,
        value: str | None = None,
        ioc_id: str | None = None,
) -> dict:
    """
    :param ioc_type: IOC type
    :param value: IOC value
    :param ioc_id: IOC ID
    """

    if not ioc_id and not (ioc_type and value):
        raise ValueError('Either ioc_id or ioc_type and value must be provided.')

    raw_res = get_custom_ioc(ioc_id) if ioc_id else search_custom_iocs(types=argToList(ioc_type), values=argToList(value))

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
        severity: str | None = None,
        source: str | None = None,
        description: str | None = None,
        expiration: str | None = None,
        applied_globally: bool | None = None,
        host_groups: list[str] | None = None,
        tags: list[str] | None = None,
) -> list[dict]:
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
    values: list[str] = argToList(value)
    applied_globally = argToBoolean(applied_globally) if applied_globally else None
    host_groups: list[str] = argToList(host_groups)
    tags = argToList(tags)
    platforms_list = argToList(platforms)

    iocs_json_batch = create_json_iocs_list(ioc_type, values, action, platforms_list, severity, source, description,
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
        action: str | None = None,
        platforms: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        description: str | None = None,
        expiration: str | None = None,
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
    extended_data = argToBoolean(demisto.args().get('extended_data', False))
    command_results = []
    for single_device in devices:
        # demisto.debug(f"single device info: {single_device}")
        # status, is_isolated = generate_status_fields(single_device.get('status'), single_device.get("device_id"))
        endpoint = Common.Endpoint(
            id=single_device.get('device_id'),
            hostname=single_device.get('hostname'),
            ip_address=single_device.get('local_ip'),
            os=single_device.get('platform_name'),
            os_version=single_device.get('os_version'),
            status=get_status(single_device.get("device_id")),
            is_isolated=get_isolation_status(single_device.get('status')),
            mac_address=single_device.get('mac_address'),
            vendor=INTEGRATION_NAME)
        if not extended_data:
            entry = get_trasnformed_dict(single_device, SEARCH_DEVICE_KEY_MAP)
            headers = ['ID', 'Hostname', 'OS', 'MacAddress', 'LocalIP', 'ExternalIP', 'FirstSeen', 'LastSeen', 'Status']
        else:
            device_groups = single_device['groups']
            single_device.update({'group_names': list(enrich_groups(device_groups).values())})
            entry = get_trasnformed_dict(single_device, SEARCH_DEVICE_VERBOSE_KEY_MAP)
            headers = list(SEARCH_DEVICE_VERBOSE_KEY_MAP.values())
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


def enrich_groups(all_group_ids) -> dict[str, Any]:
    """
        Receives a list of group_ids
        Returns a dict {group_id: group_name}
    """
    result = {}
    params = {'ids': all_group_ids}
    response_json = http_request('GET', '/devices/entities/host-groups/v1', params, status_code=404)
    for resource in response_json['resources']:
        try:
            result[resource['id']] = resource['name']
        except KeyError:
            demisto.debug(f"Could not retrieve group name for {resource=}")
    return result


def get_status(device_id):
    raw_res = http_request('GET', '/devices/entities/online-state/v1', params={'ids': device_id})
    state = raw_res.get('resources')[0].get('state', '')
    if state == 'unknown':
        demisto.debug(f"Device with id: {device_id} returned an unknown state, which indicates that the host has not"
                      f" been seen recently and we are not confident about its current state")
    return HOST_STATUS_DICT[state]


def get_isolation_status(endpoint_status):
    is_isolated = ''

    if endpoint_status == 'containment_pending':
        is_isolated = 'Pending isolation'
    elif endpoint_status == 'contained':
        is_isolated = 'Yes'
    elif endpoint_status == 'lift_containment_pending':
        is_isolated = 'Pending unisolation'
    elif endpoint_status.lower() != 'normal':
        raise DemistoException(f'Error: Unknown endpoint status was given: {endpoint_status}')
    return is_isolated


def generate_endpoint_by_contex_standard(devices):
    standard_endpoints = []
    for single_device in devices:
        # status, is_isolated = generate_status_fields(single_device.get('status'), single_device.get("device_id"))
        endpoint = Common.Endpoint(
            id=single_device.get('device_id'),
            hostname=single_device.get('hostname'),
            ip_address=single_device.get('local_ip'),
            os=single_device.get('platform_name'),
            os_version=single_device.get('os_version'),
            status=get_status(single_device.get("device_id")),
            is_isolated=get_isolation_status(single_device.get('status')),
            mac_address=single_device.get('mac_address'),
            vendor=INTEGRATION_NAME)
        standard_endpoints.append(endpoint)
    return standard_endpoints


def get_endpoint_command():
    args = demisto.args()
    if 'id' in args:
        args['ids'] = args.get('id', '')

    if not args.get('ip') and not args.get('id') and not args.get('hostname'):
        # in order not to return all the devices
        return create_entry_object(hr='Please add a filter argument - ip, hostname or id.')

    # use OR operator between filters (https://github.com/demisto/etc/issues/46353)
    raw_res = search_device(filter_operator='OR')

    if not raw_res:
        return create_entry_object(hr='Could not find any devices.')
    devices = raw_res.get('resources')

    # filter hostnames that will match the exact hostnames including case-sensitive
    if hostnames := argToList(args.get('hostname')):
        lowercase_hostnames = {hostname.lower() for hostname in hostnames}
        devices = [device for device in devices if (device.get('hostname') or '').lower() in lowercase_hostnames]

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
    hr = tableToMarkdown(f'Behavior ID: {behavior_id}', entries, headerTransform=pascalToSpace)
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
    hr = f"Detection {str(ids)[1:-1]} updated\n"
    hr += 'With the following values:\n'
    for k, arg in args.items():
        hr += f'\t{k}:{arg}\n'
    return create_entry_object(contents=raw_res, hr=hr)


def contain_host_command():
    """
        Contains hosts with user arg ids
        :return: EntryObject of contain host command
    """
    ids = argToList(demisto.args().get('ids'))
    raw_res = contain_host(ids)
    hr = f"Host {str(ids)[1:-1]} contained"
    return create_entry_object(contents=raw_res, hr=hr)


def lift_host_containment_command():
    """
        Lifts containment off a host
        :return: EntryObject of lift host containment
    """
    ids = argToList(demisto.args().get('ids'))
    raw_res = lift_host_containment(ids)
    hr = f"Containment has been lift off host {str(ids)[1:-1]}"
    return create_entry_object(contents=raw_res, hr=hr)


def run_command():
    args = demisto.args()
    host_ids = argToList(args.get('host_ids'))
    command_type = args.get('command_type')
    full_command = args.get('full_command')
    scope = args.get('scope', 'read')
    target = args.get('target', 'batch')
    timeout = int(args.get('timeout', 180))

    offline = argToBoolean(args.get('queue_offline', False))

    output = []

    if target == 'batch':
        batch_id = init_rtr_batch_session(host_ids, offline)
        timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
        timer.start()
        try:
            if scope == 'read':
                response = run_batch_read_cmd(batch_id, command_type, full_command, timeout=timeout)
            elif scope == 'write':
                response = run_batch_write_cmd(batch_id, command_type, full_command, timeout=timeout)
            else:  # scope = admin
                response = run_batch_admin_cmd(batch_id, command_type, full_command, timeout=timeout)
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
                response1 = run_single_read_cmd(host_id, command_type, full_command, offline, timeout=timeout)
            elif scope == 'write':
                response1 = run_single_write_cmd(host_id, command_type, full_command, offline, timeout=timeout)
            else:  # scope = admin
                response1 = run_single_admin_cmd(host_id, command_type, full_command, offline, timeout=timeout)
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
    offline = argToBoolean(args.get('queue_offline', False))
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

    batch_id = init_rtr_batch_session(host_ids, offline)
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
        stderr = resource.get('stderr')
        output.append({
            'HostID': resource.get('aid'),
            'SessionID': resource.get('session_id'),
            'Stdout': resource.get('stdout'),
            'Stderr': stderr,
            'BaseCommand': resource.get('base_command'),
            'Command': full_command
        })
        if stderr:
            raise DemistoException(f"cs-falcon-run-script command failed with the following error: {stderr}")

    human_readable = tableToMarkdown(f'Command {full_command} results', output)
    entry_context = {
        'CrowdStrike': {
            'Command': output
        }
    }

    return create_entry_object(contents=response, ec=entry_context, hr=human_readable)


def run_get_command(is_polling=False, offline=False):
    request_ids_for_polling = []
    args = demisto.args()
    host_ids = argToList(args.get('host_ids'))
    file_path = args.get('file_path')
    optional_hosts = argToList(args.get('optional_hosts'))
    timeout = args.get('timeout')
    timeout_duration = args.get('timeout_duration')

    timeout = timeout and int(timeout)
    response = run_batch_get_cmd(host_ids, file_path, optional_hosts, timeout, timeout_duration, offline)

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
    return None


def list_host_files_command():
    args = demisto.args()
    host_id = args.get('host_id')
    session_id = args.get('session_id')

    response = list_host_files(host_id, session_id)
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

    human_readable = tableToMarkdown('CrowdStrike Falcon files', files_output) if files_output else 'No result found'

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
    return 'resources' in raw_res


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
    devices_response = []
    if validate_response(raw_res):
        devices_response = raw_res.get('resources')
    else:
        error_message = build_error_message(raw_res)
        return_error(error_message)
    ioc_id = f"{ioc_type}:{ioc_value}"
    readable_output = tableToMarkdown(f"Devices that encountered the IOC {ioc_id}", devices_response,
                                      headers='Device ID')
    outputs = {'DeviceID': devices_response,
               'DeviceIOC':
                   {
                       'Type': ioc_type,
                       'Value': ioc_value,
                       'ID': ioc_id,
                       'DeviceID': devices_response,
                   }
               }
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CrowdStrike',
        outputs_key_field='DeviceIOC.ID',
        outputs=outputs,
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
        fetch_query = f"{fetch_query}"
        detections_ids = demisto.get(get_fetch_detections(filter_arg=fetch_query), 'resources')
    else:
        detections_ids = demisto.get(get_fetch_detections(), 'resources')
    detections_response_data = get_detections_entities(detections_ids)
    detections = list(detections_response_data.get('resources')) if detections_response_data else []
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
            fetch_query = f"{fetch_query}"
            incidents_ids = get_incidents_ids(filter_arg=fetch_query)
        else:
            incidents_ids = get_incidents_ids()
        handle_response_errors(incidents_ids)
        ids = incidents_ids.get('resources')
    if not ids:
        return CommandResults(readable_output='No incidents were found.')
    incidents_response_data = get_incidents_entities(ids)
    incidents = list(incidents_response_data.get('resources'))
    incidents_human_readable = incidents_to_human_readable(incidents)
    return CommandResults(
        readable_output=incidents_human_readable,
        outputs_prefix='CrowdStrike.Incidents',
        outputs_key_field='incident_id',
        outputs=incidents
    )


def create_host_group_command(name: str,
                              group_type: str | None = None,
                              description: str | None = None,
                              assignment_rule: str | None = None) -> CommandResults:
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
                              name: str | None = None,
                              description: str | None = None,
                              assignment_rule: str | None = None) -> CommandResults:
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


def list_host_group_members_command(host_group_id: str | None = None,
                                    filter: str | None = None,
                                    offset: str | None = None,
                                    limit: str | None = None) -> CommandResults:
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


def add_host_group_members_command(host_group_id: str, host_ids: list[str]) -> CommandResults:
    response = change_host_group_members(action_name='add-hosts',
                                         host_group_id=host_group_id,
                                         host_ids=host_ids)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def remove_host_group_members_command(host_group_id: str, host_ids: list[str]) -> CommandResults:
    response = change_host_group_members(action_name='remove-hosts',
                                         host_group_id=host_group_id,
                                         host_ids=host_ids)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def resolve_incident_command(ids: list[str], status: str):
    resolve_incident(ids, status)
    readable = '\n'.join([f'{incident_id} changed successfully to {status}' for incident_id in ids])
    return CommandResults(readable_output=readable)


def update_incident_comment_command(ids: list[str], comment: str):
    update_incident_comment(ids, comment)
    readable = '\n'.join([f'{incident_id} updated successfully with comment \"{comment}\"' for incident_id in ids])
    return CommandResults(readable_output=readable)


def list_host_groups_command(filter: str | None = None, offset: str | None = None, limit: str | None = None) \
        -> CommandResults:
    response = list_host_groups(filter, limit, offset)
    host_groups = response.get('resources')
    return CommandResults(outputs_prefix='CrowdStrike.HostGroup',
                          outputs_key_field='id',
                          outputs=host_groups,
                          readable_output=tableToMarkdown('Host Groups', host_groups, headers=HOST_GROUP_HEADERS),
                          raw_response=response)


def delete_host_groups_command(host_group_ids: list[str]) -> CommandResults:
    response = delete_host_groups(host_group_ids)
    deleted_ids = response.get('resources')
    readable = '\n'.join([f'Host groups {host_group_id} deleted successfully' for host_group_id in deleted_ids]) \
        if deleted_ids else f'Host groups {host_group_ids} are not deleted'
    return CommandResults(readable_output=readable,
                          raw_response=response)


def upload_batch_custom_ioc_command(
        multiple_indicators_json: str | None = None, timeout: str = '180',
) -> list[dict]:
    """
    :param multiple_indicators_json: A JSON object with list of CS Falcon indicators to upload.

    """
    batch_json = safe_load_json(multiple_indicators_json)
    raw_res = upload_batch_custom_ioc(batch_json, timeout=float(timeout))
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
    offline = argToBoolean(args.get('queue_offline', False))
    batch_id = init_rtr_batch_session(host_ids, offline)
    timeout = arg_to_number(args.get('timeout'))
    outputs = []

    for process_id in process_ids:
        full_command = f"{command_type} {process_id}"
        response = execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, timeout=timeout)
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
        return f"rm '{file_path}' --force"
    elif operating_system == 'Linux' or operating_system == 'Mac':
        return f"rm '{file_path}' -r -d"
    else:
        return ""


def rtr_remove_file_command(args: dict) -> CommandResults:
    file_path = args.get('file_path')
    host_ids = remove_duplicates_from_list_arg(args, 'host_ids')
    offline = argToBoolean(args.get('queue_offline', False))
    operating_system = args.get('os')
    timeout = arg_to_number(args.get('timeout'))
    full_command = match_remove_command_for_os(operating_system, file_path)
    command_type = "rm"

    batch_id = init_rtr_batch_session(host_ids, offline)
    response = execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, host_ids, timeout)
    outputs = parse_rtr_command_response(response, host_ids)
    human_readable = tableToMarkdown(
        f'{INTEGRATION_NAME} {command_type} over the file: {file_path}', outputs, headers=["HostID", "Error"])
    human_readable += get_human_readable_for_failed_command(outputs, host_ids, "HostID")
    return CommandResults(raw_response=response, readable_output=human_readable, outputs=outputs,
                          outputs_prefix="CrowdStrike.Command.rm", outputs_key_field="HostID")


def execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, host_ids=None, timeout=None):
    """
    Executes a timer for keeping the session refreshed
    """
    timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
    timer.start()
    try:
        response = run_batch_write_cmd(batch_id, command_type=command_type, full_command=full_command,
                                       optional_hosts=host_ids, timeout=timeout)
    finally:
        timer.cancel()
    return response


def execute_run_batch_admin_cmd_with_timer(batch_id, command_type, full_command, host_ids=None, timeout=None):
    timer = Timer(300, batch_refresh_session, kwargs={'batch_id': batch_id})
    timer.start()
    try:
        response = run_batch_admin_cmd(batch_id, command_type=command_type, full_command=full_command,
                                       optional_hosts=host_ids, timeout=timeout)
    finally:
        timer.cancel()
    return response


def rtr_general_command_on_hosts(host_ids: list, command: str, full_command: str, get_session_function: Callable,
                                 write_to_context=True, offline=False, timeout=None) -> \
        list[CommandResults | dict]:  # type:ignore
    """
    General function to run RTR commands depending on the given command.
    """
    batch_id = init_rtr_batch_session(host_ids, offline)
    response = get_session_function(batch_id, command_type=command, full_command=full_command,
                                    host_ids=host_ids, timeout=timeout)  # type:ignore
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
    offline = argToBoolean(args.get('queue_offline', False))
    registry_keys = remove_duplicates_from_list_arg(args, 'registry_keys')
    timeout = arg_to_number(args.get('timeout'))
    command_type = "reg"
    raw_response = []
    batch_id = init_rtr_batch_session(host_ids, offline)
    outputs = []
    files = []
    not_found_hosts = set()

    for registry_key in registry_keys:
        full_command = f"{command_type} query {registry_key}"
        response = execute_run_batch_write_cmd_with_timer(batch_id, command_type, full_command, host_ids=host_ids,
                                                          timeout=timeout)
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
        offline = argToBoolean(args.get('queue_offline', False))
        # run the first command to retrieve file
        args['hosts_and_requests_ids'] = run_get_command(is_polling=True, offline=offline)

    # we are here after we ran the cs-falcon-run-get-command command at the current run or in previous
    if not args.get('SHA256'):
        # this means that we don't have status yet (i.e we didn't get sha256)
        hosts_and_requests_ids = args.pop('hosts_and_requests_ids')
        args['request_ids'] = [res.get('RequestID') for res in hosts_and_requests_ids]
        get_status_response, args = status_get_command(args, is_polling=True)

        if args.get('SHA256'):
            # the status is ready, we can get the extracted files
            args.pop('SHA256')
            return rtr_get_extracted_file(get_status_response, args.get('filename'))  # type:ignore

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
    return None


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


def get_detection_for_incident_command(incident_id: str) -> CommandResults:
    behavior_res = get_behaviors_by_incident(incident_id)
    behaviors_id = behavior_res.get('resources')

    if not behaviors_id or behavior_res.get('meta', {}).get('pagination', {}).get('total', 0) == 0:
        return CommandResults(readable_output=f'Could not find behaviors for incident {incident_id}')

    detection_res = get_detections_by_behaviors(behaviors_id).get('resources', {})
    outputs = []

    for detection in detection_res:
        outputs.append({
            'incident_id': detection.get('incident_id'),
            'behavior_id': detection.get('behavior_id'),
            'detection_ids': detection.get('detection_ids'),

        })
    return CommandResults(outputs_prefix='CrowdStrike.IncidentDetection',
                          outputs=outputs,
                          readable_output=tableToMarkdown('Detection For Incident', outputs),
                          raw_response=detection_res)


def build_url_filter(values: list[str] | str | None):
    return 'cve.id:[\'' + "','".join(argToList(values)) + '\']'


def cs_falcon_spotlight_search_vulnerability_request(aid: list[str] | None, cve_id: list[str] | None,
                                                     cve_severity: list[str] | None, tags: list[str] | None,
                                                     status: list[str] | None, platform_name: str | None,
                                                     host_group: list[str] | None, host_type: list[str] | None,
                                                     last_seen_within: str | None, is_suppressed: str | None, filter_: str,
                                                     remediation: bool | None, evaluation_logic: bool | None,
                                                     host_info: bool | None, limit: str | None) -> dict:
    input_arg_dict = {'aid': aid,
                      'cve.id': cve_id,
                      'host_info.tags': tags,
                      'status': status,
                      'host_info.groups': host_group,
                      'last_seen_within': last_seen_within,
                      'suppression_info.is_suppressed': is_suppressed}
    input_arg_dict['cve.severity'] = [severity.upper() for severity in cve_severity] if cve_severity else None
    input_arg_dict['host_info.platform_name'] = platform_name.capitalize() if platform_name else None
    input_arg_dict['host_info.product_type_desc'] = [host_type_.capitalize() for host_type_ in host_type] if host_type else None
    remove_nulls_from_dictionary(input_arg_dict)
    # In Falcon Query Language, '+' (after decode '%2B) stands for AND and ',' for OR
    # (https://falcon.crowdstrike.com/documentation/45/falcon-query-language-fql)
    url_filter = filter_.replace('+', '%2B')
    if not any((input_arg_dict, url_filter)):
        raise DemistoException('Please add a at least one filter argument')
    for key, arg in input_arg_dict.items():
        if url_filter:
            url_filter += '%2B'
        if isinstance(arg, list):
            url_filter += f'{key}:[\'' + "','".join(arg) + '\']'
        else:
            url_filter += f"{key}:'{arg}'"  # All args should be a list. this is a fallback
    url_facet = '&facet=cve'
    for argument, url_value in (
        ('remediation', remediation),
        ('evaluation_logic', evaluation_logic),
        ('host_info', host_info),
    ):
        if argToBoolean(url_value):
            url_facet += f"&facet={argument}"
    # The url is hardcoded since facet is a parameter that can have serval values, therefore we can't use a dict
    suffix_url = f'/spotlight/combined/vulnerabilities/v1?filter={url_filter}{url_facet}&limit={limit}'
    return http_request('GET', suffix_url)


def cs_falcon_spotlight_list_host_by_vulnerability_request(cve_ids: list[str] | None, limit: str) -> dict:
    url_filter = build_url_filter(cve_ids)
    params = {'filter': url_filter, 'facet': 'host_info', 'limit': limit}
    return http_request('GET', '/spotlight/combined/vulnerabilities/v1', params=params)


def cve_request(cve_id: list[str] | None) -> dict:
    url_filter = build_url_filter(cve_id)
    return http_request('GET', '/spotlight/combined/vulnerabilities/v1',
                        params={'filter': url_filter, 'facet': 'cve'})


def cs_falcon_spotlight_search_vulnerability_command(args: dict) -> CommandResults:
    """
        Get a list of vulnerability by spotlight
        : args: filter which include params or filter param.
        : return: a list of vulnerabilities according to the user.
    """

    vulnerability_response = cs_falcon_spotlight_search_vulnerability_request(argToList(args.get('aid')),
                                                                              argToList(args.get('cve_id')),
                                                                              argToList(args.get('cve_severity')),
                                                                              argToList(args.get('tags')),
                                                                              argToList(args.get('status')),
                                                                              args.get('platform_name'),
                                                                              argToList(args.get('host_group')),
                                                                              argToList(args.get('host_type')),
                                                                              args.get('last_seen_within'),
                                                                              args.get('is_suppressed'),
                                                                              args.get('filter', ''),
                                                                              args.get('display_remediation_info'),
                                                                              args.get('display_evaluation_logic_info'),
                                                                              args.get('display_host_info'),
                                                                              args.get('limit'))
    headers = ['ID', 'Severity', 'Status', 'Base Score', 'Published Date', 'Impact Score',
               'Exploitability Score', 'Vector']
    outputs = []
    for vulnerability in vulnerability_response.get('resources', {}):
        outputs.append({'ID': vulnerability.get('cve', {}).get('id'),
                        'Severity': vulnerability.get('cve', {}).get('severity'),
                        'Status': vulnerability.get('status'),
                        'Base Score': vulnerability.get('cve', {}).get('base_score'),
                        'Published Date': vulnerability.get('cve', {}).get('published_date'),
                        'Impact Score': vulnerability.get('cve', {}).get('impact_score'),
                        'Exploitability Score': vulnerability.get('cve', {}).get('exploitability_score'),
                        'Vector': vulnerability.get('cve', {}).get('vector')
                        })
    human_readable = tableToMarkdown('List Vulnerabilities', outputs, removeNull=True, headers=headers)
    return CommandResults(raw_response=vulnerability_response,
                          readable_output=human_readable, outputs=vulnerability_response.get('resources'),
                          outputs_prefix="CrowdStrike.Vulnerability", outputs_key_field="id")


def cs_falcon_spotlight_list_host_by_vulnerability_command(args: dict) -> CommandResults:
    """
        Get a list of vulnerability by spotlight
        : args: filter which include params or filter param.
        : return: a list of vulnerabilities according to the user.
    """
    cve_ids = args.get('cve_ids')
    limit = args.get('limit', '50')
    vulnerability_response = cs_falcon_spotlight_list_host_by_vulnerability_request(cve_ids, limit)
    headers = ['CVE ID', 'hostname', 'os Version', 'Product Type Desc',
               'Local IP', 'ou', 'Machine Domain', 'Site Name',
               'CVE Exploitability Score', 'CVE Vector']
    outputs = []
    for vulnerability in vulnerability_response.get('resources', {}):
        outputs.append({'CVE ID': vulnerability.get('cve', {}).get('id'),
                        'hostname': vulnerability.get('host_info', {}).get('hostname'),
                        'os Version': vulnerability.get('host_info', {}).get('os_version'),
                        'Product Type Desc': vulnerability.get('host_info', {}).get('product_type_desc'),
                        'Local IP': vulnerability.get('host_info', {}).get('local_ip'),
                        'ou': vulnerability.get('host_info', {}).get('ou'),
                        'Machine Domain': vulnerability.get('host_info', {}).get('machine_domain'),
                        'Site Name': vulnerability.get('host_info', {}).get('site_name')})
    human_readable = tableToMarkdown('List Vulnerabilities For Host', outputs, removeNull=True, headers=headers)
    return CommandResults(raw_response=vulnerability_response,
                          readable_output=human_readable, outputs=vulnerability_response.get('resources'),
                          outputs_prefix="CrowdStrike.VulnerabilityHost", outputs_key_field="id")


def get_cve_command(args: dict) -> list[CommandResults]:
    """
        Get a list of vulnerabilities by spotlight
        : args: filter which include params or filter param.
        : return: a list of cve indicators according to the user.
    """
    cve = args.get("cve") or args.get('cve_id')
    if not cve:
        raise DemistoException('Please add a filter argument "cve".')
    command_results_list = []
    http_response = cve_request(cve)
    raw_cve = [res_element.get('cve') for res_element in http_response.get('resources', [])]
    for cve in raw_cve:
        relationships_list = create_relationships(cve)
        cve_dbot_score = create_dbot_Score(cve=cve, reliability=args.get('Reliability', 'A+ - 3rd party enrichment'))
        cve_indicator = Common.CVE(id=cve.get('id'),
                                   cvss='',
                                   published=cve.get('published_date'),
                                   modified='',
                                   description=cve.get('description'),
                                   cvss_score=cve.get('base_score'),
                                   cvss_vector=cve.get('vector'),
                                   dbot_score=cve_dbot_score,
                                   publications=create_publications(cve),
                                   relationships=relationships_list)
        cve_human_readable = {'ID': cve.get('id'),
                              'Description': cve.get('description'),
                              'Published Date': cve.get('published_date'),
                              'Base Score': cve.get('base_score')}
        human_readable = tableToMarkdown('CrowdStrike Falcon CVE', cve_human_readable,
                                         headers=['ID', 'Description', 'Published Date', 'Base Score'])
        command_results_list.append(CommandResults(raw_response=cve,
                                                   readable_output=human_readable,
                                                   relationships=relationships_list,
                                                   indicator=cve_indicator))
    return command_results_list


def create_ml_exclusion_command(args: dict) -> CommandResults:
    """Creates a machine learning exclusion.

    Args:
        args: Arguments to create the exclusion from.

    Returns:
        The created exclusion meta data.

    """
    create_args = assign_params(
        value=args.get('value'),
        excluded_from=argToList(args.get('excluded_from')),
        comment=args.get('comment'),
        groups=argToList(args.get('groups', 'all'))
    )

    exclusion = create_exclusion('ml', create_args).get('resources')
    human_readable = tableToMarkdown('CrowdStrike Falcon machine learning exclusion', exclusion, sort_headers=False,
                                     headerTransform=underscoreToCamelCase, is_auto_json_transform=True, removeNull=True)

    return CommandResults(
        outputs_prefix='CrowdStrike.MLExclusion',
        outputs_key_field='id',
        outputs=exclusion,
        readable_output=human_readable,
    )


def update_ml_exclusion_command(args: dict) -> CommandResults:
    """Updates a machine learning exclusion by providing an ID.

    Args:
        args: Arguments for updating the exclusion.

    Returns:
        The updated exclusion meta data.

    """
    update_args = assign_params(
        value=args.get('value'),
        comment=args.get('comment'),
        groups=argToList(args.get('groups'))
    )
    if not update_args:
        raise Exception('At least one argument (besides the id argument) should be provided to update the exclusion.')
    update_args.update({'id': args.get('id')})

    exclusion = update_exclusion('ml', update_args).get('resources')
    human_readable = tableToMarkdown('CrowdStrike Falcon machine learning exclusion', exclusion, sort_headers=False,
                                     headerTransform=underscoreToCamelCase, is_auto_json_transform=True, removeNull=True)

    return CommandResults(
        outputs_prefix='CrowdStrike.MLExclusion',
        outputs_key_field='id',
        outputs=exclusion,
        readable_output=human_readable,
    )


def delete_ml_exclusion_command(args: dict) -> CommandResults:
    """Delete a machine learning exclusion by providing an ID.

    Args:
        args: Arguments for deleting the exclusion (in particular only the id is needed).

    Returns:
        A message that the exclusion has been deleted.

    """
    ids = argToList(args.get('ids'))

    delete_exclusion('ml', ids)

    return CommandResults(
        readable_output=f'The machine learning exclusions with IDs {" ".join(ids)} was successfully deleted.'
    )


def search_ml_exclusion_command(args: dict) -> CommandResults:
    """Searches machine learning exclusions by providing an ID / value / cusotm-filter.

    Args:
        args: Arguments for searching the exclusions.

    Returns:
        The exclusions meta data.

    """
    if not (ids := argToList(args.get('ids'))):
        search_args = assign_params(
            sort=args.get('sort'),
            limit=args.get('limit'),
            offset=args.get('offset'),
        )
        if value := args.get('value'):
            ids = get_exclusions('ml', f"value:'{value}'", search_args).get('resources')
        else:
            ids = get_exclusions('ml', args.get('filter'), search_args).get('resources')

    if not ids:
        return CommandResults(
            readable_output='The arguments/filters you provided did not match any exclusion.'
        )

    exclusions = get_exclusion_entities('ml', ids).get('resources')
    human_readable = tableToMarkdown('CrowdStrike Falcon machine learning exclusions', exclusions, sort_headers=False,
                                     headerTransform=underscoreToCamelCase, is_auto_json_transform=True, removeNull=True)

    return CommandResults(
        outputs_prefix='CrowdStrike.MLExclusion',
        outputs_key_field='id',
        outputs=exclusions,
        readable_output=human_readable,
    )


def create_ioa_exclusion_command(args: dict) -> CommandResults:
    """Creates an IOA exclusion.

    Args:
        args: Arguments to create the exclusion from.

    Returns:
        The created exclusion meta data.

    """
    create_args = assign_params(
        name=args.get('exclusion_name'),
        pattern_id=args.get('pattern_id'),
        pattern_name=args.get('pattern_name'),
        cl_regex=args.get('cl_regex'),
        ifn_regex=args.get('ifn_regex'),
        comment=args.get('comment'),
        description=args.get('description'),
        groups=argToList(args.get('groups', 'all')),
        detection_json=args.get('detection_json')
    )

    exclusion = create_exclusion('ioa', create_args).get('resources')
    human_readable = tableToMarkdown('CrowdStrike Falcon IOA exclusion', exclusion, is_auto_json_transform=True,
                                     headerTransform=underscoreToCamelCase, sort_headers=False, removeNull=True)

    return CommandResults(
        outputs_prefix='CrowdStrike.IOAExclusion',
        outputs_key_field='id',
        outputs=exclusion,
        readable_output=human_readable,
    )


def update_ioa_exclusion_command(args: dict) -> CommandResults:
    """Updates an IOA exclusion by providing an ID.

    Args:
        args: Arguments for updating the exclusion.

    Returns:
        The updated exclusion meta data.

    """
    update_args = assign_params(
        name=args.get('exclusion_name'),
        pattern_id=args.get('pattern_id'),
        pattern_name=args.get('pattern_name'),
        cl_regex=args.get('cl_regex'),
        ifn_regex=args.get('ifn_regex'),
        comment=args.get('comment'),
        description=args.get('description'),
        groups=argToList(args.get('groups')),
        detection_json=args.get('detection_json')
    )
    if not update_args:
        raise Exception('At least one argument (besides the id argument) should be provided to update the exclusion.')
    update_args.update({'id': args.get('id')})

    exclusion = update_exclusion('ioa', update_args).get('resources')
    human_readable = tableToMarkdown('CrowdStrike Falcon IOA exclusion', exclusion, is_auto_json_transform=True,
                                     headerTransform=underscoreToCamelCase, removeNull=True, sort_headers=False)

    return CommandResults(
        outputs_prefix='CrowdStrike.IOAExclusion',
        outputs_key_field='id',
        outputs=exclusion,
        readable_output=human_readable,
    )


def delete_ioa_exclusion_command(args: dict) -> CommandResults:
    """Delete an IOA exclusion by providing an ID.

    Args:
        args: Arguments for deleting the exclusion (in particular only the id is needed).

    Returns:
        A message that the exclusion has been deleted.

    """
    ids = argToList(args.get('ids'))

    delete_exclusion('ioa', ids)

    return CommandResults(
        readable_output=f'The IOA exclusions with IDs {" ".join(ids)} was successfully deleted.'
    )


def search_ioa_exclusion_command(args: dict) -> CommandResults:
    """Searches IOA exclusions by providing an ID / name / cusotm-filter.

    Args:
        args: Arguments for searching the exclusions.

    Returns:
        The exclusions meta data.

    """
    exclusion_name = args.get('name')
    if not (ids := argToList(args.get('ids'))):
        search_args = assign_params(
            limit=args.get('limit'),
            offset=args.get('offset')
        )
        if exclusion_name:
            ids = get_exclusions('ioa', f"name:~'{exclusion_name}'", search_args).get('resources')
        else:
            ids = get_exclusions('ioa', args.get('filter'), search_args).get('resources')

    if not ids:
        return CommandResults(
            readable_output='The arguments/filters you provided did not match any exclusion.'
        )

    exclusions = get_exclusion_entities('ioa', ids).get('resources', [])
    if exclusion_name and exclusions:
        exclusions = list(filter(lambda x: x.get('name') == exclusion_name, exclusions))
    human_readable = tableToMarkdown('CrowdStrike Falcon IOA exclusions', exclusions, is_auto_json_transform=True,
                                     headerTransform=underscoreToCamelCase, removeNull=True, sort_headers=False)

    return CommandResults(
        outputs_prefix='CrowdStrike.IOAExclusion',
        outputs_key_field='id',
        outputs=exclusions,
        readable_output=human_readable,
    )


def list_quarantined_file_command(args: dict) -> CommandResults:
    """Get quarantine file metadata by specified IDs / custom-filter.

    Args:
        args: Arguments for searching the quarantine files.

    Returns:
        The quarantine files meta data.

    """
    if not (ids := argToList(args.get('ids'))):
        pagination_args = assign_params(
            limit=args.get('limit', '50'),
            offset=args.get('offset')
        )
        search_args = assign_params(
            state=args.get('state'),
            sha256=argToList(args.get('sha256')),
            filename=argToList(args.get('filename')),
            hostname=argToList(args.get('hostname')),
            username=argToList(args.get('username')),
        )

        ids = list_quarantined_files_id(args.get('filter'), search_args, pagination_args).get('resources')

    if not ids:
        return CommandResults(
            readable_output='The arguments/filters you provided did not match any files.'
        )

    files = list_quarantined_files(ids).get('resources')
    human_readable = tableToMarkdown('CrowdStrike Falcon Quarantined File', files, is_auto_json_transform=True,
                                     headerTransform=underscoreToCamelCase, sort_headers=False, removeNull=True)

    return CommandResults(
        outputs_prefix='CrowdStrike.QuarantinedFile',
        outputs_key_field='id',
        outputs=files,
        readable_output=human_readable,
    )


def apply_quarantine_file_action_command(args: dict) -> CommandResults:
    """Apply action to quarantine file.

    Args:
        args: Arguments for searching and applying action to the quarantine files.

    Returns:
        The applied quarantined files meta data.

    """
    if not (ids := argToList(args.get('ids'))):
        pagination_args = assign_params(
            limit=args.get('limit', '50'),
            offset=args.get('offset')
        )
        search_args = assign_params(
            state=args.get('state'),
            sha256=argToList(args.get('sha256')),
            filename=argToList(args.get('filename')),
            hostname=argToList(args.get('hostname')),
            username=argToList(args.get('username')),
        )
        if not search_args:
            raise Exception('At least one search argument (filename, hostname, sha256, state, username, ids, or filter)'
                            ' is required to update the quarantine file.')

        ids = list_quarantined_files_id(args.get('filter'), search_args, pagination_args).get('resources')

    update_args = assign_params(
        ids=ids,
        action=args.get('action'),
        comment=args.get('comment'),
    )
    if not update_args:
        raise Exception('At least one update argument (action, comment) should be provided to update the quarantine file.')

    apply_quarantined_files_action(update_args).get('resources')

    return CommandResults(
        readable_output=f'The Quarantined File with IDs {ids} was successfully updated.',
    )


def build_cs_falcon_filter(custom_filter: str | None = None, **filter_args) -> str:
    """Creates an FQL syntax filter from a dictionary and a custom built filter

    :custom_filter: custom filter from user (will take priority if conflicts with dictionary), defaults to None
    :filter_args: args to translate to FQL format.

    :return: FQL syntax filter.
    """

    custom_filter_list = custom_filter.split('+') if custom_filter else []
    arguments = [f'{key}:{argToList(value)}' for key, value in filter_args.items() if value]
    # custom_filter takes priority because it is first
    return "%2B".join(custom_filter_list + arguments)


def ODS_query_scans_request(**query_params) -> dict:

    remove_nulls_from_dictionary(query_params)
    # http_request messes up the params, so they were put directly in the url:
    url_params = "&".join(f"{k}={v}" for k, v in query_params.items())
    return http_request('GET', f'/ods/queries/scans/v1?{url_params}')


def ODS_get_scans_by_id_request(ids: list[str]) -> dict:

    url_params = '&'.join(f'ids={query_id}' for query_id in ids)
    return http_request('GET', f'/ods/entities/scans/v1?{url_params}')


def map_scan_resource_to_UI(resource: dict) -> dict:

    output = {
        'ID': resource.get('id'),
        'Status': resource.get('status'),
        'Severity': resource.get('severity'),
        # Every host in resource.metadata has a "filecount" which is a dictionary
        # that counts the files traversed, skipped, found to be malicious and the like.
        'File Count': '\n-\n'.join('\n'.join(f'{k}: {v}' for k, v in filecount.items())
                                   for host in resource.get('metadata', []) if (filecount := host.get('filecount', {}))),
        'Description': resource.get('description'),
        'Hosts/Host groups': resource.get('hosts') or resource.get('host_groups'),
        'Start time': resource.get('scan_started_on'),
        'End time': resource.get('scan_completed_on'),
        'Run by': resource.get('created_by')
    }
    return output


def ODS_get_scan_resources_to_human_readable(resources: list[dict]) -> str:

    human_readable = tableToMarkdown(
        'CrowdStrike Falcon ODS Scans',
        [map_scan_resource_to_UI(resource) for resource in resources],
        headers=['ID', 'Status', 'Severity', 'File Count', 'Description',
                 'Hosts/Host groups', 'End time', 'Start time', 'Run by']
    )

    return human_readable


def get_ODS_scan_ids(args: dict) -> list[str] | None:

    demisto.debug('Fetching IDs from query api')

    query_filter = build_cs_falcon_filter(
        custom_filter=args.get('filter'),
        initiated_from=args.get('initiated_from'),
        status=args.get('status'),
        severity=args.get('severity'),
        scan_started_on=args.get('scan_started_on'),
        scan_completed_on=args.get('scan_completed_on'),
    )

    raw_response = ODS_query_scans_request(
        filter=query_filter,
        offset=args.get('offset'),
        limit=args.get('limit'),
    )

    return raw_response.get('resources')


@polling_function(
    'cs-falcon-ods-query-scan',
    poll_message='Retrieving scan results:',
    polling_arg_name='wait_for_result',
    interval=arg_to_number(dict_safe_get(demisto.args(), ['interval_in_seconds'], 0, (int, str))),
    timeout=arg_to_number(dict_safe_get(demisto.args(), ['timeout_in_seconds'], 0, (int, str))),
)
def cs_falcon_ODS_query_scans_command(args: dict) -> PollResult:
    # call the query api if no ids given
    ids = argToList(args.get('ids')) or get_ODS_scan_ids(args)

    if not ids:
        command_results = CommandResults(readable_output='No scans match the arguments/filter.')
        scan_in_progress = False

    else:
        response = ODS_get_scans_by_id_request(ids)
        resources = response.get('resources', [])

        scan_in_progress = (
            len(resources) == 1
            and dict_safe_get(resources, [0, 'status']) in ('pending', 'running')
        )

        human_readable = ODS_get_scan_resources_to_human_readable(resources)
        command_results = CommandResults(
            raw_response=response,
            outputs_prefix='CrowdStrike.ODSScan',
            outputs_key_field='id',
            outputs=resources,
            readable_output=human_readable,
        )

    return PollResult(response=command_results,
                      continue_to_poll=scan_in_progress,
                      args_for_next_run=args)


def ODS_query_scheduled_scans_request(**query_params) -> dict:
    remove_nulls_from_dictionary(query_params)
    # http_request messes up the params, so they were put directly in the url:
    url_params = "&".join(f"{k}={v}" for k, v in query_params.items())
    return http_request('GET', f'/ods/queries/scheduled-scans/v1?{url_params}')


def ODS_get_scheduled_scans_by_id_request(ids: list[str]) -> dict:
    url_params = '&'.join(f'ids={query_id}' for query_id in ids)
    return http_request('GET', f'/ods/entities/scheduled-scans/v1?{url_params}')


def map_scheduled_scan_resource_to_UI(resource: dict) -> dict:
    output = {
        'ID': resource.get('id'),
        'Hosts targeted': len(resource.get('metadata', [])),
        'Description': resource.get('description'),
        'Host groups': resource.get('host_groups'),
        'Start time': resource.get('schedule', {}).get('start_timestamp'),
        'Created by': resource.get('created_by'),
    }
    return output


def ODS_get_scheduled_scan_resources_to_human_readable(resources: list[dict]) -> str:

    human_readable = tableToMarkdown(
        'CrowdStrike Falcon ODS Scheduled Scans',
        [map_scheduled_scan_resource_to_UI(resource) for resource in resources],
        headers=['ID', 'Hosts targeted', 'Description',
                 'Host groups', 'Start time', 'Created by'],
    )

    return human_readable


def get_ODS_scheduled_scan_ids(args: dict) -> list[str] | None:

    demisto.debug('Fetching IDs from query api')

    query_filter = build_cs_falcon_filter(**{
        'custom_filter': args.get('filter'),
        'initiated_from': args.get('initiated_from'),
        'status': args.get('status'),
        'created_on': args.get('created_on'),
        'created_by': args.get('created_by'),
        'schedule.start_timestamp': args.get('start_timestamp'),
        'deleted': args.get('deleted'),
    })

    raw_response = ODS_query_scheduled_scans_request(
        filter=query_filter,
        offset=args.get('offset'),
        limit=args.get('limit'),
    )

    return raw_response.get('resources')


def cs_falcon_ODS_query_scheduled_scan_command(args: dict) -> CommandResults:
    # call the query api if no ids given
    ids = argToList(args.get('ids')) or get_ODS_scheduled_scan_ids(args)

    if not ids:
        return CommandResults(readable_output='No scheduled scans match the arguments/filter.')

    response = ODS_get_scheduled_scans_by_id_request(ids)
    resources = response.get('resources', [])
    human_readable = ODS_get_scheduled_scan_resources_to_human_readable(resources)

    command_results = CommandResults(
        raw_response=response,
        outputs_prefix='CrowdStrike.ODSScheduledScan',
        outputs_key_field='id',
        outputs=resources,
        readable_output=human_readable,
    )

    return command_results


def ODS_query_scan_hosts_request(**query_params) -> dict:
    remove_nulls_from_dictionary(query_params)
    # http_request messes up the params, so they were put directly in the url:
    url_params = "&".join(f"{k}={v}" for k, v in query_params.items())
    return http_request('GET', f'/ods/queries/scan-hosts/v1?{url_params}')


def ODS_get_scan_hosts_by_id_request(ids: list[str]) -> dict:

    url_params = '&'.join(f'ids={query_id}' for query_id in ids)
    return http_request('GET', f'/ods/entities/scan-hosts/v1?{url_params}')


def get_ODS_scan_host_ids(args: dict) -> list[str]:

    query_filter = build_cs_falcon_filter(
        custom_filter=args.get('filter'),
        host_id=args.get('host_ids'),
        scan_id=args.get('scan_ids'),
        status=args.get('status'),
        started_on=args.get('started_on'),
        completed_on=args.get('completed_on'),
    )

    raw_response = ODS_query_scan_hosts_request(
        filter=query_filter,
        offset=args.get('offset'),
        limit=args.get('limit'),
    )

    return raw_response.get('resources', [])


def map_scan_host_resource_to_UI(resource: dict) -> dict:
    output = {
        'ID': resource.get('id'),
        'Scan ID': resource.get('scan_id'),
        'Host ID': resource.get('host_id'),
        'Filecount': resource.get('filecount'),
        'Status': resource.get('status'),
        'Severity': resource.get('severity'),
        'Started on': resource.get('started_on'),
    }
    return output


def ODS_get_scan_hosts_resources_to_human_readable(resources: list[dict]) -> str:

    human_readable = tableToMarkdown(
        'CrowdStrike Falcon ODS Scan Hosts',
        [map_scan_host_resource_to_UI(resource) for resource in resources],
        headers=['ID', 'Scan ID', 'Host ID',
                 'Filecount', 'Status',
                 'Severity', 'Started on'],
    )

    return human_readable


def cs_falcon_ods_query_scan_host_command(args: dict) -> CommandResults:

    ids = get_ODS_scan_host_ids(args)

    if not ids:
        return CommandResults(readable_output='No hosts to display.')

    response = ODS_get_scan_hosts_by_id_request(ids)
    resources = response.get('resources', [])
    human_readable = ODS_get_scan_hosts_resources_to_human_readable(resources)

    command_results = CommandResults(
        raw_response=response,
        outputs_prefix='CrowdStrike.ODSScanHost',
        outputs_key_field='id',
        outputs=resources,
        readable_output=human_readable,
    )

    return command_results


def ODS_query_malicious_files_request(**query_params) -> dict:
    remove_nulls_from_dictionary(query_params)
    # http_request messes up the params, so they were put directly in the url:
    url_params = "&".join(f"{k}={v}" for k, v in query_params.items())
    return http_request('GET', f'/ods/queries/malicious-files/v1?{url_params}')


def ODS_get_malicious_files_by_id_request(ids: list[str]) -> dict:

    url_params = '&'.join(f'ids={query_id}' for query_id in ids)
    return http_request('GET', f'/ods/entities/malicious-files/v1?{url_params}')


def map_malicious_file_resource_to_UI(resource: dict) -> dict:
    output = {
        'ID': resource.get('id'),
        'Scan id': resource.get('scan_id'),
        'Filename': resource.get('filename'),
        'Hash': resource.get('hash'),
        'Severity': resource.get('severity'),
        'Last updated': resource.get('last_updated'),
    }
    return output


def ODS_get_malicious_files_resources_to_human_readable(resources: list[dict]) -> str:

    human_readable = tableToMarkdown(
        'CrowdStrike Falcon ODS Malicious Files',
        [map_malicious_file_resource_to_UI(resource) for resource in resources],
        headers=['ID', 'Scan id', 'Filename', 'Hash', 'Severity', 'Last updated'],
    )

    return human_readable


def get_ODS_malicious_files_ids(args: dict) -> list[str] | None:

    demisto.debug('Fetching IDs from query api')

    query_filter = build_cs_falcon_filter(
        custom_filter=args.get('filter'),
        host_id=args.get('host_ids'),
        scan_id=args.get('scan_ids'),
        filepath=args.get('file_paths'),
        filename=args.get('file_names'),
        hash=args.get('hash'),
    )

    raw_response = ODS_query_malicious_files_request(
        filter=query_filter,
        offset=args.get('offset'),
        limit=args.get('limit'),
    )

    return raw_response.get('resources')


def cs_falcon_ODS_query_malicious_files_command(args: dict) -> CommandResults:
    # call the query api if no file_ids given
    ids = argToList(args.get('file_ids')) or get_ODS_malicious_files_ids(args)

    if not ids:
        return CommandResults(readable_output='No malicious files match the arguments/filter.')

    response = ODS_get_malicious_files_by_id_request(ids)
    resources = response.get('resources', [])
    human_readable = ODS_get_malicious_files_resources_to_human_readable(resources)

    command_results = CommandResults(
        raw_response=response,
        outputs_prefix='CrowdStrike.ODSMaliciousFile',
        outputs_key_field='id',
        outputs=resources,
        readable_output=human_readable,
    )

    return command_results


def make_create_scan_request_body(args: dict, is_scheduled: bool) -> dict:

    result = {
        'host_groups': argToList(args.get('host_groups')),
        'file_paths': argToList(args.get('file_paths')),
        'scan_exclusions': argToList(args.get('scan_exclusions')),
        'scan_inclusions': argToList(args.get('scan_inclusions')),
        'initiated_from': args.get('initiated_from'),
        'cpu_priority': CPU_UTILITY_STR_TO_INT_KEY_MAP.get(args.get('cpu_priority')),  # type: ignore[arg-type]
        'description': args.get('description'),
        'quarantine': argToBoolean(args.get('quarantine')) if args.get('quarantine') is not None else None,
        'pause_duration': arg_to_number(args.get('pause_duration')),
        'sensor_ml_level_detection': arg_to_number(args.get('sensor_ml_level_detection')),
        'sensor_ml_level_prevention': arg_to_number(args.get('sensor_ml_level_prevention')),
        'cloud_ml_level_detection': arg_to_number(args.get('cloud_ml_level_detection')),
        'cloud_ml_level_prevention': arg_to_number(args.get('cloud_ml_level_prevention')),
        'max_duration': arg_to_number(args.get('max_duration')),
    }

    if is_scheduled:
        result['schedule'] = {
            'interval': SCHEDULE_INTERVAL_STR_TO_INT.get(args['schedule_interval'].lower()),
            'start_timestamp': (
                dateparser.parse(args['schedule_start_timestamp'])
                or return_error('Invalid start_timestamp.')
            ).strftime("%Y-%m-%dT%H:%M"),
        }

    else:
        result['hosts'] = argToList(args.get('hosts'))

    return result


def ODS_create_scan_request(args: dict, is_scheduled: bool) -> dict:
    body = make_create_scan_request_body(args, is_scheduled)
    remove_nulls_from_dictionary(body)
    return http_request('POST', f'/ods/entities/{"scheduled-"*is_scheduled}scans/v1', json=body)


def ODS_verify_create_scan_command(args: dict) -> None:

    if not (args.get('hosts') or args.get('host_groups')):
        raise DemistoException('MUST set either hosts OR host_groups.')

    if not (args.get('file_paths') or args.get('scan_inclusions')):
        raise DemistoException('MUST set either file_paths OR scan_inclusions.')


def ods_create_scan(args: dict, is_scheduled: bool) -> dict:

    ODS_verify_create_scan_command(args)

    response = ODS_create_scan_request(args, is_scheduled)
    resource = dict_safe_get(response, ('resources', 0), return_type=dict, raise_return_type=False)

    if not (resource and resource.get('id')):
        raise DemistoException('Unexpected response from CrowdStrike Falcon')

    return resource


def cs_falcon_ods_create_scan_command(args: dict) -> CommandResults:

    resource = ods_create_scan(args, is_scheduled=False)
    scan_id = resource.get('id')

    query_scan_args = {
        'ids': scan_id,
        'wait_for_result': True,
        'interval_in_seconds': args.get('interval_in_seconds'),
        'timeout_in_seconds': args.get('timeout_in_seconds'),
    }

    return cs_falcon_ODS_query_scans_command(query_scan_args)


def cs_falcon_ods_create_scheduled_scan_command(args: dict) -> CommandResults:

    resource = ods_create_scan(args, is_scheduled=True)

    human_readable = f'Successfully created scheduled scan with ID: {resource.get("id")}'

    command_results = CommandResults(
        raw_response=resource,
        outputs_prefix='CrowdStrike.ODSScheduledScan',
        outputs_key_field='id',
        outputs=resource,
        readable_output=human_readable,
    )

    return command_results


def ODS_delete_scheduled_scans_request(ids: list[str], scan_filter: str | None = None) -> dict:
    ids_params = [f'ids={scan_id}' for scan_id in ids]
    filter_param = [f'filter={scan_filter.replace("+", "%2B")}'] if scan_filter else []
    url_params = '&'.join(ids_params + filter_param)
    return http_request('DELETE', f'/ods/entities/scheduled-scans/v1?{url_params}', status_code=500)


def cs_falcon_ods_delete_scheduled_scan_command(args: dict) -> CommandResults:

    ids, scan_filter = argToList(args.get('ids')), args.get('filter')
    response = ODS_delete_scheduled_scans_request(ids, scan_filter)

    if dict_safe_get(response, ['errors', 0, 'code']) == 500:
        raise DemistoException(
            'CS Falcon returned an error.\n'
            'Code: 500\n'
            f'Message: {dict_safe_get(response, ["errors", 0, "message"])}\n'
            'Perhaps there are no scans to delete?'
        )

    human_readable = tableToMarkdown('Deleted Scans:', response.get('resources', []), headers=['Scan ID'])

    command_results = CommandResults(
        raw_response=response,
        readable_output=human_readable,
    )

    return command_results


def list_identity_entities_command(args: dict) -> CommandResults:
    """List identity entities
    Args:
        args: The demisto.args() dict object.
    Returns:
        The command result object.
    """
    client = create_gql_client()
    args_keys_ls = ["sort_key", "sort_order", "max_risk_score_severity", "min_risk_score_severity"]
    ls_args_keys_ls = ["type", "entity_id", "primary_display_name", "secondary_display_name", "email"]
    variables = {}
    for key in args_keys_ls:
        if key in args:
            variables[key] = args.get(key)
    for key in ls_args_keys_ls:
        if key in args:
            variables[key] = args.get(key, "").split(",")
    if "enabled" in args:
        variables["enabled"] = argToBoolean(args.get("enabled"))
    idp_query = gql("""
    query ($sort_key: EntitySortKey, $type: [EntityType!], $sort_order: SortOrder, $entity_id: [UUID!],
           $primary_display_name: [String!], $secondary_display_name: [String!], $max_risk_score_severity: ScoreSeverity,
           $min_risk_score_severity: ScoreSeverity, $enabled: Boolean, $email: [String!], $first: Int, $after: Cursor) {
        entities(types: $type, sortKey: $sort_key, sortOrder: $sort_order, entityIds: $entity_id, enabled: $enabled,
                 primaryDisplayNames: $primary_display_name, secondaryDisplayNames: $secondary_display_name,
                 maxRiskScoreSeverity: $max_risk_score_severity, minRiskScoreSeverity: $min_risk_score_severity,
                 emailAddresses: $email, first: $first, after: $after) {
            pageInfo{
                hasNextPage
                endCursor
            }
            nodes{
                primaryDisplayName
                secondaryDisplayName
                isHuman:hasRole(type: HumanUserAccountRole)
                isProgrammatic:hasRole(type: ProgrammaticUserAccountRole)
                ...
                on
                UserEntity{
                    emailAddresses
                }
                riskScore
                riskScoreSeverity
                riskFactors{
                    type
                    severity
                }
            }
        }
    }
""")
    identity_entities_ls = []
    next_token = args.get("next_token", "")
    limit = arg_to_number(args.get("limit", "50")) or 50
    page = arg_to_number(args.get("page", "0"))
    page_size = arg_to_number(args.get("page_size", "50"))
    res_ls = []
    has_next_page = True
    if page:
        variables["first"] = page_size
        while has_next_page and page:
            if next_token:
                variables["after"] = next_token
            res = client.execute(idp_query, variable_values=variables)
            res_ls.append(res)
            page -= 1
            pageInfo = res.get("entities", {}).get("pageInfo", {})
            has_next_page = pageInfo.get("hasNextPage", False)
            if page == 0:
                identity_entities_ls.extend(res.get("entities", {}).get("nodes", []))
            if has_next_page:
                next_token = pageInfo.get("endCursor", "")
    else:
        while has_next_page and limit > 0:
            variables["first"] = min(1000, limit)
            if next_token:
                variables["after"] = next_token
            res = client.execute(idp_query, variable_values=variables)
            res_ls.append(res)
            pageInfo = res.get("entities", {}).get("pageInfo", {})
            has_next_page = pageInfo.get("hasNextPage", False)
            identity_entities_ls.extend(res.get("entities", {}).get("nodes", []))
            if has_next_page:
                next_token = pageInfo.get("endCursor", "")
            limit -= 1000
    headers = ["primaryDisplayName", "secondaryDisplayName", "isHuman", "isProgrammatic", "isAdmin", "emailAddresses",
               "riskScore", "riskScoreSeverity", "riskFactors"]

    return CommandResults(
        outputs_prefix='CrowdStrike.IDPEntity',
        outputs=createContext(response_to_context(identity_entities_ls), removeNull=True),
        readable_output=tableToMarkdown("Identity entities", identity_entities_ls, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace),
        raw_response=res_ls,
    )


def create_gql_client(url_suffix="identity-protection/combined/graphql/v1"):
    """
        Creates a gql client to handle the gql requests.
    Args:
        url_suffix: The url suffix for the request.
    Returns:
        The created client.
    """
    url_suffix = url_suffix['url'][1:] if url_suffix.startswith('/') else url_suffix
    kwargs = {
        'url': f"{SERVER}/{url_suffix}",
        'verify': USE_SSL,
        'retries': 3,
        'headers': {'Authorization': f'Bearer {get_token()}',
                    "Accept": "application/json",
                    "Content-Type": "application/json"}
    }
    transport = RequestsHTTPTransport(**kwargs)
    handle_proxy()
    client = Client(
        transport=transport,
        fetch_schema_from_transport=True,
    )
    return client


''' COMMANDS MANAGER / SWITCH PANEL '''


LOG(f'Command being called is {demisto.command()}')


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
        elif command == 'cs-falcon-update-incident-comment':
            return_results(update_incident_comment_command(comment=args.get('comment'),
                                                           ids=argToList(args.get('ids'))))
        elif command == 'cs-falcon-batch-upload-custom-ioc':
            return_results(upload_batch_custom_ioc_command(**args))

        elif command == 'cs-falcon-rtr-kill-process':
            return_results(rtr_kill_process_command(args))

        elif command == 'cs-falcon-rtr-remove-file':
            return_results(rtr_remove_file_command(args))

        elif command == 'cs-falcon-rtr-list-processes':
            host_id = args.get('host_id')
            offline = argToBoolean(args.get('queue_offline', False))
            timeout = arg_to_number(args.get('timeout'))
            return_results(
                rtr_general_command_on_hosts([host_id], "ps", "ps", execute_run_batch_write_cmd_with_timer, True, offline,
                                             timeout=timeout))

        elif command == 'cs-falcon-rtr-list-network-stats':
            host_id = args.get('host_id')
            offline = argToBoolean(args.get('queue_offline', False))
            timeout = arg_to_number(args.get('timeout'))
            return_results(
                rtr_general_command_on_hosts([host_id], "netstat", "netstat", execute_run_batch_write_cmd_with_timer,
                                             True, offline, timeout=timeout))

        elif command == 'cs-falcon-rtr-read-registry':
            return_results(rtr_read_registry_keys_command(args))

        elif command == 'cs-falcon-rtr-list-scheduled-tasks':
            full_command = f'runscript -Raw=```schtasks /query /fo LIST /v```'  # noqa: F541
            host_ids = argToList(args.get('host_ids'))
            offline = argToBoolean(args.get('queue_offline', False))
            timeout = arg_to_number(args.get('timeout'))
            return_results(rtr_general_command_on_hosts(host_ids, "runscript", full_command,
                                                        execute_run_batch_admin_cmd_with_timer, offline, timeout=timeout))
        elif command == 'cs-falcon-rtr-retrieve-file':
            return_results(rtr_polling_retrieve_file_command(args))
        elif command == 'cs-falcon-get-detections-for-incident':
            return_results(get_detection_for_incident_command(args.get('incident_id')))
        elif command == 'get-remote-data':
            return_results(get_remote_data_command(args))
        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(args))
        elif command == 'update-remote-system':
            return_results(update_remote_system_command(args))
        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command())
        elif command == 'cs-falcon-spotlight-search-vulnerability':
            return_results(cs_falcon_spotlight_search_vulnerability_command(args))
        elif command == 'cs-falcon-spotlight-list-host-by-vulnerability':
            return_results(cs_falcon_spotlight_list_host_by_vulnerability_command(args))
        elif command == 'cve':
            return_results(get_cve_command(args))
        elif command == 'cs-falcon-create-ml-exclusion':
            return_results(create_ml_exclusion_command(args))
        elif command == 'cs-falcon-update-ml-exclusion':
            return_results(update_ml_exclusion_command(args))
        elif command == 'cs-falcon-delete-ml-exclusion':
            return_results(delete_ml_exclusion_command(args))
        elif command == 'cs-falcon-search-ml-exclusion':
            return_results(search_ml_exclusion_command(args))
        elif command == 'cs-falcon-create-ioa-exclusion':
            return_results(create_ioa_exclusion_command(args))
        elif command == 'cs-falcon-update-ioa-exclusion':
            return_results(update_ioa_exclusion_command(args))
        elif command == 'cs-falcon-delete-ioa-exclusion':
            return_results(delete_ioa_exclusion_command(args))
        elif command == 'cs-falcon-search-ioa-exclusion':
            return_results(search_ioa_exclusion_command(args))
        elif command == 'cs-falcon-list-quarantined-file':
            return_results(list_quarantined_file_command(args))
        elif command == 'cs-falcon-apply-quarantine-file-action':
            return_results(apply_quarantine_file_action_command(args))
        elif command == 'cs-falcon-ods-query-scan':
            return_results(cs_falcon_ODS_query_scans_command(args))
        elif command == 'cs-falcon-ods-query-scheduled-scan':
            return_results(cs_falcon_ODS_query_scheduled_scan_command(args))
        elif command == 'cs-falcon-ods-query-scan-host':
            return_results(cs_falcon_ods_query_scan_host_command(args))
        elif command == 'cs-falcon-ods-query-malicious-files':
            return_results(cs_falcon_ODS_query_malicious_files_command(args))
        elif command == 'cs-falcon-ods-create-scan':
            return_results(cs_falcon_ods_create_scan_command(args))
        elif command == 'cs-falcon-ods-create-scheduled-scan':
            return_results(cs_falcon_ods_create_scheduled_scan_command(args))
        elif command == 'cs-falcon-ods-delete-scheduled-scan':
            return_results(cs_falcon_ods_delete_scheduled_scan_command(args))
        elif command == 'cs-falcon-list-identity-entities':
            return_results(list_identity_entities_command(args))
        else:
            raise NotImplementedError(f'CrowdStrike Falcon error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
