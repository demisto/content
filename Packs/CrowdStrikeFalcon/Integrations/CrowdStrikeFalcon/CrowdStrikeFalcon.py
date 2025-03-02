import demistomock as demisto  # noqa: F401
from CommonServerPython import *

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
MOBILE_DETECTION = "MOBILE detection"
ENDPOINT_DETECTION = 'detection'
IDP_DETECTION_FETCH_TYPE = "IDP Detection"
MOBILE_DETECTION_FETCH_TYPE = "Mobile Detection"
ON_DEMAND_SCANS_DETECTION_TYPE = "On-Demand Scans Detection"
ON_DEMAND_SCANS_DETECTION = "On-Demand Scans detection"
OFP_DETECTION_TYPE = "OFP Detection"
OFP_DETECTION = "OFP detection"
PARAMS = demisto.params()
CLIENT_ID = PARAMS.get('credentials', {}).get('identifier') or PARAMS.get('client_id')
SECRET = PARAMS.get('credentials', {}).get('password') or PARAMS.get('secret')
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS['url'].removesuffix('/')
# Should we use SSL
USE_SSL = not PARAMS.get('insecure', False)
# How many time before the first fetch to retrieve incidents
FETCH_TIME = PARAMS.get('fetch_time', '3 days')
MAX_FETCH_SIZE = 10000
PROXY = PARAMS.get('proxy', False)
BYTE_CREDS = f'{CLIENT_ID}:{SECRET}'.encode()
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Basic {base64.b64encode(BYTE_CREDS).decode()}'
}
# Note: True life time of token is actually 30 mins
TOKEN_LIFE_TIME = 28
INCIDENTS_PER_FETCH = int(PARAMS.get('incidents_per_fetch', 15))
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DETECTION_DATE_FORMAT = IOM_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DEFAULT_TIMEOUT = 30
LEGACY_VERSION = PARAMS.get('legacy_version', False)

''' KEY DICTIONARY '''

LEGACY_DETECTIONS_BASE_KEY_MAP = {
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

DETECTIONS_BASE_KEY_MAP = {
    'device.hostname': 'System',
    'device.cid': 'CustomerID',
    'device.hostinfo.domain': 'MachineDomain',
    'composite_id': 'ID',
    'created_timestamp': 'ProcessStartTime',
    'severity': 'MaxSeverity',
    'show_in_ui': 'ShowInUi',
    'status': 'Status',
    'confidence': 'MaxConfidence',
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
LEGACY_DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP = [
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

DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP = [
    {
        'Path': 'parent_details.process_graph_id',
        'NewKey': 'SensorID',
        'Delim': ':',
        'Index': 1
    },
    {
        'Path': 'parent_details.process_graph_id',
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
IDP_AND_MOBILE_DETECTION_STATUS = {'new', 'in_progress', 'closed', 'reopened'}

CS_FALCON_DETECTION_OUTGOING_ARGS = {'status': f'Updated detection status, one of {"/".join(DETECTION_STATUS)}'}

CS_FALCON_INCIDENT_OUTGOING_ARGS = {'tag': 'A tag that have been added or removed from the incident',
                                    'status': f'Updated incident status, one of {"/".join(STATUS_TEXT_TO_NUM.keys())}'}

LEGACY_CS_FALCON_DETECTION_INCOMING_ARGS = ['status', 'severity', 'behaviors.tactic', 'behaviors.scenario', 'behaviors.objective',
                                            'behaviors.technique', 'device.hostname', 'detection_id', 'behaviors.display_name']
CS_FALCON_DETECTION_INCOMING_ARGS = ['status', 'severity', 'tactic', 'scenario', 'objective',
                                     'technique', 'device.hostname', "composite_id", 'display_name', 'tags']
CS_FALCON_INCIDENT_INCOMING_ARGS = ['state', 'fine_score', 'status', 'tactics', 'techniques', 'objectives',
                                    'tags', 'hosts.hostname', 'incident_id']

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


QUARANTINE_FILES_OUTPUT_HEADERS = ['id', 'aid', 'cid', 'sha256', 'paths', 'state', 'detect_ids', 'alert_ids', 'hostname',
                                   'username', 'date_updated', 'date_created', 'extracted',
                                   'release_path_for_removable_media', 'primary_module', 'is_on_removable_disk',
                                   'sandbox_report_id', 'sandbox_report_state']

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
    LEGACY_ENDPOINT_DETECTION = 'ldt'
    ENDPOINT_OR_IDP_OR_MOBILE_OR_OFP_DETECTION = ':ind:'  # OFP was joined here since it has ':ind:' too in its id
    IOM_CONFIGURATIONS = 'iom_configurations'
    IOA_EVENTS = 'ioa_events'
    ON_DEMAND = 'ods'
    OFP = 'ofp'


MIRROR_DIRECTION = MIRROR_DIRECTION_DICT.get(demisto.params().get('mirror_direction'))
INTEGRATION_INSTANCE = demisto.integrationInstance()


''' HELPER FUNCTIONS '''


def truncate_long_time_str(detections: List[Dict], time_key: str) -> List[Dict]:
    """
    Truncates the time string in each detection to a maximum of 26 characters, to prevent an error when parsing the time.

    Args:
        detections (List[Dict]): The list of detections, each represented as a dictionary.
        time_key (str): The key in each detection dictionary that corresponds to the time string.

    Returns:
        List[Dict]: The list of detections with the time string truncated.
    """
    for event in detections:
        long_time_str = event.get(time_key)
        if long_time_str and len(long_time_str) > 26:
            event[time_key] = long_time_str[:26] + "Z"
    return detections


def modify_detection_outputs(detection):
    """
    Modifies the detection outputs in the newer version (raptor release) to be in the same format as the legacy version.
    Args:
        detection: The detection to modify.
    Returns:
        The nested modified detection.
    """
    behavior = {key: detection.pop(key, None) for key in DETECTIONS_BEHAVIORS_KEY_MAP}
    behavior.update({
        "parent_details": detection.pop("parent_details", None),
        "triggering_process_graph_id": detection.pop("triggering_process_graph_id", None)
    })
    detection["behaviors"] = [behavior]
    return detection


def error_handler(res):
    res_json = res.json()
    reason = res.reason
    demisto.debug(f'CrowdStrike Falcon error handler {res.status_code=} {reason=}')
    resources = res_json.get('resources', {})
    extracted_error_message = ''
    if resources:
        if isinstance(resources, list):
            extracted_error_message += f'\n{str(resources)}'
        else:
            for host_id, resource in resources.items():
                errors = resource.get('errors', []) if isinstance(resource, dict) else ''  # type: ignore[union-attr]
                if errors:
                    error_message = errors[0].get('message')  # type: ignore[union-attr]
                    extracted_error_message += f'\nHost ID {host_id} - {error_message}'
    elif res_json.get('errors') and not extracted_error_message:
        errors = res_json.get('errors', [])
        for error in errors:
            extracted_error_message += f"\n{error.get('message')}"
    reason += extracted_error_message
    raise DemistoException(f'Error in API call to CrowdStrike Falcon: code: {res.status_code} - reason: {reason}')


def http_request(method, url_suffix, params=None, data=None, files=None, headers=HEADERS,
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
        retries = 0
        status_list_to_retry = []
        # in case of 401,403,429 status codes we want to return the response, generate a new token and try again with retries.
        valid_status_codes = [200, 201, 202, 204, 401, 403, 429]
    else:
        # get_token_flag=False means that get_token_request() called http_request() with /oauth2/token, and we want to retry
        # to create the token in case of 429 in the first call to generic_http_request and not in the second call to avoid a
        # loop of calls to get_token_request().
        retries = 5
        # error code 401 - isn't relevant for requesting a token.
        # error code 403 - The IP is missing from the IP allowlist, no need to retry.
        status_list_to_retry = [429]
        valid_status_codes = [200, 201, 202, 204]
        demisto.debug(f'In http_request {get_token_flag=} updated retries, status_list_to_retry, valid_status_codes')

    headers['User-Agent'] = 'PANW-XSOAR'
    int_timeout = int(timeout) if timeout else 60  # 60 is the default in generic_http_request

    # Handling a case when we want to return an entry for 404 status code.
    if status_code:
        # To cover the condition when status_code is a list of status codes
        if isinstance(status_code, list):
            valid_status_codes = valid_status_codes + status_code
        else:
            valid_status_codes.append(status_code)

    try:
        res = generic_http_request(
            method=method,
            server_url=SERVER,
            headers=headers,
            url_suffix=url_suffix,
            data=data,
            files=files,
            params=params,
            proxy=PROXY,
            resp_type='response',
            verify=USE_SSL,
            error_handler=error_handler,
            json_data=json,
            timeout=int_timeout,
            ok_codes=valid_status_codes,
            retries=retries,
            status_list_to_retry=status_list_to_retry
        )
        demisto.debug(f'In http_request after the first call to generic_http_request {res=} {res.status_code=}')
    except requests.exceptions.RequestException as e:
        return_error(f'Error in connection to the server. Please make sure you entered the URL correctly.'
                     f' Exception is {str(e)}.')
    try:
        if get_token_flag:
            # removing 401,403,429 status codes, now we want to generate a new token and try again
            valid_status_codes.remove(401)
            valid_status_codes.remove(403)
            valid_status_codes.remove(429)
        if res.status_code not in valid_status_codes:
            # try to create a new token
            if res.status_code in (401, 403, 429) and get_token_flag:
                demisto.debug(f'Try to create a new token because {res.status_code=}')
                token = get_token(new_token=True)
                headers['Authorization'] = f'Bearer {token}'
                demisto.debug('calling generic_http_request with retries=5 and status_list_to_retry=[429]')
                res = generic_http_request(
                    method=method,
                    server_url=SERVER,
                    headers=headers,
                    url_suffix=url_suffix,
                    data=data,
                    files=files,
                    params=params,
                    proxy=PROXY,
                    retries=5,
                    status_list_to_retry=[429],
                    resp_type='response',
                    error_handler=error_handler,
                    json_data=json,
                    timeout=int_timeout,
                    ok_codes=valid_status_codes
                )
                demisto.debug(f'In http_request after the second call to generic_http_request {res=} {res.status_code=}')
                return res if no_json else res.json()
            else:
                demisto.debug(f'In invalid status code and {get_token_flag=}')
                error_handler(res)
        demisto.debug('In http_request end')
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


def modify_detection_summaries_outputs(detection: dict):
    """
    Modifies the detection summaries outputs in the new version (raptor release) to be in the same format as the legacy version.

    Args:
        detection: The detection to modify.
    Returns:
        The modified detection.
    """
    keys_to_move = [
        "pattern_disposition_details",
        "timestamp",
        "device_id",
        "filename",
        "alleged_filetype",
        "cmdline",
        "scenario",
        "objective",
        "tactic",
        "technique",
        "severity",
        "confidence",
        "ioc_type",
        "ioc_value",
        "user_name",
        "user_id",
        "control_graph_id",
        "triggering_process_graph_id",
        "sha256",
        "pattern_disposition",
        "parent_details",
        "md5",
        "filepath"
    ]

   # rename before adding to a nested dict
    parent_details = detection.get("parent_details", {})
    parent_keys = ["sha256", "cmdline", "md5", "process_graph_id"]
    for key in parent_keys:
        if key in parent_details:
            new_key = f"parent_{key}"
            parent_details[new_key] = parent_details.pop(key)

    # change from a flat dict to nested dict
    nested_dict = {key: detection.pop(key, None) for key in keys_to_move if key in detection}
    nested_dict["device_id"] = detection.get("device", {}).get("device_id")
    detection["behaviors"] = nested_dict

    # change from nested to flat
    detection["hostinfo"] = detection.get("device", {}).get("hostinfo")

    # rename without moving to a nested dict
    detection["detection_id"] = detection.pop("composite_id", None)

    return detection


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
    # detection_id and severity key names change between the legacy and the new version
    detection_id = detection.get('detection_id') or detection.get('composite_id')
    severity = detection.get('max_severity_displayname') or detection.get('severity_name')
    incident = {
        'name': 'Detection ID: ' + str(detection_id),
        'occurred': str(detection.get('created_timestamp')),
        'rawJSON': json.dumps(detection),
        'severity': severity_string_to_int(severity),
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


def fix_time_field(detection: dict, time_key: str):
    """
        Fix the value of the date to have only 6 figures after the ".".
        The string representation of the created_timestamp value can contain from 6 to 9 figures after the dot,
        for example: 2024-02-22T14:16:04.973070837Z. The template supports only 6 digits, so there is a need to remove the extra
        digits to use datetime.strptime().

        Args:
            detection (dict): the detection.
            time_key (str): the key of the wanted date&time field.
    """
    demisto.debug(f'fix_time_field {time_key=}')
    str_date = detection[time_key]
    split_date = str_date.split('.')
    relevant_microseconds = split_date[1][:6]
    # if 'Z' isn't in relevant_microseconds it means that it was removed since there was more than 5 digits in the microseconds.
    fixed_date = f'{split_date[0]}.{relevant_microseconds}Z' if 'Z' not in relevant_microseconds else str_date
    demisto.debug(f'fix_time_field, the original value in {time_key=} is {str_date} the updated value is {fixed_date} ')
    detection[time_key] = fixed_date


def detection_to_incident_context(detection, detection_type, start_time_key: str = 'start_time'):
    """
        Creates an incident context of an IDP/Mobile/ODS detection.

        :type detection: ``dict``
        :param detection: Single detection object.

        :return: Incident context representation of an IDP/Mobile detection.
        :rtype ``dict``
    """
    add_mirroring_fields(detection)
    demisto.debug(f'detection_to_incident_context, {detection_type=}')
    if detection_type == IDP_DETECTION_FETCH_TYPE:
        demisto.debug(f'detection_to_incident_context, {detection_type=} calling fix_time_field')
        fix_time_field(detection, start_time_key)

    incident_context = {
        'occurred': detection.get(start_time_key),
        'rawJSON': json.dumps(detection)
    }
    if detection_type in (IDP_DETECTION_FETCH_TYPE, ON_DEMAND_SCANS_DETECTION_TYPE, OFP_DETECTION_TYPE):
        incident_context['name'] = f'{detection_type} ID: {detection.get("composite_id")}'
        incident_context['last_updated'] = detection.get('updated_timestamp')
    elif detection_type == MOBILE_DETECTION_FETCH_TYPE:
        incident_context['name'] = f'{detection_type} ID: {detection.get("mobile_detection_id")}'
        incident_context['severity'] = detection.get('severity')
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
        tags: list[str] | None = None,
        file_name: str | None = None,
) -> list[dict]:
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
    :param file_name: Name of the file for file indicators.
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
            metadata=assign_params(filename=file_name) if ioc_type in {"sha256", "md5"} else None
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
        demisto.debug(f'{passed_mins=}')
        if passed_mins >= TOKEN_LIFE_TIME:
            # token expired
            demisto.debug('token expired')
            auth_token = get_token_request()
            demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
        else:
            # token hasn't expired
            demisto.debug("token hasn't expired")
            auth_token = ctx.get('auth_token')
    else:
        # there is no token
        demisto.debug('there is no token')
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
    token_res = http_request('POST', '/oauth2/token', data=body, headers=headers, get_token_flag=False)
    demisto.debug(f'In get_token_request, token_res is not None {token_res is not None}')
    if not token_res:
        err_msg = 'Authorization Error: User has no authorization to create a token. Please make sure you entered the' \
                  ' credentials correctly.'
        raise Exception(err_msg)
    demisto.debug(f'{token_res.get("expires_in")=}')
    return token_res.get('access_token')


def get_behaviors(behavior_ids: list[str]) -> dict:
    """
    Get details on behaviors by providing behavior IDs

    Args:
        behavior_ids: List of behavior IDs to get details on

    Returns:
        dict: Response data
    """
    return http_request(
        'POST',
        '/incidents/entities/behaviors/GET/v1',
        data=json.dumps({'ids': behavior_ids}),
    )


def get_ioarules(rule_ids: list[str]) -> dict:
    """
        Sends ioa rules entities request
        :param rule_ids: IDs of the requested ioa rule.
        :return: Response json of the get ioa rule entities endpoint (ioa rule objects)
    """
    params = {'ids': rule_ids}

    return http_request(
        'GET',
        '/ioarules/entities/rules/v1',
        params=params,
    )


def get_detections(last_behavior_time=None, behavior_id=None, filter_arg=None):
    """
        Sends detections request. The function will ignore the arguments passed according to priority:
        filter_arg > behavior_id > last_behavior_time

        :param last_behavior_time: 3rd priority. The last behavior time of results will be greater than this value
        :param behavior_id: 2nd priority. The result will only contain the detections with matching behavior id
        :param filter_arg: 1st priority. The result will be filtered using this argument.
        :return: Response json of the get detection endpoint (IDs of the detections)
    """
    params = {
        'sort': 'first_behavior.asc'
    }
    if filter_arg:
        params['filter'] = filter_arg
    elif behavior_id:
        params['filter'] = f"behaviors.behavior_id:'{behavior_id}'"
    elif last_behavior_time:
        params['filter'] = f"first_behavior:>'{last_behavior_time}'"

    if not LEGACY_VERSION:
        endpoint_url = "alerts/queries/alerts/v2?filter=product"
        text_to_encode = ":'epp'+type:'ldt'"
        # in the new version we send only the filter_arg argument as encoded string without the params
        if filter_arg:
            text_to_encode += f"+{filter_arg}"
        endpoint_url += urllib.parse.quote_plus(text_to_encode)
        demisto.debug(f"In get_detections: {LEGACY_VERSION =} and {endpoint_url=}")
        return http_request('GET', endpoint_url, {'sort': 'created_timestamp.asc'})
    else:
        endpoint_url = '/detects/queries/detects/v1'
        demisto.debug(f"In get_detections: {LEGACY_VERSION =} and {endpoint_url=} and {params=}")
        return http_request('GET', endpoint_url, params)


def get_fetch_detections(last_created_timestamp=None, filter_arg=None, offset: int = 0, last_updated_timestamp=None,
                         has_limit=True, limit: int = INCIDENTS_PER_FETCH):
    """ Sends detection request, based on the created_timestamp field. Used for fetch-incidents
    Args:
        last_created_timestamp: last created timestamp of the results will be greater than this value.
        filter_arg: The result will be filtered using this argument.
    Returns:
        Response json of the get detection endpoint (IDs of the detections)
    """
    sort_key = 'first_behavior.asc' if LEGACY_VERSION else 'created_timestamp.asc'
    params = {
        'sort': sort_key,
        'offset': offset,
    }
    if has_limit:
        params['limit'] = limit

    if filter_arg:
        params['filter'] = filter_arg
    elif last_created_timestamp:
        params['filter'] = f"created_timestamp:>'{last_created_timestamp}'"
    elif last_updated_timestamp:
        timestamp_key = 'date_updated' if LEGACY_VERSION else 'updated_timestamp'
        params['filter'] = f"{timestamp_key}:>'{last_updated_timestamp}'"

    endpoint_url = '/detects/queries/detects/v1' if LEGACY_VERSION else "/alerts/queries/alerts/v2?filter=product"

    if not LEGACY_VERSION:
        if params.get('filter'):
            endpoint_url += urllib.parse.quote_plus(f":'epp'+type:'ldt'+{params.pop('filter')}")
        else:
            endpoint_url += urllib.parse.quote_plus(":'epp'+type:'ldt'")
    demisto.debug(f"In get_fetch_detections: {LEGACY_VERSION =}, {endpoint_url=}, {params=}")
    response = http_request('GET', endpoint_url, params)

    return response


def get_detections_entities(detections_ids: list):
    """
        Sends detection entities request
        :param detections_ids: IDs of the requested detections.
        :return: Response json of the get detection entities endpoint (detection objects)
    """
    ids_json = {'ids': detections_ids} if LEGACY_VERSION else {"composite_ids": detections_ids}
    url = '/detects/entities/summaries/GET/v1' if LEGACY_VERSION else '/alerts/entities/alerts/v2'
    demisto.debug(f"Getting detections entities from {url} with {ids_json=}. {LEGACY_VERSION=}")
    if detections_ids:
        response = http_request(
            'POST',
            url,
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


def get_detections_ids(filter_arg=None, offset: int = 0, limit=INCIDENTS_PER_FETCH, product_type='idp'):
    """
        Send a request to retrieve IDP/ODS detections IDs.

        :type filter_arg: ``str``
        :param filter_arg: The filter to add to the query.
        :type offset: ``int``
        :param offset: The offset for the query.
        :type limit: ``int``
        :param limit: limit of idp/ods detections to retrieve each request.

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
    endpoint_url = "/alerts/queries/alerts/v1" if LEGACY_VERSION else \
        "/alerts/queries/alerts/v2?filter="
    # in the new version we need to add the product type to the filter to the url as encoded string
    if not LEGACY_VERSION and params.get('filter'):
        endpoint_url += urllib.parse.quote_plus(params.pop('filter'))

    response = http_request('GET', endpoint_url, params)

    demisto.debug(f"CrowdStrikeFalconMsg: Getting {product_type} detections from {endpoint_url} with {params=}. {response=}.\
        {LEGACY_VERSION=}")

    return response


def get_incidents_entities(incidents_ids: list):
    ids_json = {'ids': incidents_ids}
    response = http_request(
        'POST',
        '/incidents/entities/incidents/GET/v1',
        data=json.dumps(ids_json)
    )
    return response


def get_detection_entities(incidents_ids: list):
    """
        Send a request to retrieve IDP/ODS/OFP and mobile detection entities.

        :type incidents_ids: ``list``
        :param incidents_ids: The list of ids to search their entities.

        :return: The response.
        :rtype ``dict``
    """
    url_endpoint_version = 'v1' if LEGACY_VERSION else 'v2'
    ids_json = {'ids': incidents_ids} if LEGACY_VERSION else {"composite_ids": incidents_ids}
    demisto.debug(f"In get_detection_entities: Getting detection entities from\
        {url_endpoint_version} with {ids_json=}. {LEGACY_VERSION=}")
    return http_request(
        'POST',
        f'/alerts/entities/alerts/{url_endpoint_version}',
        data=json.dumps(ids_json)
    )


def get_users(offset: int, limit: int, query_filter: str | None = None) -> dict:
    """
    Get a list of users using pagination.

    Note:
        The result will include all collected paginated data, but the 'meta' key will only include information of the first page.

    Args:
        offset (int): The offset to begin from.
        limit (int): The maximum number of records to return.
        query_filter (str): Filter to use for the API request.

    Returns:
        dict: The response from the API (a combination of all paginated data).
    """
    def generate_paginated_request(_offset: int, _limit: int) -> dict:
        result: dict = {
            'method': 'GET',
            'url_suffix': '/user-management/queries/users/v1',
            'params': {
                'offset': _offset,
                'limit': _limit,
                # We need to use sort since the API doesn't guarantee a consistent order,
                # which can cause issues when using the offset parameter (repetitive & missing values)
                'sort': 'uid',
            },
        }

        if query_filter:
            result['params']['filter'] = query_filter

        return result

    response = http_request(
        **generate_paginated_request(_offset=offset, _limit=limit)
    )

    total_results = response.get('meta', {}).get('pagination', {}).get('total', 0)
    fetched_results_count = len(response.get('resources', []))

    while fetched_results_count < limit and fetched_results_count + offset < total_results:
        current_offset = offset + fetched_results_count
        remaining_results_count = min(limit, total_results) - fetched_results_count

        if remaining_results_count > 500:
            current_limit = 500

        else:
            current_limit = remaining_results_count

        current_response = http_request(
            **generate_paginated_request(_offset=current_offset, _limit=current_limit)
        )

        response['resources'].extend(current_response.get('resources', []))
        fetched_results_count += len(current_response.get('resources', []))

    return response


def get_users_data(user_ids: list[str]) -> dict:
    return http_request(
        'POST',
        '/user-management/entities/users/GET/v1',
        data=json.dumps({'ids': user_ids}),
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
        file_name: str | None = None,
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
            metadata=assign_params(filename=file_name)
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
    limit = int(args.get('limit', 50))
    offset = int(args.get('offset', 0))
    sort = args.get('sort', '')
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
    raw_res = http_request('GET', '/devices/queries/devices/v1',
                           params={'filter': url_filter, 'limit': limit, 'offset': offset, 'sort': sort})
    device_ids = raw_res.get('resources')
    if not device_ids:
        return None
    demisto.debug(f"number of devices returned from the api call is: {len(device_ids)}")
    return http_request('POST', '/devices/entities/devices/v2', json={'ids': device_ids})


def behavior_to_entry_context(behavior):
    """
        Transforms a behavior to entry context representation
        :param behavior: Behavior dict in the format of crowdstrike's API response
        :return: Behavior in entry context representation
    """
    raw_entry = get_trasnformed_dict(behavior, DETECTIONS_BEHAVIORS_KEY_MAP)
    split_key_map = LEGACY_DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP if LEGACY_VERSION else DETECTIONS_BEHAVIORS_SPLIT_KEY_MAP
    raw_entry.update(extract_transformed_dict_with_split(behavior, split_key_map))
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


def resolve_detection(ids, status, assigned_to_uuid, show_in_ui, comment, tag):
    """
        Sends a resolve detection request
        :param ids: Single or multiple ids in an array string format.
        :param status: New status of the detection.
        :param assigned_to_uuid: uuid to assign the detection to.
        :param show_in_ui: Boolean flag in string format (true/false).
        :param comment: Optional comment to add to the detection.
        :param The tag to add.
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
    if not LEGACY_VERSION:
        demisto.debug(f"in resolve_detection: {LEGACY_VERSION =} and {payload=}")
        # modify the payload to match the Raptor API
        ids = payload.pop('ids')
        payload["assign_to_uuid"] = payload.pop("assigned_to_uuid") if "assigned_to_uuid" in payload else None
        payload["update_status"] = payload.pop("status") if "status" in payload else None
        payload["append_comment"] = payload.pop("comment") if "comment" in payload else None
        if tag:
            payload["add_tag"] = tag

        data = json.dumps(resolve_detections_prepare_body_request(ids, payload))
    else:
        # We do this so show_in_ui value won't contain ""
        data = json.dumps(payload).replace('"show_in_ui": "false"', '"show_in_ui": false').replace('"show_in_ui": "true"',
                                                                                                   '"show_in_ui": true')
    url = "/alerts/entities/alerts/v3" if not LEGACY_VERSION else "/detects/entities/detects/v2"
    return http_request('PATCH', url, data=data)


def resolve_idp_or_mobile_detection(ids, status):
    """
        Send a request to update IDP/Mobile detection status.
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
                       offset: str | None,
                       sort: str | None):
    params = {'id': host_group_id,
              'filter': filter,
              'offset': offset,
              'limit': limit,
              'sort': sort}
    response = http_request(method='GET',
                            url_suffix='/devices/combined/host-group-members/v1',
                            params=params)
    return response


def update_incident_request(ids: list[str], action_parameters: dict[str, Any]):
    data = {
        "action_parameters": [
            {
                "name": action_name,
                "value": action_value
            } for action_name, action_value in action_parameters.items()
        ],
        "ids": ids,
    }

    return http_request(method='POST',
                        url_suffix='/incidents/entities/incident-actions/v1',
                        json=data)


def update_detection_request(ids: list[str], status: str) -> dict:
    if status not in DETECTION_STATUS:
        raise DemistoException(f'CrowdStrike Falcon Error: '
                               f'Status given is {status} and it is not in {DETECTION_STATUS}')
    return resolve_detection(ids=ids, status=status, assigned_to_uuid=None, show_in_ui=None, comment=None, tag=None)


def update_idp_or_mobile_detection_request(ids: list[str], status: str) -> dict:
    """
        Manage the status to send to update to for IDP/Mobile detections.
        :type ids: ``list``
        :param ids: The list of ids to update.
        :type status: ``str``
        :param status: The new status to set.
        :return: The response.
        :rtype ``dict``
    """
    if status not in IDP_AND_MOBILE_DETECTION_STATUS:
        raise DemistoException(f'CrowdStrike Falcon Error: '
                               f'Status given is {status} and it is not in {IDP_AND_MOBILE_DETECTION_STATUS}')
    return resolve_idp_or_mobile_detection(ids=ids, status=status)


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
    reopen_statuses_list = argToList(demisto.params().get('reopen_statuses', ''))
    demisto.debug(f'In get_remote_data_command {reopen_statuses_list=}')

    mirrored_data = {}
    entries: list = []
    try:
        demisto.debug(f'Performing get-remote-data command with incident or detection id: {remote_incident_id} '
                      f'and last_update: {remote_args.last_update}')
        incident_type = find_incident_type(remote_incident_id)
        demisto.debug(f'Successfully identified incident type: {incident_type} for remote incident id: {remote_incident_id}')
        if incident_type == IncidentType.INCIDENT:
            mirrored_data, updated_object = get_remote_incident_data(remote_incident_id)
            if updated_object:
                demisto.debug(f'Update incident {remote_incident_id} with fields: {updated_object}')
                detection_type = 'Incident'
                set_xsoar_entries(updated_object, entries, remote_incident_id,
                                  detection_type, reopen_statuses_list)
        # for legacy endpoint detections
        elif incident_type == IncidentType.LEGACY_ENDPOINT_DETECTION:
            mirrored_data, updated_object = get_remote_detection_data(remote_incident_id)
            if updated_object:
                demisto.debug(f'Update detection {remote_incident_id} with fields: {updated_object}')
                detection_type = 'Detection'
                set_xsoar_entries(updated_object, entries, remote_incident_id,
                                  detection_type, reopen_statuses_list)  # sets in place
        # for endpoint (in the new version) ,idp/ods/ofp/mobile detections
        elif incident_type in (IncidentType.ENDPOINT_OR_IDP_OR_MOBILE_OR_OFP_DETECTION, IncidentType.ON_DEMAND):
            mirrored_data, updated_object, detection_type = get_remote_detection_data_for_multiple_types(remote_incident_id)
            if updated_object:
                demisto.debug(f'Update {detection_type} detection {remote_incident_id} with fields: {updated_object}')
                set_xsoar_entries(
                    updated_object, entries, remote_incident_id, detection_type, reopen_statuses_list)  # sets in place

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
    if IncidentType.INCIDENT.value in remote_incident_id:
        return IncidentType.INCIDENT
    if IncidentType.LEGACY_ENDPOINT_DETECTION.value in remote_incident_id:
        return IncidentType.LEGACY_ENDPOINT_DETECTION
    if IncidentType.ENDPOINT_OR_IDP_OR_MOBILE_OR_OFP_DETECTION.value in remote_incident_id:
        return IncidentType.ENDPOINT_OR_IDP_OR_MOBILE_OR_OFP_DETECTION
    if IncidentType.ON_DEMAND.value in remote_incident_id:
        return IncidentType.ON_DEMAND
    demisto.debug(f"Unable to determine incident type for remote incident id: {remote_incident_id}")
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
    # severity key name is different in the raptor version
    severity = mirrored_data.get('max_severity_displayname') if LEGACY_VERSION else mirrored_data.get('severity_name')
    mirrored_data['severity'] = severity_string_to_int(severity)
    demisto.debug(f'In get_remote_detection_data {remote_incident_id=} {mirrored_data=}')

    incoming_args = LEGACY_CS_FALCON_DETECTION_INCOMING_ARGS if LEGACY_VERSION else CS_FALCON_DETECTION_INCOMING_ARGS
    updated_object: dict[str, Any] = {'incident_type': 'detection'}
    set_updated_object(updated_object, mirrored_data, incoming_args)
    demisto.debug(f'After set_updated_object {updated_object=}')
    return mirrored_data, updated_object


def get_remote_detection_data_for_multiple_types(remote_incident_id):
    """
        Gets the relevant detection entity from the remote system (CrowdStrike Falcon).
        This function handles the following detection types:
        - IDP (Identity Protection)
        - Mobile
        - Detection (not legacy)
        - OFP (Other File Protection)
        - ODS (On-Demand Scans)

        :type remote_incident_id: ``str``
        :param remote_incident_id: The incident id to return its information.

        :return: The detection entity.
        :rtype ``dict``
        :return: The object with the updated fields.
        :rtype ``dict``
        :return: The detection type.
        :rtype ``str``
    """
    mirrored_data_list = get_detection_entities([remote_incident_id]).get('resources', [])  # a list with one dict in it
    mirrored_data = mirrored_data_list[0]
    detection_type = ''
    mirroring_fields = ['status']
    updated_object: dict[str, Any] = {}
    if 'idp' in mirrored_data['product']:
        updated_object = {'incident_type': IDP_DETECTION}
        detection_type = 'IDP'
        mirroring_fields.append('id')
    if 'mobile' in mirrored_data['product']:
        updated_object = {'incident_type': MOBILE_DETECTION}
        detection_type = 'Mobile'
        mirroring_fields.append('mobile_detection_id')
    if 'epp' in mirrored_data['product']:
        updated_object = {'incident_type': ENDPOINT_DETECTION}
        detection_type = 'Detection'
        mirroring_fields = CS_FALCON_DETECTION_INCOMING_ARGS
    if 'ofp' in mirrored_data['type']:
        updated_object = {'incident_type': OFP_DETECTION}
        detection_type = 'ofp'
        mirroring_fields = CS_FALCON_DETECTION_INCOMING_ARGS
    if 'ods' in mirrored_data['type']:
        updated_object = {'incident_type': ON_DEMAND_SCANS_DETECTION}
        detection_type = 'ods'
        mirroring_fields = CS_FALCON_DETECTION_INCOMING_ARGS
    set_updated_object(updated_object, mirrored_data, mirroring_fields)
    demisto.debug(f'in get_remote_detection_data_for_multiple_types {mirrored_data=} { mirroring_fields=} {updated_object=}')
    return mirrored_data, updated_object, detection_type


def set_xsoar_entries(updated_object: dict[str, Any], entries: list, remote_detection_id: str,
                      incident_type_name: str, reopen_statuses_list: list):
    """
        Send the updated object to the relevant status handler

        :type updated_object: ``dict``
        :param updated_object: The updated object.
        :type entries: ``list``
        :param entries: The list of entries to add the new entry into.
        :type remote_detection_id: ``str``
        :param remote_detection_id: the remote detection id
        :type reopen_statuses_list: ``list``
        :param reopen_statuses_list: the set of statuses that should reopen an incident in XSOAR.

        :return: The response.
        :rtype ``dict``
    """
    reopen_statuses_set = {str(status).lower().strip().replace(' ', '_') for status in reopen_statuses_list}
    demisto.debug(f'In set_xsoar_entries {reopen_statuses_set=} {remote_detection_id=}')
    if demisto.params().get('close_incident'):
        if updated_object.get('status', '').lower() == 'closed':
            close_in_xsoar(entries, remote_detection_id, incident_type_name)
        elif updated_object.get('status', '').lower() in reopen_statuses_set:
            reopen_in_xsoar(entries, remote_detection_id, incident_type_name)
        else:
            demisto.debug(f"In set_xsoar_entries not closing and not reopening {remote_detection_id=}"
                          f" since {updated_object.get('status')=} and {reopen_statuses_set=}.")


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
    fetch_types = demisto.params().get('fetch_incidents_or_detections', "")

    raw_ids = []

    if 'Incidents' in fetch_types or "Endpoint Incident" in fetch_types:
        raw_ids += get_incidents_ids(last_updated_timestamp=last_update_timestamp, has_limit=False).get('resources', [])

    if 'Detections' in fetch_types or "Endpoint Detection" in fetch_types:
        raw_ids += get_fetch_detections(last_updated_timestamp=last_update_timestamp, has_limit=False).get('resources', [])

    if IDP_DETECTION_FETCH_TYPE in fetch_types:
        raw_ids += get_detections_ids(
            filter_arg=f"updated_timestamp:>'{last_update_utc.strftime(DETECTION_DATE_FORMAT)}'+product:'idp'"
        ).get('resources', [])

    if MOBILE_DETECTION_FETCH_TYPE in fetch_types:
        raw_ids += get_detections_ids(
            filter_arg=f"updated_timestamp:>'{last_update_utc.strftime(DETECTION_DATE_FORMAT)}'+product:'mobile'"
        ).get('resources', [])
    if ON_DEMAND_SCANS_DETECTION_TYPE in fetch_types:
        raw_ids += get_detections_ids(
            filter_arg=f"updated_timestamp:>'{last_update_utc.strftime(DETECTION_DATE_FORMAT)}'+type:'ods'"
        ).get('resources', [])
    if OFP_DETECTION_TYPE in fetch_types:
        raw_ids += get_detections_ids(
            filter_arg=f"updated_timestamp:>'{last_update_utc.strftime(DETECTION_DATE_FORMAT)}'+type:'ofp'"
        ).get('resources', [])

    modified_ids_to_mirror = list(map(str, raw_ids))
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
        demisto.debug(f'Successfully identified incident type: {incident_type} for remote incident id: {remote_incident_id}')
        if parsed_args.incident_changed:
            if incident_type == IncidentType.INCIDENT:
                result = update_remote_incident(delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'Incident updated successfully. Result: {result}')

            elif incident_type in (IncidentType.LEGACY_ENDPOINT_DETECTION, IncidentType.ON_DEMAND):
                result = update_remote_detection(delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'Detection updated successfully. Result: {result}')

            elif incident_type == IncidentType.ENDPOINT_OR_IDP_OR_MOBILE_OR_OFP_DETECTION:
                result = update_remote_idp_or_mobile_detection(delta, parsed_args.inc_status, remote_incident_id)
                if result:
                    demisto.debug(f'IDP/Mobile Detection updated successfully. Result: {result}')

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


def update_remote_idp_or_mobile_detection(delta, inc_status: IncidentStatus, detection_id: str) -> str:
    """
        Sends the request the request to update the relevant IDP/Mobile detection entity.

        :type delta: ``dict``
        :param delta: The modified fields.
        :type inc_status: ``IncidentStatus``
        :param inc_status: The IDP/Mobile detection status.
        :type detection_id: ``str``
        :param detection_id: The IDP/Mobile detection ID to update.
    """
    if inc_status == IncidentStatus.DONE and close_in_cs_falcon(delta):
        demisto.debug(f'Closing IDP/Mobile detection with remote ID {detection_id} in remote system.')
        return str(update_idp_or_mobile_detection_request([detection_id], 'closed'))

    # status field in CS Falcon is mapped to State field in XSOAR
    elif 'status' in delta:
        demisto.debug(f'Detection with remote ID {detection_id} status will change to "{delta.get("status")}" in remote system.')
        return str(update_idp_or_mobile_detection_request([detection_id], delta.get('status')))

    return ''


def update_remote_incident(delta: dict[str, Any], inc_status: IncidentStatus, incident_id: str) -> str:
    result = ''
    result += update_remote_incident_tags(delta, incident_id)
    result += update_remote_incident_status(delta, inc_status, incident_id)
    return result


def update_remote_incident_status(delta, inc_status: IncidentStatus, incident_id: str) -> str:
    if inc_status == IncidentStatus.DONE and close_in_cs_falcon(delta):
        demisto.debug(f'Closing incident with remote ID {incident_id} in remote system.')
        return str(update_incident_request(ids=[incident_id], action_parameters={'update_status': STATUS_TEXT_TO_NUM['Closed']}))

    # status field in CS Falcon is mapped to Source Status field in XSOAR. Don't confuse with state field
    elif 'status' in delta:
        demisto.debug(f'Incident with remote ID {incident_id} status will change to "{delta.get("status")}" in remote system.')
        status = delta.get('status')

        if status not in STATUS_TEXT_TO_NUM:
            raise DemistoException(f'CrowdStrike Falcon Error: '
                                   f"Status '{status}' is not a valid status ({' | '.join(STATUS_TEXT_TO_NUM.keys())}).")

        return str(update_incident_request(ids=[incident_id], action_parameters={'update_status': STATUS_TEXT_TO_NUM[status]}))

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
        result += str(update_incident_request(ids=[incident_id], action_parameters={request: tag}))
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

        return [updated_last_run_detections, updated_last_run_incidents, {}, {}, {}]


def fetch_incidents():
    incidents: list = []
    detections: list = []
    idp_detections: list = []
    iom_incidents: list[dict[str, Any]] = []
    ioa_incidents: list[dict[str, Any]] = []
    mobile_detections: list[dict[str, Any]] = []
    on_demand_detections: list[dict[str, Any]] = []
    ofp_detections: list[dict[str, Any]] = []
    last_run = demisto.getLastRun()
    demisto.debug(f'CrowdStrikeFalconMsg: Current last run object is {last_run}')
    if not last_run:
        last_run = [{}, {}, {}, {}, {}, {}, {}]
    last_run = migrate_last_run(last_run)
    current_fetch_info_detections: dict = last_run[0]
    current_fetch_info_incidents: dict = last_run[1]
    current_fetch_info_idp_detections: dict = {} if len(last_run) < 3 else last_run[2]
    iom_last_run: dict = {} if len(last_run) < 4 else last_run[3]
    ioa_last_run: dict = {} if len(last_run) < 5 else last_run[4]
    current_fetch_info_mobile_detections: dict = {} if len(last_run) < 6 else last_run[5]
    current_fetch_on_demand_detections: dict = {} if len(last_run) < 7 else last_run[6]
    current_fetch_ofp_detection: dict = {} if len(last_run) < 8 else last_run[7]
    params = demisto.params()
    fetch_incidents_or_detections = params.get('fetch_incidents_or_detections', "")
    look_back = int(params.get('look_back') or 1)
    fetch_limit = INCIDENTS_PER_FETCH

    demisto.debug(f"CrowdstrikeFalconMsg: Starting fetch incidents with {fetch_incidents_or_detections}")

    if 'Detections' in fetch_incidents_or_detections or "Endpoint Detection" in fetch_incidents_or_detections:
        detections_offset: int = current_fetch_info_detections.get('offset') or 0
        start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=current_fetch_info_detections,
                                                                    first_fetch=FETCH_TIME,
                                                                    look_back=look_back,
                                                                    date_format=DETECTION_DATE_FORMAT)
        fetch_limit = current_fetch_info_detections.get('limit') or INCIDENTS_PER_FETCH
        incident_type = 'detection'
        fetch_query = params.get('fetch_query')
        if fetch_query:
            fetch_query = f"created_timestamp:>'{start_fetch_time}'+{fetch_query}"
            response = get_fetch_detections(filter_arg=fetch_query, limit=fetch_limit, offset=detections_offset)
        else:
            response = get_fetch_detections(last_created_timestamp=start_fetch_time, limit=fetch_limit, offset=detections_offset)
        detections_ids: list[dict] = demisto.get(response, "resources", [])
        total_detections = demisto.get(response, "meta.pagination.total")
        detections_offset = calculate_new_offset(detections_offset, len(detections_ids), total_detections)
        if detections_offset:
            if detections_offset + fetch_limit > MAX_FETCH_SIZE:
                demisto.debug(f"CrowdStrikeFalconMsg: The new offset: {detections_offset} + limit: {fetch_limit} reached "
                              f"{MAX_FETCH_SIZE}, resetting the offset to 0")
                detections_offset = 0
            demisto.debug(f"CrowdStrikeFalconMsg: The new detections offset is {detections_offset}")
        raw_res = get_detections_entities(detections_ids)

        if raw_res is not None and "resources" in raw_res:
            full_detections = demisto.get(raw_res, "resources")

            for detection in full_detections:
                detection['incident_type'] = incident_type
                # detection_id is for the old version of the API, composite_id is for the new version (Raptor)
                detection_id = detection.get('detection_id') if LEGACY_VERSION else detection.get('composite_id')
                demisto.debug(
                    f"CrowdStrikeFalconMsg: Detection {detection_id} "
                    f"was fetched which was created in {detection['created_timestamp']}")
                incident = detection_to_incident(detection)

                detections.append(incident)

        detections = filter_incidents_by_duplicates_and_limit(incidents_res=detections,
                                                              last_run=current_fetch_info_detections,
                                                              fetch_limit=INCIDENTS_PER_FETCH, id_field='name')

        for detection in detections:
            occurred = dateparser.parse(detection["occurred"])
            if occurred:
                detection["occurred"] = occurred.strftime(DETECTION_DATE_FORMAT)
                demisto.debug(f"CrowdStrikeFalconMsg: Detection {detection['name']} occurred at {detection['occurred']}")
        current_fetch_info_detections = update_last_run_object(last_run=current_fetch_info_detections,
                                                               incidents=detections,
                                                               fetch_limit=INCIDENTS_PER_FETCH,
                                                               start_fetch_time=start_fetch_time,
                                                               end_fetch_time=end_fetch_time,
                                                               look_back=look_back,
                                                               created_time_field='occurred',
                                                               id_field='name',
                                                               date_format=DETECTION_DATE_FORMAT,
                                                               new_offset=detections_offset)
        demisto.debug(f"CrowdstrikeFalconMsg: Ending fetch endpoint_detections. Fetched {len(detections) if detections else 0}")

    if 'Incidents' in fetch_incidents_or_detections or "Endpoint Incident" in fetch_incidents_or_detections:
        incidents_offset: int = current_fetch_info_incidents.get('offset') or 0
        start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=current_fetch_info_incidents,
                                                                    first_fetch=FETCH_TIME,
                                                                    look_back=look_back,
                                                                    date_format=DATE_FORMAT)

        fetch_limit = current_fetch_info_incidents.get('limit') or INCIDENTS_PER_FETCH

        incident_type = 'incident'

        fetch_query = params.get('incidents_fetch_query')

        if fetch_query:
            fetch_query = f"start:>'{start_fetch_time}'+{fetch_query}"
            response = get_incidents_ids(filter_arg=fetch_query, limit=fetch_limit, offset=incidents_offset)

        else:
            response = get_incidents_ids(last_created_timestamp=start_fetch_time, limit=fetch_limit, offset=incidents_offset)
        incidents_ids: list[dict] = demisto.get(response, "resources", [])
        total_incidents = demisto.get(response, "meta.pagination.total")
        incidents_offset = calculate_new_offset(incidents_offset, len(incidents_ids), total_incidents)
        if incidents_offset:
            if incidents_offset + fetch_limit > MAX_FETCH_SIZE:
                demisto.debug(f"CrowdStrikeFalconMsg: The new offset: {incidents_offset} + limit: {fetch_limit} reached "
                              f"{MAX_FETCH_SIZE}, resetting the offset to 0")
                incidents_offset = 0
            demisto.debug(f"CrowdStrikeFalconMsg: The new incidents offset is {incidents_offset}")

        if incidents_ids:
            raw_res = get_incidents_entities(incidents_ids)
            if raw_res is not None and "resources" in raw_res:
                full_incidents = demisto.get(raw_res, "resources")
                for incident in full_incidents:
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

        current_fetch_info_incidents = update_last_run_object(last_run=current_fetch_info_incidents, incidents=incidents,
                                                              fetch_limit=INCIDENTS_PER_FETCH,
                                                              start_fetch_time=start_fetch_time, end_fetch_time=end_fetch_time,
                                                              look_back=look_back,
                                                              created_time_field='occurred', id_field='name',
                                                              date_format=DATE_FORMAT,
                                                              new_offset=incidents_offset)
        demisto.debug(f"CrowdstrikeFalconMsg: Ending fetch Incidents. Fetched {len(incidents)}")

    if IDP_DETECTION_FETCH_TYPE in fetch_incidents_or_detections:
        idp_detections, current_fetch_info_idp_detections = fetch_detections_by_product_type(
            current_fetch_info_idp_detections,
            look_back=look_back,
            fetch_query=params.get(
                'idp_detections_fetch_query', ""),
            detections_type=IDP_DETECTION,
            product_type='idp',
            detection_name_prefix=IDP_DETECTION_FETCH_TYPE,
            start_time_key='created_timestamp')

    if MOBILE_DETECTION_FETCH_TYPE in fetch_incidents_or_detections:
        mobile_detections, current_fetch_info_mobile_detections = fetch_detections_by_product_type(
            current_fetch_info_mobile_detections,
            look_back=look_back,
            fetch_query=params.get(
                'mobile_detections_fetch_query', ""),
            detections_type=MOBILE_DETECTION,
            product_type='mobile',
            detection_name_prefix=MOBILE_DETECTION_FETCH_TYPE,
            start_time_key='timestamp')

    if 'Indicator of Misconfiguration' in fetch_incidents_or_detections:
        demisto.debug('Fetching Indicator of Misconfiguration incidents')
        demisto.debug(f'{iom_last_run=}')
        fetch_query = params.get('iom_fetch_query', '')
        validate_iom_fetch_query(iom_fetch_query=fetch_query)

        last_resource_ids, iom_next_token, last_scan_time, first_fetch_timestamp = get_current_fetch_data(
            last_run_object=iom_last_run, date_format=IOM_DATE_FORMAT,
            last_date_key='last_scan_time', next_token_key='iom_next_token',
            last_fetched_ids_key='last_resource_ids'
        )
        filter = create_iom_filter(
            is_paginating=bool(iom_next_token),
            last_fetch_filter=iom_last_run.get('last_fetch_filter', ''),
            last_scan_time=last_scan_time, first_fetch_timestamp=first_fetch_timestamp,
            configured_fetch_query=fetch_query)
        demisto.debug(f'IOM {filter=}')
        iom_resource_ids, iom_new_next_token = iom_ids_pagination(filter=filter,
                                                                  iom_next_token=iom_next_token,
                                                                  fetch_limit=INCIDENTS_PER_FETCH,
                                                                  api_limit=500)
        demisto.debug(f'Fetched the following IOM resource IDS: {", ".join(iom_resource_ids)}')
        iom_incidents, fetched_resource_ids, new_scan_time = parse_ioa_iom_incidents(
            fetched_data=get_iom_resources(iom_resource_ids=iom_resource_ids),
            last_date=last_scan_time,
            last_fetched_ids=last_resource_ids, date_key='scan_time',
            id_key='id', date_format=IOM_DATE_FORMAT, is_paginating=bool(iom_new_next_token or iom_next_token),
            to_incident_context=iom_resource_to_incident,
            incident_type='iom_configurations')

        iom_last_run = {'iom_next_token': iom_new_next_token, 'last_scan_time': new_scan_time,
                        'last_fetch_filter': filter,
                        'last_resource_ids': fetched_resource_ids or last_resource_ids}

    if 'Indicator of Attack' in fetch_incidents_or_detections:
        demisto.debug('Fetching Indicator of Attack incidents')
        demisto.debug(f'{ioa_last_run=}')
        fetch_query = params.get('ioa_fetch_query', '')
        validate_ioa_fetch_query(ioa_fetch_query=fetch_query)

        last_fetch_event_ids, ioa_next_token, last_date_time_since, _ = get_current_fetch_data(
            last_run_object=ioa_last_run, date_format=DATE_FORMAT,
            last_date_key='last_date_time_since', next_token_key='ioa_next_token',
            last_fetched_ids_key='last_event_ids'
        )
        ioa_fetch_query = create_ioa_query(
            is_paginating=bool(ioa_next_token),
            configured_fetch_query=fetch_query,
            last_fetch_query=ioa_last_run.get('last_fetch_query', ''),
            last_date_time_since=last_date_time_since)
        demisto.debug(f'IOA {ioa_fetch_query=}')
        ioa_events, ioa_new_next_token = ioa_events_pagination(ioa_fetch_query=ioa_fetch_query,
                                                               ioa_next_token=ioa_next_token,
                                                               fetch_limit=INCIDENTS_PER_FETCH,
                                                               api_limit=1000)
        demisto.debug(f'Fetched the following IOA event IDs: {[event.get("event_id") for event in ioa_events]}')

        ioa_incidents, ioa_event_ids, new_date_time_since = parse_ioa_iom_incidents(
            fetched_data=ioa_events, last_date=last_date_time_since,
            last_fetched_ids=last_fetch_event_ids, date_key='event_created',
            id_key='event_id', date_format=DATE_FORMAT,
            is_paginating=bool(ioa_new_next_token or ioa_next_token),
            to_incident_context=ioa_event_to_incident, incident_type='ioa_events')

        ioa_last_run = {'ioa_next_token': ioa_new_next_token, 'last_date_time_since': new_date_time_since,
                        'last_fetch_query': ioa_fetch_query, 'last_event_ids': ioa_event_ids or last_fetch_event_ids}

    if ON_DEMAND_SCANS_DETECTION_TYPE in fetch_incidents_or_detections:
        if LEGACY_VERSION:
            raise DemistoException('On-Demand Scans Detection is not supported in legacy version.')
        demisto.debug('Fetching On-Demand Scans Detection incidents')
        demisto.debug(f'on_demand_detections_last_run= {current_fetch_on_demand_detections}')

        on_demand_detections, current_fetch_on_demand_detections = fetch_detections_by_product_type(
            current_fetch_on_demand_detections,
            look_back=look_back,
            fetch_query=params.get('on_demand_fetch_query', ''),
            detections_type=ON_DEMAND_SCANS_DETECTION,
            product_type='ods',
            detection_name_prefix=ON_DEMAND_SCANS_DETECTION_TYPE,
            start_time_key='created_timestamp')

    if OFP_DETECTION_TYPE in fetch_incidents_or_detections:
        if LEGACY_VERSION:
            raise DemistoException(f'{OFP_DETECTION_TYPE} is not supported in legacy version.')
        demisto.debug(f'Fetching {OFP_DETECTION_TYPE} incidents')
        demisto.debug(f'ofp_detection_last_run= {current_fetch_ofp_detection}')

        ofp_detections, current_fetch_ofp_detection = fetch_detections_by_product_type(
            current_fetch_ofp_detection,
            look_back=look_back,
            fetch_query=params.get('ofp_detection_fetch_query', ''),
            detections_type=OFP_DETECTION,
            product_type='ofp',
            detection_name_prefix=OFP_DETECTION_TYPE,
            start_time_key='created_timestamp')

    demisto.setLastRun([current_fetch_info_detections, current_fetch_info_incidents, current_fetch_info_idp_detections,
                        iom_last_run, ioa_last_run, current_fetch_info_mobile_detections, current_fetch_on_demand_detections,
                        current_fetch_ofp_detection])
    return incidents + detections + idp_detections + iom_incidents + ioa_incidents + mobile_detections + on_demand_detections\
        + ofp_detections


def fetch_detections_by_product_type(current_fetch_info: dict, look_back: int, product_type: str,
                                     fetch_query: str, detections_type: str, detection_name_prefix: str,
                                     start_time_key: str) -> tuple[List, dict]:
    """The fetch logic for idp, ods and mobile detections.

    Args:
        current_fetch_info (dict): The last run object.
        look_back (int): The number of minutes to lookback.
        product_type (str): The product_type, used for debug & query.
        fetch_query (str): The user's query param.
        detections_type (str): The detection type, used for debugging and context save.
        detection_name_prefix (str): The name prefix for the fetched incidents.
        start_time_key (str): The key to save as the incident occurred time.

    Returns:
        tuple[List, dict]: The list of the fetched incidents and the updated last object.
    """
    detections: List = []
    offset: int = current_fetch_info.get('offset') or 0
    start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=current_fetch_info,
                                                                first_fetch=FETCH_TIME,
                                                                look_back=look_back,
                                                                date_format=DETECTION_DATE_FORMAT)
    fetch_limit = current_fetch_info.get('limit') or INCIDENTS_PER_FETCH
    filter = f"product:'{product_type}'+created_timestamp:>'{start_fetch_time}'"
    if product_type in {IncidentType.ON_DEMAND.value, IncidentType.OFP.value}:
        filter = filter.replace('product:', 'type:')

    if fetch_query:
        filter += f"+{fetch_query}"
    response = get_detections_ids(filter_arg=filter, limit=fetch_limit, offset=offset, product_type=product_type)
    detections_ids: list[dict] = demisto.get(response, "resources", [])
    total_detections = demisto.get(response, "meta.pagination.total")
    offset = calculate_new_offset(offset, len(detections_ids), total_detections)
    if offset:
        if offset + fetch_limit > MAX_FETCH_SIZE:
            demisto.debug(f"CrowdStrikeFalconMsg: The new offset: {offset} + limit: {fetch_limit} reached "
                          f"{MAX_FETCH_SIZE}, resetting the offset to 0")
            offset = 0
        demisto.debug(f"CrowdStrikeFalconMsg: The new {detections_type} offset is {offset}")

    if detections_ids:
        raw_res = get_detection_entities(detections_ids)
        if "resources" in raw_res:
            full_detections = demisto.get(raw_res, "resources")
            for detection in full_detections:
                detection['incident_type'] = detections_type
                detection_to_context = detection_to_incident_context(detection, detection_name_prefix, start_time_key)
                detections.append(detection_to_context)
        detections = truncate_long_time_str(detections, 'occurred') if product_type in {
            IncidentType.ON_DEMAND.value, IncidentType.OFP.value} else detections
        detections = filter_incidents_by_duplicates_and_limit(incidents_res=detections,
                                                              last_run=current_fetch_info,
                                                              fetch_limit=INCIDENTS_PER_FETCH, id_field='name')

    current_fetch_info = update_last_run_object(last_run=current_fetch_info,
                                                incidents=detections,
                                                fetch_limit=fetch_limit,
                                                start_fetch_time=start_fetch_time,
                                                end_fetch_time=end_fetch_time,
                                                look_back=look_back,
                                                created_time_field='occurred',
                                                id_field='name',
                                                date_format=DETECTION_DATE_FORMAT,
                                                new_offset=offset)
    demisto.debug(f"CrowdstrikeFalconMsg: Ending fetch {detections_type}. Fetched {len(detections)}")
    return detections, current_fetch_info


def parse_ioa_iom_incidents(fetched_data: list[dict[str, Any]], last_date: str,
                            last_fetched_ids: list[str], date_key: str, id_key: str,
                            date_format: str, is_paginating: bool,
                            to_incident_context: Callable[[dict[str, Any], str], dict[str, Any]],
                            incident_type: str) -> tuple[list[dict[str, Any]], list[str], str]:
    """This function is in charge of parsing IOA, and IOM data from their respective API,
    to create incidents from them.

    Args:
        fetched_data (list[dict[str, Any]]): The fetched data.
        last_date (str): The last date saved in the last run object.
        last_fetched_ids (list[str]): The last fetched IDs.
        date_key (str): The key of the value that holds the date in the API.
        id_key (str): The key of the value that holds the ID in the API.
        date_format (str): The date format.
        is_paginating (bool): Whether we are doing pagination or not. When false, the previously fetched IDs
        will NOT be considered for duplicates removal.
        new_next_token (str | None): The next token that will be used in the next run.
        next_token (str | None): The next token that was used in the current round.
        to_incident_context (Callable[[dict[str, Any], str], dict[str, Any]]): The function that is used to convert
        data from the API to an incident.
        incident_type (str): The incident type.

    Returns:
        tuple[list[dict[str, Any]], list[str], str]: The fetched incidents, the fetched ids, the largest date
        found withing the fetched incidents.
    """
    incidents: list[dict[str, Any]] = []
    fetched_ids: list[str] = []
    # Hold the date_time_since of all fetched incidents, to acquire the largest date
    fetched_dates: list[datetime] = [datetime.strptime(last_date, date_format)]
    for data in fetched_data:
        data_id = data.get(id_key, '')
        if data_id not in last_fetched_ids:
            demisto.debug(f'Creating an incident for CrowdStrike CSPM ID: {data_id}')
            fetched_ids.append(data_id)
            incident_context = to_incident_context(data, incident_type)
            incidents.append(incident_context)
            event_created = reformat_timestamp(data.get(date_key, ''), date_format)
            fetched_dates.append(datetime.strptime(event_created, date_format))
        else:
            demisto.debug(f'Ignoring CSPM incident with {data_id=} - was already fetched in the previous run')
    new_last_date = max(fetched_dates).strftime(date_format)
    if is_paginating:
        demisto.debug(f'Current run did pagination, or next one will, keeping {len(last_fetched_ids)} IDs from last fetch')
        # If the next run will do pagination, or the current run did pagination, we should keep the ids from the last fetch
        # until progress is made, so we exclude them in the next fetch.
        fetched_ids.extend(last_fetched_ids)
    return incidents, fetched_ids, new_last_date


def get_current_fetch_data(last_run_object: dict[str, Any],
                           date_format: str,
                           last_date_key: str,
                           next_token_key: str,
                           last_fetched_ids_key: str,
                           ) -> tuple[list[str], str | None, str, str]:
    """Returns the last fetched ids, next token that will be used in current round, last date
    found in the last run object, and the first fetch timestamp.

    Args:
        last_run_object (dict[str, Any]): The last run object.
        date_format (str): The date format.
        last_date_key (str): The key of the value that holds the date in the last run object.
        next_token_key (str): The key of the value that holds the next token in the last run object.
        last_fetched_ids_key (str): The key of the value that holds the last fetched ids in the
        last run object.

    Returns:
        tuple[list[str], str | None, str, str]: The last fetched IDs, the next token that will be used
        in the current fetch round, the last date saved in the last run object, and the first
        fetch timestamp.
    """
    first_fetch_timestamp = reformat_timestamp(
        time=FETCH_TIME,
        date_format=date_format,
        dateparser_settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
    last_date = last_run_object.get(
        last_date_key, first_fetch_timestamp)
    # The next token is used when not all the results have been returned from the API, therefore,
    # we would need to do pagination using the next token query parameter
    next_token = last_run_object.get(next_token_key)
    # In order to deal with duplicates, we retrieve the last resource ids of the last run, so we can
    # compare them with the newly fetched ids, and ignore any duplicates
    last_fetched_ids: list[str] = last_run_object.get(last_fetched_ids_key, [])
    return last_fetched_ids, next_token, last_date, first_fetch_timestamp


def create_iom_filter(is_paginating: bool, last_fetch_filter: str,
                      last_scan_time: str, first_fetch_timestamp: str,
                      configured_fetch_query: str) -> str:
    """Retrieve the IOM filter that will be used in the current fetch round.

    Args:
        is_paginating (bool): Whether we are doing pagination or not.
        last_fetch_filter (str): The last fetch filter that was used in the previous round.
        last_scan_time (str): The last scan time.
        first_fetch_timestamp (str): The first fetch timestamp.
        configured_fetch_query (str): The fetched query configured by the user.

    Raises:
        DemistoException: If paginating and last filter is an empty string.

    Returns:
        str: The IOM filter that will be used in the current fetch.
    """
    filter = 'scan_time:'
    if is_paginating:
        if not last_fetch_filter:
            raise DemistoException('Last fetch filter must not be empty when doing pagination')
        # Doing pagination, we need to use the same fetch query as the previous round
        filter = last_fetch_filter
        demisto.debug(f'Doing pagination, using the same query as the previous round. Filter is {filter}')
    else:
        # If entered here, that means we aren't doing pagination
        if last_scan_time == first_fetch_timestamp:
            # First fetch, we want to include resources with a scan time
            # EQUAL or GREATER than the first fetch timestamp
            filter = f"{filter} >='{last_scan_time}'"
            demisto.debug(f'First fetch, looking for scan time >= {last_scan_time=}. Filter is {filter}')
        else:
            # Not first fetch, we only want to include resources with a scan time
            # GREATER than the last configured scan time, to prevent duplicates.
            filter = f"{filter} >'{last_scan_time}'"
            demisto.debug(f'Not first fetch, only looking for scan time > {last_scan_time=}. Filter is {filter}')
    if configured_fetch_query and not is_paginating:
        # If the user entered a fetch query, then append it to the filter
        demisto.debug('User entered fetch query, appending to filter')
        filter = f"{filter}+{configured_fetch_query}"
    return filter


def validate_iom_fetch_query(iom_fetch_query: str) -> None:
    if 'scan_time' in iom_fetch_query:
        raise DemistoException('scan_time is not allowed as part of the IOM fetch query.')


def add_seconds_to_date(date: str, seconds_to_add: int, date_format: str) -> str:
    """Takes in a date in string format, and adds seconds to it according to seconds_to_add.

    Args:
        date (str): The date we want to add seconds to it.
        seconds_to_add (int): The amount of seconds to add to the date.
        date_format (str): The date format.

    Returns:
        str: The date with an increase in seconds.
    """
    added_datetime = datetime.strptime(date, date_format) + timedelta(seconds=seconds_to_add)
    return added_datetime.strftime(date_format)


def create_ioa_query(is_paginating: bool, last_fetch_query: str,
                     configured_fetch_query: str, last_date_time_since: str) -> str:
    """Retrieve the IOA query that will be used in the current fetch round.

    Args:
        is_paginating (bool): Whether we are doing pagination or not.
        last_fetch_query (str): The last fetch query that was used in the previous round.
        configured_fetch_query (str): The fetched query configured by the user.
        last_date_time_since (str): The last date time since.

    Raises:
        DemistoException: If paginating and last fetch query is an empty string.

    Returns:
        str: The IOA query that will be used in the current fetch.
    """
    fetch_query = configured_fetch_query
    if is_paginating:
        # If entered here, that means we are currently doing pagination, and we need to use the
        # same fetch query as the previous round
        fetch_query = last_fetch_query
        if not fetch_query:
            raise DemistoException('Last fetch query must not be empty when doing pagination')
        demisto.debug(f'Doing pagination, using the same query as the previous round. Query is {fetch_query}')
    else:
        # If entered here, that means we aren't doing pagination, and we need to use the latest
        # date_time_since time
        fetch_query = f'{fetch_query}&date_time_since={last_date_time_since}'
        demisto.debug(f'Not doing pagination. Query is {fetch_query}')
    return fetch_query


def ioa_event_to_incident(ioa_event: dict[str, Any], incident_type: str) -> dict[str, Any]:
    """Create an incident from an IOA event.

    Args:
        ioa_event (dict[str, Any]): An IOA event.
        incident_type (str): The incident type.

    Returns:
        dict[str, Any]: An incident from an IOA event.
    """
    resource = demisto.get(ioa_event, 'aggregate.resource', {})
    id = resource.get('id', [])
    uuid = resource.get('uuid', [])
    incident_metadata = assign_params(
        mirror_direction=MIRROR_DIRECTION,
        mirror_instance=INTEGRATION_INSTANCE,
        extracted_account_id=demisto.get(ioa_event, 'cloud_account_id.aws_account_id')
        or demisto.get(ioa_event, 'cloud_account_id.azure_account_id'),
        extracted_uuid=uuid[0] if uuid else None,
        extracted_resource_id=id[0] if id else None,
        incident_type=incident_type
    )
    incident_context = {
        'name': f'IOA Event ID: {ioa_event.get("event_id")}',
        'rawJSON': json.dumps(ioa_event | incident_metadata)
    }
    return incident_context


def ioa_events_pagination(ioa_fetch_query: str, api_limit: int, ioa_next_token: str | None,
                          fetch_limit: int = INCIDENTS_PER_FETCH) -> tuple[list[dict[str, Any]], str | None]:
    """This is in charge of doing the pagination process in a single fetch run, since the fetch limit can be greater than
    the api limit, in such a case, we do multiple API calls until we reach the fetch limit, or no more results are found
    by the API.

    Args:
        ioa_fetch_query (str): The IOA fetch query.
        api_limit (int): The API limit
        ioa_next_token (str | None): The IOA next token to start the pagination from.
        fetch_limit (int, optional): The fetch limit. Defaults to INCIDENTS_PER_FETCH.

    Returns:
        tuple[list[dict[str, Any]], str | None]: A tuple where the first element is the fetched events, and the second is the next
        token that will be used in the next fetch run.
    """
    total_incidents_count = 0
    ioa_new_next_token = ioa_next_token
    fetched_ioa_events: list[dict[str, Any]] = []
    continue_pagination = True
    while continue_pagination:
        demisto.debug(f'Doing IOA pagination with the arguments: {ioa_fetch_query=}, {api_limit=}, {ioa_new_next_token=},'
                      f'{fetch_limit=}')
        ioa_events, ioa_new_next_token = get_ioa_events(ioa_fetch_query=ioa_fetch_query,
                                                        ioa_next_token=ioa_new_next_token,
                                                        limit=min(api_limit, fetch_limit - total_incidents_count))
        fetched_ioa_events.extend(ioa_events)
        total_incidents_count += len(ioa_events)
        demisto.debug(f'Results of IOA pagination: {total_incidents_count=}, {ioa_new_next_token=}')
        if (ioa_new_next_token is None) or (total_incidents_count >= fetch_limit):
            demisto.debug('Number of incidents reached the fetching limit, or there are no more results, stopping pagination')
            # If the number of fetched incidents reaches the fetching limit, or there are no more results to be fetched
            # (by checking the next token variable), then we should stop the pagination process
            continue_pagination = False
    return fetched_ioa_events, ioa_new_next_token


def get_ioa_events(ioa_fetch_query: str, ioa_next_token: str | None,
                   limit: int = INCIDENTS_PER_FETCH) -> tuple[list[dict[str, Any]], str | None]:
    """Do a single API call to receive IOA events.

    Args:
        ioa_fetch_query (str): The IOA fetch query.
        ioa_next_token (int | None): The next token to be used as part of the pagination process.
        limit (int, optional): The maximum amount to fetch IOA events. Defaults to INCIDENTS_PER_FETCH.

    Returns:
        tuple[list[dict[str, Any]], str | None]: A tuple where the first element is the returned events, and the second is the
        next token that will be used in the next API call.
    """
    # The API does not support a `query` parameter, rather a set of query params
    if ioa_next_token:
        ioa_fetch_query = f'{ioa_fetch_query}&next_token={ioa_next_token}'
    ioa_fetch_query = f'{ioa_fetch_query}&limit={limit}'
    demisto.debug(f'IOA {ioa_fetch_query=}')
    raw_response = http_request(method='GET', url_suffix=f'/detects/entities/ioa/v1?{ioa_fetch_query}')
    events = demisto.get(raw_response, 'resources.events', [])
    pagination_obj = demisto.get(raw_response, 'meta.pagination', {})
    demisto.debug(f'{pagination_obj=}')
    next_token = pagination_obj.get('next_token')
    if next_token:
        # If next_token has a value, that means more pagination is needed, and the next run should use it
        demisto.debug('next_token has a value, more pagination is needed for the next run')
        return events, next_token
    else:
        demisto.debug('next_token is None, no pagination is needed for the next run')
        # If it is None, that means no more pagination is required, therefore,
        # the next token for the next run should be None
        return events, None


def validate_ioa_fetch_query(ioa_fetch_query: str) -> None:
    """Validate the IOA fetch query.

    Args:
        ioa_fetch_query (str): The IOA fetch query.

    Raises:
        DemistoException: If the param cloud_provider is not part of the query.
        DemistoException: If an unsupported parameter has been entered.
        DemistoException: If the value of a parameter is an empty string.
        DemistoException: If a query section has a wrong format
    """
    demisto.debug(f'Validating IOA {ioa_fetch_query=}')
    if 'cloud_provider' not in ioa_fetch_query:
        raise DemistoException('A cloud provider is required as part of the IOA fetch query. Options are: aws, azure')
    # The following parameters are also supported by the API: 'date_time_since', 'next_token', 'limit', but we don't
    # allow them to be as part of the original fetch query, since they are used by the fetching mechanism, internally
    supported_params = ('cloud_provider', 'account_id', 'aws_account_id', 'azure_subscription_id', 'azure_tenant_id',
                        'severity', 'region', 'service', 'state')
    # The query has a format of 'param1=val1&param2=val2'
    for section in ioa_fetch_query.split('&'):
        param_and_value = section.split('=')
        # Since each section should have a format of 'param1=val1', then when splitting by '=', we should get
        # a list of length 2, where the first element holds the parameter that we want to validate
        if param_and_value and len(param_and_value) == 2:
            if param_and_value[0] not in supported_params:
                raise DemistoException(f'An unsupported parameter has been entered, {param_and_value[0]}.'
                                       f'Use the following parameters: {supported_params}')
            if param_and_value[1] == '':
                raise DemistoException(f'The value of the parameter {param_and_value[0]} cannot be an empty string')
        else:
            raise DemistoException(f'Query section "{section}" does not match the parameter=value format')


def reformat_timestamp(time: str, date_format: str, dateparser_settings: Any | None = None) -> str:
    """Format the given time according to the supplied date format.

    Args:
        time (str): The time to format.
        date_format (str): The date format.

    Raises:
        DemistoException: If the time is not a proper date string.

    Returns:
        str: The time in the supplied format.
    """
    if parsed_scan_time := dateparser.parse(time, settings=dateparser_settings):
        return parsed_scan_time.strftime(date_format)
    else:
        raise DemistoException(f'{time=} is not a proper date string')


def iom_resource_to_incident(iom_resource: dict[str, Any], incident_type: str) -> dict[str, Any]:
    """Create an incident from an IOM entity.

    Args:
        iom_resource (dict[str, Any]): An IOM entity.
        incident_type (str): The incident type.

    Returns:
        dict[str, Any]: An incident from an IOM entity.
    """
    incident_metadata = assign_params(
        mirror_direction=MIRROR_DIRECTION,
        mirror_instance=INTEGRATION_INSTANCE,
        incident_type=incident_type
    )

    incident_context = {
        'name': f'IOM Event ID: {iom_resource.get("id")}',
        'rawJSON': json.dumps(iom_resource | incident_metadata)
    }
    return incident_context


def iom_ids_pagination(filter: str, api_limit: int, iom_next_token: str | None,
                       fetch_limit: int = INCIDENTS_PER_FETCH) -> tuple[list[str], str | None]:
    """This is in charge of doing the pagination process in a single fetch run, since the fetch limit can be greater than
    the api limit, in such a case, we do multiple API calls until we reach the fetch limit, or no more results are found by the
    API.

    Args:
        filter (str): The IOM filter query parameter.
        api_limit (int): The API limit
        iom_next_token (str | None): The IOM next token to start the pagination from.
        fetch_limit (int, optional): The fetch limit. Defaults to INCIDENTS_PER_FETCH.

    Returns:
        tuple[list[dict[str, Any]], str | None]: A tuple where the first element is the fetched resources, and the second is the
        next token that will be used in the next fetch run.
    """
    total_incidents_count = 0
    iom_new_next_token = iom_next_token
    fetched_iom_events: list[str] = []
    continue_pagination = True
    while continue_pagination:
        demisto.debug(f'Doing IOM pagination with the arguments: {filter=}, {api_limit=}, {iom_new_next_token=},'
                      f'{fetch_limit=}')
        iom_resource_ids, iom_new_next_token = get_iom_ids_for_fetch(filter=filter, iom_next_token=iom_new_next_token,
                                                                     limit=min(api_limit, fetch_limit - total_incidents_count))
        fetched_iom_events.extend(iom_resource_ids)
        total_incidents_count += len(iom_resource_ids)
        demisto.debug(f'Results of IOM pagination: {total_incidents_count=}, {iom_new_next_token=}')
        if total_incidents_count >= fetch_limit or iom_new_next_token is None:
            # If the number of fetched incidents reaches the fetching limit, or there are no more results to be fetched
            # (by checking the next token variable), then we should stop the pagination process
            continue_pagination = False
    return fetched_iom_events, iom_new_next_token


def get_iom_ids_for_fetch(filter: str, iom_next_token: str | None = None,
                          limit: int = INCIDENTS_PER_FETCH) -> tuple[list[str], str | None]:
    """Do a single API call to receive IOM resource ids.

    Args:
        filter (str | None): The filter to use when fetching IOM events.
        iom_next_token (int | None): The next token to be used as part of the pagination process.
        limit (int, optional): The maximum amount to fetch IOA events. Defaults to INCIDENTS_PER_FETCH.

    Returns:
        tuple[list[dict[str, Any]], str | None]: A tuple where the first element is the returned events, and the second is the
        next token that will be used in the next API call.
    """
    query_params = assign_params(
        filter=filter,
        limit=limit,
        next_token=iom_next_token
    )
    demisto.debug(f'IOM {query_params=}')
    raw_response = http_request(method='GET', url_suffix='/detects/queries/iom/v2', params=query_params)
    resource_ids = raw_response.get('resources', [])
    pagination_obj = demisto.get(raw_response, 'meta.pagination', {})
    demisto.debug(f'{pagination_obj=}')
    next_token = pagination_obj.get('next_token')
    if next_token:
        # If next_token has a value, that means more pagination is needed, and the next run should use it
        return resource_ids, next_token
    else:
        # If it is None, that means no more pagination is required, therefore,
        # the next token for the next run should be None
        return resource_ids, None


def get_iom_resources(iom_resource_ids: list[str]) -> list[dict[str, Any]]:
    """Get the IOM entities/details that were fetched.

    Args:
        iom_resource_ids (list[str]): The IOM resource IDs.

    Returns:
        list[dict[str, Any]]: A list of the IOM entities.
    """
    if iom_resource_ids:
        query_params = '&'.join(f'ids={resource_id}' for resource_id in iom_resource_ids)
        raw_response = http_request('GET', '/detects/entities/iom/v2',
                                    params=query_params)
        return raw_response.get('resources', [])
    else:
        return []


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
        file_name: str | None = None,
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
                                            expiration, applied_globally, host_groups, tags, file_name)
    raw_res = upload_batch_custom_ioc(ioc_batch=iocs_json_batch)
    handle_response_errors(raw_res)
    iocs = raw_res.get('resources', [])

    entry_objects_list = []
    for ioc in iocs:
        ec = [get_trasnformed_dict(ioc, IOC_KEY_MAP)]
        ec[0]["Filename"] = ioc.get("metadata", {}).get("filename")
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
        file_name: str | None = None,
) -> dict:
    """
    :param ioc_id: The ID of the indicator to update.
    :param action: Action to take when a host observes the custom IOC.
    :param platforms: The platforms that the indicator applies to.
    :param severity: The severity level to apply to this indicator.
    :param source: The source where this indicator originated.
    :param description: A meaningful description of the indicator.
    :param expiration: The date on which the indicator will become inactive.
    :param file_name: The file name associated with the indicator.
    """

    raw_res = update_custom_ioc(
        ioc_id,
        action,
        argToList(platforms),
        severity,
        source,
        description,
        expiration,
        file_name,
    )
    handle_response_errors(raw_res)
    iocs = raw_res.get('resources', [])
    ec = [get_trasnformed_dict(iocs[0], IOC_KEY_MAP)]
    ec[0]["Filename"] = iocs[0].get("metadata", {}).get("filename")
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

        device_count = device_count_res[0].get("device_count")
        if argToBoolean(device_count_res[0].get('limit_exceeded', False)):
            demisto.debug(f'limit exceeded for {ioc_id}, trying to count by run_indicator_device_id_request')
            # rate limit exceeded, so we will get the count by running the run_indicator_device_id_request function
            # see https://falcon.crowdstrike.com/documentation/page/ed1b4a95/detection-and-prevention-policy-apis

            device_count = 0
            params = assign_params(
                type=ioc_type,
                value=value
            )

            while True:
                device_ids_raw = run_indicator_device_id_request(params)
                device_count += len(device_ids_raw.get('resources', []))
                offset = demisto.get(device_ids_raw, 'meta.pagination.offset')
                if not offset:
                    break
                params['offset'] = offset

            device_count_res[0]['device_count'] = device_count

        context = [get_trasnformed_dict(device_count, IOC_DEVICE_COUNT_MAP) for device_count in device_count_res]
        hr = f'Indicator of Compromise **{ioc_id}** device count: **{device_count}**'
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
    device_ids = []
    if not raw_res:
        return create_entry_object(hr='Could not find any devices.')
    devices = raw_res.get('resources')
    extended_data = argToBoolean(demisto.args().get('extended_data', False))
    for device in devices:
        device_id = device.get("device_id")
        device_ids.append(device_id)
    state_data = get_status(device_ids)
    command_results = []
    for single_device in devices:
        endpoint = generate_endpoint_by_contex_standard(single_device, state_data)
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
    for resource in response_json['resources'] or []:
        try:
            result[resource['id']] = resource['name']
        except KeyError:
            demisto.debug(f"Could not retrieve group name for {resource=}")
    return result


def get_status(device_ids):
    """
    Get the online status for one or more hosts by specifying each host’s unique ID (up to 100 max).
    The status can be online, offline, or unknown.
    Args:
        device_ids: list of device ids.

    Returns: dictionary contains the id:state

    """
    state_data = {}
    batch_size = 100
    for i in range(0, len(device_ids), batch_size):
        batch = device_ids[i:i + batch_size]
        raw_res = http_request('GET', '/devices/entities/online-state/v1', params={'ids': batch})
        for res in raw_res.get('resources'):
            state = res.get('state', '')
            device_id = res.get('id', '')
            if state == 'unknown':
                demisto.debug(f"Device with id: {device_id} returned an unknown state, which indicates that the host has not"
                              f" been seen recently and we are not confident about its current state")
            state_data[device_id] = HOST_STATUS_DICT[state]
    return state_data


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


def generate_endpoint_by_contex_standard(single_device, state_data):
    device_id = single_device.get('device_id')
    endpoint = Common.Endpoint(
        id=device_id,
        hostname=single_device.get('hostname'),
        ip_address=single_device.get('local_ip'),
        os=single_device.get('platform_name'),
        os_version=single_device.get('os_version'),
        status=state_data.get(device_id),
        is_isolated=get_isolation_status(single_device.get('status')),
        mac_address=single_device.get('mac_address'),
        vendor=INTEGRATION_NAME)
    return endpoint


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
    device_ids = []
    for device in devices:
        device_id = device.get("device_id")
        device_ids.append(device_id)
    state_data = get_status(device_ids)

    # filter hostnames that will match the exact hostnames including case-sensitive
    if hostnames := argToList(args.get('hostname')):
        lowercase_hostnames = {hostname.lower() for hostname in hostnames}
        devices = [device for device in devices if (device.get('hostname') or '').lower() in lowercase_hostnames]

    standard_endpoints = []
    for single_device in devices:
        standard_endpoints.append(generate_endpoint_by_contex_standard(single_device, state_data))

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

            if not LEGACY_VERSION:
                detection = modify_detection_outputs(detection)

            for path, new_key in (LEGACY_DETECTIONS_BASE_KEY_MAP.items() if LEGACY_VERSION else
                                  DETECTIONS_BASE_KEY_MAP.items()):
                detection_entry[new_key] = demisto.get(detection, path)
            behaviors = []

            for behavior in demisto.get(detection, 'behaviors'):
                behaviors.append(behavior_to_entry_context(behavior))
            detection_entry['Behavior'] = behaviors

            if extended_data:
                detection_entry['Device'] = demisto.get(detection, 'device')
                if LEGACY_VERSION:  # The new version (raptor) does not have the 'behaviors_processed' key
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
    tag = args.get('tag')
    show_in_ui = args.get('show_in_ui')
    if not (username or assigned_to_uuid or comment or status or show_in_ui or tag):
        raise DemistoException("Please provide at least one argument to resolve the detection with.")
    if LEGACY_VERSION and tag:
        raise DemistoException("tag argument is only relevant when running with API V3.")
    raw_res = resolve_detection(ids, status, assigned_to_uuid, show_in_ui, comment, tag)
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
        batch_id = args.get('batch_id', None) if args.get('batch_id', None) else init_rtr_batch_session(host_ids, offline)
        demisto.debug(f"{args.get('batch_id', None)=} , {batch_id=}")
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
                'Command': full_command,
                'BatchID': batch_id
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
    full_command = ""
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


def run_indicator_device_id_request(params):
    return http_request('GET', '/indicators/queries/devices/v1', params=params, status_code=404)


def get_indicator_device_id():
    args = demisto.args()
    ioc_type = args.get('type')
    ioc_value = args.get('value')
    params = assign_params(
        type=ioc_type,
        value=ioc_value
    )
    raw_res = run_indicator_device_id_request(params=params)
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
                                        max_severity=detection.get('max_severity_displayname') if LEGACY_VERSION else
                                        detection.get('severity_name'),
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
    if not LEGACY_VERSION:
        # modify the new version (raptor) outputs to match the old format for backward compatibility
        detections = [modify_detection_summaries_outputs(detection) for detection in detections]
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
                                    limit: str | None = None,
                                    sort: str | None = None) -> CommandResults:
    response = host_group_members(filter, host_group_id, limit, offset, sort)
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


def resolve_incident_command(ids: list[str], status: str | None = None, user_uuid: str | None = None,
                             user_name: str | None = None, add_comment: str | None = None, add_tag: str | None = None,
                             remove_tag: str | None = None) -> CommandResults:
    if not any([status, user_uuid, user_name, add_comment, add_tag, remove_tag]):
        raise DemistoException('At least one of the following arguments must be provided:'
                               'status, assigned_to_uuid, username, add_tag, remove_tag, add_comment')

    if user_name and not user_uuid:
        user_uuid = get_username_uuid(username=user_name)

    action_parameters = {}
    readable_output = f"Incident IDs '{', '.join(ids)}' have been updated successfully:\n"

    if status:
        action_parameters['update_status'] = STATUS_TEXT_TO_NUM[status]
        readable_output += f"Status has been updated to '{status}'.\n"

    if user_uuid:
        action_parameters['update_assigned_to_v2'] = user_uuid
        readable_output += f"Assigned user has been updated to '{user_uuid}'.\n"

    if add_tag:
        action_parameters['add_tag'] = add_tag
        readable_output += f"Tag '{add_tag}' has been added.\n"

    if remove_tag:
        action_parameters['delete_tag'] = remove_tag
        readable_output += f"Tag '{remove_tag}' has been removed.\n"

    if add_comment:
        action_parameters['add_comment'] = add_comment
        readable_output += f"Comment '{add_comment}' has been added.\n"

    update_incident_request(ids=ids,
                            action_parameters=action_parameters)

    return CommandResults(readable_output=readable_output)


def update_incident_comment_command(ids: list[str], comment: str):
    update_incident_request(ids=ids, action_parameters={'add_comment': comment})
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


def module_test():
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
            polling_timeout = arg_to_number(args.get('polling_timeout', 600))
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval_in_secs,
                args=args,
                timeout_in_seconds=polling_timeout)
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

    # detection_ids are under the alert_ids key in the new (raptor) API, see XSUP-41622
    detection_ids_key = 'detection_ids' if LEGACY_VERSION else 'alert_ids'
    for detection in detection_res:
        outputs.append({
            'incident_id': detection.get('incident_id'),
            'behavior_id': detection.get('behavior_id'),
            'detection_ids': detection.get(detection_ids_key),
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


def get_cve_command(args: dict) -> list[dict[str, Any]]:
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
        command_results = CommandResults(raw_response=cve, readable_output=human_readable, relationships=relationships_list,
                                         indicator=cve_indicator).to_context()
        if command_results not in command_results_list:
            command_results_list.append(command_results)
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
    if isinstance(files, list):
        for file in files:
            if isinstance(file, dict) and 'composite_ids' in file:
                file['detect_ids'] = file.pop('composite_ids')

    human_readable = tableToMarkdown('CrowdStrike Falcon Quarantined File',
                                     t=files,
                                     headers=QUARANTINE_FILES_OUTPUT_HEADERS,
                                     is_auto_json_transform=True,
                                     headerTransform=underscoreToCamelCase,
                                     sort_headers=False,
                                     removeNull=True)

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
        'retries': 10,
        'headers': {'Authorization': f'Bearer {get_token()}',
                    "Accept": "application/json",
                    "Content-Type": "application/json"}
    }
    transport = RequestsHTTPTransport(**kwargs)  # type: ignore[arg-type]
    client = Client(
        transport=transport,
        fetch_schema_from_transport=True,
    )
    return client


def cspm_list_policy_details_request(policy_ids: list[str]) -> dict[str, Any]:
    """Do an API call to retrieve policy details.

    Args:
        policy_ids (list[str]): The policy ids.

    Returns:
        dict[str, Any]: The raw response of the API.
    """
    query_params = '&'.join(f'ids={policy_id}' for policy_id in policy_ids)
    # Status codes of 500 and 400 are sometimes returned when the policy IDs given do not exist, therefore we want
    # to catch this case so we can return a proper message to the user
    # Status code of 207 is returned when the API returns data about the policy IDs that were found,
    # and an error for the policy IDs that were not found, in the same response
    return http_request(method='GET', url_suffix='/settings/entities/policy-details/v1',
                        params=query_params, status_code=[500, 400, 207])


def cs_falcon_cspm_list_policy_details_command(args: dict[str, Any]) -> CommandResults:
    """Command to list policy details.

    Args:
        args (dict[str, Any]): The arguments of the command

    Raises:
        DemistoException: If a status code of 500 is returned.

    Returns:
        CommandResults: The command results object.
    """
    policy_ids = argToList(args.get('policy_ids'))
    raw_response = cspm_list_policy_details_request(policy_ids=policy_ids)
    # The API returns errors in the form of a list, under the key 'errors'
    if errors := raw_response.get('errors', []):
        if errors[0].get('code', '') == 500:
            raise DemistoException(
                'CS Falcon CSPM returned an error.\n'
                'Code: 500\n'
                f'Message: {dict_safe_get(raw_response, ["errors", 0, "message"])}\n'
                'Perhaps the policy IDs are invalid?'
            )
        for error in errors:
            if error.get('code') == 400:
                return_warning(
                    'CS Falcon CSPM returned an error.\n'
                    f'Code:  {error.get("code")}\n'
                    f'Message: {error.get("message")}\n'
                )

    if resources := raw_response.get('resources', []):
        human_readable = tableToMarkdown('CSPM Policy Details:', resources,
                                         headers=['ID', 'description',
                                                  'policy_statement', 'policy_remediation', 'cloud_service_subtype',
                                                  'cloud_platform_type', 'cloud_service_type', 'default_severity',
                                                  'policy_type', 'tactic', 'technique'],
                                         headerTransform=string_to_table_header)
        return CommandResults(readable_output=human_readable,
                              outputs=resources,
                              outputs_key_field='ID',
                              outputs_prefix='CrowdStrike.CSPMPolicy',
                              raw_response=raw_response)
    return CommandResults(readable_output='No policy details were found for the given policy IDs.')


def cspm_list_service_policy_settings_request(policy_id: str, cloud_platform: str, service: str) -> dict[str, Any]:
    """Do an API call to retrieve the policy settings.

    Args:
        policy_id (str): The policy ID.
        cloud_platform (str): The cloud platform to filter by.
        service (str): The service type to filter by.

    Returns:
        dict[str, Any]: The raw response of the API.
    """
    query_params: dict[str, Any] = assign_params(service=service)
    if policy_id:
        query_params['policy-id'] = policy_id
    if cloud_platform:
        query_params['cloud-platform'] = cloud_platform
    return http_request(method='GET', url_suffix='/settings/entities/policy/v1', params=query_params,
                        status_code=[207])


def cs_falcon_cspm_list_service_policy_settings_command(args: dict[str, Any]) -> CommandResults:
    """Command to list service policy settings.

    Args:
        args (dict[str, Any]): The arguments of the command.

    Returns:
        CommandResults: The command results object.
    """
    policy_id = args.get('policy_id', '')
    cloud_platform = args.get('cloud_platform', '')
    service = args.get('service', '')
    limit = arg_to_number(args.get('limit')) or 50

    raw_response = cspm_list_service_policy_settings_request(policy_id=policy_id, cloud_platform=cloud_platform,
                                                             service=service)
    if resources := raw_response.get('resources', []):
        # The API does not support pagination, therefore we have to do it manually
        paginated_resources = resources[:limit]
        human_readable = tableToMarkdown('CSPM Policy Settings:', paginated_resources,
                                         headers=['policy_id', 'is_remediable',
                                                  'remediation_summary', 'name', 'policy_type',
                                                  'cloud_service_subtype', 'cloud_service', 'default_severity'],
                                         headerTransform=string_to_table_header)
        return CommandResults(readable_output=human_readable,
                              outputs=paginated_resources,
                              outputs_key_field='policy_id',
                              outputs_prefix='CrowdStrike.CSPMPolicySetting',
                              raw_response=raw_response)
    return CommandResults(readable_output='No policy settings were found for the given arguments.')


def cspm_update_policy_settings_request(account_id: str, enabled: bool, policy_id: int, regions: list[str],
                                        severity: str, tag_excluded: bool | None) -> dict[str, Any]:
    """Do an API call to update the policy settings.

    Args:
        account_id (str): The account ID.
        enabled (bool): Whether to enable the policy or not.
        policy_id (int): The policy ID.
        regions (list[str]): The regions of the policy.
        severity (str): The severity of the policy.
        tag_excluded (bool | None): Whether to exclude tag or not.

    Returns:
        dict[str, Any]: The raw response of the API.
    """
    # https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cspm-registration/UpdateCSPMPolicySettings
    # You have to be logged into https://falcon.crowdstrike.com/
    resources_body: dict[str, Any] = {
        'resources': [
            assign_params(
                account_id=account_id,
                enabled=enabled,
                policy_id=policy_id,
                regions=regions,
                severity=severity,
                tag_excluded=tag_excluded,
            )
        ]
    }
    return http_request(method='PATCH', url_suffix='/settings/entities/policy/v1',
                        json=resources_body, status_code=500)


def cs_falcon_cspm_update_policy_settings_command(args: dict[str, Any]) -> CommandResults:
    """Command to update policy settings.

    Args:
        args (dict[str, Any]): The arguments of the command.

    Raises:
        DemistoException: If the policy ID is not an integer.
        DemistoException: If a status code 500 is returned.

    Returns:
        CommandResults: The command results object.
    """
    account_id = args.get('account_id', '')
    enabled = argToBoolean(args.get('enabled', 'true'))
    policy_id = arg_to_number(args.get('policy_id'))
    if policy_id is None:
        raise DemistoException('policy_id must be an integer')
    regions = argToList(args.get('regions', []))
    severity = args.get('severity', '')
    tag_excluded = args.get('tag_excluded')
    tag_excluded = argToBoolean(tag_excluded) if tag_excluded else tag_excluded
    raw_response = cspm_update_policy_settings_request(account_id=account_id, enabled=enabled, policy_id=policy_id,
                                                       regions=regions, severity=severity, tag_excluded=tag_excluded)
    if (errors := raw_response.get('errors', [])) and errors[0].get('code', '') == 500:
        raise DemistoException(
            'CS Falcon CSPM returned an error.\n'
            'Code: 500\n'
            f'Message: {dict_safe_get(raw_response, ["errors", 0, "message"])}\n'
            'Perhaps the policy ID or account ID are invalid?'
        )
    return CommandResults(readable_output=f'Policy {policy_id} was updated successfully')


def resolve_detections_prepare_body_request(ids: list[str],
                                            action_params_values: dict[str, Any]) -> dict[str, Any]:
    """Create the body of the request to resolve detections.

    Args:
        ids (list[str]): The IDs of the detections.
        action_params_values (dict[str, Any]): A dictionary that holds key-value pairs corresponding
        to the action_parameters object of the API request.

    Returns:
        dict[str, Any]: The body of the request.
    """
    # Values need to be in the form {'name': name_of_key, 'value': value_of_key}, as can be seen here
    # https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PatchEntitiesAlertsV2

    # Implemented the same as:
    # https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_payload/_alerts.py#L40
    action_params = []
    for key, value in action_params_values.items():
        if value:
            param = {"name": key, "value": value}
            action_params.append(param)
    ids_request_key = 'composite_ids' if not LEGACY_VERSION else 'ids'
    return {'action_parameters': action_params, ids_request_key: ids}


def resolve_detections_request(ids: list[str], **kwargs) -> dict[str, Any]:
    """Do an API call to resolve detections.

    Args:
        ids (list[str]): The IDs of the detections.

    Returns:
        dict[str, Any]: The raw response of the API.
    """
    url_suffix = '/alerts/entities/alerts/v3' if not LEGACY_VERSION else '/alerts/entities/alerts/v2'
    body_payload = resolve_detections_prepare_body_request(ids=ids, action_params_values=kwargs)
    demisto.debug(f"In resolve_detections: {LEGACY_VERSION=}, {url_suffix=}, {body_payload=} ")
    return http_request(method='PATCH', url_suffix=url_suffix, json=body_payload)


def cs_falcon_resolve_identity_detection(args: dict[str, Any]) -> CommandResults:
    """Command to resolve identity detections.

    Args:
        args (dict[str, Any]): The arguments of the command.

    Returns:
        CommandResults: The command results object.
    """
    return handle_resolve_detections(args, 'IDP Detection(s) {} were successfully updated')


def cs_falcon_resolve_mobile_detection(args: dict[str, Any]) -> CommandResults:
    """Command to resolve mobile detections.

    Args:
        args (dict[str, Any]): The arguments of the command.

    Returns:
        CommandResults: The command results object.
    """
    return handle_resolve_detections(args, 'Mobile Detection(s) {} were successfully updated')


def handle_resolve_detections(args: dict[str, Any], hr_template: str) -> CommandResults:
    """Handle the mobile & identity detections resolve commands.

    Args:
        args (dict[str, Any]): The arguments of the command.

    Returns:
        CommandResults: The command results object.
    """
    ids = argToList(args.get('ids', '')) or []
    update_status = args.get('update_status', '')
    assign_to_name = args.get('assign_to_name', '')
    assign_to_uuid = args.get('assign_to_uuid', '')

    # This argument is sent to the API in the form of a string, having the values 'true' or 'false'
    unassign = args.get('unassign', '')

    append_comment = args.get('append_comment', '')
    add_tag = args.get('add_tag', '')
    remove_tag = args.get('remove_tag', '')

    # This argument is sent to the API in the form of a string, having the values 'true' or 'false'
    show_in_ui = args.get('show_in_ui', '')
    # We pass the arguments in the form of **kwargs, since we also need the arguments' names for the API,
    # and it easier to achieve that using **kwargs
    resolve_detections_request(ids=ids, update_status=update_status, assign_to_name=assign_to_name,
                               assign_to_uuid=assign_to_uuid, unassign=unassign, append_comment=append_comment,
                               add_tag=add_tag, remove_tag=remove_tag, show_in_ui=show_in_ui)
    return CommandResults(readable_output=hr_template.format(", ".join(ids)))


def cs_falcon_list_users_command(args: dict[str, Any]) -> CommandResults:
    users_ids = argToList(args.get('id'))
    offset = arg_to_number(args.get('offset')) or 0
    limit = arg_to_number(args.get('limit')) or 50
    query_filter = args.get('filter')

    if not users_ids:
        users_api_response = get_users(offset=offset, limit=limit, query_filter=query_filter)
        users_ids = users_api_response.get('resources', [])

        if not users_ids:
            return CommandResults(readable_output='No matching results found.')

    users_data_api_response = get_users_data(user_ids=users_ids)
    users_data = users_data_api_response.get('resources', [])

    def table_headers_transformer(header: str) -> str:
        mapping = {
            'uuid': 'UUID',
            'first_name': 'First Name',
            'last_name': 'Last Name',
            'uid': 'E-Mail (UID)',
            'last_login_at': 'Last Login',
        }

        return mapping.get(header, header)

    return CommandResults(
        outputs_prefix='CrowdStrike.Users',
        outputs_key_field='uuid',
        outputs=users_data,
        readable_output=tableToMarkdown(
            name='CrowdStrike Users',
            t=users_data,
            headers=['uuid', 'first_name', 'last_name', 'uid', 'last_login_at'],
            headerTransform=table_headers_transformer,
            sort_headers=False,
        ),
        raw_response=users_data_api_response,
    )


def get_incident_behavior_command(args: dict) -> CommandResults:
    behavior_ids = argToList(args['behavior_ids'])
    raw_response = get_behaviors(behavior_ids=behavior_ids)

    results = raw_response.get('resources', [])

    def table_headers_transformer(header: str) -> str:
        mapping = {
            'behavior_id': 'Behavior ID',
            'incident_ids': 'Incident IDs',
            'cid': 'CID',
            'aid': 'AID',
            'pattern_id': 'Pattern ID',
            'timestamp': 'Timestamp',
            'cmdline': 'Command Line',
            'filepath': 'File Path',
            'sha256': 'SHA256',
            'tactic': 'Tactic',
            'technique': 'Technique',
            'display_name': 'Display Name',
            'objective': 'Objective',
        }

        return mapping.get(header, header)

    return CommandResults(
        outputs_prefix='CrowdStrike.IncidentBehavior',
        outputs_key_field='behavior_id',
        outputs=results,
        readable_output=tableToMarkdown(
            name='CrowdStrike Incident Behavior',
            t=results,
            headers=['behavior_id', 'incident_ids', 'cid', 'aid', 'pattern_id', 'timestamp', 'cmdline', 'filepath',
                     'sha256', 'tactic', 'technique', 'display_name', 'objective'],
            headerTransform=table_headers_transformer,
            removeNull=True,
            sort_headers=False,
        ),
        raw_response=raw_response,
    )


def get_ioarules_command(args: dict) -> CommandResults:
    rule_ids = argToList(args['rule_ids'])
    ioarules_response_data = get_ioarules(rule_ids)

    ioarules = ioarules_response_data.get('resources', [])

    return CommandResults(
        outputs_prefix='CrowdStrike.IOARules',
        outputs_key_field='instance_id',
        outputs=ioarules,
        readable_output=tableToMarkdown(
            name='CrowdStrike IOA Rules',
            t=ioarules,
            headers=['instance_id', 'description', 'enabled', 'name', 'pattern_id'],
            headerTransform=string_to_table_header,
            removeNull=True,
            sort_headers=False,
        ),
        raw_response=ioarules_response_data,
    )


def main():
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            result = module_test()
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
            return_results(resolve_incident_command(ids=argToList(args.get('ids')),
                                                    status=args.get('status'),
                                                    user_uuid=args.get('assigned_to_uuid'),
                                                    user_name=args.get('username'),
                                                    add_comment=args.get('add_comment'),
                                                    add_tag=args.get('add_tag'),
                                                    remove_tag=args.get('remove_tag'),
                                                    ))
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
        # Mirroring commands
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
        # New commands
        elif command == 'cs-falcon-cspm-list-policy-details':
            return_results(cs_falcon_cspm_list_policy_details_command(args=args))
        elif command == 'cs-falcon-cspm-list-service-policy-settings':
            return_results(cs_falcon_cspm_list_service_policy_settings_command(args=args))
        elif command == 'cs-falcon-cspm-update-policy_settings':
            return_results(cs_falcon_cspm_update_policy_settings_command(args=args))
        elif command == 'cs-falcon-resolve-identity-detection':
            return_results(cs_falcon_resolve_identity_detection(args=args))
        elif command == 'cs-falcon-resolve-mobile-detection':
            return_results(cs_falcon_resolve_mobile_detection(args=args))
        elif command == 'cs-falcon-list-users':
            return_results(cs_falcon_list_users_command(args=args))
        elif command == 'cs-falcon-get-incident-behavior':
            return_results(get_incident_behavior_command(args=args))
        elif command == 'cs-falcon-get-ioarules':
            return_results(get_ioarules_command(args=args))
        else:
            raise NotImplementedError(f'CrowdStrike Falcon error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
