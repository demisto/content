"""
Symantec Endpoint Detection and Response (EDR) On-Prem integration with Symantec-EDR 4.6
"""
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import dateparser
import requests
from requests.auth import HTTPBasicAuth
from typing import Tuple, List, Dict, Callable
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DEFAULT_INTERVAL = 60
DEFAULT_TIMEOUT = 600
XSOAR_ISO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SYMANTEC_ISO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
INTEGRATION_CONTEXT_NAME = 'SymantecEDR'
TOKEN_ENDPOINT = '/atpapi/oauth2/tokens'
DEFAULT_PAGE = 0
DEFAULT_PAGE_SIZE = 50
PAGE_NUMBER_ERROR_MSG = 'Invalid Input Error: page number should be greater than zero. ' \
                        'Note: Page must be used along with page_size'
PAGE_SIZE_ERROR_MSG = 'Invalid Input Error: page size should be greater than zero. ' \
                      'Note: Page must be used along with page_size'
INVALID_CREDENTIALS_ERROR_MSG = 'Authorization Error: ' \
                                'The provided credentials for Symantec EDR on-premise are invalid. ' \
                                'Please provide a valid Client ID and Client Secret.'
INVALID_QUERY_ERROR_MSG = 'Invalid query arguments. Either use any optional filter in lieu of "query" ' \
                          'or explicitly use only "query" argument'
COMMAND_ACTION = ['isolate_endpoint', 'rejoin_endpoint', 'cancel_command', 'delete_endpoint_file']
SEARCH_QUERY_TYPE = ['domain', 'sha256', 'device_uid']
INCIDENT_SEVERITY = {
    1: 'Low',
    2: 'Medium',
    3: 'High'
}

INCIDENT_STATUS = {
    1: 'Open',
    2: 'Waiting',
    3: 'In-Progress',
    4: 'Close'
}

EVENT_SEVERITY = {
    'info': 1,
    'warning': 2,
    'minor': 3,
    'major': 4,
    'critical': 5,
    'fatal': 6
}

EVENT_STATUS = {
    'Unknown': 0,
    'Success': 1,
    'Failure': 2
}

SANDBOX_STATE = {
    0: 'Completed',
    1: 'In Progress',
    2: 'Error'
}


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """
    def __init__(self, base_url: str,
                 verify: bool,
                 proxy: bool,
                 client_id: str,
                 client_secret: str):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

        self.token_url = f'{base_url}{TOKEN_ENDPOINT}'
        self.client_key = client_id
        self.secret_key = client_secret

    def get_access_token(self):
        """
        Generate Access token
        Returns:
            Returns the access_token
        """
        payload = {
            "grant_type": 'client_credentials'
        }
        token_response = self._http_request(
            method='POST',
            full_url=self.token_url,
            auth=(self.client_key, self.secret_key),
            data=payload,
            error_handler=access_token_error_handler
        )
        token = token_response.get('access_token')
        return token

    def query_request_api(self, endpoint: str, params: dict, method: Optional[str] = 'POST') \
            -> Dict[str, str]:
        """
        Call Symantec EDR On-prem POST and GET Request API
        Args:
            endpoint (str): Symantec EDR on-premise endpoint
            params (dict): Request body data
            method (str): Request Method support POST and GET
        Returns:
            Return the raw api response from Symantec EDR on-premise API.
        """
        access_token = self.get_access_token()
        url_path = f'{self._base_url}{endpoint}'
        response = self._http_request(
            method=method,
            full_url=url_path,
            headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'},
            json_data=params if method == 'POST' else {},
            params=params if params and method == 'GET' else {},
            resp_type='response',
            allow_redirects=False,
            error_handler=http_request_error_handler
        )
        return response.json()

    def query_patch_api(self, endpoint: str, payload: dict) -> dict:
        """
        Call the PATCH api to add/modify or update to the endpoint
        Args:
            endpoint (str): Symantec EDR endpoint resources operation add, update, delete
            payload (str): Kwargs
        Returns:
            return response status code
        """

        result: Dict = {}
        access_token = self.get_access_token()
        url_path = f'{self._base_url}{endpoint}'

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        response = self._http_request(
            method="PATCH",
            headers=headers,
            data=payload,
            full_url=url_path,
            resp_type="response",
            return_empty_response=True
        )

        if response.status_code == 204:
            result['status'] = response.status_code
            result['message'] = 'Success'

        if response.status_code >= 400:
            error_message = f'{response.json().get("error")}, {response.json().get("message")}'
            raise DemistoException(error_message)

        return result


''' HELPER FUNCTIONS '''


def access_token_error_handler(response: requests.Response):
    """
    Error Handler for Symantec EDR on-premise access_token
    Args:
        response (response): Symantec EDR on-premise Token url response
    Raise:
         DemistoException
    """
    status_code = response.json().get('status')
    if status_code == 401:
        raise DemistoException(INVALID_CREDENTIALS_ERROR_MSG)
    elif status_code >= 400:
        raise DemistoException('Error: something went wrong, please try again.')


def http_request_error_handler(response: requests.Response):
    """
    Error Handler for Symantec EDR on-premise
    Args:
        response (response): Symantec EDR on-premise response
    Raise:
         DemistoException
    """
    if response.status_code >= 400:
        error_message = f'{response.json().get("error")}, {response.json().get("message")}'
        raise DemistoException(error_message)


def iso_creation_date(date: str):
    """
    Symantec EDR on-premise ISO 8601 date stamp format
    Args:
        date (str): ISO date example 2017-01-01T00:00:00.000Z or free text 2 days
    Returns:
        Return the ISO Date
    """
    iso_date = None
    if date:
        iso_date = dateparser.parse(date).strftime(SYMANTEC_ISO_DATE_FORMAT)[:23] + "Z"

    return iso_date


def get_data_of_current_page(offset: int, limit: int, data_list: List[Dict]):
    """
    Symantec EDR on-premise pagination
    Args:
        offset (int): Offset
        limit (int): Page Limit
        data_list (list[dict]): Raw API result list

    Returns:
        Return List of object from the response according to the limit, page and page_size.

    """
    # limit = limit if limit else DEFAULT_PAGE_SIZE
    if offset >= 0 and limit >= 0:
        return data_list[offset:(offset + limit)]
    return data_list[0:limit]


def pagination(page: Optional[int], page_size: Optional[int]):
    """
    Define pagination.
    Args:
        page: The page number.
        page_size: The number of requested results per page.
    Returns:
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    """
    if page is None:
        page = DEFAULT_PAGE
    elif page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    else:
        page = page - 1

    if page_size is None:
        page_size = DEFAULT_PAGE_SIZE
    elif page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    limit = page_size
    offset = page * page_size

    return limit, offset


def get_command_title_string(context_name: str, page: Optional[int], page_size: Optional[int],
                             total_record: Optional[int]) -> str:
    """
    Symantec EDR on-premise display title and pagination
    Args:
        context_name (str): Commands sub context name
        page (int): page Number
        page_size (int): Page Size
        total_record (int): Total Records return by API
    Returns:
        Return the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        return f'{context_name} List\nShowing page {page}\n' \
               f'Showing {page_size} out of {total_record} Record(s) Found.'

    return f"{context_name} List"


def process_sub_object(data: Dict) -> Dict:
    data_dict = dict()
    ignore_key_list = ['file', 'user']
    data_dict = extract_raw_data(data, ignore_key_list)
    return data_dict


def attacks_sub_object(data: Dict[str, Any]) -> Dict:
    ignore_key_list = ['tactic_ids', 'tactic_uids']
    attacks_dict = extract_raw_data(data, ignore_key_list, prefix='attacks')

    for attack in data:
        cnt = 0
        # tactic_ids
        tactic_ids_list = attack.get('tactic_ids', [])
        if tactic_ids_list:
            tactic_ids_dict = {
                f'attacks_tactic_ids_{cnt}': convert_list_to_str(tactic_ids_list)
            }
            attacks_dict = {**attacks_dict, **tactic_ids_dict}

        # tactic uids
        tactic_uids_list = attack.get('tactic_uids', [])
        if tactic_uids_list:
            tactic_uids_dict = {
                f'attacks_tactic_uids_{cnt}': convert_list_to_str(tactic_uids_list)
            }
            attacks_dict = {**attacks_dict, **tactic_uids_dict}
        cnt = cnt + 1
    return attacks_dict


def event_data_sub_object(data: Dict) -> Dict:
    ignore_key_list = []
    event_data_dict = {}

    sepm_server = data.get('sepm_server', {})
    search_config = data.get('search_config', {})
    atp_service = data.get('atp_service', {})

    if sepm_server:
        sepm_server_dict = extract_raw_data(sepm_server, ignore_key_list, 'event_data_sepm_server')
        event_data_dict = {**event_data_dict, **sepm_server_dict}

    if search_config:
        search_conf_dict = extract_raw_data(search_config, ignore_key_list, 'event_data_search_config')
        event_data_dict = {**event_data_dict, **search_conf_dict}

    if atp_service:
        atp_dict = extract_raw_data(atp_service, ignore_key_list, 'event_data_atp_service')
        event_data_dict = {**event_data_dict, **atp_dict}

    return event_data_dict


def enriched_data_sub_object(data: Dict[str, Any]) -> Dict:
    ignore_key_list = []
    enriched_dict = extract_raw_data(data, ignore_key_list, 'enriched_data')
    return enriched_dict


# def entity_sub_object(data: Dict[str, Any]) -> Dict:
#     entity_dict = dict()
#     return entity_dict
#
#
# def entity_result_sub_object(data: Dict[str, Any]) -> Dict:
#     return entity_sub_object(data)


def user_sub_object(data: Dict[str, Any], obj_prefix: str = None) -> Dict:
    user_dict = dict()
    ignore_key = []
    prefix = f'{obj_prefix}_user' if obj_prefix else f'user'
    user_dict = extract_raw_data(data, ignore_key, prefix)
    return user_dict


def xattributes_sub_object(data: Dict[str, Any], obj_prefix: str = None) -> Dict:
    xattributes_dict = dict()
    ignore_key = []
    prefix = f'{obj_prefix}_user' if obj_prefix else f'xattributes'
    xattributes_dict = extract_raw_data(data, ignore_key, prefix)
    return xattributes_dict


def event_actor_sub_object(data: Dict[str, Any]) -> Dict:
    event_actor_dict = dict()
    # Sub Object will be fetch separately
    ignore_key = ['file', 'user', 'xattributes']
    event_actor_dict = extract_raw_data(data, ignore_key, 'event_actor')

    # File Sub Object
    if data.get('file'):
        file_dict = file_sub_object(data.get('file'), 'event_actor')
        event_actor_dict = {**event_actor_dict, **file_dict}

    # User
    if data.get('user'):
        user_dict = user_sub_object(data.get('user'), 'event_actor')
        event_actor_dict = {**event_actor_dict, **user_dict}

    # xattributes
    if data.get('xattributes'):
        xattributes_dict = xattributes_sub_object(data.get('xattributes'), 'event_actor')
        event_actor_dict = {**event_actor_dict, **xattributes_dict}

    return event_actor_dict


def file_sub_object(data: Dict[str, Any], obj_prefix: str = None) -> Dict:
    file_dict = dict()
    ignore_key_list = ['signature_value_ids']
    prefix = f'{obj_prefix}_file' if obj_prefix else f'file'
    file_dict = extract_raw_data(data, ignore_key_list, prefix)
    return file_dict


def process_sub_object(data: Dict[str, Any]) -> Dict:
    # Process object also refer to event_actor
    return event_actor_sub_object(data)


def monitor_source_sub_object(data: Dict[str, Any]) -> Dict:
    monitor_dict = extract_raw_data(data, prefix='monitor_source')
    return monitor_dict


def connection_sub_object(data: Dict[str, Any]) -> Dict:
    con_dict = extract_raw_data(data, prefix='connection')
    return con_dict


def convert_list_to_str(data: list) -> str:
    seperator = ','
    value_str = ""
    if isinstance(data, list):
        value_str = seperator.join(map(str, data))

    return value_str


def event_object_data(data: Dict[str, Any]) -> Dict:
    """
    Retrieve event object data and return Event dict
    Args:
        data (dict): Event Object data
    Returns:
        event_dict: Event Json Data
    """
    event_dict = {}
    if not data:
        # Return empty dictionary
        return event_dict

    # Ignore to retrieve Sub Object which will be fetch based on command requirement
    ignore_list = [
        'attacks', 'av', 'bash', 'connection', 'data', 'directory', 'enriched_data', 'entity', 'entity_result',
        'event_actor', 'file', 'intrusion', 'kernel', 'link_following', 'receivers', 'process', 'reg_key', 'reg_value',
        'sandbox', 'scan', 'sender', 'service', 'session', 'monitor_source'
    ]
    event_dict = extract_raw_data(data, ignore_list)
    # Retrieve Sub Object Data
    # attacks
    attacks_data = data.get('attacks', [])
    if attacks_data:
        attacks_dict = attacks_sub_object(attacks_data)
        event_dict = {**event_dict, **attacks_dict}

    # event data
    event_data = data.get('data')
    if data.get('data'):
        event_data_dict = event_data_sub_object(data.get('data'))
        event_dict = {**event_dict, **event_data_dict}

    # Enriched Data
    enriched_data = data.get('enriched_data', {})
    if enriched_data:
        enriched_dict = enriched_data_sub_object(enriched_data)
        event_dict = {**event_dict, **enriched_dict}

    # Event_actor
    if data.get('event_actor'):
        event_actor_data = event_actor_sub_object(data.get('event_actor'))
        event_dict = {**event_dict, **event_actor_data}

    # monitor source
    monitor_source_data = data.get('monitor_source', {})
    if monitor_source_data:
        monitor_dict = monitor_source_sub_object(monitor_source_data)
        event_dict = {**event_dict, **monitor_dict}

    # Process
    process = data.get('process', {})
    if process:
        process_data = process_sub_object(process)
        event_dict = {**event_dict, **process_data}

    # connection {}
    connection = data.get('connection', {})
    if connection:
        connection_dict = connection_sub_object(connection)
        event_dict = {**event_dict, **connection_dict}

    # edr data protocols []
    edr_data_protocols = data.get('edr_data_protocols', [])
    if edr_data_protocols:
        edr_data_dict = {
            'edr_data_protocols': convert_list_to_str(edr_data_protocols)
        }
        event_dict = {**event_dict, **edr_data_dict}

    # edr files []
    edr_file = data.get('edr_files', [])
    if edr_file:
        edr_file_dict = {
            'edr_files': convert_list_to_str(edr_file)
        }
        event_dict = {**event_dict, **edr_file_dict}

    # source port []
    source_port_list = data.get('source_port', [])
    if source_port_list:
        source_port_dict = {
            'source_port': convert_list_to_str(source_port_list)
        }
        event_dict = {**event_dict, **source_port_dict}

    # target port []
    target_port_list = data.get('target_port', [])
    if target_port_list:
        target_port_dict = {
            'target_port': convert_list_to_str(target_port_list)
        }
        event_dict = {**event_dict, **target_port_dict}

    # av # TODO
    # bash # TODO
    # Entity => AuditEntityData TODO
    # directory , TODO
    # File TODO
    # Intrusion TODO
    # kernel TODO
    # link following TODO
    # Receivers TODO
    # reg_key TODO
    # reg_value TODO
    # sandbox TODO
    # scan TODO
    # sender TODO
    # service TODO
    # session TODO
    # threat TODO
    # Entity_result , Duplicate with Entity can be Ignored

    return event_dict


def domain_instance_readable_output(results: List[Dict], title: str) -> str:
    """
    Convert to XSOAR Readable output for entities Domains instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """
    disposition = {
        0: 'Healthy (0)',
        1: 'unknown (1)',
        2: 'Suspicious (2)',
        3: 'Bad (3)'
    }

    summary_data = []
    for data in results:
        disposition_val = arg_to_number(data.get('disposition'))

        new = {
            'data_source_url_domain': data.get('data_source_url_domain', ''),
            'first_seen': data.get('first_seen', ''),
            'last_seen': data.get('last_seen', ''),
            'external_ip': data.get('external_ip', ''),
            'disposition': disposition.get(disposition_val),
            'data_source_url': data.get('data_source_url', ''),
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    return markdown


def system_activity_readable_output(results: List[Dict], title: str):
    """
    Convert to User Readable output for System Activity resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
    """
    # Create Human readable data
    summary_data = []
    # Create the context Data
    context_data = []

    for data in results:
        event_data = event_object_data(data)
        # ------------- Symantec EDR Console logging System Activity -------
        new = {
            'time': event_data.get('device_time', ''),
            'type_id': event_data.get('type_id', ''),
            'severity_id': event_data.get('severity_id', ''),
            'message': event_data.get('message', ''),
            'device_ip': event_data.get('device_ip', ''),
            'atp_node_role': event_data.get('atp_node_role', '')
        }
        summary_data.append(new)
        context_data.append(event_data)

    row = summary_data[0] if summary_data else {}
    headers = list(row.keys())
    column_order = list(camelize_string(column) for column in headers)
    # , headers=headers,
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    return markdown, context_data


def endpoint_instance_readable_output(results: List[Dict], title: str) -> str:
    """
    Convert to XSOAR Readable output for entities endpoints instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """

    summary_data = []
    for data in results:
        ip_addresses = data.get("ip_addresses", [])
        new = {
            'device_uid': data.get('device_uid', ''),
            'device_name': data.get('device_name', ''),
            'device_ip': data.get('device_ip', ''),
            'domain_or_workgroup': data.get('domain_or_workgroup', ''),
            'time': data.get('time', ''),
            'ip_addresses': ip_addresses
         }
        summary_data.append(new)

    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(summary_data, "_"), headers=column_order,
                               removeNull=True)
    return markdown


def incident_readable_output(results: List[Dict], title: str):
    """
    Convert to User Readable output for Incident resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data : Formatting response data
    """
    summary_data = []
    for data in results:
        priority = arg_to_number(data.get('priority_level'))
        state = arg_to_number(data.get('state'))
        new = {
            # EDR CONSOLE Headers : ID , Description, incident Created, Detection Type, Last Updated,priority
            'incident_id': data.get('atp_incident_id', ''),
            'description': data.get('summary', ''),
            'incident_created': data.get('device_time', ''),
            'detection_type': data.get('detection_type', ''),
            'last_updated': data.get('updated', ''),
            'priority': INCIDENT_SEVERITY.get(priority),
            # ------------------
            'incident_state': INCIDENT_STATUS.get(state),
            'atp_rule_id': data.get('atp_rule_id'),
            'rule_name': data.get('rule_name'),
            'incident_uuid': data.get('uuid'),
            'log_name': data.get('log_name'),
            'recommended_action': data.get('recommended_action'),
            'summary': data.get('summary'),
            'resolution': data.get('resolution'),
            'first_seen': data.get('first_event_seen'),
            'last_seen': data.get('last_event_seen')
         }
        summary_data.append(new)
    summary_data_sorted = sorted(summary_data, key=lambda d: d['incident_id'], reverse=True)
    row = summary_data[0] if summary_data else {}
    headers = list(row.keys())
    column_order = list(camelize_string(column) for column in headers)
    # , headers=headers,
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=column_order, removeNull=True)
    return markdown


def audit_event_readable_output(results: List[Dict], title: str):
    """
    Convert to User Readable output for Audit Event
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data : Formatting response data
    """
    context_data = []
    summary_data = []
    for data in results:
        event_dict = event_object_data(data)
        # ---- Display Data ----
        new = {
            'time': event_dict.get('device_time', ''),
            'type_id': event_dict.get('type_id', ''),
            'feature_name': event_dict.get("feature_name", ''),
            'message': event_dict.get('message', ''),
            'user_agent_ip': event_dict.get('user_agent_ip', ''),
            'user_name': event_dict.get('user_name', ''),
            'severity': event_dict.get('severity_id', ''),
            'device_name': event_dict.get('device_name', ''),
            'device_ip': event_dict.get('device_ip', ''),
            'uuid': event_dict.get('uuid', ''),
        }
        summary_data.append(new)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d['time'], reverse=True)
    row = summary_data[0] if summary_data else {}
    headers = list(row.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=column_order, removeNull=True)
    return markdown, context_data


def incident_event_readable_output(results: List[Dict], title: str):
    """
    Convert to User Readable output for Event for Incident resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data : Formatting response data
    """
    context_data = []
    summary_data = []
    for data in results:
        event_dict = event_object_data(data)
        # ---- Display Data ----
        new = {
            'time': event_dict.get('device_time', ''),
            'type_id': event_dict.get('type_id', ''),
            'description': f'{event_dict.get("event_actor_file_name", "")} '
                           f'logged: {event_dict.get("enriched_data_rule_description", "")}',
            'device_name': event_dict.get('device_name', ''),
            'severity': event_dict.get('severity_id', ''),
            'device_ip': event_dict.get('device_ip', ''),
            'event_uuid': event_dict.get('event_uuid', ''),
            'incident': event_dict.get('incident', ''),
            'operation': event_dict.get('operation', ''),
            'device_domain': event_dict.get('device_domain', ''),
            'user_name': event_dict.get('user_name', ''),
        }
        summary_data.append(new)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d['time'], reverse=True)
    row = summary_data[0] if summary_data else {}
    headers = list(row.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=column_order, removeNull=True)
    return markdown, context_data


def incident_comment_readable_output(results: List[Dict], title: str, incident_id: str) -> str:
    """
    Convert to XSOAR Readable output for incident comment
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
        incident_id (str): Incident Id
    Returns:
        markdown : A string representation of the Markdown table
        summary_data : Formatted data set
    """

    summary_data = []
    for data in results:
        new = {
            'incident_id': incident_id,
            'comment': data.get('comment', ''),
            'time': data.get('time', ''),
            'user_id': data.get('user_id', ''),
            'incident_responder_name': data.get('incident_responder_name', ''),
         }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    # markdown = tableToMarkdown(title, summary_data, headers=headers,removeNull=True)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    return markdown, summary_data


def generic_readable_output(results_list: List[Dict], title: str) -> str:
    """
     Generic Readable output data for markdown
     Args:
         results_list (list): Generic Endpoint Response results data
         title (str): Title string
     Returns:
         A string representation of the Markdown table
     """
    readable_output = []
    for data in results_list:
        ignore_key_list = []
        prefix = ''
        row = extract_raw_data(data, ignore_key_list, prefix)
        readable_output.append(row)

    headers = readable_output[0] if readable_output else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(readable_output, "_"), headers=column_order,
                               removeNull=True)
    return markdown


def extract_raw_data(data: Dict, ignore_key: List = [], prefix: Optional[str] = None) -> Dict:
    """
     Retrieve Json data according and mapping field Name and value
     Args:
         data (Dict or list): Data ``dict`` or ``list``
         ignore_key (List): Ignore Key List
         prefix (str): Optional Added prefix in field name
     Returns:
         Return dict according to table field name and value
     """
    # ignore_key = ['event_actor', 'process', 'enriched_data']
    dataset: Dict = {}
    if isinstance(data, dict):
        for key, val in data.items():
            if key not in ignore_key:
                field_name = f'{prefix}_{key}' if prefix else f'{key}'
                dataset[field_name] = val

    if isinstance(data, list):
        cnt = 0
        for d in data:
            for key, val in d.items():
                if key not in ignore_key:
                    field_name = f'{prefix}_{key}_{cnt}' if prefix else f'{key}_{cnt}'
                    dataset[field_name] = val
            cnt = cnt + 1
    return dataset


def query_search_condition(q_type: str, q_value: str, ignore_validation=False) -> str:
    """
    This function make parameter query condition based on single or multiple  search values .
    Args:
        q_type (str): search query Type
        q_value (str): search query value
        ignore_validation (bool) : A boolean which ignore value Validation , Default false
    Returns:
        Return search condition.
    """
    condition = None
    if not q_type or not q_value:
        Demisto.debug('No search type and search value found. Return None')
        return condition

    list_value = argToList(q_value, ',')
    for value in list_value:
        if not ignore_validation:
            check_valid_indicator_value(q_type, value)
        condition = value if not condition else f'{condition} OR {value}'

    return condition


def get_incident_filter_query(args: Dict[str, Any]) -> str:
    """
    This function validate the incident filter search query and return the query condition
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    incident_status_dict = {'Open': 1, 'Waiting': 2, 'In-Progress': 3, 'Close': 4}
    incident_severity_dict = {'Low': 1, 'Medium': 2, 'High': 3}
    # Incident Parameters
    ids = arg_to_number(args.get('incident_id'))
    severity = incident_severity_dict.get(args.get('severity'))
    status = incident_status_dict.get(args.get('status'))
    query = args.get('query')

    if query and (ids or severity or status):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition = None
    if ids:
        condition = f'atp_incident_id: {ids}'

    if severity:
        condition = f'priority_level: {severity}' if not condition else f'{condition} AND priority_level: {severity}'

    if status:
        condition = f'state: {status}' if not condition else f'{condition} AND state: {status}'

    if query:
        condition = query

    return condition


def get_event_filter_query(args: Dict[str, Any]) -> str:
    """
    This function create the query for search condition as part of response body.
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    # Activity query Parameters
    event_type_id = arg_to_number(args.get('type_id'))
    severity = EVENT_SEVERITY.get(args.get('severity'))
    status = EVENT_STATUS.get(args.get('status'))
    query = args.get('query')

    if query and (event_type_id or severity or status):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition = None
    if event_type_id:
        condition = f'type_id: {event_type_id}'

    if severity:
        condition = f'severity_id: {severity}' if not condition else f'{condition} AND severity_id: {severity}'

    if status:
        condition = f'status_id: {status}' if not condition else f'{condition} AND status_id: {status}'

    if query:
        condition = query

    return condition


def get_association_filter_query(args: Dict) -> str:
    """
    This function validate the association filter search query and create the query search condition a
    payload based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    query_type = args.get('search_query')
    query_value = args.get('search_value')
    query = args.get('query')

    if query_type and query_type not in SEARCH_QUERY_TYPE:
        raise DemistoException(f'Invalid Search Type! Only supported type are : {SEARCH_QUERY_TYPE}')

    if query and (query_type or query_value):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    if query_type == 'sha256':
        condition = query_search_condition('sha256', query_value)
        query_condition = f'sha2: ({condition})'
    elif query_type == 'device_uid':
        condition = query_search_condition('device_uid', query_value, ignore_validation=True)
        query_condition = f'device_uid: ({condition})'
    elif query_type == 'domain':
        condition = query_search_condition('domain', query_value, ignore_validation=True)
        query_condition = f'data_source_url_domain: ({condition})'
    else:
        query_condition = query

    return query_condition


def post_request_body(args: Dict, p_limit: Optional[int] = 1) -> Dict:
    """
    This function creates a default payload based on the demisto.args().
    Args:
        args: demisto.args()
        p_limit: Page Limit (int)
    Returns:
        Return arguments dict.
    """
    # Default payload
    payload = {'verb': 'query'}

    max_limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE), arg_name='limit')
    if args.get('page_size') and p_limit > max_limit:
        # in case user pass the page_size or limit is less than page_size
        payload['limit'] = p_limit
    else:
        payload['limit'] = p_limit if p_limit != DEFAULT_PAGE_SIZE else max_limit

    from_time = iso_creation_date(args.get('start_time', None))
    to_time = iso_creation_date(args.get('end_time', None))

    if from_time:
        payload['start_time'] = from_time

    if to_time:
        payload['end_time'] = to_time

    return payload


def get_params_query(args: Dict, p_limit: Optional[int] = 0) -> Dict:
    """
    This function creates a query param based on the demisto.args().
    Args:
        args: demisto.args()
        p_limit: Page Limit (int)
    Returns:
        Return arguments dict.
    """
    query_param: Dict = {}
    ip = args.get('ip')
    url = args.get('url')
    md5 = args.get('md5')
    sha256 = args.get('sha256')

    # if ip := args.get('ip'):
    if ip:
        check_valid_indicator_value('ip', ip)

    # if url:
    #     check_valid_indicator_value('urls', url)

    if md5:
        check_valid_indicator_value('md5', md5)

    if sha256:
        check_valid_indicator_value('sha256', sha256)

    max_limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE), arg_name='limit')
    if args.get('page_size') and p_limit > max_limit:
        # in case user pass the page_size or limit is less than page_size
        query_param['limit'] = p_limit
    else:
        query_param['limit'] = p_limit if p_limit != DEFAULT_PAGE_SIZE else max_limit

    query_param['ip'] = ip
    query_param['url'] = url
    query_param['sha256'] = sha256
    # query_param['incident_trigger_sig_id'] = args.get('incident_trigger_sig_id') # Parameter is Deprecated
    query_param['id'] = arg_to_number(args.get('allowlist_id'), arg_name='allowlist_id')
    query_param['domain'] = args.get('domain')

    return query_param


def check_valid_indicator_value(indicator_type: str,indicator_value: str) -> bool:
    """
    Check the validity of indicator values
    Args:
        indicator_type: Indicator type provided in the command
            Possible Indicator type are : sha256, urls, domain, ip, md5
        indicator_value: Indicator value provided in the command
    Returns:
        True if the provided indicator values are valid
    """
    if indicator_type == 'sha256':
        if not re.match(sha256Regex, indicator_value):
            raise ValueError(f'SHA256 value"{indicator_value}" is invalid')

    if indicator_type == 'urls':
        if not re.match(urlRegex, indicator_value):
            raise ValueError(
                f'URL {indicator_value} is invalid')

    if indicator_type == 'ip':
        if not is_ip_valid(indicator_value):
            raise ValueError(f'IP "{indicator_value}" is invalid')

    if indicator_type == 'md5':
        if not re.match(md5Regex, indicator_value):
            raise ValueError(
                f'MD5 value {indicator_value} is invalid')

    return True


def get_incident_event_raw_response_data(endpoint: str, client: Client, args: Dict[str, Any], max_limit: int) -> dict:
    """
    Request to Get Incident Event response Json Data
    Args:
        endpoint : Endpoint API for request incident Events
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
        max_limit (int): Limit the maximum number of incident return
    Returns:
        Response raw result.
    """
    payload = post_request_body(args, max_limit)
    # search query as Lucene query string
    search_query = get_event_filter_query(args)
    if search_query:
        payload['query'] = search_query

    raw_response = client.query_request_api(endpoint, payload)
    return raw_response


def get_event_raw_response_data(endpoint: str, client: Client, args: Dict[str, Any], max_limit: int) -> dict:
    """
    Request to Get Event response Json Data
    Args:
        endpoint : Endpoint API for request incident Events
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
        max_limit (int): Limit the maximum number of incident return
    Returns:
        Response raw result.
    """
    payload = post_request_body(args, max_limit)
    # search query as Lucene query string
    search_query = get_event_filter_query(args)
    if search_query:
        payload['query'] = search_query
    raw_response = client.query_request_api(endpoint, payload)
    return raw_response


def get_incident_raw_response_data(endpoint: str, client: Client, args: Dict[str, Any], max_limit: int) -> dict:
    """
    Request to Get Incident response Json Data
    Args:
        endpoint : Endpoint API for request incident
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
        max_limit (int): Limit the maximum number of incident return
    Returns:
        Response raw result.
    """
    payload = post_request_body(args, max_limit)

    # search query as Lucene query string
    search_query = get_incident_filter_query(args)
    if search_query:
        payload['query'] = search_query

    raw_response = client.query_request_api(endpoint, payload)
    return raw_response


def get_incident_uuid(endpoint: str, client: Client, args: Dict[str, Any]) -> str:
    """
      Get the incident UUID
      Args:
          endpoint: API endpoint
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
              result.
    """
    # Get UUID based on incident_id
    incident_uuid = None
    data_list = get_incident_raw_response_data(endpoint, client, args, 1).get('result', [])
    if len(data_list) >= 1:
        incident_uuid = data_list[0].get('uuid')
    else:
        raise DemistoException(f'Incident ID Not Found {args.get("incident_id")}.'
                               f'Provide time range arguments if incidents is older then 30 days')

    return incident_uuid


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like
    it is supposed to and connection to the service is successful.
    Args:
        client(Client): Client class object
    Returns:
        Connection ok
    """
    message: str = ''
    endpoint = '/atpapi/v2/incidents'
    params: Dict = {
        'limit': 1
    }
    try:
        client.query_request_api(endpoint, params)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure Client ID and Client Secret are correctly set'
        else:
            raise e
    return message


def get_domain_file_association_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List of Domain and File association
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/associations/entities/domains-files'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)
    # search query as Lucene query string
    search_query = get_association_filter_query(args)
    if search_query:
        payload['query'] = search_query

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("Domain File Association",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = f'No Domain and File association data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DomainFileAssociation',
        outputs_key_field='',
        outputs=page_result
    )


def get_endpoint_domain_association_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    endpoint_domain_association_command: List of endpoint domain association
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/associations/entities/endpoints-domains'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)
    # search query as Lucene query string
    search_query = get_association_filter_query(args)
    if search_query:
        payload['query'] = search_query

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("Endpoint Domain Association",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = f'No Endpoint Domain association data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointDomainAssociation',
        outputs_key_field='',
        outputs=page_result
    )


def get_endpoint_file_association_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    endpoint_file_association_command: List of Endpoint File association
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/associations/entities/endpoints-files'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)
    # search query as Lucene query string
    search_query = get_association_filter_query(args)
    if search_query:
        payload['query'] = search_query

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("Endpoint File Association",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = f'No Endpoint File association data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointFileAssociation',
        outputs_key_field='',
        outputs=page_result
    )


def get_audit_event_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get Audit Event
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/auditevents'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    raw_response = get_event_raw_response_data(endpoint, client, args, page * page_limit)
    total_row = raw_response.get('total')

    title = get_command_title_string("Audit Event",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)
    context_data = None
    if page_result:
        readable_output, context_data = audit_event_readable_output(page_result, title)
    else:
        readable_output = f'No Event data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.AuditEvent',
        outputs_key_field='event_uuid',
        outputs=context_data,
        raw_response=raw_response
    )


def get_event_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get all events
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/events'
    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    raw_response = get_event_raw_response_data(endpoint, client, args, page * page_limit)
    total_row = raw_response.get('total')

    title = get_command_title_string("Event",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)
    context_data = None
    if page_result:
        readable_output, context_data = incident_event_readable_output(page_result, title)
    else:
        readable_output = f'No Event data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Event',
        outputs_key_field='event_uuid',
        outputs=context_data,
        raw_response=raw_response
    )


def get_event_for_incident_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    endpoint = '/atpapi/v2/incidentevents'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    raw_response = get_incident_event_raw_response_data(endpoint, client, args, page * page_limit)
    total_row = raw_response.get('total')

    title = get_command_title_string("Event for Incident",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)
    context_data = None
    if page_result:
        readable_output, context_data = incident_event_readable_output(page_result, title)
    else:
        readable_output = f'No Event for Incidents data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentEvent',
        outputs_key_field='event_uuid',
        outputs=context_data,
        raw_response=raw_response
    )


def get_incident_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    endpoint = '/atpapi/v2/incidents'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    raw_response = get_incident_raw_response_data(endpoint, client, args, page * page_limit)
    total_row = raw_response.get('total')

    title = get_command_title_string("Incident",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)
    if page_result:
        readable_output = incident_readable_output(page_result, title)
    else:
        readable_output = f'No Incidents data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Incident',
        outputs_key_field='apt_incident_id',
        outputs=page_result,
        raw_response=raw_response
    )


def get_incident_comments_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get all Incident Comments based on UUID
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    incident_id = args.get("incident_id")
    # Get UUID based on incident_id
    data_list = get_incident_raw_response_data('/atpapi/v2/incidents', client, args, 1).get('result', [])
    if len(data_list) >= 1:
        incident_uuid = data_list[0].get('uuid')
    else:
        raise DemistoException(f'Incident ID Not Found {incident_id}.'
                               f'Provide time range arguments if incidents is older then 30 days')

    endpoint = f'/atpapi/v2/incidents/{incident_uuid}/comments'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("Incident Comment",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)
    context_data = None
    if page_result:
        readable_output, context_data = incident_comment_readable_output(page_result, title, incident_id)
    else:
        readable_output = f'No Incident Comments data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentComment',
        outputs_key_field='',
        outputs=context_data
    )


def patch_incident_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
      Incident Update command is used to Add, close or update incident resolution
      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
              result.
    """
    incident_status_dict = {'Open': 1, 'Waiting': 2, 'In-Progress': 3, 'Close': 4}
    endpoint = f'/atpapi/v2/incidents'
    # Get UUID based on incident_id
    device_uuid = get_incident_uuid(endpoint, client, args)
    action = args.get('operation')
    action_list = []
    if action == 'add':
        action_desc = 'Add Comment'
        value = args.get('comment')
        if not value:
            raise ValueError(f'Invalid argument. Specifies the Incident comment!!')

        add_comment = {
                    'op': 'add',
                    'path': f'/{device_uuid}/comments',
                    'value': value
                }
        action_list.append(add_comment)
    elif action == 'close':
        action_desc = 'Close Incident'
        close_action = {
                    'op': 'replace',
                    'path': f'/{device_uuid}/state',
                    'value': 4
                }
        action_list.append(close_action)
    elif action == 'update':
        action_desc = 'Update Status'
        status = incident_status_dict.get(args.get('update_status'))
        close_action = {
                    'op': 'replace',
                    'path': f'/{device_uuid}/state',
                    'value': 4
                }
        action_list.append(close_action)
        update_state = {
                    'op': 'replace',
                    'path': f'/{device_uuid}/resolution',
                    'value': status
                }
        action_list.append(update_state)
    else:
        raise DemistoException(f'Invalid Action. Supported Incident action are "add, update, close"')

    response = client.query_patch_api(endpoint, json.dumps(action_list))

    title = f"Patch Incident {action_desc}"

    summary_data = {
        'incident_id': args.get('incident_id'),
        'status': response.get('status'),
        'Message': f'Successfully {action}ed' if action == 'add' else f'Successfully {action}d',
        'value': args.get('comment') if action == 'add' else args.get('update_status')
    }
    headers = list(summary_data.keys())
    return CommandResults(
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
    )


def get_file_instance_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get File Instance
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    sha256 = args.get('file_sha2')
    if sha256:
        check_valid_indicator_value('sha256', sha256)

    endpoint = \
        f'/atpapi/v2/entities/files/{args.get("file_sha2")}/instances' \
            if args.get('file_sha2') \
            else '/atpapi/v2/entities/files/instances'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("File Instances", arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = f'No File Instance data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.FileInstance',
        outputs_key_field='sha2',
        outputs=page_result,
        raw_response=raw_response
    )


def get_domain_instance_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get Domain Instance
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/entities/domains/instances'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("Domain Instances", arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        # readable_output = generic_readable_output(page_result, title)
        readable_output = domain_instance_readable_output(page_result, title)
    else:
        readable_output = f'No Domain Instances data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DomainInstances',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response
    )


def get_endpoint_instance_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get Endpoint Instance
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/entities/endpoints/instances'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)
    payload = post_request_body(args, page * page_limit)

    raw_response = client.query_request_api(endpoint, payload)
    total_row = raw_response.get('total')

    title = get_command_title_string("File Instances", arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = endpoint_instance_readable_output(page_result, title)
    else:
        readable_output = f'No Endpoint Instances data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointInstances',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response
    )


def get_allow_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
   Get Allow List Policies
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/policies/allow_list'
    limit = arg_to_number(args.get('limit'))

    if limit and (limit < 10 or limit > 1000):
        raise ValueError(f'Invalid input limit value: Value between Minimum = 10 , Maximum = 1000')

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    params = get_params_query(args, page * page_limit)
    raw_response = client.query_request_api(endpoint, params, 'GET')
    total_row = raw_response.get('total')

    title = get_command_title_string("Allow List Policy", arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = f'No Endpoint Instances data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.AllowListPolicy',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response
    )


def get_deny_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get deny List Policies
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/policies/deny_list'
    limit = arg_to_number(args.get('limit'))
    if limit and (limit < 10 or limit > 1000):
        raise ValueError(f'Invalid input limit value: Value between Minimum = 10 , Maximum = 1000')

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    params = get_params_query(args, page * page_limit)

    raw_response = client.query_request_api(endpoint, params, 'GET')
    total_row = raw_response.get('total')

    title = get_command_title_string("Deny List Policy", arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = f'No Endpoint Instances data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DenyListPolicy',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response
    )


def get_system_activity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get System Activity log events
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = '/atpapi/v2/systemactivities'

    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    raw_response = get_event_raw_response_data(endpoint, client, args, page * page_limit)
    total_row = raw_response.get('total')

    title = get_command_title_string("System Activities",
                                     arg_to_number(args.get('page', 0)), page_size, total_row)

    result = raw_response.get('result', [])
    page_result = get_data_of_current_page(offset, page_limit, result)
    context_data = None
    if page_result:
        readable_output, context_data = system_activity_readable_output(page_result, title)
    else:
        readable_output = f'No Endpoint Instances data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SystemActivity',
        outputs_key_field='uuid',
        outputs=context_data,
        raw_response=raw_response
    )


def get_endpoint_command(client: Client, args: Dict[str, Any], action: str) -> CommandResults:
    """
    Issue a Command Action to the SEDR On-Prem networks with following action:
        isolate - Isolates endpoint by cutting connections that the endpoint(s) has to internal networks and external
                  networks, based on the endpoint IDs
        rejoin  - Rejoins endpoints by re-establishing connections that the endpoint(s) has to internal networks
                  and external networks, based on the endpoint IDs
        delete-file - Deletes a file, i.e. deletes all instances of the file, based on the file hash that you have
                        specified from the endpoint using the Device ID
        cancel command - When you cancel a command that is already in progress, you cancel the command execution on all
                        the endpoints where it is still in progress. Only one command can be cancelled at a time
                        to the infecting devices.
    Args:
        client: client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
        action : isolate | rejoin | delete-file | cancel

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = "/atpapi/v2/commands"
    action_type = action
    device_uid = args.get('device_id')
    file_sha2 = args.get('sha2')
    command_id = args.get('command_id')

    # if action_type not in COMMAND_ACTION:
    #     raise ValueError(f'Invalid Input Error: supported values for action : {COMMAND_ACTION}')

    if action_type == 'delete_endpoint_file':
        if not device_uid or not file_sha2:
            raise DemistoException(f'Invalid Arguments. Both arguments "device_id" and file "sha2" require '
                                   f'for delete the endpoint file')
        payload = {
            'action': action_type,
            'targets': argToList({'device_uid': device_uid, 'hash': file_sha2})
        }
    elif action_type == 'cancel_command':
        payload = {'action': action_type, 'targets': argToList(command_id)}
    else:
        payload = {'action': action_type, 'targets': argToList(device_uid)}

    raw_response = client.query_request_api(endpoint, payload)
    title = f'Command {action_type}'

    summary_data = {
            "Message": raw_response.get('message'),
            "Command ID": raw_response.get('command_id'),
            "Error Code": raw_response.get('error_code')
        }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Command.{action_type}',
        outputs_key_field='command_id',
        outputs=raw_response,
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
    )


def get_endpoint_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Check the command status of isolate endpoint.
    Args:
        client: client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    command_id = args.get('command_id')
    endpoint = f'/atpapi/v2/commands/{command_id}'

    params = post_request_body(args)
    # raw_response = client.query_get_request_api(endpoint, params)
    raw_response = client.query_request_api(endpoint, params)
    total_row = raw_response.get('total')

    title = "Command Status"
    summary_data = {
            "state": raw_response.get('state'),
            "Command Issuer Name": raw_response.get('command_issuer_name'),
            "Next": raw_response.get('next'),
            "Total": raw_response.get('total')
        }

    # headers = list(summary_data.keys())
    result = raw_response.get('status', [])
    if len(result) >= 1:
        for status in result:
            summary_data['target'] = status.get('target')
            summary_data['target_state'] = status.get('state')
            summary_data['message'] = status.get('message')
            summary_data['error_code'] = status.get('error_code')

    if summary_data:
        readable_output = generic_readable_output(argToList(summary_data), title)
        # readable_output = endpoint_instance_readable_output(page_result, title)
    else:
        readable_output = f'No command status data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.CommandStatus',
        outputs_key_field='',
        outputs=summary_data
    )


def get_file_sandbox_verdict_polling_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     Get file Sandbox Verdict of specific SHA2
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """
    sha2 = args.get('file')
    endpoint = f'/atpapi/v2/sandbox/results/{sha2}/verdict'

    response_data = client.query_request_api(endpoint, {}, 'GET')
    # Sandbox verdict
    # datasets = response_data.get("status", [])
    title = "Sandbox Verdict"
    if response_data:
        readable_output = generic_readable_output(argToList(response_data), title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxVerdict',
        outputs_key_field='',
        outputs=response_data
    )


def get_file_sandbox_status_polling_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     Query file Sandbox command status,
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
    """
    command_id = args.get('command_id')
    endpoint = f'/atpapi/v2/sandbox/commands/{command_id}'

    response_data = client.query_request_api(endpoint, {}, 'GET')
    # Query Sandbox Command Status
    datasets = response_data.get("status", [])
    summary_data = {}
    if datasets:
        for data in datasets:
            new = {
                'command_id': command_id,
                'status': data.get('state'),
                'message': data.get('message'),
                'target': data.get('target'),
                'error_code': data.get('error_code')
            }
            summary_data = {**summary_data, **new}

    title = "Query File Sandbox Status"
    if datasets:
        readable_output = generic_readable_output(datasets, title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxStatus',
        outputs_key_field='',
        outputs=summary_data
    )


def get_file_sandbox_issue_polling_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     Issue File Sandbox command,
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
     """

    file_hash = args.get('file')
    if not re.match(sha256Regex, file_hash):
        raise ValueError(f'SHA256 value {file_hash} is invalid')

    # or (not re.match(md5Regex, file_hash))

    endpoint = '/atpapi/v2/sandbox/commands'
    payload = {
        'action': 'analyze',
        'targets': argToList(file_hash)
    }
    response_data = client.query_request_api(endpoint, payload)
    # Get Issue Sandbox Command
    title = "Issue Sandbox Command"
    summary_data = {
        'file_sha2': file_hash,
        'command_id': response_data.get('command_id'),
        'command_type': 'Issue Sandbox Command'
    }
    headers = list(summary_data.keys())
    column_order = list(camelize_string(column) for column in headers)
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxIssue',
        outputs_key_field='',
        outputs=summary_data,
        readable_output=tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    )


''' POLLING CODE '''


@polling_function(name='file',
                  interval=arg_to_number(demisto.args().get('interval_in_seconds', DEFAULT_INTERVAL)),
                  timeout=arg_to_number(demisto.args().get('timeout_in_seconds', DEFAULT_TIMEOUT)),
                  requires_polling_arg=False
                  )
def file_polling_command(args: Dict[str, Any], client: Client) -> PollResult:
    """
    Polling command to display the progress of the sandbox issue command.
    After the first run, progress will be shown through the status command.
    Once a file scanning is done check the status as 'Completed' and return the file verdict
    Status command will run till its status is not 'Completed'
    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request and a Client.
        client: client object to use.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    first_run = 'command_id' not in args
    if first_run:
        command_results = get_file_sandbox_issue_polling_command(client, args)
        outputs = command_results.outputs
        command_id = outputs.get('command_id')
        if command_id:
            args['command_id'] = command_id

    command_result = get_file_sandbox_status_polling_command(client, args)
    outputs = command_result.outputs
    if outputs:
        status = arg_to_number(outputs.get('status'))
        if SANDBOX_STATE.get(status) == 'Completed':
            command_result = get_file_sandbox_verdict_polling_command(client, args)
            return PollResult(response=command_result, continue_to_poll=False)

    polling_args = {**args}
    return PollResult(response=command_result, continue_to_poll=True, args_for_next_run=polling_args)


def run_polling_command(client: Client, args: dict, cmd: str, status_func: Callable, results_func: Callable):
    """
    This function is generically handling the polling flow.
    After the first run, progress will be shown through the status command.
    The run_polling_command function runs the Status command will run till its status is  not 'Completed'
    and returns a ScheduledCommand object that schedules
    the next 'results' function, until the polling is complete.
    Args:
        args: the arguments required to the command being called, under cmd
        cmd: the command to schedule by after the current command
        status_func :
        results_func: the function that retrieves the status of the previously initiated upload process
        client: a Microsoft Client object

    Returns:

    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 90))
    timeout_in_seconds = int(args.get('timeout_in_seconds', 600))
    # distinguish between the initial run, which is the Issue the file for scan, and the results run
    is_first_run = 'command_id' not in args
    if is_first_run:
        command_results = get_file_sandbox_issue_polling_command(client, args)
        outputs = command_results.outputs
        command_id = outputs.get('command_id')
        if command_id is not None:
            args['command_id'] = command_id

        # schedule next poll
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args,
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=timeout_in_seconds)
        command_results.scheduled_command = scheduled_command
        return command_results

    # not a first run
    command_result = status_func(client, args)
    outputs = command_result.outputs
    status = arg_to_number(outputs.get('status'))
    status_type = SANDBOX_STATE.get(status)

    # 0 = Completed
    if status_type != 'Completed':
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args,
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=timeout_in_seconds
        )

        # result with scheduled_command only - no update to the war room
        command_result = CommandResults(scheduled_command=scheduled_command)
        return command_result
    # # action was completed
    elif status_type == 'Complete':
        return results_func(client, args)


def file_scheduled_polling_command(client, args):
    return run_polling_command(client, args, 'file', get_file_sandbox_status_polling_command,
                               get_file_sandbox_verdict_polling_command)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        params = demisto.params()
        server = params.get('url', '')
        credentials = params.get('credentials', {})
        username = credentials.get('identifier', '')
        password = credentials.get('password', '')
        verify_certificate = params.get('insecure', False)
        # not params.get('insecure', False)
        proxy = params.get('proxy', False)
        command = demisto.command()

        client = Client(
            base_url=server,
            verify=verify_certificate,
            proxy=proxy,
            client_id=username,
            client_secret=password
        )

        args = demisto.args()

        demisto.debug(f'Command being called is {demisto.command()}')

        commands = {
            # Command Status
            "symantec-edr-endpoint-status": get_endpoint_status_command,

            # Domain File Associations
            "symantec-edr-domain-file-association-list": get_domain_file_association_list_command,

            # Endpoint Domain Associations
            "symantec-edr-endpoint-domain-association-list": get_endpoint_domain_association_list_command,

            # Endpoint File Associations
            "symantec-edr-endpoint-file-association-list": get_endpoint_file_association_list_command,

            # Get Incidents
            "symantec-edr-incident-list": get_incident_list_command,

            # Events For Incidents
            "symantec-edr-incident-event-list": get_event_for_incident_list_command,

            # Get Incident Comments
            "symantec-edr-incident-comment-get": get_incident_comments_command,

            # Patch Incidents Command to (Close Incidents, Update Resolution or Add Comments)
            "symantec-edr-incident-update": patch_incident_update_command,

            # System Activities
            "symantec-edr-system-activity-list": get_system_activity_command,

            # Audit Events
            "symantec-edr-audit-event-get": get_audit_event_command,

            # Allow List Policies
            "symantec-edr-allow-list-policy-get": get_allow_list_command,

            # Deny List Policies
            "symantec-edr-deny-list-policy-get": get_deny_list_command,

            # Domain Instances
            "symantec-edr-domain-instance-get": get_domain_instance_command,

            # Endpoint Instances
            "symantec-edr-endpoint-instance-get": get_endpoint_instance_command,

            # File Instances
            "symantec-edr-file-instance-get": get_file_instance_command,

            # Events
            "symantec-edr-event-list": get_event_list_command,

        }
        if command == "test-module":
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            return_results('ok')
        elif command == "symantec-edr-endpoint-isolate":
            return_results(get_endpoint_command(client, args, 'isolate_endpoint'))
        elif command == "symantec-edr-endpoint-rejoin":
            return_results(get_endpoint_command(client, args, 'rejoin_endpoint'))
        elif command == "symantec-edr-endpoint-delete-file":
            return_results(get_endpoint_command(client, args, 'delete_endpoint_file'))
        elif command == "symantec-edr-endpoint-cancel":
            return_results(get_endpoint_command(client, args, 'cancel_command'))
        elif command in ['file']:
            # File Sandbox Analysis, Command Status, and Verdict
            return_results(file_polling_command(args, client))
            # return_results(file_scheduled_polling_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


