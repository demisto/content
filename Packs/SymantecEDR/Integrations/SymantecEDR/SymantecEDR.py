"""
Symantec Endpoint Detection and Response (EDR) On-Prem integration with Symantec-EDR 4.6
"""
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa
import dateparser
import requests
import urllib3
from typing import Callable

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DEFAULT_INTERVAL = 10
DEFAULT_TIMEOUT = 600
# Symantec TOKEN timeout 3600 Second , or 60 mins
SESSION_TIMEOUT_SEC = 3480
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
INCIDENT_PATCH_ACTION = ['add_comment', 'close_incident', 'update_resolution']
SEARCH_QUERY_TYPE = ['domain', 'sha256', 'device_uid']
INCIDENT_PRIORITY_LEVEL: dict[str, str] = {
    '1': 'Low',
    '2': 'Medium',
    '3': 'High'
}

INCIDENT_STATUS: dict[str, str] = {
    '1': 'Open',
    '2': 'Waiting',
    '3': 'In-Progress',
    '4': 'Closed'
}

INCIDENT_RESOLUTION: dict[str, str] = {
    '0': 'INSUFFICIENT_DATA. The incident does not have sufficient information to make a determination.',
    '1': 'SECURITY_RISK. The incident indicates a true security threat.',
    '2': 'FALSE_POSITIVE. The incident has been incorrectly reported as a security threat.',
    '3': 'MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there.',
    '4': 'NOT_SET. The incident resolution was not set.',
    '5': 'BENIGN. The incident detected the activity as expected but is not a security threat.',
    '6': 'TEST. The incident was generated due to internal security testing.'
}

EVENT_SEVERITY: dict[str, str] = {
    '1': 'Info',
    '2': 'Warning',
    '3': 'Minor',
    '4': 'Major',
    '5': 'Critical',
    '6': 'Fatal'
}

# Status for Applicable events : 1, 20, 21, 1000
EVENT_STATUS: dict[str, str] = {
    '0': 'Unknown',
    '1': 'Success',
    '2': 'Failure'
}

EVENT_ATPNODE_ROLE: dict[str, str] = {
    '0': 'Pre-Bootstrap',
    '1': 'Network Scanner',
    '2': 'Management',
    '3': 'StandaloneNetwork',
    '4': 'Standalone Endpoint',
    '5': 'All in One'
}

SANDBOX_STATE: dict[str, str] = {
    '0': 'Completed',
    '1': 'In Progress',
    '2': 'Unknown'
}

DOMAIN_DISPOSITION_STATUS: dict[str, str] = {
    '0': 'Healthy',
    '1': 'unknown',
    '2': 'Suspicious',
    '3': 'Bad'
}

HTTP_ERRORS = {
    400: '400 Bad Request - Incorrect or invalid parameters',
    401: '401 Authentication error - Incorrect or invalid username or password',
    403: '403 Forbidden - please provide valid username and password.',
    404: '404 Resource not found - invalid endpoint was called.',
    408: '408 Timeout - Check Server URl/Port',
    410: '410 Gone - Access to the target resource is no longer available at the origin server',
    500: '500 Internal Server Error - please try again after some time.',
    502: '502 Bad Gateway - Could not connect to the origin server',
    503: '503 Service Unavailable'
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
    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str,
                 first_fetch: str = '3 days', fetch_limit: int = 50, is_incident_event: bool = False,
                 is_fetch_comment: bool = False, fetch_status: list = None, fetch_priority: list = None):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

        self.token_url = f'{base_url}{TOKEN_ENDPOINT}'
        self.client_key = client_id
        self.secret_key = client_secret
        self.first_fetch = first_fetch
        self.fetch_limit = fetch_limit
        self.is_incident_event = is_incident_event
        self.is_fetch_comment = is_fetch_comment
        self.fetch_status = fetch_status
        self.fetch_priority = fetch_priority
        self.sid = None

    def get_access_token(self):
        """
        Generate Access token
        Returns:
            Returns the access_token
        """
        payload = {
            "grant_type": 'client_credentials'
        }
        response = None
        if last_sid := self.get_sid_from_context():
            demisto.debug(f"Last login sid still alive. Return last sid {last_sid}")
            return last_sid
        else:
            try:
                response = self._http_request(
                    method='POST',
                    full_url=self.token_url,
                    auth=(self.client_key, self.secret_key),
                    data=payload,
                    error_handler=handle_errors
                )
                sid = response.get('access_token', '')
                self.sid = sid
                timestamp_string = int(time.time() * 1000)
                demisto.debug(f"login: success, saving sid={sid} , sid_last_datetime={timestamp_string} to integrationContext")
                demisto.setIntegrationContext({'sedr_sid': sid, 'sedr_last_sid_datatime': timestamp_string})
                return sid
            except Exception as e:
                msg = f'Something went wrong with request, {e}'
                demisto.debug(msg)
                raise DemistoException(msg, res=requests.Response)

    def get_sid_from_context(self):
        if sid := demisto.getIntegrationContext().get('sedr_sid', None):
            last_datetime = demisto.getIntegrationContext().get('sedr_last_sid_datatime', None)
            now_datetime = int(time.time() * 1000)  # Convert to Millisecond
            time_diff = int(now_datetime - last_datetime)
            demisto.debug(f"Check Last Sid: {sid}, time_diff: {time_diff}.")
            return sid if time_diff <= SESSION_TIMEOUT_SEC * 1000 else None

        demisto.debug("No last SID found in Context.")
        return None

    def query_request_api(self, endpoint: str, params: dict, method: str | None = 'POST') \
            -> dict[str, str]:
        """
        Call Symantec EDR On-prem POST and GET Request API
        Args:
            endpoint (str): Symantec EDR on-premise endpoint
            params (dict): Request body data (payload)
            method (str): Request Method support POST and GET
        Returns:
            Return the raw api response from Symantec EDR on-premise API.
        """
        access_token = self.get_access_token()
        url_path = f'{self._base_url}{endpoint}'
        try:
            response = self._http_request(
                method=method,
                full_url=url_path,
                headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'},
                json_data=params if method == 'POST' else {},
                params=params if method == 'GET' else {},
                resp_type='response',
                allow_redirects=False
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            if HTTP_ERRORS.get(err.response.status_code) is not None:
                # if it is a known http error - get the message form the preset messages
                err_response = f'Failed to execute. {response.json().get("error")},{response.json().get("message")}'
                msg = f'{HTTP_ERRORS.get(err.response.status_code)}.\n{err_response}'
                raise DemistoException(msg, res=response)
            else:
                # if it is unknown error - get the message from the error itself
                return_error(f'Failed to execute. Error: {str(err)}')
        except Exception as e:
            return_error(f'Failed to execute. Error: {str(e)}')

        return response.json()

    def query_patch_api(self, endpoint: str, payload: list) -> dict:
        """
        Call the PATCH api to add/modify or update to the endpoint
        Args:
            endpoint (str): Symantec EDR endpoint resources operation add, update, delete
            payload (List): request body
        Returns:
            return response status code
        """

        result: dict = {}
        access_token = self.get_access_token()
        url_path = f'{self._base_url}{endpoint}'

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        response = self._http_request(
            method="PATCH",
            headers=headers,
            data=json.dumps(payload),
            full_url=url_path,
            resp_type="response",
            return_empty_response=True,
        )

        if response.status_code == 204:
            result['status'] = response.status_code
            result['message'] = 'Success'

        if response.status_code >= 400:
            error_message = f'{response.json().get("error")}, {response.json().get("message")}'
            raise DemistoException(error_message, res=response)

        return result


''' HELPER FUNCTIONS '''


def handle_errors(response: requests.Response) -> None:
    """Handle http errors."""
    status = response.status_code
    if status in HTTP_ERRORS:
        raise DemistoException(f'{HTTP_ERRORS[status]}, {response.json().get("error_description")}', res=response)
    else:
        response.raise_for_status()


def http_request_error_handler(response: requests.Response):
    """
    Error Handler for Symantec EDR on-premise
    Args:
        response (response): Symantec EDR on-premise response
    Raise:
         DemistoException
    """
    if response.status_code >= 400:
        error_message = f'{response.json().get("error")},{response.json().get("message")}'
        raise DemistoException(error_message, res=response)


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
        iso_date = dateparser.parse(date).strftime(SYMANTEC_ISO_DATE_FORMAT)[:23] + "Z"  # type: ignore

    return iso_date


def get_data_of_current_page(offset: int, limit: int, data_list: list[dict[str, Any]]):
    """
    Symantec EDR on-premise pagination
    Args:
        offset (int): Offset
        limit (int): Page Limit
        data_list (list): Raw API result list

    Returns:
        Return List of object from the response according to the limit, page and page_size.

    """
    # limit = limit if limit else DEFAULT_PAGE_SIZE
    if offset >= 0 and limit >= 0:
        return data_list[offset:(offset + limit)]
    return data_list[0:limit]


def pagination(page: int | None, page_size: int | None):
    """
    Define pagination.
    Args:
        # page: The page number.
        # page_size: The number of requested results per page.
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


def get_command_title_string(context_name: str, page: int | None, page_size: int | None,
                             total_record: int | None) -> str:
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


def parse_process_sub_object(data: dict) -> dict:
    ignore_key_list: list[str] = ['file', 'user']
    return extract_raw_data(data, ignore_key_list)


def parse_attacks_sub_object(data: list[dict]) -> dict:
    ignore_key_list: list[str] = ['tactic_ids', 'tactic_uids']
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


def parse_event_data_sub_object(data: dict[str, Any]) -> dict:
    result: dict = {}
    for key, func in (
        ('event_data_sepm_server', extract_raw_data),
        ('event_data_search_config', extract_raw_data),
        ('event_data_atp_service', extract_raw_data),
    ):
        if values := data.get(key):
            result |= func(values, [], key)
    return result


def parse_enriched_data_sub_object(data: dict[str, Any]) -> dict:
    return extract_raw_data(data, [], 'enriched_data')


def parse_user_sub_object(data: dict[str, Any], obj_prefix: str | None = None) -> dict:
    prefix = f'{obj_prefix}_user' if obj_prefix else 'user'
    return extract_raw_data(data, [], prefix)


def parse_xattributes_sub_object(data: dict[str, Any], obj_prefix: str | None = None) -> dict:
    prefix = f'{obj_prefix}_xattributes' if obj_prefix else 'xattributes'
    return extract_raw_data(data, [], prefix)


def parse_event_actor_sub_object(data: dict[str, Any]) -> dict:

    # Sub Object will be fetched separately
    ignore_key: list[str] = ['file', 'user', 'xattributes']

    result = extract_raw_data(data, ignore_key, 'event_actor')

    for key, func in (
        ('file', parse_file_sub_object),
        ('user', parse_user_sub_object),
        ('xattributes', parse_xattributes_sub_object),
    ):
        if values := data.get(key):
            result |= func(values, key)
    return result


def parse_file_sub_object(data: dict[str, Any], obj_prefix: str | None = None) -> dict:
    prefix = f'{obj_prefix}_file' if obj_prefix else 'file'
    return extract_raw_data(data, ['signature_value_ids'], prefix)


def parse_monitor_source_sub_object(data: dict[str, Any]) -> dict:
    return extract_raw_data(data, [], prefix='monitor_source')


def parse_connection_sub_object(data: dict[str, Any]) -> dict:
    return extract_raw_data(data, [], prefix='connection')


def convert_list_to_str(data: list) -> str:
    seperator = ','
    return seperator.join(map(str, data)) if isinstance(data, list) else None


def parse_event_object_data(data: dict[str, Any]) -> dict:
    """
    Retrieve event object data and return Event dict
    Args:
        data (dict): Event Object data
    Returns:
        event_dict: Event Json Data
    """
    # event_dict: dict[str, Any] = {}
    if not data:
        # Return empty dictionary
        return {}

    # Ignore to retrieve Sub Object which will be fetched subsequently based on command requirement
    ignore_list = [
        'attacks', 'av', 'bash', 'connection', 'data', 'directory', 'enriched_data', 'entity', 'entity_result',
        'event_actor', 'file', 'intrusion', 'kernel', 'link_following', 'receivers', 'process', 'reg_key', 'reg_value',
        'sandbox', 'scan', 'sender', 'service', 'session', 'monitor_source'
    ]
    # event_dict = extract_raw_data(data, ignore_list)
    result = extract_raw_data(data, ignore_list)

    for key, func in (
        ('attacks', parse_attacks_sub_object),
        ('data', parse_event_data_sub_object),
        ('enriched_data', parse_enriched_data_sub_object),
        ('event_actor', parse_event_actor_sub_object),
        ('monitor_source', parse_monitor_source_sub_object),
        ('process', parse_process_sub_object),
        ('connection', parse_connection_sub_object),
        ('edr_data_protocols', convert_list_to_str),
    ):
        if values := data.get(key):
            result |= func(values)

    for item in ['edr_data_protocols', 'edr_files', 'source_port', 'target_port']:
        if values := data.get(item):
            result |= {f'{item}': values}

    # All these below event sub objects left from this implementation,
    # Only can be implemented if required for future enhancement

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

    return result


def domain_instance_readable_output(results: list[dict], title: str):
    """
    Convert to XSOAR Readable output for entities Domains instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """
    summary_data = []
    for data in results:
        disposition_val = data.get('disposition', '')
        new = {
            'data_source_url_domain': data.get('data_source_url_domain', ''),
            'first_seen': data.get('first_seen', ''),
            'last_seen': data.get('last_seen', ''),
            'external_ip': data.get('external_ip', ''),
            'disposition': DOMAIN_DISPOSITION_STATUS.get(str(disposition_val), ''),
            'data_source_url': data.get('data_source_url', '')
        }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    return markdown, summary_data


def system_activity_readable_output(results: list[dict], title: str):
    """
    Convert to User Readable output for System Activity resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
    """
    # Applicable events : 1, 20, 21, 1000
    # Human readable output
    summary_data = []
    # Context dat
    context_data = []

    for data in results:
        event_data = parse_event_object_data(data)
        event_data['severity_id'] = EVENT_SEVERITY.get(str(event_data.get('severity_id')))
        event_data['atp_node_role'] = EVENT_ATPNODE_ROLE.get(str(event_data.get('atp_node_role')))
        event_data['status_id'] = EVENT_STATUS.get(str(event_data.get('status_id')))
        # ------------- Symantec EDR Console logging System Activity -------
        new = {
            'time': event_data.get('device_time', ''),
            'type_id': event_data.get('type_id', ''),
            'severity_id': event_data.get('severity_id', ''),
            'message': event_data.get('message', ''),
            'device_ip': event_data.get('device_ip', ''),
            'atp_node_role': event_data.get('atp_node_role', ''),
            'status_id': event_data.get('status_id', '')
        }
        summary_data.append(new)
        context_data.append(event_data)

    row = summary_data[0] if summary_data else {}
    headers = list(row.keys())
    column_order = list(camelize_string(column) for column in headers)
    # , headers=headers,
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    return markdown, context_data


def endpoint_instance_readable_output(results: list[dict], title: str) -> str:
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


def incident_readable_output(results: list[dict], title: Optional[str] = None):
    """
    Convert to User Readable output for Incident resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data : Formatting response data
    """
    summary_data: list[dict[str, Any]] = []
    for data in results:
        priority = data.get('priority_level', '')
        state = data.get('state', '')
        resolution = data.get('resolution', '')
        new = {
            # EDR CONSOLE Headers : ID , Description, incident Created, Detection Type, Last Updated,priority
            'incident_id': data.get('atp_incident_id', ''),
            'description': data.get('summary', ''),
            'incident_created': data.get('device_time', ''),
            'detection_type': data.get('detection_type', ''),
            'last_updated': data.get('updated', ''),
            'priority': INCIDENT_PRIORITY_LEVEL.get(str(priority), ''),
            # ------------------
            'incident_state': INCIDENT_STATUS.get(str(state), ''),
            'atp_rule_id': data.get('atp_rule_id'),
            'rule_name': data.get('rule_name'),
            'incident_uuid': data.get('uuid'),
            'log_name': data.get('log_name'),
            'recommended_action': data.get('recommended_action'),
            # 'summary': data.get('summary'),
            'resolution': INCIDENT_RESOLUTION.get(str(resolution), ''),
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
    return markdown, summary_data


def audit_event_readable_output(results: list[dict], title: str):
    """
    Convert to User Readable output for Audit Event
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data : Formatting response data
    """
    context_data: list[dict[str, Any]] = []
    summary_data: list[dict[str, Any]] = []
    for data in results:
        event_dict = parse_event_object_data(data)
        event_dict['severity_id'] = EVENT_SEVERITY.get(str(event_dict.get('severity_id')))
        event_dict['status_id'] = EVENT_STATUS.get(str(event_dict.get('status_id')))
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
            'status_id': event_dict.get('status_id', '')
        }
        summary_data.append(new)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d['time'], reverse=True)
    row = summary_data[0] if summary_data else {}
    headers = list(row.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=column_order, removeNull=True)
    return markdown, context_data


def incident_event_readable_output(results: list[dict], title: Optional[str] = None):
    """
    Convert to User Readable output for Event for Incident resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table and context Data
        summary_data : Formatting response data
    """
    context_data: list[dict[str, Any]] = []
    summary_data: list[dict[str, Any]] = []
    for data in results:
        event_dict = parse_event_object_data(data)
        severity_id = event_dict.get('severity_id', '')
        event_dict['severity_id'] = EVENT_SEVERITY.get(str(severity_id), '')
        # ---- Display Data ----
        new = {
            'time': event_dict.get('device_time', ''),
            'type_id': event_dict.get('type_id', ''),
            'description': f'{event_dict.get("event_actor_file_name", "")} '
                           f'logged: {event_dict.get("enriched_data_rule_description", "")}',
            'device_name': event_dict.get('device_name', ''),
            'severity_id': event_dict.get('severity_id'),
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


def incident_comment_readable_output(results: list[dict], title: str, incident_id: str):
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

    summary_data: list[dict[str, Any]] = []
    for data in results:
        new = {
            'incident_id': incident_id,
            'comment': data.get('comment', ''),
            'time': data.get('time', ''),
            'user_id': data.get('user_id', ''),
            'incident_responder_name': data.get('incident_responder_name', '')
        }
        summary_data.append(new)
    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    # markdown = tableToMarkdown(title, summary_data, headers=headers,removeNull=True)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True)
    return markdown, summary_data


def generic_readable_output(results_list: list[dict], title: str) -> str:
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
        ignore_key_list: list[str] = []
        prefix = ''
        row = extract_raw_data(data, ignore_key_list, prefix)
        readable_output.append(row)

    headers = readable_output[0] if readable_output else {}
    headers = list(headers.keys())
    column_order = list(camelize_string(column) for column in headers)
    markdown = tableToMarkdown(title, camelize(readable_output, "_"), headers=column_order,
                               removeNull=True)
    return markdown


def extract_raw_data(data: list | dict, ignore_key: list[str] = [], prefix: str | None = None) -> dict:
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
    dataset: dict = {}
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


def query_search_condition(q_type: str, q_value: str, ignore_validation: bool = False) -> str:
    """
    This function make parameter query condition based on single or multiple  search values .
    Args:
        q_type (str): search query Type
        q_value (str): search query value
        ignore_validation (bool) : A boolean which ignore value Validation , Default false
    Returns:
        Return search condition.
    """
    condition: str = ''
    if not q_type or not q_value:
        return condition

    list_value = argToList(q_value, ',')
    for value in list_value:
        if not ignore_validation:
            check_valid_indicator_value(q_type, value)
        condition = value if not condition else f'{condition} OR {value}'

    return condition


def get_incident_filter_query(args: dict[str, Any]) -> str:
    """
    This function validate the incident filter search query and return the query condition
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    demisto.debug(f'Dump Incident filter query args: {args}')
    incident_status_dict: dict[str, int] = {'Open': 1, 'Waiting': 2, 'In-Progress': 3, 'Closed': 4}
    incident_severity_dict: dict[str, int] = {'Low': 1, 'Medium': 2, 'High': 3}
    # Incident Parameters
    ids = arg_to_number(args.get('incident_id', None))
    priority = incident_severity_dict.get(args.get('priority', None))
    status = incident_status_dict.get(args.get('status', None))
    query = args.get('query', None)

    if query and (ids or priority or status):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition: str = ''
    if ids is not None:
        condition = f'atp_incident_id: {ids}'

    if priority is not None:
        condition = f'priority_level: {priority}' if not condition else f'{condition} AND priority_level: {priority}'

    if status is not None:
        condition = f'state: {status}' if not condition else f'{condition} AND state: {status}'

    if query:
        condition = query

    return condition


def get_event_filter_query(args: dict[str, Any]) -> str:
    """
    This function create the query for search condition as part of response body.
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    # Activity query Parameters
    event_severity_mapping: dict[str, int] = {
        'info': 1,
        'warning': 2,
        'minor': 3,
        'major': 4,
        'critical': 5,
        'fatal': 6
    }

    event_status_mapping: dict[str, int] = {
        'Unknown': 0,
        'Success': 1,
        'Failure': 2
    }

    event_type_id = arg_to_number(args.get('type_id'))
    severity = event_severity_mapping.get(args.get('severity', ''))
    status = event_status_mapping.get(args.get('status', ''))
    query = args.get('query')

    if query and (event_type_id or severity):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition = ''
    if event_type_id:
        condition = f'type_id: {event_type_id}'

    if severity:
        condition = f'severity_id: {severity}' if not condition else f'{condition} AND severity_id: {severity}'

    if status:
        condition = f'status_id: {status}' if not condition else f'{condition} AND status_id: {status}'

    if query:
        condition = query

    return condition


def get_association_filter_query(args: dict) -> str:
    """
    This function validate the association filter search query and create the query search condition a
    payload based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    query_type = args.get('search_object', None)
    query_value = args.get('search_value', None)
    query = args.get('query', None)

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


def post_request_body(args: dict, p_limit: int = 1) -> dict:
    """
    This function creates a default payload based on the demisto.args().
    Args:
        args: demisto.args()
        p_limit: Page Limit (int)
    Returns:
        Return arguments dict.
    """
    # Default payload
    payload: dict[str, Any] = {'verb': 'query'}
    page_size = args.get('page_size')
    max_limit = args.get('limit', DEFAULT_PAGE_SIZE)

    if page_size:
        if p_limit >= max_limit:
            # in case user pass the page_size or limit is less than page_size
            payload['limit'] = p_limit
    else:
        payload['limit'] = p_limit if p_limit != DEFAULT_PAGE_SIZE else max_limit

    from_time = iso_creation_date(args.get('start_time', ''))
    to_time = iso_creation_date(args.get('end_time', ''))

    if from_time:
        payload['start_time'] = from_time

    if to_time:
        payload['end_time'] = to_time

    return payload


def get_params_query(args: dict, p_limit: int = 0) -> dict:
    """
    This function creates a query param based on the demisto.args().
    Args:
        args: demisto.args()
        p_limit: Page Limit (int)
    Returns:
        Return arguments dict.
    """
    query_param: dict = {}
    ip = args.get('ip')
    url = args.get('url')
    md5 = args.get('md5')
    sha256 = args.get('sha256')

    # if ip := args.get('ip'):
    if ip:
        check_valid_indicator_value('ip', ip)

    if md5:
        check_valid_indicator_value('md5', md5)

    if sha256:
        check_valid_indicator_value('sha256', sha256)

    max_limit = args.get('limit', DEFAULT_PAGE_SIZE)
    page_size = args.get('page_size')

    if page_size and (p_limit > max_limit):
        # in case user pass the page_size or limit, limit will ignore
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


def check_valid_indicator_value(indicator_type: str, indicator_value: str) -> bool:
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


def get_incident_raw_response(endpoint: str, client: Client, args: dict[str, Any], max_limit: int) -> dict:
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


def get_incident_uuid(client: Client, args: dict[str, Any]) -> str:
    """
      Get the incident UUID
      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
              result.
    """
    data_list = get_incident_raw_response('/atpapi/v2/incidents', client, args, 1).get('result', [])
    if len(data_list) >= 1:
        if uuid := data_list[0].get('uuid'):
            return uuid
    else:
        raise DemistoException(f'Either Incident does not exist or Unable to search incident {args.get("incident_id")} which is older than 30 days.\n'
                               f'Provide time range Arguments')


def get_request_payload(args: dict[str, Any], query_type: str | None = 'default'):
    """
    Create payload for request the endpoints
    Args:
        args: all command arguments, usually passed from ``demisto.args()``.
        query_type: payload type object are: association, event, incident, allow_list, deny_list
    Returns:
        payload (dict): Return payload for request body
        page_limit (int): page limit value
        offset (int): Pagination offset value
        page_size (int): page size or default value
    """
    # Set default value to page, page_limit and page_size
    page = arg_to_number(args.get('page', 1), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    page_limit, offset = pagination(page, page_size)

    if query_type in ('allow_list', 'deny_list'):
        limit = arg_to_number(args.get('limit'))
        if limit and (limit < 10 or limit > 1000):
            raise ValueError('Invalid input limit: Value between Minimum = 10 , Maximum = 1000')
        payload = get_params_query(args, page * page_limit)
    else:
        payload = post_request_body(args, page * page_limit)

    # search query as Lucene query string
    if query_type == 'association':
        search_query = get_association_filter_query(args)
    elif query_type == 'event':
        search_query = get_event_filter_query(args)
    elif query_type == 'incident':
        search_query = get_incident_filter_query(args)
    else:
        # default
        search_query = args.get('query', None)

    if search_query:
        payload['query'] = search_query

    return payload, page_limit, offset, page_size


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
    try:
        res = get_incident_list_command(client, {'limit': 1})
        message = 'ok'
    except DemistoException as e:
        return_error(f'Failed to execute. Error {e}')

    return message


def get_domain_file_association_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    payload, limit, offset, page_size = get_request_payload(args, 'association')
    raw_response: dict[str, Any] = client.query_request_api(endpoint, payload)
    title = get_command_title_string(
        'Domain File Association',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = 'No Domain and File association data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DomainFileAssociation',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_endpoint_domain_association_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    payload, limit, offset, page_size = get_request_payload(args, 'association')
    raw_response: dict[str, Any] = client.query_request_api(endpoint, payload)
    title = get_command_title_string(
        "Endpoint Domain Association",
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = 'No Endpoint Domain association data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointDomainAssociation',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_endpoint_file_association_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    payload, limit, offset, page_size = get_request_payload(args, 'association')
    raw_response: dict[str, Any] = client.query_request_api(endpoint, payload)
    title = get_command_title_string(
        "Endpoint File Association",
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = 'No Endpoint File association data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointFileAssociation',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_audit_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Audit Event
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    endpoint = '/atpapi/v2/auditevents'
    payload, limit, offset, page_size = get_request_payload(args, 'event')
    raw_response = client.query_request_api(endpoint, payload)

    title = get_command_title_string(
        "Audit Event",
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore
    if page_result:
        readable_output, context_data = audit_event_readable_output(page_result, title)
    else:
        readable_output = 'No Audit Event data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.AuditEvent',
        outputs_key_field='event_uuid',
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_event_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get all events
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    endpoint = '/atpapi/v2/events'
    payload, limit, offset, page_size = get_request_payload(args, 'event')
    raw_response = client.query_request_api(endpoint, payload)

    title = get_command_title_string(
        "Event",
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore
    if page_result:
        readable_output, context_data = incident_event_readable_output(page_result, title)
    else:
        readable_output = 'No Event data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Event',
        outputs_key_field='event_uuid',
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_system_activity_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get System Activity log events
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    endpoint = '/atpapi/v2/systemactivities'
    payload, limit, offset, page_size = get_request_payload(args, 'event')
    raw_response = client.query_request_api(endpoint, payload)

    title = get_command_title_string(
        "System Activities",
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore
    if page_result:
        readable_output, context_data = system_activity_readable_output(page_result, title)
    else:
        readable_output = 'No Endpoint Instances data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SystemActivity',
        outputs_key_field='uuid',
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_event_for_incident_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Event for Incident List
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    endpoint = '/atpapi/v2/incidentevents'
    payload, limit, offset, page_size = get_request_payload(args, 'event')
    raw_response = client.query_request_api(endpoint, payload)

    title = get_command_title_string(
        'Event for Incident',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore
    if page_result:
        readable_output, context_data = incident_event_readable_output(page_result, title)
    else:
        readable_output = 'No Event for Incidents data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentEvent',
        outputs_key_field='event_uuid',
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_incident_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Incident List
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    endpoint = '/atpapi/v2/incidents'

    payload, limit, offset, page_size = get_request_payload(args, 'incident')
    demisto.debug(f'Incident Payload: {payload}')
    raw_response = client.query_request_api(endpoint, payload)
    title = get_command_title_string(
        'Incident',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore
    if page_result:
        readable_output, context_data = incident_readable_output(page_result, title)
    else:
        readable_output = 'No Incidents data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Incident',
        outputs_key_field='apt_incident_id',
        outputs=context_data,
        raw_response=raw_response
    )


def get_incident_comments_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get all comments based on Incident ID
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []

    # Get UUID based on incident_id
    uuid = get_incident_uuid(client, args)
    endpoint = f'/atpapi/v2/incidents/{uuid}/comments'

    # Argument incident_id not be required in further incident command query therefor
    # remove it from args
    incident_id = args.pop("incident_id", None)
    payload, limit, offset, page_size = get_request_payload(args, 'incident')
    raw_response = client.query_request_api(endpoint, payload)
    title = get_command_title_string(
        'Incident Comment',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output, context_data = incident_comment_readable_output(page_result, title, incident_id)
    else:
        readable_output = 'No Incident Comments data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.IncidentComment',
        outputs_key_field='',
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def patch_incident_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
      Incident Update command is used to Add, close or update incident resolution
      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
              result.
    """
    endpoint = '/atpapi/v2/incidents'

    # Get UUID based on incident_id
    uuid = get_incident_uuid(client, args)
    action = args.get('action_type')
    value: str = args.get('value', '')
    if action not in INCIDENT_PATCH_ACTION:
        raise ValueError(f'Invalid Incident Patch Operation: Supported values are : {INCIDENT_PATCH_ACTION}')

    action_list: list[dict[str, Any]] = []
    # Incident Add Comment
    if action == 'add_comment':
        if not value:
            raise ValueError('Incident comments not found. Enter comments to add')

        action_desc = 'Add Comment'
        add_comment = {
            'op': 'add',
            'path': f'/{uuid}/comments',
            'value': value[:512]
        }
        action_list.append(add_comment)
        # Incident Close Incident
    elif action == 'closed':
        action_desc = 'Close Incident'
        close_action = {
            'op': 'replace',
            'path': f'/{uuid}/state',
            'value': 4
        }
        action_list.append(close_action)
        # Incident Update Resolution
    elif action == 'update_resolution':
        action_desc = 'Update Status'
        if not value.isnumeric():
            raise ValueError(f'Invalid Incident Resolution value, it must be integer: '
                             f'The Support values {INCIDENT_RESOLUTION}')
        update_state = {
            'op': 'replace',
            'path': f'/{uuid}/resolution',
            'value': arg_to_number(value)
        }
        action_list.append(update_state)
    else:
        raise DemistoException(f'Unable to perform Incident update. '
                               f'Only supported following action {INCIDENT_PATCH_ACTION}')

    response = client.query_patch_api(endpoint, action_list)
    title = f'Incident {action_desc}'

    if response.get('status') == 204:
        summary_data = {
            'incident_id': args.get('incident_id'),
            'Message': 'Successfully Updated',
        }
        headers = list(summary_data.keys())
        readable_output = tableToMarkdown(title, summary_data, headers=headers, removeNull=True)
    else:
        readable_output = f'Failed {action}. Response from endpoint {response.get("status")}'

    return CommandResults(
        readable_output=readable_output,
        ignore_auto_extract=True
    )


def get_file_instance_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    payload, limit, offset, page_size = get_request_payload(args)
    raw_response: dict[str, Any] = client.query_request_api(endpoint, payload)

    title = get_command_title_string(
        'File Instances',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = 'No File Instance data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.FileInstance',
        outputs_key_field='sha2',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_domain_instance_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Domain Instance
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    endpoint = '/atpapi/v2/entities/domains/instances'
    payload, limit, offset, page_size = get_request_payload(args)

    raw_response: dict[str, Any] = client.query_request_api(endpoint, payload)

    title = get_command_title_string(
        'Domain Instances',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output, context_data = domain_instance_readable_output(page_result, title)
    else:
        readable_output = 'No Domain Instances data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DomainInstances',
        outputs_key_field='',
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_endpoint_instance_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    payload, limit, offset, page_size = get_request_payload(args)

    raw_response: dict[str, Any] = client.query_request_api(endpoint, payload)
    title = get_command_title_string(
        'Endpoint Instances',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = endpoint_instance_readable_output(page_result, title)
    else:
        readable_output = 'No Endpoint Instances data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointInstances',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_allow_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    payload, limit, offset, page_size = get_request_payload(args, 'allow_list')
    raw_response = client.query_request_api(endpoint, payload, 'GET')

    title = get_command_title_string(
        'Allow List Policy',
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = 'No Endpoint Instances data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.AllowListPolicy',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_deny_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    payload, limit, offset, page_size = get_request_payload(args, 'deny_list')

    raw_response = client.query_request_api(endpoint, payload, 'GET')

    title = get_command_title_string(
        "Deny List Policy",
        arg_to_number(args.get('page', 0)),
        page_size,
        arg_to_number(raw_response.get('total'))
    )

    page_result = get_data_of_current_page(offset, limit, raw_response.get('result', []))  # type: ignore

    if page_result:
        readable_output = generic_readable_output(page_result, title)
    else:
        readable_output = 'No Endpoint Instances data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DenyListPolicy',
        outputs_key_field='',
        outputs=page_result,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_endpoint_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = "/atpapi/v2/commands"
    device_uid = args.get('device_id')
    file_sha2 = args.get('sha2')
    command_id = args.get('command_id')

    if demisto.command() == 'symantec-edr-endpoint-delete-file':
        if not device_uid or not file_sha2:
            raise DemistoException('Invalid Arguments. '
                                   'Both "device_id" and "sha2" arguments is required for endpoint delete action')
        payload = {
            'action': 'delete_endpoint_file',
            'targets': argToList({'device_uid': device_uid, 'hash': file_sha2})
        }
    elif demisto.command() == 'symantec-edr-endpoint-cancel-command':
        payload = {'action': 'cancel_command', 'targets': argToList(command_id)}
    elif demisto.command() == 'symantec-edr-endpoint-isolate':
        payload = {'action': 'isolate_endpoint', 'targets': argToList(device_uid)}
    elif demisto.command() == 'symantec-edr-endpoint-rejoin':
        payload = {'action': 'rejoin_endpoint', 'targets': argToList(device_uid)}
    else:
        raise DemistoException('Endpoint Command action not found.')

    raw_response = client.query_request_api(endpoint, payload)
    title = f'Command {payload.get("action")}'

    summary_data = {
        "Message": raw_response.get('message'),
        "CommandId": raw_response.get('command_id')
    }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Command.{payload.get("action")}',
        outputs_key_field='command_id',
        outputs=raw_response,
        readable_output=tableToMarkdown(title, summary_data, headers=headers, removeNull=True),
        raw_response=raw_response,
        ignore_auto_extract=True
    )


def get_endpoint_status_command(client: Client, args: dict[str, Any]) -> CommandResults:
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
    raw_response: dict[str, Any] = client.query_request_api(endpoint, params)

    title = "Command Status"
    summary_data = {
        "state": raw_response.get('state'),
        "Command Issuer Name": raw_response.get('command_issuer_name'),
    }

    result = raw_response.get('status', [])
    if len(result) >= 1:
        for status in result:
            # summary_data['target'] = status.get('target')
            summary_data['state'] = status.get('state', '')
            summary_data['message'] = status.get('message', '')
            summary_data['error_code'] = status.get('error_code', '')

    if summary_data:
        readable_output = generic_readable_output(argToList(summary_data), title)
    else:
        readable_output = 'No command status data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.CommandStatus',
        outputs_key_field='',
        outputs=summary_data,
        raw_response=raw_response,
        ignore_auto_extract=True
    )


''' FETCHES INCIDENTS '''


def fetch_incidents(client: Client) -> list:
    """
    Arguments Validation.
    Args:
        client: Client Object
    Returns:
        Incidents List
    """

    rev_incident_priority = {v: k for k, v in INCIDENT_PRIORITY_LEVEL.items()}
    rev_incident_state = {v: k for k, v in INCIDENT_STATUS.items()}

    seperator = ' OR '
    priority_list: list[str] = [rev_incident_priority.get(i) for i in client.fetch_priority]
    priority = priority_list[0] if len(priority_list) == 1 else seperator.join(map(str, priority_list))

    state_list: list[str] = [rev_incident_state.get(i) for i in client.fetch_status]
    state = state_list[0] if len(state_list) == 1 else seperator.join(map(str, state_list))

    last_run = demisto.getLastRun()
    demisto.debug(f'Last Run Object : {last_run}')

    payload = {
        "verb": "query",
        "limit": client.fetch_limit,
        "query": f'priority_level: ({priority}) AND state: ({state})'
    }
    demisto.debug(f'limit: {client.fetch_limit}, priority_level: ({priority}) AND state: ({state})')
    # demisto.getLastRun() will returns an obj with the previous run in it.
    # set First Fetch starting time in case running first time or reset
    start_time = iso_creation_date(client.first_fetch)
    start_time_n, end_time = get_fetch_run_time_range(last_run=last_run, first_fetch=client.first_fetch)

    if last_run and 'time' in last_run:
        start_time_lastrun = iso_creation_date(last_run.get('time'))

    payload['start_time'] = start_time if not last_run else start_time_lastrun
    results = client.query_request_api('/atpapi/v2/incidents', payload, 'POST').get('result', [])

    #incidents = []  # type:List
    incidents, events_result, comments_result = [], [], []  # type:List
    # Map severity to Demisto severity for incident creation
    xsoar_severity_map = {'High': 3, 'Medium': 2, 'Low': 1}

    incidents_count = 0
    if results:
        _, incidents_context = incident_readable_output(results)
        for incident in incidents_context:
            incident_id = incident.get('incident_id')
            incident_uuid = incident.get("incident_uuid")

            # Get Incidents Comments if set as true
            if client.is_fetch_comment:
                payload = {
                    "verb": "query",
                    "start_time": start_time
                } if not last_run else {"verb": "query"}
                comments_result = client.query_request_api(f'/atpapi/v2/incidents/{incident_uuid}/comments', payload, 'POST').get('result', [])

            # Fetch incident for event if set as true
            if client.is_incident_event:
                payload = {
                    "verb": "query",
                    "query": f'incident: {incident_uuid}',
                    "start_time": start_time
                }
                events_result = client.query_request_api('/atpapi/v2/incidentevents', payload).get('result', [])

            # Incidents Data
            incidents.append({
                'name': f'SEDR Incident {incident_id}',
                'details': incident.get("description"),
                'severity': xsoar_severity_map.get(str(incident.get('priority')), 0),
                'occurred': incident.get('incident_created'),
                'rawJSON': json.dumps(
                    {
                        'incident': incident,
                        'comments': comments_result,
                        'events': events_result
                    }
                )
            })
            incidents_count += 1

    # # remove duplicate incidents which were already fetched
    incidents = filter_incidents_by_duplicates_and_limit(
        incidents_res=incidents, last_run=last_run, fetch_limit=client.fetch_limit, id_field='name'
    )

    end_time = iso_creation_date('now')
    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents,
        fetch_limit=client.fetch_limit,
        start_fetch_time=start_time_n,
        end_fetch_time=end_time,
        look_back=30,
        created_time_field='occurred',
        id_field='name',
        date_format=SYMANTEC_ISO_DATE_FORMAT
    )

    demisto.debug(f'last run at the end of the incidents fetching {last_run},'
                  f'incident count : {incidents_count},'
                  f'Incident insert: {len(incidents)}')
    demisto.setLastRun(last_run)
    return incidents


''' POLLING CODE '''


def get_sandbox_verdict(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    sandbox_res = client.query_request_api(endpoint, {}, 'GET')
    file_res = client.query_request_api(f'/atpapi/v2/entities/files/{sha2}', {}, 'GET')
    response: Dict[str, Any] = {**sandbox_res, **file_res}
    # Sandbox verdict
    # datasets = response_data.get("status", [])
    title = "Sandbox Verdict"
    if response:
        readable_output = generic_readable_output(argToList(response), title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxVerdict',
        outputs_key_field='',
        outputs=response
    )


def check_sandbox_status(client: Client, args: Dict[str, Any]) -> str:
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
    try:
        endpoint = f'/atpapi/v2/sandbox/commands/{command_id}'
    except Exception as e:
        # f'Failed to execute {demisto.command()} command.\nError: {e}'
        return_error(message='File not found.', error=f'Unknown..{e}', outputs={'message': 'File Not found', 'status': 'Unknown'})

    response = client.query_request_api(endpoint, {}, 'GET')
    # Query Sandbox Command Status
    summary_data = {}
    datasets = response.get("status", [])
    if datasets:
        for data in datasets:
            new = {
                'command_id': command_id,
                'status': SANDBOX_STATE.get(str(data.get('state'))),
                'message': data.get('message'),
                'target': data.get('target'),
                'error_code': data.get('error_code')
            }
            summary_data = {**summary_data, **new}

    title = "File Sandbox Status"
    if datasets:
        readable_output = generic_readable_output(argToList(summary_data), title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxStatus',
        outputs_key_field='command_id',
        outputs=summary_data,
        raw_response=response
    )


def issue_sandbox_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    response = client.query_request_api(endpoint, payload)
    # return response.get('command_id', '')
    # Get Issue Sandbox Command
    title = "Issue Sandbox Command"
    summary_data = {
        'file_sha2': file_hash,
        'command_id': response.get('command_id'),
        'command_type': 'Issue Sandbox Command'
    }
    headers = list(summary_data.keys())
    column_order = list(camelize_string(column) for column in headers)
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxIssue',
        outputs_key_field='command_id',
        outputs=summary_data,
        readable_output=tableToMarkdown(title, camelize(summary_data, '_'), headers=column_order, removeNull=True),
        raw_response=response
    )


def sandbox_issue_polling_command(client: Client, args: Dict[str, Any]):

    if pre_cmd_id := demisto.getIntegrationContext().get('command_id'):
        args['command_id'] = pre_cmd_id

    if 'command_id' not in args:
        command_results = issue_sandbox_command(client, args)
        outputs = command_results.outputs
        new_command_id = outputs.get('command_id')
        demisto.setIntegrationContext({'command_id': new_command_id})
        if new_command_id:
            args['command_id'] = new_command_id

    return file_polling_command(args, client)


@polling_function('file',
                  interval=arg_to_number(demisto.args().get('interval_in_seconds', DEFAULT_INTERVAL)),
                  timeout=arg_to_number(demisto.args().get('timeout_in_seconds', DEFAULT_TIMEOUT)))
def file_polling_command(args: Dict[str, Any], client: Client) -> PollResult:
    """
    Polling command will show the progress of the sandbox status command after the first issue sandbox command.
    Once a file scanning is done the status will be shown as 'Completed' and return the file verdict

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request and a Client.
        client: client object to use.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """

    # time.sleep(90)
    command_result = check_sandbox_status(client, args)
    raw_response = command_result.outputs
    status = dict_safe_get(raw_response, ['status']) if raw_response else None

    if status == 'Completed':
        command_result = get_sandbox_verdict(client, args)
        demisto.setIntegrationContext({})
        return PollResult(
            response=command_result,
            continue_to_poll=False
        )
    elif status == 'Error':
        demisto.setIntegrationContext({})
        return PollResult(
            response=command_result,
            continue_to_poll=False
        )
    else:
        polling_args = {
            **args
        }
        return PollResult(
            response=command_result,
            continue_to_poll=True,
            args_for_next_run=polling_args,
            partial_result=CommandResults(
                readable_output=f'Waiting for Status ... with command id {args.get("command_id")}'
            )
        )


# ScheduledCommand
def run_polling_command(client: Client, args: dict, cmd: str, status_func: Callable, results_func: Callable):
    """
    This function can handle the polling flow.
    After the first run, progress will be shown through the status command.
    The run_polling_command function check the file scan status and will run till its status is  not 'Completed'
    and returns a ScheduledCommand object that schedules the next 'results' function, until the polling is complete.
    Args:
        client: Symantec EDR cient object
        args: the arguments required to the command being called, under cmd
        cmd: the command to schedule by after the current command
        status_func : The function that check the file scan status and return either completed or error status
        results_func: the function that retrieves the verdict based on file sandbox status


    Returns:

    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = arg_to_number(demisto.args().get('interval_in_seconds', DEFAULT_INTERVAL))
    timeout_in_seconds = arg_to_number(demisto.args().get('timeout_in_seconds', DEFAULT_TIMEOUT))

    # distinguish between the initial run, which is the Issue the file for scanning
    if pre_cmd_id := demisto.getIntegrationContext().get('command_id'):
        args['command_id'] = pre_cmd_id
    # first run ...
    if 'command_id' not in args:
        command_results = issue_sandbox_command(client, args)
        outputs = command_results.outputs
        command_id = outputs.get('command_id')
        if command_id is not None:
            demisto.setIntegrationContext({'command_id': command_id})
            args['command_id'] = command_id

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
            command_result = CommandResults(scheduled_command=scheduled_command,
                                            readable_output=f'Waiting for the polling execution..'
                                                            f'Command id {command_id}',
                                            ignore_auto_extract=True
                                            )
            return command_result

    # not a first run
    command_result = status_func(client, args)
    outputs = command_result.outputs
    status = outputs.get('status')
    if status == 'Completed':
        # # action was completed
        demisto.setIntegrationContext({})
        return results_func(client, args)
    elif status == 'Error':
        demisto.setIntegrationContext({})
        return command_result
    else:
        # in case of In progress
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
        command_result = CommandResults(scheduled_command=scheduled_command,
                                        ignore_auto_extract=True
                                        )
        return command_result


def file_scheduled_polling_command(client, args):
    return run_polling_command(client, args, 'file', check_sandbox_status, get_sandbox_verdict)


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()

        # OAuth parameters
        server_url = params.get('url', '')
        client_id = params.get('credentials', {}).get('identifier', '')
        client_secret = params.get('credentials', {}).get('password', '')
        verify_certificate = params.get('insecure', False)
        # not params.get('insecure', False)
        proxy = params.get('proxy', False)

        # Fetches Incident Parameters
        first_fetch_time = params.get('first_fetch', '3 days').strip()
        fetch_limit = arg_to_number(params.get('fetch_limit'))
        fetch_incident_event = params.get('isIncidentsEvent', False)
        fetch_comments = params.get('isIncidentComment', False)
        fetch_status = argToList(params.get('fetch_status', 'New'))
        fetch_priority = argToList(params.get('fetch_priority', 'High,Medium'))

        client = Client(base_url=server_url, verify=verify_certificate, proxy=proxy, client_id=client_id,
                        client_secret=client_secret, first_fetch=first_fetch_time, fetch_limit=fetch_limit,
                        is_incident_event=fetch_incident_event, is_fetch_comment=fetch_comments,
                        fetch_status=fetch_status, fetch_priority=fetch_priority)

        demisto.debug(f'Command being called is {demisto.command()}')

        commands = {
            # isolate_endpoint command
            "symantec-edr-endpoint-isolate": get_endpoint_command,

            # re-join command
            "symantec-edr-endpoint-rejoin": get_endpoint_command,

            # delete_endpoint_file command
            "symantec-edr-endpoint-delete-file": get_endpoint_command,

            # cancel_command
            "symantec-edr-endpoint-cancel-command": get_endpoint_command,

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
            "symantec-edr-audit-event-list": get_audit_event_command,

            # Allow List Policies
            "symantec-edr-allow-list-policy-get": get_allow_list_command,

            # Deny List Policies
            "symantec-edr-deny-list-policy-get": get_deny_list_command,

            # Domain Instances
            "symantec-edr-domain-instance-list": get_domain_instance_command,

            # Endpoint Instances
            "symantec-edr-endpoint-instance-list": get_endpoint_instance_command,

            # File Instances
            "symantec-edr-file-instance-list": get_file_instance_command,

            # Events
            "symantec-edr-event-list": get_event_list_command,

            # file Sandbox (Reputation command)
            # "file": sandbox_issue_polling_command,
            "file": file_scheduled_polling_command
        }
        command_output: CommandResults | str = ""
        if command == "test-module":
            command_output = test_module(client)
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)
            command_output = "OK"
        elif command in commands:
            command_output = commands[command](client, args)
        else:
            raise NotImplementedError

        return_results(command_output)

# Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError: {e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
