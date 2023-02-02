"""
Symantec Endpoint Detection and Response (EDR) On-Prem integration with Symantec-EDR 4.6
"""
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import dateparser
import requests
import urllib3
from typing import Callable

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 600

# Symantec TOKEN timeout 60 mins
SESSION_TIMEOUT_SEC = 3600
SYMANTEC_ISO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
INTEGRATION_CONTEXT_NAME = 'SymantecEDR'
DEFAULT_OFFSET = 0
DEFAULT_PAGE_SIZE = 50
PAGE_NUMBER_ERROR_MSG = 'Invalid Input Error: page number should be greater than zero. ' \
                        'Note: Page must be used along with page_size'
PAGE_SIZE_ERROR_MSG = 'Invalid Input Error: page size should be greater than zero. ' \
                      'Note: Page must be used along with page_size'

INVALID_QUERY_ERROR_MSG = 'Invalid query arguments. Either use any optional filter in lieu of "query" ' \
                          'or explicitly use only "query" argument'

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
                 first_fetch: str = '3 days', fetch_limit: Optional[int] = 50, is_incident_event: bool = False,
                 is_fetch_comment: bool = False, fetch_status: list = None, fetch_priority: list = None,
                 token: Optional[str] = None):

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

        self.client_key = client_id
        self.secret_key = client_secret
        self.first_fetch = first_fetch
        self.fetch_limit = fetch_limit
        self.is_incident_event = is_incident_event
        self.is_fetch_comment = is_fetch_comment
        self.fetch_status = fetch_status
        self.fetch_priority = fetch_priority
        self.access_token = token

    @property
    def headers(self):
        if self.access_token is None:  # for logging in, before self.access_token is set
            raise DemistoException('Failed to get last saved access Token')
        return {'Authorization': f'Bearer {self.access_token}', 'Content-Type': 'application/json'}

    def get_access_token_or_login(self) -> None:
        """
        Generate Access token
        Returns:
            Returns Set access_token
        """
        global_context = demisto.getIntegrationContext()
        if last_access_token := get_access_token_from_context(global_context):
            self.access_token = last_access_token
            demisto.debug(f"Last login access token still active. Return token {last_access_token}")
        else:
            try:
                response = self._http_request(
                    method='POST',
                    url_suffix='/atpapi/oauth2/tokens',
                    auth=(self.client_key, self.secret_key),
                    data={'grant_type': 'client_credentials'},
                    resp_type='response'
                )
                response.raise_for_status()

                new_access_token = response.json().get("access_token")
                self.access_token = new_access_token
                timestamp_string = int(time.time())
                demisto.debug(f"login: success, saving access token {new_access_token}\n,"
                              f"Created Timestamp : {timestamp_string}")

                if global_integration_context := demisto.getIntegrationContext():
                    global_integration_context['access_token'] = new_access_token
                    global_integration_context['access_token_timestamp'] = timestamp_string
                    demisto.setIntegrationContext(global_integration_context)
                else:
                    demisto.setIntegrationContext({
                        'access_token': new_access_token,
                        'access_token_timestamp': timestamp_string
                    })

            except requests.exceptions.HTTPError as err:
                status = response.status_code
                if status in HTTP_ERRORS:
                    raise DemistoException(f'{HTTP_ERRORS[status]}, '
                                           f'Error from API: {response.json().get("error")},'
                                           f'{response.json().get("message")}',
                                           res=response)
                else:
                    # if it is unknown error - get the message from the error itself
                    raise DemistoException(f'Failed to execute. Error: {str(err)}', res=response)

    def query_request_api(self, method: str, url_suffix: str, params: dict[str, Any] = None,
                          json_data: dict[str, Any] = None) -> Dict[str, Any]:
        """
        Call Symantec EDR On-prem POST and GET Request API
        Args:
            method (str): Request Method support POST and GET
            url_suffix (str): API endpoint
            params (dict): URL parameters to specify the query for GET.
            json_data (dict): The dictionary to send in a request for POST.

        Returns:
            Return the raw api response from Symantec EDR on-premise API.
        """
        try:
            response = self._http_request(
                method=method.upper(),
                url_suffix=url_suffix,
                headers=self.headers,
                json_data=json_data,
                params=params,
                resp_type='response',
                allow_redirects=False
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            status = response.status_code
            if status in HTTP_ERRORS:
                raise DemistoException(f'{HTTP_ERRORS[status]}, '
                                       f'Error from API: {response.json().get("error")},'
                                       f'{response.json().get("message")}',
                                       res=response)
            else:
                # if it is unknown error - get the message from the error itself
                raise DemistoException(f'Failed to execute. Error: {str(err)}', res=response)

        return response.json()

    def query_patch_api(self, endpoint: str, payload: list[dict[str, Any]]):
        """
        Call the PATCH api to add/modify or update to the endpoint
        Args:
            endpoint (str): Symantec EDR endpoint resources operation add, update, delete
            payload (List): request body
        Returns:
            return response
        """
        try:
            response = self._http_request(
                method="PATCH",
                headers=self.headers,
                json_data=payload,
                url_suffix=endpoint,
                resp_type="response",
                return_empty_response=True
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            status = response.status_code
            if status in HTTP_ERRORS:
                raise DemistoException(f'{HTTP_ERRORS[status]}, '
                                       f'Error from API: {response.json().get("error")},'
                                       f'{response.json().get("message")}',
                                       res=response)
            else:
                # if it is unknown error - get the message from the error itself
                raise DemistoException(f'Failed to execute. Error: {str(err)}', res=response)

        return response


''' HELPER FUNCTIONS '''


def get_access_token_from_context(global_context: dict[str, Any]):
    """
    Symantec EDR on-premise get previous access token from global integration context
    Args:
        global_context(dict): Integration Context data
    Returns:
        return token or None
    """
    if save_timestamp := global_context.get('access_token_timestamp'):
        now_timestamp = int(time.time())
        time_diff = int(now_timestamp - save_timestamp)

        if token := global_context.get('access_token'):
            if time_diff <= SESSION_TIMEOUT_SEC:
                LOG(f'Access token not expired ..{token}')
                return token
            elif time_diff > SESSION_TIMEOUT_SEC:
                LOG('Access token expired')
                return None
    else:
        LOG('Access Token not found, Going to be generate new access token')
        return None


def iso_creation_date(date: str):
    """
    Symantec EDR on-premise ISO 8601 date stamp format
    Args:
        date (str): ISO date example 2017-01-01T00:00:00.000Z or free text 2 days
    Returns:
        Return the ISO Date
    """
    if date:
        return dateparser.parse(date).strftime(SYMANTEC_ISO_DATE_FORMAT)[:23] + "Z"  # type: ignore

    return None


def get_headers_from_summary_data(summary_data: list[dict]):
    """
    Symantec EDR formatting Readable output Header
    Args:
        summary_data (list[dict]): Human readable output summary data

    Returns:
        Return list with camelize string headers.

    """
    if not summary_data:
        demisto.debug('Unable to find Readable Summary Data.')
        return list()

    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    return list(camelize_string(column) for column in headers)


def get_data_of_current_page(offset: int, limit: int, data_list: list[dict[str, Any]]):
    """
    Retrieve list element based on offset and limit
    Args:
        offset (int): Offset
        limit (int): Page Limit
        data_list (list): Raw API result list

    Returns:
        Return List of object from the response according to the limit, page and page_size.

    """
    if offset >= 0 and limit >= 0:
        return data_list[offset:(offset + limit)]
    return data_list[:limit]


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
        # Default OFFSET value is 0
        page = DEFAULT_OFFSET
    elif page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)

    if page_size is None:
        page_size = DEFAULT_PAGE_SIZE
    elif page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    limit = page_size
    offset = (page - 1) * page_size if page > 0 else page

    return limit, offset


def compile_command_title_string(context_name: str, page: int | None, page_size: int | None, total_record: int | None) \
        -> str:
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
            attacks_dict |= tactic_ids_dict

        # tactic uids
        tactic_uids_list = attack.get('tactic_uids', [])
        if tactic_uids_list:
            tactic_uids_dict = {
                f'attacks_tactic_uids_{cnt}': convert_list_to_str(tactic_uids_list)
            }
            attacks_dict |= tactic_uids_dict

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


def convert_list_to_str(data: Optional[list] = None) -> str:
    seperator = ','
    return seperator.join(map(str, data)) if isinstance(data, list) else ''


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

    result: dict[str, Any] = extract_raw_data(data, ignore_list)

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
            result |= func(values)  # type: ignore

    for item in ['edr_data_protocols', 'edr_files', 'source_port', 'target_port']:
        if values := data.get(item):
            result |= {f'{item}': values}

    return result


def domain_instance_readable_output(results: list[dict], title: str) -> tuple[str, list]:
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
        domain_instance = {
            'data_source_url_domain': data.get('data_source_url_domain', ''),
            'first_seen': data.get('first_seen', ''),
            'last_seen': data.get('last_seen', ''),
            'external_ip': data.get('external_ip', ''),
            'disposition': DOMAIN_DISPOSITION_STATUS.get(str(disposition_val), ''),
            'data_source_url': data.get('data_source_url', '')
        }
        summary_data.append(domain_instance)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=headers, removeNull=True)
    return markdown, summary_data


def system_activity_readable_output(results: list[dict], title: str) -> tuple[str, list]:
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
        system_activity = {
            'time': event_data.get('device_time', ''),
            'type_id': event_data.get('type_id', ''),
            'severity_id': event_data.get('severity_id', ''),
            'message': event_data.get('message', ''),
            'device_ip': event_data.get('device_ip', ''),
            'atp_node_role': event_data.get('atp_node_role', ''),
            'status_id': event_data.get('status_id', '')
        }
        summary_data.append(system_activity)
        context_data.append(event_data)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=headers, removeNull=True)
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
        endpoint_instance = {
            'device_uid': data.get('device_uid', ''),
            'device_name': data.get('device_name', ''),
            'device_ip': data.get('device_ip', ''),
            'domain_or_workgroup': data.get('domain_or_workgroup', ''),
            'time': data.get('time', ''),
            'ip_addresses': ip_addresses
        }
        summary_data.append(endpoint_instance)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data, "_"), headers=headers,
                               removeNull=True)
    return markdown


def incident_readable_output(results: list[dict], title: Optional[str] = None) -> tuple[str, list]:
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
        incident = {
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
            'resolution': INCIDENT_RESOLUTION.get(str(resolution), ''),
            'first_seen': data.get('first_event_seen'),
            'last_seen': data.get('last_event_seen')
        }
        summary_data.append(incident)
    summary_data_sorted = sorted(summary_data, key=lambda d: d['incident_id'], reverse=True)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=headers, removeNull=True)
    return markdown, summary_data


def audit_event_readable_output(results: list[dict], title: str) -> tuple[str, list]:
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
        event = {
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
        summary_data.append(event)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d['time'], reverse=True)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=headers, removeNull=True)
    return markdown, context_data


def incident_event_readable_output(results: list[dict], title: Optional[str] = None) -> tuple[str, list]:
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
        incident_for_event = {
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
        summary_data.append(incident_for_event)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d['time'], reverse=True)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data_sorted, '_'), headers=headers, removeNull=True)
    return markdown, context_data


def incident_comment_readable_output(results: list[dict], title: str, incident_id: str) -> tuple[str, list]:
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
        incident_comment = {
            'incident_id': incident_id,
            'comment': data.get('comment', ''),
            'time': data.get('time', ''),
            'user_id': data.get('user_id', ''),
            'incident_responder_name': data.get('incident_responder_name', '')
        }
        summary_data.append(incident_comment)

    headers = get_headers_from_summary_data(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=headers, removeNull=True)
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

    headers = get_headers_from_summary_data(readable_output)
    markdown = tableToMarkdown(title, camelize(readable_output, "_"), headers=headers,
                               removeNull=True)
    return markdown


def extract_raw_data(data: list | dict, ignore_key: list[str] = [], prefix: str | None = None) -> dict:
    """
     Retrieve Json data according and mapping field Name and value
     Args:
         data (dict or list): Data ``dict`` or ``list``
         ignore_key (List): Ignore Key List
         prefix (str): Optional Added prefix in field name
     Returns:
         Return dict according to table field name and value
     """
    dataset: dict = {}
    if isinstance(data, dict):
        for key, val in data.items():
            if key not in ignore_key:
                field_name = f'{prefix}_{key}' if prefix else f'{key}'
                dataset[field_name] = val

    elif isinstance(data, list):
        cnt = 0
        for d in data:
            for key, val in d.items():
                if key not in ignore_key:
                    field_name = f'{prefix}_{key}_{cnt}' if prefix else f'{key}_{cnt}'
                    dataset[field_name] = val
            cnt = cnt + 1
    else:
        raise ValueError('Unable to determined "data" argument type. Data must be either list or dict')

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


def post_request_body(args: dict, page_limit: int = 1) -> dict:
    """
    This function creates a default payload based on the demisto.args().
    Args:
        args: demisto.args()
        page_limit: Page Limit (int)
    Returns:
        Return arguments dict.
    """
    # Default payload
    payload: dict[str, Any] = {'verb': 'query'}
    page_size = args.get('page_size')
    max_limit = args.get('limit', DEFAULT_PAGE_SIZE)

    if page_size:
        if page_limit >= max_limit:
            # in case user pass the page_size or limit is less than page_size
            payload['limit'] = page_limit
    else:
        payload['limit'] = page_limit if page_limit != DEFAULT_PAGE_SIZE else max_limit

    from_time = iso_creation_date(args.get('start_time', ''))
    to_time = iso_creation_date(args.get('end_time', ''))

    if from_time:
        payload['start_time'] = from_time

    if to_time:
        payload['end_time'] = to_time

    return payload


def get_params_query(args: dict, page_limit: int = 0) -> dict:
    """
    This function creates a query param based on the demisto.args().
    Args:
        args: demisto.args()
        page_limit: Page Limit (int)
    Returns:
        Return arguments dict.
    """
    query_param: dict = {}
    ip = args.get('ip')
    url = args.get('url')
    md5 = args.get('md5')
    sha256 = args.get('sha256')

    if ip:
        check_valid_indicator_value('ip', ip)

    if md5:
        check_valid_indicator_value('md5', md5)

    if sha256:
        check_valid_indicator_value('sha256', sha256)

    max_limit = args.get('limit', DEFAULT_PAGE_SIZE)
    page_size = args.get('page_size')

    if page_size and (page_limit > max_limit):
        # in case user pass the page_size or limit, limit will ignore
        query_param['limit'] = page_limit
    else:
        query_param['limit'] = page_limit if page_limit != DEFAULT_PAGE_SIZE else max_limit

    query_param['ip'] = ip
    query_param['url'] = url
    query_param['sha256'] = sha256
    query_param['id'] = arg_to_number(args.get('allowlist_id'), arg_name='allowlist_id')
    query_param['domain'] = args.get('domain')

    return query_param


def check_valid_indicator_value(indicator_type: str, indicator_value: str) -> bool:
    """
    Check the validity of indicator values
    Args:
        indicator_type: Indicator type provided in the command
            Possible Indicator type are : sha256, urls, ip, md5
        indicator_value: Indicator value provided in the command
    Returns:
        True if the provided indicator values are valid
    """
    if indicator_type == 'ip':
        if not is_ip_valid(indicator_value):
            raise ValueError(f'"{indicator_value}" is not a valid IP')
        return True

    hash_to_regex: dict[str, Any] = {
        'sha256': sha256Regex,
        'urls': urlRegex,
        'md5': md5Regex
    }
    if indicator_type in hash_to_regex:
        if not re.match(hash_to_regex[indicator_type], indicator_value):
            raise ValueError(f'{indicator_value} is not a valid {indicator_type}')
    else:
        raise ValueError(f'Indicator {indicator_type} type does not support')

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

    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    return raw_response


def get_incident_uuid(client: Client, args: dict[str, Any]):
    """
      Get the incident UUID
      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
        Return Incident UUID
    """
    data_list = get_incident_raw_response('/atpapi/v2/incidents', client, args, 1).get('result', [])
    if data_list:
        if uuid := data_list[0].get('uuid'):
            return uuid
    else:
        raise DemistoException(f'Either Incident does not exist or Unable to search incident {args.get("incident_id")} '
                               f'which is older than 30 days.\n'
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
        message = 'ok' if res else ''
    except Exception as err:
        raise DemistoException(f'Failed to execute. Error {err}')

    return message


def get_domain_file_association_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List of Domain and File association
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object
    """
    endpoint = '/atpapi/v2/associations/entities/domains-files'

    payload, limit, offset, page_size = get_request_payload(args, 'association')
    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    title = compile_command_title_string(
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
    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    title = compile_command_title_string(
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
    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    title = compile_command_title_string(
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

    if response.status_code == 204:
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
    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = compile_command_title_string(
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

    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = compile_command_title_string(
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

    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
    title = compile_command_title_string(
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
    raw_response = client.query_request_api(method='GET', url_suffix=endpoint, params=payload, json_data={})

    title = compile_command_title_string(
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

    raw_response = client.query_request_api(method='GET', url_suffix=endpoint, params=payload, json_data={})

    title = compile_command_title_string(
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


def get_endpoint_command(client: Client, args: dict[str, Any], command: str) -> CommandResults:
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
        command: Demisto.command

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    endpoint = "/atpapi/v2/commands"
    device_uid = args.get('device_id')
    file_sha2 = args.get('sha2')
    command_id = args.get('command_id')

    if command == 'symantec-edr-endpoint-delete-file':
        if not device_uid or not file_sha2:
            raise DemistoException('Invalid Arguments. '
                                   'Both "device_id" and "sha2" arguments is required for endpoint delete action')
        payload = {
            'action': 'delete_endpoint_file',
            'targets': argToList({'device_uid': device_uid, 'hash': file_sha2})
        }
    elif command == 'symantec-edr-endpoint-cancel-command':
        payload = {'action': 'cancel_command', 'targets': argToList(command_id)}
    elif command == 'symantec-edr-endpoint-isolate':
        payload = {'action': 'isolate_endpoint', 'targets': argToList(device_uid)}
    elif command == 'symantec-edr-endpoint-rejoin':
        payload = {'action': 'rejoin_endpoint', 'targets': argToList(device_uid)}
    else:
        raise DemistoException('Endpoint Command action not found.')

    raw_response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)
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

    payload = post_request_body(args)
    raw_response: dict[str, Any] = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    title = "Command Status"
    summary_data = {
        "state": raw_response.get('state'),
        "Command Issuer Name": raw_response.get('command_issuer_name'),
    }

    if result := raw_response.get('status', ()):
        for status in result:
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
    priority_list = [rev_incident_priority.get(i) for i in client.fetch_priority]  # type: ignore
    priority = priority_list[0] if len(priority_list) == 1 else seperator.join(map(str, priority_list))

    state_list = [rev_incident_state.get(i) for i in client.fetch_status]  # type: ignore
    state = state_list[0] if len(state_list) == 1 else seperator.join(map(str, state_list))

    last_run = demisto.getLastRun()
    demisto.debug(f'Last Run Object : {last_run}')

    payload = {
        "verb": "query",
        "limit": client.fetch_limit,
        "query": f'priority_level: ({priority}) AND state: ({state})'
    }
    demisto.debug(f'limit: {client.fetch_limit}, priority_level: ({priority}) AND state: ({state})')
    # demisto.getLastRun() will return an obj with the previous run in it.
    # set First Fetch starting time in case running first time or reset
    start_time = iso_creation_date(client.first_fetch)
    start_time_n, end_time = get_fetch_run_time_range(last_run=last_run, first_fetch=client.first_fetch)

    if last_run and 'time' in last_run:
        start_time_lastrun = iso_creation_date(last_run.get('time'))

    payload['start_time'] = start_time if not last_run else start_time_lastrun
    results = client.query_request_api(method='POST', url_suffix='/atpapi/v2/incidents', params={}, json_data=payload
                                       ).get('result', [])

    incidents, events_result, comments_result = [], [], []
    # Map severity to Demisto severity for incident creation
    xsoar_severity_map = {'High': 3, 'Medium': 2, 'Low': 1}

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
                comments_result = client.query_request_api(method='POST',
                                                           url_suffix=f'/atpapi/v2/incidents/{incident_uuid}/comments',
                                                           params={},
                                                           json_data=payload).get('result', [])

            # Fetch incident for event if set as true
            if client.is_incident_event:
                payload = {
                    "verb": "query",
                    "query": f'incident: {incident_uuid}',
                    "start_time": start_time
                }
                events_result = client.query_request_api(method='POST',
                                                         url_suffix='/atpapi/v2/incidentevents',
                                                         params={},
                                                         json_data=payload).get('result', [])

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

    # remove duplicate incidents which were already fetched
    incidents_insert = filter_incidents_by_duplicates_and_limit(
        incidents_res=incidents, last_run=last_run, fetch_limit=client.fetch_limit, id_field='name'
    )

    end_time = iso_creation_date('now')
    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents_insert,
        fetch_limit=client.fetch_limit,
        start_fetch_time=start_time_n,
        end_fetch_time=end_time,
        look_back=30,
        created_time_field='occurred',
        id_field='name',
        date_format=SYMANTEC_ISO_DATE_FORMAT
    )

    demisto.debug(f'last run at the end of the incidents fetching {last_run},'
                  f'incident count : {len(incidents)},'
                  f'Incident insert: {len(incidents_insert)}')
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

    response = client.query_request_api(method='GET',
                                        url_suffix=endpoint,
                                        params={},
                                        json_data={})

    file_res = client.query_request_api(method='GET',
                                        url_suffix=f'/atpapi/v2/entities/files/{sha2}',
                                        params={},
                                        json_data={})
    response |= file_res

    # Sandbox verdict
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


def check_sandbox_status(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
     Query file Sandbox command status,
     Args:
         client: client object to use.
         args: all command arguments, usually passed from ``demisto.args()``.
     Returns:
         CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
             result.
    """
    title = "File Sandbox Status"
    if command_id := args.get('command_id'):
        endpoint = f'/atpapi/v2/sandbox/commands/{command_id}'
        try:
            response = client.query_request_api(method='GET',
                                                url_suffix=endpoint,
                                                params={},
                                                json_data={})
        except Exception as e:
            raise DemistoException(f'Unable to get Sandbox Status. Error {e}')
    else:
        raise DemistoException('Command ID missing.')

    # Query Sandbox Command Status
    summary_data = {}
    sandbox_status = response.get("status", ((),))[0]
    if sandbox_status:
        summary_data = {
            'command_id': command_id,
            'status': SANDBOX_STATE.get(str(sandbox_status.get('state'))),
            'message': sandbox_status.get('message'),
            'target': sandbox_status.get('target'),
            'error_code': sandbox_status.get('error_code')
        }

    if summary_data:
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

    sha2 = args.get('file', '')
    if not re.match(sha256Regex, sha2):
        raise ValueError(f'SHA256 value {sha2} is invalid')

    endpoint = '/atpapi/v2/sandbox/commands'
    payload = {
        'action': 'analyze',
        'targets': argToList(sha2)
    }
    response = client.query_request_api(method='POST', url_suffix=endpoint, params={}, json_data=payload)

    # Get Issue Sandbox Command
    title = "Issue Sandbox Command"
    summary_data = {
        'sha2': sha2,
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
    demisto.debug(f'-- Polling Command --\nArguments : {args}')
    demisto.debug(f'Integration Global Context Data: {demisto.getIntegrationContext()}')

    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs: int = args.get('interval_in_seconds', DEFAULT_INTERVAL)
    timeout_in_seconds: int = args.get('timeout_in_seconds', DEFAULT_TIMEOUT)

    # Check for ongoing file scanning command_id if exist
    if pre_cmd_id := demisto.getIntegrationContext().get('command_id'):
        args['command_id'] = pre_cmd_id
    # first run ...
    if 'command_id' not in args:
        # command_results = issue_sandbox_command(client, args)
        outputs: Any[object] = issue_sandbox_command(client, args).outputs
        command_id = outputs.get('command_id')

        if command_id is not None:
            if global_integration_context := demisto.getIntegrationContext():
                global_integration_context['command_id'] = command_id
                demisto.setIntegrationContext(global_integration_context)
            else:
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
    outputs = status_func(client, args).outputs
    status = outputs.get('status')
    if status == 'Completed':
        # # action was completed
        if global_integration_context := demisto.getIntegrationContext():
            del global_integration_context['command_id']
            demisto.setIntegrationContext(global_integration_context)
        return results_func(client, args)
    elif status == 'Error':
        if global_integration_context := demisto.getIntegrationContext():
            del global_integration_context['command_id']
            demisto.setIntegrationContext(global_integration_context)

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


def file_scheduled_polling_command(client: Client, args: Dict[str, Any]):
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
        proxy = params.get('proxy', False)

        # Fetches Incident Parameters
        first_fetch_time = params.get('first_fetch', '3 days').strip()
        fetch_limit = arg_to_number(params.get('max_fetch', 50))
        fetch_incident_event = params.get('isIncidentsEvent', False)
        fetch_comments = params.get('isIncidentComment', False)
        fetch_status = argToList(params.get('fetch_status', 'New'))
        fetch_priority = argToList(params.get('fetch_priority', 'High,Medium'))

        client = Client(base_url=server_url, verify=verify_certificate, proxy=proxy, client_id=client_id,
                        client_secret=client_secret, first_fetch=first_fetch_time, fetch_limit=fetch_limit,
                        is_incident_event=fetch_incident_event, is_fetch_comment=fetch_comments,
                        fetch_status=fetch_status, fetch_priority=fetch_priority)

        client.get_access_token_or_login()

        demisto.info(f'Command being called is {demisto.command()}')

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
            "file": file_scheduled_polling_command
        }
        command_output: CommandResults | str = ""
        if command == "test-module":
            command_output = test_module(client)
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)
            command_output = "OK"
        elif command in ['symantec-edr-endpoint-isolate',
                         'symantec-edr-endpoint-rejoin',
                         'symantec-edr-endpoint-delete-file',
                         'symantec-edr-endpoint-cancel-command']:
            # isolate_endpoint, re-join, delete_endpoint_file, cancel_command
            command_output = get_endpoint_command(client, args, command)
        elif command in commands:
            command_output = commands[command](client, args)
        else:
            raise NotImplementedError(f"command {command} is not supported")

        return_results(command_output)

# Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError: {e}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
