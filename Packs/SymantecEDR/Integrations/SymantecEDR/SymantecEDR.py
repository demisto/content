"""
Symantec Endpoint Detection and Response (EDR) On-Prem integration with Symantec-EDR
"""
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import dateparser
import urllib3
from typing import Callable

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 600

# Symantec TOKEN timeout 60 minutes
SESSION_TIMEOUT_SEC = 3600
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
ISO8601_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
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

EVENT_NODE_ROLE: dict[str, str] = {
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
    def headers(self) -> dict:
        """
        Client headers method
        Returns:
            self.headers
        """
        if self.access_token is None:  # for logging in, before self.access_token is set
            return {'Content-Type': 'application/json'}

        return {'Authorization': f'Bearer {self.access_token}', 'Content-Type': 'application/json'}

    @staticmethod
    def get_access_token_from_context(global_context: dict[str, Any]) -> str | None:
        """
        Symantec EDR on-premise get previous access token from global integration context
        Args:
            global_context(dict): Integration Context data
        Returns:
            return token or None
        """
        if save_timestamp := global_context.get('access_token_timestamp'):
            now_timestamp = int(time.time())
            if token := global_context.get('access_token'):
                time_diff = int(now_timestamp - save_timestamp)
                if time_diff <= SESSION_TIMEOUT_SEC:
                    return token
                else:
                    LOG('Access token expired')
        return None

    def get_access_token_or_login(self) -> None:
        """
        Generate Access token
        """
        global_context = demisto.getIntegrationContext()
        if last_access_token := self.get_access_token_from_context(global_context):
            self.access_token = last_access_token
            LOG("Access token still active. Re-use the same token")
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
            except requests.exceptions.HTTPError as exc:
                if error_msg := HTTP_ERRORS.get(exc.response.status_code):
                    raise DemistoException(f'{error_msg}', res=exc.response) from exc
                else:
                    raise

            LOG("Generated Access token.")
            self.access_token = response.json().get("access_token")
            timestamp_string = int(time.time())
            demisto.setIntegrationContext(
                demisto.getIntegrationContext() | {
                    'access_token': self.access_token, 'access_token_timestamp': timestamp_string}
            )

        return None

    def http_request(self, method: str, endpoint: str, params: dict[str, Any] = None,
                     json_data: Union[dict[str, Any], list] = None,
                     ignore_empty_response: bool = False) -> requests.Response:
        """
        Call Symantec EDR On-prem POST and GET Request API
        Args:
            method (str): Request Method support POST and GET
            endpoint (str): API endpoint
            params (dict): URL parameters to specify the query for GET.
            json_data (dict): The dictionary to send in a request for POST.
            ignore_empty_response (bool): Default is False, For PATCH method provide this argument as True
        Returns:
            Return the raw api response from Symantec EDR on-premise API.
        """
        try:
            response = self._http_request(
                method=method.upper(),
                url_suffix=endpoint,
                headers=self.headers,
                json_data=json_data,
                params=params,
                resp_type='response',
                allow_redirects=False,
                return_empty_response=ignore_empty_response
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            if error_msg := HTTP_ERRORS.get(exc.response.status_code):
                raise DemistoException(f'{error_msg}', res=exc.response) from exc
            else:
                raise

        return response

    def list_domain_file(self, payload: dict) -> dict[str, Any]:
        """
        Client method for domain file association list
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/associations/entities/domains-files',
            params={},
            json_data=payload
        ).json()

    def list_endpoint_domain(self, payload: dict) -> dict[str, Any]:
        """
        Client method for endpoint domain association list
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/associations/entities/endpoints-domains',
            params={},
            json_data=payload
        ).json()

    def list_endpoint_file(self, payload: dict) -> dict[str, Any]:
        """
        Client method for endpoint file association list
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/associations/entities/endpoints-files',
            params={},
            json_data=payload
        ).json()

    def get_audit_event(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get Audit Events
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/auditevents',
            params={},
            json_data=payload
        ).json()

    def get_event_list(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get Events List
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/events',
            params={},
            json_data=payload
        ).json()

    def get_system_activity(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get System Activity
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/systemactivities',
            params={},
            json_data=payload
        ).json()

    def get_event_for_incident(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get event for Incident
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/incidentevents',
            params={},
            json_data=payload
        ).json()

    def get_incident(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get Incident
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/incidents',
            params={},
            json_data=payload
        ).json()

    def get_incident_comment(self, payload: dict, uuid: str) -> dict[str, Any]:
        """
        Client method for get Incident
        Args:
            payload (dict): request json body
            uuid (str): Incident Unique ID
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint=f'/atpapi/v2/incidents/{uuid}/comments',
            params={},
            json_data=payload
        ).json()

    def add_incident_comment(self, uuid: str, value: str) -> requests.Response:
        """
        Client method for add Incident comment

        Args:
            uuid : Incident Unique ID
            value : Incident Comment
        Returns:
            return response json
        """
        request_data: list[dict[str, Any]] = [
            {'op': 'add', 'path': f'/{uuid}/comments', 'value': value[:512]}
        ]
        # json.dumps([payload])
        return self.http_request(
            method='PATCH',
            endpoint='/atpapi/v2/incidents',
            params={},
            json_data=request_data,
            ignore_empty_response=True
        )

    def close_incident(self, uuid: str, value: int) -> requests.Response:
        """
        Client method for close incident

        Args:
            uuid : Incident Unique ID
            value : Incident Comment
        Returns:
            return response json
        """
        request_data: list[dict[str, Any]] = [{
            'op': 'replace',
            'path': f'/{uuid}/state',
            'value': value
        }]
        return self.http_request(
            method='PATCH',
            endpoint='/atpapi/v2/incidents',
            params={},
            json_data=request_data,
            ignore_empty_response=True
        )

    def update_incident(self, uuid: str, value: int) -> requests.Response:
        """
        Client method for update incident Resolution

        Args:
            uuid : Incident Unique ID
            value : Incident Comment
        Returns:
            return response json
        """
        request_data: list[dict[str, Any]] = [{
            'op': 'replace',
            'path': f'/{uuid}/resolution',
            'value': value
        }]
        return self.http_request(
            method='PATCH',
            endpoint='/atpapi/v2/incidents',
            params={},
            json_data=request_data,
            ignore_empty_response=True
        )

    def get_file_instance(self, payload: dict, sha2: str | None) -> dict[str, Any]:
        """
        Client method for get file instance
        Args:
            payload (dict): request json body
            sha2 (str): file sha2 value
        Returns:
            return response json
        """
        endpoint = f'/atpapi/v2/entities/files/{sha2}/instances' if sha2 else '/atpapi/v2/entities/files/instances'

        return self.http_request(
            method='POST',
            endpoint=endpoint,
            params={},
            json_data=payload
        ).json()

    def get_domain_instance(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get domain instance
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/entities/domains/instances',
            params={},
            json_data=payload
        ).json()

    def get_endpoint_instance(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get endpoint instance
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/entities/endpoints/instances',
            params={},
            json_data=payload
        ).json()

    def get_allow_list(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get allow list
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='GET',
            endpoint='/atpapi/v2/policies/allow_list',
            params=payload,
            json_data={}
        ).json()

    def get_deny_list(self, payload: dict) -> dict[str, Any]:
        """
        Client method for get deny list
        Args:
            payload (dict): request json body
        Returns:
            return response json
        """
        return self.http_request(
            method='GET',
            endpoint='/atpapi/v2/policies/deny_list',
            params=payload,
            json_data={}
        ).json()

    def get_cancel_endpoint(self, command_id: str) -> dict[str, Any]:
        """
        Client method for cancel endpoint
        Args:
            command_id (str): command_id separate by commas
        Returns:
            return response json
        """
        payload = {'action': 'cancel_command', 'targets': argToList(command_id)}
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/commands',
            params={},
            json_data=payload
        ).json()

    def get_delete_endpoint(self, device_uid: str, file_sha2: str) -> dict[str, Any]:
        """
        Client method for delete endpoint
        Args:
            device_uid (str): Endpoint device id
            file_sha2 (str): Endpoint file sha2
        Returns:
            return response json
        """
        payload = {
            'action': 'delete_endpoint_file',
            'targets': [{'device_uid': device_uid, 'hash': file_sha2}]
        }
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/commands',
            params={},
            json_data=payload
        ).json()

    def get_isolate_endpoint(self, device_uid: str) -> dict[str, Any]:
        """
        Client method for Isolate endpoint
        Args:
            device_uid (str): Endpoint Device UUID
        Returns:
            return response json
        """
        payload = {'action': 'isolate_endpoint', 'targets': argToList(device_uid)}
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/commands',
            params={},
            json_data=payload
        ).json()

    def get_rejoin_endpoint(self, device_uid: str) -> dict[str, Any]:
        """
        Client method for Rejoin endpoint
        Args:
            device_uid (str): Endpoint Device UUID
        Returns:
            return response json
        """
        payload = {'action': 'rejoin_endpoint', 'targets': argToList(device_uid)}
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/commands',
            params={},
            json_data=payload
        ).json()

    def get_status_endpoint(self, command_id: str, payload: dict) -> dict[str, Any]:
        """
        Client method for get endpoint status
        Args:
            command_id (str): Endpoint command_id
            payload: request body

        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint=f'/atpapi/v2/commands/{command_id}',
            params={},
            json_data=payload).json()

    def get_sandbox_verdict_for_file(self, sha2: str) -> dict[str, Any]:
        """
        Client method for get sandbox verdict for specific file sha256
        Args:
            sha2 (str): File SHA256
        Returns:
            return response json
        """
        return self.http_request(
            method='GET',
            endpoint=f'/atpapi/v2/sandbox/results/{sha2}/verdict',
            params={},
            json_data={}).json()

    def get_file_entity(self, sha2: str) -> dict[str, Any]:
        """
        Client method for Get File Entity for specific SHA2
        Args:
            sha2 (str): File SHA256
        Returns:
            return response json
        """
        return self.http_request(
            method='GET',
            endpoint=f'/atpapi/v2/entities/files/{sha2}',
            params={},
            json_data={}).json()

    def get_sandbox_status(self, command_id: str) -> dict[str, Any]:
        """
        Client method to Get Sanbox Status for specific file
        Args:
            command_id (str): sandbox command ID
        Returns:
            return response json
        """
        return self.http_request(
            method='GET',
            endpoint=f'/atpapi/v2/sandbox/commands/{command_id}',
            params={},
            json_data={}).json()

    def submit_file_to_sandbox_analyze(self, payload: dict) -> dict[str, Any]:
        """
        Client method for sandbox analyze
        Args:
            payload: request body

        Returns:
            return response json
        """
        return self.http_request(
            method='POST',
            endpoint='/atpapi/v2/sandbox/commands',
            params={},
            json_data=payload
        ).json()


''' HELPER FUNCTIONS '''


def convert_to_iso8601(timestamp: str) -> str:
    """ Convert timestamp from iso 8601 format

    Args:
        timestamp: Any valid timestamp or provide timedelta e.g. now, "<n> days", "<n> weeks",
        "<n> months", "1 months ago"

    Returns: return timestamp in iso 8601 format.

    """
    if datetime_from_timestamp := dateparser.parse(timestamp, settings={'TIMEZONE': 'UTC'}):
        return f'{datetime_from_timestamp.strftime(ISO8601_DATE_FORMAT)[:23]}Z'
    else:
        raise ValueError(f'{timestamp} could not be parsed')


def extract_headers_for_readable_output(summary_data: list[dict]) -> list:
    """
    Symantec EDR formatting Readable output Header
    Args:
        summary_data (list[dict]): Human readable output summary data

    Returns:
        Return string headers to camel case.

    """
    if not summary_data:
        raise DemistoException('No Readable output data found to display.')

    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    return [camelize_string(column) for column in headers]


def get_data_of_current_page(response_data: list[dict[str, Any]], offset: int = 0, limit: int = 0) -> list:
    """
    Retrieve list element based on offset and limit
    Args:
        response_data (list): Raw API result list
        offset (int) : Offset
        limit (int) : Page Limit

    Returns:
        Return List of object from the response according to the limit, page and page_size.

    """

    if offset >= 0 and limit >= 0:
        demisto.debug(f'I am here {offset} <=> {limit} ...')
        return response_data[offset:(offset + limit)]
    return response_data[:limit]


def compile_command_title_string(context_name: str, args: dict, record: int) \
        -> str:
    """
    Symantec EDR on-premise display title and pagination
        If page/page_size are input, then limit should be ignored.
        If only page or page_size were input,
        then the default for the other that is missing will be added in the code.
        limit can work by itself independently, without page and page_size
    Args:
        context_name (str): Commands sub context name
        args (dict): demisto.args()
        record (int): Total Number of Records
    Returns:
        Return the title for the readable output

    """
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))

    if page is None and page_size:
        page = 1

    if page_size is None and page:
        page_size = DEFAULT_PAGE_SIZE
        if DEFAULT_PAGE_SIZE > record:
            page_size = record

    if (page and page_size) and (page > 0 and page_size > 0):
        return f'{context_name} List\nShowing page {page}\n' \
               f'Showing {page_size} out of {record} Record(s) Found.'

    return f"{context_name} List"


def parse_process_sub_object(data: dict) -> dict:
    """
    Retrieve event process sub object data
    Args:
        data (dict): Event process data
    Returns:
        return process data
    """
    ignore_key_list: list[str] = ['file', 'user']
    return extract_raw_data(data, ignore_key_list)


def parse_attacks_sub_object(data: list[dict]) -> dict:
    """
    Retrieve event attacks sub object data
    Args:
        data (dict): Event attacks data

    Returns:
        return attacks data
    """
    ignore_key_list: list[str] = ['tactic_ids', 'tactic_uids']
    attacks_dict = extract_raw_data(data, ignore_key_list, prefix='attacks')

    for attack in data:
        cnt = 0
        # tactic_ids
        if tactic_ids_list := attack.get('tactic_ids', []):
            tactic_ids_dict = {
                f'attacks_tactic_ids_{cnt}': convert_list_to_str(tactic_ids_list)
            }
            attacks_dict |= tactic_ids_dict

        # tactic uids
        if tactic_uids_list := attack.get('tactic_uids', []):
            tactic_uids_dict = {
                f'attacks_tactic_uids_{cnt}': convert_list_to_str(tactic_uids_list)
            }
            attacks_dict |= tactic_uids_dict

        cnt += 1
    return attacks_dict


def parse_event_data_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event data sub object data
    Args:
        data (dict): Event data
    Returns:
        return event data
    """
    result: dict = {}
    for key in (
        'event_data_sepm_server',
        'event_data_search_config',
        'event_data_atp_service',
    ):
        if values := data.get(key):
            result |= extract_raw_data(values, [], key)

    return result


def parse_enriched_data_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event enriched sub object data
    Args:
        data (dict): Event enriched data
    Returns:
        return enriched data
    """
    return extract_raw_data(data, [], 'enriched_data')


def parse_user_sub_object(data: dict[str, Any], obj_prefix: Optional[str]) -> dict:
    """
    Retrieve event user sub object data
    Args:
        data (dict): Event user data
        obj_prefix (optional) : Object prefix name
    Returns:
        return user data
    """
    prefix = f'{obj_prefix}_user' if obj_prefix else 'user'
    return extract_raw_data(data, [], prefix)


def parse_xattributes_sub_object(data: dict[str, Any], obj_prefix: Optional[str]) -> dict:
    """
    Retrieve event xattributes sub object data
    Args:
        data (dict): Event xattribute data
        obj_prefix (optional) : Object prefix name
    Returns:
        return event data
    """
    prefix = f'{obj_prefix}_xattributes' if obj_prefix else 'xattributes'
    return extract_raw_data(data, [], prefix)


def parse_event_actor_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event actor object data
    Args:
        data (dict): Event actor data
    Returns:
        return event actor data
    """
    # Sub Object will be fetched separately
    ignore_key: list[str] = ['file', 'user', 'xattributes']

    result = extract_raw_data(data, ignore_key, 'event_actor')

    for key, func in (
        ('file', parse_file_sub_object),
        ('user', parse_user_sub_object),
        ('xattributes', parse_xattributes_sub_object),
    ):
        if values := data.get(key):
            result |= func(values, key)  # type: ignore[operator]
    return result


def parse_file_sub_object(data: dict[str, Any], obj_prefix: Optional[str]) -> dict:
    """
    Retrieve event file object data
    Args:
        data (dict): Event monitor data
        obj_prefix (optional) : added object prefix
    Returns:
        return to event dict
    """
    prefix = f'{obj_prefix}_file' if obj_prefix else 'file'
    return extract_raw_data(data, ['signature_value_ids'], prefix)


def parse_monitor_source_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event monitor object data
    Args:
        data (dict): Event monitor data
    Returns:
        return to event dict
    """
    return extract_raw_data(data, [], prefix='monitor_source')


def parse_connection_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event connection object data and return Event dict
    Args:
        data (dict): Event connection data
    Returns:
        return Data dict
    """
    return extract_raw_data(data, [], prefix='connection')


def convert_list_to_str(data: Optional[list] = None) -> str:
    """
    Convert list value to string with comma seperator
    Args:
        data (list): values
    Returns:
        return string
    """
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
            result |= func(values)  # type: ignore[operator]

    for item in {'edr_data_protocols', 'edr_files', 'source_port', 'target_port'}:
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

    headers = extract_headers_for_readable_output(summary_data)
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
        event_data['atp_node_role'] = EVENT_NODE_ROLE.get(str(event_data.get('atp_node_role')))
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

    headers = extract_headers_for_readable_output(summary_data)
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

    headers = extract_headers_for_readable_output(summary_data)
    return tableToMarkdown(
        title,
        camelize(summary_data, "_"),
        headers=headers,
        removeNull=True
    )


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

    headers = extract_headers_for_readable_output(summary_data)
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

    headers = extract_headers_for_readable_output(summary_data)
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

    headers = extract_headers_for_readable_output(summary_data)
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

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(title, camelize(summary_data, '_'), headers=headers, removeNull=True)
    return markdown, summary_data


def generic_readable_output(results: list[dict], title: str) -> str:
    """
     Generic Readable output data for markdown
     Args:
         results (list): Generic Endpoint Response results data
         title (str): Title string
     Returns:
         A string representation of the Markdown table
     """
    readable_output = []
    for data in results:
        # ignore_key_list: list[str] = []
        row = extract_raw_data(data, [])
        readable_output.append(row)

    headers = extract_headers_for_readable_output(readable_output)
    return tableToMarkdown(title, camelize(readable_output, "_"), headers=headers, removeNull=True)


def extract_raw_data(result: list | dict, ignore_key: list, prefix: str = None) -> dict:
    """
     Retrieve response result data
     Args:
         result (dict or list): Data ``dict`` or ``list``
         ignore_key (List): Ignore Key List
         prefix (str): Optional Added prefix in field name
     Returns:
         Return dict according to table field name and value
     """
    dataset: dict = {}
    if not isinstance(result, (dict, list)):
        raise ValueError('Unable to determined result object type. Data must be either list or dict')

    raw_data = {k: v for attribute in result for (k, v) in attribute.items()} if isinstance(result, list) \
        else result

    for key, value in raw_data.items():
        if key not in ignore_key:
            field_name = f'{prefix}_{key}' if prefix else f'{key}'
            dataset[field_name] = value

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
        condition = f'{condition} OR {value}' if condition else value

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
    query = args.get('query', '')

    if query and (ids or priority or status):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition: str = ''
    if ids is not None:
        condition = f'atp_incident_id: {ids}'

    if priority is not None:
        condition = (
            f'{condition} AND priority_level: {priority} '
            if condition
            else f'priority_level: {priority}'
        )

    if status is not None:
        condition = (
            f'{condition} AND state: {status}'
            if condition
            else f'state: {status}'
        )

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
        condition = (
            f'{condition} AND severity_id: {severity}'
            if condition
            else f'severity_id: {severity}'
        )

    if status:
        condition = (
            f'{condition} AND status_id: {status}'
            if condition
            else f'status_id: {status}'
        )

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
    query_type = args.get('search_object', '')
    query_value = args.get('search_value', '')
    query = args.get('query', '')

    if query_type and query_type not in SEARCH_QUERY_TYPE:
        raise DemistoException(f'Invalid Search Type! Only supported type are : {SEARCH_QUERY_TYPE}')

    if query and (query_type or query_value):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    if query_type == 'sha256':
        condition = query_search_condition('sha256', query_value)
        return f'sha2: ({condition})'
    elif query_type == 'device_uid':
        condition = query_search_condition('device_uid', query_value, ignore_validation=True)
        return f'device_uid: ({condition})'
    elif query_type == 'domain':
        condition = query_search_condition('domain', query_value, ignore_validation=True)
        return f'data_source_url_domain: ({condition})'
    else:
        return query


# def post_request_body(args: dict, limit: int = 1) -> dict:
def post_request_body(args: dict) -> dict[str, Any]:
    """
    This function creates a default payload based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return request body payload.
    """
    # Default payload
    limit, offset = get_query_limit(args)
    payload: dict[str, Any] = {
        'verb': 'query',
        'limit': limit,
        'offset': offset
    }
    # 2022-10-31T00:00:00.000000
    if args.get('start_time'):
        if from_time := convert_to_iso8601(args.get('start_time', '')):
            payload['start_time'] = from_time

    if args.get('end_time'):
        if to_time := convert_to_iso8601(args.get('end_time', '')):
            payload['end_time'] = to_time

    return payload


def pagination(page: int | None, page_size: int | None) -> tuple[int, int]:
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
        # Default OFFSET value is 0 Or Page = 0
        page = DEFAULT_OFFSET
    elif page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)

    if page_size is None:
        page_size = DEFAULT_PAGE_SIZE
    elif page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    limit = (page * page_size) if page > 0 else page_size
    offset = (page - 1) * page_size if page > 0 else page

    return limit, offset


def get_query_limit(args: dict) -> tuple[int, int]:
    """
    This function determine the query limit based on the demisto.args().

    Scenarios:
        If page/page_size are input, then limit should be ignored.
        If only page or page_size were input,
        then the default for the other that is missing will be added in the code.
        Limit can work by itself independently, without page and page_size

    Args:
        args: demisto.args()
    Returns:
        limit (int)
        offset (int)
    """
    # Set default value to page, page_limit and page_size
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size'), arg_name='page_size')

    if page or page_size:
        page_limit, offset = pagination(page, page_size)
        return page_limit, offset

    limit: int = args.get('limit', DEFAULT_PAGE_SIZE)
    return limit, DEFAULT_OFFSET


def get_params_query(args: dict) -> dict:
    """
    This function creates a query param based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return arguments dict.
    """
    if ip := args.get('ip'):
        check_valid_indicator_value('ip', ip)

    if md5 := args.get('md5'):
        check_valid_indicator_value('md5', md5)

    if sha256 := args.get('sha256'):
        check_valid_indicator_value('sha256', sha256)

    limit, offset = get_query_limit(args)
    return {
        'limit': limit,
        'offset': offset,
        'ip': ip,
        'url': args.get('url'),
        'sha256': sha256,
        'id': arg_to_number(args.get('allowlist_id'), arg_name='allowlist_id'),
        'domain': args.get('domain')
    }


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
    if indicator_type not in hash_to_regex:
        raise ValueError(f'Indicator {indicator_type} type id not support')

    if not re.match(hash_to_regex[indicator_type], indicator_value):
        raise ValueError(f'{indicator_value} is not a valid {indicator_type}')

    return True


def get_incident_uuid(client: Client, args: dict[str, Any]) -> str | None:
    """
      Get the incident UUID
      Args:
          client: client object to use.
          args: all command arguments, usually passed from ``demisto.args()``.
      Returns:
        Return Incident UUID
    """
    payload = post_request_body(args)

    # offset does not support by API therefore need to be removed
    payload.pop('offset')

    # search query as Lucene query string
    if search_query := get_incident_filter_query(args):
        payload['query'] = search_query

    if not (
        raw_data := client.get_incident(payload).get('result', [])
    ):
        raise DemistoException(f'Incident ID not found {args.get("incident_id")}, '
                               f'May be incident ID is older than 30 days, '
                               f'If that is the case try with time range Arguments')
    return uuid if (uuid := raw_data[0].get('uuid')) else None


def get_request_payload(args: dict[str, Any], query_type: Optional[str] = None) -> dict:
    """
    Create payload for request the endpoints
    Args:
        args: all command arguments, usually passed from ``demisto.args()``.
        query_type: query type : association, event, incident, allow_list, deny_list
    Returns:
        payload (dict): Return payload for request body
    """
    if query_type in {'allow_list', 'deny_list'}:
        limit = arg_to_number(args.get('limit'))
        if limit and (limit < 10 or limit > 1000):
            raise ValueError('Invalid input limit: Value between Minimum = 10 , Maximum = 1000')
        payload = get_params_query(args)
    else:
        payload = post_request_body(args)

    # search query as Lucene query string
    if query_type == 'association':
        search_query = get_association_filter_query(args)
    elif query_type == 'event':
        search_query = get_event_filter_query(args)
    elif query_type == 'incident':
        search_query = get_incident_filter_query(args)
    else:
        # default
        search_query = args.get('query', '')

    if search_query:
        payload['query'] = search_query

    return payload


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
    message = ''
    try:
        response_json = client.http_request(
            method='POST',
            endpoint='/atpapi/v2/incidents',
            params={},
            json_data={"verb": "query", 'limit': 1})
        if response_json:
            message = 'ok'

    except Exception as e:
        raise DemistoException(
            '{e}\nMake sure the Server URL and port are correctly set'
        ) from e
    return message


def get_domain_file_association_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List of Domain and File association
    Args:
        client: Symantec EDR on-premise client object.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object
    """
    payload = get_request_payload(args, 'association')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.list_domain_file(payload)

    title = compile_command_title_string('Domain File Association', args, int(raw_response.get('total', 0)))

    if printable_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
        readable_output = generic_readable_output(printable_result, title)
    else:
        readable_output = 'No Domain and File association data to present.'

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.DomainFileAssociation',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=printable_result,
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
    payload = get_request_payload(args, 'association')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.list_endpoint_domain(payload)
    title = compile_command_title_string('Endpoint Domain Association', args, int(raw_response.get('total', 0)))

    if printable_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
        readable_output = generic_readable_output(printable_result, title)
    else:
        readable_output = 'No Endpoint Domain association data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointDomainAssociation',
        outputs_key_field='',
        outputs=printable_result,
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
    payload = get_request_payload(args, 'association')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.list_endpoint_file(payload)
    title = compile_command_title_string('Endpoint File Association', args, int(raw_response.get('total', 0)))

    if printable_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
        readable_output = generic_readable_output(printable_result, title)
    else:
        readable_output = 'No Endpoint File association data to present.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EndpointFileAssociation',
        outputs_key_field='',
        outputs=printable_result,
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
    payload = get_request_payload(args, 'event')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_audit_event(payload)
    title = compile_command_title_string('Audit Event', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
    payload = get_request_payload(args, 'event')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_event_list(payload)
    title = compile_command_title_string('Event', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
    payload = get_request_payload(args, 'event')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_system_activity(payload)
    title = compile_command_title_string('System Activities', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
    payload = get_request_payload(args, 'event')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_event_for_incident(payload)
    title = compile_command_title_string('Event for Incident', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
    payload = get_request_payload(args, 'incident')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_incident(payload)
    title = compile_command_title_string('Incident', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
    incident_id = args.pop("incident_id", None)
    if uuid is None:
        raise ValueError("Error: No Incident UUID found. Provide valid Incident IDs.")

    payload = get_request_payload(args, 'incident')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_incident_comment(payload, uuid)
    title = compile_command_title_string('Incident Comment', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
          CommandResults: A ``CommandResults`` object that is then passed to ``return_results``,
          that contains an updated
              result.
    """
    action = args.get('action_type')
    if action not in INCIDENT_PATCH_ACTION:
        raise ValueError(f'Invalid Incident Patch Operation: Supported values are : {INCIDENT_PATCH_ACTION}')

    # Get UUID based on incident_id
    status = 0
    action_desc = ''
    if uuid := get_incident_uuid(client, args):
        # Incident Add Comment
        if action == 'add_comment':
            value = args.get('value', '')
            if not value:
                raise ValueError('No Incident comment found. Enter incident comment add to incident')

            action_desc = 'Add Comment'
            response = client.add_incident_comment(uuid, value)
            status = response.status_code

            # Incident Close Incident
        elif action == 'close_incident':
            action_desc = 'Close Incident'
            response = client.close_incident(uuid, 4)
            status = response.status_code

            # Incident Update Resolution
        elif action == 'update_resolution':
            action_desc = 'Update Status'
            if not args.get('value'):
                raise ValueError(f'Invalid Incident Resolution value. provide integer value'
                                 f'Resolution supported values were {INCIDENT_RESOLUTION}')
            response = client.update_incident(uuid, int(args.get('value', 0)))
            status = response.status_code

        else:
            raise DemistoException(
                f'Unable to perform Incident update. Only support by following action {INCIDENT_PATCH_ACTION}')

    if status == 204:
        summary_data = {
            'incident_id': args.get('incident_id'),
            'Message': 'Successfully Updated',
        }
        headers = list(summary_data.keys())
        readable_output = tableToMarkdown(f'Incident {action_desc}', summary_data, headers=headers, removeNull=True)
    else:
        readable_output = f'Failed {action}. Response from endpoint {status}'

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
    if sha2 := args.get('file_sha2'):
        check_valid_indicator_value('sha256', sha2)

    payload = get_request_payload(args)
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_file_instance(payload, sha2)
    title = compile_command_title_string('File Instances', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
        client: Symantec EDR on-premise client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    context_data: list = []
    payload = get_request_payload(args)
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_domain_instance(payload)
    title = compile_command_title_string('Domain Instances', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
        client: Symantec EDR on-premise client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    payload = get_request_payload(args)
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_endpoint_instance(payload)
    title = compile_command_title_string('Endpoint Instances', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
        client: Symantec EDR on-premise client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    payload = get_request_payload(args, 'allow_list')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_allow_list(payload)
    title = compile_command_title_string('Allow List Policy', args, int(raw_response.get('total', 0)))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
        client: Symantec EDR on-premise client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    payload = get_request_payload(args, 'deny_list')
    offset = int(payload.pop('offset', ''))
    limit = int(payload.get('limit', ''))

    raw_response = client.get_deny_list(payload)
    title = compile_command_title_string('Deny List Policy', args, raw_response.get('total', 0))

    if page_result := get_data_of_current_page(raw_response.get('result', []), offset, limit):
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
    device_uid = args.get('device_id', '')
    file_sha2 = args.get('sha2', '')
    command_id = args.get('command_id', '')

    if command == 'symantec-edr-endpoint-cancel-command':
        raw_response = client.get_cancel_endpoint(command_id)
        action_type = 'Cancel Endpoint'
    elif command == 'symantec-edr-endpoint-delete-file':
        if device_uid and file_sha2:
            raw_response = client.get_delete_endpoint(device_uid, file_sha2)
            action_type = 'Delete Endpoint'
        else:
            raise DemistoException('Invalid Arguments. '
                                   'Both "device_id" and "sha2" arguments is required for endpoint delete action')
    elif command == 'symantec-edr-endpoint-isolate':
        action_type = 'Isolate Endpoint'
        raw_response = client.get_isolate_endpoint(device_uid)
    elif command == 'symantec-edr-endpoint-rejoin':
        action_type = 'Rejoin Endpoint'
        raw_response = client.get_rejoin_endpoint(device_uid)
    else:
        raise DemistoException('Endpoint Command action not found.')

    title = f'Command {action_type}'

    summary_data = {
        "Message": raw_response.get('message'),
        "CommandId": raw_response.get('command_id')
    }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Command.{action_type}',
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
    command_id = args.get('command_id', '')
    readable_data = []
    payload = post_request_body(args)
    payload.pop('offset', 0)

    raw_response = client.get_status_endpoint(command_id, payload)

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
        title = "Command Status"
        readable_data.append(summary_data)
        readable_output = generic_readable_output(readable_data, title)
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
    priority_list = [rev_incident_priority.get(i) for i in client.fetch_priority]  # type: ignore[union-attr]
    priority = priority_list[0] if len(priority_list) == 1 else seperator.join(map(str, priority_list))

    state_list = [rev_incident_state.get(i) for i in client.fetch_status]  # type: ignore[union-attr]
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
    start_time = convert_to_iso8601(client.first_fetch)
    start_time_n, end_time = get_fetch_run_time_range(last_run=last_run, first_fetch=client.first_fetch)

    if last_run and 'time' in last_run:
        query_start_time = convert_to_iso8601(last_run.get('time'))
        payload['start_time'] = query_start_time
    else:
        payload['start_time'] = start_time
    demisto.debug(f'### get_incident payload: {payload} ###')
    # payload['start_time'] = start_time_lastrun if last_run else start_time
    result = client.get_incident(payload).get('result', [])

    incidents, events_result, comments_result = [], [], []
    if result:
        _, incidents_context = incident_readable_output(result)
        # Map severity to Demisto severity for incident creation
        xsoar_severity_map = {'High': 3, 'Medium': 2, 'Low': 1}

        for incident in incidents_context:
            incident_id = incident.get('incident_id')
            incident_uuid = incident.get("incident_uuid")

            # Get Incidents Comments if set as true
            if client.is_fetch_comment:
                payload = (
                    {"verb": "query"}
                    if last_run
                    else {"verb": "query", "start_time": start_time}
                )
                demisto.debug(f'=== get incident comment payload: {payload} incident_uuid: {incident_uuid} ===')
                comments_result = client.get_incident_comment(payload, incident_uuid).get('result', [])

            # Fetch incident for event if set as true
            if client.is_incident_event:
                payload = {
                    "verb": "query",
                    "query": f'incident: {incident_uuid}',
                    "start_time": start_time
                }
                demisto.debug(f'*** Event Incident payload: {payload} ***')
                events_result = client.get_event_for_incident(payload).get('result', [])

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

    end_time = convert_to_iso8601('now')
    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents_insert,
        fetch_limit=client.fetch_limit,
        start_fetch_time=start_time_n,
        end_fetch_time=end_time,
        look_back=30,
        created_time_field='occurred',
        id_field='name',
        date_format=ISO8601_DATE_FORMAT
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
    sha2 = args.get('file', '')

    response_verdict = client.get_sandbox_verdict_for_file(sha2)
    file_res = client.get_file_entity(sha2)

    response_verdict |= file_res
    # Sandbox verdict
    title = "Sandbox Verdict"
    if response_verdict:
        readable_output = generic_readable_output([response_verdict], title)
    else:
        readable_output = f'{title} does not have data to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.SandboxVerdict',
        outputs_key_field='',
        outputs=response_verdict,
        raw_response=response_verdict
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
    readable_data = []
    title = "File Sandbox Status"
    if not (command_id := args.get('command_id')):
        raise DemistoException('Command ID missing.')

    response = client.get_sandbox_status(command_id)
    # Query Sandbox Command Status
    summary_data = {}
    if sandbox_status := response.get("status"):
        for status in sandbox_status:
            summary_data = {
                'command_id': command_id,
                'status': SANDBOX_STATE.get(str(status.get('state', ''))),
                'message': status.get('message', ''),
                'target': status.get('target', ''),
                'error_code': status.get('error_code', '')
            }

    if summary_data:
        readable_data.append(summary_data)
        readable_output = generic_readable_output(readable_data, title)
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

    payload = {
        'action': 'analyze',
        'targets': argToList(sha2)
    }
    response = client.submit_file_to_sandbox_analyze(payload)

    # Get Issue Sandbox Command
    title = "Issue Sandbox Command"
    summary_data = {
        'sha2': sha2,
        'command_id': response.get('command_id'),
        'command_type': 'Issue Sandbox Command'
    }
    headers = list(summary_data.keys())
    column_order = [camelize_string(column) for column in headers]
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
    The run_polling_command function check the file scan status and will run until status is not 'Completed'.
    It returns a ScheduledCommand object that schedules the next 'results' function until the polling is complete.
    Args:
        client: Symantec EDR client object
        args: the arguments required to the command being called
        cmd: the command to schedule by after the current command
        status_func : The function that check the file scan status and return either completed or error status
        results_func: the function that retrieves the verdict based on file sandbox status

    Returns:
        return CommandResults
    """
    demisto.debug(f'-- Polling Command --\nArguments : {args}')
    demisto.debug(f'Integration Global Context Data: {demisto.getIntegrationContext()}')

    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs: int = int(args.get('interval_in_seconds', DEFAULT_INTERVAL))
    timeout_in_seconds: int = int(args.get('timeout_in_seconds', DEFAULT_TIMEOUT))

    # Check for ongoing file scanning command_id if exist
    if pre_cmd_id := demisto.getIntegrationContext().get('command_id'):
        args['command_id'] = pre_cmd_id

    # first run ...
    if 'command_id' not in args:
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

            return CommandResults(
                scheduled_command=scheduled_command,
                readable_output=f'Waiting for the polling execution..'
                f'Command id {command_id}',
                ignore_auto_extract=True,
            )

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
        return CommandResults(
            scheduled_command=scheduled_command,
            ignore_auto_extract=True
        )


def file_scheduled_polling_command(client: Client, args: Dict[str, Any]):
    """
    File Scheduled Polling file command
    Returns:
        return polling CommandResults
    """
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
        command_output: CommandResults | str
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
