"""
Symantec Endpoint Detection and Response (EDR) On-Prem integration with Symantec-EDR
"""
import json

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import dateparser
import urllib3
import traceback
from collections.abc import Callable

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 600

# Symantec TOKEN timeout 60 minutes
SESSION_TIMEOUT_SEC = 3600
ISO8601_F_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
INTEGRATION_CONTEXT_NAME = "SymantecEDR"
DEFAULT_OFFSET = 0
DEFAULT_PAGE_SIZE = 50
PAGE_NUMBER_ERROR_MSG = (
    "Invalid Input Error: page number should be greater than zero. "
    "Note: Page must be used along with page_size"
)
PAGE_SIZE_ERROR_MSG = (
    "Invalid Input Error: page size should be greater than zero. "
    "Note: Page must be used along with page_size"
)

INVALID_QUERY_ERROR_MSG = (
    'Invalid query arguments. Either use any optional filter in lieu of "query" '
    'or explicitly use only "query" argument'
)

INCIDENT_PATCH_ACTION = ["add_comment", "close_incident", "update_resolution"]
INCIDENT_PRIORITY_LEVEL: dict[str, str] = {"1": "Low", "2": "Medium", "3": "High"}

INCIDENT_STATUS: dict[str, str] = {
    "1": "Open",
    "2": "Waiting",
    "3": "In-Progress",
    "4": "Closed",
}

INCIDENT_RESOLUTION: dict[str, str] = {
    "0": "INSUFFICIENT_DATA. The incident does not have sufficient information to make a determination.",
    "1": "SECURITY_RISK. The incident indicates a true security threat.",
    "2": "FALSE_POSITIVE. The incident has been incorrectly reported as a security threat.",
    "3": "MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there.",
    "4": "NOT_SET. The incident resolution was not set.",
    "5": "BENIGN. The incident detected the activity as expected but is not a security threat.",
    "6": "TEST. The incident was generated due to internal security testing.",
}

EVENT_SEVERITY: dict[str, str] = {
    "1": "Info",
    "2": "Warning",
    "3": "Minor",
    "4": "Major",
    "5": "Critical",
    "6": "Fatal",
}

# Status for Applicable events : 1, 20, 21, 1000
EVENT_STATUS: dict[str, str] = {"0": "Unknown", "1": "Success", "2": "Failure"}

EVENT_NODE_ROLE: dict[str, str] = {
    "0": "Pre-Bootstrap",
    "1": "Network Scanner",
    "2": "Management",
    "3": "StandaloneNetwork",
    "4": "Standalone Endpoint",
    "5": "All in One",
}

EVENT_SEVERITY_MAPPING = {
    "1": IncidentSeverity.INFO,
    "2": IncidentSeverity.LOW,
    "3": IncidentSeverity.MEDIUM,
    "4": IncidentSeverity.HIGH,
    "5": IncidentSeverity.CRITICAL,
    "6": IncidentSeverity.CRITICAL
}

EVENT_TYPE: dict[str, str] = {
    "1": "Application Activity",
    "20": "Session Audit",
    "21": "Entity Audit",
    "1000": "System Health",
    "4096": "Reputation Request",
    "4098": "Intrusion Prevention",
    "4099": "Suspicious File",
    "4100": "SONAR",
    "4102": "Antivirus (endpoint detection)",
    "4112": "Blacklist (IP/URL/Domain)",
    "4113": "Vantage",
    "4115": "Insight",
    "4116": "Mobile Insight",
    "4117": "Sandbox",
    "4118": "Blacklist (file)",
    "4123": "Endpoint File Detection",
    "4124": "Endpoint Detection",
    "4125": "Email",
    "4353": "Antivirus | Network Detection",
    "8000": "Session Events",
    "8001": "Process Events",
    "8002": "Module Event",
    "8003": "File Events",
    "8004": "Directory Events",
    "8005": "Registry Events",
    "8006": "Registry Events",
    "8007": "Network Events",
    "8009": "Kernel Events",
    "8015": "Monitored Source Events",
    "8016": "Startup Application Configuration Change Events",
    "8018": "AMSI Activity Events",
    "8080": "EOC Session Query Result Events",
    "8081": "EOC Process Query Result Events",
    "8082": "EOC Module Query Result Events",
    "8083": "EOC File Query Result Events",
    "8084": "EOC Directory Query Result Events",
    "8085": "EOC Registry Key Query Result Events",
    "8086": "EOC Registry Value Query Result Events",
    "8089": "EOC Kernel Query Result Events",
    "8090": "EOC Service Query Result Events",
}

SANDBOX_STATE: dict[str, str] = {"0": "Completed", "1": "In Progress", "2": "Unknown"}

DOMAIN_DISPOSITION_STATUS: dict[str, str] = {
    "0": "Healthy",
    "1": "unknown",
    "2": "Suspicious",
    "3": "Bad",
}

HTTP_ERRORS = {
    400: "400 Bad Request - Incorrect or invalid parameters",
    401: "401 Authentication error - Incorrect or invalid username or password",
    403: "403 Forbidden - please provide valid username and password.",
    404: "404 Resource not found - invalid endpoint was called.",
    408: "408 Timeout - Check Server URl/Port",
    410: "410 Gone - Access to the target resource is no longer available at the origin server",
    500: "500 Internal Server Error - please try again after some time.",
    502: "502 Bad Gateway - Could not connect to the origin server",
    503: "503 Service Unavailable",
}

VERDICT_TO_SCORE_DICT = {
    "clean": Common.DBotScore.GOOD,
    "file_type_unrecognized": Common.DBotScore.SUSPICIOUS,
    "malware": Common.DBotScore.BAD,
}

# Map severity to Demisto severity for incident creation
XSOAR_SEVERITY_MAP = {"High": 3, "Medium": 2, "Low": 1}

# Reverse Incident Priority and State mapping
REVERSE_INCIDENT_PRIORITY = {v: k for k, v in INCIDENT_PRIORITY_LEVEL.items()}
REVERSE_INCIDENT_STATE = {v: k for k, v in INCIDENT_STATUS.items()}
REVERSE_EVENT_SEVERITY = {v.lower(): k for k, v in EVENT_SEVERITY.items()}
REVERSE_EVENT_STATUS = {v: k for k, v in EVENT_STATUS.items()}

""" CLIENT CLASS """


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        client_id: str,
        client_secret: str,
        fetch_incidents_type: str,
        first_fetch: str = "3 days",
        fetch_limit: Optional[int] = 50,
        is_incident_event: bool = False,
        is_fetch_comment: bool = False,
        fetch_status: list = None,
        fetch_priority: list = None,
        fetch_event_status: list = None,
        fetch_event_severity: list = None,
        fetch_query: str = None,
    ):

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.client_key = client_id
        self.secret_key = client_secret
        self.fetch_incidents_type = fetch_incidents_type
        self.first_fetch = first_fetch
        self.fetch_limit = fetch_limit
        self.is_incident_event = is_incident_event
        self.is_fetch_comment = is_fetch_comment
        self.fetch_status = fetch_status
        self.fetch_priority = fetch_priority
        self.fetch_event_status = fetch_event_status
        self.fetch_event_severity = fetch_event_severity
        self.fetch_query = fetch_query
        self.access_token = self.get_access_token_or_login()

    @property
    def headers(self) -> dict:
        """
        Client headers method
        Returns:
            self.headers
        """
        if self.access_token is None:  # for logging in, before self.access_token is set
            return {"Content-Type": "application/json"}

        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def get_access_token_from_context() -> str | None:
        """
        Symantec EDR on-premise get previous access token from global integration context
        Args:

        Returns:
            return token from context or None
        """
        global_context = demisto.getIntegrationContext()
        if access_token_timestamp := global_context.get("access_token_timestamp"):
            now_timestamp = int(time.time())
            if token := global_context.get("access_token"):
                time_diff = int(now_timestamp - access_token_timestamp)
                if time_diff <= SESSION_TIMEOUT_SEC:
                    return token
                else:
                    LOG("Access token expired")
        return None

    def get_access_token_or_login(self) -> str:
        """
        Check Access Token from Context if that still valid then using the same token
         else Generate new Access token
        Return:
            return access_token
        """
        if last_access_token := self.get_access_token_from_context():
            LOG("Last access token in context is still active, reusing it")
            access_token = last_access_token
        else:
            try:
                response = self._http_request(
                    method="POST",
                    url_suffix="/atpapi/oauth2/tokens",
                    auth=(self.client_key, self.secret_key),
                    data={"grant_type": "client_credentials"},
                    resp_type="response",
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                if error_msg := HTTP_ERRORS.get(exc.response.status_code):
                    raise DemistoException(f"{error_msg}", res=exc.response) from exc

                raise

            LOG("Generated Access token.")
            access_token = response.json().get("access_token")
            demisto.setIntegrationContext(
                demisto.getIntegrationContext()
                | {
                    "access_token": access_token,
                    "access_token_timestamp": int(time.time()),
                }
            )

        return access_token

    def http_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] = None,
        json_data: Union[dict[str, Any], list] = None,
        ignore_empty_response: bool = False,
    ) -> requests.Response:
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
                resp_type="response",
                return_empty_response=ignore_empty_response,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            if error_msg := HTTP_ERRORS.get(exc.response.status_code):
                raise DemistoException(f"{error_msg}", res=exc.response) from exc

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
            method="POST",
            endpoint="/atpapi/v2/associations/entities/domains-files",
            params={},
            json_data=payload,
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
            method="POST",
            endpoint="/atpapi/v2/associations/entities/endpoints-domains",
            params={},
            json_data=payload,
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
            method="POST",
            endpoint="/atpapi/v2/associations/entities/endpoints-files",
            params={},
            json_data=payload,
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
            method="POST",
            endpoint="/atpapi/v2/auditevents",
            params={},
            json_data=payload,
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
            method="POST", endpoint="/atpapi/v2/events", params={}, json_data=payload
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
            method="POST",
            endpoint="/atpapi/v2/systemactivities",
            params={},
            json_data=payload,
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
            method="POST",
            endpoint="/atpapi/v2/incidentevents",
            params={},
            json_data=payload,
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
            method="POST", endpoint="/atpapi/v2/incidents", params={}, json_data=payload
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
            method="POST",
            endpoint=f"/atpapi/v2/incidents/{uuid}/comments",
            params={},
            json_data=payload,
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
        if len(value) > 512:
            raise ValueError(
                "The maximum allowed length of a comment is 512 characters"
            )

        request_data: list[dict[str, Any]] = [
            {"op": "add", "path": f"/{uuid}/comments", "value": value}
        ]
        return self.http_request(
            method="PATCH",
            endpoint="/atpapi/v2/incidents",
            params={},
            json_data=request_data,
            ignore_empty_response=True,
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
        request_data: list[dict[str, Any]] = [
            {"op": "replace", "path": f"/{uuid}/state", "value": value}
        ]
        return self.http_request(
            method="PATCH",
            endpoint="/atpapi/v2/incidents",
            params={},
            json_data=request_data,
            ignore_empty_response=True,
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
        request_data: list[dict[str, Any]] = [
            {"op": "replace", "path": f"/{uuid}/resolution", "value": value}
        ]
        return self.http_request(
            method="PATCH",
            endpoint="/atpapi/v2/incidents",
            params={},
            json_data=request_data,
            ignore_empty_response=True,
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
        endpoint = (
            f"/atpapi/v2/entities/files/{sha2}/instances"
            if sha2
            else "/atpapi/v2/entities/files/instances"
        )

        return self.http_request(
            method="POST", endpoint=endpoint, params={}, json_data=payload
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
            method="POST",
            endpoint="/atpapi/v2/entities/domains/instances",
            params={},
            json_data=payload,
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
            method="POST",
            endpoint="/atpapi/v2/entities/endpoints/instances",
            params={},
            json_data=payload,
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
            method="GET",
            endpoint="/atpapi/v2/policies/allow_list",
            params=payload,
            json_data={},
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
            method="GET",
            endpoint="/atpapi/v2/policies/deny_list",
            params=payload,
            json_data={},
        ).json()

    def get_cancel_endpoint(self, command_id: str) -> dict[str, Any]:
        """
        Client method for cancel endpoint
        Args:
            command_id (str): command_id separate by commas
        Returns:
            return response json
        """
        payload = {"action": "cancel_command", "targets": argToList(command_id)}
        return self.http_request(
            method="POST", endpoint="/atpapi/v2/commands", params={}, json_data=payload
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
            "action": "delete_endpoint_file",
            "targets": [{"device_uid": device_uid, "hash": file_sha2}],
        }
        return self.http_request(
            method="POST", endpoint="/atpapi/v2/commands", params={}, json_data=payload
        ).json()

    def get_isolate_endpoint(self, device_uid: str) -> dict[str, Any]:
        """
        Client method for Isolate endpoint
        Args:
            device_uid (str): Endpoint Device UUID
        Returns:
            return response json
        """
        payload = {"action": "isolate_endpoint", "targets": argToList(device_uid)}
        return self.http_request(
            method="POST", endpoint="/atpapi/v2/commands", params={}, json_data=payload
        ).json()

    def get_rejoin_endpoint(self, device_uid: str) -> dict[str, Any]:
        """
        Client method for Rejoin endpoint
        Args:
            device_uid (str): Endpoint Device UUID
        Returns:
            return response json
        """
        payload = {"action": "rejoin_endpoint", "targets": argToList(device_uid)}
        return self.http_request(
            method="POST", endpoint="/atpapi/v2/commands", params={}, json_data=payload
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
            method="POST",
            endpoint=f"/atpapi/v2/commands/{command_id}",
            params={},
            json_data=payload,
        ).json()

    def get_sandbox_verdict_for_file(self, sha2: str) -> dict[str, Any]:
        """
        Client method for get sandbox verdict for specific file sha256
        Args:
            sha2 (str): File SHA256
        Returns:
            return response json
        """
        return self.http_request(
            method="GET",
            endpoint=f"/atpapi/v2/sandbox/results/{sha2}/verdict",
            params={},
            json_data={},
        ).json()

    def get_file_entity(self, sha2: str) -> dict[str, Any]:
        """
        Client method for Get File Entity for specific SHA2
        Args:
            sha2 (str): File SHA256
        Returns:
            return response json
        """
        return self.http_request(
            method="GET",
            endpoint=f"/atpapi/v2/entities/files/{sha2}",
            params={},
            json_data={},
        ).json()

    def get_sandbox_status(self, command_id: str) -> dict[str, Any]:
        """
        Client method to Get Sanbox Status for specific file
        Args:
            command_id (str): sandbox command ID
        Returns:
            return response json
        """
        return self.http_request(
            method="GET",
            endpoint=f"/atpapi/v2/sandbox/commands/{command_id}",
            params={},
            json_data={},
        ).json()

    def submit_file_to_sandbox_analyze(self, payload: dict) -> dict[str, Any]:
        """
        Client method for sandbox analyzes
        Args:
            payload: request body

        Returns:
            return response json
        """
        return self.http_request(
            method="POST",
            endpoint="/atpapi/v2/sandbox/commands",
            params={},
            json_data=payload,
        ).json()

    def test_module(self) -> str:
        """
        Returns ok on a successful connection to the Symantec EDR API.
        Otherwise, an exception should be raised by self._http_request()
        """
        incident_type = self.fetch_incidents_type
        query = self.fetch_query or ""
        fetch_args = {"verb": "query", "limit": 1, "query": query}
        self.get_incident(fetch_args) if incident_type == "incident" else self.get_event_list(fetch_args)
        return "ok"


""" HELPER FUNCTIONS """


def convert_to_iso8601(timestamp: str) -> str:
    """Convert timestamp from an iso8601 format

    Args:
        timestamp: Any valid timestamp or provide timedelta e.g. now, "<n> days", "<n> weeks",
        "<n> months", "1 months ago"

    Returns: return timestamp in an iso 8601 format.
    """
    if datetime_from_timestamp := dateparser.parse(
        timestamp, settings={"TIMEZONE": "UTC"}
    ):
        return f"{datetime_from_timestamp.strftime(ISO8601_F_FORMAT)[:-3]}Z"
    else:
        raise ValueError(f"{timestamp=} could not be parsed")


def extract_headers_for_readable_output(summary_data: list[dict]) -> list:
    """
    Symantec EDR formatting Readable output Header
    Args:
        summary_data (list[dict]): Human readable output summary data

    Returns:
        Return string headers to a camel case.

    """
    if not summary_data:
        return []

    headers = summary_data[0] if summary_data else {}
    headers = list(headers.keys())
    return [camelize_string(column) for column in headers]


def get_data_of_current_page(
    response_data: list[dict[str, Any]], offset: int = 0, limit: int = 0
) -> list:
    """
    Retrieve a list element based on offset and limit
    Args:
        response_data (list): Raw API result list
        offset (int) : Offset
        limit (int) : Page Limit

    Returns:
        Return List of an object from the response according to the limit, page and page_size.

    """

    if offset >= 0 and limit >= 0:
        return response_data[offset:(offset + limit)]
    return response_data[:limit]


def compile_command_title_string(context_name: str, args: dict, record: int) -> str:
    """
    Symantec EDR on-premise display title and pagination
        If page/page_size is input, then the limit should be ignored.
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
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))

    if page is None and page_size:
        page = 1

    if page_size is None and page:
        page_size = DEFAULT_PAGE_SIZE
        if record < DEFAULT_PAGE_SIZE:
            page_size = record

    if (page and page_size) and (page > 0 and page_size > 0):
        return (
            f"{context_name} List\nShowing page {page}\n"
            f"Showing {page_size} out of {record} Record(s) Found."
        )

    return f"{context_name} List"


def parse_process_sub_object(data: dict) -> dict:
    """
    Retrieve event process sub object data
    Args:
        data (dict): Event process data
    Returns:
        return process data
    """
    ignore_key_list: list[str] = ["file", "user"]
    return extract_raw_data(data, ignore_key_list)


def parse_attacks_sub_object(data: list[dict]) -> dict:
    """
    Retrieve event attacks sub object data
    Args:
        data (dict): Event attacks data

    Returns:
        return attacks data
    """
    ignore_key_list: list[str] = ["tactic_ids", "tactic_uids"]
    attacks_dict = extract_raw_data(data, ignore_key_list, prefix="attacks")

    for attack in data:
        cnt = 0
        # tactic_ids
        if tactic_ids_list := attack.get("tactic_ids", []):
            tactic_ids_dict = {
                f"attacks_tactic_ids_{cnt}": convert_list_to_str(tactic_ids_list)
            }
            attacks_dict |= tactic_ids_dict

        # tactic uids
        if tactic_uids_list := attack.get("tactic_uids", []):
            tactic_uids_dict = {
                f"attacks_tactic_uids_{cnt}": convert_list_to_str(tactic_uids_list)
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
        "sepm_server",
        "search_config",
        "atp_service",
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
    return extract_raw_data(data, [], "enriched_data")


def parse_user_sub_object(data: dict[str, Any], obj_prefix: Optional[str]) -> dict:
    """
    Retrieve event user sub object data
    Args:
        data (dict): Event user data
        obj_prefix (optional) : Object prefix name
    Returns:
        return user data
    """
    prefix = f"{obj_prefix}_user" if obj_prefix else "user"
    return extract_raw_data(data, [], prefix)


def parse_xattributes_sub_object(
    data: dict[str, Any], obj_prefix: Optional[str]
) -> dict:
    """
    Retrieve event xattributes sub object data
    Args:
        data (dict): Event xattribute data
        obj_prefix (optional) : Object prefix name
    Returns:
        return event data
    """
    prefix = f"{obj_prefix}_xattributes" if obj_prefix else "xattributes"
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
    ignore_key: list[str] = ["file", "user", "xattributes"]

    result = extract_raw_data(data, ignore_key, "event_actor")

    for key, func in (
        ("file", parse_file_sub_object),
        ("user", parse_user_sub_object),
        ("xattributes", parse_xattributes_sub_object),
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
    prefix = f"{obj_prefix}_file" if obj_prefix else "file"
    return extract_raw_data(data, ["signature_value_ids"], prefix)


def parse_monitor_source_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event monitor object data
    Args:
        data (dict): Event monitor data
    Returns:
        return to event dict
    """
    return extract_raw_data(data, [], prefix="monitor_source")


def parse_connection_sub_object(data: dict[str, Any]) -> dict:
    """
    Retrieve event connection object data and return Event dict
    Args:
        data (dict): Event connection data
    Returns:
        return Data dict
    """
    return extract_raw_data(data, [], prefix="connection")


def convert_list_to_str(data: Optional[list] = None) -> str:
    """
    Convert list value to string with comma seperator
    Args:
        data (list): values
    Returns:
        return string
    """
    seperator = ","
    return seperator.join(map(str, data)) if isinstance(data, list) else ""


def parse_event_object_data(data: dict[str, Any]) -> dict:
    """
    Retrieve event object data and return Event dict
    Args:
        data (dict): Event Object data
    Returns:
        event_dict: Event Json Data
    """
    if not data:
        # Return empty dictionary
        return {}

    # Ignore to retrieve Sub Object which will be fetched subsequently based on the command requirement
    ignore_list = [
        "attacks",
        "av",
        "bash",
        "connection",
        "data",
        "directory",
        "enriched_data",
        "entity",
        "entity_result",
        "event_actor",
        "file",
        "intrusion",
        "kernel",
        "link_following",
        "receivers",
        "process",
        "reg_key",
        "reg_value",
        "sandbox",
        "scan",
        "sender",
        "service",
        "session",
        "monitor_source",
    ]

    result: dict[str, Any] = extract_raw_data(data, ignore_list)

    for key, func in (
        ("attacks", parse_attacks_sub_object),
        ("data", parse_event_data_sub_object),
        ("enriched_data", parse_enriched_data_sub_object),
        ("event_actor", parse_event_actor_sub_object),
        ("monitor_source", parse_monitor_source_sub_object),
        ("process", parse_process_sub_object),
        ("connection", parse_connection_sub_object),
        ("edr_data_protocols", convert_list_to_str),
    ):
        if values := data.get(key):
            result |= func(values)  # type: ignore[operator, arg-type]

    for item in ("edr_data_protocols", "edr_files", "source_port", "target_port"):
        if values := data.get(item):
            result |= {f"{item}": values}

    return result


def domain_instance_readable_output(
    results: list[dict], title: str
) -> tuple[str, list]:
    """
    Convert to XSOAR Readable output for entity Domains instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table
    """
    summary_data = []
    for data in results:
        disposition_val = data.get("disposition", "")
        domain_instance = {
            "data_source_url_domain": data.get("data_source_url_domain", ""),
            "first_seen": data.get("first_seen", ""),
            "last_seen": data.get("last_seen", ""),
            "external_ip": data.get("external_ip", ""),
            "disposition": DOMAIN_DISPOSITION_STATUS.get(str(disposition_val), ""),
            "data_source_url": data.get("data_source_url", ""),
        }
        summary_data.append(domain_instance)

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data, "_"), headers=headers, removeNull=True
    )
    return markdown, summary_data


def system_activity_readable_output(
    results: list[dict], title: str
) -> tuple[str, list]:
    """
    Convert to User-Readable output for System Activity resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        Human Readable table
        Content output
    """
    # Applicable events : 1, 20, 21, 1000
    summary_data = []
    context_data = []

    for data in results:
        event_data = parse_event_object_data(data)
        event_data["severity_id"] = EVENT_SEVERITY.get(
            str(event_data.get("severity_id"))
        )
        event_data["atp_node_role"] = EVENT_NODE_ROLE.get(
            str(event_data.get("atp_node_role"))
        )
        event_data["status_id"] = EVENT_STATUS.get(str(event_data.get("status_id")))
        # Symantec EDR Console logging System Activity
        system_activity = {
            "time": event_data.get("device_time", ""),
            "type_id": event_data.get("type_id", ""),
            "severity_id": event_data.get("severity_id", ""),
            "message": event_data.get("message", ""),
            "device_ip": event_data.get("device_ip", ""),
            "atp_node_role": event_data.get("atp_node_role", ""),
            "status_id": event_data.get("status_id", ""),
        }
        summary_data.append(system_activity)
        context_data.append(event_data)

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data, "_"), headers=headers, removeNull=True
    )
    return markdown, context_data


def endpoint_instance_readable_output(
    results: list[dict], title: str
) -> tuple[str, list]:
    """
    Convert to XSOAR Readable output for entities endpoints instance
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        Human Readable table
        Content output
    """

    summary_data = []
    for data in results:
        ip_addresses = data.get("ip_addresses", [])
        endpoint_instance = {
            "device_uid": data.get("device_uid", ""),
            "device_name": data.get("device_name", ""),
            "device_ip": data.get("device_ip", ""),
            "domain_or_workgroup": data.get("domain_or_workgroup", ""),
            "time": data.get("time", ""),
            "ip_addresses": ip_addresses,
        }
        summary_data.append(endpoint_instance)

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data, "_"), headers=headers, removeNull=True
    )
    return markdown, summary_data


def incident_readable_output(results: list[dict], title: str) -> tuple[str, list]:
    """
    Convert to User-Readable output for Incident resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data: Formatting response data
    """
    summary_data: list[dict[str, Any]] = []
    for data in results:
        priority = data.get("priority_level", "")
        state = data.get("state", "")
        resolution = data.get("resolution", "")
        incident = {
            "incident_id": data.get("atp_incident_id", ""),
            "description": data.get("summary", ""),
            "incident_created": data.get("device_time", ""),
            "detection_type": data.get("detection_type", ""),
            "last_updated": data.get("updated", ""),
            "priority": INCIDENT_PRIORITY_LEVEL.get(str(priority), ""),
            "incident_state": INCIDENT_STATUS.get(str(state), ""),
            "atp_rule_id": data.get("atp_rule_id"),
            "rule_name": data.get("rule_name"),
            "incident_uuid": data.get("uuid"),
            "log_name": data.get("log_name"),
            "recommended_action": data.get("recommended_action"),
            "resolution": INCIDENT_RESOLUTION.get(str(resolution), ""),
            "first_seen": data.get("first_event_seen"),
            "last_seen": data.get("last_event_seen"),
        }
        summary_data.append(incident)
    summary_data_sorted = sorted(
        summary_data, key=lambda d: d["incident_id"], reverse=True
    )

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data_sorted, "_"), headers=headers, removeNull=True
    )
    return markdown, summary_data


def audit_event_readable_output(results: list[dict], title: str) -> tuple[str, list]:
    """
    Convert to User-Readable output for Audit Event
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        markdown: A string representation of the Markdown table
        summary_data: Formatting response data
    """
    context_data: list[dict[str, Any]] = []
    summary_data: list[dict[str, Any]] = []
    for data in results:
        event_dict = parse_event_object_data(data)
        event_dict["severity_id"] = EVENT_SEVERITY.get(
            str(event_dict.get("severity_id"))
        )
        event_dict["status_id"] = EVENT_STATUS.get(str(event_dict.get("status_id")))
        # ---- Display Data ----
        event = {
            "time": event_dict.get("device_time", ""),
            "type_id": event_dict.get("type_id", ""),
            "feature_name": event_dict.get("feature_name", ""),
            "message": event_dict.get("message", ""),
            "user_agent_ip": event_dict.get("user_agent_ip", ""),
            "user_name": event_dict.get("user_name", ""),
            "severity": event_dict.get("severity_id", ""),
            "device_name": event_dict.get("device_name", ""),
            "device_ip": event_dict.get("device_ip", ""),
            "uuid": event_dict.get("uuid", ""),
            "status_id": event_dict.get("status_id", ""),
        }
        summary_data.append(event)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d["time"], reverse=True)

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data_sorted, "_"), headers=headers, removeNull=True
    )
    return markdown, context_data


def incident_event_readable_output(results: list[dict], title: str) -> tuple[str, list]:
    """
    Convert to User-Readable output for Event for Incident resources
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
    Returns:
        A string representation of the Markdown table and context Data
        summary_data: Formatting response data
    """
    context_data: list[dict[str, Any]] = []
    summary_data: list[dict[str, Any]] = []
    for data in results:
        event_dict = parse_event_object_data(data)
        severity_id = event_dict.get("severity_id", "")
        event_dict["severity_id"] = EVENT_SEVERITY.get(str(severity_id), "")
        # ---- Display Data ----
        incident_for_event = {
            "time": event_dict.get("device_time", ""),
            "type_id": event_dict.get("type_id", ""),
            "description": f'{event_dict.get("event_actor_file_name", "")} '
            f'logged: {event_dict.get("enriched_data_rule_description", "")}',
            "device_name": event_dict.get("device_name", ""),
            "severity_id": event_dict.get("severity_id"),
            "device_ip": event_dict.get("device_ip", ""),
            "event_uuid": event_dict.get("event_uuid", ""),
            "incident": event_dict.get("incident", ""),
            "operation": event_dict.get("operation", ""),
            "device_domain": event_dict.get("device_domain", ""),
            "user_name": event_dict.get("user_name", ""),
        }
        summary_data.append(incident_for_event)
        context_data.append(event_dict)

    summary_data_sorted = sorted(summary_data, key=lambda d: d["time"], reverse=True)

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data_sorted, "_"), headers=headers, removeNull=True
    )
    return markdown, context_data


def incident_comment_readable_output(
    results: list[dict], title: str, incident_id: str
) -> tuple[str, list]:
    """
    Convert to XSOAR Readable output for incident comment
    Args:
        results (list): Symantec Association Results data
        title (str): Title string
        incident_id (str): Incident Id
    Returns:
        markdown: A string representation of the Markdown table
        summary_data: Formatted data set
    """

    summary_data: list[dict[str, Any]] = []
    for data in results:
        incident_comment = {
            "incident_id": incident_id,
            "comment": data.get("comment", ""),
            "time": data.get("time", ""),
            "user_id": data.get("user_id", ""),
            "incident_responder_name": data.get("incident_responder_name", ""),
        }
        summary_data.append(incident_comment)

    headers = extract_headers_for_readable_output(summary_data)
    markdown = tableToMarkdown(
        title, camelize(summary_data, "_"), headers=headers, removeNull=True
    )
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
        row = extract_raw_data(data, [])
        readable_output.append(row)

    headers = extract_headers_for_readable_output(readable_output)
    return tableToMarkdown(
        title, camelize(readable_output, "_"), headers=headers, removeNull=True
    )


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
    if not isinstance(result, dict | list):
        raise ValueError(
            f"Unexpected data type {type(result)}:: must be either a list or dict.\ndata={result}"
        )

    raw_data = (
        {k: v for attribute in result for (k, v) in attribute.items()}
        if isinstance(result, list)
        else result
    )

    for key, value in raw_data.items():
        if key not in ignore_key:
            field_name = f"{prefix}_{key}" if prefix else f"{key}"
            dataset[field_name] = value

    return dataset


def query_search_condition(
    q_type: str, q_value: str, ignore_validation: bool = False
) -> str:
    """
    This function makes a query condition based on single or multiple search values .
    Args:
        q_type (str): search query Type
        q_value (str): search query value
        ignore_validation (bool): A boolean which ignores value Validation, Default false
    Returns:
        Return search condition.
    """
    condition: str = ""
    if not q_type or not q_value:
        return condition

    list_value = argToList(q_value, ",")
    for value in list_value:
        if not ignore_validation:
            check_valid_indicator_value(q_type, value)
        condition = f"{condition} OR {value}" if condition else value

    return condition


def get_incident_filter_query(args: dict[str, Any]) -> str:
    """
    This function validate the incident filter search query and return the query condition
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    # Incident Parameters
    ids = arg_to_number(args.get("incident_id", None))
    priority = REVERSE_INCIDENT_PRIORITY.get(args.get("priority", None))
    status = REVERSE_INCIDENT_STATE.get(args.get("status", None))
    query = args.get("query", "")

    if query and (ids or priority or status):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition: str = ""
    if ids is not None:
        condition = f"atp_incident_id: {ids}"

    if priority is not None:
        condition = (
            f"{condition} AND priority_level: {priority} "
            if condition
            else f"priority_level: {priority}"
        )

    if status is not None:
        condition = (
            f"{condition} AND state: {status}" if condition else f"state: {status}"
        )

    if query:
        condition = query

    return condition


def get_event_filter_query(args: dict[str, Any]) -> str:
    """
    This function creates the query for search condition.
    Args:
        args: demisto.args()
    Returns:
        Return string.
    """
    event_type_id = arg_to_number(args.get("type_id"))
    severity = REVERSE_EVENT_SEVERITY.get(args.get("severity", ""))
    status = REVERSE_EVENT_STATUS.get(args.get("status", ""))
    query = args.get("query")

    if query and (event_type_id or severity):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    condition = ""
    if event_type_id:
        condition = f"type_id: {event_type_id}"

    if severity:
        condition = (
            f"{condition} AND severity_id: {severity}"
            if condition
            else f"severity_id: {severity}"
        )

    if status:
        condition = (
            f"{condition} AND status_id: {status}"
            if condition
            else f"status_id: {status}"
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
    query_type = args.get("search_object", "")
    query_value = args.get("search_value", "")
    query = args.get("query", "")

    if query and (query_type or query_value):
        raise DemistoException(INVALID_QUERY_ERROR_MSG)

    if query_type == "sha256":
        condition = query_search_condition("sha256", query_value)
        return f"sha2: ({condition})"
    elif query_type == "device_uid":
        condition = query_search_condition(
            "device_uid", query_value, ignore_validation=True
        )
        return f"device_uid: ({condition})"
    elif query_type == "domain":
        condition = query_search_condition(
            "domain", query_value, ignore_validation=True
        )
        return f"data_source_url_domain: ({condition})"
    else:
        return query


def create_content_query(args: dict) -> dict[str, Any]:
    """
    This function creates content body based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return request body payload.
    """
    # Default payload
    limit, offset = get_query_limit(args)
    payload: dict[str, Any] = {"verb": "query", "limit": limit, "offset": offset}

    if (raw_start_time := args.get("start_time")) and (
        start_time := convert_to_iso8601(raw_start_time)
    ):
        payload["start_time"] = start_time

    if (raw_end_time := args.get("end_time")) and (
        end_time := convert_to_iso8601(raw_end_time)
    ):
        payload["end_time"] = end_time

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
    This function determines the query limit based on the demisto.args().

    Scenarios:
        If page/page_size is input, then the limit should be ignored.
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
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")

    if page or page_size:
        page_limit, offset = pagination(page, page_size)
        return page_limit, offset

    limit: int = args.get("limit", DEFAULT_PAGE_SIZE)
    return limit, DEFAULT_OFFSET


def create_params_query(args: dict) -> dict:
    """
    This function creates a query param based on the demisto.args().
    Args:
        args: demisto.args()
    Returns:
        Return arguments dict.
    """
    limit, offset = get_query_limit(args)
    query_params: dict = {"limit": limit, "offset": offset}

    if denylist_id := args.get("denylist_id"):
        query_params["id"] = arg_to_number(denylist_id)

    if allowlist_id := args.get("allowlist_id"):
        query_params["id"] = arg_to_number(allowlist_id)

    if ip := args.get("ip"):
        check_valid_indicator_value("ip", ip)
        query_params["ip"] = ip

    if url := args.get("url"):
        query_params["url"] = url

    if domain := args.get("domain"):
        query_params["domain"] = domain

    if md5 := args.get("md5"):
        check_valid_indicator_value("md5", md5)
        query_params["md5"] = md5

    if sha256 := args.get("sha256"):
        check_valid_indicator_value("sha256", sha256)
        query_params["sha256"] = sha256

    return query_params


def check_valid_indicator_value(indicator_type: str, indicator_value: str) -> bool:
    """
    Check the validity of indicator values
    Args:
        indicator_type: Indicator type provided in the command
            Possible Indicator type are: sha256, urls, ip, md5
        indicator_value: Indicator value provided in the command
    Returns:
        True if the provided indicator values are valid
    """
    hash_to_regex: dict[str, Any] = {
        "sha256": sha256Regex,
        "urls": urlRegex,
        "md5": md5Regex,
    }

    if indicator_type == "ip":
        if not is_ip_valid(indicator_value):
            raise ValueError(f"{indicator_value} is not a valid IP")
    else:
        if indicator_type not in hash_to_regex:
            raise ValueError(f"Indicator type {indicator_type} is not supported")

        if not re.match(hash_to_regex[indicator_type], indicator_value):
            raise ValueError(f"{indicator_value} is not a valid {indicator_type}")

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
    payload = create_content_query(args)

    # offset does not support by API, therefore, need to be removed
    payload.pop("offset")

    # search query as Lucene query string
    if search_query := get_incident_filter_query(args):
        payload["query"] = search_query

    result = client.get_incident(payload).get("result")
    return result[0].get("uuid") if result else None


def create_payload_for_query(
    args: dict[str, Any], query_type: Optional[str] = None
) -> dict:
    """
    Create payload for request the endpoints
    Args:
        args: all command arguments, usually passed from ``demisto.args()``.
        query_type: query type : association, event, incident, allow_list, deny_list
    Returns:
        payload (dict): Return payload for request body
    """
    if query_type in ("allow_list", "deny_list"):
        limit = arg_to_number(args.get("limit"))
        page_size = arg_to_number(args.get("page_size"))
        if (limit and limit < 10) or (page_size and page_size < 10):
            raise ValueError(
                "Invalid input limit or page_size. "
                "For the Deny and Allow list specify the limit/page_size range "
                "The value must be >= 10 and <= 1000."
            )
        payload = create_params_query(args)
    else:
        payload = create_content_query(args)

    # search query as Lucene query string
    if query_type == "association":
        search_query = get_association_filter_query(args)
    elif query_type == "event":
        search_query = get_event_filter_query(args)
    elif query_type == "incident":
        search_query = get_incident_filter_query(args)
    else:
        # default
        search_query = args.get("query", "")

    if search_query:
        payload["query"] = search_query

    return payload


def validate_command_argument(
    args: dict[str, Any], cmd_type: str, expected_values: list
) -> None:
    """
    Validate command arguments based on user input value and expected value.

    Args:
        - args (dict): Usually passed from ``demisto.args()``.
        - cmd_type (str): Command argument type.
        - expected_values (list): An acceptable list of value
    Raises:
     ValueError: Raise error if invalid argument is found.
    """
    arg_value = args.get(cmd_type)
    if arg_value and arg_value not in expected_values:
        raise ValueError(
            f"Invalid {cmd_type}! Only supported types are : {expected_values}"
        )


""" COMMAND FUNCTIONS """


def common_wrapper_command(
    client_func: Callable,
    cmd_args: dict,
    readable_title: str,
    context_path: str,
    output_key_field: str,
    command_type: str = None,
    func_readable_output: Callable = None,
    **kwargs,
) -> CommandResults:
    """
    Common Wrapper Command for different endpoints
    Args:
        client_func: Call client method e.g. client.list_domain_file
        cmd_args: Command arguments, usually passed from ``demisto.args()``.
        readable_title: Readable Output title
        context_path: Readable Context Output path
        output_key_field: Outputs key field
        command_type: Load the specific payload
        func_readable_output: Optional, call in case of readable output method is different for specific command
        kwargs: In case required other arguments

    Returns:
        CommandResults: A ``CommandResults`` object
    """
    context_data: list = []
    payload = create_payload_for_query(cmd_args, command_type)
    offset = int(payload.pop("offset", ""))
    limit = int(payload.get("limit", ""))

    if "uuid" in kwargs:
        raw_response = client_func(payload, kwargs["uuid"])
    elif "sha2" in kwargs:
        raw_response = client_func(payload, kwargs["sha2"])
    else:
        raw_response = client_func(payload)

    title = compile_command_title_string(
        readable_title, cmd_args, int(raw_response.get("total", 0))
    )

    if printable_result := get_data_of_current_page(
        raw_response.get("result", []), offset, limit
    ):
        if func_readable_output is None:
            readable_output = generic_readable_output(printable_result, title)
            context_data = printable_result
        elif "incident_id" in kwargs:
            readable_output, context_data = func_readable_output(
                printable_result, title, kwargs["incident_id"]
            )
        else:
            readable_output, context_data = func_readable_output(
                printable_result, title
            )
    else:
        readable_output = f"No {readable_title} data to present."

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.{context_path}",
        outputs_key_field=output_key_field,
        readable_output=readable_output,
        outputs=context_data,
        raw_response=raw_response,
        ignore_auto_extract=True,
    )


def get_domain_file_association_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    List of Domain and File association
    Args:
        client: Symantec EDR on-premise client object.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object
    """
    validate_command_argument(args, "search_object", ["sha256", "domain"])
    return common_wrapper_command(
        client_func=client.list_domain_file,
        cmd_args=args,
        readable_title="Domain File Association",
        context_path="DomainFileAssociation",
        output_key_field="sha2",
        command_type="association",
    )


def get_endpoint_domain_association_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    endpoint_domain_association_command: List of endpoint domain association
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    validate_command_argument(args, "search_object", ["device_uid", "domain"])
    return common_wrapper_command(
        client_func=client.list_endpoint_domain,
        cmd_args=args,
        readable_title="Endpoint Domain Association",
        context_path="EndpointDomainAssociation",
        output_key_field="device_uid",
        command_type="association",
    )


def get_endpoint_file_association_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    endpoint_file_association_command: List of Endpoint File association
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    validate_command_argument(args, "search_object", ["device_uid", "sha256"])

    return common_wrapper_command(
        client_func=client.list_endpoint_file,
        cmd_args=args,
        readable_title="Endpoint File Association",
        context_path="EndpointFileAssociation",
        output_key_field="sha2",
        command_type="association",
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
    return common_wrapper_command(
        client_func=client.get_audit_event,
        cmd_args=args,
        readable_title="Audit Event",
        context_path="AuditEvent",
        output_key_field="event_uuid",
        command_type="event",
        is_call_diff_readable_output=True,
        func_readable_output=audit_event_readable_output,
    )


def get_event_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get all events
    Args:
        client: Symantec EDR on-premise client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    validate_command_argument(args, "severity", list(REVERSE_EVENT_SEVERITY.keys()))
    return common_wrapper_command(
        client_func=client.get_event_list,
        cmd_args=args,
        readable_title="Event",
        context_path="Event",
        output_key_field="event_uuid",
        command_type="event",
        is_call_diff_readable_output=True,
        func_readable_output=incident_event_readable_output,
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
    validate_command_argument(args, "severity", list(REVERSE_EVENT_SEVERITY.keys()))

    return common_wrapper_command(
        client_func=client.get_system_activity,
        cmd_args=args,
        readable_title="System Activity",
        context_path="SystemActivity",
        output_key_field="uuid",
        command_type="event",
        is_call_diff_readable_output=True,
        func_readable_output=system_activity_readable_output,
    )


def get_event_for_incident_list_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get Event for Incident List
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    validate_command_argument(args, "severity", list(REVERSE_EVENT_SEVERITY.keys()))
    return common_wrapper_command(
        client_func=client.get_event_for_incident,
        cmd_args=args,
        readable_title="Event for Incident",
        context_path="IncidentEvent",
        output_key_field="event_uuid",
        command_type="event",
        is_call_diff_readable_output=True,
        func_readable_output=incident_event_readable_output,
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
    validate_command_argument(args, "priority", list(REVERSE_INCIDENT_PRIORITY.keys()))
    validate_command_argument(args, "status", list(REVERSE_INCIDENT_STATE.keys()))
    return common_wrapper_command(
        client_func=client.get_incident,
        cmd_args=args,
        readable_title="Incident",
        context_path="Incident",
        output_key_field="apt_incident_id",
        command_type="incident",
        is_call_diff_readable_output=True,
        func_readable_output=incident_readable_output,
    )


def get_incident_comments_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get all comments based on Incident ID
    Args:
        client: Symantec EDR on-premise client objectd to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    # Get UUID based on incident_id
    uuid = get_incident_uuid(client, args)
    incident_id = args.pop("incident_id", None)
    if uuid is None:
        raise ValueError(
            f"Incident ID {incident_id} was not found. "
            f"If it's older than 30 days, try increasing the time range arguments"
        )

    return common_wrapper_command(
        client_func=client.get_incident_comment,
        cmd_args=args,
        readable_title="Domain Instances",
        context_path="DomainInstances",
        output_key_field="data_source_url_domain",
        command_type="incident",
        is_call_diff_readable_output=True,
        func_readable_output=incident_comment_readable_output,
        uuid=uuid,
        incident_id=incident_id,
    )


def patch_incident_update_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
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
    action = args.get("operation")
    update_value = args.get("value", "")

    if action not in INCIDENT_PATCH_ACTION:
        raise ValueError(
            f"Invalid Incident Patch Operation: Supported values are : {INCIDENT_PATCH_ACTION}"
        )

    # Get UUID based on incident_id
    if not (uuid := get_incident_uuid(client, args)):
        raise ValueError(
            f'Incident ID {args.get("incident_id")} was not found. '
            f"If it's older than 30 days, try increasing the time range arguments"
        )
    # Incident Add Comment
    if action == "add_comment":
        if not update_value:
            raise ValueError("Comment is missing.")

        action_desc = "Add Comment"
        response = client.add_incident_comment(uuid, update_value)
        status = response.status_code

        # Incident Close Incident
    elif action == "close_incident":
        action_desc = "Close Incident"
        response = client.close_incident(uuid, 4)
        status = response.status_code

        # Incident Update Resolution
    elif action == "update_resolution":
        action_desc = "Update Status"
        if not update_value or INCIDENT_RESOLUTION.get(str(update_value)) is None:
            raise ValueError("Incident Resolution value is missing or invalid.")
        response = client.update_incident(uuid, int(args.get("value", 0)))
        status = response.status_code
    else:
        raise DemistoException(
            f"Operation {action} is not supported; it must be one of {INCIDENT_PATCH_ACTION}"
        )

    if status != 204:
        raise DemistoException(f"Failure of incident {action} operation")

    summary_data = {
        "incident_id": args.get("incident_id"),
        "Message": "Finished updating",
    }
    headers = list(summary_data.keys())
    readable_output = tableToMarkdown(
        f"Incident {action_desc}", summary_data, headers=headers, removeNull=True
    )

    return CommandResults(readable_output=readable_output, ignore_auto_extract=True)


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
    if sha2 := args.get("file_sha2"):
        check_valid_indicator_value("sha256", sha2)

    return common_wrapper_command(
        client_func=client.get_file_instance,
        cmd_args=args,
        readable_title="File Instances",
        context_path="FileInstance",
        output_key_field="sha2",
        sha2=sha2,
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
    return common_wrapper_command(
        client_func=client.get_domain_instance,
        cmd_args=args,
        readable_title="Domain Instances",
        context_path="DomainInstances",
        output_key_field="data_source_url_domain",
        is_call_diff_readable_output=True,
        func_readable_output=domain_instance_readable_output,
    )


def get_endpoint_instance_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get Endpoint Instance
    Args:
        client: Symantec EDR on-premise client object to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    return common_wrapper_command(
        client_func=client.get_endpoint_instance,
        cmd_args=args,
        readable_title="Endpoint Instances",
        context_path="EndpointInstances",
        output_key_field="device_uid",
        is_call_diff_readable_output=True,
        func_readable_output=endpoint_instance_readable_output,
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
    return common_wrapper_command(
        client_func=client.get_allow_list,
        cmd_args=args,
        readable_title="Allow List Policy",
        context_path="AllowListPolicy",
        output_key_field="id",
        command_type="allow_list",
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
    return common_wrapper_command(
        client_func=client.get_deny_list,
        cmd_args=args,
        readable_title="Deny List Policy",
        context_path="DenyListPolicy",
        output_key_field="id",
        command_type="deny_list",
    )


def get_endpoint_command(
    client: Client, args: dict[str, Any], command: str
) -> CommandResults:
    """
    Issue a Command Action to the SEDR On-Prem networks with the following action:
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
    device_uid = args.get("device_id", "")
    file_sha2 = args.get("sha2", "")
    command_id = args.get("command_id", "")

    if command == "symantec-edr-endpoint-cancel-command":
        raw_response = client.get_cancel_endpoint(command_id)
        action_type = "Cancel Endpoint"
    elif command == "symantec-edr-endpoint-delete-file":
        if device_uid and file_sha2:
            raw_response = client.get_delete_endpoint(device_uid, file_sha2)
            action_type = "Delete Endpoint"
        else:
            raise DemistoException(
                "Invalid Arguments. "
                'Both "device_id" and "sha2" arguments are required for endpoint delete action'
            )
    elif command == "symantec-edr-endpoint-isolate":
        action_type = "Isolate Endpoint"
        raw_response = client.get_isolate_endpoint(device_uid)
    elif command == "symantec-edr-endpoint-rejoin":
        action_type = "Rejoin Endpoint"
        raw_response = client.get_rejoin_endpoint(device_uid)
    else:
        raise DemistoException("Endpoint Command action not found.")

    title = f"Command {action_type}"

    summary_data = {
        "Message": raw_response.get("message"),
        "CommandId": raw_response.get("command_id"),
    }

    headers = list(summary_data.keys())
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Command.{action_type}",
        outputs_key_field="command_id",
        outputs=raw_response,
        readable_output=tableToMarkdown(
            title, summary_data, headers=headers, removeNull=True
        ),
        raw_response=raw_response,
        ignore_auto_extract=True,
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
    command_id = args.get("command_id", "")
    readable_data = []
    payload = create_content_query(args)
    payload.pop("offset", 0)

    raw_response = client.get_status_endpoint(command_id, payload)

    summary_data = {
        "state": raw_response.get("state"),
        "Command Issuer Name": raw_response.get("command_issuer_name"),
    }

    if result := raw_response.get("status", ()):
        for status in result:
            summary_data["state"] = status.get("state", "")
            summary_data["message"] = status.get("message", "")
            summary_data["error_code"] = status.get("error_code", "")

    if summary_data:
        title = "Command Status"
        readable_data.append(summary_data)
        readable_output = generic_readable_output(readable_data, title)
    else:
        readable_output = "No command status data to present."

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.CommandStatus",
        outputs_key_field="",
        outputs=summary_data,
        raw_response=raw_response,
        ignore_auto_extract=True,
    )


""" FETCHES INCIDENTS """


def fetch_incidents(client: Client, query_start_time: str) -> list:
    """
    Fetching Incidents pulls incidents and events from third party tools and convert then into incidents.
    Args:
        client: Client Object
        query_start_time: Start Time
    Returns:
        Incident Tuple
    """
    seperator = " OR "
    priority_list = [REVERSE_INCIDENT_PRIORITY.get(i) for i in client.fetch_priority]  # type: ignore[union-attr]
    priority = (
        priority_list[0]
        if len(priority_list) == 1
        else seperator.join(map(str, priority_list))
    )

    state_list = [REVERSE_INCIDENT_STATE.get(i) for i in client.fetch_status]  # type: ignore[union-attr]
    state = (
        state_list[0] if len(state_list) == 1 else seperator.join(map(str, state_list))
    )

    fetch_query = (
        client.fetch_query or f"priority_level: ({priority}) AND state: ({state})"
    )
    incident_payload = {
        "verb": "query",
        "limit": client.fetch_limit,
        "query": fetch_query,
        "start_time": query_start_time,
    }
    demisto.debug(f"Incident query with {incident_payload}")
    result = client.get_incident(incident_payload).get("result", [])

    incidents, events_result, comments_result = [], [], []
    if result:
        _, incidents_context = incident_readable_output(result, "Incident")

        for incident in incidents_context:
            incident_id = incident.get("incident_id")
            incident_uuid = incident.get("incident_uuid")

            # Get Incident Comments if set as true
            if client.is_fetch_comment:
                comment_payload = {"verb": "query", "start_time": query_start_time}
                comments_result = client.get_incident_comment(
                    comment_payload, incident_uuid
                ).get("result", [])

            # Fetch incident for event if set as true
            if client.is_incident_event:
                event_payload = {
                    "verb": "query",
                    "query": f"incident: {incident_uuid}",
                    "start_time": query_start_time,
                }
                events_result = client.get_event_for_incident(event_payload).get(
                    "result", []
                )

            # Incidents Data
            incidents.append(
                {
                    "name": f"SEDR Incident {incident_id}",
                    "details": incident.get("description"),
                    "severity": XSOAR_SEVERITY_MAP.get(str(incident["priority"])),
                    "occurred": incident.get("incident_created"),
                    "dbotMirrorId": str(incident_id),
                    "rawJSON": json.dumps(
                        {
                            "incident": incident,
                            "comments": comments_result,
                            "events": events_result,
                        }
                    ),
                }
            )

    return incidents


def fetch_events(client: Client, query_start_time: str) -> list:
    """
    Fetching Events pulls events from third party tools and convert then into incidents.
    Args:
        client: Client Object
        query_start_time: Start Time
    Returns:
        Incident list
    """
    seperator = "OR"

    severity_list = [REVERSE_EVENT_SEVERITY.get(i.lower()) for i in client.fetch_event_severity]  # type: ignore[union-attr]
    severity = (
        severity_list[0]
        if len(severity_list) == 1
        else seperator.join(map(str, severity_list))
    )
    status_list = [REVERSE_EVENT_STATUS.get(i) for i in client.fetch_event_status]  # type: ignore[union-attr]
    status = (
        status_list[0]
        if len(status_list) == 1
        else seperator.join(map(str, status_list))
    )
    fetch_query = (
        client.fetch_query or f"severity_id: ({severity}) and status_id: ({status})"
    )
    event_payload = {
        "verb": "query",
        "limit": client.fetch_limit,
        "query": fetch_query,
        "start_time": query_start_time,
    }
    demisto.debug(f"Event query with {event_payload}")
    results = client.get_event_list(event_payload).get("result", [])
    demisto.debug(f"Fetched {len(results)}")
    incidents = []
    for result in results:
        event_type = EVENT_TYPE.get(str(result.get("type_id")))
        result["event_type"] = event_type
        incidents.append(
            {
                "name": f'SEDR Event {result.get("type_id")}: {event_type} - {result.get("device_name")}',
                "severity": EVENT_SEVERITY_MAPPING.get(str(result.get("severity_id"))),
                "rawJSON": json.dumps(result),
                "occurred": result.get("device_time"),
                "uuid": result.get("uuid"),
            }
        )
    return incidents


def fetch_xsaor_incidents(client: Client, fetch_incident_type: str) -> list:
    """
    Common function for fetch incidents and events.
    Args:
        client: Client Object
        fetch_incident_type: Fetch Type
    Returns:
        Incident list
    """
    function_mapping = {
        "incidents": (fetch_incidents, "name"),
        "events": (fetch_events, "uuid"),
    }
    # demisto.getLastRun() will return an obj with the previous run in it.
    last_run = demisto.getLastRun()
    demisto.debug(f"Last Run Object : {last_run}")
    # set First Fetch starting time in case running first time or reset
    previous_start_time, previous_end_time = get_fetch_run_time_range(
        last_run=last_run, first_fetch=client.first_fetch
    )

    query_start_time = (
        convert_to_iso8601(last_run.get("time"))
        if last_run and "time" in last_run
        else convert_to_iso8601(previous_start_time)
    )
    fetch_function, id_field = function_mapping[fetch_incident_type]
    incidents = fetch_function(client, query_start_time)
    # remove duplicate incidents which were already fetched
    incidents_insert = filter_incidents_by_duplicates_and_limit(
        incidents_res=incidents,
        last_run=last_run,
        fetch_limit=client.fetch_limit,
        id_field=id_field,
    )
    current_end_time = convert_to_iso8601("now")
    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents_insert,
        fetch_limit=client.fetch_limit,
        start_fetch_time=query_start_time,
        end_fetch_time=current_end_time,
        look_back=30,
        created_time_field="occurred",
        id_field=id_field,
        date_format=f"{ISO8601_F_FORMAT}Z",
    )

    demisto.debug(f"Incident insert: {len(incidents_insert)}")
    demisto.setLastRun(last_run)
    demisto.debug(f"length of incident {len(incidents_insert)}")
    return incidents_insert


""" POLLING CODE """


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
    sha2 = args.get("file", "")
    reliability = args.get("integration_reliability", "B - Usually reliable")
    response_verdict = client.get_sandbox_verdict_for_file(
        sha2
    ) | client.get_file_entity(sha2)
    # Sandbox verdict
    title = "Sandbox Verdict"
    indicator = None
    if response_verdict:
        readable_output = generic_readable_output([response_verdict], title)
        score = VERDICT_TO_SCORE_DICT.get(
            response_verdict.get("verdict", "").lower(), Common.DBotScore.NONE
        )
        dbot_score = Common.DBotScore(
            indicator=sha2,
            indicator_type=DBotScoreType.FILE,
            integration_name=INTEGRATION_CONTEXT_NAME,
            score=score,
            malicious_description=response_verdict.get("verdict", ""),
            reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(
                reliability
            ),
        )
        indicator = Common.File(sha256=sha2, dbot_score=dbot_score)
    else:
        readable_output = f"{title} does not have data to present."

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.SandboxVerdict",
        outputs_key_field="sha2",
        outputs=response_verdict,
        raw_response=response_verdict,
        indicator=indicator,
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
    if not (command_id := args.get("command_id")):
        raise DemistoException("Command ID missing.")

    response = client.get_sandbox_status(command_id)
    # Query Sandbox Command Status
    summary_data = {}
    if sandbox_status := response.get("status"):
        for status in sandbox_status:
            summary_data = {
                "command_id": command_id,
                "status": SANDBOX_STATE.get(str(status.get("state", ""))),
                "message": status.get("message", ""),
                "target": status.get("target", ""),
                "error_code": status.get("error_code", ""),
            }

    if summary_data:
        readable_data.append(summary_data)
        readable_output = generic_readable_output(readable_data, title)
    else:
        readable_output = f"{title} does not have data to present."

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.SandboxStatus",
        outputs_key_field="command_id",
        outputs=summary_data,
        raw_response=response,
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

    sha2 = args.get("file", "")
    if get_hash_type(sha2) != "sha256":
        raise ValueError(f"SHA256 value:{sha2} is invalid")

    payload = {"action": "analyze", "targets": argToList(sha2)}
    response = client.submit_file_to_sandbox_analyze(payload)

    # Get Issue Sandbox Command
    title = "Issue Sandbox Command"
    summary_data = {
        "sha2": sha2,
        "command_id": response.get("command_id"),
        "command_type": "Issue Sandbox Command",
    }
    headers = list(summary_data.keys())
    column_order = [camelize_string(column) for column in headers]
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.SandboxIssue",
        outputs_key_field="command_id",
        outputs=summary_data,
        readable_output=tableToMarkdown(
            title, camelize(summary_data, "_"), headers=column_order, removeNull=True
        ),
        raw_response=response,
    )


# ScheduledCommand
def run_polling_command(
    client: Client, args: dict, cmd: str, status_func: Callable, results_func: Callable
):
    """
    This function can handle the polling flow.
    After the first run, progress will be shown through the status command.
    The run_polling_command function checks the file scan status and will run until status is not 'Completed'.
    It returns a ScheduledCommand object that schedules the next 'results' function until the polling is complete.
    Args:
        client: Symantec EDR client object
        args: the arguments required to the command being called
        cmd: the command to schedule by after the current command
        status_func : The function that checks the file scan status and returns either completed or error status
        results_func: the function that retrieves the verdict based on file sandbox status

    Returns:
        return CommandResults
    """
    demisto.debug(f"-- Polling Command --\nArguments : {args}")
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs: int = int(args.get("interval_in_seconds", DEFAULT_INTERVAL))
    timeout_in_seconds: int = int(args.get("timeout_in_seconds", DEFAULT_TIMEOUT))

    # Check for ongoing file scanning command_id if exist
    if pre_cmd_id := demisto.getIntegrationContext().get("command_id"):
        args["command_id"] = pre_cmd_id

    # first run ...
    if "command_id" not in args:
        outputs: Any[object] = issue_sandbox_command(client, args).outputs
        command_id = outputs.get("command_id")

        if command_id is not None:
            if global_integration_context := demisto.getIntegrationContext():
                global_integration_context["command_id"] = command_id
                demisto.setIntegrationContext(global_integration_context)
            else:
                demisto.setIntegrationContext({"command_id": command_id})

            args["command_id"] = command_id
            polling_args = {
                "interval_in_seconds": interval_in_secs,
                "polling": True,
                **args,
            }

            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval_in_secs,
                args=polling_args,
                timeout_in_seconds=timeout_in_seconds,
            )

            return CommandResults(
                scheduled_command=scheduled_command,
                readable_output=f"Waiting for the polling execution.."
                f"Command id {command_id}",
                ignore_auto_extract=True,
            )

    # not a first run
    command_result = status_func(client, args)
    outputs = status_func(client, args).outputs
    status = outputs.get("status")
    if status == "Completed":
        # action completed
        if global_integration_context := demisto.getIntegrationContext():
            global_integration_context.pop("command_id")
            demisto.setIntegrationContext(global_integration_context)
        return results_func(client, args)
    elif status == "Error":
        if global_integration_context := demisto.getIntegrationContext():
            global_integration_context.pop("command_id")
            demisto.setIntegrationContext(global_integration_context)

        return command_result
    else:
        # in case of In progress
        polling_args = {
            "interval_in_seconds": interval_in_secs,
            "polling": True,
            **args,
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=timeout_in_seconds,
        )

        # result with scheduled_command only - no update to the war room
        return CommandResults(
            scheduled_command=scheduled_command, ignore_auto_extract=True
        )


def file_scheduled_polling_command(client: Client, args: Dict[str, Any]):
    """
    File Scheduled Polling file command
    Returns:
        return polling CommandResults
    """
    return run_polling_command(
        client, args, "file", check_sandbox_status, get_sandbox_verdict
    )


""" MAIN FUNCTION """


def main() -> None:     # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()

        # OAuth parameters
        server_url = params.get("url", "")
        client_id = params.get("credentials", {}).get("identifier", "")
        client_secret = params.get("credentials", {}).get("password", "")
        verify_certificate = params.get("insecure", False)
        proxy = params.get("proxy", False)

        # Fetches Incident Parameters
        fetch_incidents_type = params.get("fetch_incidents_events_type", "incidents")
        first_fetch_time = params.get("first_fetch", "3 days").strip()
        fetch_limit = arg_to_number(params.get("max_fetch", 50))
        fetch_incident_event = params.get("isIncidentsEvent", False)
        fetch_comments = params.get("isIncidentComment", False)
        fetch_status = argToList(params.get("fetch_status", "New"))
        fetch_priority = argToList(params.get("fetch_priority", "High,Medium"))
        fetch_event_status = argToList(params.get("fetch_event_status", "Success"))
        fetch_event_severity = argToList(params.get("fetch_severity", "Info"))
        fetch_query = params.get("fetch_incidents_query", "")
        reliability = params.get("integration_reliability", "")
        args["integration_reliability"] = reliability

        client = Client(
            base_url=server_url,
            verify=verify_certificate,
            proxy=proxy,
            client_id=client_id,
            client_secret=client_secret,
            fetch_incidents_type=fetch_incidents_type,
            first_fetch=first_fetch_time,
            fetch_limit=fetch_limit,
            is_incident_event=fetch_incident_event,
            is_fetch_comment=fetch_comments,
            fetch_status=fetch_status,
            fetch_priority=fetch_priority,
            fetch_event_status=fetch_event_status,
            fetch_event_severity=fetch_event_severity,
            fetch_query=fetch_query,
        )

        demisto.info(f"Command being called is {demisto.command()}")
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
            "file": file_scheduled_polling_command,
        }
        command_output: CommandResults | str
        if command == "test-module":
            command_output = client.test_module()
        elif command == "fetch-incidents":
            incidents = fetch_xsaor_incidents(client, fetch_incidents_type)
            demisto.incidents(incidents)
            command_output = "OK"
        elif command in [
            "symantec-edr-endpoint-isolate",
            "symantec-edr-endpoint-rejoin",
            "symantec-edr-endpoint-delete-file",
            "symantec-edr-endpoint-cancel-command",
        ]:
            # isolate_endpoint, re-join, delete_endpoint_file, cancel_command
            command_output = get_endpoint_command(client, args, command)
        elif command in commands:
            command_output = commands[command](client, args)
        else:
            raise NotImplementedError(f"Command {command} is not supported")

        return_results(command_output)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {demisto.command()} command.\nError: {e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
