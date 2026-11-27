from collections.abc import Callable
from copy import deepcopy
import re
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SEVERITY_MAP: dict[str, float] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NOTE": 0.5,
}

OK_CODES = (200, 401, 201)
EVENT_TYPES = ["Contrast Incident", "Contrast Issue"]
MARKDOWN_LINK_PATTERN = re.compile(r"\[(?:\\.|[^\]\\])*\]\([^)]*\)")
HR_MARKDOWN_CHARS = r"\*_{}[]()#+-!<>~"
STATUS_CODE_TO_RETRY = [429, *(code for code in requests.status_codes._codes if code >= 500)]  # type: ignore
MAX_RETRIES = 3
BACKOFF_FACTOR = 7.5
RULE_MODE_MAPPING = {
    "Off": "OFF",
    "Monitor": "MONITOR",
    "Block": "BLOCK",
    "Block at perimeter": "BLOCK_AT_PERIMETER",
    "Monitor at perimeter": "MONITOR_AT_PERIMETER",
}
RULE_MODE_HUMAN_READABLE_LIST = list(RULE_MODE_MAPPING.keys())
RULE_MODE_REVERSE_MAPPING = {value: key for key, value in RULE_MODE_MAPPING.items()}
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_IP_POLICY_NAME_PREFIX = "XSOAR"
STATUS_LIST = ["closed", "open"]
CLOSE_REASON_LIST = ["True Positive", "False Positive", "Benign True Positive", "Other"]
STATUS_HUMAN_READABLE_LIST = ["Closed", "Open"]
SEVERITY_HUMAN_READABLE_LIST = ["Critical", "High", "Medium", "Low", "Note"]
SORT_ORDER_VALID_VALUES = ["Asc", "Desc"]
MAX_ISSUE_PAGE_SIZE = 200
MAX_OBSERVATION_PAGE_SIZE = 200
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 25
MAX_FETCH_LIMIT = 200
# Stop processing records after 4 minutes so the fetch run finishes before the 5-minute docker timeout.
FETCH_TIME_LIMIT_SECONDS = 240
FETCH_SORT = "createdTime,asc"
INCIDENT_EVENT_TYPE = "contrast_security_incidentalert"
DEFAULT_INCIDENT_NAME = "Contrast Security Incident"
ISSUE_EVENT_TYPE = "contrast_security_issuealert"
DEFAULT_ISSUE_NAME = "Contrast Security Issue"
SORT_BY_MAPPING = {
    "created_at": "createdTime",
    "updated_at": "updatedTime",
}
ISSUE_TIME_FILTER_MAPPING = {
    "created_after": "createdAfter",
    "created_before": "createdBefore",
    "modified_after": "modifiedAfter",
    "modified_before": "modifiedBefore",
}
SORT_BY_VALID_VALUES = list(SORT_BY_MAPPING.keys())
CLOSE_REASON_MAPPING = {
    "True Positive": "TRUE_POSITIVE",
    "False Positive": "FALSE_POSITIVE",
    "Benign True Positive": "TRUE_POSITIVE_BENIGN",
    "Other": "OTHER",
}
CLOSE_REASON_REVERSE_MAPPING = {value: key for key, value in CLOSE_REASON_MAPPING.items()}
# Map XSOAR incident status to Contrast Security incident/issue status (for outgoing mirroring)
XSOAR_TO_CONTRAST_STATUS = {
    IncidentStatus.ACTIVE: "OPEN",
    IncidentStatus.DONE: "CLOSED",
}
# Map Contrast Security closedReason API values to XSOAR close reasons (for incoming mirroring).
# Unmapped or missing Contrast reasons fall back to "Other".
CONTRAST_TO_XSOAR_CLOSE_REASON = {
    "TRUE_POSITIVE": "Resolved",
    "TRUE_POSITIVE_BENIGN": "Resolved",
    "FALSE_POSITIVE": "False Positive",
    "OTHER": "Other",
}
# Map XSOAR close reasons to Contrast Security closedReason API values.
# Unmapped XSOAR reasons fall back to "OTHER" since Contrast requires a close reason.
XSOAR_TO_CONTRAST_CLOSE_REASON = {
    "False Positive": "FALSE_POSITIVE",
    "Resolved": "TRUE_POSITIVE",
    "Duplicate": "OTHER",
    "Other": "OTHER",
}
MAX_OUTGOING_NOTE_LIMIT = 64000
MAX_INCIDENTS_MIRRORING_LIMIT = 5000
MAX_CONTEXT_UPDATE_RETRIES = 10
MAX_MIRRORING_PAGE_SIZE = 200
MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
ENDPOINTS = {
    "incidents_list": "/api/findings/v1beta/organizations/{}/incidents",
    "incident_get": "/api/findings/v1beta/organizations/{}/incidents/{}",
    "incident_comment": "/api/findings/v1beta/organizations/{}/incidents/{}/comments",
    "incident_status": "/api/findings/v1beta/organizations/{}/incidents/{}",
    "ip_policies": "/api/policy-management/v1/organizations/{}/ip-policies",
    "adr_rule": "/api/policy-management/v1/organizations/{}/applications/{}/adr-rules/{}",
    "issue_list": "/api/findings/v1beta/organizations/{}/issues",
    "incident_issues_list": "/api/findings/v1beta/organizations/{}/incidents/{}/issues",
    "issue_get": "/api/findings/v1beta/organizations/{}/issues/{}",
    "issue_comment": "/api/findings/v1beta/organizations/{}/issues/{}/comments",
    "issue_status": "/api/findings/v1beta/organizations/{}/issues/{}",
    "observation_get": "/api/findings/v1beta/organizations/{}/observations/{}",
    "observations_list": "/api/findings/v1beta/organizations/{}/incidents/{}/observations",
}

ERROR_MESSAGES = {
    "REQUIRED_ARGUMENT": "Missing argument {}.",
    "UNAUTHORIZED_REQUEST": "{} Unauthorized: Authentication failed. Please verify the API key, Service Key,"
    " Organization ID, and Username. {}",
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "CLOSE_REASON_REQUIRED": "{} argument is required when provided incident status is {}.",
    "INVALID_TIMESTAMP": "Provided invalid {}: {} must be a future timestamp.",
    "INVALID_IP": "'{}' is an invalid value for '{}'. Value must be a valid IP address.",
    "INVALID_TIME_RANGE": "'{}' must be earlier than or equal to '{}'.",
    "INVALID_PAGE_SIZE": "Invalid page_size: '{}'. page_size must not exceed {}.",
    "INVALID_INTEGER": "'{}' is an invalid value for '{}'. Value must be a valid positive integer.",
    "ADR_RULE_MODE_REQUIRED": "At least one of 'dev_mode', 'qa_mode' or 'prod_mode' must be provided.",
    "INVALID_MAX_FETCH": "'{}' is an invalid value for 'Max Fetch'. Value must be between 1 and {}.",
}

OUTPUT_PREFIX = {
    "INCIDENT_COMMENT": "ContrastSecurity.IncidentComment",
    "INCIDENT": "ContrastSecurity.Incident",
    "IP_POLICY": "ContrastSecurity.IPPolicy",
    "ADR_RULE": "ContrastSecurity.AdrRule",
    "ISSUE_COMMENT": "ContrastSecurity.IssueComment",
    "ISSUE": "ContrastSecurity.Issue",
    "PAGE_TOKEN_ISSUE": "ContrastSecurity.PageToken.Issue",
    "OBSERVATION": "ContrastSecurity.Observation",
    "PAGE_TOKEN_OBSERVATION": "ContrastSecurity.PageToken.Observation",
}

# URL path templates for generating links in human-readable output
URL_PATHS = {
    "incident": "/Contrast/cs/index.html#/{}/incidents/{}",
    "issue": "/Contrast/cs/index.html#/{}/issues/{}",
    "observation": "/Contrast/cs/index.html#/{}/observations/{}",
    "application": "/Contrast/cs/index.html#/{}/explorer?applicationId={}",
}


class Client(BaseClient):
    """Client for Contrast Security API."""

    def __init__(
        self,
        server_url: str,
        username: str,
        service_key: str,
        api_key: str,
        organization_id: str,
        verify_certificate: bool,
        proxy: bool,
    ):
        # Create Authorization header using username:service_key
        auth_header = b64_encode(f"{username}:{service_key}")

        super().__init__(
            server_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                "Authorization": auth_header,
                "API-Key": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        self.organization_id = organization_id

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        response_type: str = "response",
        **kwargs,
    ):
        """
        Makes an HTTP request to the Contrast Security server.

        Args:
            method (str): The HTTP method (e.g., GET, POST, PUT, DELETE).
            url_suffix (str): The URL suffix to be appended to the base URL. Defaults to an empty string.
            params (dict): Query parameters to be appended to the URL. Defaults to None.
            data (object): Data to be sent in the request body. Defaults to None.
            json_data (dict): JSON data to be sent in the request body. Defaults to None.
            response_type (str): The expected response type. Defaults to "response".
            **kwargs: Additional keyword arguments.

        Returns:
            object: The response object or parsed JSON.
        """
        headers = self._headers
        log_header = {**headers, "Authorization": "***********", "API-Key": "***********"}  # type: ignore
        demisto.debug(
            f"Making API request at {method} {url_suffix} with headers:{log_header}, params:{params} and body:{data or json_data}"
        )

        # Make the HTTP request using the _http_request method
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            data=data,
            json_data=json_data,
            params=params,
            retries=MAX_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            ok_codes=OK_CODES,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_status=True,
            resp_type="response",
            **kwargs,
        )

        if res.status_code in [401]:
            try:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, str(res.json().get("error")))
            except ValueError:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, str(res))
            raise DemistoException(err_msg)

        # Parse successful response based on requested type
        try:
            if response_type == "json":
                return res.json()
            else:
                return res  # Default to response object
        except ValueError as e:
            raise DemistoException(
                ERROR_MESSAGES["INVALID_OBJECT"].format("json", res.content),
                e,
                res,
            )

    def get_issue(self, issue_id: str) -> dict[str, Any]:
        """
        Get a specific issue by ID from Contrast Security.

        Args:
            issue_id: The ID of the issue.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["issue_get"].format(self.organization_id, issue_id)
        return self.http_request(method="GET", url_suffix=url_suffix, response_type="json")

    def get_observation(self, observation_id: str) -> dict[str, Any]:
        """
        Get a specific observation by ID from Contrast Security.

        Args:
            observation_id: The ID of the observation.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["observation_get"].format(self.organization_id, observation_id)
        return self.http_request(method="GET", url_suffix=url_suffix, response_type="json")

    def list_issues(self, query_params: dict):
        """
        Get list of issues from Contrast Security.

        Args:
            query_params: Query parameters for the request (size, cursor, etc.)

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["issue_list"].format(self.organization_id)
        return self.http_request(method="GET", url_suffix=url_suffix, params=query_params, response_type="json")

    def list_incident_issues(self, incident_id: str, query_params: dict):
        """
        Get list of issues for a specific incident from Contrast Security.

        Args:
            incident_id: The ID of the incident.
            query_params: Query parameters for the request (size, cursor)

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["incident_issues_list"].format(self.organization_id, incident_id)
        return self.http_request(method="GET", url_suffix=url_suffix, params=query_params, response_type="json")

    def list_incidents(self, query_params: dict):
        """
        Get list of incidents from Contrast Security.

        Args:
            query_params: Query parameters for the request (createdAfter, statuses, severities, sort, size, cursor, etc.)

        Returns:
            Response object or parsed JSON containing incidents
        """
        url_suffix = ENDPOINTS["incidents_list"].format(self.organization_id)
        return self.http_request(method="GET", url_suffix=url_suffix, params=query_params, response_type="json")

    def get_incident(self, incident_id: str):
        """
        Get a single incident from Contrast Security by ID.

        Args:
            incident_id: The Contrast Security incident ID (e.g. "INC-2026-305").

        Returns:
            Response object or parsed JSON containing the incident
        """
        url_suffix = ENDPOINTS["incident_get"].format(self.organization_id, incident_id)
        return self.http_request(method="GET", url_suffix=url_suffix, response_type="json")

    def incident_comment_add(self, incident_id: str, payload: dict):
        """
        Add a comment to a Contrast Security Incident.

        Args:
            incident_id: Contrast Security incident ID.
            payload: incident comment data to add.

        Returns:
            Response object or parsed JSON
        """

        url_suffix = ENDPOINTS["incident_comment"].format(self.organization_id, incident_id)
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=payload, response_type="json")

    def incident_status_update(self, incident_id: str, payload: dict):
        """
        Update the status of a Contrast Security Incident.

        Args:
            incident_id: Contrast Security incident ID.
            payload: incident status data to update.

        Returns:
            Response object or parsed JSON
        """

        url_suffix = ENDPOINTS["incident_status"].format(self.organization_id, incident_id)
        return self.http_request(method="PATCH", url_suffix=url_suffix, json_data=payload, response_type="json")

    def create_ip_policy(self, payload: dict):
        """
        Create an organization-level IP policy in Contrast Security.

        Args:
            payload: Request body containing ip, name, trusted, expirationTime and environments.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["ip_policies"].format(self.organization_id)
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=payload, response_type="json")

    def adr_rule_get(self, application_id: str, rule_id: str):
        """
        Get the modes of an ADR rule for a Contrast Security application.

        Args:
            application_id: Contrast Security application ID.
            rule_id: ID of the ADR rule to retrieve.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["adr_rule"].format(self.organization_id, application_id, rule_id)
        return self.http_request(method="GET", url_suffix=url_suffix, response_type="json")

    def adr_rule_update(self, application_id: str, rule_id: str, payload: dict):
        """
        Update the modes of an ADR rule for a Contrast Security application.

        Args:
            application_id: Contrast Security application ID.
            rule_id: ID of the ADR rule to update.
            payload: Request body containing devMode, qaMode and prodMode.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["adr_rule"].format(self.organization_id, application_id, rule_id)
        return self.http_request(method="PUT", url_suffix=url_suffix, json_data=payload, response_type="json")

    def issue_comment_add(self, issue_id: str, payload: dict):
        """
        Add a comment to a Contrast Security Issue.

        Args:
            issue_id: Contrast Security issue ID.
            payload: issue comment data to add.

        Returns:
            Response object or parsed JSON
        """

        url_suffix = ENDPOINTS["issue_comment"].format(self.organization_id, issue_id)
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=payload, response_type="json")

    def issue_status_update(self, issue_id: str, payload: dict):
        """
        Update the status of a Contrast Security Issue.

        Args:
            issue_id: Contrast Security issue ID.
            payload: issue status data to update.

        Returns:
            Response object or parsed JSON
        """

        url_suffix = ENDPOINTS["issue_status"].format(self.organization_id, issue_id)
        return self.http_request(method="PATCH", url_suffix=url_suffix, json_data=payload, response_type="json")

    def list_incident_observations(self, incident_id: str, query_params: dict | None = None):
        """
        Get list of observations for a Contrast Security Incident.

        Args:
            incident_id: ID of the incident.
            query_params: Query parameters for the request (size, cursor, createdAfter, createdBefore).

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["observations_list"].format(self.organization_id, incident_id)
        return self.http_request(method="GET", url_suffix=url_suffix, params=query_params, response_type="json")


""" Helper Functions """


def remove_empty_elements_for_fetch(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    :param d: Input dictionary or list.
    :return: Dictionary or list with all empty lists, and empty dictionaries removed.
    """
    if not isinstance(d, dict | list):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_fetch(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_fetch(v)) for k, v in d.items()) if not check_empty(v)}


def get_mirroring(params: dict, mirror_direction_param: str) -> dict:
    """
    Get mirroring configuration for the specified event type parameter.

    Args:
        params: Integration configuration parameters.
        mirror_direction_param: The parameter name for mirror direction.

    Returns:
        dict: Mirroring configuration with mirror_direction, mirror_tags, and mirror_instance
    """
    mirror_direction = params.get(mirror_direction_param, "None").strip()
    mirror_tags = params.get("note_tag", "note").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_tags": mirror_tags,
        "mirror_instance": demisto.integrationInstance(),
    }


def validate_fetch_params(params: dict) -> tuple[str, int, str]:
    """
    Validate the fetch parameters and return the event type, the max fetch and the first fetch time.

    Args:
        params: Integration parameters.

    Returns:
        tuple: Event type, max fetch and the first fetch time in RFC 3339 format.

    Raises:
        ValueError: If any parameter has an invalid value.
    """
    max_fetch = arg_to_number(params.get("max_fetch") or DEFAULT_MAX_FETCH, arg_name="Max Fetch")
    if not max_fetch or max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"].format(max_fetch, MAX_FETCH_LIMIT))

    first_fetch = arg_to_datetime(
        params.get("first_fetch") or DEFAULT_FIRST_FETCH,
        arg_name="First Fetch Time",
        required=True,
        settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True},
    )

    # Validate event type
    event_type = params.get("event_type") or EVENT_TYPES[0]
    if event_type not in EVENT_TYPES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(event_type, "Event Type", EVENT_TYPES))

    # Validate the statuses and severities of the selected event type only
    record_type = "incident" if event_type == EVENT_TYPES[0] else "issue"
    statuses = argToList(params.get(f"{record_type}_statuses"))
    severities = argToList(params.get(f"{record_type}_severities"))

    # Validate statuses
    for status in statuses:
        if status.lower() not in STATUS_LIST:
            raise ValueError(
                ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, f"{record_type.title()} Statuses", STATUS_HUMAN_READABLE_LIST)
            )

    # Validate severities
    for severity in severities:
        if severity.title() not in SEVERITY_HUMAN_READABLE_LIST:
            raise ValueError(
                ERROR_MESSAGES["INVALID_ARGUMENT"].format(
                    severity, f"{record_type.title()} Severity Levels", SEVERITY_HUMAN_READABLE_LIST
                )
            )

    return event_type, max_fetch, first_fetch.strftime(DATE_TIME_FORMAT)  # type: ignore[union-attr]


def validate_argument(value, name) -> Any:
    """
    Check if empty string is passed as value for argument and raise appropriate ValueError.

    Args:
        value: Value of the argument.
        name: Name of the argument.

    Returns:
        str: Value of the argument.

    Raises:
        ValueError: If the value is empty string.
    """
    if not value:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format(name))
    return value


def build_issue_list_query_params(args: dict) -> dict[str, Any]:
    """
    Validate the arguments of the contrastsecurity-issue-list command and build the query parameters.

    Args:
        args(dict): arguments obtained from demisto.args().

    Returns:
        dict: Query parameters for the issue list request.

    Raises:
        ValueError: If any argument has an invalid value.
    """
    sort_by = args.get("sort_by", "")
    sort_order = args.get("sort_order", "Asc")
    next_page_cursor = args.get("next_page_cursor", "")
    statuses = argToList(args.get("statuses"))
    severities = argToList(args.get("severities"))
    application_ids = argToList(args.get("application_ids"))
    repository_ids = argToList(args.get("repository_ids"))

    # Validate page_size
    page_size = arg_to_number(args.get("page_size", "50"), arg_name="page_size", required=False)
    if page_size is None or page_size <= 0:
        raise ValueError(ERROR_MESSAGES["INVALID_INTEGER"].format(args.get("page_size"), "page_size"))
    if page_size > MAX_ISSUE_PAGE_SIZE:
        raise ValueError(ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(page_size, MAX_ISSUE_PAGE_SIZE))

    query_params: dict[str, Any] = {"size": page_size}

    if next_page_cursor:
        query_params["cursor"] = next_page_cursor

    # The incident issues API supports only size and cursor
    if args.get("incident_id"):
        return query_params

    # Validate statuses
    for status in statuses:
        if status.lower() not in STATUS_LIST:
            raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "statuses", STATUS_HUMAN_READABLE_LIST))

    # Validate severities
    for severity in severities:
        if severity.title() not in SEVERITY_HUMAN_READABLE_LIST:
            raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(severity, "severities", SEVERITY_HUMAN_READABLE_LIST))

    # Validate sort_order
    if sort_order and sort_order.title() not in SORT_ORDER_VALID_VALUES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_order, "sort_order", SORT_ORDER_VALID_VALUES))

    # Validate sort_by
    if sort_by and sort_by.lower() not in SORT_BY_VALID_VALUES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_by, "sort_by", SORT_BY_VALID_VALUES))

    # Time filters are inclusive on both ends
    time_filters = {
        arg_name: arg_to_datetime(
            args.get(arg_name), arg_name=arg_name, settings={"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}
        )
        for arg_name in ISSUE_TIME_FILTER_MAPPING
    }

    # Validate time ranges
    for after_arg, before_arg in (("created_after", "created_before"), ("modified_after", "modified_before")):
        after_time, before_time = time_filters[after_arg], time_filters[before_arg]
        if after_time and before_time and after_time > before_time:
            raise ValueError(ERROR_MESSAGES["INVALID_TIME_RANGE"].format(after_arg, before_arg))

    if statuses:
        query_params["statuses"] = ",".join(status.upper() for status in statuses)

    if severities:
        query_params["severities"] = ",".join(severity.upper() for severity in severities)

    if application_ids:
        query_params["applicationIds"] = ",".join(application_ids)

    if repository_ids:
        query_params["repositoryIds"] = ",".join(repository_ids)

    for arg_name, time_filter in time_filters.items():
        if time_filter:
            query_params[ISSUE_TIME_FILTER_MAPPING[arg_name]] = time_filter.strftime(DATE_TIME_FORMAT)

    if sort_by:
        query_params["sort"] = f"{SORT_BY_MAPPING[sort_by.lower()]},{sort_order.lower()}"

    return query_params


def build_incident_observation_list_query_params(args: dict) -> dict[str, Any]:
    """
    Validate the arguments of the contrastsecurity-incident-observation-list command and build the query parameters.

    Args:
        args(dict): arguments obtained from demisto.args().

    Returns:
        dict: Query parameters for the incident observation list request.

    Raises:
        ValueError: If any argument has an invalid value.
    """
    next_page_cursor = args.get("next_page_cursor", "")

    # Validate page_size
    page_size = arg_to_number(args.get("page_size", "10"), arg_name="page_size", required=False)
    if page_size is None or page_size <= 0:
        raise ValueError(ERROR_MESSAGES["INVALID_INTEGER"].format(args.get("page_size"), "page_size"))
    if page_size > MAX_OBSERVATION_PAGE_SIZE:
        raise ValueError(ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(page_size, MAX_OBSERVATION_PAGE_SIZE))

    # Validate created_after and created_before
    date_settings = {"TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": True}
    created_after = arg_to_datetime(args.get("created_after"), arg_name="created_after", settings=date_settings)
    created_before = arg_to_datetime(args.get("created_before"), arg_name="created_before", settings=date_settings)
    if created_after and created_before and created_after > created_before:
        raise ValueError(ERROR_MESSAGES["INVALID_TIME_RANGE"].format("created_after", "created_before"))

    query_params: dict[str, Any] = {"size": page_size}

    if next_page_cursor:
        query_params["cursor"] = next_page_cursor

    if created_after:
        query_params["createdAfter"] = created_after.strftime(DATE_TIME_FORMAT)

    if created_before:
        query_params["createdBefore"] = created_before.strftime(DATE_TIME_FORMAT)

    return query_params


def trim_spaces_from_args(args):
    """
    Trim spaces from values of the args dict.

    Args:
        args: Dict to trim spaces from

    Returns:
        dict: Dict with trimmed spaces from values
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def check_empty(x: Any) -> bool:
    """
    Check if input is empty (None, empty dict, empty list, or empty string).

    :param x: Input to check.
    :type x: Any
    :return: True if x is empty, False otherwise.
    :rtype: bool
    """
    return x is None or x == {} or x == [] or x == ""


def create_markdown_link(text: str, url: str) -> str:
    """
    Create a markdown link, escaping square brackets in the link text.

    Args:
        text(str): Link text.
        url(str): Link URL.

    Returns:
        str: Markdown link.
    """
    escaped_text = text.replace("[", r"\[").replace("]", r"\]")
    return f"[{escaped_text}]({url})"


def escape_markdown_values(hr_content: dict | list[dict]) -> dict | list[dict]:
    """
    Escape the markdown characters of the human-readable values, so that values like "--" are displayed as is.
    Markdown links are kept as is.

    Args:
        hr_content(dict | list[dict]): Human-readable content.

    Returns:
        dict | list[dict]: Human-readable content with the string values escaped.
    """
    if isinstance(hr_content, list):
        return [escape_markdown_values(row) for row in hr_content]  # type: ignore[misc]
    return {
        key: "".join(f"\\{char}" if char in HR_MARKDOWN_CHARS else char for char in value)
        if isinstance(value, str) and not MARKDOWN_LINK_PATTERN.fullmatch(value)
        else value
        for key, value in hr_content.items()
    }


def build_incident_comment_add_output(comment_data: dict, platform_url: str, organization_id: str):
    """
    Build human-readable output and context for incident comment.

    Args:
        comment_data(dict): Comment data from add incident comment API.
        platform_url(str): Platform URL for generating the incident link.
        organization_id(str): Organization ID for generating the incident link.

    Returns:
        tuple: (context, readable_output)
    """
    context = [remove_empty_elements(comment_data)]
    incident_id = comment_data.get("incidentId", "")
    incident_link = urljoin(platform_url, URL_PATHS["incident"].format(organization_id, incident_id))
    hr_content = [
        {
            "Comment ID": comment_data.get("commentId", ""),
            "User UID": comment_data.get("userUid", ""),
            "Comment Text": comment_data.get("commentText", ""),
            "Created At": comment_data.get("createdTime", ""),
        }
    ]

    headers = ["Comment ID", "User UID", "Comment Text", "Created At"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown(
        f"Comment added to Incident {create_markdown_link(incident_id, incident_link)}",
        escape_markdown_values(hr_content),
        headers=headers,
        removeNull=True,
    )

    return context, readable_output


def build_incident_status_update_output(incident_data: dict, platform_url: str, organization_id: str) -> tuple:
    """
    Build human-readable output and context for incident status update.
    Args:
        incident_data(dict): Incident data obtained from incident status update API.
        platform_url(str): Platform URL for generating the incident link.
        organization_id(str): Organization ID for generating the incident link.
    Returns:
        tuple: (context, readable_output)

    """
    context = [remove_empty_elements(incident_data)]
    incident_id = incident_data.get("incidentId", "")
    incident_link = urljoin(platform_url, URL_PATHS["incident"].format(organization_id, incident_id))

    hr_content = [
        {
            "Incident ID": create_markdown_link(incident_id, incident_link),
            "Status": (incident_data.get("status") or "").title(),
            "Close Reason": CLOSE_REASON_REVERSE_MAPPING.get(
                incident_data.get("closedReason") or "", incident_data.get("closedReason") or ""
            ),
        }
    ]

    headers = ["Incident ID", "Status", "Close Reason"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown(
        "Incident status updated successfully", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return context, readable_output


def build_ip_block_output(raw_response: dict) -> tuple:
    """
    Build human-readable output and context for IP block command.

    Args:
        raw_response (dict): Created IP policy containing uuid, ip, name, trusted, expirationTime and environments.

    Returns:
        tuple: (context, readable_output)
    """
    context = [remove_empty_elements(raw_response)]

    hr_content = [
        {
            "Policy ID": raw_response.get("uuid", ""),
            "Policy Name": raw_response.get("name", ""),
            "Blocked IP": raw_response.get("ip", ""),
            "Expiration Date": raw_response.get("expirationTime") or "Forever",
        }
    ]

    headers = ["Policy ID", "Policy Name", "Blocked IP", "Expiration Date"]
    readable_output = tableToMarkdown(
        "IP address blocked successfully", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return context, readable_output


def build_adr_rule_update_output(raw_response: dict, application_id: str) -> tuple:
    """
    Build human-readable output and context for ADR rule update command.

    Args:
        raw_response (dict): Updated ADR rule containing ruleId, ruleName, ruleDescription, devMode, qaMode, prodMode,
            canBlock, canBlockAtPerimeter and isMonitorAtPerimeter.
        application_id (str): ID of the application the ADR rule belongs to.

    Returns:
        tuple: (context, readable_output)
    """
    context = remove_empty_elements({**raw_response, "applicationId": application_id})

    hr_content = [
        {
            "Application ID": application_id,
            "Rule ID": raw_response.get("ruleId", ""),
            "Rule Name": raw_response.get("ruleName", ""),
            "Rule Description": raw_response.get("ruleDescription", ""),
            "Development Mode": RULE_MODE_REVERSE_MAPPING.get(raw_response.get("devMode", ""), raw_response.get("devMode", "")),
            "QA Mode": RULE_MODE_REVERSE_MAPPING.get(raw_response.get("qaMode", ""), raw_response.get("qaMode", "")),
            "Production Mode": RULE_MODE_REVERSE_MAPPING.get(raw_response.get("prodMode", ""), raw_response.get("prodMode", "")),
        }
    ]

    headers = ["Application ID", "Rule ID", "Rule Name", "Rule Description", "Development Mode", "QA Mode", "Production Mode"]
    readable_output = tableToMarkdown(
        "ADR rule updated successfully", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return context, readable_output


def build_issues_list_output(issues: list[dict[str, Any]], platform_url: str, organization_id: str) -> tuple:
    """
    Build human-readable output and context for issues list.

    Args:
        issues(list): List of issue data from the API response content.
        platform_url(str): Platform URL for generating issue and application links.
        organization_id(str): Organization ID for generating issue and application links.

    Returns:
        tuple: (context, readable_output)
    """
    context = deepcopy(issues)
    hr_content = []

    for issue in context:
        issue_id = issue.get("issueId", "")
        issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
        issue["issueLink"] = issue_link

        application_name = issue.get("applicationName", "")
        application_id = issue.get("applicationId", "")
        application_display = application_name
        if application_id and application_name:
            application_link = urljoin(platform_url, URL_PATHS["application"].format(organization_id, application_id))
            issue["applicationLink"] = application_link
            application_display = create_markdown_link(application_name, application_link)

        hr_content.append(
            {
                "Severity": (issue.get("severity") or "").title(),
                "Contrast Score": issue.get("score", ""),
                "Issue": issue.get("title", ""),
                "Issue ID": create_markdown_link(issue_id, issue_link),
                "Status": (issue.get("status") or "").title(),
                "Application Name": application_display,
                "Application ID": application_id,
                "Number of Observations": issue.get("observationCount", ""),
                "Last Detected": issue.get("lastObservedTime", ""),
                "Environments": ", ".join(issue.get("environments") or []),
            }
        )

    headers = [
        "Severity",
        "Contrast Score",
        "Issue",
        "Issue ID",
        "Status",
        "Application Name",
        "Application ID",
        "Number of Observations",
        "Last Detected",
        "Environments",
    ]

    readable_output: str = tableToMarkdown(
        "Contrast Security Issues", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return context, readable_output


def build_issue_get_output(issue: dict[str, Any], platform_url: str, organization_id: str) -> tuple[dict[str, Any], str]:
    """
    Build human-readable output and context for a single issue.

    Args:
        issue(dict): Issue data from the get issue API response.
        platform_url(str): Platform URL for generating the issue and application links.
        organization_id(str): Organization ID for generating the issue and application links.

    Returns:
        tuple: (context, readable_output)
    """
    context = deepcopy(issue)

    issue_id = issue.get("issueId", "")
    issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
    context["issueLink"] = issue_link

    application_name = issue.get("applicationName", "")
    application_id = issue.get("applicationId", "")
    application_display = application_name
    if application_id and application_name:
        application_link = urljoin(platform_url, URL_PATHS["application"].format(organization_id, application_id))
        context["applicationLink"] = application_link
        application_display = create_markdown_link(application_name, application_link)

    cves = [cve for cve in issue.get("cves") or [] if isinstance(cve, dict) and cve.get("id")]
    status = (issue.get("status") or "").replace("_", " ").title()
    severity = (issue.get("severity") or "").replace("_", " ").title()

    hr_content = {
        "Issue ID": create_markdown_link(issue_id, issue_link),
        "Issue": issue.get("title", ""),
        "Description": issue.get("description", ""),
        "Recommendation": issue.get("recommendation", ""),
        "Status": status,
        "Severity": severity,
        "Contrast Score": issue.get("score", ""),
        "Rule ID": issue.get("ruleId", ""),
        "Rule": issue.get("ruleName", ""),
        "CVEs": ", ".join(cve.get("id", "") for cve in cves),
        "Application Name": application_display,
        "Application ID": application_id,
        "Application Language": issue.get("applicationLanguage", ""),
        "Repository": issue.get("repositoryName", ""),
        "Repository ID": issue.get("repositoryId", ""),
        "HTTP Route": issue.get("httpRoute", ""),
        "Environments": ", ".join(issue.get("environments") or []),
        "Data Types": ", ".join(issue.get("dataTypes") or []),
        "Targets": ", ".join(issue.get("targets") or []),
        "Sensors": ", ".join(issue.get("sensors") or []),
        "Techniques": ", ".join(issue.get("techniques") or []),
        "Incident Count": issue.get("incidentCount", ""),
        "Number of Observations": issue.get("observationCount", ""),
        "Attack Count": issue.get("attackCount", ""),
        "Blocked Attack Count": issue.get("blockedAttackCount", ""),
        "Exploited Attack Count": issue.get("exploitedAttackCount", ""),
        "Suspicious Attack Count": issue.get("suspiciousAttackCount", ""),
        "Created": issue.get("createdTime", ""),
        "Updated": issue.get("updatedTime", ""),
        "Closed": issue.get("closedTime", ""),
        "Last Attacked": issue.get("lastAttackedTime", ""),
        "Last Detected": issue.get("lastObservedTime", ""),
        "Runbook URL": issue.get("runbookUrl", ""),
    }

    headers = list(hr_content.keys())

    readable_output: str = tableToMarkdown(
        "Contrast Security Issue", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return remove_empty_elements(context), readable_output


def build_issue_comment_add_output(comment_data: dict, platform_url: str, organization_id: str):
    """
    Build human-readable output and context for issue comment.

    Args:
        comment_data(dict): Comment data from add issue comment API.
        platform_url(str): Platform URL for generating the issue link.
        organization_id(str): Organization ID for generating the issue link.

    Returns:
        tuple: (context, readable_output)
    """
    context = [remove_empty_elements(comment_data)]
    issue_id = comment_data.get("issueId", "")
    issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
    hr_content = [
        {
            "Comment ID": comment_data.get("commentId", ""),
            "User UID": comment_data.get("userUid", ""),
            "Comment Text": comment_data.get("commentText", ""),
            "Created At": comment_data.get("createdTime", ""),
        }
    ]

    headers = ["Comment ID", "User UID", "Comment Text", "Created At"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown(
        f"Comment added to Issue {create_markdown_link(issue_id, issue_link)}",
        escape_markdown_values(hr_content),
        headers=headers,
        removeNull=True,
    )

    return context, readable_output


def build_issue_status_update_output(issue_data: dict, platform_url: str, organization_id: str) -> tuple:
    """
    Build human-readable output and context for issue status update.
    Args:
        issue_data(dict): Issue data obtained from issue status update API.
        platform_url(str): Platform URL for generating the issue link.
        organization_id(str): Organization ID for generating the issue link.
    Returns:
        tuple: (context, readable_output)

    """
    context = [remove_empty_elements(issue_data)]
    issue_id = issue_data.get("issueId", "")
    issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))

    hr_content = [
        {
            "Issue ID": create_markdown_link(issue_id, issue_link),
            "Status": (issue_data.get("status") or "").title(),
        }
    ]

    headers = ["Issue ID", "Status"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown(
        "Issue status updated successfully", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return context, readable_output


def build_observation_get_output(
    observation: dict[str, Any], platform_url: str, organization_id: str
) -> tuple[dict[str, Any], str]:
    """
    Build human-readable output and context for a single observation.

    Args:
        observation(dict): Observation data from the get observation API response.
        platform_url(str): Platform URL for generating the observation, issue and application links.
        organization_id(str): Organization ID for generating the observation, issue and application links.

    Returns:
        tuple: (context, readable_output)
    """
    context = deepcopy(observation)

    observation_id = observation.get("observationId", "")
    observation_link = observation.get("uiUrl") or urljoin(
        platform_url, URL_PATHS["observation"].format(organization_id, observation_id)
    )
    context["observationLink"] = observation_link

    issue_id = observation.get("issueId", "")
    issue_display = issue_id
    if issue_id:
        issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
        context["issueLink"] = issue_link
        issue_display = create_markdown_link(issue_id, issue_link)

    application = observation.get("application") or {}
    application_name = application.get("name", "")
    application_id = application.get("id", "")
    application_display = application_name
    if application_id and application_name:
        application_link = urljoin(platform_url, URL_PATHS["application"].format(organization_id, application_id))
        context["applicationLink"] = application_link
        application_display = create_markdown_link(application_name, application_link)

    server = observation.get("server") or {}
    application_metadata = observation.get("applicationMetadata") or {}
    data_type = observation.get("dataType") or ""
    mitre_tactics = ", ".join(tactic.get("name", "") for tactic in observation.get("mitreTactics") or [])
    result = (observation.get("result") or "").replace("_", " ").capitalize()

    observation_info = {
        "Observation ID": create_markdown_link(observation_id, observation_link),
        "Issue ID": issue_display,
        "Type": data_type.capitalize(),
        "Severity": (observation.get("severity") or "").title(),
        "Rule Name": observation.get("ruleName", ""),
        "Rule ID": observation.get("ruleId", ""),
        "Result": result,
        "Application Name": application_display,
        "Application ID": application_id,
        "Application Language": observation.get("language", ""),
        "Server": server.get("name", ""),
        "Server ID": server.get("id", ""),
        "Environment": observation.get("environment", ""),
        "HTTP Route": observation.get("httpRoute", ""),
        "Target": (observation.get("target") or "").capitalize(),
        "Technique": (observation.get("technique") or "").capitalize(),
        "MITRE Tactics": mitre_tactics,
        "Agent Version": observation.get("agentVersion", ""),
        "Virtual Patch UUID": observation.get("virtualPatchUuid", ""),
        "Deny List UUID": observation.get("denyListUuid", ""),
        "Application Metadata": ", ".join(f"{key}: {value}" for key, value in application_metadata.items()),
        "Detected": observation.get("detectedTime", ""),
    }

    readable_output = tableToMarkdown(
        "Observation Information",
        escape_markdown_values(observation_info),
        headers=list(observation_info.keys()),
        removeNull=True,
    )

    if data_type.upper() == "ATTACK":
        readable_output += build_attack_observation_details(observation)

    return remove_empty_elements(context), readable_output


def build_attack_observation_details(observation: dict[str, Any]) -> str:
    """
    Build attack-specific observation details with attack value, vector analysis, request and code location information.

    Args:
        observation(dict): Attack observation data from the get observation API response.

    Returns:
        str: Markdown-formatted tables for the attack details. Tables without any value are skipped.
    """
    attack_payload = observation.get("attackPayload") or {}
    vector_analysis = observation.get("vectorAnalysis") or {}
    vector_fields = vector_analysis.get("vectorFields") or {}
    request = observation.get("request") or {}
    code_location = observation.get("codeLocation") or {}

    sections = {
        "Attack Value": {
            "Source IP": observation.get("sourceIp", ""),
            "URL": attack_payload.get("url", ""),
            "Attack Payload Value": attack_payload.get("value", ""),
        },
        "Vector Analysis": {
            "Vector Fields": ", ".join(f"{key}: {value}" for key, value in vector_fields.items()),
            "Call Location": vector_analysis.get("callLocation", ""),
        },
        "Request Details": {
            "Request Details": build_observation_request_details(request, observation.get("httpRoute") or ""),
        },
        "Code Location": {
            "File": code_location.get("file", ""),
            "Line": code_location.get("line", ""),
            "Snippet": code_location.get("snippet", ""),
        },
    }

    readable_output = ""
    for title, section in sections.items():
        if any(section.values()):
            readable_output += tableToMarkdown(
                title, escape_markdown_values(section), headers=list(section.keys()), removeNull=True
            )

    return readable_output


def build_observation_request_details(request: dict[str, Any], http_route: str) -> str:
    """
    Build the raw HTTP request text of an observation.

    Args:
        request(dict): Request data of the observation (method, protocol, protocolVersion, headers, body, queryString).
        http_route(str): HTTP route of the request.

    Returns:
        str: The HTTP request line, headers and body separated by new lines. Empty if the request has no details.
    """
    if not request:
        return ""

    query_string = request.get("queryString") or ""
    path = f"{http_route}?{query_string}" if query_string else http_route
    protocol = "/".join(filter(None, [request.get("protocol"), request.get("protocolVersion")])).upper()
    request_line = " ".join(filter(None, [request.get("method"), path, protocol]))

    lines = [request_line]
    for name, value in (request.get("headers") or {}).items():
        # Header values are returned either as a list of values or as a single value
        header_value = ", ".join(value) if isinstance(value, list) else value or ""
        lines.append(f"{name}: {header_value}")

    body = request.get("body") or ""
    if body:
        lines.extend(["", body])

    return "\n".join(lines)


def build_observations_list_output(
    observations: list[dict[str, Any]], platform_url: str, organization_id: str
) -> tuple[list[dict[str, Any]], str]:
    """
    Build human-readable output and context for observations list.

    Args:
        observations(list): List of observation data from the API response content.
        platform_url(str): Platform URL for generating observation, issue and application links.
        organization_id(str): Organization ID for generating observation, issue and application links.

    Returns:
        tuple: (context, readable_output)
    """
    context = deepcopy(observations)
    hr_content = []

    for observation in context:
        observation_id = observation.get("observationId", "")
        observation_link = urljoin(platform_url, URL_PATHS["observation"].format(organization_id, observation_id))
        observation["observationLink"] = observation_link

        issue_id = observation.get("issueId", "")
        issue_display = issue_id
        if issue_id:
            issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
            observation["issueLink"] = issue_link
            issue_display = create_markdown_link(issue_id, issue_link)

        application = observation.get("application") or {}
        application_name = application.get("name", "")
        application_id = application.get("id", "")
        application_display = application_name
        if application_id and application_name:
            application_link = urljoin(platform_url, URL_PATHS["application"].format(organization_id, application_id))
            observation["applicationLink"] = application_link
            application_display = create_markdown_link(application_name, application_link)

        result = (observation.get("result") or "").replace("_", " ").capitalize()

        hr_content.append(
            {
                "Observation ID": create_markdown_link(observation_id, observation_link),
                "Severity": (observation.get("severity") or "").title(),
                "Data Type": (observation.get("dataType") or "").capitalize(),
                "Source IP": observation.get("sourceIp", ""),
                "Associated Issue ID": issue_display,
                "Application Name": application_display,
                "Application ID": application_id,
                "Rule": observation.get("ruleName", ""),
                "Server": (observation.get("server") or {}).get("name", ""),
                "Environment": observation.get("environment", ""),
                "Result": result,
                "URL": observation.get("httpRoute", ""),
                "Attack Value": (observation.get("attackPayload") or {}).get("value", ""),
                "Detected": observation.get("detectedTime", ""),
            }
        )

    headers = [
        "Observation ID",
        "Severity",
        "Source IP",
        "Associated Issue ID",
        "Rule",
        "Application Name",
        "Application ID",
        "Server",
        "Environment",
        "Result",
        "Data Type",
        "URL",
        "Attack Value",
        "Detected",
    ]

    readable_output: str = tableToMarkdown(
        "Contrast Security Incident Observations", escape_markdown_values(hr_content), headers=headers, removeNull=True
    )

    return context, readable_output


def test_module(client: Client, params: dict) -> str:
    """
    Test module for Contrast Security integration.

    Args:
        client: Client object.
        params: Integration parameters.

    Returns:
        str: "ok" if connection with Contrast Security is successful.
    """
    if argToBoolean(params.get("isFetch", False)):
        fetch_incidents(client, params, last_run={}, is_test=True)
    else:
        # Test API connectivity by listing issues
        query_params = {"size": 1}

        client.list_issues(query_params=query_params)

    return "ok"


def contrast_security_incident_comment_add_command(client: Client, args: dict) -> CommandResults:
    """
    Add a comment to a Contrast Security Incident.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    incident_id = validate_argument(args.get("incident_id"), "incident_id")
    comment = validate_argument(args.get("comment"), "comment")

    payload = {"commentText": comment}

    raw_response = client.incident_comment_add(incident_id=incident_id, payload=payload)

    raw_response["incidentId"] = incident_id
    context, hr = build_incident_comment_add_output(
        raw_response, platform_url=client._base_url, organization_id=client.organization_id
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["INCIDENT_COMMENT"],
        outputs_key_field="commentId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_incident_status_update_command(client: Client, args: dict):
    """
    Update the status of a Contrast Security Incident.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    incident_id = validate_argument(args.get("incident_id"), "incident_id")
    status = validate_argument(args.get("status"), "status")
    close_reason = args.get("close_reason", "")

    if status and status.lower() not in STATUS_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", STATUS_HUMAN_READABLE_LIST))

    if status.lower() == "closed" and not close_reason:
        raise ValueError(ERROR_MESSAGES["CLOSE_REASON_REQUIRED"].format("close_reason", status))

    if close_reason and close_reason not in CLOSE_REASON_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(close_reason, "close_reason", CLOSE_REASON_LIST))

    payload = {"status": status.upper()}

    if status.lower() == "closed" and close_reason:
        payload.update({"closedReason": CLOSE_REASON_MAPPING.get(close_reason)})

    raw_response = client.incident_status_update(incident_id=incident_id, payload=payload)

    context, hr = build_incident_status_update_output(
        incident_data=raw_response, platform_url=client._base_url, organization_id=client.organization_id
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["INCIDENT"],
        outputs_key_field="incidentId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_ip_block_command(client: Client, args: dict) -> CommandResults:
    """
    Block an IP address by creating an organization-level IP policy in Contrast Security.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    ip_address = validate_argument(args.get("ip_address"), "ip_address")
    if not is_ip_valid(ip_address, accept_v6_ips=True):
        raise ValueError(ERROR_MESSAGES["INVALID_IP"].format(ip_address, "ip_address"))

    policy_name_prefix = args.get("policy_name_prefix") or DEFAULT_IP_POLICY_NAME_PREFIX

    expiration_date = arg_to_datetime(
        args.get("expiration_date"),
        settings={"TIMEZONE": "UTC", "PREFER_DATES_FROM": "future", "RETURN_AS_TIMEZONE_AWARE": True},
    )

    payload = {
        "ip": ip_address,
        "name": f"{policy_name_prefix} - {ip_address}",
        "trusted": False,
        "environments": {"development": True, "qa": True, "production": True},
    }

    # expirationTime is omitted for a permanent block
    if expiration_date:
        expiration_time = expiration_date.strftime(DATE_TIME_FORMAT)
        if expiration_date <= datetime.now(timezone.utc):
            raise ValueError(ERROR_MESSAGES["INVALID_TIMESTAMP"].format("expiration_date", expiration_time))
        payload["expirationTime"] = expiration_time

    raw_response = client.create_ip_policy(payload)

    context, hr = build_ip_block_output(raw_response)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["IP_POLICY"],
        outputs_key_field="uuid",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_adr_rule_update_command(client: Client, args: dict) -> CommandResults:
    """
    Update the modes of an ADR rule for a Contrast Security application.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    application_id = validate_argument(args.get("application_id"), "application_id")
    rule_id = validate_argument(args.get("rule_id"), "rule_id")
    modes = {
        "devMode": args.get("dev_mode", ""),
        "qaMode": args.get("qa_mode", ""),
        "prodMode": args.get("prod_mode", ""),
    }

    # Validate each provided mode with correct field name in error message
    for mode, field_name in [
        (modes["devMode"], "dev_mode"),
        (modes["qaMode"], "qa_mode"),
        (modes["prodMode"], "prod_mode"),
    ]:
        if mode and mode.capitalize() not in RULE_MODE_MAPPING:
            raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(mode, field_name, RULE_MODE_HUMAN_READABLE_LIST))

    if not any(modes.values()):
        raise ValueError(ERROR_MESSAGES["ADR_RULE_MODE_REQUIRED"])

    # All three modes are required in the request body, so keep the current mode of the rule for the modes not provided
    current_rule = {}
    if not all(modes.values()):
        current_rule = client.adr_rule_get(application_id=application_id, rule_id=rule_id)

    payload = {key: RULE_MODE_MAPPING[mode.capitalize()] if mode else current_rule.get(key) for key, mode in modes.items()}

    raw_response = client.adr_rule_update(application_id=application_id, rule_id=rule_id, payload=payload)

    context, hr = build_adr_rule_update_output(raw_response, application_id)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ADR_RULE"],
        outputs_key_field=["applicationId", "ruleId"],
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_issue_get_command(client: Client, args: dict) -> CommandResults:
    """
    Get a specific Contrast Security Issue by ID.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    issue_id = validate_argument(args.get("issue_id"), "issue_id")

    raw_response = client.get_issue(issue_id=issue_id)

    context, hr = build_issue_get_output(raw_response, platform_url=client._base_url, organization_id=client.organization_id)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUE"],
        outputs_key_field="issueId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_issue_list_command(client: Client, args: dict) -> CommandResults:
    """
    List Contrast Security Issues with provided filter parameters.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    incident_id = args.get("incident_id", "")
    query_params = build_issue_list_query_params(args)

    if incident_id:
        raw_response = client.list_incident_issues(incident_id=incident_id, query_params=query_params)
    else:
        raw_response = client.list_issues(query_params=query_params)

    issues = raw_response.get("content", [])

    if not issues:
        return CommandResults(readable_output="No issues were found for the given filters.")

    context, hr = build_issues_list_output(issues, platform_url=client._base_url, organization_id=client.organization_id)
    # Add the issue links to the raw response for the ContrastSecurityDisplayIncidentIssues script
    for issue, issue_context in zip(issues, context):
        issue["issueLink"] = issue_context.get("issueLink")

    has_next_page = raw_response.get("hasMore", False)
    # Send an empty cursor on the last page, so it overwrites the previous cursor in the merged context
    cursor = raw_response.get("cursor") if has_next_page else ""
    next_page_context = {
        "next_page_cursor": cursor,
        "name": "contrastsecurity-issue-list",
        "has_next_page": has_next_page,
    }
    if cursor:
        hr += (
            f"\nTo retrieve the next set of results, run the command with the same filters and **next_page_cursor** = `{cursor}`."
        )

    outputs = {
        f"{OUTPUT_PREFIX['ISSUE']}(val.issueId == obj.issueId)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_ISSUE']}(val.name == obj.name)": next_page_context,
    }

    return CommandResults(outputs=remove_empty_elements(outputs), raw_response=raw_response, readable_output=hr)


def contrast_security_issue_comment_add_command(client: Client, args: dict) -> CommandResults:
    """
    Add a comment to a Contrast Security Issue.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    issue_id = validate_argument(args.get("issue_id"), "issue_id")
    comment = validate_argument(args.get("comment"), "comment")

    payload = {"commentText": comment}

    raw_response = client.issue_comment_add(issue_id=issue_id, payload=payload)

    raw_response["issueId"] = issue_id
    context, hr = build_issue_comment_add_output(
        raw_response, platform_url=client._base_url, organization_id=client.organization_id
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUE_COMMENT"],
        outputs_key_field="commentId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_issue_status_update_command(client: Client, args: dict):
    """
    Update the status of a Contrast Security Issue.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    issue_id = validate_argument(args.get("issue_id"), "issue_id")
    status = validate_argument(args.get("status"), "status")

    if status and status.lower() not in STATUS_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", STATUS_HUMAN_READABLE_LIST))

    payload = {"status": status.upper()}

    raw_response = client.issue_status_update(issue_id=issue_id, payload=payload)

    context, hr = build_issue_status_update_output(
        issue_data=raw_response, platform_url=client._base_url, organization_id=client.organization_id
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUE"],
        outputs_key_field="issueId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_observation_get_command(client: Client, args: dict) -> CommandResults:
    """
    Get a specific Contrast Security Observation by ID.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    observation_id = validate_argument(args.get("observation_id"), "observation_id")

    raw_response = client.get_observation(observation_id=observation_id)

    context, hr = build_observation_get_output(
        raw_response, platform_url=client._base_url, organization_id=client.organization_id
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["OBSERVATION"],
        outputs_key_field="observationId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_incident_observation_list_command(client: Client, args: dict) -> CommandResults:
    """
    List Contrast Security incident Observations with provided filters.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    incident_id = validate_argument(args.get("incident_id"), "incident_id")
    query_params = build_incident_observation_list_query_params(args)

    raw_response = client.list_incident_observations(incident_id=incident_id, query_params=query_params)

    observations = raw_response.get("content", [])

    if not observations:
        return CommandResults(readable_output="No observations were found for the given incident.")

    context, hr = build_observations_list_output(
        observations, platform_url=client._base_url, organization_id=client.organization_id
    )

    has_next_page = raw_response.get("hasMore", False)
    # Send an empty cursor on the last page, so it overwrites the previous cursor in the merged context
    cursor = raw_response.get("cursor") if has_next_page else ""
    next_page_context = {
        "next_page_cursor": cursor,
        "name": "contrastsecurity-incident-observation-list",
        "has_next_page": has_next_page,
    }
    if cursor:
        hr += (
            f"\nTo retrieve the next set of results, run the command with the same filters and **next_page_cursor** = `{cursor}`."
        )

    outputs = {
        f"{OUTPUT_PREFIX['OBSERVATION']}(val.observationId == obj.observationId)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_OBSERVATION']}(val.name == obj.name)": next_page_context,
    }

    return CommandResults(outputs=remove_empty_elements(outputs), raw_response=raw_response, readable_output=hr)


def fetch_contrast_incidents(
    client: Client,
    last_run: dict,
    params: dict,
    max_fetch: int,
    first_fetch: str,
    start_time: float,
    is_test: bool = False,
) -> tuple[dict, list[dict]]:
    """
    Fetch Contrast Security Incidents as XSOAR incidents.

    Each run lists one page of incidents created after the last run, sorted by created time in ascending order,
    and retrieves the details of each new incident. The cursor moves to the next page only after the whole page is
    processed. When all pages are processed, the latest created time becomes the next created after. As created after
    is inclusive, the latest fetched IDs are kept to skip them in the next run. Later changes to fetched
    incidents are synced through mirroring.

    Args:
        client: Contrast Security API client.
        last_run: Last run object obtained from demisto.getLastRun().
        params: Integration parameters.
        max_fetch: Maximum number of incidents to fetch per run.
        first_fetch: First fetch time in RFC 3339 format.
        start_time: Start time of the fetch run in seconds since the epoch.
        is_test: Whether this is being called from test-module.

    Returns:
        tuple: Next run object for incidents and list of XSOAR incidents.
    """
    incident_last_run = last_run.get("incident", {})
    created_after = incident_last_run.get("created_after") or first_fetch
    cursor = incident_last_run.get("cursor")
    ingested_ids: list[str] = list(incident_last_run.get("ingested_ids", []))
    demisto.debug(
        f"Last run for Contrast Security incidents: Created after = {created_after}, Cursor = {cursor}, "
        f"Ingested IDs count = {len(ingested_ids)}"
    )
    new_ids: list[str] = []
    statuses = [status.upper() for status in argToList(params.get("incident_statuses"))]
    severities = [severity.upper() for severity in argToList(params.get("incident_severities"))]

    query_params = assign_params(
        createdAfter=created_after,
        statuses=",".join(statuses),
        severities=",".join(severities),
        sort=FETCH_SORT,
        size=max_fetch,
        cursor=cursor,
    )
    response = client.list_incidents(query_params)
    incidents_data = response.get("content", [])
    demisto.debug(f"Fetched {len(incidents_data)} Contrast Security incident(s).")

    if is_test:
        return {}, []

    mirroring_fields = get_mirroring(params, "incident_mirror_direction")
    incidents: list[dict] = []
    latest_created_time = created_after
    is_time_limit_reached = False
    for incident_data in incidents_data:
        incident_id = incident_data.get("incidentId")
        # Records are sorted by created time in ascending order, so the current record is the latest one
        latest_created_time = incident_data.get("createdTime") or latest_created_time

        if incident_id in ingested_ids:
            demisto.debug(f"Skipping already fetched Contrast Security incident {incident_id}.")
            continue

        if time.time() - start_time > FETCH_TIME_LIMIT_SECONDS:
            demisto.debug(f"Fetch time limit of {FETCH_TIME_LIMIT_SECONDS} seconds reached. Keeping the current cursor.")
            is_time_limit_reached = True
            break

        contrast_incident = client.get_incident(incident_id)
        contrast_incident.update(
            {
                "eventType": INCIDENT_EVENT_TYPE,
                "organizationUuid": contrast_incident.get("organizationId") or client.organization_id,
            }
        )
        contrast_incident.update(mirroring_fields)
        raw_json = remove_empty_elements_for_fetch(contrast_incident)
        incidents.append(
            {
                "name": raw_json.get("incidentName") or f"{DEFAULT_INCIDENT_NAME}: {incident_id}",
                "occurred": raw_json.get("createdTime"),
                "dbotMirrorId": incident_id,
                "severity": SEVERITY_MAP.get(raw_json.get("severity", ""), 0),
                "rawJSON": json.dumps(raw_json),
            }
        )
        ingested_ids.append(incident_id)
        new_ids.append(incident_id)

    incident_next_run = {"created_after": created_after, "cursor": cursor, "ingested_ids": ingested_ids}
    # Keep the current cursor when the time limit is reached, so the same page is listed again in the next run
    if not is_time_limit_reached:
        if response.get("hasMore") and response.get("cursor"):
            incident_next_run["cursor"] = response.get("cursor")
        else:
            # All pages are processed, so the next run starts from the latest created time.
            incident_next_run.update({"created_after": latest_created_time, "cursor": None})

    demisto.debug(
        f"Checkpoint for Contrast Security incidents: Created after = {incident_next_run.get('created_after')}, "
        f"Cursor = {incident_next_run.get('cursor')}"
    )
    demisto.debug(f"Ingested Contrast Security incident IDs in this run: {', '.join(new_ids)}")
    return incident_next_run, incidents


def fetch_contrast_issues(
    client: Client,
    last_run: dict,
    params: dict,
    max_fetch: int,
    first_fetch: str,
    start_time: float,
    is_test: bool = False,
) -> tuple[dict, list[dict]]:
    """
    Fetch Contrast Security Issues as XSOAR incidents.

    Each run lists one page of issues created after the last run, sorted by created time in ascending order,
    and retrieves the details of each new issue. The cursor moves to the next page only after the whole page is
    processed. When all pages are processed, the latest created time becomes the next created after. As created after
    is inclusive, the latest fetched IDs are kept to skip them in the next run. Later changes to fetched
    issues are synced through mirroring.

    Args:
        client: Contrast Security API client.
        last_run: Last run object obtained from demisto.getLastRun().
        params: Integration parameters.
        max_fetch: Maximum number of issues to fetch per run.
        first_fetch: First fetch time in RFC 3339 format.
        start_time: Start time of the fetch run in seconds since the epoch.
        is_test: Whether this is being called from test-module.

    Returns:
        tuple: Next run object for issues and list of XSOAR incidents.
    """
    issue_last_run = last_run.get("issue", {})
    created_after = issue_last_run.get("created_after") or first_fetch
    cursor = issue_last_run.get("cursor")
    ingested_ids: list[str] = list(issue_last_run.get("ingested_ids", []))
    demisto.debug(
        f"Last run for Contrast Security issues: Created after = {created_after}, Cursor = {cursor}, "
        f"Ingested IDs count = {len(ingested_ids)}"
    )
    new_ids: list[str] = []
    statuses = [status.upper() for status in argToList(params.get("issue_statuses"))]
    severities = [severity.upper() for severity in argToList(params.get("issue_severities"))]

    query_params = assign_params(
        createdAfter=created_after,
        statuses=",".join(statuses),
        severities=",".join(severities),
        sort=FETCH_SORT,
        size=max_fetch,
        cursor=cursor,
    )
    response = client.list_issues(query_params)
    issues_data = response.get("content", [])
    demisto.debug(f"Fetched {len(issues_data)} Contrast Security issue(s).")

    if is_test:
        return {}, []

    mirroring_fields = get_mirroring(params, "issue_mirror_direction")
    incidents: list[dict] = []
    latest_created_time = created_after
    is_time_limit_reached = False
    for issue_data in issues_data:
        issue_id = issue_data.get("issueId")
        # Records are sorted by created time in ascending order, so the current record is the latest one
        latest_created_time = issue_data.get("createdTime") or latest_created_time

        if issue_id in ingested_ids:
            demisto.debug(f"Skipping already fetched Contrast Security issue {issue_id}.")
            continue

        if time.time() - start_time > FETCH_TIME_LIMIT_SECONDS:
            demisto.debug(f"Fetch time limit of {FETCH_TIME_LIMIT_SECONDS} seconds reached. Keeping the current cursor.")
            is_time_limit_reached = True
            break

        contrast_issue = client.get_issue(issue_id)
        # Keys expected by the incoming mapper
        contrast_issue.update(
            {
                "eventType": ISSUE_EVENT_TYPE,
                "organizationUuid": client.organization_id,
                "url": urljoin(client._base_url, URL_PATHS["issue"].format(client.organization_id, issue_id)),
            }
        )
        contrast_issue.update(mirroring_fields)
        raw_json = remove_empty_elements_for_fetch(contrast_issue)
        incidents.append(
            {
                "name": raw_json.get("title") or f"{DEFAULT_ISSUE_NAME}: {issue_id}",
                "occurred": raw_json.get("createdTime"),
                "dbotMirrorId": issue_id,
                "severity": SEVERITY_MAP.get(raw_json.get("severity", ""), 0),
                "rawJSON": json.dumps(raw_json),
            }
        )
        ingested_ids.append(issue_id)
        new_ids.append(issue_id)

    issue_next_run = {"created_after": created_after, "cursor": cursor, "ingested_ids": ingested_ids}
    # Keep the current cursor when the time limit is reached, so the same page is listed again in the next run
    if not is_time_limit_reached:
        if response.get("hasMore") and response.get("cursor"):
            issue_next_run["cursor"] = response.get("cursor")
        else:
            # All pages are processed, so the next run starts from the latest created time.
            issue_next_run.update({"created_after": latest_created_time, "cursor": None})

    demisto.debug(
        f"Checkpoint for Contrast Security issues: Created after = {issue_next_run.get('created_after')}, "
        f"Cursor = {issue_next_run.get('cursor')}"
    )
    demisto.debug(f"Ingested Contrast Security issue IDs in this run: {', '.join(new_ids)}")
    return issue_next_run, incidents


def fetch_incidents(client: Client, params: dict, last_run: dict, is_test: bool = False) -> tuple[dict, list[dict]]:
    """
    Fetch Contrast Security Incidents or Issues as XSOAR incidents based on the configured event type.

    Args:
        client: Contrast Security API client.
        params: Integration parameters.
        last_run: Last run object obtained from demisto.getLastRun(), with a separate state for each event type.
        is_test: Whether this is being called from test-module.

    Returns:
        tuple: Next run object and list of XSOAR incidents.
    """
    start_time = time.time()
    event_type, max_fetch, first_fetch = validate_fetch_params(params)
    demisto.debug(f"Fetching Contrast Security {event_type}.")

    next_run = last_run.copy()
    if event_type == EVENT_TYPES[0]:
        next_state, incidents = fetch_contrast_incidents(client, last_run, params, max_fetch, first_fetch, start_time, is_test)
        next_run["incident"] = next_state
    else:
        next_state, incidents = fetch_contrast_issues(client, last_run, params, max_fetch, first_fetch, start_time, is_test)
        next_run["issue"] = next_state

    demisto.debug(f"Fetched {len(incidents)} incident(s) for {event_type}.")
    return next_run, incidents


def update_integration_context_with_retries(update_fn: Callable[..., Any], *args: Any) -> Any:
    """
    Applies an update to the latest integration context and saves it with a version check.
    If the context was modified by another process in between, re-reads it and retries.

    Args:
        update_fn (Callable[..., Any]): Function that modifies the given integration context in place.
            Called as update_fn(integration_context, *args).
        *args (Any): Additional arguments passed to update_fn.

    Returns:
        Any: The value returned by update_fn.
    """
    for attempt in range(1, MAX_CONTEXT_UPDATE_RETRIES + 1):
        integration_context, version = get_integration_context_with_version()
        result = update_fn(integration_context, *args)
        try:
            set_integration_context(integration_context, version=version)
            return result
        except ValueError as e:
            demisto.debug(f"Integration context version conflict: {e}. Attempt {attempt}/{MAX_CONTEXT_UPDATE_RETRIES}.")

    raise DemistoException("Failed updating integration context. Max retry attempts exceeded.")


def update_processed_incidents(integration_context: dict, incident_id: str, is_active: bool) -> list:
    """
    Adds the incident ID to the processed incidents when the incident is active, else removes it.

    Args:
        integration_context (dict): The integration context to update in place.
        incident_id (str): The Contrast Security incident ID.
        is_active (bool): Whether the incident is active in XSOAR.

    Returns:
        list: The updated processed incidents list.
    """
    processed_incidents = integration_context.get("processed_incidents") or []
    if is_active and incident_id not in processed_incidents:
        processed_incidents.append(incident_id)
    elif not is_active and incident_id in processed_incidents:
        processed_incidents.remove(incident_id)

    integration_context["processed_incidents"] = processed_incidents[-MAX_INCIDENTS_MIRRORING_LIMIT:]
    return integration_context["processed_incidents"]


def close_in_xsoar(entries: list, incident_id: str, status: str, close_reason: str) -> None:
    """
    Append a close entry to entries so XSOAR closes the mirrored incident.

    :type entries: list
    :param entries: List of entries where the closing entry will be appended.
    :type incident_id: str
    :param incident_id: The Contrast Security incident ID.
    :type status: str
    :param status: The Contrast Security incident status that triggered the closure.
    :type close_reason: str
    :param close_reason: The XSOAR close reason mapped from the Contrast Security closed reason.
    """
    demisto.debug(
        f"Closing XSOAR incident for Contrast Security incident {incident_id} via Incoming Mirroring. "
        f"Due to status: {status} is same as configured close status. Close reason: {close_reason}."
    )
    entries.append(
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": close_reason,
                "closeNotes": f"Incident closed because Contrast Security incident status '{status}' "
                "matches the configured close status.",
            },
            "ContentsFormat": EntryFormat.JSON,
        }
    )


def reopen_in_xsoar(entries: list, incident_id: str, status: str) -> None:
    """
    Append a reopen entry to entries so XSOAR reopens the mirrored incident.

    :type entries: list
    :param entries: List of entries where the reopening entry will be appended.
    :type incident_id: str
    :param incident_id: The Contrast Security incident ID.
    :type status: str
    :param status: The Contrast Security incident status that triggered the reopen.
    """
    demisto.debug(
        f"Reopening XSOAR incident for Contrast Security incident {incident_id} via Incoming Mirroring. "
        f"Due to status: {status} is same as configured open status."
    )
    entries.append({"Type": EntryType.NOTE, "Contents": {"dbotIncidentReopen": True}, "ContentsFormat": EntryFormat.JSON})


def get_remote_data_command(client: Client, args: dict, params: dict):
    """
    Incoming mirroring: fetch the latest state of a single Contrast Security incident
    and push it into the corresponding XSOAR incident.

    Called once per mirrored incident every mirror-job interval (default 1 min).

    Args:
        client: Contrast Security API client.
        args: Command arguments supplied by the XSOAR mirroring engine.
              Expected keys: remoteId, lastUpdate.
        params: Integration configuration parameters.

    Returns:
        GetRemoteDataResponse with updated incident fields and optional close/reopen entry.
    """
    dbot_mirror_id: str = args.get("id")  # type: ignore
    demisto.debug(f"Processing Contrast Security incident update for mirror ID: {dbot_mirror_id}")

    if not dbot_mirror_id:
        return "Contrast Security Remote Incident was not found."  # type: ignore

    demisto.debug(f"get-remote-data called for incident {dbot_mirror_id}")

    reopen_closed_incident = argToBoolean(params.get("reopen_closed_incident", False))
    close_active_incident = argToBoolean(params.get("close_active_incident", False))

    remote_incident_data = client.get_incident(dbot_mirror_id)
    status = remote_incident_data.get("status") or ""
    close_reason = CONTRAST_TO_XSOAR_CLOSE_REASON.get(remote_incident_data.get("closedReason") or "", "Other")

    # Build the mirrored field update that XSOAR will apply to the incident.
    # Keys match the fetched record, so the incoming mapper updates all the incident fields.
    mirrored_object = remote_incident_data
    mirrored_object["organizationUuid"] = remote_incident_data.get("organizationId") or client.organization_id
    remove_nulls_from_dictionary(mirrored_object)

    integration_context = get_integration_context() or {}
    demisto.debug(f"Before Incoming mirroring existing integration context : {integration_context}")
    processed_incidents = integration_context.get("processed_incidents") or []
    mirroring_direction = params.get("incident_mirror_direction") or ""

    # When direction is incoming-only, no outgoing mirroring populates processed_incidents
    # so in that can no ids found in processed_incidents so we bypass it to allow close/reopen unconditionally.
    close_incident_in_xsoar = dbot_mirror_id in processed_incidents or mirroring_direction.lower() == "incoming"
    open_incident_in_xsoar = dbot_mirror_id not in processed_incidents or mirroring_direction.lower() == "incoming"

    entries: list[dict] = []
    if status.upper() == "CLOSED" and close_active_incident and close_incident_in_xsoar:
        close_in_xsoar(entries, dbot_mirror_id, status, close_reason)
    elif status.upper() == "OPEN" and reopen_closed_incident and open_incident_in_xsoar:
        reopen_in_xsoar(entries, dbot_mirror_id, status)

    # Track processed incidents only when the incident is closed or reopened in XSOAR.
    # Skip the write if the incident ID is already added or removed.
    is_active = status.upper() == "OPEN"
    if entries and is_active != (dbot_mirror_id in processed_incidents):
        try:
            update_integration_context_with_retries(update_processed_incidents, dbot_mirror_id, is_active)
            demisto.debug(f"Updated {dbot_mirror_id} in processed incidents. Active: {is_active}.")
        except DemistoException as e:
            # Log and continue, so the close/reopen entry is still returned to XSOAR
            demisto.error(f"Failed to update {dbot_mirror_id} in processed incidents: {str(e)}")

    demisto.debug(f"Returning mirrored data for {dbot_mirror_id}: status={status}")
    return GetRemoteDataResponse(mirrored_object, entries=entries)


def get_modified_remote_data_command(client: Client, args: dict):
    """
    Incoming mirroring: return the list of Contrast Security incident IDs that have
    been modified since the last mirror run.

    XSOAR calls this every mirror-job interval. For each returned ID it will
    subsequently call get-remote-data to pull the full update.

    Lists the incidents modified after the last update and pages through the results
    with the cursor until there are no more pages or the mirroring limit is reached.

    Args:
        client: Contrast Security API client.
        args: Command arguments supplied by the XSOAR mirroring engine.
              Expected key: lastUpdate (ISO-8601 timestamp string).

    Returns:
        GetModifiedRemoteDataResponse with list of modified incident IDs.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = arg_to_datetime(remote_args.last_update, arg_name="lastUpdate", required=True)
    query_params = {
        "modifiedAfter": last_update.strftime(DATE_TIME_FORMAT),  # type: ignore[union-attr]
        "size": MAX_MIRRORING_PAGE_SIZE,
    }
    demisto.debug(f"get-modified-remote-data: listing incidents modified after {query_params['modifiedAfter']}")

    modified_incident_ids: list[str] = []
    while True:
        response = client.list_incidents(query_params)
        incidents_data = response.get("content", [])
        demisto.debug(f"get-modified-remote-data: got {len(incidents_data)} incident(s)")

        for incident in incidents_data:
            incident_id = incident.get("incidentId")
            if incident_id:
                modified_incident_ids.append(incident_id)

        next_cursor = response.get("cursor")
        if not (response.get("hasMore") and next_cursor):
            break

        # Mirroring limit
        if len(modified_incident_ids) >= MAX_INCIDENTS_MIRRORING_LIMIT:
            demisto.debug("get-modified-remote-data: max mirroring limit reached.")
            break

        query_params["cursor"] = next_cursor

    # At max MAX_INCIDENTS_MIRRORING_LIMIT incidents should be updated.
    modified_incident_ids = modified_incident_ids[:MAX_INCIDENTS_MIRRORING_LIMIT]
    demisto.debug(f"get-modified-remote-data: returning {len(modified_incident_ids)} modified incident ID(s)")

    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_incident_ids)


def update_remote_status(client: Client, remote_id: str, is_issue: bool, incident_status: int, xsoar_close_reason: str) -> None:
    """
    Outgoing mirroring: update the status of the Contrast Security incident/issue and track the processed incidents.

    A failed status update is logged and not raised, so the notes are still mirrored.
    Processed incidents are tracked only when the incident status is updated in Contrast Security.

    Args:
        client: Contrast Security API client.
        remote_id: The Contrast Security incident/issue ID.
        is_issue: Whether the remote ID is a Contrast Security issue.
        incident_status: The XSOAR incident status.
        xsoar_close_reason: The XSOAR close reason, mapped to the Contrast Security closedReason for incidents.
    """
    contrast_status = XSOAR_TO_CONTRAST_STATUS.get(incident_status)
    if not contrast_status:
        return

    resource_type = "Issue" if is_issue else "Incident"
    demisto.debug(f"Updating Contrast Security {resource_type} {remote_id} status to '{contrast_status}'.")

    try:
        if is_issue:
            client.issue_status_update(issue_id=remote_id, payload={"status": contrast_status})
        else:
            status_payload: dict = {"status": contrast_status}
            if contrast_status == "CLOSED":
                closed_reason = XSOAR_TO_CONTRAST_CLOSE_REASON.get(xsoar_close_reason, "OTHER")
                status_payload["closedReason"] = closed_reason
                demisto.debug(
                    f"Updating Contrast Security incident {remote_id} status to '{contrast_status}' "
                    f"with closedReason '{closed_reason}' (XSOAR closeReason: '{xsoar_close_reason}')."
                )
            client.incident_status_update(incident_id=remote_id, payload=status_payload)
    except DemistoException as e:
        demisto.error(
            f"Failed to update status for {resource_type} {remote_id} to '{contrast_status}': {str(e)}. "
            "Continuing without status update."
        )
        return

    if is_issue:
        return

    # Track processed incidents only when the status is updated in Contrast Security.
    # Skip the write if the incident ID is already added or removed.
    is_active = incident_status == IncidentStatus.ACTIVE
    integration_context = get_integration_context() or {}
    processed_incidents = integration_context.get("processed_incidents") or []
    if is_active != (remote_id in processed_incidents):
        try:
            update_integration_context_with_retries(update_processed_incidents, remote_id, is_active)
            demisto.debug(f"Updated {remote_id} in processed incidents. Active: {is_active}.")
        except DemistoException as e:
            # Log and continue, so the notes are still mirrored
            demisto.error(f"Failed to update {remote_id} in processed incidents: {str(e)}")


def add_remote_comment(client: Client, remote_id: str, is_issue: bool, comment: str, xsoar_incident_id: str) -> None:
    """
    Outgoing mirroring: add a comment to the Contrast Security incident/issue.
    Comments longer than the outgoing note limit are skipped.

    Args:
        client: Contrast Security API client.
        remote_id: The Contrast Security incident/issue ID.
        is_issue: Whether the remote ID is a Contrast Security issue.
        comment: The comment text to add.
        xsoar_incident_id: The XSOAR incident ID, used for logging.
    """
    if len(comment) > MAX_OUTGOING_NOTE_LIMIT:
        demisto.info(
            f"Skipping outgoing note for Contrast Security {remote_id} "
            f"(XSOAR Incident ID: {xsoar_incident_id}): note exceeds {MAX_OUTGOING_NOTE_LIMIT} characters."
        )
        return

    if is_issue:
        client.issue_comment_add(issue_id=remote_id, payload={"commentText": comment})
    else:
        client.incident_comment_add(incident_id=remote_id, payload={"commentText": comment})


def update_remote_system_command(client: Client, args: dict) -> str:
    """
    Outgoing mirroring: push XSOAR incident changes back to Contrast Security.

    Handles two types of updates:
    - Status changes: maps XSOAR status to Contrast Security incident/issue status.
    - Notes: mirrors tagged XSOAR notes as Contrast Security incident/issue comments.

    Supports both Contrast Security Incidents (INC-*) and Issues (ISS-*).

    Args:
        client: Contrast Security API client.
        args: Arguments supplied by the XSOAR mirroring engine.

    Returns:
        The remote incident/issue ID.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_incident_id = parsed_args.remote_incident_id
    xsoar_incident_id = (parsed_args.data or {}).get("id", "")
    incident_status = parsed_args.inc_status
    delta = parsed_args.delta or {}
    incident_changed = parsed_args.incident_changed
    new_entries = parsed_args.entries

    demisto.debug(f"Incident changed: {incident_changed}")
    demisto.debug(f"Delta information for incident: {delta}")
    demisto.debug(f"Outgoing mirroring update for Contrast Security: {remote_incident_id}")
    demisto.debug(f"Incident status: {incident_status}")

    if not remote_incident_id:
        demisto.debug("No remote incident ID found — skipping outgoing mirroring.")
        return remote_incident_id

    # Check if the ID is neither ISS- nor INC-
    if not remote_incident_id.startswith(("ISS-", "INC-")):
        demisto.debug(f"Invalid remote incident ID format: {remote_incident_id}. Expected ISS- or INC- prefix.")
        return remote_incident_id

    # Detect if this is an issue (ISS-*) or incident (INC-*)
    is_issue = remote_incident_id.startswith("ISS-")

    # Detect reopen: XSOAR signals a reopen by clearing closingUserId.
    reopen_incident = bool(delta and delta.get("closingUserId") == "")
    investigate_incident_delta = (not delta) or ("runStatus" in delta and delta.get("runStatus", "") == "waiting")
    # Incoming mirroring also sends an empty delta, so open the incident only when it is not processed yet.
    # Otherwise, an incident closed in Contrast Security is reopened when XSOAR keeps it active.
    if investigate_incident_delta and not is_issue:
        processed_incidents = (get_integration_context() or {}).get("processed_incidents") or []
        investigate_incident_delta = remote_incident_id not in processed_incidents

    is_update_status = (
        incident_status == IncidentStatus.DONE
        or (incident_status == IncidentStatus.ACTIVE and investigate_incident_delta)
        or reopen_incident
    )

    xsoar_close_reason = parsed_args.data.get("closeReason", "")
    if incident_changed and is_update_status:
        update_remote_status(client, remote_incident_id, is_issue, incident_status, xsoar_close_reason)

    # Mirror tagged notes as Contrast Security incident/issue comments.
    for entry in new_entries or []:
        demisto.debug(f"Processing entry ID: {entry.get('id')}, type: {entry.get('type')}")
        entry_content = entry.get("contents", "")
        entry_user = entry.get("user", "dbot") or "dbot"
        note_text = f"[Mirrored From XSOAR] | Incident ID: {xsoar_incident_id} | Note: {entry_content} | Added By: {entry_user}"
        add_remote_comment(client, remote_incident_id, is_issue, note_text, xsoar_incident_id)

    # Mirror closing notes when incident is being closed.
    if "closingUserId" in delta and incident_changed and incident_status == IncidentStatus.DONE:
        close_notes = parsed_args.data.get("closeNotes", "")
        close_user_id = parsed_args.data.get("closingUserId", "")
        if is_issue:
            close_reason = xsoar_close_reason
        else:
            close_reason = XSOAR_TO_CONTRAST_CLOSE_REASON.get(xsoar_close_reason, "OTHER")

        closing_note = (
            f"[Mirrored From XSOAR] | Incident ID: {xsoar_incident_id} "
            f"| Close Reason: {close_reason} | Closed By: {close_user_id} | Close Notes: {close_notes}"
        )
        add_remote_comment(client, remote_incident_id, is_issue, closing_note, xsoar_incident_id)

    return remote_incident_id


def main() -> None:
    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    # Initialize Client for API commands
    server_url = params.get("server_url", "").rstrip("/")

    # Extract username and service_key from credentials field
    username = params.get("credentials", {}).get("identifier", "")
    service_key = params.get("credentials", {}).get("password", "")

    # Extract api_key from api_credentials field
    api_key = params.get("api_credentials", {}).get("password", "")
    organization_id = params.get("organization_id", "")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        "contrastsecurity-incident-comment-add": contrast_security_incident_comment_add_command,
        "contrastsecurity-incident-status-update": contrast_security_incident_status_update_command,
        "contrastsecurity-ip-block": contrast_security_ip_block_command,
        "contrastsecurity-adr-rule-update": contrast_security_adr_rule_update_command,
        "contrastsecurity-issue-comment-add": contrast_security_issue_comment_add_command,
        "contrastsecurity-issue-list": contrast_security_issue_list_command,
        "contrastsecurity-issue-get": contrast_security_issue_get_command,
        "contrastsecurity-issue-status-update": contrast_security_issue_status_update_command,
        "contrastsecurity-observation-get": contrast_security_observation_get_command,
        "contrastsecurity-incident-observation-list": contrast_security_incident_observation_list_command,
    }
    try:
        result = None
        client = Client(
            server_url=server_url,
            username=username,
            service_key=service_key,
            api_key=api_key,
            organization_id=organization_id,
            verify_certificate=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            result = test_module(client, params)
            return_results(result)
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, params, last_run)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args, params))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args))
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            args = trim_spaces_from_args(args)
            remove_nulls_from_dictionary(args)
            result = commands[command](client, args)
            return_results(result)
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}", error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
