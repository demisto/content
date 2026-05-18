import json
import os
import time
from collections import deque
from copy import copy
from json import JSONDecodeError
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import Any

import demistomock as demisto  # noqa: F401
import uvicorn
from CommonServerPython import *  # noqa: F401
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from uvicorn.logging import AccessFormatter
from collections.abc import Callable

SEVERITY_MAP: dict[str, float] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NOTE": 0.5,
}

OK_CODES = (200, 401, 201)
EVENT_TYPES = ["Contrast Incident", "Contrast Issue"]
STATUS_CODE_TO_RETRY = [429, *(code for code in requests.status_codes._codes if code >= 500)]  # type: ignore
MAX_RETRIES = 3
BACKOFF_FACTOR = 7.5
LONG_RUNNING_INSTANCE_DEFAULT_VALUE = False
DEFAULT_RULE_VALUE = "Monitor"
RULE_MODE_HUMAN_READABLE_LIST = ["Block at perimeter", "Off", "Monitor", "Block"]
RULE_MODE_MAPPING = {"Block at perimeter": "BLOCKING_PERIMETER", "Off": "OFF", "Monitor": "MONITORING", "Block": "BLOCKING"}
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
STATUS_LIST = ["closed", "open"]
CLOSE_REASON_LIST = ["True Positive", "False Positive", "Benign True Positive", "Other"]
STATUS_HUMAN_READABLE_LIST = ["Closed", "Open"]
SORT_ORDER_VALID_VALUES = ["Asc", "Desc"]
MAX_ISSUE_PAGE_SIZE = 100
MAX_OBSERVATION_PAGE_SIZE = 1000
SORT_BY_MAPPING = {
    "cvss_score": "cvssScore",
    "issue_id": "issueId",
    "title": "title",
    "status": "status",
    "service_name": "serviceName",
    "created_at": "createdAt",
    "last_observation_at": "lastObservationAt",
    "observation_count": "observationCount",
}
SORT_BY_VALID_VALUES = list(SORT_BY_MAPPING.keys())
OBSERVATION_SORT_BY_MAPPING = {
    "http_source_ip": "HTTP_SOURCE_IP",
    "http_route": "HTTP_ROUTE",
    "rule_id": "RULE_ID",
    "service_name": "SERVICE_NAME",
    "server_name": "SERVER_NAME",
    "event_time": "EVENT_TIME",
    "attack_event_result": "ATTACKEVENT_RESULT",
    "attack_event_value": "ATTACKEVENT_VALUE",
}
OBSERVATION_SORT_BY_VALID_VALUES = list(OBSERVATION_SORT_BY_MAPPING.keys())
CLOSE_REASON_MAPPING = {
    "True Positive": "TRUE_POSITIVE",
    "False Positive": "FALSE_POSITIVE",
    "Benign True Positive": "BENIGN_TRUE_POSITIVE",
    "Other": "OTHER",
}
# Map Contrast Security incident status to XSOAR incident status
CONTRAST_STATUS_TO_XSOAR_STATUS = {
    "open": "Active",
    "closed": "Closed",
}
# Map XSOAR incident status to Contrast Security incident status (for outgoing mirroring)
XSOAR_TO_CONTRAST_STATUS = {
    IncidentStatus.ACTIVE: "open",
    IncidentStatus.DONE: "closed",
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
MIRROR_DIRECTION = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
ENDPOINTS = {
    "issues_list": "/api/ns-rest/v1/organizations/{}/issues",
    "incidents_list": "/api/ns-rest/v1/organizations/{}/incidents",
    "incident_get": "/api/ns-rest/v1/organizations/{}/incidents/{}",
    "incident_comment": "/api/ns-rest/v1/organizations/{}/incidents/{}/comments",
    "incident_status": "/api/ns-rest/v1/organizations/{}/incidents/{}/status",
    "ip_addresses": "/api/ns-rest/v1/organizations/{}/incidents/{}/ipaddresses",
    "adr_policy": "/api/ns-rest/v1/organizations/{}/incidents/{}/protectrules/bulk",
    "issue_list": "/api/ns-rest/v1/organizations/{}/issues",
    "incident_issues_list": "/api/ns-rest/v1/organizations/{}/incidents/{}/issues",
    "issue_get": "/api/ns-rest/v1/organizations/{}/issues/{}",
    "issue_get_summary": "/api/ns-rest/v1/organizations/{}/issues/{}/summary",
    "issue_comment": "/api/ns-rest/v1/organizations/{}/issues/{}/comments",
    "issue_status": "/api/ns-rest/v1/organizations/{}/issues/{}/status",
    "observation_get": "/api/ns-rest/v1/organizations/{}/observations/{}",
    "observation_get_details": "/api/ns-rest/v1/organizations/{}/observations/{}/details",
    "observations_list": "/api/ns-rest/v1/organizations/{}/incidents/{}/observations",
}

ERROR_MESSAGES = {
    "REQUIRED_ARGUMENT": "Missing argument {}.",
    "BAD_REQUEST": "The request payload contains invalid JSON format. Ensure the payload is valid JSON.",
    "WEBHOOK_UNAUTHORIZED": "Webhook authorization failed. Please check the provided credentials.",
    "UNAUTHORIZED_REQUEST": "{} Unauthorized: Authentication failed. Please verify the API key, Service Key,"
    " Organization ID, and Username. {}",
    "STORE_SAMPLES_ERROR": "Failed to store sample events",
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "MISSING_REQUIRED_PARAMS": "{} is a required parameter when long running instance is enabled.",
    "CLOSE_REASON_REQUIRED": "{} argument is required when provided incident status is {}.",
    "INVALID_TIMESTAMP": "Provided invalid {}: {} must be a future timestamp.",
    "INVALID_PAGE_SIZE": "Invalid page_size: '{}'. page_size must not exceed {}.",
    "INVALID_INTEGER": "'{}' is an invalid value for '{}'. Value must be a valid positive integer.",
}

OUTPUT_PREFIX = {
    "INCIDENT_COMMENT": "ContrastSecurity.Incident.Comment",
    "INCIDENT": "ContrastSecurity.Incident",
    "ISSUE_COMMENT": "ContrastSecurity.IssueComment",
    "ISSUES": "ContrastSecurity.Issues",
    "OBSERVATIONS": "ContrastSecurity.Observations",
}

# URL path templates for generating links in human-readable output
URL_PATHS = {
    "issue": "/Contrast/cs/index.html#/{}/issues/{}",
    "observation": "/Contrast/cs/index.html#/{}/observations/{}",
}

sample_events_to_store: deque = deque(maxlen=20)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)


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
            f"Making API request at {method} {url_suffix} with headers:{log_header}, "
            f"params:{params} and body:{data or json_data}"
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

    def get_issue_summary(self, issue_id: str) -> dict[str, Any]:
        """
        Get the summary of a specific issue by ID from Contrast Security.

        Args:
            issue_id: The ID of the issue.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["issue_get_summary"].format(self.organization_id, issue_id)
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

    def get_observation_details(self, observation_id: str) -> dict[str, Any]:
        """
        Get the details of a specific observation by ID from Contrast Security.

        Args:
            observation_id: The ID of the observation.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["observation_get_details"].format(self.organization_id, observation_id)
        return self.http_request(method="GET", url_suffix=url_suffix, response_type="json")

    def list_issues(self, query_params: dict):
        """
        Get list of issues from Contrast Security.

        Args:
            query_params: Query parameters for the request (page, size, etc.)
            response_type: Expected response type (json or response)

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
            query_params: Query parameters for the request (page, size, etc.)

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["incident_issues_list"].format(self.organization_id, incident_id)
        return self.http_request(method="GET", url_suffix=url_suffix, params=query_params, response_type="json")

    def list_incidents(self, query_params: dict):
        """
        Get list of incidents from Contrast Security.

        Args:
            query_params: Query parameters for the request (page, size, sort, etc.)

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
            payload: incident comment data to add.

        Returns:
            Response object or parsed JSON
        """

        url_suffix = ENDPOINTS["incident_status"].format(self.organization_id, incident_id)
        return self.http_request(method="PATCH", url_suffix=url_suffix, json_data=payload)

    def list_ip_address(self, incident_id: str):
        """
        Get list of IP addresses for a Contrast Security Incident.

        Args:
            incident_id: ID of the incident.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["ip_addresses"].format(self.organization_id, incident_id)
        return self.http_request(method="GET", url_suffix=url_suffix, response_type="json")

    def block_ip_addresses(self, incident_id: str, payload: dict):
        """
        Block list of IP addresses for a Contrast Security Incident.

        Args:
            incident_id: ID of the incident.
            payload: Request body containing ipAddresses list and expirationDate.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["ip_addresses"].format(self.organization_id, incident_id)
        return self.http_request(method="PUT", url_suffix=url_suffix, json_data=payload)

    def adrpolicy_update(self, incident_id: str, payload: dict):
        """
        Update ADR Policy for a Contrast Security Incident.

        Args:
            incident_id: Contrast Security incident ID.
            payload: incident comment data to add.

        Returns:
            Response object or parsed JSON
        """

        url_suffix = ENDPOINTS["adr_policy"].format(self.organization_id, incident_id)
        return self.http_request(method="PUT", url_suffix=url_suffix, json_data=payload)

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
        return self.http_request(method="PATCH", url_suffix=url_suffix, json_data=payload)

    def list_incident_observations(self, incident_id: str, query_params: dict | None = None):
        """
        Get list of observations for a Contrast Security Incident.

        Args:
            incident_id: ID of the incident.
            payload: Request body containing pageable and sort information.
            query_params: Optional query parameters for cursor-based pagination.

        Returns:
            Response object or parsed JSON
        """
        url_suffix = ENDPOINTS["observations_list"].format(self.organization_id, incident_id)
        return self.http_request(method="POST", url_suffix=url_suffix, params=query_params, json_data={}, response_type="json")


class ContrastSecurityAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: dict) -> str:
        headers = scope.get("headers", [])
        user_agent_header = list(filter(lambda header: header[0].decode() == "user-agent", headers))
        user_agent = ""
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record):  # type: ignore[override]
        recordcopy = copy(record)
        scope = recordcopy.__dict__["scope"]
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({"user_agent": user_agent})
        return super().formatMessage(recordcopy)


async def parse_incidents(request: Request, event_type: list[str]) -> list[dict]:
    """
    Parse incidents from webhook request with deduplication.

    Args:
        request: FastAPI Request object
        event_type: List of event types to process

    Returns:
        list[dict]: List of non-duplicate incidents
    """
    json_body = await request.json()

    incidents = json_body if isinstance(json_body, list) else [json_body]
    demisto.debug(f"received create incidents request of length {len(incidents)}")

    # Process events with deduplication (incidents and issues)
    non_duplicate_events = []
    duplicate_event_ids = []

    # Get the integration context for deduplication
    integration_context = get_integration_context() or {}
    demisto.debug(f"integration_context: {integration_context}")
    incident_ids = integration_context.get("incident_ids", [])
    issue_ids = integration_context.get("issue_ids", [])

    # Check which event types user wants to fetch (event_type is now optional)
    is_incident_type = "Contrast Incident" in event_type if event_type else False
    is_issue_type = "Contrast Issue" in event_type if event_type else False
    demisto.debug(f"Event types to fetch - Incidents: {is_incident_type}, Issues: {is_issue_type}")

    # If no event types are selected, skip all events
    if not is_incident_type and not is_issue_type:
        demisto.debug("No event types selected, skipping all events")
        return []

    for incident in incidents:
        raw_json = incident.get("rawJson") or incident.get("raw_json") or copy(incident)

        # Normalize rawJson field
        if not incident.get("rawJson"):
            incident.pop("raw_json", None)
            incident["rawJson"] = raw_json

        # Set XSOAR type for classifier and determine event type and check for duplicates
        observation_id = raw_json.get("observationId")
        incident_id = raw_json.get("incidentId")
        issue_id = raw_json.get("issueId")
        mirroring_fields = {}

        if observation_id:
            demisto.debug("Skipping Contrast Security observation events.")
            continue
        elif incident_id:
            if not is_incident_type:
                demisto.debug("Skipping Contrast Security incident events.")
                continue
            if incident_id not in incident_ids:
                non_duplicate_events.append(incident)
                incident_ids.append(incident_id)
                mirroring_fields = get_mirroring("incident_mirror_direction")
                mirroring_fields.update({"mirror_id": incident_id})
            else:
                duplicate_event_ids.append(incident_id)
        elif issue_id:
            if not is_issue_type:
                demisto.debug("Skipping Contrast Security issue events.")
                continue
            if issue_id not in issue_ids:
                non_duplicate_events.append(incident)
                issue_ids.append(issue_id)
                mirroring_fields = get_mirroring("issue_mirror_direction")
                mirroring_fields.update({"mirror_id": issue_id})

            else:
                duplicate_event_ids.append(issue_id)
        else:
            demisto.debug("Dropping events with unknown type or no incidentId or issueId")

        # Update mirroring details for incident
        raw_json.update(mirroring_fields)

    demisto.debug(f"New events: {len(non_duplicate_events)}, Duplicate events: {len(duplicate_event_ids)}")

    # Update integration context with new event IDs
    integration_context["incident_ids"] = incident_ids
    integration_context["issue_ids"] = issue_ids
    set_integration_context(integration_context)
    return non_duplicate_events


@app.post("/")
async def handle_post(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(basic_auth),
):
    demisto.debug("Contrast Security webhook handling request")
    params = demisto.params()
    event_type = argToList(params.get("event_type", ""))

    try:
        incidents_raw = await parse_incidents(request, event_type)
    except JSONDecodeError as e:
        demisto.error(f"Could not decode request: {e}")
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ERROR_MESSAGES["BAD_REQUEST"],
        )

    # Validate basic auth credentials (required)
    webhook_creds_param = params.get("webhook_credentials", {})

    username = webhook_creds_param.get("identifier", "")
    password = webhook_creds_param.get("password", "")

    # Verify basic auth credentials
    if not credentials or not (compare_digest(credentials.username, username) and compare_digest(credentials.password, password)):
        demisto.debug("Webhook authentication failed.")
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content=ERROR_MESSAGES["WEBHOOK_UNAUTHORIZED"])

    incidents = []
    for incident in incidents_raw:
        raw_json = incident.get("rawJson", {})
        raw_json = remove_empty_elements_for_fetch(raw_json)

        # Set incident name based on xsoar_type
        xsoar_incident_name = "Contrast Security Event"
        if raw_json.get("eventType") == "contrast_security_incidentalert":
            xsoar_incident_name = raw_json.get("incidentName", "Contrast Security triggered incident")
        elif raw_json.get("eventType") == "contrast_security_issuealert":
            xsoar_incident_name = raw_json.get("title", "Contrast Security triggered issue")

        incidents.append(
            {
                "name": xsoar_incident_name,
                "occurred": incident.get("occurred"),
                "severity": SEVERITY_MAP.get(incident.get("severity", ""), 0),
                "rawJSON": json.dumps(raw_json),
                "details": json.dumps(raw_json),
            }
        )

    demisto.debug("Creating XSOAR incidents for Contrast Security events.")
    return_incidents = demisto.createIncidents(incidents)
    demisto.debug("Created XSOAR incidents for Contrast Security events.")

    if demisto.params().get("store_samples"):
        try:
            sample_events_to_store.extend(incidents)
            integration_context = get_integration_context() or {}
            sample_events: deque = deque(integration_context.get("sample_events", []), maxlen=20)
            sample_events += sample_events_to_store
            integration_context["sample_events"] = list(sample_events)
            set_integration_context(integration_context)
        except Exception as e:
            demisto.error(f"{ERROR_MESSAGES['STORE_SAMPLES_ERROR']}: {e}")

    return return_incidents


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


def get_mirroring(mirror_direction_param: str) -> dict:
    """
    Get mirroring configuration for the specified event type parameter.

    Args:
        mirror_direction_param: The parameter name for mirror direction.

    Returns:
        dict: Mirroring configuration with mirror_direction, mirror_tags, and mirror_instance
    """
    params = demisto.params()
    mirror_direction = params.get(mirror_direction_param, "None").strip()
    mirror_tags = params.get("note_tag", "").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_tags": mirror_tags,
        "mirror_instance": demisto.integrationInstance(),
    }


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


def remove_empty_elements_for_hr(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    :param d: Input dictionary or list.
    :return: Dictionary or list with all empty lists, and empty dictionaries removed.
    """
    if not isinstance(d, dict | list):
        return str(d) if isinstance(d, int | float) else d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_hr(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_hr(v)) for k, v in d.items()) if not check_empty(v)}


def validate_configuration_params(params):
    """
    Validate configuration parameters.

    Args:
        params: Configuration parameters.

    Raises:
        ValueError: If required parameters are missing.
    """

    # Validate webhook credentials, port, and event type if long running instance is enabled
    is_long_running = argToBoolean(params.get("longRunning", LONG_RUNNING_INSTANCE_DEFAULT_VALUE))
    if is_long_running:
        missing_params = []

        # Validate webhook credentials
        webhook_credentials = params.get("webhook_credentials", {})
        if not webhook_credentials:
            missing_params.append("Webhook Credentials")
        else:
            webhook_username = webhook_credentials.get("identifier", "")
            webhook_password = webhook_credentials.get("password", "")
            if not webhook_username:
                missing_params.append("Webhook Username")
            if not webhook_password:
                missing_params.append("Webhook Password")

        # Validate listening port
        long_running_port = params.get("longRunningPort")
        if not long_running_port:
            missing_params.append("Listening Port")

        # Validate event type
        event_type = argToList(params.get("event_type"))
        if not event_type:
            missing_params.append("Event Type")

        # Raise single error if any parameters are missing
        if missing_params:
            raise ValueError(f"{ERROR_MESSAGES['MISSING_REQUIRED_PARAMS'].format(', '.join(missing_params))}.")

        # Validate event type values
        for event in event_type:
            if event not in EVENT_TYPES:
                raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(event, "Event Type", EVENT_TYPES))


def build_incident_comment_add_output(comment_data: dict):
    """
    Build human-readable output and context for incident comment.

    Args:
        comment_data(dict): Comment data from add incident comment API.

    Returns:
        tuple: (context, readable_output)
    """
    context = [remove_empty_elements(comment_data)]
    incident_id = comment_data.get("incident_id", "")
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
        f"Incident {incident_id} Comment Added Successfully.", hr_content, headers=headers, removeNull=True
    )

    return context, readable_output


def build_incident_status_update_output(incident_data: dict) -> tuple:
    """
    Build human-readable output and context for incident status update.
    Args:
        incident_data(dict): Incident data obtained from incident status update API.
    Returns:
        tuple: (context, readable_output)

    """
    context = [remove_empty_elements(incident_data)]

    hr_content = [
        {
            "Incident ID": incident_data.get("id", ""),
            "Status": incident_data.get("status", ""),
            "Close Reason": incident_data.get("close_reason", ""),
        }
    ]

    headers = ["Incident ID", "Status", "Close Reason"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("Incident Status Updated Successfully.", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def build_ip_block_output(raw_response: dict) -> tuple:
    """
    Build human-readable output and context for IP block command.

    Args:
        raw_response (dict): Raw response data containing id, IpAddresses with ip_addresses and expiration_date.

    Returns:
        tuple: (context, readable_output)
    """
    context = [remove_empty_elements(raw_response)]

    ip_addresses_data = raw_response.get("IpAddresses", {})
    hr_content = [
        {
            "Incident ID": raw_response.get("id", ""),
            "Blocked IPs": ", ".join(ip_addresses_data.get("ips", [])),
            "Expiration Date": ip_addresses_data.get("expiration_date", ""),
        }
    ]

    headers = ["Incident ID", "Blocked IPs", "Expiration Date"]
    readable_output = tableToMarkdown("IP Addresses Blocked Successfully.", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def build_adrpolicy_update_output(raw_response: dict, rule_names: list, dev_mode: str, qa_mode: str, prod_mode: str) -> tuple:
    """
    Build human-readable output and context for ADR Policy update.
    Args:
        raw_response(dict): Response data from ADR policy update.
        rule_names(list): List of rule names that were updated.
        dev_mode(str): Development mode setting.
        qa_mode(str): QA mode setting.
        prod_mode(str): Production mode setting.
    Returns:
        tuple: (context, readable_output)

    """
    context = [remove_empty_elements(raw_response)]

    hr_content = [
        {
            "Incident ID": raw_response.get("id", ""),
            "Rule Name": rule_names,
            "Development Mode": dev_mode,
            "QA Mode": qa_mode,
            "Production Mode": prod_mode,
        }
    ]

    headers = ["Incident ID", "Rule Name", "Development Mode", "QA Mode", "Production Mode"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("ADR Policy Updated Successfully.", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def build_issues_list_output(
    issues: list[dict[str, Any]], platform_url: str = "", organization_id: str = "", raw_response: dict[str, Any] | None = None
) -> tuple:
    """
    Build human-readable output and context for issues list.

    Args:
        issues(list): List of issue data from the API response content.
        platform_url(str): Platform URL for generating issue links.
        organization_id(str): Organization ID for generating issue links.
        raw_response(dict): Raw API response to update with issue links.

    Returns:
        tuple: (context, readable_output)
    """
    context: list[dict[str, Any]] = []
    hr_content = []

    for idx, issue in enumerate(issues):
        issue_data = remove_empty_elements(issue)
        issue_id = issue.get("issueId", "")
        issue_link = None

        if platform_url and organization_id and issue_id:
            issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
            issue_data["issueLink"] = issue_link
            if raw_response and "content" in raw_response:
                raw_response["content"][idx]["issueLink"] = issue_link

        context.append(issue_data)
        hr_content.append(
            {
                "CVSS Score": issue.get("cvssScore", ""),
                "Title": issue.get("title", ""),
                "Issue ID": f"[{issue_id}]({issue_link})" if issue_link else issue_id,
                "Status": issue.get("status", ""),
                "Application Name": issue.get("applicationName", ""),
                "Number of Observations": issue.get("observationCount", ""),
                "Last Attacked At": issue.get("lastAttackedAt", ""),
                "Last Observation At": issue.get("lastObservationAt", ""),
                "CVSS Vector": issue.get("cvssVector", ""),
                "Deployment Tier": ", ".join(issue.get("deploymentTier", [])) if issue.get("deploymentTier") else "",
            }
        )

    headers = [
        "CVSS Score",
        "Title",
        "Issue ID",
        "Status",
        "Application Name",
        "Number of Observations",
        "Last Attacked At",
        "Last Observation At",
        "CVSS Vector",
        "Deployment Tier",
    ]

    readable_output: str = tableToMarkdown("Contrast Security Issues", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def build_issue_get_output(
    issue: dict[str, Any], platform_url: str = "", organization_id: str = ""
) -> tuple[dict[str, Any], str]:
    """
    Build human-readable output and context for a single issue.

    Args:
        issue(dict): Issue data merged from get issue and get issue summary API responses.
        platform_url(str): Platform URL for generating issue links.
        organization_id(str): Organization ID for generating issue links.

    Returns:
        tuple: (context, readable_output)
    """
    context = remove_empty_elements(issue)

    # Prepare HR data with issue link if available
    hr_data = remove_empty_elements_for_hr(context)
    if platform_url and organization_id and hr_data.get("issueId"):
        issue_id = hr_data.get("issueId")
        issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
        hr_data["issueId"] = f"[{issue_id}]({issue_link})"

    headers = [
        "issueId",
        "title",
        "summary",
        "status",
        "applicationName",
        "applicationId",
        "ruleId",
        "cvssScore",
        "cvssVector",
        "currentIncidentId",
        "incidentCount",
        "createdAt",
        "lastAttackedAt",
        "lastAttackIdRef",
        "lastObservationAt",
        "closedAt",
        "attackCount",
        "blockedAttackCount",
        "exploitedAttackCount",
        "observationCount",
        "suspiciousAttackCount",
        "deploymentTier",
        "httpRoute",
    ]

    readable_output: str = tableToMarkdown(
        "Contrast Security Issue",
        hr_data,
        is_auto_json_transform=True,
        headerTransform=lambda f: pascalToSpace(f).replace("Id", "ID").replace("Cvss", "CVSS").replace("Http", "HTTP"),
        headers=headers,
        removeNull=True,
    )

    return context, readable_output


def build_issue_comment_add_output(comment_data: dict):
    """
    Build human-readable output and context for issue comment.

    Args:
        comment_data(dict): Comment data from add issue comment API.

    Returns:
        tuple: (context, readable_output)
    """
    context = [remove_empty_elements(comment_data)]
    issue_id = comment_data.get("issue_id", "")
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
        f"Issue {issue_id} Comment Added Successfully.", hr_content, headers=headers, removeNull=True
    )

    return context, readable_output


def build_issue_status_update_output(issue_data: dict) -> tuple:
    """
    Build human-readable output and context for issue status update.
    Args:
        issue_data(dict): Issue data obtained from issue status update API.
    Returns:
        tuple: (context, readable_output)

    """
    context = [remove_empty_elements(issue_data)]

    hr_content = [
        {
            "Issue ID": issue_data.get("id", ""),
            "Status": issue_data.get("status", ""),
        }
    ]

    headers = ["Issue ID", "Status"]

    # Create human-readable output using tableToMarkdown
    readable_output = tableToMarkdown("Issue Status Updated Successfully.", hr_content, headers=headers, removeNull=True)

    return context, readable_output


def build_observation_get_output(
    observation_data: dict[str, Any], platform_url: str = "", organization_id: str = ""
) -> tuple[list[dict[str, Any]], str]:
    """
    Build human-readable output and context for a single observation.

    Args:
        observation_data(dict): Observation data merged from get observation and details API responses.
        platform_url(str): Platform URL for generating redirect links.
        organization_id(str): Organization ID for generating redirect links.

    Returns:
        tuple: (context, readable_output)
    """
    obs_type = observation_data.get("type", "").upper()

    context = [remove_empty_elements(observation_data)]

    if obs_type == "ATTACK":
        readable_output = build_observation_common_info(observation_data, platform_url, organization_id)
        readable_output += build_attack_observation_details(observation_data)
    elif obs_type == "LIBRARY":
        readable_output = build_observation_common_info(observation_data, platform_url, organization_id)
        readable_output += build_library_observation_details(observation_data)
    else:
        readable_output = build_observation_common_info(observation_data, platform_url, organization_id)

    return context, readable_output


def build_observation_common_info(observation_data: dict[str, Any], platform_url: str = "", organization_id: str = "") -> str:
    """
    Build common observation information table with links to Contrast platform.

    Args:
        observation_data: Dictionary containing observation data from API.
        platform_url: Base URL of Contrast Security platform for generating links.
        organization_id: Organization ID for constructing Contrast platform URLs.

    Returns:
        str: Markdown-formatted table with observation information.
    """
    observation_id = observation_data.get("observationId", "")
    issue_id = observation_data.get("issueId", "")

    # Build observation link if platform URL and organization ID are available
    if platform_url and organization_id and observation_id:
        observation_link = urljoin(platform_url, URL_PATHS["observation"].format(organization_id, observation_id))
        observation_id_display = f"[{observation_id}]({observation_link})"
    else:
        observation_id_display = observation_id

    # Build issue link if platform URL and organization ID are available
    if platform_url and organization_id and issue_id:
        issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
        issue_id_display = f"[{issue_id}]({issue_link})"
    else:
        issue_id_display = issue_id

    obs_info = [
        {
            "Observation ID": observation_id_display,
            "Issue ID": issue_id_display,
            "Type": observation_data.get("type", ""),
            "Application ID": observation_data.get("applicationId", ""),
            "Application Name": observation_data.get("applicationName", ""),
            "Application Language": observation_data.get("applicationLanguage", ""),
            "Event Time": observation_data.get("eventTime", ""),
        }
    ]

    return tableToMarkdown("Observation Information", obs_info, removeNull=True, is_auto_json_transform=True, sort_headers=False)


def build_attack_observation_details(observation_data: dict[str, Any]) -> str:
    """
    Build attack-specific observation details with vector analysis and request information.

    Args:
        observation_data: Dictionary containing attack observation data from API.

    Returns:
        str: Markdown-formatted tables with attack insights, payload, vector analysis, and code location.
    """
    attack_insights = observation_data.get("attackInsightsResponseDto", {})
    code_location = attack_insights.get("codeLocation", {})
    attack_payload = attack_insights.get("attackPayload", {})
    attacker_input = attack_payload.get("attackerInput", {})

    readable_output = ""

    attack_info = [
        {
            "Summary": attack_insights.get("summary", ""),
            "Rule UUID": attack_insights.get("ruleUuid", ""),
            "URL": attack_insights.get("url", ""),
            "Recommended Actions": attack_insights.get("recommendedActions", ""),
        }
    ]
    readable_output += tableToMarkdown(
        "Attack Information", attack_info, removeNull=True, is_auto_json_transform=True, sort_headers=False
    )

    attack_value = [
        {
            "Attack Value Text": attack_insights.get("attackValueContextText", ""),
            "Attack Payload Value": attack_payload.get("value", ""),
            "Attacker Input Name": attacker_input.get("name", ""),
            "Attacker Input Type": attacker_input.get("inputType", ""),
        }
    ]
    readable_output += tableToMarkdown(
        "Attack Value", attack_value, removeNull=True, is_auto_json_transform=True, sort_headers=False
    )

    vector_analysis = [
        {
            "Vector Analysis Context Text": attack_insights.get("vectorAnalysisContextText", ""),
            "Vector Analysis Code Text": attack_insights.get("vectorAnalysisCodeText", ""),
        }
    ]
    readable_output += tableToMarkdown(
        "Vector Analysis", vector_analysis, removeNull=True, is_auto_json_transform=True, sort_headers=False
    )

    request_details = attack_insights.get("requestDetails", "")
    if request_details:
        request_details_info = [
            {
                "Request Details": request_details,
            }
        ]
        readable_output += tableToMarkdown(
            "Request Details", request_details_info, removeNull=True, is_auto_json_transform=True, sort_headers=False
        )

    code_location_info = [
        {
            "File": code_location.get("file", ""),
            "Method": code_location.get("method", ""),
        }
    ]
    readable_output += tableToMarkdown(
        "Code Location", code_location_info, removeNull=True, is_auto_json_transform=True, sort_headers=False
    )

    stack_trace = code_location.get("stack", [])
    if stack_trace:
        stack_info = [
            {
                "Description": frame.get("description", ""),
                "Type": frame.get("type", ""),
            }
            for frame in stack_trace
        ]
        readable_output += tableToMarkdown(
            "Stack Trace", stack_info, removeNull=True, is_auto_json_transform=True, sort_headers=False
        )

    return readable_output


def build_library_observation_details(observation_data: dict[str, Any]) -> str:
    """
    Build library-specific observation details with vulnerability information.

    Args:
        observation_data: Dictionary containing SCA library observation data from API.

    Returns:
        str: Markdown-formatted tables with library information and associated vulnerabilities (CVE, EPSS scores).
    """
    sca_library = observation_data.get("scaLibraryResponseDto", {})
    vulnerabilities = sca_library.get("vulnerabilities", [])

    readable_output = ""

    vuln_info = [
        {
            "Release Date": sca_library.get("releaseDate", ""),
            "License": ", ".join(sca_library.get("licenses", [])) if sca_library.get("licenses") else "",
            "Version": sca_library.get("version", ""),
            "Closest Stable Version": sca_library.get("closestStableVersion", ""),
            "Latest Stable Version": sca_library.get("latestStableVersion", ""),
            "Package URL": sca_library.get("packageUrl", ""),
            "Dependency": sca_library.get("dependency", ""),
        }
    ]
    readable_output += tableToMarkdown(
        "Vulnerability Information", vuln_info, removeNull=True, is_auto_json_transform=True, sort_headers=False
    )

    if vulnerabilities:
        vuln_list = [
            {
                "CVE ID": vuln.get("name", ""),
                "Description": vuln.get("description", ""),
                "EPSS Score": vuln.get("epssScore", ""),
                "EPSS Percentile": vuln.get("epssPercentile", ""),
                "CISA": vuln.get("cisa", False),
            }
            for vuln in vulnerabilities
        ]
        readable_output += tableToMarkdown("Vulnerabilities", vuln_list, removeNull=True, sort_headers=False)
    else:
        readable_output += "\n**No vulnerabilities found.**\n"

    return readable_output


def build_observations_list_output(
    observations: list[dict[str, Any]], platform_url: str = "", organization_id: str = ""
) -> tuple[list[dict[str, Any]], str]:
    """
    Build human-readable output and context for observations list.

    Args:
        observations(list): List of observation data from the API response.
        platform_url(str): Platform URL for generating observation links.
        organization_id(str): Organization ID for generating observation links.

    Returns:
        tuple: (context, readable_output)
    """
    context: list[dict[str, Any]] = []
    hr_content = []

    for observation in observations:
        # Build context
        context.append(remove_empty_elements(observation))

        # Build human-readable content
        observation_id = observation.get("observationId", "")
        if platform_url and organization_id and observation_id:
            obs_link = urljoin(platform_url, URL_PATHS["observation"].format(organization_id, observation_id))
            observation_id_display = f"[{observation_id}]({obs_link})"
        else:
            observation_id_display = observation_id

        issue_id = observation.get("issueId", "")
        if platform_url and organization_id and issue_id:
            issue_link = urljoin(platform_url, URL_PATHS["issue"].format(organization_id, issue_id))
            issue_id_display = f"[{issue_id}]({issue_link})"
        else:
            issue_id_display = issue_id

        hr_content.append(
            {
                "Observation ID": observation_id_display,
                "Title": observation.get("title", ""),
                "Source IP": observation.get("httpSourceIp", ""),
                "Result": observation.get("result", ""),
                "Associated Issue ID": issue_id_display,
                "URL": observation.get("httpRoute", ""),
                "Attack Value": observation.get("attackValue", ""),
                "Data Type": observation.get("dataType", ""),
                "Rule ID": observation.get("ruleId", ""),
                "Rule Name": observation.get("ruleName", ""),
                "Detected At": observation.get("detectedTime", ""),
                "Severity": observation.get("severity", ""),
                "Score": observation.get("score", ""),
                "Application ID": observation.get("applicationId", ""),
                "Application Name": observation.get("applicationName", ""),
                "Application Language": observation.get("applicationLanguage", ""),
                "Server ID": observation.get("serverId", ""),
                "Server Name": observation.get("serverName", ""),
                "Server Instance ID": observation.get("serviceInstanceId", ""),
                "Deployment Tier": observation.get("deploymentTier", ""),
            }
        )

    headers = [
        "Observation ID",
        "Title",
        "Source IP",
        "Result",
        "Associated Issue ID",
        "URL",
        "Attack Value",
        "Data Type",
        "Rule ID",
        "Rule Name",
        "Detected At",
        "Severity",
        "Score",
        "Application ID",
        "Application Name",
        "Application Language",
        "Server ID",
        "Server Name",
        "Server Instance ID",
        "Deployment Tier",
    ]

    readable_output: str = tableToMarkdown(
        "Contrast Security Incident Observations", hr_content, headers=headers, removeNull=True
    )

    return context, readable_output


def test_module(client: Client) -> str:
    """
    Test module for Contrast Security integration.

    Args:
        client: Client object.

    Returns:
        str: "ok" if connection with Contrast Security is successful.
    """

    # Test API connectivity by listing applications
    params = demisto.params()
    query_params = {"page": 0, "size": 1}

    client.list_issues(query_params=query_params)

    if not params.get("longRunningPort"):
        params["longRunningPort"] = "1111"

    return "ok"


def fetch_samples() -> None:
    """
    Fetch and display stored sample events as incidents.
    """
    integration_context = get_integration_context() or {}
    sample_events = integration_context.get("sample_events", [])
    demisto.incidents(sample_events)


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

    raw_response["incident_id"] = incident_id
    context, hr = build_incident_comment_add_output(raw_response)

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

    payload = {"status": status.lower()}

    if status == "closed" and close_reason:
        payload.update({"closedReason": CLOSE_REASON_MAPPING.get(close_reason)})

    client.incident_status_update(incident_id=incident_id, payload=payload)

    incident_data = {"id": incident_id, "status": status}
    if close_reason:
        incident_data["close_reason"] = close_reason
    context, hr = build_incident_status_update_output(incident_data=incident_data)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["INCIDENT"],
        outputs_key_field="id",
        outputs=context,
        raw_response=incident_data,
        readable_output=hr,
    )


def contrast_security_ip_block_command(client: Client, args: dict) -> CommandResults:
    """
    Block an IP address for a Contrast Security Incident.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    incident_id = validate_argument(args.get("incident_id"), "incident_id")
    ip_addresses = validate_argument(argToList(args.get("ip_addresses")), "ip_addresses")
    ip_addresses = [ip.strip() for ip in ip_addresses if ip.strip()]

    expiration_date = arg_to_datetime(args.get("expiration_date"), settings={"TIMEZONE": "UTC", "PREFER_DATES_FROM": "future"})

    invalid_format_ips = [ip for ip in ip_addresses if not is_ip_valid(ip, accept_v6_ips=True)]
    ip_addresses = [ip for ip in ip_addresses if is_ip_valid(ip, accept_v6_ips=True)]

    existing_ips = client.list_ip_address(incident_id).get("ipAddresses", [])
    existing_ips_list = [e.get("ipAddress") for e in existing_ips if e.get("ipAddress")]

    not_found = [ip for ip in ip_addresses if ip not in existing_ips_list]
    valid_ips = [ip for ip in ip_addresses if ip in existing_ips_list]

    warnings = []
    if invalid_format_ips:
        warnings.append(f"Invalid IP format: {', '.join(invalid_format_ips)}")
    if not_found:
        warnings.append(f"IP addresses were not found in incident {incident_id}: {', '.join(not_found)}")

    if warnings:
        return_warning("\n".join(warnings), exit=not valid_ips)

    current_time_str = datetime.now(timezone.utc).strftime(DATE_TIME_FORMAT)

    if expiration_date:
        expiration_date = expiration_date.strftime(DATE_TIME_FORMAT)  # type: ignore

        if expiration_date < current_time_str:  # type: ignore
            raise ValueError(ERROR_MESSAGES["INVALID_TIMESTAMP"].format("expiration_date", expiration_date))

    payload = {"ipAddresses": valid_ips}
    if expiration_date:
        payload["expirationDate"] = expiration_date  # type: ignore

    client.block_ip_addresses(incident_id, payload)

    raw_response = {"id": incident_id, "IpAddresses": {"ips": valid_ips, "expiration_date": expiration_date}}

    context, hr = build_ip_block_output(raw_response)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["INCIDENT"],
        outputs_key_field="id",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def contrast_security_adrpolicy_update_command(client: Client, args: dict) -> CommandResults:
    """
    Update ADR Policy for a Contrast Security Incident.

    Args:
        client(Client): Client object to use.
        args(dict): arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """

    incident_id = validate_argument(args.get("incident_id"), "incident_id")
    rule_names_input = validate_argument(args.get("rule_names"), "rule_names")
    dev_mode = args.get("dev_mode", DEFAULT_RULE_VALUE)
    qa_mode = args.get("qa_mode", DEFAULT_RULE_VALUE)
    prod_mode = args.get("prod_mode", DEFAULT_RULE_VALUE)

    # Parse comma-separated rule names
    rule_names = [rule.strip() for rule in rule_names_input.split(",")]

    # Validate each mode with correct field name in error message
    for mode, field_name in [
        (dev_mode, "dev_mode"),
        (qa_mode, "qa_mode"),
        (prod_mode, "prod_mode"),
    ]:
        if mode not in RULE_MODE_HUMAN_READABLE_LIST:
            raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(mode, field_name, RULE_MODE_HUMAN_READABLE_LIST))

    # Build payload with multiple rules
    rules_payload = []
    for rule_name in rule_names:
        rules_payload.append(
            {
                "devMode": RULE_MODE_MAPPING.get(dev_mode),
                "prodMode": RULE_MODE_MAPPING.get(prod_mode),
                "qaMode": RULE_MODE_MAPPING.get(qa_mode),
                "rule": rule_name,
            }
        )

    payload = {"rules": rules_payload}

    client.adrpolicy_update(incident_id=incident_id, payload=payload)

    raw_response = {
        "id": incident_id,
        "Rules": rules_payload,
    }
    context, hr = build_adrpolicy_update_output(raw_response, rule_names, dev_mode, qa_mode, prod_mode)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["INCIDENT"],
        outputs_key_field="id",
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

    issue_response = client.get_issue(issue_id=issue_id)
    summary_response = client.get_issue_summary(issue_id=issue_id)

    issue_response.update(summary_response)

    context, hr = build_issue_get_output(issue_response, platform_url=client._base_url, organization_id=client.organization_id)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUES"],
        outputs_key_field="issueId",
        outputs=context,
        raw_response=issue_response,
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
    sort_by = args.get("sort_by", "")
    sort_order = args.get("sort_order", "Asc")

    # Validate page_size
    page_size = arg_to_number(args.get("page_size", "50"), arg_name="page_size", required=False)
    if page_size is None or page_size <= 0:
        raise ValueError(ERROR_MESSAGES["INVALID_INTEGER"].format(args.get("page_size"), "page_size"))
    if page_size > MAX_ISSUE_PAGE_SIZE:
        raise ValueError(ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(page_size, MAX_ISSUE_PAGE_SIZE))

    # Validate page
    page = arg_to_number(args.get("page", "0"), arg_name="page", required=False)
    if page is None or page < 0:
        raise ValueError(ERROR_MESSAGES["INVALID_INTEGER"].format(args.get("page"), "page"))

    # Validate sort_order
    if sort_order and sort_order not in SORT_ORDER_VALID_VALUES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_order, "sort_order", SORT_ORDER_VALID_VALUES))

    # Validate sort_by
    if sort_by and sort_by not in SORT_BY_VALID_VALUES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_by, "sort_by", SORT_BY_VALID_VALUES))

    query_params: dict = {
        "page": page,
        "size": page_size,
    }

    if sort_by:
        query_params["sort"] = f"{SORT_BY_MAPPING[sort_by]},{sort_order}"

    if incident_id:
        raw_response = client.list_incident_issues(incident_id=incident_id, query_params=query_params)
    else:
        raw_response = client.list_issues(query_params=query_params)

    issues = raw_response.get("content", [])

    if not issues:
        return CommandResults(readable_output="No issues were found for the given filters.")

    context, hr = build_issues_list_output(
        issues, platform_url=client._base_url, organization_id=client.organization_id, raw_response=raw_response
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUES"],
        outputs_key_field="issueId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


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

    raw_response["issue_id"] = issue_id
    context, hr = build_issue_comment_add_output(raw_response)

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

    payload = status.lower()

    try:
        client.issue_status_update(issue_id=issue_id, payload=payload)
    except DemistoException as e:
        if "not found with previous status" in str(e):
            return_warning(f"Issue {issue_id} already has status '{status}'.", exit=True)
            return None
        raise

    issue_data = {"id": issue_id, "status": status}
    context, hr = build_issue_status_update_output(issue_data=issue_data)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ISSUES"],
        outputs_key_field="id",
        outputs=context,
        raw_response=issue_data,
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

    obs_response = client.get_observation(observation_id=observation_id)
    details_response = client.get_observation_details(observation_id=observation_id)

    obs_response.update(details_response)
    # Add observation ID manually since it's not in the API response
    obs_response["observationId"] = observation_id

    context, hr = build_observation_get_output(
        obs_response, platform_url=client._base_url, organization_id=client.organization_id
    )

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["OBSERVATIONS"],
        outputs_key_field="observationId",
        outputs=context,
        raw_response=obs_response,
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
    sort_by = args.get("sort_by", "")
    sort_order = args.get("sort_order", "Asc")
    next_page_cursor = args.get("next_page_cursor", "")

    # Validate page_size
    page_size = arg_to_number(args.get("page_size", "10"), arg_name="page_size", required=False)
    if page_size is None or page_size <= 0:
        raise ValueError(ERROR_MESSAGES["INVALID_INTEGER"].format(args.get("page_size"), "page_size"))
    if page_size > MAX_OBSERVATION_PAGE_SIZE:
        raise ValueError(ERROR_MESSAGES["INVALID_PAGE_SIZE"].format(page_size, MAX_OBSERVATION_PAGE_SIZE))

    # Validate sort_order
    if sort_order and sort_order not in SORT_ORDER_VALID_VALUES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_order, "sort_order", SORT_ORDER_VALID_VALUES))

    # Validate sort_by
    if sort_by and sort_by not in OBSERVATION_SORT_BY_VALID_VALUES:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_by, "sort_by", OBSERVATION_SORT_BY_VALID_VALUES))

    # Build query parameters for cursor-based pagination
    query_params: dict[str, Any] = {"pagination": "cursor", "size": page_size}

    if sort_by:
        query_params["sort"] = f"{OBSERVATION_SORT_BY_MAPPING.get(sort_by)},{sort_order.lower()}"

    if next_page_cursor:
        query_params["cursor"] = next_page_cursor

    raw_response = client.list_incident_observations(incident_id=incident_id, query_params=query_params)

    observations = raw_response.get("observations", [])

    if not observations:
        return CommandResults(readable_output="No observations were found for the given incident.")

    context, hr = build_observations_list_output(
        observations, platform_url=client._base_url, organization_id=client.organization_id
    )

    # Add pagination information to human-readable output if there are more results
    cursor = raw_response.get("cursor")
    has_more = raw_response.get("hasMore", False)

    if has_more and cursor:
        pagination_params = []
        if sort_by:
            pagination_params.append(f"sort_by=`{sort_by}`")
            pagination_params.append(f"sort_order=`{sort_order}`")
        pagination_params.append(f"next_page_cursor=`{cursor}`")

        pagination_params = " ".join(pagination_params)
        hr += f"\n\n**To Get Next page Observations:** {pagination_params}"

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["OBSERVATIONS"],
        outputs_key_field="observationId",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def close_in_xsoar(entries: list, incident_id: str, status: str) -> None:
    """
    Append a close entry to entries so XSOAR closes the mirrored incident.

    :type entries: list
    :param entries: List of entries where the closing entry will be appended.
    :type incident_id: str
    :param incident_id: The Contrast Security incident ID.
    :type status: str
    :param status: The Contrast Security incident status that triggered the closure.
    """
    demisto.debug(
        f"Closing XSOAR incident for Contrast Security incident {incident_id} via Incoming Mirroring. "
        f"Due to status: {status} is same as configured close status."
    )
    entries.append(
        {
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": "Other",
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


def get_remote_data_command(client: Client, args: dict):
    """
    Incoming mirroring: fetch the latest state of a single Contrast Security incident
    and push it into the corresponding XSOAR incident.

    Called once per mirrored incident every mirror-job interval (default 1 min).

    Args:
        client: Contrast Security API client.
        args: Command arguments supplied by the XSOAR mirroring engine.
              Expected keys: remoteId, lastUpdate.

    Returns:
        GetRemoteDataResponse with updated incident fields and optional close/reopen entry.
    """
    dbot_mirror_id: str = args.get("id")  # type: ignore
    demisto.debug(f"Processing Contrast Security incident update for mirror ID: {dbot_mirror_id}")

    if not dbot_mirror_id:
        return "Contrast Security Remote Incident was not found."  # type: ignore

    demisto.debug(f"get-remote-data called for incident {dbot_mirror_id}")

    params = demisto.params()
    reopen_closed_incident = params.get("reopen_closed_incident", False)
    close_active_incident = params.get("close_active_incident", False)

    remote_incident_data = client.get_incident(dbot_mirror_id)
    status = remote_incident_data.get("status", "").lower()
    score = remote_incident_data.get("score")

    # Build the mirrored field update that XSOAR will apply to the incident.
    # Field names match what the incoming mapper reads (webhook/API field names).
    mirrored_object = {"status": status, "score": score}
    remove_nulls_from_dictionary(mirrored_object)

    integration_context = demisto.getIntegrationContext()
    processed_incidents = integration_context.get("processed_incidents") or []

    entries: list[dict] = []
    if status == "closed" and dbot_mirror_id in processed_incidents and close_active_incident:
        close_in_xsoar(entries, dbot_mirror_id, status)
        processed_incidents.remove(dbot_mirror_id)
        demisto.debug(f"Removed {dbot_mirror_id} from processed incidents.")
    elif status == "open" and dbot_mirror_id not in processed_incidents and reopen_closed_incident:
        reopen_in_xsoar(entries, dbot_mirror_id, status)
        processed_incidents.append(dbot_mirror_id)
        demisto.debug(f"Added {dbot_mirror_id} to processed incidents.")

    processed_incidents = processed_incidents[-MAX_INCIDENTS_MIRRORING_LIMIT:]
    integration_context["processed_incidents"] = processed_incidents
    demisto.setIntegrationContext(integration_context)

    demisto.debug(f"Returning mirrored data for {dbot_mirror_id}: status={status}")
    return GetRemoteDataResponse(mirrored_object, entries=entries)


def get_modified_remote_data_command(client: Client, args: dict):
    """
    Incoming mirroring: return the list of Contrast Security incident IDs that have
    been modified since the last mirror run.

    XSOAR calls this every mirror-job interval. For each returned ID it will
    subsequently call get-remote-data to pull the full update.

    Paginates through the API (page size 100) until all incidents are collected
    or the 1 000-incident cap is reached.

    Args:
        client: Contrast Security API client.
        args: Command arguments supplied by the XSOAR mirroring engine.
              Expected key: lastUpdate (ISO-8601 timestamp string).

    Returns:
        GetModifiedRemoteDataResponse with list of modified incident IDs.
    """

    PAGE_SIZE = 100

    # Currently 100 incidents are updated per mirroring run.
    MAX_INCIDENTS = 100

    modified_incident_ids: list[str] = []
    current_page = 0

    while len(modified_incident_ids) < MAX_INCIDENTS:
        query_params = {
            "page": current_page,
            "size": PAGE_SIZE,
            "sort": "updatedDt,DESC",
        }

        response = client.list_incidents(query_params)
        incidents_data = response.get("content", [])
        page_meta = response.get("page", {})
        total_pages = page_meta.get("totalPages", 1)

        demisto.debug(f"get-modified-remote-data: page {current_page}/{total_pages}, " f"got {len(incidents_data)} incidents")

        for incident in incidents_data:
            incident_id = incident.get("incidentId")
            if incident_id:
                modified_incident_ids.append(incident_id)

        if current_page >= total_pages - 1 or len(incidents_data) == 0:
            break

        current_page += 1

    modified_incident_ids = modified_incident_ids[:PAGE_SIZE]
    demisto.debug(f"get-modified-remote-data: returning {len(modified_incident_ids)} incident ID(s)")

    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_incident_ids)


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
    xsoar_incident_id = parsed_args.data.get("id", "")
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
    investigate_incident_delta = not delta or delta == {"runStatus": "waiting"}
    is_update_status = (
        incident_status == IncidentStatus.DONE
        or (incident_status == IncidentStatus.ACTIVE and investigate_incident_delta)
        or reopen_incident
    )

    if incident_changed and is_update_status:
        contrast_status = XSOAR_TO_CONTRAST_STATUS.get(incident_status)
        if contrast_status:
            resource_type = "Issue" if is_issue else "Incident"
            demisto.debug(f"Updating Contrast Security {resource_type} {remote_incident_id} status to '{contrast_status}'.")

            try:
                if is_issue:
                    client.issue_status_update(issue_id=remote_incident_id, payload=contrast_status)  # type: ignore
                else:
                    status_payload: dict = {"status": contrast_status}
                    if contrast_status == "closed":
                        xsoar_close_reason = parsed_args.data.get("closeReason", "")
                        closed_reason = XSOAR_TO_CONTRAST_CLOSE_REASON.get(xsoar_close_reason, "OTHER")
                        status_payload["closedReason"] = closed_reason
                        demisto.debug(
                            f"Updating Contrast Security incident {remote_incident_id} status to '{contrast_status}' "
                            f"with closedReason '{closed_reason}' (XSOAR closeReason: '{xsoar_close_reason}')."
                        )
                    client.incident_status_update(incident_id=remote_incident_id, payload=status_payload)
            except DemistoException as e:
                demisto.debug(
                    f"Failed to update status for {resource_type} {remote_incident_id} to '{contrast_status}': {str(e)}. "
                    "Continuing without status update."
                )

    # Mirror tagged notes as Contrast Security incident/issue comments.
    if new_entries:
        for entry in new_entries:
            entry_id = entry.get("id")
            entry_type = entry.get("type")
            demisto.debug(f"Processing entry ID: {entry_id}, type: {entry_type}")

            entry_content = entry.get("contents", "")
            entry_user = entry.get("user", "dbot") or "dbot"
            note_text = (
                f"[Mirrored From XSOAR] | Incident ID: {xsoar_incident_id} " f"| Note: {entry_content} | Added By: {entry_user}"
            )
            if len(note_text) > MAX_OUTGOING_NOTE_LIMIT:
                demisto.info(
                    f"Skipping outgoing note for Contrast Security {remote_incident_id} "
                    f"(XSOAR Incident ID: {xsoar_incident_id}): note exceeds {MAX_OUTGOING_NOTE_LIMIT} characters."
                )
            else:
                if is_issue:
                    client.issue_comment_add(issue_id=remote_incident_id, payload={"commentText": note_text})
                else:
                    client.incident_comment_add(incident_id=remote_incident_id, payload={"commentText": note_text})

    # Mirror closing notes when incident is being closed.
    delta_keys = delta.keys()
    if "closingUserId" in delta_keys and incident_changed and incident_status == IncidentStatus.DONE:
        close_notes = parsed_args.data.get("closeNotes", "")
        xsoar_close_reason = parsed_args.data.get("closeReason", "")
        close_user_id = parsed_args.data.get("closingUserId", "")
        if is_issue:
            close_reason = xsoar_close_reason
        else:
            close_reason = XSOAR_TO_CONTRAST_CLOSE_REASON.get(xsoar_close_reason, "Other")

        closing_note = (
            f"[Mirrored From XSOAR] | Incident ID: {xsoar_incident_id} "
            f"| Close Reason: {close_reason} | Closed By: {close_user_id} | Close Notes: {close_notes}"
        )
        if len(closing_note) > MAX_OUTGOING_NOTE_LIMIT:
            demisto.info(
                f"Skipping outgoing closing note for Contrast Security {remote_incident_id} "
                f"(XSOAR Incident ID: {xsoar_incident_id}): note exceeds {MAX_OUTGOING_NOTE_LIMIT} characters."
            )
        else:
            if is_issue:
                client.issue_comment_add(issue_id=remote_incident_id, payload={"commentText": closing_note})
            else:
                client.incident_comment_add(incident_id=remote_incident_id, payload={"commentText": closing_note})

    return remote_incident_id


def main() -> None:
    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    port = arg_to_number(params.get("longRunningPort"))

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
        "contrastsecurity-adrpolicy-update": contrast_security_adrpolicy_update_command,
        "contrastsecurity-issue-comment-add": contrast_security_issue_comment_add_command,
        "contrastsecurity-issue-list": contrast_security_issue_list_command,
        "contrastsecurity-issue-get": contrast_security_issue_get_command,
        "contrastsecurity-issue-status-update": contrast_security_issue_status_update_command,
        "contrastsecurity-observation-get": contrast_security_observation_get_command,
        "contrastsecurity-incident-observation-list": contrast_security_incident_observation_list_command,
    }
    try:
        result = None
        validate_configuration_params(params)
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
            result = test_module(client)
            return_results(result)
        elif command == "fetch-incidents":
            fetch_samples()
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args))
        elif command == "long-running-execution":
            while True:
                certificate = demisto.params().get("certificate", "")
                private_key = demisto.params().get("key", "")
                certificate_path = ""
                private_key_path = ""
                try:
                    ssl_args: dict = {}
                    if certificate and private_key:
                        certificate_file = NamedTemporaryFile(delete=False)
                        certificate_path = certificate_file.name
                        certificate_file.write(bytes(certificate, "utf-8"))
                        certificate_file.close()
                        ssl_args["ssl_certfile"] = certificate_path

                        private_key_file = NamedTemporaryFile(delete=False)
                        private_key_path = private_key_file.name
                        private_key_file.write(bytes(private_key, "utf-8"))
                        private_key_file.close()
                        ssl_args["ssl_keyfile"] = private_key_path

                        demisto.debug("Starting HTTPS Server")
                    else:
                        demisto.debug("Starting HTTP Server")

                    integration_logger = IntegrationLogger()
                    integration_logger.buffering = False
                    log_config = dict(uvicorn.config.LOGGING_CONFIG)
                    log_config["handlers"]["default"]["stream"] = integration_logger
                    log_config["handlers"]["access"]["stream"] = integration_logger
                    log_config["formatters"]["access"] = {
                        "()": ContrastSecurityAccessFormatter,
                        "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"',
                    }

                    uvicorn.run(app, host="0.0.0.0", port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
                except Exception as e:
                    demisto.error(f"An error occurred in the long running loop: {e!s} - {format_exc()}")
                    demisto.updateModuleHealth(f"An error occurred: {e!s}")
                finally:
                    if certificate_path:
                        os.unlink(certificate_path)
                    if private_key_path:
                        os.unlink(private_key_path)
                    time.sleep(5)
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            args = trim_spaces_from_args(args)
            remove_nulls_from_dictionary(args)
            result = commands[command](client, args)
            return_results(result)
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
