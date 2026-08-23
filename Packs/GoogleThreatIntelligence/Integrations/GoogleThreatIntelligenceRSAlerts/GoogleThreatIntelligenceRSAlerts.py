import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
An integration module for the Google Threat Intelligence RS Alerts API.
API Documentation:
    https://gtidocs.virustotal.com/reference/alerts-overview
"""

from collections.abc import Callable
from typing import Any

""" CONSTANTS """

PACK_VERSION = get_pack_version() or "3.0.0"
USER_AGENT = f"CortexGTIRS-{PACK_VERSION}"
BASE_URL = "https://threatintelligence.googleapis.com/"
AUTH_BASE_URL = "https://idp.prod.identity.proactive.virustotal.com"
PLATFORM_URL = "https://proactive.virustotal.com"
OK_CODES = (200, 401)
STATUS_CODE_TO_RETRY = [429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500)]  # type: ignore
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
ERROR_MESSAGES = {
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "UNAUTHORIZED_REQUEST": "{} Unauthorized request: Invalid API key provided {}.",
    "TOKEN_GENERATION_FAILED": "Failed to generate access token using the provided API key.",
    "INVALID_MAX_FETCH": "'{}' is invalid 'max_fetch' value. Max fetch for RS Alerts should be between 1 and {}.",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "REQUIRED_ARGUMENT": "'{}' is required and cannot be empty.",
}
ENDPOINTS = {
    "AUTH_ENDPOINT": "/realms/master/exchange/api-key",
    "ALERT_LIST": "v1beta/projects/{}/alerts",
    "ALERT_GET": "v1beta/projects/{}/alerts/{}",
    "ALERT_STATUS_UPDATE": "v1beta/projects/{}/alerts/{}:{}",
}

MAX_FETCH = 200
DEFAULT_MAX_FETCH = 100
MAX_MIRRORING_LIMIT = 5000
DEFAULT_FETCH_TIME = "3 days"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

MIRROR_DIRECTION: dict[str, str] = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

# Maps RS API state value → human-readable XSOAR incident field value
RS_STATE_TO_XSOAR_STATE: dict[str, str] = {
    "STATE_UNSPECIFIED": "State Unspecified",
    "NEW": "New",
    "READ": "Read",
    "TRIAGED": "Triaged",
    "ESCALATED": "Escalated",
    "FALSE_POSITIVE": "False Positive",
    "RESOLVED": "Resolved",
    "DUPLICATE": "Duplicate",
    "BENIGN": "Benign",
    "NOT_ACTIONABLE": "Not Actionable",
    "TRACKED_EXTERNALLY": "Tracked Externally",
}

RS_OPEN_STATUSES = {"NEW", "READ", "TRIAGED", "ESCALATED"}
RS_CLOSE_STATUSES = {"FALSE_POSITIVE", "RESOLVED", "DUPLICATE", "BENIGN", "NOT_ACTIONABLE", "TRACKED_EXTERNALLY"}

# Maps RS API state to XSOAR close reason for incoming mirroring
RS_CLOSE_REASON_MAPPING: dict[str, str] = {
    "FALSE_POSITIVE": "False Positive",
    "RESOLVED": "Resolved",
    "DUPLICATE": "Duplicate",
    "BENIGN": "Other",
    "NOT_ACTIONABLE": "Other",
    "TRACKED_EXTERNALLY": "Other",
}

RS_SEVERITY_TO_XSOAR_SEVERITY: dict[str, int] = {
    "SEVERITY_LEVEL_LOW": IncidentSeverity.LOW,
    "SEVERITY_LEVEL_MEDIUM": IncidentSeverity.MEDIUM,
    "SEVERITY_LEVEL_HIGH": IncidentSeverity.HIGH,
    "SEVERITY_LEVEL_UNSPECIFIED": IncidentSeverity.UNKNOWN,
}
RS_SEVERITY_LEVEL_HR_LIST = ["Low", "Medium", "High"]
RS_SEVERITY_LEVEL_API_MAP: dict[str, str] = {
    "low": "SEVERITY_LEVEL_LOW",
    "medium": "SEVERITY_LEVEL_MEDIUM",
    "high": "SEVERITY_LEVEL_HIGH",
}
RS_RELEVANCE_LEVEL_HR_LIST = ["Low", "Medium", "High"]
RS_RELEVANCE_LEVEL_API_MAP: dict[str, str] = {
    "low": "RELEVANCE_LEVEL_LOW",
    "medium": "RELEVANCE_LEVEL_MEDIUM",
    "high": "RELEVANCE_LEVEL_HIGH",
}
RS_PRIORITY_LEVEL_HR_LIST = ["Low", "Medium", "High", "Critical"]
RS_PRIORITY_LEVEL_API_MAP: dict[str, str] = {
    "low": "PRIORITY_LEVEL_LOW",
    "medium": "PRIORITY_LEVEL_MEDIUM",
    "high": "PRIORITY_LEVEL_HIGH",
    "critical": "PRIORITY_LEVEL_CRITICAL",
}
RS_STATUS_HR_LIST = [
    "New",
    "Read",
    "Triaged",
    "Escalated",
    "Resolved",
    "Duplicate",
    "False Positive",
    "Not Actionable",
    "Benign",
    "Tracked Externally",
]
RS_STATUS_API_MAP: dict[str, str] = {
    "new": "NEW",
    "read": "READ",
    "triaged": "TRIAGED",
    "escalated": "ESCALATED",
    "resolved": "RESOLVED",
    "duplicate": "DUPLICATE",
    "false positive": "FALSE_POSITIVE",
    "not actionable": "NOT_ACTIONABLE",
    "benign": "BENIGN",
    "tracked externally": "TRACKED_EXTERNALLY",
}
RS_THREAT_SCENARIO_HR_LIST = ["Data Leak", "Initial Access Broker", "Insider Threat"]
RS_THREAT_SCENARIO_API_MAP: dict[str, str] = {
    "data leak": "data_leak",
    "initial access broker": "initial_access_broker",
    "insider threat": "insider_threat",
}
RS_ORDER_HR_LIST = ["Asc", "Desc"]
RS_ORDER_API_MAP: dict[str, str] = {
    "asc": "asc",
    "desc": "desc",
}
RS_SORT_HR_LIST = ["Create Time", "Update Time", "Relevance Level", "Severity Level", "Priority Level"]
RS_UPDATE_STATUS_HR_LIST = [
    "Read",
    "Triaged",
    "Escalated",
    "Resolved",
    "Duplicate",
    "False Positive",
    "Not Actionable",
    "Benign",
    "Tracked Externally",
]
RS_UPDATE_STATUS_API_MAP: dict[str, str] = {
    "read": "read",
    "triaged": "triage",
    "escalated": "escalate",
    "resolved": "resolve",
    "duplicate": "duplicate",
    "false positive": "falsePositive",
    "not actionable": "notActionable",
    "benign": "benign",
    "tracked externally": "trackExternally",
}
RS_SORT_API_MAP: dict[str, str] = {
    "create time": "audit.create_time",
    "update time": "audit.update_time",
    "relevance level": "relevance_analysis.relevance_level",
    "severity level": "severity_analysis.severity_level",
    "priority level": "priority_analysis.priority_level",
}
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 2147483647
DEFAULT_ORDER = "Desc"
DEFAULT_SORT = "Update Time"
DEFAULT_UPDATE_TIME = "3 days"
OUTPUT_PREFIX = "GoogleThreatIntelligenceRSAlerts.Alert"
MESSAGES = {
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
}


""" CLIENT CLASS """


class Client(BaseClient):
    """Client for Google Threat Intelligence RS Alerts API."""

    def __init__(self, server_url: str, verify_certificate: bool, proxy: bool, api_key: str, project_id: str):
        super().__init__(
            base_url=server_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                "User-Agent": USER_AGENT,
                "x-goog-user-project": project_id,
                "x-tool": USER_AGENT,
            },
        )
        self.api_key = api_key
        self.project_id = project_id

        # Use a cached access token from the integration context, or generate one if missing.
        integration_context = get_integration_context()
        self._token = integration_context.get("access_token") or self._generate_token()

    def _generate_token(self) -> str:
        """
        Exchange the configured API key for an OAuth 2.0 access token.

        Returns:
            str: The access token to use as a Bearer token on subsequent calls.
        """
        demisto.info("Generating new access token using the provided API key.")

        headers = {"User-Agent": USER_AGENT, "x-tool": USER_AGENT}
        response = self._http_request(
            method="POST",
            full_url=f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
            headers=headers,
            json_data={"api_key": self.api_key},
            retries=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            ok_codes=OK_CODES,
            raise_on_status=True,
            resp_type="response",
        )

        if response.status_code == 401:
            try:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(response.status_code, str(response.json()))
            except ValueError:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(response.status_code, response.text)
            raise DemistoException(err_msg)

        try:
            access_token = response.json().get("access_token")
        except ValueError as e:
            raise DemistoException(
                ERROR_MESSAGES["INVALID_OBJECT"].format("json", response.content),
                e,
                response,
            )

        if not access_token:
            raise DemistoException(ERROR_MESSAGES["TOKEN_GENERATION_FAILED"])

        set_integration_context({"access_token": access_token})
        return access_token

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        response_type: str = "response",
        _token_refreshed: bool = False,
        **kwargs,
    ):
        """
        Makes an authenticated HTTP request to the Google Threat Intelligence platform.

        On 401 the access token is refreshed once via _generate_token() and the request is retried.
        """
        headers = {**self._headers, "Authorization": f"Bearer {self._token}"}

        log_header = {**headers, "Authorization": "Bearer ***********"}
        demisto.debug(
            f"Making API request at {method} {url_suffix} with headers:{log_header}, params:{params} and body:{data or json_data}"
        )

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
            resp_type="response",
            raise_on_status=True,
            **kwargs,
        )

        # Refresh the token once on 401 and retry the original request.
        if res.status_code == 401 and not _token_refreshed:
            demisto.debug("Received 401 from API, refreshing access token and retrying the request.")
            self._token = self._generate_token()
            return self.http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                data=data,
                json_data=json_data,
                response_type=response_type,
                _token_refreshed=True,
                **kwargs,
            )
        elif res.status_code == 401:
            try:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, str(res.json()))
            except ValueError:
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, res.text)
            raise DemistoException(err_msg)

        if response_type == "json":
            try:
                return res.json()
            except ValueError as e:
                raise DemistoException(ERROR_MESSAGES["INVALID_OBJECT"].format(response_type, res.content), e, res)
        return res

    def get_alert_list(self, query_params: dict, response_type: str = "json"):
        """
        List RS Alerts for the configured project.

        See Also:
            https://gtidocs.virustotal.com/reference/list-alerts
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["ALERT_LIST"].format(self.project_id),
            params=query_params,
            response_type=response_type,
        )

    def get_alert(self, alert_id: str, response_type: str = "json"):
        """
        Get a single RS Alert by ID.

        See Also:
            https://gtidocs.virustotal.com/reference/get-alert
        """
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["ALERT_GET"].format(self.project_id, alert_id),
            response_type=response_type,
        )

    def update_alert_status(self, alert_id: str, state: str, response_type: str = "json"):
        """
        Update the status of a single RS Alert by ID.

        See Also:
            https://gtidocs.virustotal.com/reference/update-alert-status
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["ALERT_STATUS_UPDATE"].format(self.project_id, alert_id, state),
            response_type=response_type,
        )


""" HELPER FUNCTIONS """


def trim_spaces_from_args(args: dict) -> dict:
    """Trim spaces from string values in the supplied args dict."""
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


def parse_alert_name(alert_name: str) -> tuple[str, str]:
    """Parse a resource name like 'projects/{project_id}/alerts/{alert_id}' into its components.

    :param alert_name: Full resource name string.
    :return: Tuple of (alert_id, project_id).
    """
    name_parts = alert_name.split("/") if alert_name else []
    alert_id = name_parts[-1] if name_parts else ""
    project_id = name_parts[1] if len(name_parts) > 1 else ""
    return alert_id, project_id


def validate_rs_params(
    is_command: bool = False,
    page_size: int | None = None,
    order_by: str | None = None,
    sort_by: str | None = None,
    max_fetch_raw: int | None = None,
    relevance_level: list[str] | None = None,
    severity_level: list[str] | None = None,
    priority_level: list[str] | None = None,
    status: list[str] | None = None,
    threat_scenarios: list[str] | None = None,
) -> None:
    """
    Validate RS Alert parameters for both command and fetch contexts.

    Args:
        is_command: True for command validation, False for fetch validation
        page_size: Command-only parameter
        order_by: Command-only parameter
        sort_by: Command-only parameter
        max_fetch_raw: Fetch-only parameter
        relevance_level: Shared filter parameter
        severity_level: Shared filter parameter
        priority_level: Shared filter parameter
        status: Shared filter parameter
        threat_scenarios: Shared filter parameter

    Raises:
        ValueError: If any parameter contains an invalid value.
    """
    errors = []

    if is_command:
        if page_size is not None and (page_size < 1 or page_size > MAX_PAGE_SIZE):
            errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(page_size, "page_size", f"between 1 and {MAX_PAGE_SIZE}"))

        if order_by and order_by.lower() not in RS_ORDER_API_MAP:
            errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(order_by, "order_by", RS_ORDER_HR_LIST))

        if sort_by and sort_by.lower() not in RS_SORT_API_MAP:
            errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(sort_by, "sort_by", RS_SORT_HR_LIST))
    else:
        if max_fetch_raw is not None and (max_fetch_raw < 1 or max_fetch_raw > MAX_FETCH):
            errors.append(ERROR_MESSAGES["INVALID_MAX_FETCH"].format(max_fetch_raw, MAX_FETCH))

    if relevance_level:
        for level in relevance_level:
            if level.lower() not in RS_RELEVANCE_LEVEL_API_MAP:
                errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(level, "relevance_level", RS_RELEVANCE_LEVEL_HR_LIST))

    if severity_level:
        for level in severity_level:
            if level.lower() not in RS_SEVERITY_LEVEL_API_MAP:
                errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(level, "severity_level", RS_SEVERITY_LEVEL_HR_LIST))

    if priority_level:
        for level in priority_level:
            if level.lower() not in RS_PRIORITY_LEVEL_API_MAP:
                errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(level, "priority_level", RS_PRIORITY_LEVEL_HR_LIST))

    if status:
        for stat in status:
            if stat.lower() not in RS_STATUS_API_MAP:
                errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(stat, "status", RS_STATUS_HR_LIST))

    if threat_scenarios:
        for scenario in threat_scenarios:
            if scenario.lower() not in RS_THREAT_SCENARIO_API_MAP:
                errors.append(ERROR_MESSAGES["INVALID_ARGUMENT"].format(scenario, "threat_scenarios", RS_THREAT_SCENARIO_HR_LIST))

    if errors:
        raise ValueError("\n\n".join(errors))


def _get_filter_params_signature(
    relevance_level: list[str],
    severity_level: list[str],
    priority_level: list[str],
    status: list[str],
    threat_scenarios: list[str],
) -> str:
    """Return a stable string signature of the fetch filter params to detect changes between runs."""
    return "|".join(
        [
            ",".join(sorted(v.lower() for v in relevance_level if v.lower() in RS_RELEVANCE_LEVEL_API_MAP)),
            ",".join(sorted(v.lower() for v in severity_level if v.lower() in RS_SEVERITY_LEVEL_API_MAP)),
            ",".join(sorted(v.lower() for v in priority_level if v.lower() in RS_PRIORITY_LEVEL_API_MAP)),
            ",".join(sorted(v.lower() for v in status if v.lower() in RS_STATUS_API_MAP)),
            ",".join(sorted(v.lower() for v in threat_scenarios if v.lower() in RS_THREAT_SCENARIO_API_MAP)),
        ]
    )


def _build_rs_filter_string(
    is_command: bool = False,
    last_update_time: str | None = None,
    create_time: str | None = None,
    update_time: str | None = None,
    relevance_level: list[str] | None = None,
    severity_level: list[str] | None = None,
    priority_level: list[str] | None = None,
    status: list[str] | None = None,
    threat_scenarios: list[str] | None = None,
) -> str:
    """
    Build a CEL filter string for the RS Alerts list API.

    Args:
        is_command: True for command filter (create_time/update_time), False for fetch (last_update_time)
        last_update_time: Fetch-only parameter for time threshold
        create_time: Command-only parameter for alert creation time
        update_time: Command-only parameter for alert update time
        relevance_level: Shared filter parameter
        severity_level: Shared filter parameter
        priority_level: Shared filter parameter
        status: Shared filter parameter
        threat_scenarios: Shared filter parameter

    Returns:
        str: CEL filter string
    """
    filter_parts = []

    if is_command:
        if create_time:
            filter_parts.append(f'audit.create_time >= "{create_time}"')
        if update_time:
            filter_parts.append(f'audit.update_time >= "{update_time}"')
    else:
        if last_update_time:
            filter_parts.append(f'audit.update_time >= "{last_update_time}"')

    if relevance_level:
        api_vals = [RS_RELEVANCE_LEVEL_API_MAP[v.lower()] for v in relevance_level if v.lower() in RS_RELEVANCE_LEVEL_API_MAP]
        if api_vals:
            cond = " OR ".join(f'relevance_analysis.relevance_level = "{v}"' for v in api_vals)
            filter_parts.append(f"({cond})" if len(api_vals) > 1 else cond)

    if severity_level:
        api_vals = [RS_SEVERITY_LEVEL_API_MAP[v.lower()] for v in severity_level if v.lower() in RS_SEVERITY_LEVEL_API_MAP]
        if api_vals:
            cond = " OR ".join(f'severity_analysis.severity_level = "{v}"' for v in api_vals)
            filter_parts.append(f"({cond})" if len(api_vals) > 1 else cond)

    if priority_level:
        api_vals = [RS_PRIORITY_LEVEL_API_MAP[v.lower()] for v in priority_level if v.lower() in RS_PRIORITY_LEVEL_API_MAP]
        if api_vals:
            cond = " OR ".join(f'priority_analysis.priority_level = "{v}"' for v in api_vals)
            filter_parts.append(f"({cond})" if len(api_vals) > 1 else cond)

    if status:
        api_vals = [RS_STATUS_API_MAP[v.lower()] for v in status if v.lower() in RS_STATUS_API_MAP]
        if api_vals:
            cond = " OR ".join(f'state = "{v}"' for v in api_vals)
            filter_parts.append(f"({cond})" if len(api_vals) > 1 else cond)

    if threat_scenarios:
        api_vals = [RS_THREAT_SCENARIO_API_MAP[v.lower()] for v in threat_scenarios if v.lower() in RS_THREAT_SCENARIO_API_MAP]
        if api_vals:
            cond = " OR ".join(f'detail.detail_type = "{v}"' for v in api_vals)
            filter_parts.append(f"({cond})" if len(api_vals) > 1 else cond)

    return " AND ".join(filter_parts) if filter_parts else ""


def _build_rs_alert_list_output(alerts_data: list, title: str) -> tuple:
    """
    Build human-readable output and context for RS alerts as per TDD.

    Args:
        alerts_data: List of alerts from RS alerts API.
        title: Title for the markdown table.

    Returns:
        tuple: (context, readable_output)
    """
    hr_content = []
    context = []

    for alert in alerts_data:
        alert = remove_empty_elements_for_fetch(alert)
        context.append(alert)

        alert_id, project_id = parse_alert_name(alert.get("name", ""))
        audit = alert.get("audit", {})

        priority_level_val = demisto.get(alert, "priorityAnalysis.priorityLevel", "")
        severity_level_val = demisto.get(alert, "severityAnalysis.severityLevel", "")
        relevance_level_val = demisto.get(alert, "relevanceAnalysis.relevanceLevel", "")
        status_val = alert.get("state", "")
        detail_type_val = alert.get("detail", {}).get("detailType", "")

        display_name = alert.get("displayName", alert_id)
        vt_url = f"{PLATFORM_URL}/alerts/{alert_id}?project=projects/{project_id}" if alert_id and project_id else ""
        alert_name_display = f"[{display_name}]({vt_url})" if vt_url else display_name

        hr_content.append(
            {
                "Alert Name": alert_name_display,
                "Alert ID": alert_id,
                "Status": status_val.replace("_", " ").capitalize() if status_val else "",
                "Priority": priority_level_val.replace("PRIORITY_LEVEL_", "").capitalize() if priority_level_val else "",
                "Severity": severity_level_val.replace("SEVERITY_LEVEL_", "").capitalize() if severity_level_val else "",
                "Relevance": relevance_level_val.replace("RELEVANCE_LEVEL_", "").capitalize() if relevance_level_val else "",
                "Threat Scenario": detail_type_val.replace("_", " ").capitalize() if detail_type_val else "",
                "AI Summary": alert.get("aiSummary", ""),
                "Created Time": audit.get("createTime", ""),
                "Updated Time": audit.get("updateTime", ""),
                "Etag": alert.get("etag", ""),
                "Finding Count": alert.get("findingCount", ""),
                "Findings": alert.get("findings", ""),
            }
        )

    headers = [
        "Alert Name",
        "Alert ID",
        "Status",
        "Priority",
        "Severity",
        "Relevance",
        "Threat Scenario",
        "AI Summary",
        "Created Time",
        "Updated Time",
        "Etag",
        "Finding Count",
        "Findings",
    ]

    readable_output = tableToMarkdown(title, hr_content, headers=headers, removeNull=True)

    return context, readable_output


def _build_rs_alert_get_output(alert_data: dict, title: str) -> tuple:
    """
    Build human-readable output and context for a single RS alert with all fields.

    Args:
        alert_data: Single alert dict from RS alert get API.
        title: Title for the markdown table.

    Returns:
        tuple: (context, readable_output)
    """
    context = remove_empty_elements_for_fetch(alert_data)
    alert = remove_empty_elements_for_hr(alert_data)

    alert_id, project_id = parse_alert_name(alert.get("name", ""))
    audit = alert.get("audit", {})

    priority_analysis = alert.get("priorityAnalysis", {})
    severity_analysis = alert.get("severityAnalysis", {})
    relevance_analysis = alert.get("relevanceAnalysis", {})
    evidence = relevance_analysis.get("evidence", {})

    priority_level_val = priority_analysis.get("priorityLevel", "")
    severity_level_val = severity_analysis.get("severityLevel", "")
    relevance_level_val = relevance_analysis.get("relevanceLevel", "")
    status_val = alert.get("state", "")
    detail_type_val = alert.get("detail", {}).get("detailType", "")

    display_name = alert.get("displayName", alert_id)
    vt_url = f"{PLATFORM_URL}/alerts/{alert_id}?project=projects/{project_id}" if alert_id and project_id else ""
    alert_name_display = f"[{display_name}]({vt_url})" if vt_url else display_name

    hr_content = {
        "Alert Name": alert_name_display,
        "Alert ID": alert_id,
        "Status": status_val.replace("_", " ").capitalize() if status_val else "",
        "Priority": priority_level_val.replace("PRIORITY_LEVEL_", "").capitalize() if priority_level_val else "",
        "Priority Confidence": priority_analysis.get("confidence", "").replace("CONFIDENCE_LEVEL_", "").capitalize(),
        "Priority Reasoning": priority_analysis.get("reasoning", ""),
        "Severity": severity_level_val.replace("SEVERITY_LEVEL_", "").capitalize() if severity_level_val else "",
        "Severity Confidence": severity_analysis.get("confidence", "").replace("CONFIDENCE_LEVEL_", "").capitalize(),
        "Severity Reasoning": severity_analysis.get("reasoning", ""),
        "Relevance": relevance_level_val.replace("RELEVANCE_LEVEL_", "").capitalize() if relevance_level_val else "",
        "Relevant": relevance_analysis.get("relevant"),
        "Relevance Confidence": relevance_analysis.get("confidence", "").replace("CONFIDENCE_LEVEL_", "").capitalize(),
        "Relevance Reasoning": relevance_analysis.get("reasoning", ""),
        "Common Themes": evidence.get("commonThemes", []),
        "Distinct Themes": evidence.get("distinctThemes", []),
        "Threat Scenario": detail_type_val.replace("_", " ").capitalize() if detail_type_val else "",
        "AI Summary": alert.get("aiSummary", ""),
        "Created Time": audit.get("createTime", ""),
        "Updated Time": audit.get("updateTime", ""),
        "Creator": audit.get("creator", ""),
        "Updater": audit.get("updater", ""),
        "Etag": alert.get("etag", ""),
        "External ID": alert.get("externalId", ""),
        "Finding Count": alert.get("findingCount", ""),
        "Findings": alert.get("findings", []),
        "Configurations": alert.get("configurations", []),
    }

    headers = [
        "Alert Name",
        "Alert ID",
        "Status",
        "Priority",
        "Priority Confidence",
        "Priority Reasoning",
        "Severity",
        "Severity Confidence",
        "Severity Reasoning",
        "Relevance",
        "Relevant",
        "Relevance Confidence",
        "Relevance Reasoning",
        "Common Themes",
        "Distinct Themes",
        "Threat Scenario",
        "AI Summary",
        "Created Time",
        "Updated Time",
        "Creator",
        "Updater",
        "Etag",
        "External ID",
        "Finding Count",
        "Findings",
        "Configurations",
    ]

    readable_output = tableToMarkdown(title, hr_content, headers=headers, removeNull=True)

    return context, readable_output


def _build_rs_alert_status_update_output(alert_data: dict, title: str) -> tuple:
    """
    Build human-readable output and context for a status-updated RS alert.

    Args:
        alert_data: Alert dict returned by the update status API.
        title: Title for the markdown table.

    Returns:
        tuple: (context, readable_output)
    """
    context = remove_empty_elements_for_fetch(alert_data)
    alert = remove_empty_elements_for_hr(alert_data)

    alert_id, project_id = parse_alert_name(alert.get("name", ""))

    display_name = alert.get("displayName", alert_id)
    vt_url = f"{PLATFORM_URL}/alerts/{alert_id}?project=projects/{project_id}" if alert_id and project_id else ""
    alert_name_display = f"[{display_name}]({vt_url})" if vt_url else display_name

    status_val = alert.get("state", "")
    hr_content = {
        "Alert Name": alert_name_display,
        "Status": status_val.replace("_", " ").capitalize() if status_val else "",
    }

    readable_output = tableToMarkdown(title, hr_content, headers=["Alert Name", "Status"], removeNull=True)
    return context, readable_output


def get_mirroring(params: dict) -> dict:
    """Return mirror direction and instance name from integration params."""
    mirror_direction = (params.get("mirror_direction") or "").strip()
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
    }


""" COMMAND FUNCTIONS """


def gti_rs_alert_list_command(client: Client, args: dict) -> CommandResults:
    """
    List RS alerts for the specified filter parameters.

    Args:
        client: Client object to use.
        args: arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    page_size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), arg_name="page_size")
    order_by = args.get("order_by", DEFAULT_ORDER)
    sort_by = args.get("sort_by", DEFAULT_SORT)
    create_time = args.get("create_time")
    update_time = args.get("update_time", DEFAULT_UPDATE_TIME)
    relevance_level = argToList(args.get("relevance_level"), transform=lambda s: s.strip())
    severity_level = argToList(args.get("severity_level"), transform=lambda s: s.strip())
    priority_level = argToList(args.get("priority_level"), transform=lambda s: s.strip())
    status = argToList(args.get("status"), transform=lambda s: s.strip())
    threat_scenarios = argToList(args.get("threat_scenarios"), transform=lambda s: s.strip())

    validate_rs_params(
        is_command=True,
        page_size=page_size,
        order_by=order_by,
        sort_by=sort_by,
        relevance_level=relevance_level,
        severity_level=severity_level,
        priority_level=priority_level,
        status=status,
        threat_scenarios=threat_scenarios,
    )

    create_time_dt = None
    if create_time:
        create_time_dt = arg_to_datetime(create_time)
        if create_time_dt:
            create_time = create_time_dt.strftime(DATE_TIME_FORMAT)  # type: ignore

    update_time_dt = None
    if update_time:
        update_time_dt = arg_to_datetime(update_time)
        if update_time_dt:
            update_time = update_time_dt.strftime(DATE_TIME_FORMAT)  # type: ignore

    filter_string = _build_rs_filter_string(
        is_command=True,
        create_time=create_time,
        update_time=update_time,
        relevance_level=relevance_level,
        severity_level=severity_level,
        priority_level=priority_level,
        status=status,
        threat_scenarios=threat_scenarios,
    )

    sort_field = RS_SORT_API_MAP.get(sort_by.lower(), "audit.update_time")
    order_val = RS_ORDER_API_MAP.get(order_by.lower(), "desc")

    query_params: dict[str, Any] = {
        "pageSize": page_size,
        "orderBy": f"{sort_field} {order_val}",
    }

    if filter_string:
        query_params["filter"] = filter_string

    raw_response = client.get_alert_list(query_params, response_type="json")

    alerts_data = raw_response.get("alerts", [])
    if not alerts_data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("RS Alerts"))

    context, hr = _build_rs_alert_list_output(alerts_data, "GTI RS Alert List")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field="name",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def gti_rs_alert_get_command(client: Client, args: dict) -> CommandResults:
    """
    Get a particular RS Alert by ID.

    Args:
        client: Client object to use.
        args: arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    alert_id = args.get("alert_id", "")
    if not alert_id:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("alert_id"))

    raw_response = client.get_alert(alert_id, response_type="json")

    context, hr = _build_rs_alert_get_output(raw_response, "GTI RS Alert Information")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field="name",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def gti_rs_alert_status_update_command(client: Client, args: dict) -> CommandResults:
    """
    Update the status of a particular RS Alert by ID.

    Args:
        client: Client object to use.
        args: arguments obtained from demisto.args().

    Returns:
        CommandResults: CommandResult object
    """
    alert_id = args.get("alert_id", "")
    if not alert_id:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("alert_id"))

    status = args.get("status", "")
    if not status:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("status"))

    if status.lower() not in RS_UPDATE_STATUS_API_MAP:
        raise ValueError(ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", RS_UPDATE_STATUS_HR_LIST))

    api_status = RS_UPDATE_STATUS_API_MAP[status.lower()]
    raw_response = client.update_alert_status(alert_id, api_status, response_type="json")

    context, hr = _build_rs_alert_status_update_output(raw_response, "Alert Status Updated Successfully.")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX,
        outputs_key_field="name",
        outputs=context,
        raw_response=raw_response,
        readable_output=hr,
    )


def get_remote_data_command(client: Client, args: dict) -> GetRemoteDataResponse:
    """
    Incoming mirroring: fetch latest alert state from GTI and return fields/entries
    to apply to the XSOAR incident.
    """
    remote_args = GetRemoteDataArgs(args)
    alert_id = remote_args.remote_incident_id

    demisto.debug(f"RS Alert get_remote_data called for alert_id={alert_id}")

    alert = client.get_alert(alert_id, response_type="json")

    rs_status = alert.get("state", "")
    xsoar_status = RS_STATE_TO_XSOAR_STATE.get(rs_status, "")

    mirrored_data: dict[str, Any] = alert

    entries: list[dict] = []
    params = demisto.params()

    # Get integration context to track processed alerts
    integration_context = demisto.getIntegrationContext()
    processed_alerts = integration_context.get("processed_alerts") or []
    mirroring_direction = params.get("mirror_direction") or ""

    # Incident Reopen Entry based on GTI alert status
    if (
        rs_status in RS_OPEN_STATUSES
        and argToBoolean(params.get("reopen_incident_for_open_alert_status", True))
        and (alert_id in processed_alerts or mirroring_direction.lower() == "incoming")
    ):
        if alert_id in processed_alerts:
            processed_alerts.remove(alert_id)
            demisto.debug(f"removed {alert_id} Alert from processed alerts.")
        demisto.debug(f"RS Alert {alert_id} is open ({rs_status}), reopening XSOAR incident")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {"dbotIncidentReopen": True},
                "ContentsFormat": EntryFormat.JSON,
                "Note": False,
            }
        )
    # Incident Close Entry based on GTI alert status
    elif (
        rs_status in RS_CLOSE_STATUSES
        and argToBoolean(params.get("close_incident_for_close_alert_status", True))
        and (alert_id not in processed_alerts or mirroring_direction.lower() == "incoming")
    ):
        if alert_id not in processed_alerts:
            processed_alerts.append(alert_id)
            demisto.debug(f"added {alert_id} Alert to processed alerts.")
        close_reason = RS_CLOSE_REASON_MAPPING.get(rs_status, "Other")
        demisto.debug(f"RS Alert {alert_id} is closed ({rs_status}), closing XSOAR incident with reason={close_reason}")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": close_reason,
                    "closeNotes": f"Closed via GTI RS Alert mirroring. Alert Status: {xsoar_status}",
                },
                "ContentsFormat": EntryFormat.JSON,
                "Note": False,
            }
        )

    processed_alerts = processed_alerts[-MAX_MIRRORING_LIMIT:]
    integration_context["processed_alerts"] = processed_alerts
    demisto.setIntegrationContext(integration_context)

    return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=entries)


def get_modified_remote_data_command(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
    """
    Incoming mirroring: return alert IDs that were updated since the last sync,
    so XSOAR knows which incidents need a full get_remote_data pull.
    Paginates through all pages using nextPageToken; deduplicates and caps at MAX_MIRRORING_LIMIT.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update

    last_update_dt = arg_to_datetime(last_update)
    last_update_str = last_update_dt.strftime(DATE_TIME_FORMAT) if last_update_dt else ""

    demisto.debug(f"RS Alert get_modified_remote_data called with last_update={last_update_str}")

    modified_ids: list[str] = []
    next_alert_timestamp: str | None = None
    page_size = 1000

    while True:
        if next_alert_timestamp:
            last_update_str = next_alert_timestamp

        query_params: dict[str, Any] = {
            "pageSize": page_size,
            "orderBy": "audit.update_time asc",
        }
        if last_update_str:
            query_params["filter"] = f'audit.update_time >= "{last_update_str}"'

        response = client.get_alert_list(query_params, response_type="json")
        alerts = response.get("alerts", [])

        if not alerts:
            break

        for alert in alerts:
            alert_id, _ = parse_alert_name(alert.get("name", ""))
            if alert_id:
                modified_ids.append(alert_id)
        next_alert_timestamp = alerts[-1].get("audit", {}).get("updateTime", "")

        if not next_alert_timestamp:
            break

        if len(alerts) < page_size:
            break

        if len(modified_ids) >= MAX_MIRRORING_LIMIT:
            demisto.debug(f"RS Alert max mirroring limit ({MAX_MIRRORING_LIMIT}) reached, stopping pagination")
            break

    # Deduplicate while preserving insertion order
    result_ids = list(set(filter(None, modified_ids)))[:MAX_MIRRORING_LIMIT]

    demisto.debug(f"RS Alert get_modified_remote_data: {len(result_ids)} unique modified IDs since {last_update_str}")
    return GetModifiedRemoteDataResponse(result_ids)


def update_remote_system_command(client: Client, args: dict) -> str:
    """
    Outgoing mirroring: push XSOAR incident changes back to the corresponding
    GTI RS Alert (status updates only).
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_alert_id = parsed_args.remote_incident_id

    # inc_status and delta arrive as raw strings from XSOAR
    try:
        incident_status = int(parsed_args.inc_status) if parsed_args.inc_status is not None else IncidentStatus.ACTIVE
    except (ValueError, TypeError):
        incident_status = IncidentStatus.ACTIVE

    raw_delta = parsed_args.delta or {}
    if isinstance(raw_delta, str):
        try:
            delta: dict = json.loads(raw_delta) if raw_delta else {}
        except (ValueError, json.JSONDecodeError):
            delta = {}
    else:
        delta = raw_delta

    incident_changed = argToBoolean(parsed_args.incident_changed) if parsed_args.incident_changed is not None else False

    demisto.debug(f"RS Alert update_remote_system called for alert_id={remote_alert_id}")
    demisto.debug(f"Incident changed: {incident_changed}, status: {incident_status}, delta keys: {list(delta.keys())}")

    if not remote_alert_id:
        demisto.debug("No remote alert ID, skipping update")
        return remote_alert_id

    if not incident_changed:
        demisto.debug("No incident changes, skipping update")
        return remote_alert_id

    params = demisto.params()

    if "gtirsalertstate" in delta:
        new_status = (delta.get("gtirsalertstate") or "").strip()
        if new_status.lower() in RS_UPDATE_STATUS_API_MAP:
            api_status = RS_UPDATE_STATUS_API_MAP[new_status.lower()]
            demisto.debug(f"gtirsalertstate changed to '{new_status}', updating GTI RS Alert {remote_alert_id}")
            client.update_alert_status(remote_alert_id, api_status)
        else:
            demisto.debug(f"gtirsalertstate value '{new_status}' is not a valid RS update status, skipping")

    # Get integration context to track processed alerts
    integration_context = demisto.getIntegrationContext()
    processed_alerts = integration_context.get("processed_alerts") or []

    # Updating GTI alert status while incident is close in XSOAR
    if incident_status == IncidentStatus.DONE:
        demisto.debug(f"Incident {remote_alert_id} is closed.")
        if remote_alert_id not in processed_alerts:
            processed_alerts.append(remote_alert_id)
            demisto.debug(f"added {remote_alert_id} Alert to processed alerts.")
        alert_status = (params.get("alert_status_for_incident_closure") or "Resolved").strip()
        if alert_status.lower() in RS_UPDATE_STATUS_API_MAP:
            api_status = RS_UPDATE_STATUS_API_MAP[alert_status.lower()]
            demisto.debug(f"Incident closed, updating GTI RS Alert {remote_alert_id} to status={api_status}")
            client.update_alert_status(remote_alert_id, api_status)
        else:
            demisto.debug(f"alert_status_for_incident_closure value '{alert_status}' is not a valid RS status, skipping")

    # Updating GTI alert status while incident is reopened in XSOAR
    if delta and delta.get("closingUserId") == "":
        demisto.debug(f"Incident {remote_alert_id} is reopened.")
        if remote_alert_id in processed_alerts:
            processed_alerts.remove(remote_alert_id)
            demisto.debug(f"removed {remote_alert_id} Alert from processed alerts.")
        alert_status = (params.get("alert_status_for_incident_reopen") or "Escalated").strip()
        if alert_status.lower() in RS_UPDATE_STATUS_API_MAP:
            api_status = RS_UPDATE_STATUS_API_MAP[alert_status.lower()]
            demisto.debug(f"Incident reopened, updating GTI RS Alert {remote_alert_id} to status={api_status}")
            client.update_alert_status(remote_alert_id, api_status)
        else:
            demisto.debug(f"alert_status_for_incident_reopen value '{alert_status}' is not a valid RS status, skipping")

    processed_alerts = processed_alerts[-MAX_MIRRORING_LIMIT:]
    integration_context["processed_alerts"] = processed_alerts
    demisto.setIntegrationContext(integration_context)

    return remote_alert_id


def fetch_incidents(
    client: Client, last_run: dict, params: dict, is_test: bool = False
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch RS Alerts as XSOAR incidents from Google Threat Intelligence.

    Args:
        client (Client): Google Threat Intelligence client object.
        last_run (dict): Checkpoint data from the previous fetch run.
        params (dict): Integration configuration parameters.
        is_test (bool): When True, performs a single API call without creating incidents.

    Returns:
        tuple: List of XSOAR incidents and the updated checkpoint for the next run.
    """
    first_fetch_dt = arg_to_datetime(params.get("first_fetch", DEFAULT_FETCH_TIME))
    first_fetch_str: str = first_fetch_dt.strftime(DATE_TIME_FORMAT)  # type: ignore

    max_fetch_raw: int = arg_to_number(params.get("max_fetch", str(DEFAULT_MAX_FETCH)), "Max Fetch")  # type: ignore
    if max_fetch_raw < 1:
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"].format(max_fetch_raw, MAX_FETCH))
    max_fetch = min(int(max_fetch_raw), MAX_FETCH)
    if max_fetch_raw > MAX_FETCH:
        demisto.debug(
            f"max_fetch value {max_fetch_raw} exceeds the maximum allowed value {MAX_FETCH}. Setting max_fetch to {MAX_FETCH}."
        )

    relevance_level = argToList(params.get("relevance_level"))
    severity_level = argToList(params.get("severity_level"))
    priority_level = argToList(params.get("priority_level"))
    status = argToList(params.get("status"))
    threat_scenarios = argToList(params.get("threat_scenarios"))

    if is_test:
        validate_rs_params(
            is_command=False,
            max_fetch_raw=max_fetch_raw,
            relevance_level=relevance_level,
            severity_level=severity_level,
            priority_level=priority_level,
            status=status,
            threat_scenarios=threat_scenarios,
        )

    current_filter_sig = _get_filter_params_signature(relevance_level, severity_level, priority_level, status, threat_scenarios)
    stored_filter_sig = last_run.get("filter_params_signature", "")

    if stored_filter_sig and stored_filter_sig != current_filter_sig:
        demisto.debug("RS Alert filter params changed between fetch cycles, resetting last_update_time to first_fetch.")
        last_update_time = first_fetch_str
    else:
        last_update_time = last_run.get("last_update_time", first_fetch_str)

    current_alert_ids: list[str] = last_run.get("alert_ids", [])

    filter_string = _build_rs_filter_string(
        is_command=False,
        last_update_time=last_update_time,
        relevance_level=relevance_level,
        severity_level=severity_level,
        priority_level=priority_level,
        status=status,
        threat_scenarios=threat_scenarios,
    )

    query_params: dict[str, Any] = {
        "pageSize": max_fetch,
        "orderBy": "audit.update_time asc",
        "filter": filter_string,
    }

    demisto.debug(f"RS Alert fetch query_params: {query_params}")

    response = client.get_alert_list(query_params, response_type="json")
    alerts_list: list[dict[str, Any]] = response.get("alerts", [])

    if is_test:
        return [], {}

    alert_incidents: list[dict[str, Any]] = []
    found_alert_ids: list[str] = []
    duplicate_alert_ids: list[str] = []

    for alert in alerts_list:
        alert_id, project_id = parse_alert_name(alert.get("name", ""))

        if not alert_id or alert_id in current_alert_ids:
            duplicate_alert_ids.append(alert_id)
            continue

        audit = alert.get("audit", {})
        alert_create_time = audit.get("createTime", "") or audit.get("updateTime", "")
        severity_level_val = alert.get("severityAnalysis", {}).get("severityLevel", "SEVERITY_LEVEL_UNSPECIFIED")
        alert["incident_link"] = (
            f"{PLATFORM_URL}/alerts/{alert_id}?project=projects/{project_id}" if alert_id and project_id else ""
        )

        mirror_params = get_mirroring(params)
        mirror_params["mirror_id"] = alert_id
        alert.update(mirror_params)

        alert = remove_empty_elements_for_fetch(alert)

        alert_incidents.append(
            {
                "name": alert.get("displayName") or alert_id,
                "occurred": alert_create_time,
                "details": json.dumps(alert),
                "rawJSON": json.dumps(alert),
                "severity": RS_SEVERITY_TO_XSOAR_SEVERITY.get(severity_level_val, 0),
            }
        )
        found_alert_ids.append(alert_id)

    next_run: dict[str, Any] = {
        "last_update_time": alerts_list[-1].get("audit", {}).get("updateTime", last_update_time)
        if alerts_list
        else last_update_time,
        "alert_ids": current_alert_ids + found_alert_ids,
        "filter_params_signature": current_filter_sig,
    }

    demisto.debug(f"Fetched {len(found_alert_ids)} new RS Alert incidents")
    demisto.debug(f"Skipped {len(duplicate_alert_ids)} duplicate RS Alerts")
    demisto.debug(f"next_run: {next_run}")

    return alert_incidents, next_run


def test_module(client: Client) -> str:
    """
    Test connectivity to Google Threat Intelligence RS Alerts using the alert list endpoint.

    Args:
        client: Client object.

    Returns:
        str: "ok" if the connection with Google Threat Intelligence is successful.
    """
    params = demisto.params()
    is_fetch = params.get("isFetch", False)
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        client.get_alert_list(query_params={"pageSize": 1})
    return "ok"


def main():
    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    server_url = params.get("server_url", BASE_URL)
    api_key = str(dict_safe_get(params, ["credentials", "password"])).strip()
    project_id = params.get("project_id", "").strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Callable] = {
        "gti-rs-alert-list": gti_rs_alert_list_command,
        "gti-rs-alert-get": gti_rs_alert_get_command,
        "gti-rs-alert-status-update": gti_rs_alert_status_update_command,
    }

    try:
        result = None
        client = Client(
            server_url=server_url,
            verify_certificate=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            project_id=project_id,
        )
        args = demisto.args()
        if command == "test-module":
            result = test_module(client)
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command == "get-remote-data":
            result = get_remote_data_command(client, args)  # type: ignore
        elif command == "get-modified-remote-data":
            result = get_modified_remote_data_command(client, args)  # type: ignore
        elif command == "update-remote-system":
            result = update_remote_system_command(client, args)
        elif command in commands:
            args = trim_spaces_from_args(args)
            remove_nulls_from_dictionary(args)
            result = commands[command](client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
