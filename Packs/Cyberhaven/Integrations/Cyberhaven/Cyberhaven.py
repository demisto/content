import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""Cyberhaven Integration for Cortex XSOAR

This integration connects Cortex XSOAR to the Cyberhaven Data Security platform.
It supports fetching DLP incidents as XSOAR incidents, querying event details,
and tracing data lineage for investigation.

Authentication
--------------
Cyberhaven uses a two-step token model:
    1. A long-lived refresh token is stored in XSOAR credentials.
    2. Before each API call the Client exchanges the refresh token for a
        short-lived access token (valid for 15 minutes). The Client caches the
        access token in memory and re-fetches it only when it has expired.

Supported Commands
------------------
- test-module
- fetch-incidents
- cyberhaven-incident-list       List / search incidents with optional filters
- cyberhaven-incident-update     Update the status, assignment, or close reason of an incident
- cyberhaven-event-details-get   Retrieve full details for one or more events by ID
- cyberhaven-event-lineage-get   Retrieve the data lineage chain between two event IDs

API Reference: https://your-tenant.cyberhaven.io/public/v2/
"""

import json
import time
import urllib3
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

urllib3.disable_warnings()

""" CONSTANTS """

PACK_VERSION = get_pack_version() or "1.0.0"
USER_AGENT = f"XSOAR-Cyberhaven-{PACK_VERSION}"
UTM_PIVOT = f"?pivot={USER_AGENT}"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_SORT_ORDER = "trigger_time"
MAX_INCIDENTS_TO_FETCH = 200
DEFAULT_MAX_FETCH = 100
DEFAULT_PAGE_SIZE = 25
OK_CODES = (200, 401)
STATUS_CODE_TO_RETRY = [429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500)]  # type: ignore
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
SEVERITY_FILTER_VALUES = ("informational", "low", "medium", "high", "critical")
STATUS_FILTER_VALUES = ("open", "closed")
CLOSE_REASON_VALUES = (
    "Resolved",
    "False Positive",
    "False Positive - Destination Not at Risk",
    "False Positive - User Exempt",
    "Other",
)
CLOSE_REASON_MAPPING = {
    "Resolved": "valid",
    "False Positive": "invalid_data_mislabled",
    "False Positive - Destination Not at Risk": "invalid_destination_not_risk",
    "False Positive - User Exempt": "invalid_user_exempt",
    "Other": "invalid_other",
}
CLOSE_REASON_REVERSE_MAPPING = {v: k for k, v in CLOSE_REASON_MAPPING.items()}

ERROR_MESSAGES = {
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "UNAUTHORIZED_REQUEST": "Unauthorized request ({}): invalid refresh token. Details: {}.",
    "TOKEN_GENERATION_FAILED": "Failed to generate access token using the provided refresh token.",
    "INVALID_MIN_VALUE": "'{}' is an invalid value for '{}'. It must be greater than or equal to {}.",
    "INVALID_MAX_FETCH": "'{}' is an invalid value for 'max_fetch'. It must be between 1 and {}.",
    "INVALID_ARGUMENT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "INVALID_LIST_ARGUMENT": "{} are invalid values for '{}'. Value must be in {}.",
    "REQUIRED_ARGUMENT": "'{}' is required and cannot be empty.",
    "AT_LEAST_ONE_REQUIRED": "At least one of ({}) is required to update the incident.",
    "REQUIRED_BOTH_ARGUMENTS": "Both '{}' and '{}' are required and cannot be empty.",
    "INVALID_URL": "Invalid Server URL '{}'. Server URL must end with 'cyberhaven.io'.",
    "FIRST_FETCH_TOO_OLD": "Invalid 'First fetch time': value cannot be more than 30 days in the past.",
    "REFRESH_TOKEN_REQUIRED": "Refresh Token is required.",
}

TOKEN_ENDPOINT = "/public/v2/auth/token/access"
INCIDENTS_ENDPOINT = "/public/v2/incidents/list"
INCIDENT_PATCH_ENDPOINT = "/public/v2/incidents/{id}"
EVENT_DETAILS_ENDPOINT = "/public/v2/event-details"
EVENT_LINEAGE_ENDPOINT = "/public/v2/event-lineage"

INCIDENT_PLATFORM_LINK = "/incidents?id={id}"
EVENT_LINEAGE_LINK = '/overview?origin=dashboard&s={reference}&view="reports"'

SEVERITY_MAP: dict[str, float] = {
    "informational": IncidentSeverity.INFO,
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "critical": IncidentSeverity.CRITICAL,
    "unspecified": IncidentSeverity.UNKNOWN,
}

XSOAR_STATUS_TO_CH: dict[int, str] = {IncidentStatus.ACTIVE: "open", IncidentStatus.DONE: "closed"}

CREATED_BY_LABEL: dict[str, str] = {
    "linea_ai": "Linea AI",
    "linea_ai_and_policy": "Linea AI + Policy",
    "policy": "Policy",
}

WARNING_STATUS_LABEL: dict[str, str] = {
    "not_applicable": "Not Applicable",
    "pending": "Pending",
    "shown": "Shown",
    "skipped_timeout": "Skipped (timeout)",
    "skipped_throttled": "Skipped (throttled)",
    "skipped_other": "Skipped (other)",
}

ACTION_KIND_LABEL: dict[str, str] = {
    "dar_scan": "DAR Scan",
    "dlp_scan": "DLP Scan",
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Cyberhaven API client.

    Wraps all HTTP calls to the Cyberhaven public API.
    Handles automatic access-token refresh; callers do not need to manage tokens.

    Args:
        base_url (str): Base URL of the Cyberhaven tenant, e.g. https://your-tenant.cyberhaven.io
        refresh_token (str): Long-lived refresh token from integration credentials.
        verify (bool): Whether to verify SSL certificates.
        proxy (bool): Whether to route requests through the system proxy.
    """

    def __init__(self, base_url: str, refresh_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={"User-Agent": USER_AGENT})
        self._refresh_token = refresh_token

        integration_context = get_integration_context()
        self._access_token = integration_context.get("access_token", "")
        self._token_expiry = integration_context.get("token_expiry", 0.0)  # epoch seconds
        if not self._access_token or time.time() >= self._token_expiry - 60:
            self._access_token, self._token_expiry = self._generate_access_token()

    def _generate_access_token(self) -> tuple[str, float]:
        """Fetch a new access token if the current one is missing or expired."""
        demisto.debug("Cyberhaven: generating new access token.")
        response = self._http_request(
            method="POST",
            url_suffix=TOKEN_ENDPOINT,
            json_data={"refresh_token": self._refresh_token},
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

        # 15-minute access_token lifetime
        new_expiry = time.time() + 15 * 60
        set_integration_context({"access_token": access_token, "token_expiry": new_expiry})
        return access_token, new_expiry

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
        Makes an authenticated HTTP request to the Cyberhaven platform.

        On 401 the access token is refreshed once via _generate_access_token() and the request is retried.
        """
        headers = {**self._headers, "Authorization": f"Bearer {self._access_token}"}

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
            demisto.debug("Received 401 from API, generating new access token and retrying the request.")
            self._access_token, self._token_expiry = self._generate_access_token()
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
                err_msg = ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(res.status_code, str(res))
            raise DemistoException(err_msg)

        if response_type == "json":
            try:
                return res.json()
            except ValueError as e:
                raise DemistoException(ERROR_MESSAGES["INVALID_OBJECT"].format(response_type, res.content), e, res)
        return res

    def list_incidents(
        self,
        page_id: str = "",
        page_size: int = DEFAULT_PAGE_SIZE,
        sort_by: str = DEFAULT_SORT_ORDER,
        start_time: str = "",
        end_time: str = "",
        incident_ids: list[str] | None = None,
        policy_severities: list[str] | None = None,
        resolution_statuses: list[str] | None = None,
        assignees: list[str] | None = None,
        users: list[str] | None = None,
        include_ai_summaries: bool = True,
    ) -> dict[str, Any]:
        """Call POST /v2/incidents/list.

        Args:
            page_id (str): Opaque cursor returned by a previous call (empty for first page).
            page_size (int): Number of incidents per page.
            start_time (str): ISO-8601 datetime; only incidents at or after this time are returned.
            end_time (str): ISO-8601 datetime; only incidents before this time are returned.
            incident_ids (list[str]): Filter by incidents IDs.
            policy_severities (list[str]): Filter by policy severity levels.
            resolution_statuses (list[str]): Filter by status (e.g. ["open"]).
            assignees (list[str]): Filter by assigned analyst email.
            users (list[str]): Filter by user(s) who triggered the incident.
            include_ai_summaries (bool): Whether to include AI-generated summaries.

        Returns:
            dict: Raw API response containing "resources" (list of incidents) and "page_response".
        """
        filter_body: dict[str, Any] = assign_params(
            start_time=start_time,
            end_time=end_time,
            policy_severities=policy_severities,
            resolution_statuses=resolution_statuses,
            assignees=assignees,
            users=users,
            incident_ids=incident_ids,
        )

        page_request_body: dict[str, Any] = assign_params(size=page_size, id=page_id, sort_by=sort_by)

        body: dict[str, Any] = assign_params(
            page_request=page_request_body,
            filter=filter_body,
            include_ai_summaries=include_ai_summaries,
        )

        return self.http_request(
            method="POST",
            url_suffix=INCIDENTS_ENDPOINT,
            json_data=body,
            response_type="json",
        )

    def update_incident(
        self,
        incident_id: str,
        status: str | None = None,
        close_reason: str | None = None,
        close_note: str | None = None,
        assigned_to: str | None = None,
    ) -> dict[str, Any]:
        """Call PATCH /v2/incidents/{id}.

        Args:
            incident_id (str): The Cyberhaven incident ID to update.
            status (str | None): New status ("open" or "closed").
            close_reason (str | None): Reason for closing (e.g. "valid", "invalid_other").
            close_note (str | None): Free-text note added when closing.
            assigned_to (str | None): Email of the analyst to assign.

        Returns:
            dict: Raw API response.
        """
        patch_body = assign_params(
            status=status,
            close_reason=close_reason,
            close_note=close_note,
            assigned_to=assigned_to,
        )
        return self.http_request(
            method="PATCH",
            url_suffix=INCIDENT_PATCH_ENDPOINT.format(id=incident_id),
            json_data=patch_body,
            response_type="json",
        )

    def get_event_details(self, event_ids: list[str]) -> dict[str, Any]:
        """Call POST /v2/event-details to retrieve full event records.

        Args:
            event_ids (list[str]): One or more event UUIDs.

        Returns:
            dict: Raw API response.
        """
        return self.http_request(
            method="POST",
            url_suffix=EVENT_DETAILS_ENDPOINT,
            json_data={"ids": event_ids},
            response_type="json",
        )

    def get_event_lineage(self, start_event_id: str, end_event_id: str) -> dict[str, Any]:
        """Call POST /v2/event-lineage to retrieve the lineage chain between two events.

        Args:
            start_event_id (str): UUID of the first event in the chain.
            end_event_id (str): UUID of the last event in the chain.

        Returns:
            dict: Raw API response.
        """
        return self.http_request(
            method="POST",
            url_suffix=EVENT_LINEAGE_ENDPOINT,
            json_data={"start_event_id": start_event_id, "end_event_id": end_event_id},
            response_type="json",
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


def nullify_sentinels(d: Any) -> Any:
    """Recursively replace protobuf zero-value sentinel strings (ending with unspecified) with None."""
    if isinstance(d, str):
        return None if d.lower().endswith("unspecified") else d
    if isinstance(d, list):
        return [nullify_sentinels(v) for v in d]
    if isinstance(d, dict):
        return {k: nullify_sentinels(v) for k, v in d.items()}
    return d


def apply_api_labels(resource: dict) -> dict:
    """Replace raw API enum values with human-readable labels for display and context."""
    resource = dict(resource)
    if "created_by" in resource:
        resource["created_by"] = CREATED_BY_LABEL.get(resource.get("created_by", ""), resource.get("created_by", ""))
    if "warning_status" in resource:
        resource["warning_status"] = WARNING_STATUS_LABEL.get(
            resource.get("warning_status", ""), resource.get("warning_status", "")
        )
    if "close_reason" in resource:
        resource["close_reason"] = CLOSE_REASON_REVERSE_MAPPING.get(
            resource.get("close_reason", ""), resource.get("close_reason", "")
        )
    try:
        start_action = demisto.get(resource, "event_details.start_event.action")
        if "kind" in start_action:
            start_action["kind"] = ACTION_KIND_LABEL.get(start_action.get("kind", ""), start_action.get("kind", ""))
    except (KeyError, TypeError) as exc:
        demisto.debug(f"apply_api_labels: could not label start_event action kind, unexpected shape: {exc}")
    try:
        end_action = demisto.get(resource, "event_details.end_event.action")
        if "kind" in end_action:
            end_action["kind"] = ACTION_KIND_LABEL.get(end_action.get("kind", ""), end_action.get("kind", ""))
    except (KeyError, TypeError) as exc:
        demisto.debug(f"apply_api_labels: could not label end_event action kind, unexpected shape: {exc}")
    return resource


def get_mirroring() -> dict:
    """Return mirror direction and instance name from integration Info."""
    return {
        "mirror_direction": "Out",
        "mirror_instance": demisto.integrationInstance(),
    }


def convert_severity(severity: str) -> float:
    """Map a Cyberhaven policy severity string to an XSOAR severity float.

    Args:
        severity (str): Cyberhaven severity label (e.g. "high").

    Returns:
        float: XSOAR IncidentSeverity constant.
    """
    return SEVERITY_MAP.get(severity.lower(), IncidentSeverity.UNKNOWN)


def validate_cyberhaven_url(url: str) -> None:
    """Raise ValueError if *url* does not end with 'cyberhaven.io'."""
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    if not host.endswith("cyberhaven.io"):
        raise ValueError(ERROR_MESSAGES["INVALID_URL"].format(url))


def validate_incident_list_args(args: dict[str, Any]) -> dict[str, Any]:
    """Validate and parse arguments for cyberhaven-incident-list.

    Args:
        args (dict): Command arguments from demisto.args().

    Returns:
        dict: Parsed and validated parameters ready for the API call.

    Raises:
        ValueError: If limit is out of range, severity values are invalid, or status values are invalid.
    """
    limit: int = arg_to_number(args.get("limit", DEFAULT_PAGE_SIZE), arg_name="limit")  # type: ignore
    if limit < 1:
        raise ValueError(ERROR_MESSAGES["INVALID_MIN_VALUE"].format(limit, "limit", 1))

    start_time = ""
    end_time = ""
    if start_raw := args.get("start_time", ""):
        parsed = arg_to_datetime(start_raw)
        start_time = parsed.strftime(DATE_FORMAT) if parsed else ""
    if end_raw := args.get("end_time", ""):
        parsed = arg_to_datetime(end_raw)
        end_time = parsed.strftime(DATE_FORMAT) if parsed else ""

    severity_filter = argToList(args.get("severity", ""), transform=lambda s: s.strip().lower())
    status_filter = argToList(args.get("status", ""), transform=lambda s: s.strip().lower())

    invalid_severities = [s for s in severity_filter if s not in SEVERITY_FILTER_VALUES]
    if invalid_severities:
        raise ValueError(
            ERROR_MESSAGES["INVALID_LIST_ARGUMENT"].format(
                invalid_severities, "severity", f"[{', '.join(s.title() for s in SEVERITY_FILTER_VALUES)}]"
            )
        )

    invalid_statuses = [s for s in status_filter if s not in STATUS_FILTER_VALUES]
    if invalid_statuses:
        raise ValueError(
            ERROR_MESSAGES["INVALID_LIST_ARGUMENT"].format(
                invalid_statuses, "status", f"[{', '.join(s.title() for s in STATUS_FILTER_VALUES)}]"
            )
        )

    return {
        "limit": limit,
        "start_time": start_time,
        "end_time": end_time,
        "severity_filter": severity_filter,
        "status_filter": status_filter,
        "assignees": argToList(args.get("assignee", ""), transform=lambda s: s.strip()),
        "users": argToList(args.get("user", ""), transform=lambda s: s.strip()),
        "incident_ids": argToList(args.get("incident_ids", ""), transform=lambda s: s.strip()),
        "page_id": args.get("page_id", ""),
    }


def validate_incident_update_args(args: dict[str, Any]) -> dict[str, Any]:
    """Validate and parse arguments for cyberhaven-incident-update.

    Args:
        args (dict): Command arguments from demisto.args().

    Returns:
        dict: Parsed and validated parameters ready for the API call.

    Raises:
        ValueError: If incident_id is missing, status or close_reason are invalid,
            or none of the updatable fields are provided.
    """
    incident_id = args.get("incident_id", "")
    if not incident_id:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("incident_id"))

    status = args.get("status", "").lower()
    close_reason = args.get("close_reason", "").lower()
    close_note = args.get("close_note", "")
    assigned_to = args.get("assigned_to", "")
    valid_close_reason_values = [k.lower() for k in CLOSE_REASON_VALUES]

    if status and status not in STATUS_FILTER_VALUES:
        raise ValueError(
            ERROR_MESSAGES["INVALID_ARGUMENT"].format(status, "status", f"[{', '.join(s.title() for s in STATUS_FILTER_VALUES)}]")
        )

    if close_reason and close_reason not in valid_close_reason_values:
        raise ValueError(
            ERROR_MESSAGES["INVALID_ARGUMENT"].format(close_reason, "close_reason", f"[{', '.join(CLOSE_REASON_VALUES)}]")
        )

    if not status and not close_reason and not close_note and not assigned_to:
        raise ValueError(ERROR_MESSAGES["AT_LEAST_ONE_REQUIRED"].format("status, close_reason, close_note, assigned_to"))

    return {
        "incident_id": incident_id,
        "status": status,
        "close_reason": close_reason,
        "close_note": close_note,
        "assigned_to": assigned_to,
    }


def validate_fetch_filters(params: dict[str, Any], is_test: bool = False) -> tuple[datetime, list[str], list[str]]:
    """
    Validate first_fetch, severity and status filter params.
    Returns (first_fetch_dt, valid_severity_filter, valid_status_filter).
    Raises ValueError on invalid values when is_test=True.
    """
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    first_fetch_dt: datetime = arg_to_datetime(params.get("first_fetch", DEFAULT_FIRST_FETCH))  # type: ignore
    if first_fetch_dt and first_fetch_dt.tzinfo is not None:  # type: ignore
        first_fetch_dt = first_fetch_dt.replace(tzinfo=None)
    if first_fetch_dt < thirty_days_ago:  # type: ignore
        if is_test:
            raise ValueError(ERROR_MESSAGES["FIRST_FETCH_TOO_OLD"])
        demisto.debug("first_fetch is older than 30 days; capping to 30 days ago.")
        first_fetch_dt = thirty_days_ago

    severity_filter: list[str] = [s.lower() for s in argToList(params.get("severity_filter", ""))]
    status_filter: list[str] = [s.lower() for s in argToList(params.get("status_filter", ""))]

    valid_severity_filter = [s for s in severity_filter if s in SEVERITY_FILTER_VALUES]
    invalid_severity_filter = [s for s in severity_filter if s not in SEVERITY_FILTER_VALUES]

    valid_status_filter = [s for s in status_filter if s in STATUS_FILTER_VALUES]
    invalid_status_filter = [s for s in status_filter if s not in STATUS_FILTER_VALUES]

    if is_test:
        error_list = []
        if invalid_severity_filter:
            error_list.append(
                ERROR_MESSAGES["INVALID_LIST_ARGUMENT"].format(
                    invalid_severity_filter,
                    "Severity of incidents to fetch",
                    f"[{', '.join(s.title() for s in SEVERITY_FILTER_VALUES)}]",
                )
            )
        if invalid_status_filter:
            error_list.append(
                ERROR_MESSAGES["INVALID_LIST_ARGUMENT"].format(
                    invalid_status_filter,
                    "Status of incidents to fetch",
                    f"[{', '.join(s.title() for s in STATUS_FILTER_VALUES)}]",
                )
            )
        if error_list:
            raise ValueError("\n\n".join(error_list))

    return first_fetch_dt, valid_severity_filter, valid_status_filter


def build_incident_readable(resources: list[dict], base_url: str, title: str) -> str:
    """Build a War Room markdown table for a list of incident resources.

    Args:
        resources (list[dict]): Incident resource dicts from the API response.
        base_url (str): Integration base URL used to construct platform deep-links.
        title (str): Table heading displayed above the markdown table.

    Returns:
        str: Markdown-formatted table string.
    """
    table_data = [
        {
            "ID": f"[{r.get('id')}]({urljoin(base_url, INCIDENT_PLATFORM_LINK.format(id=r.get('id')))})",
            "Policy": demisto.get(r, "policy.name"),
            "Severity": demisto.get(r, "policy.severity"),
            "User": demisto.get(r, "user.email"),
            "Status": r.get("status", ""),
            "Blocked": r.get("blocked", ""),
            "Event Time": r.get("event_time", ""),
            "Start Event ID": demisto.get(r, "event_lineage_id.start_event_id"),
            "End Event ID": demisto.get(r, "event_lineage_id.end_event_id"),
            "AI Summary": r.get("ai_summary", ""),
        }
        for r in resources
    ]
    return tableToMarkdown(
        title,
        table_data,
        headers=[
            "ID",
            "Policy",
            "Severity",
            "User",
            "Status",
            "Blocked",
            "Event Time",
            "Start Event ID",
            "End Event ID",
            "AI Summary",
        ],
        removeNull=True,
    )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validate connectivity and credentials by fetching a single incident.

    Args:
        client (Client): Initialised Cyberhaven client.

    Returns:
        str: "ok" if the test passes; a descriptive error message otherwise.
    """
    params = demisto.params()
    is_fetch = params.get("isFetch", False)
    try:
        if is_fetch:
            fetch_incidents(client, {}, params, is_test=True)
        else:
            client.list_incidents(page_size=1)
    except DemistoException as exc:
        msg = str(exc)
        if "401" in msg or "403" in msg:
            return "Authorization Error: verify that the refresh token is correct and has not expired."
        raise
    return "ok"


def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    params: dict[str, Any],
    is_test: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch new Cyberhaven incidents and convert them to XSOAR incidents.

    Uses cursor-based pagination so no incident is missed or duplicated even if
    multiple pages arrive within the same fetch window.

    Args:
        client (Client): Initialised Cyberhaven client.
        last_run (dict): State dict persisted from the previous run.
            Expected keys: "last_fetch" (ISO timestamp), "last_ids" (list of str).
        params (dict): Integration configuration parameters from demisto.params().
        is_test (bool): When True, performs a single API call without creating incidents.

    Returns:
        tuple[list, dict]: (list of XSOAR incident dicts, next_run state dict)
    """
    first_fetch_dt, valid_severity_filter, valid_status_filter = validate_fetch_filters(params, is_test)
    first_fetch_time: str = first_fetch_dt.strftime(DATE_FORMAT)  # type: ignore

    max_fetch_raw: int = arg_to_number(params.get("max_fetch", str(DEFAULT_MAX_FETCH)), "Max Fetch")  # type: ignore
    if max_fetch_raw < 1:
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"].format(max_fetch_raw, MAX_INCIDENTS_TO_FETCH))

    max_fetch = min(int(max_fetch_raw), MAX_INCIDENTS_TO_FETCH)
    if max_fetch_raw > MAX_INCIDENTS_TO_FETCH:
        demisto.debug(
            f"max_fetch value {max_fetch_raw} exceeds the maximum allowed value {MAX_INCIDENTS_TO_FETCH}. "
            f"Setting max_fetch to {MAX_INCIDENTS_TO_FETCH}."
        )

    filter_string = json.dumps(
        {"severity": sorted(valid_severity_filter), "status": sorted(valid_status_filter)},
        sort_keys=True,
    )
    stored_filter = last_run.get("filter_string", "")

    already_fetch_ids: list[str] = last_run.get("already_fetch_ids") or []
    if stored_filter and filter_string == stored_filter:
        fetch_time: str = last_run.get("next_fetch_time") or first_fetch_time
        page_id: str = last_run.get("next_page_id") or ""
    else:
        demisto.debug(
            f"Cyberhaven fetch-incidents: filter changed (was={stored_filter!r}, now={filter_string!r}), "
            f"resetting fetch time to {last_run.get('first_fetch_time') or first_fetch_time}."
        )
        fetch_time = last_run.get("first_fetch_time") or first_fetch_time
        page_id = ""

    demisto.debug(f"Cyberhaven fetch-incidents: {fetch_time=}, fetching up to {max_fetch} incidents.")

    incidents: list[dict[str, Any]] = []

    response = client.list_incidents(
        page_id=page_id,
        page_size=max_fetch,
        start_time=fetch_time,
        resolution_statuses=valid_status_filter,
        policy_severities=valid_severity_filter,
        include_ai_summaries=True,
    )

    response = nullify_sentinels(response)
    response = remove_empty_elements_for_fetch(response)

    resources: list[dict] = response.get("resources") or []
    demisto.debug(f"Cyberhaven fetch-incidents: received {len(resources)} incidents from API.")

    for raw in resources:
        inc_id = raw.get("id", "")

        if inc_id in already_fetch_ids:
            demisto.debug(f"Cyberhaven fetch-incidents: skipping duplicate incident {inc_id}.")
            continue

        if argToBoolean(params.get("outgoing_mirroring", False)):
            mirror_params = get_mirroring()
            mirror_params["mirror_id"] = inc_id
            raw.update(mirror_params)

        raw["incident_link"] = urljoin(client._base_url, INCIDENT_PLATFORM_LINK.format(id=inc_id))
        start_event: dict[str, str] = demisto.get(raw, "event_details.start_event") or {}
        raw["start_event_json_beautify"] = json.dumps(start_event, indent=8)
        end_event: dict[str, str] = demisto.get(raw, "event_details.end_event") or {}
        raw["end_event_json_beautify"] = json.dumps(end_event, indent=8)

        if start_event and end_event:
            start_event_id: str = start_event.get("id") or ""
            start_event_time: str = start_event.get("timestamp") or ""
            end_event_id: str = end_event.get("id") or ""
            end_event_time: str = end_event.get("timestamp") or ""
            if start_event_id and start_event_time and end_event_id and end_event_time:
                reference: dict[str, Any] = {
                    "selectedCategories": ["all_categories"],
                    "time-filter": {"start_time": start_event_time, "end_time": end_event_time},
                    "global-filter": f"(e.source.raw_id == '{start_event_id}' && e.destination.raw_id == '{end_event_id}')",
                }
                reference_str = base64.b64encode(json.dumps(reference, separators=(",", ":")).encode()).decode()
                raw["event_lineage_link"] = urljoin(client._base_url, EVENT_LINEAGE_LINK.format(reference=reference_str))

        user_email = demisto.get(raw, "user.id") or demisto.get(raw, "user.local_id") or ""
        severity_label = demisto.get(raw, "policy.severity") or "unspecified"
        name = f"Cyberhaven: {demisto.get(raw, 'policy.name') or 'DLP Incident'}"
        if user_email:
            name += f" - {user_email}"
        occurred = raw.get("trigger_time") or ""

        incidents.append(
            {
                "name": name,
                "occurred": occurred,
                "details": raw.get("ai_summary", ""),
                "rawJSON": json.dumps(raw),
                "severity": convert_severity(severity_label),
                "closeReason": CLOSE_REASON_REVERSE_MAPPING.get(raw.get("close_reason", ""), raw.get("close_reason", ""))
                if raw.get("status", "").lower() == "closed"
                else "",
                "closeNotes": raw.get("close_note", "") if raw.get("status", "").lower() == "closed" else "",
            }
        )
        already_fetch_ids.append(inc_id)

    page_response = response.get("page_response") or {}
    next_page_id = page_response.get("next_id", "")

    if incidents:
        last_raw = json.loads(incidents[-1]["rawJSON"])
        new_last_fetch = last_raw.get("trigger_time") or fetch_time
    else:
        new_last_fetch = fetch_time

    next_run: dict[str, Any] = assign_params(
        next_fetch_time=new_last_fetch,
        already_fetch_ids=already_fetch_ids,
        next_page_id=next_page_id,
        filter_string=filter_string,
        first_fetch_time=first_fetch_time,
    )
    demisto.debug(f"Cyberhaven fetch-incidents: next_run={next_run}, returning {len(incidents)} incident(s).")

    if is_test:
        return [], {}

    return incidents, next_run


def cyberhaven_incident_list_command(client: Client, args: dict[str, Any]) -> list[CommandResults] | CommandResults:
    """cyberhaven-incident-list: Search and list Cyberhaven DLP incidents.

    Args:
        client (Client): Initialised Cyberhaven client.
        args (dict): Command arguments from demisto.args():
            - limit (int): Maximum number of incidents to return (default 25, max 200).
            - start_time (str): Filter incidents at or after this time (e.g. "3 days ago").
            - end_time (str): Filter incidents before this time.
            - severity (str): Comma-separated severity levels (informational, low, medium, high, critical).
            - status (str): Comma-separated statuses ("open", "closed").
            - assignee (str): Filter by assigned analyst email.
            - user (str): Filter by user email/alias who triggered the incident.
            - incident_ids (str): Comma-separated list of incident IDs to filter by.

    Returns:
        CommandResults: Formatted results with human-readable table and context data.
    """
    params = validate_incident_list_args(args)

    response = client.list_incidents(
        page_size=params.get("limit", ""),
        page_id=params.get("page_id", ""),
        start_time=params.get("start_time", ""),
        end_time=params.get("end_time", ""),
        incident_ids=params.get("incident_ids", ""),
        policy_severities=params.get("severity_filter", ""),
        resolution_statuses=params.get("status_filter", ""),
        assignees=params.get("assignees", ""),
        users=params.get("users", ""),
        sort_by=DEFAULT_SORT_ORDER,
        include_ai_summaries=True,
    )

    resources: list[dict] = response.get("resources") or []
    resources = nullify_sentinels(resources)
    resources = remove_empty_elements_for_fetch(resources)
    resources = [apply_api_labels(r) for r in resources]

    page_response = response.get("page_response") or {}

    if not resources:
        return CommandResults(readable_output="No incidents found matching the given filters.")

    readable = build_incident_readable(resources, client._base_url, "Cyberhaven Incidents")

    next_page_readable = tableToMarkdown(
        "Page Details",
        [{"Next Page ID": page_response.get("next_id", ""), "Total": page_response.get("total", "")}],
        headers=["Next Page ID", "Total"],
        removeNull=True,
    )

    return [
        CommandResults(
            readable_output=readable,
            outputs_prefix="Cyberhaven.Incident",
            outputs_key_field="id",
            outputs=resources,
            raw_response=response,
        ),
        CommandResults(
            readable_output=next_page_readable,
            outputs_prefix="Cyberhaven.IncidentPage",
            outputs_key_field="next_id",
            outputs=page_response,
            raw_response=response,
        ),
    ]


def cyberhaven_incident_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """cyberhaven-incident-update: Update the status, assignment, or closure of an incident.

    Args:
        client (Client): Initialised Cyberhaven client.
        args (dict): Command arguments from demisto.args():
            - incident_id (str, required): The Cyberhaven incident ID.
            - status (str): New status: "open" or "closed".
            - close_reason (str): Reason code when closing (e.g. "valid", "invalid_other").
            - close_note (str): Free-text closure note.
            - assigned_to (str): Analyst email to assign the incident to.

    Returns:
        CommandResults: Confirmation message and updated incident data in context.
    """
    params = validate_incident_update_args(args)
    lower_close_reason_mapping = {k.lower(): v for k, v in CLOSE_REASON_MAPPING.items()}

    response = client.update_incident(
        incident_id=params.get("incident_id", ""),
        status=params.get("status", ""),
        close_reason=lower_close_reason_mapping.get(params.get("close_reason", "")),
        close_note=params.get("close_note", ""),
        assigned_to=params.get("assigned_to", ""),
    )

    resources: list[dict] = response.get("resources") or []
    resources = nullify_sentinels(resources)
    resources = remove_empty_elements_for_fetch(resources)
    resources = [apply_api_labels(r) for r in resources]

    readable = build_incident_readable(
        resources, client._base_url, f"Incident **{params.get('incident_id')}** updated successfully."
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cyberhaven.Incident",
        outputs_key_field="id",
        outputs=resources,
        raw_response=response,
    )


def cyberhaven_event_details_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """cyberhaven-event-details-get: Retrieve full details for one or more Cyberhaven events.

    Args:
        client (Client): Initialised Cyberhaven client.
        args (dict): Command arguments from demisto.args():
            - event_ids (str, required): Comma-separated list of event UUIDs.

    Returns:
        CommandResults: Event details in the War Room and in context.
    """
    event_ids = argToList(args.get("event_ids"), transform=lambda s: s.strip())
    if not event_ids:
        raise ValueError(ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("event_ids"))

    response = client.get_event_details(event_ids)
    resources: list[dict] = response.get("resources") or []
    resources = nullify_sentinels(resources)
    resources = remove_empty_elements_for_fetch(resources)

    table_data = [
        {
            "ID": e.get("id"),
            "Time": e.get("timestamp"),
            "User": e.get("user"),
            "Action": e.get("action"),
            "Source": e.get("source"),
            "Destination": e.get("destination"),
        }
        for e in resources
    ]

    readable = tableToMarkdown(
        "Cyberhaven Event Details",
        table_data,
        headers=["ID", "Time", "User", "Action", "Source", "Destination"],
        removeNull=True,
        json_transform_mapping={
            "User": JsonTransformer(),
            "Action": JsonTransformer(),
            "Source": JsonTransformer(),
            "Destination": JsonTransformer(),
        },
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cyberhaven.Event",
        outputs_key_field="id",
        outputs=resources,
        raw_response=response,
    )


def cyberhaven_event_lineage_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """cyberhaven-event-lineage-get: Retrieve the data lineage chain between two events.

    The lineage shows every transformation a piece of data underwent from the
    first event (e.g. a file creation) to the last event (e.g. an upload).

    Args:
        client (Client): Initialised Cyberhaven client.
        args (dict): Command arguments from demisto.args():
            - start_event_id (str, required): UUID of the first event in the chain.
            - end_event_id (str, required): UUID of the last event in the chain.

    Returns:
        CommandResults: Lineage chain in the War Room and in context.
    """
    start_event_id = args.get("start_event_id")
    end_event_id = args.get("end_event_id")
    if not start_event_id or not end_event_id:
        raise ValueError(ERROR_MESSAGES["REQUIRED_BOTH_ARGUMENTS"].format("start_event_id", "end_event_id"))

    response = client.get_event_lineage(start_event_id, end_event_id)
    events: list[dict] = response.get("resources") or []
    context = nullify_sentinels(response)
    context = remove_empty_elements_for_fetch(context)

    table_data = [
        {
            "Number": i + 1,
            "ID": e,
        }
        for i, e in enumerate(events)
    ]
    readable = tableToMarkdown(
        f"Event Lineage: {start_event_id} to {end_event_id}",
        table_data,
        headers=["Number", "ID"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cyberhaven.EventLineage",
        outputs_key_field="resources",
        outputs=context,
        raw_response=response,
    )


def update_remote_system_command(client: Client, args: dict) -> str:
    """Outgoing mirror: push XSOAR analyst changes back to Cyberhaven via PATCH.

    Only the close (DONE) transition is mirrored to Cyberhaven; reopening an
    incident in XSOAR (ACTIVE) is not pushed back. Watches three XSOAR-owned
    delta fields per SYNC-01: owner, closeReason, closeNotes (only changed
    fields are sent, per SYNC-03/SYNC-05). The status transition itself is
    read directly from the incident's current status, not from the delta.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    remote_incident_id = parsed_args.remote_incident_id
    incident_status = parsed_args.inc_status

    if not remote_incident_id:
        demisto.debug("Cyberhaven update_remote_system: no remote incident ID, skipping")
        return remote_incident_id or ""

    incident_changed = argToBoolean(parsed_args.incident_changed) if parsed_args.incident_changed is not None else False
    if not incident_changed:
        demisto.debug(f"Cyberhaven update_remote_system: no changes for {remote_incident_id}, skipping")
        return remote_incident_id

    raw_delta = parsed_args.delta or {}
    if isinstance(raw_delta, str):
        try:
            delta: dict = json.loads(raw_delta) if raw_delta else {}
        except (ValueError, json.JSONDecodeError):
            delta = {}
    else:
        delta = raw_delta

    watched = {"owner", "closeReason", "closeNotes"}
    changed = {k: v for k, v in delta.items() if k in watched}

    demisto.debug(f"Cyberhaven update_remote_system: {remote_incident_id} - changed fields: {list(changed.keys())}")

    patch_fields: list[str] = []
    patch_status: str | None = None
    patch_close_reason: str | None = None
    patch_close_note: str | None = None
    patch_assigned_to: str | None = None

    if incident_status and incident_status == IncidentStatus.DONE:
        patch_status = XSOAR_STATUS_TO_CH.get(incident_status, "")

        try:
            response = client.list_incidents(incident_ids=[remote_incident_id])
        except DemistoException as exc:
            demisto.error(f"Cyberhaven update_remote_system: failed to look up incident {remote_incident_id} in CH, error={exc}")
            return remote_incident_id

        resources: list[dict] = response.get("resources") or []

        if not resources:
            demisto.debug(f"Cyberhaven update_remote_system: incident {remote_incident_id} not found in CH (404), discarding")
            return remote_incident_id
        external_status = resources[0].get("status") or ""

        if external_status != patch_status:
            patch_fields.append("status")

            if "closeReason" in changed:
                xsoar_reason = (changed.get("closeReason") or "").strip()
                ch_reason = CLOSE_REASON_MAPPING.get(xsoar_reason)

                if ch_reason:
                    patch_close_reason = ch_reason
                    patch_fields.append("close_reason")
                else:
                    demisto.debug(f"Cyberhaven update_remote_system: closeReason '{xsoar_reason}' has no CH mapping, omitting")

            if "closeNotes" in changed:
                patch_close_note = changed.get("closeNotes") or ""
                patch_fields.append("close_note")

        else:
            demisto.debug(
                f"Cyberhaven update_remote_system: incident {remote_incident_id} is already closed, "
                "so not updating for close workflow"
            )

    if "owner" in changed:
        owner_val = (changed.get("owner") or "").strip()

        if owner_val:
            patch_assigned_to = owner_val
            patch_fields.append("assigned_to")
        else:
            demisto.debug("Cyberhaven update_remote_system: owner is blank, omitting assigned_to from PATCH")

    if not patch_fields:
        demisto.debug(f"Cyberhaven update_remote_system: no mappable fields for {remote_incident_id}, skipping PATCH")
        return remote_incident_id

    demisto.debug(f"Cyberhaven update_remote_system: Patching {remote_incident_id} with fields={patch_fields}")

    try:
        client.update_incident(
            incident_id=remote_incident_id,
            status=patch_status,
            close_reason=patch_close_reason,
            close_note=patch_close_note,
            assigned_to=patch_assigned_to,
        )
        demisto.debug(f"Cyberhaven update_remote_system: PATCH succeeded for {remote_incident_id}")
    except DemistoException as exc:
        err_msg = str(exc)
        if "404" in err_msg:
            demisto.debug(f"Cyberhaven update_remote_system: incident {remote_incident_id} not found in CH (404), discarding")
        else:
            demisto.error(
                f"Cyberhaven update_remote_system: PATCH failed for incident={remote_incident_id}, "
                f"fields={patch_fields}, error={err_msg}"
            )
            return_warning(
                f"Cyberhaven reverse sync failed for incident `{remote_incident_id}`. "
                f"Fields attempted: {patch_fields}. Error: {err_msg}"
            )

    return remote_incident_id


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Parse params, initialise the Client, and dispatch to the correct command function."""

    params = demisto.params()
    params = trim_spaces_from_args(params)
    remove_nulls_from_dictionary(params)

    refresh_token: str = params.get("credentials", {}).get("password") or ""
    refresh_token = refresh_token.strip()
    base_url: str = params.get("url", "")
    verify_certificate: bool = not argToBoolean(params.get("insecure", False))
    proxy: bool = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Cyberhaven: command={command}")

    commands: dict[str, Callable] = {
        "cyberhaven-incident-list": cyberhaven_incident_list_command,
        "cyberhaven-incident-update": cyberhaven_incident_update_command,
        "cyberhaven-event-details-get": cyberhaven_event_details_get_command,
        "cyberhaven-event-lineage-get": cyberhaven_event_lineage_get_command,
    }

    try:
        if not refresh_token:
            raise DemistoException(ERROR_MESSAGES["REFRESH_TOKEN_REQUIRED"])

        validate_cyberhaven_url(base_url)

        result = None
        client = Client(
            base_url=base_url,
            refresh_token=refresh_token,
            verify=verify_certificate,
            proxy=proxy,
        )

        args = demisto.args()
        args = trim_spaces_from_args(args)
        remove_nulls_from_dictionary(args)

        if command == "test-module":
            result = test_module(client)
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif command == "update-remote-system":
            result = update_remote_system_command(client, args)
        elif command in commands:
            result = commands[command](client, args)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

        return_results(result)

    except Exception as exc:
        return_error(f"Failed to execute '{command}'.\nError: {str(exc)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
