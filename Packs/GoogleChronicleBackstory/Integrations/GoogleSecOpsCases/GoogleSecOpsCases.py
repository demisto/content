"""Main file for GoogleSecOpsCases Integration."""

import calendar
import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import demistomock as demisto
from CommonServerPython import *
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
HR_DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
STATUS_LIST_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201, 204)
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
DEFAULT_PAGE_SIZE = 50
DEFAULT_CASE_LIST_SORT_ORDER = "Desc"
DEFAULT_CASE_LIST_SORT_BY = "createTime"
DEFAULT_COMMENT_SORT_ORDER = "Desc"
DEFAULT_COMMENT_SORT_BY = "createTime"
DEFAULT_ALERT_ENTITY_SORT_BY = "id"
DEFAULT_ALERT_ENTITY_SORT_ORDER = "Desc"
MAX_PAGE_SIZE = 1000

SECOPS_V1_ALPHA_URL = "https://chronicle.{}.rep.googleapis.com/v1alpha"
OLDER_SECOPS_V1_ALPHA_URL = "https://{}-chronicle.googleapis.com/v1alpha"
DEFAULT_REGION = "us"
DEFAULT_FIRST_FETCH = "3 days"
MAX_FIRST_FETCH_DAYS = 7
MAX_FIRST_FETCH_BOUNDARY_STRINGS = ["7 day", "168 hour", "1 week"]
DEFAULT_MAX_FETCH = 50
MAX_FETCH_LIMIT = 200
CASES_EXPAND_FIELDS = "products,tasks,tags,closureDetails,sla,alertsSla"
CASE_ALERT_EXPAND_FIELDS = "sla,involvedRelations,tags,closureDetails"
CASE_SEVERITY_MAP = {
    "PRIORITY_CRITICAL": 4,
    "PRIORITY_HIGH": 3,
    "PRIORITY_MEDIUM": 2,
    "PRIORITY_LOW": 1,
    "PRIORITY_INFO": 0.5,
    "PRIORITY_UNSPECIFIED": 0,
}
DEFAULT_FILTER_LOGIC = "AND"
VALID_CASE_FILTER_LOGIC = (DEFAULT_FILTER_LOGIC, "OR")
VALID_CASE_PRIORITIES = ("UNSPECIFIED", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
VALID_CASE_STATUSES = ("CASE_DATA_STATE_UNSPECIFIED", "OPENED", "CLOSED", "MERGED", "CREATION_PENDING")
VALID_CASE_WORKFLOW_STATUSES = (
    "WORKFLOW_STATUS_UNSPECIFIED",
    "NONE",
    "IN_PROGRESS",
    "COMPLETED",
    "FAILED",
    "TERMINATED",
    "PENDING_IN_QUEUE",
    "PENDING_FOR_USER",
)
VALID_CASE_SLA_STATUSES = ("SLA_EXPIRATION_STATUS_UNSPECIFIED", "OPEN_SLA", "PASSED_DUE", "NO_SLA", "CRITICAL_EXPIRED", "PAUSED")
VALID_CASE_CLOSE_REASONS = ("MALICIOUS", "NOT_MALICIOUS", "MAINTENANCE", "INCONCLUSIVE", "UNKNOWN", "CLOSE_REASON_UNSPECIFIED")
VALID_CASE_TYPES = ("EXTERNAL", "TEST", "REQUEST", "CASE_TYPE_UNSPECIFIED")
VALID_SORT_ORDERS = ("Asc", "Desc")
CASE_UPDATE_ARGS = ("display_name", "description", "important", "incident")
VALID_CASE_ALERT_PRIORITIES = (
    "LEGACY_CASE_PRIORITY_UNSPECIFIED",
    "UNCHANGED",
    "INFORMATIVE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)
VALID_CASE_ALERT_STATUSES = ("OPEN", "CLOSE", "ALERT_STATUS_UNSPECIFIED")
DEFAULT_CASE_ALERT_LIST_SORT_BY = "createTime"
DEFAULT_CASE_ALERT_LIST_SORT_ORDER = "Desc"
CASE_ALERT_UPDATE_ARGS = ("status", "priority")
CASE_ALERT_ENTITY_UPDATE_ARGS = (
    "suspicious",
    "internal",
    "attacker",
    "pivot",
    "operating_system",
    "network_title",
    "threat_source",
    "network_priority",
)
VALID_CASE_ALERT_CLOSE_REASONS = (
    "MALICIOUS",
    "NOT_MALICIOUS",
    "MAINTENANCE",
    "INCONCLUSIVE",
    "UNKNOWN",
    "CLOSE_REASON_UNSPECIFIED",
)
DEFAULT_EXECUTION_SCOPE = "ALERT"
VALID_EXECUTION_SCOPES = (DEFAULT_EXECUTION_SCOPE, "CASE", "EXECUTION_SCOPE_UNSPECIFIED")
CASE_ID_DISPLAY = "Case ID"
ALERT_ID_DISPLAY = "Alert ID"
ENTITY_ID_DISPLAY = "Entity ID"

ENDPOINTS = {
    "CASES": "/cases",
    "CASE": "/cases/{case_id}",
    "CASES_BULK_ADD_TAG": "/cases:executeBulkAddTag",
    "CASES_REMOVE_TAG": "/cases/{case_id}:removeTag",
    "CASES_BULK_CHANGE_PRIORITY": "/cases:executeBulkChangePriority",
    "CASE_STAGE_DEFINITIONS": "/caseStageDefinitions",
    "CASES_BULK_CHANGE_STAGE": "/cases:executeBulkChangeStage",
    "CASES_BULK_REOPEN": "/cases:executeBulkReopen",
    "CASE_CLOSE_DEFINITIONS": "/caseCloseDefinitions",
    "CASES_BULK_CLOSE": "/cases:executeBulkClose",
    "CASES_BULK_ASSIGN": "/cases:executeBulkAssign",
    "LEGACY_SOAR_USERS": "/legacySoarUsers",
    "CASE_COMMENTS": "/cases/{case_id}/caseComments",
    "CASE_SLA_PAUSE": "/cases/{case_id}:pauseSla",
    "CASE_SLA_RESUME": "/cases/{case_id}:resumeSla",
    "CASE_ALERTS": "/cases/{case_id}/caseAlerts",
    "CASE_ALERT": "/cases/{case_id}/caseAlerts/{alert_id}",
    "CASE_ALERT_ADD_TAG": "/cases/{case_id}/caseAlerts/{alert_id}:addTag",
    "CASE_ALERT_REMOVE_TAG": "/cases/{case_id}/caseAlerts/{alert_id}:removeTag",
    "CASE_ALERT_MOVE": "/cases/{case_id}/caseAlerts/{alert_id}:move",
    "CASE_ALERT_SLA_PAUSE": "/cases/{case_id}/caseAlerts/{alert_id}:pauseSla",
    "CASE_ALERT_SLA_RESUME": "/cases/{case_id}/caseAlerts/{alert_id}:resumeSla",
    "CASE_ALERT_SLA_SET": "/cases/{case_id}/caseAlerts/{alert_id}:setSla",
    "CASE_ALERT_RECOMMENDATION_CREATE": "/cases/{case_id}/caseAlerts/{alert_id}:createRecommendationLongRunning",
    "CASE_ALERT_FETCH_RECOMMENDATION": "/cases/{case_id}/caseAlerts:fetchRecommendation",
    "CASE_ALERT_CUSTOMFIELD_VALUES": "/cases/{case_id}/caseAlerts/{alert_id}/customFieldValues",
    "CUSTOM_FIELDS": "/customFields",
    "CASE_ALERT_INVOLVED_ENTITIES": "/cases/{case_id}/caseAlerts/{alert_id}/involvedEntities",
    "CASE_ALERT_INVOLVED_ENTITY": "/cases/{case_id}/caseAlerts/{alert_id}/involvedEntities/{entity_id}",
    "CASE_ALERT_INVOLVED_ENTITY_ADD_PROPERTY": "/cases/{case_id}/caseAlerts/{alert_id}/involvedEntities/{entity_id}:addProperty",
    "CASE_ALERT_INVOLVED_ENTITY_UPDATE_PROPERTY": (
        "/cases/{case_id}/caseAlerts/{alert_id}/involvedEntities/{entity_id}:updateProperty"
    ),
    "LEGACY_PLAYBOOKS": "/legacyPlaybooks:legacyGetEnabledWFCards",
    "LEGACY_PLAYBOOK_ATTACH": "/legacyPlaybooks:legacyAttachNestedWorkflowToCase",
}

SECOPS_OUTPUT_PATHS = {
    "Case": "GoogleSecOps.Case",
    "CaseStageDefinition": "GoogleSecOps.CaseStageDefinition",
    "CaseCloseDefinition": "GoogleSecOps.CaseCloseDefinition",
    "CaseComment": "GoogleSecOps.CaseComment",
    "PageToken": "GoogleSecOps.PageToken",
    "CaseAlert": "GoogleSecOps.CaseAlert",
    "AlertRecommendation": "GoogleSecOps.AlertRecommendation",
    "AlertCustomFieldValue": "GoogleSecOps.AlertCustomFieldValue",
    "AlertEntity": "GoogleSecOps.AlertEntity",
    "Playbook": "GoogleSecOps.Playbook",
    "PlaybookAttach": "GoogleSecOps.PlaybookAttach",
}

MESSAGES = {
    "INTERNAL_SERVER_ERROR": (
        "Status code: {}\nError: Internal server error occurred. Failed to execute request with {} retries.\nMessage: {}"
    ),
    "RATE_LIMIT_EXCEEDED": (
        "Status code: {}\nError: API rate limit exceeded. Failed to execute request with {} retries.\nMessage: {}"
    ),
    "HTTP_ERROR": "Status code: {}\nError: {}",
    "EMPTY_RESPONSE": "Technical Error while making API call to Google SecOps. Empty response received with the status code: {}",
    "INVALID_JSON_RESPONSE": "Invalid response format while making API call to Google SecOps. Response not in JSON format",
    "TIME_IN_PAST": "Invalid value for '{arg_name}': '{time_str}' is in the past. Specify a future date or a positive duration.",
    "INVALID_PROJECT_NUMBER": "Google SecOps Project Number should be a positive number.",
    "MISSING_PROJECT_INSTANCE_ID": "Please Provide the Google SecOps Project Instance ID.",
    "MISSING_REGION": "Please Provide the valid region.",
    "INVALID_SERVICE_ACCOUNT_JSON": "User's Service Account JSON has invalid format",
    "REQUIRED_ARGUMENT": "Missing argument {}.",
    "INVALID_POSITIVE_INTEGER": "Invalid {}: {}. {} must be a positive integer.",
    "VALIDATE_SINGLE_SELECT": "{} can have one of these values only {}.",
    "INVALID_MAX_FETCH": "Incidents fetch limit should be in the range from 1 to {max_limit}. Got: {value}.",
    "INVALID_FIRST_FETCH": (
        "Invalid value for 'First Fetch Time': {}. "
        "The value cannot be older than 7 days or 168 hours (in relative manner compared to current time)."
    ),
    "FUTURE_DATE": "First fetch time should not be in the future.",
    "PERMISSION_DENIED": "Permission denied",
    "NO_RECORDS_FOUND": "No {} found.",
    "USER_NOT_FOUND": "No active user found with the provided email: {}.",
    "INVALID_INT_RANGE": "Invalid value '{}' for argument '{}'. Expected a value between {} and {}.",
    "INVALID_DATE_RANGE": "{} must be less than or equal to {}.",
    "AT_LEAST_ONE_REQUIRED": "At least one of the following arguments must be provided: {}.",
    "INVALID_NON_NEGATIVE_INTEGER": "Invalid value '{}' for argument '{}'. Value must be a non-negative integer.",
}

""" CLIENT CLASS """


class Client:
    """
    Client to use in integration to fetch data from Google SecOps.

    requires service_account_credentials : a json formatted string act as a token access
    """

    def __init__(self, params: dict[str, Any], proxy, disable_ssl):
        """
        Initialize HTTP Client.

        :param params: parameter returned from demisto.params()
        :param proxy: whether to use environment proxy
        :param disable_ssl: whether to disable ssl
        """
        encoded_service_account = str(params.get("credentials", {}).get("password", ""))
        service_account_credential = json.loads(encoded_service_account, strict=False)

        self.project_id = service_account_credential.get("project_id", "")
        # Create a credential using the Google Developer Service Account Credential and Google SecOps API scope.
        credentials = service_account.Credentials.from_service_account_info(service_account_credential, scopes=SCOPES)

        proxies = {}
        if proxy:
            proxies = handle_proxy()
            if not proxies.get("https", True):
                raise DemistoException("https proxy value is empty. Check Demisto server configuration" + str(proxies))
            https_proxy = proxies["https"]
            if not https_proxy.startswith("https") and not https_proxy.startswith("http"):
                proxies["https"] = "https://" + https_proxy
        else:
            skip_proxy()

        # Build an HTTP client which can make authorized OAuth requests.
        self.http_client = auth_requests.AuthorizedSession(credentials)
        self.proxy_info = proxies
        self.disable_ssl = disable_ssl

        self._implement_retry(retries=MAX_RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY, backoff_factor=BACKOFF_FACTOR)

        region = params.get("region", DEFAULT_REGION).lower()
        other_region = params.get("other_region", "").strip().lower()

        self.project_location = region if region != "other" else other_region

        self.project_instance_id = params.get("secops_project_instance_id", "")
        secops_project_number = params.get("secops_project_number", "")
        self.project_number = secops_project_number if secops_project_number else self.project_id
        url_format = params.get("url_format", "<chronicle>.<REGION>.<rep.googleapis.com>").lower()
        self.use_new_url_format = url_format == "<chronicle>.<region>.<rep.googleapis.com>"

    def _implement_retry(
        self, retries=0, status_list_to_retry=None, backoff_factor=5, raise_on_redirect=False, raise_on_status=False
    ):
        """
        Implements the retry mechanism.
        In the default case where retries = 0 the request will fail on the first time.

        :type retries: ``int``
        :param retries: How many retries should be made in case of a failure. when set to '0'- will fail on the first time.

        :type status_list_to_retry: ``iterable``
        :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
            A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
            and the response status code is in ``status_list_to_retry``.

        :type backoff_factor: ``float``
        :param backoff_factor:
            A backoff factor to apply between attempts after the second try
            (most errors are resolved immediately by a second try without a
            delay). urllib3 will sleep for::

                {backoff factor} * (2 ** ({number of total retries} - 1))

            seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
            for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
            than :attr:`Retry.BACKOFF_MAX`.

            By default, backoff_factor set to 5

        :type raise_on_redirect: ``bool``
        :param raise_on_redirect: Whether, if the number of redirects is
            exhausted, to raise a MaxRetryError, or to return a response with a
            response code in the 3xx range.

        :type raise_on_status: ``bool``
        :param raise_on_status: Similar meaning to ``raise_on_redirect``:
            whether we should raise an exception, or return a response,
            if status falls in ``status_forcelist`` range and retries have
            been exhausted.
        """
        try:
            method_whitelist = (
                "allowed_methods"
                if hasattr(
                    Retry.DEFAULT,  # type: ignore[attr-defined]
                    "allowed_methods",
                )
                else "method_whitelist"
            )
            whitelist_kawargs = {method_whitelist: frozenset(["GET", "POST", "PUT"])}
            retry = Retry(
                total=retries,
                read=retries,
                connect=retries,
                backoff_factor=backoff_factor,
                status=retries,
                status_forcelist=status_list_to_retry,
                raise_on_status=raise_on_status,
                raise_on_redirect=raise_on_redirect,
                **whitelist_kawargs,  # type: ignore[arg-type]
            )
            http_adapter = HTTPAdapter(max_retries=retry)

            if not self.disable_ssl:
                https_adapter = http_adapter
            elif IS_PY3 and PY_VER_MINOR >= 10:
                https_adapter = SSLAdapter(max_retries=retry, verify=not self.disable_ssl)  # type: ignore[arg-type]
            else:
                https_adapter = http_adapter

            self.http_client.mount("https://", https_adapter)

        except NameError as e:
            demisto.debug(f"_implement_retry: NameError {e}")

    @staticmethod
    def _parse_error_message(error: str, region: str) -> str:
        """
        Extract error message from error object.

        :type error: str
        :param error: Error string response to be parsed.

        :type region: str
        :param region: Region value based on the location of the Google SecOps instance.

        :return: error message
        :rtype: str
        """
        try:
            json_error = json.loads(error)
            if isinstance(json_error, list):
                json_error = json_error[0]
        except json.decoder.JSONDecodeError:
            if region.lower() == "other" and "404" in error:
                error_message = 'Invalid response from Google SecOps API. Check the provided "Other Region" parameter.'
            else:
                error_message = "Invalid response received from SecOps API. Response not in JSON format."
            demisto.debug(f"{error_message} Response - {error}")
            return error_message

        error_obj = json_error.get("error", {})
        if error_obj.get("code") == 403:
            return MESSAGES["PERMISSION_DENIED"]

        message = error_obj.get("message", "")
        status = error_obj.get("status")

        if status:
            message += f"\nStatus: {status}"
        return message

    def _create_url_path(self) -> str:
        """
        Creates the base URL path for the Google SecOps API.

        :return: Constructed URL path including project, location and instance.
        :rtype: str
        """
        parent = f"projects/{self.project_number}/locations/{self.project_location}/instances/{self.project_instance_id}"

        if self.use_new_url_format:
            url = SECOPS_V1_ALPHA_URL.format(self.project_location)
        else:
            url = OLDER_SECOPS_V1_ALPHA_URL.format(self.project_location)

        return f"{url}/{parent}"

    def validate_response(
        self,
        url_suffix: str,
        method: str = "GET",
        body=None,
        json_data: dict | None = None,
        params=None,
        allow_empty_response: bool = False,
    ) -> dict:
        """
        Get response from Google SecOps API and validate it.

        :type url_suffix: str
        :param url_suffix: URL suffix appended to the base path.

        :type method: str
        :param method: HTTP request method.

        :type body: str
        :param body: Data to pass with the request.

        :type json_data: dict
        :param json_data: JSON-serializable dict to send as request body (sets Content-Type: application/json automatically).

        :type params: dict
        :param params: Query parameters to pass with the request.

        :type allow_empty_response: bool
        :param allow_empty_response: Whether to allow an empty response body.

        :return: Parsed JSON response.
        :rtype: dict
        """
        url = urljoin(self._create_url_path(), url_suffix)
        demisto.debug(f"[SECOPS]: Request URL: {url}, params = {params}, data = {body}, json = {json_data}")
        raw_response = self.http_client.request(
            url=url, method=method, data=body, json=json_data, params=params, proxies=self.proxy_info, verify=not self.disable_ssl
        )

        if 500 <= raw_response.status_code <= 599:
            raise ValueError(
                MESSAGES["INTERNAL_SERVER_ERROR"].format(
                    raw_response.status_code, MAX_RETRIES, self._parse_error_message(raw_response.text, self.project_location)
                )
            )
        if raw_response.status_code == 429:
            raise ValueError(
                MESSAGES["RATE_LIMIT_EXCEEDED"].format(
                    raw_response.status_code, MAX_RETRIES, self._parse_error_message(raw_response.text, self.project_location)
                )
            )
        if raw_response.status_code in (400, 404):
            raise ValueError(
                MESSAGES["HTTP_ERROR"].format(
                    raw_response.status_code, self._parse_error_message(raw_response.text, self.project_location)
                )
            )
        if raw_response.status_code not in OK_CODES:
            raise ValueError(
                MESSAGES["HTTP_ERROR"].format(
                    raw_response.status_code, self._parse_error_message(raw_response.text, self.project_location)
                )
            )
        if not raw_response.text:
            if allow_empty_response:
                return {}
            raise ValueError(MESSAGES["EMPTY_RESPONSE"].format(raw_response.status_code))

        try:
            return raw_response.json()
        except json.decoder.JSONDecodeError:
            raise ValueError(MESSAGES["INVALID_JSON_RESPONSE"])

    def list_cases(
        self,
        page_size: int,
        case_filter: str | None = None,
        page_token: str | None = None,
        order_by: str | None = None,
    ) -> dict[str, Any]:
        """
        Call Google SecOps API to list Cases.

        :type page_size: int
        :param page_size: Maximum number of cases to return.

        :type case_filter: str
        :param case_filter: AIP-160 filter string.

        :type page_token: str
        :param page_token: Page token to resume pagination.

        :type order_by: str
        :param order_by: Field and direction to order results by.

        :return: Raw API response dict containing 'cases' list and optional 'nextPageToken'.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": page_size,
            "expand": CASES_EXPAND_FIELDS,
            "filter": case_filter,
            "orderBy": order_by,
            "pageToken": page_token,
        }
        remove_nulls_from_dictionary(params)

        return self.validate_response(ENDPOINTS["CASES"], params=params)

    def get_case(self, case_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Case by its ID.

        :type case_id: str
        :param case_id: The ID of the case to retrieve.

        :return: Raw API response dict for the case.
        :rtype: dict[str, Any]
        """
        url_suffix = ENDPOINTS["CASE"].format(case_id=case_id)
        params: dict[str, Any] = {"expand": CASES_EXPAND_FIELDS}
        return self.validate_response(url_suffix, params=params)

    def update_case(self, case_id: str, body: dict[str, Any], update_mask: str) -> dict[str, Any]:
        """
        Update properties of a Case using PATCH.

        :type case_id: str
        :param case_id: The ID of the case to update.

        :type body: dict[str, Any]
        :param body: Fields to update.

        :type update_mask: str
        :param update_mask: Comma-separated field paths for the updateMask query parameter.

        :return: Raw API response dict for the updated case.
        :rtype: dict[str, Any]
        """
        url_suffix = ENDPOINTS["CASE"].format(case_id=case_id)
        params: dict[str, Any] = {"updateMask": update_mask}
        return self.validate_response(url_suffix, method="PATCH", json_data=body, params=params)

    def case_tag_add(self, case_ids: list[str], tags: list[str]) -> None:
        """
        Add tags to cases in bulk using the executeBulkAddTag API.

        :type case_ids: list[str]
        :param case_ids: List of case IDs to add tags to.

        :type tags: list[str]
        :param tags: List of tags to add.
        """
        body = {"casesIds": case_ids, "tags": tags}
        self.validate_response(ENDPOINTS["CASES_BULK_ADD_TAG"], method="POST", json_data=body, allow_empty_response=True)

    def case_tag_remove(self, case_id: str, tag: str) -> None:
        """
        Remove a tag from a case using the removeTag API.

        :type case_id: str
        :param case_id: The ID of the case to remove the tag from.

        :type tag: str
        :param tag: The tag to remove.
        """
        url_suffix = ENDPOINTS["CASES_REMOVE_TAG"].format(case_id=case_id)
        body = {"tag": tag}
        self.validate_response(url_suffix, method="POST", json_data=body, allow_empty_response=True)

    def case_priority_change(self, case_ids: list[str], priority: str) -> None:
        """
        Change the priority of cases in bulk using the executeBulkChangePriority API.

        :type case_ids: list[str]
        :param case_ids: List of case IDs to change priority for.

        :type priority: str
        :param priority: The new priority value (will be converted to PRIORITY_<VALUE> format).
        """
        body = {"casesIds": case_ids, "priority": f"PRIORITY_{priority}"}
        self.validate_response(ENDPOINTS["CASES_BULK_CHANGE_PRIORITY"], method="POST", json_data=body, allow_empty_response=True)

    def case_stage_definitions_list(self) -> dict[str, Any]:
        """
        Retrieve the list of case stage definitions configured in the instance.

        :return: Raw API response dict containing 'caseStageDefinitions' list.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": MAX_PAGE_SIZE,
            "orderBy": "order",
        }
        return self.validate_response(ENDPOINTS["CASE_STAGE_DEFINITIONS"], params=params)

    def case_stage_change(self, case_ids: list[str], stage: str) -> None:
        """
        Change the workflow stage of cases in bulk using the executeBulkChangeStage API.

        :type case_ids: list[str]
        :param case_ids: List of case IDs to change stage for.

        :type stage: str
        :param stage: The new workflow stage value.
        """
        body = {"casesIds": case_ids, "stage": stage}
        self.validate_response(ENDPOINTS["CASES_BULK_CHANGE_STAGE"], method="POST", json_data=body, allow_empty_response=True)

    def case_reopen(self, case_ids: list[str], comment: str) -> None:
        """
        Reopen cases in bulk using the executeBulkReopen API.

        :type case_ids: list[str]
        :param case_ids: List of case IDs to reopen.

        :type comment: str
        :param comment: Comment explaining why the cases are being reopened.
        """
        body = {"casesIds": case_ids, "reopenComment": comment}
        self.validate_response(ENDPOINTS["CASES_BULK_REOPEN"], method="POST", json_data=body, allow_empty_response=True)

    def case_close_definitions_list(self) -> dict[str, Any]:
        """
        Retrieve the list of case close definitions configured in the instance.

        :return: Raw API response dict containing 'caseCloseDefinitions' list.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": MAX_PAGE_SIZE,
            "orderBy": "closeReason",
        }
        return self.validate_response(ENDPOINTS["CASE_CLOSE_DEFINITIONS"], params=params)

    def case_close(self, case_ids: list[str], close_reason: str, root_cause: str, close_comment: str | None = None) -> None:
        """
        Close cases in bulk using the executeBulkClose API.

        :type case_ids: list[str]
        :param case_ids: List of case IDs to close.

        :type close_reason: str
        :param close_reason: The reason for closing the cases.

        :type root_cause: str
        :param root_cause: Root cause description for the closure.

        :type close_comment: str | None
        :param close_comment: Optional comment to add when closing the cases.
        """
        body: dict[str, Any] = {"casesIds": case_ids, "closeReason": close_reason, "rootCause": root_cause}
        if close_comment:
            body["closeComment"] = close_comment
        self.validate_response(ENDPOINTS["CASES_BULK_CLOSE"], method="POST", json_data=body, allow_empty_response=True)

    def get_soar_user_ids(self, emails: list[str]) -> dict[str, str]:
        """
        Resolve email addresses to SOAR user IDs via the legacySoarUsers API.

        :type emails: list[str]
        :param emails: List of user email addresses to resolve.

        :return: Mapping of lowercased email to user ID (displayName field) for active users only.
        :rtype: dict[str, str]
        """
        email_filter = "(" + " OR ".join(f"email='{email}'" for email in emails) + ") AND accountState='ACTIVE'"
        params = {"pageSize": len(emails), "filter": email_filter}
        response = self.validate_response(ENDPOINTS["LEGACY_SOAR_USERS"], params=params)
        email_to_id: dict[str, str] = {}
        for user in response.get("legacySoarUsers", []):
            email = user.get("email", "").lower()
            user_id = user.get("displayName", "")
            if not email or not user_id:
                continue
            email_to_id[email] = user_id
        return email_to_id

    def case_assign(self, case_ids: list[str], assignee: str) -> None:
        """
        Assign cases in bulk to an analyst or SOC role using the executeBulkAssign API.

        :type case_ids: list[str]
        :param case_ids: List of case IDs to assign.

        :type assignee: str
        :param assignee: The resolved user ID or SOC role (e.g. @Tier1).
        """
        body = {"casesIds": case_ids, "userName": assignee}
        self.validate_response(ENDPOINTS["CASES_BULK_ASSIGN"], method="POST", json_data=body, allow_empty_response=True)

    def case_comments_list(
        self,
        case_id: str,
        page_size: int,
        page_token: str | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve the list of comments for a specified case.

        :type case_id: str
        :param case_id: The ID of the case to retrieve comments for.

        :type page_size: int
        :param page_size: Maximum number of comments to return.

        :type page_token: str | None
        :param page_token: Page token to resume pagination.

        :type sort_by: str | None
        :param sort_by: Field to sort results by.

        :type sort_order: str | None
        :param sort_order: Sort direction (Asc or Desc).

        :return: Raw API response dict containing 'caseComments' list and optional 'nextPageToken'.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": page_size,
            "pageToken": page_token,
            "orderBy": f"{sort_by} {sort_order.lower()}" if sort_by and sort_order else None,
        }
        remove_nulls_from_dictionary(params)

        endpoint = ENDPOINTS["CASE_COMMENTS"].format(case_id=case_id)
        return self.validate_response(endpoint, params=params)

    def case_comment_create(self, case_id: str, comment: str) -> dict[str, Any]:
        """
        Add a comment to the specified case.

        :type case_id: str
        :param case_id: The ID of the case to add the comment to.

        :type comment: str
        :param comment: The comment text to add.

        :return: Raw API response dict containing the created case comment details.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_COMMENTS"].format(case_id=case_id)
        body = {"comment": comment}
        return self.validate_response(endpoint, method="POST", json_data=body)

    def case_sla_pause(self, case_id: str, message: str | None) -> None:
        """
        Pause the SLA timer for the specified case.

        :type case_id: str
        :param case_id: The ID of the case to pause the SLA timer for.

        :type message: str | None
        :param message: The reason for pausing the SLA timer. Optional.
        """
        endpoint = ENDPOINTS["CASE_SLA_PAUSE"].format(case_id=case_id)
        body = {"message": message} if message else {}
        self.validate_response(endpoint, method="POST", json_data=body, allow_empty_response=True)

    def case_sla_resume(self, case_id: str) -> None:
        """
        Resume the SLA timer for the specified case.

        :type case_id: str
        :param case_id: The ID of the case to resume the SLA timer for.
        """
        endpoint = ENDPOINTS["CASE_SLA_RESUME"].format(case_id=case_id)
        self.validate_response(endpoint, method="POST", allow_empty_response=True)

    def list_case_alerts(
        self,
        case_id: str,
        page_size: int,
        page_token: str | None,
        alert_filter: str | None,
        order_by: str | None,
    ) -> dict[str, Any]:
        """
        Retrieve the list of Case Alerts associated with a specific Case.

        :type case_id: str
        :param case_id: The ID of the Case to list alerts for.

        :type page_size: int
        :param page_size: Maximum number of alerts to return.

        :type page_token: str | None
        :param page_token: Page token for pagination.

        :type alert_filter: str | None
        :param alert_filter: AIP-160 filter string.

        :type order_by: str | None
        :param order_by: Sort field and direction, e.g. "createTime Desc".

        :return: Raw API response dict containing 'caseAlerts' list and optional 'nextPageToken'.
        :rtype: dict[str, Any]
        """
        url_suffix = ENDPOINTS["CASE_ALERTS"].format(case_id=case_id)
        params: dict[str, Any] = {
            "pageSize": page_size,
            "pageToken": page_token,
            "filter": alert_filter or None,
            "orderBy": order_by,
            "expand": CASE_ALERT_EXPAND_FIELDS,
        }
        remove_nulls_from_dictionary(params)
        return self.validate_response(url_suffix, params=params)

    def get_case_alert(self, case_id: str, alert_id: str) -> dict[str, Any]:
        """
        Retrieve a specific Case Alert by its ID.

        :type case_id: str
        :param case_id: The ID of the case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to retrieve.

        :return: Raw API response dict for the Case Alert.
        :rtype: dict[str, Any]
        """
        url_suffix = ENDPOINTS["CASE_ALERT"].format(case_id=case_id, alert_id=alert_id)
        params: dict[str, Any] = {"expand": CASE_ALERT_EXPAND_FIELDS}
        return self.validate_response(url_suffix, params=params)

    def update_case_alert(self, case_id: str, alert_id: str, body: dict[str, Any], update_mask: str) -> dict[str, Any]:
        """
        Update properties of a Case Alert using PATCH.

        :type case_id: str
        :param case_id: The ID of the case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the alert to update.

        :type body: dict[str, Any]
        :param body: Fields to update.

        :type update_mask: str
        :param update_mask: Comma-separated field paths for the updateMask query parameter.

        :return: Raw API response dict for the updated Case Alert.
        :rtype: dict[str, Any]
        """
        url_suffix = ENDPOINTS["CASE_ALERT"].format(case_id=case_id, alert_id=alert_id)
        params: dict[str, Any] = {"updateMask": update_mask}
        return self.validate_response(url_suffix, method="PATCH", json_data=body, params=params)

    def case_alert_tag_add(self, case_id: str, alert_id: str, tag: str) -> None:
        """
        Add a tag to a Case Alert using the addTag API.

        :type case_id: str
        :param case_id: The ID of the Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to add a tag to.

        :type tag: str
        :param tag: The tag to add to the alert.
        """
        endpoint = ENDPOINTS["CASE_ALERT_ADD_TAG"].format(case_id=case_id, alert_id=alert_id)
        body = {"tag": tag}
        self.validate_response(endpoint, method="POST", json_data=body, allow_empty_response=True)

    def case_alert_tag_remove(self, case_id: str, alert_id: str, tag: str) -> None:
        """
        Remove a tag from a Case Alert using the removeTag API.

        :type case_id: str
        :param case_id: The ID of the Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to remove a tag from.

        :type tag: str
        :param tag: The tag to remove from the alert.
        """
        endpoint = ENDPOINTS["CASE_ALERT_REMOVE_TAG"].format(case_id=case_id, alert_id=alert_id)
        body = {"tag": tag}
        self.validate_response(endpoint, method="POST", json_data=body, allow_empty_response=True)

    def case_alert_move(self, case_id: str, alert_id: str, destination_case_id: str) -> dict:
        """
        Move a Case Alert to a different Case using the move API.

        :type case_id: str
        :param case_id: The ID of the source Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to move.

        :type destination_case_id: str
        :param destination_case_id: The ID of the destination Case to move the alert to.

        :return: API response containing newCaseId and valid fields.
        :rtype: dict
        """
        endpoint = ENDPOINTS["CASE_ALERT_MOVE"].format(case_id=case_id, alert_id=alert_id)
        body = {"destinationCaseId": int(destination_case_id)}
        return self.validate_response(endpoint, method="POST", json_data=body)

    def case_alert_sla_pause(self, case_id: str, alert_id: str, message: str | None) -> None:
        """
        Pause the SLA timer for the specified Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to pause the SLA timer for.

        :type message: str | None
        :param message: The reason for pausing the SLA timer. Optional.
        """
        endpoint = ENDPOINTS["CASE_ALERT_SLA_PAUSE"].format(case_id=case_id, alert_id=alert_id)
        body = {"message": message} if message else {}
        self.validate_response(endpoint, method="POST", json_data=body, allow_empty_response=True)

    def case_alert_sla_resume(self, case_id: str, alert_id: str) -> None:
        """
        Resume the SLA timer for the specified Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to resume the SLA timer for.
        """
        endpoint = ENDPOINTS["CASE_ALERT_SLA_RESUME"].format(case_id=case_id, alert_id=alert_id)
        self.validate_response(endpoint, method="POST", allow_empty_response=True)

    def case_alert_sla_set(self, case_id: str, alert_id: str, total_time_ms: int, critical_time_ms: int | None) -> None:
        """
        Set the SLA parameters for the specified Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to set the SLA for.

        :type total_time_ms: int
        :param total_time_ms: The total SLA duration in milliseconds.

        :type critical_time_ms: int | None
        :param critical_time_ms: The critical SLA threshold in milliseconds. Optional.
        """
        endpoint = ENDPOINTS["CASE_ALERT_SLA_SET"].format(case_id=case_id, alert_id=alert_id)
        body: dict = {"totalTimeMs": str(total_time_ms)}
        if critical_time_ms is not None:
            body["criticalTimeMs"] = str(critical_time_ms)
        self.validate_response(endpoint, method="POST", json_data=body, allow_empty_response=True)

    def case_alert_recommendation_create(self, case_id: str, alert_id: str) -> dict[str, Any]:
        """
        Initiate an asynchronous AI recommendation for a Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case the alert belongs to.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert to generate a recommendation for.

        :return: Response containing the recommendation ID.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_ALERT_RECOMMENDATION_CREATE"].format(case_id=case_id, alert_id=alert_id)
        return self.validate_response(endpoint, method="POST")

    def case_alert_fetch_recommendation(self, case_id: str, recommendation_id: str) -> dict[str, Any]:
        """
        Fetch a previously generated AI recommendation for a Case Alert.

        :type case_id: str
        :param case_id: The ID of the case the alert belongs to.

        :type recommendation_id: str
        :param recommendation_id: The ID of the recommendation to fetch.

        :return: Raw API response dict containing the recommendation details.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_ALERT_FETCH_RECOMMENDATION"].format(case_id=case_id)
        params: dict[str, Any] = {"recommendationId": recommendation_id}
        return self.validate_response(endpoint, params=params)

    def case_alert_customfield_list(
        self,
        case_id: str,
        alert_id: str,
        page_size: int,
        page_token: str | None = None,
        order_by: str | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve the list of custom field values associated with a Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type page_size: int
        :param page_size: Maximum number of custom field values to return.

        :type page_token: str | None
        :param page_token: Page token to resume pagination.

        :type order_by: str | None
        :param order_by: Sort field and direction, e.g. "customFieldId asc".

        :return: Raw API response dict containing 'customFieldValues' list and optional 'nextPageToken'.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": page_size,
            "pageToken": page_token,
            "orderBy": order_by,
        }
        remove_nulls_from_dictionary(params)
        endpoint = ENDPOINTS["CASE_ALERT_CUSTOMFIELD_VALUES"].format(case_id=case_id, alert_id=alert_id)
        return self.validate_response(endpoint, params=params)

    def list_custom_fields(
        self,
        page_size: int,
        page_token: str | None = None,
        custom_field_filter: str | None = None,
        order_by: str | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve the list of custom fields via the customFields API.

        :type page_size: int
        :param page_size: Maximum number of custom fields to return.

        :type page_token: str | None
        :param page_token: Page token to resume pagination.

        :type custom_field_filter: str | None
        :param custom_field_filter: AIP-160 filter expression.

        :type order_by: str | None
        :param order_by: Sort field and direction, e.g. "createTime Desc".

        :return: Raw API response dict containing 'customFields' list and optional 'nextPageToken'.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": page_size,
            "pageToken": page_token,
            "filter": custom_field_filter,
            "orderBy": order_by,
        }
        remove_nulls_from_dictionary(params)
        return self.validate_response(ENDPOINTS["CUSTOM_FIELDS"], params=params)

    def case_alert_involved_entities_list(
        self,
        case_id: str,
        alert_id: str,
        page_size: int,
        page_token: str | None = None,
        entity_filter: str | None = None,
        order_by: str | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve the list of involved entities for the specified Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type page_size: int
        :param page_size: Maximum number of entities to return.

        :type page_token: str | None
        :param page_token: Page token to resume pagination.

        :type entity_filter: str | None
        :param entity_filter: AIP-160 filter expression.

        :type order_by: str | None
        :param order_by: Sort field and direction, e.g. "createTime Desc".

        :return: Raw API response dict containing 'involvedEntities' list and optional 'nextPageToken'.
        :rtype: dict[str, Any]
        """
        params: dict[str, Any] = {
            "pageSize": page_size,
            "pageToken": page_token,
            "filter": entity_filter,
            "orderBy": order_by,
        }
        remove_nulls_from_dictionary(params)
        endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITIES"].format(case_id=case_id, alert_id=alert_id)
        return self.validate_response(endpoint, params=params)

    def case_alert_involved_entity_get(self, case_id: str, alert_id: str, entity_id: str) -> dict[str, Any]:
        """
        Retrieve a specific InvolvedEntity by its ID.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type entity_id: str
        :param entity_id: The ID of the InvolvedEntity to retrieve.

        :return: Raw API response dict for the involved entity.
        :rtype: dict[str, Any]
        """
        url_suffix = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY"].format(case_id=case_id, alert_id=alert_id, entity_id=entity_id)
        return self.validate_response(url_suffix)

    def case_alert_involved_entity_create(
        self,
        case_id: str,
        alert_id: str,
        identifier: str,
        entity_type: str,
        suspicious: bool,
        internal: bool,
        attacker: bool | None,
        pivot: bool | None,
        operating_system: str | None,
        network_title: str | None,
        threat_source: str | None,
        network_priority: int | None,
    ) -> dict[str, Any]:
        """
        Manually create a new InvolvedEntity within a Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type identifier: str
        :param identifier: The identifier name of the entity (e.g. IP address, hostname).

        :type entity_type: str
        :param entity_type: The type of the new entity.

        :type suspicious: bool
        :param suspicious: Whether the entity is suspicious.

        :type internal: bool
        :param internal: Whether the entity is internal to the organization.

        :type attacker: bool | None
        :param attacker: Whether the entity represents an attacker.

        :type pivot: bool | None
        :param pivot: Whether the entity is a pivot entity common to multiple cases.

        :type operating_system: str | None
        :param operating_system: The operating system of the entity.

        :type network_title: str | None
        :param network_title: The network name related to the entity.

        :type threat_source: str | None
        :param threat_source: The threat source name associated with the entity.

        :type network_priority: int | None
        :param network_priority: The network priority of the entity.

        :return: Raw API response dict for the created involved entity.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITIES"].format(case_id=case_id, alert_id=alert_id)
        body: dict[str, Any] = {
            "identifier": identifier,
            "type": entity_type,
            "suspicious": suspicious,
            "internal": internal,
            "attacker": attacker,
            "pivot": pivot,
            "operatingSystem": operating_system,
            "networkTitle": network_title,
            "threatSource": threat_source,
            "networkPriority": network_priority,
        }
        remove_nulls_from_dictionary(body)
        return self.validate_response(endpoint, method="POST", json_data=body)

    def case_alert_involved_entity_update(
        self,
        case_id: str,
        alert_id: str,
        entity_id: str,
        suspicious: bool | None,
        internal: bool | None,
        attacker: bool | None,
        pivot: bool | None,
        operating_system: str | None,
        network_title: str | None,
        threat_source: str | None,
        network_priority: int | None,
    ) -> dict[str, Any]:
        """
        Update an existing InvolvedEntity within a Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type entity_id: str
        :param entity_id: The ID of the Involved Entity.

        :type suspicious: bool | None
        :param suspicious: Updated suspicion flag for the entity.

        :type internal: bool | None
        :param internal: Updated internal flag for the entity.

        :type attacker: bool | None
        :param attacker: Updated attacker designation for the entity.

        :type pivot: bool | None
        :param pivot: Updated pivot designation for the entity.

        :type operating_system: str | None
        :param operating_system: Updated operating system of the entity.

        :type network_title: str | None
        :param network_title: Updated network name related to the entity.

        :type threat_source: str | None
        :param threat_source: Updated threat source associated with the entity.

        :type network_priority: int | None
        :param network_priority: Updated network priority of the entity.

        :return: Raw API response dict for the updated involved entity.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY"].format(case_id=case_id, alert_id=alert_id, entity_id=entity_id)
        body: dict[str, Any] = {
            "suspicious": suspicious,
            "internal": internal,
            "attacker": attacker,
            "pivot": pivot,
            "operatingSystem": operating_system,
            "networkTitle": network_title,
            "threatSource": threat_source,
            "networkPriority": network_priority,
        }
        remove_nulls_from_dictionary(body)
        return self.validate_response(endpoint, method="PATCH", json_data=body)

    def case_alert_involved_entity_add_property(
        self,
        case_id: str,
        alert_id: str,
        entity_id: str,
        key: str,
        value: str,
    ) -> dict[str, Any]:
        """
        Add a new custom property to an InvolvedEntity within a Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type entity_id: str
        :param entity_id: The ID of the Involved Entity.

        :type key: str
        :param key: The new property key.

        :type value: str
        :param value: The new property value.

        :return: Raw API response dict for the updated involved entity.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_ADD_PROPERTY"].format(
            case_id=case_id, alert_id=alert_id, entity_id=entity_id
        )
        body: dict[str, Any] = {"key": key, "value": value}
        return self.validate_response(endpoint, method="POST", json_data=body)

    def case_alert_involved_entity_update_property(
        self,
        case_id: str,
        alert_id: str,
        entity_id: str,
        key: str,
        value: str,
    ) -> dict[str, Any]:
        """
        Update the value of an existing custom property on an InvolvedEntity within a Case Alert.

        :type case_id: str
        :param case_id: The ID of the Case.

        :type alert_id: str
        :param alert_id: The ID of the Case Alert.

        :type entity_id: str
        :param entity_id: The ID of the Involved Entity.

        :type key: str
        :param key: The existing property key whose value should be updated.

        :type value: str
        :param value: The new property value.

        :return: Raw API response dict for the updated involved entity.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["CASE_ALERT_INVOLVED_ENTITY_UPDATE_PROPERTY"].format(
            case_id=case_id, alert_id=alert_id, entity_id=entity_id
        )
        body: dict[str, Any] = {"key": key, "value": value}
        return self.validate_response(endpoint, method="POST", json_data=body)

    def list_enabled_playbooks(self, case_environment: str | None, execution_scope: str) -> dict[str, Any]:
        """
        Retrieve the list of enabled playbooks.

        :type case_environment: str | None
        :param case_environment: Case environment to filter playbooks by.

        :type execution_scope: str
        :param execution_scope: Execution scope to filter playbooks by (ALERT or CASE).

        :return: Raw API response dict containing 'payload' list.
        :rtype: dict[str, Any]
        """
        body: dict[str, Any] = {"executionScope": execution_scope}
        if case_environment:
            body["caseEnvironment"] = case_environment
        return self.validate_response(ENDPOINTS["LEGACY_PLAYBOOKS"], method="POST", json_data=body)

    def playbook_attach(
        self,
        case_id: str,
        alert_group_identifier: str,
        alert_identifier: str,
        playbook_name: str,
        original_workflow_definition_identifier: str | None,
    ) -> dict[str, Any]:
        """
        Manually attach (trigger) a specific playbook to a Case Alert.

        :type case_id: str
        :param case_id: The cyber case ID.

        :type alert_group_identifier: str
        :param alert_group_identifier: The alert group identifier.

        :type alert_identifier: str
        :param alert_identifier: The alert identifier.

        :type playbook_name: str
        :param playbook_name: The name of the playbook (workflow) to attach.

        :type original_workflow_definition_identifier: str | None
        :param original_workflow_definition_identifier: Optional original workflow definition identifier.

        :return: Raw API response dict.
        :rtype: dict[str, Any]
        """
        endpoint = ENDPOINTS["LEGACY_PLAYBOOK_ATTACH"]
        body: dict[str, Any] = {
            "cyberCaseId": case_id,
            "alertGroupIdentifier": alert_group_identifier,
            "alertIdentifier": alert_identifier,
            "wfName": playbook_name,
            "originalWorkflowDefinitionIdentifier": original_workflow_definition_identifier,
        }
        remove_nulls_from_dictionary(body)
        return self.validate_response(endpoint, method="POST", json_data=body)


""" HELPER FUNCTIONS """


def trim_spaces_from_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Trim leading and trailing whitespace from all string argument values.

    :type args: dict[str, Any]
    :param args: Command arguments dictionary.

    :return: Arguments dictionary with string values stripped.
    :rtype: dict[str, Any]
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()
    return args


def strip_and_filter_list(list_value: list[str]) -> list[str]:
    """Strip whitespace from each item and drop empty values from the list."""
    return [value.strip() for value in list_value if value.strip()]


def check_valid_positive_number(positive_number: str) -> bool:
    """Check the validity of the positive integer."""
    return positive_number.isdecimal() and int(positive_number) > 0


def check_empty(x: Any) -> bool:
    """
    Check if input is empty (None, empty dict, empty list, or empty string).

    :type x: Any
    :param x: Input value to check.

    :return: True if x is empty, False otherwise.
    :rtype: bool
    """
    return x is None or x == {} or x == [] or x == ""


def remove_empty_elements_for_fetch(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.

    :type d: Any
    :param d: Dictionary or list to clean; non-collection values are returned as-is.

    :return: Cleaned dictionary or list with all empty elements removed.
    :rtype: Any
    """
    if not isinstance(d, dict | list):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_fetch(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_fetch(v)) for k, v in d.items()) if not check_empty(v)}


def remove_empty_elements_for_hr(d: Any) -> Any:
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary or list.
    Non-collection scalar values (int, float, bool) are converted to strings so that
    falsy values like 0 and False are preserved in human-readable output.

    :type d: Any
    :param d: Input dictionary or list.

    :return: Dictionary or list with empty elements removed and scalars stringified.
    :rtype: Any
    """
    if not isinstance(d, dict | list):
        return str(d) if isinstance(d, int | float | bool) else d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements_for_hr(v) for v in d) if not check_empty(v)]
    return {k: v for k, v in ((k, remove_empty_elements_for_hr(v)) for k, v in d.items()) if not check_empty(v)}


def date_to_utc_epoch(date_str: str, date_format: str = DATE_FORMAT) -> int:
    """
    Convert a date string to a UTC epoch timestamp in milliseconds.

    :type date_str: str
    :param date_str: Date string to convert.

    :type date_format: str
    :param date_format: Format used to parse date_str; defaults to DATE_FORMAT.

    :return: UTC epoch timestamp in milliseconds.
    :rtype: int
    """
    dt = datetime.strptime(date_str, date_format)
    return calendar.timegm(dt.timetuple()) * 1000 + dt.microsecond // 1000


def epoch_ms_to_datestring(epoch_ms: int | str, date_format: str = DATE_FORMAT) -> str:
    """
    Convert a UTC epoch timestamp in milliseconds to a formatted date string.

    :type epoch_ms: int or str
    :param epoch_ms: UTC epoch timestamp in milliseconds.

    :type date_format: str
    :param date_format: Output format; defaults to DATE_FORMAT.

    :return: Formatted UTC date string.
    :rtype: str
    """
    return datetime.fromtimestamp(int(epoch_ms) / 1000, tz=UTC).strftime(date_format)


def epoch_ms_to_time_delta(ms: int) -> str:
    """
    Convert a duration in milliseconds to a human-readable string.

    :type ms: int
    :param ms: Duration in milliseconds.

    :return: Duration as 'X days, X hours, X minutes, X seconds'.
    :rtype: str
    """
    delta = timedelta(milliseconds=ms)
    total_seconds = int(delta.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    labels = [(days, "days"), (hours, "hours"), (minutes, "minutes"), (seconds, "seconds")]
    parts = [f"{value} {unit}" for value, unit in labels if value]
    return ", ".join(parts) or "0 seconds"


def compute_cases_filter_hash(
    priorities: list | None,
    statuses: list | None,
    environments: list | None,
    tags: list | None,
    filter_logic: str,
) -> str:
    """
    Compute an MD5 hash of the case filter parameters.

    Used to detect configuration changes between fetch cycles. If the hash differs
    from the stored value, the page_token and ingested_case_ids are reset to avoid
    a 500 error caused by a stale page_token tied to a different filter.

    :type priorities: list | None
    :param priorities: List of case priority values to filter by.

    :type statuses: list | None
    :param statuses: List of case status values to filter by.

    :type environments: list | None
    :param environments: List of case environment values to filter by.

    :type tags: list | None
    :param tags: List of case tags to filter by.

    :type filter_logic: str
    :param filter_logic: Logic operator (AND/OR) used to combine filter conditions.

    :return: MD5 hex digest of the sorted, serialized filter parameters.
    :rtype: str
    """
    payload = {
        "priorities": sorted(priorities or []),
        "statuses": sorted(statuses or []),
        "environments": sorted(environments or []),
        "tags": sorted(tags or []),
        "filter_logic": filter_logic,
    }
    return hashlib.md5(json.dumps(payload, sort_keys=True).encode(), usedforsecurity=False).hexdigest()


def multiline_logs_for_list(array: list, prefix: str = "") -> None:
    """
    Log a list of items with a prefix, batched into 50 items per log message.

    :type array: list
    :param array: List of items to log.

    :type prefix: str
    :param prefix: String prepended to each log message; defaults to empty string.

    :return: None
    :rtype: None
    """
    for b in batch(array, batch_size=50):
        demisto.debug(f"{prefix}{b}")


def or_join(field: str, values: list) -> str:
    """
    Build an AIP-160 OR condition for a single field across multiple values.

    :type field: str
    :param field: AIP-160 field name.

    :type values: list
    :param values: List of values to match against the field.

    :return: AIP-160 OR filter string, e.g. (field="value1" OR field="value2").
    :rtype: str
    """
    return "(" + " OR ".join(f'{field}="{value}"' for value in values) + ")"


def any_filter(field: str, values: list) -> str:
    """
    Build an AIP-160 any() condition for a single field across multiple values.

    :type field: str
    :param field: AIP-160 field name.

    :type values: list
    :param values: List of values to match against the field.

    :return: AIP-160 any() filter string, e.g. any(field,"value1","value2").
    :rtype: str
    """
    quoted = ",".join(f'"{value}"' for value in values)
    return f"any({field},{quoted})"


def convert_time_to_ms(time_str: str, arg_name: str) -> int:
    """
    Convert a time string (relative duration or absolute datetime) to a duration in milliseconds.

    Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years,
    yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.

    For relative durations (e.g., "2 weeks"), returns the duration in milliseconds.
    For absolute datetimes, returns the milliseconds from now to that datetime.

    :type time_str: str
    :param time_str: Time string to convert.

    :type arg_name: str
    :param arg_name: The command argument name.

    :return: Duration in milliseconds.
    :rtype: int
    """
    time_str = time_str.strip()

    dt = arg_to_datetime(time_str, arg_name, settings={"TIMEZONE": "UTC", "PREFER_DATES_FROM": "future"})
    now = datetime.now(UTC)
    if dt.tzinfo is None:  # type: ignore
        dt = dt.replace(tzinfo=UTC)  # type: ignore
    delta_ms = int((dt - now).total_seconds() * 1000)  # type: ignore
    if delta_ms <= 0:
        raise ValueError(MESSAGES["TIME_IN_PAST"].format(arg_name=arg_name, time_str=time_str))
    return delta_ms


def prepare_cases_filter(
    priorities: list | None = None,
    statuses: list | None = None,
    environments: list | None = None,
    tags: list | None = None,
    display_names: list | None = None,
    case_types: list | None = None,
    stages: list | None = None,
    sources: list | None = None,
    assignees: list | None = None,
    products: list | None = None,
    important: bool | None = None,
    incident: bool | None = None,
    workflow_statuses: list | None = None,
    sla_statuses: list | None = None,
    alerts_sla_statuses: list | None = None,
    filter_logic: str = DEFAULT_FILTER_LOGIC,
) -> str:
    """
    Prepare an AIP-160 filter string from validated case filter field lists.

    :type priorities: list or None
    :param priorities: List of priority values to filter by.

    :type statuses: list or None
    :param statuses: List of status values to filter by.

    :type environments: list or None
    :param environments: List of environment values to filter by.

    :type tags: list or None
    :param tags: List of tag display names to filter by.

    :type display_names: list or None
    :param display_names: List of display name values to filter by.

    :type case_types: list or None
    :param case_types: List of case type values to filter by.

    :type stages: list or None
    :param stages: List of stage values to filter by.

    :type sources: list or None
    :param sources: List of source values to filter by.

    :type assignees: list or None
    :param assignees: List of assignee values to filter by.

    :type products: list or None
    :param products: List of product display names to filter by.

    :type important: bool or None
    :param important: Filter by important flag.

    :type incident: bool or None
    :param incident: Filter by incident flag.

    :type workflow_statuses: list or None
    :param workflow_statuses: List of workflow status values to filter by.

    :type sla_statuses: list or None
    :param sla_statuses: List of SLA status values to filter by.

    :type alerts_sla_statuses: list or None
    :param alerts_sla_statuses: List of alerts SLA status values to filter by.

    :type filter_logic: str
    :param filter_logic: Logical operator used to join conditions — "AND" or "OR".

    :return: AIP-160 filter string, or empty string if no filters are set.
    :rtype: str
    """
    # Separator placed between each condition, e.g. " AND " or " OR "
    join_separator = f" {filter_logic.upper()} "
    conditions = []

    # Fields that support equality matching across multiple values via OR e.g. (field="a" OR field="b")
    field_value_pairs: list[tuple[str, list | None]] = [
        ("priority", priorities),
        ("status", statuses),
        ("environment", environments),
        ("displayName", display_names),
        ("type", case_types),
        ("stage", stages),
        ("source", sources),
        ("assignee", assignees),
        ("workflowStatus", workflow_statuses),
        ("sla.expirationStatus", sla_statuses),
        ("alertsSla.expirationStatus", alerts_sla_statuses),
    ]

    # Build an OR expression for each field that has values provided
    for field, values in field_value_pairs:
        if values:
            conditions.append(or_join(field, values))

    # tags and products use AIP-160 any() because they are repeated fields on the case
    if tags:
        conditions.append(any_filter("tags.displayName", tags))

    if products:
        conditions.append(any_filter("products.displayName", products))

    # Boolean flags are scalar fields — emit as-is with lowercase true/false
    if important is not None:
        conditions.append(f"important={str(important).lower()}")

    if incident is not None:
        conditions.append(f"incident={str(incident).lower()}")

    return join_separator.join(conditions)


def prepare_cases_date_filter(
    create_start_time: str | None = None,
    create_end_time: str | None = None,
    update_start_time: str | None = None,
    update_end_time: str | None = None,
) -> str:
    """
    Prepare an AIP-160 filter string from date/time filter fields.
    Date conditions are always joined with AND.

    :type create_start_time: str or None
    :param create_start_time: Lower bound for case create time.

    :type create_end_time: str or None
    :param create_end_time: Upper bound for case create time.

    :type update_start_time: str or None
    :param update_start_time: Lower bound for case update time.

    :type update_end_time: str or None
    :param update_end_time: Upper bound for case update time.

    :return: AIP-160 filter string, or empty string if no date filters are set.
    :rtype: str
    """
    conditions = []
    if create_start_time:
        conditions.append(f"createTime>={date_to_utc_epoch(create_start_time)}")
    if create_end_time:
        conditions.append(f"createTime<={date_to_utc_epoch(create_end_time)}")
    if update_start_time:
        conditions.append(f"updateTime>={date_to_utc_epoch(update_start_time)}")
    if update_end_time:
        conditions.append(f"updateTime<={date_to_utc_epoch(update_end_time)}")
    return " AND ".join(conditions)


def prepare_alert_entity_filter(
    entity_types: list[str] | None = None,
    suspicious: bool | None = None,
    internal: bool | None = None,
    attacker: bool | None = None,
    pivot: bool | None = None,
    enriched: bool | None = None,
    artifact: bool | None = None,
    vulnerable: bool | None = None,
    manually_created: bool | None = None,
    threat_sources: list[str] | None = None,
    operating_systems: list[str] | None = None,
    network_titles: list[str] | None = None,
    network_priorities: list[str] | None = None,
    environments: list[str] | None = None,
    filter_logic: str = DEFAULT_FILTER_LOGIC,
) -> str:
    """
    Prepare an AIP-160 filter string for involved entities.

    :type filter_logic: str
    :param filter_logic: Logical operator used to join conditions — "AND" or "OR".

    :return: AIP-160 filter string, or empty string if no filters are set.
    :rtype: str
    """
    join_separator = f" {filter_logic.upper()} "
    conditions = []

    if entity_types:
        conditions.append(or_join("type", entity_types))

    bool_fields: list[tuple[str, bool | None]] = [
        ("suspicious", suspicious),
        ("internal", internal),
        ("attacker", attacker),
        ("pivot", pivot),
        ("enriched", enriched),
        ("artifact", artifact),
        ("vulnerable", vulnerable),
        ("manuallyCreated", manually_created),
    ]
    for field, value in bool_fields:
        if value is not None:
            conditions.append(f"{field}={str(value).lower()}")

    string_list_fields: list[tuple[str, list | None]] = [
        ("threatSource", threat_sources),
        ("operatingSystem", operating_systems),
        ("networkTitle", network_titles),
        ("environment", environments),
    ]
    for field, values in string_list_fields:
        if values:
            conditions.append(or_join(field, values))

    if network_priorities:
        conditions.append("(" + " OR ".join(f"networkPriority={v}" for v in network_priorities) + ")")

    return join_separator.join(conditions)


def prepare_sla_hr(sla: dict[str, Any]) -> dict[str, Any]:
    """
    Format an SLA dict for human-readable output.

    Converts unix-millisecond timestamp fields (expirationTime, criticalExpirationTime)
    to ISO 8601 strings via timestamp_to_datestring. Renames keys to display-friendly labels.

    :type sla: dict[str, Any]
    :param sla: Raw SLA object from the Google SecOps API response.

    :return: Dict with display-friendly keys and formatted timestamp values.
    :rtype: dict[str, Any]
    """
    result: dict[str, Any] = {
        "Status": sla.get("expirationStatus"),
    }
    expiration_time = sla.get("expirationTime")
    if expiration_time:
        result["Expiration Time"] = epoch_ms_to_datestring(expiration_time, date_format=HR_DATE_FORMAT)
    critical_expiration_time = sla.get("criticalExpirationTime")
    if critical_expiration_time:
        result["Critical Expiration Time"] = epoch_ms_to_datestring(critical_expiration_time, date_format=HR_DATE_FORMAT)
    remaining_time = sla.get("remainingTimeSinceLastPause")
    if remaining_time:
        result["Remaining Time Since Last Pause"] = epoch_ms_to_time_delta(remaining_time)
    return result


def prepare_context_hr_gcb_case_list(response: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human-readable output for case list.

    :type response: dict
    :param response: Response dictionary from API response.

    :return: Tuple of context dict and human-readable markdown string.
    :rtype: tuple[dict[str, Any], str]
    """
    cases: list[dict[str, Any]] = deepcopy(response.get("cases", []))
    next_page_token = response.get("nextPageToken", "")

    table_data: list[dict[str, Any]] = []
    for case in cases:
        parts = case.get("name", "").split("cases/")
        case_id = parts[1] if len(parts) >= 2 else ""
        case["caseId"] = case_id

        priority = case.get("priority", "")
        display_priority = priority.replace("PRIORITY_", "") if priority else ""
        create_time = case.get("createTime")
        if create_time:
            create_time = epoch_ms_to_datestring(create_time, date_format=HR_DATE_FORMAT)
        table_data.append(
            {
                CASE_ID_DISPLAY: case_id,
                "Display Name": case.get("displayName", ""),
                "Priority": display_priority,
                "Status": case.get("status", ""),
                "Score": case.get("score", ""),
                "Stage": case.get("stage", ""),
                "Environment": case.get("environment", ""),
                "Workflow Status": case.get("workflowStatus", ""),
                "Assignee": case.get("assignee", ""),
                "Tags": case.get("tags", ""),
                "SLA": prepare_sla_hr(case.get("sla", {})),
                "Alert Count": case.get("alertCount", ""),
                "Create Time": create_time,
            }
        )

    readable_output = tableToMarkdown(
        "Case List",
        remove_empty_elements_for_hr(table_data),
        headers=[
            CASE_ID_DISPLAY,
            "Display Name",
            "Priority",
            "Status",
            "Score",
            "Stage",
            "Environment",
            "Workflow Status",
            "Assignee",
            "Tags",
            "SLA",
            "Alert Count",
            "Create Time",
        ],
        removeNull=True,
        is_auto_json_transform=True,
    )

    if next_page_token:
        readable_output += (
            f"\nMaximum number of cases specified in page_size has been returned. "
            f"To fetch the next set of cases, execute the command with the page token as `{next_page_token}`."
        )

    outputs: dict[str, Any] = {}
    outputs[f"{SECOPS_OUTPUT_PATHS['Case']}(val.caseId == obj.caseId)"] = cases

    if next_page_token:
        outputs[f"{SECOPS_OUTPUT_PATHS['PageToken']}(val.command == obj.command)"] = {
            "command": "gcb-case-list",
            "nextPageToken": next_page_token,
            "totalSize": response.get("totalSize"),
        }

    return outputs, readable_output


def resolve_assignees(client: Client, assignees: list[str], raise_on_not_found: bool = False) -> list[str]:
    """
    Resolve a list of assignee values to their SOAR user IDs or pass through SOC roles.

    :type client: Client
    :param client: Client instance used to resolve emails to user IDs.

    :type assignees: list[str]
    :param assignees: List of email addresses or SOC roles (e.g. @Tier1).

    :type raise_on_not_found: bool
    :param raise_on_not_found: If True, raises ValueError when an email cannot be resolved.
        If False, unresolved emails are skipped and logged.

    :return: Resolved list of user IDs or SOC roles.
    :rtype: list[str]
    """
    resolved, not_found, emails = [], [], []
    for assignee in assignees:
        if not assignee.startswith("@"):
            emails.append(assignee)
        else:
            resolved.append(assignee)

    email_to_id: dict[str, str] = {}
    if emails:
        email_to_id = client.get_soar_user_ids(emails)

    for email in emails:
        resolved_id = email_to_id.get(email.lower())
        if not resolved_id:
            if raise_on_not_found:
                raise ValueError(MESSAGES["USER_NOT_FOUND"].format(email))
            not_found.append(email)
            continue
        resolved.append(resolved_id)
        demisto.debug(f"resolve_assignees: resolved '{email}' -> '{resolved_id}'.")
    if not_found:
        demisto.debug(f"resolve_assignees: no active user found for emails {not_found}, skipping.")
    return resolved


def prepare_context_hr_gcb_case_get_update(
    response: dict[str, Any], title: str = "Case Information", case_id: str = ""
) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for a single case response.
    Used by both gcb-case-get and gcb-case-update commands.

    :type response: dict[str, Any]
    :param response: Raw API response for a single case.

    :type title: str
    :param title: Title for the human-readable table.

    :type case_id: str
    :param case_id: Case ID to use when the response does not contain a ``name`` field.

    :return: Tuple of (context dict, human readable markdown string).
    :rtype: tuple[dict[str, Any], str]
    """
    parts = response.get("name", "").split("cases/")
    case_id = parts[1] if len(parts) >= 2 else case_id
    context: dict[str, Any] = response.copy()
    context["caseId"] = case_id
    context = remove_empty_elements(context)

    sla = prepare_sla_hr(response.get("sla", {}))
    alerts_sla = prepare_sla_hr(response.get("alertsSla", {}))
    priority = response.get("priority", "")
    display_priority = priority.replace("PRIORITY_", "") if priority else ""
    create_time = response.get("createTime")
    if create_time:
        create_time = epoch_ms_to_datestring(create_time, date_format=HR_DATE_FORMAT)

    update_time = response.get("updateTime")
    if update_time:
        update_time = epoch_ms_to_datestring(update_time, date_format=HR_DATE_FORMAT)

    raw_hr: dict[str, Any] = deepcopy(response)
    raw_hr["caseId"] = case_id
    raw_hr["sla"] = sla
    raw_hr["alertsSla"] = alerts_sla
    raw_hr["priority"] = display_priority
    raw_hr["createTime"] = create_time
    raw_hr["updateTime"] = update_time

    hr_data = remove_empty_elements_for_hr(raw_hr)

    headers = [
        "caseId",
        "displayName",
        "priority",
        "status",
        "stage",
        "assignee",
        "alertCount",
        "type",
        "environment",
        "source",
        "workflowStatus",
        "description",
        "sla",
        "alertsSla",
        "tags",
        "createTime",
        "updateTime",
        "score",
        "incident",
        "important",
        "involvedSuspiciousEntity",
        "overflowCase",
        "creatorUserId",
        "lastModifyingUserId",
        "products",
        "tasks",
        "closureDetails",
    ]

    readable_output = tableToMarkdown(
        title,
        hr_data,
        headers=headers,
        removeNull=True,
        sort_headers=False,
        is_auto_json_transform=True,
        headerTransform=lambda f: re.sub(r"\bId\b", "ID", pascalToSpace(f)).replace("Sla", "SLA"),
    )

    return context, readable_output


def prepare_context_hr_case_comment_list(response: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for case comment list.

    :type response: ``dict``
    :param response:  Response dictionary from API response.

    :return: Tuple of context and human readable output.
    """
    case_comments = deepcopy(response.get("caseComments", []))

    table_data: list[dict[str, Any]] = []
    for comment in case_comments:
        create_time_str = ""
        if comment.get("createTime"):
            create_time_ms = comment["createTime"]
            create_time_str = epoch_ms_to_datestring(create_time_ms, HR_DATE_FORMAT)

        author = comment.get("userOwnerFullName") or "Automation"
        table_data.append(
            {
                "Author": author,
                "Comment": comment.get("comment", ""),
                "Create Time": create_time_str,
            }
        )
        comment["commentId"] = str(comment.get("name", "")).rpartition("/")[2]

    readable_output = tableToMarkdown("Case Comments", table_data, headers=["Author", "Comment", "Create Time"], removeNull=True)

    next_page_token: str | None = response.get("nextPageToken")
    if next_page_token:
        readable_output += (
            f"\nMaximum number of comments specified in page_size has been returned. "
            f"To fetch the next set of comments, execute the command with the page token as `{next_page_token}`."
        )

    outputs: dict[str, Any] = {}
    outputs[f"{SECOPS_OUTPUT_PATHS['CaseComment']}(val.name == obj.name)"] = case_comments

    if next_page_token:
        outputs[f"{SECOPS_OUTPUT_PATHS['PageToken']}(val.command == obj.command)"] = {
            "command": "gcb-case-comment-list",
            "nextPageToken": next_page_token,
            "totalSize": response.get("totalSize"),
        }

    return remove_empty_elements(outputs), readable_output


def prepare_context_hr_case_comment_create(response: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for case comment create.

    :type response: ``dict``
    :param response: Response dictionary from API response.

    :return: Tuple of context and human readable output.
    """
    comment_data = deepcopy(response)

    create_time_hr = ""
    if comment_data.get("createTime"):
        create_time_ms = comment_data["createTime"]
        create_time_hr = epoch_ms_to_datestring(create_time_ms, date_format=HR_DATE_FORMAT)

    comment_data["commentId"] = str(comment_data.get("name", "")).rpartition("/")[2]

    case_id = comment_data.get("case", "")
    comment_text = comment_data.get("comment", "")

    readable_output = f'Successfully added the following comment to case "{case_id}" at {create_time_hr}:\n\n`{comment_text}`'

    return remove_empty_elements(comment_data), readable_output


def prepare_case_alerts_filter(
    display_names: list | None = None,
    priorities: list | None = None,
    statuses: list | None = None,
    products: list | None = None,
    vendors: list | None = None,
    environments: list | None = None,
    source_system_names: list | None = None,
    tags: list | None = None,
    manual: bool | None = None,
    filter_logic: str = DEFAULT_FILTER_LOGIC,
) -> str:
    """
    Prepare an AIP-160 filter string from case alert filter field lists.

    :type display_names: list or None
    :param display_names: List of display name values to filter by.

    :type priorities: list or None
    :param priorities: List of priority values to filter by.

    :type statuses: list or None
    :param statuses: List of status values to filter by.

    :type products: list or None
    :param products: List of product name values to filter by.

    :type vendors: list or None
    :param vendors: List of vendor name values to filter by.

    :type environments: list or None
    :param environments: List of environment values to filter by.

    :type source_system_names: list or None
    :param source_system_names: List of source system name values to filter by.

    :type tags: list or None
    :param tags: List of tag values to filter by.

    :type manual: bool or None
    :param manual: Filter by whether alerts were created manually.

    :type filter_logic: str
    :param filter_logic: Logical operator used to join conditions — "AND" or "OR".

    :return: AIP-160 filter string, or empty string if no filters are set.
    :rtype: str
    """
    join_separator = f" {filter_logic.upper()} "
    conditions = []

    field_value_pairs: list[tuple[str, list | None]] = [
        ("displayName", display_names),
        ("priority", priorities),
        ("status", statuses),
        ("product", products),
        ("vendor", vendors),
        ("environment", environments),
        ("sourceSystemName", source_system_names),
    ]

    for field, values in field_value_pairs:
        if values:
            conditions.append(or_join(field, values))

    if tags:
        conditions.append(any_filter("tags.tag", tags))

    if manual is not None:
        conditions.append(f"manual={str(manual).lower()}")

    return join_separator.join(conditions)


def prepare_case_alerts_date_filter(
    create_start_time: str | None = None,
    create_end_time: str | None = None,
    update_start_time: str | None = None,
    update_end_time: str | None = None,
) -> str:
    """
    Prepare an AIP-160 filter string from case alert date/time fields.
    Date conditions are always joined with AND.

    :type create_start_time: str or None
    :param create_start_time: Lower bound for alert create time.

    :type create_end_time: str or None
    :param create_end_time: Upper bound for alert create time.

    :type update_start_time: str or None
    :param update_start_time: Lower bound for alert update time.

    :type update_end_time: str or None
    :param update_end_time: Upper bound for alert update time.

    :return: AIP-160 filter string, or empty string if no date filters are set.
    :rtype: str
    """
    conditions = []
    if create_start_time:
        conditions.append(f"createTime>={date_to_utc_epoch(create_start_time)}")
    if create_end_time:
        conditions.append(f"createTime<={date_to_utc_epoch(create_end_time)}")
    if update_start_time:
        conditions.append(f"updateTime>={date_to_utc_epoch(update_start_time)}")
    if update_end_time:
        conditions.append(f"updateTime<={date_to_utc_epoch(update_end_time)}")
    return " AND ".join(conditions)


def prepare_context_hr_gcb_case_alert_list(response: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for gcb-case-alert-list.

    :type response: dict[str, Any]
    :param response: Raw API response containing 'caseAlerts' list.

    :return: Tuple of (outputs dict, human readable markdown string).
    :rtype: tuple[dict[str, Any], str]
    """
    case_alerts: list[dict[str, Any]] = deepcopy(response.get("caseAlerts", []))
    next_page_token = response.get("nextPageToken", "")
    total_size = response.get("totalSize")

    table_data: list[dict[str, Any]] = []
    for alert in case_alerts:
        parts = alert.get("name", "").split("caseAlerts/")
        alert["alertId"] = parts[1] if len(parts) >= 2 else ""
        create_time = alert.get("createTime")
        if create_time:
            create_time = epoch_ms_to_datestring(create_time, date_format=HR_DATE_FORMAT)
        table_data.append(
            {
                ALERT_ID_DISPLAY: alert.get("alertId", ""),
                "Alert Name": alert.get("displayName", ""),
                "Create Time": create_time,
                "Priority": alert.get("priority", ""),
                "Status": alert.get("status", ""),
                "Events Count": alert.get("eventCount", ""),
                "Alert SLA": prepare_sla_hr(alert.get("sla", {})),
                "Playbook Attached Name": alert.get("attachedPlaybookName", ""),
                "Playbook Attached Status": alert.get("playbookStatus", ""),
            }
        )

    readable_output = tableToMarkdown(
        "Case Alerts List",
        remove_empty_elements_for_hr(table_data),
        headers=[
            ALERT_ID_DISPLAY,
            "Alert Name",
            "Create Time",
            "Priority",
            "Status",
            "Events Count",
            "Alert SLA",
            "Playbook Attached Name",
            "Playbook Attached Status",
        ],
        removeNull=True,
        is_auto_json_transform=True,
    )

    if next_page_token:
        readable_output += (
            f"\nMaximum number of alerts specified in page_size has been returned. "
            f"To fetch the next set of alerts, execute the command with the page token as `{next_page_token}`."
        )

    outputs: dict[str, Any] = {}
    outputs[f"{SECOPS_OUTPUT_PATHS['CaseAlert']}(val.alertId == obj.alertId)"] = case_alerts

    if next_page_token:
        outputs[f"{SECOPS_OUTPUT_PATHS['PageToken']}(val.command == obj.command)"] = {
            "command": "gcb-case-alert-list",
            "nextPageToken": next_page_token,
            "totalSize": total_size,
        }

    return remove_empty_elements(outputs), readable_output


def prepare_context_hr_gcb_case_alert_get_update(
    response: dict[str, Any], title: str = "Case Alert Information", alert_id: str = ""
) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for gcb-case-alert-get and gcb-case-alert-update.

    :type response: dict[str, Any]
    :param response: Raw API response for a single Case Alert.

    :type title: str
    :param title: Title for the human-readable table.

    :type alert_id: str
    :param alert_id: Alert ID to use when the response does not contain a ``name`` field.

    :return: Tuple of (context dict, human readable markdown string).
    :rtype: tuple[dict[str, Any], str]
    """
    context = deepcopy(response)

    parts = response.get("name", "").split("caseAlerts/")
    alert_id = parts[1] if len(parts) >= 2 else alert_id
    context["alertId"] = alert_id

    tags = [t.get("tag") for t in response.get("tags", []) if t.get("tag")]

    raw_hr: dict[str, Any] = deepcopy(context)
    raw_hr["sla"] = prepare_sla_hr(response.get("sla", {}))
    for field in ("createTime", "updateTime", "startTime", "endTime"):
        val = raw_hr.get(field)
        raw_hr[field] = epoch_ms_to_datestring(val, date_format=HR_DATE_FORMAT) if val else None
    raw_hr["tags"] = ", ".join(tags)
    raw_hr["manual"] = response.get("manual", False)
    raw_hr["alertIdentifier"] = response.get("identifier", "")

    hr_data = remove_empty_elements_for_hr(raw_hr)

    headers = [
        "alertId",
        "caseId",
        "displayName",
        "status",
        "priority",
        "product",
        "vendor",
        "environment",
        "tags",
        "sla",
        "eventCount",
        "alertIdentifier",
        "alertGroupIdentifier",
        "playbookStatus",
        "attachedPlaybookName",
        "playbookRunCount",
        "createTime",
        "updateTime",
        "startTime",
        "endTime",
        "manual",
        "ruleGenerator",
        "ticketId",
        "sourceSystemName",
        "sourceIdentifier",
        "sourceGroupingIdentifier",
        "siemAlertId",
        "sourceUrl",
        "additionalProperties",
        "closureDetails",
        "involvedRelations",
    ]

    readable_output = tableToMarkdown(
        title,
        hr_data,
        headers=headers,
        removeNull=True,
        sort_headers=False,
        is_auto_json_transform=True,
        headerTransform=lambda f: re.sub(r"\bId\b", "ID", pascalToSpace(f)).replace("Sla", "SLA").replace("Url", "URL"),
    )

    return remove_empty_elements(context), readable_output


def prepare_context_hr_gcb_case_alert_recommendation_fetch(
    response: dict[str, Any], recommendation_id: str
) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for gcb-case-alert-recommendation-fetch.

    :type response: dict[str, Any]
    :param response: Raw API response from fetchRecommendation.

    :type recommendation_id: str
    :param recommendation_id: The ID of the recommendation.

    :return: Tuple of (context dict, human readable markdown string).
    :rtype: tuple[dict[str, Any], str]
    """

    context = deepcopy(response)
    context["recommendationId"] = recommendation_id

    hr_lines = ["### Alert Recommendation"]
    if state := response.get("state"):
        hr_lines.append(f"**State:** {state}")
    if recommendation := response.get("recommendation"):
        hr_lines.append(f"**Recommendation:**\n{recommendation}")
    if alert_id_to_case_id := response.get("alertIdentifierToCaseId"):
        formatted = "\n".join(f"- `{alert_id}`: {case_id}" for alert_id, case_id in alert_id_to_case_id.items())
        hr_lines.append(f"**Alert Identifier To Case ID:**\n{formatted}")
    if marketplace_actions := response.get("marketplaceActionsTriggeredManually"):
        hr_lines.append(f"**Marketplace Actions Triggered Manually:** {', '.join(marketplace_actions)}")

    readable_output = "\n\n---\n\n".join(hr_lines)

    return remove_empty_elements(context), readable_output


def prepare_context_hr_gcb_case_alert_customfield_list(
    response: dict[str, Any], id_to_display: dict[str, str]
) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for gcb-case-alert-customfield-list.

    :type response: dict
    :param response: Response dictionary from the customFieldValues API.

    :type id_to_display: dict[str, str]
    :param id_to_display: Mapping of custom field ID to display name from the customFields API.

    :return: Tuple of context outputs and human readable markdown string.
    :rtype: tuple[dict[str, Any], str]
    """
    custom_field_values: list[dict[str, Any]] = deepcopy(response.get("customFieldValues", []))

    hr_rows = []
    for cfv in custom_field_values:
        field_id = cfv.get("customFieldId", "")
        cfv["displayName"] = id_to_display.get(field_id, "")
        row = {
            "customFieldId": field_id,
            "displayName": cfv.get("displayName", ""),
            "values": ", ".join(cfv.get("values", [])),
            "valuesSearchText": cfv.get("valuesSearchText", ""),
        }
        hr_rows.append(row)

    headers = ["customFieldId", "displayName", "values", "valuesSearchText"]

    readable_output = tableToMarkdown(
        "Case Alert Custom Field Values",
        hr_rows,
        headers=headers,
        removeNull=True,
        sort_headers=False,
        headerTransform=lambda f: re.sub(r"\bId\b", "ID", pascalToSpace(f)),
    )

    next_page_token: str | None = response.get("nextPageToken")
    if next_page_token:
        readable_output += (
            f"\nMaximum number of custom field values specified in page_size has been returned. "
            f"To fetch the next set of custom field values, execute the command with the page token as `{next_page_token}`."
        )

    outputs: dict[str, Any] = {}
    outputs[f"{SECOPS_OUTPUT_PATHS['AlertCustomFieldValue']}(val.customFieldId == obj.customFieldId)"] = custom_field_values

    if next_page_token:
        outputs[f"{SECOPS_OUTPUT_PATHS['PageToken']}(val.command == obj.command)"] = {
            "command": "gcb-case-alert-customfield-list",
            "nextPageToken": next_page_token,
            "totalSize": response.get("totalSize"),
        }

    return remove_empty_elements(outputs), readable_output


def prepare_context_hr_case_alert_entity_list(response: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for alert entity list.

    :type response: ``dict``
    :param response: Response dictionary from API response.

    :return: Tuple of context and human readable output.
    :rtype: tuple[dict[str, Any], str]
    """
    entities = deepcopy(response.get("involvedEntities", []))

    hr_rows = []
    for entity in entities:
        hr_rows.append(remove_empty_elements_for_hr(entity))

    headers = [
        "id",
        "identifier",
        "type",
        "environment",
        "suspicious",
        "internal",
        "attacker",
        "pivot",
        "enriched",
        "artifact",
        "vulnerable",
        "manuallyCreated",
        "threatSource",
        "operatingSystem",
        "networkTitle",
        "networkPriority",
        "entityUri",
        "sourceSystemUri",
    ]

    readable_output = tableToMarkdown(
        "Alert Entities List",
        hr_rows,
        headers=headers,
        removeNull=True,
        sort_headers=False,
        is_auto_json_transform=True,
        headerTransform=lambda f: " ".join("ID" if p == "Id" else "URI" if p == "Uri" else p for p in pascalToSpace(f).split()),
    )

    next_page_token: str | None = response.get("nextPageToken")
    if next_page_token:
        readable_output += (
            f"\nMaximum number of entities specified in page_size has been returned. "
            f"To fetch the next set of entities, execute the command with the page token as `{next_page_token}`."
        )

    outputs: dict[str, Any] = {}
    outputs[f"{SECOPS_OUTPUT_PATHS['AlertEntity']}(val.id == obj.id)"] = entities

    if next_page_token:
        outputs[f"{SECOPS_OUTPUT_PATHS['PageToken']}(val.command == obj.command)"] = {
            "command": "gcb-case-alert-entity-list",
            "nextPageToken": next_page_token,
            "totalSize": response.get("totalSize"),
        }

    return remove_empty_elements(outputs), readable_output


def prepare_context_hr_case_alert_entity_get(
    response: dict[str, Any], title: str = "Entity Information", alert_id: str = ""
) -> tuple[dict[str, Any], str]:
    """
    Prepare context and human readable output for a single alert entity.

    :type response: ``dict``
    :param response: Response dictionary from API response.

    :type title: str
    :param title: Title for the human-readable table.

    :type alert_id: str
    :param alert_id: Alert ID the entity belongs to.

    :return: Tuple of context and human readable output.
    :rtype: tuple[dict[str, Any], str]
    """
    entity = deepcopy(response)
    entity["alertId"] = alert_id
    entity = remove_empty_elements(entity)

    hr_row = remove_empty_elements_for_hr(deepcopy(entity))

    headers = [
        "id",
        "identifier",
        "alertId",
        "caseId",
        "alertIdentifier",
        "type",
        "environment",
        "suspicious",
        "internal",
        "attacker",
        "pivot",
        "enriched",
        "artifact",
        "vulnerable",
        "manuallyCreated",
        "threatSource",
        "operatingSystem",
        "networkTitle",
        "networkPriority",
        "entityUri",
        "sourceSystemUri",
        "additionalProperties",
        "fields",
    ]

    readable_output = tableToMarkdown(
        title,
        hr_row,
        headers=headers,
        removeNull=True,
        sort_headers=False,
        is_auto_json_transform=True,
        headerTransform=lambda f: " ".join("ID" if p == "Id" else "URI" if p == "Uri" else p for p in pascalToSpace(f).split()),
    )

    return remove_empty_elements(entity), readable_output


def prepare_context_hr_gcb_playbook_list(response: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    """
    Prepare context and human readable output for enabled playbook list.

    :type response: ``dict``
    :param response: Response dictionary from API response.

    :return: Tuple of context list and human readable output.
    :rtype: tuple[list[dict[str, Any]], str]
    """
    playbooks = deepcopy(response.get("payload", []))

    headers = [
        "playbookName",
        "description",
        "playbookType",
        "originalWorkflowDefinitionIdentifier",
        "workflowDefinitionIdentifier",
        "isDebugMode",
    ]

    readable_output = tableToMarkdown(
        "Enabled Playbooks",
        remove_empty_elements_for_hr(playbooks),
        headers=headers,
        removeNull=True,
        sort_headers=False,
        is_auto_json_transform=True,
        headerTransform=pascalToSpace,
    )

    return remove_empty_elements(playbooks), readable_output


""" VALIDATION FUNCTIONS """


def validate_argument(value: Any, name: str) -> Any:
    """
    Check if empty value is passed for an argument and raise appropriate ValueError.

    :type value: Any
    :param value: Value of the argument.

    :type name: str
    :param name: Name of the argument.
    """
    if not value:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format(name))
    return value


def validate_configuration_parameters(params: dict[str, Any]):
    """
    Check whether entered configuration parameters are valid or not.

    :type params: dict
    :param params: Dictionary of demisto configuration parameter

    :return: raise ValueError if any configuration parameter is not in valid format else returns None
    :rtype: None
    """
    service_account_json = params.get("credentials", {}).get("password", "")
    project_instance_id = params.get("secops_project_instance_id", "")
    project_location = params.get("region", DEFAULT_REGION).lower()
    if project_location == "other":
        project_location = params.get("other_region", "").lower()

    project_number = params.get("secops_project_number", "")

    if not project_instance_id:
        raise ValueError(MESSAGES["MISSING_PROJECT_INSTANCE_ID"])
    if not project_location:
        raise ValueError(MESSAGES["MISSING_REGION"])

    if project_number and not check_valid_positive_number(project_number):
        raise ValueError(MESSAGES["INVALID_PROJECT_NUMBER"])

    try:
        json.loads(service_account_json, strict=False)
    except json.decoder.JSONDecodeError:
        raise ValueError(MESSAGES["INVALID_SERVICE_ACCOUNT_JSON"])


def validate_positive_integer_list(values: list[str], arg_name: str, display_name: str) -> list[str]:
    """
    Validate that all values in the list are positive integers.

    :type values: list[str]
    :param values: List of string values to validate.

    :type arg_name: str
    :param arg_name: Argument name of the field being validated.

    :type display_name: str
    :param display_name: Human-readable singular label for the field.

    :return: The original list if all values are valid.
    :rtype: list[str]
    """
    values = strip_and_filter_list(values)
    validate_argument(values, arg_name)
    invalid_values = [value for value in values if not check_valid_positive_number(value)]
    if invalid_values:
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format(arg_name, ", ".join(invalid_values), display_name))
    return values


def validate_date_range(
    start_time: Optional[datetime],
    start_time_arg: str,
    end_time: Optional[datetime],
    end_time_arg: str,
) -> None:
    """
    Validate that start time is not greater than end time.

    :type start_time: Optional[datetime]
    :param start_time: The start time value.

    :type start_time_arg: str
    :param start_time_arg: The argument name for start time (used in error messages).

    :type end_time: Optional[datetime]
    :param end_time: The end time value.

    :type end_time_arg: str
    :param end_time_arg: The argument name for end time (used in error messages).

    :raises ValueError: If start time is greater than end time.

    :return: None
    :rtype: None
    """
    if start_time and end_time and start_time > end_time:
        raise ValueError(MESSAGES["INVALID_DATE_RANGE"].format(start_time_arg, end_time_arg))


def validate_case_list_date_args(
    create_start_time: Optional[datetime],
    create_end_time: Optional[datetime],
    update_start_time: Optional[datetime],
    update_end_time: Optional[datetime],
) -> tuple[str, str, str, str]:
    """
    Validate date range arguments for gcb-case-list command and return formatted strings.

    :type create_start_time: Optional[datetime]
    :param create_start_time: The create start time value.

    :type create_end_time: Optional[datetime]
    :param create_end_time: The create end time value.

    :type update_start_time: Optional[datetime]
    :param update_start_time: The update start time value.

    :type update_end_time: Optional[datetime]
    :param update_end_time: The update end time value.

    :raises ValueError: If start time is greater than end time.

    :return: Formatted (create_start_time, create_end_time, update_start_time, update_end_time) strings or empty string.
    :rtype: tuple
    """
    validate_date_range(create_start_time, "create_start_time", create_end_time, "create_end_time")
    validate_date_range(update_start_time, "update_start_time", update_end_time, "update_end_time")

    return (
        create_start_time.strftime(DATE_FORMAT) if create_start_time else "",
        create_end_time.strftime(DATE_FORMAT) if create_end_time else "",
        update_start_time.strftime(DATE_FORMAT) if update_start_time else "",
        update_end_time.strftime(DATE_FORMAT) if update_end_time else "",
    )


def validate_case_alert_list_date_args(
    create_start_time: Optional[datetime],
    create_end_time: Optional[datetime],
    update_start_time: Optional[datetime] = None,
    update_end_time: Optional[datetime] = None,
) -> tuple[str, str, str, str]:
    """
    Validate date range arguments for gcb-case-alert-list command and return formatted strings.

    :type create_start_time: Optional[datetime]
    :param create_start_time: The create start time value.

    :type create_end_time: Optional[datetime]
    :param create_end_time: The create end time value.

    :type update_start_time: Optional[datetime]
    :param update_start_time: The update start time value.

    :type update_end_time: Optional[datetime]
    :param update_end_time: The update end time value.

    :raises ValueError: If start time is greater than end time.

    :return: Formatted (create_start_time, create_end_time, update_start_time, update_end_time) strings or empty string.
    :rtype: tuple
    """
    validate_date_range(create_start_time, "create_start_time", create_end_time, "create_end_time")
    validate_date_range(update_start_time, "update_start_time", update_end_time, "update_end_time")
    return (
        create_start_time.strftime(DATE_FORMAT) if create_start_time else "",
        create_end_time.strftime(DATE_FORMAT) if create_end_time else "",
        update_start_time.strftime(DATE_FORMAT) if update_start_time else "",
        update_end_time.strftime(DATE_FORMAT) if update_end_time else "",
    )


def validate_case_list_args(
    page_size: int,
    sort_by: str,
    sort_order: str,
    priorities: list[str],
    statuses: list[str],
    case_types: list[str],
    workflow_statuses: list[str],
    sla_statuses: list[str],
    alerts_sla_statuses: list[str],
    filter_logic: str = DEFAULT_FILTER_LOGIC,
) -> tuple[int, str, str, list[str], list[str], list[str], list[str], list[str], list[str], str]:
    """
    Validate arguments for gcb-case-list command.

    :type page_size: int
    :param page_size: Number of cases to return per page.

    :type sort_by: str
    :param sort_by: Field to sort results by.

    :type sort_order: str
    :param sort_order: Sort direction ('Asc' or 'Desc').

    :type priorities: list[str]
    :param priorities: List of priority filter values.

    :type statuses: list[str]
    :param statuses: List of status filter values.

    :type case_types: list[str]
    :param case_types: List of case type filter values.

    :type workflow_statuses: list[str]
    :param workflow_statuses: List of workflow status filter values.

    :type sla_statuses: list[str]
    :param sla_statuses: List of SLA status filter values.

    :type alerts_sla_statuses: list[str]
    :param alerts_sla_statuses: List of alerts SLA status filter values.

    :type filter_logic: str
    :param filter_logic: Logical operator to combine filter conditions ('AND' or 'OR').

    :raises ValueError: If any argument fails validation.

    :return: Validated (page_size, sort_by, sort_order, priorities, statuses, case_types,
        workflow_statuses, sla_statuses, alerts_sla_statuses, filter_logic)
    :rtype: tuple
    """
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES["INVALID_INT_RANGE"].format(page_size, "page_size", 1, MAX_PAGE_SIZE))

    sort_order = sort_order.title()
    if sort_order not in VALID_SORT_ORDERS:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", ", ".join(VALID_SORT_ORDERS)))

    validated_priorities = []
    for priority in priorities:
        if priority.upper() not in VALID_CASE_PRIORITIES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_PRIORITIES)))
        validated_priorities.append(f"PRIORITY_{priority.upper()}")

    validated_statuses = []
    for status in statuses:
        if status.upper() not in VALID_CASE_STATUSES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("status", ", ".join(VALID_CASE_STATUSES)))
        validated_statuses.append(status.upper())

    validated_case_types = []
    for case_type in case_types:
        if case_type.upper() not in VALID_CASE_TYPES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("type", ", ".join(VALID_CASE_TYPES)))
        validated_case_types.append(case_type.upper())

    validated_workflow_statuses = []
    for workflow_status in workflow_statuses:
        if workflow_status.upper() not in VALID_CASE_WORKFLOW_STATUSES:
            raise ValueError(
                MESSAGES["VALIDATE_SINGLE_SELECT"].format("workflow_status", ", ".join(VALID_CASE_WORKFLOW_STATUSES))
            )
        validated_workflow_statuses.append(workflow_status.upper())

    validated_sla_statuses = []
    for sla_status in sla_statuses:
        if sla_status.upper() not in VALID_CASE_SLA_STATUSES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("sla", ", ".join(VALID_CASE_SLA_STATUSES)))
        validated_sla_statuses.append(sla_status.upper())

    validated_alerts_sla_statuses = []
    for alerts_sla_status in alerts_sla_statuses:
        if alerts_sla_status.upper() not in VALID_CASE_SLA_STATUSES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("alerts_sla", ", ".join(VALID_CASE_SLA_STATUSES)))
        validated_alerts_sla_statuses.append(alerts_sla_status.upper())

    if filter_logic.upper() not in VALID_CASE_FILTER_LOGIC:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)))

    return (
        page_size,
        sort_by,
        sort_order,
        validated_priorities,
        validated_statuses,
        validated_case_types,
        validated_workflow_statuses,
        validated_sla_statuses,
        validated_alerts_sla_statuses,
        filter_logic,
    )


def validate_case_update_args(
    case_id: str,
    display_name: str,
    description: str,
    important: bool | None,
    incident: bool | None,
) -> tuple[dict[str, Any], str]:
    """
    Validate arguments for gcb-case-update and build the request body and updateMask.

    :type case_id: str
    :param case_id: Case ID to update.

    :type display_name: str
    :param display_name: Display name of the case.

    :type description: str
    :param description: Description of the case.

    :type important: bool or None
    :param important: Whether the case is marked as important.

    :type incident: bool or None
    :param incident: Whether the case is marked as an incident.

    :return: Tuple of (body dict, updateMask string).
    :rtype: tuple[dict[str, Any], str]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not any([display_name, description, important is not None, incident is not None]):
        raise ValueError(MESSAGES["AT_LEAST_ONE_REQUIRED"].format(", ".join(CASE_UPDATE_ARGS)))

    body: dict[str, Any] = {}
    mask_fields: list[str] = []

    if display_name:
        body["displayName"] = display_name
        mask_fields.append("displayName")
    if description:
        body["description"] = description
        mask_fields.append("description")
    if important is not None:
        body["important"] = important
        mask_fields.append("important")
    if incident is not None:
        body["incident"] = incident
        mask_fields.append("incident")

    update_mask = ",".join(mask_fields)
    return body, update_mask


def validate_case_tag_add_args(case_ids: list[str], tags: list[str]) -> tuple[list[str], list[str]]:
    """
    Validate and clean case_ids and tags by removing null and empty string values.

    :type case_ids: list[str]
    :param case_ids: List of case IDs.

    :type tags: list[str]
    :param tags: List of tags.

    :return: Validated and cleaned case_ids and tags.
    :rtype: tuple[list[str], list[str]]
    """
    valid_case_ids = validate_positive_integer_list(case_ids, arg_name="case_ids", display_name=CASE_ID_DISPLAY)

    valid_tags = strip_and_filter_list(tags)
    validate_argument(valid_tags, "tags")

    return valid_case_ids, valid_tags


def validate_case_priority_change_args(case_ids: list[str], priority: str) -> tuple[list[str], str]:
    """
    Validate and clean case_ids and priority.

    :type case_ids: list[str]
    :param case_ids: List of case IDs.

    :type priority: str
    :param priority: The new priority value.

    :return: Validated and cleaned case_ids and priority.
    :rtype: tuple[list[str], str]
    """
    valid_case_ids = validate_positive_integer_list(case_ids, arg_name="case_ids", display_name=CASE_ID_DISPLAY)

    valid_priority = priority.strip().upper()
    if valid_priority not in VALID_CASE_PRIORITIES:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_PRIORITIES)))

    return valid_case_ids, valid_priority


def validate_case_close_args(case_ids: list[str], close_reason: str) -> tuple[list[str], str]:
    """
    Validate and clean case_ids and close_reason.

    :type case_ids: list[str]
    :param case_ids: List of case IDs.

    :type close_reason: str
    :param close_reason: The reason for closing the cases.

    :return: Validated and cleaned case_ids and close_reason.
    :rtype: tuple[list[str], str]
    """
    valid_case_ids = validate_positive_integer_list(case_ids, arg_name="case_ids", display_name=CASE_ID_DISPLAY)

    valid_close_reason = close_reason.strip().upper()
    if valid_close_reason not in VALID_CASE_CLOSE_REASONS:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("close_reason", ", ".join(VALID_CASE_CLOSE_REASONS)))

    return valid_case_ids, valid_close_reason


def validate_case_comment_list_args(case_id: str, page_size: int, sort_order: str) -> tuple[str, int, str]:
    """
    Validate case_comment_list parameters.

    :type case_id: str
    :param case_id: The ID of the case.

    :type page_size: int
    :param page_size: Maximum number of comments to return.

    :type sort_order: str
    :param sort_order: Sort direction (Asc or Desc).

    :return: Validated case_id, page_size, and sort_order.
    :rtype: tuple[str, int, str]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES["INVALID_INT_RANGE"].format(page_size, "page_size", 1, MAX_PAGE_SIZE))

    valid_sort_order = sort_order.strip().capitalize()
    if valid_sort_order not in VALID_SORT_ORDERS:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", ", ".join(VALID_SORT_ORDERS)))

    return case_id, page_size, valid_sort_order


def validate_case_fetch_filter_params(priorities: list, statuses: list, filter_logic: str) -> tuple:
    """
    Validate and transform case filter parameters to API enum format.

    :type priorities: list
    :param priorities: List of case priority values to validate.

    :type statuses: list
    :param statuses: List of case status values to validate.

    :type filter_logic: str
    :param filter_logic: Logical operator used to join filter conditions — "AND" or "OR".

    :return: Tuple of (priorities, statuses, filter_logic) validated values.
    :rtype: tuple
    :raises ValueError: If any parameter value is not in the allowed values.
    """
    validated_priorities = []
    for priority in priorities:
        if priority.upper() not in VALID_CASE_PRIORITIES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("case_priorities", ", ".join(VALID_CASE_PRIORITIES)))
        validated_priorities.append(f"PRIORITY_{priority.upper()}")

    validated_statuses = []
    for status in statuses:
        if status.upper() not in VALID_CASE_STATUSES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("case_statuses", ", ".join(VALID_CASE_STATUSES)))
        validated_statuses.append(status.upper())

    if filter_logic not in VALID_CASE_FILTER_LOGIC:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("case_filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)))

    return validated_priorities, validated_statuses, filter_logic


def validate_fetch_params(params: dict[str, Any], is_test: bool = False) -> dict[str, Any]:
    """
    Validate and prepare the fetch incident parameters.

    :type params: dict[str, Any]
    :param params: Integration configuration parameters from demisto.params().

    :type is_test: bool
    :param is_test: Whether this is being called from test-module.

    :return: Dictionary containing validated and ready-to-use fetch parameters.
    :rtype: dict[str, Any]
    """
    first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH).strip()
    first_fetch_dt = arg_to_datetime(first_fetch, arg_name="First Fetch Time")  # type: ignore
    if first_fetch_dt.tzinfo is None:  # type: ignore
        first_fetch_dt = first_fetch_dt.replace(tzinfo=UTC)  # type: ignore
    now_utc = datetime.now(UTC)
    if first_fetch_dt > now_utc:  # type: ignore
        raise ValueError(MESSAGES["FUTURE_DATE"])
    max_first_fetch_dt = now_utc - timedelta(days=MAX_FIRST_FETCH_DAYS)
    first_fetch_clamped = False
    if any(boundary_str in first_fetch.lower() for boundary_str in MAX_FIRST_FETCH_BOUNDARY_STRINGS):
        first_fetch_dt += timedelta(minutes=1)  # type: ignore
    if first_fetch_dt < max_first_fetch_dt:  # type: ignore
        if is_test:
            raise ValueError(MESSAGES["INVALID_FIRST_FETCH"].format(first_fetch))
        first_fetch_dt = max_first_fetch_dt
        first_fetch_clamped = True
    first_fetch_time = first_fetch_dt.strftime(DATE_FORMAT)  # type: ignore

    max_fetch_ = params.get("max_fetch", DEFAULT_MAX_FETCH)
    if not check_valid_positive_number(str(max_fetch_)):
        raise ValueError(MESSAGES["INVALID_MAX_FETCH"].format(value=max_fetch_, max_limit=MAX_FETCH_LIMIT))
    max_fetch_ = int(max_fetch_)
    if max_fetch_ > MAX_FETCH_LIMIT:
        if is_test:
            raise ValueError(MESSAGES["INVALID_MAX_FETCH"].format(value=max_fetch_, max_limit=MAX_FETCH_LIMIT))
        else:
            demisto.debug(
                f"The Incidents fetch limit value is {max_fetch_}, which is greater than the maximum allowed value of "
                f"{MAX_FETCH_LIMIT}. Setting it to {MAX_FETCH_LIMIT}."
            )
    max_fetch = min(MAX_FETCH_LIMIT, max_fetch_)

    raw_priorities = strip_and_filter_list(argToList(params.get("case_priorities", "")))
    raw_statuses = strip_and_filter_list(argToList(params.get("case_statuses", "")))
    environments = strip_and_filter_list(argToList(params.get("case_environments", "")))
    tags = strip_and_filter_list(argToList(params.get("case_tags", "")))
    filter_logic = params.get("case_filter_logic", DEFAULT_FILTER_LOGIC).strip().upper()

    priorities, statuses, filter_logic = validate_case_fetch_filter_params(raw_priorities, raw_statuses, filter_logic)

    return {
        "max_fetch": max_fetch,
        "first_fetch": first_fetch_time,
        "priorities": priorities,
        "statuses": statuses,
        "environments": environments,
        "tags": tags,
        "filter_logic": filter_logic,
        "first_fetch_clamped": first_fetch_clamped,
    }


def validate_case_assign_args(client: Client, case_ids: list[str], assignee: str) -> tuple[list[str], str]:
    """
    Validate and clean case_ids and resolve the assignee for the case assign command.

    SOC roles (prefixed with '@') are passed through unchanged.
    Email addresses are resolved to their SOAR user ID via the legacySoarUsers API.

    :type client: Client
    :param client: Client instance used to resolve email to user ID.

    :type case_ids: list[str]
    :param case_ids: List of case IDs.

    :type assignee: str
    :param assignee: The assignee email address or SOC role (e.g. @Tier1).

    :return: Validated case_ids and resolved assignee value.
    :rtype: tuple[list[str], str]
    """
    valid_case_ids = validate_positive_integer_list(case_ids, arg_name="case_ids", display_name=CASE_ID_DISPLAY)

    resolved = resolve_assignees(client, [assignee], raise_on_not_found=True)

    return valid_case_ids, resolved[0]


def validate_case_alert_list_args(
    case_id: str,
    page_size: int,
    sort_order: str,
    priorities: list[str],
    statuses: list[str],
    filter_logic: str = DEFAULT_FILTER_LOGIC,
) -> tuple[str, int, str, list[str], list[str], str]:
    """
    Validate arguments for gcb-case-alert-list command.

    :type case_id: str
    :param case_id: The ID of the Case to list alerts for.

    :type page_size: int
    :param page_size: Maximum number of alerts to return.

    :type sort_order: str
    :param sort_order: Sort direction (Asc or Desc).

    :type priorities: list[str]
    :param priorities: List of priority filter values.

    :type statuses: list[str]
    :param statuses: List of status filter values.

    :type filter_logic: str
    :param filter_logic: Logical operator used to join filter conditions — "AND" or "OR".

    :raises ValueError: If any argument fails validation.

    :return: Validated (case_id, page_size, sort_order, priorities, statuses, filter_logic).
    :rtype: tuple
    """

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, "Case ID"))

    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES["INVALID_INT_RANGE"].format(page_size, "page_size", 1, MAX_PAGE_SIZE))

    valid_sort_order = sort_order.strip().title()
    if valid_sort_order not in VALID_SORT_ORDERS:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", ", ".join(VALID_SORT_ORDERS)))

    validated_priorities = []
    for priority in priorities:
        if priority.upper() not in VALID_CASE_ALERT_PRIORITIES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_ALERT_PRIORITIES)))
        validated_priorities.append(priority.upper())

    validated_statuses = []
    for status in statuses:
        if status.upper() not in VALID_CASE_ALERT_STATUSES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("status", ", ".join(VALID_CASE_ALERT_STATUSES)))
        validated_statuses.append(status.upper())

    valid_filter_logic = filter_logic.upper()
    if valid_filter_logic not in VALID_CASE_FILTER_LOGIC:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)))

    return (
        case_id,
        page_size,
        valid_sort_order,
        validated_priorities,
        validated_statuses,
        valid_filter_logic,
    )


def validate_case_alert_update_args(
    case_id: str,
    alert_id: str,
    status: str,
    priority: str,
    close_reason: str,
    close_comment: str,
    root_cause: str,
) -> tuple[dict[str, Any], str]:
    """
    Validate arguments for gcb-case-alert-update and build the request body and updateMask.

    :type case_id: str
    :param case_id: Case ID the alert belongs to.

    :type alert_id: str
    :param alert_id: Alert ID to update.

    :type status: str
    :param status: New status for the alert (OPEN or CLOSE).

    :type priority: str
    :param priority: New priority for the alert.

    :type close_reason: str
    :param close_reason: Closure reason (required when status is CLOSE).

    :type close_comment: str
    :param close_comment: Comment to add when closing.

    :type root_cause: str
    :param root_cause: Root cause for the alert closure.

    :return: Tuple of (body dict, updateMask string).
    :rtype: tuple[dict[str, Any], str]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if not any([status, priority]):
        raise ValueError(MESSAGES["AT_LEAST_ONE_REQUIRED"].format(", ".join(CASE_ALERT_UPDATE_ARGS)))

    body: dict[str, Any] = {}
    mask_fields: list[str] = []

    if status:
        valid_status = status.upper()
        if valid_status not in VALID_CASE_ALERT_STATUSES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("status", ", ".join(VALID_CASE_ALERT_STATUSES)))
        body["status"] = valid_status
        mask_fields.append("status")

        if valid_status == "CLOSE":
            if not close_reason:
                raise ValueError("close_reason is required when status is CLOSE.")
            if not root_cause:
                raise ValueError("root_cause is required when status is CLOSE.")
            valid_close_reason = close_reason.upper()
            if valid_close_reason not in VALID_CASE_ALERT_CLOSE_REASONS:
                raise ValueError(
                    MESSAGES["VALIDATE_SINGLE_SELECT"].format("close_reason", ", ".join(VALID_CASE_ALERT_CLOSE_REASONS))
                )
            closure_details: dict[str, Any] = {"reason": valid_close_reason, "rootCause": root_cause}
            if close_comment:
                closure_details["comment"] = close_comment
            body["closureDetails"] = closure_details
            mask_fields.append("closureDetails")

    if priority:
        valid_priority = priority.upper()
        if valid_priority not in VALID_CASE_ALERT_PRIORITIES:
            raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("priority", ", ".join(VALID_CASE_ALERT_PRIORITIES)))
        body["priority"] = valid_priority
        mask_fields.append("priority")

    update_mask = ",".join(mask_fields)
    return body, update_mask


def validate_case_alert_move_args(case_id: str, alert_id: str, destination_case_id: str) -> tuple[str, str, str]:
    """
    Validate case_id, alert_id, and destination_case_id for the case alert move command.

    :type case_id: str
    :param case_id: The ID of the source Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert to move.

    :type destination_case_id: str
    :param destination_case_id: The ID of the destination Case.

    :return: Validated case_id, alert_id, and destination_case_id.
    :rtype: tuple[str, str, str]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if not check_valid_positive_number(destination_case_id):
        raise ValueError(
            MESSAGES["INVALID_POSITIVE_INTEGER"].format("destination_case_id", destination_case_id, "Destination Case ID")
        )

    return case_id, alert_id, destination_case_id


def validate_case_alert_sla_set_args(
    case_id: str, alert_id: str, total_time: str, critical_time: str | None
) -> tuple[int, int | None]:
    """
    Validate arguments for the case alert SLA set command.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type total_time: str
    :param total_time: The total SLA duration string.

    :type critical_time: str | None
    :param critical_time: The critical SLA threshold string. Optional.

    :return: total_time_ms, and critical_time_ms.
    :rtype: tuple[int, int | None]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    total_time_ms = convert_time_to_ms(total_time, "total_time")
    critical_time_ms = convert_time_to_ms(critical_time, "critical_time") if critical_time else None

    if critical_time_ms is not None and total_time_ms <= critical_time_ms:
        raise ValueError("total_time must be greater than critical_time.")

    return total_time_ms, critical_time_ms


def validate_case_alert_customfield_list_args(case_id: str, alert_id: str, page_size: int) -> tuple[str, str, int]:
    """
    Validate arguments for the gcb-case-alert-customfield-list command.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type page_size: int
    :param page_size: Maximum number of custom field values to return.

    :return: Validated (case_id, alert_id, page_size).
    :rtype: tuple[str, str, int]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES["INVALID_INT_RANGE"].format(page_size, "page_size", 1, MAX_PAGE_SIZE))

    return case_id, alert_id, page_size


def validate_case_alert_entity_list_args(
    case_id: str,
    alert_id: str,
    page_size: int,
    sort_order: str,
    filter_logic: str = DEFAULT_FILTER_LOGIC,
) -> tuple[str, str, int, str, str]:
    """
    Validate arguments for the gcb-case-alert-entity-list command.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type page_size: int
    :param page_size: Maximum number of entities to return.

    :type sort_order: str
    :param sort_order: Sort direction (Asc or Desc).

    :type filter_logic: str
    :param filter_logic: Logical operator to combine filter conditions ('AND' or 'OR').

    :return: Validated (case_id, alert_id, page_size, sort_order, filter_logic).
    :rtype: tuple[str, str, int, str, str]
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES["INVALID_INT_RANGE"].format(page_size, "page_size", 1, MAX_PAGE_SIZE))

    valid_sort_order = sort_order.strip().capitalize()
    if valid_sort_order not in VALID_SORT_ORDERS:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("sort_order", ", ".join(VALID_SORT_ORDERS)))

    if filter_logic.upper() not in VALID_CASE_FILTER_LOGIC:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("filter_logic", ", ".join(VALID_CASE_FILTER_LOGIC)))

    return case_id, alert_id, page_size, valid_sort_order, filter_logic.upper()


def validate_case_alert_entity_get_args(case_id: str, alert_id: str, entity_id: str) -> None:
    """
    Validate arguments for the gcb-case-alert-entity-get command.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type entity_id: str
    :param entity_id: The ID of the Involved Entity.

    :rtype: None
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if not check_valid_positive_number(entity_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", entity_id, ENTITY_ID_DISPLAY))


def validate_case_alert_entity_create_args(case_id: str, alert_id: str) -> None:
    """
    Validate arguments for the gcb-case-alert-entity-create command.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :rtype: None
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))


def validate_case_alert_entity_update_args(case_id: str, alert_id: str, entity_id: str) -> None:
    """
    Validate arguments for the gcb-case-alert-entity-update command.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type entity_id: str
    :param entity_id: The ID of the Involved Entity.

    :rtype: None
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if not check_valid_positive_number(entity_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", entity_id, ENTITY_ID_DISPLAY))


def validate_case_alert_entity_property_args(case_id: str, alert_id: str, entity_id: str) -> None:
    """
    Validate arguments for the gcb-case-alert-entity-property-add and gcb-case-alert-entity-property-update commands.

    :type case_id: str
    :param case_id: The ID of the Case.

    :type alert_id: str
    :param alert_id: The ID of the Case Alert.

    :type entity_id: str
    :param entity_id: The ID of the Involved Entity.

    :rtype: None
    """
    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    if not check_valid_positive_number(entity_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("entity_id", entity_id, ENTITY_ID_DISPLAY))


""" COMMAND FUNCTIONS """


def fetch_incidents(
    client: Client, params: dict[str, Any], last_run: dict[str, Any], is_test: bool = False
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch Google SecOps Cases and convert them into XSOAR incidents.

    :type client: Client
    :param client: Client object to interact with the Google SecOps API.

    :type params: dict[str, Any]
    :param params: Integration configuration parameters from demisto.params().

    :type last_run: dict[str, Any]
    :param last_run: Last run state from demisto.getLastRun().

    :type is_test: bool
    :param is_test: Indicates whether to test the connection to the Google SecOps server.

    :return: Tuple of (list of incidents, next last_run dict).
    :rtype: tuple[list[dict[str, Any]], dict[str, Any]]
    """
    validated_params = validate_fetch_params(params, is_test=is_test)

    max_fetch = validated_params.get("max_fetch", DEFAULT_MAX_FETCH)
    first_fetch_time = validated_params.get("first_fetch")
    priorities = validated_params.get("priorities")
    statuses = validated_params.get("statuses")
    environments = validated_params.get("environments")
    tags = validated_params.get("tags")
    filter_logic: str = validated_params.get("filter_logic", DEFAULT_FILTER_LOGIC)
    first_fetch_clamped: bool = validated_params.get("first_fetch_clamped", False)

    cases_state = last_run.get("cases", {})

    # Check if filter configuration changed from last fetch cycle; if yes, reset the page_token.
    current_filter_hash = compute_cases_filter_hash(priorities, statuses, environments, tags, filter_logic)
    stored_filter_hash = cases_state.get("filter_hash")
    filter_config_changed = stored_filter_hash is not None and stored_filter_hash != current_filter_hash

    raw_last_case_create_time = cases_state.get("last_case_create_time")
    stored_last_case_create_time = (
        arg_to_datetime(raw_last_case_create_time).strftime(DATE_FORMAT)  # type: ignore
        if raw_last_case_create_time
        else ""
    )

    if filter_config_changed:
        demisto.debug("Fetch Cases: Filter config changed. Resetting page_token.")

    page_token = None if filter_config_changed else cases_state.get("page_token")
    ingested_case_ids: list = cases_state.get("ingested_case_ids", [])

    last_run_start_time = cases_state.get("start_time")
    start_dt = arg_to_datetime(last_run_start_time or first_fetch_time)
    start_time = start_dt.strftime(DATE_FORMAT)  # type: ignore

    if not last_run_start_time:
        demisto.debug(f"Fetch Cases: No start_time in last run. Using first_fetch_time={first_fetch_time} as start_time.")
        if first_fetch_clamped:
            demisto.debug(
                f"Fetch Cases: First fetch value is older than {MAX_FIRST_FETCH_DAYS} days. "
                f"Setting it to {MAX_FIRST_FETCH_DAYS} days."
            )

    demisto.debug(f"Fetch Cases: start_time={start_time}, page_token={page_token}, max_fetch={max_fetch}")

    case_filter = prepare_cases_filter(
        priorities=priorities,
        statuses=statuses,
        environments=environments,
        tags=tags,
        filter_logic=filter_logic,
    )
    filter_start_time = stored_last_case_create_time if filter_config_changed and stored_last_case_create_time else start_time
    if filter_config_changed and stored_last_case_create_time:
        demisto.debug(
            f"Fetch Cases: Filter config changed. Using last_case_create_time={stored_last_case_create_time} as start_time."
        )
    epoch_time = date_to_utc_epoch(filter_start_time, DATE_FORMAT)
    time_filter = f"createTime>={epoch_time}"
    case_filter = f"({case_filter}) AND {time_filter}" if case_filter else time_filter

    response = client.list_cases(
        page_size=max_fetch,
        case_filter=case_filter,
        page_token=page_token,
        order_by="createTime asc",
    )

    cases = response.get("cases", [])
    next_page_token = response.get("nextPageToken")

    demisto.debug(f"Fetch Cases: Retrieved {len(cases)} cases. next_page_token present: {bool(next_page_token)}")

    if is_test:
        return [], {}

    incidents: list[dict[str, Any]] = []
    ingested_cases, duplicate_cases = [], []
    last_case_create_time: str = ""

    for case in cases:
        parts = case.get("name", "").split("cases/")
        case_id = parts[1] if len(parts) >= 2 else ""

        if not case_id:
            demisto.debug(f"Fetch Cases: Skipping case with missing or empty ID. Raw name: {case.get('name', '')}")
            continue

        if case_id in ingested_case_ids:
            duplicate_cases.append(case_id)
            continue

        case["caseId"] = case_id
        processed_incident: dict[str, Any] = case.copy()

        priority = case.get("priority", "PRIORITY_UNSPECIFIED")
        processed_incident["severity"] = CASE_SEVERITY_MAP.get(priority, 0)
        raw_create_time = processed_incident.get("createTime")
        create_time = arg_to_datetime(raw_create_time or "now").strftime(DATE_FORMAT)  # type: ignore
        if raw_create_time:
            last_case_create_time = create_time

        incidents.append(
            {
                "name": f"Google SecOps Case: {case.get('displayName', case_id)}",
                "occurred": create_time,
                "rawJSON": json.dumps(remove_empty_elements_for_fetch(processed_incident)),
                "severity": processed_incident.get("severity"),
                "dbotMirrorId": f"case-{case_id}",
            }
        )
        ingested_case_ids.append(case_id)
        ingested_cases.append(case_id)

    demisto.debug(f"Fetch Cases: Successfully fetched {len(ingested_cases)} cases.")
    multiline_logs_for_list(ingested_cases, "Ingested Cases: ")
    demisto.debug(f"Fetch Cases: Skipped {len(duplicate_cases)} duplicate cases.")
    multiline_logs_for_list(duplicate_cases, "Duplicate Cases: ")

    next_cases_state: dict[str, Any] = {
        "start_time": filter_start_time,
        "ingested_case_ids": ingested_case_ids,
        "filter_hash": current_filter_hash,
        "last_case_create_time": last_case_create_time or stored_last_case_create_time,
    }
    if next_page_token:
        next_cases_state["page_token"] = next_page_token
        demisto.debug("Fetch Cases: More pages available. Storing page_token for next cycle.")

    next_state: dict[str, Any] = last_run.copy()
    next_state["cases"] = next_cases_state

    demisto.debug(
        f"Fetch Cases: Checkpoint last run - start_time: {next_cases_state.get('start_time')}, "
        f"page_token: {next_cases_state.get('page_token')}, "
        f"last_case_create_time: {next_cases_state.get('last_case_create_time')}, "
        f"filter_hash: {next_cases_state.get('filter_hash')}"
    )

    return incidents, next_state


def test_module(client: Client, params: dict[str, Any]) -> str:
    """
    Tests API connectivity and validity of provided parameters.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: Client
    :param client: Google SecOps Case client to use.

    :type params: dict[str, Any]
    :param params: Integration configuration parameters from demisto.params().

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: str
    """
    if argToBoolean(params.get("isFetch", False)):
        fetch_incidents(client, params, last_run={}, is_test=True)
    else:
        client.list_cases(page_size=1)
    return "ok"


def gcb_case_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of Cases.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing optional filter and pagination parameters.

    Returns:
        CommandResults with readable output and context data.
    """
    page_size: int = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), "page_size")  # type: ignore
    page_token = args.get("page_token")
    sort_by = args.get("sort_by", DEFAULT_CASE_LIST_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_CASE_LIST_SORT_ORDER)
    advanced_filter = args.get("advanced_filter", "")

    priorities = strip_and_filter_list(argToList(args.get("priority", "")))
    statuses = strip_and_filter_list(argToList(args.get("status", "")))
    case_types = strip_and_filter_list(argToList(args.get("type", "")))
    stages = strip_and_filter_list(argToList(args.get("stage", "")))
    sources = strip_and_filter_list(argToList(args.get("source", "")))
    raw_assignees = strip_and_filter_list(argToList(args.get("assignee", "")))
    environments = strip_and_filter_list(argToList(args.get("environment", "")))
    tags = strip_and_filter_list(argToList(args.get("tags", "")))
    products = strip_and_filter_list(argToList(args.get("products", "")))
    display_names = strip_and_filter_list(argToList(args.get("display_name", "")))
    filter_logic = args.get("filter_logic", DEFAULT_FILTER_LOGIC)
    workflow_statuses = strip_and_filter_list(argToList(args.get("workflow_status", "")))
    sla_statuses = strip_and_filter_list(argToList(args.get("sla", "")))
    alerts_sla_statuses = strip_and_filter_list(argToList(args.get("alerts_sla", "")))
    important: bool | None = arg_to_bool_or_none(args.get("important"))
    incident: bool | None = arg_to_bool_or_none(args.get("incident"))

    create_start_time_dt = arg_to_datetime(args.get("create_start_time"), arg_name="create_start_time")  # type: ignore
    create_end_time_dt = arg_to_datetime(args.get("create_end_time"), arg_name="create_end_time")  # type: ignore
    update_start_time_dt = arg_to_datetime(args.get("update_start_time"), arg_name="update_start_time")  # type: ignore
    update_end_time_dt = arg_to_datetime(args.get("update_end_time"), arg_name="update_end_time")  # type: ignore

    create_start_time, create_end_time, update_start_time, update_end_time = validate_case_list_date_args(
        create_start_time_dt, create_end_time_dt, update_start_time_dt, update_end_time_dt
    )

    (
        page_size,
        sort_by,
        sort_order,
        priorities,
        statuses,
        case_types,
        workflow_statuses,
        sla_statuses,
        alerts_sla_statuses,
        filter_logic,
    ) = validate_case_list_args(
        page_size,
        sort_by,
        sort_order,
        priorities,
        statuses,
        case_types,
        workflow_statuses,
        sla_statuses,
        alerts_sla_statuses,
        filter_logic,
    )

    if advanced_filter:
        case_filter = advanced_filter
    else:
        assignees = resolve_assignees(client, raw_assignees)
        case_filter = prepare_cases_filter(
            display_names=display_names,
            priorities=priorities,
            statuses=statuses,
            case_types=case_types,
            stages=stages,
            sources=sources,
            assignees=assignees,
            environments=environments,
            tags=tags,
            products=products,
            important=important,
            incident=incident,
            workflow_statuses=workflow_statuses,
            sla_statuses=sla_statuses,
            alerts_sla_statuses=alerts_sla_statuses,
            filter_logic=filter_logic,
        )
        date_filter = prepare_cases_date_filter(
            create_start_time=create_start_time,
            create_end_time=create_end_time,
            update_start_time=update_start_time,
            update_end_time=update_end_time,
        )
        if date_filter:
            case_filter = f"({case_filter}) AND {date_filter}" if case_filter else date_filter

    order_by = f"{sort_by} {sort_order.lower()}"

    response = client.list_cases(page_size=page_size, case_filter=case_filter, page_token=page_token, order_by=order_by)

    cases = response.get("cases", [])

    if not cases:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("cases"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_gcb_case_list(response)

    return CommandResults(
        outputs=remove_empty_elements(outputs),
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve a specific Case by its ID.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    response = client.get_case(case_id)

    if not response:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("case information"))

    context, readable_output = prepare_context_hr_gcb_case_get_update(response)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=context,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update the properties of a Case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and optional update fields.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    display_name = args.get("display_name", "")
    description = args.get("description", "")
    important = arg_to_bool_or_none(args.get("important"))
    incident = arg_to_bool_or_none(args.get("incident"))

    body, update_mask = validate_case_update_args(case_id, display_name, description, important, incident)

    response = client.update_case(case_id, body, update_mask)

    context, readable_output = prepare_context_hr_gcb_case_get_update(response, title="Updated Case Information", case_id=case_id)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=context,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_tag_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add the specified tags to the cases in bulk.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_ids and tags.

    Returns:
        CommandResults with readable output and context data.
    """
    case_ids = argToList(validate_argument(args.get("case_ids"), "case_ids"))
    tags = argToList(validate_argument(args.get("tags"), "tags"))

    case_ids, tags = validate_case_tag_add_args(case_ids, tags)

    client.case_tag_add(case_ids, tags)

    outputs = [{"caseId": case_id, "recentlyAddedTags": tags} for case_id in case_ids]
    readable_output = f"Tags {', '.join(tags)} successfully added to cases {', '.join(case_ids)}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_tag_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Remove the specified tag from a Case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and tag.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    tag = validate_argument(args.get("tag"), "tag")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    client.case_tag_remove(case_id, tag)

    outputs = {"caseId": case_id, "recentlyRemovedTag": tag}
    readable_output = f"Tag {tag} successfully removed from case {case_id}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_priority_change_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Change the priority of the specified cases in bulk.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_ids and priority.

    Returns:
        CommandResults with readable output and context data.
    """
    case_ids = argToList(validate_argument(args.get("case_ids"), "case_ids"))
    priority = validate_argument(args.get("priority"), "priority")

    case_ids, priority = validate_case_priority_change_args(case_ids, priority)

    client.case_priority_change(case_ids, priority)

    outputs = [{"caseId": case_id, "priority": priority} for case_id in case_ids]
    readable_output = f"Priority of cases {', '.join(case_ids)} successfully changed to {priority}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_stage_definition_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List case stage definitions configured in the instance.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments (unused).

    Returns:
        CommandResults with readable output and context data.
    """
    response = client.case_stage_definitions_list()

    case_stage_definitions = response.get("caseStageDefinitions", [])
    display_names = [s.get("displayName") for s in case_stage_definitions if s.get("displayName")]
    readable_output = f"Case Stage Definitions: {', '.join(display_names)}"

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseStageDefinition"],
        outputs=display_names,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_stage_change_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Change the workflow stage of the specified cases in bulk.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_ids and stage.

    Returns:
        CommandResults with readable output and context data.
    """
    case_ids = argToList(validate_argument(args.get("case_ids"), "case_ids"))
    stage = validate_argument(args.get("stage"), "stage")

    case_ids = validate_positive_integer_list(case_ids, arg_name="case_ids", display_name=CASE_ID_DISPLAY)

    client.case_stage_change(case_ids, stage)

    outputs = [{"caseId": case_id, "stage": stage} for case_id in case_ids]
    readable_output = f"Stage of cases {', '.join(case_ids)} successfully changed to {stage}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_reopen_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Reopen the specified cases in bulk.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_ids and reopen_comment.

    Returns:
        CommandResults with readable output and context data.
    """
    case_ids = argToList(validate_argument(args.get("case_ids"), "case_ids"))
    reopen_comment = validate_argument(args.get("reopen_comment"), "reopen_comment")

    case_ids = validate_positive_integer_list(case_ids, arg_name="case_ids", display_name=CASE_ID_DISPLAY)

    client.case_reopen(case_ids, reopen_comment)

    outputs = [{"caseId": case_id, "status": "OPENED"} for case_id in case_ids]
    readable_output = f"Cases {', '.join(case_ids)} successfully reopened."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_close_definition_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List case close definitions configured in the instance.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments (unused).

    Returns:
        CommandResults with readable output and context data.
    """
    response = client.case_close_definitions_list()

    case_close_definitions = response.get("caseCloseDefinitions", [])

    if not case_close_definitions:
        readable_output = MESSAGES["NO_RECORDS_FOUND"].format("case close definitions")
        return CommandResults(
            outputs_prefix=SECOPS_OUTPUT_PATHS["CaseCloseDefinition"],
            outputs=[],
            readable_output=readable_output,
            raw_response=response,
        )

    table_data = []
    for definition in case_close_definitions:
        table_data.append(
            {
                "Close Reason": definition.get("closeReason", ""),
                "Root Cause": definition.get("rootCause", ""),
            }
        )

    readable_output = tableToMarkdown(
        "Case Close Definitions", table_data, headers=["Close Reason", "Root Cause"], removeNull=True
    )

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseCloseDefinition"],
        outputs=case_close_definitions,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_close_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Close the specified cases in bulk.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_ids, close_reason, root_cause, and optional close_comment.

    Returns:
        CommandResults with readable output and context data.
    """
    case_ids = argToList(validate_argument(args.get("case_ids"), "case_ids"))
    close_reason = validate_argument(args.get("close_reason"), "close_reason")
    root_cause = validate_argument(args.get("root_cause"), "root_cause")
    close_comment = args.get("close_comment")

    case_ids, close_reason = validate_case_close_args(case_ids, close_reason)

    client.case_close(case_ids, close_reason, root_cause, close_comment)

    outputs = [
        {
            "caseId": case_id,
            "status": "CLOSED",
            "closureDetails": {
                "reason": close_reason,
                "rootCause": root_cause,
                "comment": close_comment if close_comment else None,
            },
        }
        for case_id in case_ids
    ]
    outputs = remove_empty_elements(outputs)
    readable_output = f"Cases {', '.join(case_ids)} successfully closed with reason {close_reason}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_assign_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Assign the specified cases to an analyst or SOC role.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_ids and assignee.

    Returns:
        CommandResults with readable output and context data.
    """
    case_ids = argToList(validate_argument(args.get("case_ids"), "case_ids"))
    assignee = validate_argument(args.get("assignee"), "assignee")

    case_ids, resolved_user = validate_case_assign_args(client, case_ids, assignee)

    client.case_assign(case_ids, resolved_user)

    outputs = [{"caseId": case_id, "assignee": resolved_user} for case_id in case_ids]
    readable_output = f"Cases {', '.join(case_ids)} successfully assigned to {assignee}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_comment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of comments for a specified case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and optional pagination/sorting parameters.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    page_size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), "page_size") or DEFAULT_PAGE_SIZE
    page_token = args.get("page_token")
    sort_by = args.get("sort_by", DEFAULT_COMMENT_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_COMMENT_SORT_ORDER)

    case_id, page_size, sort_order = validate_case_comment_list_args(case_id, page_size, sort_order)

    response = client.case_comments_list(case_id, page_size, page_token, sort_by, sort_order)

    case_comments = response.get("caseComments", [])

    if not case_comments:
        readable_output = MESSAGES["NO_RECORDS_FOUND"].format("case comments")
        return CommandResults(
            readable_output=readable_output,
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_case_comment_list(response)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_comment_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add a comment to the specified case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and comment.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    comment = validate_argument(args.get("comment"), "comment")

    response = client.case_comment_create(case_id, comment)

    outputs, readable_output = prepare_context_hr_case_comment_create(response)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseComment"],
        outputs_key_field="name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_sla_pause_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Pause the SLA timer for the specified case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and optional message.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    message = args.get("message")

    client.case_sla_pause(case_id, message)

    outputs = {"caseId": case_id, "slaStatus": "PAUSED"}
    readable_output = f"SLA timer for case {case_id} successfully paused."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_sla_resume_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Resume the SLA timer for the specified case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    client.case_sla_resume(case_id)

    outputs = {"caseId": case_id, "slaStatus": "SLA_EXPIRATION_STATUS_UNSPECIFIED"}
    readable_output = f"SLA timer for case {case_id} successfully resumed."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Case"],
        outputs_key_field="caseId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_alert_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of Case Alerts associated with a specific Case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and optional filter/pagination parameters.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    page_size: int = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), "page_size")  # type: ignore
    page_token = args.get("page_token")
    sort_by = args.get("sort_by", DEFAULT_CASE_ALERT_LIST_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_CASE_ALERT_LIST_SORT_ORDER)
    advanced_filter = args.get("advanced_filter", "")

    display_names = strip_and_filter_list(argToList(args.get("display_name", "")))
    priorities = strip_and_filter_list(argToList(args.get("priority", "")))
    statuses = strip_and_filter_list(argToList(args.get("status", "")))
    products = strip_and_filter_list(argToList(args.get("product", "")))
    vendors = strip_and_filter_list(argToList(args.get("vendor", "")))
    environments = strip_and_filter_list(argToList(args.get("environment", "")))
    source_system_names = strip_and_filter_list(argToList(args.get("source_system_name", "")))
    tags = strip_and_filter_list(argToList(args.get("tag", "")))
    manual: bool | None = arg_to_bool_or_none(args.get("manual"))
    filter_logic = args.get("filter_logic", DEFAULT_FILTER_LOGIC)

    create_start_time_dt = arg_to_datetime(args.get("create_start_time"), arg_name="create_start_time")  # type: ignore
    create_end_time_dt = arg_to_datetime(args.get("create_end_time"), arg_name="create_end_time")  # type: ignore
    update_start_time_dt = arg_to_datetime(args.get("update_start_time"), arg_name="update_start_time")  # type: ignore
    update_end_time_dt = arg_to_datetime(args.get("update_end_time"), arg_name="update_end_time")  # type: ignore

    create_start_time, create_end_time, update_start_time, update_end_time = validate_case_alert_list_date_args(
        create_start_time_dt, create_end_time_dt, update_start_time_dt, update_end_time_dt
    )

    case_id, page_size, sort_order, priorities, statuses, filter_logic = validate_case_alert_list_args(
        case_id, page_size, sort_order, priorities, statuses, filter_logic
    )

    if advanced_filter:
        alert_filter = advanced_filter
    else:
        alert_filter = prepare_case_alerts_filter(
            display_names=display_names,
            priorities=priorities,
            statuses=statuses,
            products=products,
            vendors=vendors,
            environments=environments,
            source_system_names=source_system_names,
            tags=tags,
            manual=manual,
            filter_logic=filter_logic,
        )
        date_filter = prepare_case_alerts_date_filter(
            create_start_time=create_start_time,
            create_end_time=create_end_time,
            update_start_time=update_start_time,
            update_end_time=update_end_time,
        )
        if date_filter:
            alert_filter = f"({alert_filter}) AND {date_filter}" if alert_filter else date_filter

    order_by = f"{sort_by} {sort_order}"

    response = client.list_case_alerts(
        case_id=case_id,
        page_size=page_size,
        page_token=page_token,
        alert_filter=alert_filter,
        order_by=order_by,
    )

    case_alerts = response.get("caseAlerts", [])

    if not case_alerts:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("case alerts"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_gcb_case_alert_list(response)

    return CommandResults(
        outputs=remove_empty_elements(outputs),
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve detailed information about a specific Case Alert by its ID.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and alert_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    response = client.get_case_alert(case_id, alert_id)

    if not response:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("case alert information"))

    context, readable_output = prepare_context_hr_gcb_case_alert_get_update(response)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=context,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update the properties of an existing Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id and optional update fields.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    status = args.get("status", "")
    priority = args.get("priority", "")
    close_reason = args.get("close_reason", "")
    close_comment = args.get("close_comment", "")
    root_cause = args.get("root_cause", "")

    body, update_mask = validate_case_alert_update_args(
        case_id, alert_id, status, priority, close_reason, close_comment, root_cause
    )

    response = client.update_case_alert(case_id, alert_id, body, update_mask)

    context, readable_output = prepare_context_hr_gcb_case_alert_get_update(
        response, title="Updated Case Alert Information", alert_id=alert_id
    )

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=context,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_tag_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add a tag to a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and tag.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    tag = validate_argument(args.get("tag"), "tag")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    client.case_alert_tag_add(case_id, alert_id, tag)

    outputs = {"alertId": alert_id, "caseId": int(case_id), "recentlyAddedTag": tag}
    readable_output = f"Tag {tag} successfully added to alert {alert_id}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_alert_tag_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Remove a tag from a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and tag.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    tag = validate_argument(args.get("tag"), "tag")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    client.case_alert_tag_remove(case_id, alert_id, tag)

    outputs = {"alertId": alert_id, "caseId": int(case_id), "recentlyRemovedTag": tag}
    readable_output = f"Tag {tag} successfully removed from alert {alert_id}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_alert_move_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Move a Case Alert to a different Case.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and destination_case_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    destination_case_id = validate_argument(args.get("destination_case_id"), "destination_case_id")

    case_id, alert_id, destination_case_id = validate_case_alert_move_args(case_id, alert_id, destination_case_id)

    response = client.case_alert_move(case_id, alert_id, destination_case_id)

    errors = response.get("errors", [])
    if errors:
        raise DemistoException("\n".join(errors))

    new_case_id = response.get("newCaseId")
    outputs = {
        "alertId": alert_id,
        "caseId": int(new_case_id),  # type: ignore
    }
    readable_output = f"Successfully moved Alert `{alert_id}` to Case `{new_case_id}`."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_sla_pause_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Pause the SLA timer for the specified Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and optional message.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))
    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    message = args.get("message")

    client.case_alert_sla_pause(case_id, alert_id, message)

    outputs = {"alertId": alert_id, "caseId": int(case_id), "slaExpirationStatus": "PAUSED"}
    readable_output = f"SLA timer for alert {alert_id} successfully paused."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_alert_sla_resume_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Resume the SLA timer for the specified Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and alert_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))
    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    client.case_alert_sla_resume(case_id, alert_id)

    outputs = {"alertId": alert_id, "caseId": int(case_id), "slaExpirationStatus": "SLA_EXPIRATION_STATUS_UNSPECIFIED"}
    readable_output = f"SLA timer for alert {alert_id} successfully resumed."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_alert_sla_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Set the SLA parameters for the specified Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, total_time, and optional critical_time.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    total_time = validate_argument(args.get("total_time"), "total_time")
    critical_time = args.get("critical_time")

    total_time_ms, critical_time_ms = validate_case_alert_sla_set_args(case_id, alert_id, total_time, critical_time)

    client.case_alert_sla_set(case_id, alert_id, total_time_ms, critical_time_ms)

    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    outputs: dict[str, Any] = {
        "alertId": alert_id,
        "caseId": int(case_id),
        "slaExpirationTime": str(now_ms + total_time_ms),
    }
    if critical_time_ms is not None:
        outputs["slaCriticalExpirationTime"] = str(now_ms + critical_time_ms)

    readable_output = f"SLA for Alert `{alert_id}` successfully set."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["CaseAlert"],
        outputs_key_field="alertId",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=outputs,
    )


def gcb_case_alert_recommendation_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Initiate an asynchronous AI recommendation for a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and alert_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    if not check_valid_positive_number(alert_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("alert_id", alert_id, ALERT_ID_DISPLAY))

    response = client.case_alert_recommendation_create(case_id, alert_id)

    recommendation_id = response.get("recommendationId", "")

    readable_output = (
        f"Successfully created the recommendation for the alert {alert_id}.\n\nRecommendation ID: {recommendation_id}"
    )

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["AlertRecommendation"],
        outputs_key_field="recommendationId",
        outputs=remove_empty_elements(response),
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_recommendation_fetch_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Fetch a previously generated AI recommendation for a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id and recommendation_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    recommendation_id = validate_argument(args.get("recommendation_id"), "recommendation_id")

    if not check_valid_positive_number(case_id):
        err_msg = MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY)
        raise ValueError(err_msg)

    response = client.case_alert_fetch_recommendation(case_id, recommendation_id)

    if not response:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("alert recommendation"))

    context, readable_output = prepare_context_hr_gcb_case_alert_recommendation_fetch(response, recommendation_id)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["AlertRecommendation"],
        outputs_key_field="recommendationId",
        outputs=context,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_customfield_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of custom field values associated with a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and optional pagination parameters.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    page_size: int = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), "page_size")  # type: ignore
    page_token = args.get("page_token")

    case_id, alert_id, page_size = validate_case_alert_customfield_list_args(case_id, alert_id, page_size)

    response = client.case_alert_customfield_list(
        case_id=case_id,
        alert_id=alert_id,
        page_size=page_size,
        page_token=page_token,
        order_by="customFieldId asc",
    )

    custom_field_values = response.get("customFieldValues", [])

    if not custom_field_values:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("custom field values"),
            raw_response=response,
        )

    field_ids = list({cfv.get("customFieldId") for cfv in custom_field_values if cfv.get("customFieldId")})
    custom_field_id_to_display_name: dict[str, str] = {}
    if field_ids:
        filter_expr = " OR ".join(f"id = {fid}" for fid in field_ids)
        custom_fields_response = client.list_custom_fields(
            page_size=len(field_ids),
            custom_field_filter=f"({filter_expr})",
        )
        for field in custom_fields_response.get("customFields", []):
            fid = field.get("id", "")
            if fid:
                custom_field_id_to_display_name[fid] = field.get("displayName", "")

    outputs, readable_output = prepare_context_hr_gcb_case_alert_customfield_list(response, custom_field_id_to_display_name)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_entity_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of Entities associated with a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and optional filter/pagination parameters.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    page_size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE), "page_size") or DEFAULT_PAGE_SIZE
    page_token = args.get("page_token")
    sort_by = args.get("sort_by", DEFAULT_ALERT_ENTITY_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_ALERT_ENTITY_SORT_ORDER)
    filter_logic = args.get("filter_logic", DEFAULT_FILTER_LOGIC)
    advanced_filter = args.get("advanced_filter", "")

    entity_types = strip_and_filter_list(argToList(args.get("entity_type", "")))
    threat_sources = strip_and_filter_list(argToList(args.get("threat_source", "")))
    operating_systems = strip_and_filter_list(argToList(args.get("operating_system", "")))
    network_titles = strip_and_filter_list(argToList(args.get("network_title", "")))
    network_priorities = strip_and_filter_list(argToList(args.get("network_priority", "")))
    environments = strip_and_filter_list(argToList(args.get("environment", "")))

    suspicious: bool | None = arg_to_bool_or_none(args.get("suspicious"))
    internal: bool | None = arg_to_bool_or_none(args.get("internal"))
    attacker: bool | None = arg_to_bool_or_none(args.get("attacker"))
    pivot: bool | None = arg_to_bool_or_none(args.get("pivot"))
    enriched: bool | None = arg_to_bool_or_none(args.get("enriched"))
    artifact: bool | None = arg_to_bool_or_none(args.get("artifact"))
    vulnerable: bool | None = arg_to_bool_or_none(args.get("vulnerable"))
    manually_created: bool | None = arg_to_bool_or_none(args.get("manually_created"))

    case_id, alert_id, page_size, sort_order, filter_logic = validate_case_alert_entity_list_args(
        case_id, alert_id, page_size, sort_order, filter_logic
    )

    if advanced_filter:
        entity_filter = advanced_filter
    else:
        entity_filter = prepare_alert_entity_filter(
            entity_types=entity_types,
            suspicious=suspicious,
            internal=internal,
            attacker=attacker,
            pivot=pivot,
            enriched=enriched,
            artifact=artifact,
            vulnerable=vulnerable,
            manually_created=manually_created,
            threat_sources=threat_sources,
            operating_systems=operating_systems,
            network_titles=network_titles,
            network_priorities=network_priorities,
            environments=environments,
            filter_logic=filter_logic,
        )

    order_by = f"{sort_by} {sort_order.lower()}"

    response = client.case_alert_involved_entities_list(
        case_id=case_id,
        alert_id=alert_id,
        page_size=page_size,
        page_token=page_token,
        entity_filter=entity_filter or None,
        order_by=order_by,
    )

    entities = response.get("involvedEntities", [])

    if not entities:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("alert entities"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_case_alert_entity_list(response)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_entity_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve detailed information about a specific Involved Entity in a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, and entity_id.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    entity_id = validate_argument(args.get("entity_id"), "entity_id")

    validate_case_alert_entity_get_args(case_id, alert_id, entity_id)

    response = client.case_alert_involved_entity_get(case_id=case_id, alert_id=alert_id, entity_id=entity_id)

    if not response:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("entity information"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_case_alert_entity_get(response, alert_id=alert_id)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["AlertEntity"],
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_entity_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Manually create a new Involved Entity within a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, entity_type, and optional fields.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    identifier = validate_argument(args.get("identifier"), "identifier")
    entity_type = validate_argument(args.get("entity_type"), "entity_type")

    suspicious = arg_to_bool_or_none(args.get("suspicious", False))
    internal = arg_to_bool_or_none(args.get("internal", False))
    attacker = arg_to_bool_or_none(args.get("attacker"))
    pivot = arg_to_bool_or_none(args.get("pivot"))
    operating_system = args.get("operating_system") or None
    network_title = args.get("network_title") or None
    threat_source = args.get("threat_source") or None

    validate_case_alert_entity_create_args(case_id, alert_id)

    network_priority = arg_to_number(args.get("network_priority"), "network_priority")
    if network_priority is not None and network_priority < 0:
        raise ValueError(MESSAGES["INVALID_NON_NEGATIVE_INTEGER"].format(network_priority, "network_priority"))

    response = client.case_alert_involved_entity_create(
        case_id=case_id,
        alert_id=alert_id,
        identifier=identifier,
        entity_type=entity_type,
        suspicious=suspicious,
        internal=internal,
        attacker=attacker,
        pivot=pivot,
        operating_system=operating_system,
        network_title=network_title,
        threat_source=threat_source,
        network_priority=network_priority,
    )

    if not response:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("entity information"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_case_alert_entity_get(response, alert_id=alert_id)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["AlertEntity"],
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_case_alert_entity_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update an existing Involved Entity within a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, entity_id, and optional fields to update.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    entity_id = validate_argument(args.get("entity_id"), "entity_id")

    suspicious = arg_to_bool_or_none(args.get("suspicious"))
    internal = arg_to_bool_or_none(args.get("internal"))
    attacker = arg_to_bool_or_none(args.get("attacker"))
    pivot = arg_to_bool_or_none(args.get("pivot"))
    operating_system = args.get("operating_system")
    network_title = args.get("network_title")
    threat_source = args.get("threat_source")
    network_priority_str = args.get("network_priority")

    if not any(
        [
            suspicious is not None,
            internal is not None,
            attacker is not None,
            pivot is not None,
            operating_system is not None,
            network_title is not None,
            threat_source is not None,
            network_priority_str is not None,
        ]
    ):
        raise ValueError(MESSAGES["AT_LEAST_ONE_REQUIRED"].format(", ".join(CASE_ALERT_ENTITY_UPDATE_ARGS)))

    validate_case_alert_entity_update_args(case_id, alert_id, entity_id)

    network_priority = arg_to_number(network_priority_str, "network_priority")
    if network_priority is not None and network_priority < 0:
        raise ValueError(MESSAGES["INVALID_NON_NEGATIVE_INTEGER"].format(network_priority, "network_priority"))

    response = client.case_alert_involved_entity_update(
        case_id=case_id,
        alert_id=alert_id,
        entity_id=entity_id,
        suspicious=suspicious,
        internal=internal,
        attacker=attacker,
        pivot=pivot,
        operating_system=operating_system,
        network_title=network_title,
        threat_source=threat_source,
        network_priority=network_priority,
    )

    if not response:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("entity information"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_case_alert_entity_get(response, "Updated Entity Information", alert_id=alert_id)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["AlertEntity"],
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def _gcb_case_alert_entity_property_command(client: Client, args: dict[str, Any], action: str) -> CommandResults:
    """
    Add/Update a custom property to an Involved Entity in a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, entity_id, key, and value.
        action: Verb prefix for the HR string — "Added" or "Updated".

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_id = validate_argument(args.get("alert_id"), "alert_id")
    entity_id = validate_argument(args.get("entity_id"), "entity_id")
    key = validate_argument(args.get("key"), "key")
    value = validate_argument(args.get("value"), "value")

    validate_case_alert_entity_property_args(case_id, alert_id, entity_id)

    if action == "Added":
        client_method = client.case_alert_involved_entity_add_property
    else:
        client_method = client.case_alert_involved_entity_update_property

    response = client_method(case_id=case_id, alert_id=alert_id, entity_id=entity_id, key=key, value=value)

    if not response:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("entity information"),
            raw_response=response,
        )

    outputs, _ = prepare_context_hr_case_alert_entity_get(response, alert_id=alert_id)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["AlertEntity"],
        outputs_key_field="id",
        outputs=outputs,
        readable_output=f"{action} Entity Property with key `{key}` and value `{value}`.\n",
        raw_response=response,
    )


def gcb_case_alert_entity_property_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add a new custom property to an Involved Entity in a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, entity_id, key, and value.

    Returns:
        CommandResults with readable output and context data.
    """
    return _gcb_case_alert_entity_property_command(client, args, action="Added")


def gcb_case_alert_entity_property_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update an existing custom property value on an Involved Entity in a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing case_id, alert_id, entity_id, key, and value.

    Returns:
        CommandResults with readable output and context data.
    """
    return _gcb_case_alert_entity_property_command(client, args, action="Updated")


def gcb_playbook_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of enabled playbooks.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments containing optional environment and execution_scope parameters.

    Returns:
        CommandResults with readable output and context data.
    """
    case_environment = args.get("environment")
    execution_scope = args.get("execution_scope", DEFAULT_EXECUTION_SCOPE).upper()

    if execution_scope not in VALID_EXECUTION_SCOPES:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format("execution_scope", ", ".join(VALID_EXECUTION_SCOPES)))

    response = client.list_enabled_playbooks(case_environment=case_environment, execution_scope=execution_scope)

    playbooks = response.get("payload", [])

    if not playbooks:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("enabled playbooks"),
            raw_response=response,
        )

    outputs, readable_output = prepare_context_hr_gcb_playbook_list(response)

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["Playbook"],
        outputs_key_field="workflowDefinitionIdentifier",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def gcb_playbook_attach_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Manually attach (trigger) a specific playbook to a Case Alert.

    Args:
        client: Client object used to interact with the Google SecOps API.
        args: Command arguments.

    Returns:
        CommandResults with readable output and context data.
    """
    case_id = validate_argument(args.get("case_id"), "case_id")
    alert_group_identifier = validate_argument(args.get("alert_group_identifier"), "alert_group_identifier")
    alert_identifier = validate_argument(args.get("alert_identifier"), "alert_identifier")
    playbook_name = validate_argument(args.get("playbook_name"), "playbook_name")
    original_workflow_definition_identifier = args.get("original_workflow_definition_identifier")

    if not check_valid_positive_number(case_id):
        raise ValueError(MESSAGES["INVALID_POSITIVE_INTEGER"].format("case_id", case_id, CASE_ID_DISPLAY))

    response = client.playbook_attach(
        case_id=case_id,
        alert_group_identifier=alert_group_identifier,
        alert_identifier=alert_identifier,
        playbook_name=playbook_name,
        original_workflow_definition_identifier=original_workflow_definition_identifier,
    )

    success = response.get("payload", False)

    outputs = {
        "caseId": case_id,
        "alertGroupIdentifier": alert_group_identifier,
        "alertIdentifier": alert_identifier,
        "playbookName": playbook_name,
        "originalWorkflowDefinitionIdentifier": original_workflow_definition_identifier,
        "success": success,
    }

    if success:
        readable_output = f"Playbook '{playbook_name}' successfully attached to alert {alert_identifier} in case {case_id}."
    else:
        readable_output = f"Failed to attach playbook '{playbook_name}' to alert {alert_identifier} in case {case_id}."

    return CommandResults(
        outputs_prefix=SECOPS_OUTPUT_PATHS["PlaybookAttach"],
        outputs_key_field="alertIdentifier",
        outputs=remove_empty_elements(outputs),
        readable_output=readable_output,
        raw_response=response,
    )


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""

    params = demisto.params()
    remove_nulls_from_dictionary(trim_spaces_from_args(params))

    proxy = argToBoolean(params.get("proxy", False))
    disable_ssl = argToBoolean(params.get("insecure", False))
    args = demisto.args()
    command = demisto.command()

    secops_commands = {
        "gcb-case-list": gcb_case_list_command,
        "gcb-case-get": gcb_case_get_command,
        "gcb-case-update": gcb_case_update_command,
        "gcb-case-tag-add": gcb_case_tag_add_command,
        "gcb-case-tag-remove": gcb_case_tag_remove_command,
        "gcb-case-priority-change": gcb_case_priority_change_command,
        "gcb-case-stage-definition-list": gcb_case_stage_definition_list_command,
        "gcb-case-stage-change": gcb_case_stage_change_command,
        "gcb-case-reopen": gcb_case_reopen_command,
        "gcb-case-close": gcb_case_close_command,
        "gcb-case-close-definition-list": gcb_case_close_definition_list_command,
        "gcb-case-assign": gcb_case_assign_command,
        "gcb-case-comment-list": gcb_case_comment_list_command,
        "gcb-case-comment-create": gcb_case_comment_create_command,
        "gcb-case-sla-pause": gcb_case_sla_pause_command,
        "gcb-case-sla-resume": gcb_case_sla_resume_command,
        "gcb-case-alert-list": gcb_case_alert_list_command,
        "gcb-case-alert-get": gcb_case_alert_get_command,
        "gcb-case-alert-update": gcb_case_alert_update_command,
        "gcb-case-alert-tag-add": gcb_case_alert_tag_add_command,
        "gcb-case-alert-tag-remove": gcb_case_alert_tag_remove_command,
        "gcb-case-alert-move": gcb_case_alert_move_command,
        "gcb-case-alert-sla-pause": gcb_case_alert_sla_pause_command,
        "gcb-case-alert-sla-resume": gcb_case_alert_sla_resume_command,
        "gcb-case-alert-sla-set": gcb_case_alert_sla_set_command,
        "gcb-case-alert-recommendation-create": gcb_case_alert_recommendation_create_command,
        "gcb-case-alert-recommendation-fetch": gcb_case_alert_recommendation_fetch_command,
        "gcb-case-alert-customfield-list": gcb_case_alert_customfield_list_command,
        "gcb-case-alert-entity-list": gcb_case_alert_entity_list_command,
        "gcb-case-alert-entity-get": gcb_case_alert_entity_get_command,
        "gcb-case-alert-entity-create": gcb_case_alert_entity_create_command,
        "gcb-case-alert-entity-update": gcb_case_alert_entity_update_command,
        "gcb-case-alert-entity-property-add": gcb_case_alert_entity_property_add_command,
        "gcb-case-alert-entity-property-update": gcb_case_alert_entity_property_update_command,
        "gcb-playbook-list": gcb_playbook_list_command,
        "gcb-playbook-attach": gcb_playbook_attach_command,
    }

    demisto.debug(f"Command being called is {command}")
    try:
        validate_configuration_parameters(params)

        # Initializing client Object
        client = Client(params=params, proxy=proxy, disable_ssl=disable_ssl)
        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in secops_commands:
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            return_results(secops_commands[command](client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
