"""Main file for GoogleSecOps Integration."""

import csv
from copy import deepcopy
from datetime import datetime
from typing import Any

import demistomock as demisto
from CommonServerPython import *
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
IOC_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
STATUS_LIST_TO_RETRY = [429] + list(range(500, 600))
MAX_RETRIES = 4
BACKOFF_FACTOR = 7.5
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 100
MAX_IOCS_FETCH_SIZE = 10000
VALID_DETECTIONS_ALERT_STATE = ["ALERTING", "NOT_ALERTING"]
VALID_DETECTIONS_LIST_BASIS = ["DETECTION_TIME", "CREATED_TIME"]
DEFAULT_SYNTAX_TYPE = "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING"
DEFAULT_CONTENT_TYPE = "PLAIN_TEXT"
VALID_CONTENT_TYPE = ["PLAIN_TEXT", "CIDR", "REGEX"]
TOTAL_TRIES = 10
FIRST_ACCESSED_TIME = "First Accessed Time"
LAST_ACCESSED_TIME = "Last Accessed Time"
IP_ADDRESS = "IP Address"
CONFIDENCE_SCORE = "Confidence Score"
VENDOR = "Google SecOps"

STANDARD_CTX_KEY_MAP = {"ip": "Address", "domain": "Name", "file": "Name"}

DBOT_SCORE_MAPPING = {0: "Unknown", 1: "Good", 2: "Suspicious", 3: "Malicious"}

CONFIDENCE_LEVEL_PRIORITY = {"unknown_severity": 0, "informational": 1, "low": 2, "medium": 3, "high": 4}
VALID_DATA_TABLE_COLUMN_TYPE = ["STRING", "REGEX", "CIDR", "NUMBER"]

SECOPS_V1_ALPHA_URL = "https://chronicle.{}.rep.googleapis.com/v1alpha"
OLDER_SECOPS_V1_ALPHA_URL = "https://{}-chronicle.googleapis.com/v1alpha"

SECOPS_OUTPUT_PATHS = {
    "Rules": "GoogleChronicleBackstory.Rules(val.ruleId == obj.ruleId)",
    "DeleteRule": "GoogleChronicleBackstory.DeleteRule(val.ruleId == obj.ruleId)",
    "Token": "GoogleChronicleBackstory.Token(val.name == obj.name)",
    "RuleAlertingChange": "GoogleChronicleBackstory.RuleAlertingChange(val.ruleId == obj.ruleId)",
    "LiveRuleStatusChange": "GoogleChronicleBackstory.LiveRuleStatusChange(val.ruleId == obj.ruleId)",
    "RetroHunt": "GoogleChronicleBackstory.RetroHunt(val.retrohuntId == obj.retrohuntId)",
    "Events": "GoogleChronicleBackstory.Events(val.id == obj.id)",
    "Detections": "GoogleChronicleBackstory.Detections(val.id == obj.id && val.ruleVersion == obj.ruleVersion)",
    "VerifyRule": "GoogleChronicleBackstory.VerifyRule(val.command_name == obj.command_name)",
    "CuratedRuleDetections": "GoogleChronicleBackstory.CuratedRuleDetections(val.id == obj.id)",
    "CuratedRules": "GoogleChronicleBackstory.CuratedRules(val.ruleId == obj.ruleId)",
    "StreamRules": "GoogleChronicleBackstory.StreamRules(val.id == obj.id)",
    "UDMEvents": "GoogleChronicleBackstory.Events(val.id == obj.id)",
    "ReferenceList": "GoogleChronicleBackstory.ReferenceList(val.name == obj.name)",
    "ListReferenceList": "GoogleChronicleBackstory.ReferenceLists(val.name == obj.name)",
    "VerifyReferenceList": "GoogleChronicleBackstory.VerifyReferenceList(val.command_name == obj.command_name)",
    "VerifyValueInReferenceList": "GoogleChronicleBackstory.VerifyValueInReferenceList(val.value == obj.value && "
    "val.case_insensitive == obj.case_insensitive)",
    "Iocs": "GoogleChronicleBackstory.Iocs(val.Artifact && val.Artifact == obj.Artifact)",
    "IocDetails": "GoogleChronicleBackstory.IocDetails(val.IoCQueried && val.IoCQueried == obj.IoCQueried)",
    "Ip": "GoogleChronicleBackstory.IP(val.IoCQueried && val.IoCQueried == obj.IoCQueried)",
    "Domain": "GoogleChronicleBackstory.Domain(val.IoCQueried && val.IoCQueried == obj.IoCQueried)",
    "DataTable": "GoogleChronicleBackstory.DataTable(val.displayName == obj.displayName)",
    "VerifyValueInDataTable": "GoogleChronicleBackstory.VerifyValueInDataTable(val.value == obj.value && "
    "val.case_insensitive == obj.case_insensitive)",
    "DataTableRows": "GoogleChronicleBackstory.DataTableRows(val.name == obj.name)",
    "RemovedDataTableRows": "GoogleChronicleBackstory.RemovedDataTableRows(val.name == obj.name)",
}

MESSAGES = {
    "INVALID_PAGE_SIZE": "Page size should be in the range from 1 to {}.",
    "REQUIRED_ARGUMENT": "Missing argument {}.",
    "INVALID_RULE_TEXT": 'Invalid rule text provided. Section "meta", "events" or "condition" is missing.',
    "VALIDATE_SINGLE_SELECT": "{} can have one of these values only {}.",
    "CHANGE_RULE_ALERTING_METADATA": "Alerting status for the rule with ID {} has been successfully {}.",
    "CHANGE_LIVE_RULE_STATUS_METADATA": "Live rule status for the rule with ID {} has been successfully {}.",
    "CANCEL_RETROHUNT": "Retrohunt for the rule with ID {} has been successfully cancelled.",
    "INVALID_DAY_ARGUMENT": 'Invalid preset time range value provided. Allowed values are "Last 1 day", "Last 7 days", '
    '"Last 15 days" and "Last 30 days"',
    "CURATED_RULE_ID_REQUIRED": "A Curated Rule ID is required to retrieve the detections.",
    "INVALID_MAX_RESULTS": "Max Results should be in the range 1 to 10000.",
    "QUERY_REQUIRED": "Query is required to retrieve the events.",
    "INVALID_LIMIT_RANGE": "Limit should be in the range from 1 to {}.",
    "INVALID_LIMIT_TYPE": "Limit must be a non-zero and positive numeric value.",
    "NO_RECORDS": "No Records Found",
}

ASSET_IDENTIFIER_NAME_DICT = {
    "host name": "hostname",
    "ip address": "assetIpAddress",
    "mac address": "mac",
    "product id": "productId",
}

CONTENT_TYPE_MAPPING = {
    "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING": "PLAIN_TEXT",
    "REFERENCE_LIST_SYNTAX_TYPE_REGEX": "REGEX",
    "REFERENCE_LIST_SYNTAX_TYPE_CIDR": "CIDR",
}

SYNTAX_TYPE_MAPPING = {
    "PLAIN_TEXT": "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
    "REGEX": "REFERENCE_LIST_SYNTAX_TYPE_REGEX",
    "CIDR": "REFERENCE_LIST_SYNTAX_TYPE_CIDR",
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

        region = params.get("region", "us").lower()
        other_region = params.get("other_region", "").strip()

        self.project_location = region if region.lower() != "other" else other_region

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

        :type backoff_factor ``float``
        :param backoff_factor:
            A backoff factor to apply between attempts after the second try
            (most errors are resolved immediately by a second try without a
            delay). urllib3 will sleep for::

                {backoff factor} * (2 ** ({number of total retries} - 1))

            seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
            for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
            than :attr:`Retry.BACKOFF_MAX`.

            By default, backoff_factor set to 5

        :type raise_on_redirect ``bool``
        :param raise_on_redirect: Whether, if the number of redirects is
            exhausted, to raise a MaxRetryError, or to return a response with a
            response code in the 3xx range.

        :type raise_on_status ``bool``
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

        except NameError:
            pass


"""VALIDATION FUNCTIONS"""


def validate_response(client: Client, url, method="GET", body=None):
    """
    Get response from Google SecOps Search API and validate it.

    :param client: object of client class
    :type client: object of client class

    :param url: url
    :type url: str

    :param method: HTTP request method
    :type method: str

    :param body: data to pass with the request
    :type body: str

    :return: response
    """
    demisto.info("[SECOPS DETECTIONS]: Request URL: " + url)
    raw_response = client.http_client.request(
        url=url, method=method, data=body, proxies=client.proxy_info, verify=not client.disable_ssl
    )

    if 500 <= raw_response.status_code <= 599:
        raise ValueError(
            f"Internal server error occurred. Failed to execute request with 3 retries.\n"
            f"Message: {parse_error_message(raw_response.text, client.project_location)}"
        )
    if raw_response.status_code == 429:
        raise ValueError(
            f"API rate limit exceeded. Failed to execute request with 3 retries.\n"
            f"Message: {parse_error_message(raw_response.text, client.project_location)}"
        )
    if raw_response.status_code == 400 or raw_response.status_code == 404:
        raise ValueError(
            f"Status code: {raw_response.status_code}\nError: {parse_error_message(raw_response.text, client.project_location)}"
        )
    if raw_response.status_code != 200:
        raise ValueError(
            f"Status code: {raw_response.status_code}\nError: {parse_error_message(raw_response.text, client.project_location)}"
        )
    if not raw_response.text:
        raise ValueError(
            "Technical Error while making API call to Google SecOps. "
            f"Empty response received with the status code: {raw_response.status_code}"
        )
    try:
        response = remove_empty_elements(raw_response.json())
        return response
    except json.decoder.JSONDecodeError:
        raise ValueError("Invalid response format while making API call to Google SecOps. Response not in JSON format")


def validate_configuration_parameters(params: dict[str, Any]):
    """
    Check whether entered configuration parameters are valid or not.

    :type param: dict
    :param params: Dictionary of demisto configuration parameter

    :return: raise ValueError if any configuration parameter is not in valid format else returns None
    :rtype: None
    """
    # get configuration parameters
    service_account_json = params.get("credentials", {}).get("password", "")
    page_size = params.get("max_fetch", DEFAULT_MAX_FETCH)
    time_window = params.get("time_window")
    first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH).lower()
    project_instance_id = params.get("secops_project_instance_id", "")
    project_location = params.get("region", "us").lower()
    if project_location == "other":
        project_location = params.get("other_region", "").lower()

    project_number = params.get("secops_project_number", "")
    if project_number and (not project_number.isnumeric() or project_number == "0"):
        raise ValueError("Google SecOps Project Number should be a positive number.")

    if not project_instance_id:
        raise ValueError("Please Provide the Google SecOps Project Instance ID.")
    if not project_location:
        raise ValueError("Please Provide the valid region.")

    try:
        # validate service_account_credential configuration parameter
        json.loads(service_account_json, strict=False)

        # validate override_confidence_score_malicious_threshold and override_confidence_score_suspicious_threshold
        # parameters
        page_size = arg_to_number(page_size, "Incidents fetch limit")
        if page_size < 1 or page_size > MAX_IOCS_FETCH_SIZE:
            raise ValueError(f"Incidents fetch limit should be in the range from 1 to {MAX_IOCS_FETCH_SIZE}.")

        arg_to_datetime(first_fetch, "First fetch time")

        arg_to_number(time_window)

        reputation_related_params = get_params_for_reputation_command(params)
        if (
            reputation_related_params["override_confidence_score_malicious_threshold"] is not None
            and reputation_related_params["override_confidence_score_malicious_threshold"] != ""
            and not reputation_related_params["override_confidence_score_malicious_threshold"].isnumeric()
        ):
            raise ValueError("Confidence Score Threshold must be a number")
        if (
            reputation_related_params["override_confidence_score_suspicious_threshold"] is not None
            and reputation_related_params["override_confidence_score_suspicious_threshold"] != ""
            and not reputation_related_params["override_confidence_score_suspicious_threshold"].isnumeric()
        ):
            raise ValueError("Confidence Score Threshold must be a number")

    except json.decoder.JSONDecodeError:
        raise ValueError("User's Service Account JSON has invalid format")


def validate_argument(value, name) -> str:
    """
    Check if empty string is passed as value for argument and raise appropriate ValueError.

    :type value: str
    :param value: value of the argument.

    :type name: str
    :param name: name of the argument.
    """
    if not value:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format(name))
    return value


def validate_page_size(page_size):
    """
    Validate that page size parameter is in numeric format or not.

    :type page_size: str
    :param page_size: this value will be check as numeric or not.

    :return: True if page size is valid  else raise ValueError.
    :rtype: bool
    """
    if not page_size or not str(page_size).isdigit() or int(page_size) == 0:
        raise ValueError("Page size must be a non-zero and positive numeric value")
    return True


def validate_rule_text(rule_text: str):
    """
    Validate the rule text.

    :type rule_text: str
    :param rule_text: the rule text
    """
    validate_argument(value=rule_text, name="rule_text")

    if "meta" not in rule_text or "events" not in rule_text or "condition" not in rule_text:
        raise ValueError(MESSAGES["INVALID_RULE_TEXT"])


def validate_list_retrohunts_args(args):
    """
    Return and validate page_size, retrohunts_list_all_versions, page_token, rule_id, state.

    :type args: Dict[str, Any]
    :param args: contains all arguments for gcb-list-retrohunts command.

    :return: Dictionary containing values of page_size, retrohunts_list_all_versions, page_token, rule_id, state
     or raise ValueError if the arguments are invalid.
    :rtype: Dict[str, Any]
    """
    page_size = args.get("page_size", 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))
    retrohunts_for_all_versions = argToBoolean(args.get("retrohunts_for_all_versions", False))
    page_token = args.get("page_token")
    rule_id = args.get("id")
    state = args.get("state")

    valid_args = {
        "page_size": page_size,
        "page_token": page_token,
        "rule_id": rule_id,
        "retrohunts_for_all_versions": retrohunts_for_all_versions,
        "state": state,
    }
    if rule_id and "@" in rule_id and retrohunts_for_all_versions:
        raise ValueError("Invalid value in argument 'id'. Expected rule_id.")

    return valid_args


def validate_preset_time_range(value: str) -> str:
    """
    Validate that preset_time_range parameter is in valid format or not and \
    strip the keyword 'Last' to extract the date range if validation is through.

    :type value: str
    :param value: this value will be check as valid or not.

    :return: 1 Day, 7 Days, 15 Days, 30 Days or ValueError.
    :rtype: string or Exception
    """
    value_split = value.split(" ")
    try:
        if value_split[0].lower() != "last":
            raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])

        day = int(value_split[1])

        if day not in [1, 7, 15, 30]:
            raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])

        if value_split[2].lower() not in ["day", "days"]:
            raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])
    except Exception:
        raise ValueError(MESSAGES["INVALID_DAY_ARGUMENT"])
    return value_split[1] + " " + value_split[2].lower()


def get_secops_default_date_range(days: str = DEFAULT_FIRST_FETCH, arg_name: str = "start_time") -> tuple:
    """
    Get Google SecOps default date range(last 3 days).

    :type days: str
    :param days: number of days.

    :type arg_name: str
    :param arg_name: name of the argument.

    :return: start_date, end_date (ISO date in UTC).
    :rtype: string
    """
    start_date, end_date = arg_to_datetime(days, arg_name), datetime.now()
    return start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)  # type: ignore


def validate_single_select(value, name, single_select_choices):
    """
    Validate the status has valid input.

    :type value: str
    param status: input from user to enable or disable the status

    :type name: str
    param name: name of the argument to validate

    :type single_select_choices: List
    param single_select_choices: list of choices to single select for an argument

    :return: status value
    :rtype: str
    """
    if value not in single_select_choices:
        raise ValueError(MESSAGES["VALIDATE_SINGLE_SELECT"].format(name, ", ".join(single_select_choices)))
    return value


def validate_and_parse_detection_start_end_time(args: dict[str, Any]) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Validate and return detection_start_time and detection_end_time as per Google SecOps or \
    raise a ValueError if the given inputs are invalid.

    :type args: dict
    :param args: contains all arguments for command

    :return : detection_start_time, detection_end_time: Detection start and end time in the format API accepts
    :rtype : Tuple[Optional[str], Optional[str]]
    """
    detection_start_time = (
        arg_to_datetime(args.get("start_time"), "start_time")
        if args.get("start_time")
        else arg_to_datetime(args.get("detection_start_time"), "detection_start_time")
    )
    detection_end_time = (
        arg_to_datetime(args.get("end_time"), "end_time")
        if args.get("end_time")
        else arg_to_datetime(args.get("detection_end_time"), "detection_end_time")
    )

    list_basis = args.get("list_basis", "")
    if list_basis:
        validate_single_select(list_basis.upper(), "list_basis", VALID_DETECTIONS_LIST_BASIS)

    if list_basis and not detection_start_time and not detection_end_time:
        raise ValueError('To sort detections by "list_basis", either "start_time" or "end_time" argument is required.')

    if detection_start_time:
        detection_start_time = detection_start_time.strftime(DATE_FORMAT)  # type: ignore
    if detection_end_time:
        detection_end_time = detection_end_time.strftime(DATE_FORMAT)  # type: ignore
    return detection_start_time, detection_end_time


def validate_and_parse_list_detections_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Return and validate page_size, detection_start_time and detection_end_time.

    :type args: Dict[str, Any]
    :param args: contains all arguments for list-detections command

    :return: Dictionary containing values of page_size, detection_start_time and detection_end_time
     or raise ValueError if the arguments are invalid
    :rtype: Dict[str, Any]
    """
    page_size = args.get("page_size", 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))

    rule_id = args.get("id", "")
    detection_for_all_versions = argToBoolean(args.get("detection_for_all_versions", False))
    if detection_for_all_versions and not rule_id:
        raise ValueError('If "detection_for_all_versions" is true, rule id is required.')

    detection_start_time, detection_end_time = validate_and_parse_detection_start_end_time(args)

    alert_state = args.get("alert_state", "")
    if alert_state:
        validate_single_select(alert_state.upper(), "alert_state", VALID_DETECTIONS_ALERT_STATE)

    valid_args = {
        "page_size": page_size,
        "detection_start_time": detection_start_time,
        "detection_end_time": detection_end_time,
        "detection_for_all_versions": detection_for_all_versions,
        "alert_state": alert_state.upper(),
    }

    return valid_args


def validate_and_parse_curatedrule_detection_start_end_time(
    args: dict[str, Any],
) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Validate and return detection_start_time and detection_end_time as per Google SecOps or \
    raise a ValueError if the given inputs are invalid.

    :type args: dict
    :param args: Contains all arguments for command.

    :return : detection_start_time, detection_end_time: Detection start and End time in the format API accepts.
    :rtype : Tuple[Optional[str], Optional[str]]
    """
    detection_start_time = arg_to_datetime(args.get("start_time"), "start_time")
    detection_end_time = arg_to_datetime(args.get("end_time"), "end_time")

    if detection_start_time:
        detection_start_time = detection_start_time.strftime(DATE_FORMAT)  # type: ignore
    if detection_end_time:
        detection_end_time = detection_end_time.strftime(DATE_FORMAT)  # type: ignore
    return detection_start_time, detection_end_time


def validate_and_parse_list_curatedrule_detections_args(args: dict[str, Any]) -> dict[str, Any]:
    """
    Return and validate page_size, detection_start_time and detection_end_time.

    :type args: Dict[str, Any]
    :param args: Contains all arguments for list-curatedrule-detections command.

    :return: Dictionary containing values of page_size, detection_start_time and detection_end_time
     or raise ValueError if the arguments are invalid.
    :rtype: Dict[str, Any]
    """
    page_size = args.get("page_size", 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))

    if not args.get("id"):
        raise ValueError(MESSAGES["CURATED_RULE_ID_REQUIRED"])

    detection_start_time, detection_end_time = validate_and_parse_curatedrule_detection_start_end_time(args)

    alert_state = args.get("alert_state", "")
    if alert_state:
        validate_single_select(alert_state.upper(), "alert_state", VALID_DETECTIONS_ALERT_STATE)

    list_basis = args.get("list_basis", "")
    if list_basis:
        validate_single_select(list_basis.upper(), "list_basis", VALID_DETECTIONS_LIST_BASIS)

    valid_args = {"page_size": page_size, "detection_start_time": detection_start_time, "detection_end_time": detection_end_time}

    return valid_args


def validate_reference_list_args(args):
    """
    Validates the input arguments dictionary to ensure the correct usage of 'lines' and 'entry_id'.

    :type args: Dict
    :param args: contains arguments of the command, either 'lines' or 'entry_id'
    """
    lines = ""
    lines_present = "lines" in args
    entry_id_present = "entry_id" in args

    if lines_present and entry_id_present:
        raise ValueError("Both 'lines' and 'entry_id' cannot be provided together.")
    if not lines_present and not entry_id_present:
        raise ValueError("Either 'lines' or 'entry_id' must be provided.")

    if entry_id_present:
        entry_id = validate_argument(args.get("entry_id"), "entry_id")
        use_delimiter_for_file = argToBoolean(args.get("use_delimiter_for_file", False))
        try:
            file_data = demisto.getFilePath(entry_id)
            file_path = file_data.get("path")
        except Exception:
            raise ValueError(f"The file with entry_id '{entry_id}' does not exist.")
        if os.path.getsize(file_path) == 0:
            raise ValueError(f"The file with entry_id '{entry_id}' is empty.")
        with open(file_path) as file:
            lines = file.read()
            if not use_delimiter_for_file:
                lines = argToList(lines, "\n")
    else:
        lines = validate_argument(args.get("lines"), "lines")
    lines = argToList(lines, args.get("delimiter", ","))
    return lines


def get_artifact_type(value):
    """
    Derive the input value's artifact type based on the regex match. \
    The returned artifact_type is compliant with the Search API.

    :type value: string
    :param value: artifact value

    :return: domain, hashSha256, hashSha1, hashMd5, destinationIpAddress or raise ValueError
    :rtype: string or Exception
    """
    # checking value if is valid ip
    if is_ip_valid(value, True):
        return "destinationIpAddress"
    else:
        hash_type = get_hash_type(value)  # checking value if is MD5, SHA-1 or SHA-256

        if hash_type != "Unknown":
            return "hash" + hash_type.capitalize()

        return "domain"  # if it's not IP or hash then it'll be considered as domain


def validate_data_table_args(args):
    """
    Validate the arguments for the data table.

    :type args: Dict[str, Any]
    :param args: it contains arguments for gcb-create-data-table command.

    :return: name, description, columns_list.
    :rtype: str, str, list
    """
    name = validate_argument(args.get("name"), "name")
    columns = validate_argument(args.get("columns"), "columns")
    description = args.get("description", "")
    if isinstance(columns, str):
        try:
            columns = json.loads(columns)
        except json.decoder.JSONDecodeError:
            raise ValueError("Invalid format for columns argument. Please provide a valid JSON format.")

    if not columns:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("columns"))

    index = 0
    columns_list = []
    for column_name, column_type in columns.items():  # type: ignore
        column_info = {
            "columnIndex": index,
            "originalColumn": column_name,
        }
        if column_type.upper() in VALID_DATA_TABLE_COLUMN_TYPE:
            column_info["columnType"] = column_type.upper()
        else:
            column_info["mappedColumnPath"] = column_type

        columns_list.append(column_info)
        index += 1

    return name, description, columns_list


def validate_data_table_rows_args(args):
    """
    Validate the arguments for the data table.

    :type args: Dict[str, Any]
    :param args: it contains arguments for gcb-create-data-table command.

    :return: name, rows.
    :rtype: str, list
    """
    name = validate_argument(args.get("name"), "name")
    rows = []
    rows_present = "rows" in args
    entry_id_present = "entry_id" in args

    if rows_present and entry_id_present:
        raise ValueError("Both 'rows' and 'entry_id' cannot be provided together.")
    if not rows_present and not entry_id_present:
        raise ValueError("Either 'rows' or 'entry_id' must be provided.")

    if entry_id_present:
        entry_id = validate_argument(args.get("entry_id"), "entry_id")
        try:
            file_data = demisto.getFilePath(entry_id)
            file_path = file_data.get("path")
        except Exception:
            raise ValueError(f"The file with entry_id '{entry_id}' does not exist.")
        if os.path.getsize(file_path) == 0:
            raise ValueError(f"The file with entry_id '{entry_id}' is empty.")
        with open(file_path) as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                rows.append(row)
    else:
        rows = validate_argument(args.get("rows"), "rows")  # type: ignore
        if isinstance(rows, str):
            try:
                rows = json.loads(rows)
            except json.decoder.JSONDecodeError:
                raise ValueError("Invalid format for rows argument. Please provide a valid JSON format.")

    if not rows:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("rows"))

    if not isinstance(rows, list):
        rows = [rows]

    return name, rows


""" HELPER FUNCTIONS """


def trim_args(args):
    """
    Trim the arguments for extra spaces.

    :type args: Dict
    :param args: it contains arguments of the command.
    """
    for key, value in args.items():
        if isinstance(value, str):
            args[key] = value.strip()

    return args


def create_url_path(client: Client) -> str:
    """
    Creates the URL path for the Google SecOps API.

    :type client: Client
    :param client: The client object containing project ID, instance ID, and location.

    :return: The constructed URL path.
    :rtype: str
    """
    project_number = client.project_number
    project_instance_id = client.project_instance_id
    project_location = client.project_location

    parent = f"projects/{project_number}/locations/{project_location}/instances/{project_instance_id}"

    if client.use_new_url_format:
        url = SECOPS_V1_ALPHA_URL.format(project_location)
    else:
        url = OLDER_SECOPS_V1_ALPHA_URL.format(project_location)

    return f"{url}/{parent}"


def generate_delayed_start_time(time_window: str, start_time: str) -> str:
    """
    Generate the delayed start time accordingly after validating the time window provided by user.

    :type time_window: str
    :param time_window: Time window to delay the start time.
    :type start_time: str
    :param start_time: Initial start time calculated by fetch_incidents method.

    :rtype: delayed_start_time: str
    :return: delayed_start_time: Returns generated delayed start time.
    """
    if not time_window:
        return start_time
    delayed_start_time = dateparser.parse(start_time, settings={"STRICT_PARSING": True})
    delayed_start_time = delayed_start_time - timedelta(minutes=int(time_window))  # type: ignore
    delayed_start_time = datetime.strftime(delayed_start_time, DATE_FORMAT)  # type: ignore

    return delayed_start_time


def add_diff_time_to_end_time(start_time: str, end_time: str) -> tuple[str, bool]:
    """
    Calculate the difference between start_time and end_time and add half of the difference to end_time.

    :type start_time: str
    :param start_time: Start time of request.
    :type end_time: str
    :param end_time: End time of request.

    :rtype: tuple[str, bool]
    :return: End time after adding half of the difference between start_time and end_time, time_diff_one_microsecond
    """

    start_time_obj = datetime.strptime(start_time, DATE_FORMAT)
    end_time_obj = datetime.strptime(end_time, DATE_FORMAT)
    time_diff_one_microsecond = False

    time_diff = end_time_obj - start_time_obj

    # Check if time difference is less than 1 microsecond
    if time_diff.total_seconds() <= 0.000001:  # 1 microsecond = 0.000001 seconds
        delayed_end_time_obj = start_time_obj + timedelta(microseconds=1)
        result = delayed_end_time_obj.strftime(DATE_FORMAT)
        demisto.debug(f"Final delayed end time with 1 microsecond difference: {result}")
        time_diff_one_microsecond = True
        return result, time_diff_one_microsecond

    # Calculate half of the time difference
    half_diff = time_diff / 2
    # Add half of the difference to start_time to get the delayed end time
    delayed_end_time_obj = start_time_obj + half_diff

    result = delayed_end_time_obj.strftime(DATE_FORMAT)
    demisto.debug(f"Final delayed end time: {result}")
    return result, time_diff_one_microsecond


def multiline_logs_for_list(array: list, prefix: str = ""):
    """
    Logs a list of items with a prefix, batched into 50 items per log message.

    :type array: list
    :param array: List of items to be logged.

    :type prefix: str
    :param prefix: String to be prefixed to the log message.
    """
    for b in batch(array, batch_size=50):
        demisto.debug(f"{prefix}{b}")


def parse_error_message(error: str, region: str):
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

    if json_error.get("error", {}).get("code") == 403:
        return "Permission denied"
    return json_error.get("error", {}).get("message", "")


def string_escape_markdown(data: Any):
    """
    Escape any chars that might break a markdown string.
    :param data: The data to be modified (required).
    :return: A modified data.
    """
    if isinstance(data, str):
        data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
    elif isinstance(data, list):
        new_data = []
        for sub_data in data:
            if isinstance(sub_data, str):
                sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
            elif isinstance(sub_data, dict):
                sub_data = {string_escape_markdown(key): string_escape_markdown(value) for key, value in sub_data.items()}
            new_data.append(sub_data)
        data = new_data
    elif isinstance(data, dict):
        data = {string_escape_markdown(key): string_escape_markdown(value) for key, value in data.items()}
    return data


def get_params_for_reputation_command(params: dict[str, Any]):
    """
    Get Demisto parameters related to the reputation command.

    :return: Dict of parameters related to reputation command.
    :rtype: dict
    """
    # fetching parameters for reputation command
    malicious_category_list = params.get("malicious_categories")
    suspicious_category_list = params.get("suspicious_categories")
    malicious_category_list = malicious_category_list if malicious_category_list is not None else ""
    suspicious_category_list = suspicious_category_list if suspicious_category_list is not None else ""

    # create list of malicious and suspicious categories based on entered comma separated values
    override_malicious_categories = [
        malicious_category.strip().lower() for malicious_category in malicious_category_list.split(",")
    ]
    override_suspicious_categories = [
        suspicious_category.strip().lower() for suspicious_category in suspicious_category_list.split(",")
    ]

    malicious_severity_list = params.get("override_severity_malicious")
    suspicious_severity_list = params.get("override_severity_suspicious")
    override_malicious_severity = malicious_severity_list if malicious_severity_list is not None else ""
    override_suspicious_severity = suspicious_severity_list if suspicious_severity_list is not None else ""

    override_malicious_confidence_score = params.get("override_confidence_score_malicious_threshold")
    override_suspicious_confidence_score = params.get("override_confidence_score_suspicious_threshold")

    malicious_confidence_score_threshold_str = params.get("override_confidence_level_malicious")
    suspicious_confidence_score_threshold_str = params.get("override_confidence_level_suspicious")

    override_malicious_confidence_score_str = (
        malicious_confidence_score_threshold_str if malicious_confidence_score_threshold_str is not None else ""
    )
    override_suspicious_confidence_score_str = (
        suspicious_confidence_score_threshold_str if suspicious_confidence_score_threshold_str is not None else ""
    )

    return {
        "malicious_categories": override_malicious_categories,
        "suspicious_categories": override_suspicious_categories,
        "override_severity_malicious": override_malicious_severity,
        "override_severity_suspicious": override_suspicious_severity,
        "override_confidence_score_malicious_threshold": override_malicious_confidence_score,
        "override_confidence_score_suspicious_threshold": override_suspicious_confidence_score,
        "override_confidence_level_malicious": override_malicious_confidence_score_str,
        "override_confidence_level_suspicious": override_suspicious_confidence_score_str,
    }


def transform_to_informal_time(total_time: float, singular_expected_string: str, plural_expected_string: str) -> str:
    """
    Convert to informal time from date to current time.

    :type total_time: float
    :param total_time: string of datetime object.

    :type singular_expected_string: string
    :param singular_expected_string: expected string if total_time is 1.

    :type plural_expected_string: string
    :param plural_expected_string: expected string if total_time is more than 1.

    :return: informal time from date to current time.
    :rtype: str
    """
    return singular_expected_string if total_time == 1 else str(total_time) + plural_expected_string


def get_informal_time(date: str) -> str:
    """
    Convert to informal time from date to current time.

    :type date: string
    :param date: string of datetime object.

    :return: informal time from date to current time.
    :rtype: str
    """
    current_time = datetime.utcnow()
    date_format = DATE_FORMAT if "." in date else IOC_DATE_FORMAT
    previous_time = parse_date_string(date, date_format=date_format)

    total_time = (current_time - previous_time).total_seconds()

    if 0 < total_time < 60:
        return transform_to_informal_time(total_time, "a second ago", " seconds ago")
    total_time = round(total_time / 60)
    if 0 < total_time < 60:
        return transform_to_informal_time(total_time, "a minute ago", " minutes ago")
    total_time = round(total_time / 60)
    if 0 < total_time < 24:
        return transform_to_informal_time(total_time, "an hour ago", " hours ago")
    total_time = round(total_time / 24)
    if 0 < total_time < 31:
        return transform_to_informal_time(total_time, "a day ago", " days ago")
    total_time = round(total_time / 31)
    if 0 < total_time < 12:
        return transform_to_informal_time(total_time, "a month ago", " months ago")
    total_time = round((total_time * 31) / 365)
    return transform_to_informal_time(total_time, "a year ago", " years ago")


def parse_list_ioc_response(ioc_matches: list) -> dict:
    """
    Parse a list of IOC responses (new structure).
    :type ioc_matches: list
    :param ioc_matches: List of IOC response dicts (new structure).
    :return: Dict with 'hr_ioc_matches', 'domain_std_context', 'context'.
    :rtype: dict
    """
    hr_ioc_matches = []
    domain_std_context = []
    context = []

    for ioc_response in ioc_matches:
        artifact = ioc_response.get("artifactIndicator", {})
        artifact_value = ""
        if artifact and isinstance(artifact, dict):
            artifact_value = list(artifact.values())[0]

        ingest_time = ioc_response.get("iocIngestTimestamp", "")
        first_seen_time = ioc_response.get("firstSeenTimestamp", "")
        last_seen_time = ioc_response.get("lastSeenTimestamp", "")
        sources_list = ioc_response.get("sources", [])
        confidence = ioc_response.get("confidenceScore", 0)
        normalized_confidence = ioc_response.get("confidenceBucket", "unknown")
        severity = ioc_response.get("rawSeverity", "")
        categories = ioc_response.get("categories", [])
        category = categories[0] if categories else ioc_response.get("categorization", "")

        # Human readable matches
        sources_context = []
        for source in sources_list:
            hr_ioc_matches.append(
                {
                    "Artifact": artifact_value,
                    "Category": category,
                    "Source": source,
                    "Confidence": normalized_confidence,
                    "Severity": severity,
                    "IOC ingest time": get_informal_time(ingest_time),
                    "First seen": get_informal_time(first_seen_time),
                    "Last seen": get_informal_time(last_seen_time),
                }
            )

            sources_context.append(
                {
                    "Category": category,
                    "IntRawConfidenceScore": confidence,
                    "NormalizedConfidenceScore": normalized_confidence,
                    "RawSeverity": severity,
                    "Source": source,
                }
            )

        if artifact.get("domain"):
            domain_std_context.append({"Name": artifact_value})

        context.append(
            {
                "Artifact": artifact_value,
                "IocIngestTime": ingest_time,
                "FirstAccessedTime": first_seen_time,
                "LastAccessedTime": last_seen_time,
                "Sources": sources_context,
            }
        )

    return {"hr_ioc_matches": hr_ioc_matches, "domain_std_context": domain_std_context, "context": context}


def get_ioc_domain_matches(client_obj, start_time: str, end_time: str, max_fetch: int, is_raw: bool = False) -> tuple:
    """
    Call Google SecOps API to get IOC domain matches in a given time window.
    :type client_obj: Client
    :param client_obj: Client object to perform API requests.
    :type start_time: str
    :param start_time: Start time of request.
    :type end_time: str
    :param end_time: End time of request.
    :type max_fetch: int
    :param max_fetch: Maximum number of results to fetch.
    :type is_raw: bool
    :param is_raw: Whether to return raw response or parsed response.

    :return: List of parsed IOC domain match events and boolean value to check if more data is available.
    :rtype: tuple
    """
    url_path = create_url_path(client_obj)
    # Adjust the endpoint and params as per Google SecOps API spec for IOC domain matches
    params = {
        "timestampRange.startTime": start_time,
        "timestampRange.endTime": end_time,
        "maxMatchesToReturn": max_fetch,
    }
    encoded_params = urllib.parse.urlencode(params)
    request_url = f"{url_path}/legacy:legacySearchEnterpriseWideIoCs?{encoded_params}"

    response_body = validate_response(client_obj, request_url)
    ioc_matches = response_body.get("matches", [])
    more_data_avaliable = response_body.get("moreDataAvailable", False)

    if is_raw:
        return ioc_matches, more_data_avaliable

    parsed_ioc = parse_list_ioc_response(ioc_matches)

    return parsed_ioc["context"], more_data_avaliable


def map_rule_response(rule):
    """
    Map rule response to required format.

    :type rule: Dict
    :param rule: raw response received from api in json format.

    :return: rule in required format.
    :rtype: Dict
    """
    rule_dict = {}
    name = rule.get("name", "")

    # Extract ID using regex
    search_pattern = r"rules/([^@]+)(?:@(.+))?"
    match = re.search(search_pattern, name)
    if match:
        rule_id, rule_version = match.groups()
    else:
        rule_id = rule_version = ""

    if not rule_version:
        rule_version = rule.get("revisionId", "")
    version_id = f"{rule_id}@{rule_version}"

    metadata = {
        "author": rule.get("author", ""),
        "created": rule.get("createTime", ""),
        "severity": rule.get("severity", {}).get("displayName", ""),
        "description": rule.get("metadata", {}).get("description", ""),
    }

    rule_dict = {
        "ruleId": rule_id,
        "versionId": version_id,
        "ruleName": rule.get("displayName", ""),
        "ruleText": rule.get("text", ""),
        "ruleType": rule.get("type", ""),
        "versionCreateTime": rule.get("revisionCreateTime", ""),
        "metadata": metadata,
        "compilationState": rule.get("compilationState", ""),
        "inputsUsed": rule.get("inputsUsed", {}),
        "referenceLists": rule.get("referenceLists", []),
        "allowedRunFrequencies": rule.get("allowedRunFrequencies", []),
    }

    return rule_dict


def get_list_rules_hr(rules: list[dict[str, Any]]) -> str:
    """
    Convert rules response into human readable.

    :param rules: list of rules.
    :type rules: list

    :return: returns human readable string for gcb-list-rules command.
    :rtype: str
    """
    hr_dict = []
    for rule in rules:
        hr_dict.append(
            {
                "Rule ID": rule.get("ruleId"),
                "Rule Name": rule.get("ruleName"),
                "Compilation State": rule.get("compilationState", ""),
            }
        )
    hr = tableToMarkdown("Rule(s) Details", hr_dict, ["Rule ID", "Rule Name", "Compilation State"], removeNull=True)
    return hr


def get_context_for_rules(rules: list[Any], next_page_token: Any) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Convert rules response into Context data.

    :param rule: list of rules.
    :type rule: list[Any]

    :param next_page_token: token to populate context data.
    :type next_page_token: str

    :return: list of rules and token to populate context data.
    :rtype: Tuple[List[Dict[str, Any]], Dict[str, str]]
    """
    rules_ec = []
    token_ec = {}
    if next_page_token:
        token_ec = {"name": "gcb-list-rules", "nextPageToken": next_page_token}
    for rule in rules:
        rules_ec.append(rule)

    return rules_ec, token_ec


def gcb_list_rules(client_obj, args: dict[str, str]) -> dict[str, Any]:
    """
    Return context data and raw response for gcb-list-rules command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args:  Dict[str, str]
    :param args: it contain arguments of gcb-list-rules command.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the fetched rules
    """
    page_size = args.get("page_size", 100)
    validate_page_size(page_size)
    page_token = args.get("page_token", "")
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))

    url = create_url_path(client_obj)
    request_url = f"{url}/rules?view=FULL&pageSize={page_size}"

    # Append parameters if specified
    if page_token:
        request_url += f"&pageToken={page_token}"

    # get list of rules from Google SecOps
    json_data = validate_response(client_obj, request_url)

    return json_data


def prepare_hr_for_rule_commands(json_data, table_title):
    """
    Prepare Human Readable output from the response received.

    :type json_data: Dict
    :param json_data: raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    hr_output = {
        "Rule ID": json_data.get("ruleId"),
        "Version ID": json_data.get("versionId"),
        "Author": json_data.get("metadata", {}).get("author"),
        "Rule Name": json_data.get("ruleName"),
        "Description": json_data.get("metadata", {}).get("description"),
        "Version Creation Time": json_data.get("versionCreateTime"),
        "Compilation Status": json_data.get("compilationState"),
        "Rule Text": json_data.get("ruleText"),
        "Reference Lists": json_data.get("referenceLists", []),
        "Allowed Run Frequencies": json_data.get("allowedRunFrequencies", []),
    }
    hr = tableToMarkdown(
        table_title,
        hr_output,
        headers=[
            "Rule ID",
            "Version ID",
            "Author",
            "Rule Name",
            "Description",
            "Version Creation Time",
            "Compilation Status",
            "Rule Text",
            "Reference Lists",
            "Allowed Run Frequencies",
        ],
        removeNull=True,
    )
    return hr


def create_rule(client_obj, rule_text: str) -> dict[str, Any]:
    """
    Return context data and raw response for gcb-create-rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_text: str
    :param rule_text: the rule text to for the rule to be created.

    :rtype: Dict[str, Any], Dict[str, Any]
    :return: json_data: Context data and raw response for the created rule.
    """
    url = create_url_path(client_obj)
    request_url = f"{url}/rules"

    req_json_data = {"text": rule_text}
    json_data = validate_response(client_obj, request_url, method="POST", body=json.dumps(req_json_data))

    return json_data


def gcb_get_rule(client_obj, rule_id):
    """
    Return context data and raw response for gcb-get-rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId.

    :rtype: Dict[str, Any]
    :return: json_data: Raw response for the fetched rules.
    """
    url = create_url_path(client_obj)
    request_url = f"{url}/rules/{rule_id}"

    json_data = validate_response(client_obj, request_url)

    return json_data


def prepare_hr_for_delete_rule(response: dict[str, str]) -> str:
    """
    Prepare human-readable for create rule command.

    :type response: Dict[str, Any]
    :param response: Response of create rule.

    :rtype: str
    :return: Human readable string for create rule command.
    """
    hr_output = {"Rule ID": response.get("ruleId"), "Action Status": response.get("actionStatus")}

    if response.get("actionStatus") == "SUCCESS":
        title = f"Rule with ID {response.get('ruleId')} deleted successfully"
    else:
        title = f"Could not delete the rule with ID {response.get('ruleId')}"

    return tableToMarkdown(title, hr_output, headers=["Rule ID", "Action Status"], removeNull=True)


def delete_rule(client_obj, rule_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-delete-rule command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: rule id of the rule to be deleted

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the created rule
    """
    url = create_url_path(client_obj)
    request_url = f"{url}/rules/{rule_id}"
    json_data = validate_response(client_obj, request_url, method="DELETE")

    json_data = {"ruleId": rule_id, "actionStatus": "SUCCESS" if not json_data else "FAILURE"}

    ec = {SECOPS_OUTPUT_PATHS["DeleteRule"]: json_data}

    return ec, json_data


def gcb_create_rule_version(client_obj, rule_id, rule_text):
    """
    Return context data and raw response for gcb-create-rule-version command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId.

    :type rule_text: str
    :param rule_text: it is the rule itself to add.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: json_data: Context data and raw response of the request.
    """
    url = create_url_path(client_obj)
    request_url = f"{url}/rules/{rule_id}"
    body = {"text": rule_text}
    json_data = validate_response(client_obj, request_url, method="PATCH", body=json.dumps(body))

    return json_data


def prepare_hr_for_gcb_change_rule_alerting_status(json_data, alerting_status):
    """
    Prepare human-readable for gcb-change-rule-alerting-status command.

    :type json_data: Dict
    :param json_data: raw response received from api in json format.

    :type alerting_status: str
    :param alerting_status: status value to be updated.

    :return: Human Readable output to display.
    :rtype: str
    """
    status = "enabled" if alerting_status == "enable" else "disabled"
    hr_output = {"Rule ID": json_data.get("ruleId"), "Action Status": json_data.get("actionStatus")}
    hr = tableToMarkdown(
        "Alerting Status",
        hr_output,
        headers=["Rule ID", "Action Status"],
        removeNull=True,
        metadata=MESSAGES["CHANGE_RULE_ALERTING_METADATA"].format(json_data.get("ruleId"), status),
    )
    return hr


def gcb_change_rule_alerting_status(client_obj, rule_id, alerting_status):
    """
    Return context data and raw response for gcb-change-rule-alerting-status command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type rule_id: str
    :param rule_id: the ruleId of the rule whose alerting status is to be updated.

    :type alerting_status: str
    :param alerting_status: indicates whether to enable or disable the alerting stats for the rule.

    :rtype: Dict[str, Any]
    :return: json_data: raw response for the update in alerting status of the rule.
    """
    body = {"alerting": alerting_status == "enable"}
    url = create_url_path(client_obj)
    request_url = f"{url}/rules/{rule_id}/deployment?updateMask=alerting"

    json_data = validate_response(client_obj, request_url, method="PATCH", body=json.dumps(body))

    return json_data


def prepare_hr_for_gcb_change_live_rule_status_command(json_data, live_rule_status):
    """
    Prepare human-readable for gcb-change-live-rule-status-command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-change-live-rule-status-command.

    :type live_rule_status: str
    :param live_rule_status: status value to be changed.

    :rtype: str
    :return: Human readable string for gcb-change-live-rule-status-command.
    """
    hr_output = {"Rule ID": json_data.get("ruleId"), "Action Status": json_data.get("actionStatus")}
    status = "enabled" if live_rule_status == "enable" else "disabled"
    hr = tableToMarkdown(
        "Live Rule Status",
        hr_output,
        headers=["Rule ID", "Action Status"],
        removeNull=True,
        metadata=MESSAGES["CHANGE_LIVE_RULE_STATUS_METADATA"].format(json_data.get("ruleId"), status),
    )

    return hr


def gcb_change_live_rule_status(client_obj, rule_id, live_rule_status):
    """
    Return context data and raw response for gcb-change-live-rule-status command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId.

    :type live_rule_status: str
    :param live_rule_status: new status of the rule to be changed.

    :rtype: Dict[str, Any]
    :return: json_data: Raw response of the request.
    """

    body = {"enabled": live_rule_status == "enable"}
    url = create_url_path(client_obj)
    request_url = f"{url}/rules/{rule_id}/deployment?updateMask=enabled"

    json_data = validate_response(client_obj, request_url, method="PATCH", body=json.dumps(body))

    return json_data


def gcb_verify_rule(client_obj, rule_text):
    """
    Return context data and raw response for gcb_verify_rule command for GoogleSecOps.
    :type client_obj: Client
    :param client_obj: Client object used to get response from API.
    :type rule_text: str
    :param rule_text: Rule text to validate.
    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request.
    """
    body = {"ruleText": rule_text}

    url = create_url_path(client_obj)
    request_url = f"{url}:verifyRuleText"

    json_data = validate_response(client_obj, request_url, method="POST", body=json.dumps(body))
    context_data = {
        **json_data,
        "success": json_data.get("success", False),
        "command_name": "gcb-verify-rule",
    }
    ec = {SECOPS_OUTPUT_PATHS["VerifyRule"]: context_data}
    return ec, json_data


def map_response_for_retrohunts(response: dict) -> dict:
    """
    Maps a response to a dictionary of retrohunt attributes.

    :param response: A single retrohunt response.
    :type response: Dict

    :return: A dictionary of retrohunt attributes.
    :rtype: Dict
    """
    name = response.get("name", "")

    # Extract IDs using regex
    search_pattern = r"rules/([^/]+)/retrohunts/([^/]+)"
    match = re.search(search_pattern, name)
    if match:
        rule_version, retrohunt_id = match.groups()
    else:
        rule_version = retrohunt_id = ""

    if not rule_version or not retrohunt_id:
        raise ValueError("Invalid response received from Google SecOps API. Missing rule version or retrohunt ID.")

    # versionId is the ruleId with version, ruleId is before the @
    version_id = rule_version
    rule_id = rule_version.split("@")[0] if "@" in rule_version else rule_version

    return {
        "retrohuntId": retrohunt_id,
        "ruleId": rule_id,
        "versionId": version_id,
        "eventStartTime": response.get("processInterval", {}).get("startTime"),
        "eventEndTime": response.get("processInterval", {}).get("endTime"),
        "retrohuntStartTime": response.get("executionInterval", {}).get("startTime"),
        "retrohuntEndTime": response.get("executionInterval", {}).get("endTime"),
        "state": response.get("state"),
        "progressPercentage": response.get("progressPercentage"),
    }


def gcb_list_retrohunts(client_obj, rule_id, state, page_size, page_token):
    """
    Return context data and raw response for gcb-list-retrohunts command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_id: str
    :param rule_id: it is the ruleId or versionId.

    :type state: str
    :param state: it is the state of the retrohunt to include in list.

    :type page_size: int
    :param page_size: it indicates the no of output entries to display.

    :type page_token: str
    :param page_token: it is the base64 page token for next page of the outputs.

    :rtype: Dict[str, Any]
    :return: json_data: raw response of the request.
    """
    url_path = create_url_path(client_obj)

    encoded_params = urllib.parse.urlencode(assign_params(pageSize=page_size, pageToken=page_token, filter=state))
    if rule_id:
        request_url = f"{url_path}/rules/{rule_id}/retrohunts?{encoded_params}"
    else:
        request_url = f"{url_path}/rules/-/retrohunts?{encoded_params}"

    json_data = validate_response(client_obj, request_url)

    return json_data


def prepare_context_hr_for_gcb_list_retrohunts_commands(json_data):
    """
    Prepare context and human-readable for gcb-list-retrohunts.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-list-retrohunts.

    :rtype: Tuple[List[Dict], str]
    :return: Entry context data and human readable string for gcb-list-retrohunts.
    """
    next_page_token = json_data.get("nextPageToken")
    json_data = json_data.get("retrohunts")
    hr_output = []
    ec_output = []
    for retrohunt in json_data:
        output = map_response_for_retrohunts(retrohunt)
        hr_output.append(
            {
                "Retrohunt ID": output.get("retrohuntId"),
                "Rule ID": output.get("ruleId"),
                "Version ID": output.get("versionId"),
                "Event Start Time": output.get("eventStartTime"),
                "Event End Time": output.get("eventEndTime"),
                "Retrohunt Start Time": output.get("retrohuntStartTime"),
                "Retrohunt End Time": output.get("retrohuntEndTime"),
                "State": output.get("state"),
                "Progress Percentage": output.get("progressPercentage"),
            }
        )
        ec_output.append(output)

    hr = tableToMarkdown(
        "Retrohunt Details",
        hr_output,
        headers=[
            "Retrohunt ID",
            "Rule ID",
            "Version ID",
            "Event Start Time",
            "Event End Time",
            "Retrohunt Start Time",
            "Retrohunt End Time",
            "State",
            "Progress Percentage",
        ],
        removeNull=True,
    )
    if next_page_token:
        hr += (
            "\nMaximum number of retrohunts specified in page_size has been returned. To fetch the next set of"
            f" retrohunts, execute the command with the page token as `{next_page_token}`"
        )
    return remove_empty_elements(ec_output), hr


def prepare_hr_for_get_retrohunt(json_data: dict[str, Any]):
    """
    Prepare context and human-readable for gcb-get-retrohunt.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-get-retrohunt.

    :rtype: Tuple[List[Dict], str]
    :return: Entry context data and human readable string for gcb-get-retrohunt.
    """
    retrohunt_details = map_response_for_retrohunts(json_data)

    hr_output = {
        "Retrohunt ID": retrohunt_details.get("retrohuntId"),
        "Rule ID": retrohunt_details.get("ruleId"),
        "Version ID": retrohunt_details.get("versionId"),
        "Event Start Time": retrohunt_details.get("eventStartTime"),
        "Event End Time": retrohunt_details.get("eventEndTime"),
        "Retrohunt Start Time": retrohunt_details.get("retrohuntStartTime"),
        "Retrohunt End Time": retrohunt_details.get("retrohuntEndTime"),
        "State": retrohunt_details.get("state"),
        "Progress Percentage": retrohunt_details.get("progressPercentage"),
    }

    headers = [
        "Retrohunt ID",
        "Rule ID",
        "Version ID",
        "Event Start Time",
        "Event End Time",
        "Retrohunt Start Time",
        "Retrohunt End Time",
        "State",
        "Progress Percentage",
    ]

    hr = tableToMarkdown("Retrohunt Details", hr_output, headers=headers, removeNull=True)
    return remove_empty_elements(retrohunt_details), hr


def gcb_get_retrohunt(client_obj, rule_or_version_id, retrohunt_id):
    """
    Return context data and raw response for gcb-get-retrohunt command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_or_version_id: str
    :param rule_or_version_id: Rule ID or Version ID of the rule whose retrohunts are to be listed.

    :type retrohunt_id: str
    :param retrohunt_id: Unique identifier for a retrohunt, defined and returned by the server.

    :rtype: Dict[str, Any]
    :return: json_data: Raw response for the created rule.
    """
    url_path = create_url_path(client_obj)

    request_url = f"{url_path}/rules/{rule_or_version_id}/retrohunts/{retrohunt_id}"
    json_data = validate_response(client_obj, request_url)

    return json_data


def gcb_start_retrohunt(client_obj, rule_id: str, start_time: str, end_time: str):
    """
    Start a retrohunt for the specified rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_id: str
    :param rule_id: Rule ID or Version ID of the rule whose retrohunt is to be started.

    :type start_time: str
    :param start_time: Start time for the time range of logs being processed.

    :type end_time: str
    :param end_time: End time for the time range of logs being processed.

    :rtype: Dict[str, Any]
    :return: json_data: Raw response for the command.
    """
    url_path = create_url_path(client_obj)
    url = f"{url_path}/rules/{rule_id}/retrohunts"

    body = {"processInterval": {"startTime": start_time, "endTime": end_time}}

    json_data = validate_response(client_obj, url, method="POST", body=json.dumps(body))

    return json_data


def prepare_hr_for_gcb_cancel_retrohunt(json_data):
    """
    Prepare human-readable for gcb-cancel-retrohunt command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of get cb-cancel-retrohunt.

    :rtype: str
    :return: Human readable string for gcb-cancel-retrohunt command.
    """
    hr_output = {
        "ID": json_data.get("id"),
        "Retrohunt ID": json_data.get("retrohuntId"),
        "Action Status": "SUCCESS" if json_data.get("cancelled") else "FAILURE",
    }

    hr = tableToMarkdown(
        "Cancelled Retrohunt",
        hr_output,
        headers=["ID", "Retrohunt ID", "Action Status"],
        removeNull=True,
        metadata=MESSAGES["CANCEL_RETROHUNT"].format(json_data.get("id")),
    )
    return hr


def gcb_cancel_retrohunt(client_obj, rule_or_version_id, retrohunt_id):
    """
    Return context data and raw response for gcb-cancel-retrohunt command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_or_version_id: str
    :param rule_or_version_id: it is the ruleId or versionId.

    :type retrohunt_id: str
    :param retrohunt_id: it is the unique id of the retrohunt.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request.
    """
    url_path = create_url_path(client_obj)
    url = f"{url_path}/operations/{retrohunt_id}:cancel"

    json_data = validate_response(client_obj, url, method="POST")
    json_data = {
        "id": rule_or_version_id,
        "retrohuntId": retrohunt_id,
        "cancelled": bool(not json_data),
    }
    ec = {SECOPS_OUTPUT_PATHS["RetroHunt"]: json_data}
    return ec, json_data


def get_default_command_args_value(args: dict[str, Any], max_page_size: int = 10000, date_range=None) -> tuple:
    """
    Validate and return command arguments default values as per Google SecOps.

    :type args: dict
    :param args: contain all arguments for command.

    :type max_page_size: int
    :param max_page_size: maximum allowed page size.

    :type date_range: string
    :param date_range: The date range to be parsed.

    :return : start_time, end_time, page_size, reference_time.
    :rtype : str, str, int, Optional[str]
    """
    preset_time_range = args.get("preset_time_range", None)
    reference_time = None
    if preset_time_range:
        preset_time_range = validate_preset_time_range(preset_time_range)
        start_time, end_time = get_secops_default_date_range(preset_time_range, "preset_time_range")
    else:
        if date_range is None:
            date_range = DEFAULT_FIRST_FETCH
        start_time, end_time = get_secops_default_date_range(days=date_range)
        if args.get("start_time"):
            start_time = arg_to_datetime(args.get("start_time"), "start_time").strftime(DATE_FORMAT)  # type: ignore
        if args.get("end_time"):
            end_time = arg_to_datetime(args.get("end_time"), "end_time").strftime(DATE_FORMAT)  # type: ignore
    if args.get("reference_time"):
        reference_time = arg_to_datetime(args.get("reference_time"), "reference_time").strftime(DATE_FORMAT)  # type: ignore

    page_size = args.get("page_size", 10000)
    validate_page_size(page_size)
    if int(page_size) > max_page_size:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(max_page_size))
    return start_time, end_time, page_size, reference_time


def get_asset_identifier_details(asset_identifier: dict[str, Any]):
    """
    Return asset identifier detail such as hostname, ip, mac.

    :param asset_identifier: A dictionary that have asset information.
    :type asset_identifier: dict

    :return: asset identifier name.
    :rtype: str
    """
    if asset_identifier.get("hostname", ""):
        return asset_identifier.get("hostname", "")
    if asset_identifier.get("ip", []):
        return "\n".join(asset_identifier.get("ip", []))
    if asset_identifier.get("mac", []):
        return "\n".join(asset_identifier.get("mac", []))
    return None


def get_more_information(event: dict[str, Any]) -> tuple:
    """
    Get more information for event from response.

    :param event: event details.
    :type event: dict

    :return: queried domain, process command line, file use by process.
    :rtype: str, str, str
    """
    queried_domain = ""
    process_command_line = ""
    file_use_by_process = ""

    if event.get("metadata", {}).get("eventType", "") == "NETWORK_DNS":
        questions = event.get("network", {}).get("dns", {}).get("questions", [])
        for question in questions:
            queried_domain += "{}\n".format(question.get("name", ""))

    if event.get("target", {}).get("process", {}).get("commandLine", ""):
        process_command_line += event.get("target", {}).get("process", {}).get("commandLine", "")

    if event.get("target", {}).get("process", {}).get("file", {}).get("fullPath", ""):
        file_use_by_process += event.get("target", {}).get("process", {}).get("file", {}).get("fullPath", "")

    return queried_domain, process_command_line, file_use_by_process


def get_list_events_hr(events: list) -> str:
    """
    Convert events response into human readable.

    :param events: list of events.
    :type events: list

    :return: returns human readable string for gcb-list-events command.
    :rtype: str
    """
    hr_dict = []
    for event in events:
        # Get queried domain, process command line, file use by process information
        queried_domain, process_command_line, file_use_by_process = get_more_information(event)

        hr_dict.append(
            {
                "Event Timestamp": event.get("metadata", {}).get("eventTimestamp", ""),
                "Event Type": event.get("metadata", {}).get("eventType", ""),
                "Principal Asset Identifier": get_asset_identifier_details(event.get("principal", {})),
                "Target Asset Identifier": get_asset_identifier_details(event.get("target", {})),
                "Queried Domain": queried_domain,
                "Process Command Line": process_command_line,
                "File In Use By Process": file_use_by_process,
            }
        )

    hr = tableToMarkdown(
        "Event(s) Details",
        hr_dict,
        [
            "Event Timestamp",
            "Event Type",
            "Principal Asset Identifier",
            "Target Asset Identifier",
            "Queried Domain",
            "File In Use By Process",
            "Process Command Line",
        ],
        removeNull=True,
    )
    return hr


def get_context_for_events(events: list) -> list:
    """
    Convert response into Context data for XSOAR.
    :param events: List of events.
    :type events: list
    :return: list of context data.
    :rtype: list
    """
    events_ec = []
    for event in events:
        event_dict = {}
        if "metadata" in event:
            event_dict.update(event.get("metadata", {}))
        event_dict.update({k: v for k, v in event.items() if k != "metadata"})
        events_ec.append(event_dict)
    return events_ec


def gcb_list_events(
    client_obj,
    asset_identifier_type: str,
    asset_identifier: str,
    start_time: str,
    end_time: str,
    reference_time: str,
    page_size: int,
) -> Dict[str, Any]:
    """
    Return context data and raw response for gcb-list-events command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type asset_identifier_type: str
    :param asset_identifier_type: type of asset identifier.

    :type asset_identifier: str
    :param asset_identifier: asset identifier.

    :type start_time: str
    :param start_time: start time of the time range.

    :type end_time: str
    :param end_time: end time of the time range.

    :type reference_time: str
    :param reference_time: reference time.

    :type page_size: int
    :param page_size: number of output entries to display.

    :rtype: Dict[str, Any]
    :return: json_data: raw response of the request
    """

    url_path = create_url_path(client_obj)
    params = {
        f"assetIndicator.{asset_identifier_type}": asset_identifier,
        "timeRange.startTime": start_time,
        "timeRange.endTime": end_time,
        "maxResults": page_size,
        "referenceTime": reference_time,
    }
    encoded_params = urllib.parse.urlencode(params)
    request_url = f"{url_path}/legacy:legacyFindAssetEvents?{encoded_params}"

    json_data = validate_response(client_obj, request_url)

    return json_data


def convert_numbers_to_strings_for_object(d: Any) -> Any:
    """
    Recursively convert all integer and float values in a object to strings,

    :param d: Input object.
    :type d: Any
    :return: An object with all integer and float values converted to strings.
    :rtype: Any
    """

    def convert(x: Any) -> Any:
        """
        Recursively convert all integer and float values in a nested data structure to strings.

        :param x: A nested data structure containing the values to be converted.
        :return: A nested data structure with all integer and float values converted to strings.
        """
        if isinstance(x, int | float):
            return str(x)
        if isinstance(x, list):
            return [convert(v) for v in x]
        if isinstance(x, dict):
            return {k: convert(v) for k, v in x.items()}
        return x

    if not isinstance(d, dict | list):
        return convert(d)
    if isinstance(d, list):
        return [convert(v) for v in d]
    return {k: convert(v) for k, v in d.items()}


def convert_string_table_case_to_title_case(input_str: str) -> str:
    """
    Convert string in table case to title case.

    :type input_str: str
    :param input_str: string in table case.

    :return: string in title case.
    """
    transformed = re.sub(r"(?<=[a-z])([A-Z])", r" \1", input_str)

    return transformed.title()


def prepare_hr_for_gcb_get_event(event: dict[str, Any]):
    """
    Prepare Human Readable output from the response received.

    :type event: Dict
    :param event: raw response received from api in json format.
    :return: Human Readable output to display.
    :rtype: str
    """

    event = convert_numbers_to_strings_for_object(event)
    metadata = event.get("metadata", {})
    event_id = metadata.get("id", "")
    human_readable = (
        tableToMarkdown(
            f"General Information for the given event with ID: {event_id}",
            metadata,
            removeNull=True,
            headerTransform=convert_string_table_case_to_title_case,
            is_auto_json_transform=True,
        )
        if metadata
        else ""
    )

    principal_info = event.get("principal", {})
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Principal Information",
            principal_info,
            is_auto_json_transform=True,
            headerTransform=convert_string_table_case_to_title_case,
            removeNull=True,
        )
        if principal_info
        else ""
    )

    target_info = event.get("target", {})
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Target Information",
            target_info,
            is_auto_json_transform=True,
            headerTransform=convert_string_table_case_to_title_case,
            removeNull=True,
        )
        if target_info
        else ""
    )

    security_result_info = event.get("securityResult", [])
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Security Result Information",
            security_result_info,
            is_auto_json_transform=True,
            headerTransform=convert_string_table_case_to_title_case,
            removeNull=True,
        )
        if security_result_info
        else ""
    )

    network_info = event.get("network", {})
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Network Information",
            network_info,
            is_auto_json_transform=True,
            headerTransform=convert_string_table_case_to_title_case,
            removeNull=True,
        )
        if network_info
        else ""
    )
    return human_readable


def get_event_list_for_detections_context(result_events: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Convert events response related to the specified detection into list of events for command's context.

    :param result_events: Dictionary containing list of events
    :type result_events: Dict[str, Any]

    :return: returns list of the events related to the specified detection
    :rtype: List[Dict[str,Any]]
    """
    events = []
    if result_events:
        for event in result_events.get("references", []):
            events.append(event.get("event", {}))
    return events


def get_events_context_for_detections(result_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert events in response into Context data for events associated with a detection.

    :param result_events: List of Dictionary containing list of events
    :type result_events: List[Dict[str, Any]]

    :return: list of events to populate in the context
    :rtype: List[Dict[str, Any]]
    """
    events_ec = []
    for collection_element in result_events:
        reference = []
        events = get_event_list_for_detections_context(collection_element)
        for event in events:
            event_dict = {}
            if "metadata" in event:
                event_dict.update(event.pop("metadata"))
            principal_asset_identifier = get_asset_identifier_details(event.get("principal", {}))
            target_asset_identifier = get_asset_identifier_details(event.get("target", {}))
            if principal_asset_identifier:
                event_dict.update({"principalAssetIdentifier": principal_asset_identifier})
            if target_asset_identifier:
                event_dict.update({"targetAssetIdentifier": target_asset_identifier})
            event_dict.update(event)
            reference.append(event_dict)
        collection_element_dict = {"references": reference, "label": collection_element.get("label", "")}
        events_ec.append(collection_element_dict)

    return events_ec


def get_context_for_detections(detection_resp: dict) -> tuple[list[dict], dict]:
    """
    Convert detections response into Context data.

    :param detection_resp: Response fetched from the API call for detections
    :type detection_resp: Dict[str, Any]

    :return: list of detections and token to populate context data
    :rtype: Tuple[List[Dict[str, Any]], Dict[str, str]]
    """
    detections_ec = []
    token_ec = {}
    next_page_token = detection_resp.get("nextPageToken")
    if next_page_token:
        token_ec = {"name": "gcb-list-detections", "nextPageToken": next_page_token}
    detections = detection_resp.get("detections", [])
    for detection in detections:
        detection_dict = detection
        result_events = detection.get("collectionElements", [])
        if result_events:
            detection_dict["collectionElements"] = get_events_context_for_detections(result_events)

        detection_details = detection.get("detection", {})
        if detection_details:
            detection_dict.update(detection_details[0])
            detection_dict.pop("detection")

        time_window_details = detection.get("timeWindow", {})
        if time_window_details:
            detection_dict.update(
                {
                    "timeWindowStartTime": time_window_details.get("startTime"),
                    "timeWindowEndTime": time_window_details.get("endTime"),
                }
            )
            detection_dict.pop("timeWindow")
        detections_ec.append(detection_dict)

    return detections_ec, token_ec


def get_hr_for_event_in_detection(event: dict[str, Any]) -> str:
    """
    Return a string containing event information for an event.

    :param event: event for which hr is to be prepared
    :return: event information in human readable format
    """
    event_info = []

    # Get queried domain, process command line, file use by process information
    queried_domain, process_command_line, file_in_use_by_process = get_more_information(event)
    queried_domain = queried_domain[:-1]

    event_timestamp = event.get("metadata", {}).get("eventTimestamp", "")
    event_type = event.get("metadata", {}).get("eventType", "")
    principal_asset_identifier = get_asset_identifier_details(event.get("principal", {}))
    target_asset_identifier = get_asset_identifier_details(event.get("target", {}))
    if event_timestamp:
        event_info.append(f"**Event Timestamp:** {event_timestamp}")
    if event_type:
        event_info.append(f"**Event Type:** {event_type}")
    if principal_asset_identifier:
        event_info.append(f"**Principal Asset Identifier:** {principal_asset_identifier}")
    if target_asset_identifier:
        event_info.append(f"**Target Asset Identifier:** {target_asset_identifier}")
    if queried_domain:
        event_info.append(f"**Queried Domain:** {queried_domain}")
    if process_command_line:
        event_info.append(f"**Process Command Line:** {process_command_line}")
    if file_in_use_by_process:
        event_info.append(f"**File In Use By Process:** {file_in_use_by_process}")
    return "\n".join(event_info)


def get_events_hr_for_detection(events: list[dict[str, Any]]) -> str:
    """
    Convert events response related to the specified detection into human readable.

    :param events: list of events
    :type events: list

    :return: returns human readable string for the events related to the specified detection
    :rtype: str
    """
    events_hr = []
    for event in events:
        events_hr.append(get_hr_for_event_in_detection(event))

    return "\n\n".join(events_hr)


def get_event_list_for_detections_hr(result_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert events response related to the specified detection into list of events for command's human readable.

    :param result_events: List having dictionary containing list of events.
    :type result_events: List[Dict[str, Any]]

    :return: returns list of the events related to the specified detection.
    :rtype: List[Dict[str,Any]]
    """
    events = []
    if result_events:
        for element in result_events:
            for event in element.get("references", []):
                events.append(event.get("event", {}))
    return events


def get_list_detections_hr(detections: list[dict[str, Any]], rule_or_version_id: str) -> str:
    """
    Convert detections response into human readable.

    :param detections: list of detections
    :type detections: list

    :type rule_or_version_id: str
    :param rule_or_version_id: rule_id or version_id to fetch the detections for.

    :return: returns human readable string for gcb-list-detections command
    :rtype: str
    """
    hr_dict = []
    for detection in detections:
        events = get_event_list_for_detections_hr(detection.get("collectionElements", []))
        detection_details = detection.get("detection", {})
        hr_dict.append(
            {
                "Detection ID": "[{}]({})".format(detection.get("id", ""), detection_details[0].get("urlBackToProduct", "")),
                "Detection Type": detection.get("type", ""),
                "Detection Time": detection.get("detectionTime", ""),
                "Events": get_events_hr_for_detection(events),
                "Alert State": detection_details[0].get("alertState", ""),
            }
        )
    rule_uri = detections[0].get("detection", {})[0].get("urlBackToProduct", "")
    if rule_uri and rule_or_version_id:
        rule_uri = rule_uri.split("/")
        rule_uri = f"{rule_uri[0]}//{rule_uri[2]}/ruleDetections?ruleId={rule_or_version_id}"
        hr_title = "Detection(s) Details For Rule: [{}]({})".format(
            detections[0].get("detection", {})[0].get("ruleName", ""), rule_uri
        )
    else:
        hr_title = "Detection(s)"
    hr = tableToMarkdown(
        hr_title, hr_dict, ["Detection ID", "Detection Type", "Detection Time", "Events", "Alert State"], removeNull=True
    )
    return hr


def get_detections(
    client_obj,
    rule_or_version_id: str,
    page_size: str,
    detection_start_time: str,
    detection_end_time: str,
    page_token: str,
    alert_state: str,
    detection_for_all_versions: bool = False,
    list_basis: str = None,
) -> tuple[dict, dict]:
    """
    Return context data and raw response for gcb-list-detections command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api
    :type rule_or_version_id: str
    :param rule_or_version_id: rule_id or version_id to fetch the detections for.
    :type page_size: str
    :param page_size: Number of detections to fetch at a time.
    :type detection_start_time: str
    :param detection_start_time: The time to start listing detections from.
    :type detection_end_time: str
    :param detection_end_time: The time to start listing detections to.
    :type page_token: str
    :param page_token: The token for the page from which the detections should be fetched.
    :type alert_state: str
    :param alert_state: Alert state for the detections to fetch.
    :type detection_for_all_versions: bool
    :param detection_for_all_versions: Whether to retrieve detections for all versions of a rule with a given rule
    identifier.
    :type list_basis: str
    :param list_basis: To sort the detections.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the fetched detections
    """
    url_path = create_url_path(client_obj)
    if not rule_or_version_id:
        rule_or_version_id = "-"
    if detection_for_all_versions and rule_or_version_id:
        rule_or_version_id = f"{rule_or_version_id}@-"
    params = {
        "ruleId": rule_or_version_id,
        "pageSize": page_size,
        "startTime": detection_start_time,
        "endTime": detection_end_time,
        "alertState": alert_state,
        "listBasis": list_basis,
        "pageToken": page_token,
    }
    remove_nulls_from_dictionary(params)
    encoded_params = urllib.parse.urlencode(params)
    request_url = f"{url_path}/legacy:legacySearchDetections?{encoded_params}"

    json_data = validate_response(client_obj, request_url)
    raw_resp = deepcopy(json_data)
    parsed_ec, token_ec = get_context_for_detections(json_data)
    ec: dict[str, Any] = {SECOPS_OUTPUT_PATHS["Detections"]: parsed_ec}
    if token_ec:
        ec.update({SECOPS_OUTPUT_PATHS["Token"]: token_ec})
    return ec, raw_resp


def get_events_context_for_curatedrule_detections(result_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert events in response into Context data for events associated with a curated rule detection.

    :param result_events: List of Dictionary containing list of events
    :type result_events: List[Dict[str, Any]]

    :return: list of events to populate in the context
    :rtype: List[Dict[str, Any]]
    """
    events_ec = []
    for collection_element in result_events:
        reference = []
        events = get_event_list_for_detections_context(collection_element)
        for event in events:
            event_dict = {}
            if "metadata" in event:
                event_dict.update(event.pop("metadata"))
            principal_asset_identifier = get_asset_identifier_details(event.get("principal", {}))
            target_asset_identifier = get_asset_identifier_details(event.get("target", {}))
            if event.get("securityResult"):
                severity = []
                for security_result in event.get("securityResult", []):
                    if isinstance(security_result, dict) and "severity" in security_result:
                        severity.append(security_result.get("severity"))
                if severity:
                    event_dict.update({"eventSeverity": ",".join(severity)})  # type: ignore
            if principal_asset_identifier:
                event_dict.update({"principalAssetIdentifier": principal_asset_identifier})
            if target_asset_identifier:
                event_dict.update({"targetAssetIdentifier": target_asset_identifier})
            event_dict.update(event)
            reference.append(event_dict)
        collection_element_dict = {"references": reference, "label": collection_element.get("label", "")}
        events_ec.append(collection_element_dict)

    return events_ec


def get_context_for_curatedrule_detections(detection_resp: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Convert curated rule detections response into Context data.

    :param detection_resp: Response fetched from the API call for curated rule detections.
    :type detection_resp: Dict[str, Any]

    :return: list of curated rule detections and token to populate context data.
    :rtype: Tuple[List[Dict[str, Any]], Dict[str, str]]
    """
    detections_ec = []
    token_ec = {}
    next_page_token = detection_resp.get("nextPageToken")
    if next_page_token:
        token_ec = {"name": "gcb-list-curatedrule-detections", "nextPageToken": next_page_token}
    detections = detection_resp.get("curatedDetections", [])
    for detection in detections:
        detection_dict = detection
        result_events = detection.get("collectionElements", [])
        if result_events:
            detection_dict["collectionElements"] = get_events_context_for_curatedrule_detections(result_events)

        detection_details = detection.get("detection", {})
        if detection_details:
            detection_dict.update(detection_details[0])
            detection_dict.pop("detection")

        time_window_details = detection.get("timeWindow", {})
        if time_window_details:
            detection_dict.update(
                {
                    "timeWindowStartTime": time_window_details.get("startTime"),
                    "timeWindowEndTime": time_window_details.get("endTime"),
                }
            )
            detection_dict.pop("timeWindow")
        detections_ec.append(detection_dict)

    return detections_ec, token_ec


def get_list_curatedrule_detections_hr(detections: list[dict[str, Any]], curatedrule_id: str) -> str:
    """
    Convert curated rule detection response into human-readable.

    :param detections: List of detections.
    :type detections: List

    :param curatedrule_id: Curated Rule ID for which detections will be fetched.
    :type curatedrule_id: str

    :return: Returns human-readable string for gcb-list-curatedrule-detections command.
    :rtype: str
    """
    hr_dict = []
    for detection in detections:
        events = get_event_list_for_detections_hr(detection.get("collectionElements", []))
        detection_details = detection.get("detection", [{}])
        hr_dict.append(
            {
                "Detection ID": "[{}]({})".format(detection.get("id", ""), detection_details[0].get("urlBackToProduct", "")),
                "Description": detection_details[0].get("description"),
                "Detection Type": detection.get("type", ""),
                "Detection Time": detection.get("detectionTime", ""),
                "Events": get_events_hr_for_detection(events),
                "Alert State": detection_details[0].get("alertState", ""),
                "Detection Severity": detection_details[0].get("severity", ""),
                "Detection Risk-Score": detection_details[0].get("riskScore", ""),
            }
        )
    rule_uri = detections[0].get("detection", {})[0].get("urlBackToProduct", "")
    if rule_uri and curatedrule_id:
        rule_uri = rule_uri.split("/")
        rule_uri = f"{rule_uri[0]}//{rule_uri[2]}/ruleDetections?ruleId={curatedrule_id}"
        hr_title = "Curated Detection(s) Details For Rule: [{}]({})".format(
            detections[0].get("detection", {})[0].get("ruleName", ""), rule_uri
        )
    else:
        hr_title = "Curated Detection(s)"
    hr = tableToMarkdown(
        hr_title,
        hr_dict,
        [
            "Detection ID",
            "Description",
            "Detection Type",
            "Detection Time",
            "Events",
            "Alert State",
            "Detection Severity",
            "Detection Risk-Score",
        ],
        removeNull=True,
    )
    return hr


def get_curatedrule_detections(
    client_obj,
    curatedrule_id: str,
    page_size: str,
    detection_start_time: str,
    detection_end_time: str,
    page_token: str,
    alert_state: str,
    list_basis: str = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Return context data and raw response for gcb-list-curatedrule-detections command.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.
    :type curatedrule_id: str
    :param curatedrule_id: curatedrule_id to fetch the detections for.
    :type page_size: str
    :param page_size: Number of detections to fetch at a time.
    :type detection_start_time: str
    :param detection_start_time: Start time of the time range to return detections for, filtering by the detection
    field specified in the list_basis parameter.
    :type detection_end_time: str
    :param detection_end_time: End time of the time range to return detections for, filtering by the detection
    field specified by the list_basis parameter.
    :type page_token: str
    :param page_token: The token for the page from which the detections should be fetched.
    :type alert_state: str
    :param alert_state: Filter detections based on whether the alert state is ALERTING or NOT_ALERTING.
    :type list_basis: str
    :param list_basis: Sort detections by DETECTION_TIME or by CREATED_TIME.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, raw_resp: Context data and raw response for the fetched detections
    """

    url_path = create_url_path(client_obj)
    params = assign_params(
        ruleId=curatedrule_id,
        pageSize=page_size,
        startTime=detection_start_time,
        endTime=detection_end_time,
        alertState=alert_state,
        listBasis=list_basis,
        pageToken=page_token,
    )
    encoded_params = urllib.parse.urlencode(params)
    request_url = f"{url_path}/legacy:legacySearchCuratedDetections?{encoded_params}"

    # get list of detections from Google SecOps
    json_data = validate_response(client_obj, request_url)
    raw_resp = deepcopy(json_data)
    parsed_ec, token_ec = get_context_for_curatedrule_detections(json_data)
    ec: dict[str, Any] = {SECOPS_OUTPUT_PATHS["CuratedRuleDetections"]: parsed_ec}
    if token_ec:
        ec.update({SECOPS_OUTPUT_PATHS["Token"]: token_ec})
    return ec, raw_resp


def map_response_for_curated_rule(curated_rule: dict) -> dict:
    """
    Map curated rule response to required format.

    :type curated_rule: Dict
    :param curated_rule: raw response received from api in json format.

    :return: rule in required format.
    :rtype: Dict
    """
    name = curated_rule.get("name", "")
    rule_set_name = curated_rule.get("curatedRuleSet", "")

    # Extract IDs using regex
    rule_id_search_pattern = r"curatedRules/(.*)"
    rule_set_search_pattern = r"curatedRuleSets/(.*)"

    rule_id_match = re.search(rule_id_search_pattern, name)
    rule_set_match = re.search(rule_set_search_pattern, rule_set_name)

    if not rule_id_match or not rule_set_match:
        raise ValueError("Invalid response received from Google SecOps API. Missing rule ID or rule set.")

    rule_id = rule_id_match.group(1)
    rule_set_id = rule_set_match.group(1)

    tactics = [tactic.get("id") for tactic in curated_rule.get("tactics", [])]
    techniques = [technique.get("id") for technique in curated_rule.get("techniques", [])]

    return {
        "ruleId": rule_id,
        "ruleName": curated_rule.get("displayName"),
        "ruleSet": rule_set_id,
        "ruleType": curated_rule.get("type"),
        "description": curated_rule.get("description"),
        "severity": curated_rule.get("severity", {}).get("displayName"),
        "precision": curated_rule.get("precision"),
        "tactics": tactics,
        "techniques": techniques,
        "metadata": curated_rule.get("metadata"),
        "updateTime": curated_rule.get("updateTime"),
    }


def prepare_context_hr_for_gcb_list_curated_rules_command(json_data: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Prepare Context and Human Readable output from the response received.

    :type json_data: Dict
    :param json_data: raw response received from api in json format.

    :return: Context and Human Readable output to display.
    :rtype: tuple[dict[str, Any], str]
    """
    curated_rules = json_data.get("curatedRules", [])

    hr_dict = []
    ec_dict = []
    for rule in curated_rules:
        curated_rule = map_response_for_curated_rule(rule)
        ec_dict.append(curated_rule)

        hr_dict.append(
            {
                "Rule ID": curated_rule.get("ruleId"),
                "Rule Name": curated_rule.get("ruleName"),
                "Severity": curated_rule.get("severity"),
                "Rule Type": curated_rule.get("ruleType"),
                "Rule Set": curated_rule.get("ruleSet"),
                "Description": curated_rule.get("description"),
            }
        )

    hr = tableToMarkdown(
        "Curated Rules", hr_dict, ["Rule ID", "Rule Name", "Severity", "Rule Type", "Rule Set", "Description"], removeNull=True
    )

    ec: dict = {SECOPS_OUTPUT_PATHS["CuratedRules"]: remove_empty_elements(ec_dict)}

    next_page_token = json_data.get("nextPageToken")
    if next_page_token:
        hr += (
            "\nMaximum number of curated rules specified in page_size has been returned. To fetch the next set of"
            f" curated rules, execute the command with the page token as `{next_page_token}`."
        )
        token_ec = {"name": "gcb-list-curatedrules", "nextPageToken": next_page_token}
        ec.update({SECOPS_OUTPUT_PATHS["Token"]: token_ec})

    return ec, hr


def gcb_list_curated_rules(client_obj: Client, page_token: str, page_size: Optional[int]) -> dict[str, Any]:
    """
    Return context data and raw response for gcb-list-curatedrules command.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type page_token: str
    :param page_token: Page token for pagination.

    :type page_size: int
    :param page_size: Maximum number of results to return.

    :rtype: Dict[str, Any]
    :return: json_data: raw response for curated rules.
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/curatedRules?pageSize={page_size}"
    if page_token:
        request_url += f"&pageToken={page_token}"

    json_data = validate_response(client_obj, request_url, method="GET")

    return json_data


def prepare_hr_for_gcb_test_rule_stream_command(detections: list) -> str:
    """
    Prepare Human Readable output from the response received.

    :type detections: list
    :param detections: raw response received from api in json format.

    :return: Human Readable output to display.
    :rtype: str
    """
    hr_dict = []
    for detection in detections:
        detection = detection.get("detection", {})
        events = get_event_list_for_detections_hr(detection.get("collectionElements", []))
        hr_dict.append(
            {
                "Detection ID": detection.get("id", ""),
                "Detection Type": detection.get("type", ""),
                "Detection Time": detection.get("detectionTime", ""),
                "Events": get_events_hr_for_detection(events),
            }
        )
    hr = tableToMarkdown("Detection(s)", hr_dict, ["Detection ID", "Detection Type", "Detection Time", "Events"], removeNull=True)
    return hr


def gcb_test_rule_stream(client_obj, rule_text, start_time, end_time, max_results):
    """
    Return context data and raw response for gcb-test-rule-stream.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_text: str
    :param rule_text: the rule text to for the rule to be created.

    :type start_time: str
    :param start_time: start time of the window.

    :type end_time: str
    :param end_time: end time of the window.

    :type max_results: int
    :param max_results: maximum number of results to return.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response for the created rule.
    """
    req_json_data = {
        "ruleText": rule_text,
        "startTime": start_time,
        "endTime": end_time,
        "maxDetections": max_results,
    }
    url = create_url_path(client_obj)
    request_url = f"{url}/legacy:legacyTestRuleStreaming"

    response = validate_response(client_obj, request_url, method="POST", body=json.dumps(req_json_data))
    json_data = []

    for item in response:
        if "ruleCompilationError" in item:
            error_message = item.get("ruleCompilationError", {}).get("errorText", "")
            raise ValueError(f"Status code: 400\nError: {error_message}")

        if "detection" in item:
            json_data.append(item)

    # context data for the command
    ec = {SECOPS_OUTPUT_PATHS["StreamRules"]: {"list": json_data}}
    return ec, json_data


def get_gcb_udm_search_command_args_value(args: dict[str, Any], max_limit=1000, date_range=None):
    """
    Validate and return gcb-udm-search command arguments default values as per Google SecOps.

    :type args: dict
    :param args: Contain all arguments for command.

    :type max_limit: int
    :param max_limit: Maximum allowed limit.

    :type date_range: string
    :param date_range: The date range to be parsed.

    :return : start_time, end_time, limit, query.
    :rtype : str, str, int, str
    """
    query = args.get("query", "")
    if not query:
        raise ValueError(MESSAGES["QUERY_REQUIRED"])
    query = urllib.parse.quote(args.get("query", ""))
    preset_time_range = args.get("preset_time_range", None)
    if preset_time_range:
        preset_time_range = validate_preset_time_range(preset_time_range)
        start_time, end_time = get_secops_default_date_range(preset_time_range, "preset_time_range")
    else:
        if date_range is None:
            date_range = DEFAULT_FIRST_FETCH
        start_time, end_time = get_secops_default_date_range(days=date_range)
        if args.get("start_time"):
            start_time = arg_to_datetime(args.get("start_time"), "start_time").strftime(DATE_FORMAT)  # type: ignore
        if args.get("end_time"):
            end_time = arg_to_datetime(args.get("end_time"), "end_time").strftime(DATE_FORMAT)  # type: ignore

    limit = args.get("limit", 200)
    if not limit or not str(limit).isdigit() or int(limit) == 0:
        raise ValueError(MESSAGES["INVALID_LIMIT_TYPE"])
    if int(limit) > max_limit:
        raise ValueError(MESSAGES["INVALID_LIMIT_RANGE"].format(max_limit))

    return start_time, end_time, limit, query


def get_udm_search_events_hr(events: list) -> str:
    """
    Convert UDM search events response into human-readable.

    :param events: List of events.
    :type events: List

    :return: Returns human-readable string for gcb-udm-search command.
    :rtype: str
    """
    hr_dict = []
    for event in events:
        # Get queried domain, process command line, file use by process information
        queried_domain, process_command_line, file_in_use_by_process = get_more_information(event)
        security_result_list = []
        for security_result in event.get("securityResult", []):
            security_result_info = []
            severity = security_result.get("severity")
            summary = security_result.get("summary")
            action = security_result.get("action", [])
            rule_name = security_result.get("ruleName")
            if severity:
                security_result_info.append(f"**Severity:** {severity}")
            if summary:
                security_result_info.append(f"**Summary:** {summary}")
            if action and isinstance(action, list):
                security_result_info.append("**Actions:** {}".format(", ".join(action)))
            if rule_name:
                security_result_info.append(f"**Rule Name:** {rule_name}")
            security_result_list.append("\n".join(security_result_info))
        security_results = "\n\n".join(security_result_list)
        hr_dict.append(
            {
                "Event ID": event.get("metadata", {}).get("id"),
                "Event Timestamp": event.get("metadata", {}).get("eventTimestamp", ""),
                "Event Type": event.get("metadata", {}).get("eventType", ""),
                "Security Results": security_results,
                "Principal Asset Identifier": get_asset_identifier_details(event.get("principal", {})),
                "Target Asset Identifier": get_asset_identifier_details(event.get("target", {})),
                "Description": event.get("metadata", {}).get("description"),
                "Product Name": event.get("metadata", {}).get("productName"),
                "Vendor Name": event.get("metadata", {}).get("vendorName"),
                "Queried Domain": queried_domain,
                "Process Command Line": re.escape(process_command_line),
                "File In Use By Process": re.escape(file_in_use_by_process),
            }
        )

    hr = tableToMarkdown(
        "Event(s) Details",
        hr_dict,
        [
            "Event ID",
            "Event Timestamp",
            "Event Type",
            "Security Results",
            "Principal Asset Identifier",
            "Target Asset Identifier",
            "Description",
            "Product Name",
            "Vendor Name",
            "Queried Domain",
            "File In Use By Process",
            "Process Command Line",
        ],
        removeNull=True,
    )
    return hr


def gcb_udm_search(client_obj, start_time: str, end_time: str, limit: int, query: str):
    """
    Make a request URL and get list of events from Google SecOps.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type start_time: str
    :param start_time: The time to start listing events from.

    :type end_time: str
    :param end_time: The time to start listing events to.

    :type limit: int
    :param limit: Number of events to fetch at a time.

    :type query: str
    :param query: Query to search events.

    :return: returns list of events
    :rtype: List[Dict[str, Any]]
    """
    url_path = create_url_path(client_obj)

    request_url = (
        f"{url_path}:udmSearch?timeRange.startTime={start_time}&timeRange.endTime={end_time}&limit={limit}&query={query}"
    )

    # get list of events from Google SecOps
    json_data = validate_response(client_obj, request_url)

    return json_data


def map_response_for_reference_list(reference_list: dict[str, Any]):
    """
    Map reference list response to required format.

    :type reference_list: Dict
    :param reference_list: raw response received from api in json format.

    :return: A dictionary of reference list attributes.
    :rtype: Dict
    """
    lines = [entry.get("value", "") for entry in reference_list.get("entries", [])]
    content_type = CONTENT_TYPE_MAPPING.get(reference_list.get("syntaxType", DEFAULT_SYNTAX_TYPE), DEFAULT_CONTENT_TYPE)

    return {
        "name": reference_list.get("displayName", ""),
        "description": reference_list.get("description", ""),
        "createTime": reference_list.get("revisionCreateTime", ""),
        "lines": lines,
        "contentType": content_type,
    }


def prepare_hr_for_gcb_create_get_update_reference_list(json_data, table_name="Reference List Details"):
    """
    Prepare human-readable for gcb_create_reference_list, gcb_get_reference_list, gcb_update_reference_list command.

    :type json_data: Dict[str, Any]
    :param json_data: Response of the command.

    :type table_name: str
    :param table_name: Name of the table to display.

    :rtype: str
    :return: Human readable string for the command.
    """
    hr_output = {
        "Name": json_data.get("name"),
        "Description": json_data.get("description"),
        "Creation Time": json_data.get("createTime"),
        "Content Type": json_data.get("contentType"),
        "Content": string_escape_markdown(json_data.get("lines")),
    }

    headers = ["Name", "Content Type", "Description", "Creation Time", "Content"]

    return tableToMarkdown(table_name, hr_output, headers=headers, removeNull=True)


def gcb_get_reference_list(client_obj, name, view):
    """
    Return context data and raw response for gcb-get-reference-list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: Unique name of the reference list.

    :type view: str
    :param view: it is the view type of the lists to be displayed.

    :rtype: Dict[str, Any]
    :return: json_data: raw response of the request.
    """
    encoded_params = urllib.parse.urlencode(assign_params(view=view))
    url = create_url_path(client_obj)
    request_url = f"{url}/referenceLists/{name}?{encoded_params}"
    json_data = validate_response(client_obj, request_url, method="GET")

    return json_data


def gcb_create_reference_list(client_obj, name, description, lines, content_type):
    """
    Return context data and raw response for gcb_create_reference_list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: the name of the list to create.

    :type description: str
    :param description: description of the list to create.

    :type lines: list
    :param lines: items to put in the list.

    :type content_type: str
    :param content_type: the content_type of lines.

    :rtype: Dict[str, Any]
    :return: json_data: raw response of the request.
    """
    syntax_type = SYNTAX_TYPE_MAPPING.get(content_type.upper(), DEFAULT_SYNTAX_TYPE)
    entries = []
    for line in lines:
        entries.append({"value": line})
    body = {
        "description": description,
        "entries": entries,
        "syntaxType": syntax_type,
    }
    url = create_url_path(client_obj)
    request_url = f"{url}/referenceLists?referenceListId={name}"
    json_data = validate_response(client_obj, request_url, method="POST", body=json.dumps(body))
    return json_data


def gcb_update_reference_list(client_obj, name, lines, description, content_type):
    """
    Return context data and raw response for gcb_update_reference_list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: the name of the list to create.

    :type description: str
    :param description: description of the list to create.

    :type lines: list
    :param lines: items to put in the list.

    :type content_type: str
    :param content_type: the content_type of lines.

    :rtype: Dict[str, Any]
    :return: json_data: raw response of the request.
    """
    url = create_url_path(client_obj)
    request_url = f"{url}/referenceLists/{name}"

    syntax_type = SYNTAX_TYPE_MAPPING.get(content_type.upper(), DEFAULT_SYNTAX_TYPE)
    entries = []
    for line in lines:
        entries.append({"value": line})
    body = {
        "description": description,
        "entries": entries,
        "syntaxType": syntax_type,
    }
    json_data = validate_response(client_obj, request_url, method="PATCH", body=json.dumps(body))

    return json_data


def prepare_hr_for_gcb_list_reference_list(reference_lists):
    """
    Prepare human-readable for gcb-list-reference-list.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-list-reference-list

    :rtype: str
    :return: Human readable string for gcb-list-reference-list
    """
    hr_output = []
    for output in reference_lists:
        hr_output.append(
            {
                "Name": output.get("name"),
                "Creation Time": output.get("createTime"),
                "Description": output.get("description"),
                "Content Type": output.get("contentType"),
                "Content": string_escape_markdown(output.get("lines")),
            }
        )
    hr = tableToMarkdown(
        "Reference List Details",
        hr_output,
        headers=["Name", "Content Type", "Creation Time", "Description", "Content"],
        removeNull=True,
    )

    return hr


def gcb_list_reference_list(client_obj, page_size, page_token, view):
    """
    Return context data and raw response for gcb-list-reference-list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type page_size: int
    :param page_size: it indicates the no. of output entries to display

    :type page_token: str
    :param page_token: it is the base64 page token for next page of the outputs

    :type view: str
    :param view: it is the view type of the lists to be displayed

    :rtype: Dict[str, Any]
    :return: json_data: raw response of the request
    """
    encoded_params = urllib.parse.urlencode(assign_params(pageSize=page_size, pageToken=page_token, view=view))

    url = create_url_path(client_obj)
    request_url = f"{url}/referenceLists?{encoded_params}"

    json_data = validate_response(client_obj, request_url, method="GET")

    return json_data


def prepare_hr_for_verify_reference_list(json_data, content_type):
    """
    Prepare human-readable for gcb-verify-reference-list.

    :type json_data: Dict[str, Any]
    :param json_data: Response of gcb-verify-reference-list.

    :type content_type: str
    :param content_type: the content_type of lines.

    :rtype: str
    :return: Human readable string for gcb-verify-reference-list.
    """
    success = json_data.get("success", False)
    if success:
        return "### All provided lines meet validation criteria"
    json_data = json_data.get("errors", [])
    hr_output = []
    for output in json_data:
        hr_output.append(
            {
                "Line Number": output.get("lineNumber"),
                "Message": string_escape_markdown(output.get("errorMessage")),
            }
        )
    hr = tableToMarkdown(
        f"The following lines contain invalid {content_type} pattern",
        hr_output,
        headers=["Line Number", "Message"],
        removeNull=True,
    )
    return hr


def gcb_verify_reference_list(client_obj, lines, syntax_type):
    """
    Return context data and raw response for gcb_verify_reference_list command.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type lines: list
    :param lines: items to validate.

    :type syntax_type: str
    :param syntax_type: the syntax_type of lines.

    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    :return: ec, json_data: Context data and raw response of the request.
    """
    url = create_url_path(client_obj)
    request_url = f"{url}:verifyReferenceList"
    body = {"entries": lines, "syntaxType": syntax_type}
    json_data = validate_response(client_obj, request_url, method="POST", body=json.dumps(body))
    json_data["command_name"] = "gcb-verify-reference-list"
    json_data["success"] = json_data.get("success", False)
    json_data["errors"] = json_data.get("errors", [])
    ec = {SECOPS_OUTPUT_PATHS["VerifyReferenceList"]: json_data}
    return ec, json_data


def get_unique_value_from_list(data: list) -> list:
    """
    Return unique value of list with preserving order.

    :type data: list
    :param data: List of values.

    :rtype: list
    :return: List of unique values.
    """
    output = []

    for value in data:
        if value and value not in output:
            output.append(value)

    return output


def gcb_list_iocs(client_obj, start_time: str, end_time: str, page_size: int) -> dict:
    """
    Make a request URL and get list of IoCs from Google SecOps.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type start_time: str
    :param start_time: The time to start listing IoCs from.

    :type end_time: str
    :param end_time: The time to end listing IoCs to.

    :type page_size: int
    :param page_size: Number of IoCs to fetch at a time.

    :return: returns list of IoCs
    :rtype: List[Dict[str, Any]]
    """
    url_path = create_url_path(client_obj)
    params = f"timestampRange.startTime={start_time}&timestampRange.endTime={end_time}&maxMatchesToReturn={page_size}"
    request_url = f"{url_path}/legacy:legacySearchEnterpriseWideIoCs?{params}"

    # get list of IoCs from Google SecOps
    json_data = validate_response(client_obj, request_url)

    return json_data


def is_category_malicious(category, reputation_params):
    """Determine if category is malicious in reputation_params."""
    return category and category.lower() in reputation_params["malicious_categories"]


def is_severity_malicious(severity, reputation_params):
    """Determine if severity is malicious in reputation_params."""
    return severity and severity.lower() in reputation_params["override_severity_malicious"]


def is_confidence_score_malicious(confidence_score, params):
    """Determine if confidence score is malicious in reputation_params."""
    return is_int_type_malicious_score(confidence_score, params) or is_string_type_malicious_score(confidence_score, params)


def is_string_type_malicious_score(confidence_score, params):
    """Determine if string type confidence score is malicious in reputation_params."""
    return not isinstance(confidence_score, int) and CONFIDENCE_LEVEL_PRIORITY.get(
        params["override_confidence_level_malicious"], 10
    ) <= CONFIDENCE_LEVEL_PRIORITY.get(confidence_score.lower(), -1)


def is_int_type_malicious_score(confidence_score, params):
    """Determine if integer type confidence score is malicious in reputation_params."""
    return (
        params["override_confidence_score_malicious_threshold"]
        and isinstance(confidence_score, int)
        and int(params["override_confidence_score_malicious_threshold"]) <= confidence_score
    )


def is_category_suspicious(category, reputation_params):
    """Determine if category is suspicious in reputation_params."""
    return category and category.lower() in reputation_params["suspicious_categories"]


def is_severity_suspicious(severity, reputation_params):
    """Determine if severity is suspicious in reputation_params."""
    return severity and severity.lower() in reputation_params["override_severity_suspicious"]


def is_confidence_score_suspicious(confidence_score, params):
    """Determine if confidence score is suspicious in reputation_params."""
    return is_int_type_suspicious_score(confidence_score, params) or is_string_type_suspicious_score(confidence_score, params)


def is_string_type_suspicious_score(confidence_score, params):
    """Determine if string type confidence score is suspicious in reputation_params."""
    return not isinstance(confidence_score, int) and CONFIDENCE_LEVEL_PRIORITY.get(
        params["override_confidence_level_suspicious"], 10
    ) <= CONFIDENCE_LEVEL_PRIORITY.get(confidence_score.lower(), -1)


def is_int_type_suspicious_score(confidence_score, params):
    """Determine if integer type confidence score is suspicious in reputation_params."""
    return (
        params["override_confidence_score_suspicious_threshold"]
        and isinstance(confidence_score, int)
        and int(params["override_confidence_score_suspicious_threshold"]) <= confidence_score
    )


def evaluate_dbot_score(category, severity, confidence_score):
    """
    Calculate the dbot score according to category, severity and confidence score configured.

    :type category: str
    :param category: category received in the response of list-ioc-details endpoint

    :type severity: str
    :param severity: severity received in the response of list-ioc-details endpoint

    :type confidence_score: int or str
    :param confidence_score: confidence_score received in the response of list-ioc-details endpoint

    :return: the function returns dbot score based on the entered parameters.
    :rtype: int
    """
    params = get_params_for_reputation_command(demisto.params())

    dbot_score = 0

    # Check if the category belongs to configured Malicious category/severity/threshold score.
    if (
        is_category_malicious(category, params)
        or is_severity_malicious(severity, params)
        or is_confidence_score_malicious(confidence_score, params)
    ):
        dbot_score = 3

    # Check if the category belongs to configured Suspicious category/severity/threshold score.
    elif (
        is_category_suspicious(category, params)
        or is_severity_suspicious(severity, params)
        or is_confidence_score_suspicious(confidence_score, params)
    ):
        dbot_score = 2

    return dbot_score


def decode_ip_address(ip_address: str) -> str:
    """
    Decode the IP address if it is in base64 format.

    :type ip_address: str
    :param ip_address: IP address to decode

    :rtype: str
    :return: decoded IP address
    """
    if is_ip_valid(ip_address, accept_v6_ips=True):
        return ip_address

    ip_bytes = b64_decode(ip_address)  # XSOAR's built-in Base64 decode
    return socket.inet_ntoa(ip_bytes)


def map_response_for_ioc_details(ioc_details):
    """
    Map ioc details response to required format.

    :type ioc_details: Dict
    :param ioc_details: raw response received from api in json format.

    :return: rule in required format.
    :rtype: Dict
    """
    ioc_detail = ioc_details.get("iocs", [{}])[0]

    if not ioc_detail:
        return {}

    confidence_score = {"strRawConfidenceScore": ioc_detail.get("confidenceScore", "")}
    # Map addresses
    addresses = []
    addresses.append({"domain": ioc_detail.get("domainAndPorts", {})})
    addresses.append({"ipAddress": ioc_detail.get("ipAndPorts", {})})

    return {
        "sourceName": ioc_details.get("metadata", {}).get("title", ""),
        "confidenceScore": confidence_score,
        "rawSeverity": ioc_detail.get("rawSeverity", ""),
        "category": ioc_detail.get("categorization", ""),
        "addresses": addresses,
        "firstActiveTime": ioc_detail.get("activeTimerange", {}).get("start", "1970-01-01T00:00:00Z"),
        "lastActiveTime": ioc_detail.get("activeTimerange", {}).get("end", "9999-12-31T23:59:59Z"),
    }


def prepare_hr_for_ioc_details(addresses, hr_table_row):
    """
    Prepare HR for IOC Details.

    :param hr_table_row: dictionary containing HR details.
    :param addresses: List of addresses.
    :return: updated HR dictionary.
    """
    address_data: list = []
    for address in addresses:
        if address.get("domain"):
            domain_indicator = address.get("domain")
            address_data.append({"Domain": domain_indicator.get("domain"), "Port": domain_indicator.get("ports", [])})
            hr_table_row["Domain"] = domain_indicator.get("domain")

        if address.get("ipAddress"):
            ip_indicator = address.get("ipAddress")
            ip_address = decode_ip_address(ip_indicator.get("ipAddress"))
            address_data.append({"IpAddress": ip_address, "Port": ip_indicator.get("ports", [])})
            hr_table_row[IP_ADDRESS] = ip_address

    return remove_empty_elements(address_data), hr_table_row


def get_context_for_ioc_details(sources, artifact_indicator, artifact_type, is_reputation_command=True):
    """
    Generate context data for reputation command and ioc details command.

    :type sources: list
    :param sources: list of the sources getting response from listiocdetails endpoint.

    :type artifact_indicator: str
    :param artifact_indicator: inputted artifact indicator.

    :type artifact_type: str
    :param artifact_type: the type of artifact.

    :type is_reputation_command: bool
    :param is_reputation_command: true if the command is execute for reputation command, default is true.

    :return: returns dict of context data, human readable, and reputation.
    :rtype: dict
    """
    dbot_context: dict = {}
    standard_context: dict = {}
    source_data_list: list = []
    hr_table_data: list = []

    # To hold the max dbot score across sources.
    dbot_score_max = 0
    for source in sources:
        source = map_response_for_ioc_details(source)
        category = source.get("category")
        severity = source.get("rawSeverity")

        # if confidence score is not in numeric value, then it set confidence score will be set to 0
        confidence_score = source.get("confidenceScore", {}).get("strRawConfidenceScore")
        if confidence_score and confidence_score.isnumeric():
            confidence_score = int(confidence_score)

        if is_reputation_command:
            # Highest confidence score across the sources is considered for dbot_score
            source_dbot_score = evaluate_dbot_score(category, severity, confidence_score)
            dbot_score_max = max(dbot_score_max, source_dbot_score)

        # prepare table content for Human Readable Data
        hr_table_row = {
            "Domain": "-",
            IP_ADDRESS: "-",
            "Category": category,
            CONFIDENCE_SCORE: confidence_score,
            "Severity": severity,
            FIRST_ACCESSED_TIME: source.get("firstActiveTime"),
            LAST_ACCESSED_TIME: source.get("lastActiveTime"),
        }

        # Parsing the Addresses data to fetch IP and Domain data for context
        address_data, hr_table_row = prepare_hr_for_ioc_details(source.get("addresses", []), hr_table_row)
        hr_table_data.append(hr_table_row)

        source_data_list.append(
            {
                "Address": address_data,
                "Category": category,
                "ConfidenceScore": confidence_score,
                "FirstAccessedTime": source.get("firstActiveTime", ""),
                "LastAccessedTime": source.get("lastActiveTime", ""),
                "Severity": severity,
            }
        )

    # Setting standard context
    standard_context[STANDARD_CTX_KEY_MAP[artifact_type]] = artifact_indicator
    if is_reputation_command:
        # set dbot context
        dbot_context = {
            "Indicator": artifact_indicator,
            "Type": artifact_type,
            "Vendor": VENDOR,
            "Score": dbot_score_max,
            "Reliability": demisto.params().get("integrationReliability"),
        }
        if dbot_score_max == 3:
            standard_context["Malicious"] = {"Vendor": VENDOR, "Description": "Found in malicious data set"}

    context = {"IoCQueried": artifact_indicator, "Sources": source_data_list}

    return {
        "dbot_context": dbot_context,
        "standard_context": standard_context,
        "context": context,
        "hr_table_data": hr_table_data,
        "reputation": DBOT_SCORE_MAPPING[dbot_score_max],
    }


def gcb_list_data_tables(client_obj, page_size: int, page_token: str) -> tuple:
    """
    List data tables.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type page_size: int
    :param page_size: page size.

    :type page_token: str
    :param page_token: page token.

    :return: raise ValueError if any error occurred during connection.
    :rtype: tuple[list[dict[str, Any]], dict[str, Any]]
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/dataTables?pageSize={page_size}"
    if page_token:
        request_url += f"&pageToken={page_token}"
    json_data = validate_response(client_obj, request_url, method="GET")
    data_tables = json_data.get("dataTables", [])
    ec = {SECOPS_OUTPUT_PATHS["DataTable"]: data_tables}
    return json_data, ec


def prepare_hr_for_list_data_table_details(data_tables: list[dict[str, Any]]) -> str:
    """
    Prepare HR for data tables.

    :type data_tables: list[dict[str, Any]]
    :param data_tables: list of data tables.

    :rtype: str
    :return: updated HR dictionary.
    """
    table_name = "Data Tables"
    readable_data_tables = deepcopy(data_tables)
    for data_table in readable_data_tables:
        column_info = []
        for column in data_table.get("columnInfo", []):
            column_info.append(
                {
                    "Column Name": column.get("originalColumn"),
                    "Column Type": column.get("columnType"),
                }
            )
        data_table["columnInfo"] = column_info
    readable_output = tableToMarkdown(
        table_name,
        readable_data_tables,
        headerTransform=pascalToSpace,
        removeNull=True,
        is_auto_json_transform=True,
        headers=[
            "displayName",
            "description",
            "columnInfo",
            "createTime",
            "updateTime",
            "approximateRowCount",
        ],
    )
    return readable_output


def prepare_hr_for_data_table_metadata_details(json_data: dict[str, Any]) -> str:
    """
    Prepare human-readable for data table metadata details.

    :type json_data: Dict[str, Any]
    :param json_data: Response of data table metadata details.

    :rtype: str
    :return: Human readable string for data table metadata details.
    """
    column_data = json_data.get("columnInfo", [])
    column_info = []
    for column in column_data:
        column_info.append({"Column Name": column.get("originalColumn"), "Column Type": column.get("columnType")})

    hr_dict = {
        "Display Name": json_data.get("displayName"),
        "Description": json_data.get("description"),
        "Create Time": json_data.get("createTime"),
        "Update Time": json_data.get("updateTime"),
        "Columns Info": column_info,
        "Approximate Row Count": json_data.get("approximateRowCount"),
    }
    headers = ["Display Name", "Description", "Columns Info", "Create Time", "Update Time", "Approximate Row Count"]
    return tableToMarkdown("Data Table Details", hr_dict, headers=headers, removeNull=True, is_auto_json_transform=True)


def gcb_create_data_table(client_obj, name: str, description: str, columns_list: list):
    """
    Make a request URL and create a new data table schema.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: The name of the data table.

    :type description: str
    :param description: The description of the data table.

    :type columns_list: list
    :param columns_list: The list of columns for the data table.

    :return: returns the created data table schema and entry context.
    :rtype: Dict[str, Any], Dict[str, Any]
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/dataTables?dataTableId={name}"
    data: dict[str, Any] = {
        "columnInfo": columns_list,
    }
    if description:
        data["description"] = description
    # create a new data table schema
    json_data = validate_response(client_obj, request_url, method="POST", body=json.dumps(data))

    ec = {SECOPS_OUTPUT_PATHS["DataTable"]: json_data}
    return json_data, ec


def gcb_get_data_table(client_obj, name: str) -> tuple[dict, dict]:
    """
    Make a request URL and get data table.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: The name of the data table.

    :return: returns the data table and entry context.
    :rtype: Dict[str, Any], Dict[str, Any]
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/dataTables/{name}"
    # get data table
    json_data = validate_response(client_obj, request_url, method="GET")

    ec = {SECOPS_OUTPUT_PATHS["DataTable"]: json_data}
    return json_data, ec


def prepare_ec_data_table_rows(rows_data: list[dict[str, Any]], columns: list[str]) -> list[dict[str, Any]]:
    """
    Prepare entry context for data table rows.

    :type rows_data: List[Dict[str, Any]]
    :param rows_data: data table rows.

    :type columns: List[str]
    :param columns: columns of the data table.

    :return: returns the entry context for data table rows.
    :rtype: List[Dict[str, Any]]
    """
    ec_data = []
    for row in rows_data:
        row_values = {}
        for index, value in enumerate(row.get("values", [])):
            row_values.update({columns[index]: value})

        row["values"] = row_values
        ec_data.append(row)

    return ec_data


def prepare_hr_for_data_table_rows(json_data: list[dict[str, Any]], title: str) -> str:
    """
    Prepare human readable for data table rows.

    :type json_data: List[Dict[str, Any]]
    :param json_data: data table rows.

    :type title: str
    :param title: title of the human readable.

    :return: returns the human readable for data table rows.
    :rtype: str
    """
    hr_dict = []
    if not json_data:
        return "### No Rows Data Found"

    for row in json_data:
        hr_dict.append(string_escape_markdown(row.get("values", [])))

    return tableToMarkdown(title, hr_dict, removeNull=True, sort_headers=False)


def gcb_get_data_table_rows(client_obj, name: str, max_rows_to_return: int, page_token: str) -> dict[str, Any]:
    """
    Make a request URL and get data table rows.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: The name of the data table.

    :type max_rows_to_return: int
    :param max_rows_to_return: The maximum number of rows to return.

    :type page_token: str
    :param page_token: The page token to use for pagination.

    :return: returns the data table rows.
    :rtype: Dict[str, Any]
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/dataTables/{name}/dataTableRows?pageSize={max_rows_to_return}"
    # get data table rows
    if page_token:
        request_url += f"&pageToken={page_token}"
    json_data = validate_response(client_obj, request_url, method="GET")

    return json_data


def prepare_body_data_for_data_table_rows(rows: list, columns: dict[str, int]) -> dict:
    """
    Prepare body data for data table rows.

    :type rows: list
    :param rows: list of rows.

    :type columns: dict
    :param columns: dictionary of columns.

    :return: returns the body data for data table rows.
    :rtype: dict
    """
    rows_data = []
    # Sort columns by index value to ensure correct order
    max_index = max(columns.values())

    for row in rows:
        # Create a list with empty values for all possible positions
        row_data = [""] * (max_index + 1)
        row_column_count = len(row.keys())
        if row_column_count != max_index + 1:
            raise ValueError("Invalid value provided in the 'rows' parameter. Please check if the all column names are provided.")
        # Fill in values at the correct indices
        for column_name, value in row.items():
            if column_name not in columns:
                raise ValueError(
                    f"Invalid value provided in the 'rows' parameter. Column '{column_name}' not found in the data table."
                )
            row_data[columns[column_name]] = value

        rows_data.append({"data_table_row": {"values": row_data}})

    return {"requests": rows_data}


def prepare_hr_and_context_for_data_table_add_rows(
    data_table_name: str, json_data: dict, rows: list[dict]
) -> tuple[str, dict[str, Any]]:
    """
    Prepare human readable and entry context for data table add rows.

    :type data_table_name: str
    :param data_table_name: name of the data table.

    :type json_data: Dict
    :param json_data: data table rows.

    :type rows: List[Dict[str, Any]]
    :param rows: list of rows.

    :return: returns the human readable and entry context for data table rows.
    :rtype: Tuple[str, Dict[str, Any]]
    """
    ec_data = []
    rows_data = json_data.get("dataTableRows", [])
    for index, row in enumerate(rows):
        ec_data.append({"name": rows_data[index].get("name"), "values": row})

    title = f"Successfully added rows to the {data_table_name} data table"
    hr = prepare_hr_for_data_table_rows(ec_data, title)

    ec = {SECOPS_OUTPUT_PATHS["DataTableRows"]: ec_data}
    return hr, ec


def gcb_data_table_add_row(client_obj, name: str, body_data: dict):
    """
    Add rows to a data table.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: The name of the data table.

    :type body_data: dict
    :param body_data: dictionary of body data.

    :return: returns the body data for data table rows.
    :rtype: dict
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/dataTables/{name}/dataTableRows:bulkCreate"

    json_data = validate_response(client_obj, request_url, method="POST", body=json.dumps(body_data))

    return json_data


def find_rows_matching_criteria(all_rows, criteria_rows, columns):
    """
    Find rows in a data table that match the given criteria.

    :type all_rows: list
    :param all_rows: list of all rows in the data table.

    :type criteria_rows: list
    :param criteria_rows: list of row criteria to match.

    :type columns: dict
    :param columns: mapping of column names to indices.

    :return: list of row IDs matching the criteria.
    :rtype: list
    """
    rows_to_remove = []

    # Process each criteria object separately as specified in the TDD
    for criteria in criteria_rows:
        for row in all_rows.get("dataTableRows", []):
            match = True
            row_values = row.get("values", [])

            # Check if all criteria fields match the row values
            for col_name, criteria_value in criteria.items():
                col_index = columns[col_name]
                if row_values[col_index] != criteria_value:
                    match = False
                    break

            if match and row not in rows_to_remove:
                rows_to_remove.append(row)
    return rows_to_remove


def gcb_data_table_delete_row(client_obj, name, row_id):
    """
    Delete a row from a data table.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type name: str
    :param name: name of the data table.

    :type row_id: str
    :param row_id: id of the row to be deleted.

    :return: response from api.
    :rtype: dict
    """
    url_path = create_url_path(client_obj)
    url = f"{url_path}/dataTables/{name}/dataTableRows/{row_id}"
    response = validate_response(client_obj, url, "DELETE")

    return response


def prepare_hr_for_get_detection(detection: dict) -> str:
    """
    Prepare human readable for get detection.

    :param detection: Response fetched from the API call for get detection.
    :type detection: Dict[str, Any]

    :return: human readable for get detection.
    :rtype: str
    """
    events = get_event_list_for_detections_hr(detection.get("collectionElements", []))
    detection_details = detection.get("detection", [{}])[0]
    severity = ""
    for label in detection_details.get("ruleLabels", []):
        if label.get("key") == "severity":
            severity = label.get("value", "")
            break

    hr_dict = {
        "Detection ID": "[{}]({})".format(detection.get("id", ""), detection_details.get("urlBackToProduct", "")),
        "Detection Type": detection.get("type", ""),
        "Rule Name": detection_details.get("ruleName", ""),
        "Rule ID": detection_details.get("ruleId", ""),
        "Rule Type": detection_details.get("ruleType", ""),
        "Severity": severity,
        "Risk Score": detection_details.get("riskScore", ""),
        "Alert State": detection_details.get("alertState", ""),
        "Description": detection_details.get("description", ""),
        "Events": get_events_hr_for_detection(events),
        "Created Time": detection.get("createdTime", ""),
        "Detection Time": detection.get("detectionTime", ""),
    }

    hr_title = f"Detection Details for {detection.get('id', '')}"
    headers = [
        "Detection ID",
        "Detection Type",
        "Rule Name",
        "Rule ID",
        "Rule Type",
        "Severity",
        "Risk Score",
        "Alert State",
        "Description",
        "Events",
        "Created Time",
        "Detection Time",
    ]

    hr = tableToMarkdown(
        hr_title,
        hr_dict,
        headers=headers,
        removeNull=True,
    )
    return hr


def get_context_for_get_detection(detection: dict) -> dict:
    """
    Convert get detection response into Context data.

    :param detection: Response fetched from the API call for get detection.
    :type detection: Dict[str, Any]

    :return: detection to populate context data.
    :rtype: Dict[str, Any]
    """
    detection_dict = detection
    result_events = detection.get("collectionElements", [])
    if result_events:
        detection_dict["collectionElements"] = get_events_context_for_detections(result_events)

    detection_details = detection.get("detection", {})
    if detection_details:
        detection_dict.update(detection_details[0])
        detection_dict.pop("detection", None)

    time_window_details = detection.get("timeWindow", {})
    if time_window_details:
        detection_dict.update(
            {
                "timeWindowStartTime": time_window_details.get("startTime"),
                "timeWindowEndTime": time_window_details.get("endTime"),
            }
        )
        detection_dict.pop("timeWindow", None)

    return detection_dict


def gcb_get_detection(client_obj, rule_id: str, detection_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Make a request URL and get detection.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type rule_id: str
    :param rule_id: The ID of the rule.

    :type detection_id: str
    :param detection_id: The ID of the detection.

    :return: returns the detection and entry context.
    :rtype: Tuple[Dict[str, Any], Dict[str, Any]]
    """
    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/legacy:legacyGetDetection?ruleId={rule_id}&detectionId={detection_id}"

    json_data = validate_response(client_obj, request_url, method="GET")

    raw_resp = deepcopy(json_data)
    parsed_ec = get_context_for_get_detection(json_data)
    ec: dict[str, Any] = {SECOPS_OUTPUT_PATHS["Detections"]: parsed_ec}

    return raw_resp, ec


""" COMMAND FUNCTIONS """


def test_function(client_obj, params: dict[str, Any]):
    """
    Perform test connectivity by validating a valid http response.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type params: Dict[str, Any]
    :param params: it contain configuration parameter.

    :return: raise ValueError if any error occurred during connection.
    :rtype: None
    """
    demisto.debug("Running Test having Proxy {}".format(params.get("proxy")))
    is_fetch = argToBoolean(params.get("isFetch", False))
    if is_fetch:
        fetch_incidents(client_obj, params, is_test=True)
    else:
        url_path = create_url_path(client_obj)
        request_url = f"{url_path}/rules?pageSize=1"

        validate_response(client_obj, request_url)
    demisto.results("ok")


def fetch_incidents(client_obj, params: dict[str, Any], is_test: bool = False) -> tuple[list, dict]:
    """
    Fetch IOC domain matches and convert them into actionable incidents for Demisto.

    :type client_obj: Client
    :param client_obj: Object of the client class.

    :type params: Dict[str, Any]
    :param params: Configuration parameter of fetch incidents.

    :type is_test: bool
    :param is_test: Whether the function is being called for test connectivity.

    :return: List of incidents and last run.
    :rtype: (list, dict)
    """

    first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH).lower()  # 3 days as default
    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))  # default page size

    index = 1
    previous_artifact_values = []
    time_window = params.get("time_window", "")

    start_time, current_time_dt = arg_to_datetime(first_fetch), datetime.now()
    start_time, end_time = start_time.strftime(DATE_FORMAT), current_time_dt.strftime(DATE_FORMAT)  # type: ignore
    current_time = end_time

    # get start_time from last run or config
    all_last_run = demisto.getLastRun()
    last_run = all_last_run.get("ioc_domain_matches", {})
    demisto.debug(
        f"Fetch IoCs: Configuration Parameters - First Fetch: {first_fetch}, Max Fetch: {max_fetch}, Time Window: {time_window}"
    )

    if last_run:
        start_time = last_run.get("start_time") or start_time
        end_time = last_run.get("end_time") or end_time
        previous_artifact_values = last_run.get("previous_artifact_values", [])
        index = last_run.get("index") or index

    delayed_start_time = generate_delayed_start_time(time_window, start_time)
    demisto.debug(
        f"Fetch IoCs: Calculated Delayed Start time: {start_time}(Start time) - {time_window}(Time Window) = {delayed_start_time}"
    )

    no_of_tries = 0
    exited_early = False

    while index == 1 and no_of_tries < TOTAL_TRIES:
        demisto.debug(
            f"Fetch IoCs: Attempt {no_of_tries + 1}. Adjusting time interval Start time {delayed_start_time}, End time {end_time}"
        )
        events, more_data_available = get_ioc_domain_matches(
            client_obj, delayed_start_time, end_time, MAX_IOCS_FETCH_SIZE, is_raw=True
        )

        if is_test:
            return [], {}
        if not more_data_available or len(events) < MAX_IOCS_FETCH_SIZE:
            demisto.debug(
                f"Fetch IoCs: Time interval contains {len(events)} IoCs (less than {MAX_IOCS_FETCH_SIZE}). "
                f"More data available: {more_data_available}. Using this interval for fetching."
            )
            exited_early = True
            break

        demisto.debug(
            f"Fetch IoCs: Time interval contains {len(events)} IoCs (exceeds {MAX_IOCS_FETCH_SIZE}). "
            f"More data available: {more_data_available}. Reducing end time."
        )
        end_time, time_diff_one_microsecond = add_diff_time_to_end_time(delayed_start_time, end_time)

        if time_diff_one_microsecond:
            demisto.debug(
                f"Fetch IoCs: Time difference is less than 1 microsecond. Processing first {MAX_IOCS_FETCH_SIZE} records only. "
                f"More data available: {more_data_available}. Records beyond {MAX_IOCS_FETCH_SIZE} will be skipped."
            )
            exited_early = True
            break

        no_of_tries += 1

        # Check if now - current_time > 4 minutes
        now = datetime.now()
        if (now - current_time_dt).total_seconds() > 240:
            demisto.debug(
                "Fetch IoCs: Time interval adjustment exceeded 4 minutes. "
                "Exiting loop and will continue from this point in the next fetch cycle."
            )
            break

    demisto.debug(f"Fetch IoCs: Calling API with Start time {delayed_start_time}, End time {end_time}")

    # If exited_early is False, it means either:
    # The current time interval contains more than 10,000 records, or Adjusting the time interval took more than 4 minutes.
    # In this case, we won’t increment the index, and in the next fetch cycle, the time interval will be reduced.
    increment_index = exited_early if index == 1 else True
    page_size = min(MAX_IOCS_FETCH_SIZE, max_fetch * index)  # type: ignore
    events, more_data_available = get_ioc_domain_matches(client_obj, delayed_start_time, end_time, page_size)

    demisto.debug(f"Fetch IoCs: Retrieved {len(events)} IoCs from API. More data available: {more_data_available}")
    ingested_artifacts, duplicate_artifacts = [], []
    incidents: list = []

    if not events and current_time == end_time:
        demisto.debug("Fetch IoCs: No data retrieved with end time as current time. Last run will not be updated.")
        return incidents, all_last_run

    if not events:
        demisto.debug("Fetch IoCs: No data retrieved, so updating start time in last run with the end time.")
        last_run.pop("end_time", None)
        last_run.update({"start_time": end_time, "index": 1})
        demisto.debug(
            f"Fetch IoCs: Updated Last Run - Start time: {last_run.get('start_time')}, End time: {last_run.get('end_time')}, "
            f"Index: {last_run.get('index')}"
        )

        all_last_run.update({"ioc_domain_matches": last_run})
        return incidents, all_last_run

    for event in events:
        artifact_value = event.get("Artifact")
        artifact_sources = ", ".join([source.get("Source", "") for source in event.get("Sources", [])])
        artifact_name = f"{artifact_value} - {artifact_sources}" if artifact_sources else artifact_value

        if artifact_name in previous_artifact_values:
            duplicate_artifacts.append(artifact_name)
            continue

        if len(incidents) == max_fetch:
            demisto.debug(
                f"Fetch IoCs: Maximum incident limit of {max_fetch} reached. "
                f"Remaining incidents will be processed in the next fetch cycle. Index will not be incremented."
            )
            increment_index = False
            break

        event["IncidentType"] = "IocDomainMatches"
        incident = {
            "name": "IOC Domain Match: {}".format(event["Artifact"]),
            "details": json.dumps(event),
            "rawJSON": json.dumps(event),
        }
        previous_artifact_values.append(artifact_name)
        ingested_artifacts.append(artifact_name)
        incidents.append(incident)

    demisto.debug(f"Fetch IoCs: Successfully fetched {len(ingested_artifacts)} artifacts:\n")
    multiline_logs_for_list(ingested_artifacts, "Ingested Artifacts: ")
    demisto.debug(f"Fetch IoCs: Skipped {len(duplicate_artifacts)} duplicate artifacts:\n")
    multiline_logs_for_list(duplicate_artifacts, "Duplicate Artifacts: ")
    last_run.update({"previous_artifact_values": previous_artifact_values})

    start_time_obj = datetime.strptime(delayed_start_time, DATE_FORMAT)
    end_time_obj = datetime.strptime(end_time, DATE_FORMAT)
    is_diff_one_microsecond = False
    time_diff = end_time_obj - start_time_obj
    # Check if time difference is less than 1 microsecond
    if time_diff.total_seconds() <= 0.000001:
        is_diff_one_microsecond = True

    demisto.debug(
        f"Fetch IoCs: Checking last run update condition - is_diff_one_microsecond={is_diff_one_microsecond}, "
        f"more_data_available={more_data_available}, page_size={page_size}"
    )
    # Update start_time and index if moreDataAvailable is false and no incidents are fetched
    if not incidents and (not more_data_available or (is_diff_one_microsecond and page_size == MAX_IOCS_FETCH_SIZE)):
        demisto.debug("Fetch IoCs: All IoCs for the current time interval have been fetched.")
        last_run.pop("end_time", None)
        last_run.update({"start_time": end_time, "index": 1})
    else:
        last_run.update({"start_time": start_time, "end_time": end_time, "index": index + 1 if increment_index else index})

    demisto.debug(
        f"Fetch IoCs: Final Last Run - Start time: {last_run.get('start_time')}, End time: {last_run.get('end_time')}, "
        f"Index: {last_run.get('index')}"
    )

    all_last_run.update({"ioc_domain_matches": last_run})
    return incidents, all_last_run


def gcb_list_rules_command(client_obj, args: dict[str, str]):
    """
    Return the latest version of all rules.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-list-rules command.

    :return: command output
    :rtype: str, dict, dict
    """
    json_data = gcb_list_rules(client_obj, args)

    rules = json_data.get("rules", "")
    new_rules = []
    for rule in rules:
        new_rule = map_rule_response(rule)
        new_rules.append(new_rule)

    if not new_rules:
        hr = "### No Rules Found"
        return hr, {}, {}

    hr = get_list_rules_hr(new_rules)

    next_page_token = json_data.get("nextPageToken")
    if next_page_token:
        hr += (
            "\nMaximum number of rules specified in page_size has been returned. To fetch the next set of"
            f" rules, execute the command with the page token as `{next_page_token}`."
        )

    parsed_ec, token_ec = get_context_for_rules(new_rules, next_page_token)
    ec: dict[str, Any] = {SECOPS_OUTPUT_PATHS["Rules"]: parsed_ec}
    if token_ec:
        ec.update({SECOPS_OUTPUT_PATHS["Token"]: token_ec})
    ec = remove_empty_elements(ec)

    return hr, ec, json_data


def gcb_create_rule_command(client_obj, args: dict[str, str]):
    """
    Create a new rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains the arguments for the gcb-create-rule command.
    """
    rule_text = args.get("rule_text", "")
    validate_rule_text(rule_text)

    json_data = create_rule(client_obj, rule_text)

    raw_resp = deepcopy(json_data)

    mapped_rule = map_rule_response(json_data)
    hr = prepare_hr_for_rule_commands(mapped_rule, "Rule Details")
    ec = {SECOPS_OUTPUT_PATHS["Rules"]: mapped_rule}
    ec = remove_empty_elements(ec)

    return hr, ec, raw_resp


def gcb_get_rule_command(client_obj, args):
    """
    Retrieve the rule details of specified Rule ID or Version ID.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments of gcb-get-rule command.

    :return: command output
    :rtype: str, dict, dict
    """
    validate_argument(args.get("id"), "id")
    json_data = gcb_get_rule(client_obj, args.get("id"))

    mapped_rule = map_rule_response(json_data)
    hr = prepare_hr_for_rule_commands(mapped_rule, "Rule Details")
    ec = {SECOPS_OUTPUT_PATHS["Rules"]: mapped_rule}
    ec = remove_empty_elements(ec)

    return hr, ec, json_data


def gcb_delete_rule_command(client_obj, args: dict[str, str]):
    """
    Delete an already existing rule.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains the arguments for the gcb-delete-rule command.
    """
    rule_id = args.get("rule_id", "")
    validate_argument(value=rule_id, name="rule_id")

    ec, json_data = delete_rule(client_obj, rule_id)

    hr = prepare_hr_for_delete_rule(json_data)
    ec = remove_empty_elements(ec)

    return hr, ec, json_data


def gcb_create_rule_version_command(client_obj, args):
    """
    Create a new version of an existing rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-create-rule-version command.

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get("rule_id"), "rule_id")
    rule_text = validate_argument(args.get("rule_text"), "rule_text")
    validate_rule_text(rule_text)
    json_data = gcb_create_rule_version(client_obj, rule_id, rule_text)

    mapped_response = map_rule_response(json_data)
    hr = prepare_hr_for_rule_commands(mapped_response, "New Rule Version Details")
    ec = {SECOPS_OUTPUT_PATHS["Rules"]: mapped_response}
    ec = remove_empty_elements(ec)

    return hr, ec, ec


def gcb_change_rule_alerting_status_command(client_obj, args):
    """
    Change the alerting status of a rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments of gcb-change-rule-alerting-status command.

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get("rule_id"), "rule_id")
    alerting_status = validate_argument(args.get("alerting_status").lower(), "alerting_status")
    validate_single_select(alerting_status, "alerting_status", ["enable", "disable"])
    json_data = gcb_change_rule_alerting_status(client_obj, rule_id, alerting_status)

    data = {"ruleId": rule_id, "actionStatus": "SUCCESS", "alertingStatus": alerting_status}
    ec = {SECOPS_OUTPUT_PATHS["RuleAlertingChange"]: data}
    ec = remove_empty_elements(ec)
    hr = prepare_hr_for_gcb_change_rule_alerting_status(data, alerting_status)
    return hr, ec, json_data


def gcb_change_live_rule_status_command(client_obj, args):
    """
    Change the live status of an existing rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-change-live-rule-status command

    :return: command output
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get("rule_id"), "rule_id")

    live_rule_status = validate_argument(args.get("live_rule_status").lower(), "live_rule_status")
    validate_single_select(live_rule_status, "live_rule_status", ["enable", "disable"])

    json_data = gcb_change_live_rule_status(client_obj, rule_id, live_rule_status)

    data = {"ruleId": rule_id, "actionStatus": "SUCCESS", "liveRuleStatus": live_rule_status}

    ec = {SECOPS_OUTPUT_PATHS["LiveRuleStatusChange"]: data}
    ec = remove_empty_elements(ec)
    hr = prepare_hr_for_gcb_change_live_rule_status_command(data, live_rule_status)
    return hr, ec, json_data


def gcb_verify_rule_command(client_obj, args):
    """
    Verify the rule has valid YARA-L 2.0 format for GoogleSecOps.

    :type client_obj: Client
    :param client_obj: Client object used to get response from API.
    :type args: Dict[str, Any]
    :param args: Arguments for gcb-verify-rule command.
    :rtype: str, dict, dict
    :return: Command output.
    """
    rule_text = args.get("rule_text", "")
    validate_rule_text(rule_text)

    ec, json_data = gcb_verify_rule(client_obj, rule_text)
    ec = remove_empty_elements(ec)
    success = json_data.get("success")
    if success:
        hr = "### Identified no known errors"
    else:
        hr = f"### Error: {json_data.get('compilationDiagnostics', [{}])[0].get('message', '')}"
    return hr, ec, json_data


def gcb_list_retrohunts_command(client_obj, args: dict):
    """
    List retrohunts for a rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains the arguments for the gcb-list-retrohunts command.
    """

    valid_args = validate_list_retrohunts_args(args)
    json_data = gcb_list_retrohunts(
        client_obj,
        valid_args.get("rule_id"),
        valid_args.get("state"),
        valid_args.get("page_size"),
        valid_args.get("page_token"),
    )
    if not json_data:
        return "## RetroHunt Details\nNo Records Found.", {}, {}

    ec_data, hr = prepare_context_hr_for_gcb_list_retrohunts_commands(json_data)

    ec = {SECOPS_OUTPUT_PATHS["RetroHunt"]: ec_data}
    return hr, ec, json_data


def gcb_get_retrohunt_command(client_obj, args: dict):
    """
    Get retrohunt for a specific version of a rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains the arguments for the gcb-list-retrohunts command.

    :rtype: str, dict, dict
    :return command output.
    """
    rule_or_version_id = validate_argument(args.get("id"), "id")
    retrohunt_id = validate_argument(args.get("retrohunt_id"), "retrohunt_id")

    json_data = gcb_get_retrohunt(client_obj, rule_or_version_id=rule_or_version_id, retrohunt_id=retrohunt_id)
    ec_data, hr = prepare_hr_for_get_retrohunt(json_data)

    ec = {SECOPS_OUTPUT_PATHS["RetroHunt"]: ec_data}
    return hr, ec, json_data


def gcb_start_retrohunt_command(client_obj, args: dict):
    """
    Initiate a retrohunt for the specified rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-start-retrohunt command.

    :return: command output.
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get("rule_id"), "rule_id")
    start_time = arg_to_datetime(args.get("start_time"), "start_time").strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # type: ignore
    end_time = arg_to_datetime(args.get("end_time"), "end_time").strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # type: ignore

    json_data = gcb_start_retrohunt(client_obj, rule_id, start_time, end_time)
    search_pattern = r"operations/(.*)"
    match = re.search(search_pattern, json_data.get("name", ""))
    retrohint_id = match.group(1) if match else None

    if not retrohint_id:
        raise ValueError("Invalid response received from Google SecOps API. Missing retrohunt ID.")

    retrohunt_detail = gcb_get_retrohunt(client_obj, rule_or_version_id=rule_id, retrohunt_id=retrohint_id)
    ec_data, hr = prepare_hr_for_get_retrohunt(retrohunt_detail)

    ec = {SECOPS_OUTPUT_PATHS["RetroHunt"]: ec_data}
    return hr, ec, json_data


def gcb_cancel_retrohunt_command(client_obj, args: dict):
    """
    Cancel a retrohunt for a specified rule.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-cancel-retrohunt command.

    :rtype: str, dict, dict
    :return command output.
    """
    rule_or_version_id = validate_argument(args.get("id"), "id")
    retrohunt_id = validate_argument(args.get("retrohunt_id"), "retrohunt_id")
    ec, json_data = gcb_cancel_retrohunt(client_obj, rule_or_version_id, retrohunt_id)
    hr = prepare_hr_for_gcb_cancel_retrohunt(json_data)
    return hr, ec, json_data


def gcb_list_events_command(client_obj, args: dict):
    """
    List all of the events discovered within your enterprise on a particular device within the specified time range.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-list-ioc command.

    :return: command output.
    :rtype: str, dict, dict
    """
    asset_identifier_type = ASSET_IDENTIFIER_NAME_DICT.get(
        args.get("asset_identifier_type", "").lower(), args.get("asset_identifier_type", "")
    )
    validate_argument(asset_identifier_type, "asset_identifier_type")
    asset_identifier = args.get("asset_identifier", "")
    validate_argument(asset_identifier, "asset_identifier")

    # retrieve arguments and validate it
    start_time, end_time, page_size, reference_time = get_default_command_args_value(args=args, date_range="2 hours")

    if not reference_time:
        reference_time = args.get("reference_time", start_time)

    json_data = gcb_list_events(
        client_obj, asset_identifier_type, asset_identifier, start_time, end_time, reference_time, page_size
    )
    events = json_data.get("events", [])

    if not events:
        hr = "### No Events Found"
        return hr, {}, {}

    hr = get_list_events_hr(events)
    platform_url = json_data.get("uri", [""])[0] if isinstance(json_data.get("uri", None), list) else json_data.get("uri", "")
    platform_url = urllib.parse.quote(platform_url, safe=":/?=&")
    hr += f"\n[View events in Google SecOps]({platform_url})" if platform_url else ""

    if json_data.get("moreDataAvailable", False):
        last_event_timestamp = events[-1].get("metadata", {}).get("eventTimestamp", "")
        hr += (
            "\n\nMaximum number of events specified in page_size has been returned. There might"
            " still be more events in your Google SecOps account."
        )
        if not dateparser.parse(last_event_timestamp, settings={"STRICT_PARSING": True}):
            demisto.error(f"Event timestamp of the last event: {last_event_timestamp} is invalid.")
            hr += " An error occurred while fetching the start time that could have been used to fetch next set of events."
        else:
            hr += f" To fetch the next set of events, execute the command with the start time as {last_event_timestamp}."

    parsed_ec = get_context_for_events(events)

    ec = {SECOPS_OUTPUT_PATHS["Events"]: remove_empty_elements(parsed_ec)}
    return hr, ec, json_data


def gcb_get_event_command(client_obj, args: dict[str, str]):
    """
    Get specific event with the given ID (Google SecOps version).

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-get-event command.

    :return: command output.
    :rtype: str, dict, dict
    """
    event_id = validate_argument(args.get("event_id"), "event_id")
    event_id = urllib.parse.quote(event_id)

    url_path = create_url_path(client_obj)
    request_url = f"{url_path}/events/{event_id}"

    json_data = validate_response(client_obj, request_url)

    event_data = deepcopy(json_data.get("udm", {}))
    hr = prepare_hr_for_gcb_get_event(deepcopy(event_data))
    parsed_ec = get_context_for_events([event_data])

    ec = {SECOPS_OUTPUT_PATHS["Events"]: remove_empty_elements(parsed_ec)}

    return hr, ec, json_data


def gcb_list_detections_command(client_obj, args: dict[str, str]):
    """
    Return the Detections for a specified Rule Version.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contain arguments of gcb-list-detections command

    :return: command output
    :rtype: str, dict, dict
    """
    valid_args = validate_and_parse_list_detections_args(args)

    ec, json_data = get_detections(
        client_obj,
        args.get("id", ""),
        valid_args.get("page_size", ""),
        valid_args.get("detection_start_time", ""),
        valid_args.get("detection_end_time", ""),
        args.get("page_token", ""),
        valid_args.get("alert_state", ""),
        valid_args.get("detection_for_all_versions", False),
        args.get("list_basis", ""),
    )

    detections = json_data.get("detections", [])
    if not detections:
        hr = "### No Detections Found"
        return hr, {}, {}

    # prepare alerts into human readable
    hr = get_list_detections_hr(detections, args.get("id", ""))
    hr += (
        "\nView all detections for this rule in Google SecOps by clicking on {} and to view individual detection"
        " in Google SecOps click on its respective Detection ID.\n\nNote: If a specific version of the rule is provided"
        " then detections for that specific version will be fetched.".format(detections[0].get("detection")[0].get("ruleName"))
    )

    next_page_token = json_data.get("nextPageToken")
    if next_page_token:
        hr += (
            "\nMaximum number of detections specified in page_size has been returned. To fetch the next set of"
            f" detections, execute the command with the page token as `{next_page_token}`."
        )

    return hr, ec, json_data


def gcb_list_curatedrule_detections_command(client_obj, args: dict[str, str]):
    """
    Return the Detections for a specified Curated Rule ID.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from API.

    :type args: Dict[str, str]
    :param args: It contain arguments of gcb-list-curatedrule-detections command.

    :return: Command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    valid_args = validate_and_parse_list_curatedrule_detections_args(args)

    ec, json_data = get_curatedrule_detections(
        client_obj,
        args.get("id", ""),
        valid_args.get("page_size", ""),
        valid_args.get("detection_start_time", ""),
        valid_args.get("detection_end_time", ""),
        args.get("page_token", ""),
        args.get("alert_state", ""),
        args.get("list_basis", ""),
    )

    detections = json_data.get("curatedDetections", [])
    if not detections:
        hr = "### No Curated Detections Found"
        return hr, {}, {}

    # prepare alerts into human-readable
    hr = get_list_curatedrule_detections_hr(detections, args.get("id", ""))
    hr += (
        "\nView all Curated Detections for this rule in Google SecOps by clicking on {} and to view individual "
        "detection in Google SecOps click on its respective Detection ID.".format(
            detections[0].get("detection")[0].get("ruleName")
        )
    )

    next_page_token = json_data.get("nextPageToken")
    if next_page_token:
        hr += (
            "\nMaximum number of detections specified in page_size has been returned. To fetch the next set of"
            f" detections, execute the command with the page token as `{next_page_token}`."
        )

    return hr, ec, json_data


def gcb_list_curated_rules_command(client_obj: Client, args: dict) -> tuple[str, dict, dict]:
    """
    List all the curated rules.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: dict
    :param args: It contains arguments of the command.

    :return: Command output.
    :rtype: tuple[str, dict, dict]
    """
    page_size = args.get("page_size", "100")
    page_token = urllib.parse.quote(args.get("page_token", ""))

    page_size = arg_to_number(page_size, arg_name="page_size")
    if page_size > 1000 or page_size < 1:  # type: ignore
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format("1000"))

    json_data = gcb_list_curated_rules(client_obj, page_token, page_size)
    ec, hr = prepare_context_hr_for_gcb_list_curated_rules_command(json_data)
    return hr, ec, json_data


def gcb_test_rule_stream_command(client_obj, args: dict[str, str]):
    """
    Stream results for given rule text.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-test-rule-stream command.

    :rtype: str, dict, dict
    :return: command output.
    """
    rule_text = args.get("rule_text", "")
    start_time = arg_to_datetime(args.get("start_time"), "start_time").strftime(DATE_FORMAT)  # type: ignore
    end_time = arg_to_datetime(args.get("end_time"), "end_time").strftime(DATE_FORMAT)  # type: ignore
    max_results = arg_to_number(args.get("max_results", 1000))

    validate_rule_text(rule_text)
    if max_results > 10000 or max_results <= 0:  # type: ignore
        raise ValueError(MESSAGES["INVALID_MAX_RESULTS"])

    ec, json_data = gcb_test_rule_stream(
        client_obj, rule_text=rule_text, start_time=start_time, end_time=end_time, max_results=max_results
    )
    hr = prepare_hr_for_gcb_test_rule_stream_command(json_data)  # select fields to be shown in HR
    return hr, ec, json_data


def gcb_udm_search_command(client_obj, args: dict[str, str]):
    """
    List all the events discovered within your enterprise for the specified query within the specified time range.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: It contain arguments of gcb-udm-search command.

    :return: Command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    start_time, end_time, limit, query = get_gcb_udm_search_command_args_value(args=args, date_range="3 days")

    # Make a request URL
    json_data = gcb_udm_search(client_obj, start_time, end_time, limit, query)

    events = json_data.get("events", [])
    if not events:
        hr = "### No events were found for the specified UDM search query."
        return hr, {}, {}

    events = [event.get("udm", {}) for event in events]

    # prepare alerts into human-readable
    hr = get_udm_search_events_hr(events)

    if json_data.get("moreDataAvailable", False):
        first_event_timestamp = events[0].get("metadata", {}).get("eventTimestamp", "")
        hr += (
            "\n\nMaximum number of events specified in limit has been returned. There might"
            " still be more events in your Google SecOps account."
        )
        if not dateparser.parse(first_event_timestamp, settings={"STRICT_PARSING": True}):
            demisto.error(f"Event timestamp of the first event: {first_event_timestamp} is invalid.")
            hr += " An error occurred while fetching the start time that could have been used to fetch next set of events."
        else:
            hr += f" To fetch the next set of events, execute the command with the start time as {first_event_timestamp}."

    parsed_ec = get_context_for_events(events)

    ec = {SECOPS_OUTPUT_PATHS["UDMEvents"]: parsed_ec}

    return hr, ec, json_data


def gcb_get_reference_list_command(client_obj, args: dict) -> tuple[str, dict, dict]:
    """
    Return the specified list.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: It contains arguments for gcb-get-reference-list command.

    :return: command output.
    :rtype: str, dict, dict
    """
    name = validate_argument(args.get("name"), "name")
    view = f"REFERENCE_LIST_VIEW_{validate_single_select(args.get('view', 'FULL'), 'view', ['FULL', 'BASIC'])}"
    json_data = gcb_get_reference_list(client_obj, name=name, view=view)

    mapped_reference_list = map_response_for_reference_list(json_data)

    ec = {SECOPS_OUTPUT_PATHS["ReferenceList"]: mapped_reference_list}
    hr = prepare_hr_for_gcb_create_get_update_reference_list(mapped_reference_list)

    return hr, ec, json_data


def gcb_create_reference_list_command(client_obj, args: dict) -> tuple[str, dict, dict]:
    """
    Create a new reference list.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from the api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-create-reference-list command.

    :rtype: str, dict, dict
    :return command output.
    """
    name = validate_argument(args.get("name"), "name")
    description = validate_argument(args.get("description"), "description")
    lines = validate_reference_list_args(args)

    valid_lines = [line.strip() for line in lines if line.strip()]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, "lines")  # Validation for empty lines list

    content_type = validate_single_select(
        args.get("content_type", DEFAULT_CONTENT_TYPE).upper(), "content_type", VALID_CONTENT_TYPE
    )

    json_data = gcb_create_reference_list(client_obj, name=name, description=description, lines=lines, content_type=content_type)
    json_data["syntaxType"] = json_data.get("syntaxType", DEFAULT_SYNTAX_TYPE)

    mapped_reference_list = map_response_for_reference_list(json_data)

    ec = {SECOPS_OUTPUT_PATHS["ReferenceList"]: mapped_reference_list}
    hr = prepare_hr_for_gcb_create_get_update_reference_list(mapped_reference_list)

    return hr, ec, json_data


def gcb_update_reference_list_command(client_obj, args: dict) -> tuple[str, dict, dict]:
    """
    Update an existing reference list.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-update-reference-list command.

    :return: command output.
    :rtype: str, dict, dict
    """
    name = validate_argument(args.get("name"), "name")

    lines = validate_reference_list_args(args)

    valid_lines = [line.strip() for line in lines if line.strip()]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, "lines")  # Validation for empty lines list
    description = args.get("description")
    content_type = validate_single_select(
        args.get("content_type", DEFAULT_CONTENT_TYPE).upper(), "content_type", VALID_CONTENT_TYPE
    )

    json_data = gcb_update_reference_list(client_obj, name=name, lines=lines, description=description, content_type=content_type)
    json_data["syntaxType"] = json_data.get("syntaxType", DEFAULT_SYNTAX_TYPE)

    mapped_reference_list = map_response_for_reference_list(json_data)

    ec = {SECOPS_OUTPUT_PATHS["ReferenceList"]: mapped_reference_list}
    hr = prepare_hr_for_gcb_create_get_update_reference_list(mapped_reference_list, "Updated Reference List Details")

    return hr, ec, json_data


def gcb_list_reference_list_command(client_obj, args):
    """
    List all the reference lists.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-list-reference-list command

    :return: command output
    :rtype: str, dict, dict
    """
    page_size = args.get("page_size", 100)
    validate_page_size(page_size)
    if int(page_size) > 1000:
        raise ValueError(MESSAGES["INVALID_PAGE_SIZE"].format(1000))
    page_token = args.get("page_token", "")

    view = validate_single_select(args.get("view", "BASIC"), "view", ["FULL", "BASIC"])
    view = f"REFERENCE_LIST_VIEW_{view}"

    json_data = gcb_list_reference_list(client_obj, page_size, page_token, view)
    reference_lists = json_data.get("referenceLists", [])
    mapped_reference_lists = []
    for reference_list in reference_lists:
        mapped_reference_lists.append(map_response_for_reference_list(reference_list))

    ec = {SECOPS_OUTPUT_PATHS["ListReferenceList"]: mapped_reference_lists}

    hr = prepare_hr_for_gcb_list_reference_list(mapped_reference_lists)
    next_page_token = json_data.get("nextPageToken")
    if next_page_token:
        hr += (
            "\nMaximum number of reference lists specified in page_size has been returned. To fetch the next set of"
            f" lists, execute the command with the page token as `{next_page_token}`"
        )

    return hr, ec, json_data


def gcb_verify_reference_list_command(client_obj, args):
    """
    Validate lines contents.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-update-reference-list command.

    :return: command output.
    :rtype: str, dict, dict
    """
    lines = validate_argument(args.get("lines"), "lines")
    lines = argToList(lines, args.get("delimiter", ","))
    valid_lines = [line.strip() for line in lines if line.strip()]  # Remove the empty("") lines
    lines_values = validate_argument(valid_lines, "lines")  # Validation for empty lines list
    lines = [{"value": value} for value in lines_values]  # line values in list of dict objects

    content_type = validate_single_select(
        args.get("content_type", DEFAULT_CONTENT_TYPE).upper(), "content_type", VALID_CONTENT_TYPE
    )
    syntax_type = SYNTAX_TYPE_MAPPING.get(content_type.upper(), DEFAULT_SYNTAX_TYPE)
    ec, json_data = gcb_verify_reference_list(client_obj, lines=lines, syntax_type=syntax_type)
    hr = prepare_hr_for_verify_reference_list(json_data, content_type)
    return hr, ec, json_data


def gcb_verify_value_in_reference_list_command(client_obj, args):
    """
    Check if the value is present in the reference list.

    :type client_obj: Client
    :param client_obj: Client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: It contains arguments for gcb-verify-value-in-reference-list command.

    :return: command output
    :rtype: str, dict, dict
    """
    delimiter = args.get("delimiter", ",")
    reference_lists_names = argToList(args.get("reference_list_names", []))
    search_values = argToList(args.get("values", []), separator=delimiter)
    case_insensitive = argToBoolean(args.get("case_insensitive_search", "false"))
    add_not_found_reference_lists = argToBoolean(args.get("add_not_found_reference_lists", "false"))

    reference_lists = validate_argument(
        get_unique_value_from_list([reference_list.strip() for reference_list in reference_lists_names]), "reference_list_names"
    )
    values = validate_argument(get_unique_value_from_list([value.strip() for value in search_values]), "values")

    found_reference_lists = {}
    not_found_reference_lists = []

    for reference_list in reference_lists:
        try:
            json_data = gcb_get_reference_list(client_obj, name=reference_list, view="REFERENCE_LIST_VIEW_FULL")
            lines = [entry.get("value", "") for entry in json_data.get("entries", [])]
            found_reference_lists[reference_list] = lines
        except Exception:
            not_found_reference_lists.append(reference_list)

    if not_found_reference_lists:
        return_warning(
            "The following Reference lists were not found: {}".format(", ".join(not_found_reference_lists)),
            exit=len(not_found_reference_lists) == len(reference_lists),
        )

    if case_insensitive:
        for reference_list, lines in found_reference_lists.items():
            found_reference_lists[reference_list] = [line.lower() for line in lines]

    hr_dict, json_data, ec_data = [], [], []
    for value in values:
        overall_status = "Not Found"
        found_lists, not_found_lists = [], []
        for reference_list, lines in found_reference_lists.items():
            if value in lines:
                found_lists.append(reference_list)
            elif case_insensitive and value.lower() in lines:
                found_lists.append(reference_list)
            else:
                not_found_lists.append(reference_list)

        if found_lists:
            overall_status = "Found"

        result = {
            "value": value,
            "found_in_lists": found_lists,
            "not_found_in_lists": not_found_lists,
            "overall_status": overall_status,
            "case_insensitive": case_insensitive,
        }
        json_data.append(result)
        data = deepcopy(result)

        hr_data = {
            "value": string_escape_markdown(value),
            "found_in_lists": ", ".join(found_lists),
            "not_found_in_lists": ", ".join(not_found_lists),
            "overall_status": overall_status,
        }

        if not add_not_found_reference_lists:
            hr_data["not_found_in_lists"] = []
            data["not_found_in_lists"] = []

        ec_data.append(data)
        hr_dict.append(hr_data)

    title = "Successfully searched provided values in the reference lists in Google SecOps."
    hr = tableToMarkdown(
        title,
        hr_dict,
        ["value", "found_in_lists", "not_found_in_lists", "overall_status"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )
    ec = {SECOPS_OUTPUT_PATHS["VerifyValueInReferenceList"]: ec_data}

    return hr, ec, json_data


def gcb_reference_list_append_content(client_obj, args):
    """
    Append content to an existing reference list.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-reference-list-append-content command.

    :return: command output
    :rtype: str, dict, dict
    """
    name = validate_argument(args.get("name"), "name")

    lines = validate_reference_list_args(args)

    valid_lines = [line.strip() for line in lines if line.strip()]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, "lines")  # Validation for empty lines list

    json_data = gcb_get_reference_list(client_obj, name=name, view="REFERENCE_LIST_VIEW_FULL")
    old_lines = [entry.get("value", "") for entry in json_data.get("entries", [])]
    syntax_type = json_data.get("syntaxType", DEFAULT_SYNTAX_TYPE)
    description = json_data.get("description")
    append_unique = argToBoolean(args.get("append_unique", False))

    if append_unique:
        new_lines = old_lines
        duplicate_lines = []
        for line in lines:
            if line not in new_lines:
                new_lines.append(line)
            else:
                duplicate_lines.append(line)
        if duplicate_lines:
            return_warning(
                "The following lines were already present: {}".format(", ".join(duplicate_lines)),
                exit=set(lines).issubset(set(duplicate_lines)),
            )
    else:
        new_lines = old_lines + lines  # type: ignore

    json_data = gcb_update_reference_list(
        client_obj,
        name=name,
        lines=new_lines,
        description=description,
        content_type=CONTENT_TYPE_MAPPING.get(syntax_type, DEFAULT_CONTENT_TYPE),
    )
    mapped_reference_list = map_response_for_reference_list(json_data)

    ec = {SECOPS_OUTPUT_PATHS["ReferenceList"]: mapped_reference_list}
    hr = prepare_hr_for_gcb_create_get_update_reference_list(mapped_reference_list, "Updated Reference List Details")
    return hr, ec, json_data


def gcb_reference_list_remove_content(client_obj, args):
    """
    Remove content from an existing reference list.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-remove-reference-list command.

    :return: command output
    :rtype: str, dict, dict
    """
    name = validate_argument(args.get("name"), "name")

    lines = validate_reference_list_args(args)

    valid_lines = [line.strip() for line in lines if line.strip()]  # Remove the empty("") lines
    lines = validate_argument(valid_lines, "lines")  # Validation for empty lines list

    json_data = gcb_get_reference_list(client_obj, name=name, view="REFERENCE_LIST_VIEW_FULL")
    old_lines = [entry.get("value", "") for entry in json_data.get("entries", [])]
    syntax_type = json_data.get("syntaxType", DEFAULT_SYNTAX_TYPE)
    description = json_data.get("description")

    redundant_lines = []
    for line in lines:
        if line in old_lines:
            while line in old_lines:
                old_lines.remove(line)
        else:
            redundant_lines.append(line)

    if redundant_lines:
        return_warning(
            "The following lines were not present: {}".format(", ".join(redundant_lines)),
            exit=(len(redundant_lines) == len(lines)),
        )

    json_data = gcb_update_reference_list(
        client_obj,
        name=name,
        lines=old_lines,
        description=description,
        content_type=CONTENT_TYPE_MAPPING.get(syntax_type, DEFAULT_CONTENT_TYPE),
    )
    mapped_reference_list = map_response_for_reference_list(json_data)

    ec = {SECOPS_OUTPUT_PATHS["ReferenceList"]: mapped_reference_list}
    hr = prepare_hr_for_gcb_create_get_update_reference_list(mapped_reference_list, "Updated Reference List Details")

    return hr, ec, json_data


def gcb_list_iocs_command(client_obj, args: dict[str, Any]):
    """
    List all of the IoCs discovered within your enterprise within the specified time range.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, Any]
    :param args: it contain arguments of gcb-list-ioc command.

    :return: command output.
    :rtype: (str, dict, dict)
    """
    # retrieve arguments and validate it

    start_time, end_time, page_size, _ = get_default_command_args_value(args=args)

    json_data = gcb_list_iocs(client_obj, start_time, end_time, page_size)

    # List of IoCs returned for further processing
    ioc_matches = json_data.get("matches", [])
    if ioc_matches:
        ioc_matches_resp = parse_list_ioc_response(ioc_matches)

        # prepare human readable response
        hr = tableToMarkdown(
            "IOC Domain Matches",
            ioc_matches_resp["hr_ioc_matches"],
            ["Artifact", "Category", "Source", "Confidence", "Severity", "IOC ingest time", "First seen", "Last seen"],
            removeNull=True,
        )
        # prepare entry context response
        ec = {
            outputPaths["domain"]: ioc_matches_resp["domain_std_context"],
            SECOPS_OUTPUT_PATHS["Iocs"]: ioc_matches_resp["context"],
        }
        return hr, remove_empty_elements(ec), json_data
    else:
        return "### No domain matches found", {}, {}


def gcb_ioc_details_command(client_obj, args: dict[str, str]):
    """
    Fetch IoC Details from Google SecOps.

    :type client_obj: Client
    :param client_obj: The Client object which abstracts the API calls to Google SecOps.

    :type args: dict
    :param args: the input artifact value, whose details are to be fetched.

    :return: command output (Human Readable, Context Data and Raw Response)
    :rtype: tuple
    """
    artifact_value = args.get("artifact_value", "")
    artifact_type = get_artifact_type(artifact_value)

    quote_artifact_value = urllib.parse.quote(artifact_value)
    url = create_url_path(client_obj)
    request_url = f"{url}/legacy:legacySearchArtifactIoCDetails?artifactIndicator.{artifact_type}={quote_artifact_value}"
    json_data = validate_response(client_obj, request_url)

    ec: dict = {}
    hr = ""
    if json_data and json_data.get("feeds"):
        normal_artifact_type = None
        if artifact_type == "destinationIpAddress":
            normal_artifact_type = "ip"
        elif artifact_type == "domain":
            normal_artifact_type = "domain"
        else:
            raise ValueError("Unsupported artifact type")

        context_dict = get_context_for_ioc_details(
            json_data.get("feeds", []), artifact_value, normal_artifact_type, is_reputation_command=False
        )
        ec = {
            outputPaths[normal_artifact_type]: context_dict["standard_context"],
            SECOPS_OUTPUT_PATHS["IocDetails"]: context_dict["context"],
        }

        if context_dict["hr_table_data"]:
            hr += tableToMarkdown(
                "IoC Details",
                context_dict["hr_table_data"],
                ["Domain", IP_ADDRESS, "Category", CONFIDENCE_SCORE, "Severity", FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME],
                removeNull=True,
            )
        else:
            hr += MESSAGES["NO_RECORDS"]

    else:
        hr += f"### For artifact: {artifact_value}\n"
        hr += MESSAGES["NO_RECORDS"]

    return hr, remove_empty_elements(ec), json_data


def ip_command(client_obj, ip_address: str):
    """
    Reputation command for given IP address.

    :type client_obj: Client
    :param client_obj: object of the client class

    :type ip_address: str
    :param ip_address: contains arguments of reputation command ip

    :return: command output
    :rtype: tuple
    """
    if not is_ip_valid(ip_address, True):
        raise ValueError(f"Invalid IP - {ip_address}")

    url = create_url_path(client_obj)
    request_url = f"{url}/legacy:legacySearchArtifactIoCDetails?artifactIndicator.destinationIpAddress={ip_address}"

    response = validate_response(client_obj, request_url)

    ec: dict = {}
    hr = ""
    if response and response.get("feeds"):
        context_dict = get_context_for_ioc_details(response.get("feeds", []), ip_address, "ip")

        # preparing human readable
        hr += "IP: " + str(ip_address) + " found with Reputation: " + str(context_dict["reputation"]) + "\n"
        if context_dict["hr_table_data"]:
            hr += tableToMarkdown(
                "Reputation Parameters",
                context_dict["hr_table_data"],
                ["Domain", IP_ADDRESS, "Category", CONFIDENCE_SCORE, "Severity", FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME],
            )
        else:
            hr += MESSAGES["NO_RECORDS"]

        # preparing entry context
        ec = {
            "DBotScore": context_dict["dbot_context"],
            outputPaths["ip"]: context_dict["standard_context"],
            SECOPS_OUTPUT_PATHS["Ip"]: context_dict["context"],
        }
    else:
        dbot_context = {
            "Indicator": ip_address,
            "Type": "ip",
            "Vendor": VENDOR,
            "Score": 0,
            "Reliability": demisto.params().get("integrationReliability"),
        }

        hr += f"### IP: {ip_address} found with Reputation: Unknown\n"
        hr += MESSAGES["NO_RECORDS"]

        ec = {"DBotScore": dbot_context}

    return hr, remove_empty_elements(ec), response


def domain_command(client_obj, domain_name: str):
    """
    Reputation command for given Domain address.

    :type client_obj: Client
    :param client_obj: object of the client class.

    :type domain_name: str
    :param domain_name: contains arguments of reputation command domain.

    :return: command output.
    :rtype: tuple
    """
    url = create_url_path(client_obj)
    request_url = f"{url}/legacy:legacySearchArtifactIoCDetails?artifactIndicator.domain={urllib.parse.quote(domain_name)}"

    response = validate_response(client_obj, request_url)

    ec: dict = {}
    hr = ""
    if response and response.get("feeds"):
        context_dict = get_context_for_ioc_details(response.get("feeds", []), domain_name, "domain")

        # preparing human readable
        hr += "Domain: " + str(domain_name) + " found with Reputation: " + str(context_dict["reputation"]) + "\n"
        if context_dict["hr_table_data"]:
            hr += tableToMarkdown(
                "Reputation Parameters",
                context_dict["hr_table_data"],
                ["Domain", IP_ADDRESS, "Category", CONFIDENCE_SCORE, "Severity", FIRST_ACCESSED_TIME, LAST_ACCESSED_TIME],
            )
        else:
            hr += MESSAGES["NO_RECORDS"]

        # preparing entry context
        ec = {
            "DBotScore": context_dict["dbot_context"],
            outputPaths["domain"]: context_dict["standard_context"],
            SECOPS_OUTPUT_PATHS["Domain"]: context_dict["context"],
        }
    else:
        dbot_context = {
            "Indicator": domain_name,
            "Type": "domain",
            "Vendor": VENDOR,
            "Score": 0,
            "Reliability": demisto.params().get("integrationReliability"),
        }

        hr += f"### Domain: {domain_name} found with Reputation: Unknown\n"
        hr += MESSAGES["NO_RECORDS"]

        ec = {"DBotScore": dbot_context}

    return hr, remove_empty_elements(ec), response


def reputation_operation_command(client_obj, indicator, reputation_function):
    """
    Call appropriate reputation command.

    Common method for reputation commands to accept argument as a comma-separated values and converted into list \
    and call specific function for all values.

    :param client_obj: object of client class.
    :param indicator: comma-separated values or single value.
    :param reputation_function: reputation command function. i.e ip_command and domain_command.

    :return: output of all value according to specified function.
    """
    artifacts = argToList(indicator, ",")
    for artifact in artifacts:
        return_outputs(*reputation_function(client_obj, artifact))


def gcb_list_data_tables_command(client_obj, args):
    """
    Returns a list of data tables.

    :type client_obj: Client
    :param client_obj: object of the client class.

    :type args: dict
    :param args: contains arguments of list data tables command.

    :return: command output
    :rtype: tuple
    """
    page_size = args.get("page_size", 100)
    validate_page_size(page_size)
    page_size = arg_to_number(page_size)
    page_token = args.get("page_token", "")

    data, ec = gcb_list_data_tables(client_obj, page_size, page_token)  # type: ignore
    data_tables = data.get("dataTables", [])
    if not data_tables:
        hr = "### No Data Tables Found"
        return hr, {}, {}
    hr = prepare_hr_for_list_data_table_details(data_tables)
    next_page_token = data.get("nextPageToken", "")
    if next_page_token:
        hr += (
            "\nMaximum number of data tables specified in page_size has been returned. To fetch the next set of"
            f" data tables, execute the command with the page token as `{next_page_token}`."
        )
    return hr, remove_empty_elements(ec), data


def gcb_create_data_table_command(client_obj, args):
    """
    Creates a new data table schema.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-create-data-table command.

    :return: command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    name, description, columns_list = validate_data_table_args(args)

    json_data, ec = gcb_create_data_table(client_obj, name, description, columns_list)

    hr = prepare_hr_for_data_table_metadata_details(json_data)

    return hr, ec, json_data


def gcb_get_data_table_command(client_obj, args):
    """
    Get a data table schema.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-get-data-table command.

    :return: command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    name = validate_argument(args.get("name"), "name")
    view = args.get("view", "basic").upper()
    validate_single_select(view, "view", ["FULL", "BASIC"])

    json_data, ec = gcb_get_data_table(client_obj, name)
    hr = prepare_hr_for_data_table_metadata_details(json_data)

    if view == "BASIC":
        return hr, ec, json_data

    max_rows_to_return: int = arg_to_number(args.get("max_rows_to_return", 100), arg_name="max_rows_to_return")  # type: ignore
    if max_rows_to_return < 1:
        raise ValueError("max_rows_to_return should be greater than 0.")
    page_token = args.get("page_token")

    rows_data = gcb_get_data_table_rows(client_obj, name, max_rows_to_return, page_token)
    columns = [column.get("originalColumn") for column in json_data.get("columnInfo", [])]
    next_page_token = rows_data.get("nextPageToken", "")
    rows_data = rows_data.get("dataTableRows", [])

    rows_ec_data = prepare_ec_data_table_rows(rows_data, columns)
    hr += prepare_hr_for_data_table_rows(rows_ec_data, "Data Table Rows Content")

    if next_page_token:
        hr += (
            "\nMaximum number of data table rows specified in max_rows_to_return has been returned. To fetch the next set of"
            f" data table rows, execute the command with the page token as `{next_page_token}`."
        )

    ec[SECOPS_OUTPUT_PATHS["DataTable"]].update({"rows": rows_ec_data})
    json_data.update({"rows": rows_ec_data})
    return hr, remove_empty_elements(ec), json_data


def gcb_verify_value_in_data_table_command(client_obj, args):
    """
    Verifies that a value is present in a data table.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-verify-value-in-data-table command.

    :return: command output.
    :rtype: str, dict, dict
    """
    delimiter = args.get("delimiter", ",")
    data_table_name = validate_argument(args.get("name"), "name")
    column_names = argToList(args.get("columns", []))
    search_values = argToList(args.get("values", []), separator=delimiter)
    case_insensitive = argToBoolean(args.get("case_insensitive_search", "false"))
    add_not_found_columns = argToBoolean(args.get("add_not_found_columns", "false"))
    page_token = args.get("page_token", "")

    values = validate_argument(get_unique_value_from_list([value.strip() for value in search_values if value.strip()]), "values")
    column_names = get_unique_value_from_list([column_name.strip() for column_name in column_names if column_name.strip()])

    # retrieve data table columns information
    table_data, _ = gcb_get_data_table(client_obj, data_table_name)
    # retrieve data table rows
    rows_json_data = gcb_get_data_table_rows(client_obj, data_table_name, 1000, page_token)

    if not rows_json_data:
        return f"### No Rows data found in the {data_table_name} data table", {}, {}

    data_table_columns = [column.get("originalColumn") for column in table_data.get("columnInfo", [])]
    next_page_token = rows_json_data.get("nextPageToken", "")
    rows_json_data = rows_json_data.get("dataTableRows", [])
    rows_data = prepare_ec_data_table_rows(rows_json_data, data_table_columns)

    # Extract and organize column values into a dictionary. Format: {"column_name": ["value1", "value2", ...], ...}
    columns_values: dict = {column_name: [] for column_name in data_table_columns}
    for row in rows_data:
        row_values = row.get("values", {})
        for column_name in data_table_columns:
            value = row_values.get(column_name, "")
            if case_insensitive:
                value = value.lower()

            columns_values[column_name].append(value)

    # If no specific columns provided, search in all columns
    if not column_names:
        column_names = data_table_columns

    not_found_data_table_columns = []
    found_data_table_columns = []

    for column_name in column_names:
        if column_name not in data_table_columns:
            not_found_data_table_columns.append(column_name)
        else:
            found_data_table_columns.append(column_name)

    if not_found_data_table_columns:
        return_warning(
            f"Columns {', '.join(not_found_data_table_columns)} not found in data table '{data_table_name}'.",
            exit=len(not_found_data_table_columns) == len(column_names),
        )

    hr_dict, json_data, ec_data = [], [], []
    for value in values:
        overall_status = "Not Found"
        found_columns, not_found_columns = [], []

        for column_name in found_data_table_columns:
            column_values: list = columns_values.get(column_name) or []
            if value in column_values:
                found_columns.append(column_name)
            elif case_insensitive and value.lower() in column_values:
                found_columns.append(column_name)
            else:
                not_found_columns.append(column_name)

        if found_columns:
            overall_status = "Found"

        result = {
            "value": value,
            "found_in_columns": found_columns,
            "not_found_in_columns": not_found_columns,
            "overall_status": overall_status,
            "case_insensitive": case_insensitive,
        }
        json_data.append(result)
        data = deepcopy(result)

        hr_data = {
            "value": string_escape_markdown(value),
            "found_in_columns": ", ".join(found_columns),
            "not_found_in_columns": ", ".join(not_found_columns),
            "overall_status": overall_status,
        }

        if not add_not_found_columns:
            hr_data["not_found_in_columns"] = []
            data["not_found_in_columns"] = []

        ec_data.append(data)
        hr_dict.append(hr_data)

    title = f"Successfully searched provided values in the {data_table_name} data table"
    hr = tableToMarkdown(
        title,
        hr_dict,
        ["value", "found_in_columns", "not_found_in_columns", "overall_status"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )
    if next_page_token:
        hr += (
            "\nThe command can search the up to 1000 rows in single execution. To search the next set of"
            f" data table rows, execute the command with the page token as `{next_page_token}`"
        )
    ec = {SECOPS_OUTPUT_PATHS["VerifyValueInDataTable"]: ec_data}

    return hr, remove_empty_elements(ec), json_data


def gcb_data_table_add_row_command(client_obj, args):
    """
    Add a row to a data table.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-data-table-add-row command.

    :return: command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    name, rows = validate_data_table_rows_args(args)

    # get data table
    data_table, _ = gcb_get_data_table(client_obj, name)
    columns = {column.get("originalColumn"): index for index, column in enumerate(data_table.get("columnInfo", []))}

    body_data = prepare_body_data_for_data_table_rows(rows, columns)
    json_data = gcb_data_table_add_row(client_obj, name, body_data)

    hr, ec = prepare_hr_and_context_for_data_table_add_rows(name, json_data, rows)

    return hr, remove_empty_elements(ec), json_data


def gcb_data_table_remove_row_command(client_obj, args):
    """
    Remove rows from a data table.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-data-table-remove-row command.

    :return: command output.
    :rtype: str, dict, dict
    """
    # retrieve arguments and validate it
    name, rows = validate_data_table_rows_args(args)
    page_token = args.get("page_token", "")

    # get data table
    data_table, _ = gcb_get_data_table(client_obj, name)
    columns = {column.get("originalColumn"): index for index, column in enumerate(data_table.get("columnInfo", []))}

    # Validate that all columns in the row criteria exist in the data table
    for row in rows:
        for column_name, _ in row.items():
            if column_name not in columns:
                raise ValueError(
                    f"Invalid value provided in the 'rows' parameter. Column '{column_name}' not found in the data table."
                )

    # Get all rows from the data table
    all_rows = gcb_get_data_table_rows(client_obj, name, 1000, page_token)
    next_page_token = all_rows.get("nextPageToken", "")

    # Find rows to remove based on the criteria
    rows_to_remove = find_rows_matching_criteria(all_rows, rows, columns)

    # Remove the matched rows
    if not rows_to_remove:
        return "### No rows found matching the criteria", {}, {}

    for row in rows_to_remove:
        row_id = row.get("name", "")
        row_id_search_pattern = r"dataTableRows/(.*)"
        row_id_match = re.search(row_id_search_pattern, row_id)
        if not row_id_match:
            raise ValueError("Invalid response received from Google SecOps API. Missing row ID.")

        row_id = row_id_match.group(1)

        _ = gcb_data_table_delete_row(client_obj, name, row_id)

    columns_names = list(columns.keys())
    rows_ec_data = prepare_ec_data_table_rows(rows_to_remove, columns_names)
    title = f"Successfully removed rows from the {name} data table"
    hr = prepare_hr_for_data_table_rows(rows_ec_data, title)
    if next_page_token:
        hr += (
            "\nThe command can search and remove the up to 1000 rows in single execution. To remove the next set of"
            f" data table rows, execute the command with the page token as `{next_page_token}`."
        )

    ec = {SECOPS_OUTPUT_PATHS["RemovedDataTableRows"]: rows_ec_data}
    return hr, remove_empty_elements(ec), {}


def gcb_get_detection_command(client_obj, args):
    """
    Retrieves the detection details of specified detection ID.

    :type client_obj: Client
    :param client_obj: client object which is used to get response from api.

    :type args: Dict[str, str]
    :param args: it contains arguments for gcb-get-detection command.

    :return: command output.
    :rtype: str, dict, dict
    """
    rule_id = validate_argument(args.get("rule_id"), "rule_id")
    detection_id = validate_argument(args.get("detection_id"), "detection_id")

    json_data, ec = gcb_get_detection(client_obj, rule_id, detection_id)

    if not json_data:
        hr = "### No Detection Details Found"
        return hr, {}, {}

    hr = prepare_hr_for_get_detection(json_data)

    return hr, remove_empty_elements(ec), json_data


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""

    secops_commands = {
        "gcb-list-rules": gcb_list_rules_command,
        "gcb-create-rule": gcb_create_rule_command,
        "gcb-get-rule": gcb_get_rule_command,
        "gcb-delete-rule": gcb_delete_rule_command,
        "gcb-create-rule-version": gcb_create_rule_version_command,
        "gcb-change-rule-alerting-status": gcb_change_rule_alerting_status_command,
        "gcb-change-live-rule-status": gcb_change_live_rule_status_command,
        "gcb-verify-rule": gcb_verify_rule_command,
        "gcb-list-retrohunts": gcb_list_retrohunts_command,
        "gcb-get-retrohunt": gcb_get_retrohunt_command,
        "gcb-start-retrohunt": gcb_start_retrohunt_command,
        "gcb-cancel-retrohunt": gcb_cancel_retrohunt_command,
        "gcb-list-events": gcb_list_events_command,
        "gcb-get-event": gcb_get_event_command,
        "gcb-list-detections": gcb_list_detections_command,
        "gcb-list-curatedrule-detections": gcb_list_curatedrule_detections_command,
        "gcb-list-curatedrules": gcb_list_curated_rules_command,
        "gcb-test-rule-stream": gcb_test_rule_stream_command,
        "gcb-udm-search": gcb_udm_search_command,
        "gcb-get-reference-list": gcb_get_reference_list_command,
        "gcb-create-reference-list": gcb_create_reference_list_command,
        "gcb-update-reference-list": gcb_update_reference_list_command,
        "gcb-list-reference-list": gcb_list_reference_list_command,
        "gcb-verify-reference-list": gcb_verify_reference_list_command,
        "gcb-verify-value-in-reference-list": gcb_verify_value_in_reference_list_command,
        "gcb-reference-list-append-content": gcb_reference_list_append_content,
        "gcb-reference-list-remove-content": gcb_reference_list_remove_content,
        "gcb-list-iocs": gcb_list_iocs_command,
        "gcb-ioc-details": gcb_ioc_details_command,
        "gcb-list-data-tables": gcb_list_data_tables_command,
        "gcb-create-data-table": gcb_create_data_table_command,
        "gcb-get-data-table": gcb_get_data_table_command,
        "gcb-verify-value-in-data-table": gcb_verify_value_in_data_table_command,
        "gcb-data-table-add-row": gcb_data_table_add_row_command,
        "gcb-data-table-remove-row": gcb_data_table_remove_row_command,
        "gcb-get-detection": gcb_get_detection_command,
    }

    params = demisto.params()
    remove_nulls_from_dictionary(demisto.params())

    # initialize configuration parameter
    proxy = params.get("proxy")
    disable_ssl = params.get("insecure", False)
    command = demisto.command()

    try:
        validate_configuration_parameters(params)

        # Initializing client Object
        client_obj = Client(params, proxy, disable_ssl)

        # trigger command based on input
        if command == "test-module":
            test_function(client_obj, params)
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(client_obj, params)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command == "ip":
            args = trim_args(demisto.args())
            ip = args.get("ip", "")
            reputation_operation_command(client_obj, ip, ip_command)
        elif command == "domain":
            args = trim_args(demisto.args())
            domain = args.get("domain", "")
            reputation_operation_command(client_obj, domain, domain_command)
        elif command in secops_commands:
            args = trim_args(demisto.args())
            return_outputs(*secops_commands[command](client_obj, args))
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
