import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa: F401

"""IMPORTS"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

import pytmv1
import urllib3
from pytmv1 import (  # noqa: E402
    TiAlert,
    SaeAlert,
    ObjectType,
    ResultCode,
    AlertStatus,
    ObjectRequest,
    EmailActivity,
    AccountRequest,
    EndpointRequest,
    ExceptionObject,
    SuspiciousObject,
    EndpointActivity,
    CollectFileRequest,
    CollectFileTaskResp,
    CustomScriptRequest,
    InvestigationResult,
    EmailMessageIdRequest,
    EmailMessageUIdRequest,
    SuspiciousObjectRequest,
    TerminateProcessRequest,
)

"""CONSTANTS"""
VENDOR_NAME = "TrendMicroVisionOneV3"
ACCOUNT_IDENTIFIERS = "account_identifiers"
EMAIL_IDENTIFIERS = "email_identifiers"
ENDPOINT_IDENTIFIERS = "endpoint_identifiers"
PROCESS_IDENTIFIERS = "process_identifiers"
COLLECT_FILES = "collect_files"
BLOCK = "block"
ANY = "any"
URL = "url"
URLS = "urls"
INTERVAL_IN_SECONDS = "interval_in_seconds"
MEDIUM = "medium"
NAME = "name"
PATH = "path"
IF_MATCH = "if_match"
INV_RESULT = "inv_result"
FALSE = "false"
TRUE = "true"
POLL = "poll"
POLL_TIME_SEC = "poll_time_sec"
POLLING = "polling"
ARGUMENTS = "arguments"
ACCOUNT_NAME = "account_name"
INTEGRATION_RELIABILITY = "integrationReliability"
INCIDENT_SEVERITY = "incident_severity"
EMPTY_STRING = ""
API_TOKEN = "apikey"
AGENT_GUID = "agent_guid"
DESCRIPTION = "description"
MESSAGE_ID = "message_id"
MAILBOX = "mailbox"
ENDPOINT = "endpoint"
START = "start"
SELECT = "select"
END = "end"
TOP = "top"
FILE = "file"
QUERY_OP = "query_op"
FIELDS = "fields"
ENTRY_ID = "entry_id"
FILE_SHA1 = "file_sha1"
SUCCEEDED = "succeeded"
SCAN_ACTION = "scan_action"
RISK_LEVEL = "risk_level"
EXPIRY_DAYS = "expiry_days"
DETECTED_END = "detected_end"
DETECTED_START = "detected_start"
INGESTED_END = "ingested_end"
INGESTED_START = "ingested_start"
TASKID = "task_id"
REPORT_ID = "report_id"
OBJECT_TYPE = "object_type"
OBJECT_VALUE = "object_value"
SCRIPT_CONTENTS = "script_contents"
QUEUED = "queued"
FAILED = "failed"
RUNNING = "running"
REJECTED = "rejected"
PARAMETER = "parameter"
WAITFORAPPROVAL = "waitForApproval"
OS_TYPE = "os"
FILEPATH = "filepath"
FILE_PATH = "file_path"
FILE_URL = "file_url"
FILE_NAME = "filename"
FILE_TYPE = "filetype"
FETCH_ALL = "fetch_all"
FETCH_MAX_COUNT = "fetch_max_count"
DEFAULT_MAX_FETCH = 5000
SCRIPT_ID = "script_id"
DOCUMENT_PASSWORD = "document_password"
ARCHIVE_PASSWORD = "archive_password"
WORKBENCH_ID = "workbench_id"
CONTENT = "content"
STATUS = "status"
SUBMISSION_ID = "submission_id"
UNIQUE_ID = "unique_id"
# Error Messages
COMMAND_CALLED = "Command being called is {command}"
# Action Descriptions
BLOCK_OBJECTS = "block_objects"
ADD_BLOCKLIST = "Add To Blocklist."
DELETE_EMAIL = "Delete Email Message."
ISOLATE_ENDPOINT = "Isolate Endpoint."
RESTORE_ENDPOINT = "Restore Endpoint."
SIGN_OUT_ACCOUNT = "Sign Out Account."
COLLECT_FILE = "Collect Forensic File."
ENABLE_ACCOUNT = "Enable User Account."
ADD_CUSTOM_SCRIPT = "Add Custom Script."
RESTORE_EMAIL = "Restore Email Message."
RUN_CUSTOM_SCRIPT = "Run Custom Script."
TERMINATE_PROCESS = "Terminate Process."
DISABLE_ACCOUNT = "Disable User Account."
ADD_SUSPICIOUS = "Add to Suspicious list."
REMOVE_BLOCKLIST = "Remove from Blocklist."
FAILED_CONNECTIVITY = "Connectivity failed!"
ADD_EXCEPTION_LIST = "Add To Exception list."
UPDATE_CUSTOM_SCRIPT = "Update Custom Script."
QUARANTINE_EMAIL = "Quarantine Email Message."
FORCE_PASSWORD_RESET = "Force Password Reset."
DELETE_SUSPICIOUS = "Delete from Suspicious list."
DELETE_EXCEPTION_LIST = "Delete from Exception list."
# Table Heading
TABLE_ENABLE_USER_ACCOUNT = "Enable user account "
TABLE_DISABLE_USER_ACCOUNT = "Disable user account "
TABLE_FORCE_SIGN_OUT = "Force sign out "
TABLE_FORCE_PASSWORD_RESET = "Force password reset "
TABLE_ADD_TO_BLOCKLIST = "Add to block list "
TABLE_REMOVE_FROM_BLOCKLIST = "Remove from block list "
TABLE_QUARANTINE_EMAIL_MESSAGE = "Quarantine email message "
TABLE_DELETE_EMAIL_MESSAGE = "Delete email message "
TABLE_RESTORE_EMAIL_MESSAGE = "Restore email message "
TABLE_ISOLATE_ENDPOINT = "Isolate endpoint connection "
TABLE_RESTORE_ENDPOINT = "Restore endpoint connection "
TABLE_TERMINATE_PROCESS = "Terminate process "
TABLE_ADD_EXCEPTION_LIST = "Add object to exception list "
TABLE_DELETE_EXCEPTION_LIST = "Delete object from exception list "
TABLE_ADD_SUSPICIOUS_LIST = "Add object to suspicious list "
TABLE_DELETE_SUSPICIOUS_LIST = "Delete object from suspicious list "
TABLE_ENDPOINT_INFO = "Endpoint info "
TABLE_GET_EMAIL_ACTIVITY_DATA = "Email activity data "
TABLE_GET_EMAIL_ACTIVITY_DATA_COUNT = "Email activity data count "
TABLE_GET_ENDPOINT_ACTIVITY_DATA = "Endpoint activity data "
TABLE_GET_ENDPOINT_ACTIVITY_DATA_COUNT = "Endpoint activity data count "
TABLE_GET_FILE_ANALYSIS_STATUS = "File analysis status "
TABLE_GET_FILE_ANALYSIS_RESULT = "File analysis result "
TABLE_GET_ALERT_DETAILS = "Alert details "
TABLE_COLLECT_FILE = "Collect forensic file "
TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION = (
    "Download information for collected forensic file "
)
TABLE_SUBMIT_FILE_TO_SANDBOX = "Submit file to sandbox "
TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX = "Submit file entry to sandbox "
TABLE_SUBMIT_URLS_TO_SANDBOX = "Submit urls to sandbox "
TABLE_SANDBOX_SUBMISSION_POLLING = "Sandbox submission polling status "
TABLE_CHECK_TASK_STATUS = "Check task status "
TABLE_DOWNLOAD_ANALYSIS_REPORT = "Download analysis report "
TABLE_DOWNLOAD_INVESTIGATION_PACKAGE = "Download investigation package "
TABLE_DOWNLOAD_SUSPICIOUS_OBJECT_LIST = "Download suspicious object list "
TABLE_ADD_NOTE = "Add note to workbench alert "
TABLE_UPDATE_STATUS = "Update workbench alert status "
TABLE_ADD_CUSTOM_SCRIPT = "Add custom script "
TABLE_RUN_CUSTOM_SCRIPT = "Run custom script "
TABLE_UPDATE_CUSTOM_SCRIPT = "Update custom script "
TABLE_DELETE_CUSTOM_SCRIPT = "Delete custom script "
TABLE_GET_CUSTOM_SCRIPT_LIST = "Get custom script list "
TABLE_DOWNLOAD_CUSTOM_SCRIPT = "Download custom script "
TABLE_GET_OBSERVED_ATTACK_TECHNIQUES = "Get Observed Attack Techniques "
# COMMAND NAMES
ENABLE_USER_ACCOUNT_COMMAND = "trendmicro-visionone-enable-user-account"
DISABLE_USER_ACCOUNT_COMMAND = "trendmicro-visionone-disable-user-account"
FORCE_SIGN_OUT_COMMAND = "trendmicro-visionone-force-signout"
FORCE_PASSWORD_RESET_COMMAND = "trendmicro-visionone-force-password-reset"
ADD_BLOCKLIST_COMMAND = "trendmicro-visionone-add-to-block-list"
REMOVE_BLOCKLIST_COMMAND = "trendmicro-visionone-remove-from-block-list"
QUARANTINE_EMAIL_COMMAND = "trendmicro-visionone-quarantine-email-message"
DELETE_EMAIL_COMMAND = "trendmicro-visionone-delete-email-message"
RESTORE_EMAIL_COMMAND = "trendmicro-visionone-restore-email-message"
ISOLATE_ENDPOINT_COMMAND = "trendmicro-visionone-isolate-endpoint"
RESTORE_ENDPOINT_COMMAND = "trendmicro-visionone-restore-endpoint-connection"
TERMINATE_PROCESS_COMMAND = "trendmicro-visionone-terminate-process"
ADD_EXCEPTION_LIST_COMMAND = "trendmicro-visionone-add-objects-to-exception-list"
DELETE_EXCEPTION_LIST_COMMAND = (
    "trendmicro-visionone-delete-objects-from-exception-list"
)
ADD_SUSPICIOUS_LIST_COMMAND = "trendmicro-visionone-add-objects-to-suspicious-list"
DELETE_SUSPICIOUS_LIST_COMMAND = (
    "trendmicro-visionone-delete-objects-from-suspicious-list"
)
GET_FILE_ANALYSIS_STATUS_COMMAND = "trendmicro-visionone-get-file-analysis-status"
GET_FILE_ANALYSIS_RESULT_COMMAND = "trendmicro-visionone-get-file-analysis-result"
COLLECT_FILE_COMMAND = "trendmicro-visionone-collect-forensic-file"
DOWNLOAD_COLLECTED_FILE_COMMAND = (
    "trendmicro-visionone-download-information-for-collected-forensic-file"
)
DOWNLOAD_ANALYSIS_REPORT_COMMAND = "trendmicro-visionone-download-analysis-report"
DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND = (
    "trendmicro-visionone-download-investigation-package"
)
DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND = (
    "trendmicro-visionone-download-suspicious-object-list"
)
FILE_TO_SANDBOX_COMMAND = "trendmicro-visionone-submit-file-to-sandbox"
FILE_ENTRY_TO_SANDBOX_COMMAND = "trendmicro-visionone-submit-file-entry-to-sandbox"
URLS_TO_SANDBOX_COMMAND = "trendmicro-visionone-submit-urls-to-sandbox"
SANDBOX_SUBMISSION_POLLING_COMMAND = (
    "trendmicro-visionone-run-sandbox-submission-polling"
)
CHECK_TASK_STATUS_COMMAND = "trendmicro-visionone-check-task-status"
GET_ENDPOINT_INFO_COMMAND = "trendmicro-visionone-get-endpoint-info"
GET_EMAIL_ACTIVITY_DATA_COMMAND = "trendmicro-visionone-get-email-activity-data"
GET_EMAIL_ACTIVITY_DATA_COUNT_COMMAND = (
    "trendmicro-visionone-get-email-activity-data-count"
)
GET_ENDPOINT_ACTIVITY_DATA_COMMAND = "trendmicro-visionone-get-endpoint-activity-data"
GET_ENDPOINT_ACTIVITY_DATA_COUNT_COMMAND = (
    "trendmicro-visionone-get-endpoint-activity-data-count"
)
GET_ALERT_DETAILS_COMMAND = "trendmicro-visionone-get-alert-details"
UPDATE_STATUS_COMMAND = "trendmicro-visionone-update-status"
ADD_NOTE_COMMAND = "trendmicro-visionone-add-note"
ADD_CUSTOM_SCRIPT_COMMAND = "trendmicro-visionone-add-custom-script"
RUN_CUSTOM_SCRIPT_COMMAND = "trendmicro-visionone-run-custom-script"
UPDATE_CUSTOM_SCRIPT_COMMAND = "trendmicro-visionone-update-custom-script"
DELETE_CUSTOM_SCRIPT_COMMAND = "trendmicro-visionone-delete-custom-script"
DOWNLOAD_CUSTOM_SCRIPT_COMMAND = "trendmicro-visionone-download-custom-script"
GET_CUSTOM_SCRIPT_LIST_COMMAND = "trendmicro-visionone-get-custom-script-list"
GET_OBSERVED_ATTACK_TECHNIQUES_COMMAND = (
    "trendmicro-visionone-get-observed-attack-techniques"
)
FETCH_INCIDENTS = "fetch-incidents"
TEST_MODULE = "test-module"

table_name = {
    ADD_NOTE_COMMAND: TABLE_ADD_NOTE,
    COLLECT_FILE_COMMAND: TABLE_COLLECT_FILE,
    UPDATE_STATUS_COMMAND: TABLE_UPDATE_STATUS,
    FORCE_SIGN_OUT_COMMAND: TABLE_FORCE_SIGN_OUT,
    ADD_BLOCKLIST_COMMAND: TABLE_ADD_TO_BLOCKLIST,
    GET_ENDPOINT_INFO_COMMAND: TABLE_ENDPOINT_INFO,
    ISOLATE_ENDPOINT_COMMAND: TABLE_ISOLATE_ENDPOINT,
    RESTORE_ENDPOINT_COMMAND: TABLE_RESTORE_ENDPOINT,
    DELETE_EMAIL_COMMAND: TABLE_DELETE_EMAIL_MESSAGE,
    CHECK_TASK_STATUS_COMMAND: TABLE_CHECK_TASK_STATUS,
    GET_ALERT_DETAILS_COMMAND: TABLE_GET_ALERT_DETAILS,
    RESTORE_EMAIL_COMMAND: TABLE_RESTORE_EMAIL_MESSAGE,
    TERMINATE_PROCESS_COMMAND: TABLE_TERMINATE_PROCESS,
    RUN_CUSTOM_SCRIPT_COMMAND: TABLE_RUN_CUSTOM_SCRIPT,
    ADD_CUSTOM_SCRIPT_COMMAND: TABLE_ADD_CUSTOM_SCRIPT,
    ADD_EXCEPTION_LIST_COMMAND: TABLE_ADD_EXCEPTION_LIST,
    REMOVE_BLOCKLIST_COMMAND: TABLE_REMOVE_FROM_BLOCKLIST,
    FILE_TO_SANDBOX_COMMAND: TABLE_SUBMIT_FILE_TO_SANDBOX,
    URLS_TO_SANDBOX_COMMAND: TABLE_SUBMIT_URLS_TO_SANDBOX,
    ENABLE_USER_ACCOUNT_COMMAND: TABLE_ENABLE_USER_ACCOUNT,
    ADD_SUSPICIOUS_LIST_COMMAND: TABLE_ADD_SUSPICIOUS_LIST,
    UPDATE_CUSTOM_SCRIPT_COMMAND: TABLE_UPDATE_CUSTOM_SCRIPT,
    DELETE_CUSTOM_SCRIPT_COMMAND: TABLE_DELETE_CUSTOM_SCRIPT,
    DISABLE_USER_ACCOUNT_COMMAND: TABLE_DISABLE_USER_ACCOUNT,
    FORCE_PASSWORD_RESET_COMMAND: TABLE_FORCE_PASSWORD_RESET,
    QUARANTINE_EMAIL_COMMAND: TABLE_QUARANTINE_EMAIL_MESSAGE,
    DELETE_EXCEPTION_LIST_COMMAND: TABLE_DELETE_EXCEPTION_LIST,
    DOWNLOAD_CUSTOM_SCRIPT_COMMAND: TABLE_DOWNLOAD_CUSTOM_SCRIPT,
    GET_CUSTOM_SCRIPT_LIST_COMMAND: TABLE_GET_CUSTOM_SCRIPT_LIST,
    DELETE_SUSPICIOUS_LIST_COMMAND: TABLE_DELETE_SUSPICIOUS_LIST,
    GET_EMAIL_ACTIVITY_DATA_COMMAND: TABLE_GET_EMAIL_ACTIVITY_DATA,
    GET_FILE_ANALYSIS_STATUS_COMMAND: TABLE_GET_FILE_ANALYSIS_STATUS,
    GET_FILE_ANALYSIS_RESULT_COMMAND: TABLE_GET_FILE_ANALYSIS_RESULT,
    DOWNLOAD_ANALYSIS_REPORT_COMMAND: TABLE_DOWNLOAD_ANALYSIS_REPORT,
    FILE_ENTRY_TO_SANDBOX_COMMAND: TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX,
    SANDBOX_SUBMISSION_POLLING_COMMAND: TABLE_SANDBOX_SUBMISSION_POLLING,
    GET_ENDPOINT_ACTIVITY_DATA_COMMAND: TABLE_GET_ENDPOINT_ACTIVITY_DATA,
    GET_EMAIL_ACTIVITY_DATA_COUNT_COMMAND: TABLE_GET_EMAIL_ACTIVITY_DATA_COUNT,
    GET_OBSERVED_ATTACK_TECHNIQUES_COMMAND: TABLE_GET_OBSERVED_ATTACK_TECHNIQUES,
    DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND: TABLE_DOWNLOAD_INVESTIGATION_PACKAGE,
    DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND: TABLE_DOWNLOAD_SUSPICIOUS_OBJECT_LIST,
    GET_ENDPOINT_ACTIVITY_DATA_COUNT_COMMAND: TABLE_GET_ENDPOINT_ACTIVITY_DATA_COUNT,
    DOWNLOAD_COLLECTED_FILE_COMMAND: TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION,
}
# disable insecure warnings
urllib3.disable_warnings()

_T = TypeVar("_T")


def unwrap(val: Optional[_T]) -> _T:
    if val is None:
        raise ValueError("Expected non-null value but received None.")
    return val


def check_datetime_aware(d):
    return (d.tzinfo is not None) and (d.tzinfo.utcoffset(d) is not None)


def status_check(v1_client: pytmv1.Client, data: dict[str, Any]) -> Any:
    """
    Check the status of particular task.
    :type data: ``dict``
    :param method: Response data to received from the end point.
    :return: task status response data.
    :rtype: ``Any``
    """
    task_id = data.get(TASKID, EMPTY_STRING)
    poll = argToBoolean(data.get(POLL, TRUE))
    poll_time_sec = arg_to_number(data.get(POLL_TIME_SEC, 0))
    message: dict[str, Any] = {}

    # Make rest call
    resp = v1_client.task.get_result(
        task_id=task_id, poll=poll, poll_time_sec=poll_time_sec  # type: ignore
    )
    # Check if error response is returned
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Assign values on a successful call
    resp_obj: pytmv1.BaseTaskResp = unwrap(resp.response)
    message = resp_obj.model_dump()
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[CHECK_TASK_STATUS_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Task_Status",
        outputs_key_field="id",
        outputs=message,
    )


def sandbox_submission_polling(v1_client: pytmv1.Client, data: dict[str, Any]) -> Any:
    """
    Check the status of sandbox submission
    :type data: ``dict``
    :param method: Response data received from sandbox.
    :return: Sandbox submission response data.
    :rtype: ``Any``
    """
    task_id = data.get(TASKID, EMPTY_STRING)
    message: dict[str, Any] = {}
    # Make rest call
    resp = v1_client.sandbox.get_submission_status(submit_id=task_id)
    resp_obj: pytmv1.SandboxSubmissionStatusResp = unwrap(resp.response)
    # Check if error response is returned
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Get the task status of rest call
    task_status = resp_obj.status
    file_entry = Common.File(sha256=None, md5=None, sha1=None, dbot_score=None)
    if task_status.lower() == SUCCEEDED:
        analysis_resp = v1_client.sandbox.get_analysis_result(submit_id=task_id)
        if _is_pytmv1_error(analysis_resp.result_code):
            error: pytmv1.Error = unwrap(analysis_resp.error)
            return_error(message=f"{error.message}", error=str(error))
        analysis_resp_obj: pytmv1.SandboxAnalysisResultResp = unwrap(
            analysis_resp.response
        )
        risk = analysis_resp_obj.risk_level
        risk_score = incident_severity_to_dbot_score(risk)
        digest: pytmv1.Digest = unwrap(analysis_resp_obj.digest)
        sha256 = digest.sha256
        md5 = digest.md5
        sha1 = digest.sha1
        reliability = demisto.params().get(INTEGRATION_RELIABILITY)
        dbot_score = Common.DBotScore(
            indicator=sha256,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=risk_score,
            reliability=reliability,
        )
        file_entry = Common.File(
            sha256=sha256, md5=md5, sha1=sha1, dbot_score=dbot_score
        )
        message = {
            "status_code": 200,
            "status": task_status,
            "report_id": analysis_resp_obj.id,
            "type": analysis_resp_obj.type,
            "digest": digest.model_dump(),
            "arguments": analysis_resp_obj.arguments,
            "analysis_completion_time": analysis_resp_obj.analysis_completion_date_time,
            "risk_level": risk,
            "detection_name_list": analysis_resp_obj.detection_names,
            "threat_type_list": analysis_resp_obj.threat_types,
            "file_type": analysis_resp_obj.true_file_type,
            "DBotScore": {
                "Score": dbot_score.score,
                "Vendor": dbot_score.integration_name,
                "Reliability": dbot_score.reliability,
            },
        }
    else:
        message = {
            "status": resp_obj.status,
            "report_id": task_id,
            "result_code": resp.result_code,
            "message": resp_obj.action,
        }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[SANDBOX_SUBMISSION_POLLING_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Sandbox_Submission_Polling",
        outputs_key_field="report_id",
        outputs=message,
        indicator=file_entry,
    )


def exception_list_count(v1_client: pytmv1.Client) -> int:
    """
    Gets the count of object present in exception list
    :return: number of exception object.
    :rtype: ``int``
    """
    new_exceptions: list[ExceptionObject] = []

    #
    # Make rest call
    try:
        v1_client.object.consume_exception(
            lambda exception: new_exceptions.append(exception)
        )
    except Exception as err:
        raise RuntimeError(f"Error while fetching exception list count.\n {err}")
    # Return length of exception list
    return len(new_exceptions)


def suspicious_list_count(v1_client: pytmv1.Client) -> int:
    """
    Gets the count of object present in suspicious list
    :return: number of suspicious object.
    :rtype: ``int``
    """
    new_suspicious: list[SuspiciousObject] = []

    # Make rest call
    try:
        v1_client.object.consume_suspicious(
            lambda suspicious: new_suspicious.append(suspicious)
        )
    except Exception as err:
        raise RuntimeError(f"Error while fetching suspicious list count.\n {err}")
    # Return length of suspicious list
    return len(new_suspicious)


def get_workbench_histories(v1_client: pytmv1.Client, start, end) -> list:
    """
    Fetches incidents based on incident severity per user selection.
    Args:
    start (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start of the data retrieval
                    time range. Oldest available value is "1970-01-01T00:00:00Z"
    end (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end of the data retrieval
                time range. "endDateTime" can not be earlier than "startDateTime".
    Returns:
        list: list of incidents fetched
    """

    if not check_datetime_aware(start):
        start = start.astimezone()
    if not check_datetime_aware(end):
        end = end.astimezone()
    # Date time format before formatting -> 2020-06-15T10:00:00.000Z
    start = start.astimezone(UTC)
    end = end.astimezone(UTC)
    start = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    end = end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    # Format start and end to remove decimal values so that the request
    # call doesn't fail due to incorrect time format for seconds.
    # Date time format after formatting -> 2020-06-15T10:00:00Z
    formatted_start = str(start[: (start.index("."))]) + str(start[-1])
    formatted_end = str(end[: (start.index("."))]) + str(end[-1])

    new_alerts: list[SaeAlert | TiAlert] = []

    # filter incidents per user preference
    def _filter_alerts(alert: SaeAlert | TiAlert) -> None:
        # If incidents of all severities need to be fetched
        if demisto.params().get(INCIDENT_SEVERITY) == ANY:
            new_alerts.append(alert)
        # If incidents of selected severity need to be fetched
        elif alert.severity.value == demisto.params().get(INCIDENT_SEVERITY):
            new_alerts.append(alert)

    # Make rest call
    try:
        v1_client.alert.consume(
            _filter_alerts,
            start_time=formatted_start,
            end_time=formatted_end,
        )
    except Exception as err:
        demisto.debug(f"Error while fetching incidents.\n {err}")
        return []
    return new_alerts


def incident_severity_to_dbot_score(severity: str) -> int:
    """
    Converts an priority string to DBot score representation
    alert severity. Can be one of:
    - Unknown -> 0
    - No Risk -> 1
    - Low or Medium -> 2
    - Critical or High -> 3
    Args:
        severity: String representation of severity.
    Returns:
        Dbot representation of severity
    """
    if not isinstance(severity, str):
        return 0
    if severity == "noRisk":
        return 1
    if severity in ["low", "medium"]:
        return 2
    if severity in ["high", "critical"]:
        return 3
    return 0


# returns initialized pytmv1 client used to make rest calls
def _get_client(name: str, api_key: str, base_url: str) -> pytmv1.Client:
    return pytmv1.init(name, api_key, base_url)


# Checks the api response for error
def _is_pytmv1_error(result_code: ResultCode) -> bool:
    return result_code == ResultCode.ERROR


# Validates object types like ip, url, domain, etc.
def _get_ot_enum(obj_type: str) -> ObjectType:
    if obj_type.upper() not in ObjectType.__members__:
        raise RuntimeError(f"Please check object type: {obj_type}")
    return ObjectType[obj_type.upper()]


def run_polling_command(
    args: dict[str, Any], cmd: str, v1_client: pytmv1.Client
) -> str | CommandResults:
    """
    Performs polling interval to check status of task.
    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``cmd``
    :param client: The command that polled for an interval.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to call respective polling commands.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get(INTERVAL_IN_SECONDS, 30))
    task_id = args.get(TASKID, EMPTY_STRING)
    if cmd == CHECK_TASK_STATUS_COMMAND:
        command_results = status_check(v1_client, args)
    else:
        command_results = sandbox_submission_polling(v1_client, args)
    statuses = [FAILED, QUEUED, REJECTED, SUCCEEDED, WAITFORAPPROVAL]
    if command_results.outputs[STATUS] not in statuses:
        # schedule next poll
        polling_args = {
            task_id: task_id,
            INTERVAL_IN_SECONDS: interval_in_secs,
            POLLING: True,
            **args,
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=1500,
        )  # The timeout interval set for 25 minutes.
        command_results = CommandResults(scheduled_command=scheduled_command)
    return command_results


def get_task_status(
    args: dict[str, Any], v1_client: pytmv1.Client
) -> str | CommandResults:
    """
    check status of task.

    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    """
    return run_polling_command(args, CHECK_TASK_STATUS_COMMAND, v1_client)


def get_sandbox_submission_status(
    args: dict[str, Any], v1_client: pytmv1.Client
) -> str | CommandResults:
    """
    call polling command to check status of sandbox submission.
    :type args: ``args``
    :param client: argument required for polling.
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    """
    return run_polling_command(args, SANDBOX_SUBMISSION_POLLING_COMMAND, v1_client)


def test_module(v1_client: pytmv1.Client) -> str:
    """
    Performs basic get request to check for connectivity to Trend XDR.
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    """

    # Make rest call
    resp = v1_client.system.check_connectivity()
    if _is_pytmv1_error(resp.result_code):
        return FAILED_CONNECTIVITY
    return "ok"


def enable_or_disable_user_account(
    v1_client: pytmv1.Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
    """
    Enable allows the user to sign in to new application and browser sessions.
    Disable signs the user out of all active application and browser sessions,
    and prevents the user from signing in any new session.
    Supported IAM systems: Azure AD and Active Directory (on-premises).

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-enable-user-account
    or trendmicro-visionone-disable-user-account.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers = safe_load_json(args[ACCOUNT_IDENTIFIERS])
    account_tasks: list[AccountRequest] = []
    message: list[dict[str, Any]] = []

    if command == ENABLE_USER_ACCOUNT_COMMAND:
        # Create account task list
        for account in account_identifiers:  # type: ignore
            account_tasks.append(
                AccountRequest(
                    account_name=account[ACCOUNT_NAME],
                    description=account.get(DESCRIPTION, ENABLE_ACCOUNT),
                )
            )
        # Make rest call
        resp = v1_client.account.enable(*account_tasks)
        enable_resp_obj: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errs: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errs}", error=str(errs))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in enable_resp_obj.items]

    if command == DISABLE_USER_ACCOUNT_COMMAND:
        # Create account task list
        for account in account_identifiers:  # type: ignore
            account_tasks.append(
                AccountRequest(
                    account_name=account[ACCOUNT_NAME],
                    description=account.get(DESCRIPTION, DISABLE_ACCOUNT),
                )
            )
        # Make rest call
        resp = v1_client.account.disable(*account_tasks)
        disable_resp_obj: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errors: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errors}", error=str(errors))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in disable_resp_obj.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[command],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.User_Account",
        outputs_key_field="task_id",
        outputs=message,
    )


def force_sign_out(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Signs the user out of all active application and browser sessions.
    Supported IAM systems: Azure AD

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers = safe_load_json(args[ACCOUNT_IDENTIFIERS])
    account_tasks: list[AccountRequest] = []
    message: list[dict[str, Any]] = []

    # Create account task list
    for account in account_identifiers:  # type: ignore
        account_tasks.append(
            AccountRequest(
                account_name=account[ACCOUNT_NAME],
                description=account.get(DESCRIPTION, SIGN_OUT_ACCOUNT),
            )
        )
    # Make rest call
    resp = v1_client.account.sign_out(*account_tasks)
    resp_obj: pytmv1.MultiResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    # Add results to message to be sent to the War Room
    message = [item.model_dump() for item in resp_obj.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FORCE_SIGN_OUT_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Force_Sign_Out",
        outputs_key_field="task_id",
        outputs=message,
    )


def force_password_reset(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Signs the user out of all active application and browser sessions,
    and forces the user to create a new password during the next sign-in attempt.
    Supported IAM systems: Azure AD and Active Directory (on-premises)

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers = safe_load_json(args[ACCOUNT_IDENTIFIERS])
    account_tasks: list[AccountRequest] = []
    message: list[dict[str, Any]] = []

    # Create account task list
    for account in account_identifiers:  # type: ignore
        account_tasks.append(
            AccountRequest(
                account_name=account[ACCOUNT_NAME],
                description=account.get(DESCRIPTION, FORCE_PASSWORD_RESET),
            )
        )
    # Make rest call
    resp = v1_client.account.reset(*account_tasks)
    resp_obj: pytmv1.MultiResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        errors: list[pytmv1.MsError] = unwrap(resp.errors)
        return_error(message=f"{errors}", error=str(errors))
    # Add results to message to be sent to the War Room
    message = [item.model_dump() for item in resp_obj.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FORCE_PASSWORD_RESET_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Force_Password_Reset",
        outputs_key_field="task_id",
        outputs=message,
    )


def get_endpoint_info(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Retrieve information about the endpoint queried and
    sends the result to demisto war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    endpoint = json.loads(args.get(ENDPOINT, EMPTY_STRING))
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    new_endpoint_data: list[Any] = []
    message: list[dict[str, Any]] = []
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # Make rest call
    try:
        v1_client.endpoint.consume_data(
            lambda endpoint_data: new_endpoint_data.append(endpoint_data),
            op=query_op,
            **endpoint,
        )
    except Exception as e:
        raise RuntimeError(f"Something went wrong while fetching endpoint data: {e}")
    # Load json objects to list
    for endpoint in new_endpoint_data:
        message.append(endpoint.model_dump())
    # Check if endpoint(s) returned
    if len(message) == 0:
        err_msg = f"No endpoint found. Please check endpoint: {endpoint} and query_op: {query_op}."
        return_error(message=err_msg)

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ENDPOINT_INFO_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Endpoint_Info",
        outputs_key_field="endpoint_name",
        outputs=message,
    )


def get_endpoint_activity_data(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Displays search results from the Endpoint Activity Data source
    in a paginated list and sends the result to demisto war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Optional Params
    fields = json.loads(args.get(FIELDS, EMPTY_STRING))
    start = args.get(START, EMPTY_STRING)
    end = args.get(END, EMPTY_STRING)
    top = args.get(TOP, EMPTY_STRING)
    select = args.get(SELECT, EMPTY_STRING).split(",")
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    fetch_all = args.get(FETCH_ALL, FALSE)
    fetch_max_count = int(args.get(FETCH_MAX_COUNT, DEFAULT_MAX_FETCH))
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # list to contain endpoint activity data
    new_endpoint_activity: list[EndpointActivity] = []
    # Output to be sent to war room
    message: list[Any] = []
    # Get the activity count
    count_obj = get_endpoint_activity_data_count(v1_client, args)
    activity_count = int(count_obj.outputs.get("endpoint_activity_count", EMPTY_STRING))  # type: ignore
    if fetch_all == TRUE:
        if activity_count > fetch_max_count and fetch_max_count != 0:
            return_error(
                f"Please refine search, this query returns more than {fetch_max_count} results."
            )
        # Make rest call
        resp = v1_client.endpoint.consume_activity(
            lambda activity: new_endpoint_activity.append(activity),
            start_time=start,
            end_time=end,
            top=top,
            select=select,
            op=query_op,
            **fields,
        )
        # Parse endpoint activity data to message list and send to war room
        for activity in new_endpoint_activity:
            message.append(activity.model_dump())
    else:
        # Make rest call
        resp = v1_client.endpoint.list_activity(  # type: ignore[assignment]
            start_time=start,
            end_time=end,
            top=top,
            select=select,
            op=query_op,
            **fields,
        )
        resp_obj: pytmv1.ListEndpointActivityResp = unwrap(resp.response)  # type: ignore[assignment]
        # Parse endpoint activity data to message list and send to war room
        for activity in resp_obj.items:
            message.append(activity.model_dump())

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ENDPOINT_ACTIVITY_DATA_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Endpoint_Activity_Data",
        outputs_key_field="endpoint_host_name",
        outputs=message,
    )


def get_endpoint_activity_data_count(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Fetches endpoint activity data count.

    :return: sends data count to demisto war room.
    :rtype: ``int``
    """
    start = args.get(START, EMPTY_STRING)
    end = args.get(END, EMPTY_STRING)
    select = args.get(SELECT, EMPTY_STRING).split(",")
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    fields = json.loads(args.get(FIELDS, EMPTY_STRING))
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # Make rest call
    resp = v1_client.endpoint.get_activity_count(
        start_time=start,
        end_time=end,
        top=500,
        select=select,
        op=query_op,
        **fields,
    )
    resp_obj: pytmv1.GetEndpointActivitiesCountResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    activity_count = {"endpoint_activity_count": resp_obj.total_count}

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ENDPOINT_ACTIVITY_DATA_COUNT_COMMAND],
            activity_count,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Endpoint_Activity_Count",
        outputs_key_field="endpoint_activity_count",
        outputs=activity_count,
    )


def get_email_activity_data(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Displays search results from the Email Activity Data source
    in a paginated list and sends the result to demisto war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Optional Params
    fields = json.loads(args.get(FIELDS, EMPTY_STRING))
    start = args.get(START, EMPTY_STRING)
    end = args.get(END, EMPTY_STRING)
    top = args.get(TOP, EMPTY_STRING)
    select = args.get(SELECT, EMPTY_STRING).split(",")
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    fetch_all = args.get(FETCH_ALL, FALSE)
    fetch_max_count = int(args.get(FETCH_MAX_COUNT, DEFAULT_MAX_FETCH))
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # list to populate email activity data
    new_email_activity: list[EmailActivity] = []
    # Output to be sent to war room
    message: list[Any] = []
    # Get the activity count
    count_obj = get_email_activity_data_count(v1_client, args)
    activity_count = int(count_obj.outputs.get("email_activity_count", EMPTY_STRING))  # type: ignore
    # Check if user would like to fetch all activity
    if fetch_all == TRUE:
        if activity_count > fetch_max_count and fetch_max_count != 0:
            return_error(
                f"Please refine search, this query returns more than {fetch_max_count} results."
            )
        # Make rest call
        resp = v1_client.email.consume_activity(
            lambda activity: new_email_activity.append(activity),
            start_time=start,
            end_time=end,
            top=top,
            select=select,
            op=query_op,
            **fields,
        )
        # Parse endpoint activity data to message list and send to war room
        for activity in new_email_activity:
            message.append(activity.model_dump())
    else:
        # Make rest call
        resp = v1_client.email.list_activity(  # type: ignore[assignment]
            start_time=start,
            end_time=end,
            top=top,
            select=select,
            op=query_op,
            **fields,
        )
        resp_obj: pytmv1.ListEmailActivityResp = unwrap(resp.response)  # type: ignore[assignment]
        for activity in resp_obj.items:
            message.append(activity.model_dump())

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_EMAIL_ACTIVITY_DATA_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Email_Activity_Data",
        outputs_key_field="mail_to_addresses",
        outputs=message,
    )


def get_email_activity_data_count(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Fetches email activity data count.

    :return: sends activity data count to demisto war room.
    :rtype: ``int`
    """
    fields = json.loads(args.get(FIELDS, EMPTY_STRING))
    start = args.get(START, EMPTY_STRING)
    end = args.get(END, EMPTY_STRING)
    select = args.get(SELECT, EMPTY_STRING).split(",")
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # Make rest call
    resp = v1_client.email.get_activity_count(
        start_time=start,
        end_time=end,
        top=500,
        select=select,
        op=query_op,
        **fields,
    )
    resp_obj: pytmv1.GetEmailActivitiesCountResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Return the total count
    activity_count = {"email_activity_count": resp_obj.total_count}

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_EMAIL_ACTIVITY_DATA_COUNT_COMMAND],
            activity_count,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Email_Activity_Count",
        outputs_key_field="email_activity_count",
        outputs=activity_count,
    )


def add_or_remove_from_block_list(
    v1_client: pytmv1.Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
    """
    Retrieve data from the add or remove from block list and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-add-to-block-list
    or trendmicro-visionone-remove-from-block-list.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects = safe_load_json(args[BLOCK_OBJECTS])
    block_tasks: list[ObjectRequest] = []
    message: list[dict[str, Any]] = []

    if command == ADD_BLOCKLIST_COMMAND:
        # Create block task list
        for obj in block_objects:  # type: ignore
            block_tasks.append(
                ObjectRequest(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, ADD_BLOCKLIST),
                )
            )
        # Make rest call
        resp = v1_client.object.add_block(*block_tasks)
        add_block_resp_obj: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errs: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errs}", error=str(errs))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in add_block_resp_obj.items]

    if command == REMOVE_BLOCKLIST_COMMAND:
        # Create unblock task list
        for obj in block_objects:  # type: ignore
            block_tasks.append(
                ObjectRequest(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, REMOVE_BLOCKLIST),
                )
            )
        # Make rest call
        resp = v1_client.object.delete_block(*block_tasks)
        remove_block_resp_obj: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errors: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errors}", error=str(errors))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in remove_block_resp_obj.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[command],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.BlockList",
        outputs_key_field="task_id",
        outputs=message,
    )


def fetch_incidents(v1_client: pytmv1.Client):
    """
    This function executes to get all workbench alerts by using
    startDateTime, endDateTime and sends the result to war room.
    """
    end = datetime.now(UTC)
    days = int(demisto.params().get("first_fetch", ""))

    last_run = demisto.getLastRun()
    if last_run and "start_time" in last_run:
        start = datetime.fromisoformat(last_run.get("start_time", ""))
    else:
        start = end + timedelta(days=-days)
    # Fetch alerts
    alerts: list[Any] = get_workbench_histories(v1_client, start, end)
    # list to store incidents that will be sent to the UI
    incidents: list[dict[str, Any]] = []
    if alerts:
        # Alerts are fetched per created_date_time in descending order
        # Set the last_event to the created_date_time for the first alert
        # in alert list to get the latest created_date_time
        for record in alerts:
            incident = {
                "name": record.model,
                "dbotMirrorId": record.id,
                "details": record.description if isinstance(record, SaeAlert) else None,
                "occurred": record.created_date_time,
                "severity": incident_severity_to_dbot_score(record.severity),
                "rawJSON": record.model_dump_json(),
            }
            incidents.append(incident)
    demisto.setLastRun({"start_time": end.isoformat()})
    demisto.incidents(incidents)
    return incidents


def quarantine_or_delete_email_message(
    v1_client: pytmv1.Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
    """
    Retrieve data from the quarantine or delete email message and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-quarantine-email-message
    or trendmicro-visionone-delete-email-message.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    email_identifiers = safe_load_json(args[EMAIL_IDENTIFIERS])
    message: list[dict[str, Any]] = []
    email_tasks: list[EmailMessageIdRequest | EmailMessageUIdRequest] = []

    if command == QUARANTINE_EMAIL_COMMAND:
        # Create email task list
        for email in email_identifiers:  # type: ignore
            if email.get(MESSAGE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageIdRequest(
                        message_id=email[MESSAGE_ID],
                        mail_box=email.get(MAILBOX, EMPTY_STRING),
                        description=email.get(DESCRIPTION, QUARANTINE_EMAIL),
                    )
                )
            elif email.get(UNIQUE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageUIdRequest(
                        unique_id=email[UNIQUE_ID],
                        description=email.get(DESCRIPTION, QUARANTINE_EMAIL),
                    )
                )
        # Make rest call
        resp = v1_client.email.quarantine(*email_tasks)
        quarantine_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errs: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errs}", error=str(errs))

        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in quarantine_resp.items]

    if command == DELETE_EMAIL_COMMAND:
        # Create email task list
        for email in email_identifiers:  # type: ignore
            if email.get(MESSAGE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageIdRequest(
                        message_id=email[MESSAGE_ID],
                        mail_box=email.get(MAILBOX, EMPTY_STRING),
                        description=email.get(DESCRIPTION, DELETE_EMAIL),
                    )
                )
            elif email.get(UNIQUE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageUIdRequest(
                        unique_id=email[UNIQUE_ID],
                        description=email.get(DESCRIPTION, DELETE_EMAIL),
                    )
                )
        # Make rest call
        resp = v1_client.email.delete(*email_tasks)
        delete_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errors: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errors}", error=str(errors))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in delete_resp.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[command],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Email",
        outputs_key_field="task_id",
        outputs=message,
    )


def restore_email_message(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Restores a quarantined email message and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-quarantine-email-message
    or trendmicro-visionone-delete-email-message

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    email_identifiers = safe_load_json(args[EMAIL_IDENTIFIERS])
    message: list[dict[str, Any]] = []
    email_tasks: list[EmailMessageIdRequest | EmailMessageUIdRequest] = []

    # Create email task list
    for email in email_identifiers:  # type: ignore
        if email.get(MESSAGE_ID, EMPTY_STRING):
            email_tasks.append(
                EmailMessageIdRequest(
                    message_id=email[MESSAGE_ID],
                    description=email.get(DESCRIPTION, RESTORE_EMAIL),
                    mail_box=email.get(MAILBOX, EMPTY_STRING),
                )
            )
        elif email.get(UNIQUE_ID, EMPTY_STRING):
            email_tasks.append(
                EmailMessageUIdRequest(
                    unique_id=email[UNIQUE_ID],
                    description=email.get(DESCRIPTION, RESTORE_EMAIL),
                )
            )
        # Make rest call
        resp = v1_client.email.restore(*email_tasks)
        restore_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errs: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errs}", error=str(errs))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in restore_resp.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[RESTORE_EMAIL_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Email",
        outputs_key_field="task_id",
        outputs=message,
    )


def isolate_or_restore_connection(
    v1_client: pytmv1.Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
    """
    Retrieve data from the isolate or restore endpoint connection and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-isolate-endpoint
    or trendmicro-visionone-restore-endpoint-connection

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    endpoint_identifiers = safe_load_json(args[ENDPOINT_IDENTIFIERS])
    message: list[dict[str, Any]] = []
    endpt_tasks: list[EndpointRequest] = []

    if command == ISOLATE_ENDPOINT_COMMAND:
        # Create endpoint task list
        for endpt in endpoint_identifiers:  # type: ignore
            if endpt.get(ENDPOINT, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointRequest(
                        endpoint_name=endpt[ENDPOINT],
                        description=endpt.get(DESCRIPTION, ISOLATE_ENDPOINT),
                    )
                )
            elif endpt.get(AGENT_GUID, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointRequest(
                        agent_guid=endpt[AGENT_GUID],
                        description=endpt.get(DESCRIPTION, ISOLATE_ENDPOINT),
                    )  # type: ignore
                )
        # Make rest call
        resp = v1_client.endpoint.isolate(*endpt_tasks)
        isolate_endpoint_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errs: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errs}", error=str(errs))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in isolate_endpoint_resp.items]

    if command == RESTORE_ENDPOINT_COMMAND:
        # Create endpoint task list
        for endpt in endpoint_identifiers:  # type: ignore
            if endpt.get(ENDPOINT, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointRequest(
                        endpoint_name=endpt[ENDPOINT],
                        description=endpt.get(DESCRIPTION, RESTORE_ENDPOINT),
                    )
                )
            elif endpt.get(AGENT_GUID, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointRequest(
                        agent_guid=endpt[AGENT_GUID],
                        description=endpt.get(DESCRIPTION, RESTORE_ENDPOINT),
                    )  # type: ignore
                )
        # Make rest call
        resp = v1_client.endpoint.restore(*endpt_tasks)
        restore_endpoint_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errors: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errors}", error=str(errors))
        # Add results to message to be sent to the War Room
        message = [item.model_dump() for item in restore_endpoint_resp.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[command],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Endpoint_Connection",
        outputs_key_field="task_id",
        outputs=message,
    )


def terminate_process(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Terminate the process running on the end point and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    process_identifiers = safe_load_json(args[PROCESS_IDENTIFIERS])
    process_tasks: list[TerminateProcessRequest] = []
    message: list[dict[str, Any]] = []

    # Create process task list
    for process in process_identifiers:  # type: ignore
        if process.get(ENDPOINT):
            process_tasks.append(
                TerminateProcessRequest(
                    file_sha1=process[FILE_SHA1],
                    endpoint_name=process[ENDPOINT],
                    file_name=process.get(FILE_NAME, EMPTY_STRING),
                    description=process.get(DESCRIPTION, TERMINATE_PROCESS),
                )
            )
        elif process.get(AGENT_GUID):
            process_tasks.append(
                TerminateProcessRequest(
                    file_sha1=process[FILE_SHA1],
                    agent_guid=process[AGENT_GUID],
                    file_name=process.get(FILE_NAME, EMPTY_STRING),
                    description=process.get(DESCRIPTION, TERMINATE_PROCESS),
                )  # type: ignore
            )
    # Make rest call
    resp = v1_client.endpoint.terminate_process(*process_tasks)
    process_resp: pytmv1.MultiResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        errs: list[pytmv1.MsError] = unwrap(resp.errors)
        return_error(message=f"{errs}", error=str(errs))
    # Add results to message to be sent to the War Room
    message = [item.model_dump() for item in process_resp.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            TABLE_TERMINATE_PROCESS,
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Terminate_Process",
        outputs_key_field="task_id",
        outputs=message,
    )


def add_or_delete_from_exception_list(
    v1_client: pytmv1.Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
    """
    Add or Delete the exception object to exception list and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: type of command either
    trendmicro-visionone-add-objects-to-exception-list or
    trendmicro-visionone-delete-objects-from-exception-list

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects = safe_load_json(args[BLOCK_OBJECTS])
    excp_tasks: list[ObjectRequest] = []
    message: dict[str, Any] = {}

    if command == ADD_EXCEPTION_LIST_COMMAND:
        # Create exception task list
        for obj in block_objects:  # type: ignore
            excp_tasks.append(
                ObjectRequest(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, ADD_EXCEPTION_LIST),
                )
            )
        # Make rest call
        resp = v1_client.object.add_exception(*excp_tasks)
        add_excp_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            errs: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errs}", error=str(errs))
        message = {
            "message": "success",
            "multi_response": [item.model_dump() for item in add_excp_resp.items],
        }

    if command == DELETE_EXCEPTION_LIST_COMMAND:
        # Create exception task list
        for obj in block_objects:  # type: ignore
            excp_tasks.append(
                ObjectRequest(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, DELETE_EXCEPTION_LIST),
                )
            )
        # Make rest call
        resp = v1_client.object.delete_exception(*excp_tasks)
        rmv_excp_resp: pytmv1.MultiResp = unwrap(resp.response)
        # Check if an error occurred for each call
        if _is_pytmv1_error(resp.result_code):
            errors: list[pytmv1.MsError] = unwrap(resp.errors)
            return_error(message=f"{errors}", error=str(errors))
        message = {
            "message": "success",
            "multi_response": [item.model_dump() for item in rmv_excp_resp.items],
        }
    # Get the total count of items in exception list
    exception_count = exception_list_count(v1_client)
    # Add count of total exception items to message
    message["total_items"] = exception_count
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[command],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Exception_List",
        outputs_key_field="multi_response",
        outputs=message,
    )


def add_to_suspicious_list(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Add suspicious object to suspicious list and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects = safe_load_json(args[BLOCK_OBJECTS])

    suspicious_tasks: list[SuspiciousObjectRequest] = []
    message: dict[str, Any] = {}

    # Create suspicious task list
    for block in block_objects:  # type: ignore
        suspicious_tasks.append(
            SuspiciousObjectRequest(
                object_type=_get_ot_enum(block[OBJECT_TYPE]),
                object_value=block[OBJECT_VALUE],
                scan_action=block.get(SCAN_ACTION, BLOCK),
                risk_level=block.get(RISK_LEVEL, MEDIUM),
                days_to_expiration=block.get(EXPIRY_DAYS, 30),
                description=block.get(DESCRIPTION, ADD_SUSPICIOUS),
            )
        )
    # Make rest call
    resp = v1_client.object.add_suspicious(*suspicious_tasks)
    add_sus_resp: pytmv1.MultiResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        errs: list[pytmv1.MsError] = unwrap(resp.errors)
        return_error(message=f"{errs}", error=str(errs))
    # Get the total count of items in suspicious list
    suspicious_count = suspicious_list_count(v1_client)
    # Add results to message to be sent to the War Room
    message = {
        "message": "success",
        "multi_response": [item.model_dump() for item in add_sus_resp.items],
        "total_items": suspicious_count,
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[ADD_SUSPICIOUS_LIST_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Suspicious_List",
        outputs_key_field="multi_response",
        outputs=message,
    )


def delete_from_suspicious_list(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Delete the suspicious object from suspicious list and
    sends the result to demist war room.

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects = safe_load_json(args[BLOCK_OBJECTS])

    suspicious_tasks: list[ObjectRequest] = []
    message: dict[str, Any] = {}

    # Create suspicious task list
    for block in block_objects:  # type: ignore
        suspicious_tasks.append(
            ObjectRequest(
                object_type=_get_ot_enum(block[OBJECT_TYPE]),
                object_value=block[OBJECT_VALUE],
                description=block.get(DESCRIPTION, DELETE_SUSPICIOUS),
            )
        )
    # Make rest call
    resp = v1_client.object.delete_suspicious(*suspicious_tasks)
    dlt_sus_resp: pytmv1.MultiResp = unwrap(resp.response)
    if _is_pytmv1_error(resp.result_code):
        errs: list[pytmv1.MsError] = unwrap(resp.errors)
        return_error(message=f"{errs}", error=str(errs))
    # Get the total count of items in suspicious list
    suspicious_count = suspicious_list_count(v1_client)
    # Add results to message to be sent to the War Room
    message = {
        "message": "success",
        "multi_response": [item.model_dump() for item in dlt_sus_resp.items],
        "total_items": suspicious_count,
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DELETE_SUSPICIOUS_LIST_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Suspicious_List",
        outputs_key_field="multi_response",
        outputs=message,
    )


def get_file_analysis_status(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Get the status of file based on task id and
    sends the result to demist war room

    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    task_id = args.get(TASKID, EMPTY_STRING)
    message: dict[str, Any] = {}

    # Make rest call
    resp = v1_client.sandbox.get_submission_status(submit_id=task_id)
    resp_obj: pytmv1.SandboxSubmissionStatusResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    message = resp_obj.model_dump()

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_FILE_ANALYSIS_STATUS_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.File_Analysis_Status",
        outputs_key_field="id",
        outputs=message,
    )


def get_file_analysis_result(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Get the report of file based on report id and sends the result to demist war room
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    report_id = args.get(REPORT_ID, EMPTY_STRING)
    # Optional Params
    poll = argToBoolean(args.get(POLL, TRUE))
    poll_time_sec = arg_to_number(args.get(POLL_TIME_SEC, 0))
    message: dict[str, Any] = {}

    # Make rest call
    resp = v1_client.sandbox.get_analysis_result(
        submit_id=report_id,
        poll=poll,
        poll_time_sec=poll_time_sec,  # type: ignore
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Extract values on successful call
    reliability = demisto.params().get(INTEGRATION_RELIABILITY)
    sandbox_response: pytmv1.SandboxAnalysisResultResp = unwrap(resp.response)
    risk = sandbox_response.risk_level
    risk_score = incident_severity_to_dbot_score(risk)
    digest: pytmv1.Digest = unwrap(sandbox_response.digest)
    sha256 = digest.sha256
    md5 = digest.md5
    sha1 = digest.sha1
    # Create DBot Score
    dbot_score = Common.DBotScore(
        indicator=sha256,
        indicator_type=DBotScoreType.FILE,
        integration_name=VENDOR_NAME,
        score=risk_score,
        reliability=reliability,
    )
    # Create file
    file_entry = Common.File(sha256=sha256, md5=md5, sha1=sha1, dbot_score=dbot_score)
    # Add results to message to be sent to the War Room
    message = {
        "status": resp.result_code,
        "id": sandbox_response.id,
        "type": sandbox_response.type,
        "digest": digest.model_dump(),
        "arguments": sandbox_response.arguments,
        "risk_level": risk,
        "threat_types": sandbox_response.threat_types,
        "true_file_type": sandbox_response.true_file_type,
        "detection_names": sandbox_response.detection_names,
        "analysis_completion_date_time": sandbox_response.analysis_completion_date_time,
        "DBotScore": {
            "Score": dbot_score.score,
            "Vendor": dbot_score.integration_name,
            "Reliability": dbot_score.reliability,
        },
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_FILE_ANALYSIS_RESULT_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.File_Analysis_Result",
        outputs_key_field="id",
        outputs=message,
        indicator=file_entry,
    )


def collect_file(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Collect forensic file and sends the result to demist war room
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    collect_files = safe_load_json(args[COLLECT_FILES])
    # Create file task list
    file_tasks: list[CollectFileRequest] = []
    message: list[dict[str, Any]] = []

    # Create file task list
    for file in collect_files:  # type: ignore
        if file.get(ENDPOINT, EMPTY_STRING):
            file_tasks.append(
                CollectFileRequest(
                    endpoint_name=file[ENDPOINT],
                    file_path=file[FILE_PATH],
                    description=file.get(DESCRIPTION, COLLECT_FILE),
                )
            )
        elif file.get(AGENT_GUID, EMPTY_STRING):
            file_tasks.append(
                CollectFileRequest(
                    agent_guid=file[AGENT_GUID],
                    file_path=file[FILE_PATH],
                    description=file.get(DESCRIPTION, COLLECT_FILE),
                )  # type: ignore
            )
    # Make rest call
    resp = v1_client.endpoint.collect_file(*file_tasks)
    file_resp: pytmv1.MultiResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        errs: list[pytmv1.MsError] = resp.errors
        return_error(message=f"{errs}", error=str(errs))

    message = [item.model_dump() for item in file_resp.items]

    return CommandResults(
        readable_output=tableToMarkdown(
            TABLE_COLLECT_FILE,
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Collect_Forensic_File",
        outputs_key_field="task_id",
        outputs=message,
    )


def download_information_collected_file(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Get the analysis report of file based on action id and sends
    the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    task_id = args.get(TASKID, EMPTY_STRING)
    # Optional Params
    poll = argToBoolean(args.get(POLL, TRUE))
    poll_time_sec = arg_to_number(args.get(POLL_TIME_SEC, 0))
    # Make rest call
    resp = v1_client.task.get_result_class(
        task_id=task_id,
        class_=CollectFileTaskResp,
        poll=poll,
        poll_time_sec=poll_time_sec,  # type: ignore
    )
    resp_obj: pytmv1.CollectFileTaskResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    message = resp_obj.model_dump()
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DOWNLOAD_COLLECTED_FILE_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Download_Information_For_Collected_Forensic_File",
        outputs_key_field="resource_location",
        outputs=message,
    )


def download_analysis_report(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> Any | CommandResults:
    """
    Get the analysis report of file based on action id and sends
    the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    submit_id = args.get(SUBMISSION_ID, EMPTY_STRING)
    # Optional Params
    poll = argToBoolean(args.get(POLL, TRUE))
    poll_time_sec = arg_to_number(args.get(POLL_TIME_SEC, 0))

    # Create name for pdf report file to be downloaded
    name = "Trend_Micro_Sandbox_Analysis_Report"
    file_name = f"{name}_{datetime.now(UTC).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.pdf"

    # Make rest call
    resp = v1_client.sandbox.download_analysis_result(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec  # type: ignore
    )
    analysis_resp: pytmv1.BytesResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Extract content value on successful call
    data = analysis_resp.content

    resp_msg = "Please click download to download PDF Report."
    # fileResult takes response data and creates a file with
    # the specified extension that can be downloaded in the war room
    output_file = fileResult(f"{file_name}", data, file_type=EntryType.ENTRY_INFO_FILE)
    message = {
        "submission_id": submit_id,
        "result_code": resp.result_code,
        "message": resp_msg,
    }
    return [
        output_file,
        CommandResults(
            readable_output=tableToMarkdown(
                table_name[DOWNLOAD_ANALYSIS_REPORT_COMMAND],
                message,
                headerTransform=string_to_table_header,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Download_Analysis_Report",
            outputs_key_field="submission_id",
            outputs=message,
        ),
    ]


def download_investigation_package(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> Any | CommandResults:
    """
    Downloads the Investigation Package of the specified object based on
    submission id and sends the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    submit_id = args.get(SUBMISSION_ID, EMPTY_STRING)
    # Optional Params
    poll = argToBoolean(args.get(POLL, TRUE))
    poll_time_sec = arg_to_number(args.get(POLL_TIME_SEC, 0))

    # Create name for zip package to be downloaded
    name = "Sandbox_Investigation_Package"
    file_name = f"{name}_{datetime.now(UTC).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.zip"

    # Make rest call
    resp = v1_client.sandbox.download_investigation_package(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec  # type: ignore
    )
    investigation_resp: pytmv1.BytesResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Extract content value on successful call
    data = investigation_resp.content

    # fileResult takes response data and creates a file with
    # the specified extension that can be downloaded in the war room
    output_file = fileResult(f"{file_name}", data, file_type=EntryType.ENTRY_INFO_FILE)
    resp_msg = "Please click download to download .zip file."
    message = {
        "submission_id": submit_id,
        "result_code": resp.result_code,
        "message": resp_msg,
    }

    return [
        output_file,
        CommandResults(
            readable_output=tableToMarkdown(
                table_name[DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND],
                message,
                headerTransform=string_to_table_header,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Download_Investigation_Package",
            outputs_key_field="submission_id",
            outputs=message,
        ),
    ]


def download_suspicious_object_list(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Downloads the suspicious object list associated to the specified object
    Note: Suspicious Object lists are only available for objects with a high risk level
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    submit_id = args.get(SUBMISSION_ID, EMPTY_STRING)
    # Optional Params
    poll = argToBoolean(args.get(POLL, TRUE))
    poll_time_sec = arg_to_number(args.get(POLL_TIME_SEC, 0))
    suspicious_objects: list[dict[str, str]] = []

    # Make rest call
    resp = v1_client.sandbox.list_suspicious(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec  # type: ignore
    )
    sus_list_resp: pytmv1.ListSandboxSuspiciousResp = unwrap(resp.response)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Extract suspicious objects from response
    for item in sus_list_resp.items:
        suspicious_objects.append(item.model_dump())

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND],
            suspicious_objects,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Download_Suspicious_Object_list",
        outputs_key_field="risk_level",
        outputs=suspicious_objects,
    )


def submit_file_to_sandbox(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    submit file to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    file_url = args.get(FILE_URL, EMPTY_STRING)
    file_name = args.get("file_name", EMPTY_STRING)
    # Optional Params
    document_pass = args.get(DOCUMENT_PASSWORD, EMPTY_STRING)
    archive_pass = args.get(ARCHIVE_PASSWORD, EMPTY_STRING)
    arguments = args.get(ARGUMENTS, EMPTY_STRING)

    # Get file contents
    _file = requests.get(file_url, allow_redirects=True, timeout=30)
    # Make rest call
    resp = v1_client.sandbox.submit_file(
        file=_file.content,
        file_name=file_name,
        document_password=document_pass,
        archive_password=archive_pass,
        arguments=arguments,
    )
    sub_file_resp: pytmv1.SubmitFileToSandboxResp = unwrap(resp.response)
    digest: pytmv1.Digest = unwrap(sub_file_resp.digest)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    message = {
        "code": 202,
        "message": resp.result_code,
        "task_id": sub_file_resp.id,
        "digest": digest.model_dump(),
        "arguments": sub_file_resp.arguments,
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FILE_TO_SANDBOX_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Submit_File_to_Sandbox",
        outputs_key_field="task_id",
        outputs=message,
    )


def submit_file_entry_to_sandbox(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    submit file entry to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    entry = args.get(ENTRY_ID, EMPTY_STRING)
    # Optional Params
    archive_pass = args.get(ARCHIVE_PASSWORD, EMPTY_STRING)
    document_pass = args.get(DOCUMENT_PASSWORD, EMPTY_STRING)
    arguments = args.get(ARGUMENTS, EMPTY_STRING)

    # Use entry ID to get file details from demisto
    file_ = demisto.getFilePath(entry)
    file_name = file_.get(NAME, EMPTY_STRING)
    file_path = file_.get(PATH, EMPTY_STRING)
    with open(file_path, "rb") as f:
        contents = f.read()
    # Make rest call
    resp = v1_client.sandbox.submit_file(
        file=contents,
        file_name=file_name,
        document_password=document_pass,
        archive_password=archive_pass,
        arguments=arguments,
    )
    sub_file_resp: pytmv1.SubmitFileToSandboxResp = unwrap(resp.response)
    digest: pytmv1.Digest = unwrap(sub_file_resp.digest)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    message = {
        "code": 202,
        "message": resp.result_code,
        "filename": file_name,
        "entry_id": entry,
        "file_path": file_path,
        "task_id": sub_file_resp.id,
        "digest": digest.model_dump(),
        "arguments": sub_file_resp.arguments,
    }

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FILE_ENTRY_TO_SANDBOX_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Submit_File_Entry_to_Sandbox",
        outputs_key_field="entry_id",
        outputs=message,
    )


def submit_urls_to_sandbox(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    submit Urls to sandbox and send the result to demist war room
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    urls: list[str] = argToList(args[URLS])
    submit_urls_resp: list[dict[str, Any]] = []
    # Make rest call
    resp = v1_client.sandbox.submit_url(*urls)
    urls_resp: pytmv1.MultiUrlResp = unwrap(resp.response)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        errs: list[pytmv1.MsError] = unwrap(resp.errors)
        return_error(message=f"{errs}", error=str(errs))
    for item in urls_resp.items:
        submit_urls_resp.append(item.model_dump())

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[URLS_TO_SANDBOX_COMMAND],
            submit_urls_resp,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Submit_Urls_to_Sandbox",
        outputs_key_field="id",
        outputs=submit_urls_resp,
    )


def get_alert_details(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Fetch information for a specific alert and display in war room.
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id: str = args.get(WORKBENCH_ID, EMPTY_STRING)
    message: dict[str, Any] = {}
    # Make rest call
    resp = v1_client.alert.get(alert_id=workbench_id)
    alert_resp: pytmv1.GetAlertResp = unwrap(resp.response)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Extract values from response
    etag = alert_resp.etag
    alert = alert_resp.data.model_dump()
    # Add results to message to be sent to the War Room
    message = {"etag": etag, "alert": alert}

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ALERT_DETAILS_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Alert_Details",
        outputs_key_field="etag",
        outputs=message,
    )


def add_note(v1_client: pytmv1.Client, args: dict[str, Any]) -> str | CommandResults:
    """
    Adds a note to an existing workbench alert
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id = args.get(WORKBENCH_ID, EMPTY_STRING)
    content = args.get(CONTENT, EMPTY_STRING)
    message: dict[str, Any] = {}

    # Make rest call
    resp = v1_client.note.create(alert_id=workbench_id, note_content=content)
    note_resp: pytmv1.AddAlertNoteResp = unwrap(resp.response)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    message = {
        "code": 201,
        "message": f"Note has been successfully added to {workbench_id}",
        "note_id": note_resp.note_id,
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[ADD_NOTE_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Add_Note",
        outputs_key_field="note_id",
        outputs=message,
    )


def update_status(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Updates the status of an existing workbench alert
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id = args.get(WORKBENCH_ID, EMPTY_STRING)
    status = args.get(STATUS, EMPTY_STRING)
    if_match = args.get(IF_MATCH, EMPTY_STRING)
    inv_res = args.get(INV_RESULT, EMPTY_STRING)
    message: dict[str, Any] = {}
    # Assign enum status
    sts = AlertStatus[status.upper()]
    inv_result = InvestigationResult[inv_res.upper()]
    # Make rest call
    resp = v1_client.alert.update_status(
        alert_id=workbench_id,
        status=sts,
        etag=if_match,
        inv_result=inv_result,
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    # Add results to message to be sent to the War Room
    message = {
        "code": 204,
        "Workbench_Id": workbench_id,
        "message": f"Successfully updated status for {workbench_id} to {status}.",
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[UPDATE_STATUS_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Update_Status",
        outputs_key_field="Workbench_Id",
        outputs=message,
    )


def run_custom_script(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Runs custom script using endpoint (hostname) or agent_guid
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects = safe_load_json(args[BLOCK_OBJECTS])
    script_tasks: list[CustomScriptRequest] = []
    message: list[dict[str, Any]] = []
    # Create custom script task list
    for script in block_objects:  # type: ignore
        if script.get(ENDPOINT, EMPTY_STRING):
            script_tasks.append(
                CustomScriptRequest(
                    file_name=script[FILE_NAME],
                    endpoint_name=script[ENDPOINT],
                    parameter=script.get(PARAMETER, EMPTY_STRING),
                    description=script.get(DESCRIPTION, RUN_CUSTOM_SCRIPT),
                )
            )
        elif script.get(AGENT_GUID, EMPTY_STRING):
            script_tasks.append(
                CustomScriptRequest(
                    file_name=script[FILE_NAME],
                    agent_guid=script[AGENT_GUID],
                    parameter=script.get(PARAMETER, EMPTY_STRING),
                    description=script.get(DESCRIPTION, RUN_CUSTOM_SCRIPT),
                )
            )
    # Make rest call
    resp = v1_client.script.run(*script_tasks)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        errs: list[pytmv1.MsError] = unwrap(resp.errors)
        return_error(message=f"{errs}", error=str(errs))
    script_resp: pytmv1.MultiResp = unwrap(resp.response)
    # Add results to message to be sent to the War Room
    message = [item.model_dump() for item in script_resp.items]
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[RUN_CUSTOM_SCRIPT_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Run_Custom_Script",
        outputs_key_field="task_id",
        outputs=message,
    )


def get_custom_script_list(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Fetches a list of custom scripts in Response Management under Custom Script tab
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Optional Params
    filename = args.get(FILE_NAME, EMPTY_STRING)
    filetype = args.get(FILE_TYPE, EMPTY_STRING)
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    fields: dict[str, str] = {}
    if filename and filetype:
        fields = {"fileName": filename, "fileType": filetype}
    elif filename:
        fields = {"fileName": filename}
    elif filetype:
        fields = {"fileType": filetype}
    # response contents for war room will be stored here
    message: list[dict[str, Any]] = []
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    else:
        query_op = pytmv1.QueryOp.AND
    # Make rest call
    resp = v1_client.script.list(op=query_op, **fields)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    script_resp: pytmv1.ListCustomScriptsResp = unwrap(resp.response)
    # Add results to message to be sent to the War Room
    for item in script_resp.items:
        message.append(
            {
                "id": item.id,
                "filename": item.file_name,
                "filetype": item.file_type.value,
                "description": item.description,
            }
        )
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_CUSTOM_SCRIPT_LIST_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Get_Custom_Script_List",
        outputs_key_field="id",
        outputs=message,
    )


def add_custom_script(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Adds a custom script to Response Management under Custom Script tab
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    filename = args.get(FILE_NAME, EMPTY_STRING)
    filetype = args.get(FILE_TYPE, EMPTY_STRING)
    description = args.get(DESCRIPTION, ADD_CUSTOM_SCRIPT)
    script_contents = args.get(SCRIPT_CONTENTS, EMPTY_STRING)
    # Assign the file type enum
    if filetype.lower() == "bash":
        filetype = pytmv1.ScriptType.BASH
    elif filetype.lower() == "powershell":
        filetype = pytmv1.ScriptType.POWERSHELL
    # Make rest call
    resp = v1_client.script.create(
        script_type=filetype,
        script_name=filename,
        script_content=script_contents,
        description=description,
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    script_resp: pytmv1.AddCustomScriptResp = unwrap(resp.response)
    id: str = script_resp.script_id
    # Add results to message to be sent to the War Room
    message: dict[str, str] = {"id": id}
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[ADD_CUSTOM_SCRIPT_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Add_Custom_Script",
        outputs_key_field="id",
        outputs=message,
    )


def download_custom_script(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Download a custom script from Response Management under Custom Script tab
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    script_id = args.get(SCRIPT_ID, EMPTY_STRING)
    # Make rest call
    resp = v1_client.script.download(script_id=script_id)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        demisto.results(
            f"The script was not found. Please check script id: {script_id} and try again."
        )
        return_error(message=f"{err.message}", error=str(err))
    resp_text: pytmv1.TextResp = unwrap(resp.response)
    text: str = resp_text.text
    # Add results to message to be sent to the War Room
    message: dict[str, str] = {"text": text}
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DOWNLOAD_CUSTOM_SCRIPT_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Download_Custom_Script",
        outputs_key_field="text",
        outputs=message,
    )


def update_custom_script(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Updates a custom script in Response Management under Custom Script tab
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    filetype = args.get(FILE_TYPE, EMPTY_STRING)
    filename = args.get(FILE_NAME, EMPTY_STRING)
    script_id = args.get(SCRIPT_ID, EMPTY_STRING)
    description = args.get(DESCRIPTION, UPDATE_CUSTOM_SCRIPT)
    script_contents = args.get(SCRIPT_CONTENTS, EMPTY_STRING)
    # Assign the file type enum
    if filetype.lower() == "bash":
        filetype = pytmv1.ScriptType.BASH
    elif filetype.lower() == "powershell":
        filetype = pytmv1.ScriptType.POWERSHELL
    # Make rest call
    resp = v1_client.script.update(
        script_name=filename,
        script_type=filetype,
        description=description,
        script_content=script_contents,
        script_id=script_id,
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        return_error(message=f"{err.message}", error=str(err))
    resp_code: ResultCode = unwrap(resp.result_code)
    val: str = resp_code.value
    # Add results to message to be sent to the War Room
    message: dict[str, str] = {"status": val}
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[UPDATE_CUSTOM_SCRIPT_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Update_Custom_Script",
        outputs_key_field="status",
        outputs=message,
    )


def delete_custom_script(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Delete a custom script from Response Management under Custom Script tab
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    script_id = args.get(SCRIPT_ID, EMPTY_STRING)
    # Make rest call
    resp = v1_client.script.delete(script_id=script_id)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        demisto.results(
            f"The script was not found. Please check script id: {script_id} and try again."
        )
        return_error(message=f"{err.message}", error=str(err))
    resp_code: ResultCode = unwrap(resp.result_code)
    val: str = resp_code.value
    # Add results to message to be sent to the War Room
    message: dict[str, str] = {"status": val}
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DELETE_CUSTOM_SCRIPT_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Delete_Custom_Script",
        outputs_key_field="status",
        outputs=message,
    )


def get_observed_attack_techniques(
    v1_client: pytmv1.Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Displays a list of Observed Attack Techniques events that match the specified criteria
    :type client: ``Client``
    :param v1_client: pytmv1.Client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required params
    fields = json.loads(args.get(FIELDS, EMPTY_STRING))
    # Optional params
    top = args.get(TOP, EMPTY_STRING)
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    detected_end_time = args.get(DETECTED_END, EMPTY_STRING)
    ingested_end_time = args.get(INGESTED_END, EMPTY_STRING)
    detected_start_time = args.get(DETECTED_START, EMPTY_STRING)
    ingested_start_time = args.get(INGESTED_START, EMPTY_STRING)
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    else:
        query_op = pytmv1.QueryOp.AND
    # Make rest call
    resp = v1_client.oat.list(
        detected_start_date_time=detected_start_time,
        detected_end_date_time=detected_end_time,
        ingested_start_date_time=ingested_start_time,
        ingested_end_date_time=ingested_end_time,
        top=top,
        op=query_op,
        **fields,
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        err: pytmv1.Error = unwrap(resp.error)
        raise Exception(f"{err.message}", str(err))
    resp_type: pytmv1.ListOatsResp = unwrap(resp.response)
    if resp_type.total_count > 50:
        raise Exception(
            "Please refine search, this query returns more than 50 results."
        )

    # Add results to message to be sent to the War Room
    message: list[dict[str, Any]] = []
    for item in resp_type.items:
        _detail = item.detail.model_dump()
        _filters = [item.model_dump() for item in item.filters]
        _endpoint = item.endpoint.model_dump() if item.endpoint is not None else ""
        message.append(
            {
                "id": item.uuid,
                "source": item.source,
                "detail": _detail,
                "filters": _filters,
                "endpoint": _endpoint,
                "entity_name": item.entity_name,
                "entity_type": item.entity_type,
                "detected_date_time": item.detected_date_time,
                "ingested_date_time": item.ingested_date_time,
            }
        )
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_OBSERVED_ATTACK_TECHNIQUES_COMMAND],
            message,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Get_Observed_Attack_Techniques",
        outputs_key_field="id",
        outputs=message,
    )


def main():  # pragma: no cover
    try:
        """GLOBAL VARS"""
        params = demisto.params()

        base_url: str = params.get(URL, "")
        api_key: str = params.get(API_TOKEN, {}).get("password")

        if base_url == "":
            raise RuntimeError(
                "The base_url cannot be empty, please provide a valid value."
            )
        v1_client = _get_client(VENDOR_NAME, api_key, base_url)

        command = demisto.command()
        demisto.debug(COMMAND_CALLED.format(command=command))
        args = demisto.args()

        if command == TEST_MODULE:
            return_results(test_module(v1_client))

        elif command == FETCH_INCIDENTS:
            return_results(fetch_incidents(v1_client))

        elif command in (ENABLE_USER_ACCOUNT_COMMAND, DISABLE_USER_ACCOUNT_COMMAND):
            return_results(enable_or_disable_user_account(v1_client, command, args))

        elif command == FORCE_SIGN_OUT_COMMAND:
            return_results(force_sign_out(v1_client, args))

        elif command == FORCE_PASSWORD_RESET_COMMAND:
            return_results(force_password_reset(v1_client, args))

        elif command in (ADD_BLOCKLIST_COMMAND, REMOVE_BLOCKLIST_COMMAND):
            return_results(add_or_remove_from_block_list(v1_client, command, args))

        elif command in (QUARANTINE_EMAIL_COMMAND, DELETE_EMAIL_COMMAND):
            return_results(quarantine_or_delete_email_message(v1_client, command, args))

        elif command == RESTORE_EMAIL_COMMAND:
            return_results(restore_email_message(v1_client, args))

        elif command in (ISOLATE_ENDPOINT_COMMAND, RESTORE_ENDPOINT_COMMAND):
            return_results(isolate_or_restore_connection(v1_client, command, args))

        elif command == TERMINATE_PROCESS_COMMAND:
            return_results(terminate_process(v1_client, args))

        elif command in (ADD_EXCEPTION_LIST_COMMAND, DELETE_EXCEPTION_LIST_COMMAND):
            return_results(add_or_delete_from_exception_list(v1_client, command, args))

        elif command == ADD_SUSPICIOUS_LIST_COMMAND:
            return_results(add_to_suspicious_list(v1_client, args))

        elif command == DELETE_SUSPICIOUS_LIST_COMMAND:
            return_results(delete_from_suspicious_list(v1_client, args))

        elif command == GET_FILE_ANALYSIS_STATUS_COMMAND:
            return_results(get_file_analysis_status(v1_client, args))

        elif command == GET_FILE_ANALYSIS_RESULT_COMMAND:
            return_results(get_file_analysis_result(v1_client, args))

        elif command == GET_ENDPOINT_INFO_COMMAND:
            return_results(get_endpoint_info(v1_client, args))

        elif command == GET_ENDPOINT_ACTIVITY_DATA_COMMAND:
            return_results(get_endpoint_activity_data(v1_client, args))

        elif command == GET_ENDPOINT_ACTIVITY_DATA_COUNT_COMMAND:
            return_results(get_endpoint_activity_data_count(v1_client, args))

        elif command == GET_EMAIL_ACTIVITY_DATA_COMMAND:
            return_results(get_email_activity_data(v1_client, args))

        elif command == GET_EMAIL_ACTIVITY_DATA_COUNT_COMMAND:
            return_results(get_email_activity_data_count(v1_client, args))

        elif command == COLLECT_FILE_COMMAND:
            return_results(collect_file(v1_client, args))

        elif command == DOWNLOAD_COLLECTED_FILE_COMMAND:
            return_results(download_information_collected_file(v1_client, args))

        elif command == FILE_TO_SANDBOX_COMMAND:
            return_results(submit_file_to_sandbox(v1_client, args))

        elif command == FILE_ENTRY_TO_SANDBOX_COMMAND:
            return_results(submit_file_entry_to_sandbox(v1_client, args))

        elif command == URLS_TO_SANDBOX_COMMAND:
            return_results(submit_urls_to_sandbox(v1_client, args))

        elif command == SANDBOX_SUBMISSION_POLLING_COMMAND:
            if args.get(POLLING) == TRUE:
                cmd_res = get_sandbox_submission_status(args, v1_client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(sandbox_submission_polling(v1_client, args))

        elif command == DOWNLOAD_ANALYSIS_REPORT_COMMAND:
            return_results(download_analysis_report(v1_client, args))

        elif command == DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND:
            return_results(download_investigation_package(v1_client, args))

        elif command == DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND:
            return_results(download_suspicious_object_list(v1_client, args))

        elif command == UPDATE_STATUS_COMMAND:
            return_results(update_status(v1_client, args))

        elif command == GET_ALERT_DETAILS_COMMAND:
            return_results(get_alert_details(v1_client, args))

        elif command == ADD_NOTE_COMMAND:
            return_results(add_note(v1_client, args))

        elif command == RUN_CUSTOM_SCRIPT_COMMAND:
            return_results(run_custom_script(v1_client, args))

        elif command == GET_CUSTOM_SCRIPT_LIST_COMMAND:
            return_results(get_custom_script_list(v1_client, args))

        elif command == ADD_CUSTOM_SCRIPT_COMMAND:
            return_results(add_custom_script(v1_client, args))

        elif command == UPDATE_CUSTOM_SCRIPT_COMMAND:
            return_results(update_custom_script(v1_client, args))

        elif command == DOWNLOAD_CUSTOM_SCRIPT_COMMAND:
            return_results(download_custom_script(v1_client, args))

        elif command == DELETE_CUSTOM_SCRIPT_COMMAND:
            return_results(delete_custom_script(v1_client, args))

        elif command == CHECK_TASK_STATUS_COMMAND:
            if args.get(POLLING) == TRUE:
                cmd_res = get_task_status(args, v1_client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(status_check(v1_client, args))

        elif command == GET_OBSERVED_ATTACK_TECHNIQUES_COMMAND:
            return_results(get_observed_attack_techniques(v1_client, args))

        else:
            demisto.error(f"{command} command is not implemented.")
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as error:
        return return_error(
            f"Failed to execute {demisto.command()} command. Error: {str(error)}"
        )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
