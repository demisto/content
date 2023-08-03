import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""IMPORTS"""
from CommonServerUserPython import *  # noqa: F401

import json
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, TypeVar, Union

# from requests.models import HTTPError
import pytmv1
from pytmv1 import (
    ExceptionObject,
    InvestigationStatus,
    MsData,
    ObjectType,
    ResultCode,
    SaeAlert,
    SuspiciousObject,
    TiAlert,
)

"""CONSTANTS"""
USER_AGENT = "TMV1CortexXSOARApp/1.1"
VENDOR_NAME = "TrendMicroVisionOneV3"
BLOCK = "block"
MEDIUM = "medium"
URL = "url"
POST = "post"
GET = "get"
PATCH = "patch"
IF_MATCH = "if_match"
FALSE = False
TRUE = "true"
POLL = "poll"
POLL_TIME_SEC = "poll_time_sec"
POLLING = "polling"
ARGUMENTS = "arguments"
ACCOUNT_NAME = "account_name"
AUTHORIZATION = "Authorization"
BEARER = "Bearer "
CONTENT_TYPE_JSON = "application/json"
EMPTY_STRING = ""
ASCII = "ascii"
API_TOKEN = "apikey"
VALUE_TYPE = "value_type"
TARGET_VALUE = "target_value"
DESCRIPTION = "description"
MESSAGE_ID = "message_id"
MAILBOX = "mail_box"
FIELD = "field"
ENDPOINT = "endpoint"
QUERY_OP = "query_op"
ENTRY_ID = "entry_id"
DATA = "data"
TYPE = "type"
VALUE = "value"
FILE_SHA = "file_sha1"
FILENAME = "filename"
CRITERIA = "criteria"
EXCEPTION_LIST = "exceptionList"
SUSPICIOUS_LIST = "suspiciousObjectList"
LAST_MODIFIED = "lastModified"
SCAN_ACTION = "scan_action"
RISK_LEVEL = "risk_level"
EXPIRY_DAYS = "expiry_days"
TASKID = "task_id"
REPORT_ID = "report_id"
FAILED = "failed"
OBJECT_TYPE = "object_type"
OBJECT_VALUE = "object_value"
PROCESSING = "processing"
QUEUED = "queued"
RUNNING = "running"
WAITFORAPPROVAL = "waitForApproval"
OS_TYPE = "os"
FILEPATH = "filepath"
FILE_PATH = "file_path"
FILE_NAME = "filename"
DOCUMENT_PASSWORD = "document_password"
ARCHIVE_PASSWORD = "archive_password"
WORKBENCH_ID = "workbench_id"
CONTENT = "content"
STATUS = "status"
SUBMISSION_ID = "submission_id"
UNIQUE_ID = "unique_id"
# End Points
ENABLE_USER_ACCOUNT = "/v3.0/response/domainAccounts/enable"
DISABLE_USER_ACCOUNT = "/v3.0/response/domainAccounts/disable"
FORCE_SIGN_OUT = "/v3.0/response/domainAccounts/signOut"
FORCE_PASSWORD_RESET = "/v3.0/response/domainAccounts/resetPassword"
ADD_BLOCKLIST_ENDPOINT = "/v3.0/response/suspiciousObjects"
REMOVE_BLOCKLIST_ENDPOINT = "/v3.0/response/suspiciousObjects/delete"
QUARANTINE_EMAIL_ENDPOINT = "/v3.0/response/emails/quarantine"
DELETE_EMAIL_ENDPOINT = "/v3.0/response/emails/delete"
ISOLATE_CONNECTION_ENDPOINT = "/v3.0/response/endpoints/isolate"
TERMINATE_PROCESS_ENDPOINT = "/v3.0/response/endpoints/terminateProcess"
RESTORE_CONNECTION_ENDPOINT = "/v3.0/response/endpoints/restore"
ADD_OBJECT_TO_EXCEPTION_LIST = "/v3.0/threatintel/suspiciousObjectExceptions"
DELETE_OBJECT_FROM_EXCEPTION_LIST = (
    "/v3.0/threatintel/suspiciousObjectExceptions/delete"
)
ADD_OBJECT_TO_SUSPICIOUS_LIST = "/v3.0/threatintel/suspiciousObjects"
DELETE_OBJECT_FROM_SUSPICIOUS_LIST = "/v3.0/threatintel/suspiciousObjects/delete"
TASK_DETAIL_ENDPOINT = "/v3.0/response/tasks/{taskId}"
GET_ENDPOINT_INFO_ENDPOINT = "/v3.0/eiqs/endpoints"
GET_FILE_STATUS = "/v3.0/sandbox/tasks/{taskId}"
GET_FILE_RESULT = "/v3.0/sandbox/analysisResults/{reportId}"
ADD_NOTE_ENDPOINT = "/v3.0/workbench/alerts/{alertId}/notes"
UPDATE_STATUS_ENDPOINT = "/v3.0/workbench/alerts/{workbenchId}"
COLLECT_FORENSIC_FILE = "/v3.0/response/endpoints/collectFile"
DOWNLOAD_INFORMATION_COLLECTED_FILE = "/v3.0/response/tasks/{taskId}"
SUBMIT_FILE_TO_SANDBOX = "/v3.0/sandbox/files/analyze"
DOWNLOAD_ANALYSIS_REPORT = "/v3.0/sandbox/analysisResults/{submissionId}/report"
DOWNLOAD_INVESTIGATION_PACKAGE = (
    "/v3.0/sandbox/analysisResults/{submissionId}/investigationPackage"
)
DOWNLOAD_SUSPICIOUS_OBJECT_LIST = (
    "/v3.0/sandbox/analysisResults/{submissionId}/suspiciousObjects"
)
WORKBENCH_HISTORIES = "/v3.0/workbench/alerts"
# Error Messages
RESPONSE_ERROR = "Error in API call: [%d] - %s"
RETRY_ERROR = "The max tries exceeded [%d] - %s"
COMMAND_CALLED = "Command being called is {command}"
COMMAND_EXECUTION_ERROR = "Failed to execute {error} command. Error"
AUTHORIZATION_ERROR = (
    "Authorization Error: make sure URL/API Key is correctly set. Error - {error}"
)
PARAMETER_ISSUE = "{param} is not a valid parameter. Kindly provide valid parameter"
FILE_NOT_FOUND = "No such file present in {filepath}"
# General Messages:
RAW_RESPONSE = "The raw response data - {raw_response}"
SUCCESS_RESPONSE = "success with url {url} and response status {status}"
EXCEPTION_MESSAGE = "Successfully {task} object to exception list with response {code}, Total items in exception list - {length}"
SUCCESS_TEST = "Successfully connected to the vision one API."
POLLING_MESSAGE = "The task has not completed, will check status again in 30 seconds"
# Workbench Statuses
NEW = "New"
IN_PROGRESS = "In Progress"
RESOLVED_TRUE_POSITIVE = "True Positive"
RESOLVED_FALSE_POSITIVE = "False Positive"
# Table Heading
TABLE_ENABLE_USER_ACCOUNT = "Enable user account "
TABLE_DISABLE_USER_ACCOUNT = "Disable user account "
TABLE_FORCE_SIGN_OUT = "Force sign out "
TABLE_FORCE_PASSWORD_RESET = "Force password reset "
TABLE_ADD_TO_BLOCKLIST = "Add to block list "
TABLE_REMOVE_FROM_BLOCKLIST = "Remove from block list "
TABLE_QUARANTINE_EMAIL_MESSAGE = "Quarantine email message "
TABLE_DELETE_EMAIL_MESSAGE = "Delete email message "
TABLE_ISOLATE_ENDPOINT_MESSAGE = "Isolate endpoint connection "
TABLE_RESTORE_ENDPOINT_MESSAGE = "Restore endpoint connection "
TABLE_TERMINATE_PROCESS = "Terminate process "
TABLE_ADD_EXCEPTION_LIST = "Add object to exception list "
TABLE_DELETE_EXCEPTION_LIST = "Delete object from exception list "
TABLE_ADD_SUSPICIOUS_LIST = "Add object to suspicious list "
TABLE_DELETE_SUSPICIOUS_LIST = "Delete object from suspicious list "
TABLE_ENDPOINT_INFO = "Endpoint info "
TABLE_GET_FILE_ANALYSIS_STATUS = "File analysis status "
TABLE_GET_FILE_ANALYSIS_RESULT = "File analysis result "
TABLE_COLLECT_FILE = "Collect forensic file "
TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION = (
    "The download information for collected forensic file "
)
TABLE_SUBMIT_FILE_TO_SANDBOX = "Submit file to sandbox "
TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX = "Submit file entry to sandbox "
TABLE_SANDBOX_SUBMISSION_POLLING = "Sandbox submission polling status "
TABLE_CHECK_TASK_STATUS = "Check task status "
TABLE_DOWNLOAD_ANALYSIS_REPORT = "Download analysis report "
TABLE_DOWNLOAD_INVESTIGATION_PACKAGE = "Download investigation package "
TABLE_DOWNLOAD_SUSPICIOUS_OBJECT_LIST = "Download suspicious object list "
TABLE_ADD_NOTE = "Add note to workbench alert "
TABLE_UPDATE_STATUS = "Update workbench alert status "
# COMMAND NAMES
ENABLE_USER_ACCOUNT_COMMAND = "trendmicro-visionone-enable-user-account"
DISABLE_USER_ACCOUNT_COMMAND = "trendmicro-visionone-disable-user-account"
FORCE_SIGN_OUT_COMMAND = "trendmicro-visionone-force-signout"
FORCE_PASSWORD_RESET_COMMAND = "trendmicro-visionone-force-password-reset"
ADD_BLOCKLIST_COMMAND = "trendmicro-visionone-add-to-block-list"
REMOVE_BLOCKLIST_COMMAND = "trendmicro-visionone-remove-from-block-list"
QUARANTINE_EMAIL_COMMAND = "trendmicro-visionone-quarantine-email-message"
DELETE_EMAIL_COMMAND = "trendmicro-visionone-delete-email-message"
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
SANDBOX_SUBMISSION_POLLING_COMMAND = (
    "trendmicro-visionone-run-sandbox-submission-polling"
)
CHECK_TASK_STATUS_COMMAND = "trendmicro-visionone-check-task-status"
GET_ENDPOINT_INFO_COMMAND = "trendmicro-visionone-get-endpoint-info"
UPDATE_STATUS_COMMAND = "trendmicro-visionone-update-status"
ADD_NOTE_COMMAND = "trendmicro-visionone-add-note"
FETCH_INCIDENTS = "fetch-incidents"
TEST_MODULE = "test-module"

table_name = {
    ENABLE_USER_ACCOUNT_COMMAND: TABLE_ENABLE_USER_ACCOUNT,
    DISABLE_USER_ACCOUNT_COMMAND: TABLE_DISABLE_USER_ACCOUNT,
    FORCE_SIGN_OUT_COMMAND: TABLE_FORCE_SIGN_OUT,
    FORCE_PASSWORD_RESET_COMMAND: TABLE_FORCE_PASSWORD_RESET,
    ADD_BLOCKLIST_COMMAND: TABLE_ADD_TO_BLOCKLIST,
    REMOVE_BLOCKLIST_COMMAND: TABLE_REMOVE_FROM_BLOCKLIST,
    QUARANTINE_EMAIL_COMMAND: TABLE_QUARANTINE_EMAIL_MESSAGE,
    DELETE_EMAIL_COMMAND: TABLE_DELETE_EMAIL_MESSAGE,
    ISOLATE_ENDPOINT_COMMAND: TABLE_ISOLATE_ENDPOINT_MESSAGE,
    RESTORE_ENDPOINT_COMMAND: TABLE_RESTORE_ENDPOINT_MESSAGE,
    TERMINATE_PROCESS_COMMAND: TABLE_TERMINATE_PROCESS,
    ADD_EXCEPTION_LIST_COMMAND: TABLE_ADD_EXCEPTION_LIST,
    DELETE_EXCEPTION_LIST_COMMAND: TABLE_DELETE_EXCEPTION_LIST,
    ADD_SUSPICIOUS_LIST_COMMAND: TABLE_ADD_SUSPICIOUS_LIST,
    DELETE_SUSPICIOUS_LIST_COMMAND: TABLE_DELETE_SUSPICIOUS_LIST,
    GET_FILE_ANALYSIS_STATUS_COMMAND: TABLE_GET_FILE_ANALYSIS_STATUS,
    GET_FILE_ANALYSIS_RESULT_COMMAND: TABLE_GET_FILE_ANALYSIS_RESULT,
    COLLECT_FILE_COMMAND: TABLE_COLLECT_FILE,
    DOWNLOAD_COLLECTED_FILE_COMMAND: TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION,
    DOWNLOAD_ANALYSIS_REPORT_COMMAND: TABLE_DOWNLOAD_ANALYSIS_REPORT,
    DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND: TABLE_DOWNLOAD_INVESTIGATION_PACKAGE,
    DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND: TABLE_DOWNLOAD_SUSPICIOUS_OBJECT_LIST,
    FILE_TO_SANDBOX_COMMAND: TABLE_SUBMIT_FILE_TO_SANDBOX,
    FILE_ENTRY_TO_SANDBOX_COMMAND: TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX,
    SANDBOX_SUBMISSION_POLLING_COMMAND: TABLE_SANDBOX_SUBMISSION_POLLING,
    CHECK_TASK_STATUS_COMMAND: TABLE_CHECK_TASK_STATUS,
    GET_ENDPOINT_INFO_COMMAND: TABLE_ENDPOINT_INFO,
    UPDATE_STATUS_COMMAND: TABLE_UPDATE_STATUS,
    ADD_NOTE_COMMAND: TABLE_ADD_NOTE,
}
# disable insecure warnings
urllib3.disable_warnings()

_T = TypeVar("_T")


def unwrap(val: _T | None) -> _T:
    if val is None:
        raise ValueError("Expected non-null value but received None.")
    return val


def check_datetime_aware(d):
    return (d.tzinfo is not None) and (d.tzinfo.utcoffset(d) is not None)


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, proxy: bool, verify: bool) -> None:
        """
        Inherit the BaseClient class from the demistomock.
        :type base_url: ``str``
        :param base_url: Base server address with suffix, for example: https://example.com/api/v2/.
        :type api_key: ``str``
        :param api_key: api token to access the api data.
        :type proxy: ``bool``
        :param proxy: Whether the request should use the system proxy settings.
        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.
        :return: returns None
        :rtype: ``None``
        """
        self.base_url = base_url
        self.api_key = api_key
        self.status = None
        self.app = "Trend Micro Vision One V3"

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def status_check(self, v1_client: pytmv1.Client, data: Dict[str, Any]) -> Any:
        """
        Check the status of particular task.
        :type data: ``dict``
        :param method: Response data to received from the end point.
        :return: task status response data.
        :rtype: ``Any``
        """
        task_id = data.get(TASKID, EMPTY_STRING)
        poll = data.get(POLL, FALSE)
        poll_time_sec = data.get(POLL_TIME_SEC, 0)
        message: dict[str, Any] = {}
        # Make rest call
        resp = v1_client.get_base_task_result(task_id, poll, poll_time_sec)
        # Check if error response is returned
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[CHECK_TASK_STATUS_COMMAND], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Task_Status",
                outputs_key_field="error",
                outputs=err,
            )
        # Assign values on a successful call
        else:
            message = {
                "taskId": unwrap(resp.response).id,
                "taskStatus": unwrap(resp.response).status,
                "createdDateTime": unwrap(resp.response).created_date_time,
                "action": unwrap(resp.response).action,
                "description": unwrap(resp.response).description,
                "account": unwrap(resp.response).account,
            }
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[CHECK_TASK_STATUS_COMMAND], message, removeNull=True
            ),
            outputs_prefix="VisionOne.Task_Status",
            outputs_key_field="taskId",
            outputs=message,
        )

    def sandbox_submission_polling(
        self, v1_client: pytmv1.Client, data: Dict[str, Any]
    ) -> Any:
        """
        Check the status of sandbox submission
        :type data: ``dict``
        :param method: Response data received from sandbox.
        :return: Sandbox submission response data.
        :rtype: ``Any``
        """
        task_id = data.get(TASKID, EMPTY_STRING)
        resp = v1_client.get_sandbox_submission_status(submit_id=task_id)
        # Check if error response is returned
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[SANDBOX_SUBMISSION_POLLING_COMMAND], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Sandbox_Submission_Polling",
                outputs_key_field="error",
                outputs=err,
            )
        # Get the task status of rest call
        else:
            task_status = unwrap(resp.response).status

        file_entry = None
        if task_status.lower() == "succeeded":
            resp = v1_client.get_sandbox_analysis_result(submit_id=task_id)
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[SANDBOX_SUBMISSION_POLLING_COMMAND],
                        err,
                        removeNull=True,
                    ),
                    outputs_prefix="VisionOne.Sandbox_Submission_Polling",
                    outputs_key_field="error",
                    outputs=err,
                )
            else:
                risk = unwrap(resp.response).risk_level
                risk_score = incident_severity_to_dbot_score(risk)
                digest = unwrap(resp.response).digest
                sha256 = unwrap(digest).sha256
                md5 = unwrap(digest).md5
                sha1 = unwrap(digest).sha1
                reliability = demisto.params().get("integrationReliability")
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
                    "taskStatus": task_status,
                    "report_id": unwrap(resp.response).id,
                    "type": unwrap(resp.response).type,
                    "digest": unwrap(resp.response).digest,
                    "arguments": unwrap(resp.response).arguments,
                    "analysis_completion_time": unwrap(
                        resp.response
                    ).analysis_completion_date_time,
                    "risk_level": unwrap(resp.response).risk_level,
                    "detection_name_list": unwrap(resp.response).detection_names,
                    "threat_type_list": unwrap(resp.response).threat_types,
                    "file_type": unwrap(resp.response).true_file_type,
                    "DBotScore": {
                        "Score": dbot_score.score,
                        "Vendor": dbot_score.integration_name,
                        "Reliability": dbot_score.reliability,
                    },
                }
        else:
            message = {
                "taskStatus": task_status,
                "report_id": task_id,
                "code": unwrap(resp.response).status,
                "message": unwrap(resp.response).action,
            }
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[SANDBOX_SUBMISSION_POLLING_COMMAND], message, removeNull=True
            ),
            outputs_prefix="VisionOne.Sandbox_Submission_Polling",
            outputs_key_field="report_id",
            outputs=message,
            indicator=Common.File(file_entry),
        )

    def exception_list_count(self, v1_client: pytmv1.Client) -> int:
        """
        Gets the count of object present in exception list

        :return: number of exception object.
        :rtype: ``int``
        """
        new_exceptions: List[ExceptionObject] = []
        try:
            v1_client.consume_exception_list(
                lambda exception: new_exceptions.append(exception)
            )
        except Exception as err:
            raise RuntimeError(f"Something went wrong {err}")
        # Return length of exception list
        return len(new_exceptions)

    def suspicious_list_count(self, v1_client: pytmv1.Client) -> int:
        """
        Gets the count of object present in suspicious list
        :return: number of suspicious object.
        :rtype: ``int``
        """
        new_suspicious: List[SuspiciousObject] = []

        try:
            v1_client.consume_suspicious_list(
                lambda suspicious: new_suspicious.append(suspicious)
            )
        except Exception as err:
            raise RuntimeError(f"Something went wrong {err}")
        # Return length of suspicious list
        return len(new_suspicious)

    def get_workbench_histories(self, v1_client, start, end) -> list:
        if not check_datetime_aware(start):
            start = start.astimezone()
        if not check_datetime_aware(end):
            end = end.astimezone()
        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
        start = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end = end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        # Format start and end to remove decimal values so that the request call
        # doesn't fail due to incorrect time format for seconds.
        formatted_start = str(start[: (start.index("."))]) + str(start[-1])
        formatted_end = str(end[: (start.index("."))]) + str(end[-1])

        new_alerts: List[Union[SaeAlert, TiAlert]] = []
        try:
            v1_client.consume_alert_list(
                lambda alert: new_alerts.append(alert),
                start_time=formatted_start,
                end_time=formatted_end,
            )
        except Exception as err:
            demisto.debug(f"Something went wrong {err}")
            return []
        return new_alerts


def incident_severity_to_dbot_score(severity: str):
    """
    Converts an priority string to DBot score representation
    alert severity. Can be one of:
    Unknown -> 0
    No Risk -> 1
        Low or Medium -> 2
        Critical or High -> 3
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


def _get_client(name: str, api_key: str, base_url: str) -> pytmv1.Client:
    return pytmv1.client(name, api_key, base_url)


@staticmethod
def _is_pytmv1_error(resp) -> Dict[str, Any] | None:
    message: Dict[str, Any] = {}
    if resp.result_code == ResultCode.ERROR:
        message = {
            "result_code": resp.result_code,
            "error": resp.errors if resp.errors else resp.error,
        }
        return message
    elif resp.response is None:
        message = {"result_code": 400, "error": "The action could not be completed."}
        return message
    return None


@staticmethod
def _get_ot_enum(obj_type: str) -> ObjectType:
    if not obj_type.upper() in ObjectType.__members__:
        raise RuntimeError(f"Please check object type: {obj_type}")
    return ObjectType[obj_type.upper()]


def run_polling_command(
    args: Dict[str, Any], cmd: str, client: Client, v1_client: pytmv1.Client
) -> Union[str, CommandResults]:
    """
    Performs polling interval to check status of task.
    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``cmd``
    :param client: The command that polled for an interval.

    :type client: ``Client``
    :param client: client object to use http_request.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get("interval_in_seconds", 30))
    task_id = args.get(TASKID, EMPTY_STRING)
    if cmd == CHECK_TASK_STATUS_COMMAND:
        command_results = client.status_check(v1_client, args)
    else:
        command_results = client.sandbox_submission_polling(v1_client, args)
    statuses = [
        "succeeded",
        "failed",
        "timeout",
        "successful",
        "queued",
        "rejected",
        "waitForApproval",
    ]
    if command_results.outputs.get("taskStatus") not in statuses:
        # schedule next poll
        polling_args = {
            task_id: task_id,
            "interval_in_seconds": interval_in_secs,
            "polling": True,
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
    args: Dict[str, Any], client: Client, v1_client: pytmv1.Client
) -> Union[str, CommandResults]:
    """
    check status of task.

    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``Client``
    :param client: client object to use http_request.
    """
    return run_polling_command(args, CHECK_TASK_STATUS_COMMAND, client, v1_client)


def get_sandbox_submission_status(
    args: Dict[str, Any], client: Client, v1_client: pytmv1.Client
) -> Union[str, CommandResults]:
    """
    call polling command to check status of sandbox submission.
    :type args: ``args``
    :param client: argument required for polling.
    :type client: ``Client``
    :param client: client object to use http_request.
    """
    return run_polling_command(
        args, SANDBOX_SUBMISSION_POLLING_COMMAND, client, v1_client
    )


def test_module(v1_client: pytmv1.Client) -> Any:
    """
    Performs basic get request to get item samples.
    :type client: ``Client``
    :param client: client object to use http_request.
    """
    resp = v1_client.check_connectivity()
    if _is_pytmv1_error(resp) is not None:
        return "Connectivity failed!"
    return "ok"


def enable_or_disable_user_account(
    v1_client: pytmv1.Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Enable allows the user to sign in to new application and browser sessions.
    Disable signs the user out of all active application and browser sessions,
    and prevents the user from signing in any new session.
    Supported IAM systems: Azure AD and Active Directory (on-premises).

    :type client: ``Client``
    :param client: client object to use http_request.

    :type command: ``str``
    :param command: type of command either
    trendmicro-visionone-enable-user-account or
    trendmicro-visionone-disable-user-account.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers: List[Dict[str, str]] = json.loads(
        args.get("account_identifiers", [{}])
    )
    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}

    if command == ENABLE_USER_ACCOUNT_COMMAND:
        # Make rest call
        for account in account_identifiers:
            resp = v1_client.enable_account(
                pytmv1.AccountTask(
                    account_name=account[ACCOUNT_NAME],
                    description=account.get(DESCRIPTION, "Enable User Account."),
                )
            )
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.User_Account",
                    outputs_key_field="error",
                    outputs=err,
                )
            else:
                multi_resp.append(unwrap(resp.response).items[0])

        message = {"multi_response": [item.dict() for item in multi_resp]}

    if command == DISABLE_USER_ACCOUNT_COMMAND:
        # Make rest call
        for account in account_identifiers:
            resp = v1_client.disable_account(
                pytmv1.AccountTask(
                    account_name=account[ACCOUNT_NAME],
                    description=account.get(DESCRIPTION, "Enable User Account."),
                )
            )
            # Check if error response is returned
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.User_Account",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.User_Account",
        outputs_key_field="multi_response",
        outputs=message,
    )


def force_sign_out(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Signs the user out of all active application and browser sessions.
    Supported IAM systems: Azure AD

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers: List[Dict[str, str]] = json.loads(
        args.get("account_identifiers", [{}])
    )
    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}
    # Make rest call
    for account in account_identifiers:
        resp = v1_client.sign_out_account(
            pytmv1.AccountTask(
                account_name=account[ACCOUNT_NAME],
                description=account.get(DESCRIPTION, "Sign Out Account."),
            )
        )
        # Check if an error occurred for each call
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[FORCE_SIGN_OUT_COMMAND], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Force_Sign_Out",
                outputs_key_field="error",
                outputs=err,
            )
        # Append values to multi_status on successful call
        else:
            multi_resp.append(unwrap(resp.response).items[0])
    # Aggregate of all results to be sent to the War Room
    message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FORCE_SIGN_OUT_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Force_Sign_Out",
        outputs_key_field="multi_response",
        outputs=message,
    )


def force_password_reset(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Signs the user out of all active application and browser sessions,
    and forces the user to create a new password during the next sign-in attempt.
    Supported IAM systems: Azure AD and Active Directory (on-premises)

    :type v1_client: ``pytmv1.Client``
    :param v1_client: v1_client to make rest calls.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers: List[Dict[str, str]] = json.loads(
        args.get("account_identifiers", [{}])
    )
    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}
    # Make rest call
    for account in account_identifiers:
        resp = v1_client.reset_password_account(
            pytmv1.AccountTask(
                account_name=account[ACCOUNT_NAME],
                description=account.get(DESCRIPTION, "Force Password Reset."),
            )
        )
        # Check if an error occurred for each call
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[FORCE_PASSWORD_RESET_COMMAND], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Force_Password_Reset",
                outputs_key_field="error",
                outputs=err,
            )
        # Append values to multi_status on successful call
        else:
            multi_resp.append(unwrap(resp.response).items[0])
    # Aggregate of all results to be sent to the War Room
    message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FORCE_PASSWORD_RESET_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Force_Password_Reset",
        outputs_key_field="multi_response",
        outputs=message,
    )


def get_endpoint_info(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve information about the endpoint queried and
    sends the result to demisto war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    endpoint = args.get(ENDPOINT, EMPTY_STRING)
    query_op = args.get(QUERY_OP, EMPTY_STRING)

    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND

    new_endpoint_data: List[Any] = []
    endpoint_data: Dict[str, Any] = {}
    # Make rest call
    try:
        v1_client.consume_endpoint_data(
            lambda endpoint_data: new_endpoint_data.append(endpoint_data),
            pytmv1.QueryOp(query_op),
            endpoint,
        )
    except Exception as e:
        raise RuntimeError(f"Something went wrong while fetching endpoint data: {e}")
    # Load json objects to list
    endpoint_data_resp: List[Dict[str, Any]] = []
    for endpoint in new_endpoint_data:
        endpoint_data_resp.append(endpoint.dict())
    if len(endpoint_data_resp) == 0:
        message = {"error": f"No endpoint found. Please check endpoint {endpoint}."}
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[GET_ENDPOINT_INFO_COMMAND],
                message,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Endpoint_Info",
            outputs_key_field="error",
            outputs=message,
        )
    else:
        endpoint_data = {
            "status": "success",
            "logonAccount": endpoint_data_resp[0]
            .get("login_account", {})
            .get("value", ""),
            "hostname": endpoint_data_resp[0].get("endpoint_name", {}).get("value", ""),
            "macAddr": endpoint_data_resp[0].get("mac_address", {}).get("value", ""),
            "ip": endpoint_data_resp[0].get("ip", {}).get("value", [])[0],
            "osName": endpoint_data_resp[0].get("os_name", ""),
            "osVersion": endpoint_data_resp[0].get("os_version", ""),
            "osDescription": endpoint_data_resp[0].get("os_description"),
            "productCode": endpoint_data_resp[0].get("product_code"),
            "agentGuid": endpoint_data_resp[0].get("agent_guid"),
            "installedProductCodes": endpoint_data_resp[0].get(
                "installed_product_codes", []
            )[0],
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ENDPOINT_INFO_COMMAND], endpoint_data, removeNull=True
        ),
        outputs_prefix="VisionOne.Endpoint_Info",
        outputs_key_field="hostname",
        outputs=endpoint_data,
    )


def add_or_remove_from_block_list(
    v1_client: pytmv1.Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve data from the add or remove from block list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type command: ``str``
    :param command: type of command either
    trendmicro-visionone-add-to-block-list or
    trendmicro-visionone-remove-from-block-list.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects: List[Dict[str, str]] = json.loads(args.get("block_objects", [{}]))
    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}
    if command == ADD_BLOCKLIST_COMMAND:
        # Make rest call
        for block in block_objects:
            resp = v1_client.add_to_block_list(
                pytmv1.ObjectTask(
                    object_type=_get_ot_enum(block[OBJECT_TYPE]),
                    object_value=block[OBJECT_VALUE],
                    description=block.get(DESCRIPTION, "Add To Blocklist."),
                )
            )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.BlockList",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    if command == REMOVE_BLOCKLIST_COMMAND:
        # Make rest call
        for block in block_objects:
            resp = v1_client.remove_from_block_list(
                pytmv1.ObjectTask(
                    object_type=_get_ot_enum(block[OBJECT_TYPE]),
                    object_value=block[OBJECT_VALUE],
                    description=block.get(DESCRIPTION, "Add To Blocklist."),
                )
            )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.BlockList",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.BlockList",
        outputs_key_field="multi_response",
        outputs=message,
    )


def fetch_incidents(client: Client, v1_client: pytmv1.Client):
    """
    This function executes to get all workbench alerts by using
    startDateTime, endDateTime
    """
    end = datetime.now(timezone.utc)
    days = int(demisto.params().get("first_fetch", ""))

    last_run = demisto.getLastRun()
    if last_run and "start_time" in last_run:
        start = datetime.fromisoformat(last_run.get("start_time", ""))
    else:
        start = end + timedelta(days=-days)

    alerts: List[Any] = []
    alerts.extend(client.get_workbench_histories(v1_client, start, end))

    incidents: List[Dict[str, Any]] = []
    if alerts:
        for record in alerts:
            incident = {
                "name": record.model,
                "occurred": record.created_date_time,
                "severity": incident_severity_to_dbot_score(record.severity),
                "rawJSON": json.dumps(record),
            }
            incidents.append(incident)
            last_event = datetime.strptime(
                record["createdDateTime"], "%Y-%m-%dT%H:%M:%SZ"
            )

            next_search = last_event + timedelta(0, 1)
            demisto.setLastRun({"start_time": next_search.isoformat()})

    if incidents:
        demisto.incidents(incidents)
    else:
        demisto.incidents([])

    return incidents


def quarantine_or_delete_email_message(
    v1_client: pytmv1.Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve data from the quarantine or delete email message and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type command: ``str``
    :param command: type of command either
    trendmicro-visionone-quarantine-email-message or
    trendmicro-visionone-delete-email-message

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    email_identifiers: List[Dict[str, str]] = json.loads(
        args.get("email_identifiers", [{}])
    )
    message: Dict[str, Any] = {}
    multi_resp: List[MsData] = []

    if command == QUARANTINE_EMAIL_COMMAND:
        # Make rest call
        for msg in email_identifiers:
            if msg[MESSAGE_ID].startswith("<") and msg[MESSAGE_ID].endswith(">"):
                resp = v1_client.quarantine_email_message(
                    pytmv1.EmailMessageIdTask(
                        message_id=msg[MESSAGE_ID],
                        description=msg.get(DESCRIPTION, "Quarantine Email Message."),
                        mail_box=msg.get(MAILBOX, EMPTY_STRING),
                    )
                )
            else:
                resp = v1_client.quarantine_email_message(
                    pytmv1.EmailMessageUIdTask(
                        unique_id=msg[MESSAGE_ID],
                        description=msg.get(DESCRIPTION, "Quarantine Email Message."),
                    )
                )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.Email",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    if command == DELETE_EMAIL_COMMAND:
        # Make rest call
        for msg in email_identifiers:
            if msg[MESSAGE_ID].startswith("<") and msg[MESSAGE_ID].endswith(">"):
                resp = v1_client.delete_email_message(
                    pytmv1.EmailMessageIdTask(
                        message_id=msg[MESSAGE_ID],
                        description=msg.get(DESCRIPTION, "Delete Email Message."),
                        mail_box=msg.get(MAILBOX, EMPTY_STRING),
                    )
                )
            else:
                resp = v1_client.delete_email_message(
                    pytmv1.EmailMessageUIdTask(
                        unique_id=msg[MESSAGE_ID],
                        description=msg.get(DESCRIPTION, "Delete Email Message."),
                    )
                )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.Email",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.Email",
        outputs_key_field="multi_response",
        outputs=message,
    )


def isolate_or_restore_connection(
    v1_client: pytmv1.Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve data from the isolate or restore endpoint connection and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type command: ``str``
    :param command: type of command either
    trendmicro-visionone-isolate-endpoint or
    trendmicro-visionone-restore-endpoint-connection

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    endpoint_identifiers: List[Dict[str, str]] = json.loads(
        args.get("endpoint_identifiers", [{}])
    )
    message: Dict[str, Any] = {}
    multi_resp: List[MsData] = []

    if command == ISOLATE_ENDPOINT_COMMAND:
        for endpnt in endpoint_identifiers:
            resp = v1_client.isolate_endpoint(
                pytmv1.EndpointTask(
                    endpoint_name=endpnt[ENDPOINT],
                    description=endpnt.get(DESCRIPTION, "Isolate Endpoint connection."),
                )
            )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.Endpoint_Connection",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    if command == RESTORE_ENDPOINT_COMMAND:
        for endpnt in endpoint_identifiers:
            resp = v1_client.restore_endpoint(
                pytmv1.EndpointTask(
                    endpoint_name=endpnt[ENDPOINT],
                    description=endpnt.get(DESCRIPTION, "Restore Endpoint connection."),
                )
            )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.Endpoint_Connection",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.Endpoint_Connection",
        outputs_key_field="multi_response",
        outputs=message,
    )


def terminate_process(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Terminate the process running on the end point and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    process_identifiers: List[Dict[str, str]] = json.loads(
        args.get("process_identifiers", [{}])
    )
    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}
    # Make rest call
    for process in process_identifiers:
        resp = v1_client.terminate_process(
            pytmv1.ProcessTask(
                endpoint_name=process[ENDPOINT],
                file_sha1=process[FILE_SHA],
                description=process.get(DESCRIPTION, "Terminate Process."),
                file_name=process.get(FILE_NAME, EMPTY_STRING),
            )
        )
        # Check if an error occurred for each call
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[TABLE_TERMINATE_PROCESS], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Terminate_Process",
                outputs_key_field="error",
                outputs=err,
            )
        # Append values to multi_status on successful call
        else:
            multi_resp.append(unwrap(resp.response).items[0])
        # Aggregate of all results to be sent to the War Room
        message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(
            TABLE_TERMINATE_PROCESS, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Terminate_Process",
        outputs_key_field="multi_response",
        outputs=message,
    )


def add_or_delete_from_exception_list(
    client: Client, v1_client: pytmv1.Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Add or Delete the exception object to exception list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

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
    block_objects: List[Dict[str, str]] = json.loads(args.get("block_objects", [{}]))

    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}

    if command == ADD_EXCEPTION_LIST_COMMAND:
        # Make rest call
        for block in block_objects:
            resp = v1_client.add_to_exception_list(
                pytmv1.ObjectTask(
                    object_type=_get_ot_enum(block[OBJECT_TYPE]),
                    object_value=block[OBJECT_VALUE],
                    description=block.get(DESCRIPTION, "Add To Exception List."),
                )
            )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.Exception_List",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])

    if command == DELETE_EXCEPTION_LIST_COMMAND:
        # Make rest call
        for block in block_objects:
            resp = v1_client.remove_from_exception_list(
                pytmv1.ObjectTask(
                    object_type=_get_ot_enum(block[OBJECT_TYPE]),
                    object_value=block[OBJECT_VALUE],
                    description=block.get(DESCRIPTION, "Delete From Exception List."),
                )
            )
            # Check if an error occurred for each call
            if (err := _is_pytmv1_error(resp)) is not None:
                return CommandResults(
                    readable_output=tableToMarkdown(
                        table_name[command], err, removeNull=True
                    ),
                    outputs_prefix="VisionOne.Exception_List",
                    outputs_key_field="error",
                    outputs=err,
                )
            # Append values to multi_status on successful call
            else:
                multi_resp.append(unwrap(resp.response).items[0])

    exception_list_count = client.exception_list_count(v1_client)
    # Aggregate of all results to be sent to the War Room
    message = {
        "message": "success",
        "multi_response": [item.dict() for item in multi_resp],
        "total_items": exception_list_count,
    }
    return CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.Exception_List",
        outputs_key_field="multi_response",
        outputs=message,
    )


def add_to_suspicious_list(
    client: Client, v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Add suspicious object to suspicious list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects: List[Dict[str, Any]] = json.loads(args.get("block_objects", [{}]))

    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}

    for block in block_objects:
        resp = v1_client.add_to_suspicious_list(
            pytmv1.SuspiciousObjectTask(
                object_type=_get_ot_enum(block[OBJECT_TYPE]),
                object_value=block[OBJECT_VALUE],
                scan_action=block.get(SCAN_ACTION, BLOCK),
                risk_level=block.get(RISK_LEVEL, MEDIUM),
                days_to_expiration=block.get(EXPIRY_DAYS, 30),
            )
        )
        # Check if an error occurred for each call
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[ADD_SUSPICIOUS_LIST_COMMAND], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Suspicious_List",
                outputs_key_field="error",
                outputs=err,
            )
        # Append values to multi_status on successful call
        else:
            multi_resp.append(unwrap(resp.response).items[0])

    suspicious_list_count = client.suspicious_list_count(v1_client)

    message = {
        "message": "success",
        "multi_response": [item.dict() for item in multi_resp],
        "total_items": suspicious_list_count,
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[ADD_SUSPICIOUS_LIST_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Suspicious_List",
        outputs_key_field="multi_response",
        outputs=message,
    )


def delete_from_suspicious_list(
    client: Client, v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Delete the suspicious object from suspicious list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects: List[Dict[str, str]] = json.loads(args.get("block_objects", [{}]))

    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}

    # Make rest call
    for block in block_objects:
        resp = v1_client.remove_from_suspicious_list(
            pytmv1.ObjectTask(
                object_type=_get_ot_enum(block[OBJECT_TYPE]),
                object_value=block[OBJECT_VALUE],
            )
        )
        # Check if an error occurred for each call
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[DELETE_SUSPICIOUS_LIST_COMMAND], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Suspicious_List",
                outputs_key_field="error",
                outputs=err,
            )
        # Append values to multi_status on successful call
        else:
            multi_resp.append(unwrap(resp.response).items[0])
    # Fetch suspicious list count
    suspicious_list_count = client.suspicious_list_count(v1_client)

    message = {
        "message": "success",
        "multi_response": [item.dict() for item in multi_resp],
        "total_items": suspicious_list_count,
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DELETE_SUSPICIOUS_LIST_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Suspicious_List",
        outputs_key_field="multi_response",
        outputs=message,
    )


def get_file_analysis_status(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Get the status of file based on task id and
    sends the result to demist war room

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    task_id = args.get(TASKID, EMPTY_STRING)

    message: Dict[str, Any] = {}

    # Make rest call
    resp = v1_client.get_sandbox_submission_status(submit_id=task_id)

    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[GET_FILE_ANALYSIS_STATUS_COMMAND], err, removeNull=True
            ),
            outputs_prefix="VisionOne.File_Analysis_Status",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "status": unwrap(resp.response).status,
            "id": unwrap(resp.response).id,
            "action": unwrap(resp.response).action,
            "createdDateTime": unwrap(resp.response).created_date_time,
            "lastActionDateTime": unwrap(resp.response).last_action_date_time,
            "resourceLocation": unwrap(resp.response).resource_location,
            "isCached": unwrap(resp.response).is_cached,
            "digest": unwrap(resp.response).digest,
            "arguments": unwrap(resp.response).arguments,
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_FILE_ANALYSIS_STATUS_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.File_Analysis_Status",
        outputs_key_field="id",
        outputs=message,
    )


def get_file_analysis_result(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Get the report of file based on report id and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    report_id = args.get(REPORT_ID, EMPTY_STRING)
    # Optional Params
    poll = args.get(POLL, FALSE)
    poll_time_sec = args.get(POLL_TIME_SEC, 0)
    message: Dict[str, Any] = {}

    # Make rest call
    resp = v1_client.get_sandbox_analysis_result(
        submit_id=report_id,
        poll=poll,  # type: ignore
        poll_time_sec=poll_time_sec,  # type: ignore
    )
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[GET_FILE_ANALYSIS_RESULT_COMMAND], err, removeNull=True
            ),
            outputs_prefix="VisionOne.File_Analysis_Report",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        reliability = demisto.params().get("integrationReliability")
        risk = unwrap(resp.response).risk_level
        risk_score = incident_severity_to_dbot_score(risk)
        digest = unwrap(resp.response).digest
        sha256 = unwrap(digest).sha256
        md5 = unwrap(digest).md5
        sha1 = unwrap(digest).sha1
        # Create DBot Score
        dbot_score = Common.DBotScore(
            indicator=sha256,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=risk_score,
            reliability=reliability,
        )
        # Create file
        file_entry = Common.File(
            sha256=sha256, md5=md5, sha1=sha1, dbot_score=dbot_score
        )
        message = {
            "status_code": resp.result_code,
            "message": "success",
            "report_id": unwrap(resp.response).id,
            "type": unwrap(resp.response).type,
            "digest": unwrap(resp.response).digest,
            "arguments": unwrap(resp.response).arguments,
            "analysisCompletionDateTime": unwrap(
                resp.response
            ).analysis_completion_date_time,
            "riskLevel": unwrap(resp.response).risk_level,
            "detectionNames": unwrap(resp.response).detection_names,
            "threatTypes": unwrap(resp.response).threat_types,
            "trueFileType": unwrap(resp.response).true_file_type,
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
            outputs_prefix="VisionOne.File_Analysis_Report",
            outputs_key_field="report_id",
            outputs=message,
            indicator=file_entry,
        )


def collect_file(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Collect forensic file and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    collect_files: List[Dict[str, str]] = json.loads(args.get("collect_files", [{}]))

    multi_resp: List[MsData] = []
    message: Dict[str, Any] = {}

    # Make rest call
    for data in collect_files:
        resp = v1_client.collect_file(
            pytmv1.FileTask(
                endpoint_name=data[ENDPOINT],
                file_path=data[FILE_PATH],
                description=data.get(DESCRIPTION, "Collect File."),
            )
        )
        # Check if an error occurred during rest call
        if (err := _is_pytmv1_error(resp)) is not None:
            return CommandResults(
                readable_output=tableToMarkdown(
                    table_name[TABLE_COLLECT_FILE], err, removeNull=True
                ),
                outputs_prefix="VisionOne.Collect_Forensic_File",
                outputs_key_field="error",
                outputs=err,
            )
        # Assign values on a successful call
        else:
            multi_resp.append(unwrap(resp.response).items[0])

    message = {"multi_response": [item.dict() for item in multi_resp]}

    return CommandResults(
        readable_output=tableToMarkdown(TABLE_COLLECT_FILE, message, removeNull=True),
        outputs_prefix="VisionOne.Collect_Forensic_File",
        outputs_key_field="multi_response",
        outputs=message,
    )


def download_information_collected_file(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[Any, CommandResults]:
    """
    Get the analysis report of file based on action id and sends
    the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    task_id = args.get(TASKID, EMPTY_STRING)
    # Optional Params
    poll = args.get(POLL, FALSE)
    poll_time_sec = args.get(POLL_TIME_SEC, 0)
    # Make rest call
    resp = v1_client.get_base_task_result(
        task_id=task_id,
        poll=poll,
        poll_time_sec=poll_time_sec,
    )
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[DOWNLOAD_COLLECTED_FILE_COMMAND], err, removeNull=True
            ),
            outputs_prefix="VisionOne.Download_Information_For_Collected_Forensic_File",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "taskId": unwrap(resp.response).id,
            "status": unwrap(resp.response).status,
            "createdDateTime": unwrap(resp.response).created_date_time,
            "lastActionDateTime": unwrap(resp.response).last_action_date_time,
            "action": unwrap(resp.response).action,
            "description": unwrap(resp.response).description,
            "account": unwrap(resp.response).account,
        }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DOWNLOAD_COLLECTED_FILE_COMMAND], message, removeNull=True
        ),
        outputs_prefix=("VisionOne.Download_Information_For_Collected_Forensic_File"),
        outputs_key_field="taskId",
        outputs=message,
    )


def download_analysis_report(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[Any, CommandResults]:
    """
    Get the analysis report of file based on action id and sends
    the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    submit_id = args.get(SUBMISSION_ID, EMPTY_STRING)
    # Optional Params
    poll = args.get(POLL, FALSE)
    poll_time_sec = args.get(POLL_TIME_SEC, 0)
    file_name = args.get(FILE_NAME)

    # If a file name is not provided, default value of Sandbox_Analysis_Report is set.
    if not file_name:
        name = "Trend_Micro_Sandbox_Analysis_Report"
        file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.pdf"

    # Make rest call
    resp = v1_client.download_sandbox_analysis_result(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
    )

    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[DOWNLOAD_ANALYSIS_REPORT_COMMAND], err, removeNull=True
            ),
            outputs_prefix="VisionOne.Download_Analysis_Report",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        data = unwrap(resp.response).content

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
                table_name[DOWNLOAD_ANALYSIS_REPORT_COMMAND], message, removeNull=True
            ),
            outputs_prefix="VisionOne.Download_Analysis_Report",
            outputs_key_field="submission_id",
            outputs=message,
        ),
    ]


def download_investigation_package(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[Any, CommandResults]:
    """
    Downloads the Investigation Package of the specified object based on
    submission id and sends the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    submit_id = args.get(SUBMISSION_ID, EMPTY_STRING)
    # Optional Params
    poll = args.get(POLL, FALSE)
    poll_time_sec = args.get(POLL_TIME_SEC, 0)
    file_name = args.get(FILE_NAME)
    # If a file name is not provided, default value of
    # Sandbox_Investigation_Package is set for the package.
    if not file_name:
        name = "Sandbox_Investigation_Package"
        file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.pdf"

    # Make rest call
    resp = v1_client.download_sandbox_investigation_package(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
    )

    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND], err, removeNull=True
            ),
            outputs_prefix="VisionOne.Download_Investigation_Package",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        data = unwrap(resp.response).content

    resp_msg = "Please click download to download .zip file."
    # fileResult takes response data and creates a file with
    # the specified extension that can be downloaded in the war room
    output_file = fileResult(f"{file_name}", data, file_type=EntryType.ENTRY_INFO_FILE)
    resp_msg = "Please select download to start download"
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
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Download_Investigation_Package",
            outputs_key_field="submission_id",
            outputs=message,
        ),
    ]


def download_suspicious_object_list(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Downloads the suspicious object list associated to the specified object
    Note: Suspicious Object Lists are only available for objects with a high risk level
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    submit_id = args.get(SUBMISSION_ID, EMPTY_STRING)
    # Optional Params
    poll = args.get(POLL, FALSE)
    poll_time_sec = args.get(POLL_TIME_SEC, 0)
    # Make rest call
    resp = v1_client.get_sandbox_suspicious_list(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
    )
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND],
                err,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Download_Suspicious_Object_list",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "code": resp.result_code,
            "riskLevel": unwrap(resp.response).items[0].risk_level,
            "analysisCompletionDateTime": unwrap(resp.response)
            .items[0]
            .analysis_completion_date_time,
            "expiredDateTime": unwrap(resp.response).items[0].expired_date_time,
            "rootSha1": unwrap(resp.response).items[0].root_sha1,
            "ip": unwrap(resp.response).items[0].value,
        }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND],
            message,
            removeNull=True,
        ),
        outputs_prefix="VisionOne.Download_Suspicious_Object_list",
        outputs_key_field="riskLevel",
        outputs=message,
    )


def submit_file_to_sandbox(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    submit file to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    file_path = args.get(FILE_PATH, b"")
    file_name = args.get(FILE_NAME, EMPTY_STRING)
    # Optional Params
    document_pass = args.get(DOCUMENT_PASSWORD, EMPTY_STRING)
    archive_pass = args.get(ARCHIVE_PASSWORD, EMPTY_STRING)
    arguments = args.get(ARGUMENTS, EMPTY_STRING)

    # Make rest call
    resp = v1_client.submit_file_to_sandbox(
        file=file_path,
        file_name=file_name,
        document_password=document_pass,
        archive_password=archive_pass,
        arguments=arguments,
    )
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[FILE_TO_SANDBOX_COMMAND],
                err,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Submit_File_to_Sandbox",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "message": resp.result_code,
            "code": 202,
            "task_id": unwrap(resp.response).id,
            "digest": unwrap(resp.response).digest,
            "arguments": unwrap(resp.response).arguments,
        }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FILE_TO_SANDBOX_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Submit_File_to_Sandbox",
        outputs_key_field="message",
        outputs=message,
    )


def submit_file_entry_to_sandbox(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    submit file entry to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
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
    file_name = file_.get("name", EMPTY_STRING)
    file_path = file_.get("path", b"")
    with open(file_path, "rb") as f:
        contents = f.read()
    # Make rest call
    resp = v1_client.submit_file_to_sandbox(
        file=contents,
        file_name=file_name,
        document_password=document_pass,
        archive_password=archive_pass,
        arguments=arguments,
    )
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[FILE_ENTRY_TO_SANDBOX_COMMAND],
                err,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Submit_File_Entry_to_Sandbox",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "code": 202,
            "message": resp.result_code,
            "filename": file_name,
            "entryId": entry,
            "file_path": file_.get("path", EMPTY_STRING),
            "task_id": unwrap(resp.response).id,
            "digest": unwrap(resp.response).digest,
            "arguments": unwrap(resp.response).arguments,
        }

    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[FILE_ENTRY_TO_SANDBOX_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Submit_File_Entry_to_Sandbox",
        outputs_key_field="entryId",
        outputs=message,
    )


def add_note(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Adds a note to an existing workbench alert
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id = args.get(WORKBENCH_ID, EMPTY_STRING)
    content = args.get(CONTENT, EMPTY_STRING)

    message: Dict[str, Any] = {}
    # Make rest call
    resp = v1_client.add_alert_note(alert_id=workbench_id, note=content)
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[ADD_NOTE_COMMAND],
                err,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Add_Note",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "code": 201,
            "message": resp.result_code,
            "note_id": unwrap(resp.response).note_id,
        }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[ADD_NOTE_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Add_Note",
        outputs_key_field="note_id",
        outputs=message,
    )


def update_status(
    v1_client: pytmv1.Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Updates the status of an existing workbench alert
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id = args.get(WORKBENCH_ID, EMPTY_STRING)
    status = args.get(STATUS, EMPTY_STRING)
    if_match = args.get(IF_MATCH, EMPTY_STRING)

    message: Dict[str, Any] = {}
    # Choose Status Enum
    sts = status.upper()
    if sts not in InvestigationStatus.__members__:
        message = {"error": f"Invalid investigation status {status} provided!"}
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[UPDATE_STATUS_COMMAND], message, removeNull=True
            ),
            outputs_prefix="VisionOne.Update_Status",
            outputs_key_field="error",
            outputs=message,
        )
    # Assign enum status
    status = InvestigationStatus[sts]
    # Make rest call
    resp = v1_client.edit_alert_status(
        alert_id=workbench_id, status=status, if_match=if_match
    )
    # Check if an error occurred during rest call
    if (err := _is_pytmv1_error(resp)) is not None:
        return CommandResults(
            readable_output=tableToMarkdown(
                table_name[UPDATE_STATUS_COMMAND],
                err,
                removeNull=True,
            ),
            outputs_prefix="VisionOne.Update_Status",
            outputs_key_field="error",
            outputs=err,
        )
    # Add values to message on successful call
    else:
        message = {
            "Workbench_Id": workbench_id,
            "code": 204,
            "message": f"Workbench status has been updated to {status}",
        }
    return CommandResults(
        readable_output=tableToMarkdown(
            table_name[UPDATE_STATUS_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Update_Status",
        outputs_key_field="Workbench_Id",
        outputs=message,
    )


def main():  # pragma: no cover
    try:
        """GLOBAL VARS"""
        params = demisto.params()

        base_url: str | None = params.get(URL)
        api_key = params.get(API_TOKEN).get("password")  # type: ignore
        proxy = params.get("proxy", False)
        verify = not params.get("insecure", False)

        assert base_url is not None
        client = Client(base_url, api_key, proxy, verify)
        v1_client: pytmv1.Client = _get_client(
            "Trend Micro Vision One V3", api_key, base_url
        )

        command = demisto.command()
        demisto.debug(COMMAND_CALLED.format(command=command))
        args = demisto.args()

        if command == TEST_MODULE:
            return_results(test_module(v1_client))

        elif command == FETCH_INCIDENTS:
            return_results(fetch_incidents(client, v1_client))

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

        elif command in (ISOLATE_ENDPOINT_COMMAND, RESTORE_ENDPOINT_COMMAND):
            return_results(isolate_or_restore_connection(v1_client, command, args))

        elif command == TERMINATE_PROCESS_COMMAND:
            return_results(terminate_process(v1_client, args))

        elif command in (ADD_EXCEPTION_LIST_COMMAND, DELETE_EXCEPTION_LIST_COMMAND):
            return_results(
                add_or_delete_from_exception_list(client, v1_client, command, args)
            )

        elif command == ADD_SUSPICIOUS_LIST_COMMAND:
            return_results(add_to_suspicious_list(client, v1_client, args))

        elif command == DELETE_SUSPICIOUS_LIST_COMMAND:
            return_results(delete_from_suspicious_list(client, v1_client, args))

        elif command == GET_FILE_ANALYSIS_STATUS_COMMAND:
            return_results(get_file_analysis_status(v1_client, args))

        elif command == GET_FILE_ANALYSIS_RESULT_COMMAND:
            return_results(get_file_analysis_result(v1_client, args))

        elif command == GET_ENDPOINT_INFO_COMMAND:
            return_results(get_endpoint_info(v1_client, args))

        elif command == COLLECT_FILE_COMMAND:
            return_results(collect_file(v1_client, args))

        elif command == DOWNLOAD_COLLECTED_FILE_COMMAND:
            return_results(download_information_collected_file(v1_client, args))

        elif command == FILE_TO_SANDBOX_COMMAND:
            return_results(submit_file_to_sandbox(v1_client, args))

        elif command == FILE_ENTRY_TO_SANDBOX_COMMAND:
            return_results(submit_file_entry_to_sandbox(v1_client, args))

        elif command == SANDBOX_SUBMISSION_POLLING_COMMAND:
            if args.get(POLLING) == TRUE:
                cmd_res = get_sandbox_submission_status(args, client, v1_client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(client.sandbox_submission_polling(v1_client, args))

        elif command == DOWNLOAD_ANALYSIS_REPORT_COMMAND:
            return_results(download_analysis_report(v1_client, args))

        elif command == DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND:
            return_results(download_investigation_package(v1_client, args))

        elif command == DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND:
            return_results(download_suspicious_object_list(v1_client, args))

        elif command == UPDATE_STATUS_COMMAND:
            return_results(update_status(v1_client, args))

        elif command == ADD_NOTE_COMMAND:
            return_results(add_note(v1_client, args))

        elif command == CHECK_TASK_STATUS_COMMAND:
            if args.get(POLLING) == TRUE:
                cmd_res = get_task_status(args, client, v1_client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(client.status_check(v1_client, args))

        else:
            demisto.error(f"{command} command is not implemented.")
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as error:
        return return_error(
            f"Failed to execute {demisto.command()} command. Error: {str(error)}"
        )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
