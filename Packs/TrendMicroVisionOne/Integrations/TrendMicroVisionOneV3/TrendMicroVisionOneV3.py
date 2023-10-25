import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa: F401

"""IMPORTS"""

import json
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Type, TypeVar, Union
import pytmv1
from pytmv1 import (
    AccountTask,
    AccountTaskResp,
    BaseTaskResp,
    BlockListTaskResp,
    CollectFileTaskResp,
    EmailActivity,
    EmailMessageIdTask,
    EmailMessageTaskResp,
    EmailMessageUIdTask,
    EndpointActivity,
    EndpointTask,
    EndpointTaskResp,
    ExceptionObject,
    FileTask,
    InvestigationStatus,
    ObjectTask,
    ObjectType,
    ProcessTask,
    ResultCode,
    SaeAlert,
    SuspiciousObject,
    SuspiciousObjectTask,
    TerminateProcessTaskResp,
    TiAlert,
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
FALSE = "false"
TRUE = "true"
POLL = "poll"
POLL_TIME_SEC = "poll_time_sec"
POLLING = "polling"
ARGUMENTS = "arguments"
ACCOUNT_NAME = "account_name"
INTEGRATION_RELIABILITY = "integrationReliability"
INCIDENT_SEVERITY = "incidentSeverity"
EMPTY_STRING = ""
API_TOKEN = "apikey"
AGENT_GUID = "agent_guid"
DESCRIPTION = "description"
MESSAGE_ID = "message_id"
MAILBOX = "mailbox"
APP_NAME = "Trend Micro Vision One V3"
ENDPOINT = "endpoint"
START = "start"
SELECT = "select"
END = "end"
TOP = "top"
QUERY_OP = "query_op"
FIELDS = "fields"
GET_ACTIVITY_DATA_COUNT = "get_activity_data_count"
ENTRY_ID = "entry_id"
FILE_SHA1 = "file_sha1"
SUCCEEDED = "succeeded"
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
RESTORE_EMAIL = "Restore Email Message."
TERMINATE_PROCESS = "Terminate Process."
DISABLE_ACCOUNT = "Disable User Account."
ADD_SUSPICIOUS = "Add to Suspicious List."
REMOVE_BLOCKLIST = "Remove from Blocklist."
FAILED_CONNECTIVITY = "Connectivity failed!"
ADD_EXCEPTION_LIST = "Add To Exception List."
QUARANTINE_EMAIL = "Quarantine Email Message."
FORCE_PASSWORD_RESET = "Force Password Reset."
DELETE_SUSPICIOUS = "Delete from Suspicious List."
DELETE_EXCEPTION_LIST = "Delete from Exception List."
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
TABLE_GET_ENDPOINT_ACTIVITY_DATA_COUNT = "Endpoint activity data count"
TABLE_GET_FILE_ANALYSIS_STATUS = "File analysis status "
TABLE_GET_FILE_ANALYSIS_RESULT = "File analysis result "
TABLE_GET_ALERT_DETAILS = "Alert details"
TABLE_COLLECT_FILE = "Collect forensic file "
TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION = (
    "The download information for collected forensic file "
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
GET_ENDPOINT_ACTIVITY_DATA_COMMAND = "trendmicro-visionone-get-endpoint-activity-data"
GET_ALERT_DETAILS_COMMAND = "trendmicro-visionone-get-alert-details"
UPDATE_STATUS_COMMAND = "trendmicro-visionone-update-status"
ADD_NOTE_COMMAND = "trendmicro-visionone-add-note"
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
    ADD_EXCEPTION_LIST_COMMAND: TABLE_ADD_EXCEPTION_LIST,
    REMOVE_BLOCKLIST_COMMAND: TABLE_REMOVE_FROM_BLOCKLIST,
    FILE_TO_SANDBOX_COMMAND: TABLE_SUBMIT_FILE_TO_SANDBOX,
    URLS_TO_SANDBOX_COMMAND: TABLE_SUBMIT_URLS_TO_SANDBOX,
    ENABLE_USER_ACCOUNT_COMMAND: TABLE_ENABLE_USER_ACCOUNT,
    ADD_SUSPICIOUS_LIST_COMMAND: TABLE_ADD_SUSPICIOUS_LIST,
    DISABLE_USER_ACCOUNT_COMMAND: TABLE_DISABLE_USER_ACCOUNT,
    FORCE_PASSWORD_RESET_COMMAND: TABLE_FORCE_PASSWORD_RESET,
    QUARANTINE_EMAIL_COMMAND: TABLE_QUARANTINE_EMAIL_MESSAGE,
    DELETE_EXCEPTION_LIST_COMMAND: TABLE_DELETE_EXCEPTION_LIST,
    DELETE_SUSPICIOUS_LIST_COMMAND: TABLE_DELETE_SUSPICIOUS_LIST,
    GET_EMAIL_ACTIVITY_DATA_COMMAND: TABLE_GET_EMAIL_ACTIVITY_DATA,
    GET_FILE_ANALYSIS_STATUS_COMMAND: TABLE_GET_FILE_ANALYSIS_STATUS,
    GET_FILE_ANALYSIS_RESULT_COMMAND: TABLE_GET_FILE_ANALYSIS_RESULT,
    DOWNLOAD_ANALYSIS_REPORT_COMMAND: TABLE_DOWNLOAD_ANALYSIS_REPORT,
    FILE_ENTRY_TO_SANDBOX_COMMAND: TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX,
    GET_ENDPOINT_ACTIVITY_DATA_COMMAND: TABLE_GET_ENDPOINT_ACTIVITY_DATA,
    SANDBOX_SUBMISSION_POLLING_COMMAND: TABLE_SANDBOX_SUBMISSION_POLLING,
    DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND: TABLE_DOWNLOAD_INVESTIGATION_PACKAGE,
    DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND: TABLE_DOWNLOAD_SUSPICIOUS_OBJECT_LIST,
    DOWNLOAD_COLLECTED_FILE_COMMAND: TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION,
}
# disable insecure warnings
urllib3.disable_warnings()

_T = TypeVar("_T")


def unwrap(val: Union[_T, None]) -> _T:
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
        self.app = APP_NAME

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def status_check(self, data: Dict[str, Any]) -> Any:
        """
        Check the status of particular task.
        :type data: ``dict``
        :param method: Response data to received from the end point.
        :return: task status response data.
        :rtype: ``Any``
        """
        task_id = data.get(TASKID, EMPTY_STRING)
        poll = data.get(POLL, TRUE)
        poll_time_sec = arg_to_number(data.get(POLL_TIME_SEC, 0))
        message: Dict[str, Any] = {}

        # Initialize pytmv1 client
        v1_client = _get_client(APP_NAME, self.api_key, self.base_url)

        # Make rest call
        resp = v1_client.get_base_task_result(task_id, poll, poll_time_sec)
        # Check if error response is returned
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
        # Get the task action type that will be used to
        # fetch task class which is used in get_task_result
        action = unwrap(resp.response).action
        # Make rest call using task class to get final result
        task_resp = v1_client.get_task_result(
            class_=_get_task_type(action),
            task_id=task_id,
            poll=poll,
            poll_time_sec=poll_time_sec,
        )
        # Assign values on a successful call
        message = unwrap(task_resp.response).dict()
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

    def sandbox_submission_polling(self, data: Dict[str, Any]) -> Any:
        """
        Check the status of sandbox submission
        :type data: ``dict``
        :param method: Response data received from sandbox.
        :return: Sandbox submission response data.
        :rtype: ``Any``
        """
        task_id = data.get(TASKID, EMPTY_STRING)
        message: Dict[str, Any] = {}
        # Initialize pytmv1 client
        v1_client = _get_client(APP_NAME, self.api_key, self.base_url)

        resp = v1_client.get_sandbox_submission_status(submit_id=task_id)
        # Check if error response is returned
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
        # Get the task status of rest call
        task_status = unwrap(resp.response).status

        file_entry = None
        if task_status.lower() == SUCCEEDED:
            analysis_resp = v1_client.get_sandbox_analysis_result(submit_id=task_id)
            if _is_pytmv1_error(analysis_resp.result_code):
                return_error(
                    message=f"{unwrap(analysis_resp.error).message}",
                    error=str(analysis_resp.error),
                )
            risk = unwrap(analysis_resp.response).risk_level
            risk_score = incident_severity_to_dbot_score(risk)
            digest = unwrap(unwrap(analysis_resp.response).digest)
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
                "report_id": unwrap(analysis_resp.response).id,
                "type": unwrap(analysis_resp.response).type,
                "digest": unwrap(unwrap(analysis_resp.response).digest).dict(),
                "arguments": unwrap(analysis_resp.response).arguments,
                "analysis_completion_time": unwrap(
                    analysis_resp.response
                ).analysis_completion_date_time,
                "risk_level": unwrap(analysis_resp.response).risk_level,
                "detection_name_list": unwrap(analysis_resp.response).detection_names,
                "threat_type_list": unwrap(analysis_resp.response).threat_types,
                "file_type": unwrap(analysis_resp.response).true_file_type,
                "DBotScore": {
                    "Score": dbot_score.score,
                    "Vendor": dbot_score.integration_name,
                    "Reliability": dbot_score.reliability,
                },
            }
        else:
            message = {
                "status": unwrap(resp.response).status,
                "report_id": task_id,
                "result_code": resp.result_code,
                "message": unwrap(resp.response).action,
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
            indicator=Common.File(file_entry),
        )

    def exception_list_count(self) -> int:
        """
        Gets the count of object present in exception list
        :return: number of exception object.
        :rtype: ``int``
        """
        new_exceptions: List[ExceptionObject] = []
        # Initialize pytmv1 client
        v1_client = _get_client(APP_NAME, self.api_key, self.base_url)
        # Make rest call
        try:
            v1_client.consume_exception_list(
                lambda exception: new_exceptions.append(exception)
            )
        except Exception as err:
            raise RuntimeError(f"Error while fetching exception list count.\n {err}")
        # Return length of exception list
        return len(new_exceptions)

    def suspicious_list_count(self) -> int:
        """
        Gets the count of object present in suspicious list
        :return: number of suspicious object.
        :rtype: ``int``
        """
        new_suspicious: List[SuspiciousObject] = []
        # Initialize pytmv1 client
        v1_client = _get_client(APP_NAME, self.api_key, self.base_url)
        # Make rest call
        try:
            v1_client.consume_suspicious_list(
                lambda suspicious: new_suspicious.append(suspicious)
            )
        except Exception as err:
            raise RuntimeError(f"Error while fetching suspicious list count.\n {err}")
        # Return length of suspicious list
        return len(new_suspicious)

    def get_workbench_histories(self, start, end) -> list:
        """
        Fetches incidents based on incident severity per user selection.
        Args:
        start (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start of the data retrieval
                     time range. Oldest available value is "1970-01-01T00:00:00Z"
        end (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end of the data retrieval
                   time range. "endDateTime" can not be earlier than "startDateTime".
        Returns:
            list: List of incidents fetched
        """
        # Initialize pytmv1 client
        v1_client = _get_client(APP_NAME, self.api_key, self.base_url)
        if not check_datetime_aware(start):
            start = start.astimezone()
        if not check_datetime_aware(end):
            end = end.astimezone()
        # Date time format before formatting -> 2020-06-15T10:00:00.000Z
        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
        start = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end = end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        # Format start and end to remove decimal values so that the request
        # call doesn't fail due to incorrect time format for seconds.
        # Date time format after formatting -> 2020-06-15T10:00:00Z
        formatted_start = str(start[: (start.index("."))]) + str(start[-1])
        formatted_end = str(end[: (start.index("."))]) + str(end[-1])

        new_alerts: List[Union[SaeAlert, TiAlert]] = []

        # filter incidents per user preference
        def _filter_alerts(alert: Union[SaeAlert, TiAlert]) -> None:
            # If incidents of all severities need to be fetched
            if demisto.params().get(INCIDENT_SEVERITY) == ANY:
                new_alerts.append(alert)
            # If incidents of selected severity need to be fetched
            elif alert.severity.value == demisto.params().get(INCIDENT_SEVERITY):
                new_alerts.append(alert)

        # Make rest call
        try:
            v1_client.consume_alert_list(
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
    return pytmv1.client(name, api_key, base_url)


# Checks the api response for error
def _is_pytmv1_error(result_code: ResultCode) -> bool:
    return result_code == ResultCode.ERROR


# Validates object types like ip, url, domain, etc.
def _get_ot_enum(obj_type: str) -> ObjectType:
    if not obj_type.upper() in ObjectType.__members__:
        raise RuntimeError(f"Please check object type: {obj_type}")
    return ObjectType[obj_type.upper()]


# Use response action type and return task class associated
def _get_task_type(action: str) -> Type[BaseTaskResp]:
    task_dict: Dict[Any, List[str]] = {
        AccountTaskResp: [
            "enableAccount",
            "disableAccount",
            "forceSignOut",
            "resetPassword",
        ],
        BlockListTaskResp: ["block", "restoreBlock"],
        EmailMessageTaskResp: ["quarantineMessage", "restoreMessage", "deleteMessage"],
        EndpointTaskResp: ["isolate", "restoreIsolate"],
        TerminateProcessTaskResp: ["terminateProcess"],
    }

    for task, task_values in task_dict.items():
        if action in task_values:
            return task
    raise ValueError()


def run_polling_command(
    args: Dict[str, Any], cmd: str, client: Client
) -> Union[str, CommandResults]:
    """
    Performs polling interval to check status of task.
    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``cmd``
    :param client: The command that polled for an interval.

    :type client: ``Client``
    :param client: client object used to call respective polling commands.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get(INTERVAL_IN_SECONDS, 30))
    task_id = args.get(TASKID, EMPTY_STRING)
    if cmd == CHECK_TASK_STATUS_COMMAND:
        command_results = client.status_check(args)
    else:
        command_results = client.sandbox_submission_polling(args)
    statuses = [
        "failed",
        "queued",
        "rejected",
        "running",
        "succeeded",
        "waitForApproval",
    ]
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


def get_task_status(args: Dict[str, Any], client: Client) -> Union[str, CommandResults]:
    """
    check status of task.

    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    """
    return run_polling_command(args, CHECK_TASK_STATUS_COMMAND, client)


def get_sandbox_submission_status(
    args: Dict[str, Any], client: Client
) -> Union[str, CommandResults]:
    """
    call polling command to check status of sandbox submission.
    :type args: ``args``
    :param client: argument required for polling.
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    """
    return run_polling_command(args, SANDBOX_SUBMISSION_POLLING_COMMAND, client)


def test_module(client: Client) -> str:
    """
    Performs basic get request to check for connectivity to Trend XDR.
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    """
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.check_connectivity()
    if _is_pytmv1_error(resp.result_code):
        return FAILED_CONNECTIVITY
    return "ok"


def enable_or_disable_user_account(
    client: Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Enable allows the user to sign in to new application and browser sessions.
    Disable signs the user out of all active application and browser sessions,
    and prevents the user from signing in any new session.
    Supported IAM systems: Azure AD and Active Directory (on-premises).

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-enable-user-account
    or trendmicro-visionone-disable-user-account.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers: List[Dict[str, str]] = []
    for account in args["account_identifiers"]:
        account_identifiers.append(account)
    account_tasks: List[AccountTask] = []
    message: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    if command == ENABLE_USER_ACCOUNT_COMMAND:
        # Create account task list
        for account in account_identifiers:
            account_tasks.append(
                AccountTask(
                    account_name=account[ACCOUNT_NAME],
                    description=account.get(DESCRIPTION, ENABLE_ACCOUNT),
                )
            )
        # Make rest call
        resp = v1_client.enable_account(*account_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

    if command == DISABLE_USER_ACCOUNT_COMMAND:
        # Create account task list
        for account in account_identifiers:
            account_tasks.append(
                AccountTask(
                    account_name=account[ACCOUNT_NAME],
                    description=account.get(DESCRIPTION, DISABLE_ACCOUNT),
                )
            )
        # Make rest call
        resp = v1_client.disable_account(*account_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

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


def force_sign_out(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Signs the user out of all active application and browser sessions.
    Supported IAM systems: Azure AD

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers: List[Dict[str, str]] = []
    for account in args[ACCOUNT_IDENTIFIERS]:
        account_identifiers.append(account)
    account_tasks: List[AccountTask] = []
    message: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Create account task list
    for account in account_identifiers:
        account_tasks.append(
            AccountTask(
                account_name=account[ACCOUNT_NAME],
                description=account.get(DESCRIPTION, SIGN_OUT_ACCOUNT),
            )
        )
    # Make rest call
    resp = v1_client.sign_out_account(*account_tasks)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    # Add results to message to be sent to the War Room
    message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Signs the user out of all active application and browser sessions,
    and forces the user to create a new password during the next sign-in attempt.
    Supported IAM systems: Azure AD and Active Directory (on-premises)

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    account_identifiers: List[Dict[str, str]] = []
    for account in args[ACCOUNT_IDENTIFIERS]:
        account_identifiers.append(account)
    account_tasks: List[AccountTask] = []
    message: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Create account task list
    for account in account_identifiers:
        account_tasks.append(
            AccountTask(
                account_name=account[ACCOUNT_NAME],
                description=account.get(DESCRIPTION, FORCE_PASSWORD_RESET),
            )
        )
    # Make rest call
    resp = v1_client.reset_password_account(*account_tasks)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    # Add results to message to be sent to the War Room
    message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve information about the endpoint queried and
    sends the result to demisto war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    endpoint_list = argToList(args.get(ENDPOINT, EMPTY_STRING))
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    new_endpoint_data: List[Any] = []
    message: List[Dict[str, Any]] = []
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND

    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    try:
        v1_client.consume_endpoint_data(
            lambda endpoint_data: new_endpoint_data.append(endpoint_data),
            query_op,
            *endpoint_list,
        )
    except Exception as e:
        raise RuntimeError(f"Something went wrong while fetching endpoint data: {e}")
    # Load json objects to list
    endpoint_data_resp: List[Dict[str, Any]] = []
    for endpoint in new_endpoint_data:
        endpoint_data_resp.append(endpoint.dict())
    # Check if endpoint(s) returned
    if len(endpoint_data_resp) == 0:
        err_msg = f"No endpoint found. Please check endpoint {endpoint_list}."
        return_error(message=err_msg)
    else:
        message = endpoint_data_resp

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
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
    fields = args.get(FIELDS, EMPTY_STRING)
    start = args.get(START, EMPTY_STRING)
    end = args.get(END, EMPTY_STRING)
    top = args.get(TOP, EMPTY_STRING)
    select = args.get(SELECT, EMPTY_STRING).split(",")
    get_activity_data_count = args.get(GET_ACTIVITY_DATA_COUNT, FALSE)
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # List to contain endpoint activity data
    endpoint_activity_data: List[EndpointActivity] = []
    message: list[Any] = []
    # Should the data count be fetched
    if get_activity_data_count == TRUE:
        count = get_endpoint_activity_data_count(
            v1_client, start, end, query_op, top, select, fields
        )
        message.append({"total_count": count})
    # Make rest call
    try:
        v1_client.consume_endpoint_activity_data(
            lambda consumer: endpoint_activity_data.append(consumer),
            start_time=start,
            end_time=end,
            top=top,
            select=select,
            op=query_op,
            **fields,
        )
    except Exception as err:
        return_error(f"Something went wrong. {err}")

    # Check if endpoint activity data is returned
    if len(endpoint_activity_data) == 0:
        err_msg = "No endpoint data found. Please check queries provided."
        return_error(message=err_msg)
    # Parse endpoint activity data to message list and send to war room
    for activity in endpoint_activity_data:
        message.append(activity.dict())

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
    v1_client: pytmv1.Client, start, end, query_op, top, select, fields
) -> int:
    """
    Fetches endpoint activity data count.

    :return: sends data count to demisto war room.
    :rtype: ``int``
    """
    # Make rest call
    resp = v1_client.get_endpoint_activity_data_count(
        start_time=start,
        end_time=end,
        top=top,
        select=select,
        op=query_op,
        **fields,
    )
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Add results to message to be sent to the War Room
    return unwrap(resp.response).total_count


def get_email_activity_data(
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
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
    fields = args.get(FIELDS, EMPTY_STRING)
    start = args.get(START, EMPTY_STRING)
    end = args.get(END, EMPTY_STRING)
    top = args.get(TOP, EMPTY_STRING)
    select = args.get(SELECT, EMPTY_STRING).split(",")
    get_activity_data_count = args.get(GET_ACTIVITY_DATA_COUNT, FALSE)
    query_op = args.get(QUERY_OP, EMPTY_STRING)
    # Choose QueryOp Enum based on user choice
    if query_op.lower() == "or":
        query_op = pytmv1.QueryOp.OR
    elif query_op.lower() == "and":
        query_op = pytmv1.QueryOp.AND
    # List to populate email activity data
    email_activity_data: List[EmailActivity] = []
    message: list[Any] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Should the data count be fetched
    if get_activity_data_count == TRUE:
        count = get_email_activity_data_count(
            v1_client, start, end, query_op, top, select, fields
        )
        message.append({"total_count": count})
    # Make rest call
    try:
        v1_client.consume_email_activity_data(
            lambda consumer: email_activity_data.append(consumer),
            start_time=start,
            end_time=end,
            top=top,
            select=select,
            op=query_op,
            **fields,
        )
    except Exception as err:
        return_error(f"Something went wrong. {err}")
    # Check if an error occurred
    if len(email_activity_data) == 0:
        err_msg = "No email activity data found. Please check queries provided."
        return_error(message=err_msg)
    for activity in email_activity_data:
        message.append(activity.dict())

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
    v1_client: pytmv1.Client, start, end, query_op, top, select, fields
) -> int:
    """
    Fetches email activity data count.

    :return: sends activity data count to demisto war room.
    :rtype: ``int`
    """
    # Make rest call
    resp = v1_client.get_email_activity_data_count(
        start_time=start,
        end_time=end,
        top=top,
        select=select,
        op=query_op,
        **fields,
    )
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Return the total count
    return unwrap(resp.response).total_count


def add_or_remove_from_block_list(
    client: Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve data from the add or remove from block list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-add-to-block-list
    or trendmicro-visionone-remove-from-block-list.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects: List[Dict[str, str]] = []
    for block in args[BLOCK_OBJECTS]:
        block_objects.append(block)
    block_tasks: List[ObjectTask] = []
    message: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    if command == ADD_BLOCKLIST_COMMAND:
        # Create block task list
        for obj in block_objects:
            block_tasks.append(
                ObjectTask(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, ADD_BLOCKLIST),
                )
            )
        # Make rest call
        resp = v1_client.add_to_block_list(*block_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

    if command == REMOVE_BLOCKLIST_COMMAND:
        # Create unblock task list
        for obj in block_objects:
            block_tasks.append(
                ObjectTask(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, REMOVE_BLOCKLIST),
                )
            )
        # Make rest call
        resp = v1_client.remove_from_block_list(*block_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

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


def fetch_incidents(client: Client):
    """
    This function executes to get all workbench alerts by using
    startDateTime, endDateTime and sends the result to war room.
    """
    end = datetime.now(timezone.utc)
    days = int(demisto.params().get("first_fetch", ""))

    last_run = demisto.getLastRun()
    if last_run and "start_time" in last_run:
        start = datetime.fromisoformat(last_run.get("start_time", ""))
    else:
        start = end + timedelta(days=-days)
    # Fetch alerts
    alerts: List[Any] = client.get_workbench_histories(start, end)
    # List to store incidents that will be sent to the UI
    incidents: List[Dict[str, Any]] = []
    if alerts:
        # Alerts are fetched per created_date_time in descending order
        # Set the last_event to the created_date_time for the first alert
        # in alert list to get the latest created_date_time
        last_event = datetime.strptime(
            alerts[0].created_date_time, "%Y-%m-%dT%H:%M:%SZ"
        )
        for record in alerts:
            incident = {
                "name": record.model,
                "dbotMirrorId": record.id,
                "details": record.description if isinstance(record, SaeAlert) else None,
                "occurred": record.created_date_time,
                "severity": incident_severity_to_dbot_score(record.severity),
                "rawJSON": json.dumps(record),
            }
            incidents.append(incident)
            next_search = last_event + timedelta(0, 1)
            demisto.setLastRun({"start_time": next_search.isoformat()})

    demisto.incidents(incidents)
    return incidents


def quarantine_or_delete_email_message(
    client: Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve data from the quarantine or delete email message and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-quarantine-email-message
    or trendmicro-visionone-delete-email-message.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    email_identifiers: List[Dict[str, str]] = []
    for email in args[EMAIL_IDENTIFIERS]:
        email_identifiers.append(email)
    message: List[Dict[str, Any]] = []
    email_tasks: List[Union[EmailMessageIdTask, EmailMessageUIdTask]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    if command == QUARANTINE_EMAIL_COMMAND:
        # Create email task list
        for email in email_identifiers:
            if email.get(MESSAGE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageIdTask(
                        message_id=email[MESSAGE_ID],
                        description=email.get(DESCRIPTION, QUARANTINE_EMAIL),
                        mail_box=email.get(MAILBOX, EMPTY_STRING),
                    )
                )
            elif email.get(UNIQUE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageUIdTask(
                        unique_id=email[UNIQUE_ID],
                        description=email.get(DESCRIPTION, QUARANTINE_EMAIL),
                    )
                )
        # Make rest call
        resp = v1_client.quarantine_email_message(*email_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))

        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

    if command == DELETE_EMAIL_COMMAND:
        # Create email task list
        for email in email_identifiers:
            if email.get(MESSAGE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageIdTask(
                        message_id=email[MESSAGE_ID],
                        description=email.get(DESCRIPTION, DELETE_EMAIL),
                        mail_box=email.get(MAILBOX, EMPTY_STRING),
                    )
                )
            elif email.get(UNIQUE_ID, EMPTY_STRING):
                email_tasks.append(
                    EmailMessageUIdTask(
                        unique_id=email[UNIQUE_ID],
                        description=email.get(DESCRIPTION, DELETE_EMAIL),
                    )
                )
        # Make rest call
        resp = v1_client.delete_email_message(*email_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Restores a quarantined email message and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-quarantine-email-message
    or trendmicro-visionone-delete-email-message

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    email_identifiers: List[Dict[str, str]] = []
    for email in args[EMAIL_IDENTIFIERS]:
        email_identifiers.append(email)
    message: List[Dict[str, Any]] = []
    email_tasks: List[Union[EmailMessageIdTask, EmailMessageUIdTask]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    # Create email task list
    for email in email_identifiers:
        if email.get(MESSAGE_ID, EMPTY_STRING):
            email_tasks.append(
                EmailMessageIdTask(
                    message_id=email[MESSAGE_ID],
                    description=email.get(DESCRIPTION, RESTORE_EMAIL),
                    mail_box=email.get(MAILBOX, EMPTY_STRING),
                )
            )
        elif email.get(UNIQUE_ID, EMPTY_STRING):
            email_tasks.append(
                EmailMessageUIdTask(
                    unique_id=email[UNIQUE_ID],
                    description=email.get(DESCRIPTION, RESTORE_EMAIL),
                )
            )
        # Make rest call
        resp = v1_client.restore_email_message(*email_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Retrieve data from the isolate or restore endpoint connection and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type command: ``str``
    :param command: Either trendmicro-visionone-isolate-endpoint
    or trendmicro-visionone-restore-endpoint-connection

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    endpoint_identifiers: List[Dict[str, str]] = []
    for endpoint in args[ENDPOINT_IDENTIFIERS]:
        endpoint_identifiers.append(endpoint)
    message: List[Dict[str, Any]] = []
    endpt_tasks: List[EndpointTask] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    if command == ISOLATE_ENDPOINT_COMMAND:
        # Create endpoint task list
        for endpt in endpoint_identifiers:
            if endpt.get(ENDPOINT, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointTask(
                        endpoint_name=endpt[ENDPOINT],
                        description=endpt.get(DESCRIPTION, ISOLATE_ENDPOINT),
                    )
                )
            elif endpt.get(AGENT_GUID, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointTask(
                        agent_guid=endpt[AGENT_GUID],
                        description=endpt.get(DESCRIPTION, ISOLATE_ENDPOINT),
                    )  # type: ignore
                )
        # Make rest call
        resp = v1_client.isolate_endpoint(*endpt_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

    if command == RESTORE_ENDPOINT_COMMAND:
        # Create endpoint task list
        for endpt in endpoint_identifiers:
            if endpt.get(ENDPOINT, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointTask(
                        endpoint_name=endpt[ENDPOINT],
                        description=endpt.get(DESCRIPTION, RESTORE_ENDPOINT),
                    )
                )
            elif endpt.get(AGENT_GUID, EMPTY_STRING):
                endpt_tasks.append(
                    EndpointTask(
                        agent_guid=endpt[AGENT_GUID],
                        description=endpt.get(DESCRIPTION, RESTORE_ENDPOINT),
                    )  # type: ignore
                )
        # Make rest call
        resp = v1_client.restore_endpoint(*endpt_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        # Add results to message to be sent to the War Room
        message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Terminate the process running on the end point and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    process_identifiers: List[Dict[str, str]] = []
    for process in args[PROCESS_IDENTIFIERS]:
        process_identifiers.append(process)
    process_tasks: List[ProcessTask] = []
    message: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    # Create process task list
    for process in process_identifiers:
        if process.get(ENDPOINT):
            process_tasks.append(
                ProcessTask(
                    endpoint_name=process[ENDPOINT],
                    file_sha1=process[FILE_SHA1],
                    description=process.get(DESCRIPTION, TERMINATE_PROCESS),
                    file_name=process.get(FILE_NAME, EMPTY_STRING),
                )
            )
        elif process.get(AGENT_GUID):
            process_tasks.append(
                ProcessTask(
                    agent_guid=process[AGENT_GUID],
                    file_sha1=process[FILE_SHA1],
                    description=process.get(DESCRIPTION, TERMINATE_PROCESS),
                    file_name=process.get(FILE_NAME, EMPTY_STRING),
                )  # type: ignore
            )
    # Make rest call
    resp = v1_client.terminate_process(*process_tasks)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    # Add results to message to be sent to the War Room
    message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, command: str, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Add or Delete the exception object to exception list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

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
    block_objects: List[Dict[str, str]] = []
    for block in args[BLOCK_OBJECTS]:
        block_objects.append(block)
    excp_tasks: List[ObjectTask] = []
    message: Dict[str, Any] = {}
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    if command == ADD_EXCEPTION_LIST_COMMAND:
        # Create exception task list
        for obj in block_objects:
            excp_tasks.append(
                ObjectTask(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, ADD_EXCEPTION_LIST),
                )
            )
        # Make rest call
        resp = v1_client.add_to_exception_list(*excp_tasks)
        # Check if an error occurred
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        message = {
            "message": "success",
            "multi_response": [item.dict() for item in unwrap(resp.response).items],
        }

    if command == DELETE_EXCEPTION_LIST_COMMAND:
        # Create exception task list
        for obj in block_objects:
            excp_tasks.append(
                ObjectTask(
                    object_type=_get_ot_enum(obj[OBJECT_TYPE]),
                    object_value=obj[OBJECT_VALUE],
                    description=obj.get(DESCRIPTION, DELETE_EXCEPTION_LIST),
                )
            )
        # Make rest call
        resp = v1_client.remove_from_exception_list(*excp_tasks)
        # Check if an error occurred for each call
        if _is_pytmv1_error(resp.result_code):
            return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
        message = {
            "message": "success",
            "multi_response": [item.dict() for item in unwrap(resp.response).items],
        }
    # Get the total count of items in exception list
    exception_list_count = client.exception_list_count()
    # Add count of total exception items to message
    message["total_items"] = exception_list_count
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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Add suspicious object to suspicious list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects: List[Dict[str, Any]] = []
    for block in args[BLOCK_OBJECTS]:
        block_objects.append(block)

    suspicious_tasks: List[SuspiciousObjectTask] = []
    message: Dict[str, Any] = {}
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Create suspicious task list
    for block in block_objects:
        suspicious_tasks.append(
            SuspiciousObjectTask(
                object_type=_get_ot_enum(block[OBJECT_TYPE]),
                object_value=block[OBJECT_VALUE],
                scan_action=block.get(SCAN_ACTION, BLOCK),
                risk_level=block.get(RISK_LEVEL, MEDIUM),
                days_to_expiration=block.get(EXPIRY_DAYS, 30),
                description=block.get(DESCRIPTION, ADD_SUSPICIOUS),
            )
        )
    # Make rest call
    resp = v1_client.add_to_suspicious_list(*suspicious_tasks)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    # Get the total count of items in suspicious list
    suspicious_list_count = client.suspicious_list_count()
    # Add results to message to be sent to the War Room
    message = {
        "message": "success",
        "multi_response": [item.dict() for item in unwrap(resp.response).items],
        "total_items": suspicious_list_count,
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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Delete the suspicious object from suspicious list and
    sends the result to demist war room.

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    block_objects: List[Dict[str, str]] = []
    for block in args[BLOCK_OBJECTS]:
        block_objects.append(block)

    suspicious_tasks: List[ObjectTask] = []
    message: Dict[str, Any] = {}

    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Create suspicious task list
    for block in block_objects:
        suspicious_tasks.append(
            ObjectTask(
                object_type=_get_ot_enum(block[OBJECT_TYPE]),
                object_value=block[OBJECT_VALUE],
                description=block.get(DESCRIPTION, DELETE_SUSPICIOUS),
            )
        )
    # Make rest call
    resp = v1_client.remove_from_suspicious_list(*suspicious_tasks)
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    # Get the total count of items in suspicious list
    suspicious_list_count = client.suspicious_list_count()
    # Add results to message to be sent to the War Room
    message = {
        "message": "success",
        "multi_response": [item.dict() for item in unwrap(resp.response).items],
        "total_items": suspicious_list_count,
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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Get the status of file based on task id and
    sends the result to demist war room

    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    task_id = args.get(TASKID, EMPTY_STRING)
    message: Dict[str, Any] = {}
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.get_sandbox_submission_status(submit_id=task_id)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Add results to message to be sent to the War Room
    message = unwrap(resp.response).dict()

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Get the report of file based on report id and sends the result to demist war room
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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

    message: Dict[str, Any] = {}
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.get_sandbox_analysis_result(
        submit_id=report_id,
        poll=poll,
        poll_time_sec=poll_time_sec,
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Extract values on successful call
    reliability = demisto.params().get(INTEGRATION_RELIABILITY)
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
    file_entry = Common.File(sha256=sha256, md5=md5, sha1=sha1, dbot_score=dbot_score)
    # Add results to message to be sent to the War Room
    message = {
        "status": resp.result_code,
        "id": unwrap(resp.response).id,
        "type": unwrap(resp.response).type,
        "digest": unwrap(unwrap(resp.response).digest).dict(),
        "arguments": unwrap(resp.response).arguments,
        "risk_level": unwrap(resp.response).risk_level,
        "threat_types": unwrap(resp.response).threat_types,
        "true_file_type": unwrap(resp.response).true_file_type,
        "detection_names": unwrap(resp.response).detection_names,
        "analysis_completion_date_time": unwrap(
            resp.response
        ).analysis_completion_date_time,
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


def collect_file(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Collect forensic file and sends the result to demist war room
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    collect_files: List[Dict[str, str]] = []
    for file in args[COLLECT_FILES]:
        collect_files.append(file)
    # Create file task list
    file_tasks: List[FileTask] = []
    message: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Create file task list
    for file in collect_files:
        if file.get(ENDPOINT, EMPTY_STRING):
            file_tasks.append(
                FileTask(
                    endpoint_name=file[ENDPOINT],
                    file_path=file[FILE_PATH],
                    description=file.get(DESCRIPTION, COLLECT_FILE),
                )
            )
        elif file.get(AGENT_GUID, EMPTY_STRING):
            file_tasks.append(
                FileTask(
                    agent_guid=file[AGENT_GUID],
                    file_path=file[FILE_PATH],
                    description=file.get(DESCRIPTION, COLLECT_FILE),
                )  # type: ignore
            )
    # Make rest call
    resp = v1_client.collect_file(*file_tasks)
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))

    message = [item.dict() for item in unwrap(resp.response).items]

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
    client: Client, args: Dict[str, Any]
) -> Union[Any, CommandResults]:
    """
    Get the analysis report of file based on action id and sends
    the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.get_task_result(
        task_id=task_id,
        class_=CollectFileTaskResp,
        poll=poll,
        poll_time_sec=poll_time_sec,
    )
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Add results to message to be sent to the War Room
    message = unwrap(resp.response).dict()
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
    client: Client, args: Dict[str, Any]
) -> Union[Any, CommandResults]:
    """
    Get the analysis report of file based on action id and sends
    the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    # Create name for pdf report file to be downloaded
    name = "Trend_Micro_Sandbox_Analysis_Report"
    file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.pdf"

    # Make rest call
    resp = v1_client.download_sandbox_analysis_result(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
    )

    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Extract content value on successful call
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
    client: Client, args: Dict[str, Any]
) -> Union[Any, CommandResults]:
    """
    Downloads the Investigation Package of the specified object based on
    submission id and sends the file to demist war room where it can be downloaded.
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    # Create name for zip package to be downloaded
    name = "Sandbox_Investigation_Package"
    file_name = f"{name}_{datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%d:%H:%M:%S')}.zip"

    # Make rest call
    resp = v1_client.download_sandbox_investigation_package(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
    )

    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Extract content value on successful call
    data = unwrap(resp.response).content

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Downloads the suspicious object list associated to the specified object
    Note: Suspicious Object Lists are only available for objects with a high risk level
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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
    suspicious_objects: List[Dict[str, str]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.get_sandbox_suspicious_list(
        submit_id=submit_id, poll=poll, poll_time_sec=poll_time_sec
    )
    # Check if an error occurred
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Extract suspicious objects from response
    for item in unwrap(resp.response).items:
        suspicious_objects.append(item.dict())

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    submit file to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    file_path = args.get(FILE_PATH, EMPTY_STRING)
    file_name = args.get(FILE_NAME, EMPTY_STRING)
    # Optional Params
    document_pass = args.get(DOCUMENT_PASSWORD, EMPTY_STRING)
    archive_pass = args.get(ARCHIVE_PASSWORD, EMPTY_STRING)
    arguments = args.get(ARGUMENTS, EMPTY_STRING)
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Get file contents
    _file = requests.get(file_path, allow_redirects=True, timeout=30)
    # Make rest call
    resp = v1_client.submit_file_to_sandbox(
        file=_file.content,
        file_name=file_name,
        document_password=document_pass,
        archive_password=archive_pass,
        arguments=arguments,
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Add results to message to be sent to the War Room
    message = {
        "code": 202,
        "message": resp.result_code,
        "task_id": unwrap(resp.response).id,
        "digest": unwrap(resp.response).digest.dict(),
        "arguments": unwrap(resp.response).arguments,
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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    submit file entry to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Use entry ID to get file details from demisto
    file_ = demisto.getFilePath(entry)
    file_name = file_.get(NAME, EMPTY_STRING)
    file_path = file_.get(PATH, EMPTY_STRING)
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
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Add results to message to be sent to the War Room
    message = {
        "code": 202,
        "message": resp.result_code,
        "filename": file_name,
        "entry_id": entry,
        "file_path": file_path,
        "task_id": unwrap(resp.response).id,
        "digest": unwrap(resp.response).digest.dict(),
        "arguments": unwrap(resp.response).arguments,
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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    submit Urls to sandbox and send the result to demist war room
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    urls: List[str] = []
    # extract urls and add to urls list
    for url in args[URLS]:
        urls.append(url)
    submit_urls_resp: List[Dict[str, Any]] = []
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)

    # Make rest call
    resp = v1_client.submit_urls_to_sandbox(*urls)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.errors)}", error=str(resp.errors))
    for item in unwrap(resp.response).items:
        submit_urls_resp.append(item.dict())

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
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Fetch information for a specific alert and display in war room.
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id: str = args.get(WORKBENCH_ID, EMPTY_STRING)
    message: Dict[str, Any] = {}
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.get_alert_details(alert_id=workbench_id)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Extract values from response
    etag = unwrap(resp.response).etag
    alert = unwrap(resp.response).alert.dict()
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


def add_note(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Adds a note to an existing workbench alert
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    # Required Params
    workbench_id = args.get(WORKBENCH_ID, EMPTY_STRING)
    content = args.get(CONTENT, EMPTY_STRING)
    message: Dict[str, Any] = {}
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Make rest call
    resp = v1_client.add_alert_note(alert_id=workbench_id, note=content)
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
    # Add results to message to be sent to the War Room
    message = {
        "code": 201,
        "message": f"Note has been successfully added to {workbench_id}",
        "note_id": unwrap(resp.response).note_id(),
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


def update_status(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Updates the status of an existing workbench alert
    :type client: ``Client``
    :param client: client object used to initialize pytmv1 client.
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
    # Initialize pytmv1 client
    v1_client = _get_client(APP_NAME, client.api_key, client.base_url)
    # Choose Status Enum
    sts = status.upper()
    if sts not in InvestigationStatus.__members__:
        err_msg = f"Invalid investigation status ({status}) provided!"
        return_error(message=err_msg)
    # Assign enum status
    status = InvestigationStatus[sts]
    # Make rest call
    resp = v1_client.edit_alert_status(
        alert_id=workbench_id, status=status, if_match=if_match
    )
    # Check if an error occurred during rest call
    if _is_pytmv1_error(resp.result_code):
        return_error(message=f"{unwrap(resp.error).message}", error=str(resp.error))
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


def main():  # pragma: no cover
    try:
        """GLOBAL VARS"""
        params = demisto.params()

        base_url: Union[str, None] = params.get(URL)
        api_key = params.get(API_TOKEN).get("password")  # type: ignore
        proxy = params.get("proxy", False)
        verify = not params.get("insecure", False)

        assert base_url is not None
        client = Client(base_url, api_key, proxy, verify)

        command = demisto.command()
        demisto.debug(COMMAND_CALLED.format(command=command))
        args = demisto.args()

        if command == TEST_MODULE:
            return_results(test_module(client))

        elif command == FETCH_INCIDENTS:
            return_results(fetch_incidents(client))

        elif command in (ENABLE_USER_ACCOUNT_COMMAND, DISABLE_USER_ACCOUNT_COMMAND):
            return_results(enable_or_disable_user_account(client, command, args))

        elif command == FORCE_SIGN_OUT_COMMAND:
            return_results(force_sign_out(client, args))

        elif command == FORCE_PASSWORD_RESET_COMMAND:
            return_results(force_password_reset(client, args))

        elif command in (ADD_BLOCKLIST_COMMAND, REMOVE_BLOCKLIST_COMMAND):
            return_results(add_or_remove_from_block_list(client, command, args))

        elif command in (QUARANTINE_EMAIL_COMMAND, DELETE_EMAIL_COMMAND):
            return_results(quarantine_or_delete_email_message(client, command, args))

        elif command == RESTORE_EMAIL_COMMAND:
            return_results(restore_email_message(client, args))

        elif command in (ISOLATE_ENDPOINT_COMMAND, RESTORE_ENDPOINT_COMMAND):
            return_results(isolate_or_restore_connection(client, command, args))

        elif command == TERMINATE_PROCESS_COMMAND:
            return_results(terminate_process(client, args))

        elif command in (ADD_EXCEPTION_LIST_COMMAND, DELETE_EXCEPTION_LIST_COMMAND):
            return_results(add_or_delete_from_exception_list(client, command, args))

        elif command == ADD_SUSPICIOUS_LIST_COMMAND:
            return_results(add_to_suspicious_list(client, args))

        elif command == DELETE_SUSPICIOUS_LIST_COMMAND:
            return_results(delete_from_suspicious_list(client, args))

        elif command == GET_FILE_ANALYSIS_STATUS_COMMAND:
            return_results(get_file_analysis_status(client, args))

        elif command == GET_FILE_ANALYSIS_RESULT_COMMAND:
            return_results(get_file_analysis_result(client, args))

        elif command == GET_ENDPOINT_INFO_COMMAND:
            return_results(get_endpoint_info(client, args))

        elif command == COLLECT_FILE_COMMAND:
            return_results(collect_file(client, args))

        elif command == DOWNLOAD_COLLECTED_FILE_COMMAND:
            return_results(download_information_collected_file(client, args))

        elif command == FILE_TO_SANDBOX_COMMAND:
            return_results(submit_file_to_sandbox(client, args))

        elif command == FILE_ENTRY_TO_SANDBOX_COMMAND:
            return_results(submit_file_entry_to_sandbox(client, args))

        elif command == URLS_TO_SANDBOX_COMMAND:
            return_results(submit_urls_to_sandbox(client, args))

        elif command == SANDBOX_SUBMISSION_POLLING_COMMAND:
            if args.get(POLLING) == TRUE:
                cmd_res = get_sandbox_submission_status(args, client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(client.sandbox_submission_polling(args))

        elif command == DOWNLOAD_ANALYSIS_REPORT_COMMAND:
            return_results(download_analysis_report(client, args))

        elif command == DOWNLOAD_INVESTIGATION_PACKAGE_COMMAND:
            return_results(download_investigation_package(client, args))

        elif command == DOWNLOAD_SUSPICIOUS_OBJECT_LIST_COMMAND:
            return_results(download_suspicious_object_list(client, args))

        elif command == UPDATE_STATUS_COMMAND:
            return_results(update_status(client, args))

        elif command == GET_ALERT_DETAILS_COMMAND:
            return_results(get_alert_details(client, args))

        elif command == ADD_NOTE_COMMAND:
            return_results(add_note(client, args))

        elif command == CHECK_TASK_STATUS_COMMAND:
            if args.get(POLLING) == TRUE:
                cmd_res = get_task_status(args, client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(client.status_check(args))

        else:
            demisto.error(f"{command} command is not implemented.")
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as error:
        return return_error(
            f"Failed to execute {demisto.command()} command. Error: {str(error)}"
        )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
