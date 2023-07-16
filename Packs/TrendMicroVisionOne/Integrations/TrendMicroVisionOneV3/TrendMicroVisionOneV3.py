import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""IMPORTS"""
from CommonServerUserPython import *  # noqa: F401

import base64
import json
import re
import requests
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Union
from requests.models import HTTPError

"""CONSTANTS"""
USER_AGENT = "TMV1CortexXSOARApp/1.1"
VENDOR_NAME = "TrendMicroVisionOneV3"
URL = "url"
POST = "post"
GET = "get"
PATCH = "patch"
ARGUMENTS = "arguments"
ACCOUNT_NAME = "accountName"
AUTHORIZATION = "Authorization"
BEARER = "Bearer "
CONTENT_TYPE_JSON = "application/json"
EMPTY_STRING = ""
ASCII = "ascii"
API_TOKEN = "apikey"
VALUE_TYPE = "value_type"
TARGET_VALUE = "target_value"
DESCRIPTION = "description"
MESSAGE_ID = "messageId"
MAILBOX = "mailBox"
FIELD = "field"
ENDPOINT = "endpoint"
ENTRY_ID = "entry_id"
DATA = "data"
TYPE = "type"
VALUE = "value"
FILESHA = "file_sha1"
FILENAME = "filename"
CRITERIA = "criteria"
EXCEPTION_LIST = "exceptionList"
SUSPICIOUS_LIST = "suspiciousObjectList"
LAST_MODIFIED = "lastModified"
SCAN_ACTION = "scan_action"
RISK_LEVEL = "risk_level"
EXPIRYDAY = "expiry_days"
TASKID = "task_id"
REPORT_ID = "report_id"
FAILED = "failed"
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

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def http_request(
        self,
        method: str,
        url_suffix: str,
        json_data=None,
        params=None,
        headers=None,
        data=None,
    ) -> Any:
        """
        Override http_request method from BaseClient class. This method will print an error based on status code
        and exceptions.
        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.
        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.
        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.
        :type params: ``dict``
        :param params: URL parameters to specify the query.
        :type data: ``dict``
        :param data: The data to send in a 'POST' request.
        :return: response data
        :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        token = self.api_key
        # Headers will be passed in for certain actions
        # This header will be ignored in such cases
        if not headers:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": f"{CONTENT_TYPE_JSON};charset=utf-8",
            }

        try:
            response = self._http_request(
                method=method,
                full_url=f"{self.base_url}{url_suffix}",
                retries=3,
                json_data=json_data,
                params=params,
                headers=headers,
                resp_type="response",
                ok_codes=(200, 201, 202, 204, 207),
                data=data,
            )
            # Check if response has a status code of 207 and parse response through multi_status_check
            # to check for valid or invalid calls based on response status for the multi status response.
            if response.status_code == 207:
                self.multi_status_check(response.json())

        except DemistoException as error:
            demisto.error(error.message)
            return_error(error, error.message)
        if response.ok:
            demisto.info(
                SUCCESS_RESPONSE.format(
                    url=f"{self.base_url}{url_suffix}", status=response.status_code
                )
            )
            self.status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            if content_type.__contains__(CONTENT_TYPE_JSON):
                # Handle empty response
                if response.text == EMPTY_STRING:
                    return response
                else:
                    return response.json()
            else:
                return response

    def multi_status_check(self, response: List[Any]) -> List[Any]:
        """
        Check the response code for 207 multi status response
        and return an error if the status is 400, 403, 404, 500.
        :type response: ``dict``
        :return: error object with code, status and message
        :rtype: ``dict``
        """
        err_obj: Dict[str, Any] = {}
        success_codes = [200, 201, 202, 204]
        if response[0].get("status") not in success_codes:
            err_status = response[0].get("status", int)
            err_code = response[0].get("body", {}).get("error", {}).get("code", "")
            err_msg = response[0].get("body", {}).get("error", {}).get("message", "")

            err_obj["status"] = err_status
            err_obj["code"] = err_code
            err_obj["message"] = err_msg
            return return_error(err_obj)
        return response

    def status_check(self, data: Dict[str, Any]) -> Any:
        """
        Check the status of particular task.
        :type data: ``dict``
        :param method: Response data to received from the end point.
        :return: task status response data.
        :rtype: ``Any``
        """
        task_id = data.get(TASKID)
        query_params: Dict[str, Any] = {}
        response = self.http_request(
            GET, TASK_DETAIL_ENDPOINT.format(taskId=task_id), params=query_params
        )
        message = {
            "taskId": response.get("id"),
            "taskStatus": response.get("status"),
            "createdDateTime": response.get("createdDateTime"),
            "action": response.get("action"),
            "endpointName": response.get("endpointName"),
            "account": response.get("account"),
        }
        return CommandResults(
            readable_output=tableToMarkdown(
                "Status of task ", message, removeNull=True
            ),
            outputs_prefix=("VisionOne.Task_Status"),
            outputs_key_field="taskId",
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
        task_id = data.get(TASKID)
        submission_status_call = self.http_request(
            GET, GET_FILE_STATUS.format(taskId=task_id)
        )
        task_status = submission_status_call.get("status", "")
        error_code = submission_status_call.get("error", {}).get("code", "")
        error_message = submission_status_call.get("error", {}).get("message", "")
        file_entry = None
        if task_status == "succeeded":
            response = self.http_request(GET, GET_FILE_RESULT.format(reportId=task_id))
            risk = response.get("riskLevel", "")
            risk_score = self.incident_severity_to_dbot_score(risk)
            sha256 = response.get("digest", {}).get("sha256")
            md5 = response.get("digest", {}).get("md5")
            sha1 = response.get("digest", {}).get("sha1")
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
                "status_code": self.status,
                "taskStatus": task_status,
                "message": "success",
                "report_id": response.get("id", ""),
                "type": response.get("type", ""),
                "digest": response.get("digest", {}),
                "arguments": response.get("arguments", ""),
                "analysis_completion_time": response.get(
                    "analysisCompletionDateTime", ""
                ),
                "risk_level": response.get("riskLevel", ""),
                "detection_name_list": response.get("detectionNames", []),
                "threat_type_list": response.get("threatTypes", []),
                "file_type": response.get("trueFileType", ""),
                "DBotScore": {
                    "Score": dbot_score.score,
                    "Vendor": dbot_score.integration_name,
                    "Reliability": dbot_score.reliability,
                },
            }
        else:
            message = {
                "taskStatus": task_status,
                "task_id": task_id,
                "code": error_code,
                "message": error_message,
            }
        results = CommandResults(
            readable_output=tableToMarkdown(
                TABLE_SANDBOX_SUBMISSION_POLLING, message, removeNull=True
            ),
            outputs_prefix="VisionOne.Sandbox_Submission_Polling",
            outputs_key_field="report_id",
            outputs=message,
            indicator=file_entry,
        )
        return results

    def lookup_type(self, param: Any) -> str:
        # Regex expression for validating IPv4
        regex = (
            "(([0-9]|[1-9][0-9]|1[0-9][0-9]|"
            "2[0-4][0-9]|25[0-5])\\.){3}"
            "([0-9]|[1-9][0-9]|1[0-9][0-9]|"
            "2[0-4][0-9]|25[0-5])"
        )

        # Regex expression for validating IPv6
        regex1 = "((([0-9a-fA-F]){1,4})\\:){7}" + "([0-9a-fA-F]){1,4}"

        # Regex expression for validating MacAddress
        regex2 = "([0-9A-Fa-f]{2}[:-]){5}" + "([0-9A-Fa-f]{2})"

        # Regex expression for validating agentGuid
        regex3 = (
            "[0-9a-f]{8}-[0-9a-f]{4}-[1-5]"
            "[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
            "[0-9a-f]{12}"
        )

        p = re.compile(regex)
        p1 = re.compile(regex1)
        p2 = re.compile(regex2)
        p3 = re.compile(regex3)

        # Checking if it is a valid IPv4 addresses
        if re.search(p, param):
            return "ip"

        # Checking if it is a valid IPv6 addresses
        elif re.search(p1, param):
            return "ipv6"

        # Checking if it is a valid IPv6 addresses
        elif re.search(p2, param):
            return "macAddress"

        # Checking if it is a valid agenGuid
        elif re.search(p3, param):
            return "agentGuid"

        # Otherwise use hostname type
        return "endpointName"

    def get_paginated_results(self, response, headers) -> list:
        """
        Get the paginated results after initial API call
        :return: additional items list using skipToken.
        :rtype: ``list``
        """
        url = response.get("nextLink", "")
        results = []
        while url:
            req = urllib.request.Request(url=url, headers=headers)
            resp = json.loads(urllib.request.urlopen(req).read())
            url = resp.get("nextLink", "")
            results += resp["items"]
        return results

    def exception_list_count(self) -> int:
        """
        Gets the count of object present in exception list

        :return: number of exception object.
        :rtype: ``int``
        """
        token = self.api_key
        headers = {"Authorization": "Bearer " + token}
        query_params = {"top": 200}
        response = self.http_request(
            GET, ADD_OBJECT_TO_EXCEPTION_LIST, params=query_params, headers=headers
        )
        exception_count = self.get_paginated_results(response, headers)
        final_results = []
        final_results += response.get("items", [])
        final_results += exception_count
        return len(final_results)

    def suspicious_list_count(self) -> int:
        """
        Gets the count of object present in suspicious list
        :return: number of suspicious object.
        :rtype: ``int``
        """
        token = self.api_key
        headers = {"Authorization": "Bearer " + token}
        query_params = {"top": 200}
        response = self.http_request(
            GET, ADD_OBJECT_TO_SUSPICIOUS_LIST, params=query_params, headers=headers
        )
        suspicious_count = self.get_paginated_results(response, headers)
        final_results = []
        final_results += response.get("items", [])
        final_results += suspicious_count
        return len(final_results)

    def get_workbench_histories(
        self, start, end, dateTimeTarget, orderBy, investigationStatus
    ) -> list:
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
        query_params: Dict[str, Any] = {
            "startDateTime": f"{formatted_start}",
            "endDateTime": f"{formatted_end}",
            "dateTimeTarget": f"{dateTimeTarget}",
            "orderBy": f"{orderBy}",
        }
        token = self.api_key
        headers = {
            "Authorization": "Bearer " + token,
            "TMV1-Filter": f"investigationStatus eq '{investigationStatus}'",
        }

        response = self.http_request(
            GET, WORKBENCH_HISTORIES, params=query_params, headers=headers
        )
        additional_alerts = self.get_paginated_results(response, headers)
        final_results = []
        final_results += response.get("items", [])
        final_results += additional_alerts
        return final_results

    def incident_severity_to_dbot_score(self, severity: str):
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
    :param client: client object to use http_request.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get("interval_in_seconds", 30))
    task_id = args.get(TASKID, "")
    if cmd == CHECK_TASK_STATUS_COMMAND:
        command_results = client.status_check(args)
    else:
        command_results = client.sandbox_submission_polling(args)
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


def get_task_status(args: Dict[str, Any], client: Client) -> Union[str, CommandResults]:
    """
    check status of task.

    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``Client``
    :param client: client object to use http_request.
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
    :param client: client object to use http_request.
    """
    return run_polling_command(args, SANDBOX_SUBMISSION_POLLING_COMMAND, client)


def test_module(client: Client) -> Any:
    """
    Performs basic get request to get item samples.
    :type client: ``Client``
    :param client: client object to use http_request.
    """
    client.http_request("GET", ADD_OBJECT_TO_EXCEPTION_LIST)
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
    account_name = args.get(ACCOUNT_NAME)
    description = args.get(DESCRIPTION)
    body = [{"accountName": f"{account_name}", "description": f"{description}"}]
    if command == ENABLE_USER_ACCOUNT_COMMAND:
        response = client.http_request(POST, ENABLE_USER_ACCOUNT, data=json.dumps(body))
    if command == DISABLE_USER_ACCOUNT_COMMAND:
        response = client.http_request(
            POST, DISABLE_USER_ACCOUNT, data=json.dumps(body)
        )

    resp_headers = response[0].get("headers", {})[0].get("value", "").split("/")
    task_id = resp_headers[-1]
    message = {"status_code": response[0].get("status", int), "taskId": task_id}
    results = CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.User_Account",
        outputs_key_field="taskId",
        outputs=message,
    )
    return results


def force_sign_out(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
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
    account_name = args.get(ACCOUNT_NAME)
    description = args.get(DESCRIPTION)
    body = [{"accountName": f"{account_name}", "description": f"{description}"}]
    response = client.http_request(POST, FORCE_SIGN_OUT, data=json.dumps(body))
    resp_headers = response[0].get("headers", {})[0].get("value", "").split("/")
    task_id = resp_headers[-1]
    message = {"status_code": response[0].get("status", int), "taskId": task_id}
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[FORCE_SIGN_OUT_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Force_Sign_Out",
        outputs_key_field="taskId",
        outputs=message,
    )
    return results


def force_password_reset(
    client: Client, args: Dict[str, Any]
) -> Union[str, CommandResults]:
    """
    Signs the user out of all active application and browser sessions,
    and forces the user to create a new password during the next sign-in attempt.
    Supported IAM systems: Azure AD and Active Directory (on-premises)

    :type client: ``Client``
    :param client: client object to use http_request.

    :type args: ``dict``
    :param args: args object to fetch the argument data.

    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    account_name = args.get(ACCOUNT_NAME)
    description = args.get(DESCRIPTION)
    body = [{"accountName": f"{account_name}", "description": f"{description}"}]
    response = client.http_request(POST, FORCE_PASSWORD_RESET, data=json.dumps(body))
    resp_headers = response[0].get("headers", {})[0].get("value", "").split("/")
    task_id = resp_headers[-1]
    message = {"status_code": response[0].get("status", int), "taskId": task_id}
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[FORCE_PASSWORD_RESET_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Force_Password_Reset",
        outputs_key_field="taskId",
        outputs=message,
    )
    return results


def get_endpoint_info(
    client: Client, args: Dict[str, Any]
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

    value = args.get(ENDPOINT)
    field = client.lookup_type(value)

    token = client.api_key
    query_params: Dict[str, Any] = {"top": 50}
    headers = {
        "Authorization": f"Bearer {token}",
        "TMV1-Query": f"{field} eq '{value}'",
    }

    response = client.http_request(
        GET, GET_ENDPOINT_INFO_ENDPOINT, params=query_params, headers=headers
    )
    additional_endpoints = client.get_paginated_results(response, headers)
    final_results = []
    final_results += response.get("items", [])
    final_results += additional_endpoints
    if not final_results:
        return_error("No endpoint found for the query provided.")
    endpoint_data = {
        "status": "success",
        "logonAccount": final_results[0].get("loginAccount", "").get("value", ""),
        "hostname": final_results[0].get("endpointName", "").get("value", ""),
        "macAddr": final_results[0].get("macAddress", {}).get("value", ""),
        "ip": final_results[0].get("ip", {}).get("value", [])[0],
        "osName": final_results[0].get("osName", ""),
        "osVersion": final_results[0].get("osVersion", ""),
        "osDescription": final_results[0].get("osDescription", ""),
        "productCode": final_results[0].get("productCode", ""),
        "agentGuid": final_results[0].get("agentGuid", ""),
        "installedProductCodes": final_results[0].get("installedProductCodes", [])[0],
    }

    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ENDPOINT_INFO_COMMAND], endpoint_data, removeNull=True
        ),
        outputs_prefix="VisionOne.Endpoint_Info",
        outputs_key_field="hostname",
        outputs=endpoint_data,
    )
    return results


def add_delete_block_list_mapping(data: List[dict]) -> Dict[str, Any]:
    """
    Mapping add to block list response data.

    :type data: ``dict``
    :param data: Response data to received from the end point.

    :return: mapped response data.
    :rtype: ``dict``
    """
    status = data[0].get("status", "")
    resp_headers = data[0].get("headers", [])
    task_list = resp_headers[0].get("value").split("/")
    task_id = task_list[-1]
    resp_msg = "success"
    return {"status": status, "taskId": task_id, "message": resp_msg}


def add_or_remove_from_block_list(
    client: Client, command: str, args: Dict[str, Any]
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
    value_type = args.get(VALUE_TYPE)
    target_value = args.get(TARGET_VALUE)
    query_params: Dict[str, Any] = {}
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    body = [
        {
            "description": f"{value_type} that needs to be blocked/unblocked",
            f"{value_type}": f"{target_value}",
        }
    ]
    if command == ADD_BLOCKLIST_COMMAND:
        response = client.http_request(
            POST, ADD_BLOCKLIST_ENDPOINT, params=query_params, data=json.dumps(body)
        )
    if command == REMOVE_BLOCKLIST_COMMAND:
        response = client.http_request(
            POST, REMOVE_BLOCKLIST_ENDPOINT, params=query_params, data=json.dumps(body)
        )

    mapping_data = add_delete_block_list_mapping(response)
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[command], mapping_data, removeNull=True
        ),
        outputs_prefix="VisionOne.BlockList",
        outputs_key_field="taskId",
        outputs=mapping_data,
    )
    return results


def fetch_incidents(client: Client):
    """
    This function executes to get all workbench alerts by using
    startDateTime, endDateTime, dateTimeTarget, orderBy and
    TMV1-Filter
    """
    end = datetime.now(timezone.utc)
    dateTimeTarget = "createdDateTime"
    orderBy = "createdDateTime desc"
    investigationStatus = "New"
    days = int(demisto.params().get("first_fetch"))

    last_run = demisto.getLastRun()
    if last_run and "start_time" in last_run:
        start = datetime.fromisoformat(last_run.get("start_time"))
    else:
        start = end + timedelta(days=-days)

    alerts: List[Any] = []
    alerts.extend(
        client.get_workbench_histories(
            start, end, dateTimeTarget, orderBy, investigationStatus
        )
    )

    incidents = []
    if alerts:
        for record in alerts:
            incident = {
                "name": record.get("model"),
                "occurred": record.get("createdDateTime"),
                "severity": client.incident_severity_to_dbot_score(
                    record.get("severity")
                ),
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


def quarantine_delete_email_mapping(data: List[Any]) -> Dict[str, Any]:
    """
    Mapping quarantine email message response data.

    :type data: ``dict``
    :param method: Response data to received from the end point.

    :return: mapped response data.
    :rtype: ``dict``
    """
    status = data[0].get("status", {})
    resp_headers = data[0].get("headers", [])[0]
    task_id = None
    if resp_headers:
        task_list = resp_headers.get("value").split("/")
        task_id = task_list[-1]
    return {"status": status, "taskId": task_id}


def quarantine_or_delete_email_message(
    client: Client, command: str, args: Dict[str, Any]
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
    messageId = args.get(MESSAGE_ID)
    mailBox = args.get(MAILBOX)
    description = args.get(DESCRIPTION)
    uniqueId = args.get(UNIQUE_ID)
    query_params: Dict[str, Any] = {}
    if not description:
        description = EMPTY_STRING
    if not mailBox:
        mailBox = EMPTY_STRING
    if command == QUARANTINE_EMAIL_COMMAND:
        if uniqueId:
            body = [{"description": f"{description}", "uniqueId": f"{uniqueId}"}]
        else:
            body = [
                {
                    "description": f"{description}",
                    "messageId": f"{messageId}",
                    "mailBox": f"{mailBox}",
                }
            ]

        response = client.http_request(
            POST, QUARANTINE_EMAIL_ENDPOINT, params=query_params, data=json.dumps(body)
        )

    elif command == DELETE_EMAIL_COMMAND:
        if uniqueId:
            body = [{"description": f"{description}", "uniqueId": f"{uniqueId}"}]
        else:
            body = [
                {
                    "description": f"{description}",
                    "messageId": f"{messageId}",
                    "mailBox": f"{mailBox}",
                }
            ]

        response = client.http_request(
            POST, DELETE_EMAIL_ENDPOINT, params=query_params, data=json.dumps(body)
        )

    mapping_data = quarantine_delete_email_mapping(response)
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[command], mapping_data, removeNull=True
        ),
        outputs_prefix="VisionOne.Email",
        outputs_key_field="taskId",
        outputs=mapping_data,
    )
    return results


def isolate_restore_endpoint_mapping(data: List[dict]) -> Dict[str, Any]:
    """
    Mapping isolate endpoint and restore endpoint response data.

    :type data: ``dict``
    :param method: Response data to received from the end point.

    :return: mapped response data.
    :rtype: ``dict``
    """
    value = data[0].get("headers", [])[0].get("value", "")
    task_id = value.split("/")[-1]
    task_status = data[0].get("status", "")
    return {"taskId": task_id, "taskStatus": task_status}


def isolate_or_restore_connection(
    client: Client, command: str, args: Dict[str, str]
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
    value = args.get(ENDPOINT)
    field = client.lookup_type(value)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    body = [{"description": description, f"{field}": f"{value}"}]
    if command == ISOLATE_ENDPOINT_COMMAND:
        response = client.http_request(
            POST, ISOLATE_CONNECTION_ENDPOINT, data=json.dumps(body)
        )

    elif command == RESTORE_ENDPOINT_COMMAND:
        response = client.http_request(
            POST, RESTORE_CONNECTION_ENDPOINT, data=json.dumps(body)
        )

    mapping_data = isolate_restore_endpoint_mapping(response)

    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[command], mapping_data, removeNull=True
        ),
        outputs_prefix="VisionOne.Endpoint_Connection",
        outputs_key_field="taskId",
        outputs=mapping_data,
    )
    return results


def terminate_process(
    client: Client, args: Dict[str, Any]
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
    value = args.get(ENDPOINT)
    field = client.lookup_type(value)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    file_sha1 = args.get(FILESHA)
    filename = args.get(FILENAME)
    query_params: Dict[str, Any] = {}
    body = [
        {
            "description": f"{description}",
            f"{field}": f"{value}",
            "fileSha1": f"{file_sha1}",
            "fileName": f"{filename}",
        }
    ]
    response = client.http_request(
        POST, TERMINATE_PROCESS_ENDPOINT, params=query_params, data=json.dumps(body)
    )

    value = response[0].get("headers", [])[0].get("value", "")
    task_id = value.split("/")[-1]
    task_status = response[0].get("status", int)
    message = {"taskId": task_id, "taskStatus": task_status}
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_TERMINATE_PROCESS, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Terminate_Process",
        outputs_key_field="taskId",
        outputs=message,
    )
    return results


def add_or_delete_from_exception_list(
    client: Client, command: str, args: Dict[str, Any]
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
    field = args.get(TYPE)
    value = args.get(VALUE)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    query_params: Dict[str, Any] = {}
    if command == ADD_EXCEPTION_LIST_COMMAND:
        body = [{f"{field}": f"{value}", "description": f"{description}"}]
        response = client.http_request(
            POST,
            ADD_OBJECT_TO_EXCEPTION_LIST,
            params=query_params,
            data=json.dumps(body),
        )

    elif command == DELETE_EXCEPTION_LIST_COMMAND:
        body = [{f"{field}": f"{value}"}]
        response = client.http_request(
            POST,
            DELETE_OBJECT_FROM_EXCEPTION_LIST,
            params=query_params,
            data=json.dumps(body),
        )
    status_code = response[0]["status"]
    exception_list = client.exception_list_count()

    message = {
        "message": "success",
        "status_code": status_code,
        "total_items": exception_list,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(table_name[command], message, removeNull=True),
        outputs_prefix="VisionOne.Exception_List",
        outputs_key_field="message",
        outputs=message,
    )
    return results


def add_to_suspicious_list(
    client: Client, args: Dict[str, Any]
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
    field = args.get(TYPE)
    value = args.get(VALUE)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    scan_action = args.get(SCAN_ACTION)
    query_params: Dict[str, Any] = {}
    if scan_action and scan_action not in ("log", "block"):
        return_error(PARAMETER_ISSUE.format(param=SCAN_ACTION))
    risk_level = args.get(RISK_LEVEL)
    if risk_level and risk_level not in ("high", "medium", "low"):
        return_error(PARAMETER_ISSUE.format(param=RISK_LEVEL))
    expiry = args.get(EXPIRYDAY)
    if not expiry:
        expiry = 7
    body = [
        {
            f"{field}": f"{value}",
            "description": description,
            "scanAction": scan_action,
            "riskLevel": risk_level,
            "daysToExpiration": expiry,
        }
    ]
    response = client.http_request(
        POST, ADD_OBJECT_TO_SUSPICIOUS_LIST, params=query_params, data=json.dumps(body)
    )
    status_code = response[0]["status"]
    suspicious_list = client.suspicious_list_count()

    message = {
        "message": "success",
        "status_code": status_code,
        "total_items": suspicious_list,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[ADD_SUSPICIOUS_LIST_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Suspicious_List",
        outputs_key_field="message",
        outputs=message,
    )
    return results


def delete_from_suspicious_list(
    client: Client, args: Dict[str, Any]
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
    field = args.get(TYPE)
    value = args.get(VALUE)
    body = [{f"{field}": value}]
    query_params: Dict[str, Any] = {}
    response = client.http_request(
        POST,
        DELETE_OBJECT_FROM_SUSPICIOUS_LIST,
        params=query_params,
        data=json.dumps(body),
    )
    status_code = response[0]["status"]
    suspicious_list = client.suspicious_list_count()

    message = {
        "message": "success",
        "status_code": status_code,
        "total_items": suspicious_list,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[DELETE_SUSPICIOUS_LIST_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Suspicious_List",
        outputs_key_field="message",
        outputs=message,
    )
    return results


def get_file_analysis_status(
    client: Client, args: Dict[str, Any]
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
    task_id = args.get(TASKID)
    response = client.http_request(GET, GET_FILE_STATUS.format(taskId=task_id))
    message = {
        "status": response.get("status"),
        "id": response.get("id", ""),
        "action": response.get("action", ""),
        "error": response.get("error", {}),
        "createdDateTime": response.get("createdDateTime", ""),
        "lastActionDateTime": response.get("lastActionDateTime", ""),
        "resourceLocation": response.get("resourceLocation", ""),
        "isCached": response.get("isCached", ""),
        "digest": response.get("digest", {}),
        "arguments": response.get("arguments", ""),
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_GET_FILE_ANALYSIS_STATUS, message, removeNull=True
        ),
        outputs_prefix="VisionOne.File_Analysis_Status",
        outputs_key_field="message",
        outputs=message,
    )
    return results


def get_file_analysis_result(
    client: Client, args: Dict[str, Any]
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
    report_id = args.get(REPORT_ID)
    response = client.http_request(GET, GET_FILE_RESULT.format(reportId=report_id))
    risk = response.get("riskLevel", "")
    risk_score = client.incident_severity_to_dbot_score(risk)
    sha256 = response.get("digest", {}).get("sha256")
    md5 = response.get("digest", {}).get("md5")
    sha1 = response.get("digest", {}).get("sha1")
    reliability = demisto.params().get("integrationReliability")
    dbot_score = Common.DBotScore(
        indicator=sha256,
        indicator_type=DBotScoreType.FILE,
        integration_name=VENDOR_NAME,
        score=risk_score,
        reliability=reliability,
    )
    file_entry = Common.File(sha256=sha256, md5=md5, sha1=sha1, dbot_score=dbot_score)
    message = {
        "status_code": client.status,
        "message": "success",
        "report_id": response.get("id", ""),
        "type": response.get("type", ""),
        "digest": response.get("digest", ""),
        "arguments": response.get("arguments", ""),
        "analysisCompletionDateTime": response.get("analysisCompletionDateTime", ""),
        "riskLevel": response.get("riskLevel", ""),
        "detectionNames": response.get("detectionNames", []),
        "threatTypes": response.get("threatTypes", []),
        "trueFileType": response.get("trueFileType", ""),
        "DBotScore": {
            "Score": dbot_score.score,
            "Vendor": dbot_score.integration_name,
            "Reliability": dbot_score.reliability,
        },
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_GET_FILE_ANALYSIS_RESULT, message, removeNull=True
        ),
        outputs_prefix="VisionOne.File_Analysis_Report",
        outputs_key_field="message",
        outputs=message,
        indicator=file_entry,
    )
    return results


def collect_file(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Collect forensic file and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    value = args.get(ENDPOINT)
    field = client.lookup_type(value)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    file_path = args.get(FILE_PATH)
    query_params: Dict[str, Any] = {}
    body = [{"description": description, f"{field}": value, "filePath": file_path}]
    response = client.http_request(
        POST, COLLECT_FORENSIC_FILE, params=query_params, data=json.dumps(body)
    )[0]
    task_status = response.get("status", {})
    task_id = None
    if task_status == 202:
        resp_headers = response.get("headers", [])[0]
        task_list = resp_headers.get("value").split("/")
        task_id = task_list[-1]
    error = response.get("body", {}).get("error", {})
    message = {"taskId": task_id, "taskStatus": task_status, "error": error}
    results = CommandResults(
        readable_output=tableToMarkdown(TABLE_COLLECT_FILE, message, removeNull=True),
        outputs_prefix="VisionOne.Collect_Forensic_File",
        outputs_key_field="taskId",
        outputs=message,
    )
    return results


def download_information_collected_file(
    client: Client, args: Dict[str, Any]
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
    task_id = args.get(TASKID)
    query_params: Dict[str, Any] = {}
    response = client.http_request(
        GET,
        DOWNLOAD_INFORMATION_COLLECTED_FILE.format(taskId=task_id),
        params=query_params,
    )
    message = {
        "taskId": response.get("id"),
        "status": response.get("status"),
        "createdDateTime": response.get("createdDateTime"),
        "lastActionDateTime": response.get("lastActionDateTime"),
        "description": response.get("description"),
        "action": response.get("action"),
        "account": response.get("account"),
        "agentGuid": response.get("agentGuid"),
        "endpointName": response.get("endpointName"),
        "filePath": response.get("filePath"),
        "fileSha1": response.get("fileSha1"),
        "fileSha256": response.get("fileSha256"),
        "fileSize": response.get("fileSize"),
        "resourceLocation": response.get("resourceLocation"),
        "expiredDateTime": response.get("expiredDateTime"),
        "password": response.get("password"),
    }
    return CommandResults(
        readable_output=tableToMarkdown(
            "Download information for collected file ", message, removeNull=True
        ),
        outputs_prefix=("VisionOne.Download_Information_For_Collected_Forensic_File"),
        outputs_key_field="resourceLocation",
        outputs=message,
    )


def download_analysis_report(
    client: Client, args: Dict[str, Any]
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
    submission_id = args.get(SUBMISSION_ID)
    file_name = args.get(FILE_NAME)
    # If a file name is not provided, default value
    # of Sandbox_Analysis_Report is set for the pdf.
    if not file_name:
        file_name = "Sandbox_Analysis_Report.pdf"
    query_params: Dict[str, Any] = {}
    token = client.api_key
    headers = {AUTHORIZATION: f"{BEARER} {token}"}
    response = requests.get(
        f"{client.base_url}"
        + DOWNLOAD_ANALYSIS_REPORT.format(submissionId=submission_id),
        params=query_params,
        headers=headers,
    )
    data = response.content
    code = response.status_code
    resp_msg = "Please select download to start download"
    # fileResult takes response data and creates a file with
    # the specified extension that can be downloaded in the war room
    output_file = fileResult(f"{file_name}", data, file_type=EntryType.ENTRY_INFO_FILE)
    message = {"submissionId": submission_id, "code": code, "message": resp_msg}
    results = [
        output_file,
        CommandResults(
            readable_output=tableToMarkdown(
                TABLE_DOWNLOAD_ANALYSIS_REPORT, message, removeNull=True
            ),
            outputs_prefix="VisionOne.Download_Analysis_Report",
            outputs_key_field="submissionId",
            outputs=message,
        ),
    ]
    return results


def download_investigation_package(
    client: Client, args: Dict[str, Any]
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
    submission_id = args.get(SUBMISSION_ID)
    file_name = args.get(FILE_NAME)
    # If a file name is not provided, default value of
    # Sandbox_Investigation_Package is set for the package.
    if not file_name:
        file_name = "Sandbox_Investigation_Package.zip"
    query_params: Dict[str, Any] = {}
    token = client.api_key
    headers = {AUTHORIZATION: f"{BEARER} {token}"}
    response = requests.get(
        f"{client.base_url}"
        + DOWNLOAD_INVESTIGATION_PACKAGE.format(submissionId=submission_id),
        params=query_params,
        headers=headers,
    )
    data = response.content
    code = response.status_code
    resp_msg = "Please select download to start download"
    # fileResult takes response data and creates a file with
    # the specified extension that can be downloaded in the war room
    output_file = fileResult(f"{file_name}", data, file_type=EntryType.ENTRY_INFO_FILE)
    message = {"submissionId": submission_id, "code": code, "message": resp_msg}
    results = [
        output_file,
        CommandResults(
            readable_output=tableToMarkdown(
                TABLE_DOWNLOAD_INVESTIGATION_PACKAGE, message, removeNull=True
            ),
            outputs_prefix="VisionOne.Download_Investigation_Package",
            outputs_key_field="submissionId",
            outputs=message,
        ),
    ]
    return results


def download_suspicious_object_list(
    client: Client, args: Dict[str, Any]
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
    submission_id = args.get(SUBMISSION_ID)
    query_params: Dict[str, Any] = {}
    token = client.api_key
    headers = {AUTHORIZATION: f"{BEARER} {token}"}
    response = client.http_request(
        GET,
        DOWNLOAD_SUSPICIOUS_OBJECT_LIST.format(submissionId=submission_id),
        params=query_params,
        headers=headers,
    )
    message = {
        "code": client.status,
        "riskLevel": response.get("items", [])[0].get("riskLevel", ""),
        "analysisCompletionDateTime": response.get("items", [])[0].get(
            "analysisCompletionDateTime", ""
        ),
        "expiredDateTime": response.get("items", [])[0].get("expiredDateTime", ""),
        "rootSha1": response.get("items", [])[0].get("rootSha1", ""),
        "ip": response.get("items", [])[0].get("ip", ""),
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_DOWNLOAD_SUSPICIOUS_OBJECT_LIST, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Download_Suspicious_Object_list",
        outputs_key_field="riskLevel",
        outputs=message,
    )
    return results


def submit_file_to_sandbox(
    client: Client, args: Dict[str, Any]
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
    query_params: Dict[str, Any] = {}
    data = {}
    file_path = args.get(FILE_PATH)
    file_name = args.get(FILE_NAME)
    document_pass = args.get(DOCUMENT_PASSWORD)
    if document_pass:
        data["documentPassword"] = base64.b64encode(document_pass.encode(ASCII)).decode(
            ASCII
        )
    archive_pass = args.get(ARCHIVE_PASSWORD)
    if archive_pass:
        data["archivePassword"] = base64.b64encode(archive_pass.encode(ASCII)).decode(
            ASCII
        )
    arguments = args.get(ARGUMENTS)
    if arguments:
        data["arguments"] = arguments
    token = client.api_key
    headers = {AUTHORIZATION: f"{BEARER} {token}"}
    try:
        file_content = requests.get(file_path, allow_redirects=True)  # type: ignore
        files = {
            "file": (file_name, file_content.content, "application/x-zip-compressed")
        }
        result = requests.post(
            f"{client.base_url}{SUBMIT_FILE_TO_SANDBOX}",
            params=query_params,
            headers=headers,
            data=data,
            files=files,
        )
        result.raise_for_status()
    except HTTPError as http_err:
        demisto.error(http_err)
        return_error(http_err)
    except Exception as err:
        demisto.error(err)
        return_error(err)
    else:
        response = result.json()

    message = {
        "message": "success",
        "code": f"{result.status_code}",
        "task_id": response.get("id", ""),
        "digest": response.get("digest", ""),
        "arguments": response.get("arguments", ""),
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_SUBMIT_FILE_TO_SANDBOX, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Submit_File_to_Sandbox",
        outputs_key_field="message",
        outputs=message,
    )
    return results


def submit_file_entry_to_sandbox(
    client: Client, args: Dict[str, Any]
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
    entry = args.get(ENTRY_ID)
    file_ = demisto.getFilePath(entry)
    file_name = file_.get("name")
    file_path = file_.get("path")
    archive_pass = args.get(ARCHIVE_PASSWORD)
    document_pass = args.get(DOCUMENT_PASSWORD)
    query_params: Dict[Any, Any] = {}
    headers = {AUTHORIZATION: f"{BEARER} {client.api_key}"}
    with open(file_path, "rb") as f:
        contents = f.read()
    data = {}
    if document_pass:
        data["documentPassword"] = base64.b64encode(document_pass.encode(ASCII)).decode(
            ASCII
        )
    if archive_pass:
        data["archivePassword"] = base64.b64encode(archive_pass.encode(ASCII)).decode(
            ASCII
        )
    files = {"file": (f"{file_name}", contents, "application/octet-stream")}
    try:
        result = requests.post(
            f"{client.base_url}{SUBMIT_FILE_TO_SANDBOX}",
            params=query_params,
            headers=headers,
            data=data,
            files=files,
        )
        result.raise_for_status()
    except HTTPError as http_err:
        demisto.error(http_err)
        return_error(http_err)
    except Exception as err:
        demisto.error(err)
        return_error(err)
    response = result.json()
    message = {
        "filename": file_name,
        "entryId": entry,
        "file_path": file_.get("path", ""),
        "message": "Success",
        "code": "Success",
        "task_id": response.get("id", ""),
        "digest": response.get("digest", ""),
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Submit_File_Entry_to_Sandbox",
        outputs_key_field="entryId",
        outputs=message,
    )
    return results


def add_note(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Adds a note to an existing workbench alert
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    workbench_id = args.get(WORKBENCH_ID)
    content = args.get(CONTENT)

    body = {"content": content}
    query_params: Dict[str, Any] = {}
    token = client.api_key
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json;charset=utf-8",
    }
    response = requests.post(
        f"{client.base_url}" + ADD_NOTE_ENDPOINT.format(alertId=workbench_id),
        params=query_params,
        headers=headers,
        data=json.dumps(body),
    )
    response_code = response.status_code
    location = response.headers.get("Location", "").split("/")
    note_id = location[-1]
    resp_msg = "success"
    message = {
        "Workbench_Id": workbench_id,
        "code": response_code,
        "note_id": note_id,
        "message": resp_msg,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(TABLE_ADD_NOTE, message, removeNull=True),
        outputs_prefix="VisionOne.Add_Note",
        outputs_key_field="note_id",
        outputs=message,
    )
    return results


def update_status(client: Client, args: Dict[str, Any]) -> Union[str, CommandResults]:
    """
    Updates the status of an existing workbench alert
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    workbench_id = args.get(WORKBENCH_ID)
    status = args.get(STATUS)

    if status == "new":
        status = NEW
    elif status == "in progress":
        status = IN_PROGRESS
    elif status == "true positive":
        status = RESOLVED_TRUE_POSITIVE
    elif status == "false positive":
        status = RESOLVED_FALSE_POSITIVE

    query_params: Dict[str, Any] = {}
    body = {"investigationStatus": status}
    client.http_request(
        PATCH,
        UPDATE_STATUS_ENDPOINT.format(workbenchId=workbench_id),
        params=query_params,
        data=json.dumps(body),
    )

    response_code = client.status
    response_msg = "Alert status changed successfully"
    message = {
        "Workbench_Id": workbench_id,
        "code": response_code,
        "message": response_msg,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(TABLE_UPDATE_STATUS, message, removeNull=True),
        outputs_prefix="VisionOne.Update_Status",
        outputs_key_field="Workbench_Id",
        outputs=message,
    )
    return results


def main():  # pragma: no cover
    try:
        """GLOBAL VARS"""
        params = demisto.params()

        base_url = params.get(URL)
        api_key = params.get(API_TOKEN).get("password")
        proxy = params.get("proxy", False)
        verify = not params.get("insecure", False)

        client = Client(base_url, api_key, proxy, verify)

        command = demisto.command()
        demisto.debug(COMMAND_CALLED.format(command=command))
        args = demisto.args()

        if command == "test-module":
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

        elif command == SANDBOX_SUBMISSION_POLLING_COMMAND:
            if args.get("polling") == "true":
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

        elif command == ADD_NOTE_COMMAND:
            return_results(add_note(client, args))

        elif command == CHECK_TASK_STATUS_COMMAND:
            if args.get("polling") == "true":
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
