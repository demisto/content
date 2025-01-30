import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""IMPORTS"""
from CommonServerUserPython import *  # noqa: F401

import base64
import json
import requests
import urllib3
import re
from datetime import datetime, timedelta, UTC
from typing import Any
from requests.models import HTTPError

"""CONSTANTS"""
USER_AGENT = "TMV1CortexXSOARApp/1.1"
VENDOR_NAME = "TrendMicroVisionOne"
URL = "url"
POST = "post"
GET = "get"
PUT = "put"
AUTHORIZATION = "Authorization"
BEARER = "Bearer "
CONTENT_TYPE_JSON = "application/json"
EMPTY_STRING = ""
ASCII = "ascii"
API_TOKEN = "apikey"
VALUE_TYPE = "value_type"
TARGET_VALUE = "target_value"
PRODUCT_ID = "product_id"
DESCRIPTION = "description"
MESSAGE_ID = "message_id"
MAILBOX = "mailbox"
MESSAGE_DELIVERY_TIME = "message_delivery_time"
COMPUTER_ID = "computer_id"
FIELD = "field"
ENDPOINT = "endpoint"
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
ENTRY_ID = "entry_id"
TASKSTATUS = "taskStatus"
OS_TYPE = "os"
FILE_PATH = "file_path"
FILE_URL = "file_url"
FILE_NAME = "filename"
DOCUMENT_PASSWORD = "document_password"
ARCHIVE_PASSWORD = "archive_password"
ACTION_ID = "actionId"
WORKBENCH_ID = "workbench_id"
CONTENT = "content"
STATUS = "status"
# End Points
ADD_BLOCKLIST_ENDPOINT = "/v2.0/xdr/response/block"
REMOVE_BLOCKLIST_ENDPOINT = "/v2.0/xdr/response/restoreBlock"
QUARANTINE_EMAIL_ENDPOINT = "/v2.0/xdr/response/quarantineMessage"
DELETE_EMAIL_ENDPOINT = "/v2.0/xdr/response/deleteMessage"
ISOLATE_CONNECTION_ENDPOINT = "/v2.0/xdr/response/isolate"
TERMINATE_PROCESS_ENDPOINT = "/v2.0/xdr/response/terminateProcess"
RESTORE_CONNECTION_ENDPOINT = "/v2.0/xdr/response/restoreIsolate"
ADD_OBJECT_TO_EXCEPTION_LIST = "/v2.0/xdr/threatintel/suspiciousObjects/exceptions"
DELETE_OBJECT_FROM_EXCEPTION_LIST = (
    "/v2.0/xdr/threatintel/suspiciousObjects/exceptions/delete"
)
ADD_OBJECT_TO_SUSPICIOUS_LIST = "/v2.0/xdr/threatintel/suspiciousObjects"
DELETE_OBJECT_FROM_SUSPICIOUS_LIST = "/v2.0/xdr/threatintel/suspiciousObjects/delete"
TASK_DETAIL_ENDPOINT = "/v2.0/xdr/response/getTask"
GET_COMPUTER_ID_ENDPOINT = "/v2.0/xdr/eiqs/query/agentInfo"
GET_ENDPOINT_INFO_ENDPOINT = "/v2.0/xdr/eiqs/query/endpointInfo"
GET_FILE_STATUS = "/v2.0/xdr/sandbox/tasks/{taskId}"
GET_FILE_REPORT = "/v2.0/xdr/sandbox/reports/{reportId}"
ADD_NOTE_ENDPOINT = "/v2.0/xdr/workbench/workbenches/{workbenchId}/notes"
UPDATE_STATUS_ENDPOINT = "/v2.0/xdr/workbench/workbenches/{workbenchId}"
COLLECT_FORENSIC_FILE = "/v2.0/xdr/response/collectFile"
DOWNLOAD_INFORMATION_COLLECTED_FILE = "/v2.0/xdr/response/downloadInfo"
SUBMIT_FILE_TO_SANDBOX = "/v2.0/xdr/sandbox/file"
WORKBENCH_HISTORIES = "/v2.0/xdr/workbench/workbenchHistories"
# Error Messages
RESPONSE_ERROR = "Error in API call: [%d] - %s"
RETRY_ERROR = "The max tries exceeded [%d] - %s"
COMMAND_CALLED = "Command being called is {command}"
COMMAND_EXECUTION_ERROR = "Failed to execute {error} command. Error"
AUTHORIZATION_ERROR = (
    "Authorization Error: make sure URL/API Key is correctly set. Error - {error}"
)
PARAMETER_ISSUE = "{param} is not a valid parameter. Kindly provide valid parameter"
FILE_TYPE_ERROR = "Kindly provide valid file 'type'"
FILE_NOT_FOUND = "No such file present in {filepath}"
# General Messages:
RAW_RESPONSE = "The raw response data - {raw_response}"
SUCCESS_RESPONSE = "success with url {url} and response status {status}"
EXCEPTION_MESSAGE = "Successfully {task} object to exception list with response {code}, Total items in exception list - {length}"
SUCCESS_TEST = "Successfully connected to the vision one API."
POLLING_MESSAGE = "The task has not completed, will check status again in 30 seconds"
# Workbench Statuses
NEW = 0
IN_PROGRESS = 1
RESOLVED_TRUE_POSITIVE = 2
RESOLVED_FALSE_POSITIVE = 3
# Table Heading
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
TABLE_ENDPOINT_INFO = "Endpoint info "
TABLE_DELETE_SUSPICIOUS_LIST = "Delete object from suspicious list "
TABLE_GET_FILE_ANALYSIS_STATUS = "File analysis status "
TABLE_GET_FILE_ANALYSIS_REPORT = "File analysis report "
TABLE_COLLECT_FILE = "Collect forensic file "
TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION = (
    "The download information for collected forensic file "
)
TABLE_SUBMIT_FILE_TO_SANDBOX = "Submit file to sandbox "
TABLE_SUBMIT_FILE_ENTRY_TO_SANDBOX = "Submit file entry to sandbox "
TABLE_SANDBOX_SUBMISSION_POLLING = "Sandbox submission polling status "
TABLE_ADD_NOTE = "Add note to workbench alert "
TABLE_UPDATE_STATUS = "Update workbench alert status"
# COMMAND NAMES
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
GET_FILE_ANALYSIS_STATUS = "trendmicro-visionone-get-file-analysis-status"
GET_FILE_ANALYSIS_REPORT = "trendmicro-visionone-get-file-analysis-report"
COLLECT_FILE = "trendmicro-visionone-collect-forensic-file"
DOWNLOAD_COLLECTED_FILE = (
    "trendmicro-visionone-download-information-for-collected-forensic-file"
)
FILE_TO_SANDBOX = "trendmicro-visionone-submit-file-to-sandbox"
FILE_ENTRY_TO_SANDBOX = "trendmicro-visionone-submit-file-entry-to-sandbox"
SANDBOX_SUBMISSION_POLLING = "trendmicro-visionone-run-sandbox-submission-polling"
CHECK_TASK_STATUS = "trendmicro-visionone-check-task-status"
GET_ENDPOINT_INFO_COMMAND = "trendmicro-visionone-get-endpoint-info"
UPDATE_STATUS = "trendmicro-visionone-update-status"
ADD_NOTE = "trendmicro-visionone-add-note"
FETCH_INCIDENTS = "fetch-incidents"

table_name = {
    ADD_BLOCKLIST_COMMAND: TABLE_ADD_TO_BLOCKLIST,
    REMOVE_BLOCKLIST_COMMAND: TABLE_REMOVE_FROM_BLOCKLIST,
    QUARANTINE_EMAIL_COMMAND: TABLE_QUARANTINE_EMAIL_MESSAGE,
    DELETE_EMAIL_COMMAND: TABLE_DELETE_EMAIL_MESSAGE,
    ISOLATE_ENDPOINT_COMMAND: TABLE_ISOLATE_ENDPOINT_MESSAGE,
    RESTORE_ENDPOINT_COMMAND: TABLE_RESTORE_ENDPOINT_MESSAGE,
    ADD_EXCEPTION_LIST_COMMAND: TABLE_ADD_EXCEPTION_LIST,
    DELETE_EXCEPTION_LIST_COMMAND: TABLE_DELETE_EXCEPTION_LIST,
    ADD_SUSPICIOUS_LIST_COMMAND: TABLE_ADD_SUSPICIOUS_LIST,
    GET_ENDPOINT_INFO_COMMAND: TABLE_ENDPOINT_INFO,
    DELETE_SUSPICIOUS_LIST_COMMAND: TABLE_DELETE_SUSPICIOUS_LIST,
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
        self, method: str, url_suffix: str, json_data=None, params=None, data=None
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
        header = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": f"{CONTENT_TYPE_JSON};charset=utf-8",
            "User-Agent": USER_AGENT,
        }
        try:
            response = self._http_request(
                method=method,
                full_url=f"{self.base_url}{url_suffix}",
                retries=3,
                json_data=json_data,
                params=params,
                headers=header,
                resp_type="response",
                ok_codes=(200, 201),
                data=data,
            )
        except DemistoException as error:
            demisto.error(error.message)
            return_error(error.message)
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
        return None

    def status_check(self, data: dict[str, Any]) -> Any:
        """
        Check the status of particular task.
        :type data: ``dict``
        :param method: Response data to received from the end point.
        :return: task status response data.
        :rtype: ``Any``
        """
        action_id = data.get(ACTION_ID)
        params = {"actionId": action_id}
        response = self.http_request(GET, TASK_DETAIL_ENDPOINT, params=params)
        message = {
            "actionId": action_id,
            "taskStatus": response.get("data").get("taskStatus"),
        }
        return CommandResults(
            readable_output=tableToMarkdown(
                "Status of task ", message, removeNull=True
            ),
            outputs_prefix=("VisionOne.Task_Status"),
            outputs_key_field="actionId",
            outputs=message,
        )

    def sandbox_submission_polling(self, data: dict[str, Any]) -> Any:
        """
        Check the status of sandbox submission
        :type data: ``dict``
        :param method: Response data received from sandbox.
        :return: Sandbox submission response data.
        :rtype: ``Any``
        """
        task_id = data.get(TASKID)
        result = self.http_request(GET, GET_FILE_STATUS.format(taskId=task_id))
        risk = result.get("data", {}).get("analysisSummary", {}).get("riskLevel", "")
        risk_score = self.incident_severity_to_dbot_score(risk)
        sha256 = result.get("data", {}).get("digest", {}).get("sha256")
        md5 = result.get("data", {}).get("digest", {}).get("md5")
        sha1 = result.get("data", {}).get("digest", {}).get("sha1")
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
            "message": result.get("message", ""),
            "code": result.get("code", ""),
            "task_id": result.get("data", {}).get("taskId", ""),
            "taskStatus": result.get("data", {}).get("taskStatus", ""),
            "digest": result.get("data", {}).get("digest", ""),
            "analysis_completion_time": result.get("data", {})
            .get("analysisSummary", "")
            .get("analysisCompletionTime", ""),
            "risk_level": result.get("data", {})
            .get("analysisSummary", "")
            .get("riskLevel", ""),
            "description": result.get("data", {})
            .get("analysisSummary", "")
            .get("description", ""),
            "detection_name_list": result.get("data", {})
            .get("analysisSummary", "")
            .get("detectionNameList", ""),
            "threat_type_list": result.get("data", {})
            .get("analysisSummary", "")
            .get("threatTypeList", ""),
            "file_type": result.get("data", {})
            .get("analysisSummary", "")
            .get("trueFileType", ""),
            "report_id": result.get("data", {}).get("reportId", ""),
            "DBotScore": {
                "Score": dbot_score.score,
                "Vendor": dbot_score.integration_name,
                "Reliability": dbot_score.reliability,
            },
        }
        return CommandResults(
            readable_output=tableToMarkdown(
                TABLE_SANDBOX_SUBMISSION_POLLING, message, removeNull=True
            ),
            outputs_prefix="VisionOne.Sandbox_Submission_Polling",
            outputs_key_field="report_id",
            outputs=message,
            indicator=file_entry,
        )

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

        # Regex expression for validating mac
        regex2 = "([0-9A-Fa-f]{2}[:-]){5}" + "([0-9A-Fa-f]{2})"

        p = re.compile(regex)
        p1 = re.compile(regex1)
        p2 = re.compile(regex2)

        # Checking if it is a valid IPv4 addresses
        if re.search(p, param):
            return "ip"

        # Checking if it is a valid IPv6 addresses
        elif re.search(p1, param):
            return "ipv6"

        # Checking if it is a valid IPv6 addresses
        elif re.search(p2, param):
            return "macaddr"

        # Otherwise use hostname type
        return "hostname"

    def get_computer_id(self, field: Any, value: Any) -> str:
        """
        Fetch particular computer id using hostname, macaddress or ip.
        :type field: ``str``
        :param field: type of field to search hostname, macaddress or ip.
        :type value: ``str``
        :param value: value of the particular field.
        :return: value of computer id.
        :rtype: ``str``
        """
        body = {CRITERIA: {FIELD: field, VALUE: value}}
        response = self.http_request(
            POST, GET_COMPUTER_ID_ENDPOINT, data=json.dumps(body)
        )

        if response["status"] == "FAIL":
            return_error("kindly provide valid field value")
        computer_id = response.get("result").get("computerId")
        return computer_id

    def exception_list_count(self) -> int:
        """
        Gets the count of object present in exception list

        :return: number of exception object.
        :rtype: ``int``
        """
        response = self.http_request(GET, ADD_OBJECT_TO_EXCEPTION_LIST)
        list_of_exception = response.get(DATA).get(EXCEPTION_LIST)
        exception_count = len(list_of_exception)
        return exception_count

    def suspicious_list_count(self) -> int:
        """
        Gets the count of object present in suspicious list
        :return: number of suspicious object.
        :rtype: ``int``
        """
        response = self.http_request(GET, ADD_OBJECT_TO_SUSPICIOUS_LIST)
        list_of_exception = response.get(DATA).get(SUSPICIOUS_LIST)
        exception_count = len(list_of_exception)
        return exception_count

    def get_workbench_histories(self, start, end, offset=None, size=None) -> str:
        if not check_datetime_aware(start):
            start = start.astimezone()
        if not check_datetime_aware(end):
            end = end.astimezone()
        start = start.astimezone(UTC)
        end = end.astimezone(UTC)
        start = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end = end.isoformat(timespec="milliseconds").replace("+00:00", "Z")

        params = dict(
            [("startTime", start), ("endTime", end), ("sortBy", "createdTime")]
            + ([("offset", offset)] if offset is not None else [])
            + ([("limit", size)] if size is not None else [])
        )

        response = self.http_request(GET, WORKBENCH_HISTORIES, params=params)["data"][
            "workbenchRecords"
        ]
        return response

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
    args: dict[str, Any], cmd: str, client: Client
) -> str | CommandResults:
    """
    Performs polling interval to check status of task or sandbox submission result.
    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``cmd``
    :param client: The command that polled for an interval.

    :type client: ``Client``
    :param client: client object to use http_request.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get("interval_in_seconds", 30))
    action_id = args.get(ACTION_ID)
    task_id = args.get(TASKID)
    if cmd == CHECK_TASK_STATUS:
        command_results = client.status_check(args)
        value = ACTION_ID
    else:
        command_results = client.sandbox_submission_polling(args)
        value = TASKID
    if command_results.outputs.get("taskStatus") not in (
        "success",
        "failed",
        "timeout",
        "skipped",
        "finished",
    ):
        # schedule next poll
        polling_args = {
            f"{value}": action_id if action_id else task_id,
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


def get_task_status(args: dict[str, Any], client: Client) -> str | CommandResults:
    """
    check status of task.

    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``Client``
    :param client: client object to use http_request.
    """
    return run_polling_command(args, CHECK_TASK_STATUS, client)


def get_sandbox_submission_status(
    args: dict[str, Any], client: Client
) -> str | CommandResults:
    """
    call polling command to check status of sandbox submission.

    :type args: ``args``
    :param client: argument required for polling.

    :type client: ``Client``
    :param client: client object to use http_request.
    """
    return run_polling_command(args, SANDBOX_SUBMISSION_POLLING, client)


def test_module(client: Client) -> Any:
    """
    Performs basic get request to get item samples.
    :type client: ``Client``
    :param client: client object to use http_request.
    """
    client.http_request("GET", "/v2.0/xdr/threatintel/suspiciousObjects/exceptions")
    return "ok"


def get_endpoint_info(
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Retrieve information abouut the endpoint queried and
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

    computer_id = client.get_computer_id(field, value)
    body = {"computerId": computer_id}
    response = client.http_request(
        POST, GET_ENDPOINT_INFO_ENDPOINT, data=json.dumps(body)
    )

    message = {
        "message": response.get("message", ""),
        "errorCode": response.get("errorCodecode", ""),
        "status": response.get("status", ""),
        "logonAccount": response.get("result", {})
        .get("logonAccount", "")
        .get("value", ""),
        "hostname": response.get("result", {}).get("hostname", "").get("value", ""),
        "macAddr": response.get("result", {}).get("macAddr", "").get("value", ""),
        "ip": response.get("result", {}).get("ip", "").get("value", ""),
        "osName": response.get("result", {}).get("osName", ""),
        "osVersion": response.get("result", {}).get("osVersion", ""),
        "osDescription": response.get("result", {}).get("osDescription", ""),
        "productCode": response.get("result", {}).get("productCode", ""),
    }

    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[GET_ENDPOINT_INFO_COMMAND], message, removeNull=True
        ),
        outputs_prefix="VisionOne.Endpoint_Info",
        outputs_key_field="message",
        outputs=message,
    )
    return results


def add_delete_block_list_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """
    Mapping add to block list response data.

    :type data: ``dict``
    :param data: Response data to received from the end point.

    :return: mapped response data.
    :rtype: ``dict``
    """
    action_id = data.get("actionId", {})
    task_status = data.get("taskStatus", {})
    return {"actionId": action_id, "taskStatus": task_status}


def add_or_remove_from_block_list(
    client: Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
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
    product_id = args.get(PRODUCT_ID)
    if not product_id:
        product_id = EMPTY_STRING
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    body = {
        "valueType": value_type,
        "targetValue": target_value,
        "productId": product_id,
        "description": description,
    }
    if command == ADD_BLOCKLIST_COMMAND:
        response = client.http_request(
            POST, ADD_BLOCKLIST_ENDPOINT, data=json.dumps(body)
        )
    elif command == REMOVE_BLOCKLIST_COMMAND:
        response = client.http_request(
            POST, REMOVE_BLOCKLIST_ENDPOINT, data=json.dumps(body)
        )
    else:
        response = None
        demisto.debug(f"{command} didn't mach any condition. {response=}")

    mapping_data = add_delete_block_list_mapping(response)
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[command], mapping_data, removeNull=True
        ),
        outputs_prefix="VisionOne.BlockList",
        outputs_key_field="actionId",
        outputs=mapping_data,
    )
    return results


def fetch_incidents(client: Client):
    """
    This function do the loop to get all workbench alerts by changing
    the parameters of both 'offset' and 'size'.
    """
    offset = 0
    size = demisto.params().get("max_fetch")
    end = datetime.now(UTC)
    days = int(demisto.params().get("first_fetch"))

    last_run = demisto.getLastRun()
    if last_run and "start_time" in last_run:
        start = datetime.fromisoformat(last_run.get("start_time"))
    else:
        start = end + timedelta(days=-days)

    alerts: List[Any] = []
    alerts.extend(client.get_workbench_histories(start, end, offset, size))

    incidents = []
    if alerts:
        for record in alerts:
            incident = {
                "name": record["workbenchName"],
                "occurred": record["createdTime"],
                "severity": client.incident_severity_to_dbot_score(record["severity"]),
                "rawJSON": json.dumps(record),
            }
            incidents.append(incident)
            last_event = datetime.strptime(record["createdTime"], "%Y-%m-%dT%H:%M:%SZ")

        next_search = last_event + timedelta(0, 1)

        demisto.setLastRun({"start_time": next_search.isoformat()})

    if incidents:
        demisto.incidents(incidents)
    else:
        demisto.incidents([])

    return incidents


def quarantine_delete_email_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """
    Mapping quarantine email message response data.

    :type data: ``dict``
    :param method: Response data to received from the end point.

    :return: mapped response data.
    :rtype: ``dict``
    """
    action_id = data.get("actionId", {})
    task_status = data.get("taskStatus", {})
    return {"actionId": action_id, "taskStatus": task_status}


def quarantine_or_delete_email_message(
    client: Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
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
    message_id = args.get(MESSAGE_ID)
    mailbox = args.get(MAILBOX)
    message_delivery_time = args.get(MESSAGE_DELIVERY_TIME)
    product_id = args.get(PRODUCT_ID)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    body = {
        "messageId": message_id,
        "mailBox": mailbox,
        "messageDeliveryTime": message_delivery_time,
        "productId": product_id,
        "description": description,
    }
    if command == QUARANTINE_EMAIL_COMMAND:
        response = client.http_request(
            POST, QUARANTINE_EMAIL_ENDPOINT, data=json.dumps(body)
        )

    elif command == DELETE_EMAIL_COMMAND:
        response = client.http_request(
            POST, DELETE_EMAIL_ENDPOINT, data=json.dumps(body)
        )
    else:
        response = None
        demisto.debug(f"{command=} didn't match any condition. {response=}")

    mapping_data = quarantine_delete_email_mapping(response)
    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[command], mapping_data, removeNull=True
        ),
        outputs_prefix="VisionOne.Email",
        outputs_key_field="actionId",
        outputs=mapping_data,
    )
    return results


def isolate_restore_endpoint_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """
    Mapping isolate endpoint and restore endpoint response data.

    :type data: ``dict``
    :param method: Response data to received from the end point.

    :return: mapped response data.
    :rtype: ``dict``
    """
    action_id = data.get("actionId", {})
    task_status = data.get("taskStatus", {})
    return {"actionId": action_id, "taskStatus": task_status}


def isolate_or_restore_connection(
    client: Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
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
    product_id = args.get(PRODUCT_ID)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    computer_id = client.get_computer_id(field, value)
    body = {
        "computerId": computer_id,
        "productId": product_id,
        "description": description,
    }
    if command == ISOLATE_ENDPOINT_COMMAND:
        response = client.http_request(
            POST, ISOLATE_CONNECTION_ENDPOINT, data=json.dumps(body)
        )

    elif command == RESTORE_ENDPOINT_COMMAND:
        response = client.http_request(
            POST, RESTORE_CONNECTION_ENDPOINT, data=json.dumps(body)
        )
    else:
        response = {}
        demisto.debug(f"The {command=} didn't match the conditions. {response=}")

    mapping_data = isolate_restore_endpoint_mapping(response)

    results = CommandResults(
        readable_output=tableToMarkdown(
            table_name[command], mapping_data, removeNull=True
        ),
        outputs_prefix="VisionOne.Endpoint_Connection",
        outputs_key_field="actionId",
        outputs=mapping_data,
    )
    return results


def terminate_process(
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
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
    file_list = []
    value = args.get(ENDPOINT)
    field = client.lookup_type(value)
    product_id = args.get(PRODUCT_ID)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    computer_id = client.get_computer_id(field, value)
    file_sha1 = args.get(FILESHA)
    filename = args.get(FILENAME)
    if filename:
        file_list.append(filename)
    body = {
        "computerId": computer_id,
        "fileSha1": file_sha1,
        "productId": product_id,
        "description": description,
        "filename": file_list,
    }
    response = client.http_request(
        POST, TERMINATE_PROCESS_ENDPOINT, data=json.dumps(body)
    )

    action_id = response.get("actionId", {})
    task_status = response.get("taskStatus", {})
    message = {"actionId": action_id, "taskStatus": task_status}
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_TERMINATE_PROCESS, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Terminate_Process",
        outputs_key_field="actionId",
        outputs=message,
    )
    return results


def add_or_delete_from_exception_list(
    client: Client, command: str, args: dict[str, Any]
) -> str | CommandResults:
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
    types = args.get(TYPE)
    value = args.get(VALUE)
    body = {DATA: [{"type": types, "value": value}]}
    if command == ADD_EXCEPTION_LIST_COMMAND:
        description = args.get(DESCRIPTION)
        if not description:
            description = EMPTY_STRING
        body[DATA][0][DESCRIPTION] = description
        client.http_request(POST, ADD_OBJECT_TO_EXCEPTION_LIST, data=json.dumps(body))

    elif command == DELETE_EXCEPTION_LIST_COMMAND:
        client.http_request(
            POST, DELETE_OBJECT_FROM_EXCEPTION_LIST, data=json.dumps(body)
        )

    exception_list = client.exception_list_count()

    message = {
        "message": "success",
        "status_code": client.status,
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
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
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
    types = args.get(TYPE)
    value = args.get(VALUE)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    scan_action = args.get(SCAN_ACTION)
    if scan_action and scan_action not in ("log", "block"):
        return_error(PARAMETER_ISSUE.format(param=SCAN_ACTION))
    risk_level = args.get(RISK_LEVEL)
    if risk_level and risk_level not in ("high", "medium", "low"):
        return_error(PARAMETER_ISSUE.format(param=RISK_LEVEL))
    expiry = args.get(EXPIRYDAY)
    if not expiry:
        expiry = 0
    body = {
        DATA: [
            {
                "type": types,
                "value": value,
                "description": description,
                "scanAction": scan_action,
                "riskLevel": risk_level,
                "expiredDay": expiry,
            }
        ]
    }
    client.http_request(POST, ADD_OBJECT_TO_SUSPICIOUS_LIST, data=json.dumps(body))
    suspicious_list = client.suspicious_list_count()

    message = {
        "message": "success",
        "status_code": client.status,
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
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
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
    types = args.get(TYPE)
    value = args.get(VALUE)
    body = {DATA: [{"type": types, "value": value}]}
    client.http_request(POST, DELETE_OBJECT_FROM_SUSPICIOUS_LIST, data=json.dumps(body))

    exception_list = client.suspicious_list_count()

    message = {
        "message": "success",
        "status_code": client.status,
        "total_items": exception_list,
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
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
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
    risk = response.get("data", {}).get("analysisSummary", {}).get("riskLevel", "")
    risk_score = client.incident_severity_to_dbot_score(risk)
    sha256 = response.get("data", {}).get("digest", {}).get("sha256")
    md5 = response.get("data", {}).get("digest", {}).get("md5")
    sha1 = response.get("data", {}).get("digest", {}).get("sha1")
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
        "message": response.get("message", ""),
        "code": response.get("code", ""),
        "task_id": response.get("data", {}).get("taskId", ""),
        "taskStatus": response.get("data", {}).get("taskStatus", ""),
        "digest": response.get("data", {}).get("digest", ""),
        "analysis_completion_time": response.get("data", {})
        .get("analysisSummary", "")
        .get("analysisCompletionTime", ""),
        "risk_level": response.get("data", {})
        .get("analysisSummary", "")
        .get("riskLevel", ""),
        "description": response.get("data", {})
        .get("analysisSummary", "")
        .get("description", ""),
        "detection_name_list": response.get("data", {})
        .get("analysisSummary", "")
        .get("detectionNameList", ""),
        "threat_type_list": response.get("data", {})
        .get("analysisSummary", "")
        .get("threatTypeList", ""),
        "file_type": response.get("data", {})
        .get("analysisSummary", "")
        .get("trueFileType", ""),
        "report_id": response.get("data", {}).get("reportId", ""),
        "DBotScore": {
            "Score": dbot_score.score,
            "Vendor": dbot_score.integration_name,
            "Reliability": dbot_score.reliability,
        },
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_GET_FILE_ANALYSIS_STATUS, message, removeNull=True
        ),
        outputs_prefix="VisionOne.File_Analysis_Status",
        outputs_key_field="message",
        outputs=message,
        indicator=file_entry,
    )
    return results


def get_file_analysis_report(
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
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
    types = args.get(TYPE)
    if types not in ("vaReport", "investigationPackage", "suspiciousObject"):
        return_error(FILE_TYPE_ERROR)
    params = {TYPE: types}
    response = client.http_request(
        GET, GET_FILE_REPORT.format(reportId=report_id), params=params
    )
    if isinstance(response, dict):

        message = {
            "message": response.get("message", ""),
            "code": response.get("code", ""),
            "data": [],
        }
        if len(response.get("data", [])) > 0:
            for data in response.get("data", {}):
                data_value = {
                    "type": data.get("type", ""),
                    "value": data.get("value", ""),
                    "risk_level": data.get("riskLevel", ""),
                    "analysis_completion_time": data.get("analysisCompletionTime", ""),
                    "expired_time": data.get("expiredTime", ""),
                    "root_file_sha1": data.get("rootFileSha1", ""),
                }
                message.get("data", {}).append(data_value)
        results = CommandResults(
            readable_output=tableToMarkdown(
                TABLE_GET_FILE_ANALYSIS_REPORT, message, removeNull=True
            ),
            outputs_prefix="VisionOne.File_Analysis_Report",
            outputs_key_field="message",
            outputs=message,
        )
    elif response.headers.get("Content-Type", "") == "binary/octet-stream":
        data = response.content
        if types == "vaReport":
            results = fileResult(
                "Sandbox_Analysis_Report.pdf", data, file_type=EntryType.ENTRY_INFO_FILE
            )
        else:
            results = fileResult(
                "Sandbox_Investigation_Package.zip",
                data,
                file_type=EntryType.ENTRY_INFO_FILE,
            )
    else:
        results = CommandResults()
        demisto.debug(f"The code didn't match any condition. {results=}")
    return results


def collect_file(client: Client, args: dict[str, Any]) -> str | CommandResults:
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
    product_id = args.get(PRODUCT_ID)
    description = args.get(DESCRIPTION)
    if not description:
        description = EMPTY_STRING
    computer_id = client.get_computer_id(field, value)  # type: ignore
    file_path = args.get(FILE_PATH)
    os = args.get(OS_TYPE)
    body = {
        "description": description,
        "productId": product_id,
        "computerId": computer_id,
        "filePath": file_path,
        "os": os,
    }
    response = client.http_request(POST, COLLECT_FORENSIC_FILE, data=json.dumps(body))

    task_status = response.get("taskStatus", {})
    action_id = response.get("actionId", {})
    message = {"actionId": action_id, "taskStatus": task_status}
    results = CommandResults(
        readable_output=tableToMarkdown(TABLE_COLLECT_FILE, message, removeNull=True),
        outputs_prefix="VisionOne.Collect_Forensic_File",
        outputs_key_field="actionId",
        outputs=message,
    )
    return results


def download_information_collected_file(
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    Gets the download information for collected forensic file and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    action_id = args.get(ACTION_ID)
    params = {"actionId": action_id}
    response = client.http_request(
        GET, DOWNLOAD_INFORMATION_COLLECTED_FILE, params=params
    )

    file_url = response.get("data", "").get("url", "")
    expires = response.get("data", "").get("expires", "")
    password = response.get("data", "").get("password", "")
    filename = response.get("data", "").get("filename", "")
    message = {
        "url": file_url,
        "expires": expires,
        "password": password,
        "filename": filename,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(
            TABLE_COLLECTED_FORENSIC_FILE_DOWNLOAD_INFORMATION, message, removeNull=True
        ),
        outputs_prefix="VisionOne.Download_Information_For_Collected_Forensic_File",
        outputs_key_field="url",
        outputs=message,
    )
    return results


def submit_file_to_sandbox(
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
    """
    submit file to sandbox and sends the result to demist war room
    :type client: ``Client``
    :param client: client object to use http_request.
    :type args: ``dict``
    :param args: args object to fetch the argument data.
    :return: sends data to demisto war room.
    :rtype: ``dict`
    """
    data = {}
    params: dict[Any, Any] = {}
    file_url = args.get(FILE_URL)
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
    headers = {AUTHORIZATION: f"{BEARER}{client.api_key}"}
    try:
        file_content = requests.get(file_url, allow_redirects=True)  # type: ignore
        files = {
            "file": (file_name, file_content.content, "application/x-zip-compressed")
        }
        result = requests.post(
            f"{client.base_url}{SUBMIT_FILE_TO_SANDBOX}",
            params=params,
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
        "message": response.get("message", ""),
        "code": response.get("code", ""),
        "task_id": response.get("data", "").get("taskId", ""),
        "digest": response.get("data", "").get("digest", ""),
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
    client: Client, args: dict[str, Any]
) -> str | CommandResults:
    entry = args.get(ENTRY_ID)
    file_ = demisto.getFilePath(entry)
    file_name = file_.get("name")
    file_path = file_.get("path")
    archive_pass = args.get(ARCHIVE_PASSWORD)
    document_pass = args.get(DOCUMENT_PASSWORD)
    query_params: dict[Any, Any] = {}
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
    except HTTPError as http_err:
        demisto.error(http_err)
        return_error(http_err)
    response = result.json()
    message = {
        "filename": file_name,
        "entryId": entry,
        "file_path": file_.get("path", ""),
        "message": response.get("message"),
        "task_id": response.get("data", {}).get("taskId", ""),
        "code": response.get("code", ""),
        "digest": response.get("data", {}).get("digest", {}),
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


def add_note(client: Client, args: dict[str, Any]) -> str | CommandResults:
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
    response = client.http_request(
        POST, ADD_NOTE_ENDPOINT.format(workbenchId=workbench_id), data=json.dumps(body)
    )

    note_id = response.get("data").get("id")
    response_code = response.get("info").get("code")
    response_msg = response.get("info").get("msg")
    message = {
        "Workbench_Id": workbench_id,
        "noteId": note_id,
        "response_code": response_code,
        "response_msg": response_msg,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(TABLE_ADD_NOTE, message, removeNull=True),
        outputs_prefix="VisionOne.Add_Note",
        outputs_key_field="noteId",
        outputs=message,
    )
    return results


def update_status(client: Client, args: dict[str, Any]) -> str | CommandResults:
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
        update_status = NEW
    elif status == "in_progress":
        update_status = IN_PROGRESS
    elif status == "resolved_true_positive":
        update_status = RESOLVED_TRUE_POSITIVE
    elif status == "resolved_false_positive":
        update_status = RESOLVED_FALSE_POSITIVE
    else:
        update_status = None
        demisto.debug(f"{status=} didn't match any condition. {update_status=}")

    body = {"investigationStatus": update_status}
    response = client.http_request(
        PUT,
        UPDATE_STATUS_ENDPOINT.format(workbenchId=workbench_id),
        data=json.dumps(body),
    )

    response_code = response.get("info").get("code")
    response_msg = response.get("info").get("msg")
    message = {
        "Workbench_Id": workbench_id,
        "response_code": response_code,
        "response_msg": response_msg,
    }
    results = CommandResults(
        readable_output=tableToMarkdown(TABLE_UPDATE_STATUS, message, removeNull=True),
        outputs_prefix="VisionOne.Update_Status",
        outputs_key_field="Workbench_Id",
        outputs=message,
    )
    return results


def main():
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

        elif command == "fetch-incidents":
            return_results(fetch_incidents(client))

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

        elif command == GET_FILE_ANALYSIS_STATUS:
            return_results(get_file_analysis_status(client, args))

        elif command == GET_FILE_ANALYSIS_REPORT:
            return_results(get_file_analysis_report(client, args))

        elif command == GET_ENDPOINT_INFO_COMMAND:
            return_results(get_endpoint_info(client, args))

        elif command == COLLECT_FILE:
            return_results(collect_file(client, args))

        elif command == DOWNLOAD_COLLECTED_FILE:
            return_results(download_information_collected_file(client, args))

        elif command == FILE_TO_SANDBOX:
            return_results(submit_file_to_sandbox(client, args))

        elif command == FILE_ENTRY_TO_SANDBOX:
            return_results(submit_file_entry_to_sandbox(client, args))

        elif command == SANDBOX_SUBMISSION_POLLING:
            if args.get("polling") == "true":
                cmd_res = get_sandbox_submission_status(args, client)
                if cmd_res is not None:
                    return_results(cmd_res)
            else:
                return_results(client.sandbox_submission_polling(args))

        elif command == UPDATE_STATUS:
            return_results(update_status(client, args))

        elif command == ADD_NOTE:
            return_results(add_note(client, args))

        elif command == CHECK_TASK_STATUS:
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
        demisto.error(COMMAND_EXECUTION_ERROR.format(error=error))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
