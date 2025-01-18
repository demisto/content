import json
import os
import re
import time
from copy import copy
from dataclasses import dataclass
from datetime import datetime
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import Any

import logging
import dateparser
import requests
import syslogmp
import urllib3
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from gevent.server import StreamServer
from pydantic import BaseModel  # pylint: disable=no-name-in-module
from uvicorn.logging import AccessFormatter
from urllib.parse import urlparse

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

# CONSTANTS
MAX_SAMPLES = 20
BUF_SIZE = 1024
MAX_PORT: int = 65535

HTTP_ERRORS = {
    400: "400 Bad Request - Incorrect or invalid parameters",
    401: "401 Authentication error - Incorrect or invalid username or password",
    403: "403 Forbidden - please provide valid username and password.",
    404: "404 Resource not found - invalid endpoint was called.",
    408: "408 Timeout - Check Server URl/Port",
    410: "410 Gone - Access to the target resource is no longer available at the origin server",
    500: "500 Internal Server Error - please try again after some time.",
    502: "502 Bad Gateway - Could not connect to the origin server",
    503: "503 Service Unavailable",
}


class Incident(BaseModel):  # pylint: disable=R0903,C0115
    name: str | None = None
    type: str | None = None
    occurred: str | None = None
    raw_json: dict | None = None


client = None

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name="Authorization")


class GenericWebhookAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: dict) -> str:
        headers = scope.get("headers", [])
        user_agent_header = list(
            filter(lambda header: header[0].decode() == "user-agent", headers)
        )
        user_agent = ""
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record: logging.LogRecord) -> str:
        recordcopy = copy(record)
        user_agent = self.get_user_agent(recordcopy.__dict__["scope"])
        recordcopy.__dict__.update({"user_agent": user_agent})
        return super().formatMessage(recordcopy)


@app.post("/")
async def handle_post(
    incident: dict,
    request: Request,
    credentials: HTTPBasicCredentials = Depends(basic_auth),
    token: APIKey = Depends(token_auth),
):
    del credentials, token
    global client
    incident_type: str | None = demisto.params().get(
        "incidentType", "Commvault Suspicious File Activity"
    )
    incident_body = handle_post_helper(client, incident, request)
    if client:
        client.create_incident(
            incident_body,  # type: ignore
            datetime.fromtimestamp((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()),  # type: ignore
            incident_type,
            False,
        )  # type: ignore
    return "OK"


def handle_post_helper(client, incident, request):
    try:
        current_date = datetime.utcnow()
        epoch = datetime(1970, 1, 1)
        seconds_since_epoch = (current_date - epoch).total_seconds()
        event_id = incident[field_mapper(Constants.event_id, Constants.source_webhook)]
        event_time = incident[
            field_mapper(Constants.event_time, Constants.source_webhook)
        ]
        hostname = (
            ""
            if (request is None)  # type: ignore
            or (request.client is None)
            or (request.client.host is None)  # type: ignore
            else request.client.host  # type: ignore
        )
        incident_body = {
            "facility": Constants.facility,
            "msg": None,
            "msg_id": None,
            "process_id": None,
            "sd": {},
            "timestamp": datetime.fromtimestamp(seconds_since_epoch).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "occurred": None,
            "originating_program": incident[
                field_mapper(Constants.originating_program, Constants.source_webhook)
            ],
            "event_id": event_id,
            "event_time": event_time,
            "host_name": hostname,
        }
        inc = client.get_incident_details(incident.get("Description"))  # type: ignore
        if inc.get(Constants.anomaly_sub_type, "Undefined") != "File Type":  # type: ignore
            return {}
        incident_body.update(inc)  # type: ignore
        return incident_body
    except Exception as err:
        logging.error(f"could not print REQUEST: {err}")
    return {}


def get_backup_anomaly(anomaly_id: int) -> str:
    """
    Get Anomaly type from anomaly id
    """
    anomaly_dict = {
        0: "Undefined",
        1: "File Activity",
        2: "File Type",
        3: "Threat Analysis",
    }
    return anomaly_dict.get(anomaly_id, "Undefined")


def parse_no_length_limit(data: bytes) -> syslogmp.parser.Message:
    """
    Get syslog parser message
    """
    parser = syslogmp.parser._Parser(b"")
    parser.stream = syslogmp.parser.Stream(data)

    priority_value = parser._parse_pri_part()
    timestamp, hostname = parser._parse_header_part()
    message = parser._parse_msg_part()

    return syslogmp.parser.Message(
        facility=priority_value.facility,
        severity=priority_value.severity,
        timestamp=timestamp,
        hostname=hostname,
        message=message,
    )


def if_zero_set_none(value: str | None | int) -> str | None | int:
    """
    If the value is zero, return None
    """
    if value and int(value) > 0:
        return value
    return None


def extract_from_regex(
    message: str, default_value: str | None, *regex_string_args: str
) -> str | None:
    """
    From the message, extract the strings matching the given patterns
    """
    for pattern in regex_string_args:
        matches = re.search(pattern, message, re.IGNORECASE)
        if matches and len(matches.groups()) > 0:
            return matches.group(1).strip()
    return default_value


def format_alert_description(msg: str) -> str:
    """
    Format alert description
    """
    default_value = msg
    if msg.find("<html>") != -1 and msg.find("</html>") != -1:
        resp = msg[msg.find("<html>") + 6: msg.find("</html>")]
        msg = resp.strip()
        if msg.find("Detected ") != -1 and msg.find(" Please click ") != -1:
            msg = msg[msg.find("Detected "): msg.find(" Please click ")]
            return msg
    return default_value


" MAIN FUNCTION "


@dataclass(frozen=True)
class Constants:
    event_id: str = "event_id"
    event_time: str = "event_time"
    anomaly_sub_type: str = "anomaly_sub_type"
    originating_client: str = "originating_client"
    originating_program: str = "originating_program"
    job_id: str = "job_id"
    affected_files_count: str = "affected_files_count"
    modified_files_count: str = "modified_files_count"
    deleted_files_count: str = "deleted_files_count"
    renamed_files_count: str = "renamed_files_count"
    created_files_count: str = "created_files_count"
    severity_high: str = "High"
    facility: str = "Commvault"
    severity_info: str = "Informational"
    path_key: str = "path"
    source_syslog: str = "syslog"
    source_webhook: str = "webhook"
    source_fetch_incidents: str = "fetch"
    description: str = "description"
    max_vm_fetch: int = 1000
    default_recovery_group_name: str = "APIRecoveryGroup"


def field_mapper(field_name: str, source: str = Constants.source_syslog) -> str:
    """
    Map incoming fields
    :param field_name: Query by field name
    :return: Return incoming field by field name
    """
    field_map = {}
    if source == Constants.source_syslog:
        field_map[Constants.event_id] = "Event ID"
        field_map[Constants.event_time] = "Event Date"
        field_map[Constants.originating_program] = "Program"
    if source == Constants.source_fetch_incidents:
        field_map[Constants.event_id] = "id"
        field_map[Constants.event_time] = "timeSource"
        field_map[Constants.originating_program] = "subsystem"
    if source == Constants.source_webhook:
        field_map[Constants.event_id] = "Event ID"
        field_map[Constants.event_time] = "Event Date"
        field_map[Constants.originating_program] = "Program"
    field_map[Constants.anomaly_sub_type] = "AnomalyType"
    field_map[Constants.job_id] = "job"
    field_map[Constants.originating_client] = "client"
    field_map[Constants.affected_files_count] = "SuspiciousFileCount"
    field_map[Constants.modified_files_count] = "Modified"
    field_map[Constants.renamed_files_count] = "Renamed"
    field_map[Constants.created_files_count] = "Created"
    field_map[Constants.deleted_files_count] = "Deleted"
    return field_map[field_name]


class Client(BaseClient):
    """
    Client wrapper for Commvault Client
    """

    job_details_body = {
        "opType": 1,
        "entity": {"_type_": 0},
        "options": {"restoreIndex": True},
        "queries": [
            {
                "type": 0,
                "queryId": "MimeFileList",
                "whereClause": [
                    {
                        "criteria": {
                            "field": 38,
                            "dataOperator": 9,
                            "values": ["file"],
                        }
                    },
                    {
                        "criteria": {
                            "field": 147,
                            "dataOperator": 0,
                            "values": ["2"],
                        }
                    },
                ],
                "dataParam": {
                    "sortParam": {"ascending": True, "sortBy": [0]},
                    "paging": {"firstNode": 0, "pageSize": -1, "skipNode": 0},
                },
            },
            {
                "type": 1,
                "queryId": "MimeFileCount",
                "whereClause": [
                    {
                        "criteria": {
                            "field": 38,
                            "dataOperator": 9,
                            "values": ["file"],
                        }
                    },
                    {
                        "criteria": {
                            "field": 147,
                            "dataOperator": 0,
                            "values": ["2"],
                        }
                    },
                ],
                "dataParam": {
                    "sortParam": {"ascending": True, "sortBy": [0]},
                    "paging": {"firstNode": 0, "pageSize": -1, "skipNode": 0},
                },
            },
        ],
        "paths": [{"path": "/**/*"}],
    }

    access_token_expiry_in_days = 7
    access_token = None
    access_token_last_generation = None
    current_api_token: str = ""
    qsdk_token = None
    keyvault_tenant_id = None
    keyvault_client_id = None
    keyvault_client_secret = None
    keyvault_url = None
    key_secret_name = "access-token-for-xsoar"
    ws_url = None

    def __init__(self, base_url: str, verify: bool, proxy: bool):
        """
        Constructor to initialize the Commvault client object
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.qsdk_token = None
        if not base_url.endswith("/"):
            self.ws_url = base_url + "/"
        else:
            self.ws_url = base_url

    def set_props(self, params):
        self.keyvault_url = params.get("AzureKeyVaultUrl", {}).get("password")
        self.keyvault_tenant_id = params.get("AzureKeyVaultTenantId", {}).get(
            "password"
        )
        self.keyvault_client_id = params.get("AzureKeyVaultClientId")
        self.keyvault_client_secret = params.get("AzureKeyVaultClientSecret", {}).get(
            "password"
        )

    def get_host(self):
        if self.ws_url:
            domain = urlparse(self.ws_url)
            if domain.netloc:
                return domain.netloc.split(":")[0]
        return None

    @property
    def headers(self) -> dict:
        """
        Client headers method
        Returns:
            self.headers
        """
        if (
            not hasattr(self, "qsdk_token") or self.qsdk_token is None
        ):  # for logging in, before self.access_token is set
            return {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        return {
            "authtoken": self.qsdk_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def http_request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict[str, Any] | None = None,
        ignore_empty_response: bool = False,
        headers: dict | None = None,
    ) -> dict:
        """
        Function to make http calls
        """
        try:
            response = self._http_request(
                method=method.upper(),
                url_suffix=endpoint,
                headers=headers if headers else self.headers,
                json_data=json_data,
                params=params,
                resp_type="response",
                return_empty_response=ignore_empty_response,
            )

            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            error_msg = HTTP_ERRORS.get(exc.response.status_code)
            if error_msg:
                raise DemistoException(f"{error_msg}", res=exc.response) from exc
        retval = response.json()
        return retval

    def validate_session_or_generate_token(self, api_token: str) -> bool:
        """
        Check for last token generation and generate new token
        """
        context_info = demisto.getIntegrationContext()
        if "tokenDetails" in context_info:
            self.access_token = context_info.get("tokenDetails", {}).get("accessToken")
            self.access_token_last_generation = context_info.get(
                "tokenDetails", {}
            ).get("accessTokenGenerationTime")
        if self.access_token_last_generation is None:
            demisto.debug("Token is not present, we will create new token.")
            return self.generate_access_token(api_token)
        else:
            current_epoch = int(datetime.now().timestamp())
            token_expiry_from_last_generation = int(
                self.access_token_last_generation
                + str(self.access_token_expiry_in_days * 7 * 24 * 60 * 60)
            )
            if current_epoch > token_expiry_from_last_generation:
                demisto.debug("Token is expired, re-generating")
                return self.generate_access_token(api_token)
            else:
                self.qsdk_token = f"QSDK {self.access_token}"
        return True

    def generate_access_token(self, api_token: str) -> bool:
        """
        Generate access token from API token
        """
        new_access_token = None
        auth_token = "QSDK " + api_token
        self.qsdk_token = auth_token
        current_epoch = int(datetime.now().timestamp())
        token_expiry_epoch = (
            current_epoch + self.access_token_expiry_in_days * 24 * 60 * 60
        )
        token_name = f"soar-crt{current_epoch}-exp{token_expiry_epoch}"
        request_body = {
            "tokenExpires": {"time": token_expiry_epoch},
            "scope": 2,
            "tokenName": token_name,
        }
        try:
            response = self.http_request("POST", "/ApiToken/User", None, request_body)
            new_access_token = response.get("token")
            current_epoch = int(datetime.now().timestamp())
            self.current_api_token = str(new_access_token)
            self.access_token = str(new_access_token)
            self.qsdk_token = f"QSDK {str(new_access_token)}"
            self.access_token_last_generation = current_epoch
            current_token_dict = demisto.getIntegrationContext()
            current_token_dict.update(
                {
                    "tokenDetails": {
                        "accessToken": str(new_access_token),
                        "accessTokenGenerationTime": str(current_epoch),
                    }
                }
            )
            demisto.setIntegrationContext(current_token_dict)

        except Exception as error:
            demisto.debug(f"Could not generate access token [{error}]")
            return False
        return True

    def prepare_globals_and_create_server(
        self,
        port: int,
        certificate_path: str | None,
        private_key_path: str | None,
    ) -> StreamServer:
        """
        Prepares global environments of LOG_FORMAT and creates the server to listen
        to Syslog messages.
        Args:
            port (int): Port
            certificate_path (Optional[str]): Certificate path. For SSL connection.
            private_key_path (Optional[str]): Private key path. For SSL connection.

        Returns:
            (StreamServer): Server to listen to Syslog messages.
        """
        if certificate_path and private_key_path:
            server = StreamServer(
                ("0.0.0.0", port),  # disable-secrets-detection
                self.perform_long_running_execution,
                keyfile=private_key_path,
                certfile=certificate_path,
            )
        else:
            server = StreamServer(
                ("0.0.0.0", port),  # disable-secrets-detection
                self.perform_long_running_execution,
            )

        return server

    def perform_long_running_execution(self, sock: Any, address: tuple) -> None:
        """
        The long running execution loop. Gets input, and performs a while True loop
        and logs any error that happens.
        Stops when there is no more data to read.
        Args:
            sock: Socket.
            address(tuple): Address. Not used inside loop so marked as underscore.

        Returns:
            (None): Reads data, calls   that creates incidents from inputted data.
        """
        file_obj = sock.makefile(mode="rb")
        try:
            while True:
                try:
                    line = file_obj.readline()
                    if not line:
                        demisto.info(f"Disconnected from {address}")
                        break
                    self.perform_long_running_loop(line.strip())
                except Exception as error:
                    demisto.error(traceback.format_exc())
                    demisto.error(
                        f"Error occurred during long running loop. Error was: {error}"
                    )
        finally:
            file_obj.close()

    def perform_long_running_loop(self, socket_data: bytes) -> None:
        """
        Function to start long running loop
        """
        incident_type: str = demisto.params().get(
            "incidentType", "Commvault Suspicious File Activity"
        )

        extracted_message = self.parse_incoming_message(socket_data)
        if extracted_message:
            demisto.debug("Succeeded in parsing the message ")
        else:
            demisto.debug("Failed in parsing the message ")
        if extracted_message:
            dts = datetime.fromisoformat(str(extracted_message.get("timestamp")))
            self.create_incident(extracted_message, dts, incident_type, False)

    def create_incident(
        self,
        extracted_message: Union[list, dict[str, Any]],
        date_obj: datetime,
        incident_type: str,
        is_fetch: bool,
    ) -> None:
        """
        Function to start create incidents
        """
        date_str = date_obj.strftime("%d %B, %Y, %H:%M:%S")
        incidents = []
        if type(extracted_message) is not list:
            extracted_message = [extracted_message]
        for message_ in extracted_message:
            incident = {
                "name": f"Suspicious File Activity Detected at [{date_str}]",
                "rawJSON": json.dumps(message_),
                "occurred": message_.get("occurred"),
                "type": incident_type,
                "details": "\n".join([f"{k}: {v}" for k, v in message_.items() if v]),
            }
            if message_.get(Constants.anomaly_sub_type, "Undefined") == "File Type":
                incidents.append(incident)
        if is_fetch:
            demisto.incidents(incidents)
            # self.define_indicator(extracted_message.get("originating_client"))
        else:
            demisto.createIncidents(incidents)
            # self.define_indicator(extracted_message.get("originating_client"))

    def get_events_list(self, last_run, first_fetch_time, max_fetch) -> Optional[Any]:
        """
        Function to get events
        """
        current_date = datetime.utcnow()
        epoch = datetime(1970, 1, 1)
        seconds_since_epoch = int((current_date - epoch).total_seconds())
        fromtime = last_run
        if fromtime is None:
            fromtime = str(dateparser.parse(first_fetch_time))
            fromtime = int(time.mktime(datetime.fromisoformat(fromtime).timetuple()))
        ustring = (
            "/events?level=10&showInfo=false&showMinor=false&"
            "showMajor=true&showCritical=false&"
            "showAnomalous=true"
        )
        event_endpoint = f"{ustring}&fromTime={fromtime}&toTime={seconds_since_epoch}"  # disable-secrets-detection
        headers = self.headers
        if max_fetch is None:
            max_fetch = 50
        headers["pagingInfo"] = f"0,{max_fetch}"
        resp = self.http_request("GET", event_endpoint, None, headers=headers)
        if resp and resp.get("commservEvents"):
            return resp.get("commservEvents")
        return None

    def get_subclient_content_list(self, subclient_id: Union[int, str]) -> dict:
        """
        Get content from subclient
        :param subclient_id: subclient Id
        :return: string
        """
        resp = self.http_request("GET", "/Subclient/" + str(subclient_id), None)
        resp = resp.get("subClientProperties", [{}])[0].get("content")
        return resp

    def define_severity(self, anomaly_sub_type: str) -> str | None:
        """
        Function to get severity from anomaly sub type
        """
        severity = None
        if anomaly_sub_type in ("File Type", "Threat Analysis"):
            severity = Constants.severity_high
        elif anomaly_sub_type == "File Activity":
            severity = Constants.severity_info
        return severity

    def fetch_file_details(
        self, job_id: Union[int, str] | None, subclient_id: Union[int, str]
    ) -> tuple[list, list]:
        """
        Function to fetch the scanned folders list during the backup job
        """
        folders_list = []
        if job_id is None:
            return [], []
        files_list = self.get_files_list(job_id)
        folder_response = self.get_subclient_content_list(subclient_id)
        for resp in folder_response:
            folders_list.append(resp[Constants.path_key])
        return files_list, folders_list

    """def define_indicator(self, originating_client: str) -> None:

        Define an indicator
        :param originating_client: client which has generated the event

        indicator_list = []
        indicator_list.append(
            {
                "value": f"client [{originating_client}]",
                "type": "Client",
                "score": 2,
                "rawJSON": {
                    "value": f"client [{originating_client}]",
                    "type": "Client",
                    "verdict": "suspicious",
                    "score": 2,
                },
            }
        )
        demisto.createIndicators(indicator_list)"""

    def parse_incoming_message(self, log_message: bytes) -> dict | None:
        """
        Function to parse incoming message from syslog
        """
        try:
            syslog_message: syslogmp.Message = parse_no_length_limit(log_message)
            message = syslog_message.message.decode("utf-8")

            event_time = extract_from_regex(
                message,
                "",
                "#011 {}: (.*?)#011".format(
                    field_mapper(Constants.event_time, Constants.source_syslog)
                ),
            )
            event_id = extract_from_regex(
                message,
                "",
                "#011 {}: (.*?)#011".format(
                    field_mapper(Constants.event_id, Constants.source_syslog)
                ),
            )
            incident = {
                "facility": Constants.facility,
                "host_name": syslog_message.hostname,
                "msg": None,
                "msg_id": None,
                "process_id": None,
                "sd": {},
                "timestamp": syslog_message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "occurred": None,
                "event_time": event_time,
                "event_id": event_id,
                "originating_program": extract_from_regex(
                    message,
                    "",
                    r"{}: ([\w]+)+:?".format(
                        field_mapper(
                            Constants.originating_program, Constants.source_syslog
                        )
                    ),
                ),
            }

            inc = self.get_incident_details(message)  # type: ignore
            if inc.get(Constants.anomaly_sub_type, "Undefined") != "File Type":  # type: ignore
                return None
            incident.update(inc)  # type: ignore
            return incident
        except syslogmp.parser.MessageFormatError as error:
            demisto.debug(
                f"Could not parse the log message, got MessageFormatError. Error was: {error}"
            )
        return None

    def get_incident_details(self, message: str) -> dict | None:
        """
        Function to get incident  details from the alert description
        """
        anomaly_sub_type = extract_from_regex(
            message,
            "0",
            rf"{field_mapper(Constants.anomaly_sub_type)}:\[(.*?)\]",
        )
        if anomaly_sub_type is None or anomaly_sub_type == "0":
            return None
        anomaly_sub_type = get_backup_anomaly(int(anomaly_sub_type))
        job_id = extract_from_regex(
            message,
            "0",
            rf"{field_mapper(Constants.job_id)} \[(.*?)\]",
        )

        description = format_alert_description(message)

        job_details = self.get_job_details(job_id)
        if job_details is None:
            demisto.info(f"Invalid job [{job_id}]")
            return None
        job_start_time = int(
            job_details.get("jobs", [{}])[0].get("jobSummary", {}).get("jobStartTime")
        )
        job_end_time = int(
            job_details.get("jobs", [{}])[0].get("jobSummary", {}).get("jobEndTime")
        )
        subclient_id = (
            job_details.get("jobs", [{}])[0]
            .get("jobSummary", {})
            .get("subclient", {})
            .get("subclientId")
        )
        files_list, scanned_folder_list = self.fetch_file_details(job_id, subclient_id)
        details = {
            "subclient_id": subclient_id,
            "files_list": files_list,
            "scanned_folder_list": scanned_folder_list,
            "anomaly_sub_type": anomaly_sub_type,
            "severity": self.define_severity(anomaly_sub_type),
            "originating_client": extract_from_regex(
                message,
                "",
                rf"{field_mapper(Constants.originating_client)} \[(.*?)\]",
            ),
            "affected_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}:\[(.*?)\]".format(
                        field_mapper(Constants.affected_files_count)
                    ),
                )
            ),
            "modified_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(
                        field_mapper(Constants.modified_files_count)
                    ),
                )
            ),
            "deleted_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(
                        field_mapper(Constants.deleted_files_count)
                    ),
                )
            ),
            "renamed_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(
                        field_mapper(Constants.renamed_files_count)
                    ),
                )
            ),
            "created_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(
                        field_mapper(Constants.created_files_count)
                    ),
                )
            ),
            "job_start_time": datetime.utcfromtimestamp(job_start_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "job_end_time": datetime.utcfromtimestamp(job_end_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "job_id": job_id,
            "external_link": extract_from_regex(
                message, "", "href='(.*?)'", 'href="(.*?)"'
            ),
            "description": description,
        }
        return details

    def get_job_details(self, job_id: Union[int, str] | None) -> dict | None:
        """
        Get job details by job Id
        :param job_id: Job Id
        :return: string
        """
        out = None
        response = self.http_request("GET", "/Job/" + str(job_id), None)
        if ("totalRecordsWithoutPaging" in response) and (
            int(response["totalRecordsWithoutPaging"]) > 0
        ):
            out = response
        return out

    def get_files_list(self, job_id: Union[int, str]) -> list:
        """
        Get file list from analysis job
        :param job_id: Job Id
        :return: list
        """
        self.job_details_body["advOptions"] = {
            "advConfig": {"browseAdvancedConfigBrowseByJob": {"jobId": int(job_id)}}
        }
        resp = self.http_request("POST", "/DoBrowse", None, self.job_details_body)
        browse_responses = resp.get("browseResponses", [])
        file_list = []
        for browse_resp in browse_responses:
            if browse_resp.get("respType") == 0:
                browse_result = browse_resp.get("browseResult")
                if "dataResultSet" in browse_result:
                    for data_result_set in browse_result.get("dataResultSet"):
                        file = {}
                        filepath = data_result_set.get("path")
                        file["sizeinkb"] = data_result_set.get("size")
                        file["folder"] = "\\".join(filepath.split("\\")[:-1])
                        file["filename"] = data_result_set.get("displayName")
                        file_list.append(file)
        return file_list

    def get_key_vault_access_token(self) -> str | None:
        """
        Get access token to get/set secret in azure keyvault
        :return:
        """
        access_token = None
        try:
            url = f"https://login.microsoftonline.com/{self.keyvault_tenant_id}/oauth2/token"  # disable-secrets-detection
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "grant_type": "client_credentials",
                "client_id": self.keyvault_client_id,
                "client_secret": self.keyvault_client_secret,
                "resource": "https://vault.azure.net",  # disable-secrets-detection
            }
            demisto.debug("Trying to login to keyvault...")
            response = requests.post(url, headers=headers, data=data)
            access_token = response.json().get("access_token")
        except Exception as error:
            demisto.debug(
                f"Failed to generate the access token to connect to Azure Keyvault due to [{error}]"
            )
        return access_token

    def get_secret_from_key_vault(self) -> str | None:
        """
        Read secret from key vault
        :return:
        """
        secret = None
        keyvault_access_token = self.get_key_vault_access_token()
        url = f"{self.keyvault_url}/secrets/{self.key_secret_name}?api-version=7.2"
        headers = {"Authorization": f"Bearer {keyvault_access_token}"}
        response = requests.get(url, headers=headers)
        response_json = response.json()
        if "error" in response_json:
            if "was not found in this key vault" in response_json.get("error", {}).get(
                "message", ""
            ):
                secret = None
        else:
            secret = response_json.get("value")
        return secret

    def set_secret_in_key_vault(self, secret_key_value: str) -> bytes:
        """
        Set secret in azure key vault
        :return:
        """
        keyvault_access_token = self.get_key_vault_access_token()
        endpoint = f"{self.keyvault_url}/secrets/{self.key_secret_name}?api-version=7.2"
        headers = {
            "Authorization": f"Bearer {keyvault_access_token}",
            "Content-Type": "application/json",
        }
        body = {"value": secret_key_value}
        response = requests.put(endpoint, headers=headers, json=body)
        return response.content

    def disable_providers(self, identity_server_name: str) -> bool:
        """
        :param identity_server_name: Identity Server to disable
        :return: True/False
        """
        not_enable = False
        try:
            response = self.http_request("GET", f"/V4/SAML/{identity_server_name}")
            if "error" in response:
                demisto.debug(
                    f"Error [{response.get('error', {}).get('errorString', '')}]"
                )
                return False
            if response.get("enabled"):
                demisto.debug(
                    f"SAML is enabled for identity server [{identity_server_name}]. Going to disable it"
                )
                body = {"enabled": not_enable, "type": "SAML"}
                response = self.http_request(
                    "PUT",
                    f"/V4/SAML/{identity_server_name}",
                    json_data=body,
                )
                if response.get("errorCode", 0) > 0:
                    demisto.debug(
                        f"Could not disable as [{response.get('errMessage')}]"
                    )
                    return False
        except Exception as error:
            demisto.debug(f"Could not disable identity provider due to [{error}]")
            return False
        return True

    def fetch_and_disable_saml_identity_provider(self) -> bool:
        """
        Fetch SAML Providers and disable them
        """
        response = self.http_request("GET", "/IdentityServers")
        if "errorMessage" in response:
            return False
        identity_servers = []
        if "identityServers" in response:
            identity_servers = response["identityServers"]
        saml_identity_servers = [s for s in identity_servers if s.get("type") == 1]
        for identity_server_info in saml_identity_servers:
            identity_server_name = identity_server_info.get("IdentityServerName")
            if self.disable_providers(identity_server_name):
                demisto.debug(f"Identity Server [{identity_server_name}] is disabled")
        return True

    def disable_user(self, user_email: str) -> bool:
        """
        Disable user
        :return: True/False
        """
        user_id = None
        try:
            response = self.http_request("GET", "/User?level=10")
            userslist = response["users"]
            current_user = next(
                (
                    user
                    for user in userslist
                    if user.get("email") == user_email or user.get("UPN") == user_email
                ),
                None,
            )
            if current_user:
                user_id = str(current_user.get("userEntity", {}).get("userId"))
                response = self.http_request("GET", f"/User/{user_id}")
                if response.get("users", [{}])[0].get("enableUser"):
                    response = self.http_request("PUT", f"/User/{user_id}/Disable")
                    if response.get("response", [{}])[0].get("errorCode") > 0:
                        demisto.debug(f"Failed to disable user [{user_email}].")
                        return False
                else:
                    demisto.debug(f"User [{user_email}] is already disabled.")
            else:
                demisto.debug(f"Could not find user with email [{user_email}]")
                return False
        except Exception as error:
            demisto.debug(f"Could not disable user [{user_email}] due to [{error}]")
            return False
        return True

    def get_client_id(self) -> str:
        """
        Get client id from the client name
        """

        clientname = (
            demisto.incident().get("CustomFields", {}).get("commvaultoriginatingclient")
        )
        if clientname is not None:
            resp = self.http_request("GET", "/GetId?clientname=" + clientname)
            return str(resp.get("clientId"))
        return "0"

    def is_port_in_use(self, port: int) -> bool:
        """
        Check if port is available
        :return:True/False
        """
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_:
            if port > 0:
                return socket_.connect_ex(("localhost", port)) == 0
            return False

    def disable_data_aging(self) -> dict:
        """
        Disable data aging for the given client
        """
        clientId = self.get_client_id()
        requestObj = {
            "clientProperties": {
                "Client": {"ClientEntity": {"clientId": int(clientId)}},
                "clientProps": {
                    "clientActivityControl": {
                        "activityControlOptions": [
                            {
                                "activityType": 16,
                                "enableActivityType": False,
                                "enableAfterADelay": False,
                            }
                        ]
                    }
                },
            }
        }
        response = self.http_request(
            "POST", "/Client/" + str(clientId), None, requestObj
        )

        return response

    def validate_azure_keyvault_configuration(self) -> bool:
        """
        Validate Azure Keyvault Configuration
        :return: True/False
        """
        if (
            (self.keyvault_url is not None and len(self.keyvault_url) != 0)
            or (
                self.keyvault_client_id is not None
                and len(self.keyvault_client_id) != 0
            )
            or (
                self.keyvault_client_secret is not None
                and len(self.keyvault_client_secret) != 0
            )
            or (
                self.keyvault_tenant_id is not None
                and len(self.keyvault_tenant_id) != 0
            )
        ):
            if (
                (self.keyvault_url is None or len(self.keyvault_url) == 0)
                or (
                    self.keyvault_client_id is None or len(self.keyvault_client_id) == 0
                )
                or (
                    self.keyvault_client_secret is None
                    or len(self.keyvault_client_secret) == 0
                )
                or (
                    self.keyvault_tenant_id is None or len(self.keyvault_tenant_id) == 0
                )
            ):
                return False
            else:
                if self.get_key_vault_access_token() is None:
                    return False
        return True

    def list_recovery_target(self):
        """
        This function lists all available recovery targets and returns the ID of the first recovery target in the list.

        Returns:
            str: The ID of the first recovery target in the list, or None if no recovery targets are found.
        """
        recovery_target_id = None
        response = self.http_request("GET", "/V4/recoverytargets", None)
        if response is not None and "recoveryTargets" in response:
            targets = response["recoveryTargets"]
            for current_target in targets:
                # Always selecting first recovery target with application type CLEAN_ROOM
                if current_target.get("applicationType") == "CLEAN_ROOM":
                    recovery_target_id = current_target["id"]
                    break
        return recovery_target_id

    def search_recovery_group(self, recovery_group_name):
        """
        This function searches for a recovery group with the given name and returns its ID if found.

        Args:
            recovery_group_name (str): The name of the recovery group to search for.

        Returns:
            str: The ID of the recovery group if found, or None if not found.
        """
        recovery_group_id = None
        response = self.http_request("GET", "/recoverygroups")
        if response is not None and "recoveryGroups" in response:
            groups = response["recoveryGroups"]
            for group in groups:
                current_group_name = group["name"].lower()
                if current_group_name == recovery_group_name.lower():
                    recovery_group_id = group["id"]
                    demisto.info(
                        "Found recovery group {} with id [{}]".format(
                            recovery_group_name, recovery_group_id
                        )
                    )
        return recovery_group_id

    def add_recovery_group(self, target_id, recovery_group_name):
        """
        This function creates a new recovery group with the given name and target ID, or returns the ID of an existing
        recovery group with the same name.

        Args:
            target_id (str): The ID of the recovery target to associate with the recovery group.
            recovery_group_name (str): The name of the recovery group to create or search for.

        Returns:
            str: The ID of the newly created or existing recovery group.
        """
        recovery_group_id = None
        recovery_group_id = self.search_recovery_group(recovery_group_name)
        if recovery_group_id is None:
            data = {
                "name": recovery_group_name,
                "target": {"id": target_id},
                "recoveryPointDetails": {
                    "recoveryPoint": 0,
                    "recoveryPointCategory": "AUTOMATIC",
                },
            }
            response = self.http_request("POST", "/recoverygroup", json_data=data)
            if response is not None and "recoveryGroup" in response:
                recovery_group_id = response["recoveryGroup"]["id"]
        else:
            demisto.info(f"Recovery group exists with id [{recovery_group_id}]")
        return recovery_group_id

    def add_vm_to_recovery(
        self, target_id, recovery_group_id, vm_info, recovery_point_timestamp
    ):
        """
        This function adds a virtual machine to a recovery group with the specified recovery point timestamp.

        Args:
            target_id (str): The ID of the recovery target.
            recovery_group_id (str): The ID of the recovery group to add the VM to.
            vm_info (dict): A dictionary containing information about the VM, including backupSetId, vmGuid, vmName,
                vmGroupId, and hypervisorId.
            recovery_point_timestamp (int): The recovery point timestamp for the VM.

        Returns:
            bool: True if the VM was successfully added to the recovery group, False otherwise.
        """
        data = {
            "entities": [
                {
                    "backupSet": {"id": vm_info["backupSetId"]},
                    "virtualMachine": {
                        "GUID": vm_info["vmGuid"],
                        "name": vm_info["vmName"],
                    },
                    "target": {"id": target_id},
                    "recoveryGroup": {"id": recovery_group_id},
                    "vmGroup": {"id": vm_info["vmGroupId"]},
                    "client": {"id": vm_info["hypervisorId"]},
                    "recoveryPointDetails": {
                        "entityRecoveryPoint": recovery_point_timestamp,
                        "inheritedFrom": "RECOVERY_ENTITY",
                        "entityRecoveryPointCategory": "POINT_IN_TIME",
                    },
                    "workload": 8,
                }
            ]
        }

        response = self.http_request(
            "POST", f"/recoverygroup/{recovery_group_id}/entity", json_data=data
        )
        if response is not None:
            if response["errorCode"] == 0:
                demisto.info(
                    "Added the entity VM [{}] to recovery group".format(
                        vm_info["vmName"]
                    )
                )
            else:
                demisto.info(
                    "Error code [{}] : Failed to add entity due to [{}]".format(
                        response["errorCode"], response["errorMessage"]
                    )
                )
        else:
            demisto.error(f"Status code [{response.status_code}]")
            return False
        return True

    def fetch_vm_details(self, vm_name):
        """
        This function fetches details of a virtual machine with the given name.

        Args:
            vm_name (str): The name of the virtual machine to fetch details for.

        Returns:
            dict: A dictionary containing information about the VM, including vmName, vmGroupId, hypervisorId, vmGuid,
                and backupSetId. If the VM is not found, an empty dictionary is returned.
        """
        vm_info = {}
        headers = self.headers
        headers["pagingInfo"] = f"0,{Constants.max_vm_fetch}"
        response = self.http_request("GET", "/v4/virtualmachines", headers=headers)
        if response is not None and "virtualMachines" in response:
            vms = response["virtualMachines"]
            for vm in vms:
                current_vm_name = vm["name"].lower()
                if current_vm_name == vm_name.lower():
                    demisto.info(f"Found VM [{current_vm_name}] ")
                    vm_info["vmName"] = vm_name
                    vm_info["vmGroupId"] = vm["vmGroup"]["id"]
                    vm_info["hypervisorId"] = vm["hypervisor"]["id"]
                    vm_info["vmGuid"] = vm["UUID"]
                    if "backupset" in vm:
                        vm_info["backupSetId"] = vm["backupset"]["backupSetId"]
        return vm_info

    def get_point_in_time_timestamp(self, input_date):
        """
        This function calculates a timestamp for a point in time based on the number of days specified.

        Args:
            num_days (int): The number of days to go back from the current time.

        Returns:
            int: The timestamp for the specified point in time.
        """
        epoch_time = None
        try:
            dt = datetime.strptime(input_date, "%d:%m:%Y %H:%M:%S")
            dt = dt.replace(tzinfo=None)
            epoch_time = int(dt.timestamp())
        except Exception:
            demisto.error(
                "Invalid recovery point format. Use format dd:mm:yyyy hh:mm:ss"
            )
        return epoch_time

    def add_vm_to_recovery_group(self, vm_name, inpute_date):
        point_in_time_ts = self.get_point_in_time_timestamp(inpute_date)
        demisto.error(f"Point in time reference {point_in_time_ts}")
        recovery_group_name = Constants.default_recovery_group_name
        target_id = self.list_recovery_target()
        demisto.debug(f"Target Id {target_id}")
        if target_id is not None:
            vm_info = self.fetch_vm_details(vm_name)
            demisto.debug(f"Found VM with details {vm_info}")
            if len(vm_info) > 0:
                recovery_group_id = self.add_recovery_group(
                    target_id, recovery_group_name
                )
                if recovery_group_id is not None:
                    if self.add_vm_to_recovery(
                        target_id, recovery_group_id, vm_info, point_in_time_ts
                    ):
                        return True
                    else:
                        raise Exception(f"Add VM [{vm_name}] to recovery group failed.")
                else:
                    raise Exception("Recovery group is not available.")
            else:
                raise Exception("VM information is not available.")
        else:
            raise Exception("Recovery target is not available.")
        return False

    def run_uvicorn_server(
        self, port: int, certificate_path: str | None, private_key_path: str | None
    ) -> None:
        """
        Start uvicorn server
        """
        try:
            ssl_args = {}  # type: ignore
            if certificate_path and private_key_path:
                ssl_args["ssl_certfile"] = certificate_path
                ssl_args["ssl_keyfile"] = private_key_path
            integration_logger = IntegrationLogger()
            integration_logger.buffering = False
            log_config = dict(uvicorn.config.LOGGING_CONFIG)
            log_config["handlers"]["default"]["stream"] = integration_logger
            log_config["handlers"]["access"]["stream"] = integration_logger
            log_config["formatters"]["access"] = {
                "()": GenericWebhookAccessFormatter,
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"',
            }
            if port > 0:
                while True:
                    uvicorn.run(
                        app,
                        host="0.0.0.0",  # disable-secrets-detection
                        port=port,
                        log_config=log_config,
                        **ssl_args,  # type: ignore
                    )
        except Exception as error:
            demisto.error(
                f"An error occurred in the long running loop: {str(error)} - {format_exc()}"
            )
            demisto.updateModuleHealth(f"An error occurred: {str(error)}")


def fetch_incidents(
    client, last_run, first_fetch_time
) -> tuple[dict, Union[list, None]]:
    max_fetch = demisto.params().get("max_fetch")

    events = client.get_events_list(
        None if (last_run is None) else last_run, first_fetch_time, max_fetch
    )

    current_date = datetime.utcnow()
    epoch = datetime(1970, 1, 1)

    seconds_since_epoch = int((current_date - epoch).total_seconds())
    out = []

    if events is None:
        demisto.info("There are no events")
        return {"lastRun": str(seconds_since_epoch)}, None
    domain = client.get_host()

    events = sorted(events, key=lambda d: d.get("timeSource"))

    lasttimestamp = None

    for event in events:
        if event.get("eventCodeString") == "14:337":
            lasttimestamp = {"lastRun": str(int(event.get("timeSource")) + 1)}
            event_id = event[
                field_mapper(Constants.event_id, Constants.source_fetch_incidents)
            ]
            event_time = event[
                field_mapper(Constants.event_time, Constants.source_fetch_incidents)
            ]
            incident = {
                "facility": Constants.facility,
                "msg": None,
                "msg_id": None,
                "process_id": None,
                "sd": {},
                "host_name": domain,
                "timestamp": datetime.fromtimestamp(seconds_since_epoch).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "occurred": None,
                "event_id": event_id,
                "event_time": datetime.fromtimestamp(event_time).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "originating_program": event[
                    field_mapper(
                        Constants.originating_program,
                        Constants.source_fetch_incidents,
                    )
                ],
            }
            det = client.get_incident_details(event[Constants.description])
            if det.get(Constants.anomaly_sub_type, "Undefined") == "File Type":  # type: ignore
                incident.update(det)  # type: ignore
                out.append(incident)
    if lasttimestamp is None:
        lasttimestamp = {"lastRun": str(seconds_since_epoch)}
    return lasttimestamp, out


def disable_data_aging(client):
    resp = client.disable_data_aging()
    err_resp = ""
    if resp:
        if "errorCode" in resp and int(resp.get("errorCode")) != 0:
            if resp.get("errorMessage"):
                err_resp = resp.get("errorMessage")
        else:
            err_resp = "Successfully disabled data aging on the client"
    else:
        err_resp = "Error disabling data aging on the client"
    return CommandResults(
        outputs_prefix="CommvaultSecurityIQ.DisableDataAging",
        outputs_key_field="DisableDataAging",
        outputs={"DisableDataAgingResponse": err_resp},
    )


def copy_files_to_war_room():
    files = demisto.incident().get("CustomFields", {}).get("commvaultfileslist")
    out_resp = ""
    for file_ in files if (files is not None) else []:
        out_resp = out_resp + file_["folder"] + "\\" + file_["filename"] + "\n"
    demisto.results(fileResult("Suspiciousfiles.txt", str(out_resp).encode()))
    return "Copied files to the War Room with the file name Suspiciousfiles.txt"


def generate_access_token(client, cv_api_token):
    resp = None
    if client.generate_access_token(cv_api_token):
        resp = "Successfully generated access token"
    else:
        raise DemistoException("Could not generate access token")
    return CommandResults(
        outputs_prefix="CommvaultSecurityIQ.GenerateToken",
        outputs_key_field="GenerateToken",
        outputs={"GenerateTokenResponse": resp},
    )


def fetch_and_disable_saml_identity_provider(client):
    resp = None

    if client.fetch_and_disable_saml_identity_provider():
        resp = "Successfully disabled SAML identity provider"
    else:
        raise DemistoException("Could not disable SAML identity provider")
    return CommandResults(
        outputs_prefix="CommvaultSecurityIQ.DisableSaml",
        outputs_key_field="DisableSaml",
        outputs={"DisableSamlResponse": resp},
    )


def disable_user(client, user_email):
    resp = None

    if client.disable_user(user_email):
        resp = "Successfully disabled user"
    else:
        raise DemistoException(f"Could not disable user :- {user_email}")
    return CommandResults(
        outputs_prefix="CommvaultSecurityIQ.DisableUser",
        outputs_key_field="DisableUser",
        outputs={"DisableUserResponse": resp},
    )


def get_secret_from_key_vault(client):
    client.set_secret_in_key_vault("")
    resp = client.get_secret_from_key_vault()
    if resp is None:
        raise DemistoException("Could not get access token fro keyvault")
    return CommandResults(
        outputs_prefix="CommvaultSecurityIQ.GetAccessToken",
        outputs_key_field="GetAccessToken",
        outputs={"GetAccessTokenResponse": resp},
    )


def add_vm_to_cleanroom(client, vm_name, clean_recovery_point_date):
    resp = None
    if client.add_vm_to_recovery_group(vm_name, clean_recovery_point_date):
        resp = "Successfully added entity to clean room."
    else:
        raise DemistoException("Could not add entity to clean room")
    return CommandResults(
        outputs_prefix="CommvaultSecurityIQ.AddEntityToCleanroom",
        outputs_key_field="AddEntityToCleanroom",
        outputs={"AddEntityToCleanroomResponse": resp},
    )


def get_params(params):
    return (
        params.get("first_fetch", "1 day").strip(),
        params.get("creds_certificate", {}).get("identifier"),
        params.get("creds_certificate", {}).get("password", ""),
        params.get("CVWebserviceUrl", ""),
        params.get("incidentType", "Commvault Suspicious File Activity"),
        params.get("CommvaultAPIToken", {}).get("password"),
        params.get("isFetch", False),
        params.get("longRunning", False),
    )


def validate_inputs(
    portno, client, is_valid_cv_token, is_fetch, is_long_running, forwarding_rule_type
):
    try:
        is_valid_cv_token = True
        if is_fetch and is_long_running:
            raise DemistoException(
                "Please enable only fetch incidents/long running integration"
            )
        if portno > 0 and client.is_port_in_use(portno):
            raise DemistoException(
                f"Port [{portno}] is in use, please specify another port"
            )
        if not is_valid_cv_token:
            raise DemistoException("Invalid Commvault API token/service URL.")
        if not is_fetch and not is_long_running:
            raise DemistoException(
                "Please enable fetch incidents/use forwarding rules."
            )
        else:
            if (
                forwarding_rule_type
                in (
                    Constants.source_syslog,
                    Constants.source_webhook,
                )
                and is_fetch
            ):
                raise DemistoException(
                    "Fetch incidents can not be used with forwarding rule."
                )
        if not client.validate_azure_keyvault_configuration():
            raise DemistoException(
                "Invalid Azure Keyvault configuration. Please provide correct parameters."
            )

    except OSError as error:
        if "Address already in use" in str(error):
            raise DemistoException(
                f"Given port: {portno} is already in use. Please either change port or "
                f"make sure to close the connection in the server using that port."
            )
        raise error


def main() -> None:
    """
    Main function
    """
    global client
    params = demisto.params()
    command = demisto.command()
    (
        first_fetch_time,
        certificate,
        private_key,
        cv_webservice_url,
        incident_type,
        cv_api_token,
        is_fetch,
        is_long_running,
    ) = get_params(params)
    client = Client(base_url=cv_webservice_url + "api", verify=False, proxy=False)
    is_valid_cv_token = True
    # Azure Key Vault Parameters
    client.set_props(params)
    client.qsdk_token = f"QSDK {cv_api_token}"
    forwarding_rule_type: str | None = params.get("forwardingRule")
    port: int = 0
    try:
        if is_long_running and (not is_fetch):
            port = int(params.get("longRunningPort"))
    except (ValueError, TypeError):
        raise DemistoException(
            f"Invalid listen port - {port}. Make sure your port is a number"
        )
    if not is_fetch and is_long_running and (port < 0 or port > MAX_PORT):
        raise DemistoException(
            f"Given port: {port} is not valid and must be between 0-{MAX_PORT}"
        )
    if forwarding_rule_type is not None:
        forwarding_rule_type = forwarding_rule_type.lower()
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if command == "test-module":
            validate_inputs(
                port,
                client,
                is_valid_cv_token,
                is_fetch,
                is_long_running,
                forwarding_rule_type,
            )
            return_results("ok")
        elif command == "fetch-incidents":
            lr = demisto.getLastRun()
            last_fetch, out = fetch_incidents(
                client,
                last_run=({} if lr is None else lr).get("lastRun"),
                first_fetch_time=first_fetch_time,
            )
            demisto.setLastRun(last_fetch)
            if (out is None) or len(out) == 0:
                demisto.incidents([])
            else:
                seconds_since_epoch = (
                    date_to_timestamp(datetime.now(), date_format="%Y-%m-%dT%H:%M:%S")
                    // 1000
                )
                client.create_incident(
                    out,
                    datetime.fromtimestamp(seconds_since_epoch),
                    incident_type,
                    True,
                )
        elif command == "long-running-execution":
            try:
                certificate_path = ""
                private_key_path = ""
                if certificate and private_key:
                    with NamedTemporaryFile(delete=False) as certificate_file:
                        certificate_path = certificate_file.name
                        certificate_file.write(bytes(certificate, "utf-8"))
                    with NamedTemporaryFile(delete=False) as private_key_file:
                        private_key_path = private_key_file.name
                        private_key_file.write(bytes(private_key, "utf-8"))
                if forwarding_rule_type == Constants.source_syslog:
                    server: StreamServer = client.prepare_globals_and_create_server(
                        port, certificate_path, private_key_path
                    )
                    server.serve_forever()
                if forwarding_rule_type == Constants.source_webhook:
                    client.run_uvicorn_server(port, certificate_path, private_key_path)
            except Exception as error:
                demisto.error(
                    f"An error occurred in the long running loop: {str(error)} - {format_exc()}"
                )
                demisto.updateModuleHealth(f"An error occurred: {str(error)}")
            finally:
                if certificate_path:
                    os.unlink(certificate_path)
                if private_key_path:
                    os.unlink(private_key_path)
                time.sleep(5)
        elif command == "commvault-security-set-disable-data-aging":
            return_results(disable_data_aging(client))
        elif command == "commvault-security-get-generate-token":
            return_results(generate_access_token(client, cv_api_token))
        elif command == "commvault-security-set-disable-saml-provider":
            return_results(fetch_and_disable_saml_identity_provider(client))
        elif command == "commvault-security-set-disable-user":
            user_email = demisto.args().get("user_email")
            return_results(disable_user(client, user_email))
        elif command == "commvault-security-get-access-token-from-keyvault":
            return_results(get_secret_from_key_vault(client))
        elif command == "commvault-security-get-copy-files-list-to-war-room":
            return_results(copy_files_to_war_room())
        elif command == "commvault-security-set-cleanroom-add-vm-to-recovery-group":
            vm_name = demisto.args().get("vm_name")
            clean_recovery_point_time = demisto.args().get("clean_recovery_point")
            return_results(
                add_vm_to_cleanroom(client, vm_name, clean_recovery_point_time)
            )
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    # Log exceptions and return errors
    except Exception as error:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(error)}"
        )


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
