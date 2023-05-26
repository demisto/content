import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import os
import re
import time
from copy import copy
from dataclasses import dataclass
from datetime import datetime
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import Any, Dict, List, Optional, Tuple

import requests
import syslogmp
import urllib3
import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from gevent.server import StreamServer
from pydantic import BaseModel
from uvicorn.logging import AccessFormatter
from urllib.parse import urlparse


# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

" CONSTANTS "
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
    name: Optional[str] = None
    type: Optional[str] = None
    occurred: Optional[str] = None
    raw_json: Optional[Dict] = None


client = None

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name="Authorization")


class GenericWebhookAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: Dict) -> str:
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
        scope = recordcopy.__dict__["scope"]
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({"user_agent": user_agent})
        return super().formatMessage(recordcopy)


@app.post("/")
async def handle_post(
    incident: dict,
    request: Request,
    credentials: HTTPBasicCredentials = Depends(basic_auth),
    token: APIKey = Depends(token_auth),
):
    global client
    try:
        incident_type: Optional[str] = demisto.params().get(
            "incident_type", "Suspicious File Activity"
        )
        current_date = datetime.utcnow()
        epoch = datetime(1970, 1, 1)
        seconds_since_epoch = (current_date - epoch).total_seconds()
        timestamp = datetime.fromtimestamp(seconds_since_epoch)
        event_id = incident[
            field_mapper(Constants.event_id, Constants.source_webhook)
        ]
        event_time = incident[
            field_mapper(Constants.event_time, Constants.source_webhook)
        ]
        hostname = request.client.host  # type: ignore
        incident_body = {
            "facility": Constants.facility,
            "msg": None,
            "msg_id": None,
            "process_id": None,
            "sd": {},
            "timestamp": datetime.fromtimestamp(seconds_since_epoch).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "version": None,
            "occurred": None,
            "originating_program": incident[
                field_mapper(
                    Constants.originating_program, Constants.source_webhook
                )
            ],
            "event_id": event_id,
            "event_time": event_time,
            "host_name": hostname,
        }
        incident_body.update(
            client.get_incident_details(incident["Description"])  # type: ignore
        )
    except Exception as err:
        logging.error(f"could not print REQUEST: {err}")
        return {"status": "ERR"}

    credentials_param = demisto.params().get("credentials")
    if credentials_param and credentials_param.get("identifier"):
        username = credentials_param.get("identifier")
        password = credentials_param.get("password", "")
        auth_failed = False
        header_name = None
        if username.startswith("_header"):
            header_name = username.split(":")[1]
            token_auth.model.name = header_name
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (
            not (
                compare_digest(credentials.username, username)
                and compare_digest(credentials.password, password)
            )
        ):
            auth_failed = True
        if auth_failed:
            request_headers = dict(request.headers)
            secret_header = (header_name or "Authorization").lower()
            if secret_header in request_headers:
                request_headers[secret_header] = "***"
            demisto.debug(
                f"Authorization failed - request headers {request_headers}"
            )
            return Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content="Authorization failed.",
            )

    client.create_incident(incident_body, timestamp, incident_type, False)  # type: ignore

    return "OK"


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


def if_zero_set_none(value: Optional[str]) -> Optional[str]:
    """
    If the value is zero, return None
    """
    if value and int(value) > 0:
        return value
    return None


def extract_from_regex(
    message: str, default_value: Optional[str], *regex_string_args: str
) -> Optional[str]:
    """
    From the message, extract the strings matching the given patterns
    """
    try:
        for pattern in regex_string_args:
            matches = re.search(pattern, message, re.IGNORECASE)
            if matches and len(matches.groups()) > 0:
                return matches.group(1).strip()
    except Exception as error:
        logging.error(
            f"Error occured in extract_from_regex. Exception [{error}]"
        )
    return default_value


def format_alert_description(msg: str) -> str:
    """
    Format alert description
    """
    default_value = msg
    resp = re.search("<html>(.*)</html>", msg, re.IGNORECASE)
    if resp and len(resp.groups()) > 0:
        msg = resp.group(1).strip()
        if msg:
            msg = re.sub("<span.*</span>", "", msg)
            if msg:
                msg = re.sub("Please click.*details.", "", msg)
                return msg
            return msg
    return default_value


def update_integration_context_samples(
    incident: dict, max_samples: int = MAX_SAMPLES
) -> None:
    """
    Updates the integration context samples with the newly created incident.
    If the size of the samples has reached `MAX_SAMPLES`, will pop out the latest sample.
    Args:
        incident (dict): The newly created incident.
        max_samples (int): Max samples size.

    Returns:
        (None): Modifies the integration context samples field.
    """
    ctx = get_integration_context()
    updated_samples_list: List[Dict] = [incident] + ctx.get("samples", [])
    if len(updated_samples_list) > max_samples:
        updated_samples_list.pop()
    ctx["samples"] = updated_samples_list
    set_integration_context(ctx)


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
    facility: str = "Commvault"
    severity_high: str = "High"
    severity_info: str = "Informational"
    path_key: str = "path"
    source_syslog: str = "syslog"
    source_webhook: str = "webhook"
    source_fetch_incidents: str = "fetch"
    description: str = "description"


def field_mapper(
    field_name: str, source: str = Constants.source_syslog
) -> str:
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
        super().__init__(base_url=base_url, verify=False, proxy=False)
        self.qsdk_token = None
        self.ws_url = base_url

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
        params: Optional[dict] = None,
        json_data: Optional[Dict[str, Any]] = None,
        ignore_empty_response: bool = False,
        headers: Optional[dict] = None,
    ) -> Dict:
        """
        Function to make http calls
        """
        try:
            demisto.debug(f"Calling {endpoint} ")
            if not headers:
                headers = self.headers
            response = self._http_request(
                method=method.upper(),
                url_suffix=endpoint,
                headers=headers,
                json_data=json_data,
                params=params,
                resp_type="response",
                return_empty_response=ignore_empty_response,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            error_msg = HTTP_ERRORS.get(exc.response.status_code)
            if error_msg:
                raise DemistoException(
                    f"{error_msg}", res=exc.response
                ) from exc
            raise
        retval = response.json()

        return retval

    def validate_session_or_generate_token(self, api_token: str) -> bool:
        """
        Check for last token generation and generate new token
        """
        if self.access_token_last_generation is None:
            demisto.debug("Token is not present, we will create new token.")
            if not self.generate_access_token(api_token):
                return False
        else:
            current_epoch = int(datetime.now().timestamp())
            token_expiry_from_last_generation = (
                self.access_token_last_generation
                + self.access_token_expiry_in_days * 7 * 24 * 60 * 60
            )
            if current_epoch > token_expiry_from_last_generation:
                demisto.debug("Token is expired, re-generating")
                if not self.generate_access_token(api_token):
                    return False
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
        response = self.http_request(
            "POST", "/ApiToken/User", None, request_body
        )
        try:
            new_access_token = response["token"]
            current_epoch = int(datetime.now().timestamp())
            self.current_api_token = new_access_token
            self.qsdk_token = "QSDK {}".format(new_access_token)
            self.access_token_last_generation = current_epoch
            set_integration_context({"accessToken": new_access_token})
            set_integration_context(
                {"acessTokenGenerationTime": current_epoch}
            )
        except KeyError as error:
            demisto.debug(f"Could not generate access token [{error}]")
            return False
        return True

    def prepare_globals_and_create_server(
        self,
        port: int,
        certificate: Optional[str],
        private_key: Optional[str],
    ) -> StreamServer:
        """
        Prepares global environments of LOG_FORMAT and creates the server to listen
        to Syslog messages.
        Args:
            port (int): Port
            certificate (Optional[str]): Certificate. For SSL connection.
            private_key (Optional[str]): Private key. For SSL connection.

        Returns:
            (StreamServer): Server to listen to Syslog messages.
        """
        if certificate and private_key:
            with NamedTemporaryFile(delete=False) as certificate_file:
                certificate_path = certificate_file.name
                certificate_file.write(bytes(certificate, "utf-8"))

            with NamedTemporaryFile(delete=False) as private_key_file:
                private_key_path = private_key_file.name
                private_key_file.write(bytes(private_key, "utf-8"))
            server = StreamServer(
                ("0.0.0.0", port),
                self.perform_long_running_execution,
                keyfile=private_key_path,
                certfile=certificate_path,
            )
            demisto.debug("Starting HTTPS Server")
        else:
            server = StreamServer(
                ("0.0.0.0", port), self.perform_long_running_execution
            )
            demisto.debug("Starting HTTP Server")
        return server

    def perform_long_running_execution(
        self, sock: Any, address: tuple
    ) -> None:
        """
        The long running execution loop. Gets input, and performs a while True loop and logs any error that happens.
        Stops when there is no more data to read.
        Args:
            sock: Socket.
            address(tuple): Address. Not used inside loop so marked as underscore.

        Returns:
            (None): Reads data, calls   that creates incidents from inputted data.
        """
        demisto.debug("Starting long running execution")
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
                    demisto.error(
                        traceback.format_exc()
                    )  # print the traceback
                    demisto.error(
                        f"Error occurred during long running loop. Error was: {error}"
                    )
                finally:
                    demisto.debug("Finished reading message")
        finally:
            file_obj.close()

    def perform_long_running_loop(self, socket_data: bytes) -> None:
        """
        Function to start long running loop
        """
        incident_type: str = demisto.params().get(
            "incident_type", "Suspicious File Activity"
        )

        extracted_message = self.parse_incoming_message(socket_data)
        if extracted_message:
            demisto.debug("Succeeded in parsing the message ")
        else:
            demisto.debug("Failed in parsing the message ")
        if extracted_message:
            dts = datetime.fromisoformat(extracted_message["timestamp"])
            self.create_incident(extracted_message, dts, incident_type, False)

    def create_incident(
        self,
        extracted_message: Union[List, Dict[str, Any]],
        date_obj: datetime,
        incident_type: str,
        is_fetch: bool,
    ) -> None:
        """
        Function to start create incidents
        """
        date_str = date_obj.strftime("%d %B, %Y, %H:%M:%S")
        incidents = []
        if type(extracted_message) != list:
            extracted_message = [extracted_message]
        for message_ in extracted_message:
            incident = {
                "name": f"Suspicious File Activity Detected at [{date_str}]",
                "rawJSON": json.dumps(message_),
                "occurred": message_["occurred"],
                "type": incident_type,
                "details": "\n".join(
                    [f"{k}: {v}" for k, v in message_.items() if v]
                ),
            }
            incidents.append(incident)
        if is_fetch:
            demisto.incidents(incidents)
            # self.define_indicator(extracted_message["originating_client"])
        else:
            demisto.createIncidents(incidents)
            # self.define_indicator(extracted_message["originating_client"])

    def get_events_list(self) -> Optional[List]:
        """
        Function to get events
        """
        self.validate_session_or_generate_token(self.current_api_token)
        current_date = datetime.utcnow()
        epoch = datetime(1970, 1, 1)
        seconds_since_epoch = int((current_date - epoch).total_seconds())
        interval = demisto.params().get("incidentFetchInterval")
        from_time = int(seconds_since_epoch - int(interval) * 60)
        event_endpoint = f"""/events?level=10&showInfo=false&showMinor=false
        &showMajor=true&showCritical=false&lastDuration=1
        &fromTime={from_time}&toTime={seconds_since_epoch}"""
        headers = self.headers
        headers["pagingInfo"] = "-1"
        resp = self.http_request("GET", event_endpoint, None, headers=headers)
        if resp and resp["commservEvents"]:
            return resp["commservEvents"]
        return None

    def get_subclient_content_list(
        self, subclient_id: Union[int, str]
    ) -> Dict:
        """
        Get content from subclient
        :param subclient_id: subclient Id
        :return: string
        """
        self.validate_session_or_generate_token(self.current_api_token)
        resp = self.http_request(
            "GET", "/Subclient/" + str(subclient_id), None
        )
        resp = resp["subClientProperties"][0]["content"]
        return resp

    def define_severity(self, anomaly_sub_type: str) -> Optional[str]:
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
        self, job_id: Optional[Union[int, str]], subclient_id: Union[int, str]
    ) -> Tuple[List, List]:
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

    def define_indicator(self, originating_client: str) -> None:
        """
        Define an indicator
        :param originating_client: client which has generated the event
        """
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
        demisto.createIndicators(indicator_list)

    def parse_incoming_message(self, log_message: bytes) -> Optional[Dict]:
        """
        Function to parse incoming message from syslog
        """
        try:
            syslog_message: syslogmp.Message = parse_no_length_limit(
                log_message
            )
        except syslogmp.parser.MessageFormatError as error:
            demisto.debug(
                f"Could not parse the log message, got MessageFormatError. Error was: {error}"
            )
            return None
        self.validate_session_or_generate_token(self.current_api_token)
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
            "timestamp": syslog_message.timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "version": None,
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

        incident.update(self.get_incident_details(message))  # type: ignore
        return incident

    def get_incident_details(self, message: str) -> Optional[Dict]:
        """
        Function to get incident  details from the alert description
        """
        anomaly_sub_type = extract_from_regex(
            message,
            "0",
            r"{}:\[(.*?)\]".format(field_mapper(Constants.anomaly_sub_type)),
        )
        if anomaly_sub_type is None or anomaly_sub_type == "0":
            return None
        anomaly_sub_type = get_backup_anomaly(int(anomaly_sub_type))
        job_id = extract_from_regex(
            message,
            "0",
            r"{} \[(.*?)\]".format(field_mapper(Constants.job_id)),
        )

        description = format_alert_description(message)

        job_details = self.get_job_details(job_id)
        if job_details is None:
            demisto.log(f"Invalid job [{job_id}]")
            return None
        job_start_time = int(
            job_details["jobs"][0]["jobSummary"]["jobStartTime"]
        )
        job_end_time = int(job_details["jobs"][0]["jobSummary"]["jobEndTime"])
        subclient_id = job_details["jobs"][0]["jobSummary"]["subclient"][
            "subclientId"
        ]
        files_list, scanned_folder_list = self.fetch_file_details(
            job_id, subclient_id
        )
        details = {
            "subclient_id": subclient_id,
            "files_list": files_list,
            "scanned_folder_list": scanned_folder_list,
            "anomaly_sub_type": anomaly_sub_type,
            "severity": self.define_severity(anomaly_sub_type),
            "originating_client": extract_from_regex(
                message,
                "",
                r"{} \[(.*?)\]".format(
                    field_mapper(Constants.originating_client)
                ),
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
            "job_start_time": datetime.utcfromtimestamp(
                job_start_time
            ).strftime("%Y-%m-%d %H:%M:%S"),
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

    def get_job_details(
        self, job_id: Optional[Union[int, str]]
    ) -> Optional[Dict]:
        """
        Get job details by job Id
        :param job_id: Job Id
        :return: string
        """
        out = None
        self.validate_session_or_generate_token(self.current_api_token)
        response = self.http_request("GET", "/Job/" + str(job_id), None)
        if response["totalRecordsWithoutPaging"] > 0:
            out = response
        return out

    def get_files_list(self, job_id: Union[int, str]) -> List:
        """
        Get file list from analysis job
        :param job_id: Job Id
        :return: list
        """
        self.job_details_body["advOptions"] = {
            "advConfig": {
                "browseAdvancedConfigBrowseByJob": {"jobId": int(job_id)}
            }
        }
        self.validate_session_or_generate_token(self.current_api_token)
        resp = self.http_request(
            "POST", "/DoBrowse", None, self.job_details_body
        )
        browse_responses = resp["browseResponses"]
        file_list = []
        for browse_resp in browse_responses:
            if browse_resp["respType"] == 0:
                browse_result = browse_resp["browseResult"]
                if "dataResultSet" in browse_result:
                    for data_result_set in browse_result["dataResultSet"]:
                        file = {}
                        filepath = data_result_set["path"]
                        file["sizeinkb"] = data_result_set["size"]
                        file["folder"] = "\\".join(filepath.split("\\")[:-1])
                        file["filename"] = data_result_set["displayName"]
                        file_list.append(file)
        return file_list

    def get_key_vault_access_token(self) -> Optional[str]:
        """
        Get access token to get/set secret in azure keyvault
        :return:
        """
        access_token = None
        try:
            url = f"https://login.microsoftonline.com/{self.keyvault_tenant_id}/oauth2/token"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "grant_type": "client_credentials",
                "client_id": self.keyvault_client_id,
                "client_secret": self.keyvault_client_secret,
                "resource": "https://vault.azure.net",
            }
            demisto.debug("Trying to login to keyvault...")
            response = requests.post(url, headers=headers, data=data)
            access_token = response.json().get("access_token")
        except Exception as error:
            demisto.debug(
                f"Failed to generate the access token to connect to Azure Keyvault due to [{error}]"
            )
        return access_token

    def get_secret_from_key_vault(self) -> Optional[str]:
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
            if (
                "was not found in this key vault"
                in response_json["error"]["message"]
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
            self.validate_session_or_generate_token(self.current_api_token)
            response = self.http_request(
                "GET", "/V4/SAML/{}".format(identity_server_name)
            )
            if "error" in response:
                demisto.debug(f"Error [{response['error']['errorString']}]")
                return False
            else:
                if response["enabled"]:
                    demisto.debug(
                        f"SAML is enabled for identity server [{identity_server_name}]. Going to disable it"
                    )
                    body = {"enabled": not_enable, "type": "SAML"}
                    response = self.http_request(
                        "PUT",
                        "/V4/SAML/{}".format(identity_server_name),
                        json_data=body,
                    )
                    if response["errorCode"] > 0:
                        demisto.debug(
                            f"Could not disable as [{response['errMessage']}]"
                        )
                        return False
        except Exception as error:
            demisto.debug(
                f"Could not disable identity provider due to [{error}]"
            )
        return True

    def fetch_and_disable_saml_identity_provider(self) -> bool:
        """
        Fetch SAML Providers and disable them
        """
        self.validate_session_or_generate_token(self.current_api_token)
        response = self.http_request("GET", "/IdentityServers")
        if "errorMessage" in response:
            return False
        saml_identity_servers = [
            s for s in response["identityServers"] if s["type"] == 1
        ]
        for identity_server_info in saml_identity_servers:
            identity_server_name = identity_server_info["IdentityServerName"]
            if self.disable_providers(identity_server_name):
                demisto.debug(
                    f"Identity Server [{identity_server_name}] is disabled"
                )
        return True

    def disable_user(self, user_email: str) -> bool:
        """
        Disable user
        :return: True/False
        """
        user_id = None
        try:
            self.validate_session_or_generate_token(self.current_api_token)
            response = self.http_request("GET", "/User?level=10")
            current_user = next(
                (
                    user
                    for user in response["users"]
                    if user["email"] == user_email or user["UPN"] == user_email
                ),
                None,
            )
            if current_user:
                user_id = str(current_user["userEntity"]["userId"])
                response = self.http_request("GET", f"/User/{user_id}")
                if response["users"][0]["enableUser"]:
                    response = self.http_request(
                        "PUT", f"/User/{user_id}/Disable"
                    )
                    if response["response"][0]["errorCode"] > 0:
                        demisto.debug(
                            f"Failed to disable user [{user_email}]."
                        )
                        return False
                else:
                    demisto.debug(f"User [{user_email}] is already disabled.")
            else:
                demisto.debug(f"Could not find user with email [{user_email}]")
        except Exception as error:
            demisto.debug(
                f"Could not disable user [{user_email}] due to [{error}]"
            )
        return True

    def get_client_id(self) -> str:
        """
        Get client id from the client name
        """

        clientname = demisto.incident()["CustomFields"]["originatingclient"]
        resp = self.http_request("GET", "/GetId?clientname=" + clientname)
        return resp["clientId"]

    def is_port_in_use(self, port: int) -> bool:
        """
        Check if port is available
        :return:True/False
        """
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_:
            return socket_.connect_ex(("localhost", port)) == 0

    def disable_data_aging(self) -> Dict:
        """
        Disable data aging for the given client
        """
        clientId = self.get_client_id()
        requestObj = {
            "clientProperties": {
                "Client": {"ClientEntity": {"clientId": clientId}},
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
            self.keyvault_url is not None
            or self.keyvault_client_id is not None
            or self.keyvault_client_secret is not None
            or self.keyvault_tenant_id is not None
        ):
            if (
                self.keyvault_url is None
                or self.keyvault_client_id is None
                or self.keyvault_client_secret is None
                or self.keyvault_tenant_id is None
            ):
                return False
        else:
            if self.get_key_vault_access_token() is None:
                return False
        return True

    def run_uvicorn_server(
        self, port: int, certificate: Optional[str], private_key: Optional[str]
    ) -> None:
        """
        Start uvicorn server
        """
        while True:

            certificate_path = ""
            private_key_path = ""
            try:
                ssl_args = {}

                if certificate and private_key:
                    with NamedTemporaryFile(delete=False) as certificate_file:
                        certificate_path = certificate_file.name
                        certificate_file.write(bytes(certificate, "utf-8"))

                    ssl_args["ssl_certfile"] = certificate_path

                    with NamedTemporaryFile(delete=False) as private_key_file:
                        private_key_path = private_key_file.name
                        private_key_file.write(bytes(private_key, "utf-8"))

                    ssl_args["ssl_keyfile"] = private_key_path
                    demisto.debug("Starting HTTPS Server")
                else:
                    demisto.debug("Starting HTTP Server")

                integration_logger = IntegrationLogger()
                integration_logger.buffering = False
                log_config = dict(uvicorn.config.LOGGING_CONFIG)
                log_config["handlers"]["default"][
                    "stream"
                ] = integration_logger
                log_config["handlers"]["access"]["stream"] = integration_logger
                log_config["formatters"]["access"] = {
                    "()": GenericWebhookAccessFormatter,
                    "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"',
                }
                uvicorn.run(
                    app,
                    host="0.0.0.0",
                    port=port,
                    log_config=log_config,
                    **ssl_args,  # type: ignore
                )
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


def fetch_incidents(client: Client) -> List:
    incident_type = demisto.params().get(
        "incident_type", "Suspicious File Activity"
    )
    events = client.get_events_list()
    if events is None:
        demisto.info("There are no events")
        return
    current_date = datetime.utcnow()
    epoch = datetime(1970, 1, 1)

    seconds_since_epoch = int((current_date - epoch).total_seconds())
    out = []

    domain = client.get_host()

    for event in events:
        if event["eventCodeString"] == "14:337":
            event_id = event[
                field_mapper(
                    Constants.event_id, Constants.source_fetch_incidents
                )
            ]
            event_time = event[
                field_mapper(
                    Constants.event_time, Constants.source_fetch_incidents
                )
            ]
            incident = {
                "facility": Constants.facility,
                "msg": None,
                "msg_id": None,
                "process_id": None,
                "sd": {},
                "host_name": domain,
                "timestamp": datetime.fromtimestamp(
                    seconds_since_epoch
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "version": None,
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
            incident.update(det)  # type: ignore
            out.append(incident)
    if len(out) == 0:
        demisto.incidents([])
    else:
        client.create_incident(
            out,
            datetime.fromtimestamp(seconds_since_epoch),
            incident_type,
            True,
        )


def disable_data_aging(client):
    resp = client.disable_data_aging()
    if resp:
        if "errorCode" in resp and int(resp["errorCode"]) != 0:
            if resp["errorMessage"]:
                return_error(resp["errorMessage"])
        else:
            return_outputs("Successfully disabled data aging on the client")
    else:
        return_error("Error disabling data aging on the client")
    return resp


def copy_files_to_war_room():
    try:

        files = demisto.incident()["CustomFields"]["fileslist"]
        out_resp = ""
        for file_ in files:
            out_resp = (
                out_resp
                + file_["folder"]
                + "\\"
                + file_["filename"]
                + "\n"
            )
        demisto.results(
            fileResult("Suspiciousfiles.txt", str(out_resp).encode())
        )
        return "Copied files to the War Room with the file name Suspiciousfiles.txt"
    except Exception as error:
        return None


def generate_access_token(client, cv_api_token):
    return client.generate_access_token(cv_api_token)


def fetch_and_disable_saml_identity_provider():
    return client.fetch_and_disable_saml_identity_provider()


def main() -> None:
    """
    Main function
    """
    global client
    params = demisto.params()
    command = demisto.command()
    message_regex: Optional[str] = params.get("message_regex")
    certificate: Optional[str] = params.get("certificate")
    private_key: Optional[str] = params.get("private_key")
    cv_webservice_url: str = params.get("CVWebserviceUrl")
    cv_api_token: str = params.get("Commvault API Token")
    is_fetch: List[str] = params.get("isFetch")
    client = Client(base_url=cv_webservice_url, verify=False, proxy=False)
    is_valid_cv_token = None
    # Azure Key Vault Parameters
    client.keyvault_url = params.get("AzureKeyVaultUrl")
    client.keyvault_tenant_id = params.get("AzureKeyVaultTenantId")
    client.keyvault_client_id = params.get("AzureKeyVaultClientId")
    client.keyvault_client_secret = params.get("AzureKeyVaultClientSecret")
    is_valid_cv_token = client.validate_session_or_generate_token(cv_api_token)
    forwarding_rule_type: Optional[str] = params.get("forwardingRule")
    port: int = 0
    try:
        if not is_fetch:
            port = int(params.get("longRunningPort"))
    except (ValueError, TypeError):
        raise DemistoException(
            f"Invalid listen port - {port}. Make sure your port is a number"
        )
    if not is_fetch and (port < 0 or MAX_PORT < port):
        raise DemistoException(
            f"Given port: {port} is not valid and must be between 0-{MAX_PORT}"
        )
    if forwarding_rule_type is not None:
        forwarding_rule_type = forwarding_rule_type.lower()
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if command == "test-module":
            try:
                if port > 0:
                    if client.is_port_in_use(port):
                        raise DemistoException(
                            f"Port [{port}] is in use, please specify another port"
                        )
                if not is_valid_cv_token:
                    raise DemistoException(
                        "Invalid Commvault API token. Please check service URL or API token."
                    )
                if not is_fetch:
                    if not (
                        forwarding_rule_type == Constants.source_syslog
                        or forwarding_rule_type == Constants.source_webhook
                    ):
                        raise DemistoException(
                            "Please enable fetch incidents or use forwarding rules."
                        )
                else:
                    if forwarding_rule_type in (
                        Constants.source_syslog,
                        Constants.source_webhook,
                    ):
                        raise DemistoException(
                            "Fetch incidents can not be used with forwarding rule."
                        )
                if client.validate_azure_keyvault_configuration():
                    raise DemistoException(
                        "Invalid Azure Keyvault configuration. Please provide correct parameters."
                    )

            except OSError as error:
                if "Address already in use" in str(error):
                    raise DemistoException(
                        f"Given port: {port} is already in use. Please either change port or "
                        f"make sure to close the connection in the server using that port."
                    )
                raise error
            return_results("ok")
        elif command == "fetch-incidents":
            fetch_incidents(client)

        elif command == "long-running-execution":
            if forwarding_rule_type == Constants.source_syslog:
                server: StreamServer = (
                    client.prepare_globals_and_create_server(
                        port, certificate, private_key
                    )
                )
                server.serve_forever()
            if forwarding_rule_type == Constants.source_webhook:
                client.run_uvicorn_server(port, certificate, private_key)

        elif command == "disable-data-aging":
            disable_data_aging(client)
        elif command == "generate_token":
            generate_access_token(client, cv_api_token)
        elif command == "disable-saml-provider":
            client.fetch_and_disable_saml_identity_provider()
        # elif command == "disable-user":
            # client.disable_user("")
        elif command == "get-access-token-from-keyvault":
            client.set_secret_in_key_vault("")
            client.get_secret_from_key_vault()
        elif command == "copy-files-list-to-war-room":
            copy_files_to_war_room()
        else:
            raise NotImplementedError(
                f"Command '{command}' is not implemented."
            )

    # Log exceptions and return errors
    except Exception as error:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(error)}"
        )


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

register_module_line('ComvmaultSecurityIQ', 'end', __line__())
