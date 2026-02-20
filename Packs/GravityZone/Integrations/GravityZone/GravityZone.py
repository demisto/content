import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""IMPORTS"""

from typing import Any
from datetime import datetime, timedelta, UTC
import base64
import dateparser
import email
import io
import json
import tarfile
import urllib3
import uuid
import zipfile

# Disable insecure warnings

urllib3.disable_warnings()

""" CONSTANTS """


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
GZ_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"  # GravityZone date format with timezone info
INTEGRATION_NAME = "GravityZone"
COMMAND_DOWNLOAD_FILE = "DownloadFile"
COMMAND_RUN_COMMAND = "RunCommand"
COMMAND_KILL_PROCESS = "KillProcess"
COMMAND_ISOLATE = "Isolate"
COMMAND_RESTORE_FROM_ISOLATION = "Deisolate"
COMMAND_UPLOAD_FILE = "UploadFile"

ACTIVITY_STATUS_SUCCESS = "success"
ACTIVITY_STATUS_PENDING = "pending"
ACTIVITY_STATUS_IN_PROGRESS = "in_progress"
ACTIVITY_STATUS_FAILED = "failed"
ACTIVITY_STATUS_TO_BE_RETRIEVED = "to_be_retrieved"

ACTIVITY_TYPE_DOWNLOAD_FILE = 1
ACTIVITY_TYPE_RUN_COMMAND = 2
ACTIVITY_NUMERIC_TO_COMMAND_NAME = {
    ACTIVITY_TYPE_DOWNLOAD_FILE: COMMAND_DOWNLOAD_FILE,
    ACTIVITY_TYPE_RUN_COMMAND: COMMAND_RUN_COMMAND,
}

LIVE_SEARCH_TIMEOUT = 600
LIVE_SEARCH_INTERVAL = 10
LIVE_SEARCH_QUERY_PROCESS_PER_HASH = "QUERY_PROCESS_PER_HASH"
LIVE_SEARCH_QUERY_RUNNING_HASH = "QUERY_RUNNING_HASH"

POLL_TIMEOUT = 1200
POLL_INTERVAL = 10

FETCH_LIMIT = 50

TASK_TYPE_ISOLATE_ENDPOINT_PARENT = 16
TASK_TYPE_RESTORE_ENDPOINT_PARENT = 17
TASK_TYPE_KILL_PROCESS_PARENT = 21
TASK_TYPE_REMOTE_ACCESS_DOWNLOAD_PARENT = 24
TASK_NUMERIC_TO_COMMAND_NAME = {
    TASK_TYPE_KILL_PROCESS_PARENT: COMMAND_KILL_PROCESS,
    TASK_TYPE_ISOLATE_ENDPOINT_PARENT: COMMAND_ISOLATE,
    TASK_TYPE_RESTORE_ENDPOINT_PARENT: COMMAND_RESTORE_FROM_ISOLATION,
    TASK_TYPE_REMOTE_ACCESS_DOWNLOAD_PARENT: COMMAND_UPLOAD_FILE,
}
TASK_STATUS_PENDING = 1
TASK_STATUS_PROCESSING = 2
TASK_STATUS_PROCESSED = 3
TASK_OUTPUT_HEADERS = ["EndpointID", "Hostname", "StartDate", "EndDate", "Error"]


INCIDENT_TYPE_EDR = "incident"
INCIDENT_TYPE_XDR = "extendedIncident"
INCIDENT_TYPE_MAPPING = {
    INCIDENT_TYPE_EDR: "Incident (EDR)",
    INCIDENT_TYPE_XDR: "Extended Incident (XDR)",
}
INCIDENT_STATUS_STR_OPEN = "open"
INCIDENT_STATUS_STR_CLOSED = "closed"
INCIDENT_STATUS_STR_IN_PROGRESS = "in_progress"
INCIDENT_STATUS_STR_FALSE_POSITIVE = "false_positive"

INCIDENT_STATUS_INT_MAPPING = {
    INCIDENT_STATUS_STR_OPEN: IncidentStatus.PENDING,
    INCIDENT_STATUS_STR_CLOSED: IncidentStatus.DONE,
    INCIDENT_STATUS_STR_IN_PROGRESS: IncidentStatus.ACTIVE,
    INCIDENT_STATUS_STR_FALSE_POSITIVE: IncidentStatus.DONE,
}
INCIDENT_STATUS_STR_MAPPING = {
    INCIDENT_STATUS_STR_OPEN: "Pending",
    INCIDENT_STATUS_STR_CLOSED: "Done",
    INCIDENT_STATUS_STR_IN_PROGRESS: "Active",
    INCIDENT_STATUS_STR_FALSE_POSITIVE: "Done",
}

GRAVITY_ZONE_INCIDENT_STATUS_OPEN = 1
GRAVITY_ZONE_INCIDENT_STATUS_IN_PROGRESS = 2
GRAVITY_ZONE_INCIDENT_STATUS_DONE = 3
GRAVITY_ZONE_INCIDENT_STATUS_FALSE_POSITIVE = 4

INCIDENT_STATUS_MAPPING = {
    IncidentStatus.DONE: GRAVITY_ZONE_INCIDENT_STATUS_DONE,
    IncidentStatus.ARCHIVE: GRAVITY_ZONE_INCIDENT_STATUS_DONE,
    IncidentStatus.PENDING: GRAVITY_ZONE_INCIDENT_STATUS_OPEN,
    IncidentStatus.ACTIVE: GRAVITY_ZONE_INCIDENT_STATUS_IN_PROGRESS,
}

ENDPOINT_DEVICE_STATE_MAPPING = {1: "Online", 2: "Offline", 3: "Offline"}


""" CLIENT CLASS """


class Client(BaseClient):
    @logger
    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        jwt_token: str | None = None,
        verify: bool = True,
        proxy: bool = False,
    ):
        """
        Client class to interact with GravityZone API.
        Args:
            url (str): Base URL of the GravityZone API.
            api_key (Optional[str]): API key for Basic Authentication.
            jwt_token (Optional[str]): JWT token for Bearer Authentication.
            verify (bool): Whether to verify SSL certificates.
            proxy (bool): Whether to use system proxy settings.
        Raises:
            DemistoException: If neither api_key nor jwt_token is provided.
        """
        super().__init__(base_url=f"{url.strip('/')}", verify=verify, proxy=proxy)

        if not api_key and (not jwt_token):
            raise DemistoException("Either 'api_key' or 'jwt_token' must be provided for authentication.")

        self.api_key = api_key
        self.jwt_token = jwt_token
        self.headers = self._build_headers()

    def _build_headers(self) -> dict[str, Any]:
        """
        Build the headers for the HTTP requests based on the authentication method.
        Returns:
            dict[str, Any]: Headers for the HTTP requests.
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            auth_sequence = f"{self.api_key}:".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(auth_sequence).decode()}"
        elif self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        return headers

    @logger
    def call(self, url_suffix: str, method: str, params: dict | None = None) -> Any:
        """
        Make a JSON-RPC call to the GravityZone API.
        Args:
            url_suffix (str): The URL suffix for the API endpoint.
            method (str): The JSON-RPC method to call.
            params (Optional[dict]): The parameters for the JSON-RPC method.
        Returns:
            Any: The result of the JSON-RPC call.
        Raises:
            DemistoException: If the JSON-RPC response contains an error.
        """
        url_suffix = url_suffix.lstrip("/")
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}
        response = self._http_request(
            method="POST",
            url_suffix=f"/api/{url_suffix}",
            headers=self.headers,
            json_data=payload,
            params={},
            resp_type="json",
            return_empty_response=False,
            raise_on_status=True,
        )

        if "error" in response:
            error_code = response["error"].get("code")
            error_message = response["error"].get("message", "Unknown error")
            error_data = response["error"].get("data", {})
            raise DemistoException(f"JSON-RPC Error {error_code}: {error_message} - {error_data}")

        return response.get("result")

    @logger
    def upload_file(
        self,
        bucket_name: str,
        file_name: str,
        file_path: str,
        metadata: dict | None = None,
    ) -> Any:
        """
        Upload a file to the GravityZone storage bucket.
        Args:
            bucket_name (str): The name of the storage bucket.
            file_name (str): The name of the file to upload.
            file_path (str): The local path to the file.
            metadata (Optional[dict]): Optional metadata for the file.
        Returns:
            Any: The response from the upload operation.
        """
        with open(file_path, "rb") as f:
            file_content = f.read()

        files = {"file": (file_name, file_content, "application/octet-stream")}
        data = {}
        if metadata:
            data["metadata"] = json.dumps(metadata)
        response = self._http_request(
            method="POST",
            url_suffix=f"/storage/{bucket_name}",
            headers={"Authorization": self.headers.get("Authorization", "")},
            files=files,
            data=data,
            params={},
            resp_type="json",
            return_empty_response=False,
            raise_on_status=True,
        )

        return response

    @logger
    def download_file(self, bucket_name: str, file_name: str) -> Any:
        """
        Download a file from the GravityZone storage bucket.
        Args:
            bucket_name (str): The name of the storage bucket.
            file_name (str): The name of the file to download.
        Returns:
            Any: The HTTP response containing the file content.
        """
        response = self._http_request(
            method="GET",
            url_suffix=f"/storage/{bucket_name}/{file_name}",
            headers=self.headers,
            params={},
            resp_type="response",
            return_empty_response=False,
            raise_on_status=True,
        )

        return response

    @logger
    def get_investigation_file_url(self, activity_id: str, target_id: str) -> Any:
        """
        Get the URL for an investigation file.
        Args:
            activity_id (str): The ID of the investigation activity.
            target_id (str): The ID of the target endpoint.
        Returns:
            Any: The response containing the file URL and status.
        """
        return self.call(
            "/v1.0/jsonrpc/investigation",
            "getInvestigationFileUrl",
            {"activityId": activity_id, "targetId": target_id},
        )

    @logger
    def get_task_status(self, task_id: str) -> Any:
        """
        Get the status of a task.
        Args:
            task_id (str): The ID of the task.
        Returns:
            Any: The response containing the task status.
        """
        return self.call(
            "/v1.1/jsonrpc/network",
            "getTaskStatus",
            {"taskId": task_id, "options": {"returnSubtasks": True}},
        )

    @logger
    def get_live_search_query_task_result(self, task_id: str, page: int = 1, per_page: int = 5000) -> Any:
        """
        Get the results of a live search query task.
        Args:
            task_id (str): The ID of the live search query task.
            page (int): The page number to retrieve.
            per_page (int): The number of results per page.
        Returns:
            Any: The response containing the live search query task results.
        """
        return self.call(
            "/v1.0/jsonrpc/internal",
            "getLiveSearchQueryTaskResult",
            {"taskId": task_id, "page": page, "perPage": per_page},
        )

    @logger
    def get_my_company(self) -> Any:
        """
        Get details of the authenticated user's company.
        Returns:
            Any: The response containing the company details.
        """
        return self.call("/v1.0/jsonrpc/companies", "getCompanyDetails")

    @logger
    def get_endpoints(self) -> list[Any]:
        """
        Get the list of managed endpoints.
        Returns:
            list[Any]: A list of managed endpoints.
        """
        company_details = self.get_my_company()
        parent_id = company_details["id"]
        all_endpoints = []
        page = 1
        per_page = 100
        while True:
            response = self.call(
                "/v1.0/jsonrpc/network",
                "getEndpointsList",
                {"parentId": parent_id, "page": page, "perPage": per_page},
            )
            items = response.get("items", [])
            all_endpoints.extend(items)
            if page >= response.get("pagesCount", 1) or not items:
                break
            page += 1
        return all_endpoints

    @logger
    def get_endpoint(self, endpoint_id: str) -> Any:
        """
        Get details of a managed endpoint.
        Args:
            endpoint_id (str): The ID of the managed endpoint.
        Returns:
            Any: The response containing the endpoint details.
        """
        return self.call(
            "/v1.0/jsonrpc/network",
            "getManagedEndpointDetails",
            {
                "endpointId": endpoint_id,
                "options": {
                    "includeScanLogs": True,
                    "returnProductOutdated": True,
                    "includeLastLoggedUsers": True,
                },
            },
        )

    @logger
    def start_retrieve_investigation_file_from_endpoint(self, target_id: str, path: str) -> Any:
        """
        Start the retrieval of an investigation file from an endpoint.
        Args:
            target_id (str): The ID of the target endpoint.
            path (str): The path of the file to retrieve.
        Returns:
            Any: The response containing the activity ID.
        """
        return self.call(
            "/v1.0/jsonrpc/investigation",
            "startRetrieveInvestigationFileFromEndpoint",
            {"targetId": target_id, "path": path},
        )

    @logger
    def start_kill_process_on_endpoint(self, target_id: str, process_id: int) -> Any:
        """
        Start the process of killing a process on an endpoint.
        Args:
            target_id (str): The ID of the target endpoint.
            process_id (int): The ID of the process to kill.
        Returns:
            Any: The response containing the task ID.
        """
        return self.call(
            "/v1.0/jsonrpc/investigation",
            "killProcess",
            {"targetId": target_id, "processId": process_id},
        )

    @logger
    def start_command_execution_on_endpoint(self, target_id: str, command: str) -> Any:
        """
        Start the process of executing a command on an endpoint.
        Args:
            target_id (str): The ID of the target endpoint.
            command (str): The command to execute.
        Returns:
            Any: The response containing the activity ID.
        """
        return self.call(
            "/v1.0/jsonrpc/investigation",
            "startCommandExecutionOnEndpoint",
            {"targetId": target_id, "command": command},
        )

    @logger
    def start_isolate_endpoint(self, target_id: str) -> Any:
        """
        Start the process of isolating an endpoint.
        Args:
            target_id (str): The ID of the target endpoint.
        Returns:
            Any: The response containing the task ID.
        """
        return self.call(
            "/v1.1/jsonrpc/incidents",
            "createIsolateEndpointTask",
            {"endpointId": target_id},
        )

    @logger
    def start_deisolate_endpoint(self, target_id: str) -> Any:
        """
        Start the process of de-isolating an endpoint.
        Args:
            target_id (str): The ID of the target endpoint.
        Returns:
            Any: The response containing the task ID.
        """
        return self.call(
            "/v1.1/jsonrpc/incidents",
            "createRestoreEndpointFromIsolationTask",
            {"endpointId": target_id},
        )

    @logger
    def start_collect_investigation_package_on_endpoint(self, target_id: str) -> Any:
        """
        Start the process of collecting an investigation package on an endpoint.
        Args:
            target_id (str): The ID of the target endpoint.
        Returns:
            Any: The response containing the activity ID.
        """
        return self.call(
            "/v1.0/jsonrpc/investigation",
            "collectInvestigationPackage",
            {"targetId": target_id},
        )

    @logger
    def start_live_search_query_find_running_process_tree_by_hash(self, endpoints: list[str], process_hash: str) -> Any:
        """
        Start a live search query to find running process trees by hash.
        Args:
            endpoints (List[str]): List of endpoint IDs to query.
            process_hash (str): The hash of the process to search for.
        Returns:
            Any: The response containing the live search query information.
        """
        return self.call(
            "/v1.0/jsonrpc/internal",
            "runPredefinedLiveSearchQuery",
            {
                "endpoints": endpoints,
                "queryType": LIVE_SEARCH_QUERY_PROCESS_PER_HASH,
                "querySpecifics": {"hash": process_hash},
            },
        )

    @logger
    def start_live_search_query_find_endpoints_running_process_by_hash(self, endpoints: list[str], process_hash: str) -> Any:
        """
        Start a live search query to find endpoints running a specific process by hash.
        Args:
            endpoints (List[str]): List of endpoint IDs to query.
            process_hash (str): The hash of the process to search for.
        Returns:
            Any: The response containing the live search query information.
        """
        return self.call(
            "/v1.0/jsonrpc/internal",
            "runPredefinedLiveSearchQuery",
            {
                "endpoints": endpoints,
                "queryType": LIVE_SEARCH_QUERY_RUNNING_HASH,
                "querySpecifics": {"hash": process_hash},
            },
        )

    @logger
    def get_incidents(
        self,
        start_time: str | None = None,
        end_time: str | None = None,
        target_id: str | None = None,
        max_fetch: int = FETCH_LIMIT,
    ) -> list[dict[str, Any]]:
        """
        Get a list of incidents with optional filtering by time range and target ID.
        Args:
            start_time (Optional[str]): The start time for filtering incidents.
            end_time (Optional[str]): The end time for filtering incidents.
            target_id (Optional[str]): The target endpoint ID for filtering incidents.
            max_fetch (int): The maximum number of incidents to fetch.
        Returns:
            List[dict[str, Any]]: A list of incidents.
        """
        params = {
            "filters": {},
            "options": {"includeChildCompanies": True},
            "page": 1,
            "perPage": 1000,
        }
        if start_time and end_time:
            params["filters"] = {"startDate": start_time, "endDate": end_time}
        if target_id:
            params["filters"] = {"endpointId": target_id}

        page = 1
        all_incidents = []
        while True:
            params["page"] = page
            response = self.call("/v1.2/jsonrpc/incidents", "getIncidentsList", params)
            items = response.get("items", [])
            all_incidents.extend(items)
            if len(all_incidents) >= max_fetch:
                break
            if page >= response.get("pagesCount", 1) or not items:
                break
            page += 1
        return all_incidents[:max_fetch]

    @logger
    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """
        Get details of a specific incident by its ID.
        Args:
            incident_id (str): The ID of the incident.
        Returns:
            dict[str, Any]: The response containing the incident details.
        """
        return self.call("/v1.2/jsonrpc/incidents", "getIncident", {"id": incident_id})

    @logger
    def add_incident_note(self, incident_type: str, incident_id: str, note: str) -> dict[str, Any]:
        """
        Add a note to a specific incident.
        Args:
            incident_type (str): The type of the incident.
            incident_id (str): The ID of the incident.
            note (str): The note to add.
        Returns:
            dict[str, Any]: The response from the add operation.
        """
        type = f"{incident_type}s"
        return self.call(
            "/v1.0/jsonrpc/incidents",
            "updateIncidentNote",
            {"type": type, "incidentId": incident_id, "note": note},
        )

    @logger
    def change_incident_status(self, incident_id: str, status: int) -> dict[str, Any]:
        """
        Change the status of a specific incident.
        Args:
            incident_id (str): The ID of the incident.
            status (int): The new status for the incident.
        Returns:
            dict[str, Any]: The response from the status change operation.
        """
        return self.call(
            "/v1.0/jsonrpc/incidents",
            "changeIncidentStatus",
            {"type": "incidents", "incidentId": incident_id, "status": status},
        )


""" HELPER FUNCTIONS """


class FileManagement:
    def __init__(self, client: Client) -> None:
        self.client = client

    @logger
    def upload_file(self, bucket_name: str, entry_id: str, metadata: dict | None = None) -> dict[str, Any]:
        """
        Upload a file to the GravityZone storage bucket from a Demisto entry ID.
        Args:
            bucket_name (str): The name of the storage bucket.
            entry_id (str): The Demisto entry ID of the file to upload.
            metadata (Optional[dict]): Optional metadata for the file.
        Returns:
            dict[str, Any]: The response from the upload operation.
        """
        file_ = demisto.getFilePath(entry_id)
        file_name = file_.get("name")
        file_path = file_.get("path")
        if not file_path:
            raise DemistoException(f"Could not find file for entry ID {entry_id}")
        if not file_name:
            raise DemistoException(f"Could not determine the file name for entry ID {entry_id}")
        try:
            return self.client.upload_file(bucket_name, file_name, file_path, metadata)
        except FileNotFoundError:
            raise DemistoException(f"File not found: {file_path}")

    @logger
    def _read_zip_from_memory(self, zip_bytes: bytes) -> bytes | None:
        """
        Read the first file from a ZIP archive in memory.
        Args:
            zip_bytes (bytes): The bytes of the ZIP archive.
        Returns:
            Optional[bytes]: The content of the first file in the archive, or None if no file is found.
        """
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zip_ref:
            for file_name in zip_ref.namelist():
                if not file_name.endswith("/"):
                    with zip_ref.open(file_name) as file:
                        return file.read()
        return None

    @logger
    def _read_tgz_from_memory(self, tgz_bytes: bytes) -> bytes | None:
        """
        Read the first file from a TGZ archive in memory.
        Args:
            tgz_bytes (bytes): The bytes of the TGZ archive.
        Returns:
            Optional[bytes]: The content of the first file in the archive, or None if no file is found.
        """
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    extracted_file = tar.extractfile(member)
                    return extracted_file.read() if extracted_file else None
        return None

    @logger
    def _get_file_content_from_archive(self, archive_bytes: bytes) -> str | None:
        """
        Extract the content of the first file from an archive in memory.
        Args:
            archive_bytes (bytes): The bytes of the archive.
        Returns:
            Optional[str]: The content of the first file in the archive as a string, or None if no file is found.
        """
        if archive_bytes[:2] == b"PK":
            content = self._read_zip_from_memory(archive_bytes)
        elif archive_bytes[:2] == b"7z":
            content = None
        elif archive_bytes[:2] == b"\x1f\x8b":
            content = self._read_tgz_from_memory(archive_bytes)
        else:
            content = archive_bytes

        if content:
            return content.decode()
        else:
            return None

    @logger
    def download_file(self, bucket_name: str, file_name: str, save_path: str | None = None) -> Union[dict[str, Any], str, None]:
        """
        Download a file from the GravityZone storage bucket.
        Args:
            bucket_name (str): The name of the storage bucket.
            file_name (str): The name of the file to download.
            save_path (Optional[str]): The local path to save the file. If None, returns file content.
        Returns:
            Union[dict[str, Any], str, None]: The file result if saved locally, the file content as a string, or None on error.
        """
        try:
            response = self.client.download_file(bucket_name, file_name)
            if save_path:
                content_disposition = response.headers.get("Content-Disposition", "").lower()
                if content_disposition:
                    filename = email.message_from_string(f"Content-Disposition: {content_disposition}\n\n").get_filename()
                    if filename:
                        result = fileResult(save_path, response.content)
                        return result
                demisto.debug(f"Cannot determine the file name from the response ( bucket: {bucket_name}, file: {file_name} ).")
                return None
            else:
                unpacked_archive = self._get_file_content_from_archive(response.content)
                if unpacked_archive is not None:
                    return unpacked_archive
                else:
                    unique_filename = f"command_output_{uuid.uuid4().hex}.7z"
                    return fileResult(unique_filename, response.content)
        except Exception as e:
            demisto.debug(f"Failed to download the file {file_name}, {str(e)}, {traceback.format_exc()}")
            return None


@polling_function(
    name="gz-poll-investigation-activity-status",
    timeout=POLL_TIMEOUT,
    interval=POLL_INTERVAL,
    requires_polling_arg=False,
)
def check_investigation_status(args: dict[str, Any], client: Client) -> PollResult:
    """
    Polling function to check the status of an investigation activity.
    Args:
        args (Dict[str, Any]): The arguments containing target_id, activity_id, output_file, and metadata.
            target_id (str): The ID of the target endpoint.
            activity_id (str): The ID of the investigation activity.
            output_file (str): The local path to save the file.
            metadata (Dict[str, Any]): Additional metadata for the activity.
        client (Client): The GravityZone client instance.
    Returns:
        PollResult: The result of the polling operation.
    """
    target_id = args.get("target_id")
    activity_id = args.get("activity_id")
    output_file = args.get("output_file")
    metadata = args.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    if output_file and len(output_file) == 0:
        output_file = None

    if not target_id or not activity_id:
        return PollResult(
            CommandResults(
                readable_output="Both 'target_id' and 'activity_id' must be provided.",
                entry_type=EntryType.ERROR,
            )
        )

    investigation_file_url = client.get_investigation_file_url(activity_id, target_id)

    current_status = investigation_file_url.get("status")
    url = investigation_file_url.get("url")
    error_code = investigation_file_url.get("errorCode")

    activity_type = metadata.get("activityType")

    command_name_from_activity_type = ACTIVITY_NUMERIC_TO_COMMAND_NAME.get(activity_type, f"UnknownActivity_{hex(activity_type)}")

    activity_output_prefix = f"GravityZone.Command.{command_name_from_activity_type}"

    headers = ["EndpointID", "Status", "ErrorCode"]

    raw_response = {
        "activity_id": activity_id,
        "activity_type": command_name_from_activity_type,
        "target_id": target_id,
        "status": current_status,
        "url": url,
        "errorCode": error_code,
    }

    data = {
        "ActivityID": activity_id,
        "ActivityType": command_name_from_activity_type,
        "Status": "Pending",
        "EndpointID": target_id,
        "ErrorCode": error_code,
    }

    if activity_type == ACTIVITY_TYPE_RUN_COMMAND:
        data["Command"] = metadata.get("command")
        headers.extend(["Command"])
    elif activity_type == ACTIVITY_TYPE_DOWNLOAD_FILE:
        data["RemoteFile"] = metadata.get("remoteFile")
        data["OutputFile"] = metadata.get("outputFile")
        headers.extend(["OutputFile", "RemoteFile"])

    if current_status == ACTIVITY_STATUS_SUCCESS:
        bucket = investigation_file_url.get("bucket")
        if not bucket:
            data["Status"] = "Failed"
            data["ErrorCode"] = "NoBucket"
            return PollResult(
                CommandResults(
                    raw_response=raw_response,
                    readable_output=tableToMarkdown(
                        f"{activity_output_prefix} command on host {target_id}:",
                        [data],
                        headers=headers,
                    ),
                    outputs=[data],
                    outputs_prefix=activity_output_prefix,
                    outputs_key_field="ActivityID",
                    entry_type=EntryType.ERROR,
                )
            )

        file_management = FileManagement(client)
        result = file_management.download_file(bucket, investigation_file_url["fileId"], output_file)

        if isinstance(result, str):
            data["Output"] = result
            headers.append("Output")
        elif isinstance(result, dict):
            data["FileID"] = result.get("FileID", "")
            data["FileName"] = result.get("File", "")
            headers.append("FileID")
        elif result is None:
            data["Status"] = "Failed"
            data["ErrorCode"] = "DownloadFailed"
            return PollResult(
                CommandResults(
                    raw_response=raw_response,
                    readable_output=tableToMarkdown(
                        f"{activity_output_prefix} command on host {target_id}:",
                        [data],
                        headers=headers,
                    ),
                    outputs=[data],
                    outputs_prefix=activity_output_prefix,
                    outputs_key_field="ActivityID",
                    entry_type=EntryType.ERROR,
                )
            )

        data["Status"] = "Success"

        return PollResult(
            response=[
                CommandResults(
                    raw_response=result,
                    readable_output=tableToMarkdown(
                        f"{activity_output_prefix} command on host {target_id}:",
                        [data],
                        headers=headers,
                    ),
                    outputs=[data],
                    outputs_prefix=activity_output_prefix,
                    outputs_key_field="ActivityID",
                    entry_type=EntryType.NOTE,
                ),
                result,
            ]
        )

    if current_status == ACTIVITY_STATUS_FAILED:
        data["Status"] = "Failed"
        return PollResult(
            CommandResults(
                raw_response=raw_response,
                readable_output=tableToMarkdown(
                    f"{activity_output_prefix} command on host {target_id}:",
                    [data],
                    headers=headers,
                ),
                outputs=[data],
                outputs_prefix=activity_output_prefix,
                outputs_key_field="ActivityID",
                entry_type=EntryType.ERROR,
            )
        )

    return PollResult(
        continue_to_poll=True,
        response=CommandResults(
            raw_response=raw_response,
            readable_output=f"Activity {command_name_from_activity_type} ('{activity_id}') still in progress, host {target_id}.",
            entry_type=EntryType.NOTE,
        ),
    )


@logger
def get_investigation_results(
    client: Client,
    target_id: str,
    activity_id: str,
    output_file: str,
    metadata: dict[str, Any],
) -> PollResult:
    """
    Get the results of an investigation activity.
    Args:
        client (Client): The GravityZone client instance.
        target_id (str): The ID of the target endpoint.
        activity_id (str): The ID of the investigation activity.
        output_file (str): The local path to save the file.
        metadata (Dict[str, Any]): Additional metadata for the activity.
    Returns:
        PollResult: The result of the investigation activity.
    """
    return check_investigation_status(
        {
            "target_id": target_id,
            "activity_id": activity_id,
            "output_file": output_file,
            "metadata": metadata,
        },
        client,
    )


@polling_function(
    name="gz-poll-task-status",
    timeout=POLL_TIMEOUT,
    interval=POLL_INTERVAL,
    requires_polling_arg=False,
)
def check_task_status(
    args: dict[str, Any],
    client: Client,
) -> PollResult:
    """
    Polling function to check the status of a task.
    Args:
        args (Dict[str, Any]): The arguments containing task_id and metadata.
            task_id (str): The ID of the task.
            metadata (Dict[str, Any]): Additional metadata for the task.
        client (Client): The GravityZone client instance.
    Returns:
        PollResult: The result of the polling operation.
    """
    task_id = args.get("task_id", "unknown")
    metadata = args.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    task_output = client.get_task_status(task_id)

    current_status = task_output.get("status")

    if current_status == TASK_STATUS_PROCESSED:
        return PollResult(
            generate_processed_task_command_result(
                task_id,
                task_output,
                metadata,
                error_code=next(
                    (subtask["errorCode"] for subtask in task_output.get("subtasks", []) if subtask.get("status") == 2),
                    None,
                ),
            )
        )

    return PollResult(
        continue_to_poll=True,
        response=CommandResults(
            raw_response=task_output,
            readable_output=f"Task '{task_id}' still pending.",
            entry_type=EntryType.NOTE,
        ),
    )


@logger
def get_task_results(
    client: Client,
    task_id: str,
    metadata: dict[str, Any],
) -> PollResult:
    """
    Get the results of a task.
    Args:
        client (Client): The GravityZone client instance.
        task_id (str): The ID of the task.
        metadata (Dict[str, Any]): Additional metadata for the task.
    Returns:
        PollResult: The result of the task.
    """
    return check_task_status({"task_id": task_id, "metadata": metadata}, client)


@polling_function(
    name="gz-poll-live-search-status",
    timeout=LIVE_SEARCH_TIMEOUT,
    interval=LIVE_SEARCH_INTERVAL,
    requires_polling_arg=False,
)
def query_live_search_results(args: dict[str, Any], client: Client) -> PollResult:
    """
    Polling function to query live search results.
    Args:
        args (Dict[str, Any]): The arguments containing task_id.
            task_id (str): The ID of the live search query task.
            search_type (str): The type of live search query.
        client (Client): The GravityZone client instance.
    Returns:
        PollResult: The result of the live search query.
    """
    task_id = args.get("task_id")
    search_type = args.get("search_type", "")
    if search_type == LIVE_SEARCH_QUERY_PROCESS_PER_HASH:
        output_prefix = "GravityZone.Command.ProcessTreeForHash"
        outputs_key_field = "EndpointID"
    elif search_type == LIVE_SEARCH_QUERY_RUNNING_HASH:
        output_prefix = "GravityZone.Command.EndpointsRunningProcessHash"
        outputs_key_field = "ProcessHash"
    else:
        output_prefix = "GravityZone.Command.UnknownLiveSearchType"
        outputs_key_field = "EndpointID"
    metadata = args.get("metadata", "{}")
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    if not task_id:
        return PollResult(
            CommandResults(
                readable_output="`task_id` must be provided.",
                entry_type=EntryType.ERROR,
            )
        )

    try:
        response = client.get_live_search_query_task_result(task_id, page=1, per_page=5000)
        pages_count = int(response["pagesCount"]) + 1
        results = response["items"]

        for i in range(2, pages_count):
            results.extend(client.get_live_search_query_task_result(task_id, page=i, per_page=5000)["items"])

        return PollResult(
            CommandResults(
                raw_response=results,
                readable_output=tableToMarkdown(
                    "Live Search Results",
                    [generate_human_readable_live_search_result(x, metadata) for x in results],
                ),
                outputs=[generate_context_live_search_result(x, metadata) for x in results],
                outputs_prefix=output_prefix,
                outputs_key_field=outputs_key_field,
            )
        )

    except Exception as e:
        return PollResult(
            continue_to_poll=True,
            response=CommandResults(
                raw_response=str(e),
                readable_output=f"Query {task_id} still pending. Got error: {str(e)}",
                entry_type=EntryType.ERROR,
            ),
        )


@logger
def get_live_search_results(client: Client, task_id: str, search_type: str, metadata: str = "{}") -> PollResult:
    """
    Get the results of a live search query.
    Args:
        client (Client): The GravityZone client instance.
        task_id (str): The ID of the live search query task.
    Returns:
        PollResult: The result of the live search query.
    """
    return query_live_search_results({"task_id": task_id, "search_type": search_type, "metadata": metadata}, client)


def generate_context_for_incident(raw_incident: dict[str, Any]) -> dict[str, Any]:
    """
    Generate the context dictionary for a GravityZone incident.
    Args:
        raw_incident (Dict[str, Any]): The raw incident data from GravityZone.
    Returns:
        Dict[str, Any]: The formatted incident context.
    """
    return {
        "ID": raw_incident.get("incidentId"),
        "Number": raw_incident.get("incidentNumber"),
        "Type": raw_incident.get("incidentType"),
        "Company": {
            "Name": raw_incident.get("company", {}).get("name"),
            "ID": raw_incident.get("company", {}).get("id"),
        },
        "Severity": {"Score": raw_incident.get("severityScore")},
        "Status": INCIDENT_STATUS_INT_MAPPING.get(raw_incident.get("status", "open"), IncidentStatus.PENDING),
        "ActionTaken": raw_incident.get("mainAction"),
        "Created": raw_incident.get("created"),
        "LastUpdated": raw_incident.get("lastUpdated"),
        "LastProcessed": raw_incident.get("lastProcessed"),
        "Permalink": raw_incident.get("incidentLink"),
        "AssignedPriority": raw_incident.get("priority"),
        "AssignedUser": format_incident_assignee_for_context(raw_incident),
        "Notes": format_incident_notes_for_context(raw_incident),
        "Alerts": format_incident_alerts_for_context(raw_incident),
        "RawJSON": raw_incident,
    }


def format_incident_assignee_for_context(
    raw_incident: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Format the assignee information for the incident context.
    Args:
        raw_incident (Dict[str, Any]): The raw incident data from GravityZone.
    Returns:
        Dict[str, Any] | None: The formatted assignee information or None if no assignee.
    """
    assignee = raw_incident.get("assignee")
    if not assignee:
        return None
    return {
        "ID": assignee.get("userId"),
        "Email": assignee.get("userName"),
        "Company": {
            "ID": assignee.get("companyId"),
            "Name": assignee.get("companyName"),
        },
    }


def format_incident_notes_for_context(
    raw_incident: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Format the notes for the incident context.
    Args:
        raw_incident (Dict[str, Any]): The raw incident data from GravityZone.
    Returns:
        List[Dict[str, str]]: The formatted list of notes.
    """
    notes = []
    for note in raw_incident.get("notes", []):
        notes.append(
            {
                "Text": note.get("text"),
                "User": note.get("userName"),
                "Date": note.get("created"),
            }
        )
    return notes


def format_incident_alerts_for_context(
    raw_incident: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Format the alerts for the incident context.
    Args:
        raw_incident (Dict[str, Any]): The raw incident data from GravityZone.
    Returns:
        List[Dict[str, str]]: The formatted list of alerts.
    """
    alerts = []
    incident_type = raw_incident.get("incidentType")
    if incident_type == INCIDENT_TYPE_EDR:
        for item in raw_incident.get("details", {}).get("alerts"):
            alerts.append(format_edr_alert_for_context(item, raw_incident))
    elif incident_type == INCIDENT_TYPE_XDR:
        for item in raw_incident.get("details", {}).get("alerts"):
            alerts.append(format_xdr_alert_for_context(item, raw_incident))
    else:
        demisto.debug(f"Unknown incident type: {incident_type}. Skipping 'alerts' formating for context")
    return alerts


def format_edr_alert_for_context(alert: dict[str, Any], raw_incident: dict[str, Any]) -> dict[str, Any]:
    """
    Format an EDR alert for the incident context.
    Args:
        alert (Dict[str, Any]): The raw alert data from GravityZone.
        raw_incident (Dict[str, Any]): The raw incident data from GravityZone.
    Returns:
        Dict[str, Any]: The formatted alert context.
    """
    result: dict[str, Any] = {
        "Name": alert.get("name"),
        "Date": alert.get("date"),
        "DetectedBy": {
            "Name": alert.get("detectedBy", {}).get("name"),
            "Class": alert.get("detectedBy", {}).get("class"),
        },
        "Resources": [],
    }
    alert_resources = alert.get("resources", [])
    for resource in alert_resources:
        context_resource = {}
        for key, value in resource.get("details", {}).items():
            if value is not None:
                context_resource[key[:1].upper() + key[1:]] = value
        resource_type = resource.get("type", "unknown")
        context_resource["Type"] = resource_type
        result["Resources"].append(context_resource)
    return result


def format_xdr_alert_for_context(alert: dict[str, Any], raw_incident: dict[str, Any]) -> dict[str, str]:
    """
    Format an XDR alert for the incident context.
    Args:
        alert (Dict[str, Any]): The raw alert data from GravityZone.
        raw_incident (Dict[str, Any]): The raw incident data from GravityZone.
    Returns:
        Dict[str, str]: The formatted alert context.
    """
    result = {
        "Name": alert.get("name"),
        "Date": alert.get("date"),
        "Sensors": alert.get("sensors", []),
        "Tactic": alert.get("tactic"),
        "Transitions": [],
    }
    transitions = alert.get("transitions", [])
    if not transitions:
        return result
    for transition in transitions:
        to_node_id = transition.get("to", "")
        from_node_id = transition.get("from", "")
        to_node = get_node_by_id(to_node_id, raw_incident)
        from_node = get_node_by_id(from_node_id, raw_incident)
        to_node_name = to_node.get("name") if to_node else "[undefined]"
        from_node_name = from_node.get("name") if from_node else "[undefined]"

        resources = transition.get("resources", [])
        transition_resources = []
        for resource in resources:
            context_resource = {}
            for key, value in resource.get("details", {}).items():
                if value is not None:
                    context_resource[key[:1].upper() + key[1:]] = value
            resource_type = resource.get("type", "unknown")
            context_resource["Type"] = resource_type
            transition_resources.append(context_resource)

        result["Transitions"].append(
            {
                "From": {"NodeID": from_node_id, "NodeName": from_node_name},
                "To": {"NodeID": to_node_id, "NodeName": to_node_name},
                "Resources": transition_resources,
            }
        )
    return result


def generate_context_for_summarized_incidents(
    raw_incidents: list[dict[str, Any]],
) -> list[dict[str, str | None]]:
    """
    Generate the context list for summarized GravityZone incidents.
    Args:
        raw_incidents (List[Dict[str, Any]]): The list of raw incident data from GravityZone.
    Returns:
        List[Dict[str, str | None]]: The list of formatted incident contexts.
    """
    incidents = []
    for raw_incident in raw_incidents:
        incident = {
            "ID": raw_incident.get("incidentId"),
            "Number": raw_incident.get("incidentNumber"),
            "Type": raw_incident.get("incidentType"),
            "CompanyName": raw_incident.get("company", {}).get("name"),
            "CompanyID": raw_incident.get("company", {}).get("id"),
            "SeverityScore": raw_incident.get("severityScore"),
            "Status": INCIDENT_STATUS_INT_MAPPING.get(raw_incident.get("status", "open"), IncidentStatus.PENDING),
            "ActionTaken": raw_incident.get("mainAction"),
            "Created": raw_incident.get("created"),
            "LastUpdated": raw_incident.get("lastUpdated"),
            "LastProcessed": raw_incident.get("lastProcessed"),
            "Permalink": raw_incident.get("incidentLink"),
            "AssignedPriority": raw_incident.get("priority"),
            "AssignedUserId": raw_incident.get("assignee"),
            "AttackTypes": raw_incident.get("attackTypes"),
            "RawJSON": raw_incident,
        }
        incidents.append(incident)
    return incidents


def generate_endpoint_by_contex_standard(device) -> Common.Endpoint:
    """
    Generate an endpoint object from device data using the context standard.
    Args:
        device (dict): The device data from GravityZone.
    Returns:
        Common.Endpoint: The generated endpoint object.
    """
    device_id = device.get("id")
    device_state = device.get("state")
    state = ENDPOINT_DEVICE_STATE_MAPPING.get(device_state, "Offline")
    endpoint = Common.Endpoint(
        id=device_id,
        hostname=device.get("name"),
        ip_address=device.get("ip"),
        os=device.get("operatingSystem"),
        status=state,
        vendor=INTEGRATION_NAME,
    )
    return endpoint


def generate_endpoint_entry(device) -> dict[str, Any]:
    """
    Generate an endpoint entry dictionary from device data.
    Args:
        device (dict): The device data from GravityZone.
    Returns:
        Dict[str, Any]: The generated endpoint entry.
    """
    device_id = device.get("id")
    entry = {
        "ID": device_id,
        "Hostname": device.get("name"),
        "IP": device.get("ip"),
        "OS": device.get("operatingSystem"),
        "Status": ENDPOINT_DEVICE_STATE_MAPPING.get(device.get("state"), "Offline"),
        "Vendor": INTEGRATION_NAME,
        "LastLoggedUsers": ", ".join(device.get("lastLoggedUsers", [])),
    }
    return entry


def generate_endpoint_from_list_by_contex_standard(device) -> Common.Endpoint:
    """
    Generate an endpoint object from device data in a list using the context standard.
    Args:
        device (dict): The device data from GravityZone.
    Returns:
        Common.Endpoint: The generated endpoint object.
    """
    device_id = device.get("id")
    endpoint = Common.Endpoint(
        id=device_id,
        hostname=device.get("name"),
        ip_address=device.get("ip"),
        os=device.get("operatingSystemVersion"),
        mac_address=device.get("macs")[0],
        vendor=INTEGRATION_NAME,
    )
    return endpoint


def generate_human_readable_incident_from_context(
    context_incident: dict[str, Any],
) -> str:
    """
    Generate a human-readable string for a GravityZone incident from its context.
    Args:
        context_incident (Dict[str, Any]): The incident context data.
    Returns:
        str: The human-readable incident string.
    """
    incident_readable_output = get_incident_human_readable_output(context_incident)
    notes_readable_output = get_incident_notes_human_readable_output(context_incident)
    alerts_readable_output = get_incident_alerts_human_readable_output(context_incident)
    return f"{incident_readable_output}\n{notes_readable_output}\n{alerts_readable_output}"


def get_incident_human_readable_output(context_incident: dict[str, Any]) -> str:
    """
    Generate the human-readable output for a GravityZone incident.
    Args:
        context_incident (Dict[str, Any]): The incident context data.
    Returns:
        str: The human-readable incident string."""
    data = {
        "ID": context_incident.get("ID"),
        "Type": INCIDENT_TYPE_MAPPING.get(context_incident.get("Type", "unknown"), "Unknown"),
        "Number": context_incident.get("Number"),
        "Company Name": context_incident.get("Company", {}).get("Name"),
        "Severity Score": str(context_incident.get("Severity", {}).get("Score")) + "%",
        "Status": str(context_incident.get("Status"))
        + " ("
        + INCIDENT_STATUS_STR_MAPPING.get(context_incident.get("RawJSON", {}).get("status", ""), "unknown")
        + ")",
        "Action Taken": context_incident.get("ActionTaken", "").capitalize(),
        "Created": context_incident.get("Created"),
        "Last Updated": context_incident.get("LastUpdated"),
        "Last Processed": context_incident.get("LastProcessed"),
        "Permalink": context_incident.get("Permalink"),
        "Assigned Priority": context_incident.get("AssignedPriority", "").capitalize(),
    }
    assignee = context_incident.get("AssignedUser")
    if not assignee:
        data["Assigned User"] = "Unassigned"
    else:
        data["Assigned User"] = assignee.get("Email") + " (" + assignee.get("ID") + ")"
    return tableToMarkdown("Gravity Zone Incident", data)


def get_incident_notes_human_readable_output(context_incident: dict[str, Any]) -> str:
    """
    Generate the human-readable output for the notes of a GravityZone incident.
    Args:
        context_incident (Dict[str, Any]): The incident context data.
    Returns:
        str: The human-readable notes string.
    """
    data = []
    for note in context_incident.get("Notes") or []:
        data.append(
            {
                "Text": note.get("Text"),
                "User": note.get("User"),
                "Date": note.get("Date"),
            }
        )
    return tableToMarkdown("Incident Notes", data, headers=["Text", "User", "Date"])


def get_incident_alerts_human_readable_output(context_incident: dict[str, Any]) -> str:
    """
    Generate the human-readable output for the alerts of a GravityZone incident.
    Args:
        context_incident (Dict[str, Any]): The incident context data.
    Returns:
        str: The human-readable alerts string.
    """
    data = []
    for alert in context_incident.get("Alerts", []):
        row = {
            "Name": alert.get("Name"),
            "Date": alert.get("Date"),
        }
        sensors = alert.get("Sensors")
        tactic = alert.get("Tactic")
        detected_by = alert.get("DetectedBy")
        transitions = alert.get("Transitions")
        resources = alert.get("Resources")
        if sensors:
            row["Sensors"] = ", ".join(sensors)
        if tactic:
            row["Tactic"] = tactic
        if detected_by:
            row["Detected By"] = detected_by.get("Name")
            detected_by_class = detected_by.get("Class")
            if detected_by_class:
                row["Detected By"] += f" ({detected_by_class})"
        if transitions:
            row["Transitions"] = json.dumps(transitions, indent=2)
        if resources:
            row["Resources"] = json.dumps(resources, indent=2)
        data.append(row)
    return tableToMarkdown("Incident Alerts", data)


def generate_human_readable_summarized_incidents_from_context(
    context_incidents: list[dict[str, Any]],
) -> str:
    """
    Generate a human-readable string for summarized GravityZone incidents from their context.
    Args:
        context_incidents (List[Dict[str, Any]]): The list of incident context data.
    Returns:
        str: The human-readable summarized incidents string.
    """
    processed_incidents = []
    for incident in context_incidents:
        processed_incident = {
            "ID": incident.get("ID"),
            "Number": incident.get("Number"),
            "Type": INCIDENT_TYPE_MAPPING.get(incident.get("Type", "unknown"), "Unknown"),
            "Company Name": incident.get("CompanyName"),
            "Severity Score": str(incident.get("SeverityScore")) + "%",
            "Status": str(incident.get("Status"))
            + " ("
            + INCIDENT_STATUS_STR_MAPPING.get(incident.get("RawJSON", {}).get("status", "unknown"), "unknown")
            + ")",
            "ActionTaken": incident.get("ActionTaken", "").capitalize(),
            "Created": incident.get("Created"),
            "Last Updated": incident.get("LastUpdated"),
            "Last Processed": incident.get("LastProcessed"),
            "Permalink": incident.get("Permalink"),
            "Assigned Priority": incident.get("AssignedPriority", "").capitalize(),
            "Assigned User ID": (incident.get("AssignedUserId") if incident.get("AssignedUserId") else "Unassigned"),
            "Attack Types": ", ".join(incident.get("AttackTypes", [])),
        }
        processed_incidents.append(processed_incident)
    return tableToMarkdown("Summarized Incidents List", processed_incidents)


def get_node_by_id(node_id: str, incident: dict[str, Any]) -> dict[str, str] | None:
    """
    Retrieve a node by its ID from the incident details.
    Args:
        node_id (str): The ID of the node to retrieve.
        incident (Dict[str, Any]): The incident data containing nodes.
    Returns:
        Dict[str, str] | None: The node data if found, otherwise None.
    """
    for node in incident.get("details", {}).get("nodes", []):
        if node.get("id") == node_id:
            return node
    return None


def convert_from_gz_to_cortex(gz_incident: dict, include_json: bool) -> dict:
    """
    Convert a GravityZone incident to Cortex XSOAR incident format.
    Args:
        gz_incident (dict): The GravityZone incident data.
        include_json (bool): Whether to include the raw JSON in the output.
    Returns:
        dict: The converted Cortex XSOAR incident data.
    """
    gz_status = gz_incident.get("status", INCIDENT_STATUS_STR_IN_PROGRESS)
    status = INCIDENT_STATUS_INT_MAPPING.get(gz_status, IncidentStatus.PENDING)
    gz_incident["name"] = f"{gz_incident.get('incidentNumber', 'Unknown incident number')}"
    gz_incident_type = gz_incident.get("incidentType")
    incident = {
        "incidentId": gz_incident.get("incidentId"),
        "name": gz_incident["name"],
        "incident_type": gz_incident_type,
        "occurred": gz_incident.get("created"),
        "status": status,
    }
    params = demisto.params()
    mirroring_direction = params.get("mirror_direction")
    mirror_instance = demisto.integrationInstance()
    gz_incident["mirror_direction"] = mirroring_direction
    gz_incident["mirror_instance"] = mirror_instance
    gz_incident["mirror_tags"] = []

    if include_json:
        incident["rawJSON"] = json.dumps(gz_incident)
    return incident


def get_gz_status_matched_to_cortex_status(cortex_status: int, cortex_reason: str | None = None) -> int:
    """
    Map Cortex XSOAR incident status to GravityZone incident status.
    Args:
        cortex_status (int): The Cortex XSOAR incident status.
        cortex_reason (Optional[str]): The reason for the status, if applicable.
    Returns:
        int: The corresponding GravityZone incident status.
    """
    if cortex_reason and cortex_reason.lower() == "false positive":
        return GRAVITY_ZONE_INCIDENT_STATUS_FALSE_POSITIVE
    return INCIDENT_STATUS_MAPPING.get(cortex_status, GRAVITY_ZONE_INCIDENT_STATUS_OPEN)


def generate_human_readable_live_search_result(result: dict[str, Any], metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """
    Generate a human-readable live search result from the raw result data.
    Args:
        result (Dict[str, Any]): The raw live search result data.
    Returns:
        Dict[str, Any]: The formatted live search result."""
    data = {
        "EndpointID": result.get("protectedEntityId"),
        "Results": result.get("results"),
    }
    # Enrich data with all fields in metadata
    if metadata:
        for k, v in metadata.items():
            k = "".join(word.capitalize() for word in k.split("_"))
            if k not in data and v is not None:
                data[k] = v
    return data


def generate_context_live_search_result(result: dict[str, Any], metadata: dict[str, Any] = {}) -> dict[str, Any]:
    """
    Generate a context live search result from the raw result data.
    Args:
        result (Dict[str, Any]): The raw live search result data.
    Returns:
        Dict[str, Any]: The formatted live search result."""
    try:
        json_data = json.loads(result.get("results", "{}"))
    except Exception:
        json_data = {}
    data = {
        "EndpointID": result.get("protectedEntityId"),
        "Cmdline": json_data.get("cmdline", None),
        "ParentPID": (int(json_data["parent"]) if json_data.get("parent") is not None else None),
        "Path": json_data.get("path", None),
        "PID": int(json_data["pid"]) if json_data.get("pid") is not None else None,
    }
    # Filter out None values from data
    data = {k: v for k, v in data.items() if v is not None}
    # Enrich data with all fields in metadata
    if metadata:
        for k, v in metadata.items():
            k = "".join(word.capitalize() for word in k.split("_"))
            if k not in data and v is not None:
                data[k] = v
    return data


def fill_task_output_with_metadata(data: dict[str, Any], task_type: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """
    Fill the task output data with additional metadata based on the task type.
    Args:
        data (Dict[str, Any]): The task output data.
        task_type (str): The type of the task.
        metadata (Dict[str, Any]): The additional metadata.
    Returns:
        Dict[str, Any]: The updated task output data.
    """
    if task_type == COMMAND_KILL_PROCESS:
        process_pid = metadata.get("processId")
        process_path = metadata.get("path")
        data["ProcessID"] = process_pid if process_pid else -1
        data["ProcessPath"] = process_path if process_path else ""
    elif task_type == COMMAND_UPLOAD_FILE:
        local_file = metadata.get("localFile")
        destination_path = metadata.get("destinationPath")
        data["EntryID"] = local_file
        data["DestinationPath"] = destination_path
    return data


def fill_task_headers_with_metadata(task_type: str, metadata: dict[str, Any], headers: list) -> None:
    """
    Fill the task output headers with additional metadata based on the task type.
    Args:x
        task_type (str): The type of the task.
        metadata (Dict[str, Any]): The additional metadata.
        headers (list): The list of headers to be updated.
    """
    if task_type == COMMAND_KILL_PROCESS:
        process_pid = metadata.get("processId")
        process_path = metadata.get("path")
        if process_pid:
            headers.append("ProcessID")
        if process_path:
            headers.append("ProcessPath")
    elif task_type == COMMAND_UPLOAD_FILE:
        headers.append("EntryID")
        headers.append("DestinationPath")


def generate_processed_task_command_result(
    task_id: str,
    task_output: dict,
    metadata: dict[str, Any],
    error_code: int | None = None,
) -> CommandResults:
    """
    Generate the CommandResults for a processed task.
    Args:
        task_id (str): The ID of the task.
        task_output (dict): The output data of the task.
        metadata (Dict[str, Any]): The additional metadata.
        error_code (Optional[int]): The error code if the task failed.
    Returns:
        CommandResults: The generated CommandResults object.
    """
    task_type = task_output.get("type", "")
    command_name_from_task_type = TASK_NUMERIC_TO_COMMAND_NAME.get(task_type, f"UnknownTask_{hex(task_type)}")
    task_output_prefix = f"GravityZone.Command.{command_name_from_task_type}"
    outputs = []
    hosts = []
    for subtask in task_output.get("subtasks", []):
        data = generate_task_output(
            task_id=task_id,
            task_type=command_name_from_task_type,
            endpoint_id=subtask.get("endpointId"),
            status="Processed",
            end_date=subtask.get("endDate"),
            host_name=subtask.get("endpointName"),
            error_code=subtask.get("errorCode", "Success"),
            error=subtask.get("errorMessage", "Success"),
            start_date=subtask.get("startDate"),
        )
        outputs.append(fill_task_output_with_metadata(data, command_name_from_task_type, metadata))
        hosts.append(subtask.get("endpointId"))
    headers = TASK_OUTPUT_HEADERS.copy()
    fill_task_headers_with_metadata(command_name_from_task_type, metadata, headers)
    human_readable = tableToMarkdown(
        f"{task_output_prefix} command on hosts {', '.join(hosts)}:",
        outputs,
        headers=headers,
    )
    if error_code:
        response_entry_type = EntryType.ERROR
    else:
        response_entry_type = EntryType.NOTE
    return CommandResults(
        raw_response=task_output,
        readable_output=human_readable,
        outputs=outputs,
        outputs_prefix=task_output_prefix,
        outputs_key_field="TaskID",
        entry_type=response_entry_type,
    )


def generate_task_output(
    task_id: str,
    task_type: str,
    endpoint_id: str,
    status: str | None = None,
    end_date: str | None = None,
    host_name: str | None = None,
    error_code: str | None = None,
    error: str | None = None,
    start_date: str | None = None,
) -> dict[str, Any]:
    """
    Generate the output dictionary for a task.
    Args:
        task_id (str): The ID of the task.
        task_type (str): The type of the task.
        endpoint_id (str): The ID of the endpoint.
        status (Optional[str]): The status of the task.
        end_date (Optional[str]): The end date of the task.
        host_name (Optional[str]): The name of the host.
        error_code (Optional[str]): The error code if the task failed.
        error (Optional[str]): The error message if the task failed.
        start_date (Optional[str]): The start date of the task.
    Returns:
        Dict[str, Any]: The generated task output dictionary.
    """
    return {
        "TaskID": task_id,
        "TaskType": task_type,
        "Status": status if status else "Error",
        "EndDate": end_date if end_date else datetime.now().isoformat(),
        "EndpointID": endpoint_id,
        "Hostname": host_name if host_name else "Unknown",
        "ErrorCode": error_code if error_code else "-1000",
        "Error": error if error else "Invalid Command Arguments",
        "StartDate": start_date if start_date else datetime.now().isoformat(),
    }


def fetch_incidents(client: Client, start_fetch_time, end_fetch_time, fetch_limit=FETCH_LIMIT) -> list[dict]:
    """
    Fetches incidents from GravityZone within the specified time range.
    Args:
        client (Client): The GravityZone client instance.
        start_fetch_time (str): The start time for fetching incidents.
        end_fetch_time (str): The end time for fetching incidents.
        fetch_limit (int): The maximum number of incidents to fetch.
    Returns:
        list[dict]: A list of fetched incidents.
    """
    incidents: list[dict[str, Any]] = []

    gz_incidents = client.get_incidents(
        start_time=start_fetch_time,
        end_time=end_fetch_time,
        max_fetch=fetch_limit,
    )

    for incident in gz_incidents:
        incident["occurred"] = incident["created"]

    params = demisto.params()
    mirroring_direction = params.get("mirror_direction")
    mirror_instance = demisto.integrationInstance()

    for gz_incident in gz_incidents:
        gz_incident["mirror_direction"] = mirroring_direction
        gz_incident["mirror_instance"] = mirror_instance
        gz_incident["mirror_tags"] = []
        incident = convert_from_gz_to_cortex(gz_incident, include_json=True)
        incidents.append(incident)

    return incidents


def get_entries(new_incident: dict, old_incident: dict) -> list[dict]:
    """
    Generate entries for incident status changes.
    Args:
        new_incident (dict): The updated incident data.
        old_incident (dict): The previous incident data.
    Returns:
        list[dict]: A list of entries reflecting the status change.
    """

    if not new_incident or not old_incident:
        return []

    new_status = new_incident.get("status")
    old_status = old_incident.get("status")

    if new_status == old_status:
        return []

    if new_status == IncidentStatus.DONE:
        return [
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "closeReason": "Incident was resolved in GravityZone platform",
                    "dbotIncidentClose": True,
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        ]

    return [
        {
            "Type": EntryType.NOTE,
            "Contents": {"dbotIncidentReopen": True},
            "ContentsFormat": EntryFormat.JSON,
        }
    ]


""" COMMAND FUNCTIONS """


@logger
def test_module(client: Client, args: dict[str, Any]) -> str:
    """
    Test the GravityZone client connectivity and fetch incidents.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        str: "ok" if the test is successful.
    """
    try:
        params = demisto.params()
        now_dt = datetime.now(UTC)
        if params.get("isFetch"):
            first_fetch_time = (now_dt - timedelta(minutes=1)).strftime(GZ_DATE_FORMAT)
            fetch_incidents(
                client=client,
                start_fetch_time=first_fetch_time,
                end_fetch_time=now_dt.strftime(GZ_DATE_FORMAT),
                fetch_limit=1,
            )
        else:
            start_time = (now_dt - timedelta(minutes=5)).strftime(GZ_DATE_FORMAT)
            end_time = (now_dt + timedelta(minutes=5)).strftime(GZ_DATE_FORMAT)
            client.get_incidents(start_time=start_time, end_time=end_time)

        return "ok"
    except Exception as e:
        return f"Test failed: {str(e)}"


@logger
def gz_poll_task_status_command(args: dict[str, Any], client: Client) -> PollResult:
    """
    Poll the status of a task in GravityZone.
    Args:
        args (Dict[str, Any]): The command arguments.
        client (Client): The GravityZone client instance.
    Returns:
        PollResult: The result of the task status polling.
    """
    return check_task_status(args, client)


@logger
def gz_poll_investigation_activity_status_command(args: dict[str, Any], client: Client) -> PollResult:
    """
    Poll the status of an investigation activity in GravityZone.
    Args:
        args (Dict[str, Any]): The command arguments.
        client (Client): The GravityZone client instance.
    Returns:
        PollResult: The result of the investigation activity status polling.
    """
    return check_investigation_status(args, client)


@logger
def gz_poll_live_search_status_command(args: dict[str, Any], client: Client) -> PollResult:
    """
    Poll the status of a live search in GravityZone.
    Args:
        args (Dict[str, Any]): The command arguments.
        client (Client): The GravityZone client instance.
    Returns:
        PollResult: The result of the live search status polling.
    """
    return query_live_search_results(args, client)


@logger
def get_mapping_fields_command(client: Client, args: dict[str, Any]) -> GetMappingFieldsResponse:
    """
    Get the mapping fields for GravityZone incidents.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        GetMappingFieldsResponse: The mapping fields response.
    """
    xdr_incident_type_scheme = SchemeTypeMapping(type_name="GravityZone XDR")
    xdr_incident_type_scheme.add_field(name="status", description="Incident status")

    edr_incident_type_scheme = SchemeTypeMapping(type_name="GravityZone EDR")
    edr_incident_type_scheme.add_field(name="status", description="Incident status")

    return GetMappingFieldsResponse([xdr_incident_type_scheme, edr_incident_type_scheme])


@logger
def fetch_incidents_command(client: Client, args: dict[str, Any]) -> None:
    """
    Fetch incidents from GravityZone and set them in Demisto.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        None
    """
    params = demisto.params()

    incidents = []

    fetch_limit_param = params.get("max_fetch", FETCH_LIMIT)
    look_back = int(params.get("look_back", 300))
    first_fetch = params.get("first_fetch", "3 days")
    time_zone = params.get("time_zone", 0)

    last_run = demisto.getLastRun()

    fetch_limit = arg_to_number(last_run.get("limit", None) or fetch_limit_param) or FETCH_LIMIT
    start_fetch_time, end_fetch_time = get_fetch_run_time_range(
        last_run=last_run,
        first_fetch=first_fetch,
        look_back=look_back,
        timezone=time_zone,
        date_format=GZ_DATE_FORMAT,
    )

    incidents_res = fetch_incidents(
        client=client,
        start_fetch_time=start_fetch_time,
        end_fetch_time=end_fetch_time,
        fetch_limit=fetch_limit,
    )

    incidents = filter_incidents_by_duplicates_and_limit(
        incidents_res=incidents_res,
        last_run=last_run,
        fetch_limit=fetch_limit,
        id_field="incidentId",
    )

    last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents,
        fetch_limit=fetch_limit,
        start_fetch_time=start_fetch_time,
        end_fetch_time=end_fetch_time,
        look_back=look_back,
        created_time_field="occurred",
        id_field="incidentId",
        date_format=GZ_DATE_FORMAT,
    )

    demisto.incidents(incidents)
    demisto.setLastRun(last_run)


@logger
def get_modified_remote_data_command(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Get the IDs of modified remote incidents from GravityZone.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        GetModifiedRemoteDataResponse: The response containing modified incident IDs.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    end_time = datetime.now(UTC) + timedelta(days=7)
    last_update_utc = dateparser.parse(remote_args.last_update, settings={"TIMEZONE": "UTC"})
    # if last_update_utc is None:
    last_update_utc = datetime.now(UTC) - timedelta(days=7)

    raw_incidents = client.get_incidents(
        start_time=last_update_utc.strftime(GZ_DATE_FORMAT),
        end_time=end_time.strftime(GZ_DATE_FORMAT),
        max_fetch=1000,
    )
    modified_incident_ids = [incident.get("incidentId") for incident in raw_incidents]
    modified_incident_ids = sorted(modified_incident_ids, key=lambda x: str(x))
    return GetModifiedRemoteDataResponse(modified_incident_ids)


@logger
def get_remote_data_command(client: Client, args: dict[str, Any]) -> GetRemoteDataResponse | None:
    """
    Get the remote incident data from GravityZone and generate entries for status changes.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        GetRemoteDataResponse: The response containing the incident data and entries.
    """
    parsed_args = GetRemoteDataArgs(args)
    old_incident = demisto.investigation()
    new_incident_raw_data = client.get_incident(parsed_args.remote_incident_id)
    new_incident_data = convert_from_gz_to_cortex(new_incident_raw_data, include_json=True)
    parsed_entries = get_entries(new_incident=new_incident_data, old_incident=old_incident)
    new_incident_data["id"] = new_incident_data["incidentId"]
    return GetRemoteDataResponse(new_incident_data, parsed_entries)


@logger
def update_remote_system_command(client: Client, args: dict[str, Any]) -> str:
    """
    Update the remote incident in GravityZone based on changes in Demisto.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        str: The remote incident ID.
    """
    parsed_args = UpdateRemoteSystemArgs(args)

    demisto.debug(
        f"update_remote_system_command command args are:"
        f"id: {parsed_args.remote_incident_id}, "
        f"data: {parsed_args.data}, "
        f"entries: {parsed_args.entries}, "
        f"incident_changed: {parsed_args.incident_changed}, "
        f"remote_incident_id: {parsed_args.remote_incident_id}, "
        f"inc_status: {parsed_args.inc_status}, "
        f"delta: {parsed_args.delta}"
    )

    incident_id: str = parsed_args.remote_incident_id

    try:
        if not parsed_args.incident_changed:
            return incident_id

        incident = client.get_incident(incident_id)
        if not incident:
            raise DemistoException(f"Incident {incident_id} was not found")

        if parsed_args.delta.get("closeNotes"):
            incident_type = incident.get("incidentType", "incident")
            client.add_incident_note(incident_type, incident_id, parsed_args.delta.get("closeNotes"))

        gz_status = get_gz_status_matched_to_cortex_status(parsed_args.inc_status, parsed_args.delta.get("closeReason"))
        existing_cortex_status = INCIDENT_STATUS_INT_MAPPING.get(
            incident.get("status", INCIDENT_STATUS_STR_OPEN), IncidentStatus.PENDING
        )
        existing_gz_status = INCIDENT_STATUS_MAPPING.get(existing_cortex_status, GRAVITY_ZONE_INCIDENT_STATUS_OPEN)
        if gz_status != existing_gz_status:
            demisto.debug(f"Changing incident {incident_id} status to {gz_status} from {existing_gz_status} in GravityZone")
            client.change_incident_status(incident_id, gz_status)

    except Exception:
        pass

    return incident_id


@logger
def gz_get_incident_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get an incident from GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the incident to retrieve.
    Returns:
        CommandResults: The command results containing the incident data.
    """
    incident_id = args.get("id", "UNKNOWN_INCIDENT_ID")

    raw_response = client.get_incident(incident_id)
    context_data = generate_context_for_incident(raw_response)
    human_readable = generate_human_readable_incident_from_context(context_data)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="GravityZone.Incident",
        outputs_key_field="ID",
        outputs=context_data,
        raw_response=raw_response,
        replace_existing=True,
    )


@logger
def gz_list_incidents_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List incidents from GravityZone within a specified time range and optional endpoint ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            endpoint_id (str, optional): The ID of the endpoint to filter incidents.
    Returns:
        CommandResults: The command results containing the list of incidents.
    """
    endpoint_id = args.get("endpoint_id", "")
    incidents = []

    now_dt = datetime.now(UTC)
    start_time = (now_dt - timedelta(days=3)).strftime(GZ_DATE_FORMAT)
    end_time = (now_dt + timedelta(days=3)).strftime(GZ_DATE_FORMAT)

    incidents = client.get_incidents(
        start_time=start_time,
        end_time=end_time,
        target_id=endpoint_id if endpoint_id else None,
    )
    context_data = generate_context_for_summarized_incidents(incidents)
    readable_output = generate_human_readable_summarized_incidents_from_context(context_data)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GravityZone.SummarizedIncidents",
        outputs_key_field="ID",
        outputs=context_data,
        raw_response=incidents,
    )


@logger
def gz_add_incident_note_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add a note to an incident in GravityZone.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID(s) of the incident(s) to add the note to.
            note (str): The note text to add.
    Returns:
        CommandResults: The command results containing the status of the note addition.
    """
    incident_ids = argToList(str(args.get("id", "UNKNOWN_INCIDENT_ID")))
    note = args.get("note", "")

    command = "AddIncidentNote"
    output_prefix = f"GravityZone.Command.{command}"
    outputs = []
    raw_responses = []

    for incident_id in incident_ids:
        output = {
            "IncidentID": incident_id,
            "Note": note,
        }
        raw_response = {
            "incident_id": incident_id,
            "note": note,
        }
        try:
            incident = client.get_incident(incident_id)
            if not incident:
                raise DemistoException(f"Incident {incident_id} was not found")
            incident_type = incident.get("incidentType", "incident")
            result = client.add_incident_note(incident_type, incident_id, note)
            if not result:
                raise DemistoException(f"Incident {incident_id} note was not added successfully")
            status = "Success"
        except Exception:
            status = "Cannot add incident note"
        output["CommandStatus"] = status
        raw_response["command_status"] = status
        outputs.append(output)
        raw_responses.append(raw_response)

    return CommandResults(
        raw_response=raw_responses,
        readable_output=tableToMarkdown(
            f"{output_prefix} command on incidents {', '.join(incident_ids)}:",
            outputs,
            headers=["IncidentID", "Note", "CommandStatus"],
        ),
        outputs=outputs,
        outputs_prefix=output_prefix,
        outputs_key_field="IncidentID",
        entry_type=EntryType.NOTE,
    )


@logger
def gz_change_incident_status_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Change the status of an incident in GravityZone.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID(s) of the incident(s) to change the status of.
            status (str): The new status to set for the incident(s).
    Returns:
        CommandResults: The command results containing the status of the status change.
    """
    incident_ids = argToList(str(args.get("id", None)))
    status = args.get("status", "PENDING")

    valid_statuses = {
        "PENDING": IncidentStatus.PENDING,
        "ACTIVE": IncidentStatus.ACTIVE,
        "DONE": IncidentStatus.DONE,
        "ARCHIVE": IncidentStatus.ARCHIVE,
    }

    cortex_status = valid_statuses[status]
    gz_status = INCIDENT_STATUS_MAPPING.get(cortex_status, GRAVITY_ZONE_INCIDENT_STATUS_OPEN)

    command = "ChangeIncidentStatus"
    output_prefix = f"GravityZone.Command.{command}"
    outputs, raw_responses = [], []

    for incident_id in incident_ids:
        output = {"IncidentID": incident_id, "IncidentStatus": status}
        raw_response = {"incident_id": incident_id, "incident_status": status}
        try:
            result = client.change_incident_status(incident_id, gz_status)
            if not result:
                raise DemistoException(f"Incident {incident_id} status was not updated")
            result_status = "Success"
        except Exception:
            result_status = "Cannot update incident status"
        output["CommandStatus"] = result_status
        raw_response["command_status"] = result_status
        outputs.append(output)
        raw_responses.append(raw_response)

    return CommandResults(
        raw_response=raw_responses,
        readable_output=tableToMarkdown(
            f"{output_prefix} command on incidents {', '.join(incident_ids)}:",
            outputs,
            headers=["IncidentID", "IncidentStatus", "CommandStatus"],
        ),
        outputs=outputs,
        outputs_prefix=output_prefix,
        outputs_key_field="IncidentID",
        entry_type=EntryType.NOTE,
    )


@logger
def gz_get_process_tree_for_hash_on_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Get the process tree for a given process hash on a specific endpoint.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint.
            process_hash (str): The hash of the process to search for.
    Returns:
        PollResult: The result of the live search for the process tree.
    """
    process_hash = args.get("process_hash", "UNKNOWN_PROCESS_HASH").lower()
    endpoint_id = args.get("id", "")

    task_id = client.start_live_search_query_find_running_process_tree_by_hash([endpoint_id], process_hash)

    return get_live_search_results(client, task_id, LIVE_SEARCH_QUERY_PROCESS_PER_HASH, metadata="{}")


@logger
def gz_get_endpoints_running_process_hash_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Get the endpoints running a specific process hash.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            process_hash (str): The hash of the process to search for.
    Returns:
        PollResult: The result of the live search for the endpoints running the process hash.
    """
    process_hash = args.get("process_hash", "UNKNOWN_PROCESS_HASH").lower()

    task_id = client.start_live_search_query_find_endpoints_running_process_by_hash([], process_hash)

    return get_live_search_results(
        client,
        task_id,
        LIVE_SEARCH_QUERY_RUNNING_HASH,
        metadata=json.dumps({"process_hash": process_hash}),
    )


@logger
def gz_list_endpoints_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List all endpoints in GravityZone.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
    Returns:
        CommandResults: The command results containing the list of endpoints.
    """
    endpoints_details = client.get_endpoints()
    endpoints = []
    raw_endpoints = []
    for endpoint_details in endpoints_details:
        endpoint = generate_endpoint_from_list_by_contex_standard(endpoint_details)
        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        endpoints.append(endpoint_context)
        raw_endpoints.append(endpoint_details)

    return CommandResults(
        readable_output=tableToMarkdown("Gravity Zone Endpoints", endpoints),
        raw_response=raw_endpoints,
    )


def endpoint_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get an endpoint from GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint to retrieve.
    Returns:
        CommandResults: The command results containing the endpoint data.
    """
    endpoint_id = args.get("id", "")

    endpoint_details = client.get_endpoint(endpoint_id)
    endpoint = generate_endpoint_by_contex_standard(endpoint_details)
    endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)

    return CommandResults(
        readable_output=tableToMarkdown("Gravity Zone Endpoint", endpoint_context),
        raw_response=endpoint_details,
        indicator=endpoint,
    )


def gz_get_endpoint_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get an endpoint from GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint to retrieve.
    Returns:
        CommandResults: The command results containing the endpoint data.
    """
    endpoint_id = args.get("id", "")

    endpoint_details = client.get_endpoint(endpoint_id)
    entry = generate_endpoint_entry(endpoint_details)
    endpoint = generate_endpoint_by_contex_standard(endpoint_details)
    output_prefix = "GravityZone.Endpoint"

    return CommandResults(
        readable_output=tableToMarkdown(
            "Gravity Zone Endpoint",
            entry,
            headers=[
                "ID",
                "Hostname",
                "IP",
                "OS",
                "Status",
                "Vendor",
                "LastLoggedUsers",
            ],
        ),
        raw_response=endpoint_details,
        indicator=endpoint,
        outputs=entry,
        outputs_prefix=output_prefix,
        outputs_key_field="ID",
        entry_type=EntryType.NOTE,
    )


def gz_isolate_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Isolate an endpoint in GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint to isolate.
    Returns:
        PollResult: The command results of the isolation task.
    """
    endpoint_id = args.get("id", "")

    result = client.start_isolate_endpoint(endpoint_id)

    return get_task_results(client, result[0], {"endpointId": endpoint_id})


def gz_deisolate_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Deisolate an endpoint in GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint to deisolate.
    Returns:
        PollResult: The command results of the deisolation task.
    """
    endpoint_id = args.get("id", "")

    result = client.start_deisolate_endpoint(endpoint_id)

    return get_task_results(client, result[0], {"endpointId": endpoint_id})


def gz_run_command_on_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Run a command on an endpoint in GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint.
            command (str): The command to run on the endpoint.
    Returns:
        CommandResults: The command results of the command execution.
    """
    endpoint_id = args.get("id", "")
    command = args.get("command", "")

    command_execution_activity_id = client.start_command_execution_on_endpoint(endpoint_id, command)

    return get_investigation_results(
        client,
        endpoint_id,
        command_execution_activity_id,
        "",
        {
            "activityType": ACTIVITY_TYPE_RUN_COMMAND,
            "targetId": endpoint_id,
            "command": command,
        },
    )


def gz_download_file_from_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Download a file from an endpoint in GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint.
            remote_file (str): The full path of the remote file to download.
            output_file (str): The name of the output file.
    Returns:
        PollResult: The command results of the file download.
    """
    endpoint_id = args.get("id", "")
    remote_file = args.get("remote_file", "")
    output_file = args.get("output_file", "")

    retrieve_activity_id = client.start_retrieve_investigation_file_from_endpoint(endpoint_id, remote_file)

    return get_investigation_results(
        client,
        endpoint_id,
        retrieve_activity_id,
        output_file,
        {
            "activityType": ACTIVITY_TYPE_DOWNLOAD_FILE,
            "targetId": endpoint_id,
            "remoteFile": remote_file,
            "outputFile": output_file,
        },
    )


def gz_upload_file_to_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Upload a file to an endpoint in GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint.
            entry_id (str): The ID of the file entry to upload.
            remote_location (str): The destination path on the endpoint.
    Returns:
        PollResult: The command results of the file upload.
    """
    endpoint_id = args.get("id", "")
    entry_id = args.get("entry_id", "")
    remote_location = args.get("remote_location", "")

    response = FileManagement(client).upload_file(
        "investigationFiles",
        entry_id,
        {"protectedEntityId": endpoint_id, "path": remote_location},
    )
    upload_task_id = response["additionalData"]["taskId"]

    return get_task_results(
        client,
        upload_task_id,
        {
            "localFile": entry_id,
            "endpointId": endpoint_id,
            "destinationPath": remote_location,
        },
    )


def gz_download_investigation_package_from_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Download an investigation package from an endpoint in GravityZone by its ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint.
            output_file (str): The name of the output file.
    Returns:
        PollResult: The command results of the investigation package download.
    """
    endpoint_id = args.get("id", "")
    output_file = args.get("output_file", "")

    result = client.start_collect_investigation_package_on_endpoint(endpoint_id)

    if "activityId" in result:
        activity_id = result["activityId"]
    else:
        return PollResult(
            CommandResults(
                raw_response=result,
                readable_output=f"Collect investigation package for endpoint '{endpoint_id}' failed.",
                entry_type=EntryType.ERROR,
            )
        )

    return get_investigation_results(
        client,
        endpoint_id,
        activity_id,
        output_file,
        {
            "activityType": ACTIVITY_TYPE_DOWNLOAD_FILE,
            "targetId": endpoint_id,
            "outputFile": output_file,
        },
    )


def gz_kill_process_on_endpoint_command(client: Client, args: dict[str, Any]) -> PollResult:
    """
    Kill a process on an endpoint in GravityZone by its Process ID.
    Args:
        client (Client): The GravityZone client instance.
        args (Dict[str, Any]): The command arguments.
            id (str): The ID of the endpoint.
            pid (str): The Process ID of the process to be killed.
    Returns:
        PollResult: The command results of the process kill.
    """
    endpoint_id = args.get("id", "")
    process_id = int(args.get("pid", 0))

    kill_task_id = client.start_kill_process_on_endpoint(endpoint_id, process_id)

    return get_task_results(client, kill_task_id, {"targetId": endpoint_id, "processId": process_id})


def main():
    command: str = demisto.command()

    try:
        params = demisto.params()
        args = demisto.args()

        base_url = params.get("url", "")
        api_key = params.get("credentials", {}).get("password")
        verify_certificate = not argToBoolean(params.get("insecure", False))
        proxy = argToBoolean(params.get("proxy", False))

        client = Client(
            url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
        )

        # Map command names to their corresponding functions
        command_function_map = {
            "test-module": test_module,
            ### GravityZone Polling Commands ###
            "gz-poll-task-status": gz_poll_task_status_command,
            "gz-poll-investigation-activity-status": gz_poll_investigation_activity_status_command,
            "gz-poll-live-search-status": gz_poll_live_search_status_command,
            ### GravityZone Endpoint Commands ###
            "gz-list-endpoints": gz_list_endpoints_command,
            "endpoint": endpoint_command,
            "gz-get-endpoint-by-id": gz_get_endpoint_by_id_command,
            "gz-download-investigation-package-from-endpoint": gz_download_investigation_package_from_endpoint_command,
            "gz-download-file-from-endpoint": gz_download_file_from_endpoint_command,
            "gz-isolate-endpoint": gz_isolate_endpoint_command,
            "gz-deisolate-endpoint": gz_deisolate_endpoint_command,
            "gz-kill-process-on-endpoint": gz_kill_process_on_endpoint_command,
            "gz-run-command-on-endpoint": gz_run_command_on_endpoint_command,
            "gz-upload-file-to-endpoint": gz_upload_file_to_endpoint_command,
            "gz-get-endpoints-running-process-hash": gz_get_endpoints_running_process_hash_command,
            "gz-get-process-tree-for-hash-on-endpoint": gz_get_process_tree_for_hash_on_endpoint_command,
            ### GravityZone Incident Commands ###
            "fetch-incidents": fetch_incidents_command,
            "gz-get-incident-by-id": gz_get_incident_by_id_command,
            "gz-list-incidents": gz_list_incidents_command,
            "gz-add-incident-note": gz_add_incident_note_command,
            "gz-change-incident-status": gz_change_incident_status_command,
            ### Cortex XSOAR EDL Commands ###
            "get-modified-remote-data": get_modified_remote_data_command,
            "get-remote-data": get_remote_data_command,
            "update-remote-system": update_remote_system_command,
            "get-mapping-fields": get_mapping_fields_command,
        }

        polling_functions = [
            "gz-poll-task-status",
            "gz-poll-investigation-activity-status",
            "gz-poll-live-search-status",
        ]

        if command in command_function_map:
            if command in polling_functions:
                results = command_function_map[command](args, client)
            else:
                results = command_function_map[command](client, args)
            return_results(results)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
