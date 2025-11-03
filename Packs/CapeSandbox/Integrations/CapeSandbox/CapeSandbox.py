import os
import re
import time
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401, F403

urllib3.disable_warnings()  # Disable insecure warnings

"""
CapeSandbox integration

Sections:
- Constants and helpers
- Client (API paths and methods)
- Command implementations
- Main router
"""


# region Constants and helpers
# =================================
# Constants and helpers
# =================================
INTEGRATION_NAME = "CapeSandbox"
POLLING_INTERVAL_SECONDS = 60
POLLING_TIMEOUT_SECONDS = 60 * 15
LIST_DEFAULT_LIMIT = 50


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Normalize and extract integration configuration from demisto.params()."""
    base_url = (params.get("url", "")).rstrip("/")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    # API Token credentials
    token_credentials = params.get("token_credentials", {})
    api_token = token_credentials.get("password", params.get("api_token"))

    # Basic Auth credentials
    credentials = params.get("credentials", {})
    username = credentials.get("identifier", params.get("username"))
    password = credentials.get("password", params.get("password"))

    if not base_url:
        raise DemistoException("Server URL (url) is required.")

    # precedence: api_token over username/password
    if api_token and (username or password):
        demisto.debug("CapeSandbox: api_token provided; username/password will be ignored.")

    return {
        "base_url": base_url,
        "verify_certificate": verify_certificate,
        "proxy": proxy,
        "api_token": api_token,
        "username": username,
        "password": password,
    }


def build_submit_form(args: dict[str, Any], url_mode: bool = False) -> dict[str, Any]:
    form = assign_params(
        package=args.get("package"),
        timeout=arg_to_number(args.get("timeout")),
        priority=arg_to_number(args.get("priority")),
        options=args.get("options"),
        machine=args.get("machine"),
        platform=args.get("platform"),
        tags=args.get("tags"),
        custom=args.get("custom"),
        memory="1" if argToBoolean(args.get("memory", False)) else None,
        enforce_timeout=("1" if argToBoolean(args.get("enforce_timeout", False)) else None),
        clock=args.get("clock"),
    )
    if url_mode:
        form["url"] = args.get("url")
    return form


def extract_entry_file_data(entry_id: str) -> tuple[str, str]:
    """
    Retrieves the local file path and original name for a given entry ID.
    Handles all potential errors related to file fetching.

    Args:
        entry_id: The ID of the entry (e.g., file) in the War Room.

    Returns:
        A tuple containing (file_path: str, file_name: str).

    Raises:
        DemistoException: If the entry is not found or is not a file.
    """
    try:
        filepath_result = demisto.getFilePath(entry_id)

        if not filepath_result or "path" not in filepath_result:
            raise ValueError("Entry is not a valid file entry.")

    except ValueError as error:
        demisto.debug(f"Error fetching file path for {entry_id!r}", error)
        raise DemistoException(f"Could not find file or entry: {entry_id!r}")

    except Exception as error:
        raise DemistoException(f"An unexpected error occurred while processing entry {entry_id!r}", error)

    path = filepath_result["path"]
    name = filepath_result.get("name")

    final_name = name if name else os.path.basename(path)

    return path, final_name


def get_entry_path(entry_id: str) -> tuple[str, str]:
    """
    Wrapper function to safely extract file data.

    Args:
        entry_id: The ID of the entry.

    Returns:
        (file_path: str, file_name: str).
    """
    return extract_entry_file_data(entry_id)


def build_file_name(
    file_identifier: str | int,
    file_type: Literal["file", "report", "screenshot", "network_dump"] | None = None,
    screenshot_number: int | None = None,
    file_format: (Literal["pdf", "html", "csv", "zip", "pcap", "bin"] | str | None) = None,
) -> str:
    """
    Constructs a standardized filename based on the task identifier and file metadata.
    """
    TYPE_MAP = {
        "screenshot": {"ext": "png", "part": "screenshot"},
        "report": {
            "ext": str(file_format) if file_format else "json",
            "part": "report",
        },
        "file": {
            "ext": str(file_format) if file_format else "json",
            "part": "file",
        },
        "network_dump": {
            "ext": "pcap",
            "part": "network_dump",
        },
    }

    extension = str(file_format) if file_format else "dat"
    middle_part_base = None

    if file_type in TYPE_MAP:
        info = TYPE_MAP[file_type]
        extension = info["ext"]
        middle_part_base = info["part"]

    # Special handling for screenshot number
    if file_type == "screenshot" and screenshot_number is not None:
        middle_part_base = f"screenshot_{screenshot_number}"

    # Construct the final filename parts
    middle_part_str = f"_{middle_part_base}" if middle_part_base else ""

    return f"cape_task_{file_identifier}{middle_part_str}.{extension}"


def status_is_reported(status_response: str) -> bool:
    return status_response == "reported"


def initiate_polling(command: str, args: dict, task_id: int | str, api_target: str, outputs_prefix: str) -> CommandResults:
    """
    Calculates polling parameters, logs them, and returns CommandResults
    to initiate the polling sequence.
    """

    polling_interval = arg_to_number(args.get("pollingInterval")) or POLLING_INTERVAL_SECONDS
    polling_timeout = arg_to_number(args.get("pollingTimeout")) or POLLING_TIMEOUT_SECONDS

    demisto.debug(
        f"Command '{command}' execution finished successfully. Initiating Polling for "
        f"Task ID: {task_id}. Interval: {polling_interval}s, Timeout: {polling_timeout}s."
    )

    next_args = {**args, "task_id": str(task_id), "outputs_prefix": outputs_prefix}

    readable = f"Submitted {api_target}. Task ID {task_id}. Polling initiated, checking every " f"{polling_interval}s."

    return CommandResults(
        readable_output=readable,
        outputs_prefix=outputs_prefix,
        outputs={"id": task_id, "target": api_target, "status": "pending"},
        scheduled_command=ScheduledCommand(
            command="cape-task-poll",
            next_run_in_seconds=polling_interval,
            args=next_args,
            timeout_in_seconds=polling_timeout,
        ),
    )


# Hash validators (regex-based)
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def is_valid_md5(value: str | None) -> bool:
    return bool(_MD5_RE.fullmatch(value or ""))


def is_valid_sha1(value: str | None) -> bool:
    return bool(_SHA1_RE.fullmatch(value or ""))


def is_valid_sha256(value: str | None) -> bool:
    return bool(_SHA256_RE.fullmatch(value or ""))


# endregion
# region Client (API)
# =================================
# Client (API paths and methods)
# =================================


class ApiPrefix(Enum):
    """Base versioning prefixes for the API."""

    V2 = "apiv2"


class Resource(Enum):
    """Core resource names."""

    API_TOKEN_AUTH = "api-token-auth"
    FILES = "files"
    TASKS = "tasks"
    MACHINES = "machines"


class Action(Enum):
    """Common actions or sub-paths."""

    CREATE = "create"
    STATUS = "status"
    VIEW = "view"
    GET = "get"
    DELETE = "delete"
    FILE = "file"
    URL = "url"
    ID = "id"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    PCAP = "pcap"


class CustomHeaders(Enum):
    FILES_STREAM = {"Content-Type": "application/octet-stream"}


class ResponseTypes(Enum):
    JSON = "json"
    CONTENT = "content"


class AuthParams(Enum):
    TOKEN_KEY = "token"
    VALID_UNTIL_KEY = "valid_until"
    CACHE_KEY = "auth_info"
    TOKEN_TTL_SECONDS = 60 * 60 * 24 * 1


# ---------- API Path Templates ----------
BASE_PREFIX = ApiPrefix.V2.value

# Resource base paths for convenience
TASKS_BASE = f"{BASE_PREFIX}/{Resource.TASKS.value}"
FILES_BASE = f"{BASE_PREFIX}/{Resource.FILES.value}"
MACHINES_BASE = f"{BASE_PREFIX}/{Resource.MACHINES.value}"

# -- Authentication --
API_AUTH = f"{BASE_PREFIX}/{Resource.API_TOKEN_AUTH.value}/"

# -- Tasks --
TASK_CREATE_FILE = f"{TASKS_BASE}/{Action.CREATE.value}/{Action.FILE.value}/"
TASK_CREATE_URL = f"{TASKS_BASE}/{Action.CREATE.value}/{Action.URL.value}/"
TASK_STATUS = f"{TASKS_BASE}/{Action.STATUS.value}/{{task_id}}/"
TASK_VIEW = f"{TASKS_BASE}/{Action.VIEW.value}/{{task_id}}/"
TASK_LIST = f"{TASKS_BASE}/list/{{limit}}/{{offset}}/"
TASK_DELETE = f"{TASKS_BASE}/{Action.DELETE.value}/{{task_id}}/"
TASK_GET_REPORT_BASE = f"{TASKS_BASE}/{Action.GET.value}/report/{{task_id}}/"
TASK_GET_PCAP = f"{TASKS_BASE}/{Action.GET.value}/{Action.PCAP.value}/{{task_id}}/"
CUCKOO_STATUS_URL = f"{BASE_PREFIX}/cuckoo/{Action.STATUS.value}/"
TASK_SCREENSHOTS_LIST = f"{TASKS_BASE}/{Action.GET.value}/screenshot/{{task_id}}/"
TASK_SCREENSHOT_GET = f"{TASKS_BASE}/{Action.GET.value}/screenshot/{{task_id}}/{{number}}/"

# -- Files --
FILE_VIEW_BY_TASK = f"{FILES_BASE}/{Action.VIEW.value}/{Action.ID.value}/{{task_id}}/"
FILE_VIEW_BY_MD5 = f"{FILES_BASE}/{Action.VIEW.value}/{Action.MD5.value}/{{md5}}/"
FILE_VIEW_BY_SHA256 = f"{FILES_BASE}/{Action.VIEW.value}/{Action.SHA256.value}/{{sha256}}/"
FILES_GET_BY_TASK = f"{FILES_BASE}/{Action.GET.value}/task/{{task_id}}"
FILES_GET_BY_MD5 = f"{FILES_BASE}/{Action.GET.value}/{Action.MD5.value}/{{md5}}"
FILES_GET_BY_SHA1 = f"{FILES_BASE}/{Action.GET.value}/{Action.SHA1.value}/{{sha1}}"
FILES_GET_BY_SHA256 = f"{FILES_BASE}/{Action.GET.value}/{Action.SHA256.value}/{{sha256}}"

# -- Machines --
MACHINES_LIST = f"{MACHINES_BASE}/list/"
MACHINE_VIEW = f"{MACHINES_BASE}/{Action.VIEW.value}/{{name}}/"


# ---------- Client: Auth & HTTP ----------
class CapeSandboxClient(BaseClient):  # noqa: F405
    """Client for CAPE Sandbox API.

    Supports two auth flows:
    - API Token (preferred): pass header Authorization: Token <token>
    - Username/Password: obtain token via POST /apiv2/api-token-auth/ and cache in integration context
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        base_url = base_url.rstrip("/") + "/"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_token = (api_token or "").strip() if api_token else None
        self.username = (username or "").strip() if username else None
        self.password = (password or "").strip() if password else None

        demisto.debug(f"Client initialized. Base URL: {base_url}, Verify SSL: {verify}, Proxy: {proxy}")

        if self.api_token:
            auth_type = "API Token"

        elif self.username and self.password:
            auth_type = "Username/Password"

        else:
            raise DemistoException("Either API token or Username + Password must be provided.")

        demisto.debug(f"Client initialization ended successfully. Authentication type: {auth_type}")

    # ---------- Auth & Token ----------
    def _auth_headers(self) -> dict[str, str]:
        token = self.ensure_token()
        return {"Authorization": f"Token {token}"}

    def _get_valid_cached_token(self) -> str | None:
        """
        Attempts to retrieve a non-expired token from the integration cache.

        Returns:
            str | None: The valid token string if found and not expired, otherwise None.
        """
        time_now = int(time.time())
        integration_context = get_integration_context() or {}
        cached_auth_info = integration_context.get(AuthParams.CACHE_KEY.value)

        if not cached_auth_info or not isinstance(cached_auth_info, dict):
            demisto.debug("Auth cache is empty or corrupt.")
            return None

        cached_token = cached_auth_info.get(AuthParams.TOKEN_KEY.value)
        valid_until_str = cached_auth_info.get(AuthParams.VALID_UNTIL_KEY.value)

        if not cached_token or not valid_until_str:
            demisto.debug("Cached auth info is missing token or expiry time.")
            return None

        try:
            valid_until = int(valid_until_str)

            if time_now < valid_until:
                time_remaining = valid_until - time_now
                demisto.debug(f"Using cached token, valid for {time_remaining} more seconds.")
                return cached_token

            demisto.debug(f"Cached token expired at {time.ctime(valid_until)}. Renewing.")

            return None

        except ValueError:
            demisto.debug("Invalid 'valid_until' value found in cache. Forcing renewal.")
            return None

    def _check_for_api_error(self, response: dict[str, Any], url_suffix: str) -> None:
        """
        Checks the CAPE JSON response for the specific error field: 'error': True.
        If an error is detected, logs the failure and raises a DemistoException.
        """
        if isinstance(response, dict) and response.get("error") is True:
            fail_message = (
                response.get("error_value") or response.get("failed") or response.get("message") or "Unknown API error occurred."
            )

            demisto.debug(
                f"CAPE API call for {url_suffix} failed with explicit error flag",
                {"url": url_suffix, "message": fail_message, "response": response},
            )

            raise DemistoException(f"CapeSandbox API call failed for {url_suffix}, " f"with error {fail_message}")

    def ensure_token(self) -> str:
        """
        Returns a valid token. If api_token is provided, uses it.
        Otherwise, it checks the cache (TTL), and generates and caches a new token if needed, using username/password.
        """
        time_now = int(time.time())
        demisto.debug("Starting token retrieval process.")

        if self.api_token:
            demisto.debug("Using API token provided in integration parameters.")
            return self.api_token

        if not (self.username and self.password):
            demisto.debug("No token or username/password provided. Raising configuration error.")
            raise DemistoException("Either API token or Username + Password must be provided.")

        cached_token = self._get_valid_cached_token()
        if cached_token:
            return cached_token

        demisto.debug("No valid cached token found. Attempting to generate a new token via API.")

        data = {"username": self.username, "password": self.password}

        resp = self._http_request(method="POST", url_suffix=API_AUTH, data=data)
        token = resp.get("token", resp.get("key", ""))

        if not token:
            demisto.debug(f"Token generation failed. Response keys missing token/key. Response: {resp}")
            raise DemistoException("Failed to obtain API token from CAPE response.")

        demisto.debug("Successfully received new API token.")

        new_valid_until = time_now + AuthParams.TOKEN_TTL_SECONDS.value

        new_auth_info = {
            AuthParams.TOKEN_KEY.value: token,
            AuthParams.VALID_UNTIL_KEY.value: str(new_valid_until),
        }

        integration_context = get_integration_context() or {}  # Re-fetch context to avoid race condition or stale data
        integration_context[AuthParams.CACHE_KEY.value] = new_auth_info
        set_integration_context(integration_context)

        demisto.debug(f"Successfully **regenerated and cached** a new token. It is valid until {time.ctime(new_valid_until)}.")

        return token

    def http_request(
        self,
        method: str,
        headers: dict[str, str] | None = None,
        url_suffix: str = "",
        full_url: str = "",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        resp_type: str = ResponseTypes.JSON.value,
        ok_codes: tuple[int, ...] | None = None,
    ) -> Any:
        merged_headers = self._auth_headers()
        if headers:
            merged_headers.update(headers)

        demisto.debug(f"Executing API request: {method} {url_suffix}.")

        response = self._http_request(
            method=method,
            headers=merged_headers,
            url_suffix=url_suffix,
            full_url=full_url,
            params=params,
            data=data,
            json_data=json_data,
            files=files,
            resp_type=resp_type,
            ok_codes=(200, 201, 202, 204),
        )

        demisto.debug(f"API request to {url_suffix} completed. Response type: {resp_type}.")

        if resp_type == ResponseTypes.JSON.value:
            self._check_for_api_error(response, url_suffix)

        return response

    # ---------- Submit ----------
    def submit_file(self, form: dict[str, Any], file_path: str, is_pcap: bool) -> dict[str, Any]:
        """Create a task by uploading a file."""

        data = form.copy()
        if is_pcap:
            data["pcap"] = "1"
        basename = Path(file_path).name
        with open(file_path, "rb") as f:
            files = {"file": (basename, f)}
            return self.http_request("POST", url_suffix=TASK_CREATE_FILE, files=files, data=data)

    def submit_url(self, form: dict[str, Any]) -> dict[str, Any]:
        """Create a task by submitting a URL"""
        return self.http_request("POST", url_suffix=TASK_CREATE_URL, data=form)

    # ---------- Task Operations ----------
    def get_task_status(self, task_id: int | str) -> dict[str, Any]:
        """Return task status"""
        return self.http_request("GET", url_suffix=TASK_STATUS.format(task_id=task_id))

    def get_task_view(self, task_id: int | str) -> dict[str, Any]:
        """Return task details"""
        return self.http_request("GET", url_suffix=TASK_VIEW.format(task_id=task_id))

    def delete_task(self, task_id: int | str) -> dict[str, Any]:
        """Delete a task by ID."""
        return self.http_request("GET", url_suffix=TASK_DELETE.format(task_id=task_id))

    def list_tasks(self, limit: int, offset: int) -> dict[str, Any]:
        """Return list of tasks with pagination."""
        if limit <= 0:
            demisto.debug(f"Error: list_tasks called with invalid limit: {limit}")
            raise DemistoException("limit must be > 0")
        if offset < 0:
            demisto.debug(f"Error: list_tasks called with invalid offset: {offset}")
            raise DemistoException("offset must be >= 0")

        return self.http_request("GET", url_suffix=TASK_LIST.format(limit=limit, offset=offset))

    def get_task_report(self, task_id: int | str, format: str | None = None, zip_download: bool = False) -> Any:
        """Return task report. If zip_download is True, returns bytes content of a zip; otherwise JSON.

        Supported formats include: json (default), maec, maec5, metadata, lite, all, dist, dropped.
        """
        suffix = TASK_GET_REPORT_BASE.format(task_id=task_id)
        if format:
            suffix += f"{format}/"
        if zip_download:
            suffix += "zip/"
            return self.http_request("GET", url_suffix=suffix, resp_type=ResponseTypes.CONTENT.value)

        return self.http_request("GET", url_suffix=suffix)

    def get_task_pcap(self, task_id: int | str, format: str | None = None, zip_download: bool = False) -> Any:
        """Download the PCAP dump of a Task by ID. Return object will be application/vnd.tcpdump.pcap. (.pcap)"""
        return self.http_request(
            "GET",
            url_suffix=TASK_GET_PCAP.format(task_id=task_id),
            resp_type=ResponseTypes.CONTENT.value,
        )

    def list_task_screenshots(self, task_id: int | str) -> Any:
        """Return list/metadata of screenshots for a task (JSON)."""
        return self.http_request("GET", url_suffix=TASK_SCREENSHOTS_LIST.format(task_id=task_id))

    def get_task_screenshot(self, task_id: int | str, number: int | str) -> bytes:
        """Return a specific screenshot content (binary)."""
        return self.http_request(
            "GET",
            url_suffix=TASK_SCREENSHOT_GET.format(task_id=task_id, number=number),
            resp_type=ResponseTypes.CONTENT.value,
        )

    # ---------- File View & Download ----------
    def files_view_by_task(self, task_id: int | str) -> dict[str, Any]:
        return self.http_request("GET", url_suffix=FILE_VIEW_BY_TASK.format(task_id=task_id))

    def files_view_by_md5(self, md5: str) -> dict[str, Any]:
        """Return file details by MD5."""
        if not is_valid_md5(md5):
            raise DemistoException("Invalid MD5 hash format.")
        return self.http_request("GET", url_suffix=FILE_VIEW_BY_MD5.format(md5=md5))

    def files_view_by_sha256(self, sha256: str) -> dict[str, Any]:
        """Return file details by SHA256."""
        if not is_valid_sha256(sha256):
            raise DemistoException("Invalid SHA256 hash format.")
        return self.http_request("GET", url_suffix=FILE_VIEW_BY_SHA256.format(sha256=sha256))

    def files_get_by_task(self, task_id: int | str) -> bytes:
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_TASK.format(task_id=task_id),
            headers=CustomHeaders.FILES_STREAM.value,
            resp_type=ResponseTypes.CONTENT.value,
        )

    def files_get_by_md5(self, md5: str) -> dict[str, Any]:
        """Return file details by MD5."""
        if not is_valid_md5(md5):
            raise DemistoException("Invalid MD5 hash format.")
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_MD5.format(md5=md5),
            headers=CustomHeaders.FILES_STREAM.value,
            resp_type=ResponseTypes.CONTENT.value,
        )

    def files_get_by_sha1(self, sha1: str) -> dict[str, Any]:
        """Return file details by SHA1."""
        if not is_valid_sha1(sha1):
            raise DemistoException("Invalid SHA1 hash format.")
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_SHA1.format(sha1=sha1),
            headers=CustomHeaders.FILES_STREAM.value,
            resp_type=ResponseTypes.CONTENT.value,
        )

    def files_get_by_sha256(self, sha256: str) -> dict[str, Any]:
        """Return file details by SHA256."""
        if not is_valid_sha256(sha256):
            raise DemistoException("Invalid SHA256 hash format.")
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_SHA256.format(sha256=sha256),
            headers=CustomHeaders.FILES_STREAM.value,
            resp_type=ResponseTypes.CONTENT.value,
        )

    # ---------- Machines ----------
    def list_machines(self) -> dict[str, Any]:
        """Return list of analysis machines."""
        return self.http_request("GET", url_suffix=MACHINES_LIST)

    def view_machine(self, name: str) -> dict[str, Any]:
        """Return details for a specific analysis machine by name."""
        if not name:
            raise DemistoException("machine_name is required")
        return self.http_request("GET", url_suffix=MACHINE_VIEW.format(name=name))

    # ---------- Status ----------
    def get_cuckoo_status(self) -> dict[str, Any]:
        """Return overall CAPE status."""
        return self.http_request("GET", url_suffix=CUCKOO_STATUS_URL)


# endregion
# region Command implementations
# =================================
# Command implementations
# =================================
def test_module(client: CapeSandboxClient) -> str:
    """Test connectivity and credentials by ensuring a valid token exists."""
    command = "Test Module"
    demisto.debug(f"Starting execution of command: {command}")
    client.ensure_token()
    demisto.debug(f"Command '{command}' execution finished successfully.")

    return "ok"


# ---------- Submit & Poll ----------
@polling_function(
    name="cape-task-poll",
    interval=POLLING_INTERVAL_SECONDS,
    timeout=POLLING_TIMEOUT_SECONDS,
)
def cape_task_poll_report(args: dict[str, Any], client: CapeSandboxClient) -> PollResult:
    """
    Polls the CAPE service for the task status until the report is ready.

    Polling Flow:
    1. Status Check: Queries the task status (running or reported).
    2. Polling Continuation: If 'running', schedules the next poll (continue_to_poll=True).
    3. Final Report: If 'reported', fetches the detailed task view and the raw report file.
    4. Result Compilation: Returns final CommandResults (task metadata) and a fileResult (the report).

    Args:
        args: Dictionary containing 'task_id'.
        client: The configured CapeSandboxClient instance.

    Returns:
        PollResult: Contains polling status and final results if complete.
    """
    task_id = args["task_id"]
    demisto.debug(f"Starting polling for Task ID: {task_id}.")

    polling_interval = arg_to_number(args.get("pollingInterval", POLLING_INTERVAL_SECONDS))

    # --- Status Check ---
    demisto.debug(f"Polling status for Task ID {task_id}.")

    try:
        resp = client.get_task_status(task_id)

        status = resp.get("data", "")
        demisto.debug(f"The status for Task ID {task_id} is '{status}'.")

    except DemistoException as error:
        # Check if the error is the specific 429 Too Many Requests error
        error_message = str(error)
        if "429" in error_message or "Too Many Requests" in error_message:
            demisto.debug(f"Task ID {task_id}: Received throttling error (429). Ignoring failure and scheduling next poll.")
            readable = (
                f"Task ID {task_id} received a **Too Many Requests (429)** error. "
                f"Continuing to poll in {polling_interval} seconds."
            )

            return PollResult(
                response=None,
                args_for_next_run={**args},
                continue_to_poll=True,
                partial_result=CommandResults(readable_output=readable),
            )

        raise error

    if status_is_reported(status):
        demisto.debug(f"Task ID {task_id} status is 'reported'. Fetching final results.")

        # --- Final Report Fetch ---
        task_view = client.get_task_view(task_id)
        readable = tableToMarkdown(
            f"{INTEGRATION_NAME} Task {task_id}",
            task_view.get("data") or task_view,
            headers=[
                "id",
                "target",
                "category",
                "priority",
                "machine",
                "package",
                "platform",
                "started_on",
                "completed_on",
                "status",
                "running_processes",
                "domains",
            ],
            headerTransform=string_to_table_header,
        )
        final_output_prefix = args.get("outputs_prefix", "Cape.Task")
        final_results = CommandResults(
            readable_output=readable,
            outputs_prefix=final_output_prefix,
            outputs_key_field="id",
            outputs=task_view.get("data") or task_view,
        )

        # Fetch the JSON report file content
        report_file_content = client.get_task_report(task_id=task_id, format="json", zip_download=True)
        filename = build_file_name(file_identifier=task_id, file_type="report", file_format="zip")
        file_result = fileResult(filename, report_file_content)

        # --- Result Compilation ---
        final_readable = f"Polling finished successfully for Task {task_id}. Results returned."
        demisto.debug(final_readable)

        return PollResult(
            response=[
                file_result,
                final_results,
            ],
            continue_to_poll=False,
            partial_result=CommandResults(readable_output=final_readable),
        )

    # --- Polling Continuation ---
    else:
        continuation_output_prefix = args.get("outputs_prefix", "Cape.Task")
        readable = f"Task ID {task_id} status is '{status}'. " f"Scheduling next check in {polling_interval} seconds."
        demisto.debug(readable)

        status_update = CommandResults(
            readable_output=readable,
            outputs_prefix=continuation_output_prefix,
            outputs={"id": task_id, "status": status},
        )

        return PollResult(
            response=None,
            args_for_next_run={**args},
            continue_to_poll=True,
            partial_result=status_update,
        )


def cape_file_submit_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """
    Submits a file (or PCAP) to CAPE, retrieves the task_id, and initiates the polling sequence.
    """
    command = "Submit File"
    demisto.debug(f"Starting execution of command: {command}")

    entry_id = args.get("entry_id")

    if not entry_id:
        raise DemistoException("entry_id is required for cape-file-submit.")

    try:
        file_path, filename = get_entry_path(entry_id)
    except Exception as error:
        raise DemistoException(f"Failed to resolve entry_id '{entry_id}' to a local file path: {error}")

    is_pcap = filename.lower().endswith(".pcap")

    # Execute the submission API call
    form = build_submit_form(args)
    submit_resp = client.submit_file(form=form, file_path=file_path, is_pcap=is_pcap)
    task_ids = ((submit_resp or {}).get("data", {})).get("task_ids", [])

    if not task_ids:
        raise DemistoException(f"No task id returned from CAPE. Response: {submit_resp}")

    return initiate_polling(
        command=command,
        args=args,
        task_id=task_ids[0],
        api_target=filename,
        outputs_prefix="Cape.Task.File",
    )


def cape_url_submit_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """
    Submits a URL to CAPE, retrieves the task_id, and initiates the polling sequence.
    """
    command = "Submit URL"
    demisto.debug(f"Starting execution of command: {command}")

    url = args.get("url")

    if not url:
        raise DemistoException("URL is required for cape-url-submit.")

    form = build_submit_form(args, url_mode=True)
    submit_resp = client.submit_url(form=form)
    task_ids = ((submit_resp or {}).get("data", {})).get("task_ids", [])

    if not task_ids:
        raise DemistoException(f"No task id returned from CAPE. Response: {submit_resp}.")

    return initiate_polling(
        command=command,
        args=args,
        task_id=task_ids[0],
        api_target=url,
        outputs_prefix="Cape.Task.Url",
    )


# ---------- Retrieval ----------
def cape_file_view_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """View file information by one of: `task_id`, `md5`, or `sha256`."""
    command = "Get File View"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = arg_to_number(args.get("task_id"))
    md5 = args.get("md5")
    sha256 = args.get("sha256")

    lookup_id = task_id or md5 or sha256
    demisto.debug(f"Starting file view command for ID: {lookup_id}.")

    if not lookup_id:
        raise DemistoException("Provide one of: task_id, md5, sha256")

    if sum(bool(x) for x in [task_id, md5, sha256]) > 1:
        raise DemistoException("Provide only one of task_id, md5, sha256")

    resp: dict[str, Any] = {}

    if task_id:
        demisto.debug(f"Calling files_view_by_task for task ID: {task_id}.")
        resp = client.files_view_by_task(task_id)

    elif md5:
        demisto.debug(f"Calling files_view_by_md5 for MD5: {md5}.")
        resp = client.files_view_by_md5(md5)

    elif sha256:
        demisto.debug(f"Calling files_view_by_sha256 for SHA256: {sha256}.")
        resp = client.files_view_by_sha256(sha256)

    demisto.debug(f"File view retrieved for {lookup_id}. Formatting results.")

    data = resp.get("data", resp)
    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} File View",
        data if isinstance(data, dict) else [data],
        headers=[
            "id",
            "file_type",
            "md5",
            "crc32",
            "sha256",
            "sha512",
            "Parent",
            "source_url",
        ],
        headerTransform=string_to_table_header,
    )

    demisto.debug(f"Command '{command}' execution finished successfully.")
    return CommandResults(
        outputs_prefix="Cape.File",
        outputs=data,
        readable_output=readable,
        outputs_key_field="id",
    )


def cape_pcap_file_download_command(client: CapeSandboxClient, args: dict[str, Any]) -> Any:
    """Download the PCAP dump of a Task by ID. Return object will be application/vnd.tcpdump.pcap. (.pcap)."""
    command = "Download PCAP File"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = args["task_id"]

    dump_pcap = client.get_task_pcap(task_id)

    filename = build_file_name(
        file_identifier=task_id,
        file_type="network_dump",
        file_format="pcap",
    )

    demisto.debug(f"Command '{command}' execution finished successfully (Returning file: {filename}).")
    return fileResult(filename, dump_pcap)


def cape_sample_file_download_command(client: CapeSandboxClient, args: dict[str, Any]) -> Any:
    """Download a sample from a Task by one of: `task_id`, `md5`, `sha1` or `sha256`."""
    command = "Download Sample File"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = arg_to_number(args.get("task_id"))
    md5 = args.get("md5")
    sha1 = args.get("sha1")
    sha256 = args.get("sha256")

    if not any([task_id, md5, sha1, sha256]):
        raise DemistoException("Provide one of: task_id, md5, sha1, sha256")

    if sum(bool(x) for x in [task_id, md5, sha1, sha256]) > 1:
        raise DemistoException("Provide only one of task_id, md5, sha1 ,sha256")

    resp: bytes | dict[str, Any] = b""
    filename_base = ""

    if task_id:
        resp = client.files_get_by_task(task_id)
        filename_base = str(task_id)

    elif md5:
        resp = client.files_get_by_md5(md5)
        filename_base = "md5"

    elif sha1:
        resp = client.files_get_by_sha1(sha1)
        filename_base = "sha1"

    elif sha256:
        resp = client.files_get_by_sha256(sha256)
        filename_base = "sha256"

    filename = build_file_name(
        file_identifier=filename_base,
        file_type="file",
        file_format="bin",
    )

    demisto.debug(f"Command '{command}' execution finished successfully (Returning file: {filename}).")

    return fileResult(filename, resp)


def cape_task_delete_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """Delete task by id."""
    command = "Delete Task"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = args["task_id"]
    demisto.debug(f"Starting task delete command for Task ID: {task_id}.")

    demisto.debug(f"Sending delete request to API for Task ID: {task_id}.")
    client.delete_task(task_id)
    demisto.debug(f"API confirmed deletion of Task ID: {task_id}.")

    readable = f"Task id={task_id} was deleted successfully"

    demisto.debug(f"Command '{command}' execution finished successfully.")
    return CommandResults(readable_output=readable)


# ---------- Management ----------
def cape_tasks_list_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """List tasks with pagination or fetch a single task by `task_id`."""
    command = "List Tasks"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = arg_to_number(args.get("task_id"))

    # Get page_size/limit and cap at default limit
    requested_limit = arg_to_number(args.get("page_size") or args.get("limit")) or LIST_DEFAULT_LIMIT
    api_limit = min(requested_limit, LIST_DEFAULT_LIMIT)

    # Normalize page to at least 1
    page = max(arg_to_number(args.get("page")) or 1, 1)
    offset = (page - 1) * api_limit

    DATA_KEYS = [
        "id",
        "category",
        "machine",
        "target",
        "package",
        "platform",
        "options",
        "status",
        "timeout",
        "memory",
        "tags",
        "added_on",
        "completed_on",
    ]

    if task_id:
        # --- Single Task View ---
        task = client.get_task_view(task_id)
        data = task.get("data") or task
        readable = tableToMarkdown(
            f"{INTEGRATION_NAME} Task {task_id}",
            data if isinstance(data, dict) else [data],
            headers=DATA_KEYS,
            headerTransform=string_to_table_header,
        )

        demisto.debug(f"Command '{command}' execution finished successfully (Single Task View).")
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Cape.Task",
            outputs_key_field="id",
            outputs=data,
        )

    # --- List View ---
    resp = client.list_tasks(limit=api_limit, offset=offset)
    data = resp.get("data", resp)
    items = data if isinstance(data, list) else [data]

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Tasks (page={page}, page_size={api_limit})",
        items,
        headers=DATA_KEYS,
        headerTransform=string_to_table_header,
    )

    demisto.debug(f"Command '{command}' execution finished successfully (List View).")
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task",
        outputs_key_field="id",
        outputs=items,
    )


def cape_task_report_get_command(client: CapeSandboxClient, args: dict[str, Any]) -> Any:
    """
    Get a task report. When 'zip=true', returns a ZIP file. Otherwise returns the JSON 'info' object.
    """
    command = "Get Task Report"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = args["task_id"]
    file_format = args.get("format", "json").strip().lower()
    zip_flag = argToBoolean(args.get("zip", False))

    if zip_flag:
        content = client.get_task_report(task_id=task_id, format=file_format, zip_download=True)
        filename = build_file_name(file_identifier=task_id, file_type="report", file_format="zip")

        demisto.debug(f"Command '{command}' execution finished successfully (Returning ZIP file).")
        return fileResult(filename, content)

    resp = client.get_task_report(task_id=task_id, format=file_format, zip_download=False)

    info = (resp or {}).get("info") or {}

    if not info:
        if resp and isinstance(resp, dict) and resp.get("message"):
            raise DemistoException(f"Failed to retrieve report for task {task_id}: {resp['message']}")

        raise DemistoException(f"No info object found in report for task {task_id}")

    target_file = (resp or {}).get("target", {}).get("file", {})

    hr_data = info

    if target_file:
        hr_data["file_name"] = target_file.get("name")
        hr_data["file_path"] = target_file.get("path")
        hr_data["file_size"] = target_file.get("size")
        hr_data["crc32"] = target_file.get("crc32")
        hr_data["sha1"] = target_file.get("sha1")
        hr_data["sha256"] = target_file.get("sha256")
        hr_data["ssdeep"] = target_file.get("ssdeep")
        hr_data["file_type"] = target_file.get("type")

    headers = [
        "id",
        "started",
        "ended",
        "category",
        "machine",
        "package",
        "tlp",
        "options",
        "source_url",
        "route",
        "user_id",
        "file_name",
        "file_path",
        "file_size",
        "crc32",
        "sha1",
        "sha256",
        "ssdeep",
        "file_type",
    ]

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Task Report {task_id} ({file_format.upper()})",
        hr_data,
        headers=headers,
        headerTransform=string_to_table_header,
    )

    demisto.debug(f"Command '{command}' execution finished successfully (Returning JSON report).")
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task.Report",
        outputs_key_field="id",
        outputs=info,
    )


def cape_machines_list_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """List machines or view a single machine by `machine_name`."""
    command = "List Machines"
    demisto.debug(f"Starting execution of command: {command}")

    machine_name = args.get("machine_name")
    all_results = arg_to_bool_or_none(args.get("all_results"))
    limit = arg_to_number(args.get("limit", LIST_DEFAULT_LIMIT))
    demisto.debug(f"Starting machines list command. Target machine: {machine_name or 'All'}")

    if machine_name:
        demisto.debug(f"Fetching view for specific machine: {machine_name=}.")
        resp = client.view_machine(machine_name)
        machine = resp.get("machine", resp.get("data", resp))

        readable = tableToMarkdown(
            f"{INTEGRATION_NAME} Machine {machine.get('name', machine_name)}",
            machine,
            headers=[
                "id",
                "status",
                "name",
                "arch",
                "resultserver_ip",
                "resultserver_port",
                "ip",
                "label",
                "locked_changed_on",
                "locked",
                "platform",
                "snapshot",
                "interface",
                "status_changed_on",
                "tags",
            ],
            headerTransform=string_to_table_header,
        )

        demisto.debug(f"Command '{command}' execution finished successfully (Single Machine View).")
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Cape.Machine",
            outputs_key_field="id",
            outputs=machine,
        )

    demisto.debug("Fetching list of all available machines.")
    resp = client.list_machines()
    machines = resp.get("machines", resp.get("data", resp))

    if isinstance(machines, dict):
        machines = [machines]

    if not all_results:
        machines = machines[:limit]

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Machines (count={len(machines)})",
        machines,
        headers=[
            "id",  # Id -> Task Id
            "status",
            "name",
            "arch",
            "resultserver_ip",
            "resultserver_port",
            "ip",
            "label",
            "locked_changed_on",
            "locked",
            "platform",
            "snapshot",
            "interface",
            "status_changed_on",
            "tags",
        ],
        headerTransform=string_to_table_header,
    )

    demisto.debug(f"Command '{command}' execution finished successfully (List View). Found {len(machines)} total machines.")
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Machine",
        outputs_key_field="id",
        outputs=machines,
    )


def cape_cuckoo_status_get_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """Return overall CAPE/Cuckoo status as human-readable only."""
    command = "Get Cuckoo Status"
    demisto.debug(f"Starting execution of command: {command}")

    demisto.debug("Sending request to get Cuckoo/CAPE server status.")
    resp = client.get_cuckoo_status() or {}
    data = resp.get("data", resp)

    if not isinstance(data, dict) or not data.get("tasks"):
        demisto.debug(f"Status response incomplete or unexpected. Keys received: {list(data.keys())}")

    hostname = data.get("hostname", "N/A")
    demisto.debug(f"Status retrieved. Hostname: {hostname}. Processing results.")

    tasks = data.get("tasks") or {}
    server = data.get("server") or {}
    machines = data.get("machines") or {}

    row = {
        "Version": data.get("version"),
        "Hostname": hostname,
        "Tasks Reported": tasks.get("reported"),
        "Tasks Running": tasks.get("running"),
        "Tasks Completed": tasks.get("completed"),
        "Tasks Pending": tasks.get("pending"),
        "Server Usage": server.get("storage", {}).get("used_by"),
        "Machines Available": machines.get("available"),
        "Machines Total": machines.get("total"),
        "Tools": data.get("tools"),
    }

    readable = tableToMarkdown(f"{INTEGRATION_NAME} Status", row, headerTransform=string_to_table_header)

    demisto.debug(f"Command '{command}' execution finished successfully.")
    return CommandResults(readable_output=readable)


def cape_task_screenshot_download_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """Download screenshots for a task."""
    command = "List Task Screenshots"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = args["task_id"]
    single_number = arg_to_number(args.get("screenshot"))

    if not task_id:
        raise DemistoException("Task ID is missing for download screenshot.")

    if single_number:
        candidates_raw = [single_number]

    else:
        # about to call with taskif
        meta = client.list_task_screenshots(task_id)

        candidates_raw = meta.get("screenshots") or meta.get("data") or meta

        if not isinstance(candidates_raw, list):
            candidates_raw = []

    file_entries = []
    candidate_numbers = []

    for item in candidates_raw:
        current_number: int | None = None
        if isinstance(item, dict):
            current_number = arg_to_number(item.get("number"))
        elif isinstance(item, int):
            current_number = item
        if current_number is not None:
            candidate_numbers.append(current_number)

    if not candidate_numbers and not single_number:  # TODO
        candidate_numbers.extend(range(1, 6))

    processed_numbers = set()

    for number in candidate_numbers:
        if number in processed_numbers:
            continue

        try:
            content = client.get_task_screenshot(task_id=task_id, number=number)
            filename = build_file_name(task_id, "screenshot", number)

            file_meta = fileResult(filename, content)

            file_meta["TaskID"] = task_id
            file_meta["ScreenshotNumber"] = number
            file_entries.append(file_meta)

            processed_numbers.add(number)

        except DemistoException as error:
            demisto.debug(f"Failed to fetch screenshot {number} for task {task_id}: {error}")

        # except Exception as error:
        #     demisto.debug(
        #         f"Unexpected error while processing screenshot {number}: {error}"
        #     )

    if not file_entries:
        raise DemistoException(f"No screenshots found for task {task_id}")

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Screenshots for Task {task_id}",
        file_entries,
        headers=["TaskID", "ScreenshotNumber", "Name", "Size", "SHA1", "MD5"],
        headerTransform=string_to_table_header,
    )

    demisto.debug(f"Command '{command}' execution finished successfully.")
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task.Screenshot",
        outputs_key_field="ScreenshotNumber",
        outputs=file_entries,
    )


# endregion
# region Main router
# =================================
# Main router
# =================================
def main() -> None:
    demisto.debug("--- CapeSandbox Integration START ---")

    params: dict[str, Any] = demisto.params()
    args = demisto.args()

    command = demisto.command()
    demisto.debug(f"Received command: {command}")

    try:
        config = parse_integration_params(params)

        base_url = config["base_url"]
        verify_certificate = config["verify_certificate"]
        proxy = config["proxy"]
        api_token = config["api_token"]
        username = config["username"]
        password = config["password"]
        client = CapeSandboxClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_token=api_token,
            username=username,
            password=password,
        )

        demisto.debug(f"Starting execution of command: {command}...")

        command_map = {
            "test-module": lambda: test_module(client),
            "cape-file-submit": lambda: cape_file_submit_command(client, args),
            "cape-file-view": lambda: cape_file_view_command(client, args),
            "cape-sample-download": lambda: cape_sample_file_download_command(client, args),
            "cape-url-submit": lambda: cape_url_submit_command(client, args),
            "cape-tasks-list": lambda: cape_tasks_list_command(client, args),
            "cape-task-delete": lambda: cape_task_delete_command(client, args),
            "cape-task-screenshot-download": lambda: cape_task_screenshot_download_command(client, args),
            "cape-task-report-get": lambda: cape_task_report_get_command(client, args),
            "cape-pcap-file-download": lambda: cape_pcap_file_download_command(client, args),
            "cape-machines-list": lambda: cape_machines_list_command(client, args),
            "cape-cuckoo-status-get": lambda: cape_cuckoo_status_get_command(client, args),
            "cape-task-poll": lambda: cape_task_poll_report(args, client),
        }

        if command not in command_map:
            raise NotImplementedError(f"Command {command} is not implemented")

        result = command_map[command]()
        return_results(result)

        demisto.debug(f"Command '{command}' execution finished successfully.")

    except Exception as error:
        return_error(
            f"Failed to execute {command} command. Error: {str(error)}",
            error=str(error),
            outputs=traceback.format_exc(),
        )

    finally:
        demisto.debug("--- CapeSandbox Integration END ---")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
