import json
import os
import re
import time
from dataclasses import dataclass
from enum import StrEnum
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
MAX_RETRY_ATTEMPTS = 3
RETRY_BASE_DELAY = 5


@dataclass(frozen=True)
class FileTypeInfo:
    """File type metadata for building standardized filenames."""

    ext: str
    part: str


# File type configurations
FILE_TYPE_SCREENSHOT = FileTypeInfo(ext="png", part="screenshot")
FILE_TYPE_REPORT = FileTypeInfo(ext="json", part="report")
FILE_TYPE_FILE = FileTypeInfo(ext="json", part="file")
FILE_TYPE_NETWORK_DUMP = FileTypeInfo(ext="pcap", part="network_dump")


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Normalize and extract integration configuration from demisto.params()."""
    demisto.debug("Parsing integration parameters.")

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

    demisto.debug(
        f"Parsed config: {base_url=}, {verify_certificate=}, "
        f"{proxy=}, has_api_token={bool(api_token)}, has_username={bool(username)}"
    )

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
    demisto.debug(f"Building submit form with {url_mode=}")
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
    demisto.debug(f"Built form with {len(form)} parameters: {list(form.keys())}")
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
        raise DemistoException(f"Could not find file or entry: {entry_id!r}", error)

    except Exception as error:
        raise DemistoException(f"An unexpected error occurred while processing entry {entry_id!r}", error)

    path = filepath_result["path"]
    name = filepath_result.get("name")

    final_name = name or os.path.basename(path)

    return path, final_name


def build_file_name(
    file_identifier: str | int,
    file_type_info: FileTypeInfo | None = None,
    screenshot_number: int | None = None,
    file_format: (Literal["pdf", "html", "csv", "zip", "pcap", "bin"] | str | None) = None,
) -> str:
    """
    Constructs a standardized filename based on the task identifier and file metadata.

    Args:
        file_identifier: Task ID or other identifier for the file
        file_type_info: FileTypeInfo instance containing extension and part information
        screenshot_number: Optional screenshot number for screenshot files
        file_format: Optional format override for the file extension

    Returns:
        Standardized filename string
    """

    extension = "dat"
    middle_part_base = None

    # Get defaults from FileTypeInfo if provided
    if file_type_info:
        extension = file_type_info.ext
        middle_part_base = file_type_info.part

    # Apply overrides based on other args
    if file_format:
        extension = str(file_format)

    # Special handling for screenshot number always overrides
    if file_type_info is FILE_TYPE_SCREENSHOT and screenshot_number is not None:
        middle_part_base = f"screenshot_{screenshot_number}"
        extension = "png"  # Ensure it's always png

    # Construct the final filename
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


# Hash validators (using CommonServerPython regex patterns)
def is_valid_md5(value: str | None) -> bool:
    return bool(value and md5Regex.fullmatch(value))


def is_valid_sha1(value: str | None) -> bool:
    return bool(value and sha1Regex.fullmatch(value))


def is_valid_sha256(value: str | None) -> bool:
    return bool(value and sha256Regex.fullmatch(value))


# endregion
# region Client (API)
# =================================
# Client (API paths and methods)
# =================================


class ApiPrefix(StrEnum):
    """Base versioning prefixes for the API."""

    V2 = "apiv2"


class Resource(StrEnum):
    """Core resource names."""

    API_TOKEN_AUTH = "api-token-auth"
    FILES = "files"
    TASKS = "tasks"
    MACHINES = "machines"


class Action(StrEnum):
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


class ResponseTypes(StrEnum):
    JSON = "json"
    CONTENT = "content"


class AuthParams(StrEnum):
    TOKEN_KEY = "token"
    VALID_UNTIL_KEY = "valid_until"
    CACHE_KEY = "auth_info"


TOKEN_TTL_SECONDS = 60 * 60 * 24 * 1
FILES_STREAM_HEADERS = {"Content-Type": "application/octet-stream"}


# ---------- API Path Templates ----------
BASE_PREFIX = f"{ApiPrefix.V2}"

# Resource base paths for convenience
TASKS_BASE = f"{BASE_PREFIX}/{Resource.TASKS}"
FILES_BASE = f"{BASE_PREFIX}/{Resource.FILES}"
MACHINES_BASE = f"{BASE_PREFIX}/{Resource.MACHINES}"

# -- Authentication --
API_AUTH = f"{BASE_PREFIX}/{Resource.API_TOKEN_AUTH}/"

# -- Tasks --
TASK_CREATE_FILE = f"{TASKS_BASE}/{Action.CREATE}/{Action.FILE}/"
TASK_CREATE_URL = f"{TASKS_BASE}/{Action.CREATE}/{Action.URL}/"
TASK_STATUS = f"{TASKS_BASE}/{Action.STATUS}/{{task_id}}/"
TASK_VIEW = f"{TASKS_BASE}/{Action.VIEW}/{{task_id}}/"
TASK_LIST = f"{TASKS_BASE}/list/{{limit}}/{{offset}}/"
TASK_DELETE = f"{TASKS_BASE}/{Action.DELETE}/{{task_id}}/"
TASK_GET_REPORT_BASE = f"{TASKS_BASE}/{Action.GET}/report/{{task_id}}/"
TASK_GET_PCAP = f"{TASKS_BASE}/{Action.GET}/{Action.PCAP}/{{task_id}}/"
CUCKOO_STATUS_URL = f"{BASE_PREFIX}/cuckoo/{Action.STATUS}/"
TASK_SCREENSHOTS_LIST = f"{TASKS_BASE}/{Action.GET}/screenshot/{{task_id}}/"
TASK_SCREENSHOT_GET = f"{TASKS_BASE}/{Action.GET}/screenshot/{{task_id}}/{{number}}/"

# -- Files --
FILE_VIEW_BY_TASK = f"{FILES_BASE}/{Action.VIEW}/{Action.ID}/{{task_id}}/"
FILE_VIEW_BY_MD5 = f"{FILES_BASE}/{Action.VIEW}/{Action.MD5}/{{md5}}/"
FILE_VIEW_BY_SHA256 = f"{FILES_BASE}/{Action.VIEW}/{Action.SHA256}/{{sha256}}/"
FILES_GET_BY_TASK = f"{FILES_BASE}/{Action.GET}/task/{{task_id}}"
FILES_GET_BY_MD5 = f"{FILES_BASE}/{Action.GET}/{Action.MD5}/{{md5}}"
FILES_GET_BY_SHA1 = f"{FILES_BASE}/{Action.GET}/{Action.SHA1}/{{sha1}}"
FILES_GET_BY_SHA256 = f"{FILES_BASE}/{Action.GET}/{Action.SHA256}/{{sha256}}"

# -- Machines --
MACHINES_LIST = f"{MACHINES_BASE}/list/"
MACHINE_VIEW = f"{MACHINES_BASE}/{Action.VIEW}/{{name}}"


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
        self.api_token = api_token.strip() if api_token else None
        self.username = username.strip() if username else None
        self.password = password.strip() if password else None

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
        cached_auth_info = integration_context.get(AuthParams.CACHE_KEY)

        if not cached_auth_info or not isinstance(cached_auth_info, dict):
            demisto.debug("Auth cache is empty or corrupt.")
            return None

        cached_token = cached_auth_info.get(AuthParams.TOKEN_KEY)
        valid_until_str = cached_auth_info.get(AuthParams.VALID_UNTIL_KEY)

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

    def _check_for_api_error(self, response: dict[str, Any] | bytes, url_suffix: str, resp_type: str) -> None:
        """
        Checks the CAPE response for the specific error field: 'error': True.
        Handles both JSON dict responses and binary content responses that might be JSON errors.
        If an error is detected, logs the failure and raises a DemistoException.
        """
        # If response type is content (bytes), try to parse as JSON to check for errors
        if resp_type == ResponseTypes.CONTENT and isinstance(response, bytes):
            try:
                response = json.loads(response.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                # Not JSON or not decodable, treat as valid binary content
                return

        # Check for error in dict response
        if isinstance(response, dict) and response.get("error") is True:
            fail_message = (
                response.get("error_value") or response.get("failed") or response.get("message") or "Unknown API error occurred."
            )

            demisto.debug(
                f"CAPE API call for {url_suffix} failed with explicit error flag",
                {"url": url_suffix, "message": fail_message, "response": response},
            )

            raise DemistoException(f"CapeSandbox API call failed with error: {fail_message}")

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

        new_valid_until = time_now + TOKEN_TTL_SECONDS

        new_auth_info = {
            AuthParams.TOKEN_KEY: token,
            AuthParams.VALID_UNTIL_KEY: str(new_valid_until),
        }

        integration_context = get_integration_context() or {}  # Re-fetch context to avoid race condition or stale data
        integration_context[AuthParams.CACHE_KEY] = new_auth_info
        set_integration_context(integration_context)

        demisto.debug(f"Successfully **regenerated and cached** a new token. It is valid until {time.ctime(new_valid_until)}.")

        return token

    def _handle_429_error(
        self,
        error: DemistoException,
        attempt: int,
        method: str,
        endpoint: str,
    ) -> bool:
        """
        Handle 429 (rate limit) errors with retry logic.

        Args:
            error: The DemistoException that was raised
            attempt: Current attempt number (0-based)
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (url_suffix or full_url)

        Returns:
            bool: True if should retry, False if should raise the error
        """
        error_msg = str(error)

        # Check if this is a 429 rate limit error
        if "[429]" not in error_msg and "Too Many Requests" not in error_msg:
            # Not a rate limit error, don't retry
            demisto.debug(f"Non-429 error encountered: {type(error).__name__}")
            return False

        # It's a 429 error
        if attempt < MAX_RETRY_ATTEMPTS - 1:
            # We can retry
            wait_time = self._extract_retry_wait_time(error_msg)

            demisto.info(
                f"Rate limit (429) encountered for {method} {endpoint}. "
                f"Attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS} failed. "
                f"Retrying after {wait_time} seconds."
            )

            time.sleep(wait_time)  # pylint: disable=E9003
            return True
        else:
            # Max retries exceeded
            demisto.error(
                f"Rate limit (429) - Max retries ({MAX_RETRY_ATTEMPTS}) exceeded " f"for {method} {endpoint}. Giving up."
            )
            return False

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        resp_type: str = ResponseTypes.JSON,
    ) -> Any:
        """
        Execute HTTP request with automatic retry on 429 (rate limit) errors.

        Implements retry logic for rate limiting with smart wait time extraction.

        Args:
            method: HTTP method (GET, POST, etc.)
            url_suffix: API endpoint path (relative to base_url)
            headers: Optional additional headers to merge with auth headers
            data: Optional form data for POST requests
            files: Optional files for multipart uploads
            resp_type: Response type - 'json' or 'content' (binary)

        Returns:
            Response data (dict for JSON, bytes for content)
        """
        # Prepare headers with authentication
        merged_headers = self._auth_headers()
        if headers:
            merged_headers.update(headers)

        endpoint = url_suffix

        # Retry loop for 429 errors
        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                demisto.debug(f"API request attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}: " f"{method} {endpoint}")

                response = self._http_request(
                    method=method,
                    headers=merged_headers,
                    url_suffix=url_suffix,
                    data=data,
                    files=files,
                    resp_type=resp_type,
                    ok_codes=(200, 201, 202, 204),
                )

                demisto.debug(f"API request successful on attempt {attempt + 1}: " f"{method} {endpoint}")

                self._check_for_api_error(response, url_suffix, resp_type)

                return response

            except DemistoException as error:
                # Check if we should retry (429 error) or raise immediately
                should_retry = self._handle_429_error(error, attempt, method, endpoint)

                if should_retry:
                    continue
                else:
                    raise

        # This should never be reached, but just in case
        raise DemistoException(f"Failed to complete request to {endpoint} " f"after {MAX_RETRY_ATTEMPTS} attempts")

    def _extract_retry_wait_time(self, error_message: str) -> int:
        """
        Extract the wait time from a 429 error message.

        Expected format: 'Expected available in 35 seconds.'

        Args:
            error_message: The error message containing wait time information

        Returns:
            int: Number of seconds to wait (defaults to base delay if not found)
        """
        try:
            # Try to parse JSON from error message
            if '{"detail":' in error_message or "{'detail':" in error_message:
                # Extract JSON portion
                json_start = error_message.find("{")
                json_end = error_message.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = error_message[json_start:json_end]
                    # Handle single quotes
                    json_str = json_str.replace("'", '"')
                    error_data = json.loads(json_str)
                    detail = error_data.get("detail", "")

                    # Extract seconds from detail message
                    # Format: "Request was throttled. Expected available in 35 seconds."
                    match = re.search(r"(\d+)\s+seconds?", detail)
                    if match:
                        wait_seconds = int(match.group(1))
                        demisto.debug(f"Extracted wait time from API response: {wait_seconds} seconds")
                        return wait_seconds
        except Exception as parse_error:
            demisto.debug(f"Could not parse wait time from error message: {parse_error}")

        # Default to base delay if we can't extract the wait time
        demisto.debug(f"Using default retry delay: {RETRY_BASE_DELAY} seconds")
        return RETRY_BASE_DELAY

    # ---------- Submit ----------
    def submit_file(self, form: dict[str, Any], file_path: str, is_pcap: bool) -> dict[str, Any]:
        """Create a task by uploading a file."""
        demisto.debug(f"Submitting file: {file_path=}, {is_pcap=}")

        data = form.copy()
        if is_pcap:
            data["pcap"] = "1"
            demisto.debug("Added pcap flag to submission data")

        basename = Path(file_path).name
        demisto.debug(f"File basename: {basename}")

        with open(file_path, "rb") as f:
            files = {"file": (basename, f)}
            demisto.debug(f"Sending file upload request with {len(data)} data parameters")
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
            return self.http_request("GET", url_suffix=suffix, resp_type=ResponseTypes.CONTENT)

        return self.http_request("GET", url_suffix=suffix)

    def get_task_pcap(self, task_id: int | str, format: str | None = None, zip_download: bool = False) -> Any:
        """Download the PCAP dump of a Task by ID. Return object will be application/vnd.tcpdump.pcap. (.pcap)"""
        return self.http_request(
            "GET",
            url_suffix=TASK_GET_PCAP.format(task_id=task_id),
            resp_type=ResponseTypes.CONTENT,
        )

    def list_task_screenshots(self, task_id: int | str) -> Any:
        """Return list/metadata of screenshots for a task (JSON)."""
        return self.http_request(
            "GET",
            url_suffix=TASK_SCREENSHOTS_LIST.format(task_id=task_id),
            resp_type=ResponseTypes.CONTENT,
        )

    def get_task_screenshot(self, task_id: int | str, number: int | str) -> bytes:
        """Return a specific screenshot content (binary)."""
        return self.http_request(
            "GET",
            url_suffix=TASK_SCREENSHOT_GET.format(task_id=task_id, number=number),
            resp_type=ResponseTypes.CONTENT,
        )

    def download_all_screenshots_zip(self, task_id: int | str) -> bytes:
        """Return all screenshots as a single ZIP file (binary)."""
        return self.http_request(
            "GET",
            url_suffix=TASK_SCREENSHOTS_LIST.format(task_id=task_id),
            resp_type=ResponseTypes.CONTENT,
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
            headers=FILES_STREAM_HEADERS,
            resp_type=ResponseTypes.CONTENT,
        )

    def files_get_by_md5(self, md5: str) -> dict[str, Any]:
        """Return file details by MD5."""
        if not is_valid_md5(md5):
            raise DemistoException("Invalid MD5 hash format.")
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_MD5.format(md5=md5),
            headers=FILES_STREAM_HEADERS,
            resp_type=ResponseTypes.CONTENT,
        )

    def files_get_by_sha1(self, sha1: str) -> dict[str, Any]:
        """Return file details by SHA1."""
        if not is_valid_sha1(sha1):
            raise DemistoException("Invalid SHA1 hash format.")
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_SHA1.format(sha1=sha1),
            headers=FILES_STREAM_HEADERS,
            resp_type=ResponseTypes.CONTENT,
        )

    def files_get_by_sha256(self, sha256: str) -> dict[str, Any]:
        """Return file details by SHA256."""
        if not is_valid_sha256(sha256):
            raise DemistoException("Invalid SHA256 hash format.")
        return self.http_request(
            "GET",
            url_suffix=FILES_GET_BY_SHA256.format(sha256=sha256),
            headers=FILES_STREAM_HEADERS,
            resp_type=ResponseTypes.CONTENT,
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
    3. Final Report: If 'reported', calls a helper to fetch the detailed task view and report.
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
        demisto.debug(f"Raw status response: {resp}")

        status = resp.get("data", "")
        demisto.debug(f"The status for Task ID {task_id} is '{status}'.")

    except Exception as error:
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
        final_output_prefix = args.get("outputs_prefix", "Cape.Task")

        # Call the new helper to do all the work
        final_results_list = _handle_reported_task(client, task_id, final_output_prefix)

        # --- Result Compilation ---
        final_readable = f"Polling finished successfully for Task {task_id}. Results returned."
        demisto.debug(final_readable)

        return PollResult(
            response=final_results_list,  # Pass the list from the helper
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


def _handle_reported_task(client: CapeSandboxClient, task_id: str, final_output_prefix: str) -> list[Any]:
    """
    Fetches, formats, and returns the final task view and report file
    once a task's status is 'reported'.
    """
    demisto.debug(f"Fetching final task view for task_id: {task_id}")
    task_view = client.get_task_view(task_id)
    demisto.debug(f"Task view data keys: {list(task_view.keys()) if isinstance(task_view, dict) else 'N/A'}")

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

    final_results = CommandResults(
        readable_output=readable,
        outputs_prefix=final_output_prefix,
        outputs_key_field="id",
        outputs=task_view.get("data") or task_view,
    )

    # Fetch the JSON report file content
    demisto.debug(f"Fetching ZIP report for task_id: {task_id}")
    report_file_content = client.get_task_report(task_id=task_id, format="json", zip_download=True)
    demisto.debug(f"Report ZIP size: {len(report_file_content)} bytes")

    filename = build_file_name(file_identifier=task_id, file_type_info=FILE_TYPE_REPORT, file_format="zip")
    demisto.debug(f"Generated report filename: {filename}")
    file_result = fileResult(filename, report_file_content)

    # Return a list of all results to be passed to PollResult
    return [file_result, final_results]


def cape_file_submit_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """
    Submits a file (or PCAP) to CAPE, retrieves the task_id, and initiates the polling sequence.
    """
    command = "Submit File"
    demisto.debug(f"Starting execution of command: {command}")

    entry_id = args["entry_id"]

    try:
        file_path, filename = extract_entry_file_data(entry_id)
        demisto.debug(f"Resolved entry_id '{entry_id}' to file: {filename} at path: {file_path}")
    except Exception as error:
        demisto.debug(f"Failed to resolve entry_id '{entry_id}': {error}")
        raise DemistoException(f"Failed to resolve entry_id '{entry_id}' to a local file path: {error}")

    is_pcap = filename.lower().endswith(".pcap")
    demisto.debug(f"File type detection: is_pcap={is_pcap}, filename={filename}")

    # Execute the submission API call
    form = build_submit_form(args)
    demisto.debug(f"Submitting file with form containing {len(form)} parameters")

    submit_resp = client.submit_file(form=form, file_path=file_path, is_pcap=is_pcap)
    demisto.debug(f"Received submission response: {submit_resp}")

    task_ids = ((submit_resp or {}).get("data", {})).get("task_ids", [])

    if not task_ids:
        demisto.debug(f"No task IDs found in response: {submit_resp}")
        raise DemistoException(f"No task id returned from CAPE. Response: {submit_resp}")

    demisto.debug(f"Successfully submitted file. Task IDs: {task_ids}")
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

    url = args["url"]

    demisto.debug(f"Submitting URL: {url}")
    form = build_submit_form(args, url_mode=True)
    demisto.debug(f"Submitting URL with form containing {len(form)} parameters")

    submit_resp = client.submit_url(form=form)
    demisto.debug(f"Received submission response: {submit_resp}")

    task_ids = ((submit_resp or {}).get("data", {})).get("task_ids", [])

    if not task_ids:
        demisto.debug(f"No task IDs found in response: {submit_resp}")
        raise DemistoException(f"No task id returned from CAPE. Response: {submit_resp}.")

    demisto.debug(f"Successfully submitted URL. Task IDs: {task_ids}")
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
    demisto.debug(f"Parsed identifiers: {task_id=}, {md5=}, {sha256=}, {lookup_id=}")

    if not lookup_id:
        raise DemistoException("Provide one of: task_id, md5, sha256")

    if sum(bool(x) for x in [task_id, md5, sha256]) > 1:
        raise DemistoException("Provide only one of task_id, md5, sha256")

    resp: dict[str, Any] = {}

    if task_id:
        demisto.debug(f"Calling files_view_by_task for task ID: {task_id}.")
        resp = client.files_view_by_task(task_id)
        demisto.debug(f"Received response for task_id {task_id}: {resp}")

    elif md5:
        demisto.debug(f"Calling files_view_by_md5 for MD5: {md5}.")
        resp = client.files_view_by_md5(md5)
        demisto.debug(f"Received response for MD5 {md5}: {resp}")

    elif sha256:
        demisto.debug(f"Calling files_view_by_sha256 for SHA256: {sha256}.")
        resp = client.files_view_by_sha256(sha256)
        demisto.debug(f"Received response for SHA256 {sha256}: {resp}")

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
    demisto.debug(f"Downloading PCAP for task_id: {task_id}")

    dump_pcap = client.get_task_pcap(task_id)
    demisto.debug(f"Successfully retrieved PCAP data. Size: {len(dump_pcap)} bytes")

    filename = build_file_name(
        file_identifier=task_id,
        file_type_info=FILE_TYPE_NETWORK_DUMP,
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

    demisto.debug(f"Parsed identifiers: {task_id=}, {md5=}, {sha1=}, {sha256=}")

    if not any([task_id, md5, sha1, sha256]):
        raise DemistoException("Provide one of: task_id, md5, sha1, sha256")

    if sum(bool(x) for x in [task_id, md5, sha1, sha256]) > 1:
        raise DemistoException("Provide only one of task_id, md5, sha1 ,sha256")

    resp: bytes | dict[str, Any] = b""
    filename_base = ""

    if task_id:
        demisto.debug(f"Downloading sample by task_id: {task_id}")
        resp = client.files_get_by_task(task_id)
        filename_base = str(task_id)

    elif md5:
        demisto.debug(f"Downloading sample by MD5: {md5}")
        resp = client.files_get_by_md5(md5)
        filename_base = "md5"

    elif sha1:
        demisto.debug(f"Downloading sample by SHA1: {sha1}")
        resp = client.files_get_by_sha1(sha1)
        filename_base = "sha1"

    elif sha256:
        demisto.debug(f"Downloading sample by SHA256: {sha256}")
        resp = client.files_get_by_sha256(sha256)
        filename_base = "sha256"

    demisto.debug(f"Successfully retrieved sample file. Size: {len(resp) if isinstance(resp, bytes) else 'N/A'} bytes")

    filename = build_file_name(
        file_identifier=filename_base,
        file_type_info=FILE_TYPE_FILE,
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

    readable = f"Task ID: {task_id} was deleted successfully"

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

    demisto.debug(f"Pagination parameters: {task_id=}, {requested_limit=}, " f"{api_limit=}, {page=}, {offset=}")

    DATA_KEYS = [
        "id",
        "target",
        "status",
        "added_on",
        "completed_on",
        "category",
        "timeout",
        "tags",
        "machine",
        "package",
        "platform",
        "options",
        "memory",
    ]

    if task_id:
        # --- Single Task View ---
        demisto.debug(f"Fetching single task view for task_id: {task_id}")
        task = client.get_task_view(task_id)
        demisto.debug(f"Received task view response: {task}")
        data = task.get("data") or task
        readable = tableToMarkdown(
            f"{INTEGRATION_NAME} Task {task_id}",
            [data],
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
    demisto.debug(f"Fetching task list with limit={api_limit}, offset={offset}")
    resp = client.list_tasks(limit=api_limit, offset=offset)
    demisto.debug(f"Raw list response keys: {list(resp.keys()) if isinstance(resp, dict) else 'N/A'}")

    data = resp.get("data", resp)

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        demisto.debug("API returned a single dict, wrapping in a list.")
        items = [data]
    else:
        demisto.debug(f"Unexpected data type from API: {type(data)}. Using empty list.")
        items = []

    demisto.debug(f"Received task list with {len(items)} items")

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

    demisto.debug(f"Report parameters: {task_id=}, {file_format=}, {zip_flag=}")

    if zip_flag:
        demisto.debug(f"Downloading ZIP report for task_id: {task_id}")
        content = client.get_task_report(task_id=task_id, format=file_format, zip_download=True)
        demisto.debug(f"Successfully retrieved ZIP report. Size: {len(content)} bytes")
        filename = build_file_name(file_identifier=task_id, file_type_info=FILE_TYPE_REPORT, file_format="zip")

        demisto.debug(f"Command '{command}' execution finished successfully (Returning ZIP file).")
        return fileResult(filename, content)

    demisto.debug(f"Fetching JSON report for task_id: {task_id}")
    resp = client.get_task_report(task_id=task_id, format=file_format, zip_download=False)
    demisto.debug(f"Received report response. Keys: {list(resp.keys()) if isinstance(resp, dict) else 'N/A'}")

    info = (resp or {}).get("info") or {}

    if not info:
        demisto.debug(f"No 'info' object found in report response: {resp}")
        if resp and isinstance(resp, dict) and resp.get("message"):
            raise DemistoException(f"Failed to retrieve report for task {task_id}: {resp['message']}")

        raise DemistoException(f"No info object found in report for task {task_id}")

    target_file = (resp or {}).get("target", {}).get("file", {})
    demisto.debug(f"Target file present: {bool(target_file)}")

    hr_data = info

    if target_file:
        demisto.debug(f"Enriching report with target file metadata: {list(target_file.keys())}")
        hr_data["file_name"] = target_file.get("name")
        hr_data["file_path"] = target_file.get("path")
        hr_data["file_size"] = target_file.get("size")
        hr_data["crc32"] = target_file.get("crc32")
        hr_data["sha1"] = target_file.get("sha1")
        hr_data["sha256"] = target_file.get("sha256")
        hr_data["ssdeep"] = target_file.get("ssdeep")
        hr_data["file_type"] = target_file.get("type")
    else:
        demisto.debug("No target file metadata found in report")

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
    demisto.debug(f"Raw machines response keys: {list(resp.keys()) if isinstance(resp, dict) else 'N/A'}")

    machines_data = resp.get("machines", resp.get("data", resp))
    demisto.debug(f"Machines data type: {type(machines_data)}")

    if isinstance(machines_data, list):
        machines = machines_data
    elif isinstance(machines_data, dict):
        demisto.debug("Converting single machine dict to list")
        machines = [machines_data]
    else:
        demisto.debug(f"Unexpected machine data type {type(machines_data)}, using empty list.")
        machines = []

    demisto.debug(f"Total machines before filtering: {len(machines)}")
    if not all_results:
        demisto.debug(f"Limiting results to {limit} machines")
        machines = machines[:limit]
    demisto.debug(f"Final machine count: {len(machines)}")

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Machines (count={len(machines)})",
        machines,
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
    server_storage = server.get("storage") or {}

    row = {
        "Version": data.get("version"),
        "Hostname": hostname,
        "Tasks Reported": tasks.get("reported"),
        "Tasks Running": tasks.get("running"),
        "Tasks Completed": tasks.get("completed"),
        "Tasks Pending": tasks.get("pending"),
        "Server Usage": server_storage.get("used_by"),
        "Machines Available": machines.get("available"),
        "Machines Total": machines.get("total"),
        "Tools": data.get("tools"),
    }

    readable = tableToMarkdown(f"{INTEGRATION_NAME} Status", row, headerTransform=string_to_table_header)

    demisto.debug(f"Command '{command}' execution finished successfully.")
    return CommandResults(readable_output=readable)


def cape_task_screenshot_download_command(client: CapeSandboxClient, args: dict[str, Any]) -> CommandResults:
    """
    Download screenshots for a task.

    - If 'screenshot' arg is provided, downloads that single image.
    - If 'screenshot' arg is NOT provided, downloads all screenshots as a single ZIP file.
    """
    command = "Download Task Screenshots"
    demisto.debug(f"Starting execution of command: {command}")

    task_id = args["task_id"]
    screenshot_number = args.get("screenshot")

    try:
        if screenshot_number:
            # Case 1: Download a single screenshot
            file_meta, readable_title = _download_single_screenshot(client, task_id, screenshot_number)
        else:
            # Case 2: Download all screenshots as a zip
            file_meta, readable_title = _download_all_screenshots_zip(client, task_id)

        # We will always have just one file result (either the image or the zip)
        file_entries = [file_meta]

    except DemistoException as error:
        demisto.debug(f"Failed to fetch screenshots for task {task_id}: {error}")
        raise DemistoException(f"Failed to fetch screenshots for task {task_id}: {error}")

    if not file_entries:
        demisto.debug(f"No screenshots successfully downloaded for task {task_id}")
        raise DemistoException(f"No screenshots found for task {task_id}")

    readable = tableToMarkdown(
        readable_title,
        file_entries,
        headers=["TaskID", "ScreenshotNumber", "Name", "Size", "SHA1", "MD5", "Note"],
        headerTransform=string_to_table_header,
    )

    demisto.debug(f"Command '{command}' execution finished successfully.")
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task.Screenshot",
        outputs_key_field="Name",
        outputs=file_entries,
    )


def _download_single_screenshot(client: CapeSandboxClient, task_id: str, number: str) -> tuple[dict, str]:
    """Downloads a single screenshot and builds its metadata."""

    demisto.debug(f"Downloading single screenshot {number} for task {task_id}")
    content = client.get_task_screenshot(task_id=task_id, number=number)
    filename = build_file_name(
        file_identifier=task_id,
        file_type_info=FILE_TYPE_SCREENSHOT,
        screenshot_number=int(number),
    )

    file_meta = fileResult(filename, content)
    file_meta["TaskID"] = task_id
    file_meta["ScreenshotNumber"] = number

    readable_title = f"{INTEGRATION_NAME} Screenshot {number} for Task {task_id}"

    # Return both the file data and the title for the Markdown table
    return file_meta, readable_title


def _download_all_screenshots_zip(client: CapeSandboxClient, task_id: str) -> tuple[dict, str]:
    """Downloads all screenshots as a zip and builds its metadata."""

    demisto.debug(f"Downloading all screenshots as ZIP for task {task_id}")
    content = client.download_all_screenshots_zip(task_id=task_id)

    filename = build_file_name(file_identifier=task_id, file_type_info=FILE_TYPE_FILE, file_format="zip")

    file_meta = fileResult(filename, content)
    file_meta["TaskID"] = task_id
    file_meta["Note"] = "All screenshots downloaded as a single ZIP file."
    readable_title = f"{INTEGRATION_NAME} All Screenshots (ZIP) for Task {task_id}"

    return file_meta, readable_title


# endregion
# region Main router
# =================================
# Main router
# =================================

COMMAND_MAP: dict[str, Any] = {
    "test-module": test_module,
    "cape-file-submit": cape_file_submit_command,
    "cape-file-view": cape_file_view_command,
    "cape-sample-download": cape_sample_file_download_command,
    "cape-url-submit": cape_url_submit_command,
    "cape-tasks-list": cape_tasks_list_command,
    "cape-task-delete": cape_task_delete_command,
    "cape-task-screenshot-download": cape_task_screenshot_download_command,
    "cape-task-report-get": cape_task_report_get_command,
    "cape-pcap-file-download": cape_pcap_file_download_command,
    "cape-machines-list": cape_machines_list_command,
    "cape-cuckoo-status-get": cape_cuckoo_status_get_command,
    "cape-task-poll": cape_task_poll_report,
}


def main() -> None:
    """Main entry point for CapeSandbox integration."""
    demisto.debug("CapeSandbox integration started")

    command = demisto.command()
    demisto.debug(f"Received command: '{command}'")

    try:
        if command not in COMMAND_MAP:
            raise DemistoException(f"Command '{command}' is not implemented")

        demisto.debug(f"Command '{command}' validated successfully")

        demisto.debug("Parsing integration configuration")
        config = parse_integration_params(demisto.params())
        demisto.debug("Configuration parsed successfully")

        demisto.debug("Initializing CapeSandbox client")
        client = CapeSandboxClient(
            base_url=config["base_url"],
            verify=config["verify_certificate"],
            proxy=config["proxy"],
            api_token=config["api_token"],
            username=config["username"],
            password=config["password"],
        )
        demisto.debug("Client initialized successfully")

        command_func = COMMAND_MAP[command]
        demisto.debug(f"Executing command function for '{command}'")

        if command == "test-module":
            result = command_func(client)
        elif command == "cape-task-poll":
            result = command_func(demisto.args(), client)
        else:
            result = command_func(client, demisto.args())

        return_results(result)
        demisto.debug(f"Command '{command}' completed successfully")

    except Exception as error:
        error_msg = f"Failed to execute {command=}. Error: {str(error)}"
        demisto.debug(f"Error: {error_msg}\nTrace: {traceback.format_exc()}")
        return_error(error_msg, error=str(error))

    finally:
        demisto.debug("CapeSandbox integration finished")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
