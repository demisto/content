from __future__ import annotations

import os
import re
from enum import Enum
from pathlib import Path
from typing import Any

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
POLLING_TIMEOUT_SECONDS = 60 * 60 * 5


def parse_integration_params(params: dict[str, Any]) -> dict[str, Any]:
    """Normalize and extract integration configuration from demisto.params()."""
    base_url = (params.get("url") or "").rstrip("/")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    credentials = params.get("credentials")
    username = (
        credentials.get("identifier")
        if isinstance(credentials, dict)
        else params.get("username")
    )
    password = (
        credentials.get("password")
        if isinstance(credentials, dict)
        else params.get("password")
    )
    api_token = params.get("api_token")

    if not base_url:
        raise DemistoException("Server URL (url) is required.")

    # precedence: api_token over username/password
    if api_token and (username or password):
        demisto.debug(
            "CapeSandbox: api_token provided; username/password will be ignored."
        )

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
        memory="1" if argToBoolean(args.get("memory")) else None,
        enforce_timeout="1" if argToBoolean(args.get("enforce_timeout")) else None,
        clock=args.get("clock"),
    )
    if url_mode:
        form["url"] = args.get("url")
    return form


def get_entry_path(entry_id: str) -> tuple[str, str]:
    file_path = get_file_path(entry_id)
    path = file_path["path"]
    name = file_path.get("name") or os.path.basename(path)
    return path, name


def status_is_reported(status_response: dict[str, Any]) -> bool:
    return (status_response or {}).get("data") == "reported"


# Hash validators (regex-based)
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def is_valid_md5(value: str | None) -> bool:
    return bool(_MD5_RE.fullmatch(value or ""))


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
    DELETE = "delete"
    FILE = "file"
    URL = "url"
    MD5 = "md5"
    SHA256 = "sha256"


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
TASK_STATUS = f"{TASKS_BASE}/{Action.STATUS.value}" + "/{task_id}/"
TASK_VIEW = f"{TASKS_BASE}/{Action.VIEW.value}" + "/{task_id}/"
TASK_LIST = f"{TASKS_BASE}/list" + "/{limit}/{offset}/"
TASK_DELETE = f"{TASKS_BASE}/{Action.DELETE.value}" + "/{task_id}/"
TASK_GET_REPORT_BASE = f"{TASKS_BASE}/get/report" + "/{task_id}/"
STATUS_URL = "cuckoo/status/"
TASK_SCREENSHOTS_LIST = f"{TASKS_BASE}/screenshots" + "/{task_id}/"
TASK_SCREENSHOT_GET = f"{TASKS_BASE}/screenshots" + "/{task_id}/{number}/"

# -- Files --
FILE_VIEW_BY_TASK = f"{FILES_BASE}/{Action.VIEW.value}" + "/{task_id}/"
FILE_VIEW_BY_MD5 = f"{FILES_BASE}/{Action.VIEW.value}/{Action.MD5.value}" + "/{md5}/"
FILE_VIEW_BY_SHA256 = (
    f"{FILES_BASE}/{Action.VIEW.value}/{Action.SHA256.value}" + "/{sha256}/"
)

# -- Machines --
MACHINES_LIST = f"{MACHINES_BASE}/list/"
MACHINE_VIEW = f"{MACHINES_BASE}/{Action.VIEW.value}" + "/{name}/"


# ---------- Client: Auth & HTTP ----------
class CapeSandboxClient(BaseClient):
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
        self.api_token = (api_token or "").strip() or None
        self.username = (username or "").strip() or None
        self.password = (password or "").strip() or None

        if not self.api_token and not (self.username and self.password):
            raise DemistoException(
                "Either API token or Username + Password must be provided."
            )

    def _auth_headers(self) -> dict[str, str]:
        token = self.ensure_token()
        return {"Authorization": f"Token {token}"}

    def ensure_token(self) -> str:
        """Returns a valid token. If api_token param provided, use it. Otherwise, retrieve and cache via username/password."""

        if self.api_token:
            return self.api_token

        integration_context = get_integration_context() or {}
        cached = integration_context.get("api_token")
        if cached:
            return cached

        if not (self.username and self.password):
            raise DemistoException(
                "Username and password are required to obtain API token."
            )

        data = {"username": self.username, "password": self.password}
        resp = self._http_request(method="POST", url_suffix=API_AUTH, data=data)
        token = resp.get("token") or resp.get("key") or ""
        if not token:
            raise DemistoException("Failed to obtain API token from CAPE response.")
        set_integration_context({"api_token": token})
        return token

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        full_url: str = "",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        resp_type: str = "json",
        ok_codes: tuple[int, ...] | None = None,
    ) -> Any:
        headers = self._auth_headers()  # TODO move to init and use the _http..
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            params=params,
            data=data,
            json_data=json_data,
            files=files,
            headers=headers,
            resp_type=resp_type,
            ok_codes=ok_codes,
        )

    # ---------- Submit ----------
    def submit_file(
        self, form: dict[str, Any], file_path: str, is_pcap: bool
    ) -> dict[str, Any]:
        """Create a task by uploading a file."""

        data = form.copy()
        if is_pcap:
            data["pcap"] = "1"
        basename = Path(file_path).name
        with open(file_path, "rb") as f:
            files = {"file": (basename, f)}
            return self.http_request(
                "POST", url_suffix=TASK_CREATE_FILE, files=files, data=data
            )

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
            raise DemistoException("limit must be > 0")
        if offset < 0:
            raise DemistoException("offset must be >= 0")
        return self.http_request(
            "GET", url_suffix=TASK_LIST.format(limit=limit, offset=offset)
        )

    def get_task_report(
        self, task_id: int | str, fmt: str | None = None, zip_download: bool = False
    ) -> Any:
        """Return task report. If zip_download is True, returns bytes content of a zip; otherwise JSON.

        Supported formats include: json (default), maec, maec5, metadata, lite, all, dist, dropped.
        """
        suffix = TASK_GET_REPORT_BASE.format(task_id=task_id)
        if fmt:
            suffix += f"{fmt}/"
        if zip_download:
            suffix += "zip/"
            return self.http_request("GET", url_suffix=suffix, resp_type="content")
        return self.http_request("GET", url_suffix=suffix)

    # ---------- Status ----------
    def get_status(self) -> dict[str, Any]:
        """Return overall CAPE status."""
        return self.http_request("GET", url_suffix=STATUS_URL)

    # ---------- Screenshots ----------
    def list_task_screenshots(self, task_id: int | str) -> Any:
        """Return list/metadata of screenshots for a task (JSON)."""
        return self.http_request(
            "GET", url_suffix=TASK_SCREENSHOTS_LIST.format(task_id=task_id)
        )

    def get_task_screenshot(self, task_id: int | str, number: int | str) -> bytes:
        """Return a specific screenshot content (binary)."""
        return self.http_request(
            "GET",
            url_suffix=TASK_SCREENSHOT_GET.format(task_id=task_id, number=number),
            resp_type="content",
        )

    # ---------- File Views ----------
    def files_view_by_task(self, task_id: int | str) -> dict[str, Any]:
        return self.http_request(
            "GET", url_suffix=FILE_VIEW_BY_TASK.format(task_id=task_id)
        )

    def files_view_by_md5(self, md5: str) -> dict[str, Any]:
        """Return file details by MD5."""
        if not is_valid_md5(md5):
            raise DemistoException("Invalid MD5 hash format.")
        return self.http_request("GET", url_suffix=FILE_VIEW_BY_MD5.format(md5=md5))

    def files_view_by_sha256(self, sha256: str) -> dict[str, Any]:
        """Return file details by SHA256."""
        if not is_valid_sha256(sha256):
            raise DemistoException("Invalid SHA256 hash format.")
        return self.http_request(
            "GET", url_suffix=FILE_VIEW_BY_SHA256.format(sha256=sha256)
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


# endregion
# region Command implementations
# =================================
# Command implementations
# =================================
def test_module(client: CapeSandboxClient) -> str:
    """Test connectivity and credentials by ensuring a valid token exists."""
    client.ensure_token()
    return "ok"


# ---------- Submit & Poll ----------
def cape_file_submit_command2(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """Submit a file (or PCAP) to CAPE and poll until the task is reported.

    First call requires `entry_id`. Subsequent polls pass back `task_id`.
    """
    task_id = args.get("task_id")
    if task_id:
        status = client.get_task_status(task_id)
        if status_is_reported(status):
            task = client.get_task_view(task_id)
            readable = tableToMarkdown(
                f"{INTEGRATION_NAME} Task {task_id}",
                task.get("data") or task,
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
                ],
                headerTransform=pascalToSpace,
            )
            return CommandResults(
                readable_output=readable,
                outputs_prefix="Cape.Task",
                outputs_key_field="id",
                outputs=task.get("data") or task,
            )
        return CommandResults(
            readable_output=f"Task {task_id} is not ready yet. Scheduling next poll in {POLLING_INTERVAL_SECONDS}s.",
            scheduled_command=ScheduledCommand(
                command="cape-file-submit",
                next_run_in_seconds=POLLING_INTERVAL_SECONDS,
                args={"task_id": task_id},
            ),
        )

    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id is required for cape-file-submit.")

    try:
        file_path, filename = get_entry_path(entry_id)
    except Exception as ex:
        raise DemistoException(
            f"Failed to resolve entry_id '{entry_id}' to a local file path: {ex}"
        )
    is_pcap = filename.lower().endswith(".pcap")

    form = build_submit_form(args)
    submit_resp = client.submit_file(form=form, file_path=file_path, is_pcap=is_pcap)
    task_ids = ((submit_resp or {}).get("data") or {}).get("task_ids") or []
    if not task_ids:
        raise DemistoException(
            f"No task id returned from CAPE. Response: {submit_resp}"
        )
    task_id = task_ids[0]

    md = f"Submitted file {filename}. Task ID {task_id}. Polling will continue every {POLLING_INTERVAL_SECONDS}s until ready."
    return CommandResults(
        readable_output=md,
        scheduled_command=ScheduledCommand(
            command="cape-file-submit",
            next_run_in_seconds=POLLING_INTERVAL_SECONDS,
            args={"task_id": task_id},
        ),
    )


@polling_function(
    name="cape-file-submit",
    interval=POLLING_INTERVAL_SECONDS,
    timeout=POLLING_TIMEOUT_SECONDS,
)
def cape_file_poll_report(
    args: dict[str, Any], client: CapeSandboxClient
) -> PollResult:
    """
    Polls the CAPE service for the task status until the report is ready.
    This function is called repeatedly by XSOAR's scheduling mechanism.
    """
    task_id = args.get("task_id")
    if not task_id:
        raise DemistoException("Task ID is missing for polling sequence.")

    status = client.get_task_status(task_id)

    # Check if the final status has been reached
    if status_is_reported(status):
        task = client.get_task_view(task_id)

        # Build the final CommandResults object
        readable = tableToMarkdown(
            f"{INTEGRATION_NAME} Task {task_id}",
            task.get("data") or task,
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
            ],
            headerTransform=pascalToSpace,
        )
        final_results = CommandResults(
            readable_output=readable,
            outputs_prefix="Cape.Task",
            outputs_key_field="id",
            outputs=task.get("data") or task,
        )

        # Return PollResult with the final response to terminate polling
        return PollResult(response=final_results)

    # If not ready, continue polling
    else:
        # Return PollResult with continue_to_poll=True to schedule the next run
        readable = f"Task {task_id} is not ready yet. Scheduling next poll in {POLLING_INTERVAL_SECONDS}s."

        # Optionally, you can return a partial_result to update the War Room
        return PollResult(
            response=None,
            continue_to_poll=True,
            partial_result=CommandResults(readable_output=readable),
        )


def cape_file_submit_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> PollResult:
    """
    Submits a file (or PCAP) to CAPE, retrieves the task_id, and initiates the polling sequence.
    This function is called once by the command_map.
    """

    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id is required for cape-file-submit.")

    try:
        file_path, filename = get_entry_path(entry_id)
    except Exception as ex:
        raise DemistoException(
            f"Failed to resolve entry_id '{entry_id}' to a local file path: {ex}"
        )
    is_pcap = filename.lower().endswith(".pcap")

    # Execute the submission API call
    form = build_submit_form(args)
    submit_resp = client.submit_file(form=form, file_path=file_path, is_pcap=is_pcap)

    task_ids = ((submit_resp or {}).get("data") or {}).get("task_ids") or []
    if not task_ids:
        raise DemistoException(
            f"No task id returned from CAPE. Response: {submit_resp}"
        )
    task_id = task_ids[0]

    md = f"Submitted file {filename}. Task ID {task_id}. Polling will continue every {POLLING_INTERVAL_SECONDS}s until ready."

    # 2. Initiate the polling sequence by calling the polling function
    return cape_file_poll_report(
        {"task_id": task_id, **args}, client  # Pass the new task_id and original args
    )


def cape_url_submit_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """Submit a URL to CAPE and poll until the task is reported.

    First call requires `url`. Subsequent polls pass back `task_id`.
    """
    task_id = args.get("task_id")
    if task_id:
        status = client.get_task_status(task_id)
        if status_is_reported(status):
            task = client.get_task_view(task_id)
            readable = tableToMarkdown(
                f"{INTEGRATION_NAME} Task {task_id}",
                task.get("data") or task,
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
                ],
                headerTransform=pascalToSpace,
            )
            return CommandResults(
                readable_output=readable,
                outputs_prefix="Cape.Task",
                outputs_key_field="id",
                outputs=task.get("data") or task,
            )
        return CommandResults(
            readable_output=f"URL Task {task_id} is not ready yet. Scheduling next poll in {POLLING_INTERVAL_SECONDS}s.",
            scheduled_command=ScheduledCommand(
                command="cape-url-submit",
                next_run_in_seconds=POLLING_INTERVAL_SECONDS,
                args={"task_id": task_id},
            ),
        )

    url = args.get("url")
    if not url:
        raise DemistoException("url is required for cape-url-submit.")

    form = build_submit_form(args, url_mode=True)
    submit_resp = client.submit_url(form=form)
    task_ids = ((submit_resp or {}).get("data") or {}).get("task_ids") or []
    if not task_ids:
        raise DemistoException(
            f"No task id returned from CAPE. Response: {submit_resp}"
        )
    task_id = task_ids[0]

    md = f"Submitted URL {url}. Task ID {task_id}. Polling will continue every {POLLING_INTERVAL_SECONDS}s until ready."
    return CommandResults(
        readable_output=md,
        scheduled_command=ScheduledCommand(
            command="cape-url-submit",
            next_run_in_seconds=POLLING_INTERVAL_SECONDS,
            args={"task_id": task_id},
        ),
    )


# ---------- Retrieval ----------
def cape_file_view_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """View file information by one of: `task_id`, `md5`, or `sha256`."""
    task_id = args.get("task_id")
    md5 = args.get("md5")
    sha256 = args.get("sha256")

    if not any([task_id, md5, sha256]):
        raise DemistoException("Provide one of: task_id, md5, sha256")
    if sum(bool(x) for x in [task_id, md5, sha256]) > 1:
        raise DemistoException("Provide only one of task_id, md5, sha256")

    if task_id:
        resp = client.files_view_by_task(task_id)
    elif md5:
        resp = client.files_view_by_md5(md5)
    else:
        resp = client.files_view_by_sha256(sha256)  # type: ignore[arg-type]

    data = resp.get("data") or resp
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
            "parent",
            "source_url",
        ],
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task.File",
        outputs_key_field="id",
        outputs=data,
    )


def cape_task_delete_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """Delete one or more tasks by id. Accepts a list in `task_id`."""
    task_ids = argToList(args.get("task_id"))
    if not task_ids:
        raise DemistoException("task_id is required")

    lines: list[str] = []
    for tid in task_ids:
        client.delete_task(tid)
        lines.append(f"Task id={tid} was deleted successfully")

    readable = "\n".join(lines)
    return CommandResults(readable_output=readable)


# ---------- Management ----------
def cape_tasks_list_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """List tasks with pagination or fetch a single task by `task_id`."""
    task_id = args.get("task_id")
    if task_id:
        task = client.get_task_view(task_id)
        data = task.get("data") or task
        readable = tableToMarkdown(
            f"{INTEGRATION_NAME} Task {task_id}",
            data if isinstance(data, dict) else [data],
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
            ],
            headerTransform=pascalToSpace,
        )
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Cape.Task",
            outputs_key_field="id",
            outputs=data,
        )

    default_limit = 50
    page_size = (
        arg_to_number(args.get("page_size"))
        or arg_to_number(args.get("limit"))
        or default_limit
    )
    page_size = int(min(max(1, page_size), 50))
    page = int(arg_to_number(args.get("page")) or 1)
    if page < 1:
        page = 1
    offset = (page - 1) * page_size

    resp = client.list_tasks(limit=page_size, offset=offset)
    data = resp.get("data") or resp
    items = data if isinstance(data, list) else [data]

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Tasks (page={page}, page_size={page_size})",
        items,
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
        ],
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task",
        outputs_key_field="id",
        outputs=items,
    )


def cape_task_report_get_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> Any:
    """Get a task report.

    When `zip=true`, returns a ZIP file. Otherwise returns the JSON `info` object.
    """
    task_id = args.get("task_id")
    if not task_id:
        raise DemistoException("task_id is required")

    fmt = (args.get("format") or "").strip().lower() or None
    zip_flag = argToBoolean(args.get("zip"))

    if zip_flag:
        content = client.get_task_report(task_id=task_id, fmt=fmt, zip_download=True)
        filename_fmt = fmt or "json"
        filename = f"cape_task_{task_id}_report_{filename_fmt}.zip"
        return fileResult(filename, content)

    resp = client.get_task_report(task_id=task_id, fmt=fmt, zip_download=False)
    info = (resp or {}).get("info") or {}
    if not info:
        raise DemistoException(f"No info object found in report for task {task_id}")

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
    ]
    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Task Report {task_id}",
        info,
        headers=headers,
        headerTransform=pascalToSpace,
    )

    # return fileResult("file_name", "result.content")
    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Task.Report",
        outputs_key_field="id",
        outputs=info,
    )


def cape_machines_list_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """List machines or view a single machine by `machine_name`."""
    machine_name = args.get("machine_name")
    all_results = argToBoolean(args.get("all_results"))
    limit = int(arg_to_number(args.get("limit")) or 50)
    if limit < 1:
        limit = 50

    if machine_name:
        resp = client.view_machine(machine_name)
        machine = resp.get("machine") or resp.get("data") or resp
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
            headerTransform=pascalToSpace,
        )
        return CommandResults(
            readable_output=readable,
            outputs_prefix="Cape.Machine",
            outputs_key_field="id",
            outputs=machine,
        )

    resp = client.list_machines()
    machines = resp.get("machines") or resp.get("data") or resp
    if isinstance(machines, dict):
        machines = [machines]
    if not all_results:
        machines = machines[:limit]

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
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Cape.Machine",
        outputs_key_field="id",
        outputs=machines,
    )


def cape_status_get_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> CommandResults:
    """Return overall CAPE/Cuckoo status as human-readable only."""
    resp = client.get_status() or {}
    tasks = resp.get("tasks") or {}
    server = resp.get("server") or {}
    machines = resp.get("machines") or {}

    # compute server usage in a readable way
    stagage = server.get("stagage")
    storage = server.get("storage")
    server_usage = None
    if isinstance(stagage, dict):
        server_usage = stagage.get("used_by")
    elif isinstance(storage, dict):
        server_usage = storage.get("used_by")

    row = {
        "Tasks reported": tasks.get("reported"),
        "Tasks running": tasks.get("running"),
        "Tasks completed": tasks.get("completed"),
        "Tasks pending": tasks.get("pending"),
        "Hostname": resp.get("hostname"),
        "Server Usage": server_usage,
        "Machines available": machines.get("available"),
        "Machines total": machines.get("total"),
        "Tools": resp.get("tools"),
    }

    readable = tableToMarkdown(
        f"{INTEGRATION_NAME} Status", row, headerTransform=pascalToSpace
    )
    return CommandResults(readable_output=readable)


def cape_task_screenshot_download_command(
    client: CapeSandboxClient, args: dict[str, Any]
) -> Any:
    """Download screenshots for a task.

    If 'screenshot' is provided, downloads that single screenshot.
    Otherwise, attempts to list and download all screenshots for the task.
    Returns file entries (list of fileResult dicts or a single one).
    """
    task_id = args.get("task_id")
    if not task_id:
        raise DemistoException("task_id is required")
    number = args.get("screenshot")

    if number:
        content = client.get_task_screenshot(task_id=task_id, number=number)
        filename = f"cape_task_{task_id}_screenshot_{number}.png"
        return fileResult(filename, content)

    # Download all screenshots
    meta = client.list_task_screenshots(task_id)
    # Try to find a list of indices
    candidates = []
    if isinstance(meta, dict):
        candidates = meta.get("screenshots") or meta.get("data") or []
    elif isinstance(meta, list):
        candidates = meta

    file_entries = []
    for idx in candidates:
        num = idx.get("number") if isinstance(idx, dict) else idx
        if num is None:
            continue
        try:
            content = client.get_task_screenshot(task_id=task_id, number=num)
            filename = f"cape_task_{task_id}_screenshot_{num}.png"
            file_entries.append(fileResult(filename, content))
        except Exception as ex:
            demisto.debug(f"Failed to fetch screenshot {num} for task {task_id}: {ex}")

    # Fallback: if no candidates found, try first few indices
    if not file_entries:
        for num in range(1, 6):
            try:
                content = client.get_task_screenshot(task_id=task_id, number=num)
                filename = f"cape_task_{task_id}_screenshot_{num}.png"
                file_entries.append(fileResult(filename, content))
            except Exception:
                break

    if not file_entries:
        raise DemistoException(f"No screenshots found for task {task_id}")

    return file_entries


# endregion
# region Main router
# =================================
# Main router
# =================================
def main() -> None:
    params: dict[str, Any] = demisto.params()
    args = demisto.args()

    config = parse_integration_params(params)

    base_url = config["base_url"]
    verify_certificate = config["verify_certificate"]
    proxy = config["proxy"]
    api_token = config["api_token"]
    username = config["username"]
    password = config["password"]

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = CapeSandboxClient(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_token=api_token,
            username=username,
            password=password,
        )

        command_map = {
            "test-module": lambda: test_module(client),
            "cape-file-submit": lambda: cape_file_submit_command(client, args),
            "cape-file-view": lambda: cape_file_view_command(client, args),
            "cape-url-submit": lambda: cape_url_submit_command(client, args),
            "cape-tasks-list": lambda: cape_tasks_list_command(client, args),
            "cape-task-delete": lambda: cape_task_delete_command(client, args),
            "cape-task-screenshot-download": lambda: cape_task_screenshot_download_command(
                client, args
            ),
            "cape-task-report-get": lambda: cape_task_report_get_command(client, args),
            "cape-machines-list": lambda: cape_machines_list_command(client, args),
            "cape-status-get": lambda: cape_status_get_command(client, args),
        }

        if command not in command_map:
            raise NotImplementedError(f"Command {command} is not implemented")

        result = command_map[command]()
        return_results(result)

    except Exception as error:
        return_error(f"Failed to execute {command} command. Error: {str(error)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
