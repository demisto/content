"""Browser Use Cloud (v3) integration for Cortex XSOAR / XSIAM.

Wraps the public REST API at https://api.browser-use.com/v3 (see
https://docs.browser-use.com/cloud/api-reference). Authentication uses the
`X-Browser-Use-API-Key` header with a key starting with `bu_`.

The integration intentionally talks to the REST API directly using the
`BaseClient._http_request` helper so it can run on the lean
`demisto/python3` Docker image without needing the `browser-use-sdk`
package (which would pull in heavy transitive dependencies).
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401  # pylint: disable=W0614

import time
from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

INTEGRATION_NAME = "Browser Use"
INTEGRATION_CONTEXT = "BrowserUse"
DEFAULT_BASE_URL = "https://api.browser-use.com"
API_VERSION_PATH = "/v3"
DEFAULT_PAGE_SIZE = 50
DEFAULT_POLL_INTERVAL = 10
DEFAULT_POLL_TIMEOUT = 600

# Agent task statuses considered terminal (i.e. no longer running)
TERMINAL_TASK_STATUSES = {"stopped", "timed_out", "error"}


""" CLIENT CLASS """


class Client(BaseClient):
    """REST client for the Browser Use Cloud API (v3)."""

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        # All API endpoints live under /v3 so we bake it into the base URL.
        full_base = f"{base_url.rstrip('/')}{API_VERSION_PATH}"
        headers = {
            "X-Browser-Use-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        super().__init__(base_url=full_base, verify=verify, proxy=proxy, headers=headers)

    # --- Account ---------------------------------------------------------

    def get_account(self) -> dict:
        return self._http_request("GET", "/billing/account")

    # --- Agent Sessions (Tasks) ------------------------------------------

    def run_task(self, body: dict) -> dict:
        return self._http_request("POST", "/sessions", json_data=body)

    def get_task(self, session_id: str) -> dict:
        return self._http_request("GET", f"/sessions/{session_id}")

    def list_tasks(self, page: int | None = None, page_size: int | None = None) -> dict:
        params = assign_params(page=page, page_size=page_size)
        return self._http_request("GET", "/sessions", params=params)

    def stop_task(self, session_id: str, strategy: str | None = None) -> dict:
        body = assign_params(strategy=strategy)
        return self._http_request("POST", f"/sessions/{session_id}/stop", json_data=body, resp_type="response")

    def delete_task(self, session_id: str) -> dict:
        return self._http_request("DELETE", f"/sessions/{session_id}", resp_type="response")

    def list_task_messages(
        self,
        session_id: str,
        after: str | None = None,
        before: str | None = None,
        limit: int | None = None,
    ) -> dict:
        params = assign_params(after=after, before=before, limit=limit)
        return self._http_request("GET", f"/sessions/{session_id}/messages", params=params)

    # --- Browser sessions (raw / CDP) ------------------------------------

    def create_browser(self, body: dict) -> dict:
        return self._http_request("POST", "/browsers", json_data=body)

    def get_browser(self, session_id: str) -> dict:
        return self._http_request("GET", f"/browsers/{session_id}")

    def list_browsers(self, page_size: int | None = None, page_number: int | None = None,
                      filter_by: str | None = None) -> dict:
        params = assign_params(pageSize=page_size, pageNumber=page_number, filterBy=filter_by)
        return self._http_request("GET", "/browsers", params=params)

    def stop_browser(self, session_id: str) -> dict:
        body = {"action": "stop"}
        return self._http_request("PATCH", f"/browsers/{session_id}", json_data=body)

    # --- Profiles --------------------------------------------------------

    def list_profiles(self, page_size: int | None = None, page_number: int | None = None,
                      query: str | None = None) -> dict:
        params = assign_params(pageSize=page_size, pageNumber=page_number, query=query)
        return self._http_request("GET", "/profiles", params=params)

    def get_profile(self, profile_id: str) -> dict:
        return self._http_request("GET", f"/profiles/{profile_id}")

    def create_profile(self, name: str | None = None, user_id: str | None = None) -> dict:
        body = assign_params(name=name, userId=user_id)
        return self._http_request("POST", "/profiles", json_data=body)

    def delete_profile(self, profile_id: str) -> dict:
        return self._http_request("DELETE", f"/profiles/{profile_id}", resp_type="response")

    # --- Workspaces ------------------------------------------------------

    def list_workspaces(self, page_size: int | None = None, page_number: int | None = None) -> dict:
        params = assign_params(pageSize=page_size, pageNumber=page_number)
        return self._http_request("GET", "/workspaces", params=params)

    def get_workspace(self, workspace_id: str) -> dict:
        return self._http_request("GET", f"/workspaces/{workspace_id}")

    def create_workspace(self, name: str | None = None) -> dict:
        body = assign_params(name=name)
        return self._http_request("POST", "/workspaces", json_data=body)

    def delete_workspace(self, workspace_id: str) -> dict:
        return self._http_request("DELETE", f"/workspaces/{workspace_id}", resp_type="response")

    def list_workspace_files(self, workspace_id: str, prefix: str | None = None,
                             limit: int | None = None, include_urls: bool | None = None) -> dict:
        params = assign_params(prefix=prefix, limit=limit, includeUrls=include_urls)
        return self._http_request("GET", f"/workspaces/{workspace_id}/files", params=params)


""" HELPER FUNCTIONS """


def _bool_arg(args: dict, name: str, default: bool = False) -> bool:
    """Convert a string arg to bool using XSOAR's argToBoolean helper."""
    value = args.get(name)
    if value is None or value == "":
        return default
    return argToBoolean(value)


def build_run_task_body(args: dict, params: dict) -> dict:
    """Build the JSON body for POST /sessions from command args + instance params."""
    body: dict[str, Any] = {}

    # Required-ish: a task or an existing session id.
    if task := args.get("task"):
        body["task"] = task
    if session_id := args.get("session_id"):
        body["sessionId"] = session_id

    # Model selection: arg overrides instance default.
    model = args.get("model") or params.get("default_model")
    if model:
        body["model"] = model

    # Optional knobs.
    if profile_id := args.get("profile_id"):
        body["profileId"] = profile_id
    if workspace_id := args.get("workspace_id"):
        body["workspaceId"] = workspace_id

    keep_alive = args.get("keep_alive")
    if keep_alive is not None and keep_alive != "":
        body["keepAlive"] = argToBoolean(keep_alive)

    max_cost = args.get("max_cost_usd") or params.get("default_max_cost_usd")
    if max_cost not in (None, ""):
        body["maxCostUsd"] = float(max_cost)

    proxy_country = args.get("proxy_country") or params.get("default_proxy_country")
    if proxy_country:
        body["proxyCountryCode"] = proxy_country

    timeout = args.get("session_timeout_min") or params.get("default_session_timeout_min")
    if timeout not in (None, ""):
        body["timeout"] = arg_to_number(timeout)

    if enable_recording := args.get("enable_recording"):
        body["enableRecording"] = argToBoolean(enable_recording)

    return body


def task_to_context(task: dict) -> dict:
    """Format a SessionResponse for the XSOAR context (CamelCase keys)."""
    if not isinstance(task, dict):
        return {}
    return {
        "ID": task.get("id"),
        "Status": task.get("status"),
        "Model": task.get("model"),
        "Title": task.get("title"),
        "Output": task.get("output"),
        "OutputSchema": task.get("outputSchema"),
        "StepCount": task.get("stepCount"),
        "LastStepSummary": task.get("lastStepSummary"),
        "IsTaskSuccessful": task.get("isTaskSuccessful"),
        "LiveUrl": task.get("liveUrl"),
        "RecordingUrls": task.get("recordingUrls"),
        "ProfileID": task.get("profileId"),
        "WorkspaceID": task.get("workspaceId"),
        "ProxyCountryCode": task.get("proxyCountryCode"),
        "MaxCostUsd": task.get("maxCostUsd"),
        "TotalInputTokens": task.get("totalInputTokens"),
        "TotalOutputTokens": task.get("totalOutputTokens"),
        "ProxyUsedMb": task.get("proxyUsedMb"),
        "LlmCostUsd": task.get("llmCostUsd"),
        "ProxyCostUsd": task.get("proxyCostUsd"),
        "BrowserCostUsd": task.get("browserCostUsd"),
        "TotalCostUsd": task.get("totalCostUsd"),
        "ScreenshotUrl": task.get("screenshotUrl"),
        "CreatedAt": task.get("createdAt"),
        "UpdatedAt": task.get("updatedAt"),
    }


def browser_to_context(item: dict) -> dict:
    return {
        "ID": item.get("id"),
        "Status": item.get("status"),
        "LiveUrl": item.get("liveUrl"),
        "CdpUrl": item.get("cdpUrl"),
        "TimeoutAt": item.get("timeoutAt"),
        "StartedAt": item.get("startedAt"),
        "FinishedAt": item.get("finishedAt"),
        "ProxyUsedMb": item.get("proxyUsedMb"),
        "ProxyCost": item.get("proxyCost"),
        "BrowserCost": item.get("browserCost"),
        "AgentSessionID": item.get("agentSessionId"),
        "RecordingUrl": item.get("recordingUrl"),
    }


def profile_to_context(item: dict) -> dict:
    return {
        "ID": item.get("id"),
        "Name": item.get("name"),
        "UserID": item.get("userId"),
        "LastUsedAt": item.get("lastUsedAt"),
        "CookieDomains": item.get("cookieDomains"),
        "CreatedAt": item.get("createdAt"),
        "UpdatedAt": item.get("updatedAt"),
    }


def workspace_to_context(item: dict) -> dict:
    return {
        "ID": item.get("id"),
        "Name": item.get("name"),
        "CreatedAt": item.get("createdAt"),
        "UpdatedAt": item.get("updatedAt"),
    }


def message_to_context(msg: dict) -> dict:
    return {
        "ID": msg.get("id"),
        "SessionID": msg.get("sessionId"),
        "Role": msg.get("role"),
        "Type": msg.get("type"),
        "Summary": msg.get("summary"),
        "Data": msg.get("data"),
        "ScreenshotUrl": msg.get("screenshotUrl"),
        "Hidden": msg.get("hidden"),
        "CreatedAt": msg.get("createdAt"),
    }


def account_to_context(acc: dict) -> dict:
    plan = acc.get("planInfo") or {}
    return {
        "Name": acc.get("name"),
        "ProjectID": acc.get("projectId"),
        "TotalCreditsBalanceUsd": acc.get("totalCreditsBalanceUsd"),
        "MonthlyCreditsBalanceUsd": acc.get("monthlyCreditsBalanceUsd"),
        "AdditionalCreditsBalanceUsd": acc.get("additionalCreditsBalanceUsd"),
        "RateLimit": acc.get("rateLimit"),
        "Plan": {
            "Name": plan.get("planName"),
            "SubscriptionStatus": plan.get("subscriptionStatus"),
            "SubscriptionID": plan.get("subscriptionId"),
            "SubscriptionCurrentPeriodEnd": plan.get("subscriptionCurrentPeriodEnd"),
            "SubscriptionCanceledAt": plan.get("subscriptionCanceledAt"),
        },
    }


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validates the API key by hitting the billing/account endpoint."""
    try:
        client.get_account()
    except DemistoException as exc:
        msg = str(exc)
        if "401" in msg or "403" in msg or "Unauthorized" in msg:
            return "Authorization Error: make sure the API Key is correct (it must start with 'bu_')."
        raise
    return "ok"


def account_info_command(client: Client) -> CommandResults:
    raw = client.get_account()
    ctx = account_to_context(raw)
    headers = ["Name", "ProjectID", "TotalCreditsBalanceUsd", "MonthlyCreditsBalanceUsd",
               "AdditionalCreditsBalanceUsd", "RateLimit"]
    md = tableToMarkdown(f"{INTEGRATION_NAME} - Account", ctx, headers=headers, removeNull=True)
    if plan := ctx.get("Plan"):
        md += "\n" + tableToMarkdown("Plan", plan, removeNull=True)
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Account",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def task_run_command(client: Client, args: dict, params: dict) -> CommandResults:
    """Dispatch an agent task. Optionally poll until the task reaches a terminal state."""
    if not args.get("task") and not args.get("session_id"):
        raise DemistoException("Either 'task' or 'session_id' must be provided.")

    body = build_run_task_body(args, params)
    raw = client.run_task(body)
    task_id = raw.get("id")

    wait = _bool_arg(args, "wait", default=False)
    if wait and task_id:
        poll_timeout = arg_to_number(args.get("poll_timeout") or params.get("polling_timeout") or DEFAULT_POLL_TIMEOUT) \
            or DEFAULT_POLL_TIMEOUT
        poll_interval = arg_to_number(
            args.get("poll_interval") or params.get("polling_interval") or DEFAULT_POLL_INTERVAL
        ) or DEFAULT_POLL_INTERVAL
        raw = _wait_for_task(client, task_id, poll_timeout, poll_interval)

    ctx = task_to_context(raw)
    headers = ["ID", "Status", "Model", "Title", "StepCount", "LastStepSummary",
               "IsTaskSuccessful", "TotalCostUsd", "LiveUrl"]
    md = tableToMarkdown(f"{INTEGRATION_NAME} - Task `{ctx.get('ID')}`", ctx, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Task",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def _wait_for_task(client: Client, session_id: str, timeout_sec: int, interval_sec: int) -> dict:
    """Poll GET /sessions/{id} until the agent reports a terminal status or we time out.

    Always performs at least one fetch so callers receive a real session view
    even if the timeout is very short.
    """
    deadline = time.time() + timeout_sec
    while True:
        last = client.get_task(session_id)
        status = (last.get("status") or "").lower()
        if status in TERMINAL_TASK_STATUSES:
            return last
        if time.time() >= deadline:
            return last
        time.sleep(interval_sec)


def task_get_command(client: Client, args: dict) -> CommandResults:
    session_id = args["session_id"]
    raw = client.get_task(session_id)
    ctx = task_to_context(raw)
    headers = ["ID", "Status", "Model", "Title", "StepCount", "LastStepSummary",
               "IsTaskSuccessful", "TotalCostUsd", "LiveUrl", "RecordingUrls"]
    md = tableToMarkdown(f"{INTEGRATION_NAME} - Task `{session_id}`", ctx, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Task",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def task_list_command(client: Client, args: dict) -> CommandResults:
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size") or DEFAULT_PAGE_SIZE)
    raw = client.list_tasks(page=page, page_size=page_size)
    sessions = raw.get("sessions", []) or []
    ctx = [task_to_context(s) for s in sessions]
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Tasks (page {raw.get('page', page)}, total {raw.get('total', len(ctx))})",
        ctx,
        headers=["ID", "Status", "Model", "Title", "TotalCostUsd", "CreatedAt"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Task",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def task_stop_command(client: Client, args: dict) -> CommandResults:
    session_id = args["session_id"]
    strategy = args.get("strategy") or "session"
    client.stop_task(session_id, strategy=strategy)
    md = f"Task `{session_id}` stopped (strategy=`{strategy}`)."
    return CommandResults(
        readable_output=md,
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Task",
        outputs_key_field="ID",
        outputs={"ID": session_id, "Status": "stopped"},
    )


def task_messages_list_command(client: Client, args: dict) -> CommandResults:
    session_id = args["session_id"]
    raw = client.list_task_messages(
        session_id,
        after=args.get("after"),
        before=args.get("before"),
        limit=arg_to_number(args.get("limit")),
    )
    messages = raw.get("messages", []) or []
    ctx_messages = [message_to_context(m) for m in messages]
    output = {"SessionID": session_id, "Messages": ctx_messages, "HasMore": raw.get("hasMore")}
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Messages for `{session_id}` (HasMore={raw.get('hasMore')})",
        ctx_messages,
        headers=["ID", "CreatedAt", "Role", "Type", "Summary"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.TaskMessages",
        outputs_key_field="SessionID",
        outputs=output,
        readable_output=md,
        raw_response=raw,
    )


def task_screenshot_get_command(client: Client, args: dict) -> CommandResults:
    """Fetch the latest screenshot URL for an agent task."""
    session_id = args["session_id"]
    raw = client.get_task(session_id)
    url = raw.get("screenshotUrl")
    if not url:
        return CommandResults(readable_output=f"No screenshot available for task `{session_id}` yet.")
    output = {"ID": session_id, "ScreenshotUrl": url}
    md = f"### Latest screenshot for `{session_id}`\n\n[Open screenshot]({url})\n\n_Note: presigned URL — expires in ~5 minutes._"
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Task",
        outputs_key_field="ID",
        outputs=output,
        readable_output=md,
    )


def browser_create_command(client: Client, args: dict, params: dict) -> CommandResults:
    body: dict[str, Any] = {}
    if profile_id := args.get("profile_id"):
        body["profileId"] = profile_id
    proxy_country = args.get("proxy_country") or params.get("default_proxy_country")
    if proxy_country:
        body["proxyCountryCode"] = proxy_country
    timeout = args.get("timeout_min") or params.get("default_session_timeout_min")
    if timeout not in (None, ""):
        body["timeout"] = arg_to_number(timeout)
    if width := args.get("screen_width"):
        body["browserScreenWidth"] = arg_to_number(width)
    if height := args.get("screen_height"):
        body["browserScreenHeight"] = arg_to_number(height)
    if allow_resize := args.get("allow_resizing"):
        body["allowResizing"] = argToBoolean(allow_resize)
    if enable_recording := args.get("enable_recording"):
        body["enableRecording"] = argToBoolean(enable_recording)

    raw = client.create_browser(body)
    ctx = browser_to_context(raw)
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Browser session created `{ctx.get('ID')}`",
        ctx,
        headers=["ID", "Status", "LiveUrl", "CdpUrl", "TimeoutAt", "StartedAt"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Browser",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def browser_get_command(client: Client, args: dict) -> CommandResults:
    session_id = args["session_id"]
    raw = client.get_browser(session_id)
    ctx = browser_to_context(raw)
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Browser `{session_id}`",
        ctx,
        headers=["ID", "Status", "LiveUrl", "CdpUrl", "TimeoutAt", "StartedAt", "FinishedAt", "RecordingUrl"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Browser",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def browser_list_command(client: Client, args: dict) -> CommandResults:
    raw = client.list_browsers(
        page_size=arg_to_number(args.get("page_size") or DEFAULT_PAGE_SIZE),
        page_number=arg_to_number(args.get("page_number")),
        filter_by=args.get("filter_by"),
    )
    items = raw.get("sessions") or raw.get("items") or []
    if isinstance(raw, list):  # defensive
        items = raw
    ctx = [browser_to_context(item) for item in items]
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Browser sessions",
        ctx,
        headers=["ID", "Status", "LiveUrl", "StartedAt", "FinishedAt"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Browser",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def browser_stop_command(client: Client, args: dict) -> CommandResults:
    session_id = args["session_id"]
    raw = client.stop_browser(session_id)
    ctx = browser_to_context(raw if isinstance(raw, dict) else {"id": session_id, "status": "stopped"})
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Browser",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=f"Browser session `{session_id}` stop requested.",
        raw_response=raw if isinstance(raw, dict) else {},
    )


def profile_list_command(client: Client, args: dict) -> CommandResults:
    raw = client.list_profiles(
        page_size=arg_to_number(args.get("page_size") or DEFAULT_PAGE_SIZE),
        page_number=arg_to_number(args.get("page_number")),
        query=args.get("query"),
    )
    items = raw.get("profiles") or raw.get("items") or []
    ctx = [profile_to_context(p) for p in items]
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Profiles",
        ctx,
        headers=["ID", "Name", "UserID", "LastUsedAt", "CreatedAt"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Profile",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def profile_get_command(client: Client, args: dict) -> CommandResults:
    profile_id = args["profile_id"]
    raw = client.get_profile(profile_id)
    ctx = profile_to_context(raw)
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Profile `{profile_id}`",
        ctx,
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Profile",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def profile_create_command(client: Client, args: dict) -> CommandResults:
    raw = client.create_profile(name=args.get("name"), user_id=args.get("user_id"))
    ctx = profile_to_context(raw)
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Profile",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=tableToMarkdown(f"{INTEGRATION_NAME} - Profile created", ctx, removeNull=True),
        raw_response=raw,
    )


def profile_delete_command(client: Client, args: dict) -> CommandResults:
    profile_id = args["profile_id"]
    client.delete_profile(profile_id)
    return CommandResults(readable_output=f"Profile `{profile_id}` deleted.")


def workspace_list_command(client: Client, args: dict) -> CommandResults:
    raw = client.list_workspaces(
        page_size=arg_to_number(args.get("page_size") or DEFAULT_PAGE_SIZE),
        page_number=arg_to_number(args.get("page_number")),
    )
    items = raw.get("workspaces") or raw.get("items") or []
    ctx = [workspace_to_context(w) for w in items]
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Workspaces",
        ctx,
        headers=["ID", "Name", "CreatedAt", "UpdatedAt"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Workspace",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=md,
        raw_response=raw,
    )


def workspace_get_command(client: Client, args: dict) -> CommandResults:
    workspace_id = args["workspace_id"]
    raw = client.get_workspace(workspace_id)
    ctx = workspace_to_context(raw)
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Workspace",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=tableToMarkdown(f"{INTEGRATION_NAME} - Workspace `{workspace_id}`", ctx, removeNull=True),
        raw_response=raw,
    )


def workspace_create_command(client: Client, args: dict) -> CommandResults:
    raw = client.create_workspace(name=args.get("name"))
    ctx = workspace_to_context(raw)
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Workspace",
        outputs_key_field="ID",
        outputs=ctx,
        readable_output=tableToMarkdown(f"{INTEGRATION_NAME} - Workspace created", ctx, removeNull=True),
        raw_response=raw,
    )


def workspace_delete_command(client: Client, args: dict) -> CommandResults:
    workspace_id = args["workspace_id"]
    client.delete_workspace(workspace_id)
    return CommandResults(readable_output=f"Workspace `{workspace_id}` deleted.")


def workspace_files_list_command(client: Client, args: dict) -> CommandResults:
    workspace_id = args["workspace_id"]
    raw = client.list_workspace_files(
        workspace_id,
        prefix=args.get("prefix"),
        limit=arg_to_number(args.get("limit") or DEFAULT_PAGE_SIZE),
        include_urls=_bool_arg(args, "include_urls", default=False),
    )
    files = raw.get("files") or raw.get("items") or []
    ctx_files = [
        {
            "Path": f.get("path"),
            "Size": f.get("size"),
            "LastModified": f.get("lastModified"),
            "Url": f.get("url"),
        }
        for f in files
    ]
    output = {"ID": workspace_id, "Files": ctx_files}
    md = tableToMarkdown(
        f"{INTEGRATION_NAME} - Files in workspace `{workspace_id}`",
        ctx_files,
        headers=["Path", "Size", "LastModified", "Url"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Workspace",
        outputs_key_field="ID",
        outputs=output,
        readable_output=md,
        raw_response=raw,
    )


""" MAIN """

# Map XSOAR command names to (callable, requires_params)
COMMAND_DISPATCH: dict[str, Any] = {
    "browser-use-account-info": (account_info_command, False),
    "browser-use-task-run": (task_run_command, True),
    "browser-use-task-get": (task_get_command, False),
    "browser-use-task-list": (task_list_command, False),
    "browser-use-task-stop": (task_stop_command, False),
    "browser-use-task-messages-list": (task_messages_list_command, False),
    "browser-use-task-screenshot-get": (task_screenshot_get_command, False),
    "browser-use-browser-create": (browser_create_command, True),
    "browser-use-browser-get": (browser_get_command, False),
    "browser-use-browser-list": (browser_list_command, False),
    "browser-use-browser-stop": (browser_stop_command, False),
    "browser-use-profile-list": (profile_list_command, False),
    "browser-use-profile-get": (profile_get_command, False),
    "browser-use-profile-create": (profile_create_command, False),
    "browser-use-profile-delete": (profile_delete_command, False),
    "browser-use-workspace-list": (workspace_list_command, False),
    "browser-use-workspace-get": (workspace_get_command, False),
    "browser-use-workspace-create": (workspace_create_command, False),
    "browser-use-workspace-delete": (workspace_delete_command, False),
    "browser-use-workspace-files-list": (workspace_files_list_command, False),
}


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = (params.get("url") or DEFAULT_BASE_URL).rstrip("/")
    api_key = (params.get("credentials") or {}).get("password") or params.get("apikey")
    if not api_key:
        return_error("API Key is required. Configure it under the integration instance settings.")

    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"{INTEGRATION_NAME} - Command being called is `{command}`")

    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
            return

        handler = COMMAND_DISPATCH.get(command)
        if handler is None:
            raise NotImplementedError(f"Command `{command}` is not implemented in {INTEGRATION_NAME}.")

        func, needs_params = handler
        if needs_params:
            return_results(func(client, args, params))
        elif func is account_info_command:
            return_results(func(client))
        else:
            return_results(func(client, args))

    except Exception as exc:  # noqa: BLE001
        demisto.error(f"{INTEGRATION_NAME} - failed to execute `{command}`: {exc}")
        return_error(f"Failed to execute {command} command. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
