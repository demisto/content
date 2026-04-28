"""Unit tests for the Browser Use integration.

Run inside the Docker image with:
    demisto-sdk pre-commit -i Packs/BrowserUse/Integrations/BrowserUse/
"""

from __future__ import annotations

import pytest
from CommonServerPython import DemistoException

from BrowserUse import (
    Client,
    INTEGRATION_CONTEXT,
    account_info_command,
    account_to_context,
    browser_create_command,
    browser_get_command,
    browser_list_command,
    browser_stop_command,
    browser_to_context,
    build_run_task_body,
    profile_create_command,
    profile_delete_command,
    profile_get_command,
    profile_list_command,
    profile_to_context,
    task_get_command,
    task_list_command,
    task_messages_list_command,
    task_run_command,
    task_screenshot_get_command,
    task_stop_command,
    task_to_context,
    test_module as run_test_module,
    workspace_create_command,
    workspace_delete_command,
    workspace_files_list_command,
    workspace_get_command,
    workspace_list_command,
    workspace_to_context,
)


BASE_URL = "https://api.example.com"
API_BASE = f"{BASE_URL}/v3"


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key="bu_test_key", verify=False, proxy=False)


# ---------------------------------------------------------------------------
# Helpers / formatters
# ---------------------------------------------------------------------------

class TestFormatters:
    def test_task_to_context_maps_camelcase(self):
        ctx = task_to_context(
            {
                "id": "abc",
                "status": "running",
                "model": "claude-sonnet-4.6",
                "title": "Visit example.com",
                "isTaskSuccessful": True,
                "totalCostUsd": "0.05",
                "stepCount": 3,
            }
        )
        assert ctx["ID"] == "abc"
        assert ctx["Status"] == "running"
        assert ctx["IsTaskSuccessful"] is True
        assert ctx["StepCount"] == 3
        assert ctx["TotalCostUsd"] == "0.05"

    def test_browser_to_context(self):
        ctx = browser_to_context({"id": "b1", "status": "active", "liveUrl": "https://x", "cdpUrl": "wss://y"})
        assert ctx == {
            "ID": "b1",
            "Status": "active",
            "LiveUrl": "https://x",
            "CdpUrl": "wss://y",
            "TimeoutAt": None,
            "StartedAt": None,
            "FinishedAt": None,
            "ProxyUsedMb": None,
            "ProxyCost": None,
            "BrowserCost": None,
            "AgentSessionID": None,
            "RecordingUrl": None,
        }

    def test_profile_to_context(self):
        ctx = profile_to_context({"id": "p1", "name": "main", "userId": "u1"})
        assert ctx["ID"] == "p1"
        assert ctx["Name"] == "main"
        assert ctx["UserID"] == "u1"

    def test_workspace_to_context(self):
        ctx = workspace_to_context({"id": "w1", "name": "intel"})
        assert ctx["ID"] == "w1"
        assert ctx["Name"] == "intel"

    def test_account_to_context_includes_plan(self):
        ctx = account_to_context(
            {
                "name": "Tester",
                "projectId": "proj-1",
                "totalCreditsBalanceUsd": 10.5,
                "rateLimit": 60,
                "planInfo": {"planName": "Pro", "subscriptionStatus": "active"},
            }
        )
        assert ctx["Name"] == "Tester"
        assert ctx["TotalCreditsBalanceUsd"] == 10.5
        assert ctx["Plan"]["Name"] == "Pro"
        assert ctx["Plan"]["SubscriptionStatus"] == "active"


class TestBuildRunTaskBody:
    def test_arg_overrides_param_default(self):
        body = build_run_task_body(
            args={
                "task": "Go visit example.com",
                "model": "claude-opus-4.6",
                "keep_alive": "true",
                "max_cost_usd": "2.5",
                "proxy_country": "de",
                "session_timeout_min": "30",
                "enable_recording": "true",
            },
            params={
                "default_model": "claude-sonnet-4.6",
                "default_max_cost_usd": "1.0",
                "default_proxy_country": "us",
                "default_session_timeout_min": "60",
            },
        )
        assert body == {
            "task": "Go visit example.com",
            "model": "claude-opus-4.6",
            "keepAlive": True,
            "maxCostUsd": 2.5,
            "proxyCountryCode": "de",
            "timeout": 30,
            "enableRecording": True,
        }

    def test_param_defaults_applied_when_args_missing(self):
        body = build_run_task_body(
            args={"task": "do something"},
            params={"default_model": "bu-mini", "default_max_cost_usd": "0.25", "default_proxy_country": "fr",
                    "default_session_timeout_min": "15"},
        )
        assert body["model"] == "bu-mini"
        assert body["maxCostUsd"] == 0.25
        assert body["proxyCountryCode"] == "fr"
        assert body["timeout"] == 15
        assert "keepAlive" not in body
        assert "enableRecording" not in body

    def test_session_id_only(self):
        body = build_run_task_body(
            args={"session_id": "sess-1", "task": "follow-up"},
            params={},
        )
        assert body["sessionId"] == "sess-1"
        assert body["task"] == "follow-up"


# ---------------------------------------------------------------------------
# test-module
# ---------------------------------------------------------------------------

class TestTestModule:
    def test_test_module_ok(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/billing/account", json={"name": "u", "projectId": "p", "rateLimit": 1})
        assert run_test_module(client) == "ok"

    def test_test_module_unauthorized(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/billing/account", status_code=401, json={"detail": "Unauthorized"})
        result = run_test_module(client)
        assert "Authorization Error" in result

    def test_test_module_other_error_propagates(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/billing/account", status_code=500, json={"detail": "boom"})
        with pytest.raises(DemistoException):
            run_test_module(client)


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

class TestAccount:
    def test_account_info(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/billing/account",
            json={"name": "Mike", "projectId": "p1", "totalCreditsBalanceUsd": 12.3, "rateLimit": 30,
                  "planInfo": {"planName": "Free"}},
        )
        result = account_info_command(client)
        assert result.outputs["Name"] == "Mike"
        assert result.outputs["TotalCreditsBalanceUsd"] == 12.3
        assert result.outputs["Plan"]["Name"] == "Free"
        assert result.outputs_prefix == f"{INTEGRATION_CONTEXT}.Account"


# ---------------------------------------------------------------------------
# Tasks (agent sessions)
# ---------------------------------------------------------------------------

class TestTasks:
    def test_task_run_requires_task_or_session(self, client):
        with pytest.raises(DemistoException, match="Either 'task' or 'session_id'"):
            task_run_command(client, args={}, params={})

    def test_task_run_no_wait(self, client, requests_mock):
        requests_mock.post(
            f"{API_BASE}/sessions",
            json={"id": "s1", "status": "created", "model": "claude-sonnet-4.6", "title": "go"},
        )
        result = task_run_command(client, args={"task": "go"}, params={})
        assert result.outputs["ID"] == "s1"
        assert result.outputs["Status"] == "created"
        assert result.outputs_prefix == f"{INTEGRATION_CONTEXT}.Task"

    def test_task_run_with_wait_polls_until_terminal(self, client, requests_mock, mocker):
        # POST /sessions -> created
        requests_mock.post(
            f"{API_BASE}/sessions",
            json={"id": "s2", "status": "created"},
        )
        # GET /sessions/s2 progressively
        responses = [
            {"json": {"id": "s2", "status": "running", "stepCount": 1}},
            {"json": {"id": "s2", "status": "running", "stepCount": 2}},
            {"json": {"id": "s2", "status": "stopped", "stepCount": 3, "isTaskSuccessful": True,
                      "totalCostUsd": "0.42"}},
        ]
        requests_mock.get(f"{API_BASE}/sessions/s2", responses)
        # Avoid actually sleeping in the polling loop.
        mocker.patch("BrowserUse.time.sleep", return_value=None)

        result = task_run_command(
            client,
            args={"task": "go", "wait": "true", "poll_interval": "1", "poll_timeout": "60"},
            params={},
        )
        assert result.outputs["Status"] == "stopped"
        assert result.outputs["IsTaskSuccessful"] is True
        assert result.outputs["TotalCostUsd"] == "0.42"

    def test_task_run_wait_times_out_returns_last_view(self, client, requests_mock, mocker):
        requests_mock.post(f"{API_BASE}/sessions", json={"id": "s3", "status": "created"})
        # Always still running
        requests_mock.get(f"{API_BASE}/sessions/s3", json={"id": "s3", "status": "running", "stepCount": 1})
        mocker.patch("BrowserUse.time.sleep", return_value=None)
        # First call sets the deadline (=100+1=101). Every subsequent call returns a value far past that,
        # so the loop performs exactly one fetch and then exits with the last view.
        time_values = iter([100, 100.5])

        def _fake_time() -> float:
            try:
                return next(time_values)
            except StopIteration:
                return 1_000_000  # always past deadline

        mocker.patch("BrowserUse.time.time", side_effect=_fake_time)

        result = task_run_command(
            client,
            args={"task": "go", "wait": "true", "poll_interval": "1", "poll_timeout": "1"},
            params={},
        )
        # We accept whatever the last view was.
        assert result.outputs["ID"] == "s3"
        assert result.outputs["Status"] == "running"

    def test_task_get(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/sessions/s1",
            json={"id": "s1", "status": "stopped", "isTaskSuccessful": True, "output": "done",
                  "recordingUrls": ["https://r1"]},
        )
        result = task_get_command(client, args={"session_id": "s1"})
        assert result.outputs["Status"] == "stopped"
        assert result.outputs["RecordingUrls"] == ["https://r1"]

    def test_task_list(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/sessions",
            json={"sessions": [{"id": "s1", "status": "stopped"}, {"id": "s2", "status": "running"}],
                  "total": 2, "page": 1, "pageSize": 50},
        )
        result = task_list_command(client, args={})
        assert isinstance(result.outputs, list)
        assert {o["ID"] for o in result.outputs} == {"s1", "s2"}

    def test_task_stop_session_strategy(self, client, requests_mock):
        m = requests_mock.post(f"{API_BASE}/sessions/s1/stop", status_code=204)
        result = task_stop_command(client, args={"session_id": "s1", "strategy": "task"})
        assert m.called
        body = m.last_request.json()
        assert body == {"strategy": "task"}
        assert result.outputs["ID"] == "s1"
        assert result.outputs["Status"] == "stopped"

    def test_task_messages_list(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/sessions/s1/messages",
            json={"messages": [
                {"id": "m1", "sessionId": "s1", "role": "ai", "type": "browser_action", "summary": "click",
                 "createdAt": "2026-04-28T12:00:00Z"},
                {"id": "m2", "sessionId": "s1", "role": "ai", "type": "assistant_message", "summary": "done",
                 "createdAt": "2026-04-28T12:01:00Z"},
            ], "hasMore": False},
        )
        result = task_messages_list_command(client, args={"session_id": "s1"})
        assert result.outputs["SessionID"] == "s1"
        assert result.outputs["HasMore"] is False
        assert len(result.outputs["Messages"]) == 2
        assert result.outputs["Messages"][0]["ID"] == "m1"

    def test_task_screenshot_present(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/sessions/s1", json={"id": "s1", "screenshotUrl": "https://shot"})
        result = task_screenshot_get_command(client, args={"session_id": "s1"})
        assert result.outputs["ScreenshotUrl"] == "https://shot"
        assert "Open screenshot" in result.readable_output

    def test_task_screenshot_absent(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/sessions/s1", json={"id": "s1"})
        result = task_screenshot_get_command(client, args={"session_id": "s1"})
        assert "No screenshot available" in result.readable_output


# ---------------------------------------------------------------------------
# Browser sessions
# ---------------------------------------------------------------------------

class TestBrowsers:
    def test_browser_create_uses_param_defaults(self, client, requests_mock):
        m = requests_mock.post(
            f"{API_BASE}/browsers",
            json={"id": "b1", "status": "active", "liveUrl": "https://l", "cdpUrl": "wss://c"},
        )
        result = browser_create_command(
            client,
            args={},
            params={"default_proxy_country": "us", "default_session_timeout_min": "60"},
        )
        assert m.called
        body = m.last_request.json()
        assert body["proxyCountryCode"] == "us"
        assert body["timeout"] == 60
        assert result.outputs["ID"] == "b1"
        assert result.outputs["LiveUrl"] == "https://l"

    def test_browser_get(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/browsers/b1", json={"id": "b1", "status": "active"})
        result = browser_get_command(client, args={"session_id": "b1"})
        assert result.outputs["ID"] == "b1"

    def test_browser_list(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/browsers",
            json={"sessions": [{"id": "b1", "status": "active"}, {"id": "b2", "status": "stopped"}]},
        )
        result = browser_list_command(client, args={})
        assert {o["ID"] for o in result.outputs} == {"b1", "b2"}

    def test_browser_stop(self, client, requests_mock):
        m = requests_mock.patch(f"{API_BASE}/browsers/b1", json={"id": "b1", "status": "stopped"})
        result = browser_stop_command(client, args={"session_id": "b1"})
        assert m.called
        assert m.last_request.json() == {"action": "stop"}
        assert result.outputs["ID"] == "b1"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

class TestProfiles:
    def test_profile_list(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/profiles",
            json={"profiles": [{"id": "p1", "name": "main"}, {"id": "p2", "name": "alt"}]},
        )
        result = profile_list_command(client, args={})
        assert {o["ID"] for o in result.outputs} == {"p1", "p2"}

    def test_profile_get(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/profiles/p1", json={"id": "p1", "name": "main"})
        result = profile_get_command(client, args={"profile_id": "p1"})
        assert result.outputs["Name"] == "main"

    def test_profile_create(self, client, requests_mock):
        requests_mock.post(f"{API_BASE}/profiles", json={"id": "p9", "name": "fresh", "userId": "u1"})
        result = profile_create_command(client, args={"name": "fresh", "user_id": "u1"})
        assert result.outputs["ID"] == "p9"

    def test_profile_delete(self, client, requests_mock):
        requests_mock.delete(f"{API_BASE}/profiles/p1", status_code=204)
        result = profile_delete_command(client, args={"profile_id": "p1"})
        assert "deleted" in result.readable_output


# ---------------------------------------------------------------------------
# Workspaces
# ---------------------------------------------------------------------------

class TestWorkspaces:
    def test_workspace_list(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/workspaces",
            json={"workspaces": [{"id": "w1", "name": "intel"}]},
        )
        result = workspace_list_command(client, args={})
        assert result.outputs[0]["Name"] == "intel"

    def test_workspace_get(self, client, requests_mock):
        requests_mock.get(f"{API_BASE}/workspaces/w1", json={"id": "w1", "name": "intel"})
        result = workspace_get_command(client, args={"workspace_id": "w1"})
        assert result.outputs["Name"] == "intel"

    def test_workspace_create(self, client, requests_mock):
        requests_mock.post(f"{API_BASE}/workspaces", json={"id": "w9", "name": "new"})
        result = workspace_create_command(client, args={"name": "new"})
        assert result.outputs["ID"] == "w9"

    def test_workspace_delete(self, client, requests_mock):
        requests_mock.delete(f"{API_BASE}/workspaces/w1", status_code=204)
        result = workspace_delete_command(client, args={"workspace_id": "w1"})
        assert "deleted" in result.readable_output

    def test_workspace_files_list(self, client, requests_mock):
        requests_mock.get(
            f"{API_BASE}/workspaces/w1/files",
            json={"files": [
                {"path": "a.txt", "size": 12, "lastModified": "2026-04-28T12:00:00Z"},
                {"path": "b.json", "size": 50, "lastModified": "2026-04-28T12:01:00Z", "url": "https://x"},
            ]},
        )
        result = workspace_files_list_command(
            client, args={"workspace_id": "w1", "include_urls": "true"}
        )
        assert result.outputs["ID"] == "w1"
        assert len(result.outputs["Files"]) == 2
        assert result.outputs["Files"][1]["Url"] == "https://x"
