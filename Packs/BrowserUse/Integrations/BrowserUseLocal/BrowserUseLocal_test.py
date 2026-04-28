"""Unit tests for the Browser Use Local integration.

The tests intentionally avoid importing the real `browser_use` library — they
inject a fake ``browser_use`` module into ``sys.modules`` so the integration
code paths can be exercised without Chromium or LLM SDKs being present.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest


# --------------------------------------------------------------------------- #
# Fake `browser_use` module — installed once at collection time
# --------------------------------------------------------------------------- #


class _FakeChat:
    """Stand-in for ChatBrowserUse / ChatAnthropic / ChatGoogle / ChatOpenAI."""

    instances: list["_FakeChat"] = []

    def __init__(self, model: str | None = None, api_key: str | None = None):
        self.model = model
        self.api_key = api_key
        _FakeChat.instances.append(self)


class _FakeBrowser:
    instances: list["_FakeBrowser"] = []

    def __init__(self, headless: bool = True, use_cloud: bool = False, api_key: str | None = None):
        self.headless = headless
        self.use_cloud = use_cloud
        self.api_key = api_key
        _FakeBrowser.instances.append(self)


class _FakeHistory:
    def __init__(self, output: Any, done: bool = True, success: bool | None = True,
                 urls: list[str] | None = None):
        self._output = output
        self._done = done
        self._success = success
        self._urls = urls or []

    def final_result(self):
        return self._output

    def is_done(self):
        return self._done

    def is_successful(self):
        return self._success

    def urls(self):
        return self._urls


class _FakeAgent:
    last_kwargs: dict[str, Any] = {}

    def __init__(self, task: str, llm: Any, browser: Any, output_model: Any | None = None):
        _FakeAgent.last_kwargs = {"task": task, "llm": llm, "browser": browser, "output_model": output_model}

    async def run(self, max_steps: int | None = None):  # noqa: ARG002
        return _FakeHistory(output={"summary": "ok", "echo": _FakeAgent.last_kwargs["task"]},
                            urls=["https://example.com"])


def _install_fake_browser_use() -> None:
    fake = types.ModuleType("browser_use")
    fake.ChatBrowserUse = _FakeChat  # type: ignore[attr-defined]
    fake.ChatAnthropic = _FakeChat  # type: ignore[attr-defined]
    fake.ChatGoogle = _FakeChat  # type: ignore[attr-defined]
    fake.ChatOpenAI = _FakeChat  # type: ignore[attr-defined]
    fake.Browser = _FakeBrowser  # type: ignore[attr-defined]
    fake.Agent = _FakeAgent  # type: ignore[attr-defined]
    fake.__version__ = "0.0.0-test"  # type: ignore[attr-defined]
    sys.modules["browser_use"] = fake


_install_fake_browser_use()

# Now we can import the integration safely.
from BrowserUseLocal import (  # noqa: E402
    INTEGRATION_CONTEXT,
    _build_llm,
    agent_run_command,
    test_module,
    version_command,
)
from CommonServerPython import DemistoException  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_fakes():
    _FakeChat.instances.clear()
    _FakeBrowser.instances.clear()
    _FakeAgent.last_kwargs = {}
    yield


# --------------------------------------------------------------------------- #
# LLM factory
# --------------------------------------------------------------------------- #


class TestBuildLlm:
    def test_browser_use_default_model(self):
        llm = _build_llm("browser-use", None, "bu_test")
        assert llm.model == "browser-use/bu-30b-a3b-preview"
        assert llm.api_key == "bu_test"

    def test_anthropic_sets_env(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        _build_llm("anthropic", "claude-sonnet-4-6", "sk-ant-test")
        import os
        assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-test"

    def test_unknown_provider_raises(self):
        with pytest.raises(DemistoException, match="Unsupported llm_provider"):
            _build_llm("nonsense", None, "x")


# --------------------------------------------------------------------------- #
# test-module
# --------------------------------------------------------------------------- #


class TestTestModule:
    def test_ok_with_browser_use_provider(self):
        assert test_module({"llm_provider": "browser-use"}) == "ok"

    def test_anthropic_requires_key(self):
        result = test_module({"llm_provider": "anthropic"})
        assert "API Key is required" in result

    def test_anthropic_ok_with_key(self):
        assert test_module({"llm_provider": "anthropic", "llm_credentials": {"password": "sk"}}) == "ok"


# --------------------------------------------------------------------------- #
# agent-run
# --------------------------------------------------------------------------- #


class TestAgentRun:
    def test_requires_task(self):
        with pytest.raises(DemistoException, match="`task` is required"):
            agent_run_command({}, {})

    def test_basic_run(self):
        params = {"llm_provider": "browser-use", "default_headless": "true"}
        args = {"task": "do something"}
        result = agent_run_command(params, args)
        assert result.outputs["Task"] == "do something"
        assert result.outputs["Provider"] == "browser-use"
        assert result.outputs["IsDone"] is True
        assert result.outputs["IsSuccessful"] is True
        assert result.outputs["VisitedUrls"] == ["https://example.com"]
        assert result.outputs["FinalOutput"] == {"summary": "ok", "echo": "do something"}
        assert result.outputs_prefix == f"{INTEGRATION_CONTEXT}.AgentRun"
        # browser was created headless and not cloud-backed
        assert _FakeBrowser.instances[-1].headless is True
        assert _FakeBrowser.instances[-1].use_cloud is False

    def test_use_cloud_browser_requires_key(self):
        params = {"llm_provider": "browser-use", "default_use_cloud_browser": "true"}
        with pytest.raises(DemistoException, match="use_cloud_browser=true"):
            agent_run_command(params, {"task": "go"})

    def test_use_cloud_browser_with_key(self):
        params = {
            "llm_provider": "browser-use",
            "default_use_cloud_browser": "true",
            "cloud_credentials": {"password": "bu_cloud_key"},
        }
        result = agent_run_command(params, {"task": "go"})
        assert _FakeBrowser.instances[-1].use_cloud is True
        assert _FakeBrowser.instances[-1].api_key == "bu_cloud_key"
        assert result.outputs["IsDone"] is True

    def test_invalid_output_schema(self):
        with pytest.raises(DemistoException, match="must be valid JSON"):
            agent_run_command(
                {"llm_provider": "browser-use"},
                {"task": "go", "output_schema": "{not-json"},
            )

    def test_output_schema_passed_to_agent(self):
        agent_run_command(
            {"llm_provider": "browser-use"},
            {"task": "go", "output_schema": '{"type":"object","properties":{"x":{"type":"string"}}}'},
        )
        assert _FakeAgent.last_kwargs["output_model"] == {
            "type": "object",
            "properties": {"x": {"type": "string"}},
        }

    def test_per_command_provider_override(self):
        # Configure instance with browser-use, but call with anthropic+key
        params = {"llm_provider": "browser-use", "llm_credentials": {"password": "sk-ant-1"}}
        args = {"task": "go", "llm_provider": "anthropic", "model": "claude-sonnet-4-6"}
        result = agent_run_command(params, args)
        assert result.outputs["Provider"] == "anthropic"
        assert result.outputs["Model"] == "claude-sonnet-4-6"


# --------------------------------------------------------------------------- #
# version
# --------------------------------------------------------------------------- #


class TestVersion:
    def test_version_command(self):
        result = version_command()
        assert result.outputs["BrowserUseVersion"] == "0.0.0-test"
