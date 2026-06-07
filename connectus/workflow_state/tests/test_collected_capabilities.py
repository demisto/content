"""Tests for ``workflow_state.api.collected_capabilities``.

This helper backs the single-capability optimization in the params
analyzer (``check_command_params.py --single-capability-test-module-only``):
when an integration resolves to exactly one collected capability, every
command trivially routes to it, so only ``test-module`` needs per-command
analysis for the connection.

Unlike ``test_module_params``, a missing/empty/unparseable cell must
degrade to ``[]`` (full-analysis fallback) rather than raise.
"""
from __future__ import annotations

import pytest

import workflow_state as ws
from workflow_state import collected_capabilities


def _make_row(**overrides: str) -> dict[str, str]:
    row = {
        "Integration ID": "MyIntegration",
        "Integration File Path": "Templates/Integrations/Authentication/Authentication.yml",
        "Connector ID": "fake-connector",
        "assignee": "Jane Doe",
        "Auth Details": "",
        "Collect Capabilities": "",
        "Params to Commands": "",
        "Params for test with default in code": "",
        "Params to Capabilities": "",
        "Release Notes": "",
    }
    row.update(overrides)
    return row


@pytest.fixture
def patch_csv(monkeypatch: pytest.MonkeyPatch):
    def _set(rows: list[dict[str, str]]) -> None:
        monkeypatch.setattr(ws, "load_csv", lambda: rows)
    return _set


class TestCollectedCapabilities:
    def test_single_capability_returns_one_entry(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": '["Automation"]'})])
        assert collected_capabilities("MyIntegration") == ["Automation"]

    def test_multiple_capabilities_returns_all(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": '["Fetch Issues", "Automation"]'})])
        assert collected_capabilities("MyIntegration") == ["Fetch Issues", "Automation"]

    def test_empty_cell_returns_empty_list(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": ""})])
        assert collected_capabilities("MyIntegration") == []

    def test_empty_json_list_returns_empty_list(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": "[]"})])
        assert collected_capabilities("MyIntegration") == []

    def test_unparseable_cell_degrades_to_empty(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": "not json{"})])
        assert collected_capabilities("MyIntegration") == []

    def test_non_list_json_degrades_to_empty(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": '{"a": 1}'})])
        assert collected_capabilities("MyIntegration") == []

    def test_non_string_entries_are_filtered_out(self, patch_csv) -> None:
        patch_csv([_make_row(**{"Collect Capabilities": '["Automation", 1, "", null]'})])
        assert collected_capabilities("MyIntegration") == ["Automation"]

    def test_missing_integration_returns_empty(self, patch_csv) -> None:
        patch_csv([_make_row()])
        assert collected_capabilities("DoesNotExist") == []
