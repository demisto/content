"""Tests for the read-only ``context`` verb and ``status --format=json``.

Covers:

1. ``cmd_context`` on a known fixture id emits valid JSON with all
   expected top-level keys, the correct file paths, and the current
   step (composed from the existing api.py helpers).
2. ``cmd_context`` reuses :func:`auth_param_ids` — when an ``Auth
   Details`` cell is set, the derived ignore params appear under
   ``auth_ignore_params``.
3. ``cmd_context`` on an unknown id exits non-zero with a clear error
   on stderr (mirrors ``files`` / ``auth-params``).
4. ``cmd_context`` degrades gracefully when the Integration File Path
   is stale: it emits ``file_paths: null`` + a ``file_paths_error`` key
   and still emits the rest of the document.
5. ``status --format=json`` returns parseable JSON (a list, one element
   per requested id); ``status`` with no flag produces the historical
   text output unchanged.

Like the dry-run tests, these mock the package-level ``load_csv`` so the
verb sees an in-process fixture row. ``save_csv`` is wired to explode —
``context`` and the ``status`` read path must never mutate the CSV.
"""
from __future__ import annotations

import json

import pytest

import workflow_state as ws
from workflow_state import cli as ws_cli
from workflow_state.api import auth_param_ids
from workflow_state.display import format_status


# A real on-disk integration that ships with the repo, used so
# get_integration_files (which resolves paths relative to BASE_DIR)
# returns real yml/code paths without us having to fabricate files.
_REAL_YML_REL = "Templates/Integrations/Authentication/Authentication.yml"

# A well-formed Auth Details payload whose APIKey profile declares one
# xsoar param id (``api_key`` → projected to ``key``) plus an
# other_connection entry. auth_param_ids() should surface both.
_AUTH_JSON = (
    '{"auth_types":[{"type":"APIKey","name":"primary",'
    '"xsoar_param_map":{"api_key":"key"}}],'
    '"other_connection":["url"]}'
)


def _make_row(**overrides: str) -> dict[str, str]:
    row = {
        "Integration ID": "MyIntegration",
        "Integration File Path": _REAL_YML_REL,
        "Connector ID": "fake-connector",
        "assignee": "Jane Doe",
        "Auth Details": "",
        "Params to Commands": "",
        "Params for test with default in code": "",
        "Params to Capabilities": "",
        "Release Notes": "",
    }
    row.update(overrides)
    return row


@pytest.fixture
def mock_csv(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    """Mock the package-level load_csv() so every module-local indirection
    (cli.load_csv / api.load_csv → workflow_state.load_csv) sees one row.
    save_csv explodes — these are read-only verbs.
    """
    rows = [_make_row()]
    monkeypatch.setattr(ws, "load_csv", lambda: rows)

    def _exploding_save(_rows):  # pragma: no cover — guard
        raise AssertionError("save_csv() must NOT be invoked by a read-only verb.")

    monkeypatch.setattr(ws, "save_csv", _exploding_save)
    return rows


# ---------------------------------------------------------------------------
# context — happy path
# ---------------------------------------------------------------------------


class TestContextHappyPath:
    def test_emits_all_expected_top_level_keys(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        ws_cli.cmd_context(["MyIntegration"])
        out = capsys.readouterr().out
        payload = json.loads(out)  # must be valid JSON

        expected = {
            "integration_id",
            "connector_id",
            "assignee",
            "file_paths",
            "data_columns",
            "auth_ignore_params",
            "current_step",
            "current_step_index",
            "completed_steps",
            "total_steps",
            "all_complete",
        }
        assert expected.issubset(set(payload.keys()))
        assert payload["integration_id"] == "MyIntegration"
        assert payload["connector_id"] == "fake-connector"
        assert payload["assignee"] == "Jane Doe"

    def test_file_paths_resolved_from_real_integration(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        ws_cli.cmd_context(["MyIntegration"])
        payload = json.loads(capsys.readouterr().out)

        fp = payload["file_paths"]
        assert fp is not None
        assert "file_paths_error" not in payload
        # The yml path should be the real relative path from the CSV row.
        assert fp["yml"] == _REAL_YML_REL
        # The Authentication template ships a .py and a _test.py.
        assert fp["code"] == "Templates/Integrations/Authentication/Authentication.py"
        assert (
            fp["test"]
            == "Templates/Integrations/Authentication/Authentication_test.py"
        )
        # All five canonical keys are present (even if some are null).
        assert set(fp.keys()) == {"yml", "code", "description", "readme", "test"}

    def test_current_step_matches_state_machine(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        # A fresh row (only identity + assignee) sits at the first
        # unfinished workflow step. context should surface that step.
        ws_cli.cmd_context(["MyIntegration"])
        payload = json.loads(capsys.readouterr().out)

        cur = ws.current_step(mock_csv[0])
        assert payload["current_step"] == (cur.name if cur else None)
        assert payload["current_step_index"] == (cur.index if cur else None)
        assert isinstance(payload["completed_steps"], int)
        assert isinstance(payload["all_complete"], bool)

    def test_data_columns_parsed_to_json_or_null(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        row = _make_row(**{"Params to Capabilities": '{"caps": ["a", "b"]}'})
        monkeypatch.setattr(ws, "load_csv", lambda: [row])
        monkeypatch.setattr(ws, "save_csv", lambda _r: None)

        ws_cli.cmd_context(["MyIntegration"])
        payload = json.loads(capsys.readouterr().out)

        dc = payload["data_columns"]
        # Set cell → parsed JSON value.
        assert dc["Params to Capabilities"] == {"caps": ["a", "b"]}
        # Unset cells → null.
        assert dc["Params to Commands"] is None
        assert dc["Release Notes"] is None


# ---------------------------------------------------------------------------
# context — auth_param_ids reuse
# ---------------------------------------------------------------------------


class TestContextAuthIgnoreParams:
    def test_auth_ignore_params_populated_when_auth_details_set(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        row = _make_row(**{"Auth Details": _AUTH_JSON})
        monkeypatch.setattr(ws, "load_csv", lambda: [row])
        monkeypatch.setattr(ws, "save_csv", lambda _r: None)

        ws_cli.cmd_context(["MyIntegration"])
        payload = json.loads(capsys.readouterr().out)

        # Reuses auth_param_ids → same set the standalone verb produces.
        expected = auth_param_ids("MyIntegration")
        assert payload["auth_ignore_params"] == expected
        assert payload["auth_ignore_params"]  # non-empty
        # Auth Details itself is surfaced (parsed) under data_columns.
        assert payload["data_columns"]["Auth Details"] == json.loads(_AUTH_JSON)

    def test_auth_ignore_params_empty_when_auth_unset(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        # No Auth Details → auth_param_ids would raise; context degrades
        # to an empty list rather than throwing.
        ws_cli.cmd_context(["MyIntegration"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["auth_ignore_params"] == []


# ---------------------------------------------------------------------------
# context — error / degradation paths
# ---------------------------------------------------------------------------


class TestContextErrors:
    def test_unknown_id_exits_non_zero_with_stderr_message(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_context(["DoesNotExist"])
        assert exc.value.code != 0
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "DoesNotExist" in err

    def test_missing_positional_exits_non_zero(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_context([])
        assert exc.value.code != 0
        assert "Usage" in capsys.readouterr().err

    def test_stale_file_path_degrades_gracefully(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        row = _make_row(
            **{"Integration File Path": "Packs/Nope/Integrations/Nope/Nope.yml"}
        )
        monkeypatch.setattr(ws, "load_csv", lambda: [row])
        monkeypatch.setattr(ws, "save_csv", lambda _r: None)

        # Must NOT raise — the rest of the document still emits.
        ws_cli.cmd_context(["MyIntegration"])
        payload = json.loads(capsys.readouterr().out)

        assert payload["file_paths"] is None
        assert "file_paths_error" in payload
        assert payload["file_paths_error"]
        # The rest is still present.
        assert payload["integration_id"] == "MyIntegration"
        assert "data_columns" in payload


# ---------------------------------------------------------------------------
# status --format=json
# ---------------------------------------------------------------------------


class TestStatusJsonFormat:
    def test_json_format_returns_parseable_list(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        ws_cli.cmd_status(["MyIntegration", "--format=json"])
        out = capsys.readouterr().out
        payload = json.loads(out)
        # Single id still yields a one-element list (stable shape).
        assert isinstance(payload, list)
        assert len(payload) == 1
        assert payload[0]["name"] == "MyIntegration"
        assert "current_step" in payload[0]
        assert "completed_steps" in payload[0]

    def test_json_format_unknown_id_surfaces_error_in_document(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        ws_cli.cmd_status(["MyIntegration", "Nope", "--format=json"])
        payload = json.loads(capsys.readouterr().out)
        assert isinstance(payload, list)
        assert len(payload) == 2
        assert payload[0]["name"] == "MyIntegration"
        assert "error" in payload[1]

    def test_invalid_format_exits_non_zero(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            ws_cli.cmd_status(["MyIntegration", "--format=xml"])
        assert exc.value.code != 0
        assert "format" in capsys.readouterr().err.lower()

    def test_text_output_unchanged_without_flag(
        self, mock_csv: list[dict[str, str]], capsys: pytest.CaptureFixture
    ) -> None:
        # No flag → byte-for-byte the historical format_status() rendering.
        ws_cli.cmd_status(["MyIntegration"])
        out = capsys.readouterr().out
        expected = format_status(mock_csv[0]) + "\n"
        assert out == expected
