"""Tests for the ``Connector Folder Path`` identity column (Phase 0b).

Covers:
  * The config exposes the column as the 4th identity column.
  * ``set-connector-path`` writes the cell and rejects empty input
    (and does NOT cascade-reset workflow steps — identity write).
  * ``context`` surfaces ``connector_folder_path``.
  * ``status`` header surfaces a ``Connector Folder:`` line.
  * ``show-step <id> 4`` resolves to the new identity column.
"""
from __future__ import annotations

import csv as _csv
import json
from pathlib import Path

import pytest

import workflow_state
from workflow_state import cli as wf_cli
from workflow_state.api import set_integration_connector_path
from workflow_state.config_loader import _reset_config_for_testing

_COL_CONNECTOR_FOLDER_PATH = 4  # identity column #4 (after Connector ID)


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


@pytest.fixture
def temp_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Seed a CSV (with the current schema) with one row whose workflow
    columns are all done, so we can assert that an identity write does
    NOT disturb them."""
    cfg = workflow_state.get_config()
    header = list(cfg.all_columns)
    p = tmp_path / "pipeline.csv"
    row = {col: "" for col in header}
    row["Integration ID"] = "TestInt"
    row["Integration File Path"] = "Packs/X/Integrations/X/X.yml"
    row["Connector ID"] = "ConnX"
    # Connector Folder Path intentionally left blank (populated at creation time).
    row["assignee"] = "tester"
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        w.writerow(header)
        w.writerow([row[col] for col in header])
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(p))
    return p


def _read_cell(csv_path: Path, integration_id: str, column: str) -> str:
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        for r in _csv.DictReader(f):
            if r.get("Integration ID") == integration_id:
                return r.get(column, "")
    raise AssertionError(f"row {integration_id!r} not found")


# ---------------------------------------------------------------------------
# Config / schema
# ---------------------------------------------------------------------------

def test_connector_folder_path_is_fourth_identity_column() -> None:
    cfg = workflow_state.get_config()
    names = cfg.identity_column_names
    assert names[3] == "Connector Folder Path"
    assert cfg.all_columns[_COL_CONNECTOR_FOLDER_PATH - 1] == "Connector Folder Path"


# ---------------------------------------------------------------------------
# api setter
# ---------------------------------------------------------------------------

def test_set_connector_path_writes_cell(temp_csv: Path) -> None:
    result = set_integration_connector_path("TestInt", "connectors/salesforce")
    assert result.get("connector_folder_path") == "connectors/salesforce"
    assert _read_cell(temp_csv, "TestInt", "Connector Folder Path") == "connectors/salesforce"


def test_set_connector_path_strips_whitespace(temp_csv: Path) -> None:
    set_integration_connector_path("TestInt", "  connectors/salesforce  ")
    assert _read_cell(temp_csv, "TestInt", "Connector Folder Path") == "connectors/salesforce"


def test_set_connector_path_rejects_empty(temp_csv: Path) -> None:
    result = set_integration_connector_path("TestInt", "   ")
    assert "error" in result
    assert _read_cell(temp_csv, "TestInt", "Connector Folder Path") == ""


def test_set_connector_path_unknown_integration(temp_csv: Path) -> None:
    result = set_integration_connector_path("DoesNotExist", "connectors/x")
    assert "error" in result


def test_set_connector_path_does_not_cascade_reset(temp_csv: Path) -> None:
    """Writing the identity column must not clear workflow steps."""
    cfg = workflow_state.get_config()
    # Mark a checkpoint done first.
    rows = workflow_state.load_csv()
    idx = next(i for i, r in enumerate(rows) if r["Integration ID"] == "TestInt")
    first_checkpoint = next(s for s in cfg.steps if s.kind == "checkpoint")
    # Fill all steps before the checkpoint so it's reachable, then mark it.
    for s in cfg.steps:
        if s.index < first_checkpoint.index:
            rows[idx][s.name] = "{}" if s.kind == "data" else "✅"
    rows[idx][first_checkpoint.name] = "✅"
    workflow_state.save_csv(rows)

    set_integration_connector_path("TestInt", "connectors/salesforce")

    assert _read_cell(temp_csv, "TestInt", first_checkpoint.name) == "✅"
    assert _read_cell(temp_csv, "TestInt", "Connector Folder Path") == "connectors/salesforce"


# ---------------------------------------------------------------------------
# CLI setter
# ---------------------------------------------------------------------------

def test_cmd_set_connector_path(temp_csv: Path, capsys) -> None:
    wf_cli.cmd_set_connector_path(["TestInt", "connectors/salesforce"])
    out = capsys.readouterr().out
    assert "connectors/salesforce" in out
    assert _read_cell(temp_csv, "TestInt", "Connector Folder Path") == "connectors/salesforce"


def test_cmd_set_connector_path_empty_exits(temp_csv: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_set_connector_path(["TestInt", ""])
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# Read surfacing: context / show-step / status
# ---------------------------------------------------------------------------

def test_context_surfaces_connector_folder_path(temp_csv: Path, capsys) -> None:
    set_integration_connector_path("TestInt", "connectors/salesforce")
    wf_cli.cmd_context(["TestInt"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["connector_folder_path"] == "connectors/salesforce"


def test_show_step_resolves_connector_folder_path_by_number(temp_csv: Path, capsys) -> None:
    set_integration_connector_path("TestInt", "connectors/salesforce")
    wf_cli.cmd_show_step(["TestInt", str(_COL_CONNECTOR_FOLDER_PATH)])
    out = capsys.readouterr().out
    assert "Connector Folder Path" in out
    assert "connectors/salesforce" in out


def test_status_header_shows_connector_folder(temp_csv: Path, capsys) -> None:
    set_integration_connector_path("TestInt", "connectors/salesforce")
    wf_cli.cmd_status(["TestInt"])
    out = capsys.readouterr().out
    assert "Connector Folder:" in out
    assert "connectors/salesforce" in out
