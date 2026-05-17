"""Tests for the ``verify button placement`` flag column.

These tests drive the CLI's ``set-verify-placement`` and ``show-step``
verbs end-to-end against a throwaway pipeline CSV so the real CSV is
never touched.

Covers:
  * enum acceptance for each of ``connection`` / ``configuration`` /
    ``none``;
  * enum rejection with a message that names the valid values;
  * default-on-read fallback (empty cell → ``connection``).
"""
from __future__ import annotations

import csv as _csv
from io import StringIO
from pathlib import Path

import pytest

import workflow_state
from workflow_state import cli as wf_cli
from workflow_state.config_loader import _reset_config_for_testing


_FLAG_COLUMN = "verify button placement"
_VALID_VALUES = ("connection", "configuration", "none")
_DEFAULT_VALUE = "connection"


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


@pytest.fixture
def temp_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point workflow_state at a throwaway pipeline CSV seeded with one row.

    The seed pre-fills the three ``data`` steps preceding ``verify button
    placement`` (assignee + Auth Details + Params to Commands) with non-
    empty strings — for ``data`` kind steps, ``is_done`` just checks for
    non-emptiness, so any string puts the workflow's "current step" at #4.
    """
    cfg = workflow_state.get_config()
    header = list(cfg.all_columns)
    p = tmp_path / "pipeline.csv"
    row = {col: "" for col in header}
    row["Integration ID"] = "TestInt"
    row["Integration File Path"] = "Packs/X/Integrations/X/X.yml"
    row["Connector ID"] = "ConnX"
    # Sentinel-ish non-empty strings to put current step at #4
    # (verify button placement). The state machine doesn't validate
    # JSON shape on read for current_step purposes, only on the setter.
    row["assignee"] = "tester"
    row["Auth Details"] = "{}"
    row["Params to Commands"] = "{}"
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        w.writerow(header)
        w.writerow([row[col] for col in header])
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(p))
    return p


def _capture_show_step(integration: str, column: str, capsys) -> str:
    """Run ``show-step`` and return the captured stdout."""
    wf_cli.cmd_show_step([integration, column])
    return capsys.readouterr().out


@pytest.mark.parametrize("value", _VALID_VALUES)
def test_set_verify_placement_accepts_each_enum_value(
    temp_csv: Path, capsys, value: str
) -> None:
    wf_cli.cmd_set_verify_placement(["TestInt", value])
    out = _capture_show_step("TestInt", _FLAG_COLUMN, capsys)
    assert value in out
    # The "(default; cell empty)" marker should NOT appear once explicitly set.
    assert "default" not in out.lower() or "cell empty" not in out.lower()


def test_set_verify_placement_rejects_unknown_value(temp_csv: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_set_verify_placement(["TestInt", "garbage"])
    assert exc.value.code == 1
    err = capsys.readouterr().out
    # Error message should name the valid values.
    for valid in _VALID_VALUES:
        assert valid in err, f"expected {valid!r} in error message:\n{err}"


def test_default_on_read_for_empty_cell(temp_csv: Path, capsys) -> None:
    # Don't call set-verify-placement: the cell is empty.
    out = _capture_show_step("TestInt", _FLAG_COLUMN, capsys)
    assert _DEFAULT_VALUE in out
    # The marker that the cell was empty should be present.
    assert "default" in out.lower()


def test_set_then_readback_via_column_number(temp_csv: Path, capsys) -> None:
    """``verify button placement`` lives at CSV column #7 (3 identity + step #4)."""
    cfg = workflow_state.get_config()
    expected_csv_col = len(cfg.identity_columns) + cfg.step_by_name[_FLAG_COLUMN].index
    assert expected_csv_col == 7, "schema drift: verify button placement is no longer at column 7"

    wf_cli.cmd_set_verify_placement(["TestInt", "configuration"])
    out = _capture_show_step("TestInt", "7", capsys)
    assert "configuration" in out
    assert _FLAG_COLUMN in out


def test_persisted_value_round_trips_on_disk(temp_csv: Path) -> None:
    """The value lands in the right column on disk."""
    wf_cli.cmd_set_verify_placement(["TestInt", "none"])
    with open(temp_csv, "r", encoding="utf-8", newline="") as f:
        r = _csv.reader(f)
        header = next(r)
        row = next(r)
    col_idx = header.index(_FLAG_COLUMN)
    assert row[col_idx] == "none"
