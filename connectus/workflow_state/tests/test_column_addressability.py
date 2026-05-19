"""Tests for 1-based column-number addressability.

The CLI verbs ``show-step``, ``markpass``, ``skip``, ``fail``, and
``reset-to`` all route their column argument through
:func:`workflow_state.cli._resolve_column_or_exit`, which in turn calls
:meth:`workflow_state.types.WorkflowConfig.resolve_column_ref`.

These tests exercise the resolver via the two CLI verbs that exercise
both ends of the ``allow_identity`` switch:

  * ``show-step`` — read-only, identity columns ALLOWED;
  * ``markpass`` — write, identity columns FORBIDDEN.

If the CSV schema shifts (e.g. a step is reordered), the hard-coded
column numbers below need to update too. The expected-column assertions
at the top of the file are the canary.
"""
from __future__ import annotations

import csv as _csv
from pathlib import Path

import pytest

import workflow_state
from workflow_state import cli as wf_cli
from workflow_state.config_loader import _reset_config_for_testing


# ---------------------------------------------------------------------------
# Schema canaries — these encode the expected column positions in the
# bundled YAML (3 identity columns + 16 steps). If the YAML shifts, fix
# these numbers in lock-step with the column references below.
# ---------------------------------------------------------------------------

_EXPECTED_TOTAL_COLS = 19
_COL_INTEGRATION_ID = 1          # identity (allowed for show-step)
_COL_AUTH_DETAILS = 5            # step #2 → CSV column 5
_COL_VERIFY_PLACEMENT = 7        # step #4 → CSV column 7
_COL_GENERATED_MANIFEST = 10     # step #7 → CSV column 10 (first checkpoint, after Params for test with default in code + Params to Capabilities)


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


@pytest.fixture
def temp_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Seed a CSV with steps 1-6 already done so ``markpass <id> 10``
    (the first checkpoint, ``generated manifest``) is at the workflow's
    current step. Identity + earlier data/flag steps are pre-filled."""
    cfg = workflow_state.get_config()
    header = list(cfg.all_columns)
    p = tmp_path / "pipeline.csv"
    row = {col: "" for col in header}
    row["Integration ID"] = "TestInt"
    row["Integration File Path"] = "Packs/X/Integrations/X/X.yml"
    row["Connector ID"] = "ConnX"
    row["assignee"] = "tester"
    row["Auth Details"] = "{}"
    row["Params to Commands"] = "{}"
    row["verify button placement"] = "connection"
    row["Params for test with default in code"] = "{}"
    row["Params to Capabilities"] = "{}"
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        w.writerow(header)
        w.writerow([row[col] for col in header])
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(p))
    return p


def test_schema_canary(temp_csv: Path) -> None:
    """Sanity-check the column numbers this file hard-codes."""
    cfg = workflow_state.get_config()
    cols = cfg.all_columns
    assert len(cols) == _EXPECTED_TOTAL_COLS
    assert cols[_COL_INTEGRATION_ID - 1] == "Integration ID"
    assert cols[_COL_AUTH_DETAILS - 1] == "Auth Details"
    assert cols[_COL_VERIFY_PLACEMENT - 1] == "verify button placement"
    assert cols[_COL_GENERATED_MANIFEST - 1] == "generated manifest"


# ---------------------------------------------------------------------------
# show-step (read-only; identity columns allowed)
# ---------------------------------------------------------------------------

def test_show_step_resolves_auth_details_by_number(temp_csv: Path, capsys) -> None:
    wf_cli.cmd_show_step(["TestInt", str(_COL_AUTH_DETAILS)])
    out = capsys.readouterr().out
    assert "Auth Details" in out


def test_show_step_resolves_verify_placement_by_number(temp_csv: Path, capsys) -> None:
    wf_cli.cmd_show_step(["TestInt", str(_COL_VERIFY_PLACEMENT)])
    out = capsys.readouterr().out
    assert "verify button placement" in out


def test_show_step_resolves_identity_column_by_number(temp_csv: Path, capsys) -> None:
    wf_cli.cmd_show_step(["TestInt", str(_COL_INTEGRATION_ID)])
    out = capsys.readouterr().out
    assert "Integration ID" in out


# ---------------------------------------------------------------------------
# show-step --raw (machine-consumer contract; no header, no pretty-printing)
# ---------------------------------------------------------------------------

def test_show_step_raw_emits_cell_verbatim(temp_csv: Path, capsys) -> None:
    """--raw on a non-empty cell prints only the raw cell value + newline."""
    wf_cli.cmd_show_step(["--raw", "TestInt", "Auth Details"])
    out = capsys.readouterr().out
    # The fixture seeds Auth Details = "{}". With --raw we must get
    # exactly that — no header, no decoration, no pretty-printing.
    assert out == "{}\n"


def test_show_step_raw_empty_cell_prints_nothing(temp_csv: Path, capsys) -> None:
    """--raw on an empty cell emits no output at all (not even a default)."""
    # ``Params to Capabilities`` is seeded to "{}" in the fixture; clear it
    # by writing an empty string directly into the loaded row so we can
    # exercise the empty-cell branch.
    wf_cli.cmd_show_step(["--raw", "TestInt", "generated manifest"])
    out = capsys.readouterr().out
    assert out == ""


def test_show_step_raw_flag_position_insensitive(temp_csv: Path, capsys) -> None:
    """--raw may appear anywhere in argv (before, between, or after positionals)."""
    wf_cli.cmd_show_step(["TestInt", "Auth Details", "--raw"])
    out = capsys.readouterr().out
    assert out == "{}\n"


def test_show_step_raw_skips_flag_default(temp_csv: Path, capsys) -> None:
    """--raw must NOT substitute the read-side default for empty flag cells.

    The decorated form of ``verify button placement`` prints
    ``connection (default; cell empty)`` when the cell is empty. ``--raw``
    must instead emit nothing for an empty cell (the fixture seeds it,
    so we re-clear by writing an empty value first).
    """
    # The fixture seeds verify-placement = "connection". Reach into the
    # CSV directly to clear it, then verify --raw emits "".
    import csv as _csv
    with open(temp_csv, "r", encoding="utf-8", newline="") as fh:
        rows = list(_csv.reader(fh))
    header = rows[0]
    col_idx = header.index("verify button placement")
    rows[1][col_idx] = ""
    with open(temp_csv, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerows(rows)

    wf_cli.cmd_show_step(["--raw", "TestInt", "verify button placement"])
    out = capsys.readouterr().out
    assert out == ""


def test_show_step_no_raw_still_decorates(temp_csv: Path, capsys) -> None:
    """Default (no --raw) output continues to include the decorative header."""
    wf_cli.cmd_show_step(["TestInt", "Auth Details"])
    out = capsys.readouterr().out
    assert "=" in out
    assert "Auth Details" in out


# ---------------------------------------------------------------------------
# markpass (write; identity columns forbidden)
# ---------------------------------------------------------------------------

def test_markpass_resolves_checkpoint_by_number(temp_csv: Path, capsys) -> None:
    """markpass <id> 8 → 'generated manifest' (first checkpoint)."""
    wf_cli.cmd_markpass(["TestInt", str(_COL_GENERATED_MANIFEST)])
    out = capsys.readouterr().out
    assert "generated manifest" in out
    # Verify it actually landed in the cell.
    with open(temp_csv, "r", encoding="utf-8", newline="") as f:
        r = _csv.reader(f)
        header = next(r)
        row = next(r)
    col_idx = header.index("generated manifest")
    assert row[col_idx] == "✅"


def test_markpass_rejects_identity_column_by_number(temp_csv: Path, capsys) -> None:
    """Identity columns can be NAMED but not WRITTEN to via markpass."""
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_markpass(["TestInt", str(_COL_INTEGRATION_ID)])
    assert exc.value.code == 1
    err = capsys.readouterr().out
    # Error message should mention the identity-column rejection.
    assert "identity" in err.lower()
    assert "#1" in err or "1 " in err  # the column number is named


def test_markpass_rejects_out_of_range_high(temp_csv: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_markpass(["TestInt", "99"])
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "between 1 and" in err
    assert str(_EXPECTED_TOTAL_COLS) in err


def test_markpass_rejects_out_of_range_zero(temp_csv: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_markpass(["TestInt", "0"])
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "between 1 and" in err


def test_markpass_negative_falls_through_to_name_resolution(
    temp_csv: Path, capsys
) -> None:
    """``-1`` is not all-digits → resolver treats it as a name → unknown column."""
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_markpass(["TestInt", "-1"])
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "unknown column" in err.lower()
    assert "-1" in err


def test_markpass_garbage_string_falls_through_to_name_resolution(
    temp_csv: Path, capsys
) -> None:
    """Non-digit strings go through the name-lookup branch → unknown column."""
    with pytest.raises(SystemExit) as exc:
        wf_cli.cmd_markpass(["TestInt", "abc"])
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "unknown column" in err.lower()
    assert "abc" in err
