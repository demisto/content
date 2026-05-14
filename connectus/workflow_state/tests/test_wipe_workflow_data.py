"""Tests for :func:`workflow_state.csv_io.wipe_workflow_data`.

These tests redirect ``workflow_state.CSV_PATH`` at the package level
(matching the existing ``csv_io._csv_path`` indirection) so the real
pipeline file is never touched.
"""
from __future__ import annotations

import csv as _csv
from pathlib import Path

import pytest

import workflow_state
from workflow_state.config_loader import _reset_config_for_testing
from workflow_state.csv_io import wipe_workflow_data


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


@pytest.fixture
def temp_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point workflow_state at a throwaway CSV inside ``tmp_path``."""
    p = tmp_path / "pipeline.csv"
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(p))
    return p


def _seed_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        r = _csv.reader(f)
        header = next(r)
        return header, [list(row) for row in r]


def test_refuses_without_confirm(temp_csv: Path) -> None:
    # Need a file on disk so the missing-confirm error fires before the
    # FileNotFoundError check.
    _seed_csv(
        temp_csv,
        ["Integration ID", "Integration File Path", "Connector ID"],
        [["a", "p/a.yml", "ConnA"]],
    )
    with pytest.raises(RuntimeError, match="confirm=True"):
        wipe_workflow_data()  # confirm defaults to False
    # The file is untouched.
    header, rows = _read_csv(temp_csv)
    assert header == ["Integration ID", "Integration File Path", "Connector ID"]
    assert rows == [["a", "p/a.yml", "ConnA"]]


def test_missing_csv_raises_file_not_found(temp_csv: Path) -> None:
    # temp_csv path is set but no file exists.
    with pytest.raises(FileNotFoundError):
        wipe_workflow_data(confirm=True, backup=False)


def test_wipes_workflow_columns_preserves_identity(temp_csv: Path) -> None:
    cfg = workflow_state.get_config()
    header = list(cfg.all_columns)
    # Two rows: one totally clean, one with several workflow cells filled.
    n_workflow = len(cfg.workflow_columns)
    row_clean = ["int-1", "Packs/X/x.yml", "ConnX"] + [""] * n_workflow
    row_dirty_values = ["✅"] * n_workflow
    row_dirty = ["int-2", "Packs/Y/y.yml", "ConnY"] + row_dirty_values
    _seed_csv(temp_csv, header, [row_clean, row_dirty])

    result = wipe_workflow_data(confirm=True, backup=False)

    assert result["rows"] == 2
    assert result["cells_cleared"] == n_workflow  # only row_dirty had data
    assert result["rows_touched"] == 1
    assert result["backup_path"] is None
    assert result["header"] == header

    new_header, new_rows = _read_csv(temp_csv)
    assert new_header == header
    assert len(new_rows) == 2
    # Identity columns intact.
    assert new_rows[0][:3] == ["int-1", "Packs/X/x.yml", "ConnX"]
    assert new_rows[1][:3] == ["int-2", "Packs/Y/y.yml", "ConnY"]
    # Every workflow column is empty for every row.
    for r in new_rows:
        assert len(r) == len(header)
        assert all(cell == "" for cell in r[3:])


def test_writes_backup_when_requested(temp_csv: Path) -> None:
    cfg = workflow_state.get_config()
    header = list(cfg.all_columns)
    n_workflow = len(cfg.workflow_columns)
    _seed_csv(
        temp_csv,
        header,
        [["int-1", "p/1.yml", "ConnA"] + [""] * n_workflow],
    )
    original_bytes = temp_csv.read_bytes()

    result = wipe_workflow_data(confirm=True, backup=True)

    backup_path = result["backup_path"]
    assert isinstance(backup_path, str)
    assert backup_path.startswith(str(temp_csv) + ".bak.")
    # Backup is byte-identical to the pre-wipe state.
    assert Path(backup_path).read_bytes() == original_bytes


def test_realigns_header_to_yaml_when_old_header_drifted(
    temp_csv: Path,
) -> None:
    """If the on-disk header has bogus extra columns, the rewrite should
    rebuild the header from the YAML and only carry forward identity
    columns by name."""
    cfg = workflow_state.get_config()
    expected_header = list(cfg.all_columns)
    drifted_header = ["Integration ID", "Integration File Path",
                      "Connector ID", "obsolete_step_a", "obsolete_step_b"]
    _seed_csv(
        temp_csv,
        drifted_header,
        [
            ["int-1", "p/1.yml", "ConnA", "junk1", "junk2"],
            ["int-2", "p/2.yml", "ConnB", "", ""],
        ],
    )

    result = wipe_workflow_data(confirm=True, backup=False)

    assert result["header"] == expected_header
    assert result["rows"] == 2
    new_header, new_rows = _read_csv(temp_csv)
    assert new_header == expected_header
    assert new_rows[0][:3] == ["int-1", "p/1.yml", "ConnA"]
    assert new_rows[1][:3] == ["int-2", "p/2.yml", "ConnB"]
    # No leftover obsolete columns.
    for r in new_rows:
        assert len(r) == len(expected_header)
        assert all(cell == "" for cell in r[3:])
