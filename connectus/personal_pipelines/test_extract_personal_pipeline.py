"""Tests for ``extract_personal_pipeline.py``.

Follows the conventions in ``connectus/workflow_state/tests/`` — a temp CSV
seeded with ``cfg.all_columns`` as the header and ``workflow_state.CSV_PATH``
monkeypatched at the package namespace so :func:`workflow_state.load_csv`
reads it.

The extractor's logic is factored into importable functions
(``select_rows``, ``resolve_destination``, ``run_extract``) plus a thin
``main(argv)`` wrapper, so the tests exercise behaviour directly without
shelling out. A few end-to-end ``main([...])`` cases cover the argparse seam.
"""
from __future__ import annotations

import csv as _csv
import os
from pathlib import Path

import pytest

import workflow_state
from workflow_state.config_loader import _reset_config_for_testing

from personal_pipelines import extract_personal_pipeline as epp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_config_for_testing()
    yield
    _reset_config_for_testing()


def _make_row(header: list[str], **values: str) -> dict[str, str]:
    row = {col: "" for col in header}
    row.update(values)
    return row


@pytest.fixture
def temp_main_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Seed a main pipeline CSV with a handful of known rows."""
    cfg = workflow_state.get_config()
    header = list(cfg.all_columns)
    rows = [
        _make_row(header, **{
            "Integration ID": "AMP",
            "Connector ID": "Cisco Security",
            "assignee": "YuvHayun",
        }),
        _make_row(header, **{
            "Integration ID": "AMPv2",
            "Connector ID": "Cisco Security",
            "assignee": "noydavidi",
        }),
        _make_row(header, **{
            "Integration ID": "APIVoid",
            "Connector ID": "APIVoid",
            "assignee": "YuvHayun",
        }),
        _make_row(header, **{
            "Integration ID": "ZScaler",
            "Connector ID": "ZScaler",
            "assignee": "juschwartz",
        }),
    ]
    p = tmp_path / "pipeline.csv"
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow([row[col] for col in header])
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(p))
    return p


@pytest.fixture
def out_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the default personal-pipelines output dir into tmp_path and
    pin BASE_DIR so relative-path reporting is deterministic."""
    d = tmp_path / "personal_pipelines"
    d.mkdir()
    monkeypatch.setattr(epp, "PERSONAL_PIPELINES_DIR", d)
    monkeypatch.setattr(epp, "BASE_DIR", str(tmp_path))
    return d


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = _csv.DictReader(f)
        header = list(reader.fieldnames or [])
        rows = list(reader)
    return header, rows


def _ids(rows: list[dict[str, str]]) -> list[str]:
    return [r.get("Integration ID", "") for r in rows]


# ---------------------------------------------------------------------------
# select_rows
# ---------------------------------------------------------------------------

def test_select_by_assignee_case_insensitive(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    selected = epp.select_rows(rows, assignee="yuvhayun")
    assert _ids(selected) == ["AMP", "APIVoid"]


def test_select_by_connector(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    selected = epp.select_rows(rows, connector="Cisco Security")
    assert _ids(selected) == ["AMP", "AMPv2"]


def test_select_by_single_integration_id(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    selected = epp.select_rows(rows, integration_ids=["apivoid"])
    assert _ids(selected) == ["APIVoid"]


def test_select_by_repeated_integration_ids(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    selected = epp.select_rows(rows, integration_ids=["AMP", "ZScaler"])
    assert _ids(selected) == ["AMP", "ZScaler"]


def test_select_union_dedups_and_preserves_order(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    # APIVoid is matched by both --assignee YuvHayun and --integration-id;
    # AMP by both assignee and connector. Expect main-file order, no dups.
    selected = epp.select_rows(
        rows,
        assignee="YuvHayun",
        connector="Cisco Security",
        integration_ids=["APIVoid"],
    )
    assert _ids(selected) == ["AMP", "AMPv2", "APIVoid"]


def test_select_mine_uses_git_user(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    selected = epp.select_rows(rows, mine=True, git_user_name="juschwartz")
    assert _ids(selected) == ["ZScaler"]


def test_select_no_selector_raises(temp_main_csv: Path) -> None:
    rows = workflow_state.load_csv()
    with pytest.raises(epp.ExtractError):
        epp.select_rows(rows)


# ---------------------------------------------------------------------------
# slugify / destination resolution
# ---------------------------------------------------------------------------

def test_slugify() -> None:
    assert epp.slugify("Joey Schwartz") == "joey-schwartz"
    assert epp.slugify("  A__B  ") == "a-b"
    assert epp.slugify("!!!") == ""


def test_resolve_destination_default_slugified(out_dir: Path) -> None:
    dest = epp.resolve_destination(
        output=None, name=None, git_user_name="Joey Schwartz"
    )
    assert dest == (out_dir / "joey-schwartz.csv").resolve()


def test_resolve_destination_fallback_stem(out_dir: Path) -> None:
    dest = epp.resolve_destination(output=None, name=None, git_user_name=None)
    assert dest == (out_dir / "personal-pipeline.csv").resolve()


def test_resolve_destination_name(out_dir: Path) -> None:
    dest = epp.resolve_destination(
        output=None, name="My Work", git_user_name="ignored"
    )
    assert dest == (out_dir / "my-work.csv").resolve()


def test_resolve_destination_output_overrides_name(
    out_dir: Path, tmp_path: Path
) -> None:
    # repo-root-relative output (BASE_DIR is monkeypatched to tmp_path)
    dest = epp.resolve_destination(
        output="custom/loc.csv", name="ignored", git_user_name="ignored"
    )
    assert dest == (tmp_path / "custom" / "loc.csv").resolve()


def test_resolve_destination_output_absolute(out_dir: Path, tmp_path: Path) -> None:
    abs_target = tmp_path / "abs" / "thing.csv"
    dest = epp.resolve_destination(
        output=str(abs_target), name=None, git_user_name=None
    )
    assert dest == abs_target.resolve()


# ---------------------------------------------------------------------------
# run_extract — file output / header / loadability
# ---------------------------------------------------------------------------

def _base_kwargs(**overrides):
    kwargs = dict(
        mine=False,
        assignee=None,
        connector=None,
        integration_ids=[],
        name=None,
        output=None,
        force=False,
        dry_run=False,
    )
    kwargs.update(overrides)
    return kwargs


def test_run_extract_writes_canonical_header_and_rows(
    temp_main_csv: Path, out_dir: Path
) -> None:
    rc = epp.run_extract(**_base_kwargs(assignee="YuvHayun", name="mine"))
    assert rc == 0
    dest = out_dir / "mine.csv"
    assert dest.exists()

    cfg = workflow_state.get_config()
    header, rows = _read_csv(dest)
    assert header == list(cfg.all_columns)
    assert _ids(rows) == ["AMP", "APIVoid"]


def test_run_extract_output_is_reloadable_as_pipeline(
    temp_main_csv: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc = epp.run_extract(**_base_kwargs(connector="Cisco Security", name="cs"))
    assert rc == 0
    dest = out_dir / "cs.csv"
    # Point the workflow tooling at the generated file and load it back.
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(dest))
    reloaded = workflow_state.load_csv()
    assert _ids(reloaded) == ["AMP", "AMPv2"]


def test_run_extract_no_selector_errors_no_file(
    temp_main_csv: Path, out_dir: Path, capsys
) -> None:
    rc = epp.run_extract(**_base_kwargs())
    assert rc == 1
    assert list(out_dir.iterdir()) == []
    err = capsys.readouterr().err
    assert "at least one selector is required" in err


def test_run_extract_empty_match_errors_no_file(
    temp_main_csv: Path, out_dir: Path, capsys
) -> None:
    rc = epp.run_extract(**_base_kwargs(assignee="nobody"))
    assert rc == 1
    assert list(out_dir.iterdir()) == []
    err = capsys.readouterr().err
    assert "no rows matched" in err
    assert "list-connectors" in err


def test_run_extract_overwrite_refused(
    temp_main_csv: Path, out_dir: Path, capsys
) -> None:
    dest = out_dir / "mine.csv"
    dest.write_text("pre-existing", encoding="utf-8")
    rc = epp.run_extract(**_base_kwargs(assignee="YuvHayun", name="mine"))
    assert rc == 1
    assert dest.read_text(encoding="utf-8") == "pre-existing"
    assert "already exists" in capsys.readouterr().err


def test_run_extract_force_overwrites(temp_main_csv: Path, out_dir: Path) -> None:
    dest = out_dir / "mine.csv"
    dest.write_text("pre-existing", encoding="utf-8")
    rc = epp.run_extract(
        **_base_kwargs(assignee="YuvHayun", name="mine", force=True)
    )
    assert rc == 0
    _header, rows = _read_csv(dest)
    assert _ids(rows) == ["AMP", "APIVoid"]


def test_run_extract_dry_run_writes_nothing(
    temp_main_csv: Path, out_dir: Path, capsys
) -> None:
    rc = epp.run_extract(
        **_base_kwargs(assignee="YuvHayun", name="mine", dry_run=True)
    )
    assert rc == 0
    assert not (out_dir / "mine.csv").exists()
    out = capsys.readouterr().out
    assert "DRY-RUN" in out
    assert "Rows:        2" in out
    assert "AMP" in out and "APIVoid" in out


def test_run_extract_success_prints_env_line(
    temp_main_csv: Path, out_dir: Path, tmp_path: Path, capsys
) -> None:
    rc = epp.run_extract(**_base_kwargs(assignee="YuvHayun", name="mine"))
    assert rc == 0
    out = capsys.readouterr().out
    # BASE_DIR is tmp_path; the file lives in tmp_path/personal_pipelines/.
    assert "CONNECTUS_PIPELINE_CSV=personal_pipelines/mine.csv" in out


def test_run_extract_mine_no_git_user_errors(
    temp_main_csv: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(epp, "_git_user_name", lambda: None)
    rc = epp.run_extract(**_base_kwargs(mine=True))
    assert rc == 1
    assert list(out_dir.iterdir()) == []
    assert "could not determine your git user name" in capsys.readouterr().err


def test_run_extract_mine_uses_monkeypatched_git_user(
    temp_main_csv: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(epp, "_git_user_name", lambda: "juschwartz")
    rc = epp.run_extract(**_base_kwargs(mine=True, name="mine"))
    assert rc == 0
    _header, rows = _read_csv(out_dir / "mine.csv")
    assert _ids(rows) == ["ZScaler"]


# ---------------------------------------------------------------------------
# End-to-end main([...])
# ---------------------------------------------------------------------------

def test_main_assignee_end_to_end(temp_main_csv: Path, out_dir: Path) -> None:
    rc = epp.main(["--assignee", "YuvHayun", "--name", "e2e"])
    assert rc == 0
    _header, rows = _read_csv(out_dir / "e2e.csv")
    assert _ids(rows) == ["AMP", "APIVoid"]


def test_main_repeated_integration_id_end_to_end(
    temp_main_csv: Path, out_dir: Path
) -> None:
    rc = epp.main([
        "--integration-id", "AMP",
        "--integration-id", "ZScaler",
        "--name", "ids",
    ])
    assert rc == 0
    _header, rows = _read_csv(out_dir / "ids.csv")
    assert _ids(rows) == ["AMP", "ZScaler"]


def test_main_no_selector_returns_nonzero(
    temp_main_csv: Path, out_dir: Path
) -> None:
    rc = epp.main(["--name", "nope"])
    assert rc == 1
    assert not (out_dir / "nope.csv").exists()


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------

def test_missing_main_csv_errors_no_file(
    tmp_path: Path, out_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """A missing/unreadable main CSV → clean error, exit 1, no output file."""
    missing = tmp_path / "does-not-exist.csv"
    assert not missing.exists()
    monkeypatch.setattr(workflow_state, "CSV_PATH", str(missing))

    rc = epp.main(["--assignee", "YuvHayun", "--name", "mine"])
    assert rc == 1
    assert not (out_dir / "mine.csv").exists()
    err = capsys.readouterr().err
    assert str(missing) in err
    assert "connectus-migration-pipeline.csv" in err


def test_name_path_traversal_is_neutralized(out_dir: Path) -> None:
    """A hostile --name must resolve to a sanitized stem INSIDE the
    personal_pipelines dir (no traversal, no leading-slash escape)."""
    for hostile in ("../../etc/evil", "/abs/evil"):
        dest = epp.resolve_destination(
            output=None, name=hostile, git_user_name=None
        )
        # Destination stays inside the personal_pipelines dir.
        assert dest.parent == out_dir.resolve()
        # Filename is a sanitized stem (no path separators, ends in .csv).
        assert os.sep not in dest.name
        assert dest.suffix == ".csv"
        assert ".." not in dest.name
        # Nothing was written outside (or inside) the folder by resolution.
        assert not dest.exists()
    assert list(out_dir.iterdir()) == []


def test_dry_run_does_not_trip_overwrite_guard(
    temp_main_csv: Path, out_dir: Path
) -> None:
    """--dry-run with an existing destination (and no --force) succeeds,
    writes nothing, and leaves the existing file byte-for-byte unchanged."""
    dest = out_dir / "mine.csv"
    original = b"pre-existing bytes\n"
    dest.write_bytes(original)

    rc = epp.run_extract(
        **_base_kwargs(assignee="YuvHayun", name="mine", dry_run=True)
    )
    assert rc == 0
    assert dest.read_bytes() == original
