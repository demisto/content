"""CSV I/O for the workflow_state package.

Reads and writes the bundled ``connectus/connectus-migration-pipeline.csv``
file. Both read and write paths normalize each row via
:func:`~workflow_state.state_machine.normalize_row` so contradictory
"value-past-incomplete-step" cells get cleaned up automatically.

Per Q4 (design overrides): ``CSV_PATH`` stays hardcoded here — it is
not driven by YAML config.

The module reads ``CSV_PATH`` from the package namespace at call time
so that tests using ``monkeypatch.setattr(workflow_state, "CSV_PATH", ...)``
work transparently. Same for ``os`` (some tests patch ``os.replace``).
"""
from __future__ import annotations

import csv
import io
import os as _os_module
import sys
import tempfile
from pathlib import Path
from typing import Optional

try:
    import fcntl  # POSIX-only; used for the cross-process commit lock.
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

from workflow_state.config_loader import get_config
from workflow_state.state_machine import _normalize_rows_with_warning


#: Environment variable that, when set & non-empty, overrides the bundled
#: pipeline CSV path. The value is a full path: absolute, or relative to the
#: repo root (``BASE_DIR``); ``~`` is expanded. Loaded from the unified root
#: ``.env`` via :func:`env_loader.load_env`.
PIPELINE_CSV_ENV_VAR = "CONNECTUS_PIPELINE_CSV"

# This file is connectus/workflow_state/csv_io.py — go up TWO dirs to
# reach the workspace root.
BASE_DIR = _os_module.path.dirname(
    _os_module.path.dirname(_os_module.path.dirname(_os_module.path.abspath(__file__)))
)

#: The bundled default pipeline CSV path (used when the env var is unset/empty).
_DEFAULT_CSV_PATH = _os_module.path.join(
    BASE_DIR, "connectus", "connectus-migration-pipeline.csv"
)


def _resolve_pipeline_csv() -> str:
    """Resolve the pipeline CSV path, honoring ``CONNECTUS_PIPELINE_CSV``.

    Returns the env override (with ``~`` expanded and relative paths resolved
    against :data:`BASE_DIR`) when ``CONNECTUS_PIPELINE_CSV`` is set & non-empty,
    else the bundled :data:`_DEFAULT_CSV_PATH`.
    """
    load_env()
    raw = (_os_module.environ.get(PIPELINE_CSV_ENV_VAR) or "").strip()
    if not raw:
        return _DEFAULT_CSV_PATH
    expanded = _os_module.path.expanduser(raw)
    if _os_module.path.isabs(expanded):
        return expanded
    return _os_module.path.join(BASE_DIR, expanded)


#: The active pipeline CSV path. Computed once at import time from the env
#: override (if any) or the bundled default. Tests may monkeypatch
#: ``workflow_state.CSV_PATH`` directly — :func:`_csv_path` reads it from the
#: package namespace at call time, so monkeypatching still wins.
CSV_PATH = _resolve_pipeline_csv()

# Re-exposed at the package namespace so tests can monkey-patch e.g.
# ``workflow_state.os.replace``.
os = _os_module


def _csv_path() -> str:
    """Look up CSV_PATH from the package namespace at call time."""
    import workflow_state as _ws
    return _ws.CSV_PATH


def _os() -> object:
    """Look up the ``os`` module via the package namespace."""
    import workflow_state as _ws
    return _ws.os


def load_csv() -> list[dict[str, str]]:
    """Load the CSV and return list of row dicts. Normalizes on read."""
    cfg = get_config()
    expected = cfg.all_columns
    csv_path = _csv_path()
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        if fieldnames != expected:
            missing = [c for c in expected if c not in fieldnames]
            extra = [c for c in fieldnames if c not in expected]
            print(
                "WARNING: CSV header does not match expected schema.\n"
                f"  Expected {len(expected)} columns, got {len(fieldnames)}.\n"
                f"  Missing: {missing}\n"
                f"  Extra:   {extra}",
                file=sys.stderr,
            )
        rows = list(reader)

    _normalize_rows_with_warning(rows, context="loaded")
    return rows


def _lock_path(csv_path: str) -> str:
    """Sidecar lock file path for the pipeline CSV commit lock."""
    return csv_path + ".lock"


def _read_rows_from_disk(csv_path: str) -> list[dict[str, str]]:
    """Read the CSV currently on disk as raw row dicts (no normalize warnings).

    Returns ``[]`` if the file does not exist yet (first write). Used by the
    locked merge-write in :func:`save_csv` to obtain the authoritative latest
    state before overlaying this caller's rows.
    """
    if not _os().path.exists(csv_path):
        return []
    with open(csv_path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _write_rows_atomic(final_rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    """Serialize ``final_rows`` and atomically replace the CSV on disk."""
    csv_path = _csv_path()
    os_mod = _os()
    target_dir = os_mod.path.dirname(csv_path) or "."

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(final_rows)

    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_dir,
            prefix=".connectus-migration-pipeline.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp_path = tmp.name
            tmp.write(output.getvalue())
        os_mod.replace(tmp_path, csv_path)
        tmp_path = None
    finally:
        if tmp_path is not None and os_mod.path.exists(tmp_path):
            try:
                os_mod.remove(tmp_path)
            except OSError:
                pass


class _csv_commit_lock:
    """Context manager: exclusive cross-process lock for a CSV commit.

    Acquires an exclusive :func:`fcntl.flock` on the sidecar ``<csv>.lock`` file
    for the duration of the ``with`` block, so a re-read + write inside the block
    is atomic with respect to other committing processes. No-op when ``fcntl`` is
    unavailable (non-POSIX).
    """

    def __init__(self) -> None:
        self._fd = None

    def __enter__(self):
        if fcntl is not None:
            lock_path = _lock_path(_csv_path())
            self._fd = _os_module.open(
                lock_path, _os_module.O_CREAT | _os_module.O_RDWR, 0o644
            )
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                _os_module.close(self._fd)
                self._fd = None
        return False


def save_csv(rows: list[dict[str, str]]) -> None:
    """Write the FULL row list back to CSV atomically. Normalizes on write.

    This is the authoritative whole-file writer (bulk operations, resets that
    span the file, etc.). It writes ``rows`` verbatim under the commit lock — it
    does NOT merge with disk, so callers that only changed ONE integration and
    might be racing other processes must use :func:`save_row` instead to avoid
    the lost-update race.
    """
    if not rows:
        return

    _normalize_rows_with_warning(rows, context="saved")
    fieldnames = list(rows[0].keys())
    with _csv_commit_lock():
        _write_rows_atomic(rows, fieldnames)


def save_row(row: dict[str, str]) -> None:
    """Commit a SINGLE integration's row safely under the cross-process lock.

    Concurrency-safe against the lost-update race: holds the exclusive commit
    lock while it RE-READS the current CSV from disk, replaces ONLY this row
    (matched by ``Integration ID``, case-insensitive; appended if new), and
    atomically rewrites. Because only the one changed row is overlaid onto the
    freshly-read file, concurrent commits to OTHER rows are preserved.

    The lock is held only for the brief re-read/write, NOT for any slow work the
    caller did beforehand (e.g. a parity gate), so parallelism is preserved.
    """
    _normalize_rows_with_warning([row], context="saved")
    target_key = (row.get("Integration ID") or "").strip().lower()

    with _csv_commit_lock():
        disk_rows = _read_rows_from_disk(_csv_path())
        if not disk_rows:
            _write_rows_atomic([row], list(row.keys()))
            return

        fieldnames = list(disk_rows[0].keys())
        replaced = False
        final_rows: list[dict[str, str]] = []
        for r in disk_rows:
            if (r.get("Integration ID") or "").strip().lower() == target_key:
                final_rows.append(row)
                replaced = True
            else:
                final_rows.append(r)
        if not replaced:
            final_rows.append(row)
        _write_rows_atomic(final_rows, fieldnames)


def find_row(rows: list[dict[str, str]], integration_id: str) -> Optional[int]:
    """Find a row by Integration ID (case-insensitive). Returns index or None."""
    name_lower = integration_id.lower().strip()
    for i, row in enumerate(rows):
        if row.get("Integration ID", "").strip().lower() == name_lower:
            return i
    return None


# ---------------------------------------------------------------------------
# Destructive helpers
# ---------------------------------------------------------------------------

def wipe_workflow_data(
    *,
    confirm: bool = False,
    backup: bool = True,
) -> dict[str, object]:
    """⚠️  DESTRUCTIVE: wipe all workflow columns from the pipeline CSV.

    For each existing data row, preserves every identity column verbatim
    (``Integration ID``, ``Integration File Path``, ``Connector ID`` and
    any future identity columns declared in
    :data:`connectus/workflow_state_config.yml`) and clears every
    workflow column to the empty string. The header is regenerated from
    the YAML config so it always matches the current workflow plan
    (i.e. running this after adding/removing/renaming a step in the
    YAML re-aligns the CSV columns to that plan).

    This is intended for the rare case where the workflow plan changes
    shape and you want to keep the integration roster but throw away
    every per-row state cell. **Do not use this to "reset" a single
    integration** — use the ``reset`` CLI command for that.

    Parameters
    ----------
    confirm:
        Must be ``True`` or this function raises :class:`RuntimeError`
        without touching disk. This is a guardrail so accidental
        callers (typos, misconfigured scripts, an LLM auto-completing)
        cannot blow the file away.
    backup:
        When ``True`` (default), write a sibling backup file at
        ``<csv>.bak.<unix-timestamp>`` (preserving the *current* CSV
        contents) before rewriting. The backup path is returned in the
        result dict.

    Returns
    -------
    dict
        A summary of what changed::

            {
              "csv_path":      str,             # path that was rewritten
              "backup_path":   str | None,      # backup copy, if backup=True
              "rows":          int,             # data row count (preserved)
              "header":        list[str],       # YAML-derived header written
              "cells_cleared": int,             # workflow cells that had data
              "rows_touched":  int,             # rows whose workflow cols had data
            }

    Raises
    ------
    RuntimeError
        If ``confirm`` is not ``True``.
    FileNotFoundError
        If the pipeline CSV does not exist.
    """
    if confirm is not True:
        raise RuntimeError(
            "wipe_workflow_data() refused to run: pass confirm=True to opt in. "
            "This call would have erased every workflow cell from "
            "the connectus pipeline CSV."
        )

    cfg = get_config()
    expected_header = list(cfg.all_columns)
    identity_cols = list(cfg.identity_column_names)
    n_workflow = len(cfg.workflow_columns)

    csv_path = _csv_path()
    if not _os().path.exists(csv_path):
        raise FileNotFoundError(csv_path)

    # Read the existing rows. Use the raw csv reader rather than the
    # package's normalising load_csv() because we want to preserve
    # identity columns even if the on-disk header has drifted from the
    # current YAML schema (which is the most common reason this
    # function is called).
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        try:
            old_header = next(reader)
        except StopIteration as e:  # pragma: no cover - empty file
            raise RuntimeError(f"{csv_path} is empty; nothing to wipe") from e
        old_rows = [list(r) for r in reader]

    # Index identity columns by name in the OLD header so we can carry
    # them forward by name (not by position). Missing identity columns
    # become empty strings (caller will see them in the diagnostics).
    old_idx = {name: i for i, name in enumerate(old_header)}
    workflow_old_indices = [
        old_idx[name] for name in cfg.workflow_columns if name in old_idx
    ]

    cells_cleared = 0
    rows_touched = 0
    for r in old_rows:
        had_data = False
        for i in workflow_old_indices:
            if i < len(r) and r[i].strip():
                cells_cleared += 1
                had_data = True
        if had_data:
            rows_touched += 1

    # Optional sibling backup of the *current* file before rewrite.
    backup_path: Optional[str] = None
    if backup:
        ts = int(__import__("time").time())
        backup_path = f"{csv_path}.bak.{ts}"
        # Use shutil.copy2 to preserve mode/mtime, similar to `cp`.
        import shutil
        shutil.copy2(csv_path, backup_path)

    # Build the new rows: identity columns by name, then 16 empty cells.
    new_rows: list[list[str]] = []
    for r in old_rows:
        ident = [
            (r[old_idx[name]] if name in old_idx and old_idx[name] < len(r) else "")
            for name in identity_cols
        ]
        new_rows.append(ident + [""] * n_workflow)

    # Atomic write via a tempfile sibling, mirroring save_csv()'s pattern.
    output = io.StringIO()
    writer = csv.writer(
        output,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\n",
    )
    writer.writerow(expected_header)
    writer.writerows(new_rows)

    os_mod = _os()
    target_dir = os_mod.path.dirname(csv_path) or "."
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_dir,
            prefix=".connectus-migration-pipeline.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp_path = tmp.name
            tmp.write(output.getvalue())
        os_mod.replace(tmp_path, csv_path)
        tmp_path = None
    finally:
        if tmp_path is not None and os_mod.path.exists(tmp_path):
            try:
                os_mod.remove(tmp_path)
            except OSError:
                pass

    return {
        "csv_path": csv_path,
        "backup_path": backup_path,
        "rows": len(new_rows),
        "header": expected_header,
        "cells_cleared": cells_cleared,
        "rows_touched": rows_touched,
    }
