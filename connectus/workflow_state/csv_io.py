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
from typing import Optional

from workflow_state.config_loader import get_config
from workflow_state.state_machine import _normalize_rows_with_warning


# This file is connectus/workflow_state/csv_io.py — go up TWO dirs to
# reach the workspace root, matching the legacy module's BASE_DIR.
BASE_DIR = _os_module.path.dirname(
    _os_module.path.dirname(_os_module.path.dirname(_os_module.path.abspath(__file__)))
)
CSV_PATH = _os_module.path.join(BASE_DIR, "connectus", "connectus-migration-pipeline.csv")

# Re-exposed for monkey-patch parity with the legacy module
# (tests do ``monkeypatch.setattr(workflow_state.os, "replace", _boom)``).
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


def save_csv(rows: list[dict[str, str]]) -> None:
    """Write rows back to CSV atomically. Normalizes on write."""
    if not rows:
        return

    _normalize_rows_with_warning(rows, context="saved")

    fieldnames = list(rows[0].keys())

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)

    csv_path = _csv_path()
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


def find_row(rows: list[dict[str, str]], integration_id: str) -> Optional[int]:
    """Find a row by Integration ID (case-insensitive). Returns index or None."""
    name_lower = integration_id.lower().strip()
    for i, row in enumerate(rows):
        if row.get("Integration ID", "").strip().lower() == name_lower:
            return i
    return None
