#!/usr/bin/env python3
"""Align connector engine settings from the migration pipeline CSV.

PLACEHOLDER (WIP)
=================
This is a scaffold for a future patch that will read the migration pipeline CSV
and perform engine-alignment operations on already-generated ConnectUs
connectors. The real logic is NOT implemented yet — for now the script is a
deliberate NO-OP: it discovers the connection files, reports what it *would*
consider, writes nothing, and exits 0. This lets the E2E harness wire it in
today (input == expected) and flip to real assertions once the logic lands.

CLI contract
------------
Kept consistent with the sibling patches (``add_vault_support.py``,
``propagate_advanced_flag.py``) so the generic E2E harness can drive it::

    python3 patches/align_engines.py \
        --csv <path/to/connectus-migration-pipeline.csv> \   # REQUIRED
        --connectors-dir <connectors root> \                 # REQUIRED
        [--path <connector>] \                               # restrict to one connector
        [--dry-run]                                          # report only; write nothing

Flags
-----
--csv             Path to the migration pipeline CSV (source of engine data).
--connectors-dir  Connectors root to scan.
--path            Restrict to a single connector dir/name.
--dry-run         Compute + report intended changes, write nothing, exit 0.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

CONNECTION_FILENAME = "connection.yaml"


def _iter_connection_files(connectors_dir: Path, path: str | None) -> list[Path]:
    """Return the connection.yaml files in scope (all, or one connector)."""
    root = connectors_dir / path if path else connectors_dir
    if not root.is_dir():
        return []
    return sorted(root.rglob(CONNECTION_FILENAME))


def align_engines(
    csv_path: Path,
    connectors_dir: Path,
    path: str | None,
    dry_run: bool,
) -> list[Path]:
    """Placeholder engine-alignment pass.

    Currently a NO-OP: it enumerates the in-scope connection files (and confirms
    the CSV exists) but performs no mutation. Returns the list of files that
    WOULD be considered for alignment, so the report is meaningful even while the
    real logic is unimplemented.
    """
    if not csv_path.is_file():
        raise FileNotFoundError(f"pipeline CSV not found: {csv_path}")

    files = _iter_connection_files(connectors_dir, path)
    # TODO(align_engines): parse csv_path, resolve per-connector engine settings
    # and apply them here (respecting dry_run + idempotency). No-op for now.
    _ = dry_run  # intentionally unused until real logic lands
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Align connector engine settings from the migration CSV (WIP no-op).",
    )
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--connectors-dir", required=True, type=Path)
    parser.add_argument("--path", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    considered = align_engines(
        csv_path=args.csv,
        connectors_dir=args.connectors_dir,
        path=args.path,
        dry_run=args.dry_run,
    )

    verb = "would align" if args.dry_run else "aligned"
    # Placeholder never mutates, so nothing is actually changed yet.
    print(f"align_engines (placeholder): considered {len(considered)} connection(s)")
    print(f"{verb} 0 connection(s) — engine-alignment logic not implemented yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
