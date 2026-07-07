"""Example patch script for the GENERIC black-box E2E harness.

This is a deliberately tiny, self-contained "patch" whose only job is to
demonstrate that the E2E harness in ``patches/e2e/`` can drive **any** script
(not just ``add_vault_support.py`` / ``propagate_advanced_flag.py``) via the
per-case ``script`` + ``args`` keys in ``case.json``.

What it does
------------
For every ``connection.yaml`` under ``--connectors-dir`` (optionally restricted
to one connector via ``--path``), it sets ``metadata.owner`` to the value of
``--owner``. It is:

* IDEMPOTENT — if ``metadata.owner`` already equals the requested value nothing
  is written (so a second run is a no-op, satisfying the harness's idempotency
  assertion);
* DRY-RUN aware — with ``--dry-run`` it reports intended changes and writes
  nothing, exiting 0 (satisfying the harness's dry-run assertion).

This intentionally uses a DIFFERENT flag contract (``--owner`` instead of the
legacy ``--pipeline-csv`` etc.) to prove the ``args`` template can shape argv
for an arbitrary script.

Usage (as invoked by the harness via the case ``args`` template)::

    python3 examples/set_metadata_owner.py \
        --connectors-dir <tmp>/connectors \
        [--path <connector>] \
        --owner "connectors-team@example.com" \
        [--dry-run]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

CONNECTION_FILENAME = "connection.yaml"


def _iter_connection_files(connectors_dir: Path, path: str | None) -> list[Path]:
    """Return the connection.yaml files to consider.

    When ``path`` is given, scope to that single connector directory (matched by
    name); otherwise scan every connector under ``connectors_dir``.
    """
    root = connectors_dir / path if path else connectors_dir
    if not root.is_dir():
        return []
    return sorted(root.rglob(CONNECTION_FILENAME))


def _leading_directive(text: str) -> str:
    """Preserve a leading ``# yaml-language-server`` (or comment) block, if any."""
    lines = text.splitlines(keepends=True)
    kept: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or stripped == "":
            kept.append(line)
            continue
        break
    return "".join(kept)


def _apply_owner(conn_file: Path, owner: str, dry_run: bool) -> bool:
    """Set ``metadata.owner`` on one connection.yaml. Returns True if changed."""
    raw = conn_file.read_text()
    directive = _leading_directive(raw)
    data = yaml.safe_load(raw) or {}

    metadata = data.setdefault("metadata", {})
    if metadata.get("owner") == owner:
        return False  # idempotent: nothing to do

    metadata["owner"] = owner
    if dry_run:
        return True  # report only

    body = yaml.safe_dump(data, sort_keys=False)
    conn_file.write_text(directive + body)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Set metadata.owner on connections.")
    parser.add_argument("--connectors-dir", required=True, type=Path)
    parser.add_argument("--path", default=None)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    files = _iter_connection_files(args.connectors_dir, args.path)
    changed: list[Path] = []
    for conn_file in files:
        if _apply_owner(conn_file, args.owner, args.dry_run):
            changed.append(conn_file)

    verb = "would modify" if args.dry_run else "modified"
    if changed:
        print(f"{verb} {len(changed)} connection(s):")
        for c in changed:
            print(f"  - {c}")
    else:
        print("no connections needed changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
