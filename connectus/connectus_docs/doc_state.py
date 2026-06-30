"""Documentation state tracking on the migration pipeline CSV.

Self-contained state layer for the documentation skill. It reads/writes the SAME
``connectus-migration-pipeline.csv`` used by the migration workflow, but does NOT
touch the migration ``workflow_state`` package or its step-machine — the only
coupling is the shared CSV file. It manages exactly one new column,
``Documentation Completed`` (§6), and provides four operations:

* ``doc-status <connector>``     — per-member documentation state for a connector.
* ``set-doc-complete <connector>`` — mark EVERY member row of a connector ✅.
* ``doc-next [--mine]``          — the next connector that still needs docs.
* ``doc-dashboard``             — counts of documented vs pending connectors.
* ``doc-find [pattern]``         — list connectors FROM THE CSV (optionally
  filtered by a case-insensitive substring on slug or Connector ID). This is the
  ONLY sanctioned way to build a candidate list (e.g. "document all the
  microsoft ones"). NEVER enumerate connectors from the filesystem
  (``ls connectors/``) — folders exist that are NOT in the pipeline and must
  never be documented (§3.1).

Concurrency
-----------
Writes use the same re-read + overlay + atomic-replace pattern as
``workflow_state.save_row`` so parallel per-connector subtasks (§3.3) do not lose
each other's updates: each writer re-reads the CSV, appends the column if absent,
overlays only the target connector's member rows, and atomically replaces the
file via ``os.replace`` of a temp file in the same directory.

Usage::

    python3 -m connectus_docs.doc_state doc-status akamai
    python3 -m connectus_docs.doc_state set-doc-complete akamai
    python3 -m connectus_docs.doc_state doc-next --mine
    python3 -m connectus_docs.doc_state doc-dashboard
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from resolvers import pipeline_csv_path  # noqa: E402

DOC_COLUMN = "Documentation Completed"
DONE_MARK = "✅"

_CONNECTOR_FOLDER_COL = "Connector Folder Path"
_CONNECTOR_ID_COL = "Connector ID"
_INTEGRATION_ID_COL = "Integration ID"
_ASSIGNEE_COL = "assignee"


# --------------------------------------------------------------------------- #
# CSV IO (concurrency-safe)
# --------------------------------------------------------------------------- #
def _read(csv_path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    """Return ``(fieldnames, rows)`` from the CSV."""
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    return fieldnames, rows


def _ensure_column(fieldnames: List[str], rows: List[Dict[str, str]]) -> List[str]:
    """Append ``DOC_COLUMN`` (idempotently) and backfill blanks on every row."""
    if DOC_COLUMN not in fieldnames:
        fieldnames = fieldnames + [DOC_COLUMN]
    for row in rows:
        row.setdefault(DOC_COLUMN, "")
        if DOC_COLUMN not in row or row[DOC_COLUMN] is None:
            row[DOC_COLUMN] = ""
    return fieldnames


def _atomic_write(csv_path: Path, fieldnames: List[str], rows: List[Dict[str, str]]) -> None:
    """Write rows atomically (temp file in same dir + os.replace)."""
    fd, tmp = tempfile.mkstemp(dir=str(csv_path.parent), suffix=".csv.tmp")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                # Only emit known columns; drop any extra keys defensively.
                writer.writerow({k: row.get(k, "") for k in fieldnames})
        os.replace(tmp, csv_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _slug_of(folder_value: str) -> str:
    return (folder_value or "").rstrip("/").rsplit("/", 1)[-1]


def _member_rows(rows: List[Dict[str, str]], slug: str) -> List[Dict[str, str]]:
    return [r for r in rows if _slug_of(r.get(_CONNECTOR_FOLDER_COL, "")) == slug]


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #
def doc_status(slug: str, csv_path: Optional[Path] = None) -> Dict[str, object]:
    """Return per-member documentation state for ``slug``.

    Raises:
        ValueError: if no member rows exist for the slug.
    """
    csv_path = csv_path or pipeline_csv_path()
    fieldnames, rows = _read(csv_path)
    _ensure_column(fieldnames, rows)
    members = _member_rows(rows, slug)
    if not members:
        raise ValueError(f"No member rows for connector slug {slug!r} in {csv_path}.")
    member_states = [
        {
            "integration_id": m.get(_INTEGRATION_ID_COL, ""),
            "documented": m.get(DOC_COLUMN, "") == DONE_MARK,
        }
        for m in members
    ]
    return {
        "slug": slug,
        "connector_id": members[0].get(_CONNECTOR_ID_COL, ""),
        "members": member_states,
        "complete": all(m["documented"] for m in member_states),
    }


def set_doc_complete(slug: str, csv_path: Optional[Path] = None) -> int:
    """Mark EVERY member row of ``slug`` as documented (✅). Concurrency-safe.

    Returns:
        The number of member rows marked.

    Raises:
        ValueError: if no member rows exist for the slug.
    """
    csv_path = csv_path or pipeline_csv_path()
    # Re-read under the write to overlay only our rows (lost-update safe).
    fieldnames, rows = _read(csv_path)
    fieldnames = _ensure_column(fieldnames, rows)
    members = _member_rows(rows, slug)
    if not members:
        raise ValueError(f"No member rows for connector slug {slug!r} in {csv_path}.")
    for m in members:
        m[DOC_COLUMN] = DONE_MARK
    _atomic_write(csv_path, fieldnames, rows)
    return len(members)


def _connectors_in_order(rows: List[Dict[str, str]]) -> List[str]:
    """Distinct connector slugs in first-seen CSV order (skipping blanks)."""
    seen: List[str] = []
    for r in rows:
        slug = _slug_of(r.get(_CONNECTOR_FOLDER_COL, ""))
        if slug and slug not in seen:
            seen.append(slug)
    return seen


def doc_next(mine: bool = False, csv_path: Optional[Path] = None) -> Optional[Dict[str, str]]:
    """Return the next connector that still needs docs, or ``None`` if all done.

    A connector "needs docs" when ANY of its member rows lacks the ✅ mark.

    Args:
        mine: when True, restrict to connectors whose member rows are assigned to
            the current git user (``git config user.name``).
    """
    csv_path = csv_path or pipeline_csv_path()
    fieldnames, rows = _read(csv_path)
    _ensure_column(fieldnames, rows)

    me = _git_user_name() if mine else None
    for slug in _connectors_in_order(rows):
        members = _member_rows(rows, slug)
        if mine and me is not None:
            if not any((m.get(_ASSIGNEE_COL, "") == me) for m in members):
                continue
        if any(m.get(DOC_COLUMN, "") != DONE_MARK for m in members):
            return {"slug": slug, "connector_id": members[0].get(_CONNECTOR_ID_COL, "")}
    return None


def list_connectors(
    pattern: Optional[str] = None, csv_path: Optional[Path] = None
) -> List[Dict[str, object]]:
    """List connectors FROM THE PIPELINE CSV, optionally filtered by substring.

    This is the authoritative way to enumerate documentation candidates (§3.1).
    Connectors are taken ONLY from the CSV's ``Connector Folder Path`` column —
    never from the filesystem — so connector folders that are not in the pipeline
    can never be picked up for documentation.

    Args:
        pattern: optional case-insensitive substring; when given, a connector is
            included only if the substring appears in its slug OR its Connector
            ID. When omitted, all connectors are returned.

    Returns:
        One dict per distinct connector (first-seen CSV order), each with:
        ``slug``, ``connector_id``, ``members`` (count), ``complete`` (bool).
    """
    csv_path = csv_path or pipeline_csv_path()
    fieldnames, rows = _read(csv_path)
    _ensure_column(fieldnames, rows)
    needle = (pattern or "").strip().lower()
    out: List[Dict[str, object]] = []
    for slug in _connectors_in_order(rows):
        members = _member_rows(rows, slug)
        connector_id = members[0].get(_CONNECTOR_ID_COL, "") if members else ""
        if needle and needle not in slug.lower() and needle not in connector_id.lower():
            continue
        out.append(
            {
                "slug": slug,
                "connector_id": connector_id,
                "members": len(members),
                "complete": all(m.get(DOC_COLUMN, "") == DONE_MARK for m in members),
            }
        )
    return out


def doc_dashboard(csv_path: Optional[Path] = None) -> Dict[str, int]:
    """Return connector-level documented vs pending counts."""
    csv_path = csv_path or pipeline_csv_path()
    fieldnames, rows = _read(csv_path)
    _ensure_column(fieldnames, rows)
    total = 0
    done = 0
    for slug in _connectors_in_order(rows):
        total += 1
        members = _member_rows(rows, slug)
        if all(m.get(DOC_COLUMN, "") == DONE_MARK for m in members):
            done += 1
    return {"connectors_total": total, "documented": done, "pending": total - done}


def _git_user_name() -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True, text=True, check=False,
        )
        name = out.stdout.strip()
        return name or None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="doc_state", description="Documentation state on the pipeline CSV.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_status = sub.add_parser("doc-status", help="per-member documentation state for a connector")
    p_status.add_argument("slug")

    p_set = sub.add_parser("set-doc-complete", help="mark every member row of a connector documented")
    p_set.add_argument("slug")

    p_next = sub.add_parser("doc-next", help="next connector needing docs")
    p_next.add_argument("--mine", action="store_true", help="restrict to my assigned connectors")

    p_find = sub.add_parser(
        "doc-find",
        help="list connectors FROM THE CSV (optional substring filter); the ONLY "
        "sanctioned way to build a candidate list — never use 'ls connectors/'",
    )
    p_find.add_argument(
        "pattern",
        nargs="?",
        default=None,
        help="case-insensitive substring matched on slug or Connector ID",
    )

    sub.add_parser("doc-dashboard", help="documented vs pending connector counts")

    args = parser.parse_args(argv)

    if args.cmd == "doc-status":
        try:
            st = doc_status(args.slug)
        except ValueError as exc:
            print(f"ERROR {exc}")
            return 1
        mark = DONE_MARK if st["complete"] else "…"
        print(f"{mark} {st['slug']} ({st['connector_id']}) — complete={st['complete']}")
        for m in st["members"]:
            flag = DONE_MARK if m["documented"] else " "
            print(f"  [{flag}] {m['integration_id']}")
        return 0

    if args.cmd == "set-doc-complete":
        try:
            n = set_doc_complete(args.slug)
        except ValueError as exc:
            print(f"ERROR {exc}")
            return 1
        print(f"{DONE_MARK} marked {n} member row(s) documented for '{args.slug}'.")
        return 0

    if args.cmd == "doc-next":
        nxt = doc_next(mine=args.mine)
        if nxt is None:
            print("All connectors documented." if not args.mine else "None of your connectors need docs.")
            return 0
        print(f"Next: {nxt['slug']} ({nxt['connector_id']})")
        return 0

    if args.cmd == "doc-find":
        matches = list_connectors(pattern=args.pattern)
        if not matches:
            scope = f" matching {args.pattern!r}" if args.pattern else ""
            print(f"No connectors found in the pipeline CSV{scope}.")
            return 0
        label = f" matching {args.pattern!r}" if args.pattern else ""
        print(f"{len(matches)} connector(s) in pipeline CSV{label}:")
        for c in matches:
            mark = DONE_MARK if c["complete"] else " "
            print(
                f"  [{mark}] {c['slug']} ({c['connector_id']}) "
                f"— {c['members']} member(s)"
            )
        return 0

    if args.cmd == "doc-dashboard":
        d = doc_dashboard()
        print(
            f"Connectors: {d['connectors_total']}  "
            f"documented: {d['documented']}  pending: {d['pending']}"
        )
        return 0

    parser.error(f"unknown command {args.cmd!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
