#!/usr/bin/env python3
"""Back-fill the ``advanced: true`` FieldGroup flag on already-generated ConnectUs
``configurations.yaml`` and ``connection.yaml`` manifests.

Overview
========
The XSOAR integration YML lets individual ``configuration[]`` params declare
``advanced: true`` (surfacing them in the collapsible "Advanced" UI panel). The
ConnectUs FieldGroup schema exposes the same boolean at the ROW level
(a ``configurations[]`` list item — the ``- fields:`` block). Some generator
runs dropped that information; this patch retrofits it WITHOUT regenerating.

For each connector (discovered via the migration pipeline CSV) the patch:

  1. Resolves every source XSOAR YML feeding the connector (a connector may be
     fed by MULTIPLE handlers). The advanced param set is the union of every
     source param whose ``advanced`` is true.
  2. Walks each ``configurations[]`` block in ``configurations.yaml`` and
     ``connection.yaml`` and marks the block ``advanced: true`` when a field in
     it resolves to an advanced source param (R4a/R4b) OR is one of the
     always-advanced injected/backend fields (R3).
  3. Leaves everything else untouched (R4c) — notably the engine params
     (``engine_mode``/``engine``/``engineGroup``), which are out of scope.

ID resolution
-------------
Connector field ``id``s are transformed/prefixed relative to the source param
``name`` (e.g. ``passthrough_jamf_v2_insecure`` -> ``insecure``, or a credential
``credentials`` -> ``credentials_username`` + ``credentials_password``). The
authoritative ``id -> field_name`` mapping is the handler's
``serializer.yaml`` ``field_mappings``. When a handler has no mapping for an id,
we fall back to ``id == name``.

Always-advanced injected fields (R3)
------------------------------------
A small fixed set of fields are advanced even though they are not present (with
``advanced: true``) in the source YML because the generator injects them:

    * ``integrationLogLevel``  (backend log-level select; may be prefixed and is
                                resolved back via the serializer to
                                ``integrationLogLevel``)
    * ``defaultIgnore``        (backend automation opt-out checkbox)
    * ``eventFetchInterval``   (auto-injected event-collector duration)

Note ``incidentFetchInterval`` is deliberately NOT in this set (it is injected
but never advanced), and ``assetsFetchInterval`` is covered by the normal
source-driven path (it carries ``advanced: true`` in the source YML).

Scope
-----
Only ``configurations.yaml`` and ``connection.yaml`` are edited. The edit is
whole-block: if a block bundles both advanced and non-advanced fields (which
does not occur in current data) it is left untouched and a warning is emitted,
rather than mislabelling the block.

CLI
---
    # Whole tree, using the default pipeline CSV:
    python3 add_advanced_section.py --dry-run
    python3 add_advanced_section.py

    # Single connector, explicit connectors dir + CSV (as the E2E harness runs):
    python3 add_advanced_section.py \
        --connectors-dir /tmp/sandbox/connectors \
        --path acme-creds \
        --pipeline-csv /tmp/sandbox/connectus-migration-pipeline.csv

The patch edits files in place using ruamel.yaml so comments, key order and
formatting are preserved.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from ruamel.yaml import YAML

# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #
SCRIPT_DIR = Path(__file__).resolve().parent  # content/connectus/connectus_migration
CONNECTUS_DIR = SCRIPT_DIR.parent  # content/connectus
CONTENT_REPO = CONNECTUS_DIR.parent  # content
DEFAULT_PIPELINE_CSV = CONNECTUS_DIR / "connectus-migration-pipeline.csv"

# CSV columns.
COL_INTEGRATION_ID = "Integration ID"
COL_INTEGRATION_PATH = "Integration File Path"
COL_CONNECTOR_PATH = "Connector Folder Path"

# The manifests we edit.
TARGET_FILES = ("configurations.yaml", "connection.yaml")

# R3: always-advanced injected/backend fields, keyed by RESOLVED field_name
# (i.e. after serializer id->field_name resolution).
ALWAYS_ADVANCED_FIELD_NAMES = frozenset(
    {"integrationLogLevel", "defaultIgnore", "eventFetchInterval", "assetsFetchInterval"}
)

EXIT_OK = 0
EXIT_USAGE = 2


# --------------------------------------------------------------------------- #
# YAML round-trip helper
# --------------------------------------------------------------------------- #
def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=2, offset=0)
    return y


def _load(path: Path):
    return _yaml().load(path.read_text())


# --------------------------------------------------------------------------- #
# Source XSOAR YML -> advanced param names
# --------------------------------------------------------------------------- #
def _resolve_integration_path(raw: str, csv_path: Path) -> Path | None:
    """Resolve a CSV ``Integration File Path`` to an existing file.

    The value is repo-relative. Try (in order): the CSV's own ``input/`` tree
    (the E2E fixture layout, where Packs sit beside the CSV), then the content
    repo root (production layout).
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    candidates = [
        csv_path.parent / raw,  # fixture: input/Packs/...
        CONTENT_REPO / raw,  # production: content/Packs/...
        Path(raw),  # last resort (absolute or cwd-relative)
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _advanced_param_names(integration_yml: Path) -> set[str]:
    """Return the set of source-YML param names carrying ``advanced: true``."""
    data = _load(integration_yml) or {}
    names: set[str] = set()
    for entry in data.get("configuration") or []:
        if isinstance(entry, dict) and entry.get("advanced") is True:
            name = entry.get("name")
            if name:
                names.add(str(name))
    return names


# --------------------------------------------------------------------------- #
# Per-handler linkage: handler.yaml -> integration id -> source advanced names
#                       serializer.yaml -> connector id -> source field_name
# --------------------------------------------------------------------------- #
def _handler_integration_id(handler_dir: Path) -> str | None:
    data = _load(handler_dir / "handler.yaml") or {}
    labels = (data.get("triggering") or {}).get("labels") or {}
    val = labels.get("xsoar-integration-id")
    return str(val) if val else None


def _handler_field_mappings(handler_dir: Path) -> dict[str, str]:
    data = _load(handler_dir / "serializer.yaml") if (handler_dir / "serializer.yaml").is_file() else {}
    mapping: dict[str, str] = {}
    for fm in (data or {}).get("field_mappings") or []:
        if isinstance(fm, dict) and "id" in fm and "field_name" in fm:
            mapping[str(fm["id"])] = str(fm["field_name"])
    return mapping


def _advanced_field_ids(
    connector_dir: Path,
    integration_id_to_advanced: dict[str, set[str]],
) -> set[str]:
    """Compute the concrete set of connector field ids that must be advanced.

    Resolution is PER-HANDLER: a serializer-mapped id is advanced iff it
    resolves (via THAT handler's serializer) to a param that is advanced in
    THAT handler's own source YML (or is an always-advanced injected field).

    Bare ids (present in no serializer) fall back to ``id == field_name`` and
    are checked against the UNION of every handler's advanced set — these are
    unprefixed backend/first-profile fields that are not claimed by any
    prefixed serializer mapping.
    """
    handlers_root = connector_dir / "components" / "handlers"
    advanced_ids: set[str] = set()
    all_mapped_ids: set[str] = set()
    union_advanced_names: set[str] = set()

    handler_dirs = (
        [d for d in handlers_root.iterdir() if d.is_dir()]
        if handlers_root.is_dir()
        else []
    )

    for hdir in handler_dirs:
        integ_id = _handler_integration_id(hdir)
        adv_names = integration_id_to_advanced.get(integ_id, set()) if integ_id else set()
        union_advanced_names |= adv_names
        mappings = _handler_field_mappings(hdir)
        for cid, fname in mappings.items():
            all_mapped_ids.add(cid)
            if fname in adv_names or fname in ALWAYS_ADVANCED_FIELD_NAMES:
                advanced_ids.add(cid)

    return advanced_ids, all_mapped_ids, union_advanced_names


# --------------------------------------------------------------------------- #
# Block classification + mutation
# --------------------------------------------------------------------------- #
def _field_ids(block: dict) -> list[str]:
    fields = block.get("fields")
    if not isinstance(fields, list):
        return []
    return [str(f.get("id")) for f in fields if isinstance(f, dict) and "id" in f]


def _field_id_is_advanced(
    field_id: str,
    advanced_ids: set[str],
    all_mapped_ids: set[str],
    union_advanced_names: set[str],
) -> bool:
    """True iff a single connector field id must be advanced."""
    if field_id in advanced_ids:
        return True
    # Bare id claimed by no serializer -> id == field_name fallback.
    if field_id not in all_mapped_ids:
        return (
            field_id in union_advanced_names
            or field_id in ALWAYS_ADVANCED_FIELD_NAMES
        )
    return False


def _block_is_advanced(
    block: dict,
    advanced_ids: set[str],
    all_mapped_ids: set[str],
    union_advanced_names: set[str],
) -> bool | None:
    """Decide whether a block should be marked advanced.

    Returns True/False, or None when the block MIXES advanced and non-advanced
    fields (ambiguous — caller should skip + warn).
    """
    ids = _field_ids(block)
    if not ids:
        return False
    flags = [
        _field_id_is_advanced(fid, advanced_ids, all_mapped_ids, union_advanced_names)
        for fid in ids
    ]
    if all(flags):
        return True
    if not any(flags):
        return False
    return None  # mixed


def _iter_blocks(node):
    """Yield every ``configurations[]`` list item that is a ``{fields: ...}`` block."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "configurations" and isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "fields" in item:
                        yield item
                    yield from _iter_blocks(item)
            else:
                yield from _iter_blocks(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_blocks(item)


def _set_block_advanced(block: dict) -> None:
    """Insert ``advanced: true`` as the FIRST key of the block (before fields)."""
    if block.get("advanced") is True:
        return
    block["advanced"] = True
    # Move 'advanced' to the front to match the golden layout.
    try:
        block.move_to_end("advanced", last=False)  # CommentedMap supports this
    except (AttributeError, KeyError):
        pass


def _patch_manifest(
    path: Path,
    advanced_ids: set[str],
    all_mapped_ids: set[str],
    union_advanced_names: set[str],
) -> tuple[int, list[str]]:
    """Patch one manifest in place. Returns (num_blocks_marked, warnings)."""
    data = _load(path)
    if data is None:
        return 0, []
    marked = 0
    warnings: list[str] = []
    for block in _iter_blocks(data):
        if block.get("advanced") is True:
            continue  # idempotent
        decision = _block_is_advanced(
            block, advanced_ids, all_mapped_ids, union_advanced_names
        )
        if decision is True:
            _set_block_advanced(block)
            marked += 1
        elif decision is None:
            warnings.append(
                f"{path}: skipped mixed advanced/non-advanced block "
                f"(fields={_field_ids(block)})"
            )
    if marked:
        buf = path
        yaml = _yaml()
        with buf.open("w") as fh:
            yaml.dump(data, fh)
    return marked, warnings


# --------------------------------------------------------------------------- #
# Discovery + per-connector processing
# --------------------------------------------------------------------------- #
def _connector_folder_name(raw: str) -> str:
    """Normalise a CSV ``Connector Folder Path`` to its bare connector dir name."""
    raw = (raw or "").strip().rstrip("/")
    if not raw:
        return ""
    # Drop a leading ``connectors/`` segment if present.
    parts = Path(raw).parts
    if parts and parts[0] == "connectors":
        parts = parts[1:]
    return "/".join(parts)


def _load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def process(
    connectors_dir: Path,
    csv_path: Path,
    only_connector: str | None,
    dry_run: bool,
) -> tuple[int, int, list[str]]:
    """Process all connectors. Returns (connectors_changed, blocks_marked, warns)."""
    rows = _load_rows(csv_path)

    # Map: XSOAR Integration ID -> advanced param names (from its source YML).
    # Also collect the set of connector folders referenced.
    integration_advanced: dict[str, set[str]] = {}
    connector_folders: set[str] = set()
    for row in rows:
        conn = _connector_folder_name(row.get(COL_CONNECTOR_PATH, ""))
        if conn:
            connector_folders.add(conn)
        integ_id = (row.get(COL_INTEGRATION_ID) or "").strip()
        integ_path = _resolve_integration_path(
            row.get(COL_INTEGRATION_PATH, ""), csv_path
        )
        names = _advanced_param_names(integ_path) if integ_path else set()
        if integ_id:
            integration_advanced.setdefault(integ_id, set()).update(names)

    connectors_changed = 0
    blocks_marked = 0
    warnings: list[str] = []

    for conn in sorted(connector_folders):
        if only_connector and conn != only_connector:
            continue
        connector_dir = connectors_dir / conn
        if not connector_dir.is_dir():
            warnings.append(f"connector folder not found: {connector_dir}")
            continue

        advanced_ids, all_mapped_ids, union_names = _advanced_field_ids(
            connector_dir, integration_advanced
        )

        conn_marked = 0
        for fname in TARGET_FILES:
            manifest = connector_dir / fname
            if not manifest.is_file():
                continue
            if dry_run:
                data = _load(manifest)
                if data is None:
                    continue
                for block in _iter_blocks(data):
                    if block.get("advanced") is True:
                        continue
                    decision = _block_is_advanced(
                        block, advanced_ids, all_mapped_ids, union_names
                    )
                    if decision is True:
                        conn_marked += 1
                        print(
                            f"[dry-run] would mark advanced: {conn}/{fname} "
                            f"fields={_field_ids(block)}"
                        )
                    elif decision is None:
                        warnings.append(
                            f"{manifest}: mixed advanced/non-advanced block "
                            f"(fields={_field_ids(block)})"
                        )
            else:
                marked, warns = _patch_manifest(
                    manifest, advanced_ids, all_mapped_ids, union_names
                )
                conn_marked += marked
                warnings.extend(warns)
                if marked:
                    print(f"marked {marked} block(s) advanced in {conn}/{fname}")

        if conn_marked:
            connectors_changed += 1
            blocks_marked += conn_marked

    return connectors_changed, blocks_marked, warnings


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--connectors-dir",
        type=Path,
        default=None,
        help="Path to the connectors/ root to patch. Defaults to "
        "unified-connectors-content/connectors relative to the pipeline CSV, "
        "or the CSV's sibling connectors/ dir in fixtures.",
    )
    ap.add_argument(
        "--path",
        default=None,
        help="Restrict to a single connector (bare folder name, e.g. 'acme-creds').",
    )
    ap.add_argument(
        "path_positional",
        nargs="?",
        default=None,
        help="Optional positional alias for --path.",
    )
    ap.add_argument(
        "--pipeline-csv",
        type=Path,
        default=DEFAULT_PIPELINE_CSV,
        help="Path to the migration pipeline CSV.",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Report intended changes without writing any files.",
    )
    args = ap.parse_args(argv)

    csv_path: Path = args.pipeline_csv
    if not csv_path.is_file():
        print(f"ERROR: pipeline CSV not found: {csv_path}", file=sys.stderr)
        return EXIT_USAGE

    # Resolve connectors dir.
    connectors_dir: Path | None = args.connectors_dir
    if connectors_dir is None:
        sibling = csv_path.parent / "connectors"
        if sibling.is_dir():
            connectors_dir = sibling
        else:
            connectors_dir = CONTENT_REPO.parent / "unified-connectors-content" / "connectors"
    if not connectors_dir.is_dir():
        print(f"ERROR: connectors dir not found: {connectors_dir}", file=sys.stderr)
        return EXIT_USAGE

    only = args.path or args.path_positional
    if only:
        only = _connector_folder_name(only)

    connectors_changed, blocks_marked, warnings = process(
        connectors_dir=connectors_dir,
        csv_path=csv_path,
        only_connector=only,
        dry_run=args.dry_run,
    )

    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    verb = "would modify" if args.dry_run else "modified"
    print(
        f"\nSummary: {verb} {blocks_marked} block(s) across "
        f"{connectors_changed} connector(s)."
    )
    if args.dry_run:
        print("(--dry-run: no files were written.)")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
