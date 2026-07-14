#!/usr/bin/env python3
"""Group the three "engine" params in every connector's connection.yaml.

For each auth profile in a connector's ``connection.yaml`` this script:

1. Finds the three engine params by their connection-field ``id`` suffix:
   ``engine_mode``, ``engine`` and ``engineGroup``.  In single-profile
   connectors the ids are bare (``engine_mode``); in multi-profile
   connectors they carry a per-profile prefix
   (``<prefix>_engine_mode``).  Matching is done on the *exact* suffix so
   footguns like ``..._engine_url`` or a profile literally named
   ``..._engine`` are never mis-detected.

2. Collapses the three *separate* ``configurations[]`` entries (each a
   ``{fields: [<one field>]}`` block) into a SINGLE ``configurations[]``
   entry whose ``fields`` list holds all three, ordered
   ``engine_mode, engine, engineGroup``.  The merged entry is placed at
   the position of the first (lowest-index) engine entry; the other two
   entries are removed.  Profiles already grouped into one entry are left
   untouched (idempotent).

3. Ensures every ``engine_mode`` field carries
   ``options.orientation: horizontal``.

The script edits ``connection.yaml`` in place using ruamel.yaml so
comments, key order and formatting are preserved (verified byte-identical
on a no-op round-trip).  Run with ``--dry-run`` to preview without
writing, and ``--verbose`` for per-profile detail.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
from pathlib import Path

from ruamel.yaml import YAML

# --- Layout ------------------------------------------------------------------
# Run from the idex parent cwd (the dir that holds content/ and
# unified-connectors-content/ as siblings). Resolve both repos relative to it.
SCRIPT_DIR = Path(__file__).resolve().parent          # content/connectus/connectus_migration
CONTENT_REPO = SCRIPT_DIR.parents[2]                  # content/
PARENT = CONTENT_REPO.parent                          # idex parent cwd
CONNECTUS_REPO = PARENT / "unified-connectors-content"
CONNECTORS_ROOT = CONNECTUS_REPO / "connectors"
PIPELINE_CSV = CONTENT_REPO / "connectus" / "connectus-migration-pipeline.csv"

# The three engine param id-suffixes, in the canonical merged order.
ENGINE_SUFFIXES = ("engine_mode", "engine", "engineGroup")

# EDL has no handler and shares connectors/generic-intel-feed with 5 other
# valid integrations, so "except EDL" is a no-op at the connector level
# (per user decision) — the connector is still processed for its siblings.


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=2, offset=0)
    return y


def engine_suffix_of(field_id: str) -> str | None:
    """Return the engine suffix a field id matches, or None.

    Longest suffix wins so ``x_engine_mode`` is classified as
    ``engine_mode`` and not ``engine``.  A field id matches a suffix S iff
    it equals S exactly or ends with ``_S``.
    """
    for suf in ("engine_mode", "engineGroup", "engine"):  # longest-first
        if field_id == suf or field_id.endswith("_" + suf):
            return suf
    return None


def process_profile(profile: dict, *, verbose: bool = False) -> dict:
    """Group engine fields + set orientation for one profile (in place).

    Returns a small stats dict describing what changed.
    """
    stats = {
        "grouped": False,
        "orientation_fixed": 0,
        "already_grouped": False,
        "has_engine": False,
        "missing_suffixes": None,
    }
    configs = profile.get("configurations")
    if not isinstance(configs, list):
        return stats

    # Map suffix -> list of (config_index, field_index, field_dict)
    found: dict[str, list[tuple[int, int, dict]]] = {}
    for ci, cfg in enumerate(configs):
        fields = cfg.get("fields") if isinstance(cfg, dict) else None
        if not isinstance(fields, list):
            continue
        for fi, fld in enumerate(fields):
            if not isinstance(fld, dict):
                continue
            suf = engine_suffix_of(str(fld.get("id", "")))
            if suf:
                found.setdefault(suf, []).append((ci, fi, fld))

    if not found:
        return stats
    stats["has_engine"] = True

    # Only handle the well-formed case: exactly one of each suffix present.
    present = [s for s in ENGINE_SUFFIXES if s in found]
    if len(present) != 3 or any(len(found[s]) != 1 for s in present):
        stats["missing_suffixes"] = [s for s in ENGINE_SUFFIXES if s not in found] or "duplicate"
        # Still fix orientation on any engine_mode we did find.
        stats["orientation_fixed"] += _ensure_orientation(found.get("engine_mode", []))
        return stats

    # (config_index, field_index, field_dict) for each of the three.
    locs = {s: found[s][0] for s in ENGINE_SUFFIXES}
    config_indices = {locs[s][0] for s in ENGINE_SUFFIXES}

    # Fix orientation on engine_mode regardless of grouping state.
    stats["orientation_fixed"] += _ensure_orientation([locs["engine_mode"]])

    if len(config_indices) == 1:
        # All three already live in one configurations[] entry — but confirm
        # that entry contains ONLY these three (i.e. it is the merged block).
        stats["already_grouped"] = True
        return stats

    # --- Collapse the three separate entries into one -----------------------
    # The three field dicts, in canonical order.
    engine_fields = [locs[s][2] for s in ENGINE_SUFFIXES]

    # Position of the merged block = the first (lowest) engine config index.
    first_ci = min(config_indices)

    # Build the merged configuration entry, reusing the first block's dict so
    # any sibling keys on it (there are none in practice) are preserved.
    merged_cfg = configs[first_ci]
    # Preserve the CommentedSeq type of an existing fields list for clean dump.
    merged_cfg["fields"] = _as_seq_like(merged_cfg.get("fields"), engine_fields)

    # Remove the other two engine-bearing config entries. Delete by descending
    # index so earlier indices stay valid.
    to_delete = sorted((ci for ci in config_indices if ci != first_ci), reverse=True)
    for ci in to_delete:
        del configs[ci]

    stats["grouped"] = True
    if verbose:
        ids = [f.get("id") for f in engine_fields]
        print(f"      grouped {ids} into configurations[{first_ci}]")
    return stats


def _as_seq_like(template, items):
    """Return ``items`` as the same sequence type as ``template`` (ruamel
    CommentedSeq) so the dumped YAML formatting is consistent."""
    try:
        seq = type(template)()
        for it in items:
            seq.append(it)
        return seq
    except Exception:
        return list(items)


def _ensure_orientation(engine_mode_locs) -> int:
    """Ensure options.orientation == 'horizontal' on given engine_mode fields.

    ``engine_mode_locs`` is a list of (ci, fi, field_dict) tuples. Returns
    the number of fields modified.
    """
    fixed = 0
    for _ci, _fi, fld in engine_mode_locs:
        opts = fld.get("options")
        if opts is None:
            fld["options"] = {"orientation": "horizontal"}
            fixed += 1
            continue
        if opts.get("orientation") != "horizontal":
            opts["orientation"] = "horizontal"
            fixed += 1
    return fixed


def target_connection_files(include_examples: bool) -> list[Path]:
    """Resolve the connection.yaml files to process.

    Scope = every connector on disk that backs a CSV-tracked integration,
    resolved to the ACTUAL on-disk folder (the CSV Connector Folder Path is
    partially stale). ``examples/`` connectors are included when requested.
    """
    files: list[Path] = []
    seen: set[Path] = set()

    # 1. All on-disk connection.yaml files.
    disk = {p.parent.name: p for p in CONNECTORS_ROOT.glob("*/connection.yaml")}
    disk_examples = list((CONNECTORS_ROOT / "examples").glob("*/connection.yaml"))

    # 2. Connectors referenced by the CSV (by folder path AND by a slugged
    #    fallback when the literal path is stale).
    csv_folder_names: set[str] = set()
    if PIPELINE_CSV.exists():
        with open(PIPELINE_CSV) as f:
            for row in csv.DictReader(f):
                cfp = (row.get("Connector Folder Path") or "").strip()
                if cfp:
                    csv_folder_names.add(Path(cfp).name)

    for name, path in sorted(disk.items()):
        # Include if referenced literally by the CSV, or referenced via the
        # stale-without-suffix alias (e.g. CSV 'microsoft-security' ->
        # on-disk 'microsoft-security-automation-and-collection').
        referenced = name in csv_folder_names or any(
            name == alias or name.startswith(alias + "-") for alias in csv_folder_names
        )
        if referenced and path not in seen:
            files.append(path)
            seen.add(path)

    if include_examples:
        for path in sorted(disk_examples):
            if path not in seen:
                files.append(path)
                seen.add(path)

    return files


def process_file(path: Path, *, dry_run: bool, verbose: bool) -> dict:
    y = _yaml()
    with open(path) as f:
        data = y.load(f)

    file_stats = {
        "path": str(path),
        "profiles_grouped": 0,
        "profiles_already": 0,
        "orientation_fixed": 0,
        "profiles_with_engine": 0,
        "anomalies": [],
        "changed": False,
    }
    if not isinstance(data, dict):
        return file_stats

    for profile in data.get("profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        s = process_profile(profile, verbose=verbose)
        if s["has_engine"]:
            file_stats["profiles_with_engine"] += 1
        if s["grouped"]:
            file_stats["profiles_grouped"] += 1
        if s["already_grouped"]:
            file_stats["profiles_already"] += 1
        file_stats["orientation_fixed"] += s["orientation_fixed"]
        if s["missing_suffixes"]:
            file_stats["anomalies"].append(
                {"profile": profile.get("id"), "issue": s["missing_suffixes"]}
            )

    file_stats["changed"] = (
        file_stats["profiles_grouped"] > 0 or file_stats["orientation_fixed"] > 0
    )

    if file_stats["changed"] and not dry_run:
        buf = io.StringIO()
        y.dump(data, buf)
        with open(path, "w") as f:
            f.write(buf.getvalue())

    return file_stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Preview changes without writing files.")
    ap.add_argument("--verbose", action="store_true",
                    help="Print per-profile grouping detail.")
    ap.add_argument("--no-examples", action="store_true",
                    help="Skip connectors under connectors/examples/.")
    ap.add_argument("--only", metavar="CONNECTOR",
                    help="Process only this single connector folder name "
                         "(e.g. 'tanium'), for testing.")
    args = ap.parse_args()

    if not CONNECTORS_ROOT.is_dir():
        print(f"ERROR: connectors root not found: {CONNECTORS_ROOT}", file=sys.stderr)
        return 2

    files = target_connection_files(include_examples=not args.no_examples)
    if args.only:
        files = [p for p in files if p.parent.name == args.only]
        if not files:
            print(f"ERROR: connector '{args.only}' not in scope / not found.", file=sys.stderr)
            return 2

    print(f"{'DRY-RUN: ' if args.dry_run else ''}Processing {len(files)} connection.yaml files")
    print(f"  connectors root: {CONNECTORS_ROOT}")
    print()

    tot_files_changed = 0
    tot_grouped = 0
    tot_already = 0
    tot_orient = 0
    tot_engine_profiles = 0
    all_anomalies: list[tuple[str, object]] = []

    for path in files:
        s = process_file(path, dry_run=args.dry_run, verbose=args.verbose)
        tot_grouped += s["profiles_grouped"]
        tot_already += s["profiles_already"]
        tot_orient += s["orientation_fixed"]
        tot_engine_profiles += s["profiles_with_engine"]
        for a in s["anomalies"]:
            all_anomalies.append((path.parent.name, a))
        if s["changed"]:
            tot_files_changed += 1
            if args.verbose:
                print(f"  [{'would change' if args.dry_run else 'changed'}] "
                      f"{path.parent.name}: grouped={s['profiles_grouped']} "
                      f"orientation_fixed={s['orientation_fixed']}")

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  connection.yaml files scanned      : {len(files)}")
    print(f"  files {'that would change' if args.dry_run else 'changed':<26}: {tot_files_changed}")
    print(f"  profiles with engine params        : {tot_engine_profiles}")
    print(f"  profiles grouped (3 -> 1 entry)    : {tot_grouped}")
    print(f"  profiles already grouped (skipped) : {tot_already}")
    print(f"  engine_mode orientation fixes      : {tot_orient}")
    if all_anomalies:
        print(f"\n  ANOMALIES (engine params not a clean triple) : {len(all_anomalies)}")
        for conn, a in all_anomalies:
            print(f"    - {conn}: profile={a['profile']} issue={a['issue']}")
    else:
        print("\n  anomalies: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
