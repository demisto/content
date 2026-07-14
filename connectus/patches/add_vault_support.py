#!/usr/bin/env python3
"""Patch already-committed ConnectUs ``connection.yaml`` files to BACK-FILL the
schema-valid ``vault_mappings`` block on type-9 PASSTHROUGH profiles.

Background
==========
The manifest generator now derives a profile-level ``vault_mappings`` block for
every PASSTHROUGH profile that carries type-9 (Credentials widget) credentials
(see ``connectus_migration.manifest_generator._build_vault_mappings`` and the
``_VAULT_MAP_SLOT_FOR_LEAF`` table). This script retrofits the SAME block onto
connectors that were ALREADY committed to disk by an earlier generator — WITHOUT
regenerating from the source XSOAR YML.

Standalone-by-design
====================
This patch is deliberately STANDALONE: it does NOT import the generator. The
generator derives ``vault_mappings`` from a freshly-built ``raw_param_map`` (the
``<param>.<leaf> -> role`` map it computes while reading the integration YML).
On an ALREADY-committed manifest that information is already encoded in the
profile's own ``metadata.xsoar.interpolation_mapping`` string, so we reproduce
the equivalent derivation FROM THE PROFILE rather than from the integration YML.
This means the integration YML / pipeline CSV / handler linkage are NOT required
to compute the result (``--pipeline-csv`` is accepted for CLI-contract
compatibility with ``flatten_non_type9_nesting.py`` but is not needed here).

Derivation (mirrors ``_build_vault_mappings``, sourced from interpolation_mapping)
=================================================================================
A profile's ``metadata.xsoar.interpolation_mapping`` is a comma-joined string of
``<role>:<xsoar_path>`` entries (the INVERSE of the generator's raw param map:
the role is on the LEFT, the xsoar_path on the RIGHT). For each entry:

  * a DOTTED ``xsoar_path`` (``<param>.<leaf>``) is a type-9 credential leaf.
    Group by ``<param>``; map the leaf onto a vault slot via the same table the
    generator uses — ``identifier`` -> ``user``, ``password`` -> ``password`` —
    valued by that entry's ROLE (the left-hand side). Out-of-scope leaves (e.g.
    ``sshkey``) are ignored (no slot invented).
  * a FLAT (non-dotted) ``xsoar_path`` is NOT a type-9 credential -> ignored.

One ``vault_mappings`` entry is produced per ``<param>``, ordered by each param's
FIRST appearance (left-to-right) in the interpolation_mapping string:

    {"id": <param>, "map": {<slot>: <role>, ...}}   # map has >=1 key

For the RemoteAccess fixture this yields (matching the golden):

    - id: credentials
      map: {user: username, password: password}
    - id: additional_password
      map: {password: additional_password}

Scope guard
===========
* ONLY ``type: passthrough`` profiles qualify. ``plain`` / ``api_key`` /
  ``external_auth`` / ``oauth2*`` profiles are NEVER touched.
* The ``vault_support`` boolean is NEVER added, removed or altered.
* A passthrough profile with no dotted type-9 cred in its interpolation_mapping
  gets nothing added.

Idempotency
===========
A passthrough profile that ALREADY has a ``vault_mappings`` key is skipped
(no duplicate, no reorder). Re-running the patch is a no-op.

Placement
=========
``vault_mappings`` is inserted immediately AFTER the profile's ``description``
key (before ``metadata``), via a ruamel round-trip so the rest of the file is
preserved verbatim. If there is no ``description``, it falls back to after
``title`` and finally to before ``metadata`` / append.

Dry-run / idempotency / formatting
==================================
* ``--dry-run`` computes + REPORTS intended changes but writes nothing.
* Unrelated YAML content / key order is preserved (ruamel round-trip).

Usage
=====
    # Whole-repo dry run (recommended first):
    python3 patches/add_vault_support.py --dry-run

    # Whole-repo apply in place (default):
    python3 patches/add_vault_support.py

    # Restrict to a single connector or connection.yaml:
    python3 patches/add_vault_support.py --path connectors/remoteaccess
    python3 patches/add_vault_support.py --path connectors/remoteaccess/connection.yaml

Run from anywhere; paths are resolved via the same env-wired helpers the rest of
the connectus toolchain uses (``CONNECTUS_REPO_DIR`` / repo-root fallback).
"""

from __future__ import annotations

import argparse
import io
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ruamel.yaml gives round-trip fidelity (preserves key order, comments, quoting,
# block style). It is a declared dependency of this repo; we fall back to PyYAML
# only if it is somehow unavailable, accepting reduced formatting fidelity.
try:
    from ruamel.yaml import YAML  # type: ignore
    from ruamel.yaml.comments import CommentedMap  # type: ignore

    _HAVE_RUAMEL = True
except ImportError:  # pragma: no cover - exercised only on misconfigured envs
    import yaml as _pyyaml  # type: ignore

    _HAVE_RUAMEL = False


# --------------------------------------------------------------------------- #
# Repo-root / path resolution — reuse the canonical connectus helpers.
# --------------------------------------------------------------------------- #
_HERE = Path(__file__).resolve().parent           # .../content/connectus/patches
_CONNECTUS_DIR = _HERE.parent                      # .../content/connectus
if str(_CONNECTUS_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTUS_DIR))

try:
    # Single, unified env loader + repo-root finder used by the whole toolchain.
    from env_loader import find_repo_root, load_env  # type: ignore
except Exception:  # pragma: no cover - defensive fallback only
    def find_repo_root(start: Path | None = None) -> Path:  # type: ignore
        origin = (start or Path(__file__)).resolve()
        for cand in (origin, *origin.parents):
            if (cand / ".git").exists() or (cand / "pyproject.toml").exists():
                return cand
        return _CONNECTUS_DIR.parent.parent

    def load_env(override: bool = False):  # type: ignore
        return None


_CONNECTUS_REPO_ENV = "CONNECTUS_REPO_DIR"
_CONNECTUS_REPO_DIRNAME = "unified-connectors-content"


def resolve_connectors_dir(explicit: str | None) -> Path:
    """Resolve the ``unified-connectors-content/connectors`` directory.

    Resolution order (mirrors ``flatten_non_type9_nesting.resolve_connectors_dir``):

    1. ``explicit`` (``--connectors-dir``) wins.
    2. ``$CONNECTUS_REPO_DIR/connectors`` when the env var is set.
    3. ``<repo-root>/unified-connectors-content/connectors`` (sibling default).
    """
    import os

    if explicit:
        return Path(os.path.abspath(explicit))
    override = os.environ.get(_CONNECTUS_REPO_ENV)
    if override and override.strip():
        return Path(os.path.abspath(override.strip())) / "connectors"
    return find_repo_root() / _CONNECTUS_REPO_DIRNAME / "connectors"


# --------------------------------------------------------------------------- #
# YAML round-trip helpers (mirror flatten_non_type9_nesting).
# --------------------------------------------------------------------------- #
def _make_yaml() -> "YAML":
    y = YAML()
    y.preserve_quotes = True
    # Match the generator's emitted block style: 2-space indent, sequences
    # dedented to their parent (the on-disk convention across all manifests:
    # ``profiles:`` then ``- id: ...`` at column 0 under it).
    y.indent(mapping=2, sequence=2, offset=0)
    y.width = 10**9  # never auto-wrap long scalars (e.g. interpolation_mapping)
    return y


def load_yaml(path: Path) -> dict:
    """Load a connection.yaml, preserving formatting where possible."""
    text = path.read_text()
    if _HAVE_RUAMEL:
        return _make_yaml().load(text) or {}
    return _pyyaml.safe_load(text) or {}


def dump_yaml(doc: dict, path: Path) -> None:
    """Write ``doc`` back to ``path`` preserving round-trip formatting."""
    if _HAVE_RUAMEL:
        buf = io.StringIO()
        _make_yaml().dump(doc, buf)
        path.write_text(buf.getvalue())
        return
    with path.open("w") as fh:  # pragma: no cover - fallback path
        _pyyaml.safe_dump(
            doc, fh, sort_keys=False, default_flow_style=False, allow_unicode=True
        )


def dumps_yaml(doc: dict) -> str:
    """Serialize ``doc`` to a string (used for dry-run change detection)."""
    if _HAVE_RUAMEL:
        buf = io.StringIO()
        _make_yaml().dump(doc, buf)
        return buf.getvalue()
    return _pyyaml.safe_dump(  # pragma: no cover - fallback path
        doc, sort_keys=False, default_flow_style=False, allow_unicode=True
    )


# --------------------------------------------------------------------------- #
# Derivation helpers.
# --------------------------------------------------------------------------- #
# Map a type-9 credential leaf name -> the vault_mappings ``map`` slot it fills
# (kept in lock-step with manifest_generator._VAULT_MAP_SLOT_FOR_LEAF). Only the
# ``identifier`` (username) and ``password`` (secret) leaves are in scope; any
# other leaf (e.g. sshkey) is ignored — we never invent a slot for it.
_VAULT_MAP_SLOT_FOR_LEAF: dict[str, str] = {
    "identifier": "user",
    "password": "password",
}

# Profile types that may carry vault_mappings. Mirrors the generator: ONLY
# passthrough profiles qualify.
_PASSTHROUGH = "passthrough"


def parse_interpolation_mapping(mapping: str) -> list[tuple[str, str]]:
    """``role:path,role2:path2`` -> ordered list of ``(role, xsoar_path)``.

    Order is preserved so first-appearance ordering of params is deterministic
    (mirrors ``flatten_non_type9_nesting.parse_interpolation_mapping``).
    """
    out: list[tuple[str, str]] = []
    for chunk in (mapping or "").split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        role, _, path = chunk.partition(":")
        out.append((role.strip(), path.strip()))
    return out


def derive_vault_mappings(interpolation_mapping: str) -> list[dict] | None:
    """Derive the ``vault_mappings`` list for a passthrough profile.

    Reproduces ``manifest_generator._build_vault_mappings`` but sources the
    ``<param>.<leaf> -> role`` relationship from the committed profile's
    ``interpolation_mapping`` (where the role is the LEFT side and the dotted
    xsoar_path the RIGHT side) instead of from a freshly-built raw_param_map.

    Returns a list of ``{"id": <param>, "map": {<slot>: <role>, ...}}`` entries
    (one per distinct type-9 cred param, ordered by first appearance) or ``None``
    when nothing should be emitted.
    """
    ordered_params: list[str] = []
    maps_by_param: dict[str, dict[str, str]] = {}
    for role, xsoar_path in parse_interpolation_mapping(interpolation_mapping):
        if "." not in xsoar_path:
            # Flat path: not a type-9 credential leaf -> ignore.
            continue
        param, _, leaf = xsoar_path.partition(".")
        slot = _VAULT_MAP_SLOT_FOR_LEAF.get(leaf)
        if slot is None:
            # Out-of-scope leaf (e.g. sshkey): do not invent a slot for it.
            continue
        if param not in maps_by_param:
            maps_by_param[param] = {}
            ordered_params.append(param)
        maps_by_param[param][slot] = role

    # Drop any param whose only leaves were out-of-scope (empty map): the schema
    # requires minProperties>=1, and an entry with no slots carries no meaning.
    entries = [
        {"id": param, "map": maps_by_param[param]}
        for param in ordered_params
        if maps_by_param[param]
    ]
    return entries or None


def _as_yaml_value(entries: list[dict]):
    """Convert plain entries into a ruamel-friendly value preserving slot order.

    ruamel dumps plain ``dict``/``list`` fine, but to keep the ``map`` slots in a
    stable, golden-matching order (``user`` before ``password``) under round-trip
    we materialize each ``map`` as a ``CommentedMap`` when ruamel is present.
    """
    if not _HAVE_RUAMEL:
        return entries
    out = []
    for entry in entries:
        cm = CommentedMap()
        cm["id"] = entry["id"]
        slot_map = CommentedMap()
        # Stable slot order: user first (if present), then password, then any
        # other slots in insertion order.
        for slot in ("user", "password"):
            if slot in entry["map"]:
                slot_map[slot] = entry["map"][slot]
        for slot, val in entry["map"].items():
            if slot not in slot_map:
                slot_map[slot] = val
        cm["map"] = slot_map
        out.append(cm)
    return out


def _insert_after_key(profile: dict, new_key: str, new_value, anchors: list[str]) -> None:
    """Insert ``new_key`` immediately AFTER the first present key in ``anchors``.

    Falls back to inserting BEFORE ``metadata`` (if present) and finally to a
    plain append. Uses ruamel ``CommentedMap.insert`` when available so the rest
    of the mapping's order/comments are preserved.
    """
    if _HAVE_RUAMEL and isinstance(profile, CommentedMap):
        keys = list(profile.keys())
        # 1) After the first available anchor key (e.g. description, then title).
        for anchor in anchors:
            if anchor in keys:
                profile.insert(keys.index(anchor) + 1, new_key, new_value)
                return
        # 2) Before metadata.
        if "metadata" in keys:
            profile.insert(keys.index("metadata"), new_key, new_value)
            return
        # 3) Append.
        profile[new_key] = new_value
        return

    # Plain-dict (PyYAML fallback): rebuild the mapping to honour placement.
    items = list(profile.items())
    profile.clear()
    inserted = False
    for key, val in items:
        if not inserted and key == "metadata":
            profile[new_key] = new_value
            inserted = True
        profile[key] = val
        if not inserted and key in anchors:
            profile[new_key] = new_value
            inserted = True
    if not inserted:
        profile[new_key] = new_value


# --------------------------------------------------------------------------- #
# Result type (mirror flatten_non_type9_nesting.PatchResult).
# --------------------------------------------------------------------------- #
@dataclass
class PatchResult:
    """Outcome of patching one connection.yaml."""

    path: Path
    modified: bool = False
    # Profile ids that gained a vault_mappings block.
    backfilled_profiles: list[str] = field(default_factory=list)
    # Human-readable per-change detail lines (for reporting).
    details: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Core: patch ONE connection.yaml in memory, optionally write.
# --------------------------------------------------------------------------- #
def patch_file(path: Path, dry_run: bool = False) -> PatchResult:
    """Patch a single ``connection.yaml``.

    Args:
        path: Path to the connection.yaml.
        dry_run: When True, compute changes but do NOT write.

    Returns:
        A :class:`PatchResult`. ``modified`` reflects whether the file content
        would change (whether or not it was actually written).
    """
    result = PatchResult(path=path)
    doc = load_yaml(path)
    if not isinstance(doc, dict):
        return result

    profiles = doc.get("profiles")
    if not isinstance(profiles, list):
        return result

    changed_any = False
    for prof in profiles:
        if not isinstance(prof, dict):
            continue
        if _patch_profile(prof, result):
            changed_any = True

    if changed_any:
        result.modified = True
        if not dry_run:
            dump_yaml(doc, path)
    return result


def _patch_profile(prof: dict, result: PatchResult) -> bool:
    """Back-fill vault_mappings on one profile in place. Returns True if changed."""
    # Scope guard: passthrough profiles ONLY. Never touch plain / api_key /
    # external_auth / oauth2*, and never the vault_support boolean.
    if str(prof.get("type", "")) != _PASSTHROUGH:
        return False

    # Idempotency: a profile that already declares vault_mappings is left as-is.
    if "vault_mappings" in prof:
        return False

    xsoar_meta = (prof.get("metadata") or {}).get("xsoar") or {}
    mapping = xsoar_meta.get("interpolation_mapping")
    if not mapping:
        return False

    entries = derive_vault_mappings(str(mapping))
    if not entries:
        # Passthrough but no dotted type-9 cred: add nothing.
        return False

    _insert_after_key(
        prof,
        "vault_mappings",
        _as_yaml_value(entries),
        anchors=["description", "title"],
    )

    prof_id = str(prof.get("id", "?"))
    result.backfilled_profiles.append(prof_id)
    pretty = ", ".join(
        f"{e['id']}={{{', '.join(f'{k}:{v}' for k, v in e['map'].items())}}}"
        for e in entries
    )
    result.details.append(
        f"  profile '{prof_id}': added vault_mappings [{pretty}]"
    )
    return True


# --------------------------------------------------------------------------- #
# Scanning (mirror flatten_non_type9_nesting).
# --------------------------------------------------------------------------- #
def find_connection_files(connectors_dir: Path) -> list[Path]:
    """Glob ``<connectors_dir>/**/connection.yaml`` (sorted, de-duplicated)."""
    if not connectors_dir.is_dir():
        return []
    return sorted(set(connectors_dir.glob("**/connection.yaml")))


def _resolve_scan_targets(connectors_dir: Path, restrict: str | None) -> list[Path]:
    """Resolve the set of connection.yaml files to process.

    ``restrict`` may be:
      * None                      -> whole repo (all connectors).
      * a connection.yaml path    -> just that file.
      * a connector dir / name    -> that connector's connection.yaml.
    """
    if not restrict:
        return find_connection_files(connectors_dir)

    p = Path(restrict)
    candidates = [p]
    if not p.is_absolute():
        candidates += [
            connectors_dir / restrict,
            connectors_dir.parent / restrict,  # allow 'connectors/<name>...'
            Path.cwd() / restrict,
        ]
    for cand in candidates:
        if cand.is_file() and cand.name == "connection.yaml":
            return [cand]
        if cand.is_dir():
            cy = cand / "connection.yaml"
            if cy.is_file():
                return [cy]
    # Last resort: treat as a bare connector folder name.
    cy = connectors_dir / restrict / "connection.yaml"
    if cy.is_file():
        return [cy]
    return []


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #
def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what WOULD change without writing any files.",
    )
    ap.add_argument(
        "--connectors-dir",
        default=None,
        help=(
            "Path to the unified-connectors-content 'connectors' dir. Defaults "
            "to $CONNECTUS_REPO_DIR/connectors, else "
            "<repo-root>/unified-connectors-content/connectors."
        ),
    )
    ap.add_argument(
        "--path",
        default=None,
        help=(
            "Restrict to a single connection.yaml or connector dir/name "
            "(default: scan ALL connectors)."
        ),
    )
    ap.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional alias for --path.",
    )
    ap.add_argument(
        "--pipeline-csv",
        default=None,
        help=(
            "Path to the discovery CSV. Accepted for CLI-contract parity with "
            "flatten_non_type9_nesting.py; this patch derives vault_mappings "
            "from each profile's own interpolation_mapping and does NOT need it."
        ),
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    load_env()

    connectors_dir = resolve_connectors_dir(args.connectors_dir)
    restrict = args.path or args.positional_path

    targets = _resolve_scan_targets(connectors_dir, restrict)
    if not targets:
        where = restrict or str(connectors_dir)
        print(f"No connection.yaml files found for: {where}", file=sys.stderr)
        return 1

    scanned = 0
    modified_results: list[PatchResult] = []
    for conn in targets:
        scanned += 1
        res = patch_file(conn, dry_run=args.dry_run)
        if res.modified:
            modified_results.append(res)

    _print_summary(connectors_dir, scanned, modified_results, args.dry_run)
    return 0


def _connector_name(path: Path) -> str:
    return path.resolve().parent.name


def _print_summary(
    connectors_dir: Path,
    scanned: int,
    modified: list[PatchResult],
    dry_run: bool,
) -> None:
    tag = "DRY-RUN" if dry_run else "APPLIED"
    verb = "would be modified" if dry_run else "modified"
    print("=" * 72)
    print(f"add_vault_support [{tag}]")
    print(f"connectors dir: {connectors_dir}")
    print("-" * 72)
    print(f"Scanned : {scanned} manifest(s)")
    print(f"{verb.capitalize():8}: {len(modified)} manifest(s)")

    if modified:
        print("\nChanged connectors:")
        for res in modified:
            profs = ", ".join(res.backfilled_profiles) or "(none)"
            print(
                f"  - {_connector_name(res.path)}: "
                f"vault_mappings back-filled on [{profs}]"
            )
            for line in res.details:
                print(f"    {line.strip()}")
        if dry_run:
            print("\n(--dry-run: no files were written.)")
    else:
        print("\nNothing to change — all passthrough profiles already correct.")
    print("=" * 72)


if __name__ == "__main__":
    raise SystemExit(main())
