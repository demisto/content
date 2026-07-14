#!/usr/bin/env python3
"""Patch already-generated ConnectUs ``connection.yaml`` files for the
*non-type-9 nesting* bug.

Background
==========
The manifest generator previously nested NON-type-9 auth params into dotted
``<param>.identifier`` / ``<param>.password`` leaves. Only XSOAR **type 9**
(the Credentials widget) may legitimately nest. Types 4 (Encrypted text), 14
(Certificate/Key), and everything else must be FLAT. The generator has since
been fixed (it flattens + warns going forward — see
``connectus_migration.manifest_generator._flatten_non_type9_param_map``). This
script repairs the manifests that were ALREADY written to disk by the old
generator.

What "nested" looks like on disk
================================
A profile's ``metadata.xsoar.interpolation_mapping`` is a comma-joined string of
``<auth_parameter>:<xsoar_path>`` entries. A NESTED entry has a dotted
``xsoar_path`` (``<param>.identifier`` or ``<param>.password``). The
corresponding ``configurations[].fields[]`` have ids derived from the dotted
key (mirroring ``manifest_generator._connection_field_id_from_map_key``):

* ``<param>.identifier``                 -> field id ``<param>_username``
* ``<param>.password`` (with .identifier sibling) -> field id ``<param>_password``
* ``<param>.password`` (no .identifier sibling)   -> field id bare ``<param>``

How a param's XSOAR type is resolved
====================================
For each dotted leaf we look up the *bare param name* (segment before the dot)
in the originating XSOAR integration YML's ``configuration[].type``.

Resolution is **PER-PROFILE**, not per-folder. A shared connector folder (e.g.
``aws`` with ~30 handlers) mixes many source integrations, and the SAME param
name can have DIFFERENT types across them (``access_key`` is type 0 in most AWS
integrations but type 9 in ``AWS-WAF``). Merging the whole folder's params would
clobber types and could corrupt a legitimately-nested type-9 profile. Instead,
each ``profiles[]`` entry is mapped back to its single source integration via the
handler linkage (mirrors ``fix_connection_mask_title.scope_for_integration``):

    components/handlers/<h>/handler.yaml
        triggering.labels.xsoar-integration-id   == the source integration
        id  ``xsoar-<view_group>``               == the profile's view_group
        capabilities[].auth_options[].id         == the profile's id

The profile's ``{param_name: type}`` is then read from THAT integration's YML
``configuration`` (resolved via the pipeline CSV ``Integration File Path``).

  * type == 9  -> leave the nesting alone (correct).
  * type != 9  -> FLATTEN the leaf (mirrors the fixed generator).
  * type cannot be resolved -> SKIP and REPORT (never blindly flatten — that
    could corrupt a legitimately-nested type-9 param whose YML we failed to
    read). Override with ``--flatten-unresolved`` to flatten unresolved leaves.

Flattening semantics (mirror of ``_flatten_non_type9_param_map``)
=================================================================
For each non-type-9 dotted leaf:
  * ``interpolation_mapping``: replace the dotted ``xsoar_path`` with the bare
    ``<param>``. When BOTH ``.identifier`` and ``.password`` leaves exist for the
    same param, they collapse onto a SINGLE flat entry; the ``.password``
    (secret) leaf wins so the surviving auth role is the credential role, not the
    username role.
  * ``configurations[].fields[]``: collapse the ``<param>_username`` +
    ``<param>_password`` fields into a single ``<param>`` field carrying the
    winning ``metadata.auth.parameter`` and ``options.mask: true`` (secret).
    A lone bare-``<param>`` field (single-leaf nesting) is kept in place with the
    same masking guarantee.

Safety / idempotency
====================
* Type-9 nesting is NEVER touched.
* A second run is a no-op (already-flat params have no dotted leaf to rewrite).
* Unrelated YAML content / key order is preserved (ruamel round-trip).
* ``--dry-run`` reports what WOULD change without writing.

Usage
=====
    # Whole-repo dry run (recommended first):
    python3 patches/flatten_non_type9_nesting.py --dry-run

    # Whole-repo apply in place (default):
    python3 patches/flatten_non_type9_nesting.py

    # Restrict to a single connector or connection.yaml:
    python3 patches/flatten_non_type9_nesting.py --path connectors/akamai
    python3 patches/flatten_non_type9_nesting.py --path connectors/akamai/connection.yaml

Run from anywhere; paths are resolved via the same env-wired helpers the rest
of the connectus toolchain uses (``CONNECTUS_REPO_DIR`` / repo-root fallback).
"""

from __future__ import annotations

import argparse
import csv
import inspect
import io
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Union

# A per-profile type resolver. Production form takes (connection_path, profile)
# and scopes types to that profile's source integration; a simpler 1-arg form
# (connection_path) is also accepted for unit tests.
TypeLookup = Union[
    Callable[[Path], dict],
    Callable[[Path, dict], dict],
]


def _call_type_lookup(type_lookup: "TypeLookup", path: Path, profile: dict) -> dict:
    """Invoke ``type_lookup`` supporting both the 1-arg and 2-arg signatures.

    The 2-arg ``(connection_path, profile)`` form is preferred (it lets the
    production resolver scope param types to the profile's source integration).
    A 1-arg ``(connection_path)`` form is accepted for convenience in tests.
    """
    try:
        sig = inspect.signature(type_lookup)
        n_params = len(
            [
                p
                for p in sig.parameters.values()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
        )
    except (TypeError, ValueError):
        n_params = 1
    if n_params >= 2:
        return type_lookup(path, profile) or {}  # type: ignore[call-arg]
    return type_lookup(path) or {}  # type: ignore[call-arg]

# ruamel.yaml gives round-trip fidelity (preserves key order, comments, quoting,
# block style). It is a declared dependency of this repo (used elsewhere); we
# fall back to PyYAML only if it is somehow unavailable, accepting reduced
# formatting fidelity in that case.
try:
    from ruamel.yaml import YAML  # type: ignore

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
_PIPELINE_CSV = _CONNECTUS_DIR / "connectus-migration-pipeline.csv"
_CONTENT_ROOT = _CONNECTUS_DIR.parent              # .../content


def resolve_connectors_dir(explicit: str | None) -> Path:
    """Resolve the ``unified-connectors-content/connectors`` directory.

    Resolution order (mirrors
    ``manifest_generator.resolve_connectors_root`` and ``gates.py``):

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
# YAML round-trip helpers.
# --------------------------------------------------------------------------- #
def _make_yaml() -> "YAML":
    y = YAML()
    y.preserve_quotes = True
    # Match the generator's emitted block style: 2-space indent, sequences
    # dedented to their parent (the on-disk convention seen across all manifests:
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
# interpolation_mapping <-> param-map helpers.
# --------------------------------------------------------------------------- #
def parse_interpolation_mapping(mapping: str) -> list[tuple[str, str]]:
    """``role:path,role2:path2`` -> ordered list of ``(auth_parameter, xsoar_path)``.

    Order is preserved so the rewritten mapping keeps its original entry order.
    """
    out: list[tuple[str, str]] = []
    for chunk in (mapping or "").split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        role, _, path = chunk.partition(":")
        out.append((role.strip(), path.strip()))
    return out


def _field_id_from_dotted(param: str, leaf: str, sibling_leaves: set[str]) -> str:
    """Mirror ``manifest_generator._connection_field_id_from_map_key``.

    ``<param>.identifier`` -> ``<param>_username``;
    ``<param>.password``   -> ``<param>_password`` when a ``.identifier`` sibling
                              exists, else bare ``<param>``.
    """
    if leaf == "identifier":
        return f"{param}_username"
    if leaf == "password":
        if "identifier" in sibling_leaves:
            return f"{param}_password"
        return param
    return f"{param}_{leaf}"


# --------------------------------------------------------------------------- #
# Result type.
# --------------------------------------------------------------------------- #
@dataclass
class PatchResult:
    """Outcome of patching one connection.yaml."""

    path: Path
    modified: bool = False
    flattened_params: list[str] = field(default_factory=list)
    unresolved_params: list[str] = field(default_factory=list)
    # Human-readable per-change detail lines (for reporting).
    details: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Core: patch ONE connection.yaml in memory, optionally write.
# --------------------------------------------------------------------------- #
def patch_file(
    path: Path,
    type_lookup: "TypeLookup",
    dry_run: bool = False,
    flatten_unresolved: bool = False,
) -> PatchResult:
    """Patch a single ``connection.yaml``.

    Args:
        path: Path to the connection.yaml.
        type_lookup: a PER-PROFILE resolver. It may be called either as
            ``type_lookup(connection_path, profile_dict)`` (production, to scope
            param types to the profile's source integration) or, for simple unit
            tests, as a 1-arg ``type_lookup(connection_path)``. Both forms are
            accepted (see :func:`_call_type_lookup`). Returns
            ``{param_name: xsoar_type}``.
        dry_run: When True, compute changes but do NOT write.
        flatten_unresolved: When True, flatten dotted leaves whose origin type
            cannot be resolved (default False — those are skipped + reported).

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
        # Resolve param types scoped to THIS profile's source integration.
        param_types = _call_type_lookup(type_lookup, path, prof)
        if _patch_profile(
            prof, param_types, flatten_unresolved, result
        ):
            changed_any = True

    if changed_any:
        result.modified = True
        if not dry_run:
            dump_yaml(doc, path)
    return result


def _patch_profile(
    prof: dict,
    param_types: dict[str, int],
    flatten_unresolved: bool,
    result: PatchResult,
) -> bool:
    """Patch one profile in place. Returns True if it changed."""
    xsoar_meta = (prof.get("metadata") or {}).get("xsoar") or {}
    mapping = xsoar_meta.get("interpolation_mapping")
    if not mapping:
        return False

    entries = parse_interpolation_mapping(mapping)

    # Group dotted leaves by bare param to detect .identifier/.password pairs and
    # to know the sibling leaves when deriving field ids.
    leaves_by_param: dict[str, set[str]] = {}
    for _role, path_val in entries:
        if "." in path_val:
            param, _, leaf = path_val.partition(".")
            leaves_by_param.setdefault(param, set()).add(leaf)

    # Decide, per bare param, whether to flatten.
    #   flatten  -> positively resolved non-type-9
    #   skip     -> type 9, OR unresolved (unless flatten_unresolved)
    params_to_flatten: set[str] = set()
    for param in leaves_by_param:
        ptype = param_types.get(param)
        if ptype is None:
            if flatten_unresolved:
                params_to_flatten.add(param)
            else:
                if param not in result.unresolved_params:
                    result.unresolved_params.append(param)
            continue
        if int(ptype) != 9:
            params_to_flatten.add(param)
        # type 9: legitimately nested — leave alone.

    if not params_to_flatten:
        return False

    # ---- 1) Rewrite interpolation_mapping -------------------------------- #
    # Mirror _flatten_non_type9_param_map: collapse dotted leaves of a flattened
    # param to ONE bare entry; the .password (secret) leaf wins.
    new_entries: list[tuple[str, str]] = []
    # Track which flattened params already emitted a (secret-winning) entry.
    emitted_secret: set[str] = set()
    emitted_param: set[str] = set()
    # First pass: find the winning role per flattened param (password wins).
    winning_role: dict[str, str] = {}
    for role, path_val in entries:
        if "." not in path_val:
            continue
        param, _, leaf = path_val.partition(".")
        if param not in params_to_flatten:
            continue
        if leaf == "password":
            winning_role[param] = role
            emitted_secret.add(param)
        elif param not in winning_role:
            winning_role[param] = role

    for role, path_val in entries:
        if "." not in path_val:
            new_entries.append((role, path_val))
            continue
        param, _, _leaf = path_val.partition(".")
        if param not in params_to_flatten:
            # Type-9 (or unresolved-and-skipped) dotted leaf: keep verbatim.
            new_entries.append((role, path_val))
            continue
        # Flattened param: emit a single bare entry with the winning role.
        if param in emitted_param:
            continue
        emitted_param.add(param)
        new_entries.append((winning_role[param], param))

    new_mapping = ",".join(f"{r}:{p}" for r, p in new_entries)
    if new_mapping != mapping:
        xsoar_meta["interpolation_mapping"] = new_mapping

    # ---- 2) Collapse fields ---------------------------------------------- #
    for param in sorted(params_to_flatten):
        leaves = leaves_by_param.get(param, set())
        win_role = winning_role[param]
        _collapse_fields(prof, param, leaves, win_role)
        if param not in result.flattened_params:
            result.flattened_params.append(param)
        result.details.append(
            f"  profile '{prof.get('id', '?')}': flattened '{param}' "
            f"(dotted leaves {sorted(leaves)}) -> flat '{param}' "
            f"[auth.parameter={win_role}, mask=true]"
        )

    return True


def _collapse_fields(
    prof: dict, param: str, leaves: set[str], win_role: str
) -> None:
    """Collapse the dotted-leaf fields of ``param`` into a single flat field.

    The surviving field id is the bare ``<param>``; it carries
    ``metadata.auth.parameter = win_role`` and ``options.mask = True`` (a
    flattened non-type-9 param is always a secret: type 4 / 14). All
    ``<param>_username`` / ``<param>_password`` / bare ``<param>`` fields for this
    param are removed and replaced by one consolidated field, keeping the field's
    original position and any unrelated options (required/hidden etc.).
    """
    # The field ids that belonged to this param's nested leaves.
    target_ids = {
        _field_id_from_dotted(param, leaf, leaves) for leaf in leaves
    }
    target_ids.add(param)  # lone-bare-leaf case

    # Find the configuration group + field to keep (prefer the secret/password
    # leaf's field so its options survive; else the first matching field).
    keep_field: dict | None = None
    password_field_id = _field_id_from_dotted(param, "password", leaves)
    for cfg in prof.get("configurations", []) or []:
        for f in cfg.get("fields", []) or []:
            if f.get("id") in target_ids and f.get("id") == password_field_id:
                keep_field = f
                break
        if keep_field is not None:
            break
    if keep_field is None:
        for cfg in prof.get("configurations", []) or []:
            for f in cfg.get("fields", []) or []:
                if f.get("id") in target_ids:
                    keep_field = f
                    break
            if keep_field is not None:
                break
    if keep_field is None:
        return  # nothing to collapse (mapping-only edge)

    # Mutate the kept field into the consolidated flat field.
    keep_field["id"] = param
    meta = keep_field.setdefault("metadata", {})
    auth = meta.setdefault("auth", {})
    auth["parameter"] = win_role
    opts = keep_field.setdefault("options", {})
    opts["mask"] = True

    # Remove all OTHER fields for this param, and drop now-empty config groups.
    new_configs: list = []
    for cfg in prof.get("configurations", []) or []:
        fields = cfg.get("fields", []) or []
        kept = [
            f
            for f in fields
            if f is keep_field or f.get("id") not in target_ids
        ]
        if kept:
            cfg["fields"] = kept
            new_configs.append(cfg)
        # else: empty group -> drop it entirely.
    prof["configurations"] = new_configs


# --------------------------------------------------------------------------- #
# Production type resolver: connector folder -> source YML param types.
# --------------------------------------------------------------------------- #
def _load_pipeline_rows(csv_path: Path) -> list[dict]:
    if not csv_path.is_file():
        return []
    with csv_path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _folder_slug(connector_id: str) -> str:
    """Mirror ``manifest_generator.title_to_slug`` (Connector ID -> folder slug)."""
    return connector_id.strip().lower().replace(" ", "-").replace("---", "-")


def _yml_param_types(yml_path: Path) -> dict[str, int]:
    """Read ``{param_name: xsoar_type}`` from an integration YML ``configuration``.

    Uses PyYAML ``safe_load`` purely to READ source types — these YMLs are never
    written back, so round-trip fidelity is irrelevant here.
    """
    if not yml_path.is_file():
        return {}
    try:
        import yaml as _y

        doc = _y.safe_load(yml_path.read_text()) or {}
    except Exception:
        return {}
    out: dict[str, int] = {}
    for c in doc.get("configuration", []) or []:
        name = c.get("name")
        if name is None:
            continue
        try:
            out[str(name)] = int(c.get("type", 0) or 0)
        except (TypeError, ValueError):
            out[str(name)] = 0
    return out


def _profile_source_integrations(connection_path: Path, profile: dict) -> set[str]:
    """Map a profile back to its source XSOAR integration id(s) via handlers.

    Mirrors ``fix_connection_mask_title.scope_for_integration`` in reverse: scan
    ``<connector>/components/handlers/*/handler.yaml`` and collect the
    ``triggering.labels.xsoar-integration-id`` of any handler that OWNS this
    profile — i.e. whose ``id`` is ``xsoar-<profile.view_group>`` OR whose
    ``capabilities[].auth_options[].id`` includes ``profile.id``.

    Returns the set of owning integration ids (usually exactly one). Empty when
    no handler links to this profile (e.g. a hand-authored connector).
    """
    import yaml as _y

    connector_dir = connection_path.resolve().parent
    handlers_root = connector_dir / "components" / "handlers"
    if not handlers_root.is_dir():
        return set()

    prof_id = str(profile.get("id", ""))
    prof_vg = str(profile.get("view_group", ""))
    owners: set[str] = set()
    for hdir in sorted(handlers_root.iterdir()):
        hpath = hdir / "handler.yaml"
        if not hpath.is_file():
            continue
        try:
            hy = _y.safe_load(hpath.read_text()) or {}
        except Exception:
            continue
        iid = (hy.get("triggering", {}).get("labels", {}) or {}).get(
            "xsoar-integration-id"
        ) or (hy.get("metadata", {}) or {}).get("xsoar-integration-id")
        if not iid:
            continue
        hid = str(hy.get("id", ""))
        vg = hid[len("xsoar-"):] if hid.startswith("xsoar-") else ""
        pids = {
            ao.get("id")
            for cap in hy.get("capabilities", []) or []
            for ao in cap.get("auth_options", []) or []
            if ao.get("id")
        }
        if (prof_vg and vg == prof_vg) or (prof_id and prof_id in pids):
            owners.add(str(iid))
    return owners


def make_repo_type_lookup(
    csv_path: Path = _PIPELINE_CSV,
    content_root: Path = _CONTENT_ROOT,
) -> Callable[[Path, dict], dict[str, int]]:
    """Build the real PER-PROFILE ``(connection_path, profile) -> {param: type}``.

    For each profile it resolves the owning source integration(s) via the
    handler.yaml linkage (:func:`_profile_source_integrations`), looks up each
    integration's YML via the pipeline CSV (``Integration ID`` ->
    ``Integration File Path``), and merges those integrations' param-type maps.

    Scoping to the profile's own integration(s) is what prevents a shared
    connector folder from clobbering a param's type across integrations (the
    AWS ``access_key`` type-0-vs-type-9 collision). When the handler linkage
    can't resolve an integration (rare; hand-authored connectors), it falls back
    to the connector-folder rows from the CSV so the patch still has SOME types
    rather than treating everything as unresolved.
    """
    rows = _load_pipeline_rows(csv_path)
    yml_by_integration: dict[str, str] = {}
    by_folder: dict[str, list[str]] = {}
    by_slug: dict[str, list[str]] = {}
    for row in rows:
        iid = (row.get("Integration ID") or "").strip()
        yml = (row.get("Integration File Path") or "").strip()
        if iid:
            yml_by_integration[iid] = yml
        cfp = (row.get("Connector Folder Path") or "").strip()
        if cfp and yml:
            by_folder.setdefault(cfp.rstrip("/").split("/")[-1], []).append(yml)
        cid = (row.get("Connector ID") or "").strip()
        if cid and yml:
            by_slug.setdefault(_folder_slug(cid), []).append(yml)

    types_cache: dict[str, dict[str, int]] = {}

    def _types_for_yml(yml_rel: str) -> dict[str, int]:
        if not yml_rel:
            return {}
        if yml_rel in types_cache:
            return types_cache[yml_rel]
        p = Path(yml_rel)
        if not p.is_absolute():
            p = content_root / yml_rel
        t = _yml_param_types(p)
        types_cache[yml_rel] = t
        return t

    def lookup(connection_path: Path, profile: dict) -> dict[str, int]:
        owners = _profile_source_integrations(connection_path, profile)
        merged: dict[str, int] = {}
        if owners:
            for iid in sorted(owners):
                merged.update(_types_for_yml(yml_by_integration.get(iid, "")))
            return merged
        # Fallback: no handler linkage — use the connector-folder CSV rows.
        folder = connection_path.resolve().parent.name
        for yml_rel in by_folder.get(folder) or by_slug.get(folder) or []:
            merged.update(_types_for_yml(yml_rel))
        return merged

    return lookup


# --------------------------------------------------------------------------- #
# Scanning.
# --------------------------------------------------------------------------- #
def find_connection_files(connectors_dir: Path) -> list[Path]:
    """Glob ``<connectors_dir>/**/connection.yaml`` (sorted, de-duplicated).

    Uses a recursive glob so the scan covers the whole connectors tree (the
    standard layout is one level deep, ``connectors/<name>/connection.yaml``,
    but ``**`` is future-proof for nested layouts).
    """
    if not connectors_dir.is_dir():
        return []
    return sorted(set(connectors_dir.glob("**/connection.yaml")))


def _resolve_scan_targets(
    connectors_dir: Path, restrict: str | None
) -> list[Path]:
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
        "--flatten-unresolved",
        action="store_true",
        help=(
            "Also flatten dotted leaves whose origin XSOAR type cannot be "
            "resolved (default: skip + report them, to avoid corrupting "
            "legitimately-nested type-9 params)."
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

    type_lookup = make_repo_type_lookup()

    scanned = 0
    modified_results: list[PatchResult] = []
    unresolved_results: list[PatchResult] = []
    for conn in targets:
        scanned += 1
        res = patch_file(
            conn,
            type_lookup,
            dry_run=args.dry_run,
            flatten_unresolved=args.flatten_unresolved,
        )
        if res.modified:
            modified_results.append(res)
        if res.unresolved_params:
            unresolved_results.append(res)

    _print_summary(
        connectors_dir, scanned, modified_results, unresolved_results, args.dry_run
    )
    return 0


def _connector_name(path: Path) -> str:
    return path.resolve().parent.name


def _print_summary(
    connectors_dir: Path,
    scanned: int,
    modified: list[PatchResult],
    unresolved: list[PatchResult],
    dry_run: bool,
) -> None:
    tag = "DRY-RUN" if dry_run else "APPLIED"
    verb = "would be modified" if dry_run else "modified"
    print("=" * 72)
    print(f"flatten_non_type9_nesting [{tag}]")
    print(f"connectors dir: {connectors_dir}")
    print("-" * 72)
    print(f"Scanned : {scanned} manifest(s)")
    print(f"{verb.capitalize():8}: {len(modified)} manifest(s)")

    if modified:
        print("\nChanged connectors:")
        for res in modified:
            params = ", ".join(res.flattened_params) or "(mapping-only)"
            print(f"  - {_connector_name(res.path)}: flattened [{params}]")
            for line in res.details:
                print(f"    {line.strip()}")

    if unresolved:
        print("\nUnresolved params SKIPPED (origin XSOAR type not found):")
        for res in unresolved:
            print(
                f"  - {_connector_name(res.path)}: "
                f"{', '.join(res.unresolved_params)}"
            )
        print(
            "  (re-run with --flatten-unresolved to force-flatten these, "
            "or fix the pipeline CSV / YML resolution.)"
        )

    if not modified and not unresolved:
        print("\nNothing to change — all manifests are already correct.")
    print("=" * 72)


if __name__ == "__main__":
    raise SystemExit(main())
