#!/usr/bin/env python3
"""Patch already-generated ConnectUs ``configurations.yaml`` and ``connection.yaml``
files to back-fill the FieldGroup ``advanced: true`` flag for params that were
marked advanced in their source XSOAR integration YML.

Background
==========
The XSOAR integration YML allows individual ``configuration[]`` entries to declare
``advanced: true``, which surfaces the param in the legacy "Advanced" UI panel.
The ConnectUs FieldGroup schema exposes the same boolean at the ROW level
(``general_configurations.configurations[].advanced`` and equivalents). Earlier
generator runs dropped that information; this patch retrofits it onto manifests
that were ALREADY committed to disk by an earlier generator — WITHOUT
regenerating from the source XSOAR YML.

Standalone-by-design
====================
This patch is deliberately STANDALONE: it does NOT import the generator. The
source-of-truth ``advanced`` lookup is reconstructed from the original XSOAR YML
located via ``handler.yaml`` (``triggering.labels.xsoar-integration-id``) plus
the pipeline CSV (``Integration File Path``), mirroring the same per-handler
linkage already used by ``flatten_non_type9_nesting.py``. Mirrors conventions of
``flatten_non_type9_nesting.py`` and ``add_vault_support.py`` in this same dir
(ruamel round-trip; CLI flags; env-loader resolution).

----------------------------------------------------------------------------- #
TASK 0.1 — Schema / placement lock-down (FieldGroup contexts)
----------------------------------------------------------------------------- #
The FieldGroup schema (``schema/definitions/field.schema.json`` lines 480–511)
defines THREE row-level properties relevant here:

    * ``view_group``               — string (grouped-connector tile id)
    * ``required_for_capabilities``— string[] (which capabilities need this row)
    * ``advanced``                 — bool (collapsible Advanced panel)

A FieldGroup row appears in FIVE on-disk placement contexts. For each, the
schema dictates whether ``view_group``, ``required_for_capabilities`` and
``advanced`` are LEGAL — and when SPLITTING a mixed row (to separate the
advanced from the non-advanced fields), the patch must propagate sibling
properties only where they remain LEGAL. The matrix below is the lock-down:

  ╔══╦══════════════════════════════════════════════╦═══════════════╦══════════════════════╦══════════╗
  ║ #║ Context                                      ║ view_group    ║ required_for_caps    ║ advanced ║
  ╠══╬══════════════════════════════════════════════╬═══════════════╬══════════════════════╬══════════╣
  ║ 1║ configurations.yaml ->                       ║ LEGAL (when   ║ LEGAL                ║ LEGAL    ║
  ║  ║   general_configurations.configurations[]    ║ grouped only) ║ (forbidden if grouped║          ║
  ║  ║                                              ║               ║  per OPA Check 30 —  ║          ║
  ║  ║                                              ║               ║  patch never INVENTS ║          ║
  ║  ║                                              ║               ║  it, only propagates)║          ║
  ║ 2║ configurations.yaml ->                       ║ FORBIDDEN     ║ FORBIDDEN            ║ LEGAL    ║
  ║  ║   configurations[].configurations[]          ║ (inherited    ║ (per-capability rows ║          ║
  ║  ║   (per-capability rows)                      ║  from entry)  ║  imply the cap)      ║          ║
  ║ 3║ connection.yaml ->                           ║ LEGAL (when   ║ LEGAL                ║ LEGAL    ║
  ║  ║   general_configurations.configurations[]    ║ grouped only) ║                      ║          ║
  ║ 4║ connection.yaml ->                           ║ FORBIDDEN     ║ FORBIDDEN            ║ LEGAL    ║
  ║  ║   profiles[].configurations[]                ║ (derived from ║ (per-profile rows    ║          ║
  ║  ║   (per-profile rows)                         ║  handler.yaml ║  imply the cap)      ║          ║
  ║  ║                                              ║  auth_options)║                      ║          ║
  ║ 5║ capabilities.yaml ->                         ║ FORBIDDEN     ║ FORBIDDEN            ║ LEGAL    ║
  ║  ║   general_configurations.configurations[]    ║               ║                      ║          ║
  ╚══╩══════════════════════════════════════════════╩═══════════════╩══════════════════════╩══════════╝

Propagation policy on row-SPLIT
-------------------------------
When a single FieldGroup row contains BOTH advanced and non-advanced fields, the
patch SPLITS it into two sibling rows (non-advanced first, then advanced) and
propagates row-level siblings per the rules:

  * ``view_group``                propagates ONLY on general_configurations rows
                                  (contexts 1 and 3) AND ONLY when the connector
                                  is grouped (``connector.yaml settings.grouped:
                                  true``). Per-capability (2), per-profile (4)
                                  and capabilities.yaml (5) NEVER carry it.
  * ``required_for_capabilities`` propagates ONLY on general_configurations rows
                                  (contexts 1, 3, 5). Per-capability (2) and
                                  per-profile (4) NEVER carry it.
  * ``advanced``                  legal in every context; this is the entire
                                  reason the patch exists.

Per-capability and per-profile SPLIT rows therefore get NEITHER ``view_group``
nor ``required_for_capabilities`` — they carry only ``fields`` and ``advanced``.

NOTE this patch targets contexts 1, 2, 3, 4. Context 5
(``capabilities.yaml``) is currently out-of-scope for the initial RED baseline;
the schema legality is documented here for completeness so a future extension
has the placement contract pinned down.

Scope: both ``configurations.yaml`` AND ``connection.yaml`` are touched. Within
``connection.yaml``, advanced legality is identical to ``configurations.yaml``
(general vs. per-profile mirror general vs. per-capability).

Usage
=====
    # Whole-repo dry run (recommended first):
    python3 patches/propagate_advanced_flag.py --dry-run

    # Whole-repo apply in place (default):
    python3 patches/propagate_advanced_flag.py

    # Restrict to a single connector or connection.yaml:
    python3 patches/propagate_advanced_flag.py --path connectors/qualys
    python3 patches/propagate_advanced_flag.py --path connectors/qualys/connection.yaml

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
from typing import Callable, Literal, Union

# ruamel.yaml gives round-trip fidelity (preserves key order, comments, quoting,
# block style). It is a declared dependency of this repo (used elsewhere); we
# fall back to PyYAML only if it is somehow unavailable, accepting reduced
# formatting fidelity in that case.
try:
    from ruamel.yaml import YAML  # type: ignore
    from ruamel.yaml.comments import CommentedMap, CommentedSeq  # type: ignore

    _HAVE_RUAMEL = True
except ImportError:  # pragma: no cover - exercised only on misconfigured envs
    import yaml as _pyyaml  # type: ignore

    _HAVE_RUAMEL = False
    CommentedMap = dict  # type: ignore
    CommentedSeq = list  # type: ignore


# A per-row advanced-set resolver. Production form takes
# (yaml_path, row_context_dict) and scopes the advanced set to the row's owning
# handler(s); a simpler 1-arg form (yaml_path) is also accepted for unit tests.
AdvancedLookup = Union[
    Callable[[Path], "set[str]"],
    Callable[[Path, dict], "set[str]"],
]


# A typed, internally-passed row descriptor. The patch walks rows in five
# placement contexts (see the Schema lock-down table in the module docstring);
# every helper below routes off ``kind`` to apply the right
# propagation/scoping rule. Using a dataclass instead of a loose dict gives
# the helpers a single typed signature, makes the field names discoverable
# from a single source of truth, and prevents accidental key-typo bugs (e.g.
# ``capabilty_id``). The dataclass is INTERNAL — at the public-lookup
# boundary :func:`_RowContext.to_lookup_dict` exports a plain dict so
# user-supplied ``advanced_lookup`` callables continue to receive the same
# ``dict`` they always have (tests rely on this).
@dataclass
class _RowContext:
    """Internal descriptor of where a FieldGroup row lives in its manifest.

    Fields:
        kind: Which of the four in-scope placement contexts this row sits in.
            "general" covers both general_configurations sections
            (configurations.yaml AND connection.yaml); the distinction never
            matters for propagation, only the "general vs. per-X" axis does.
        view_group: Enclosing tile id when the row is per-capability /
            per-profile (inherited from the parent capability or profile so a
            per-profile resolver can match against ``handler.id``); empty
            otherwise.
        capability_id: Enclosing capability id for ``kind == per_capability``;
            empty otherwise. Used by the production resolver to scope the
            advanced set to the handler(s) implementing this capability.
        profile_id: Enclosing profile id for ``kind == per_profile``; empty
            otherwise. Used by the production resolver to scope the advanced
            set to the handler(s) exposing this auth profile.
    """

    kind: Literal["general", "per_capability", "per_profile"] = "general"
    view_group: str = ""
    capability_id: str = ""
    profile_id: str = ""

    def to_lookup_dict(self) -> dict:
        """Project to the dict shape that user-supplied lookups receive.

        WHY: the public ``advanced_lookup(yaml_path, context)`` contract has
        always taken a plain dict (unit tests construct lookups that read
        ``context.get("capability_id", "")`` etc.). The internal dataclass is
        a refactoring tool; at the boundary we hand back the equivalent dict
        so the contract is unchanged.
        """
        return {
            "kind": self.kind,
            "view_group": self.view_group,
            "capability_id": self.capability_id,
            "profile_id": self.profile_id,
        }


def _call_advanced_lookup(
    lookup: "AdvancedLookup", path: Path, context: dict | None = None
) -> set | None:
    """Invoke ``lookup`` supporting BOTH the 1-arg and 2-arg signatures.

    The 2-arg ``(yaml_path, context)`` form is preferred (it lets the
    production resolver scope the advanced set to the row's owning source
    integration(s)). A 1-arg ``(yaml_path)`` form is also accepted so unit
    tests can express a single global advanced set inline.

    Return contract (post-Fix #2 semantic shift):
      * ``None``  -> the lookup could NOT resolve the row's owner (handler
                     missing, pipeline-CSV gap, source YML unreadable, etc.).
                     This is the "investigate this" signal that surfaces in
                     ``PatchResult.unmatched_params``.
      * ``set()`` -> the owner WAS resolved and has zero advanced params. This
                     is a benign noop — common for connectors whose source
                     integration simply doesn't declare ``advanced: true`` on
                     any param. Must NOT be reported as unmatched.
      * non-empty ``set[str]`` -> normal case; the row is patched accordingly.

    The shim is intentionally faithful to ``None``: a user-supplied lookup
    that returns ``None`` is signalling "resolution failed", and we propagate
    it unchanged. Any other falsy return (``False``, ``[]``) is coerced to
    ``set()`` to keep the dual-form contract ergonomic; ``None`` is the only
    explicit sentinel.

    WHY a dual-signature shim instead of forcing one form? Tests inject a
    trivial lookup that doesn't care which row it's resolving, while the
    production lookup MUST see the row context to scope the advanced set to
    the correct handler. Supporting both keeps the test fixtures small without
    weakening the production contract.
    """
    try:
        sig = inspect.signature(lookup)
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
        raw = lookup(path, context or {})  # type: ignore[call-arg]
    else:
        raw = lookup(path)  # type: ignore[call-arg]
    if raw is None:
        return None
    return set(raw)


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
    ``flatten_non_type9_nesting.resolve_connectors_dir``):

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
    """Build a ``ruamel.yaml.YAML`` configured to match the generator's output.

    The point of this patch is to BACK-FILL flags on already-committed
    manifests; the diff must therefore be confined to the lines we touched.
    A vanilla ruamel YAML would re-indent the file and rewrite long scalars,
    drowning the real change in formatting churn. The settings here mirror
    what the manifest generator emits: 2-space mapping indent, sequences
    dedented under their parent key, and effectively unlimited line width
    (so long scalars like ``interpolation_mapping`` are never re-wrapped).
    """
    y = YAML()
    y.preserve_quotes = True
    # Match the generator's emitted block style: 2-space indent, sequences
    # dedented to their parent (the on-disk convention across all manifests:
    # ``profiles:`` then ``- id: ...`` at column 0 under it).
    y.indent(mapping=2, sequence=2, offset=0)
    y.width = 10**9  # never auto-wrap long scalars (e.g. interpolation_mapping)
    return y


def load_yaml(path: Path) -> dict:
    """Load a configurations.yaml / connection.yaml, preserving formatting."""
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
# Result type.
# --------------------------------------------------------------------------- #
@dataclass
class PatchResult:
    """Outcome of patching one configurations.yaml / connection.yaml."""

    path: Path
    modified: bool = False
    # FieldGroup rows promoted as a whole (single-type rows where every field
    # was advanced) — recorded as a short identifier string per row.
    promoted_rows: list[str] = field(default_factory=list)
    # FieldGroup rows split into a non-advanced + advanced sibling pair.
    split_rows: list[str] = field(default_factory=list)
    # Param names in the manifest that could not be resolved against any source
    # YML (no handler / pipeline-CSV path / param entry); reported, not changed.
    unmatched_params: list[str] = field(default_factory=list)
    # Human-readable per-change detail lines (for reporting).
    details: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Connector-level helpers (read connector.yaml settings).
# --------------------------------------------------------------------------- #
def _connector_is_grouped(connector_dir: Path) -> bool:
    """Read ``<connector_dir>/connector.yaml`` and return ``settings.grouped``.

    Returns False when ``connector.yaml`` is missing, malformed or doesn't
    declare the ``grouped`` flag — a sane default that mirrors the schema's
    'tile rendering is OFF unless explicitly enabled' contract.
    """
    cpath = connector_dir / "connector.yaml"
    if not cpath.is_file():
        return False
    try:
        import yaml as _y

        doc = _y.safe_load(cpath.read_text()) or {}
    except Exception:
        return False
    return bool((doc.get("settings") or {}).get("grouped"))


# --------------------------------------------------------------------------- #
# Core: patch ONE configurations.yaml / connection.yaml in memory, optionally
# write.
# --------------------------------------------------------------------------- #
def patch_file(
    path: Path,
    advanced_lookup: "AdvancedLookup",
    dry_run: bool = False,
    grouped: bool | None = None,
    connector_dir: Path | None = None,
) -> PatchResult:
    """Patch a single ``configurations.yaml`` or ``connection.yaml``.

    Args:
        path: Path to the YAML file.
        advanced_lookup: a PER-ROW resolver returning the set of XSOAR-advanced
            param names for the row's owning handler(s). Both the 2-arg
            ``(yaml_path, row_context)`` and the 1-arg ``(yaml_path)`` forms are
            accepted (see :func:`_call_advanced_lookup`).
        dry_run: When True, compute changes but do NOT write.
        grouped: Optional override of the connector's ``settings.grouped`` flag.
            When None, derived from ``<connector_dir>/connector.yaml`` (else
            False).
        connector_dir: Path to the connector directory (defaults to the YAML's
            parent). Used to locate ``connector.yaml`` for the ``grouped``
            lookup when not supplied explicitly.

    Returns:
        A :class:`PatchResult`. ``modified`` reflects whether the file content
        would change (whether or not it was actually written).
    """
    result = PatchResult(path=path)
    doc = load_yaml(path)
    if not isinstance(doc, dict):
        return result

    cdir = connector_dir or path.resolve().parent
    is_grouped = grouped if grouped is not None else _connector_is_grouped(cdir)

    if path.name == "configurations.yaml":
        _walk_configurations_yaml(doc, path, advanced_lookup, is_grouped, result)
    elif path.name == "connection.yaml":
        _walk_connection_yaml(doc, path, advanced_lookup, is_grouped, result)
    else:
        # Unknown shape — be conservative and leave untouched.
        return result

    if result.modified and not dry_run:
        dump_yaml(doc, path)
    return result


def _walk_configurations_yaml(
    doc: dict,
    yaml_path: Path,
    advanced_lookup: "AdvancedLookup",
    grouped: bool,
    result: PatchResult,
) -> None:
    """Walk ``configurations.yaml`` — both general_configurations and the
    per-capability sections — invoking :func:`_patch_row` on each FieldGroup row.
    """
    # general_configurations.configurations[] (context 1)
    gc = doc.get("general_configurations")
    if isinstance(gc, dict):
        rows = gc.get("configurations")
        if isinstance(rows, list):
            _patch_rows_in_list(
                rows,
                yaml_path,
                advanced_lookup,
                result,
                row_context=_RowContext(kind="general"),
                grouped=grouped,
            )

    # configurations[].configurations[] (context 2 — per-capability rows)
    caps = doc.get("configurations")
    if isinstance(caps, list):
        for cap in caps:
            if not isinstance(cap, dict):
                continue
            rows = cap.get("configurations")
            if not isinstance(rows, list):
                continue
            cap_ctx = _RowContext(
                kind="per_capability",
                capability_id=str(cap.get("id", "")),
                view_group=str(cap.get("view_group", "")),
            )
            _patch_rows_in_list(
                rows, yaml_path, advanced_lookup, result, cap_ctx, grouped
            )


def _walk_connection_yaml(
    doc: dict,
    yaml_path: Path,
    advanced_lookup: "AdvancedLookup",
    grouped: bool,
    result: PatchResult,
) -> None:
    """Walk ``connection.yaml`` — general_configurations and every
    ``profiles[].configurations[]`` block — invoking :func:`_patch_row` on
    each FieldGroup row.
    """
    # general_configurations.configurations[] (context 3)
    gc = doc.get("general_configurations")
    if isinstance(gc, dict):
        rows = gc.get("configurations")
        if isinstance(rows, list):
            _patch_rows_in_list(
                rows,
                yaml_path,
                advanced_lookup,
                result,
                row_context=_RowContext(kind="general"),
                grouped=grouped,
            )

    # profiles[].configurations[] (context 4 — per-profile rows)
    profs = doc.get("profiles")
    if isinstance(profs, list):
        for prof in profs:
            if not isinstance(prof, dict):
                continue
            rows = prof.get("configurations")
            if not isinstance(rows, list):
                continue
            prof_ctx = _RowContext(
                kind="per_profile",
                profile_id=str(prof.get("id", "")),
                view_group=str(prof.get("view_group", "")),
            )
            _patch_rows_in_list(
                rows, yaml_path, advanced_lookup, result, prof_ctx, grouped
            )


def _patch_rows_in_list(
    rows: list,
    yaml_path: Path,
    advanced_lookup: "AdvancedLookup",
    result: PatchResult,
    row_context: "_RowContext",
    grouped: bool,
) -> None:
    """Iterate ``rows`` in place, calling :func:`_patch_row` on each entry.

    Uses a manual index (instead of ``for ... enumerate``) so a row-SPLIT —
    which inserts a new sibling AFTER the current row — can advance past the
    newly-inserted advanced sibling on the next iteration. The inserted row
    is itself already ``advanced: true``, so re-patching it would be a no-op
    via idempotency, but skipping it is cheaper and produces a cleaner
    promoted/split tally in the result.
    """
    idx = 0
    while idx < len(rows):
        row = rows[idx]
        if not isinstance(row, dict):
            idx += 1
            continue
        inserted = _patch_row(
            row, rows, idx, yaml_path, advanced_lookup, row_context, result, grouped
        )
        idx += 2 if inserted else 1


def _collect_advanced_field_ids(
    row: dict,
    yaml_path: Path,
    advanced_lookup: "AdvancedLookup",
    row_context: "_RowContext",
    result: PatchResult,
) -> tuple[list[str], list[str]] | None:
    """Resolve ``row`` to ``(all_field_ids, advanced_field_ids_in_row)``.

    Returns ``None`` when the row should be left untouched (already advanced,
    no fields, or the advanced set is empty / disjoint from this row).

    WHY a helper: keeps :func:`_patch_row` focused on routing decisions
    (promote vs. split). The lookup-and-filter dance — including the
    "no resolver hit -> report as unmatched, do not mutate" rule — is a
    self-contained step that doesn't depend on the promote/split branching
    and is easier to reason about in isolation.
    """
    if row.get("advanced") is True:  # idempotency: already promoted
        return None

    fields = row.get("fields")
    if not isinstance(fields, list) or not fields:
        return None

    field_ids = [str(f.get("id", "")) for f in fields if isinstance(f, dict)]
    if not field_ids:
        return None

    advanced_set = _call_advanced_lookup(
        advanced_lookup, yaml_path, row_context.to_lookup_dict()
    )

    # Unmatched reporting: ONLY when the lookup signals resolution failure
    # (returns ``None``). An EMPTY set means "owner resolved, advanced set is
    # empty by design" — a benign noop, not a pipeline/handler-linkage gap.
    # Conflating the two (pre-Fix #2) buried real failures under a flood of
    # spurious warnings on every per-capability / per-profile row whose owner
    # simply had no advanced params.
    if advanced_set is None:
        for fid in field_ids:
            if fid and fid not in result.unmatched_params:
                result.unmatched_params.append(fid)
        return None

    if not advanced_set:
        # Resolved successfully with zero advanced params -> noop, no report.
        return None

    advanced_in_row = [fid for fid in field_ids if fid in advanced_set]
    if not advanced_in_row:
        return None

    return field_ids, advanced_in_row


def _patch_row(
    row: dict,
    parent_list: list,
    idx: int,
    yaml_path: Path,
    advanced_lookup: "AdvancedLookup",
    row_context: "_RowContext",
    result: PatchResult,
    grouped: bool,
) -> bool:
    """Patch ONE FieldGroup row in place.

    Returns True iff a new sibling was inserted (so the caller knows to skip
    past it). Whole-row promotion and idempotent no-ops both return False.

    WHY this function is intentionally small: the heavy lifting lives in
    :func:`_collect_advanced_field_ids` (lookup + unmatched reporting),
    :func:`_promote_whole_row` (all-advanced rows) and :func:`_split_mixed_row`
    (mixed rows). This function is the dispatch layer that chooses between
    those two branches based on the simple "is every field in this row
    advanced?" test.
    """
    fetched = _collect_advanced_field_ids(
        row, yaml_path, advanced_lookup, row_context, result
    )
    if fetched is None:
        return False
    field_ids, advanced_in_row = fetched

    if len(advanced_in_row) == len(field_ids):
        _promote_whole_row(row, row_context, idx, result)
        return False

    _split_mixed_row(
        row,
        parent_list,
        idx,
        row["fields"],
        advanced_in_row,
        row_context,
        grouped,
    )
    result.split_rows.append(_row_label(row, row_context, idx))
    result.modified = True
    return True


def _promote_whole_row(
    row: dict,
    row_context: "_RowContext",
    idx: int,
    result: PatchResult,
) -> None:
    """Promote a row whose every field is XSOAR-advanced.

    Inserts ``advanced: true`` IMMEDIATELY BEFORE the ``fields:`` key (so
    existing siblings like ``view_group`` / ``required_for_capabilities``
    stay in their declared positions). WHY in-place: the row already has the
    right shape and siblings — we are only flipping a boolean. Splitting
    would invent a second row with no fields, which the schema rejects.
    """
    _insert_before_key(row, "advanced", True, "fields")
    result.promoted_rows.append(_row_label(row, row_context, idx))
    result.modified = True


def _split_mixed_row(
    row: dict,
    parent_list: list,
    idx: int,
    fields: list,
    advanced_field_ids: list[str],
    row_context: "_RowContext",
    grouped: bool,
) -> None:
    """Split ``row`` (a mixed advanced/non-advanced FieldGroup row) in place.

    The original row keeps its non-advanced fields (preserving relative order)
    and its siblings (view_group / required_for_capabilities). A NEW sibling
    row is inserted at ``parent_list[idx + 1]`` with:

      * ``view_group`` propagated ONLY when ``kind == "general"`` AND the
        connector is grouped AND the original row had one.
      * ``required_for_capabilities`` propagated ONLY when ``kind == "general"``
        AND the original row had one.
      * ``advanced: true``.
      * ``fields:`` containing the advanced fields in their original order.

    Per-capability and per-profile split rows therefore carry NEITHER
    view_group nor required_for_capabilities — the FieldGroup schema forbids
    those siblings in those contexts.
    """
    advanced_set = set(advanced_field_ids)
    nonadvanced_fields = [
        f for f in fields if isinstance(f, dict) and f.get("id") not in advanced_set
    ]
    advanced_fields = [
        f for f in fields if isinstance(f, dict) and f.get("id") in advanced_set
    ]

    # Mutate the original row's `fields` to keep only the non-advanced fields,
    # preserving the surrounding list object's identity / sequence-style.
    if _HAVE_RUAMEL and isinstance(row.get("fields"), CommentedSeq):
        original = row["fields"]
        del original[:]
        original.extend(nonadvanced_fields)
    else:
        row["fields"] = list(nonadvanced_fields)

    # Build the new sibling row, mirroring the on-disk key order
    # (view_group, required_for_capabilities, advanced, fields).
    if _HAVE_RUAMEL:
        new_row: dict = CommentedMap()
        new_fields_seq: list = CommentedSeq()
        for f in advanced_fields:
            new_fields_seq.append(f)
    else:
        new_row = {}
        new_fields_seq = list(advanced_fields)

    is_general = row_context.kind == "general"

    if is_general and grouped and "view_group" in row:
        new_row["view_group"] = row["view_group"]
    if is_general and "required_for_capabilities" in row:
        new_row["required_for_capabilities"] = row["required_for_capabilities"]
    new_row["advanced"] = True
    new_row["fields"] = new_fields_seq

    parent_list.insert(idx + 1, new_row)


def _row_label(row: dict, row_context: "_RowContext", idx: int) -> str:
    """Short human-readable identifier for a row (for result.promoted_rows etc.).

    Format matches the placement context so a glance at the summary line tells
    an operator both WHICH row changed and which scope it lived in (general,
    per-capability with capability id, per-profile with profile id).
    """
    kind = row_context.kind
    field_ids = [
        str(f.get("id", "")) for f in row.get("fields", []) if isinstance(f, dict)
    ]
    ids_str = ",".join(field_ids) if field_ids else "?"
    if kind == "per_capability":
        return f"{kind}[{row_context.capability_id}]#{idx}({ids_str})"
    if kind == "per_profile":
        return f"{kind}[{row_context.profile_id}]#{idx}({ids_str})"
    return f"{kind}#{idx}({ids_str})"


def _insert_before_key(
    row: dict, new_key: str, new_value, anchor_key: str
) -> None:
    """Insert ``new_key: new_value`` immediately BEFORE ``anchor_key`` in ``row``.

    Falls back to APPEND when the anchor is missing. Uses ruamel
    ``CommentedMap.insert`` when available so the rest of the mapping's
    order/comments are preserved verbatim.
    """
    if _HAVE_RUAMEL and isinstance(row, CommentedMap):
        keys = list(row.keys())
        if anchor_key in keys:
            row.insert(keys.index(anchor_key), new_key, new_value)
            return
        row[new_key] = new_value
        return

    # Plain-dict fallback: rebuild the mapping to honour placement.
    items = list(row.items())
    row.clear()
    inserted = False
    for key, val in items:
        if not inserted and key == anchor_key:
            row[new_key] = new_value
            inserted = True
        row[key] = val
    if not inserted:
        row[new_key] = new_value


# --------------------------------------------------------------------------- #
# Production advanced-set resolver: connector folder -> source YML advanced set.
# --------------------------------------------------------------------------- #
def _load_pipeline_rows(csv_path: Path) -> list[dict]:
    """Read a pipeline CSV and return its rows as a list of dicts."""
    if not csv_path.is_file():
        return []
    with csv_path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _folder_slug(connector_id: str) -> str:
    """Mirror ``manifest_generator.title_to_slug`` (Connector ID -> folder slug)."""
    return connector_id.strip().lower().replace(" ", "-").replace("---", "-")


def _yml_advanced_param_names(yml_path: Path) -> set:
    """Return the set of ``{c["name"]}`` for which the source YML's
    ``configuration[]`` entry declares ``advanced: true``.

    Uses PyYAML ``safe_load`` purely to READ — these YMLs are never written
    back, so round-trip fidelity is irrelevant here.
    """
    if not yml_path.is_file():
        return set()
    try:
        import yaml as _y

        doc = _y.safe_load(yml_path.read_text()) or {}
    except Exception:
        return set()
    out: set = set()
    for c in doc.get("configuration", []) or []:
        name = c.get("name")
        if name is None:
            continue
        if c.get("advanced") is True:
            out.add(str(name))
    return out


def _handler_entries(connector_dir: Path) -> list[tuple[str, Path, dict]]:
    """Return ``[(xsoar_integration_id, handler_dir, handler_yaml_doc), ...]`` for
    every handler under ``connector_dir/components/handlers/``.

    Each handler_yaml_doc is the plain-Python representation of the handler.yaml.
    Handlers without an ``xsoar-integration-id`` label are skipped.
    """
    import yaml as _y

    handlers_root = connector_dir / "components" / "handlers"
    if not handlers_root.is_dir():
        return []

    out: list[tuple[str, Path, dict]] = []
    for hdir in sorted(handlers_root.iterdir()):
        hpath = hdir / "handler.yaml"
        if not hpath.is_file():
            continue
        try:
            hy = _y.safe_load(hpath.read_text()) or {}
        except Exception:
            continue
        # Defensive normalisation: a handler.yaml may legitimately have
        # ``triggering: null``, ``triggering: [list]``, ``labels: null`` or
        # ``metadata: null``. The previous ``hy.get("triggering", {}).get(...)``
        # chain raised AttributeError on any non-mapping intermediate (the
        # ``{}`` default only applies when the KEY is absent, not when the
        # value is None / non-dict). Surrounding try/except only wraps
        # ``safe_load``, so an exception here aborts the entire connector. We
        # therefore coerce each level to a dict before the next ``.get`` —
        # explicit normalisation keeps the intent visible at the call site
        # and isolates one malformed handler to itself rather than letting
        # it take down the whole scan.
        triggering = hy.get("triggering") or {}
        if not isinstance(triggering, dict):
            triggering = {}
        labels = triggering.get("labels") or {}
        if not isinstance(labels, dict):
            labels = {}
        meta = hy.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        iid = labels.get("xsoar-integration-id") or meta.get(
            "xsoar-integration-id"
        )
        if not iid:
            continue
        out.append((str(iid), hdir, hy))
    return out


def _row_source_integrations(
    yaml_path: Path, row_context: dict
) -> list[tuple[str, Path]]:
    """Resolve a FieldGroup row back to its owning XSOAR integration(s).

    For ``kind == "general"``: returns ALL handlers under the connector (the
    advanced set is the UNION across handlers).

    For ``kind == "per_capability"``: returns the handler(s) whose
    ``capabilities[].id`` includes the row's enclosing ``capability_id``.

    For ``kind == "per_profile"``: returns the handler(s) whose
    ``capabilities[].auth_options[].id`` includes the row's enclosing
    ``profile_id`` (matching the same backlink ``flatten_non_type9_nesting``
    uses).

    Returns a list of ``(xsoar_integration_id, handler_dir)`` tuples. Empty
    when nothing matches (e.g. a hand-authored connector with no handlers).
    """
    connector_dir = yaml_path.resolve().parent
    handlers = _handler_entries(connector_dir)
    if not handlers:
        return []

    kind = (row_context or {}).get("kind", "general")
    if kind == "general":
        return [(iid, hdir) for iid, hdir, _ in handlers]

    if kind == "per_capability":
        cap_id = (row_context or {}).get("capability_id", "")
        owners: list[tuple[str, Path]] = []
        for iid, hdir, hy in handlers:
            cap_ids = {
                cap.get("id")
                for cap in hy.get("capabilities", []) or []
                if cap.get("id")
            }
            if cap_id and cap_id in cap_ids:
                owners.append((iid, hdir))
        return owners

    if kind == "per_profile":
        prof_id = (row_context or {}).get("profile_id", "")
        prof_vg = (row_context or {}).get("view_group", "")
        owners = []
        for iid, hdir, hy in handlers:
            hid = str(hy.get("id", ""))
            vg = hid[len("xsoar-"):] if hid.startswith("xsoar-") else ""
            pids = {
                ao.get("id")
                for cap in hy.get("capabilities", []) or []
                for ao in cap.get("auth_options", []) or []
                if ao.get("id")
            }
            if (prof_vg and vg == prof_vg) or (prof_id and prof_id in pids):
                owners.append((iid, hdir))
        return owners

    return []


def make_repo_advanced_lookup(
    csv_path: Path = _PIPELINE_CSV,
    content_root: Path = _CONTENT_ROOT,
) -> Callable[[Path, dict], set]:
    """Build the real PER-ROW ``(yaml_path, row_context) -> {advanced param names}``.

    For each row it resolves the owning source integration(s) via the
    handler.yaml linkage (:func:`_row_source_integrations`), looks up each
    integration's YML via the pipeline CSV (``Integration ID`` ->
    ``Integration File Path``), and returns the UNION of those integrations'
    ``advanced: true`` param-name sets.

    The CSV's ``Integration File Path`` values may be either absolute or
    relative. Relative paths are first resolved against the CSV's parent
    directory (so test fixtures with their own self-contained ``Packs/`` tree
    just work) and then against ``content_root`` (matching the prod layout
    where the CSV lives at ``content/connectus/`` but the YMLs live under
    ``content/Packs/``).
    """
    rows = _load_pipeline_rows(csv_path)
    csv_parent = csv_path.resolve().parent if csv_path else None
    yml_by_integration: dict[str, str] = {}
    for row in rows:
        iid = (row.get("Integration ID") or "").strip()
        yml = (row.get("Integration File Path") or "").strip()
        if iid:
            yml_by_integration[iid] = yml

    # Cache values are EITHER a set (YML successfully parsed, possibly empty)
    # OR ``None`` (YML couldn't be located). Carrying the None through the
    # cache prevents repeated stat() of the same missing path for connectors
    # whose handlers all share a missing source YML.
    advanced_cache: dict[str, set | None] = {}

    def _advanced_for_yml(yml_rel: str) -> set | None:
        """Return + cache the advanced-param set for ONE integration YML.

        Returns ``None`` when the YML path was missing/unlocatable so the
        caller can distinguish "resolved, empty" from "couldn't locate the
        owner YML" — the same None-vs-set() sentinel applied at the row level.

        Caches by the raw CSV value so repeated rows (multi-handler
        connectors that share a source integration) hit the filesystem at
        most once per integration. Tries absolute / CSV-parent-relative /
        content-root-relative in that order so the same code works for
        production layout and for self-contained test fixtures.
        """
        if not yml_rel:
            return None
        if yml_rel in advanced_cache:
            return advanced_cache[yml_rel]
        p = Path(yml_rel)
        candidates: list[Path] = []
        if p.is_absolute():
            candidates.append(p)
        else:
            if csv_parent is not None:
                candidates.append(csv_parent / yml_rel)
            candidates.append(content_root / yml_rel)
        chosen = next((c for c in candidates if c.is_file()), None)
        if chosen is None:
            advanced_cache[yml_rel] = None
            return None
        adv = _yml_advanced_param_names(chosen)
        advanced_cache[yml_rel] = adv
        return adv

    def lookup(yaml_path: Path, row_context: dict) -> set | None:
        """The actual per-row resolver returned to :func:`patch_file`.

        Walks the row's owning handlers, looks up each handler's source YML
        via the pipeline CSV, and unions the per-integration advanced sets.
        Receives a plain dict for ``row_context`` to match the public
        contract documented on :data:`AdvancedLookup`.

        Sentinel contract (post-Fix #2):
          * ``None``  — RESOLUTION FAILURE. Either no owning handler could be
                        located for the row (e.g. per-capability row whose
                        capability id matches no handler), OR none of the
                        located handlers' source YMLs could be read. This is
                        the only condition that should appear in the patch's
                        "Unmatched params" summary.
          * ``set()`` — At least one owning handler's source YML was located
                        and parsed; the union of advanced-param names happens
                        to be empty. Benign noop, not an unmatched event.
          * non-empty ``set[str]`` — Normal case.
        """
        owners = _row_source_integrations(yaml_path, row_context)
        if not owners:
            return None
        merged: set = set()
        any_resolved = False
        for iid, _hdir in owners:
            adv = _advanced_for_yml(yml_by_integration.get(iid, ""))
            if adv is None:
                # This owner's YML wasn't locatable. Don't poison the union;
                # the other owners may still resolve.
                continue
            any_resolved = True
            merged.update(adv)
        if not any_resolved:
            # NONE of the row's owners could be resolved to a source YML.
            # Surface this as resolution failure rather than as a misleading
            # "owner has no advanced params" empty-set result.
            return None
        return merged

    return lookup


# --------------------------------------------------------------------------- #
# Scanning.
# --------------------------------------------------------------------------- #
def find_connection_files(connectors_dir: Path) -> list[Path]:
    """Glob ``<connectors_dir>/**/connection.yaml`` (sorted, de-duplicated)."""
    if not connectors_dir.is_dir():
        return []
    return sorted(set(connectors_dir.glob("**/connection.yaml")))


def find_configuration_files(connectors_dir: Path) -> list[Path]:
    """Glob ``<connectors_dir>/**/configurations.yaml`` (sorted, de-duplicated)."""
    if not connectors_dir.is_dir():
        return []
    return sorted(set(connectors_dir.glob("**/configurations.yaml")))


def _resolve_scan_targets(
    connectors_dir: Path, restrict: str | None
) -> list[Path]:
    """Resolve the set of connector directories to process.

    Unlike ``flatten_non_type9_nesting`` (which returns a list of
    ``connection.yaml`` files), this helper returns a list of CONNECTOR
    DIRECTORIES because each connector may have BOTH a ``configurations.yaml``
    AND a ``connection.yaml`` that need patching.

    ``restrict`` may be:
      * None                          -> whole repo (every connector dir).
      * a connector dir / name        -> just that connector dir.
      * a connection.yaml / configurations.yaml path
                                      -> the enclosing connector dir.
    """
    if not restrict:
        if not connectors_dir.is_dir():
            return []
        return sorted(
            p for p in connectors_dir.iterdir() if p.is_dir()
        )

    p = Path(restrict)
    candidates = [p]
    if not p.is_absolute():
        candidates += [
            connectors_dir / restrict,
            connectors_dir.parent / restrict,  # allow 'connectors/<name>...'
            Path.cwd() / restrict,
        ]
    for cand in candidates:
        if cand.is_file() and cand.name in {"connection.yaml", "configurations.yaml"}:
            return [cand.parent]
        if cand.is_dir():
            return [cand]
    # Last resort: treat as a bare connector folder name.
    bare = connectors_dir / restrict
    if bare.is_dir():
        return [bare]
    return []


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #
def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    WHY a dedicated factory (instead of inlining in :func:`main`): the same
    parser shape is reused by tests / external harnesses that want to inspect
    the flag contract without invoking the patch. The flag set mirrors
    ``flatten_non_type9_nesting`` and ``add_vault_support`` so an operator
    can move between the three patches with the same muscle memory.
    """
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
            "Restrict to a single connector dir/name, configurations.yaml or "
            "connection.yaml (default: scan ALL connectors)."
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
            "Path to the discovery CSV used to map a handler's "
            "xsoar-integration-id to its source YML (default: "
            "<connectus>/connectus-migration-pipeline.csv)."
        ),
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    """Entry point — resolve targets, build the production advanced lookup,
    walk every configurations.yaml + connection.yaml under the scan target,
    and print a summary."""
    args = _build_arg_parser().parse_args(argv)
    load_env()

    connectors_dir = resolve_connectors_dir(args.connectors_dir)
    restrict = args.path or args.positional_path

    connector_dirs = _resolve_scan_targets(connectors_dir, restrict)
    if not connector_dirs:
        where = restrict or str(connectors_dir)
        print(
            f"No connector dirs found for: {where}", file=sys.stderr
        )
        return 1

    csv_path = (
        Path(args.pipeline_csv).resolve() if args.pipeline_csv else _PIPELINE_CSV
    )
    advanced_lookup = make_repo_advanced_lookup(csv_path, _CONTENT_ROOT)

    scanned = 0
    modified_results: list[PatchResult] = []
    unmatched_results: list[PatchResult] = []
    for cdir in connector_dirs:
        for yaml_name in ("configurations.yaml", "connection.yaml"):
            yp = cdir / yaml_name
            if not yp.is_file():
                continue
            scanned += 1
            res = patch_file(
                yp,
                advanced_lookup,
                dry_run=args.dry_run,
                connector_dir=cdir,
            )
            if res.modified:
                modified_results.append(res)
            if res.unmatched_params:
                unmatched_results.append(res)

    _print_summary(
        connectors_dir, scanned, modified_results, unmatched_results, args.dry_run
    )
    return 0


def _connector_name(path: Path) -> str:
    """Return the enclosing connector folder name for a manifest path.

    Used purely for human-friendly summary lines (e.g.
    ``qualys/configurations.yaml``) so an operator can scan the report
    without copying full absolute paths.
    """
    return path.resolve().parent.name


def _print_summary(
    connectors_dir: Path,
    scanned: int,
    modified: list[PatchResult],
    unmatched: list[PatchResult],
    dry_run: bool,
) -> None:
    """Print a human-readable run summary mirroring add_vault_support's banner."""
    tag = "DRY-RUN" if dry_run else "APPLIED"
    verb = "would be modified" if dry_run else "modified"
    print("=" * 72)
    print(f"propagate_advanced_flag [{tag}]")
    print(f"connectors dir: {connectors_dir}")
    print("-" * 72)
    print(f"Scanned : {scanned} manifest(s)")
    print(f"{verb.capitalize():8}: {len(modified)} manifest(s)")

    if modified:
        print("\nChanged manifests:")
        for res in modified:
            promoted = ", ".join(res.promoted_rows) or "-"
            split = ", ".join(res.split_rows) or "-"
            print(
                f"  - {_connector_name(res.path)}/{res.path.name}: "
                f"promoted=[{promoted}] split=[{split}]"
            )
        if dry_run:
            print("\n(--dry-run: no files were written.)")

    if unmatched:
        print("\nUnmatched params (no lookup hit — investigate pipeline / handler):")
        for res in unmatched:
            print(
                f"  - {_connector_name(res.path)}/{res.path.name}: "
                f"{', '.join(res.unmatched_params)}"
            )

    if not modified and not unmatched:
        print("\nNothing to change — every row already correct.")
    print("=" * 72)


if __name__ == "__main__":
    raise SystemExit(main())
