#!/usr/bin/env python3
"""Align connector engine settings across already-generated ConnectUs connectors.

What this patch does
====================
Older connector manifests emitted the three "engine" configuration fields
(``engine_mode``, ``engine``, ``engine_group``) as *three separate*
``- fields:`` groups, used the legacy ``engine_group`` identifier, and left the
engine/engine-group fields optional. This patch normalizes them to the current
convention. For every auth profile in ``connection.yaml`` it will:

1. **Merge** the ``*engine_mode`` / ``*engine`` / ``*engine_group`` field groups
   into a single ``- fields:`` block (engine_mode first, then engine, then the
   renamed engineGroup) so the three engine params live together.
2. **Rename** the ``engine_group`` identifier to ``engineGroup`` wherever it acts
   as an identifier:
     * the connection field ``id`` (suffix-preserving, e.g.
       ``plain_protectwise_engine_group`` -> ``plain_protectwise_engineGroup``),
     * the ``engine_mode`` radio dropdown ``key: engine_group`` -> ``engineGroup``,
     * ``triggers.yaml`` condition ``value: engine_group``, effect ``id`` and
       condition-child ``id``,
     * the handler ``serializer.yaml`` ``field_mappings[].id`` (suffix-preserving),
       and (defensively) normalizes its ``field_name`` to ``engineGroup``.
   The *display* value ``dynamicField: engine-group`` (hyphenated) and the
   ``label: Engine Group`` are deliberately left untouched, as are the unrelated
   ``no_engine`` / ``engine`` tokens.
3. **Require** the engine and engineGroup fields: sets ``create_modifiers.required``
   and ``edit_modifiers.required`` to ``true`` on both.

The transform is *idempotent* (safe to run twice — an already-aligned connector
is a no-op) and confined to ``connection.yaml``, ``triggers.yaml`` and the
handler ``serializer.yaml`` files; every other manifest is left byte-for-byte
untouched. Editing goes through a ruamel round-trip so diffs stay minimal.

CLI contract
------------
Kept consistent with the sibling patches (``add_vault_support.py``,
``propagate_advanced_flag.py``) so the generic E2E harness can drive it::

    python3 patches/align_engines.py \
        --csv <path/to/connectus-migration-pipeline.csv> \   # REQUIRED
        --connectors-dir <connectors root> \                 # REQUIRED
        [--path <connector>] \                               # restrict to one connector
        [--dry-run]                                          # report only; write nothing
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

try:  # pragma: no cover - exercised via the E2E harness
    from ruamel.yaml import YAML

    _HAVE_RUAMEL = True
except ImportError:  # pragma: no cover - fallback path
    import yaml as _pyyaml  # type: ignore

    _HAVE_RUAMEL = False

CONNECTION_FILENAME = "connection.yaml"
TRIGGERS_FILENAME = "triggers.yaml"
SERIALIZER_FILENAME = "serializer.yaml"

LEGACY_SUFFIX = "engine_group"
CANONICAL_SUFFIX = "engineGroup"
MODE_SUFFIX = "engine_mode"
ENGINE_SUFFIX = "engine"


# --------------------------------------------------------------------------- #
# YAML round-trip helpers (mirror propagate_advanced_flag.py conventions)
# --------------------------------------------------------------------------- #
def _make_yaml() -> "YAML":
    """Build a ruamel YAML configured to match the manifest generator's output.

    2-space mapping indent, sequences dedented under their parent key, and an
    effectively unlimited line width so long scalars are never re-wrapped. This
    keeps the diff confined to the nodes we actually change.
    """
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=2, offset=0)
    y.width = 10**9
    return y


def load_yaml(path: Path) -> dict:
    """Load a manifest, preserving round-trip formatting."""
    text = path.read_text()
    if _HAVE_RUAMEL:
        return _make_yaml().load(text) or {}
    return _pyyaml.safe_load(text) or {}  # pragma: no cover - fallback path


def dumps_yaml(doc: dict) -> str:
    """Serialize ``doc`` to a string (used for change detection + writing)."""
    if _HAVE_RUAMEL:
        buf = io.StringIO()
        _make_yaml().dump(doc, buf)
        return buf.getvalue()
    return _pyyaml.safe_dump(  # pragma: no cover - fallback path
        doc, sort_keys=False, default_flow_style=False, allow_unicode=True
    )


# --------------------------------------------------------------------------- #
# Small identifier helpers
# --------------------------------------------------------------------------- #
def _has_suffix(identifier: str, suffix: str) -> bool:
    """True if ``identifier`` is exactly ``suffix`` or ``<prefix>_<suffix>``."""
    return identifier == suffix or identifier.endswith("_" + suffix)


def _rename_group_suffix(identifier: str) -> str:
    """Rename a trailing legacy ``engine_group`` token to ``engineGroup``.

    Suffix-preserving so ``plain_protectwise_engine_group`` becomes
    ``plain_protectwise_engineGroup`` and bare ``engine_group`` becomes
    ``engineGroup``. Any other value is returned unchanged.
    """
    if identifier == LEGACY_SUFFIX:
        return CANONICAL_SUFFIX
    if identifier.endswith("_" + LEGACY_SUFFIX):
        prefix = identifier[: -len(LEGACY_SUFFIX)]
        return prefix + CANONICAL_SUFFIX
    return identifier


def _group_single_field_id(group: object) -> str | None:
    """Return the ``id`` of a group shaped ``{"fields": [{"id": ...}]}``."""
    if not isinstance(group, dict):
        return None
    fields = group.get("fields")
    if not isinstance(fields, list) or len(fields) != 1:
        return None
    field = fields[0]
    if not isinstance(field, dict):
        return None
    field_id = field.get("id")
    return field_id if isinstance(field_id, str) else None


def _set_required_true(field: dict) -> bool:
    """Force ``create_modifiers.required`` + ``edit_modifiers.required`` to true.

    Returns True if anything changed.
    """
    changed = False
    options = field.get("options")
    if not isinstance(options, dict):
        return False
    for modifiers_key in ("create_modifiers", "edit_modifiers"):
        modifiers = options.get(modifiers_key)
        if isinstance(modifiers, dict) and modifiers.get("required") is not True:
            modifiers["required"] = True
            changed = True
    return changed


def _rename_mode_values(field: dict) -> bool:
    """Rename the ``engine_group`` dropdown key in an engine_mode radio.

    Leaves ``no_engine`` / ``engine`` keys and every ``label`` untouched.
    Returns True if anything changed.
    """
    changed = False
    options = field.get("options")
    if not isinstance(options, dict):
        return False
    values = options.get("values")
    if not isinstance(values, list):
        return False
    for value in values:
        if isinstance(value, dict) and value.get("key") == LEGACY_SUFFIX:
            value["key"] = CANONICAL_SUFFIX
            changed = True
    return changed


# --------------------------------------------------------------------------- #
# connection.yaml transform
# --------------------------------------------------------------------------- #
def _align_configurations(configurations: list) -> bool:
    """Merge + rename + require the engine trio within one profile's configs.

    Scans the ``configurations`` list for a group whose single field id ends in
    ``engine_mode``; the immediately following groups ending in ``engine`` and
    ``engine_group`` (in that order) are folded into the engine_mode group's
    ``fields`` list. Returns True if the list was mutated.
    """
    if not isinstance(configurations, list):
        return False

    changed = False
    index = 0
    while index < len(configurations):
        group = configurations[index]
        group_id = _group_single_field_id(group)
        if group_id is None or not _has_suffix(group_id, MODE_SUFFIX):
            index += 1
            continue

        mode_fields = group["fields"]  # type: ignore[index]
        mode_field = mode_fields[0]

        # Always normalize the mode radio (key rename) even if already merged.
        if _rename_mode_values(mode_field):
            changed = True

        # Try to absorb the following engine + engine_group groups.
        next_index = index + 1
        engine_group_obj = (
            configurations[next_index] if next_index < len(configurations) else None
        )
        engine_id = _group_single_field_id(engine_group_obj)
        if (
            engine_id is not None
            and _has_suffix(engine_id, ENGINE_SUFFIX)
            and not _has_suffix(engine_id, MODE_SUFFIX)
        ):
            engine_field = engine_group_obj["fields"][0]  # type: ignore[index]
            group_group_obj = (
                configurations[next_index + 1]
                if next_index + 1 < len(configurations)
                else None
            )
            grp_id = _group_single_field_id(group_group_obj)
            if grp_id is not None and _has_suffix(grp_id, LEGACY_SUFFIX):
                grp_field = group_group_obj["fields"][0]  # type: ignore[index]

                # Rename the engineGroup field id (suffix-preserving).
                new_id = _rename_group_suffix(grp_field["id"])
                if grp_field.get("id") != new_id:
                    grp_field["id"] = new_id
                    changed = True

                # Require both engine and engineGroup fields.
                if _set_required_true(engine_field):
                    changed = True
                if _set_required_true(grp_field):
                    changed = True

                # Fold engine + engineGroup into the mode group, drop their
                # standalone groups.
                mode_fields.append(engine_field)
                mode_fields.append(grp_field)
                del configurations[next_index : next_index + 2]
                changed = True

        index += 1

    return changed


def align_connection(doc: dict) -> bool:
    """Apply the engine alignment across every profile in a connection doc."""
    profiles = doc.get("profiles")
    if not isinstance(profiles, list):
        return False
    changed = False
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        configurations = profile.get("configurations")
        if isinstance(configurations, list) and _align_configurations(configurations):
            changed = True
    return changed


# --------------------------------------------------------------------------- #
# triggers.yaml transform
# --------------------------------------------------------------------------- #
def _rename_condition_ids(condition: object) -> bool:
    """Rename legacy engine_group identifiers inside a trigger condition tree."""
    changed = False
    if isinstance(condition, dict):
        cid = condition.get("id")
        if isinstance(cid, str):
            new_id = _rename_group_suffix(cid)
            if new_id != cid:
                condition["id"] = new_id
                changed = True
        cval = condition.get("value")
        if isinstance(cval, str):
            new_val = _rename_group_suffix(cval)
            if new_val != cval:
                condition["value"] = new_val
                changed = True
        children = condition.get("children")
        if isinstance(children, list):
            for child in children:
                if _rename_condition_ids(child):
                    changed = True
    return changed


def align_triggers(doc: dict) -> bool:
    """Rename engine_group identifiers across trigger conditions + effects."""
    triggers = doc.get("triggers")
    if not isinstance(triggers, list):
        return False
    changed = False
    for trigger in triggers:
        if not isinstance(trigger, dict):
            continue
        if _rename_condition_ids(trigger.get("conditions")):
            changed = True
        effects = trigger.get("effects")
        if isinstance(effects, list):
            for effect in effects:
                if isinstance(effect, dict) and isinstance(effect.get("id"), str):
                    new_id = _rename_group_suffix(effect["id"])
                    if new_id != effect["id"]:
                        effect["id"] = new_id
                        changed = True
    return changed


# --------------------------------------------------------------------------- #
# serializer.yaml transform
# --------------------------------------------------------------------------- #
def align_serializer(doc: dict) -> bool:
    """Rename engine_group field-mapping ids + normalize the field_name."""
    mappings = doc.get("field_mappings")
    if not isinstance(mappings, list):
        return False
    changed = False
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        mid = mapping.get("id")
        if not isinstance(mid, str):
            continue
        is_group_mapping = _has_suffix(mid, LEGACY_SUFFIX)
        already_group_mapping = _has_suffix(mid, CANONICAL_SUFFIX)
        if is_group_mapping:
            new_id = _rename_group_suffix(mid)
            if new_id != mid:
                mapping["id"] = new_id
                changed = True
        # Defensive field_name normalization for the engine-group mapping.
        if (is_group_mapping or already_group_mapping) and mapping.get(
            "field_name"
        ) == LEGACY_SUFFIX:
            mapping["field_name"] = CANONICAL_SUFFIX
            changed = True
    return changed


# --------------------------------------------------------------------------- #
# File-level orchestration
# --------------------------------------------------------------------------- #
def _apply_to_file(path: Path, transform, dry_run: bool) -> bool:
    """Load ``path``, run ``transform`` on the doc, write back if it changed.

    Returns True if the file's serialized content would change.
    """
    if not path.is_file():
        return False
    doc = load_yaml(path)
    before = dumps_yaml(doc)
    transform(doc)
    after = dumps_yaml(doc)
    if after == before:
        return False
    if not dry_run:
        path.write_text(after)
    return True


def _iter_connection_files(connectors_dir: Path, path: str | None) -> list[Path]:
    """Return the connection.yaml files in scope (all, or one connector)."""
    root = connectors_dir / path if path else connectors_dir
    if not root.is_dir():
        return []
    return sorted(root.rglob(CONNECTION_FILENAME))


def _serializer_files(connector_dir: Path) -> list[Path]:
    """Return every handler serializer.yaml under a connector directory."""
    handlers_root = connector_dir / "components" / "handlers"
    if not handlers_root.is_dir():
        return []
    return sorted(handlers_root.rglob(SERIALIZER_FILENAME))


def align_engines(
    csv_path: Path,
    connectors_dir: Path,
    path: str | None,
    dry_run: bool,
) -> list[Path]:
    """Align engine settings across the in-scope connectors.

    ``csv_path`` is required to preserve the shared CLI contract; the alignment
    itself is derived structurally from the connector manifests. Returns the
    list of files that were (or, under ``--dry-run``, would be) modified.
    """
    if not csv_path.is_file():
        raise FileNotFoundError(f"pipeline CSV not found: {csv_path}")

    modified: list[Path] = []
    for connection_file in _iter_connection_files(connectors_dir, path):
        connector_dir = connection_file.parent

        if _apply_to_file(connection_file, align_connection, dry_run):
            modified.append(connection_file)

        triggers_file = connector_dir / TRIGGERS_FILENAME
        if _apply_to_file(triggers_file, align_triggers, dry_run):
            modified.append(triggers_file)

        for serializer_file in _serializer_files(connector_dir):
            if _apply_to_file(serializer_file, align_serializer, dry_run):
                modified.append(serializer_file)

    return modified


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Align connector engine settings across ConnectUs connectors.",
    )
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--connectors-dir", required=True, type=Path)
    parser.add_argument("--path", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    modified = align_engines(
        csv_path=args.csv,
        connectors_dir=args.connectors_dir,
        path=args.path,
        dry_run=args.dry_run,
    )

    verb = "would align" if args.dry_run else "aligned"
    print(f"align_engines: {verb} {len(modified)} file(s)")
    for path_ in modified:
        print(f"  - {path_}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
