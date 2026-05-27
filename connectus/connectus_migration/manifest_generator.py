"""Scaffold or update a unified-connectors-content connector from an XSOAR integration.

This is the **template** version of the script. The two main entry points
(:func:`create_manifest_from_scratch` and :func:`add_handler_to_existing_connector`)
are intentionally left as empty stubs — per-file generation rules will be
added incrementally in subsequent iterations.

Usage:
    python -m demisto_sdk.scripts.manifest_generator \\
        Packs/Salesforce/Integrations/Salesforce/Salesforce.yml \\
        "Salesforce" \\
        '{"identity-posture-ai-security": ["sync_interval", "create_user_enabled"]}'
"""

import io
import json
import logging
import re
import shutil
from pathlib import Path
from typing import Any
from collections.abc import Callable

import typer
import yaml

logger = logging.getLogger(__name__)

main = typer.Typer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def title_to_slug(title: str) -> str:
    """Derive a connector directory slug from its human title.

    Lowercases the title and removes all spaces. This is the canonical mapping
    from a connector's display title (e.g. ``"Microsoft Defender"``) to its
    directory name on disk (e.g. ``microsoftdefender``).
    """
    return title.strip().lower().replace(" ", "")


def connector_exists(connector_dir: Path) -> bool:
    """Return True if ``connector_dir`` looks like an already-initialized connector.

    A directory counts as an existing connector only when it both exists and
    contains a ``connector.yaml`` file at its root. This avoids treating empty
    or partially-created directories as existing connectors.
    """
    return connector_dir.is_dir() and (connector_dir / "connector.yaml").is_file()


def load_integration_yml(path: Path) -> dict:
    """Load and return the integration YAML at ``path`` as a dict."""
    if not path.is_file():
        raise FileNotFoundError(f"Integration yml not found: {path}")
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def parse_mapped_params(raw: str) -> dict[str, Any]:
    """Parse the ``mapped_params`` JSON string into a dict.

    The exact consumption of ``mapped_params`` is left to future iterations;
    for now this helper just guarantees we have a valid JSON object to pass
    down to the dispatch targets.
    """
    try:
        data = json.loads(raw)
    except Exception as exc:  # JSON handler may raise various errors
        raise ValueError(f"--mapped-params is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("--mapped-params must decode to a JSON object")
    return data


def get_pack_tags(integration_path: Path) -> list[str]:
    """Extract the list of tags from the integration's pack metadata.

    Walks up 3 levels from the integration YML path to find the pack root,
    then reads ``pack_metadata.json``'s ``tags`` field. Returns an empty list
    if the file doesn't exist or the field is missing.

    Args:
        integration_path: Path to the integration YML
            (e.g., ``Packs/Salesforce/Integrations/Salesforce/Salesforce.yml``).

    Returns:
        List of tag strings as declared in pack_metadata.json. Empty if
        not available.
    """
    pack_root = integration_path.parent.parent.parent
    metadata_path = pack_root / "pack_metadata.json"
    if not metadata_path.is_file():
        logger.warning(
            f"[manifest_generator] pack_metadata.json not found at {metadata_path}; "
            f"defaulting to empty tags list."
        )
        return []
    try:
        with open(metadata_path) as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.warning(
            f"[manifest_generator] Failed to parse {metadata_path}: {exc}; "
            f"defaulting to empty tags list."
        )
        return []
    tags = data.get("tags", [])
    if not isinstance(tags, list):
        logger.warning(
            f"[manifest_generator] pack_metadata.json 'tags' is not a list "
            f"at {metadata_path}; defaulting to empty tags list."
        )
        return []
    return tags


def merge_tags_case_insensitive(existing: list[str], new: list[str]) -> list[str]:
    """Merge two tag lists with case-insensitive dedup, preserving existing order.

    Existing tags retain their original casing and position. New tags are
    appended only if their case-folded form is not already present (in either
    the existing list or earlier-added new entries).

    Examples:
        merge_tags_case_insensitive(["Forensics", "endpoint"],
                                     ["forensics", "Network", "ENDPOINT"])
        → ["Forensics", "endpoint", "Network"]
    """
    existing_lower = {t.lower() for t in existing}
    result = list(existing)
    seen = set(existing_lower)
    for tag in new:
        if tag.lower() not in seen:
            result.append(tag)
            seen.add(tag.lower())
    return result


def bump_minor_version(version: str) -> str:
    """Bump the minor component of a semver version (X.Y.Z → X.(Y+1).0).

    Examples:
        bump_minor_version("1.0.0") → "1.1.0"
        bump_minor_version("2.3.5") → "2.4.0"

    Raises:
        ValueError: if ``version`` is not a valid semver string.
    """
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid semver version '{version}'; expected 'X.Y.Z' format."
        )
    try:
        major, minor, _patch = (int(p) for p in parts)
    except ValueError as exc:
        raise ValueError(
            f"Invalid semver version '{version}'; all components must be integers."
        ) from exc
    return f"{major}.{minor + 1}.0"


def deep_merge_dicts(base: dict, overrides: dict) -> dict:
    """Deep-merge ``overrides`` into ``base``, returning a NEW dict.

    Semantics (manual wins on conflict; siblings preserved):
      - Two dicts at the same path → recurse into both, merging keys.
      - Dict vs non-dict, or two non-dicts → ``overrides`` wins.
      - Lists are treated as leaves: ``overrides`` replaces ``base`` entirely.
      - Keys present only in ``base`` are kept untouched.
      - Keys present only in ``overrides`` are added.

    Does NOT mutate either input. Returns a new dict.

    Examples:
        deep_merge_dicts(
            {"a": {"b": 1, "x": [1, 2]}, "c": "hello"},
            {"a": {"c": 2, "x": [9]}, "d": "new"},
        )
        # → {"a": {"b": 1, "c": 2, "x": [9]}, "c": "hello", "d": "new"}
    """
    if not overrides:
        return dict(base) if base else {}
    if not base:
        return dict(overrides)
    result: dict = {}
    all_keys = set(base) | set(overrides)
    for key in all_keys:
        if key in overrides and key in base:
            base_val = base[key]
            override_val = overrides[key]
            if isinstance(base_val, dict) and isinstance(override_val, dict):
                result[key] = deep_merge_dicts(base_val, override_val)
            else:
                # List or scalar conflict — overrides wins.
                result[key] = override_val
        elif key in overrides:
            result[key] = overrides[key]
        else:
            result[key] = base[key]
    return result


def build_connector_yaml(
    connector_title: str,
    pack_tags: list[str],
    author_image_filename: str = "",
) -> dict:
    """Build the dict for a brand-new connector.yaml.

    All TBD fields (description, category, domain, vendor) are set to empty
    strings. Per-task spec:
      - publisher: "Palo Alto Networks" (hardcoded)
      - author_image: pass-through of ``author_image_filename`` (filename
        relative to the connector root; e.g. ``"salesforce.png"``). Defaults
        to empty string when no image is supplied.
      - ownership.team: "xsoar"
      - ownership.maintainers: ["@xsoar-content"]
      - version: "1.0.0"
      - settings.allow_skip_verification: False
    """
    return {
        "id": title_to_slug(connector_title),
        "metadata": {
            "title": connector_title,
            "description": "",
            "version": "1.0.0",
            "category": "",
            "tags": list(pack_tags),
            "domain": "",
            "vendor": "",
            "publisher": "Palo Alto Networks",
            "author_image": author_image_filename,
            "ownership": {
                "team": "xsoar",
                "maintainers": ["@xsoar-content"],
            },
        },
        "settings": {
            "allow_skip_verification": False,
        },
    }


def _copy_author_image(
    connector_dir: Path, connector_id: str, source_image_path: Path
) -> str:
    """Copy the source author image into the connector root.

    Destination filename is ``<connector_id><source_suffix>`` (original
    extension preserved — e.g. ``salesforce.png`` if source was a PNG,
    ``salesforce.svg`` if source was an SVG). Returns just the filename,
    which is also the relative path to use in
    ``connector.yaml`` ``metadata.author_image`` (the YAML lives at the
    connector root alongside the image).

    Mutates the filesystem only — creates the parent dir if missing,
    overwrites an existing dest. Raises ``FileNotFoundError`` if
    ``source_image_path`` does not exist.
    """
    if not source_image_path.is_file():
        raise FileNotFoundError(
            f"Author image not found at {source_image_path}; cannot copy."
        )
    dest_filename = f"{connector_id}{source_image_path.suffix}"
    connector_dir.mkdir(parents=True, exist_ok=True)
    dest_path = connector_dir / dest_filename
    shutil.copy2(source_image_path, dest_path)
    logger.info(
        f"[manifest_generator] Copied author image "
        f"{source_image_path} -> {dest_path}"
    )
    return dest_filename


def derive_handler_id(integration_id: str) -> str:
    """Derive the handler id from the integration's commonfields.id.

    Format: ``"xsoar_" + integration_id.lower().replace(" ", "")``.

    Examples:
        derive_handler_id("Salesforce") → "xsoar_salesforce"
        derive_handler_id("My Integration") → "xsoar_myintegration"
        derive_handler_id("CrowdStrike Falcon") → "xsoar_crowdstrikefalcon"
    """
    return f"xsoar_{integration_id.strip().lower().replace(' ', '')}"


def slugify_capability_name(name: str) -> str:
    """Convert a capability name to its kebab-case ID.

    Lowercases, replaces any non-alphanumeric run with a single dash,
    and strips leading/trailing dashes.

    Examples:
        slugify_capability_name("Fetch Issues") → "fetch-issues"
        slugify_capability_name("Threat Intelligence & Enrichment")
            → "threat-intelligence-enrichment"
        slugify_capability_name("Automation") → "automation"
    """
    s = name.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)  # any non-alphanumeric → dash
    s = re.sub(r"-+", "-", s)  # collapse multiple dashes
    s = s.strip("-")  # strip leading/trailing
    return s


def build_handler_yaml(
    integration_yml: dict,
    connector_title: str,
    pack_tags: list[str],
    mapped_params: dict[str, Any],
    auth_methods: dict[str, Any],
    cap_name_to_handler_cap_id: dict[str, str] | None = None,
) -> dict:
    """Build the dict for a brand-new handler.yaml.

    Reads from the integration YML:
      - ``commonfields.id`` for the handler id (transformed via derive_handler_id)
      - ``display`` for the description template

    Builds the ``capabilities`` list from ``mapped_params`` (excluding the
    ``general_configurations`` key). Each capability gets the same
    ``auth_options`` derived from ``auth_methods["auth_types"]``.

    By default the cap ``id`` is the bare slug (``slugify_capability_name``).
    When ``cap_name_to_handler_cap_id`` is provided it acts as an override
    mapping: for each cap name present in the mapping, the corresponding
    value is used as the cap id (used by the append path to reference
    sub-cap ids like ``<handler_id>-<cap_slug>``). Cap names not in the
    mapping fall back to the bare slug.

    All other fields are hardcoded per the spec:
      - module: "xsoar"
      - ownership.team: "xsoar", maintainers: ["@xsoar-content"]
      - enabled: True
      - triggering.type: "PUB_SUB", labels.xsoar-content-id: "", args: {}
      - test_connection: type=endpoint, host=xsoar-api, endpoint=/test/api/
    """
    integration_id = integration_yml.get("commonfields", {}).get("id", "")
    integration_display = integration_yml.get("display", "")
    handler_id = derive_handler_id(integration_id)

    # Build auth_options once (shared across all capabilities)
    auth_options = [
        {"id": at.get("name", ""), "scopes": ["api"]}
        for at in auth_methods.get("auth_types", [])
    ]

    cap_id_overrides = cap_name_to_handler_cap_id or {}

    # Build capabilities list — skip "general_configurations" key
    capabilities = []
    for cap_name in mapped_params:
        if cap_name == "general_configurations":
            continue
        cap_id = cap_id_overrides.get(cap_name) or slugify_capability_name(cap_name)
        capabilities.append(
            {
                "id": cap_id,
                "auth_options": list(auth_options),  # copy to avoid shared mutation
            }
        )

    return {
        "id": handler_id,
        "metadata": {
            "version": "1.0.0",
            "description": (
                f"XSOAR handler for {integration_display} integration for "
                f"{connector_title} connector"
            ),
            "module": "xsoar",
            "tags": list(pack_tags),
            "ownership": {
                "team": "xsoar",
                "maintainers": ["@xsoar-content"],
            },
        },
        "enabled": True,
        "triggering": {
            "type": "PUB_SUB",
            "labels": {
                "xsoar-content-id": "",
            },
            "args": {},
        },
        "capabilities": capabilities,
        "test_connection": {
            "type": "endpoint",
            "host": "xsoar-api",
            "endpoint": "/test/api/",
        },
    }


HANDLER_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../../../../schema/handler.schema.json\n"
)


def write_handler_yaml(handler_yaml_path: Path, handler_data: dict) -> None:
    """Write a handler.yaml file with the schema directive line prepended.

    The schema directive is a yaml-language-server VS Code hint and should
    appear as the first line of the file, before any YAML content.
    """
    handler_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(handler_yaml_path, "w") as fh:
        fh.write(HANDLER_SCHEMA_DIRECTIVE)
        yaml.safe_dump(handler_data, fh)


SERIALIZER_PLACEHOLDER = "# TODO: serializer config\n"
SERIALIZER_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../../../../schema/serializer.schema.json\n"
)


def write_serializer_yaml(serializer_yaml_path: Path) -> None:
    """Write a placeholder ``serializer.yaml`` file at the given path.

    The file contains only a single comment line — real serializer config
    will be added in a future iteration. Raises ``FileExistsError`` if the
    target path already exists, to prevent silently overwriting handler
    serializer configs.
    """
    serializer_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    if serializer_yaml_path.exists():
        raise FileExistsError(
            f"Serializer file already exists at {serializer_yaml_path}. "
            f"Refusing to overwrite."
        )
    with open(serializer_yaml_path, "w") as fh:
        fh.write(SERIALIZER_PLACEHOLDER)


# ---------------------------------------------------------------------------
# Field-id dedup + serializer registration
# ---------------------------------------------------------------------------


def collect_existing_field_ids(
    capabilities_data: dict | None,
    configurations_data: dict | None,
    connection_data: dict | None = None,
) -> set[str]:
    """Return the set of every ``ConnectorField.id`` declared anywhere in the
    connector's three field-bearing files.

    Conflict scope (per Q1=a, Q4=b in the design):
      - ``capabilities.yaml`` general_configurations[].configurations[].fields[].id
      - ``configurations.yaml`` configurations[].configurations[].fields[].id
      - ``connection.yaml``    profiles[].configurations[].fields[].id

    Any of the three dicts may be ``None``/empty (e.g., when called early in
    a from-scratch run before that file has been written yet). Tolerates
    schema-incomplete dicts (missing keys) by treating them as empty.
    """
    result: set[str] = set()

    if capabilities_data:
        gen = capabilities_data.get("general_configurations") or {}
        for group in gen.get("configurations") or []:
            for field in group.get("fields") or []:
                fid = (field or {}).get("id")
                if fid:
                    result.add(fid)

    if configurations_data:
        for cfg in configurations_data.get("configurations") or []:
            for group in cfg.get("configurations") or []:
                for field in group.get("fields") or []:
                    fid = (field or {}).get("id")
                    if fid:
                        result.add(fid)

    if connection_data:
        for profile in connection_data.get("profiles") or []:
            for group in profile.get("configurations") or []:
                for field in group.get("fields") or []:
                    fid = (field or {}).get("id")
                    if fid:
                        result.add(fid)

    return result


def register_serializer_entry(
    handler_dir: Path, new_id: str, original_id: str
) -> None:
    """Append one ``field_mappings`` entry to a handler's ``serializer.yaml``.

    Behavior:
      - Creates the file if it does not exist (with the schema directive
        comment line prepended), or if it exists as a comment-only stub
        (the legacy ``# TODO: serializer config`` placeholder) by rewriting
        it with the schema directive + a fresh dict body.
      - Preserves any existing ``field_mappings`` and ``computed_fields``
        entries when the file is already dict-based.
      - Idempotent: if an entry with the same ``id`` AND ``field_name``
        already exists, the file is left untouched (no duplicate appended,
        no write).
    """
    handler_dir.mkdir(parents=True, exist_ok=True)
    serializer_path = handler_dir / "serializer.yaml"

    # Load existing content (if any) — strip schema directive and tolerate the
    # legacy comment-only placeholder.
    existing: dict = {}
    if serializer_path.is_file():
        with open(serializer_path) as fh:
            raw = fh.read()
        # Strip leading directive / comment lines that are not YAML.
        body = _strip_leading_comments(raw)
        loaded = yaml.safe_load(io.StringIO(body)) if body.strip() else None
        if isinstance(loaded, dict):
            existing = loaded

    field_mappings = existing.setdefault("field_mappings", [])
    entry = {"id": new_id, "field_name": original_id}

    # Idempotency guard: skip if an identical entry already exists.
    for fm in field_mappings:
        if (
            isinstance(fm, dict)
            and fm.get("id") == new_id
            and fm.get("field_name") == original_id
        ):
            return
    field_mappings.append(entry)

    with open(serializer_path, "w") as fh:
        fh.write(SERIALIZER_SCHEMA_DIRECTIVE)
        yaml.safe_dump(existing, fh)


def _strip_leading_comments(text: str) -> str:
    """Strip leading comment lines (``# ...``) and blank lines.

    Used so we can re-parse a serializer.yaml that begins with the
    ``# yaml-language-server`` directive — the directive is metadata for the
    editor, not valid YAML structure to merge into.
    """
    lines = text.splitlines(keepends=True)
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.startswith("#") or stripped == "":
            idx += 1
            continue
        break
    return "".join(lines[idx:])


def dedup_field_id_and_register(
    existing_ids: set[str],
    handler_id: str,
    handler_dir: Path,
    field_id: str,
) -> str:
    """Decide the final connector field id for ``field_id`` under handler
    ``handler_id``, applying the dedup-via-rename rule (Q1=a, Q2=a, Q3=a).

    If ``field_id`` is not already in ``existing_ids``, returns it unchanged
    and adds it to the set.

    If it IS in ``existing_ids``, returns ``f"{handler_id}_{field_id}"``,
    adds the renamed id to the set, and appends a ``field_mappings`` entry
    to the handler's ``serializer.yaml`` (idempotent) mapping the renamed
    connector id back to the original XSOAR param name.

    Mutates ``existing_ids`` in place so subsequent calls see the new id.
    """
    if field_id not in existing_ids:
        existing_ids.add(field_id)
        return field_id
    renamed = f"{handler_id}_{field_id}"
    register_serializer_entry(handler_dir, new_id=renamed, original_id=field_id)
    existing_ids.add(renamed)
    return renamed


def emit_field_for_param(
    name: str,
    yml_params_by_name: dict[str, dict] | None,
    handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
) -> list[dict]:
    """Return one or more connectus field dicts for an XSOAR yml param name.

    Resolution policy (Q1=a / Q2=a / Q3=c / Q4=a / Q5=a):

      - If ``yml_params_by_name`` is missing or doesn't contain ``name``,
        log a warning and fall back to the bare-id shape ``{"id": name}``
        (with dedup-rename applied when requested).
      - Otherwise, dispatch through :func:`map_xsoar_param_to_connectus_field`
        which returns a list of rich field dicts (one for most types, two
        for type 9 / credentials).
      - For each emitted dict, run dedup-via-rename on its ``id`` (treating
        each credentials half independently per Q5=a). Title and all other
        keys are preserved across the rename per Q4=a.

    All three dedup parameters are optional — callers that pass them in
    enable rename + serializer registration; callers that omit them get
    bare emission.
    """
    use_dedup = (
        existing_ids is not None and handler_id and handler_dir is not None
    )

    def _maybe_rename(original_id: str) -> str:
        if use_dedup:
            return dedup_field_id_and_register(
                existing_ids, handler_id, handler_dir, original_id  # type: ignore[arg-type]
            )
        return original_id

    # Fallback path: no YAML param dict available for this name.
    if not yml_params_by_name or name not in yml_params_by_name:
        if yml_params_by_name is not None:
            logger.warning(
                f"[manifest_generator] No XSOAR yml config entry found for "
                f"param '{name}' (handler='{handler_id}'). Emitting bare-id "
                f"field only — rich metadata (title, field_type, options) "
                f"will be missing."
            )
        return [{"id": _maybe_rename(name)}]

    # Rich path: materialize via the type-aware dispatcher.
    raw_fields = map_xsoar_param_to_connectus_field(yml_params_by_name[name])

    out: list[dict] = []
    for raw in raw_fields:
        original_id = raw.get("id", "")
        renamed = _maybe_rename(original_id)
        if renamed != original_id:
            field_copy = dict(raw)
            field_copy["id"] = renamed
            out.append(field_copy)
        else:
            out.append(raw)
    return out


# ============================================================
# Synthetic-field helpers (cap-gated hidden toggles / etc.)
#
# These helpers materialize fields that are NOT 1:1 from an XSOAR yml
# param. They synthesize a hidden, defaulted field that the platform
# uses internally to gate a capability (e.g., the Fetch Secrets cap's
# isFetchCredentials toggle). The pattern is expected to recur — every
# new "platform-gate-toggle-per-capability" feature follows the same
# shape: a hidden toggle with a fixed default, optionally renamed for
# the sub-capability path, optionally bridged via a serializer entry.
# ============================================================

# Default human-readable title for the isFetchCredentials toggle when the
# integration YAML doesn't supply a custom ``display`` string.
_ISFETCHCREDENTIALS_DEFAULT_TITLE = "Fetch credentials"

# The original XSOAR yml param name for the credentials-fetch checkbox.
# Stripped from mapper results by ``add_secret_capability`` so we don't
# emit it twice (once as the synthetic gated toggle below, once via the
# generic param-mapping path).
ISFETCHCREDENTIALS_PARAM_NAME = "isFetchCredentials"


def build_synthetic_hidden_toggle(
    *,
    field_id: str,
    title: str,
    default_value: bool = False,
    required: bool = False,
) -> dict:
    """Build a ``toggle`` field dict that is hidden in both create and
    edit modes, with a fixed boolean default. Reusable across any
    synthetic "platform-gate-toggle-per-capability" feature.

    Shape matches :func:`_map_type_8` (XSOAR type 8 -> connectus toggle)
    plus :func:`_apply_common_field_metadata`, but built directly from
    parameters (no XSOAR yml param dict needed) so it can be used for
    purely synthetic fields the integration YAML doesn't carry.

    Args:
      field_id: connector-side field id (already deduped / renamed by
        the caller — this helper does not rename).
      title: human-readable label shown in the UI when the field is
        unhidden by a downstream trigger.
      default_value: boolean default. Used by the platform for any
        instance that doesn't override the value.
      required: requiredness flag mirrored into both create_modifiers
        and edit_modifiers. Defaults to False — a hidden toggle that's
        also required would block instance creation.

    Returns the connectus field dict (NOT wrapped in a FieldGroup —
    callers fold it into whatever group structure they need).
    """
    return {
        "id": field_id,
        "title": title,
        "field_type": "toggle",
        "options": {
            "default_value": bool(default_value),
            "create_modifiers": {"required": bool(required), "hidden": True},
            "edit_modifiers": {"required": bool(required), "hidden": True},
        },
    }


def register_renamed_field_serializer_entry(
    handler_dir: Path,
    original_id: str,
    renamed_id: str,
) -> None:
    """Idempotently register a serializer field_mappings entry that
    bridges ``renamed_id`` (the connector-side field id, after rename)
    back to ``original_id`` (the XSOAR yml param name the integration
    actually reads at runtime).

    Thin wrapper around :func:`register_serializer_entry` so the intent
    "this is a rename bridge" reads clearly at call sites — and so the
    rename-bridge pattern lives in one named function instead of being
    open-coded everywhere. The ``adjust_checkbox_trigger``,
    ``dedup_field_id_and_register``, and ``add_secret_capability``
    sub-cap paths all need this.
    """
    register_serializer_entry(
        handler_dir, new_id=renamed_id, original_id=original_id
    )


def adjust_checkbox_trigger(capability_id: str, param_id: str) -> None:
    """Hook for the triggers.yaml generator (not yet implemented).

    Intended future behavior: emit a trigger of the form

        - conditions:
            type: capability_condition
            id: <capability_id>
            behavior: selected
            operator: eq
            value: true
          effects:
            - id: <param_id>
              action:
                hidden: false
                required: true

    so the (otherwise hidden) toggle ``param_id`` is revealed and
    required when the user selects the capability ``capability_id``.
    For now this is a no-op stub.
    """
    # TODO: wire to triggers.yaml emission once the triggers builder is
    # implemented. Schema reference at
    # ../../../unified-connectors-content/schema/triggers.schema.json
    # (capability_condition leaf + EffectAction hidden/required).
    pass


def _resolve_title_from_yml(
    yml_params_by_name: dict[str, dict] | None,
    yml_param_name: str,
    fallback: str,
) -> str:
    """Return the human-readable title for a synthetic field, preferring
    the integration YAML's ``display`` value when present and non-blank.

    Generic helper used by every ``add_<capability>_capability`` builder
    that emits a synthetic / hybrid field: if the integration YAML
    carries the source param, the connector should use its ``display``
    string (so a vendor-curated label like "Enable credentials sync"
    overrides our generic fallback). When the YAML doesn't carry the
    param, OR carries it with no display, OR carries a whitespace-only
    display, fall back to the caller-supplied constant.
    """
    if yml_params_by_name and (yml := yml_params_by_name.get(yml_param_name)):
        display = yml.get("display") or ""
        if display.strip():
            return display
    return fallback


def add_secret_capability(
    *,
    capability_id: str,
    is_sub_capability: bool,
    mapped_params: dict[str, list[str]],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_dir: Path | None = None,
) -> dict:
    """Build the per-capability template dict for the ``Fetch Secrets``
    capability, with a single synthetic ``isFetchCredentials`` toggle
    field (hidden, optional, default ``False``).

    Caller contract (D1 — caller decides the cap topology):
      - If this Fetch Secrets capability is being added as a **top-level
        capability**, pass ``is_sub_capability=False`` (typical:
        ``capability_id="fetch-secrets"``) — the toggle keeps its plain
        id ``"isFetchCredentials"``.
      - If a top-level ``fetch-secrets`` already exists and this is being
        added as a **sub-capability** under it, pass
        ``is_sub_capability=True`` and a sub-cap id (e.g.
        ``capability_id="fetch-secrets-xsoar-myhandler"``). The toggle id
        becomes ``f"{capability_id}_isFetchCredentials"`` so it cannot
        collide with the root-cap toggle.

    Side effects:
      1. Strips ``"isFetchCredentials"`` from every bucket of
         ``mapped_params`` (mutates in place) so the standard
         param-mapping pass doesn't re-emit it.
      2. When ``is_sub_capability=True`` AND ``handler_dir`` is supplied,
         registers a serializer ``field_mappings`` entry bridging the
         renamed connector id back to the original yml name
         ``isFetchCredentials`` (D2 — uses the generic
         :func:`register_renamed_field_serializer_entry`).
      3. Calls :func:`adjust_checkbox_trigger` with the chosen
         ``capability_id`` and ``param_id`` — currently a no-op stub.

    Title resolution (D3): if ``yml_params_by_name`` carries an entry
    for ``isFetchCredentials`` and that entry has a non-empty
    ``display``, use it. Otherwise fall back to the constant
    ``"Fetch credentials"``.

    Returns:
      A dict shaped::

          {
              "capability_id": <capability_id>,
              "fields": [<the_toggle_field>],
          }

      The caller folds this into the larger configurations.yaml
      per-capability bucket and then adds the rest of the standard
      mapper-produced params for the same capability.
    """
    # --- §1. Decide the connector-side field id (D1 rule) ---------------
    if is_sub_capability:
        field_id = f"{capability_id}_{ISFETCHCREDENTIALS_PARAM_NAME}"
    else:
        field_id = ISFETCHCREDENTIALS_PARAM_NAME

    # --- §2. Resolve the human-readable title (D3 rule) -----------------
    # Uses the generic _resolve_title_from_yml helper (third use case ->
    # extracted in the log-collection follow-up).
    title = _resolve_title_from_yml(
        yml_params_by_name,
        ISFETCHCREDENTIALS_PARAM_NAME,
        fallback=_ISFETCHCREDENTIALS_DEFAULT_TITLE,
    )

    # --- §3. Build the field dict via the generic synthetic helper ------
    field = build_synthetic_hidden_toggle(
        field_id=field_id,
        title=title,
        default_value=False,
        required=False,
    )

    # --- §4. Strip the original yml name from mapper results ------------
    # Mapper results are keyed by yml-param-name (NOT by connector
    # field-id), so we strip the literal "isFetchCredentials" regardless
    # of whether the field was later renamed for the sub-cap path.
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n for n in names if n != ISFETCHCREDENTIALS_PARAM_NAME
        ]

    # --- §5. Sub-cap rename bridge (D2 rule) ----------------------------
    if is_sub_capability and handler_dir is not None:
        register_renamed_field_serializer_entry(
            handler_dir,
            original_id=ISFETCHCREDENTIALS_PARAM_NAME,
            renamed_id=field_id,
        )

    # --- §6. Trigger hook (D1+D3 combined) ------------------------------
    adjust_checkbox_trigger(capability_id=capability_id, param_id=field_id)

    return {
        "capability_id": capability_id,
        "fields": [field],
    }


# ------------------------------------------------------------------ #
# Log Collection capability builder
# ------------------------------------------------------------------ #

# Default human-readable titles + fallback default for the synthetic /
# fallback emission paths in ``add_log_collection_capability``.
_ISFETCHEVENTS_DEFAULT_TITLE = "Fetch events"
_EVENTFETCHINTERVAL_DEFAULT_TITLE = "Events Fetch Interval"
EVENTFETCHINTERVAL_FALLBACK_DEFAULT = "1"  # string per XSOAR convention (E1=a)

# The original XSOAR yml param names for the two log-collection params.
# Stripped from mapper results by ``add_log_collection_capability`` so we
# don't emit them twice (once as the synthetic / hybrid field below,
# once via the generic param-mapping path).
ISFETCHEVENTS_PARAM_NAME = "isFetchEvents"
EVENTFETCHINTERVAL_PARAM_NAME = "eventFetchInterval"


def _build_isfetchevents_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``isFetchEvents`` toggle field.

    Path A (no yml_param): pure synthetic via
    :func:`build_synthetic_hidden_toggle` — default False, hidden in
    both modifier blocks, required False.

    Path B (yml_param present): delegate to :func:`_map_type_8` so the
    shape matches what every other type-8 param produces (preserves
    ``defaultvalue``, ``hidden``, ``required``). Then override the
    ``id`` (since the caller may have renamed it for the sub-cap path)
    and re-apply the resolved ``title``.
    """
    if yml_param is None:
        return build_synthetic_hidden_toggle(
            field_id=field_id,
            title=title,
            default_value=False,
            required=False,
        )
    field = _map_type_8(yml_param)
    field["id"] = field_id
    field["title"] = title
    return field


def _build_numeric_fetch_interval_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
    fallback_default: str,
) -> dict:
    """Generic numeric "fetch interval"-style field builder.

    Shape (matches :func:`_map_type_19`'s output for XSOAR type-19
    numeric params): connectus ``input`` field with
    ``options.is_number_input: true``. The connectus schema has no
    dedicated ``number`` type — numeric inputs are ``input`` with the
    ``is_number_input`` flag set (a known wart documented in
    ``unified-connectors-content/plans/deferred-validation-gaps.md``).

    Default-value handling (E1=a / E2=a):
      - If ``yml_param`` is provided AND carries a non-None
        ``defaultvalue``, use it verbatim (XSOAR convention is a
        string like ``"1"`` or ``"720"``).
      - Otherwise, inject ``fallback_default`` so the user always
        sees a value, never blank.

    Visibility / requiredness:
      - If ``yml_param`` is provided, honor its ``hidden`` and
        ``required`` keys via :func:`_apply_common_field_metadata`
        (already invoked by ``_map_type_19``).
      - If no yml_param, default to visible + optional.

    Reused by :func:`_build_eventfetchinterval_field` (fallback ``"1"``)
    and :func:`_build_assetsfetchinterval_field` (fallback ``"720"``).
    """
    if yml_param is None:
        return {
            "id": field_id,
            "title": title,
            "field_type": "input",
            "options": {
                "is_number_input": True,
                "default_value": fallback_default,
                "create_modifiers": {"required": False, "hidden": False},
                "edit_modifiers": {"required": False, "hidden": False},
            },
        }
    field = _map_type_19(yml_param)
    field["id"] = field_id
    field["title"] = title
    # E2=a: inject fallback default when the yml carries the param but
    # without an explicit defaultvalue.
    options = field.setdefault("options", {})
    if "default_value" not in options:
        options["default_value"] = fallback_default
    return field


def _build_eventfetchinterval_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Thin wrapper over :func:`_build_numeric_fetch_interval_field`
    bound to the log-collection capability's ``"1"`` fallback default.
    """
    return _build_numeric_fetch_interval_field(
        yml_param=yml_param,
        field_id=field_id,
        title=title,
        fallback_default=EVENTFETCHINTERVAL_FALLBACK_DEFAULT,
    )


def add_log_collection_capability(
    *,
    capability_id: str,
    is_sub_capability: bool,
    is_long_running_capability: bool,
    mapped_params: dict[str, list[str]],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_dir: Path | None = None,
) -> dict:
    """Build the per-capability template dict for the ``Log Collection``
    capability with up to two fields: ``isFetchEvents`` (toggle, hidden
    by default unless the yml overrides) and ``eventFetchInterval``
    (numeric input, visible by default, default ``"1"``).

    Caller contract (mirrors :func:`add_secret_capability`):
      - ``capability_id`` is the connector-side capability id. Pass
        ``"log-collection"`` for the top-level case, or a sub-cap id
        like ``"log-collection-xsoar-myhandler"`` for the sub-cap case.
      - ``is_sub_capability`` flips the field-id naming: when ``True``,
        each emitted field's id becomes
        ``f"{capability_id}_{original_name}"`` so it cannot collide
        with the root-cap version.
      - ``is_long_running_capability`` is the master switch that
        determines BOTH (a) whether the trigger hook fires for
        ``isFetchEvents`` AND (b) the emission shape semantics. See
        the scenario table below.

    Scenarios (combination of ``is_long_running_capability`` x yml presence):

      | LR    | yml has param  | isFetchEvents emission              | trigger? |
      |-------|----------------|--------------------------------------|----------|
      | False | (any)          | synthetic — default False, hidden    | YES      |
      | True  | yes            | yml-driven via _map_type_8           | NO       |
      | True  | no             | synthetic fallback (same as A shape) | NO       |

      | LR    | yml has param  | eventFetchInterval emission                          |
      |-------|----------------|------------------------------------------------------|
      | False | (any)          | yml if present (default "1" injected if missing),    |
      |       |                | else synthetic with default "1", VISIBLE             |
      | True  | yes            | yml-driven via _map_type_19 (default "1" injected    |
      |       |                | if yml has the param but no defaultvalue)            |
      | True  | no             | synthetic fallback with default "1", VISIBLE         |

      The trigger-suppression rule (point 3 in the spec): the trigger
      hook for ``isFetchEvents`` fires ONLY when
      ``is_long_running_capability=False``. In long-running scenarios
      Rule 7's pinning already gates the capability, so a reveal-when-
      selected trigger would be redundant.

    Side effects:
      1. Strips both ``isFetchEvents`` AND ``eventFetchInterval`` from
         every bucket of ``mapped_params`` in place (E4: even if neither
         was in the yml, the mapper may have placed them there via
         test-module / get-events routing).
      2. Sub-cap rename bridges (D2 — generic
         :func:`register_renamed_field_serializer_entry`): when
         ``is_sub_capability=True`` AND ``handler_dir`` is supplied,
         writes a serializer field_mappings entry for EACH emitted
         field that was renamed (0, 1, or 2 entries depending on
         which fields the scenario emitted).
      3. Calls :func:`adjust_checkbox_trigger` for ``isFetchEvents``
         only when ``is_long_running_capability=False`` (trigger
         suppression rule).

    Returns:
      A dict shaped::

          {
              "capability_id": <capability_id>,
              "fields": [<emitted_fields>],
          }

      The fields list has 0, 1, or 2 entries depending on the scenario.
      The caller folds this into the larger configurations.yaml
      per-capability bucket and then adds the rest of the standard
      mapper-produced params for the same capability.
    """
    # --- §1. Resolve the connector-side field ids (sub-cap rename) ------
    ifc_field_id = (
        f"{capability_id}_{ISFETCHEVENTS_PARAM_NAME}"
        if is_sub_capability
        else ISFETCHEVENTS_PARAM_NAME
    )
    efi_field_id = (
        f"{capability_id}_{EVENTFETCHINTERVAL_PARAM_NAME}"
        if is_sub_capability
        else EVENTFETCHINTERVAL_PARAM_NAME
    )

    # --- §2. Resolve titles (E3 — generic helper) -----------------------
    ifc_title = _resolve_title_from_yml(
        yml_params_by_name,
        ISFETCHEVENTS_PARAM_NAME,
        fallback=_ISFETCHEVENTS_DEFAULT_TITLE,
    )
    efi_title = _resolve_title_from_yml(
        yml_params_by_name,
        EVENTFETCHINTERVAL_PARAM_NAME,
        fallback=_EVENTFETCHINTERVAL_DEFAULT_TITLE,
    )

    # --- §3. Look up yml params (may be None) ---------------------------
    ifc_yml = (
        yml_params_by_name.get(ISFETCHEVENTS_PARAM_NAME)
        if yml_params_by_name
        else None
    )
    efi_yml = (
        yml_params_by_name.get(EVENTFETCHINTERVAL_PARAM_NAME)
        if yml_params_by_name
        else None
    )

    # --- §4. Build the two fields per the scenario rules ----------------
    fields: list[dict] = []

    # isFetchEvents:
    #   not long-running  -> synthetic (hidden False default) regardless
    #                        of whether yml carries it (yml only used for title)
    #   long-running      -> yml-driven if present, else synthetic fallback
    if not is_long_running_capability:
        # Scenario A: always synthetic shape. Title may have been
        # vendor-overridden via yml.display through _resolve_title_from_yml.
        ifc_field = _build_isfetchevents_field(
            yml_param=None, field_id=ifc_field_id, title=ifc_title
        )
    else:
        # Scenarios B/C: yml-driven; fall back to synthetic when missing (E4).
        ifc_field = _build_isfetchevents_field(
            yml_param=ifc_yml, field_id=ifc_field_id, title=ifc_title
        )
    fields.append(ifc_field)

    # eventFetchInterval: always emitted (E4 — fall back to synthetic when missing).
    efi_field = _build_eventfetchinterval_field(
        yml_param=efi_yml, field_id=efi_field_id, title=efi_title
    )
    fields.append(efi_field)

    # --- §5. Strip both yml names from mapper results -------------------
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n
            for n in names
            if n not in (ISFETCHEVENTS_PARAM_NAME, EVENTFETCHINTERVAL_PARAM_NAME)
        ]

    # --- §6. Sub-cap rename bridges (per emitted field) -----------------
    if is_sub_capability and handler_dir is not None:
        if ifc_field_id != ISFETCHEVENTS_PARAM_NAME:
            register_renamed_field_serializer_entry(
                handler_dir,
                original_id=ISFETCHEVENTS_PARAM_NAME,
                renamed_id=ifc_field_id,
            )
        if efi_field_id != EVENTFETCHINTERVAL_PARAM_NAME:
            register_renamed_field_serializer_entry(
                handler_dir,
                original_id=EVENTFETCHINTERVAL_PARAM_NAME,
                renamed_id=efi_field_id,
            )

    # --- §7. Trigger suppression rule (point 3 of the spec) -------------
    # Trigger fires ONLY for the non-long-running case. In B/C the
    # long-running Rule 7 pinning already gates the capability, so a
    # reveal-when-selected trigger would be redundant.
    if not is_long_running_capability:
        adjust_checkbox_trigger(
            capability_id=capability_id, param_id=ifc_field_id
        )

    return {
        "capability_id": capability_id,
        "fields": fields,
    }


# ------------------------------------------------------------------ #
# Fetch Assets and Vulnerabilities capability builder
# ------------------------------------------------------------------ #

# Default human-readable titles + fallback default for the synthetic /
# fallback emission paths in ``add_assets_capability``.
_ISFETCHASSETS_DEFAULT_TITLE = "Fetch assets and vulnerabilities"
_ASSETSFETCHINTERVAL_DEFAULT_TITLE = "Assets Fetch Interval"
ASSETSFETCHINTERVAL_FALLBACK_DEFAULT = "720"  # string per XSOAR convention (E1=a)

# The original XSOAR yml param names for the two assets capability params.
# Stripped from mapper results by ``add_assets_capability`` so we don't
# emit them twice.
ISFETCHASSETS_PARAM_NAME = "isFetchAssets"
ASSETSFETCHINTERVAL_PARAM_NAME = "assetsFetchInterval"


def _build_assetsfetchinterval_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Thin wrapper over :func:`_build_numeric_fetch_interval_field`
    bound to the fetch-assets capability's ``"720"`` fallback default.
    """
    return _build_numeric_fetch_interval_field(
        yml_param=yml_param,
        field_id=field_id,
        title=title,
        fallback_default=ASSETSFETCHINTERVAL_FALLBACK_DEFAULT,
    )


def add_assets_capability(
    *,
    capability_id: str,
    is_sub_capability: bool,
    mapped_params: dict[str, list[str]],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_dir: Path | None = None,
) -> dict:
    """Build the per-capability template dict for the ``Fetch Assets and
    Vulnerabilities`` capability with two fields: ``isFetchAssets``
    (always synthetic hidden toggle, default ``False``) and
    ``assetsFetchInterval`` (numeric input, visible by default, fallback
    ``"720"`` per E1=a).

    Unlike :func:`add_log_collection_capability`, this builder does NOT
    take an ``is_long_running_capability`` flag — per the spec there is
    no long-running variant for the fetch-assets capability: both
    fields are always emitted and the trigger hook ALWAYS fires for
    ``isFetchAssets`` (no suppression rule).

    Caller contract (mirrors the other ``add_<capability>_capability``
    builders):
      - ``capability_id``: connector-side capability id. Pass
        ``"fetch-assets-and-vulnerabilities"`` for the top-level case
        or a sub-cap id for the sub-cap case.
      - ``is_sub_capability``: flips the field-id naming (each emitted
        field's id becomes ``f"{capability_id}_{original_name}"``).

    Field emission rules:

      | field                | yml has param  | emission                                          |
      |----------------------|----------------|---------------------------------------------------|
      | isFetchAssets        | (irrelevant)   | always synthetic hidden toggle, default False;    |
      |                      |                | title may use yml.display via _resolve_title_from_yml |
      | assetsFetchInterval  | yes            | yml-driven via _map_type_19; fallback "720"       |
      |                      |                | injected if yml carries the param but no          |
      |                      |                | defaultvalue (E2=a)                               |
      | assetsFetchInterval  | no             | pure synthetic visible numeric input, default "720" |

    Side effects:
      1. Strips both ``isFetchAssets`` AND ``assetsFetchInterval`` from
         every bucket of ``mapped_params`` in place so the standard
         param-mapping pass doesn't re-emit them.
      2. Sub-cap rename bridges (per emitted field whose id was
         renamed) via :func:`register_renamed_field_serializer_entry`.
      3. ALWAYS calls :func:`adjust_checkbox_trigger` for the
         ``isFetchAssets`` field — there is no trigger-suppression
         rule for the fetch-assets capability.

    Returns the template dict ``{"capability_id": ..., "fields": [...]}``
    with exactly 2 entries in ``fields``.
    """
    # --- §1. Resolve the connector-side field ids (sub-cap rename) ------
    ifa_field_id = (
        f"{capability_id}_{ISFETCHASSETS_PARAM_NAME}"
        if is_sub_capability
        else ISFETCHASSETS_PARAM_NAME
    )
    afi_field_id = (
        f"{capability_id}_{ASSETSFETCHINTERVAL_PARAM_NAME}"
        if is_sub_capability
        else ASSETSFETCHINTERVAL_PARAM_NAME
    )

    # --- §2. Resolve titles (E3 — generic helper) -----------------------
    ifa_title = _resolve_title_from_yml(
        yml_params_by_name,
        ISFETCHASSETS_PARAM_NAME,
        fallback=_ISFETCHASSETS_DEFAULT_TITLE,
    )
    afi_title = _resolve_title_from_yml(
        yml_params_by_name,
        ASSETSFETCHINTERVAL_PARAM_NAME,
        fallback=_ASSETSFETCHINTERVAL_DEFAULT_TITLE,
    )

    # --- §3. Look up yml params (may be None) ---------------------------
    afi_yml = (
        yml_params_by_name.get(ASSETSFETCHINTERVAL_PARAM_NAME)
        if yml_params_by_name
        else None
    )

    # --- §4. Build the two fields ---------------------------------------
    # isFetchAssets: ALWAYS synthetic hidden toggle (no yml-driven path).
    ifa_field = build_synthetic_hidden_toggle(
        field_id=ifa_field_id,
        title=ifa_title,
        default_value=False,
        required=False,
    )
    # assetsFetchInterval: yml-driven if present, else synthetic fallback.
    afi_field = _build_assetsfetchinterval_field(
        yml_param=afi_yml, field_id=afi_field_id, title=afi_title
    )

    fields: list[dict] = [ifa_field, afi_field]

    # --- §5. Strip both yml names from mapper results -------------------
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n
            for n in names
            if n not in (ISFETCHASSETS_PARAM_NAME, ASSETSFETCHINTERVAL_PARAM_NAME)
        ]

    # --- §6. Sub-cap rename bridges (per emitted field) -----------------
    if is_sub_capability and handler_dir is not None:
        if ifa_field_id != ISFETCHASSETS_PARAM_NAME:
            register_renamed_field_serializer_entry(
                handler_dir,
                original_id=ISFETCHASSETS_PARAM_NAME,
                renamed_id=ifa_field_id,
            )
        if afi_field_id != ASSETSFETCHINTERVAL_PARAM_NAME:
            register_renamed_field_serializer_entry(
                handler_dir,
                original_id=ASSETSFETCHINTERVAL_PARAM_NAME,
                renamed_id=afi_field_id,
            )

    # --- §7. Trigger hook (ALWAYS fires for isFetchAssets) --------------
    # Per spec: no long-running suppression rule for fetch-assets.
    adjust_checkbox_trigger(
        capability_id=capability_id, param_id=ifa_field_id
    )

    return {
        "capability_id": capability_id,
        "fields": fields,
    }


CAPABILITIES_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/capabilities.schema.json\n"
)


def build_capabilities_yaml(
    mapped_params: dict[str, Any],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
) -> dict:
    """Build the dict for capabilities.yaml.

    When ``yml_params_by_name`` is provided, each ``general_configurations``
    field is materialized via :func:`emit_field_for_param` — a rich dict
    with ``title``, ``field_type``, ``options`` (default_value, mask,
    create/edit_modifiers, etc.) sourced from the underlying XSOAR yml
    param. Type 9 (credentials) params expand into two fields. Missing yml
    entries fall back to a bare ``{"id": name}`` shape with a warning
    (per Q3=c).

    Dedup-via-rename (per Q1=a/Q2=a/Q3=a/Q4=b design): when ``handler_id``
    + ``handler_dir`` are supplied, any ``general_configurations`` field id
    that collides with an entry in ``existing_ids`` is renamed and a
    serializer entry is registered. Capability ids are NOT deduped here —
    capability id collisions are handled by the append flow's promote-to-
    sub-capability path, not by this builder.

    Backwards-compatible: callers omitting all extra args get bare-id
    fields with no dedup side-effects.
    """
    general_params = mapped_params.get("general_configurations", []) or []
    general_fields: list[dict] = []
    for p in general_params:
        general_fields.extend(
            emit_field_for_param(
                p,
                yml_params_by_name,
                handler_id=handler_id,
                handler_dir=handler_dir,
                existing_ids=existing_ids,
            )
        )

    capabilities = []
    for cap_name in mapped_params:
        if cap_name == "general_configurations":
            continue
        capabilities.append({"id": slugify_capability_name(cap_name)})

    return {
        "metadata": {
            "title": "Capabilities",
            "description": "Configure the capabilities for this instance",
        },
        "general_configurations": {
            "description": "General configurations for all capabilities",
            "configurations": [{"fields": general_fields}],
        },
        "capabilities": capabilities,
    }


def write_capabilities_yaml(
    capabilities_yaml_path: Path, capabilities_data: dict
) -> None:
    """Write a capabilities.yaml file with the schema directive line prepended."""
    capabilities_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(capabilities_yaml_path, "w") as fh:
        fh.write(CAPABILITIES_SCHEMA_DIRECTIVE)
        yaml.safe_dump(capabilities_data, fh)


def build_configurations_yaml(
    mapped_params: dict[str, Any],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
) -> dict:
    """Build the dict for configurations.yaml.

    When ``yml_params_by_name`` is provided, each per-capability field is
    materialized via :func:`emit_field_for_param` (rich shape with title +
    field_type + options). Type 9 credentials expand to two fields each.

    Dedup-via-rename (per Q1=a/Q2=a/Q3=a/Q4=b design): when ``handler_id`` +
    ``handler_dir`` are supplied, any field id colliding with an entry in
    ``existing_ids`` is renamed to ``f"{handler_id}_{field_id}"`` and a
    ``field_mappings`` entry is appended to ``handler_dir/serializer.yaml``
    (creating the file if missing). ``existing_ids`` is mutated in place so
    later calls see freshly-claimed ids.

    Backwards-compatible: callers omitting all extra args get bare-id
    fields with no dedup side-effects.
    """
    configurations = []
    for cap_name, params in mapped_params.items():
        if cap_name == "general_configurations":
            continue
        cap_id = slugify_capability_name(cap_name)
        fields: list[dict] = []
        for p in (params or []):
            fields.extend(
                emit_field_for_param(
                    p,
                    yml_params_by_name,
                    handler_id=handler_id,
                    handler_dir=handler_dir,
                    existing_ids=existing_ids,
                )
            )
        configurations.append(
            {
                "id": cap_id,
                "configurations": [{"fields": fields}],
            }
        )

    return {
        "metadata": {
            "title": "Configuration",
            "description": "Adjust and refine your configurations",
        },
        "configurations": configurations,
    }


def find_existing_handler_for_capability(
    connector_dir: Path, cap_id: str
) -> Path:
    """Find the handler.yaml file that references the given capability id.

    Walks ``<connector_dir>/components/handlers/*/handler.yaml`` and returns
    the path of the (single) handler whose ``capabilities`` list contains an
    entry with ``id == cap_id``.

    Raises ``RuntimeError`` if 0 or >1 matching handlers are found
    (indicates an unexpected state — promotion logic assumes exactly one
    existing handler holds a flat capability).
    """
    handlers_dir = connector_dir / "components" / "handlers"
    if not handlers_dir.is_dir():
        raise RuntimeError(
            f"Expected handlers directory at {handlers_dir} but it does not exist."
        )
    matches: list[Path] = []
    for handler_yaml_path in sorted(handlers_dir.glob("*/handler.yaml")):
        with open(handler_yaml_path) as fh:
            # Skip the schema directive line if present, then load the body.
            first_line = fh.readline()
            rest = fh.read()
            if not first_line.startswith("# yaml-language-server"):
                # No directive — the first line was actual content.
                rest = first_line + rest
        data = yaml.safe_load(io.StringIO(rest)) or {}
        for cap_entry in data.get("capabilities", []) or []:
            if cap_entry.get("id") == cap_id:
                matches.append(handler_yaml_path)
                break
    if len(matches) == 0:
        raise RuntimeError(
            f"No existing handler found referencing capability '{cap_id}' "
            f"under {handlers_dir}. Cannot perform Case 2 promotion."
        )
    if len(matches) > 1:
        raise RuntimeError(
            f"Multiple handlers reference capability '{cap_id}': {matches}. "
            f"Case 2 promotion requires exactly one. State is inconsistent."
        )
    return matches[0]


def rename_handler_capability_id(
    handler_yaml_path: Path, old_cap_id: str, new_cap_id: str
) -> None:
    """Rename a capability id inside an existing handler.yaml file.

    Loads the file, finds the cap entry with ``id == old_cap_id``, replaces
    its id with ``new_cap_id``, writes back. Preserves the schema directive
    line (re-prepended) and all other fields untouched.
    """
    with open(handler_yaml_path) as fh:
        first_line = fh.readline()
        rest = fh.read()
    has_directive = first_line.startswith("# yaml-language-server")
    body = rest if has_directive else first_line + rest
    data = yaml.safe_load(io.StringIO(body)) or {}
    for cap_entry in data.get("capabilities", []) or []:
        if cap_entry.get("id") == old_cap_id:
            cap_entry["id"] = new_cap_id
            break
    with open(handler_yaml_path, "w") as fh:
        if has_directive:
            fh.write(first_line)
        yaml.safe_dump(data, fh)


def append_capability_to_files(
    cap_name: str,
    cap_params: list[str],
    new_handler_id: str,
    capabilities_data: dict,
    configurations_data: dict,
    connector_dir: Path,
    yml_params_by_name: dict[str, dict] | None = None,
    existing_ids: set[str] | None = None,
) -> str:
    """Process one capability for the append-handler path.

    Determines which case applies (1, 2, or 3) and mutates
    ``capabilities_data``, ``configurations_data``, and (for Case 2) the
    existing handler.yaml file.

    Returns the cap id that the NEW handler should reference in its own
    handler.yaml ``capabilities`` list (either the bare slug for Case 3, or
    the sub-cap id ``<new_handler_id>-<cap_slug>`` for Cases 1 and 2).

    When ``yml_params_by_name`` is supplied, each new field is materialized
    via :func:`emit_field_for_param` (rich shape with title + field_type +
    options; type 9 / credentials split into two fields each). Missing yml
    entries fall back to bare-id shape with a warning (Q3=c).

    Dedup-via-rename: when ``existing_ids`` is supplied, every newly-added
    field id is checked against the set; collisions are renamed to
    ``f"{new_handler_id}_{field_id}"`` and a ``field_mappings`` entry is
    appended to the new handler's ``serializer.yaml``. ``existing_ids`` is
    mutated in place so subsequent calls in the same append session see
    freshly-claimed ids.
    """
    handler_dir = connector_dir / "components" / "handlers" / new_handler_id

    def _emit_fields(params: list[str]) -> list[dict]:
        result: list[dict] = []
        for p in params:
            result.extend(
                emit_field_for_param(
                    p,
                    yml_params_by_name,
                    handler_id=new_handler_id,
                    handler_dir=handler_dir,
                    existing_ids=existing_ids,
                )
            )
        return result

    cap_slug = slugify_capability_name(cap_name)
    new_sub_cap_id = f"{new_handler_id}-{cap_slug}"

    existing_cap = next(
        (
            c
            for c in capabilities_data.get("capabilities", []) or []
            if c.get("id") == cap_slug
        ),
        None,
    )

    # Case 3: capability does not exist anywhere — add at top level.
    if existing_cap is None:
        capabilities_data.setdefault("capabilities", []).append({"id": cap_slug})
        configurations_data.setdefault("configurations", []).append(
            {
                "id": cap_slug,
                "configurations": [{"fields": _emit_fields(cap_params)}],
            }
        )
        return cap_slug

    has_sub_caps = bool(existing_cap.get("sub_capabilities"))

    # Case 2: capability is currently flat — promote into sub-caps.
    if not has_sub_caps:
        existing_handler_path = find_existing_handler_for_capability(
            connector_dir, cap_slug
        )
        existing_handler_id = existing_handler_path.parent.name
        existing_sub_cap_id = f"{existing_handler_id}-{cap_slug}"

        # Step 2.1: rename cap id inside the existing handler.yaml.
        rename_handler_capability_id(
            existing_handler_path, cap_slug, existing_sub_cap_id
        )

        # Step 2.2: introduce sub_capabilities on the parent in capabilities.yaml.
        existing_cap["sub_capabilities"] = [{"id": existing_sub_cap_id}]

        # Step 2.3: rename the existing top-level entry in configurations.yaml
        # (per spec: drop parent's entry — the renamed entry IS the new sub-cap entry).
        for cfg_entry in configurations_data.get("configurations", []) or []:
            if cfg_entry.get("id") == cap_slug:
                cfg_entry["id"] = existing_sub_cap_id
                break

    # Case 1 (or fall-through after promotion): append the new sub-cap.
    existing_cap.setdefault("sub_capabilities", []).append({"id": new_sub_cap_id})
    configurations_data.setdefault("configurations", []).append(
        {
            "id": new_sub_cap_id,
            "configurations": [{"fields": _emit_fields(cap_params)}],
        }
    )

    return new_sub_cap_id


def merge_general_configurations(
    capabilities_data: dict,
    new_general_params: list[str],
    yml_params_by_name: dict[str, dict] | None = None,
    new_handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
) -> None:
    """Append new general params to capabilities.yaml's general_configurations.

    Mutates ``capabilities_data`` in place. Deduplicates by field id
    (case-sensitive). Existing entries are left untouched.

    When ``yml_params_by_name`` is supplied, each new param is materialized
    via :func:`emit_field_for_param` (rich shape with title + field_type +
    options; type 9 / credentials split into two fields each).

    Dedup-via-rename: when ``existing_ids`` is supplied along with
    ``new_handler_id`` + ``handler_dir``, a new param colliding with any
    entry in ``existing_ids`` is renamed to ``f"{new_handler_id}_{p}"`` and
    a ``field_mappings`` entry is appended to the handler's serializer.yaml.
    ``existing_ids`` is mutated in place. Backwards-compatible: callers
    omitting all extra args get the previous (bare-id) behavior.
    """
    if not new_general_params:
        return
    gen = capabilities_data.setdefault("general_configurations", {})
    gen.setdefault("description", "General configurations for all capabilities")
    configurations = gen.setdefault("configurations", [{"fields": []}])
    if not configurations:
        configurations.append({"fields": []})
    fields = configurations[0].setdefault("fields", [])
    local_existing = {f.get("id") for f in fields}
    for param in new_general_params:
        if param in local_existing:
            # In-bucket dedup — already present in this very general_configurations
            # block (same field id, same handler likely re-adding); skip.
            continue
        new_fields = emit_field_for_param(
            param,
            yml_params_by_name,
            handler_id=new_handler_id,
            handler_dir=handler_dir,
            existing_ids=existing_ids,
        )
        for new_field in new_fields:
            if new_field["id"] in local_existing:
                continue
            fields.append(new_field)
            local_existing.add(new_field["id"])


def build_summary_yaml(connector_title: str) -> dict:
    """Build the dict for a brand-new summary.yaml.

    Per spec, all fields are simple:
      - title: hardcoded "Summary"
      - description: templated as f"Summary for connector {connector_title}"
      - link: empty string (TBD)
      - next_steps: empty string (TBD)
    """
    return {
        "metadata": {
            "title": "Summary",
            "description": f"Summary for connector {connector_title}",
            "link": "",
            "next_steps": "",
        },
    }


# ---------------------------------------------------------------------------
# XSOAR param type → connectus field mapping
# ---------------------------------------------------------------------------
# One helper per XSOAR `type:` integer. Each emits a connectus-shaped field
# dict with the deterministic extras that depend on the type alone (mask,
# is_number_input, options.values, credentials split, default-value coercion).
# Auth-name heuristics + name→metadata.auth.parameter mappings are NOT
# applied here; they will be layered on by a follow-up helper.
#
# See connectus/connectus_migration/param_type_mapping.md for the full spec.
# ---------------------------------------------------------------------------
def _is_hidden_on_platform(yml_param: dict) -> bool:
    """Return True if the XSOAR YML param is hidden on the Cortex Platform.

    Mirrors the rule in
    :func:`connector_param_mapper._collect_hidden_params` (line 354) — the
    param is considered hidden-on-platform if EITHER:
      - Its ``hidden`` field is ``True`` (boolean, hidden in all marketplaces)
      - Its ``hidden`` field is a list containing the string ``"platform"``

    Anything else (no ``hidden``, ``hidden: false``, or a list that does NOT
    contain ``"platform"``) is visible.

    NOTE: Semantics are intentionally identical to
    ``connector_param_mapper._collect_hidden_params``. If that function's logic
    ever changes, update this helper in lockstep.
    """
    hidden_value = yml_param.get("hidden")
    return hidden_value is True or (
        isinstance(hidden_value, list) and "platform" in hidden_value
    )


def _apply_common_field_metadata(field: dict, yml_param: dict) -> None:
    """Layer the type-independent metadata (title, help_text, default_value,
    required gates) onto an already-built connectus field dict.

    Mutates ``field`` in place. Does NOT touch ``options.values`` or
    ``options.mask`` etc. — those are type-specific and set by the per-type
    helpers BEFORE this is called.
    """
    name = yml_param.get("name", "")
    display = yml_param.get("display") or name
    field.setdefault("title", display)

    options = field.setdefault("options", {})

    additional_info = yml_param.get("additionalinfo")
    if additional_info:
        options["description"] = additional_info

    # Per-type coercion is handled by the caller BEFORE invoking this helper
    # (so the value is already in the right shape). For types where coercion
    # isn't needed, just pass through.
    if (
        "defaultvalue" in yml_param
        and yml_param["defaultvalue"] is not None
        and "default_value" not in options
    ):
        options["default_value"] = yml_param["defaultvalue"]

    required = bool(yml_param.get("required"))
    hidden = _is_hidden_on_platform(yml_param)
    options["create_modifiers"] = {"required": required, "hidden": hidden}
    options["edit_modifiers"] = {"required": required, "hidden": hidden}


def _coerce_toggle_default(raw: Any) -> bool:
    """Convert XSOAR's str/bool default for type 8 (boolean) into a Python bool."""
    if isinstance(raw, str):
        return raw.lower() == "true"
    return bool(raw)


def _coerce_multi_select_default(raw: Any) -> list:
    """Convert XSOAR's CSV-string default for type 16 (multi-select) into a list of keys."""
    if isinstance(raw, str):
        return [s.strip() for s in raw.split(",") if s.strip()]
    if isinstance(raw, list):
        return raw
    return [raw]


# ---- Per-type mappers ------------------------------------------------------

def _map_type_0(yml_param: dict) -> dict:
    """XSOAR type 0 — Short text → connectus `input`."""
    field = {"id": yml_param["name"], "field_type": "input"}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_1(yml_param: dict) -> dict:
    """XSOAR type 1 — Hidden short text (legacy) → connectus `input` with mask."""
    field = {"id": yml_param["name"], "field_type": "input", "options": {"mask": True}}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_4(yml_param: dict) -> dict:
    """XSOAR type 4 — Encrypted → connectus `input` with mask."""
    field = {"id": yml_param["name"], "field_type": "input", "options": {"mask": True}}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_8(yml_param: dict) -> dict:
    """XSOAR type 8 — Boolean → connectus `toggle`. Coerces default_value to bool."""
    field = {"id": yml_param["name"], "field_type": "toggle"}
    options = field.setdefault("options", {})
    if "defaultvalue" in yml_param and yml_param["defaultvalue"] is not None:
        options["default_value"] = _coerce_toggle_default(yml_param["defaultvalue"])
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_9(yml_param: dict) -> list[dict]:
    """XSOAR type 9 — Credentials (compound) → 1 or 2 connectus `input` fields.

    If the YAML carries ``hiddenusername: true``, only the password half is
    emitted (the credentials store is being repurposed as a secret-only sink).
    Otherwise both username + password fields are emitted.

    Note: this helper does NOT set ``metadata.auth.parameter`` — that's
    layered on by the auth-name-heuristics helper later in the migration
    pipeline. We only emit the deterministic shape here.
    """
    name = yml_param.get("name", "")
    display = yml_param.get("display") or name
    display_password = yml_param.get("displaypassword") or display

    fields: list[dict] = []

    # Compute once and reuse for both halves so they stay in lockstep.
    required = bool(yml_param.get("required"))
    hidden = _is_hidden_on_platform(yml_param)

    if not yml_param.get("hiddenusername"):
        username_field = {
            "id": f"{name}_username",
            "title": display,
            "field_type": "input",
        }
        # Required + hidden gates: same as parent.
        username_field["options"] = {
            "create_modifiers": {"required": required, "hidden": hidden},
            "edit_modifiers": {"required": required, "hidden": hidden},
        }
        # additionalinfo (if any) goes on the username half.
        additional_info = yml_param.get("additionalinfo")
        if additional_info:
            username_field["options"]["description"] = additional_info
        fields.append(username_field)

    password_field = {
        "id": f"{name}_password" if not yml_param.get("hiddenusername") else name,
        "title": display_password,
        "field_type": "input",
        "options": {"mask": True},
    }
    password_field["options"]["create_modifiers"] = {"required": required, "hidden": hidden}
    password_field["options"]["edit_modifiers"] = {"required": required, "hidden": hidden}
    fields.append(password_field)

    return fields


def _map_type_12(yml_param: dict) -> dict:
    """XSOAR type 12 — Long text → connectus `text_area`."""
    field = {"id": yml_param["name"], "field_type": "text_area"}
    _apply_common_field_metadata(field, yml_param)
    return field


def _build_select_values(yml_param: dict, label_key: str = "value") -> list[dict]:
    """Build connectus `options.values` from the YAML's `options:` list.

    Each connectus item is `{key: ..., value/label: ...}` depending on the
    target field type:
    - select uses {key, value}  → label_key="value"
    - multi_select uses {key, label} → label_key="label"
    """
    items = []
    for v in yml_param.get("options", []) or []:
        items.append({"key": v, label_key: v})
    return items


def _map_type_13(yml_param: dict) -> dict:
    """XSOAR type 13 — Single-select (system catalogue) → connectus `select`."""
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": _build_select_values(yml_param, label_key="value")},
    }
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_14(yml_param: dict) -> dict:
    """XSOAR type 14 — Encrypted long text → connectus `text_area` with mask."""
    field = {"id": yml_param["name"], "field_type": "text_area", "options": {"mask": True}}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_15(yml_param: dict) -> dict:
    """XSOAR type 15 — Single-select → connectus `select` with `{key, value}` items."""
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": _build_select_values(yml_param, label_key="value")},
    }
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_16(yml_param: dict) -> dict:
    """XSOAR type 16 — Multi-select → connectus `multi_select` with `{key, label}` items.

    Coerces CSV string default → list of keys.
    """
    field = {
        "id": yml_param["name"],
        "field_type": "multi_select",
        "options": {"values": _build_select_values(yml_param, label_key="label")},
    }
    if "defaultvalue" in yml_param and yml_param["defaultvalue"] is not None:
        field["options"]["default_value"] = _coerce_multi_select_default(
            yml_param["defaultvalue"]
        )
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_17(yml_param: dict) -> dict:
    """XSOAR type 17 — Date → connectus `input` (no native date picker)."""
    field = {"id": yml_param["name"], "field_type": "input"}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_18(yml_param: dict) -> dict:
    """XSOAR type 18 — Grouped single-select → connectus `select` (categories flattened)."""
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": _build_select_values(yml_param, label_key="value")},
    }
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_19(yml_param: dict) -> dict:
    """XSOAR type 19 — Numeric/interval → connectus `input` with `is_number_input: true`."""
    field = {
        "id": yml_param["name"],
        "field_type": "input",
        "options": {"is_number_input": True},
    }
    _apply_common_field_metadata(field, yml_param)
    return field


# Registry mapping XSOAR type integer → mapper function.
MAPPERS: dict[int, Callable] = {
    0: _map_type_0,
    1: _map_type_1,
    4: _map_type_4,
    8: _map_type_8,
    9: _map_type_9,
    12: _map_type_12,
    13: _map_type_13,
    14: _map_type_14,
    15: _map_type_15,
    16: _map_type_16,
    17: _map_type_17,
    18: _map_type_18,
    19: _map_type_19,
}


def map_xsoar_param_to_connectus_field(yml_param: dict) -> list[dict]:
    """Public dispatcher: map an XSOAR YAML config param to one or more connectus field dicts.

    Looks up the right `_map_type_<N>` helper from ``MAPPERS`` based on the
    YAML's ``type`` integer. Raises ``ValueError`` for unknown types.

    Returns a list — single-field types yield a one-element list; only
    type 9 (credentials) returns a list with multiple entries.
    """
    xsoar_type = yml_param.get("type", 0)
    mapper = MAPPERS.get(xsoar_type)
    if mapper is None:
        raise ValueError(
            f"No connectus field mapper for XSOAR type {xsoar_type}. "
            f"Param: {yml_param.get('name', '<unnamed>')}. "
            f"Known types: {sorted(MAPPERS.keys())}"
        )
    result = mapper(yml_param)
    if isinstance(result, dict):
        return [result]
    return result


# ---------------------------------------------------------------------------
# Dispatch targets (stubs — per-file rules to be added later)
# ---------------------------------------------------------------------------
def create_manifest_from_scratch(
    connector_dir: Path,
    integration_yml: dict,
    integration_path: Path,
    connector_title: str,
    mapped_params: dict[str, Any],
    auth_methods: dict[str, Any],
    author_image_path: Path | None = None,
    manual_connector_fields: dict | None = None,
    manual_handler_fields: dict | None = None,
    manual_summary_fields: dict | None = None,
    manual_capabilities_fields: dict | None = None,
    manual_configurations_fields: dict | None = None,
    manual_serializer_fields: dict | None = None,
    manual_connection_fields: dict | None = None,
) -> None:
    """Create a brand-new connector folder from scratch.

    If ``author_image_path`` is provided, the image is copied into the
    connector root as ``<connector_id><source_suffix>`` and that filename is
    written into ``connector.yaml``'s ``metadata.author_image`` field. When
    not provided, ``author_image`` is left as an empty string.
    """
    logger.info(f"[manifest_generator] Creating new connector at {connector_dir}")
    logger.debug(
        f"[manifest_generator] auth_methods received with "
        f"{len(auth_methods.get('auth_types', []))} auth_types"
    )

    if manual_serializer_fields:
        logger.info(
            "[manifest_generator] manual_serializer_fields received with keys "
            f"{list(manual_serializer_fields.keys())} but serializer.yaml is a "
            "string stub — overrides will NOT be applied until serializer becomes dict-based."
        )
    if manual_connection_fields:
        logger.info(
            "[manifest_generator] manual_connection_fields received with keys "
            f"{list(manual_connection_fields.keys())} but connection.yaml is not yet "
            "implemented — overrides will NOT be applied until that file is built."
        )

    # Create the connector directory if it doesn't exist
    connector_dir.mkdir(parents=True, exist_ok=True)

    # Copy the author image (if provided) into the connector root before
    # building connector.yaml so we can record the dest filename.
    author_image_filename = ""
    if author_image_path is not None:
        connector_id = title_to_slug(connector_title)
        author_image_filename = _copy_author_image(
            connector_dir, connector_id, author_image_path
        )

    # Generate connector.yaml
    pack_tags = get_pack_tags(integration_path)
    connector_data = build_connector_yaml(
        connector_title, pack_tags, author_image_filename=author_image_filename
    )
    connector_data = deep_merge_dicts(connector_data, manual_connector_fields or {})
    connector_yaml_path = connector_dir / "connector.yaml"
    with open(connector_yaml_path, "w") as fh:
        yaml.safe_dump(connector_data, fh)
    logger.info(f"[manifest_generator] Generated {connector_yaml_path}")

    # Generate handler.yaml for this integration
    handler_data = build_handler_yaml(
        integration_yml,
        connector_title,
        pack_tags,
        mapped_params,
        auth_methods,
    )
    handler_data = deep_merge_dicts(handler_data, manual_handler_fields or {})
    handler_id = handler_data["id"]
    handler_yaml_path = (
        connector_dir / "components" / "handlers" / handler_id / "handler.yaml"
    )
    handler_dir = handler_yaml_path.parent
    write_handler_yaml(handler_yaml_path, handler_data)
    logger.info(f"[manifest_generator] Generated {handler_yaml_path}")

    # Generate summary.yaml (one per connector — only on from-scratch path)
    summary_data = build_summary_yaml(connector_title)
    summary_data = deep_merge_dicts(summary_data, manual_summary_fields or {})
    summary_yaml_path = connector_dir / "summary.yaml"
    with open(summary_yaml_path, "w") as fh:
        yaml.safe_dump(summary_data, fh)
    logger.info(f"[manifest_generator] Generated {summary_yaml_path}")

    # Dedup bookkeeping: from-scratch starts with an empty set; both
    # builders mutate it in place so cross-file collisions (e.g., a field
    # appearing in both general_configurations and a per-capability bucket)
    # trigger the rename + serializer registration in the second emission.
    existing_field_ids: set[str] = set()

    # Build a name -> yml param dict lookup once so the field materializer
    # can produce rich field shapes (title / field_type / options / etc.)
    # for every emitted param.
    yml_params_by_name = {
        p["name"]: p
        for p in (integration_yml.get("configuration") or [])
        if p.get("name")
    }

    # Generate capabilities.yaml
    capabilities_data = build_capabilities_yaml(
        mapped_params,
        yml_params_by_name=yml_params_by_name,
        handler_id=handler_id,
        handler_dir=handler_dir,
        existing_ids=existing_field_ids,
    )
    capabilities_data = deep_merge_dicts(
        capabilities_data, manual_capabilities_fields or {}
    )
    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    write_capabilities_yaml(capabilities_yaml_path, capabilities_data)
    logger.info(f"[manifest_generator] Generated {capabilities_yaml_path}")

    # Generate configurations.yaml (no schema directive)
    configurations_data = build_configurations_yaml(
        mapped_params,
        yml_params_by_name=yml_params_by_name,
        handler_id=handler_id,
        handler_dir=handler_dir,
        existing_ids=existing_field_ids,
    )
    configurations_data = deep_merge_dicts(
        configurations_data, manual_configurations_fields or {}
    )
    configurations_yaml_path = connector_dir / "configurations.yaml"
    with open(configurations_yaml_path, "w") as fh:
        yaml.safe_dump(configurations_data, fh)
    logger.info(f"[manifest_generator] Generated {configurations_yaml_path}")

    # Generate serializer.yaml stub (per-handler placeholder) — only if
    # the dedup step did not already create a dict-based serializer.yaml.
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    if not serializer_yaml_path.exists():
        write_serializer_yaml(serializer_yaml_path)
        logger.info(f"[manifest_generator] Generated {serializer_yaml_path}")
    else:
        logger.info(
            f"[manifest_generator] Serializer.yaml already present at "
            f"{serializer_yaml_path} (populated by dedup step); not overwriting"
        )

    # TODO: generate connection.yaml
    # TODO: generate connection.yaml from auth_methods


def add_handler_to_existing_connector(
    connector_dir: Path,
    integration_yml: dict,
    integration_path: Path,
    connector_title: str,
    mapped_params: dict[str, Any],
    auth_methods: dict[str, Any],
    author_image_path: Path | None = None,
    manual_connector_fields: dict | None = None,
    manual_handler_fields: dict | None = None,
    manual_summary_fields: dict | None = None,
    manual_capabilities_fields: dict | None = None,
    manual_configurations_fields: dict | None = None,
    manual_serializer_fields: dict | None = None,
    manual_connection_fields: dict | None = None,
) -> None:
    """Add a new handler under an existing connector and update shared files.

    Note: ``author_image_path`` is accepted for API uniformity but the
    append path does NOT touch the connector's author image — that is a
    from-scratch-only operation (per spec). If provided, it's silently
    ignored.
    """
    # Author image is owned by the from-scratch path only.
    _ = author_image_path
    logger.info(
        f"[manifest_generator] Updating existing connector at {connector_dir}"
    )
    logger.debug(
        f"[manifest_generator] auth_methods received with "
        f"{len(auth_methods.get('auth_types', []))} auth_types"
    )

    if manual_serializer_fields:
        logger.info(
            "[manifest_generator] manual_serializer_fields received with keys "
            f"{list(manual_serializer_fields.keys())} but serializer.yaml is a "
            "string stub — overrides will NOT be applied until serializer becomes dict-based."
        )
    if manual_connection_fields:
        logger.info(
            "[manifest_generator] manual_connection_fields received with keys "
            f"{list(manual_connection_fields.keys())} but connection.yaml is not yet "
            "implemented — overrides will NOT be applied until that file is built."
        )
    # Note: manual_summary_fields is accepted for API uniformity but the
    # append path does not touch summary.yaml.
    _ = manual_summary_fields

    # Update connector.yaml: merge tags + bump version
    connector_yaml_path = connector_dir / "connector.yaml"
    with open(connector_yaml_path) as fh:
        connector_data = yaml.safe_load(fh) or {}

    metadata = connector_data.setdefault("metadata", {})

    # Merge tags case-insensitively
    existing_tags = metadata.get("tags") or []
    pack_tags = get_pack_tags(integration_path)
    merged_tags = merge_tags_case_insensitive(existing_tags, pack_tags)
    metadata["tags"] = merged_tags

    # Bump minor version
    current_version = metadata.get("version", "")
    new_version = bump_minor_version(current_version)
    metadata["version"] = new_version
    logger.info(
        f"[manifest_generator] Bumped version: {current_version} → {new_version}"
    )

    connector_data = deep_merge_dicts(connector_data, manual_connector_fields or {})

    with open(connector_yaml_path, "w") as fh:
        yaml.safe_dump(connector_data, fh)
    logger.info(f"[manifest_generator] Updated {connector_yaml_path}")

    # Pre-flight: pre-compute the new handler id and check the handler.yaml
    # path is free BEFORE we mutate any shared files. This avoids leaving
    # capabilities.yaml / configurations.yaml in a half-updated state when
    # the handler can't be added because it already exists.
    new_handler_id = derive_handler_id(
        integration_yml.get("commonfields", {}).get("id", "")
    )
    handler_yaml_path = (
        connector_dir
        / "components"
        / "handlers"
        / new_handler_id
        / "handler.yaml"
    )
    if handler_yaml_path.exists():
        raise FileExistsError(
            f"Handler file already exists at {handler_yaml_path}. "
            f"This handler ('{new_handler_id}') is already registered under this connector."
        )

    # Load capabilities.yaml + configurations.yaml so we can mutate them
    # in-memory before writing both back at the end. Tolerate missing files
    # (treat as empty starting state) — older connectors may not have
    # generated these yet.
    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    configurations_yaml_path = connector_dir / "configurations.yaml"
    if capabilities_yaml_path.is_file():
        with open(capabilities_yaml_path) as fh:
            first_line = fh.readline()
            rest = fh.read()
            if not first_line.startswith("# yaml-language-server"):
                rest = first_line + rest
        capabilities_data = yaml.safe_load(io.StringIO(rest)) or {}
    else:
        capabilities_data = {}
    if configurations_yaml_path.is_file():
        with open(configurations_yaml_path) as fh:
            configurations_data = yaml.safe_load(fh) or {}
    else:
        configurations_data = {}

    # Optional: load connection.yaml so dedup considers its profile field ids
    # (per Q4=b in the design). Tolerate missing file; we don't generate one
    # yet, but a previous run or manual file may exist.
    connection_yaml_path = connector_dir / "connection.yaml"
    if connection_yaml_path.is_file():
        with open(connection_yaml_path) as fh:
            connection_data = yaml.safe_load(fh) or {}
    else:
        connection_data = {}

    # Build the cross-file existing-id set BEFORE any new field is added so
    # newcomers get renamed against the full prior state.
    existing_field_ids = collect_existing_field_ids(
        capabilities_data, configurations_data, connection_data
    )
    handler_dir = (
        connector_dir / "components" / "handlers" / new_handler_id
    )

    # Build a name -> yml param dict lookup once so the field materializer
    # can produce rich field shapes for every emitted param.
    yml_params_by_name = {
        p["name"]: p
        for p in (integration_yml.get("configuration") or [])
        if p.get("name")
    }

    # Merge general configurations (deduplicated by field id).
    merge_general_configurations(
        capabilities_data,
        mapped_params.get("general_configurations", []) or [],
        yml_params_by_name=yml_params_by_name,
        new_handler_id=new_handler_id,
        handler_dir=handler_dir,
        existing_ids=existing_field_ids,
    )

    # Per-capability append: compute the cap id mapping the new handler
    # should use, while mutating capabilities/configurations data.
    cap_name_to_handler_cap_id: dict[str, str] = {}
    for cap_name, cap_params in mapped_params.items():
        if cap_name == "general_configurations":
            continue
        handler_cap_id = append_capability_to_files(
            cap_name=cap_name,
            cap_params=cap_params or [],
            new_handler_id=new_handler_id,
            capabilities_data=capabilities_data,
            configurations_data=configurations_data,
            connector_dir=connector_dir,
            yml_params_by_name=yml_params_by_name,
            existing_ids=existing_field_ids,
        )
        cap_name_to_handler_cap_id[cap_name] = handler_cap_id

    # Generate handler.yaml for this new integration (with sub-cap-aware ids).
    handler_data = build_handler_yaml(
        integration_yml,
        connector_title,
        pack_tags,
        mapped_params,
        auth_methods,
        cap_name_to_handler_cap_id=cap_name_to_handler_cap_id,
    )
    handler_data = deep_merge_dicts(handler_data, manual_handler_fields or {})
    write_handler_yaml(handler_yaml_path, handler_data)
    logger.info(f"[manifest_generator] Generated {handler_yaml_path}")

    # Generate serializer.yaml stub (per-handler placeholder) — skip if the
    # dedup pass already created a dict-based serializer.yaml.
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    if not serializer_yaml_path.exists():
        write_serializer_yaml(serializer_yaml_path)
        logger.info(f"[manifest_generator] Generated {serializer_yaml_path}")
    else:
        logger.info(
            f"[manifest_generator] Serializer.yaml already present at "
            f"{serializer_yaml_path} (populated by dedup step); not overwriting"
        )

    # Write capabilities.yaml back (with schema directive).
    capabilities_data = deep_merge_dicts(
        capabilities_data, manual_capabilities_fields or {}
    )
    write_capabilities_yaml(capabilities_yaml_path, capabilities_data)
    logger.info(f"[manifest_generator] Updated {capabilities_yaml_path}")

    # Write configurations.yaml back (no schema directive).
    configurations_data = deep_merge_dicts(
        configurations_data, manual_configurations_fields or {}
    )
    with open(configurations_yaml_path, "w") as fh:
        yaml.safe_dump(configurations_data, fh)
    logger.info(f"[manifest_generator] Updated {configurations_yaml_path}")

    # TODO: append to connection.yaml (skip existing profile ids)
    # TODO: generate connection.yaml from auth_methods


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------
@main.command()
def generate_manifest(
    integration_path: Path = typer.Argument(
        ...,
        exists=True,
        help="Path to the XSOAR integration YML file.",
    ),
    connector_title: str = typer.Argument(
        ...,
        help="Human-readable connector title (e.g. 'Salesforce'). The "
        "directory slug is derived as title.lower().replace(' ', '').",
    ),
    mapped_params: str = typer.Argument(
        ...,
        help="JSON string output of connector_param_mapper.py "
        "(shape: {capability: [params]}).",
    ),
    auth_methods: str = typer.Argument(
        "{}",
        help=(
            "JSON string describing authentication methods. Shape:\n"
            '{"auth_types": [...], "other_connection": [...]}\n'
            "Used to generate connection.yaml in a future iteration. "
            "Pass '{}' or omit to disable."
        ),
    ),
    connectors_root: Path = typer.Option(
        Path.cwd() / "connectors",
        "--connectors-root",
        help="Root directory under which connector folders live. "
        "Defaults to <CWD>/connectors.",
    ),
    author_image_path: Path = typer.Option(
        None,
        "--author-image-path",
        help=(
            "Optional path to an author image file to copy into the new "
            "connector's root as <connector_id><source_suffix>. Used to "
            "populate connector.yaml's metadata.author_image field. "
            "From-scratch path only — silently ignored on the append path."
        ),
    ),
    manual_connector_fields: str = typer.Option(
        "{}",
        "--manual-connector-fields",
        help="JSON string of manual overrides to deep-merge into connector.yaml.",
    ),
    manual_handler_fields: str = typer.Option(
        "{}",
        "--manual-handler-fields",
        help="JSON string of manual overrides to deep-merge into handler.yaml.",
    ),
    manual_summary_fields: str = typer.Option(
        "{}",
        "--manual-summary-fields",
        help="JSON string of manual overrides to deep-merge into summary.yaml.",
    ),
    manual_capabilities_fields: str = typer.Option(
        "{}",
        "--manual-capabilities-fields",
        help="JSON string of manual overrides to deep-merge into capabilities.yaml.",
    ),
    manual_configurations_fields: str = typer.Option(
        "{}",
        "--manual-configurations-fields",
        help="JSON string of manual overrides to deep-merge into configurations.yaml.",
    ),
    manual_serializer_fields: str = typer.Option(
        "{}",
        "--manual-serializer-fields",
        help=(
            "JSON string of manual overrides for serializer.yaml. "
            "NOT YET APPLIED — serializer.yaml is currently a stub."
        ),
    ),
    manual_connection_fields: str = typer.Option(
        "{}",
        "--manual-connection-fields",
        help=(
            "JSON string of manual overrides for connection.yaml. "
            "NOT YET APPLIED — connection.yaml is not yet implemented."
        ),
    ),
) -> None:
    """Scaffold a new connector or add a handler to an existing one.

    The script decides between the two paths automatically:

    * If ``<connectors_root>/<slug>/connector.yaml`` exists, only the
      handler is added (and shared files are updated).
    * Otherwise, the full connector folder is created from scratch.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    integration_yml = load_integration_yml(integration_path)
    mapped_params_dict = parse_mapped_params(mapped_params)
    auth_methods_dict = parse_mapped_params(auth_methods)

    manual_connector_fields_dict = parse_mapped_params(manual_connector_fields)
    manual_handler_fields_dict = parse_mapped_params(manual_handler_fields)
    manual_summary_fields_dict = parse_mapped_params(manual_summary_fields)
    manual_capabilities_fields_dict = parse_mapped_params(manual_capabilities_fields)
    manual_configurations_fields_dict = parse_mapped_params(
        manual_configurations_fields
    )
    manual_serializer_fields_dict = parse_mapped_params(manual_serializer_fields)
    manual_connection_fields_dict = parse_mapped_params(manual_connection_fields)

    slug = title_to_slug(connector_title)
    connector_dir = connectors_root / slug

    logger.info(
        f"[manifest_generator] integration={integration_path} "
        f"title={connector_title!r} slug={slug!r} target={connector_dir} "
        f"auth_methods_keys={list(auth_methods_dict.keys())}"
    )

    if connector_exists(connector_dir):
        add_handler_to_existing_connector(
            connector_dir=connector_dir,
            integration_yml=integration_yml,
            integration_path=integration_path,
            connector_title=connector_title,
            mapped_params=mapped_params_dict,
            auth_methods=auth_methods_dict,
            author_image_path=author_image_path,
            manual_connector_fields=manual_connector_fields_dict,
            manual_handler_fields=manual_handler_fields_dict,
            manual_summary_fields=manual_summary_fields_dict,
            manual_capabilities_fields=manual_capabilities_fields_dict,
            manual_configurations_fields=manual_configurations_fields_dict,
            manual_serializer_fields=manual_serializer_fields_dict,
            manual_connection_fields=manual_connection_fields_dict,
        )
    else:
        create_manifest_from_scratch(
            connector_dir=connector_dir,
            integration_yml=integration_yml,
            integration_path=integration_path,
            connector_title=connector_title,
            mapped_params=mapped_params_dict,
            auth_methods=auth_methods_dict,
            author_image_path=author_image_path,
            manual_connector_fields=manual_connector_fields_dict,
            manual_handler_fields=manual_handler_fields_dict,
            manual_summary_fields=manual_summary_fields_dict,
            manual_capabilities_fields=manual_capabilities_fields_dict,
            manual_configurations_fields=manual_configurations_fields_dict,
            manual_serializer_fields=manual_serializer_fields_dict,
            manual_connection_fields=manual_connection_fields_dict,
        )


if __name__ == "__main__":
    main()
