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
from pathlib import Path
from typing import Any

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


def build_connector_yaml(connector_title: str, pack_tags: list[str]) -> dict:
    """Build the dict for a brand-new connector.yaml.

    All TBD fields (description, category, domain, vendor) are set to empty
    strings. Per-task spec:
      - publisher: "Palo Alto Networks" (hardcoded)
      - author_image: "icon-gcp" (hardcoded)
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
            "author_image": "icon-gcp",
            "ownership": {
                "team": "xsoar",
                "maintainers": ["@xsoar-content"],
            },
        },
        "settings": {
            "allow_skip_verification": False,
        },
    }


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


CAPABILITIES_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/capabilities.schema.json\n"
)


def build_capabilities_yaml(mapped_params: dict[str, Any]) -> dict:
    """Build the dict for capabilities.yaml.

    Per POC: only 'id' is populated for each capability and each general-config
    field. Other schema-required fields (title, description, default_enabled,
    required) are intentionally omitted — to be added later.
    """
    general_params = mapped_params.get("general_configurations", []) or []
    general_fields = [{"id": p} for p in general_params]

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


def build_configurations_yaml(mapped_params: dict[str, Any]) -> dict:
    """Build the dict for configurations.yaml.

    Per POC: only the 'id' (capability-id and field-id) is populated.
    Other field metadata (title, type, options, etc.) intentionally omitted.
    """
    configurations = []
    for cap_name, params in mapped_params.items():
        if cap_name == "general_configurations":
            continue
        cap_id = slugify_capability_name(cap_name)
        fields = [{"id": p} for p in (params or [])]
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
) -> str:
    """Process one capability for the append-handler path.

    Determines which case applies (1, 2, or 3) and mutates
    ``capabilities_data``, ``configurations_data``, and (for Case 2) the
    existing handler.yaml file.

    Returns the cap id that the NEW handler should reference in its own
    handler.yaml ``capabilities`` list (either the bare slug for Case 3, or
    the sub-cap id ``<new_handler_id>-<cap_slug>`` for Cases 1 and 2).
    """
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
                "configurations": [{"fields": [{"id": p} for p in cap_params]}],
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
            "configurations": [{"fields": [{"id": p} for p in cap_params]}],
        }
    )

    return new_sub_cap_id


def merge_general_configurations(
    capabilities_data: dict, new_general_params: list[str]
) -> None:
    """Append new general params to capabilities.yaml's general_configurations.

    Mutates ``capabilities_data`` in place. Deduplicates by field id
    (case-sensitive). Existing entries are left untouched.
    """
    if not new_general_params:
        return
    gen = capabilities_data.setdefault("general_configurations", {})
    gen.setdefault("description", "General configurations for all capabilities")
    configurations = gen.setdefault("configurations", [{"fields": []}])
    if not configurations:
        configurations.append({"fields": []})
    fields = configurations[0].setdefault("fields", [])
    existing_ids = {f.get("id") for f in fields}
    for param in new_general_params:
        if param not in existing_ids:
            fields.append({"id": param})
            existing_ids.add(param)


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
# Dispatch targets (stubs — per-file rules to be added later)
# ---------------------------------------------------------------------------
def create_manifest_from_scratch(
    connector_dir: Path,
    integration_yml: dict,
    integration_path: Path,
    connector_title: str,
    mapped_params: dict[str, Any],
    auth_methods: dict[str, Any],
) -> None:
    """Create a brand-new connector folder from scratch.

    For now, only generates ``connector.yaml``. The other files
    (capabilities.yaml, configurations.yaml, connection.yaml, handlers/) will
    be added in follow-up iterations.
    """
    logger.info(f"[manifest_generator] Creating new connector at {connector_dir}")
    logger.debug(
        f"[manifest_generator] auth_methods received with "
        f"{len(auth_methods.get('auth_types', []))} auth_types"
    )

    # Create the connector directory if it doesn't exist
    connector_dir.mkdir(parents=True, exist_ok=True)

    # Generate connector.yaml
    pack_tags = get_pack_tags(integration_path)
    connector_data = build_connector_yaml(connector_title, pack_tags)
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
    handler_id = handler_data["id"]
    handler_yaml_path = (
        connector_dir / "components" / "handlers" / handler_id / "handler.yaml"
    )
    write_handler_yaml(handler_yaml_path, handler_data)
    logger.info(f"[manifest_generator] Generated {handler_yaml_path}")

    # Generate serializer.yaml stub (per-handler placeholder)
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    write_serializer_yaml(serializer_yaml_path)
    logger.info(f"[manifest_generator] Generated {serializer_yaml_path}")

    # Generate summary.yaml (one per connector — only on from-scratch path)
    summary_data = build_summary_yaml(connector_title)
    summary_yaml_path = connector_dir / "summary.yaml"
    with open(summary_yaml_path, "w") as fh:
        yaml.safe_dump(summary_data, fh)
    logger.info(f"[manifest_generator] Generated {summary_yaml_path}")

    # Generate capabilities.yaml
    capabilities_data = build_capabilities_yaml(mapped_params)
    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    write_capabilities_yaml(capabilities_yaml_path, capabilities_data)
    logger.info(f"[manifest_generator] Generated {capabilities_yaml_path}")

    # Generate configurations.yaml (no schema directive)
    configurations_data = build_configurations_yaml(mapped_params)
    configurations_yaml_path = connector_dir / "configurations.yaml"
    with open(configurations_yaml_path, "w") as fh:
        yaml.safe_dump(configurations_data, fh)
    logger.info(f"[manifest_generator] Generated {configurations_yaml_path}")

    # TODO: generate connection.yaml
    # TODO: generate connection.yaml from auth_methods


def add_handler_to_existing_connector(
    connector_dir: Path,
    integration_yml: dict,
    integration_path: Path,
    connector_title: str,
    mapped_params: dict[str, Any],
    auth_methods: dict[str, Any],
) -> None:
    """Add a new handler under an existing connector and update shared files.

    For now, only updates ``connector.yaml`` (merges pack tags + bumps minor
    version). The other files will be updated in follow-up iterations.
    """
    logger.info(
        f"[manifest_generator] Updating existing connector at {connector_dir}"
    )
    logger.debug(
        f"[manifest_generator] auth_methods received with "
        f"{len(auth_methods.get('auth_types', []))} auth_types"
    )

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

    # Merge general configurations (deduplicated by field id).
    merge_general_configurations(
        capabilities_data, mapped_params.get("general_configurations", []) or []
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
    write_handler_yaml(handler_yaml_path, handler_data)
    logger.info(f"[manifest_generator] Generated {handler_yaml_path}")

    # Generate serializer.yaml stub (per-handler placeholder)
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    write_serializer_yaml(serializer_yaml_path)
    logger.info(f"[manifest_generator] Generated {serializer_yaml_path}")

    # Write capabilities.yaml back (with schema directive).
    write_capabilities_yaml(capabilities_yaml_path, capabilities_data)
    logger.info(f"[manifest_generator] Updated {capabilities_yaml_path}")

    # Write configurations.yaml back (no schema directive).
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
            '{"auth_types": [...], "config": "...", "additional_params": [...]}\n'
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
        )
    else:
        create_manifest_from_scratch(
            connector_dir=connector_dir,
            integration_yml=integration_yml,
            integration_path=integration_path,
            connector_title=connector_title,
            mapped_params=mapped_params_dict,
            auth_methods=auth_methods_dict,
        )


if __name__ == "__main__":
    main()
