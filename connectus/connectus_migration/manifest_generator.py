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
# ---------------------------------------------------------------------------
# Connector id / title naming convention (per guide §3.3.1)
# ---------------------------------------------------------------------------
# Capability families classified for suffix derivation. The "collection"
# umbrella covers every fetch capability regardless of which specific
# fetch capabilities are exposed.
_COLLECTION_CAP_IDS: frozenset[str] = frozenset(
    {
        "log-collection",
        "fetch-issues",
        "fetch-assets-and-vulnerabilities",
        "threat-intelligence-and-enrichment",
        "fetch-secrets",
    }
)
_AUTOMATION_CAP_ID = "automation-and-remediation"


def derive_connector_suffix(mapped_params: dict) -> tuple[str, str]:
    """Compute the connector-id / title suffix from declared capabilities.

    Per guide §3.3.1 *Suffix derivation*:

      - Only ``automation-and-remediation``      → ``"Automation"``
      - Only one or more collection capabilities → ``"Collection"``
      - Both automation AND ≥1 collection        → ``"Automation and Collection"``

    Returns ``(id_form, title_form)``:
      - id_form: lowercase, dashes (e.g. ``"automation-and-collection"``)
      - title_form: Title Case, spaces (e.g. ``"Automation and Collection"``)

    Args:
        mapped_params: The full mapper output dict — bucket-key →
            param-list. The function looks at the keys (excluding
            ``general_configurations``) and resolves each through
            :func:`slugify_capability_name` to get its canonical id.

    Raises:
        ValueError: if ``mapped_params`` declares zero capabilities
            (per guide §3.3.1 *Flags*: "If the connector declares zero
            capabilities, raise a flag — every connector must expose at
            least one capability family.").
    """
    declared_cap_ids = {
        slugify_capability_name(cap_name)
        for cap_name in mapped_params
        if cap_name != "general_configurations"
    }
    if not declared_cap_ids:
        raise ValueError(
            "Cannot derive connector id suffix: mapped_params declares "
            "zero capabilities. Per guide §3.3.1, every connector must "
            "expose at least one capability family."
        )

    has_automation = _AUTOMATION_CAP_ID in declared_cap_ids
    has_collection = bool(declared_cap_ids & _COLLECTION_CAP_IDS)

    if has_automation and has_collection:
        return "automation-and-collection", "Automation and Collection"
    if has_automation:
        return "automation", "Automation"
    # Only collection capabilities (or unknown ones that shouldn't reach
    # here — slugify_capability_name would have raised earlier).
    return "collection", "Collection"


def _vendor_to_id_slug(vendor: str) -> str:
    """Lowercase + dash-separate the vendor name for use in the connector id.

    Per guide §3.3.1 *Vendor prefix*: id form is lowercased, spaces
    replaced with dashes, any other non-``[a-z0-9-]`` character stripped
    or replaced with a dash. Collapses runs of dashes.
    """
    s = vendor.strip().lower()
    s = re.sub(r"[^a-z0-9-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


def _vendor_to_title(vendor: str) -> str:
    """Render the vendor name in Title Case for use in metadata.title.

    Per guide §3.3.1: the title form preserves spaces and uses Title
    Case. ``Palo Alto Networks`` ↔ ``palo alto networks`` round-trips.
    """
    return " ".join(w.capitalize() for w in vendor.strip().split())


def derive_connector_id_and_title(
    vendor: str, mapped_params: dict
) -> tuple[str, str]:
    """Derive the connector id and title per guide §3.3.1.

    Combines the vendor prefix with the capability suffix.

    Args:
        vendor: Vendor name (e.g. ``"Okta"``, ``"Palo Alto Networks"``).
            Must be a non-empty string containing at least one
            ``[A-Za-z0-9]`` character — otherwise per guide §3.3.1
            *Flags* the connector id cannot be cleanly rendered and a
            manual id is required.
        mapped_params: The full mapper output dict (see
            :func:`derive_connector_suffix`).

    Returns:
        ``(connector_id, connector_title)`` — e.g.
        ``("okta-automation-and-collection", "Okta Automation and Collection")``.

    Raises:
        ValueError: if ``vendor`` is empty/unparseable, or if
            ``mapped_params`` declares zero capabilities.
    """
    vendor_id = _vendor_to_id_slug(vendor)
    if not vendor_id:
        raise ValueError(
            f"Vendor name '{vendor}' cannot be rendered as a connector id "
            f"slug (no [a-z0-9] characters after normalization). Per "
            f"guide §3.3.1 *Flags*, this requires manual id selection."
        )
    suffix_id, suffix_title = derive_connector_suffix(mapped_params)
    return (
        f"{vendor_id}-{suffix_id}",
        f"{_vendor_to_title(vendor)} {suffix_title}",
    )


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


def get_pack_categories(integration_path: Path) -> list[str]:
    """Extract the list of categories from the integration's pack metadata.

    Walks up 3 levels from the integration YML path to find the pack root,
    then reads ``pack_metadata.json``'s ``categories`` field. Returns an
    empty list if the file doesn't exist or the field is missing/invalid.

    Per guide §3.3, ``connector.yaml`` ``metadata.categories`` is the union
    of all relevant packs' ``categories`` (the connector schema requires at
    least one). Callers should flag an empty result for manual review.

    Args:
        integration_path: Path to the integration YML.

    Returns:
        List of category strings as declared in pack_metadata.json. Empty
        if not available.
    """
    pack_root = integration_path.parent.parent.parent
    metadata_path = pack_root / "pack_metadata.json"
    if not metadata_path.is_file():
        logger.warning(
            f"[manifest_generator] pack_metadata.json not found at {metadata_path}; "
            f"defaulting to empty categories list."
        )
        return []
    try:
        with open(metadata_path) as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.warning(
            f"[manifest_generator] Failed to parse {metadata_path}: {exc}; "
            f"defaulting to empty categories list."
        )
        return []
    categories = data.get("categories", [])
    if not isinstance(categories, list):
        logger.warning(
            f"[manifest_generator] pack_metadata.json 'categories' is not a list "
            f"at {metadata_path}; defaulting to empty categories list."
        )
        return []
    return categories


def get_supported_modules(
    integration_yml: dict, integration_path: Path
) -> list[str]:
    """Resolve the integration's supported license modules.

    Per guide §3.3 / §3.4 + §3.1 item 14: licenses come from the
    integration YML's ``supportedModules`` field; if absent, from the
    parent pack's ``pack_metadata.json`` ``supported_modules`` field. If
    neither is found, returns an empty list (caller flags for manual
    intervention — capabilities.schema permits an empty
    ``required_license`` but the migration guide wants an explicit set).

    The returned values are used verbatim as ``config.required_license``
    entries, so they must already match the capabilities.schema license
    enum. Any value not in the enum will fail validation downstream —
    callers/reviewers should reconcile non-conforming module names.

    Args:
        integration_yml: The loaded integration YML dict.
        integration_path: Path to the integration YML (used to locate the
            parent pack's pack_metadata.json fallback).

    Returns:
        List of license/module strings. Empty if none declared.
    """
    modules = integration_yml.get("supportedModules")
    if isinstance(modules, list) and modules:
        return list(modules)

    pack_root = integration_path.parent.parent.parent
    metadata_path = pack_root / "pack_metadata.json"
    if not metadata_path.is_file():
        logger.warning(
            f"[manifest_generator] No supportedModules on integration and no "
            f"pack_metadata.json at {metadata_path}; required_license will be "
            f"empty. Flag for manual intervention (guide §3.3)."
        )
        return []
    try:
        with open(metadata_path) as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.warning(
            f"[manifest_generator] Failed to parse {metadata_path}: {exc}; "
            f"required_license will be empty."
        )
        return []
    pack_modules = data.get("supported_modules", [])
    if not isinstance(pack_modules, list):
        logger.warning(
            f"[manifest_generator] pack_metadata.json 'supported_modules' is not "
            f"a list at {metadata_path}; required_license will be empty."
        )
        return []
    if not pack_modules:
        logger.warning(
            f"[manifest_generator] Neither integration supportedModules nor pack "
            f"supported_modules found for {integration_path}; required_license "
            f"will be empty. Flag for manual intervention (guide §3.3)."
        )
    return pack_modules


def get_pack_id(integration_path: Path) -> str:
    """Extract the pack id from the integration's filesystem path.

    Per AGENTS.md: every integration lives under
    ``Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.yml``.
    The pack id is the ``<PackName>`` segment — i.e. the parent of
    ``Integrations``. Used by :func:`build_handler_yaml` to populate
    ``triggering.labels.xsoar-pack-id`` per guide §3.8.

    Returns an empty string if the path is not in the expected structure
    (e.g., tmp_path fixtures in tests that don't simulate the full
    Packs/ tree). Callers can then fall back to the integration id per
    guide §4.6 reference.

    Args:
        integration_path: Path to the integration YML.

    Returns:
        The pack id (parent-of-parent-of-parent directory name) or
        empty string if not derivable.
    """
    try:
        # <pack_root>/Integrations/<IntegrationName>/<IntegrationName>.yml
        return integration_path.parent.parent.parent.name
    except (AttributeError, IndexError):
        return ""


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
    vendor: str = "",
    mapped_params: dict | None = None,
    categories: list[str] | None = None,
) -> dict:
    """Build the dict for a brand-new connector.yaml.

    Per-task spec and Section 3.3 of the migration guide:
      - publisher: "Palo Alto Networks" (hardcoded)
      - author_image: pass-through of ``author_image_filename`` (filename
        relative to the connector root; e.g. ``"salesforce.png"``). Defaults
        to empty string when no image is supplied.
      - ownership.team: "xsoar"
      - ownership.maintainers: ["@xsoar-content"]
      - version: "1.0.0"
      - settings.allow_skip_verification: True (per guide §3.3: "Always
        true unless the vendor explicitly requires successful verification")
      - metadata.domain: always "" (out of scope for grouped connectors).

    Vendor-driven fields (per user decision on review point 1):
      - ``vendor`` populates ``metadata.vendor`` verbatim.
      - ``metadata.description`` = ``"integration for <vendor> products."``.
      - ``id`` and ``metadata.title`` are derived via
        :func:`derive_connector_id_and_title` (vendor prefix + capability
        suffix) when both ``vendor`` and ``mapped_params`` are supplied.
        Otherwise they fall back to the legacy stub form (slug/title of
        ``connector_title``) so existing callers keep working.
      - ``metadata.categories`` is the caller-provided ``categories`` list
        (schema requires ≥1 entry — callers that cannot source any should
        flag for manual review; this builder leaves the list as-is).
    """
    # Derive id/title from the vendor + declared capabilities when we have
    # enough information; otherwise keep the legacy stub behaviour.
    if vendor and mapped_params:
        connector_id, metadata_title = derive_connector_id_and_title(
            vendor, mapped_params
        )
    else:
        connector_id, metadata_title = title_to_slug(connector_title), connector_title

    description = f"integration for {vendor} products." if vendor else ""

    return {
        "id": connector_id,
        "metadata": {
            "title": metadata_title,
            "description": description,
            "version": "1.0.0",
            "categories": list(categories or []),
            "tags": list(pack_tags),
            "domain": "",
            "vendor": vendor,
            "publisher": "Palo Alto Networks",
            "author_image": author_image_filename,
            "ownership": {
                "team": "xsoar",
                "maintainers": ["@xsoar-content"],
            },
        },
        "settings": {
            "allow_skip_verification": True,
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

    Per guide §3.8 + §4.6 Salesforce reference: format is
    ``"xsoar-" + integration_id.lower()`` with internal whitespace
    runs collapsed to single dashes. The previous behaviour
    (underscore separator + spaces removed) does not match the
    convention used by every reference connector in the spec.

    Examples:
        derive_handler_id("Salesforce") → "xsoar-salesforce"
        derive_handler_id("My Integration") → "xsoar-my-integration"
        derive_handler_id("CrowdStrike Falcon") → "xsoar-crowdstrike-falcon"
        derive_handler_id("EWS v2") → "xsoar-ews-v2"
    """
    # Lowercase + collapse internal whitespace runs to single dashes.
    slug = re.sub(r"\s+", "-", integration_id.strip().lower())
    return f"xsoar-{slug}"


# ---------------------------------------------------------------------------
# Canonical capability ids (per guide §3.4 + CO119 validator)
# ---------------------------------------------------------------------------
# The mapper (``connector_param_mapper.py``) emits ONE of six bucket keys
# for each non-general capability. The connectus spec REQUIRES the exact
# canonical id for each — and the CO119 IsCapabilityNameValid validator
# will reject anything else.
#
# Bucket key (from mapper) → canonical capability id (manifest).
#
# IMPORTANT: keys here must match the constants in
# ``connector_param_mapper.py``:
#   - AUTOMATION_CAPABILITY                 = "Automation"
#   - FETCH_ISSUES_CAPABILITIES             = "Fetch Issues"
#   - FETCH_EVENTS_CAPABILITIES             = "Log Collection"
#   - FETCH_SECRETS_CAPABILITIES            = "Fetch Secrets"
#   - FETCH_INDICATORS_CAPABILITIES         = "Threat Intelligence & Enrichment"
#   - FETCH_ASSETS_CAPABILITIES             = "Fetch Assets and Vulnerabilities"
CANONICAL_CAPABILITY_IDS: dict[str, str] = {
    "Automation": "automation-and-remediation",
    "Fetch Issues": "fetch-issues",
    "Log Collection": "log-collection",
    "Fetch Secrets": "fetch-secrets",
    "Threat Intelligence & Enrichment": "threat-intelligence-and-enrichment",
    "Fetch Assets and Vulnerabilities": "fetch-assets-and-vulnerabilities",
}

# Display titles for each canonical capability id. Used to populate the
# REQUIRED ``title`` field on every capability entry (capabilities.schema
# requires id + title + default_enabled + required).
CANONICAL_CAPABILITY_TITLES: dict[str, str] = {
    "automation-and-remediation": "Automation and Remediation",
    "fetch-issues": "Fetch Issues",
    "log-collection": "Log Collection",
    "fetch-secrets": "Fetch Secrets",
    "threat-intelligence-and-enrichment": "Threat Intelligence and Enrichment",
    "fetch-assets-and-vulnerabilities": "Fetch Assets and Vulnerabilities",
}

# Placeholder per-capability descriptions. capabilities.schema REQUIRES a
# non-empty ``description`` on every Capability (guide §3.4 marks these as
# "IN PROGRESS — Tech team / PM / tech-writer to write them up"). We emit a
# generic placeholder so the manifest validates; flag for tech-writer review.
CANONICAL_CAPABILITY_DESCRIPTIONS: dict[str, str] = {
    "automation-and-remediation": (
        "Run automation and remediation commands for this connector."
    ),
    "fetch-issues": "Fetch issues from this connector.",
    "log-collection": "Collect logs and events from this connector.",
    "fetch-secrets": "Fetch secrets and credentials from this connector.",
    "threat-intelligence-and-enrichment": (
        "Fetch threat intelligence indicators and enrich data from this connector."
    ),
    "fetch-assets-and-vulnerabilities": (
        "Fetch assets and vulnerabilities from this connector."
    ),
}

# Fetch capabilities that, per guide §3.4 note 6, must only be shown to
# customers holding an ``agentix`` or ``xsiam`` license. The connector's
# ``config.required_license`` for these capabilities is intersected with
# {agentix, xsiam}.
_LICENSE_RESTRICTED_FETCH_CAPS: frozenset[str] = frozenset(
    {"fetch-issues", "log-collection", "fetch-assets-and-vulnerabilities"}
)
_AGENTIX_XSIAM_LICENSES: tuple[str, ...] = ("agentix", "xsiam")

# ---------------------------------------------------------------------------
# Capability-scoped handler actions (per connectus handler.schema Action)
# ---------------------------------------------------------------------------
# Each capability family that supports a "reset last run" style UI action is
# mapped to its single Action descriptor. The Action shape is
# ``{type, display, description}`` where ``type`` is a member of the closed
# handler.schema enum:
#   reset_integration_context, reset_assets_last_run, reset_incidents_last_run,
#   reset_feed_last_run, reset_events_last_run
#
# ``reset_integration_context`` is intentionally NOT emitted here — it is a
# connector-specific rule (Microsoft Teams, across all capabilities) that is
# deferred until the generator gains connector-identity-aware action logic.
#
# Keyed by canonical capability id (the value side of
# ``CANONICAL_CAPABILITY_IDS``). Capability families without a reset action
# (``automation-and-remediation``, ``fetch-secrets``) are deliberately absent.
CAPABILITY_ACTIONS: dict[str, dict] = {
    "fetch-assets-and-vulnerabilities": {
        "type": "reset_assets_last_run",
        "display": "Reset Assets Last Run",
        "description": (
            "Clears the saved last-run cursor for asset and vulnerability "
            "collection, forcing the next fetch to start from the beginning."
        ),
    },
    "fetch-issues": {
        "type": "reset_incidents_last_run",
        "display": "Reset Incidents Last Run",
        "description": (
            "Clears the saved last-run cursor for issue/incident collection, "
            "forcing the next fetch to start from the beginning."
        ),
    },
    "threat-intelligence-and-enrichment": {
        "type": "reset_feed_last_run",
        "display": "Reset Feed Last Run",
        "description": (
            "Clears the saved last-run cursor for threat intelligence feed "
            "collection, forcing the next fetch to start from the beginning."
        ),
    },
    "log-collection": {
        "type": "reset_events_last_run",
        "display": "Reset Events Last Run",
        "description": (
            "Clears the saved last-run cursor for log/event collection, "
            "forcing the next fetch to start from the beginning."
        ),
    },
}


def slugify_capability_name(name: str) -> str:
    """Convert a mapper bucket key to its canonical capability id.

    The mapper (``connector_param_mapper.py``) emits one of six bucket
    keys; the manifest requires the exact canonical id per guide §3.4.
    This mapping is hardcoded (NOT a generic slugifier) because the
    canonical ids include literal ``and`` segments (e.g.
    ``automation-and-remediation``, ``threat-intelligence-and-enrichment``)
    that a regex-based slugifier would drop.

    Raises:
        ValueError: if ``name`` is not one of the six known bucket keys.
            Callers (e.g. the entry-point flows) should fail loudly rather
            than silently emit a non-canonical id that will fail CO119.

    Examples:
        slugify_capability_name("Automation")
            → "automation-and-remediation"
        slugify_capability_name("Fetch Issues") → "fetch-issues"
        slugify_capability_name("Threat Intelligence & Enrichment")
            → "threat-intelligence-and-enrichment"
    """
    canonical = CANONICAL_CAPABILITY_IDS.get(name)
    if canonical is None:
        raise ValueError(
            f"Unknown capability bucket key '{name}'. "
            f"Expected one of: {sorted(CANONICAL_CAPABILITY_IDS.keys())}. "
            f"This usually means the upstream mapper emitted a bucket key "
            f"that the manifest generator does not recognise — add the "
            f"mapping in CANONICAL_CAPABILITY_IDS if a new capability has "
            f"been introduced."
        )
    return canonical


# Per guide §3.8 + §4.6 (Salesforce reference). The default backend
# workload every XSOAR handler runs in.
DEFAULT_HANDLER_WORKLOADS: list[str] = ["xsoar-pod"]


def make_sub_capability_id(handler_id: str, cap_name: str) -> str:
    """Compute the sub-capability id for a (handler, capability-family) pair.

    Format is ``"<handler_id>-<cap_slug>"`` where ``cap_slug`` is the
    canonical capability id (:func:`slugify_capability_name`). This is the
    single source of truth for sub-cap id derivation, used by both the
    from-scratch path and the append path so a connector is *always* modelled
    as parent-capability + sub-capability (never a flat top-level capability).
    """
    return f"{handler_id}-{slugify_capability_name(cap_name)}"


def build_sub_capability_entry(
    sub_cap_id: str, cap_name: str, required: bool = False
) -> dict:
    """Build a schema-complete ``SubCapability`` entry.

    capabilities.schema requires ``id`` + ``title`` + ``default_enabled`` +
    ``required`` on every sub-capability. The title reuses the canonical
    capability family title.

    Per guide §3.4: ``default_enabled`` is **always False** on a
    sub-capability (the user opts in explicitly). Per guide §3.1 item 13:
    when a capability has exactly ONE sub-capability it must be marked
    ``required: true`` (so selecting the parent implies the lone sub-cap);
    callers pass ``required=True`` in that case.
    """
    cap_slug = slugify_capability_name(cap_name)
    return {
        "id": sub_cap_id,
        "title": CANONICAL_CAPABILITY_TITLES[cap_slug],
        "default_enabled": False,
        "required": required,
    }


def _actions_for_capability(cap_name: str) -> list[dict]:
    """Return the handler ``actions[]`` list for a mapper capability bucket key.

    ``cap_name`` is one of the six mapper bucket keys (e.g. ``"Fetch Issues"``).
    It is resolved through :func:`slugify_capability_name` to its canonical
    capability id and then looked up in :data:`CAPABILITY_ACTIONS`.

    Keying off the bucket key (rather than the possibly-decorated handler cap
    id) means this works identically on the from-scratch path (bare canonical
    slug) and the append path (sub-cap id ``<handler_id>-<cap_slug>``) — the
    capability family is the same in both cases.

    Returns a fresh one-element list when the capability family defines a reset
    action, else an empty list (callers omit the ``actions`` key entirely so
    action-free capabilities stay byte-identical to the pre-actions output).
    """
    canonical = slugify_capability_name(cap_name)
    action = CAPABILITY_ACTIONS.get(canonical)
    return [dict(action)] if action else []


def build_handler_yaml(
    integration_yml: dict,
    connector_title: str,
    pack_tags: list[str],
    mapped_params: dict[str, Any],
    auth_methods: dict[str, Any],
    cap_name_to_handler_cap_id: dict[str, str] | None = None,
    pack_id: str = "",
) -> dict:
    """Build the dict for a brand-new handler.yaml.

    Reads from the integration YML:
      - ``commonfields.id`` for the handler id (transformed via
        :func:`derive_handler_id` → ``xsoar-<integration-id>`` form)
      - ``display`` for the description template

    Builds the ``capabilities`` list from ``mapped_params`` (excluding the
    ``general_configurations`` key). Each capability uses one of the two
    shapes defined by handler.schema:

      - **Authenticated shape** (when ``auth_methods.auth_types`` is
        non-empty): ``{id, auth_options: [{id, scopes, workloads}]}``
        where ``workloads`` lives on each auth_option (per AuthOption
        schema). NO capability-level ``workloads``.

      - **Anonymous shape** (when ``auth_methods.auth_types`` is empty):
        ``{id, auth: "none", workloads: ["xsoar-pod"]}``. NO
        ``auth_options``. Required by the schema's oneOf — empty
        ``auth_options: []`` would fail ``minItems: 1``.

    By default the cap ``id`` is the canonical slug
    (:func:`slugify_capability_name`). When ``cap_name_to_handler_cap_id``
    is provided it acts as an override mapping (used by the append path
    to reference sub-cap ids).

    All other fields per guide §3.8 + §4.6 Salesforce reference:
      - ``module: "xsoar"``
      - ``ownership.team: "xsoar"`` + ``maintainers: ["@xsoar-content"]``
        (matches CO114 / CO123 expectations).
      - ``enabled: True``
      - ``triggering.type: "PUB_SUB"``, with two labels:
        ``xsoar-integration-id`` (the raw integration id) and
        ``xsoar-pack-id`` (pack id from caller; falls back to the
        integration id when omitted, matching the Salesforce reference).
      - ``test_connection``: ``type: service``, ``service: xsoar``,
        ``endpoint: /settings/integration/connector/verification`` per
        guide §3.8. Every XSOAR handler routes its verification through
        the platform's standard service endpoint.
    """
    integration_id = integration_yml.get("commonfields", {}).get("id", "")
    integration_display = integration_yml.get("display", "")
    handler_id = derive_handler_id(integration_id)

    # Build auth_options per the AuthOption schema (workloads required).
    #
    # CRITICAL handler↔connection linkage (design §3): each auth_option's
    # ``id`` MUST equal the connection.yaml profile id produced by
    # :func:`derive_profile_id` (same integration_id + same seen-set ordering
    # as :func:`build_connection_yaml`), and — for the grouped model — each
    # option carries ``view_group`` = the integration's tile id
    # (:func:`slugify_view_group_id`). The connection page is
    # handler-authoritative for tiles.
    # ``id`` is the connection profile id produced by
    # :func:`derive_profile_id` so handler and connection.yaml stay in
    # lockstep (the same seen-set ordering as :func:`build_connection_yaml`).
    # ``derive_profile_id`` is tolerant of legacy name-only entries (no
    # ``type``) and only raises on a present-but-unrecognized ``type``.
    auth_types = auth_methods.get("auth_types", [])
    handler_view_group = slugify_view_group_id(integration_id)
    seen_profile_ids: set[str] = set()
    auth_options = [
        {
            "id": derive_profile_id(at, integration_id, seen_profile_ids),
            "view_group": handler_view_group,
            "scopes": ["api"],
            "workloads": list(DEFAULT_HANDLER_WORKLOADS),
        }
        for at in auth_types
    ]
    has_auth = len(auth_options) > 0

    cap_id_overrides = cap_name_to_handler_cap_id or {}

    # Build capabilities list — skip "general_configurations" key.
    capabilities = []
    for cap_name in mapped_params:
        if cap_name == "general_configurations":
            continue
        # Capabilities are ALWAYS modelled as sub-capabilities. When the
        # caller supplies an override (append path), use it; otherwise
        # (from-scratch path) default to this handler's own sub-cap id
        # ``<handler_id>-<cap_slug>`` so the handler references the sub-cap
        # entry that capabilities.yaml/configurations.yaml emit.
        cap_id = cap_id_overrides.get(cap_name) or make_sub_capability_id(
            handler_id, cap_name
        )
        if has_auth:
            # Authenticated shape: auth_options carries workloads.
            cap_entry: dict = {
                "id": cap_id,
                "auth_options": [dict(opt) for opt in auth_options],
            }
        else:
            # Anonymous shape: no auth_options, capability-level
            # workloads + auth='none' discriminator.
            cap_entry = {
                "id": cap_id,
                "auth": "none",
                "workloads": list(DEFAULT_HANDLER_WORKLOADS),
            }
        # Attach capability-scoped UI actions (e.g. reset_*_last_run) when the
        # capability family defines one. The key is omitted entirely for
        # action-free families so their output is unchanged.
        actions = _actions_for_capability(cap_name)
        if actions:
            cap_entry["actions"] = actions
        capabilities.append(cap_entry)

    # triggering.labels: per Salesforce §4.6 reference. ``xsoar-pack-id``
    # defaults to the integration id when caller omits it (matches the
    # reference's behavior of using identical values for both labels).
    effective_pack_id = pack_id or integration_id

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
                "xsoar-integration-id": integration_id,
                "xsoar-pack-id": effective_pack_id,
            },
            "args": {},
        },
        "capabilities": capabilities,
        "test_connection": {
            "type": "service",
            "service": "xsoar",
            "endpoint": "/settings/integration/connector/verification",
        },
    }


HANDLER_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../../../../schema/handler.schema.json\n"
)

# Schema directives for the connector-root files (one ``../`` per directory
# level from the file to the repo-root ``schema/`` dir). connector.yaml and
# summary.yaml both live at ``connectors/<vendor>/`` → two levels up.
CONNECTOR_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/connector.schema.json\n"
)
SUMMARY_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/summary.schema.json\n"
)


class _NoAliasDumper(yaml.SafeDumper):
    """A SafeDumper that never emits YAML anchors/aliases (``&id001`` /
    ``*id001``).

    The default ``yaml.safe_dump`` deduplicates repeated object references
    (e.g. the shared ``scopes``/``workloads`` lists reused across handler
    capabilities) into anchors + aliases. That is valid YAML but brittle
    and hard to hand-review in a generated manifest, so we force every
    occurrence to be written out in full.
    """

    def ignore_aliases(self, data: Any) -> bool:  # noqa: D401 - simple override
        return True


def _dump_yaml(data: Any, fh: Any) -> None:
    """Dump ``data`` to ``fh`` with the no-alias dumper and stable key sort.

    Single choke-point so every manifest file is serialized identically
    (no anchors/aliases) — keeps output deterministic and review-friendly.
    """
    yaml.dump(data, fh, Dumper=_NoAliasDumper, default_flow_style=False)


def write_handler_yaml(handler_yaml_path: Path, handler_data: dict) -> None:
    """Write a handler.yaml file with the schema directive line prepended.

    The schema directive is a yaml-language-server VS Code hint and should
    appear as the first line of the file, before any YAML content. The
    body is serialized with :class:`_NoAliasDumper` so repeated list
    references (shared ``scopes``/``workloads``) are written out in full
    rather than collapsed into ``&id001`` / ``*id001`` anchors.
    """
    handler_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(handler_yaml_path, "w") as fh:
        fh.write(HANDLER_SCHEMA_DIRECTIVE)
        _dump_yaml(handler_data, fh)


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

      - **Platform-hidden filter** (per guide §3.1 *Assumptions #4*): if
        the underlying yml param declares ``hidden: [platform]`` (the
        marketplace-keyed form indicating the param is hidden on the
        Platform marketplace), this function returns an EMPTY list. The
        param is excluded from the manifest entirely. Callers must
        handle empty results by skipping the field emission.
      - If ``yml_params_by_name`` is missing or doesn't contain ``name``,
        log a warning and fall back to the bare-id shape ``{"id": name}``
        (with dedup-rename applied when requested). This bare-id path
        cannot apply the platform-hidden filter (no yml metadata to
        check) — so any platform-hidden filtering MUST happen via the
        rich path.
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

    yml_param = yml_params_by_name[name]

    # Platform-hidden filter (guide §3.1 *Assumptions #4*): skip params
    # XSOAR marks as hidden on the Platform marketplace. Per
    # :func:`_is_hidden_on_platform`, BOTH ``hidden: true`` (boolean form
    # = hidden in every marketplace including platform) AND
    # ``hidden: [..., "platform", ...]`` (marketplace-keyed form) qualify.
    # This keeps us in lockstep with the mapper's
    # ``_collect_hidden_params`` which uses the same rule to drop these
    # params from capability routing.
    if _is_hidden_on_platform(yml_param):
        logger.info(
            f"[manifest_generator] Skipping param '{name}' (handler='{handler_id}'): "
            f"marked hidden on platform marketplace per guide §3.1 #4."
        )
        return []

    # Rich path: materialize via the type-aware dispatcher.
    raw_fields = map_xsoar_param_to_connectus_field(yml_param)

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
    open-coded everywhere. The ``dedup_field_id_and_register`` and
    ``add_secret_capability`` sub-cap paths all need this.
    """
    register_serializer_entry(
        handler_dir, new_id=renamed_id, original_id=original_id
    )


# NOTE: adjust_checkbox_trigger was removed per user decision — triggers
# emission is deferred. The three capability builders (add_secret_capability,
# add_log_collection_capability, add_assets_capability) no longer call it.


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
        default_value=True,
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
            default_value=True,
            required=False,
        )
    field = _map_type_8(yml_param)
    field["id"] = field_id
    field["title"] = title
    return field


# ---------------------------------------------------------------------------
# Duration field type (per plans/duration-field-type.md)
# ---------------------------------------------------------------------------
# Fetch-interval fields render as a multi-unit ``duration`` picker rather
# than a bare numeric input. The author declares which unit boxes render
# via ``options.units`` (ordered, render left-to-right) and an optional
# per-unit ``options.default_value`` object (omitted units default to 0).
#
# XSOAR expresses fetch-interval defaults as a single integer count of
# MINUTES (e.g. ``"1"``, ``"720"``, ``"1440"``). We render days / hours /
# minutes boxes and decompose the minute count across them.
_MINUTES_PER_HOUR = 60
_MINUTES_PER_DAY = 24 * _MINUTES_PER_HOUR

# Render order of the duration boxes (left-to-right). Closed enum per the
# field-options schema (``days|hours|minutes|seconds``); seconds is not
# meaningful for minute-granularity fetch intervals so it is not rendered.
DURATION_UNITS: list[str] = ["days", "hours", "minutes"]


def _minutes_to_duration_default(total_minutes: int) -> dict[str, int]:
    """Decompose a minute count into a ``duration`` per-unit default object.

    The XSOAR fetch-interval default is a single integer in MINUTES. This
    helper splits it across the rendered duration boxes (days / hours /
    minutes), emitting ONLY the non-zero units (omitted units default to
    ``0`` per the duration field contract — guide
    ``plans/duration-field-type.md`` §2).

    A non-positive count (``0`` or negative — a meaningless interval) is
    coerced to the minimum sensible value of **1 minute**, matching the
    "no default → 1 minute" rule applied by the callers.

    Examples:
        _minutes_to_duration_default(5)    → {"minutes": 5}
        _minutes_to_duration_default(60)   → {"hours": 1}
        _minutes_to_duration_default(720)  → {"hours": 12}
        _minutes_to_duration_default(1440) → {"days": 1}
        _minutes_to_duration_default(1500) → {"days": 1, "hours": 1}
        _minutes_to_duration_default(0)    → {"minutes": 1}
    """
    if total_minutes <= 0:
        return {"minutes": 1}

    days, remainder = divmod(total_minutes, _MINUTES_PER_DAY)
    hours, minutes = divmod(remainder, _MINUTES_PER_HOUR)

    default: dict[str, int] = {}
    if days:
        default["days"] = days
    if hours:
        default["hours"] = hours
    if minutes:
        default["minutes"] = minutes
    return default


def _coerce_interval_minutes(raw: Any) -> int | None:
    """Parse a raw XSOAR ``defaultvalue`` into an integer minute count.

    Returns ``None`` when the value is missing or cannot be parsed as an
    integer (so callers fall back to the "1 minute" rule). XSOAR stores
    the value as a string like ``"720"``, but tolerate ints/floats too.
    """
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _build_numeric_fetch_interval_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
    fallback_default: str,
) -> dict:
    """Generic "fetch interval" field builder → connectus ``duration``.

    Shape (per ``plans/duration-field-type.md``): a connectus
    ``duration`` field with ``options.units`` = :data:`DURATION_UNITS`
    (days / hours / minutes boxes) and ``options.default_value`` as a
    per-unit object.

    Default-value handling — the XSOAR ``defaultvalue`` is an integer
    count of MINUTES which we convert to the duration object via
    :func:`_minutes_to_duration_default`:
      - If ``yml_param`` carries a parseable ``defaultvalue``, convert
        that minute count (e.g. ``"60"`` → ``{"hours": 1}``).
      - Otherwise (no yml param, or yml param without a usable
        ``defaultvalue``), default to **1 minute** (``{"minutes": 1}``).
        ``fallback_default`` is the minute count (as a string, e.g.
        ``"1"`` for events / ``"720"`` for assets) used when the param
        is entirely synthetic (no yml).

    Visibility / requiredness:
      - If ``yml_param`` is provided, honor its ``hidden`` and
        ``required`` keys via :func:`_apply_common_field_metadata`.
      - If no yml_param, default to visible + optional.

    Reused by :func:`_build_eventfetchinterval_field` (fallback ``"1"``)
    and :func:`_build_assetsfetchinterval_field` (fallback ``"720"``).
    """
    if yml_param is None:
        minutes = _coerce_interval_minutes(fallback_default)
        default_value = _minutes_to_duration_default(
            minutes if minutes is not None else 1
        )
        return {
            "id": field_id,
            "title": title,
            "field_type": "duration",
            "options": {
                "units": list(DURATION_UNITS),
                "default_value": default_value,
                "create_modifiers": {"required": False, "hidden": False},
                "edit_modifiers": {"required": False, "hidden": False},
            },
        }

    # yml-driven path: reuse _map_type_19 only to honor hidden/required
    # metadata, then convert it into a duration field.
    field = _map_type_19(yml_param)
    field["id"] = field_id
    field["title"] = title
    field["field_type"] = "duration"

    options = field.setdefault("options", {})
    # _map_type_19 emits the numeric-input flag; the duration field does
    # not use it.
    options.pop("is_number_input", None)
    options["units"] = list(DURATION_UNITS)

    # Convert the yml minute count (if any) into a per-unit object; when
    # absent or unparseable, fall back to 1 minute.
    minutes = _coerce_interval_minutes(yml_param.get("defaultvalue"))
    options["default_value"] = _minutes_to_duration_default(
        minutes if minutes is not None else 1
    )
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
    (``duration`` picker, visible by default, default 1 minute when no
    yml default; a yml ``defaultvalue`` in minutes is converted into a
    per-unit object — see :func:`_build_numeric_fetch_interval_field`).

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
      3. (Trigger emission deferred — ``adjust_checkbox_trigger`` removed.)

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
    ``assetsFetchInterval`` (``duration`` picker, visible by default,
    falling back to 12 hours = 720 minutes when no yml default; a yml
    ``defaultvalue`` in minutes is converted into a per-unit object —
    see :func:`_build_numeric_fetch_interval_field`).

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
      | assetsFetchInterval  | yes            | duration field; yml defaultvalue (minutes)        |
      |                      |                | converted to a per-unit object. No defaultvalue   |
      |                      |                | → 1 minute ({minutes: 1}).                         |
      | assetsFetchInterval  | no             | synthetic visible duration, fallback 12h (720 min)|

    Side effects:
      1. Strips both ``isFetchAssets`` AND ``assetsFetchInterval`` from
         every bucket of ``mapped_params`` in place so the standard
         param-mapping pass doesn't re-emit them.
      2. Sub-cap rename bridges (per emitted field whose id was
         renamed) via :func:`register_renamed_field_serializer_entry`.
      3. (Trigger emission deferred — ``adjust_checkbox_trigger`` removed.)

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
        default_value=True,
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

    return {
        "capability_id": capability_id,
        "fields": fields,
    }


# ------------------------------------------------------------------ #
# Threat Intelligence & Enrichment capability builder
# ------------------------------------------------------------------ #

# Default human-readable titles for the synthetic / fallback emission
# paths in ``add_indicators_capability``.
_FEED_DEFAULT_TITLE = "Fetch indicators"
_FEEDFETCHINTERVAL_DEFAULT_TITLE = "Feed Fetch Interval"
_FEEDRELIABILITY_DEFAULT_TITLE = "Source Reliability"
_FEEDEXPIRATIONPOLICY_DEFAULT_TITLE = ""  # module.go does not set a display
_FEEDEXPIRATIONINTERVAL_DEFAULT_TITLE = ""  # no display name per spec
_FEEDREPUTATION_DEFAULT_TITLE = "Indicator Verdict"
_FEEDBYPASSEXCLUSIONLIST_DEFAULT_TITLE = "Bypass exclusion list"

# Fallback default for feedFetchInterval when the yml doesn't carry the
# param. DefaultFeedFetchTime = 4 * time.Hour = 240 minutes (module.go).
FEEDFETCHINTERVAL_FALLBACK_DEFAULT = "240"  # string per XSOAR convention

# The original XSOAR yml param names for the feed capability params.
# Stripped from mapper results by ``add_indicators_capability`` so we
# don't emit them twice.
FEED_PARAM_NAME = "feed"
FEEDRELIABILITY_PARAM_NAME = "feedReliability"
FEEDEXPIRATIONPOLICY_PARAM_NAME = "feedExpirationPolicy"
FEEDEXPIRATIONINTERVAL_PARAM_NAME = "feedExpirationInterval"
FEEDREPUTATION_PARAM_NAME = "feedReputation"
FEEDBYPASSEXCLUSIONLIST_PARAM_NAME = "feedBypassExclusionList"
FEEDFETCHINTERVAL_PARAM_NAME = "feedFetchInterval"

# All feed param names that are stripped from mapped_params by the builder.
_FEED_STRIPPED_PARAMS: frozenset[str] = frozenset(
    {
        FEED_PARAM_NAME,
        FEEDRELIABILITY_PARAM_NAME,
        FEEDEXPIRATIONPOLICY_PARAM_NAME,
        FEEDEXPIRATIONINTERVAL_PARAM_NAME,
        FEEDREPUTATION_PARAM_NAME,
        FEEDBYPASSEXCLUSIONLIST_PARAM_NAME,
        FEEDFETCHINTERVAL_PARAM_NAME,
    }
)

# ---------------------------------------------------------------------------
# Fallback option values + defaults sourced from module.go / feedIndicator.go
# ---------------------------------------------------------------------------
# Public feed reliabilities (sorted alphabetically, matching
# GetAllPublicFeedReliabilities() in feedIndicator.go).
FEED_RELIABILITY_OPTIONS: list[dict] = [
    {"key": "A - Completely reliable", "label": "A - Completely reliable"},
    {"key": "B - Usually reliable", "label": "B - Usually reliable"},
    {"key": "C - Fairly reliable", "label": "C - Fairly reliable"},
    {"key": "D - Not usually reliable", "label": "D - Not usually reliable"},
    {"key": "E - Unreliable", "label": "E - Unreliable"},
    {"key": "F - Reliability cannot be judged", "label": "F - Reliability cannot be judged"},
]
FEED_RELIABILITY_DEFAULT = "F - Reliability cannot be judged"
FEED_RELIABILITY_ADDITIONAL_INFO = (
    "Reliability of the source providing the intelligence data"
)

# feedBypassExclusionList additionalinfo (module.go line 411).
FEED_BYPASS_EXCLUSION_ADDITIONAL_INFO = (
    "When selected, the exclusion list is ignored for indicators from "
    "this feed. This means that if an indicator from this feed is on the "
    "exclusion list, the indicator might still be added to the system."
)

# feedReputation default (module.go: ReputationNotSet = "").
FEED_REPUTATION_DEFAULT = ""

# feedReputation additionalinfo (module.go line 692).
FEED_REPUTATION_ADDITIONAL_INFO = (
    "Indicators from this integration instance will be marked with this verdict"
)

# feedExpirationPolicy default (expiration.go: ExpirationPolicyByIndicatorType).
FEED_EXPIRATION_POLICY_DEFAULT = "indicatorType"

# feedExpirationInterval default (module.go line 710: "20160" = 2 weeks).
FEED_EXPIRATION_INTERVAL_DEFAULT = "20160"


# ---------------------------------------------------------------------------
# Per-field builders for the indicators capability
# ---------------------------------------------------------------------------


def _build_feed_toggle_field(
    field_id: str,
    title: str,
) -> dict:
    """Build the ``feed`` checkbox field — always default ``True``, hidden.

    Per spec: the ``feed`` param is always emitted as a hidden checkbox
    with ``default_value: true``. The yml's hidden/default values are
    IGNORED — this is a hardcoded synthetic field.
    """
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "options": {
            "default_value": True,
            "create_modifiers": {"required": False, "hidden": True},
            "edit_modifiers": {"required": False, "hidden": True},
        },
    }


def _build_feedfetchinterval_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Thin wrapper over :func:`_build_numeric_fetch_interval_field`
    bound to the indicators capability's ``"240"`` fallback default
    (DefaultFeedFetchTime = 4 hours = 240 minutes).
    """
    return _build_numeric_fetch_interval_field(
        yml_param=yml_param,
        field_id=field_id,
        title=title,
        fallback_default=FEEDFETCHINTERVAL_FALLBACK_DEFAULT,
    )


def _build_feedreliability_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``feedReliability`` select field.

    When ``yml_param`` is provided, honor its ``hidden``, ``required``,
    ``defaultvalue``, ``additionalinfo``, and ``options`` (if any).
    When absent, fall back to the module.go defaults:
      - options = public feed reliabilities (A through F)
      - default = "F - Reliability cannot be judged"
      - required = True
      - additionalinfo = reliability description
    """
    if yml_param is not None:
        # yml-driven path: delegate to _map_type_15 for the select shape,
        # then overlay our fallback defaults for missing keys.
        field = _map_type_15(yml_param)
        field["id"] = field_id
        field["title"] = title
        options = field.setdefault("options", {})
        # If yml didn't carry options, inject the platform defaults.
        if not options.get("values"):
            options["values"] = list(FEED_RELIABILITY_OPTIONS)
        if "default_value" not in options:
            options["default_value"] = FEED_RELIABILITY_DEFAULT
        if "description" not in options:
            options["description"] = FEED_RELIABILITY_ADDITIONAL_INFO
        # feedReliability is required by default per module.go.
        if not yml_param.get("required"):
            # Only override if yml didn't explicitly set required.
            for mod_key in ("create_modifiers", "edit_modifiers"):
                mod = options.get(mod_key, {})
                mod["required"] = True
                options[mod_key] = mod
        return field

    # Synthetic fallback path.
    return {
        "id": field_id,
        "title": title,
        "field_type": "select",
        "options": {
            "values": list(FEED_RELIABILITY_OPTIONS),
            "default_value": FEED_RELIABILITY_DEFAULT,
            "description": FEED_RELIABILITY_ADDITIONAL_INFO,
            "create_modifiers": {"required": True, "hidden": False},
            "edit_modifiers": {"required": True, "hidden": False},
        },
    }


def _build_feedexpirationpolicy_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``feedExpirationPolicy`` select field (type 17).

    When ``yml_param`` is provided, delegate to :func:`_map_type_17`
    (hardcoded platform values). When absent, build a synthetic select
    with the same hardcoded values and the module.go default
    ``"indicatorType"``.
    """
    if yml_param is not None:
        field = _map_type_17(yml_param)
        field["id"] = field_id
        if title:
            field["title"] = title
        options = field.setdefault("options", {})
        if "default_value" not in options:
            options["default_value"] = FEED_EXPIRATION_POLICY_DEFAULT
        return field

    # Synthetic fallback path.
    result: dict = {
        "id": field_id,
        "field_type": "select",
        "options": {
            "values": list(FEED_EXPIRATION_POLICY_VALUES),
            "default_value": FEED_EXPIRATION_POLICY_DEFAULT,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }
    if title:
        result["title"] = title
    return result


def _build_feedexpirationinterval_field(
    yml_param: dict | None,
    field_id: str,
) -> dict:
    """Build the ``feedExpirationInterval`` numeric input field.

    Per spec: **no display name** (title omitted or empty), **hidden by
    default** (revealed via a trigger when ``feedExpirationPolicy ==
    interval``). Default ``"20160"`` (2 weeks in minutes) from module.go.

    When ``yml_param`` is provided, honor its ``defaultvalue`` and
    ``additionalinfo`` but force hidden=True regardless.
    """
    if yml_param is not None:
        field = _map_type_19(yml_param)
        field["id"] = field_id
        # No display name per spec.
        field.pop("title", None)
        options = field.setdefault("options", {})
        if "default_value" not in options:
            options["default_value"] = FEED_EXPIRATION_INTERVAL_DEFAULT
        # Force hidden — the trigger reveals it.
        for mod_key in ("create_modifiers", "edit_modifiers"):
            mod = options.setdefault(mod_key, {})
            mod["hidden"] = True
        return field

    # Synthetic fallback path.
    return {
        "id": field_id,
        "field_type": "input",
        "options": {
            "is_number_input": True,
            "default_value": FEED_EXPIRATION_INTERVAL_DEFAULT,
            "create_modifiers": {"required": False, "hidden": True},
            "edit_modifiers": {"required": False, "hidden": True},
        },
    }


def _build_feedreputation_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``feedReputation`` select field (type 18).

    When ``yml_param`` is provided, delegate to :func:`_map_type_18`
    (hardcoded platform values). When absent, build a synthetic select
    with the same hardcoded values and the module.go default ``""``
    (ReputationNotSet).
    """
    if yml_param is not None:
        field = _map_type_18(yml_param)
        field["id"] = field_id
        field["title"] = title
        options = field.setdefault("options", {})
        if "default_value" not in options:
            options["default_value"] = FEED_REPUTATION_DEFAULT
        if "description" not in options:
            options["description"] = FEED_REPUTATION_ADDITIONAL_INFO
        return field

    # Synthetic fallback path.
    return {
        "id": field_id,
        "title": title,
        "field_type": "select",
        "options": {
            "values": list(INDICATOR_REPUTATION_VALUES),
            "default_value": FEED_REPUTATION_DEFAULT,
            "description": FEED_REPUTATION_ADDITIONAL_INFO,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def _build_feedbypassexclusionlist_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``feedBypassExclusionList`` checkbox field.

    When ``yml_param`` is provided, delegate to :func:`_map_type_8`.
    When absent, build a synthetic checkbox with the module.go
    additionalinfo text and no default.
    """
    if yml_param is not None:
        field = _map_type_8(yml_param)
        field["id"] = field_id
        field["title"] = title
        options = field.setdefault("options", {})
        if "description" not in options:
            options["description"] = FEED_BYPASS_EXCLUSION_ADDITIONAL_INFO
        return field

    # Synthetic fallback path.
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "options": {
            "description": FEED_BYPASS_EXCLUSION_ADDITIONAL_INFO,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


# ---------------------------------------------------------------------------
# Trigger builder for feedExpirationInterval reveal
# ---------------------------------------------------------------------------


def _build_feed_expiration_interval_trigger(
    expiration_policy_field_id: str,
    expiration_interval_field_id: str,
) -> dict:
    """Build the trigger that reveals ``feedExpirationInterval`` when
    ``feedExpirationPolicy == 'interval'``.

    Per the user-provided format and the triggers.yaml schema:

    .. code-block:: yaml

        - conditions:
              id: feedExpirationPolicy
              behavior: value
              operator: eq
              value: 'interval'
          effects:
            - id: feedExpirationInterval
              action:
                hidden: false

    Both field ids are passed in so the sub-cap path can use the renamed
    ids (e.g. ``<capability_id>_feedExpirationPolicy``).
    """
    return {
        "conditions": {
            "id": expiration_policy_field_id,
            "behavior": "value",
            "operator": "eq",
            "value": "interval",
        },
        "effects": [
            {
                "id": expiration_interval_field_id,
                "action": {
                    "hidden": False,
                },
            },
        ],
    }


def add_indicators_capability(
    *,
    capability_id: str,
    is_sub_capability: bool,
    mapped_params: dict[str, list[str]],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_dir: Path | None = None,
) -> dict:
    """Build the per-capability template dict for the ``Threat Intelligence
    & Enrichment`` capability with up to 7 fields:

      1. ``feed`` — checkbox, always default true + hidden true
      2. ``feedFetchInterval`` — duration picker (fallback 240 min = 4h)
      3. ``feedReliability`` — select (required, fallback Undetermined)
      4. ``feedExpirationPolicy`` — select (type 17 hardcoded values)
      5. ``feedExpirationInterval`` — numeric input (hidden, no display,
         revealed via trigger when feedExpirationPolicy == interval)
      6. ``feedReputation`` — select (type 18 hardcoded values)
      7. ``feedBypassExclusionList`` — checkbox

    Caller contract (mirrors the other ``add_<capability>_capability``
    builders):
      - ``capability_id``: connector-side capability id. Pass
        ``"threat-intelligence-and-enrichment"`` for the top-level case
        or a sub-cap id for the sub-cap case.
      - ``is_sub_capability``: flips the field-id naming (each emitted
        field's id becomes ``f"{capability_id}_{original_name}"``).

    **Note on ``tlp_color`` and ``feedTags``**: these are NOT handled by
    this builder. They are left in ``mapped_params`` for the standard
    :func:`emit_field_for_param` / :func:`build_configurations_yaml`
    path, which only emits them if they are explicitly present in the
    integration yml.

    Side effects:
      1. Strips all 7 feed param names from every bucket of
         ``mapped_params`` in place so the standard param-mapping pass
         doesn't re-emit them.
      2. Sub-cap rename bridges (per emitted field whose id was renamed)
         via :func:`register_renamed_field_serializer_entry`.

    Returns:
      A dict shaped::

          {
              "capability_id": <capability_id>,
              "fields": [<emitted_fields>],
              "triggers": [<trigger_dicts>],
          }

      The ``triggers`` list contains 0 or 1 entries (the
      feedExpirationInterval reveal trigger). The caller collects
      triggers from all builders and writes them to ``triggers.yaml``.
    """
    # --- §1. Resolve the connector-side field ids (sub-cap rename) ------
    def _field_id(original: str) -> str:
        return f"{capability_id}_{original}" if is_sub_capability else original

    feed_field_id = _field_id(FEED_PARAM_NAME)
    ffi_field_id = _field_id(FEEDFETCHINTERVAL_PARAM_NAME)
    fr_field_id = _field_id(FEEDRELIABILITY_PARAM_NAME)
    fep_field_id = _field_id(FEEDEXPIRATIONPOLICY_PARAM_NAME)
    fei_field_id = _field_id(FEEDEXPIRATIONINTERVAL_PARAM_NAME)
    frep_field_id = _field_id(FEEDREPUTATION_PARAM_NAME)
    fbe_field_id = _field_id(FEEDBYPASSEXCLUSIONLIST_PARAM_NAME)

    # --- §2. Resolve titles (generic helper) ----------------------------
    feed_title = _resolve_title_from_yml(
        yml_params_by_name, FEED_PARAM_NAME, fallback=_FEED_DEFAULT_TITLE
    )
    ffi_title = _resolve_title_from_yml(
        yml_params_by_name, FEEDFETCHINTERVAL_PARAM_NAME,
        fallback=_FEEDFETCHINTERVAL_DEFAULT_TITLE,
    )
    fr_title = _resolve_title_from_yml(
        yml_params_by_name, FEEDRELIABILITY_PARAM_NAME,
        fallback=_FEEDRELIABILITY_DEFAULT_TITLE,
    )
    fep_title = _resolve_title_from_yml(
        yml_params_by_name, FEEDEXPIRATIONPOLICY_PARAM_NAME,
        fallback=_FEEDEXPIRATIONPOLICY_DEFAULT_TITLE,
    )
    # feedExpirationInterval has no display name per spec — always empty.
    frep_title = _resolve_title_from_yml(
        yml_params_by_name, FEEDREPUTATION_PARAM_NAME,
        fallback=_FEEDREPUTATION_DEFAULT_TITLE,
    )
    fbe_title = _resolve_title_from_yml(
        yml_params_by_name, FEEDBYPASSEXCLUSIONLIST_PARAM_NAME,
        fallback=_FEEDBYPASSEXCLUSIONLIST_DEFAULT_TITLE,
    )

    # --- §3. Look up yml params (may be None) ---------------------------
    def _yml(name: str) -> dict | None:
        return yml_params_by_name.get(name) if yml_params_by_name else None

    # --- §4. Build the 7 fields -----------------------------------------
    fields: list[dict] = []

    # 1. feed — always synthetic (hardcoded true + hidden)
    fields.append(_build_feed_toggle_field(
        field_id=feed_field_id, title=feed_title,
    ))

    # 2. feedFetchInterval — duration picker
    fields.append(_build_feedfetchinterval_field(
        yml_param=_yml(FEEDFETCHINTERVAL_PARAM_NAME),
        field_id=ffi_field_id, title=ffi_title,
    ))

    # 3. feedReliability — select (required)
    fields.append(_build_feedreliability_field(
        yml_param=_yml(FEEDRELIABILITY_PARAM_NAME),
        field_id=fr_field_id, title=fr_title,
    ))

    # 4. feedExpirationPolicy — select (type 17)
    fields.append(_build_feedexpirationpolicy_field(
        yml_param=_yml(FEEDEXPIRATIONPOLICY_PARAM_NAME),
        field_id=fep_field_id, title=fep_title,
    ))

    # 5. feedExpirationInterval — numeric input (hidden, no display)
    fields.append(_build_feedexpirationinterval_field(
        yml_param=_yml(FEEDEXPIRATIONINTERVAL_PARAM_NAME),
        field_id=fei_field_id,
    ))

    # 6. feedReputation — select (type 18)
    fields.append(_build_feedreputation_field(
        yml_param=_yml(FEEDREPUTATION_PARAM_NAME),
        field_id=frep_field_id, title=frep_title,
    ))

    # 7. feedBypassExclusionList — checkbox
    fields.append(_build_feedbypassexclusionlist_field(
        yml_param=_yml(FEEDBYPASSEXCLUSIONLIST_PARAM_NAME),
        field_id=fbe_field_id, title=fbe_title,
    ))

    # --- §5. Strip all feed param names from mapper results -------------
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n for n in names if n not in _FEED_STRIPPED_PARAMS
        ]

    # --- §6. Sub-cap rename bridges (per emitted field) -----------------
    if is_sub_capability and handler_dir is not None:
        _original_to_renamed = {
            FEED_PARAM_NAME: feed_field_id,
            FEEDFETCHINTERVAL_PARAM_NAME: ffi_field_id,
            FEEDRELIABILITY_PARAM_NAME: fr_field_id,
            FEEDEXPIRATIONPOLICY_PARAM_NAME: fep_field_id,
            FEEDEXPIRATIONINTERVAL_PARAM_NAME: fei_field_id,
            FEEDREPUTATION_PARAM_NAME: frep_field_id,
            FEEDBYPASSEXCLUSIONLIST_PARAM_NAME: fbe_field_id,
        }
        for original, renamed in _original_to_renamed.items():
            if renamed != original:
                register_renamed_field_serializer_entry(
                    handler_dir,
                    original_id=original,
                    renamed_id=renamed,
                )

    # --- §7. Build the feedExpirationInterval reveal trigger -------------
    triggers: list[dict] = [
        _build_feed_expiration_interval_trigger(
            expiration_policy_field_id=fep_field_id,
            expiration_interval_field_id=fei_field_id,
        )
    ]

    return {
        "capability_id": capability_id,
        "fields": fields,
        "triggers": triggers,
    }


# ------------------------------------------------------------------ #
# Fetch Issues capability builder
# ------------------------------------------------------------------ #

# Default human-readable titles for the synthetic / fallback emission
# paths in ``add_fetch_issues_capability``.
_ISFETCH_DEFAULT_TITLE = "Fetch incidents"
_INCIDENTTYPE_DEFAULT_TITLE = "Incident type"
_INCIDENTFETCHINTERVAL_DEFAULT_TITLE = "Incidents Fetch Interval"
_MAPPER_INCOMING_DEFAULT_TITLE = "Incoming Mapper"
_CLASSIFIER_DEFAULT_TITLE = "Classifier"
_LONGRUNNING_DEFAULT_TITLE = "Long running instance"

# Fallback default for incidentFetchInterval when the yml doesn't carry
# the param. DefaultIncidentFetchTime = 1 * time.Minute = 1 minute.
INCIDENTFETCHINTERVAL_FALLBACK_DEFAULT = "1"  # string per XSOAR convention

# The original XSOAR yml param names for the fetch-issues capability params.
# Stripped from mapper results by ``add_fetch_issues_capability`` so we
# don't emit them twice.
ISFETCH_PARAM_NAME = "isFetch"
INCIDENTTYPE_PARAM_NAME = "incidentType"
INCIDENTFETCHINTERVAL_PARAM_NAME = "incidentFetchInterval"
ALERTFETCHINTERVAL_PARAM_NAME = "alertFetchInterval"
LONGRUNNING_PARAM_NAME = "longRunning"

# Connector-side field ids for the dynamic fields (mapper + classifier).
# These are NOT XSOAR config param names — they are connector-level field
# ids that map to the XSOAR instance-level fields via the dynamic values
# mechanism.
MAPPER_INCOMING_FIELD_ID = "mapper_incoming"
CLASSIFIER_FIELD_ID = "classifier"

# All fetch-issues param names that are stripped from mapped_params.
_FETCH_ISSUES_STRIPPED_PARAMS: frozenset[str] = frozenset(
    {
        ISFETCH_PARAM_NAME,
        INCIDENTTYPE_PARAM_NAME,
        INCIDENTFETCHINTERVAL_PARAM_NAME,
        ALERTFETCHINTERVAL_PARAM_NAME,
    }
)


# ---------------------------------------------------------------------------
# Per-field builders for the fetch-issues capability
# ---------------------------------------------------------------------------


def _build_isfetch_field(
    field_id: str,
    title: str,
) -> dict:
    """Build the ``isFetch`` checkbox field — always default ``True``, hidden.

    Per spec: the ``isFetch`` param is always emitted as a hidden checkbox
    with ``default_value: true``. The yml's hidden/default values are
    IGNORED — this is a hardcoded synthetic field.
    """
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "options": {
            "default_value": True,
            "create_modifiers": {"required": False, "hidden": True},
            "edit_modifiers": {"required": False, "hidden": True},
        },
    }


def _build_incidentfetchinterval_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Thin wrapper over :func:`_build_numeric_fetch_interval_field`
    bound to the fetch-issues capability's ``"1"`` fallback default
    (DefaultIncidentFetchTime = 1 minute).
    """
    return _build_numeric_fetch_interval_field(
        yml_param=yml_param,
        field_id=field_id,
        title=title,
        fallback_default=INCIDENTFETCHINTERVAL_FALLBACK_DEFAULT,
    )


def _build_dynamic_select_field(
    *,
    field_id: str,
    title: str,
    dynamic_field_type: str,
    integration_id: str,
    default_value: str | None = None,
    required: bool = False,
    hidden: bool = False,
    description: str = "",
) -> dict:
    """Build a dynamic ``select`` field whose options are fetched at runtime
    by the XSOAR provider.

    Per ``plans/dynamic-field-values.md``: the field carries
    ``metadata.dynamic_values`` with ``provider: "xsoar"`` and
    ``trigger: ["on_create", "on_edit"]``. ``options.values`` is NOT set
    (forbidden when dynamic_values is present). ``options.default_value``
    is a literal pre-selection hint (applied only if the fetched list
    contains the key; silently ignored otherwise).

    Args:
        field_id: Connector-side field id.
        title: Human-readable label.
        dynamic_field_type: The XSOAR dynamic field type string
            (e.g. ``"incident-type"``, ``"mapper-incoming"``,
            ``"classifier"``).
        integration_id: The ``commonfields.id`` of the integration —
            passed as ``params.integrationID`` to the XSOAR provider.
        default_value: Optional literal pre-selection hint.
        required: Whether the field is required.
        hidden: Whether the field is hidden.
        description: Optional description text.
    """
    field: dict = {
        "id": field_id,
        "title": title,
        "field_type": "select",
        "metadata": {
            "dynamic_values": {
                "provider": "xsoar",
                "trigger": ["on_create", "on_edit"],
                "params": {
                    "integrationID": integration_id,
                    "dynamicField": dynamic_field_type,
                },
            },
        },
        "options": {
            "searchable": True,
            "clearable": True,
            "create_modifiers": {"required": required, "hidden": hidden},
            "edit_modifiers": {"required": required, "hidden": hidden},
        },
    }
    if default_value:
        field["options"]["default_value"] = default_value
    if description:
        field["options"]["description"] = description
    return field


def _build_longrunning_field(
    field_id: str,
    title: str,
) -> dict:
    """Build the ``longRunning`` checkbox field — hidden, default ``True``.

    Only emitted for long-running integrations mapped to Fetch Issues.
    """
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "options": {
            "default_value": True,
            "create_modifiers": {"required": False, "hidden": True},
            "edit_modifiers": {"required": False, "hidden": True},
        },
    }


def add_fetch_issues_capability(
    *,
    capability_id: str,
    is_sub_capability: bool,
    is_long_running: bool,
    mapped_params: dict[str, list[str]],
    integration_yml: dict,
    yml_params_by_name: dict[str, dict] | None = None,
    handler_dir: Path | None = None,
) -> dict:
    """Build the per-capability template dict for the ``Fetch Issues``
    capability with up to 6 fields:

      1. ``isFetch`` — checkbox, always default true + hidden true
      2. ``incidentType`` — dynamic select (``incident-type``)
      3. ``incidentFetchInterval`` — duration picker (fallback 1 min)
      4. ``mapper_incoming`` — dynamic select (``mapper-incoming``),
         default from ``integration_yml["defaultmapperin"]``
      5. ``classifier`` — dynamic select (``classifier``),
         default from ``integration_yml["defaultclassifier"]``
      6. ``longRunning`` — checkbox, hidden + default true
         (only when ``is_long_running=True``)

    Caller contract (mirrors the other ``add_<capability>_capability``
    builders):
      - ``capability_id``: connector-side capability id. Pass
        ``"fetch-issues"`` for the top-level case or a sub-cap id.
      - ``is_sub_capability``: flips the field-id naming.
      - ``is_long_running``: when True, adds the ``longRunning`` hidden
        checkbox and strips ``longRunning`` from ``mapped_params``.
      - ``integration_yml``: the full integration YAML dict — needed for
        ``commonfields.id`` (dynamic field ``integrationID`` param),
        ``defaultmapperin``, and ``defaultclassifier``.

    Side effects:
      1. Strips ``isFetch``, ``incidentType``, ``incidentFetchInterval``,
         ``alertFetchInterval`` from every bucket of ``mapped_params``.
         When ``is_long_running=True``, also strips ``longRunning``.
      2. Sub-cap rename bridges via serializer for each renamed field.

    Returns:
      ``{"capability_id", "fields", "triggers"}`` — triggers is always
      empty for fetch-issues (no conditional reveal needed).
    """
    integration_id = (integration_yml.get("commonfields") or {}).get("id", "")

    # --- §1. Resolve the connector-side field ids (sub-cap rename) ------
    def _field_id(original: str) -> str:
        return f"{capability_id}_{original}" if is_sub_capability else original

    isfetch_field_id = _field_id(ISFETCH_PARAM_NAME)
    inctype_field_id = _field_id(INCIDENTTYPE_PARAM_NAME)
    incfi_field_id = _field_id(INCIDENTFETCHINTERVAL_PARAM_NAME)
    mapper_field_id = _field_id(MAPPER_INCOMING_FIELD_ID)
    classifier_field_id = _field_id(CLASSIFIER_FIELD_ID)
    lr_field_id = _field_id(LONGRUNNING_PARAM_NAME) if is_long_running else ""

    # --- §2. Resolve titles (generic helper) ----------------------------
    isfetch_title = _resolve_title_from_yml(
        yml_params_by_name, ISFETCH_PARAM_NAME,
        fallback=_ISFETCH_DEFAULT_TITLE,
    )
    inctype_title = _resolve_title_from_yml(
        yml_params_by_name, INCIDENTTYPE_PARAM_NAME,
        fallback=_INCIDENTTYPE_DEFAULT_TITLE,
    )
    incfi_title = _resolve_title_from_yml(
        yml_params_by_name, INCIDENTFETCHINTERVAL_PARAM_NAME,
        fallback=_INCIDENTFETCHINTERVAL_DEFAULT_TITLE,
    )

    # --- §3. Look up yml params and integration-level defaults ----------
    def _yml(name: str) -> dict | None:
        return yml_params_by_name.get(name) if yml_params_by_name else None

    # incidentType default from yml config param's defaultvalue (if present).
    inctype_yml = _yml(INCIDENTTYPE_PARAM_NAME)
    inctype_default = (
        inctype_yml.get("defaultvalue")
        if inctype_yml and inctype_yml.get("defaultvalue")
        else None
    )

    # mapper_incoming default from integration yml top-level field.
    mapper_default = integration_yml.get("defaultmapperin") or None
    # classifier default from integration yml top-level field.
    classifier_default = integration_yml.get("defaultclassifier") or None

    # --- §4. Build the fields -------------------------------------------
    fields: list[dict] = []

    # 1. isFetch — always synthetic (hardcoded true + hidden)
    fields.append(_build_isfetch_field(
        field_id=isfetch_field_id, title=isfetch_title,
    ))

    # 2. incidentType — dynamic select
    fields.append(_build_dynamic_select_field(
        field_id=inctype_field_id,
        title=inctype_title,
        dynamic_field_type="incident-type",
        integration_id=integration_id,
        default_value=inctype_default,
    ))

    # 3. incidentFetchInterval — duration picker
    fields.append(_build_incidentfetchinterval_field(
        yml_param=_yml(INCIDENTFETCHINTERVAL_PARAM_NAME),
        field_id=incfi_field_id, title=incfi_title,
    ))

    # 4. mapper_incoming — dynamic select
    fields.append(_build_dynamic_select_field(
        field_id=mapper_field_id,
        title=_MAPPER_INCOMING_DEFAULT_TITLE,
        dynamic_field_type="mapper-incoming",
        integration_id=integration_id,
        default_value=mapper_default,
    ))

    # 5. classifier — dynamic select
    fields.append(_build_dynamic_select_field(
        field_id=classifier_field_id,
        title=_CLASSIFIER_DEFAULT_TITLE,
        dynamic_field_type="classifier",
        integration_id=integration_id,
        default_value=classifier_default,
    ))

    # 6. longRunning — only for long-running integrations
    if is_long_running:
        fields.append(_build_longrunning_field(
            field_id=lr_field_id,
            title=_LONGRUNNING_DEFAULT_TITLE,
        ))

    # --- §5. Strip fetch-issues param names from mapper results ---------
    stripped = set(_FETCH_ISSUES_STRIPPED_PARAMS)
    if is_long_running:
        stripped.add(LONGRUNNING_PARAM_NAME)
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n for n in names if n not in stripped
        ]

    # --- §6. Sub-cap rename bridges (per emitted field) -----------------
    if is_sub_capability and handler_dir is not None:
        _original_to_renamed = {
            ISFETCH_PARAM_NAME: isfetch_field_id,
            INCIDENTTYPE_PARAM_NAME: inctype_field_id,
            INCIDENTFETCHINTERVAL_PARAM_NAME: incfi_field_id,
            MAPPER_INCOMING_FIELD_ID: mapper_field_id,
            CLASSIFIER_FIELD_ID: classifier_field_id,
        }
        if is_long_running:
            _original_to_renamed[LONGRUNNING_PARAM_NAME] = lr_field_id
        for original, renamed in _original_to_renamed.items():
            if renamed != original:
                register_renamed_field_serializer_entry(
                    handler_dir,
                    original_id=original,
                    renamed_id=renamed,
                )

    return {
        "capability_id": capability_id,
        "fields": fields,
        "triggers": [],
    }


CAPABILITIES_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/capabilities.schema.json\n"
)


# ---------------------------------------------------------------------------
# Mandatory general_configurations fields (per guide §3.4 + §3.7)
# ---------------------------------------------------------------------------
# Every connector MUST emit these two fields in
# ``capabilities.yaml`` → ``general_configurations[].configurations[0].fields``,
# regardless of whether they appear in the integration's XSOAR yml.
#
# Source of truth: guide §4.3 (Salesforce reference, lines 1318-1365 of the
# migration guide). These are NOT user-configurable from the integration
# yml — they are platform-mandated and rendered identically across every
# connector.


def _instance_name_field() -> dict:
    """Build the mandatory ``instance_name`` field for general_configurations.

    Per guide §3.4 + §4.3 Salesforce reference. The shape includes:
      - ``metadata.connector.parameter: "instance_name"`` — tells the BE
        this field maps to the connector-level instance name slot.
      - ``validations`` — pattern (alphanumerics + space/underscore/dash)
        + async uniqueness check.
      - ``create_modifiers.required: true`` / ``edit_modifiers.required: true``
        — both surfaces require a value.

    Returns a fresh dict on every call so callers can mutate safely.
    """
    return {
        "id": "instance_name",
        "title": "Instance name",
        "field_type": "input",
        "metadata": {"connector": {"parameter": "instance_name"}},
        "validations": [
            {
                "trigger": "change",
                "rules": [
                    {
                        "type": "pattern",
                        "value": "^[a-zA-Z0-9 _-]+$",
                        "message": (
                            "Only alphanumeric characters, spaces, "
                            "underscores, and hyphens are allowed."
                        ),
                    },
                    {"type": "async", "validation_type": "uniqueness"},
                ],
            }
        ],
        "options": {
            "placeholder": "Please Enter Name for an Instance",
            "create_modifiers": {
                "required": True,
                "read_only": False,
                "hidden": False,
            },
            "edit_modifiers": {
                "required": True,
                "read_only": False,
                "hidden": False,
            },
        },
    }


def _integration_log_level_field() -> dict:
    """Build the mandatory ``integrationLogLevel`` field for general_configurations.

    Per guide §3.4 + §3.7 + §4.3 Salesforce reference. This is a BE-managed
    field (``metadata.xsoar.config_type: "backend"``) — the values are
    consumed by the platform's logging layer, NOT by the integration code.

    Default value is "Off" per the Salesforce reference. The 3 select
    options (Off / Debug / Verbose) are platform-defined and identical
    across every connector.

    Returns a fresh dict on every call so callers can mutate safely.
    """
    return {
        "id": "integrationLogLevel",
        "title": "Integration Log Level",
        "field_type": "select",
        "metadata": {"xsoar": {"config_type": "backend"}},
        "options": {
            "description": "Set the log level for the integration",
            "placeholder": "Select log level",
            "default_value": "Off",
            "values": [
                {"key": "Off", "label": "Off"},
                {"key": "Debug", "label": "Debug"},
                {"key": "Verbose", "label": "Verbose"},
            ],
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def _required_license_for_capability(
    cap_id: str, supported_modules: list[str] | None
) -> list[str]:
    """Compute ``config.required_license`` for a capability.

    Base list is the integration's / pack's ``supported_modules`` (already
    normalized to the capabilities.schema license enum by the caller). For
    the license-restricted fetch capabilities (guide §3.4 note 6) the list
    is intersected with ``{agentix, xsiam}`` so those capabilities are only
    visible to customers holding one of those licenses.

    Returns a (possibly empty) list — an empty list is valid per
    capabilities.schema (means "always visible").
    """
    base = list(supported_modules or [])
    if cap_id in _LICENSE_RESTRICTED_FETCH_CAPS:
        if base:
            return [lic for lic in base if lic in _AGENTIX_XSIAM_LICENSES]
        # No declared modules → default to the agentix/xsiam restriction.
        return list(_AGENTIX_XSIAM_LICENSES)
    return base


def build_capabilities_yaml(
    mapped_params: dict[str, Any],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
    supported_modules: list[str] | None = None,
) -> dict:
    """Build the dict for capabilities.yaml.

    Per guide §3.4 + §4.3 (Salesforce reference), capabilities.yaml
    MUST include the mandatory ``instance_name`` field in
    ``general_configurations`` (FE-tagged via
    ``metadata.connector.parameter``).

    ``integrationLogLevel`` and user-mapped ``general_configurations``
    params are emitted in ``configurations.yaml`` (NOT here) — each
    inside a ``view_group``-pinned field group per handler. See
    :func:`build_per_handler_general_config` and
    :func:`build_configurations_yaml`.

    Each capability entry includes the REQUIRED schema fields
    (capabilities.schema: id + title + default_enabled + required):
      - ``title`` — from CANONICAL_CAPABILITY_TITLES lookup
      - ``default_enabled: true`` (per Salesforce reference §4.3)
      - ``required: false`` (per guide §3.4: "Always false")

    Backwards-compatible: callers omitting all extra args get bare-id
    fields with no dedup side-effects.
    """
    # Only instance_name lives in capabilities.yaml general_configurations.
    # integrationLogLevel + user-mapped params → configurations.yaml.
    general_fields: list[dict] = [
        _instance_name_field(),
    ]

    capabilities = []
    for cap_name in mapped_params:
        if cap_name == "general_configurations":
            continue
        cap_id = slugify_capability_name(cap_name)
        parent_entry: dict = {
            "id": cap_id,
            "title": CANONICAL_CAPABILITY_TITLES[cap_id],
            # capabilities.schema REQUIRES a non-empty description (guide
            # §3.4 — placeholder, flag for tech-writer review).
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS[cap_id],
            # Per guide §3.4 + §4.3 Salesforce reference.
            "default_enabled": True,
            "required": False,
        }
        # config.required_license — aggregate of the integration's
        # supported_modules, intersected with {agentix, xsiam} for the
        # license-restricted fetch capabilities (guide §3.4 note 6).
        required_license = _required_license_for_capability(
            cap_id, supported_modules
        )
        parent_entry["config"] = {"required_license": required_license}

        # Capabilities are ALWAYS modelled as parent + one sub-capability,
        # even on a fresh connector. The parent carries the canonical family
        # id/title; the lone sub-capability is keyed by this handler's sub-cap
        # id ``<handler_id>-<cap_slug>`` (the id the handler.yaml and
        # configurations.yaml entries reference). The bare-slug fallback only
        # applies when no handler_id is supplied (legacy callers).
        #
        # Per guide §3.1 item 13: a capability with exactly ONE
        # sub-capability marks that lone sub-cap ``required: true`` so
        # selecting the parent implies the sub-cap.
        if handler_id:
            sub_cap_id = make_sub_capability_id(handler_id, cap_name)
            parent_entry["sub_capabilities"] = [
                build_sub_capability_entry(sub_cap_id, cap_name, required=True)
            ]
        capabilities.append(parent_entry)

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


# ---------------------------------------------------------------------------
# Per-handler general_configurations fields
# ---------------------------------------------------------------------------
# Per the grouped-example reference, every handler added to a connector
# gets two fields in configurations.yaml → general_configurations, each
# inside a view_group-pinned field group where view_group id = handler id.
# Both fields are prefixed with the handler id for global uniqueness
# (Appendix C) and bridged back to their canonical names via serializer
# field_mappings.

# Canonical base param names (the XSOAR runtime expects these).
_INTEGRATION_LOG_LEVEL_PARAM = "integrationLogLevel"
_DEFAULT_IGNORE_PARAM = "defaultIgnore"


def _per_handler_log_level_field(handler_id: str) -> dict:
    """Build the per-handler ``integrationLogLevel`` field.

    Per the grouped-example reference: each handler gets its own
    ``<handler_id>_integrationLogLevel`` select field in
    ``configurations.yaml`` → ``general_configurations``, pinned to
    the handler's ``view_group``. The handler's ``serializer.yaml``
    maps the prefixed id back to ``integrationLogLevel``.

    Shape matches the grouped-example reference (lines 100-124 of
    ``configurations.yaml``).
    """
    return {
        "id": f"{handler_id}_{_INTEGRATION_LOG_LEVEL_PARAM}",
        "title": "Integration Log Level",
        "field_type": "select",
        "metadata": {
            "xsoar": {
                "config_type": "backend",
            },
        },
        "options": {
            "description": f"Set the log level for the {handler_id} integration.",
            "placeholder": "Select log level",
            "default_value": "Off",
            "values": [
                {"key": "Off", "label": "Off"},
                {"key": "Debug", "label": "Debug"},
                {"key": "Verbose", "label": "Verbose"},
            ],
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def _per_handler_default_ignore_field(handler_id: str) -> dict:
    """Build the per-handler ``defaultIgnore`` checkbox field.

    Per the grouped-example reference (lines 325-338 of
    ``configurations.yaml``): "Do not use in CLI by default" — a
    visible checkbox, always default ``false``, backend-managed.

    Shape matches the grouped-example reference.
    """
    return {
        "id": f"{handler_id}_{_DEFAULT_IGNORE_PARAM}",
        "title": "Do not use in CLI by default",
        "field_type": "checkbox",
        "metadata": {
            "xsoar": {
                "config_type": "backend",
            },
        },
        "options": {
            "default_value": False,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def build_per_handler_general_config(
    handler_id: str,
    handler_dir: Path,
    mapped_params: dict[str, Any] | None = None,
    yml_params_by_name: dict[str, dict] | None = None,
    existing_ids: set[str] | None = None,
) -> dict:
    """Build the per-handler general_configurations field group entry.

    Returns a dict shaped::

        {
            "view_group": "<handler_id>",
            "relevant_for_capabilities": [<cap_ids>],
            "fields": [
                <integrationLogLevel field>,
                <defaultIgnore field>,
                <user-mapped general_configurations params...>,
            ],
        }

    The ``relevant_for_capabilities`` list contains the canonical
    capability ids that this handler serves (derived from
    ``mapped_params`` keys, excluding ``general_configurations``).

    User-mapped ``general_configurations`` params (from
    ``mapped_params["general_configurations"]``) are emitted here
    (NOT in capabilities.yaml) — each materialized via
    :func:`emit_field_for_param` with dedup support.

    Also registers serializer ``field_mappings`` entries for the
    ``integrationLogLevel`` and ``defaultIgnore`` fields so the XSOAR
    runtime receives the canonical param names.

    The caller is responsible for:
      1. Adding the returned dict to
         ``configurations_data["general_configurations"]["configurations"]``.
      2. Adding a ``view_groups`` registry entry
         ``{"id": handler_id, "label": handler_id}`` to
         ``configurations_data["view_groups"]``.
    """
    log_level = _per_handler_log_level_field(handler_id)
    default_ignore = _per_handler_default_ignore_field(handler_id)

    # Register serializer mappings so the XSOAR runtime sees the
    # canonical param names.
    register_renamed_field_serializer_entry(
        handler_dir,
        original_id=_INTEGRATION_LOG_LEVEL_PARAM,
        renamed_id=log_level["id"],
    )
    register_renamed_field_serializer_entry(
        handler_dir,
        original_id=_DEFAULT_IGNORE_PARAM,
        renamed_id=default_ignore["id"],
    )

    fields: list[dict] = [log_level, default_ignore]

    # User-mapped general_configurations params — emitted here (in
    # configurations.yaml) rather than in capabilities.yaml, each
    # pinned to this handler's view_group.
    reserved_ids = {"instance_name", "integrationLogLevel", "defaultIgnore"}
    if mapped_params:
        general_params = mapped_params.get("general_configurations", []) or []
        for p in general_params:
            if p in reserved_ids:
                logger.warning(
                    "[manifest_generator] User-param '%s' in "
                    "general_configurations collides with a "
                    "platform-mandated field — skipping.",
                    p,
                )
                continue
            fields.extend(
                emit_field_for_param(
                    p,
                    yml_params_by_name,
                    handler_id=handler_id,
                    handler_dir=handler_dir,
                    existing_ids=existing_ids,
                )
            )

    # Compute relevant_for_capabilities from mapped_params keys. Capabilities
    # are modelled as sub-capabilities, so this references the sub-cap ids
    # ``<handler_id>-<cap_slug>`` this handler serves (falling back to the bare
    # slug only when no handler_id is supplied).
    cap_ids: list[str] = []
    if mapped_params:
        for cap_name in mapped_params:
            if cap_name == "general_configurations":
                continue
            cap_ids.append(
                make_sub_capability_id(handler_id, cap_name)
                if handler_id
                else slugify_capability_name(cap_name)
            )

    result: dict = {
        "view_group": handler_id,
        "fields": fields,
    }
    if cap_ids:
        result["relevant_for_capabilities"] = cap_ids
    return result


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
        # Capabilities are ALWAYS modelled as sub-capabilities — key each
        # per-capability configuration entry by the sub-cap id
        # ``<handler_id>-<cap_slug>`` so it matches the sub-capability emitted
        # in capabilities.yaml and referenced by handler.yaml. Falls back to
        # the bare slug only when no handler_id is supplied (legacy callers).
        cap_id = (
            make_sub_capability_id(handler_id, cap_name)
            if handler_id
            else slugify_capability_name(cap_name)
        )
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
        entry: dict = {
            "id": cap_id,
            "configurations": [{"fields": fields}],
        }
        # Per grouped-example reference: each per-capability entry
        # carries ``view_group: <handler_id>`` so the FE knows which
        # tile to render it under.
        if handler_id:
            entry["view_group"] = handler_id
        configurations.append(entry)

    return {
        "metadata": {
            "title": "Configuration",
            "description": "Adjust and refine your configuration",
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
    new_sub_cap_id = make_sub_capability_id(new_handler_id, cap_name)

    existing_cap = next(
        (
            c
            for c in capabilities_data.get("capabilities", []) or []
            if c.get("id") == cap_slug
        ),
        None,
    )

    # Case 3: capability does not exist anywhere — create the parent
    # capability with a single sub-capability (NOT a flat top-level
    # capability). Capabilities are ALWAYS modelled as parent + sub-capability,
    # so even a brand-new capability is added as a sub-capability and the
    # handler/configurations reference the sub-cap id.
    #
    # Per capabilities.schema: every (sub-)capability entry MUST include
    # id + title + default_enabled + required.
    if existing_cap is None:
        capabilities_data.setdefault("capabilities", []).append(
            {
                "id": cap_slug,
                "title": CANONICAL_CAPABILITY_TITLES[cap_slug],
                "default_enabled": True,
                "required": False,
                "sub_capabilities": [
                    build_sub_capability_entry(new_sub_cap_id, cap_name)
                ],
            }
        )
        configurations_data.setdefault("configurations", []).append(
            {
                "id": new_sub_cap_id,
                "configurations": [{"fields": _emit_fields(cap_params)}],
            }
        )
        return new_sub_cap_id

    has_sub_caps = bool(existing_cap.get("sub_capabilities"))

    # Case 2: capability is currently flat — promote into sub-caps.
    if not has_sub_caps:
        existing_handler_path = find_existing_handler_for_capability(
            connector_dir, cap_slug
        )
        existing_handler_id = existing_handler_path.parent.name
        existing_sub_cap_id = make_sub_capability_id(existing_handler_id, cap_name)

        # Step 2.1: rename cap id inside the existing handler.yaml.
        rename_handler_capability_id(
            existing_handler_path, cap_slug, existing_sub_cap_id
        )

        # Step 2.2: introduce sub_capabilities on the parent in capabilities.yaml.
        existing_cap["sub_capabilities"] = [
            build_sub_capability_entry(existing_sub_cap_id, cap_name)
        ]

        # Step 2.3: rename the existing top-level entry in configurations.yaml
        # (per spec: drop parent's entry — the renamed entry IS the new sub-cap entry).
        for cfg_entry in configurations_data.get("configurations", []) or []:
            if cfg_entry.get("id") == cap_slug:
                cfg_entry["id"] = existing_sub_cap_id
                break

    # Case 1 (or fall-through after promotion): append the new sub-cap.
    existing_cap.setdefault("sub_capabilities", []).append(
        build_sub_capability_entry(new_sub_cap_id, cap_name)
    )
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

    Per spec and the worked Salesforce reference (guide §4.5):
      - title: hardcoded "Summary"
      - description: templated as f"Summary for connector {connector_title}"
      - link and next_steps are OPTIONAL per summary.schema and are
        omitted from the default output (callers can add them via
        ``manual_summary_fields`` deep-merge).
    """
    return {
        "metadata": {
            "title": "Summary",
            "description": f"Summary for connector {connector_title}",
        },
    }


# ---------------------------------------------------------------------------
# triggers.yaml emission
# ---------------------------------------------------------------------------
TRIGGERS_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/triggers.schema.json\n"
)


def build_triggers_yaml(triggers: list[dict]) -> dict:
    """Build the dict for a triggers.yaml file.

    Per the triggers.schema.json, the top-level key is ``triggers``
    containing an array of trigger objects (each with ``conditions`` +
    ``effects``).

    Args:
        triggers: List of trigger dicts (each shaped per the schema:
            ``{conditions: ..., effects: [...]}``) collected from
            capability builders.

    Returns:
        A dict ready for ``yaml.safe_dump``.
    """
    return {"triggers": list(triggers)}


def write_triggers_yaml(triggers_yaml_path: Path, triggers_data: dict) -> None:
    """Write a triggers.yaml file with the schema directive line prepended.

    Only call this when ``triggers_data["triggers"]`` is non-empty —
    callers should skip the write entirely when no triggers exist.
    """
    triggers_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(triggers_yaml_path, "w") as fh:
        fh.write(TRIGGERS_SCHEMA_DIRECTIVE)
        yaml.safe_dump(triggers_data, fh)


CONNECTION_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../schema/connection.schema.json\n"
)


def write_connection_yaml(connection_yaml_path: Path, connection_data: dict) -> None:
    """Write a connection.yaml file with the schema directive line prepended.

    Mirrors :func:`write_capabilities_yaml` / :func:`write_triggers_yaml` —
    connection.yaml lives at the connector root, so the directive uses the
    same ``../../schema/`` relative prefix.
    """
    connection_yaml_path.parent.mkdir(parents=True, exist_ok=True)
    with open(connection_yaml_path, "w") as fh:
        fh.write(CONNECTION_SCHEMA_DIRECTIVE)
        yaml.safe_dump(connection_data, fh)


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
    """XSOAR type 1 — Hidden short text → connectus `input` with mask."""
    field = {"id": yml_param["name"], "field_type": "input", "options": {"mask": True}}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_4(yml_param: dict) -> dict:
    """XSOAR type 4 — Encrypted → connectus `input` with mask."""
    field = {"id": yml_param["name"], "field_type": "input", "options": {"mask": True}}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_8(yml_param: dict) -> dict:
    """XSOAR type 8 — Boolean → connectus ``checkbox``.

    Per guide Appendix A: type 8 maps to ``checkbox`` (NOT ``toggle``).
    The two field types render differently in the UI — ``checkbox`` is
    an opt-in tickbox, ``toggle`` is an on/off slider. The platform
    (BE + FE) expects ``checkbox`` for XSOAR boolean params.

    Coerces ``defaultvalue`` to bool (the XSOAR yml uses string "true"
    / "false" or Python bool).
    """
    field = {"id": yml_param["name"], "field_type": "checkbox"}
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


def _build_select_values(yml_param: dict, label_key: str = "label") -> list[dict]:
    """Build connectus `options.values` from the YAML's `options:` list.

    Each connectus item is `{key: ..., label: ...}`. Per the live
    field-options schema (``SelectValuesItem`` / ``MultiSelectValuesItem``)
    BOTH ``select`` and ``multi_select`` use the ``{key, label}`` shape —
    ``label_key`` is retained for call-site clarity but defaults to
    ``"label"``.
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
        "options": {"values": _build_select_values(yml_param, label_key="label")},
    }
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_14(yml_param: dict) -> dict:
    """XSOAR type 14 — Encrypted long text → connectus `text_area` with mask."""
    field = {"id": yml_param["name"], "field_type": "text_area", "options": {"mask": True}}
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_15(yml_param: dict) -> dict:
    """XSOAR type 15 — Single-select → connectus `select` with `{key, label}` items."""
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": _build_select_values(yml_param, label_key="label")},
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


# Hardcoded enum values per guide Appendix A. These are platform-defined
# for the two Feed-related XSOAR types and are NOT sourced from the
# integration yml's ``options:`` list (the yml options for these types
# are explicitly IGNORED by the migration script).

# Per guide Appendix A type 17: "Feed Expiration Policy".
FEED_EXPIRATION_POLICY_VALUES: list[dict] = [
    {"key": "Indicator Type", "label": "Indicator Type"},
    {"key": "Time Interval", "label": "Time Interval"},
    {"key": "Never Expire", "label": "Never Expire"},
    {"key": "When removed from the feed", "label": "When removed from the feed"},
]

# Per guide Appendix A type 18: "Indicator / Feed Reputation". The
# "new mapped values" — the legacy XSOAR values were
# None/Good/Suspicious/Bad. The platform consumer (BE+FE) expects the
# Unknown/Benign/Suspicious/Malicious form below.
INDICATOR_REPUTATION_VALUES: list[dict] = [
    {"key": "Unknown", "label": "Unknown"},
    {"key": "Benign", "label": "Benign"},
    {"key": "Suspicious", "label": "Suspicious"},
    {"key": "Malicious", "label": "Malicious"},
]


def _map_type_17(yml_param: dict) -> dict:
    """XSOAR type 17 — Feed Expiration Policy → connectus ``select``.

    Per guide Appendix A: hardcoded display labels (the yml's
    ``options`` list, if any, is IGNORED). Only added when
    ``script.Feed: true``; the integration yml's ``defaultvalue`` is
    preserved if present (via :func:`_apply_common_field_metadata`).

    The previous behavior (treat type 17 as a generic Date ``input``)
    was incorrect — guide Appendix A is the authoritative spec.
    """
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": list(FEED_EXPIRATION_POLICY_VALUES)},
    }
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_18(yml_param: dict) -> dict:
    """XSOAR type 18 — Indicator / Feed Reputation → connectus ``select``.

    Per guide Appendix A: hardcoded values (Unknown / Benign /
    Suspicious / Malicious) — these are the "new mapped values". The
    legacy XSOAR values None/Good/Suspicious/Bad are NOT preserved.
    The yml's ``options`` list is IGNORED.

    The previous behavior (treat type 18 as a generic "Grouped
    single-select" pulling values from the yml) was incorrect — guide
    Appendix A is the authoritative spec.
    """
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": list(INDICATOR_REPUTATION_VALUES)},
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


def _map_type_22(yml_param: dict) -> dict:
    """XSOAR type 22 — Copy to Clipboard → connectus ``label``.

    Per guide Appendix A (rare type, in informal use): type 22 renders
    the param's value as a read-only display that the user can copy.
    The connectus ``label`` field type (defined in
    field.schema.json's ``FieldType`` enum) is the closest semantic
    match — it renders a static element with no input affordance.

    Note: ``label`` fields don't carry the standard create/edit
    modifiers, mask, or is_number_input options.
    """
    field = {"id": yml_param["name"], "field_type": "label"}
    # Apply title (display) + description (additionalinfo) but skip
    # default_value / modifiers (the label has no editable surface).
    title = yml_param.get("display")
    if title:
        field["title"] = title
    additional_info = yml_param.get("additionalinfo")
    if additional_info:
        field.setdefault("options", {})["description"] = additional_info
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
    22: _map_type_22,
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


# ===========================================================================
# connection.yaml builders  (see plans/connection-auth-types-design.md)
# Part A: auth_types -> profiles[] | Part B: proxy/insecure |
# Part C: engine 3-field + Appendix G/H + triggers | Part D: view_groups +
# general_configurations (rest of other_connection)
# ===========================================================================

# ---------------------------------------------------------------------------
# Part A — classification → connection profile type
# ---------------------------------------------------------------------------
# auth_types[].type (4-value classifier enum) → connection.yaml profile type.
AUTH_TYPE_TO_PROFILE_TYPE: dict[str, str] = {
    "APIKey": "api_key",
    "Plain": "plain",
    "Passthrough": "passthrough",
}

# (profile_type, classifier-role) → connection.yaml metadata.auth.parameter.
# Only canonical types need a remap; passthrough roles pass through verbatim.
ROLE_TO_AUTH_PARAMETER: dict[tuple[str, str], str] = {
    ("api_key", "key"): "api_key",
}

# Fixed human titles for the canonical profile types (design OQ-4).
_PROFILE_TYPE_TITLES: dict[str, str] = {
    "api_key": "API Key",
    "plain": "Username & Password",
}


def _slug_word(text: str) -> str:
    """Lowercase + collapse non-word chars, keeping ``[a-z0-9_]``.

    Used for the connection-profile id purpose segment, which the
    connection schema requires to match ``[\\w]{3,}`` after the dot.
    """
    s = re.sub(r"[^a-zA-Z0-9_]+", "_", text.strip().lower())
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def derive_profile_id(
    auth_type_entry: dict,
    integration_id: str,
    seen_profile_ids: set[str] | None = None,
) -> str:
    """Compute the connection-profile id ``<profile_type>.<slug(integration_id)>``.

    D2a collision guard: a 2nd+ profile of the same type within one integration
    gets ``_<slug(name)>`` appended so ids stay unique. ``seen_profile_ids`` is
    mutated in place to track emitted ids.
    """
    raw_type = auth_type_entry.get("type")
    if raw_type is None:
        # Legacy / name-only auth_type (no ``type``): derive a stable id from
        # the entry name so handler + connection stay in lockstep without a
        # canonical profile type. Real workflow outputs always carry ``type``.
        name_slug = _slug_word(auth_type_entry.get("name", "") or "auth")
        profile_type = name_slug or "auth"
    else:
        profile_type = AUTH_TYPE_TO_PROFILE_TYPE.get(raw_type)
        if profile_type is None:
            # ``type`` present but unrecognized → genuinely bad input.
            raise ValueError(
                f"Unknown auth_types[].type '{raw_type}'. "
                f"Expected one of {sorted(AUTH_TYPE_TO_PROFILE_TYPE)}."
            )
    purpose = _slug_word(integration_id)
    if len(purpose) < 3:
        purpose = f"{purpose}_xsoar"
    candidate = f"{profile_type}.{purpose}"
    if seen_profile_ids is not None and candidate in seen_profile_ids:
        name_slug = _slug_word(auth_type_entry.get("name", "") or "alt")
        candidate = f"{profile_type}.{purpose}_{name_slug}"
    if seen_profile_ids is not None:
        seen_profile_ids.add(candidate)
    return candidate


def _connection_field_id_from_map_key(map_key: str, sibling_keys: set[str]) -> str:
    """Derive the connectus field id for one ``xsoar_param_map`` key (D3, map-only).

    ``<param>.identifier`` -> ``<param>_username``;
    ``<param>.password`` -> ``<param>_password`` when the sibling ``.identifier``
    is present in this map, else bare ``<param>``;
    non-dotted (flat secret) -> the key verbatim.
    """
    if "." not in map_key:
        return map_key
    param, _, leaf = map_key.partition(".")
    if leaf == "identifier":
        return f"{param}_username"
    if leaf == "password":
        if f"{param}.identifier" in sibling_keys:
            return f"{param}_password"
        return param
    return f"{param}_{leaf}"


def _auth_parameter_for_role(profile_type: str, role: str) -> str:
    """Map a classifier role to ``metadata.auth.parameter``.

    Canonical types remap via :data:`ROLE_TO_AUTH_PARAMETER` (e.g. APIKey's
    ``key`` -> ``api_key``); ``plain`` roles and ``passthrough`` free-form roles
    pass through unchanged.
    """
    return ROLE_TO_AUTH_PARAMETER.get((profile_type, role), role)


def _connection_profile_title(profile_type: str, connector_title: str) -> str:
    """Human title for a profile (OQ-4: fixed for canonical, derived for passthrough)."""
    if profile_type in _PROFILE_TYPE_TITLES:
        return _PROFILE_TYPE_TITLES[profile_type]
    base = connector_title.strip() or "Connection"
    return f"{base} Credentials"


def _connection_field_title(
    field_id: str, yml_params_by_name: dict[str, dict] | None
) -> str:
    """Best-effort human title for a connection auth field (enrichment-only)."""
    if yml_params_by_name:
        base = field_id
        for suffix in ("_username", "_password"):
            if field_id.endswith(suffix):
                base = field_id[: -len(suffix)]
                break
        yml = yml_params_by_name.get(base)
        if yml:
            if field_id.endswith("_password") or field_id == base:
                label = yml.get("displaypassword") or yml.get("display")
            else:
                label = yml.get("display")
            if label and str(label).strip():
                return str(label)
    return field_id.replace("_", " ").strip().title() or field_id


def build_connection_profile(
    auth_type_entry: dict,
    integration_id: str,
    connector_title: str = "",
    yml_params_by_name: dict[str, dict] | None = None,
    seen_profile_ids: set[str] | None = None,
) -> dict:
    """Build ONE ``connection.yaml`` ``profiles[]`` entry (Part A — auth fields only).

    Non-auth proxy / insecure / engine fields are attached separately by
    :func:`attach_per_profile_connection_fields` (design D-D8 home 1).
    """
    raw_type = auth_type_entry.get("type")
    if raw_type is None:
        # Legacy / name-only auth_type: behave like a free-form (passthrough)
        # profile — roles pass through unchanged and the title is derived.
        profile_type = "passthrough"
    else:
        profile_type = AUTH_TYPE_TO_PROFILE_TYPE.get(raw_type)
        if profile_type is None:
            raise ValueError(
                f"Unknown auth_types[].type '{raw_type}'. "
                f"Expected one of {sorted(AUTH_TYPE_TO_PROFILE_TYPE)}."
            )
    profile_id = derive_profile_id(auth_type_entry, integration_id, seen_profile_ids)
    xsoar_param_map = auth_type_entry.get("xsoar_param_map") or {}
    map_keys = set(xsoar_param_map.keys())

    fields: list[dict] = []
    for map_key in sorted(xsoar_param_map.keys()):
        role = xsoar_param_map[map_key]
        field_id = _connection_field_id_from_map_key(map_key, map_keys)
        auth_parameter = _auth_parameter_for_role(profile_type, role)
        is_username = auth_parameter == "username"
        fields.append(
            {
                "id": field_id,
                "title": _connection_field_title(field_id, yml_params_by_name),
                "field_type": "input",
                "metadata": {"auth": {"parameter": auth_parameter}},
                "options": {
                    "mask": not is_username,
                    "create_modifiers": {"required": True, "hidden": False},
                    "edit_modifiers": {"required": True, "hidden": False},
                },
            }
        )

    return {
        "id": profile_id,
        "type": profile_type,
        "title": _connection_profile_title(profile_type, connector_title),
        "description": (
            f"Authentication profile for "
            f"{connector_title or integration_id} ({profile_type})."
        ),
        "configurations": [{"fields": fields}],
    }


# ---------------------------------------------------------------------------
# Part B — proxy / insecure detection + field builders
# ---------------------------------------------------------------------------
# Normalized synonym sets (lower + strip _/- before matching).
PROXY_SYNONYMS: frozenset[str] = frozenset({"proxy", "useproxy"})
# `trust` REMOVED (B-D5). Matched by whole-token equality (B.4), not substring.
INSECURE_SYNONYMS: frozenset[str] = frozenset(
    {"insecure", "unsecure", "verify", "secure"}
)

_PROXY_DEFAULT_TITLE = "Use system proxy settings"
_INSECURE_DEFAULT_TITLE = "Trust any certificate (not secure)"


def _normalize_param_id(pid: str) -> str:
    """Lowercase + remove ``_``/``-`` for exact (proxy) matching."""
    return re.sub(r"[_-]+", "", pid.strip().lower())


def _tokenize_param_id(pid: str) -> list[str]:
    """Split on ``_``/``-`` boundaries, lowercased (insecure token matching)."""
    return [t for t in re.split(r"[_-]+", pid.strip().lower()) if t]


def classify_connection_param(pid: str) -> str | None:
    """Classify an ``other_connection`` id as ``"proxy"`` / ``"insecure"`` / None.

    - proxy: normalized id in :data:`PROXY_SYNONYMS` (exact).
    - insecure: any whole token in :data:`INSECURE_SYNONYMS` (B.4 — avoids the
      ``secure`` ⊂ ``insecure`` substring hazard).
    """
    if _normalize_param_id(pid) in PROXY_SYNONYMS:
        return "proxy"
    if any(tok in INSECURE_SYNONYMS for tok in _tokenize_param_id(pid)):
        return "insecure"
    return None


def _bool_switch_field(
    *,
    field_id: str,
    title: str,
    description: str = "",
) -> dict:
    """Build a non-secret boolean ``switch`` connection field (Part B / D-D8 home 1).

    Carries ``metadata.event.publish: true`` (legal inside a profile) AND
    ``metadata.xsoar.config_type: "backend"`` (backend-managed toggle). Always
    ``default_value: false`` (B-D6), ``mask: false``, optional + visible.
    """
    options: dict[str, Any] = {
        "mask": False,
        "default_value": False,
        "create_modifiers": {"required": False, "hidden": False},
        "edit_modifiers": {"required": False, "hidden": False},
    }
    if description:
        options["description"] = description
    return {
        "id": field_id,
        "title": title,
        "field_type": "switch",
        "metadata": {
            "event": {"publish": True},
            "xsoar": {"config_type": "backend"},
        },
        "options": options,
    }


def _resolve_title(
    yml_params_by_name: dict[str, dict] | None,
    yml_param_name: str,
    fallback: str,
) -> str:
    """Prefer the YML ``display`` for the param, else the fallback."""
    if yml_params_by_name and (yml := yml_params_by_name.get(yml_param_name)):
        display = yml.get("display") or ""
        if str(display).strip():
            return str(display)
    return fallback


def build_proxy_field(
    pid: str, yml_params_by_name: dict[str, dict] | None = None
) -> dict:
    """Build the ``proxy`` switch field (id == original yml id, verbatim)."""
    return _bool_switch_field(
        field_id=pid,
        title=_resolve_title(yml_params_by_name, pid, _PROXY_DEFAULT_TITLE),
        description=_field_description(yml_params_by_name, pid),
    )


def build_insecure_field(
    pid: str, yml_params_by_name: dict[str, dict] | None = None
) -> dict:
    """Build the ``insecure`` switch field (id == original yml id, verbatim)."""
    return _bool_switch_field(
        field_id=pid,
        title=_resolve_title(yml_params_by_name, pid, _INSECURE_DEFAULT_TITLE),
        description=_field_description(yml_params_by_name, pid),
    )


def _field_description(
    yml_params_by_name: dict[str, dict] | None, pid: str
) -> str:
    """Pull ``additionalinfo`` (else empty) for a field's description."""
    if yml_params_by_name and (yml := yml_params_by_name.get(pid)):
        info = yml.get("additionalinfo") or ""
        if str(info).strip():
            return str(info)
    return ""


# ---------------------------------------------------------------------------
# Part C — engine 3-field pattern + carve-out lists + visibility triggers
# ---------------------------------------------------------------------------
# Appendix G — emit NO engine fields AND no proxy. (lowercased for matching)
ENGINE_PROXY_EXCLUDED: frozenset[str] = frozenset(
    s.lower()
    for s in {
        "EDL",
        "ExportIndicators",
        "PingCastle",
        "Publish List",
        "Simple API Proxy",
        "Syslog v2",
        "TAXII Server",
        "TAXII2 Server",
        "Web File Repository",
        "Workday_IAM_Event_Generator",
        "XSOAR-Web-Server",
        "Microsoft Teams",
        "AWS-SNS-Listener",
        "AWS",
        "Azure",
        "GCP",
    }
)

# Appendix H — single-engine: emit engine_mode (2-opt) + engine, NO engine_group.
SINGLE_ENGINE_INTEGRATIONS: frozenset[str] = frozenset(
    s.lower()
    for s in {"saml", "slack", "sharedagent", "syslog", "mattermost", "duo"}
)

# Engine field id stems (prefixed per integration when emitted).
ENGINE_MODE = "engine_mode"
ENGINE = "engine"
ENGINE_GROUP = "engine_group"

# Serializer field_name targets back to the XSOAR param names.
ENGINE_SERIALIZER_TARGETS: dict[str, str] = {
    ENGINE_MODE: "engine_mode",
    ENGINE: "engine",
    ENGINE_GROUP: "engineGroup",  # camelCase XSOAR param name (D-D3)
}

_ENGINE_MODE_VALUES_FULL = [
    {"key": "no_engine", "label": "No engine"},
    {"key": "engine", "label": "Engine"},
    {"key": "engine_group", "label": "Engine Group"},
]
_ENGINE_MODE_VALUES_SINGLE = [
    {"key": "no_engine", "label": "No engine"},
    {"key": "engine", "label": "Engine"},
]


def engine_exclusion_class(integration_id: str) -> str:
    """Return ``"excluded"`` (Appendix G) / ``"single"`` (Appendix H) / ``"full"``.

    G wins over H. Case-insensitive exact match on ``commonfields.id``.
    """
    key = integration_id.strip().lower()
    if key in ENGINE_PROXY_EXCLUDED:
        return "excluded"
    if key in SINGLE_ENGINE_INTEGRATIONS:
        return "single"
    return "full"


def _engine_common_metadata(
    integration_id: str, dynamic_field: str
) -> dict:
    """metadata block for a dynamic engine select: event.publish + backend +
    dynamic_values (engine / engine-group)."""
    return {
        "event": {"publish": True},
        "xsoar": {"config_type": "backend"},
        "dynamic_values": {
            "provider": "xsoar",
            "trigger": ["on_create", "on_edit"],
            "params": {
                "integrationID": integration_id,
                "dynamicField": dynamic_field,
            },
        },
    }


def build_engine_mode_field(field_id: str, *, single_engine: bool) -> dict:
    """Static ``engine_mode`` select (2-option for Appendix H, else 3-option)."""
    values = (
        _ENGINE_MODE_VALUES_SINGLE if single_engine else _ENGINE_MODE_VALUES_FULL
    )
    return {
        "id": field_id,
        "title": "Engine",
        "field_type": "select",
        "metadata": {
            "event": {"publish": True},
            "xsoar": {"config_type": "backend"},
        },
        "options": {
            "mask": False,
            "default_value": "no_engine",
            "values": [dict(v) for v in values],
            "create_modifiers": {"required": True, "hidden": False},
            "edit_modifiers": {"required": True, "hidden": False},
        },
    }


def build_engine_field(field_id: str, integration_id: str) -> dict:
    """Dynamic ``engine`` select (dynamicField: engine)."""
    return {
        "id": field_id,
        "title": "Engine",
        "field_type": "select",
        "metadata": _engine_common_metadata(integration_id, "engine"),
        "options": {
            "mask": False,
            "placeholder": "Select an engine",
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def build_engine_group_field(field_id: str, integration_id: str) -> dict:
    """Dynamic ``engine_group`` select (dynamicField: engine-group)."""
    return {
        "id": field_id,
        "title": "Engine Group",
        "field_type": "select",
        "metadata": _engine_common_metadata(integration_id, "engine-group"),
        "options": {
            "mask": False,
            "placeholder": "Select an engine group",
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def build_engine_triggers(
    *, mode_id: str, engine_id: str | None, engine_group_id: str | None
) -> list[dict]:
    """Visibility triggers: hide ``engine`` unless mode==engine; hide
    ``engine_group`` unless mode==engine_group. References the (possibly
    prefixed) per-profile ids."""
    triggers: list[dict] = []
    if engine_id:
        triggers.append(
            {
                "conditions": {
                    "id": mode_id,
                    "behavior": "value",
                    "operator": "neq",
                    "value": "engine",
                },
                "effects": [{"id": engine_id, "action": {"hidden": True}}],
            }
        )
    if engine_group_id:
        triggers.append(
            {
                "conditions": {
                    "id": mode_id,
                    "behavior": "value",
                    "operator": "neq",
                    "value": "engine_group",
                },
                "effects": [{"id": engine_group_id, "action": {"hidden": True}}],
            }
        )
    return triggers


# ---------------------------------------------------------------------------
# Part C/B — attach per-profile non-auth fields (proxy/insecure/engine)
# ---------------------------------------------------------------------------
# Type for the serializer-bridge callback the caller supplies (so this module
# stays filesystem-free). Signature: (handler_dir, new_id, original_id).
SerializerBridge = Callable[[Path, str, str], None]

# Materializes connectus field dict(s) from one XSOAR yml param dict. Bound to
# ``map_xsoar_param_to_connectus_field`` at call sites. Declared here (above
# ``attach_per_profile_connection_fields``) so per-profile rest-field emission
# can be typed.
FieldMapper = Callable[[dict], list[dict]]


def _maybe_prefixed_id(
    base_id: str,
    integration_prefix: str,
    existing_ids: set[str],
    handler_dir: Path | None,
    serializer_bridge: SerializerBridge | None,
    serializer_target: str | None = None,
) -> str:
    """Return ``base_id`` if free, else ``<prefix>_<base_id>`` + register a
    serializer bridge mapping the prefixed id back to ``serializer_target``
    (defaults to ``base_id``). Mutates ``existing_ids``.

    This is the per-profile collision dedup (C-D4): the first profile keeps the
    bare id; subsequent profiles get a prefixed id + serializer mapping.
    """
    if base_id not in existing_ids:
        existing_ids.add(base_id)
        return base_id
    renamed = f"{integration_prefix}_{base_id}"
    existing_ids.add(renamed)
    if handler_dir is not None and serializer_bridge is not None:
        serializer_bridge(handler_dir, renamed, serializer_target or base_id)
    return renamed


def _materialize_rest_connection_fields(
    pid: str,
    yml_params_by_name: dict[str, dict] | None,
    field_mapper: FieldMapper | None,
) -> list[dict]:
    """Materialize the connectus field(s) for a non-auth "rest" connection
    param (server URL / host / port / region / ...).

    Mirrors the body of the former
    :func:`build_connection_general_configurations`: uses ``field_mapper``
    when the integration YML carries the param, else falls back to a bare
    ``input`` field. The caller is responsible for id-prefixing + serializer
    bridging + ``event`` metadata.
    """
    yml = (yml_params_by_name or {}).get(pid)
    if yml is None or field_mapper is None:
        return [{"id": pid, "field_type": "input", "options": {}}]
    return field_mapper(yml)


def attach_per_profile_connection_fields(
    profiles: list[dict],
    integration_id: str,
    other_connection: list[str],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_dir: Path | None = None,
    serializer_bridge: SerializerBridge | None = None,
    field_mapper: FieldMapper | None = None,
) -> list[dict]:
    """Append the non-auth connection fields into EACH profile (D-D8 home 1).

    Per the "no general_configurations" rule, ALL non-auth connection fields
    live inside each auth profile:
      - the **rest** of ``other_connection`` (server URL / host / port /
        region / ...) — materialized via ``field_mapper`` and emitted FIRST,
      - then ``proxy`` / ``insecure`` switches,
      - then the engine 3-field pattern.

    Every field is duplicated into every profile. A shared ``existing_ids``
    set means the FIRST profile keeps the bare id and every subsequent
    profile gets a ``<prefix>_<id>`` id plus a ``serializer.yaml``
    ``field_mappings`` bridge back to the original XSOAR param name (C-D4).

    Returns the list of engine-visibility triggers (Part C.4) to merge into
    ``triggers.yaml`` — one rule-pair per profile that emitted engine fields.

    Honors Appendix G (no proxy + no engine) and Appendix H (no engine_group).
    """
    excl = engine_exclusion_class(integration_id)
    prefix = _slug_word(integration_id)

    # Classify other_connection: proxy / insecure / engine are special; the
    # REST (host/url/port/region) are generic non-auth fields.
    proxy_ids = [p for p in other_connection if classify_connection_param(p) == "proxy"]
    insecure_ids = [
        p for p in other_connection if classify_connection_param(p) == "insecure"
    ]
    rest_ids = [
        p for p in other_connection if classify_connection_param(p) is None
    ]

    # Track ids already used across profiles for dedup-via-rename.
    existing_ids: set[str] = set()
    all_triggers: list[dict] = []

    for profile in profiles:
        cfgs = profile.setdefault("configurations", [{"fields": []}])
        if not cfgs:
            cfgs.append({"fields": []})
        target_fields = cfgs[0].setdefault("fields", [])

        # --- rest of other_connection (host / url / port / region / ...) ---
        # Emitted FIRST so the server/host fields render at the top of the
        # profile form. Each materialized field is id-prefixed on the 2nd+
        # profile and bridged back to its original XSOAR param name. They
        # carry metadata.event.publish so the handler receives the value in
        # the lifecycle event (they have no auth tag, so this is schema-valid).
        for pid in rest_ids:
            for raw in _materialize_rest_connection_fields(
                pid, yml_params_by_name, field_mapper
            ):
                original_id = raw.get("id", pid)
                field = dict(raw)
                fid = _maybe_prefixed_id(
                    original_id,
                    prefix,
                    existing_ids,
                    handler_dir,
                    serializer_bridge,
                    original_id,
                )
                field["id"] = fid
                options = field.setdefault("options", {})
                options.setdefault("mask", False)
                metadata = field.setdefault("metadata", {})
                metadata.setdefault("event", {"publish": True})
                target_fields.append(field)

        # --- proxy (skip entirely for Appendix G) ---
        if excl != "excluded":
            for pid in proxy_ids:
                fid = _maybe_prefixed_id(
                    pid, prefix, existing_ids, handler_dir, serializer_bridge, pid
                )
                field = build_proxy_field(pid, yml_params_by_name)
                field["id"] = fid
                target_fields.append(field)

        # --- insecure (always, per Part B; Appendix G does NOT skip it) ---
        for pid in insecure_ids:
            fid = _maybe_prefixed_id(
                pid, prefix, existing_ids, handler_dir, serializer_bridge, pid
            )
            field = build_insecure_field(pid, yml_params_by_name)
            field["id"] = fid
            target_fields.append(field)

        # --- engine 3-field (skip for Appendix G; no engine_group for H) ---
        if excl == "excluded":
            continue

        mode_fid = _maybe_prefixed_id(
            ENGINE_MODE, prefix, existing_ids, handler_dir, serializer_bridge,
            ENGINE_SERIALIZER_TARGETS[ENGINE_MODE],
        )
        engine_fid = _maybe_prefixed_id(
            ENGINE, prefix, existing_ids, handler_dir, serializer_bridge,
            ENGINE_SERIALIZER_TARGETS[ENGINE],
        )
        single = excl == "single"
        target_fields.append(
            build_engine_mode_field(mode_fid, single_engine=single)
        )
        target_fields.append(build_engine_field(engine_fid, integration_id))

        group_fid: str | None = None
        if not single:
            group_fid = _maybe_prefixed_id(
                ENGINE_GROUP, prefix, existing_ids, handler_dir,
                serializer_bridge, ENGINE_SERIALIZER_TARGETS[ENGINE_GROUP],
            )
            target_fields.append(
                build_engine_group_field(group_fid, integration_id)
            )

        all_triggers.extend(
            build_engine_triggers(
                mode_id=mode_fid, engine_id=engine_fid, engine_group_id=group_fid
            )
        )

    return all_triggers


# ---------------------------------------------------------------------------
# Part D — view_groups registry + general_configurations (rest of other_connection)
# ---------------------------------------------------------------------------
def slugify_view_group_id(integration_id: str) -> str:
    """Tile id for an integration (lowercase, dashes)."""
    s = integration_id.strip().lower()
    s = re.sub(r"[^a-z0-9-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


def integration_field_prefix(integration_id: str) -> str:
    """Field-id prefix for an integration (lowercase, no separators)."""
    return _slug_word(integration_id).replace("_", "")


def build_view_groups_registry(
    integrations: list[tuple[str, str]],
) -> list[dict]:
    """Build the ``view_groups`` registry — one ``{id,label,help_text}`` per
    integration. ``integrations`` is a list of ``(integration_id, display)``.
    """
    registry: list[dict] = []
    for integration_id, display in integrations:
        tile = slugify_view_group_id(integration_id)
        label = display or integration_id
        registry.append(
            {
                "id": tile,
                "label": label,
                "help_text": (
                    f"Connection settings for the {label} integration."
                ),
            }
        )
    return registry


def build_connection_yaml(
    auth_methods: dict,
    integration_id: str,
    connector_title: str = "",
    yml_params_by_name: dict[str, dict] | None = None,
    field_mapper: FieldMapper | None = None,
    handler_dir: Path | None = None,
    serializer_bridge: SerializerBridge | None = None,
    integration_display: str = "",
) -> tuple[dict, list[dict]]:
    """Assemble the full ``connection.yaml`` dict for a single-integration
    (one-tile) grouped connector, plus the engine-visibility triggers.

    Returns ``(connection_dict, triggers)``. Raises ``ValueError`` when
    ``auth_types`` is empty (D9 — never-expected for this generator).
    """
    auth_types = auth_methods.get("auth_types") or []
    if not auth_types:
        raise ValueError(
            f"connection.yaml for '{integration_id}': auth_types is empty. "
            f"At least one auth profile was expected (NoneRequired is out of "
            f"scope for this generator)."
        )
    other_connection = list(auth_methods.get("other_connection") or [])

    # Part A — auth-only profiles.
    seen_profile_ids: set[str] = set()
    profiles = [
        build_connection_profile(
            entry,
            integration_id,
            connector_title=connector_title,
            yml_params_by_name=yml_params_by_name,
            seen_profile_ids=seen_profile_ids,
        )
        for entry in auth_types
    ]

    # Part B/C/D — attach ALL non-auth connection fields per profile: the rest
    # of other_connection (host/url/port) first, then proxy/insecure, then the
    # engine 3-field pattern. connection.yaml intentionally has NO
    # general_configurations — every non-auth field is duplicated into each
    # profile (id-prefixed + serializer-bridged on the 2nd+ profile).
    triggers = attach_per_profile_connection_fields(
        profiles,
        integration_id,
        other_connection,
        yml_params_by_name=yml_params_by_name,
        handler_dir=handler_dir,
        serializer_bridge=serializer_bridge,
        field_mapper=field_mapper,
    )

    connection: dict[str, Any] = {
        "metadata": {
            "title": "Connection",
            "description": (
                "Enter the credentials to securely authorize the connection"
            ),
        },
        "view_groups": build_view_groups_registry(
            [(integration_id, integration_display or connector_title)]
        ),
        "profiles": profiles,
    }

    return connection, triggers


def merge_connection_data(
    existing: dict,
    new_connection: dict,
) -> dict:
    """Merge the new handler's connection dict (delta) into an existing
    ``connection.yaml`` dict for the append path.

    Strategy 1 (per user direction): the append case only adds the new
    handler's auth profiles, its view-group(s) and its
    general_configurations rows — everything else (top-level metadata,
    prior profiles/view_groups) is owned by the from-scratch path and is
    left untouched.

    Mutates and returns ``existing``:
      - ``profiles[]``: append new profiles whose ``id`` is not already
        present (skip duplicates).
      - ``view_groups[]``: union by ``id`` (skip duplicates).
      - ``general_configurations.configurations[]``: append the new
        handler's configuration block(s).
      - ``metadata``: only seeded from ``new_connection`` when the existing
        file had none (e.g. first-ever connection.yaml on this connector).

    Field-id collisions across profiles are handled upstream by
    :func:`build_connection_yaml` via the serializer bridge (the new
    handler's profile field ids were already deduped against
    ``existing`` because the caller threads ``connection_data`` through
    :func:`collect_existing_field_ids` before building).
    """
    if not existing.get("metadata") and new_connection.get("metadata"):
        existing["metadata"] = new_connection["metadata"]

    # Profiles — append, skip duplicate ids.
    existing_profiles = existing.setdefault("profiles", [])
    existing_profile_ids = {p.get("id") for p in existing_profiles}
    for profile in new_connection.get("profiles", []) or []:
        if profile.get("id") in existing_profile_ids:
            continue
        existing_profiles.append(profile)
        existing_profile_ids.add(profile.get("id"))

    # View-groups — union by id.
    new_vgs = new_connection.get("view_groups", []) or []
    if new_vgs:
        existing_vgs = existing.setdefault("view_groups", [])
        existing_vg_ids = {vg.get("id") for vg in existing_vgs}
        for vg in new_vgs:
            if vg.get("id") in existing_vg_ids:
                continue
            existing_vgs.append(vg)
            existing_vg_ids.add(vg.get("id"))

    # connection.yaml intentionally has NO general_configurations — every
    # non-auth connection field lives inside each auth profile (emitted by
    # attach_per_profile_connection_fields). Nothing to merge here.

    return existing


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
    vendor: str = "",
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

    # Generate connector.yaml. vendor (when supplied) drives id/title
    # derivation + description; categories come from the pack metadata
    # (schema requires >=1 — flag when none are found).
    pack_tags = get_pack_tags(integration_path)
    pack_categories = get_pack_categories(integration_path)
    if vendor and not pack_categories:
        logger.warning(
            "[manifest_generator] No categories found in pack_metadata.json for "
            f"{integration_path}; connector.yaml metadata.categories will be empty, "
            "which FAILS connector.schema (minItems: 1). Flag for manual review."
        )
    connector_data = build_connector_yaml(
        connector_title,
        pack_tags,
        author_image_filename=author_image_filename,
        vendor=vendor,
        mapped_params=mapped_params,
        categories=pack_categories,
    )
    connector_data = deep_merge_dicts(connector_data, manual_connector_fields or {})
    connector_yaml_path = connector_dir / "connector.yaml"
    with open(connector_yaml_path, "w") as fh:
        fh.write(CONNECTOR_SCHEMA_DIRECTIVE)
        _dump_yaml(connector_data, fh)
    logger.info(f"[manifest_generator] Generated {connector_yaml_path}")

    # Generate handler.yaml for this integration. Pack id is sourced
    # from the integration path (per AGENTS.md pack-tree layout) and
    # threaded through to populate triggering.labels.xsoar-pack-id per
    # guide §3.8.
    pack_id = get_pack_id(integration_path)
    handler_data = build_handler_yaml(
        integration_yml,
        connector_title,
        pack_tags,
        mapped_params,
        auth_methods,
        pack_id=pack_id,
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
        fh.write(SUMMARY_SCHEMA_DIRECTIVE)
        _dump_yaml(summary_data, fh)
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

    # Generate capabilities.yaml. supported_modules drives each
    # capability's config.required_license (guide §3.4).
    supported_modules = get_supported_modules(integration_yml, integration_path)
    capabilities_data = build_capabilities_yaml(
        mapped_params,
        yml_params_by_name=yml_params_by_name,
        handler_id=handler_id,
        handler_dir=handler_dir,
        existing_ids=existing_field_ids,
        supported_modules=supported_modules,
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

    # Per-handler general_configurations: add integrationLogLevel +
    # defaultIgnore fields in a view_group-pinned field group. Also
    # register the view_groups registry entry.
    per_handler_gc = build_per_handler_general_config(
        handler_id,
        handler_dir,
        mapped_params=mapped_params,
        yml_params_by_name=yml_params_by_name,
        existing_ids=existing_field_ids,
    )
    configurations_data.setdefault("general_configurations", {}).setdefault(
        "configurations", []
    ).append(per_handler_gc)
    configurations_data.setdefault("view_groups", []).append(
        {"id": handler_id, "label": handler_id}
    )

    configurations_data = deep_merge_dicts(
        configurations_data, manual_configurations_fields or {}
    )
    configurations_yaml_path = connector_dir / "configurations.yaml"
    with open(configurations_yaml_path, "w") as fh:
        yaml.safe_dump(configurations_data, fh)
    logger.info(f"[manifest_generator] Generated {configurations_yaml_path}")

    # Per Batch 7 (Part A.7.1) + guide §3.9: serializer.yaml is OPTIONAL
    # and is only emitted when at least one field_mappings entry exists
    # (the dedup step writes it on-demand via
    # :func:`register_serializer_entry`). The previous behavior of
    # writing a 1-line "# TODO: serializer config" stub for every
    # handler violated serializer.schema's ``anyOf`` (requires
    # field_mappings OR computed_fields with ≥1 item).
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    if serializer_yaml_path.exists():
        logger.info(
            f"[manifest_generator] Serializer.yaml present at "
            f"{serializer_yaml_path} (populated by dedup step)"
        )
    else:
        logger.info(
            f"[manifest_generator] No dedup collisions for handler — "
            f"serializer.yaml not generated (optional per guide §3.9)."
        )

    # Collect triggers from capability builders and write triggers.yaml
    # when at least one trigger exists.
    all_triggers: list[dict] = []

    # Invoke the indicators capability builder when the TI&E bucket is
    # present in mapped_params.
    ti_bucket_key = "Threat Intelligence & Enrichment"
    if ti_bucket_key in mapped_params:
        ti_result = add_indicators_capability(
            capability_id=slugify_capability_name(ti_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
        )
        all_triggers.extend(ti_result.get("triggers", []))

    # Invoke the fetch-issues capability builder when the Fetch Issues
    # bucket is present in mapped_params.
    fi_bucket_key = "Fetch Issues"
    if fi_bucket_key in mapped_params:
        script = integration_yml.get("script") or {}
        fi_is_long_running = script.get("longRunning") is True
        fi_result = add_fetch_issues_capability(
            capability_id=slugify_capability_name(fi_bucket_key),
            is_sub_capability=False,
            is_long_running=fi_is_long_running,
            mapped_params=mapped_params,
            integration_yml=integration_yml,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
        )
        all_triggers.extend(fi_result.get("triggers", []))

    # Generate connection.yaml (Parts A–D) — profiles from auth_types,
    # per-profile proxy/insecure/engine (event.publish), and a
    # general_configurations block for the rest of other_connection. The
    # field_mapper reuses the existing param→field materializer and the
    # serializer_bridge reuses the existing serializer registration so
    # cross-file field-id collisions are renamed + bridged. Engine
    # visibility triggers are folded into the connector's single
    # triggers.yaml.
    #
    # connection.yaml is OPTIONAL (README "connection.yaml is optional"):
    # when there are no auth_types the connector is anonymous (handler uses
    # the auth='none' shape) and no connection.yaml is emitted. This mirrors
    # :func:`build_handler_yaml`'s anonymous branch.
    if auth_methods.get("auth_types"):
        integration_id = integration_yml.get("commonfields", {}).get("id", "")
        integration_display = integration_yml.get("display", "")
        connection_data, engine_triggers = build_connection_yaml(
            auth_methods,
            integration_id,
            connector_title=connector_title,
            yml_params_by_name=yml_params_by_name,
            field_mapper=map_xsoar_param_to_connectus_field,
            handler_dir=handler_dir,
            serializer_bridge=register_serializer_entry,
            integration_display=integration_display,
        )
        all_triggers.extend(engine_triggers)
        connection_data = deep_merge_dicts(
            connection_data, manual_connection_fields or {}
        )
        connection_yaml_path = connector_dir / "connection.yaml"
        write_connection_yaml(connection_yaml_path, connection_data)
        logger.info(f"[manifest_generator] Generated {connection_yaml_path}")
    else:
        logger.info(
            "[manifest_generator] No auth_types — anonymous connector; "
            "connection.yaml not generated (optional per schema)."
        )

    if all_triggers:
        triggers_data = build_triggers_yaml(all_triggers)
        triggers_yaml_path = connector_dir / "triggers.yaml"
        write_triggers_yaml(triggers_yaml_path, triggers_data)
        logger.info(f"[manifest_generator] Generated {triggers_yaml_path}")


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
        fh.write(CONNECTOR_SCHEMA_DIRECTIVE)
        _dump_yaml(connector_data, fh)
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

    # Generate handler.yaml for this new integration (with sub-cap-aware
    # ids). Pack id from the integration path → triggering.labels.xsoar-pack-id.
    pack_id = get_pack_id(integration_path)
    handler_data = build_handler_yaml(
        integration_yml,
        connector_title,
        pack_tags,
        mapped_params,
        auth_methods,
        cap_name_to_handler_cap_id=cap_name_to_handler_cap_id,
        pack_id=pack_id,
    )
    handler_data = deep_merge_dicts(handler_data, manual_handler_fields or {})
    write_handler_yaml(handler_yaml_path, handler_data)
    logger.info(f"[manifest_generator] Generated {handler_yaml_path}")

    # Per-handler general_configurations: add integrationLogLevel +
    # defaultIgnore fields in a view_group-pinned field group. Also
    # register the view_groups registry entry (dedup: skip if already
    # present from a prior handler addition).
    new_handler_dir = handler_yaml_path.parent
    per_handler_gc = build_per_handler_general_config(
        new_handler_id,
        new_handler_dir,
        mapped_params=mapped_params,
        yml_params_by_name=yml_params_by_name,
        existing_ids=existing_field_ids,
    )
    configurations_data.setdefault("general_configurations", {}).setdefault(
        "configurations", []
    ).append(per_handler_gc)
    existing_vg_ids = {
        vg.get("id")
        for vg in configurations_data.get("view_groups", [])
    }
    if new_handler_id not in existing_vg_ids:
        configurations_data.setdefault("view_groups", []).append(
            {"id": new_handler_id, "label": new_handler_id}
        )

    # Per Batch 7 (Part A.7.1) + guide §3.9: serializer.yaml is OPTIONAL.
    # The dedup pass writes it on-demand when collision-rename produces
    # a field_mappings entry. The per-handler general_config above also
    # writes serializer entries (for integrationLogLevel + defaultIgnore).
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    if serializer_yaml_path.exists():
        logger.info(
            f"[manifest_generator] Serializer.yaml present at "
            f"{serializer_yaml_path} (populated by dedup step)"
        )
    else:
        logger.info(
            f"[manifest_generator] No dedup collisions for handler — "
            f"serializer.yaml not generated (optional per guide §3.9)."
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

    # Collect triggers from capability builders and write triggers.yaml
    # when at least one trigger exists.
    all_triggers: list[dict] = []

    # Invoke the indicators capability builder when the TI&E bucket is
    # present in mapped_params.
    ti_bucket_key = "Threat Intelligence & Enrichment"
    if ti_bucket_key in mapped_params:
        ti_result = add_indicators_capability(
            capability_id=slugify_capability_name(ti_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
        )
        all_triggers.extend(ti_result.get("triggers", []))

    # Invoke the fetch-issues capability builder when the Fetch Issues
    # bucket is present in mapped_params.
    fi_bucket_key = "Fetch Issues"
    if fi_bucket_key in mapped_params:
        script = integration_yml.get("script") or {}
        fi_is_long_running = script.get("longRunning") is True
        fi_result = add_fetch_issues_capability(
            capability_id=slugify_capability_name(fi_bucket_key),
            is_sub_capability=False,
            is_long_running=fi_is_long_running,
            mapped_params=mapped_params,
            integration_yml=integration_yml,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
        )
        all_triggers.extend(fi_result.get("triggers", []))

    # Build the NEW handler's connection delta (Parts A–D) and merge it into
    # the existing connection.yaml: append new auth profiles, union the new
    # view-group, and append the new general_configurations rows. The new
    # handler's profile/general-config field ids were already deduped against
    # the prior connection.yaml because ``connection_data`` was threaded
    # through :func:`collect_existing_field_ids` above; the serializer_bridge
    # registers field_mappings for any renamed ids. Engine visibility
    # triggers are folded into ``all_triggers`` before the merge-write below.
    #
    # When the new handler is anonymous (no auth_types) it contributes no
    # connection profiles; connection.yaml is left untouched (and not
    # created when it did not already exist), mirroring the from-scratch
    # anonymous branch.
    if auth_methods.get("auth_types"):
        integration_id = integration_yml.get("commonfields", {}).get("id", "")
        integration_display = integration_yml.get("display", "")
        new_connection, engine_triggers = build_connection_yaml(
            auth_methods,
            integration_id,
            connector_title=connector_title,
            yml_params_by_name=yml_params_by_name,
            field_mapper=map_xsoar_param_to_connectus_field,
            handler_dir=new_handler_dir,
            serializer_bridge=register_serializer_entry,
            integration_display=integration_display,
        )
        all_triggers.extend(engine_triggers)
        merge_connection_data(connection_data, new_connection)
        connection_data = deep_merge_dicts(
            connection_data, manual_connection_fields or {}
        )
        write_connection_yaml(connection_yaml_path, connection_data)
        logger.info(f"[manifest_generator] Updated {connection_yaml_path}")
    else:
        logger.info(
            "[manifest_generator] New handler is anonymous (no auth_types) — "
            "connection.yaml left untouched."
        )

    if all_triggers:
        triggers_data = build_triggers_yaml(all_triggers)
        triggers_yaml_path = connector_dir / "triggers.yaml"
        # For the append path, merge with existing triggers if present.
        if triggers_yaml_path.is_file():
            with open(triggers_yaml_path) as fh:
                first_line = fh.readline()
                rest = fh.read()
                if not first_line.startswith("# yaml-language-server"):
                    rest = first_line + rest
            existing_triggers_data = yaml.safe_load(io.StringIO(rest)) or {}
            existing_list = existing_triggers_data.get("triggers", []) or []
            triggers_data["triggers"] = existing_list + triggers_data["triggers"]
        write_triggers_yaml(triggers_yaml_path, triggers_data)
        logger.info(f"[manifest_generator] Updated {triggers_yaml_path}")


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
    vendor: str = typer.Option(
        "",
        "--vendor",
        help=(
            "Vendor name (e.g. 'Microsoft Graph', 'Okta'). Drives "
            "connector.yaml metadata.vendor, the description "
            "('integration for <vendor> products.'), and the id/title "
            "capability-suffix derivation (guide §3.3.1). From-scratch "
            "path only. When omitted, the legacy stub id/title/description "
            "are emitted."
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
            vendor=vendor,
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
