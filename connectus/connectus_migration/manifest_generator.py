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

import copy
import io
import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any
from collections.abc import Callable

import sys

import typer
import yaml

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import find_repo_root, load_env  # noqa: E402

logger = logging.getLogger(__name__)

# Env var (read from the canonical root .env) that overrides where connector
# folders are written. Mirrors ``workflow_state.gates._connectus_repo_root``
# so generation and the later ``make validate`` gate agree on the repo root.
_CONNECTUS_REPO_ENV = "CONNECTUS_REPO_DIR"
_CONNECTUS_REPO_DIRNAME = "unified-connectors-content"


def resolve_connectors_root(explicit: Path | None) -> Path:
    """Resolve the connectors root directory.

    Resolution order (call ``load_env()`` before this so $CONNECTUS_REPO_DIR
    from the canonical root .env is visible):

    1. ``explicit`` if the caller passed ``--connectors-root`` (wins).
    2. ``$CONNECTUS_REPO_DIR/connectors`` when the env var is set.
    3. ``<content-repo>/unified-connectors-content/connectors`` (the
       historical default).
    """
    if explicit is not None:
        return explicit
    override = os.environ.get(_CONNECTUS_REPO_ENV)
    if override and override.strip():
        return Path(os.path.abspath(override.strip())) / "connectors"
    return find_repo_root() / _CONNECTUS_REPO_DIRNAME / "connectors"

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

# ---------------------------------------------------------------------------
# Fetch mutex (per guide 3.4 note 7 + 3.5)
# ---------------------------------------------------------------------------
# A single handler (== one integration) cannot enable more than one of its
# OWN fetch capabilities at a time. The mutex covers all five fetch
# capabilities. When one of the handler's fetch sub-capabilities is
# selected, every OTHER fetch sub-capability of the SAME handler is marked
# ``read_only: true`` so the user can pick only one.
#
# Scope is PER-HANDLER: we only ever pair fetch sub-capabilities that belong
# to the same handler (e.g. ``log-collection_<handler>`` <-> ``fetch-issues_<handler>``).
# We never pair across handlers, and never pair two sub-capabilities of the
# same capability family (a handler maps each fetch family to exactly one
# sub-capability).
_FETCH_MUTEX_MESSAGE = "Select only one fetch option."

# ---------------------------------------------------------------------------
# Collection → automation auto-enable + lock (per guide §3.5.1)
# ---------------------------------------------------------------------------
# Every fetch (collection) sub-capability a handler contributes MUST
# auto-enable AND lock that handler's ``automation-and-remediation``
# sub-capability — every fetch type also needs automation. When any of the
# handler's collection sub-capabilities is selected, the automation sub-cap is
# turned ON (``enabled: true``) and locked (``read_only: true``) so the user
# cannot clear it while the dependency is active. The effect is reversible
# (guide §2.10): when no collection sub-cap is selected the lock/auto-enable
# are lifted. Message text is verbatim from guide §3.5.1.
_COLLECTION_AUTOMATION_MESSAGE = (
    "A selected capability enables this setting. "
    "Clear the active dependency to disable it"
)
CONNECTOR_TO_AUTHOR_IMAGE_PATH = Path(__file__).resolve().parent / "connector_to_author_image.json"

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
    return title.strip().lower().replace(" ", "-").replace("---", "-")


def connector_exists_and_valid(connector_dir: Path) -> bool:
    """Return True if ``connector_dir`` looks like an already-initialized connector.

    A directory counts as an existing connector only when it both exists and
    contains a ``connector.yaml`` file at its root. This avoids treating empty
    or partially-created directories as existing connectors.
    """
    existing_connector_path = connector_dir / "connector.yaml"
    if connector_dir.is_dir() and (existing_connector_path).is_file():
        with open(existing_connector_path) as fh:
            yml = yaml.safe_load(fh) or {}
            if yml.get("metadata", {}).get("ownership", {}).get("team", "") != "xsoar":
                raise Exception("There's already exist a non-xsoar connector with this id.")
        return True
    return False


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


# ---------------------------------------------------------------------------
# Connector id / title similarity guard (from-scratch flow)
# ---------------------------------------------------------------------------
def _normalize_for_similarity(value: str) -> str:
    """Normalize an id/title for similarity comparison.

    Lowercases the value and removes ALL whitespace so the comparison is
    case-insensitive and space-insensitive (e.g. ``"Palo Alto"`` and
    ``"paloalto"`` normalize to the same ``"paloalto"``).
    """
    return re.sub(r"\s+", "", (value or "").lower())


def iterate_existing_connector_id_titles(
    connectors_root: Path, skip_dir: Path | None = None
):
    """Yield ``(connector_path, existing_id, existing_title)`` for each
    initialized connector under ``connectors_root``.

    Walks ``<connectors_root>/*/connector.yaml``. The new connector's own
    target directory (``skip_dir``) is skipped so a connector never matches
    against itself. Connectors whose ``connector.yaml`` cannot be parsed are
    skipped with a warning. ``existing_id`` comes from the top-level ``id``
    key; ``existing_title`` from ``metadata.title`` — either may be an empty
    string when absent.
    """
    if not connectors_root.is_dir():
        return
    skip_resolved = skip_dir.resolve() if skip_dir is not None else None
    for connector_yaml_path in sorted(connectors_root.glob("*/connector.yaml")):
        connector_dir = connector_yaml_path.parent
        if skip_resolved is not None and connector_dir.resolve() == skip_resolved:
            continue
        try:
            with open(connector_yaml_path) as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as exc:
            logger.warning(
                f"[manifest_generator] Failed to parse {connector_yaml_path} "
                f"during similarity check: {exc}; skipping."
            )
            continue
        existing_id = data.get("id") or ""
        existing_title = (data.get("metadata") or {}).get("title") or ""
        yield connector_dir, existing_id, existing_title


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
      - settings.skip_cut_off_check: True (emitted for every generated
        connector).
      - metadata.domain: always "" (out of scope for grouped connectors).

    Vendor-driven fields (per user decision on review point 1):
      - ``vendor`` populates ``metadata.vendor`` verbatim.
      - ``metadata.description`` = ``"integrate with <vendor> products."``.
      - ``id`` and ``metadata.title`` are derived via
        :func:`derive_connector_id_and_title` (vendor prefix + capability
        suffix) when both ``vendor`` and ``mapped_params`` are supplied.
        Otherwise they fall back to the legacy stub form (slug/title of
        ``connector_title``) so existing callers keep working.
      - ``metadata.categories`` is the caller-provided ``categories`` list
        (schema requires ≥1 entry — callers that cannot source any should
        flag for manual review; this builder leaves the list as-is).
    """
    connector_id, metadata_title = title_to_slug(connector_title), connector_title

    description = f"integrate with {vendor} products." if vendor else ""

    return {
        "id": connector_id,
        "enabled": True,
        "metadata": {
            "title": metadata_title,
            "description": description,
            "version": "1.0.0",
            "categories": list(categories or []),
            "tags": list(pack_tags),
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
            "grouped": True,
            "skip_cut_off_check": True,
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
    slug = slug.replace("---", "-")
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

# Mapper bucket keys that map to a *fetch* (collection) capability. Used by the
# fetch-mutex logic (guide §3.4 note 7 + §3.5) to decide which of a handler's
# capability buckets participate in the mutex. Derived from
# ``CANONICAL_CAPABILITY_IDS`` ∩ ``_COLLECTION_CAP_IDS`` so it stays in lockstep
# when a new fetch family is added.
_FETCH_MUTEX_BUCKET_KEYS: frozenset[str] = frozenset(
    bucket_key
    for bucket_key, cap_id in CANONICAL_CAPABILITY_IDS.items()
    if cap_id in _COLLECTION_CAP_IDS
)

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

# ---------------------------------------------------------------------------
# Sub-capability -> licenses lookup (single source of truth)
# ---------------------------------------------------------------------------
# Licenses are resolved per sub-capability from
# ``sub_capabilities_to_licenses.json`` (keyed by sub_capability_id). A
# capability's ``config.required_license`` is the deduped UNION of the
# licenses of every sub-capability registered under it. This file is the
# single source of truth — there is no ``supportedModules`` fallback and no
# agentix/xsiam post-filtering.
# The path defaults to the production registry next to this module, but can be
# overridden via the ``CONNECTUS_SUB_CAPABILITIES_TO_LICENSES_PATH`` environment
# variable. The override exists so the e2e (golden-file) suite — which runs this
# generator as a subprocess — can point at a per-case fixture registry instead
# of mutating the shared production file.
SUB_CAPABILITIES_TO_LICENSES_PATH = Path(
    os.environ.get("CONNECTUS_SUB_CAPABILITIES_TO_LICENSES_PATH")
    or (Path(__file__).resolve().parent / "sub_capabilities_to_licenses.json")
)

# Module-level cache of the parsed JSON so we don't re-read the file on every
# capability. Populated lazily by :func:`_load_sub_capability_licenses`.
_SUB_CAPABILITY_LICENSES_CACHE: dict[str, list[str]] | None = None


def _load_sub_capability_licenses() -> dict[str, list[str]]:
    """Load and cache the sub-capability -> licenses mapping.

    Reads :data:`SUB_CAPABILITIES_TO_LICENSES_PATH` once and caches the
    parsed dict for subsequent calls. The JSON maps each sub_capability_id
    (e.g. ``"automation-and-remediation_absolute"``) to its list of license
    strings.

    Raises:
        RuntimeError: if the file is missing or does not decode to a JSON
            object (the migration cannot resolve licenses without it).
    """
    global _SUB_CAPABILITY_LICENSES_CACHE
    if _SUB_CAPABILITY_LICENSES_CACHE is not None:
        return _SUB_CAPABILITY_LICENSES_CACHE
    if not SUB_CAPABILITIES_TO_LICENSES_PATH.is_file():
        raise RuntimeError(
            f"Sub-capability licenses file not found at "
            f"{SUB_CAPABILITIES_TO_LICENSES_PATH}; cannot resolve "
            f"config.required_license."
        )
    try:
        with open(SUB_CAPABILITIES_TO_LICENSES_PATH) as fh:
            data = json.load(fh)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to parse sub-capability licenses file at "
            f"{SUB_CAPABILITIES_TO_LICENSES_PATH}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"Sub-capability licenses file at "
            f"{SUB_CAPABILITIES_TO_LICENSES_PATH} must decode to a JSON "
            f"object mapping sub_capability_id -> list[str]."
        )
    _SUB_CAPABILITY_LICENSES_CACHE = data
    return data


def _load_connector_id_image() -> dict[str, str]:
    """Load and cache the sub-capability -> licenses mapping.

    Reads :data:`CONNECTOR_TO_AUTHOR_IMAGE_PATH` once and caches the
    parsed dict for subsequent calls. The JSON maps each sub_capability_id
    (e.g. ``"automation-and-remediation_absolute"``) to its list of license
    strings.

    Raises:
        RuntimeError: if the file is missing or does not decode to a JSON
            object (the migration cannot resolve licenses without it).
    """
    global _SUB_CAPABILITY_LICENSES_CACHE
    if _SUB_CAPABILITY_LICENSES_CACHE is not None:
        return _SUB_CAPABILITY_LICENSES_CACHE
    if not CONNECTOR_TO_AUTHOR_IMAGE_PATH.is_file():
        raise RuntimeError(
            f"Sub-capability licenses file not found at "
            f"{CONNECTOR_TO_AUTHOR_IMAGE_PATH}; cannot resolve "
            f"config.required_license."
        )
    try:
        with open(CONNECTOR_TO_AUTHOR_IMAGE_PATH) as fh:
            data = json.load(fh)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to parse sub-capability licenses file at "
            f"{CONNECTOR_TO_AUTHOR_IMAGE_PATH}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"Sub-capability licenses file at "
            f"{CONNECTOR_TO_AUTHOR_IMAGE_PATH} must decode to a JSON "
            f"object mapping sub_capability_id -> list[str]."
        )
    return data


def licenses_for_sub_capability(sub_cap_id: str) -> list[str]:
    """Return the list of licenses registered for ``sub_cap_id``.

    Looks the sub-capability id up in
    ``sub_capabilities_to_licenses.json``.

    Raises:
        RuntimeError: if ``sub_cap_id`` is not present in the JSON. Per the
            license design, every sub-capability that reaches the manifest
            MUST have an explicit license entry — a missing id is a hard
            failure rather than a silent empty list.
    """
    table = _load_sub_capability_licenses()
    if sub_cap_id not in table:
        raise RuntimeError(
            f"Sub-capability id '{sub_cap_id}' not found in "
            f"{SUB_CAPABILITIES_TO_LICENSES_PATH}. Every sub-capability "
            f"must have an explicit license entry; regenerate the licenses "
            f"file (see license_aggregator.py) to add it."
        )
    return list(table[sub_cap_id])


def union_licenses_for_sub_caps(sub_cap_ids: list[str]) -> list[str]:
    """Return the deduped union of licenses across the given sub-cap ids.

    The result is the set union of every sub-capability's licenses
    (resolved via :func:`licenses_for_sub_capability`), deduped and
    returned as a list. Order is not significant; we sort for a
    deterministic, review-friendly output.

    Raises:
        RuntimeError: propagated from :func:`licenses_for_sub_capability`
            when any id is missing from the JSON.
    """
    unioned: set[str] = set()
    for sub_cap_id in sub_cap_ids:
        unioned.update(licenses_for_sub_capability(sub_cap_id))
    return sorted(unioned)

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
    },
    "fetch-issues": {
        "type": "reset_incidents_last_run",
    },
    "threat-intelligence-and-enrichment": {
        "type": "reset_feed_last_run",
    },
    "log-collection": {
        "type": "reset_events_last_run",
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


def handler_id_to_integration_slug(handler_id: str) -> str:
    """Recover the integration-id slug from a handler id.

    A handler id is ``"xsoar-" + <integration-id-slug>`` (see
    :func:`derive_handler_id`), where the slug is the integration's
    ``commonfields.id`` lowercased with internal whitespace runs collapsed
    to single dashes. This strips the leading ``"xsoar-"`` prefix to recover
    that slug, which is used to build the sub-capability id per the
    ``<capability_id>_<integration-id-slug>`` convention.

    Examples:
        handler_id_to_integration_slug("xsoar-salesforce") → "salesforce"
        handler_id_to_integration_slug("xsoar-hello-world-iam")
            → "hello-world-iam"
    """
    prefix = "xsoar-"
    if handler_id.startswith(prefix):
        return handler_id[len(prefix):]
    return handler_id


def make_sub_capability_id(handler_id: str, cap_name: str) -> str:
    """Compute the sub-capability id for a (handler, capability-family) pair.

    Format is ``"<capability_id>_<integration-id-slug>"`` where
    ``capability_id`` is the canonical capability id
    (:func:`slugify_capability_name`) and ``integration-id-slug`` is the
    integration's ``commonfields.id`` lowercased with spaces replaced by
    dashes (recovered from ``handler_id`` via
    :func:`handler_id_to_integration_slug`).

    Example: ``Hello World IAM`` integration in the
    ``automation-and-remediation`` capability →
    ``automation-and-remediation_hello-world-iam``.

    This is the single source of truth for sub-cap id derivation, used by
    both the from-scratch path and the append path so a connector is
    *always* modelled as parent-capability + sub-capability (never a flat
    top-level capability).
    """
    cap_slug = slugify_capability_name(cap_name)
    integration_slug = handler_id_to_integration_slug(handler_id)
    return f"{cap_slug}_{integration_slug}"


def build_sub_capability_entry(
    sub_cap_id: str,
    cap_name: str,
    required: bool = False,
    integration_name: str = "",
) -> dict:
    """Build a schema-complete ``SubCapability`` entry.

    capabilities.schema requires ``id`` + ``title`` + ``default_enabled`` +
    ``required`` on every sub-capability.

    The ``title`` is the integration's display ``name`` (the ``name`` field
    from the integration YAML, e.g. ``"Salesforce IAM"``) — each
    sub-capability is named after the integration whose handler exposes it.
    When ``integration_name`` is not supplied (legacy callers) the title
    falls back to the canonical capability family title so existing behaviour
    is preserved.

    Per guide §3.4: ``default_enabled`` is **always False** on a
    sub-capability (the user opts in explicitly). Per guide §3.1 item 13:
    when a capability has exactly ONE sub-capability it must be marked
    ``required: true`` (so selecting the parent implies the lone sub-cap);
    callers pass ``required=True`` in that case.
    """
    cap_slug = slugify_capability_name(cap_name)
    title = integration_name or CANONICAL_CAPABILITY_TITLES[cap_slug]
    return {
        "id": sub_cap_id,
        "title": title,
        "default_enabled": False,
        "required": required,
        "config": {"required_license": licenses_for_sub_capability(sub_cap_id)}
    }


def _actions_for_capability(cap_name: str) -> list[dict]:
    """Return the handler ``actions[]`` list for a mapper capability bucket key.

    ``cap_name`` is one of the six mapper bucket keys (e.g. ``"Fetch Issues"``).
    It is resolved through :func:`slugify_capability_name` to its canonical
    capability id and then looked up in :data:`CAPABILITY_ACTIONS`.

    Keying off the bucket key (rather than the possibly-decorated handler cap
    id) means this works identically on the from-scratch path (bare canonical
    slug) and the append path (sub-cap id
    ``<capability_id>_<integration-id-slug>``) — the capability family is the
    same in both cases.

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
        non-empty): ``{id, auth_options: [{id, workloads}]}`` where
        ``workloads`` lives on each auth_option (per AuthOption schema).
        ``scopes`` is omitted (optional in the schema). NO capability-level
        ``workloads``.

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
    integration_name = integration_yml.get("name", "")
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
    seen_profile_ids: set[str] = set()
    # ``scopes`` is intentionally omitted from auth_options (it is optional per
    # the AuthOption schema). Only ``id`` and ``workloads`` are emitted.
    auth_options = [
        {
            "id": derive_profile_id(at, integration_id, seen_profile_ids),
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
        # ``<capability_id>_<integration-id-slug>`` so the handler references
        # the sub-cap entry that capabilities.yaml/configurations.yaml emit.
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
                f"XSOAR handler for {integration_name}."
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
    """Dump ``data`` to ``fh`` with the no-alias dumper, preserving key order.

    Single choke-point so every manifest file is serialized identically
    (no anchors/aliases) — keeps output deterministic and review-friendly.

    ``sort_keys=False`` is REQUIRED: the builder dicts construct top-level
    keys in their canonical manifest order (``metadata`` →
    ``general_configurations`` → body). PyYAML's default ``sort_keys=True``
    would alphabetize them, pushing ``general_configurations`` after the
    body and ``metadata`` to the bottom — which is not the shape the
    connector schema/examples expect.
    """
    yaml.dump(
        data,
        fh,
        Dumper=_NoAliasDumper,
        default_flow_style=False,
        sort_keys=False,
    )


# Canonical top-level key order for configurations.yaml, matching the
# connector examples (metadata → view_groups → general_configurations →
# configurations). The builder appends general_configurations / view_groups
# AFTER the per-capability configurations list, so without this reorder the
# user-visible order would be metadata → configurations → general_configurations
# → view_groups. Any key not listed here is appended after, in its existing
# relative order.
_CONFIGURATIONS_KEY_ORDER = (
    "metadata",
    "view_groups",
    "general_configurations",
    "configurations",
)


def split_fields_blocks(block: dict) -> list[dict]:
    """Expand ONE field group so each field sits in its own ``fields`` block.

    Per guide §3.7 item 2, every field must be the sole entry of its own
    ``fields:`` block (each block renders as a single UI row). Builders emit
    one block holding many fields::

        {"id": "...", "view_group": "...", "fields": [a, b, c]}

    This returns one block per field, copying the sibling keys (everything
    except ``fields`` — e.g. ``id``, ``view_group``,
    ``relevant_for_capabilities``) onto each produced block::

        [{"id": ..., "view_group": ..., "fields": [a]},
         {"id": ..., "view_group": ..., "fields": [b]},
         {"id": ..., "view_group": ..., "fields": [c]}]

    Notes:
      - An EMPTY block (``fields: []``) is preserved as a single block with
        ``fields: []`` so empty sub-capability entries keep their
        ``view_group`` binding (guide §3.7 rule 4).
      - Only the block-level ``fields`` list is split; a field's OWN inner
        ``fields`` (e.g. a ``checkbox_group``'s items — guide §3.7 item 2
        sole exception) is left untouched because it is part of the field
        object, not the block.
    """
    sibling_keys = {k: v for k, v in block.items() if k != "fields"}
    fields = block.get("fields", [])
    if not fields:
        out = dict(sibling_keys)
        out["fields"] = []
        return [out]
    result: list[dict] = []
    for field in fields:
        out = dict(sibling_keys)
        out["fields"] = [field]
        result.append(out)
    return result


def _split_block_list(blocks: list[dict]) -> list[dict]:
    """Apply :func:`split_fields_blocks` to every block in ``blocks``."""
    expanded: list[dict] = []
    for block in blocks:
        if isinstance(block, dict) and "fields" in block:
            expanded.extend(split_fields_blocks(block))
        else:
            expanded.append(block)
    return expanded


def normalize_connection_field_blocks(connection_data: dict) -> dict:
    """Return a copy of ``connection_data`` with one field per ``fields`` block.

    Splits every ``profiles[].configurations[]`` field group so each field
    renders in its own UI row (guide §3.7 item 2). The input is deep-copied
    so in-memory builder state (and the tests asserting on it) is untouched —
    only the written YAML adopts the one-field-per-block shape.
    """
    data = copy.deepcopy(connection_data)
    for profile in data.get("profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        cfgs = profile.get("configurations")
        if isinstance(cfgs, list):
            profile["configurations"] = _split_block_list(cfgs)
    return data


def normalize_configurations_field_blocks(configurations_data: dict) -> dict:
    """Return a copy of ``configurations_data`` with one field per block.

    Splits every field group under:
      - ``general_configurations.configurations[]`` and
      - ``configurations[].configurations[]`` (per sub-capability)
    so each field renders in its own UI row (guide §3.7 item 2). The input is
    deep-copied so in-memory builder state is untouched — only the written
    YAML adopts the one-field-per-block shape.
    """
    data = copy.deepcopy(configurations_data)

    general = data.get("general_configurations")
    if isinstance(general, dict):
        gen_cfgs = general.get("configurations")
        if isinstance(gen_cfgs, list):
            general["configurations"] = _split_block_list(gen_cfgs)

    for entry in data.get("configurations", []) or []:
        if not isinstance(entry, dict):
            continue
        sub_cfgs = entry.get("configurations")
        if isinstance(sub_cfgs, list):
            entry["configurations"] = _split_block_list(sub_cfgs)

    return data


def _ordered_configurations(data: dict) -> dict:
    """Return ``data`` with top-level keys in the canonical configurations order.

    Also normalizes every ``fields`` block so each field occupies its own
    block (guide §3.7 item 2) — applied here so both configurations.yaml
    write sites are covered by this single choke-point.

    Preserves all values untouched (nested ordering is left as-is). Keys not in
    :data:`_CONFIGURATIONS_KEY_ORDER` keep their original relative position at
    the end.
    """
    data = normalize_configurations_field_blocks(data)
    ordered: dict = {}
    for key in _CONFIGURATIONS_KEY_ORDER:
        if key in data:
            ordered[key] = data[key]
    for key, value in data.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


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

SERIALIZER_SCHEMA_DIRECTIVE = (
    "# yaml-language-server: $schema=../../../../../schema/serializer.schema.json\n"
)


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
      - ``configurations.yaml`` general_configurations[].configurations[].fields[].id
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
        # configurations.yaml general_configurations block — where per-handler
        # ``integrationLogLevel`` and user-mapped general_configurations fields
        # live. Mirrors :func:`sweep_hidden_defaults_to_serializer`, which also
        # scans BOTH this block and the per-capability entries. Omitting it
        # meant a second handler's general_configurations field ids never
        # collided, so they kept their bare id with no serializer bridge.
        gc = configurations_data.get("general_configurations") or {}
        for group in gc.get("configurations") or []:
            for field in group.get("fields") or []:
                fid = (field or {}).get("id")
                if fid:
                    result.add(fid)
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
        _dump_yaml(existing, fh)


def build_capability_gated_computed_field(
    *,
    output_id: str,
    value: Any,
    sub_capability_ids: list[str],
    single_group: bool = False,
) -> dict:
    """Build a single ``computed_fields`` rule that injects ``output_id``=``value``.

    The rule mirrors RULE 5 in the Salesforce example serializer.yaml: a
    synthetic output parameter pushed into the lifecycle notification message
    when a sub-capability is enabled.

    Gating (per migration decision):
      - **One** sub-capability id -> a single ``any_of`` group with one
        ``capability`` condition (``value: "on"``). Used for params that are
        strictly attached to one sub-capability.
      - **Multiple** sub-capability ids -> one ``any_of`` group PER id (OR
        logic), so the value is injected if ANY of the listed sub-capabilities
        is enabled. Used for params not attached to any single sub-capability
        (e.g. ``general_configurations`` hidden-default params), which list all
        the handler's available sub-capability ids.

    Returns a dict shaped per ``serializer.schema.json`` ``ComputedFieldRule``::

        {
            "output": [{"id": <output_id>, "value": <value>}],
            "any_of": [
                {"conditions": [
                    {"type": "capability",
                     "options": {"capability_id": <sub_cap_id>, "value": "on"}}
                ]},
                ...
            ],
        }
    """
    def _condition(sub_cap_id: str) -> dict:
        return {
            "type": "capability",
            "options": {"capability_id": sub_cap_id, "value": "on"},
        }

    if single_group:
        # All sub-capabilities listed as conditions within ONE ``any_of`` group.
        # Used by the sweep for orphan hidden+default params (e.g. ``first_fetch``)
        # whose golden lists every capability as conditions in a single group.
        groups = [{"conditions": [_condition(cid) for cid in sub_capability_ids]}]
    else:
        # One ``any_of`` group PER sub-capability id (OR-of-groups).
        groups = [{"conditions": [_condition(cid)]} for cid in sub_capability_ids]
    return {
        "output": [{"id": output_id, "value": value}],
        "any_of": groups,
    }


def register_computed_field_entry(
    handler_dir: Path, rule: dict
) -> None:
    """Append one ``computed_fields`` rule to a handler's ``serializer.yaml``.

    Behavior mirrors :func:`register_serializer_entry` (creates the file with
    the schema directive when missing / comment-only stub, preserves existing
    ``field_mappings`` and ``computed_fields`` entries when dict-based), but
    appends to the ``computed_fields`` list instead of ``field_mappings``.

    Idempotent: if a rule with the same ``output`` AND ``any_of`` already
    exists, the file is left untouched (no duplicate appended, no write).
    """
    handler_dir.mkdir(parents=True, exist_ok=True)
    serializer_path = handler_dir / "serializer.yaml"

    existing: dict = {}
    if serializer_path.is_file():
        with open(serializer_path) as fh:
            raw = fh.read()
        body = _strip_leading_comments(raw)
        loaded = yaml.safe_load(io.StringIO(body)) if body.strip() else None
        if isinstance(loaded, dict):
            existing = loaded

    computed_fields = existing.setdefault("computed_fields", [])

    # Idempotency guard: skip if an identical rule already exists.
    for cf in computed_fields:
        if (
            isinstance(cf, dict)
            and cf.get("output") == rule.get("output")
            and cf.get("any_of") == rule.get("any_of")
        ):
            return
    computed_fields.append(rule)

    with open(serializer_path, "w") as fh:
        fh.write(SERIALIZER_SCHEMA_DIRECTIVE)
        _dump_yaml(existing, fh)


# ============================================================
# Hidden-default → serializer "sweep" (authoritative final pass)
#
# Guideline (per migration owner):
#   Every XSOAR param that is BOTH hidden-on-platform AND carries a
#   ``defaultvalue`` MUST be moved out of ``configurations.yaml`` and into the
#   handler's ``serializer.yaml`` ``computed_fields`` (the platform injects the
#   fixed default at runtime, gated on the relevant capability). A hidden field
#   with a default value must NEVER survive in ``configurations.yaml``.
#
# The per-field path (:func:`emit_field_for_param`) already implements this for
# params that flow through it, but two classes of param escape that path:
#   1. Params emitted by dedicated capability builders (e.g.
#      ``eventFetchInterval`` / ``alertFetchInterval`` via ``_map_type_19``),
#      which honour ``hidden`` but do NOT reroute to the serializer.
#   2. "Orphan" config-only params the param-mapper never routes into any
#      capability bucket (e.g. ``max_concurrent_tasks``), so they never reach
#      ``emit_field_for_param`` at all.
#
# This sweep runs AFTER ``configurations.yaml`` is fully assembled (so it sees
# every field regardless of which code path produced it) and BEFORE the file is
# written. It is the single, provably-complete choke point for the rule.
# ============================================================

# Params that are hidden-on-platform WITH a default but must NEVER be swept to
# the serializer because they are managed by a different, intentional mechanism:
#   - ``feedExpirationInterval`` is hidden-by-default and revealed via its own
#     ``feedExpirationPolicy == 'interval'`` trigger (see
#     :func:`_build_feed_expiration_interval_trigger`). It is a genuine
#     user-editable field once revealed, so it stays in configurations.yaml.
# Connection-section params and ``defaultIgnore`` are excluded dynamically by
# the caller (they are not driven off this static set).
# NOTE: literal rather than ``FEEDEXPIRATIONINTERVAL_PARAM_NAME`` because that
# constant is defined later in the module; this set is evaluated at import time.
# Kept in lockstep with ``FEEDEXPIRATIONINTERVAL_PARAM_NAME`` ("feedExpirationInterval").
SWEEP_EXCLUDED_PARAMS: frozenset[str] = frozenset(
    {
        "feedExpirationInterval", "longRunning"
    }
)

# Mirroring params are managed by the platform's incident-mirroring machinery,
# NOT by the serializer. Even when they are hidden-on-platform and carry a
# ``defaultvalue``, they must NEVER be swept into ``serializer.yaml``
# ``computed_fields`` — injecting a fixed default for them would break/override
# the mirroring contract. These are the standard XSOAR mirroring param names
# (see the incident-mirroring integration template); add more here if a new
# mirroring param is introduced.
MIRROR_PARAMS: frozenset[str] = frozenset(
    {
        "mirror_options",
        "close_incident",
        "mirror_limit",
        # Common siblings of the mirroring trio (suggested additions):
        "mirror_direction",
        "mirror_tag",
        "incoming_tags",
        "outgoing_tags",
        "comment_tag",
        "work_notes_tag",
        "close_out",
        "close_notes",
    }
)

# XSOAR-param-name → connector-field-id renames applied by capability builders
# that the platform consumes DIRECTLY (no serializer ``field_mappings`` bridge
# back to the XSOAR name). The fetch-issues builder migrates the legacy
# "incident" names to the Platform "alert" names (guide §line 889-890):
#   incidentFetchInterval -> alertFetchInterval
#   incidentType          -> incidentType
# When the sweep moves one of these hidden+default params to the serializer it
# must (a) remove the RENAMED field id from configurations.yaml and (b) emit the
# computed_fields output using the RENAMED id (what the platform reads).
# Literals kept in lockstep with ``ALERTFETCHINTERVAL_FIELD_ID`` /
# ``incidentType_FIELD_ID`` (defined later in the module).
_KNOWN_BUILDER_FIELD_RENAMES: dict[str, str] = {
    "incidentFetchInterval": "alertFetchInterval",
    "incidentType": "incidentType",
}

# XSOAR-param-name → owning capability BUCKET KEY for params emitted by the
# dedicated capability builders. A swept param listed here is attached to a
# SINGLE capability, so its serializer computed_fields rule must gate ONLY on
# that capability's sub-cap id (not OR-gated across the whole handler). Params
# NOT in this map and NOT routed into a specific ``mapped_params`` bucket are
# treated as unattached "orphans" (e.g. ``max_concurrent_tasks``) and fall back
# to OR-gating across all of the handler's sub-capabilities.
#
# Bucket-key literals kept in lockstep with the ``*_BUCKET_KEY`` constants
# (defined later in the module) — ``LOG_COLLECTION_BUCKET_KEY`` ("Log
# Collection"), ``FETCH_ISSUES_BUCKET_KEY`` ("Fetch Issues"), "Fetch Assets and
# Vulnerabilities", "Threat Intelligence & Enrichment".
_BUILDER_PARAM_TO_BUCKET_KEY: dict[str, str] = {
    # Log Collection builder
    "isFetchEvents": "Log Collection",
    "eventFetchInterval": "Log Collection",
    # Fetch Issues builder
    "isFetch": "Fetch Issues",
    "incidentType": "Fetch Issues",
    "incidentFetchInterval": "Fetch Issues",
    # Fetch Assets and Vulnerabilities builder
    "isFetchAssets": "Fetch Assets and Vulnerabilities",
    "assetsFetchInterval": "Fetch Assets and Vulnerabilities",
    # Indicators / feed builder (feedExpirationInterval is excluded from the
    # sweep entirely; the rest gate on the TI&E capability).
    "feedFetchInterval": "Threat Intelligence & Enrichment",
    "feedReliability": "Threat Intelligence & Enrichment",
    "feedExpirationPolicy": "Threat Intelligence & Enrichment",
    "feedReputation": "Threat Intelligence & Enrichment",
    "feedBypassExclusionList": "Threat Intelligence & Enrichment",
    "feedIncremental": "Threat Intelligence & Enrichment",
}


def _load_serializer_field_mappings(handler_dir: Path | None) -> dict[str, str]:
    """Return a ``{connector_field_id: original_xsoar_name}`` map from a
    handler's ``serializer.yaml`` ``field_mappings`` block.

    The dedup-via-rename step (:func:`dedup_field_id_and_register`) and the
    capability builders register ``field_mappings`` entries shaped
    ``{"id": <renamed_id>, "field_name": <original_name>}`` whenever a field id
    is renamed (e.g. ``<handler>_eventFetchInterval`` → ``eventFetchInterval``).

    The sweep matches configurations fields by their original XSOAR param name;
    this reverse map lets it also recognise a field that was renamed away from
    its bare name. Returns an empty dict when no serializer / no mappings exist.
    """
    if handler_dir is None:
        return {}
    serializer_path = handler_dir / "serializer.yaml"
    if not serializer_path.is_file():
        return {}
    with open(serializer_path) as fh:
        body = _strip_leading_comments(fh.read())
    loaded = yaml.safe_load(io.StringIO(body)) if body.strip() else None
    if not isinstance(loaded, dict):
        return {}
    mapping: dict[str, str] = {}
    for fm in loaded.get("field_mappings", []) or []:
        if isinstance(fm, dict) and fm.get("id") and fm.get("field_name"):
            mapping[str(fm["id"])] = str(fm["field_name"])
    return mapping


def connection_param_names_from_auth(auth_methods: dict | None) -> set[str]:
    """Return the set of XSOAR param names that live on the connection.

    These are excluded from the configurations sweep because they belong to
    ``connection.yaml`` (auth profiles + other_connection), never
    ``configurations.yaml``.

    Sources (mirrors what :func:`build_connection_yaml` consumes):
      - Every ``auth_types[*].xsoar_param_map`` KEY. Keys may be a bare param
        name (``clientToken``) or a credentials leaf (``creds.password`` /
        ``creds.identifier``); we take the base param name (before the first
        ``.``) so the type-9 credentials param itself is matched.
      - Every entry in the top-level ``other_connection`` list.

    Returns an empty set when ``auth_methods`` is falsy.
    """
    if not auth_methods:
        return set()
    names: set[str] = set()
    for auth_type in auth_methods.get("auth_types", []) or []:
        if not isinstance(auth_type, dict):
            continue
        for map_key in (auth_type.get("xsoar_param_map") or {}):
            base = str(map_key).split(".", 1)[0]
            if base:
                names.add(base)
    for entry in auth_methods.get("other_connection", []) or []:
        if entry:
            names.add(str(entry))
    return names


def collect_swept_hidden_default_params(
    integration_yml: dict,
    connection_param_names: set[str] | None = None,
) -> dict[str, Any]:
    """Collect XSOAR params that must be moved to serializer ``computed_fields``.

    A param qualifies when ALL of the following hold:
      1. It is hidden-on-platform (:func:`_is_hidden_on_platform` — i.e.
         ``hidden: true`` OR ``hidden`` is a list containing ``"platform"``).
      2. It carries a non-``None`` ``defaultvalue`` in the YAML.
      3. It is NOT in :data:`SWEEP_EXCLUDED_PARAMS` (``feedExpirationInterval``).
      4. It is NOT ``defaultIgnore`` (managed by the automation capability).
      5. It is NOT a connection-section param (auth / other_connection) — those
         live on connection.yaml, never configurations.yaml.
      6. It is NOT a mirroring param (:data:`MIRROR_PARAMS` — ``mirror_options``,
         ``close_incident``, ``mirror_limit``, …) — those are owned by the
         platform's mirroring machinery, not the serializer.

    Returns a ``{param_name: coerced_default_value}`` dict (the value coerced to
    its native serializer type via :func:`_coerce_hidden_default_value`).
    """
    connection_param_names = connection_param_names or set()
    swept: dict[str, Any] = {}
    for param in integration_yml.get("configuration", []) or []:
        name = param.get("name", "")
        if not name:
            continue
        if name in SWEEP_EXCLUDED_PARAMS or name == _DEFAULT_IGNORE_PARAM:
            continue
        # Mirroring params are owned by the platform's mirroring machinery —
        # never sweep them into serializer computed_fields.
        if name in MIRROR_PARAMS:
            continue
        if name in connection_param_names:
            continue
        if not _is_hidden_on_platform(param):
            continue
        # XSOAR yml conventionally uses ``defaultvalue`` (no underscore), but
        # some content / migration inputs use ``default_value``. Accept either.
        default = param.get("defaultvalue")
        if default is None:
            default = param.get("default_value")
        if default is None:
            continue
        swept[name] = _coerce_hidden_default_value(param)
    return swept


def _remove_field_from_configurations(
    configurations_data: dict,
    field_ids: set[str],
    general_config_view_group: str | None = None,
) -> set[str]:
    """Remove every field whose ``id`` is in ``field_ids`` from a
    configurations.yaml data dict, scanning BOTH the per-capability
    ``configurations`` entries AND the ``general_configurations`` block.

    Empty field groups left behind by the removal are pruned. Returns the set
    of field ids that were actually found and removed (for logging / accuracy).

    ``general_config_view_group``: when set, the ``general_configurations``
    scrub is RESTRICTED to field groups whose ``view_group`` matches it. This
    scopes the sweep to the NEW handler's general_configurations rows on the
    append path — without it, a bare-id field shared with an EXISTING handler
    (e.g. ``first_fetch`` under a different view_group) would be wrongly removed
    from that other handler. ``None`` preserves the previous behaviour (scrub
    every general_configurations group — correct for the single-handler
    from-scratch path).
    """
    removed: set[str] = set()

    def _scrub_group_list(groups: list, view_group_filter: str | None = None) -> None:
        for group in groups:
            if not isinstance(group, dict):
                continue
            if (
                view_group_filter is not None
                and group.get("view_group") != view_group_filter
            ):
                # Group belongs to a different handler — leave it untouched.
                continue
            fields = group.get("fields")
            if not isinstance(fields, list):
                continue
            kept = []
            for f in fields:
                if isinstance(f, dict) and f.get("id") in field_ids:
                    removed.add(str(f.get("id")))
                    continue
                kept.append(f)
            group["fields"] = kept
        # Prune now-empty field groups.
        groups[:] = [g for g in groups if (g.get("fields") if isinstance(g, dict) else g)]

    # Per-capability configuration entries. Scope to the new handler's entries
    # (matched by ``view_group``) when a filter is supplied so a builder-renamed
    # field shared with an EXISTING handler (e.g. ``alertFetchInterval`` in that
    # handler's fetch-issues entry) is not wrongly removed.
    for entry in configurations_data.get("configurations", []) or []:
        if not (isinstance(entry, dict) and isinstance(entry.get("configurations"), list)):
            continue
        if (
            general_config_view_group is not None
            and entry.get("view_group") != general_config_view_group
        ):
            continue
        _scrub_group_list(entry["configurations"])

    # general_configurations block (optionally scoped to one view_group).
    gc = configurations_data.get("general_configurations")
    if isinstance(gc, dict) and isinstance(gc.get("configurations"), list):
        _scrub_group_list(
            gc["configurations"], view_group_filter=general_config_view_group
        )

    return removed


def sweep_hidden_defaults_to_serializer(
    configurations_data: dict,
    integration_yml: dict,
    handler_id: str,
    handler_dir: Path,
    mapped_params: dict[str, Any] | None = None,
    connection_param_names: set[str] | None = None,
) -> dict[str, Any]:
    """Final authoritative pass: move every hidden+default XSOAR param out of
    ``configurations_data`` and into the handler's serializer ``computed_fields``.

    For each param returned by :func:`collect_swept_hidden_default_params`:
      1. Remove its field from ``configurations_data`` — matched by the original
         XSOAR param name AND any renamed connector id that maps back to it via
         the handler's ``serializer.yaml`` ``field_mappings`` (so a renamed
         ``<handler>_eventFetchInterval`` is caught too).
      2. Register a capability-gated ``computed_fields`` rule whose ``output``
         id is the ORIGINAL XSOAR param name (the runtime contract) and value is
         the coerced default. The rule is gated (OR logic) on ALL of the
         handler's sub-capability ids — correct for orphan params not attached
         to any single capability (e.g. ``max_concurrent_tasks``) and harmless
         for params that happen to belong to one capability.

    Idempotent: :func:`register_computed_field_entry` dedupes identical rules, so
    a param already moved by :func:`emit_field_for_param` is not duplicated.

    Returns the ``{param_name: value}`` dict that was swept (for logging/tests).
    """
    swept = collect_swept_hidden_default_params(
        integration_yml, connection_param_names
    )
    if not swept:
        return {}

    mapped_params = mapped_params or {}

    def _sub_cap_id(cap_name: str) -> str:
        return (
            make_sub_capability_id(handler_id, cap_name)
            if handler_id
            else slugify_capability_name(cap_name)
        )

    # All of the handler's sub-capability ids — the OR-gating fallback used only
    # for unattached "orphan" params (not owned by any single capability).
    all_cap_ids = [
        _sub_cap_id(cap_name)
        for cap_name in mapped_params
        if cap_name != "general_configurations"
    ]

    def _owning_capability_ids(param_name: str) -> list[str]:
        """Resolve the sub-cap id(s) a swept param should gate on.

        Resolution order (most specific first):
          1. Builder-owned param (:data:`_BUILDER_PARAM_TO_BUCKET_KEY`) — gate on
             that single capability's sub-cap id, when the bucket is present for
             this handler.
          2. Mapper-routed param — if the param appears in exactly one
             ``mapped_params`` bucket, gate on that bucket's sub-cap id.
          3. Orphan (config-only, not attached anywhere, e.g.
             ``max_concurrent_tasks``) — OR-gate across ALL of the handler's
             sub-capabilities.
        """
        # 1. Builder-owned single capability.
        bucket = _BUILDER_PARAM_TO_BUCKET_KEY.get(param_name)
        if bucket and bucket in mapped_params:
            return [_sub_cap_id(bucket)]

        # 2. Mapper-routed: find the bucket(s) that list this param.
        owning_buckets = [
            cap_name
            for cap_name, params in mapped_params.items()
            if cap_name != "general_configurations" and param_name in (params or [])
        ]
        if len(owning_buckets) == 1:
            return [_sub_cap_id(owning_buckets[0])]

        # 3. Orphan / ambiguous → OR-gate across all handler sub-capabilities.
        return all_cap_ids

    # Reverse map for fields renamed via the serializer ``field_mappings``
    # (dedup-via-rename + sub-cap prefixing) so removal also catches those ids.
    renamed_to_original = _load_serializer_field_mappings(handler_dir)
    original_to_renamed: dict[str, set[str]] = {}
    for renamed_id, original_name in renamed_to_original.items():
        original_to_renamed.setdefault(original_name, set()).add(renamed_id)

    for name, value in swept.items():
        # Determine the connector-side field id + the serializer output id.
        #
        # Some capability builders rename the XSOAR param to a Platform
        # "alert" id that the platform consumes DIRECTLY (no field_mappings
        # bridge back to the XSOAR name) — e.g. fetch-issues maps
        # ``incidentFetchInterval`` -> ``alertFetchInterval`` (see
        # :data:`_KNOWN_BUILDER_FIELD_RENAMES`). For those, both the field to
        # remove AND the computed_fields output id are the RENAMED id.
        # Otherwise the field id == the XSOAR param name and the output id is
        # the XSOAR name (the runtime contract).
        builder_renamed = _KNOWN_BUILDER_FIELD_RENAMES.get(name)
        output_id = builder_renamed or name

        # Field ids that could represent this param in configurations.yaml:
        # the XSOAR name, any field_mappings-renamed id, and the known
        # builder-renamed id.
        candidate_ids = {name} | original_to_renamed.get(name, set())
        if builder_renamed:
            candidate_ids.add(builder_renamed)
        # Scope the general_configurations scrub to THIS handler's view_group so
        # a bare-id field shared with an existing handler (e.g. ``first_fetch``
        # under another handler's view_group) is not wrongly removed.
        removed = _remove_field_from_configurations(
            configurations_data,
            candidate_ids,
            general_config_view_group=(
                view_group_id_for_handler(handler_id) if handler_id else None
            ),
        )

        # Gate on the param's OWNING capability (single) when known; fall back
        # to OR across all sub-capabilities only for unattached orphans.
        gating_ids = _owning_capability_ids(name)

        # Orphan params (gated across ALL the handler's sub-capabilities, e.g.
        # ``first_fetch``) list every capability as conditions in a SINGLE
        # ``any_of`` group. Params attached to a single owning capability keep
        # the one-group-per-id form.
        is_orphan_gating = gating_ids == all_cap_ids and len(gating_ids) > 1

        rule = build_capability_gated_computed_field(
            output_id=output_id,
            value=value,
            sub_capability_ids=gating_ids,
            single_group=is_orphan_gating,
        )
        register_computed_field_entry(handler_dir, rule)

        logger.info(
            "[manifest_generator] Sweep moved hidden+default param '%s' "
            "(handler='%s') to serializer computed_fields as output '%s' with "
            "value %r (removed field ids %s, gated on %s).",
            name,
            handler_id,
            output_id,
            value,
            sorted(removed) if removed else "<none in configurations>",
            gating_ids,
        )

    return swept


def assert_no_hidden_defaults_in_configurations(
    configurations_data: dict,
) -> None:
    """Safety guard: raise if any configurations.yaml field is BOTH hidden AND
    carries a ``default_value``.

    Such a field violates the hidden+default → serializer rule (it should have
    been swept to ``computed_fields``). The only sanctioned exception is
    :data:`SWEEP_EXCLUDED_PARAMS` (``feedExpirationInterval``), which is hidden
    until its reveal trigger fires.

    A field is considered hidden when EITHER its ``create_modifiers.hidden`` or
    ``edit_modifiers.hidden`` is ``True``.
    """
    offenders: list[str] = []

    def _field_is_hidden(options: dict) -> bool:
        for mod_key in ("create_modifiers", "edit_modifiers"):
            mod = options.get(mod_key)
            if isinstance(mod, dict) and mod.get("hidden") is True:
                return True
        return False

    def _check_groups(groups: list) -> None:
        for group in groups or []:
            if not isinstance(group, dict):
                continue
            for field in group.get("fields", []) or []:
                if not isinstance(field, dict):
                    continue
                fid = str(field.get("id", ""))
                # Allow the sanctioned exception both as a bare id and as a
                # dedup-renamed id (``<handler_id>_feedExpirationInterval``),
                # since a 2nd+ handler's copy is id-prefixed.
                if fid in SWEEP_EXCLUDED_PARAMS or any(
                    fid.endswith(f"_{p}") for p in SWEEP_EXCLUDED_PARAMS
                ):
                    continue
                options = field.get("options")
                if not isinstance(options, dict):
                    continue
                has_default = "default_value" in options
                if has_default and _field_is_hidden(options):
                    offenders.append(fid)

    for entry in configurations_data.get("configurations", []) or []:
        if isinstance(entry, dict):
            _check_groups(entry.get("configurations", []))

    gc = configurations_data.get("general_configurations")
    if isinstance(gc, dict):
        _check_groups(gc.get("configurations", []))

    if offenders:
        raise ValueError(
            "configurations.yaml contains hidden fields that still carry a "
            "default_value (these must be moved to serializer computed_fields "
            f"via the sweep): {sorted(offenders)}"
        )


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


def _coerce_hidden_default_value(yml_param: dict) -> Any:
    """Coerce an XSOAR yml param's ``defaultvalue`` to its native type for use
    as a serializer ``computed_fields`` output value.

    XSOAR stores defaults as strings even for boolean (type 8) params. The
    serializer ``ComputedOutput.value`` accepts string / number / boolean, so:
      - type 8 (boolean) -> Python ``bool`` via :func:`_coerce_toggle_default`.
      - everything else -> the raw ``defaultvalue`` passed through unchanged
        (string / number — already JSON-serializable).
    """
    # Accept both ``defaultvalue`` (XSOAR convention) and ``default_value``.
    # XSOAR stores ``defaultvalue`` as a STRING even for numeric params; the
    # ``default_value`` fallback (used by some migration inputs) may be parsed
    # by YAML as an int/float, so normalize it to a string to match the XSOAR
    # convention (the serializer ``computed_fields`` value is then consistent
    # with builder-emitted defaults like ``alertFetchInterval: '30'``).
    raw = yml_param.get("defaultvalue")
    if raw is None:
        raw = yml_param.get("default_value")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            raw = str(raw)
    if yml_param.get("type") == 8:
        return _coerce_toggle_default(raw)
    return raw


def emit_field_for_param(
    name: str,
    yml_params_by_name: dict[str, dict] | None,
    handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
    gating_capability_ids: list[str] | None = None,
) -> list[dict]:
    """Return one or more connectus field dicts for an XSOAR yml param name.

    Resolution policy (Q1=a / Q2=a / Q3=c / Q4=a / Q5=a):

      - **Platform-hidden filter** (per guide §3.1 *Assumptions #4*): if
        the underlying yml param declares ``hidden: [platform]`` (the
        marketplace-keyed form indicating the param is hidden on the
        Platform marketplace), the param is NOT emitted as a manifest
        field. Per the no-more-hidden-defaults rule, if the param carries
        a ``defaultvalue`` AND ``gating_capability_ids`` + ``handler_dir``
        are supplied, a serializer ``computed_fields`` rule is registered
        instead (output id = original yml param name, value = coerced
        default, gated on the listed capabilities — OR logic). Hidden
        params with NO default are dropped entirely (as before). Either
        way this function returns an EMPTY list; callers must handle empty
        results by skipping the field emission.
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
        has_default = (
            "defaultvalue" in yml_param and yml_param["defaultvalue"] is not None
        )
        if has_default and handler_dir is not None and gating_capability_ids:
            value = _coerce_hidden_default_value(yml_param)
            rule = build_capability_gated_computed_field(
                output_id=name,
                value=value,
                sub_capability_ids=gating_capability_ids,
            )
            register_computed_field_entry(handler_dir, rule)
            logger.info(
                f"[manifest_generator] Hidden param '{name}' "
                f"(handler='{handler_id}') moved to serializer computed_fields "
                f"with default value {value!r} (gated on "
                f"{gating_capability_ids})."
            )
        else:
            logger.info(
                f"[manifest_generator] Skipping param '{name}' (handler='{handler_id}'): "
                f"marked hidden on platform marketplace with no default value "
                f"(or no gating context) per guide §3.1 #4."
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


def _apply_fetch_checkbox_visibility_rule(
    checkbox_fields: list[dict],
    *,
    capability_id: str = "",
    handler_dir: Path | None = None,
    field_id_to_yml_name: dict[str, str] | None = None,
    has_real_fetch_flag: bool = True,
    fetch_toggle_field_id: str = "",
) -> list[dict]:
    """Apply the "count both checkboxes together" rule, serializer-first.

    Within a fetch capability the set of fetch checkboxes is
    ``{fetch_toggle, longRunning}`` — ``isFetchEvents`` for Log Collection,
    ``isFetch`` for Fetch Issues. The behavior is decided by how many of them
    this capability emits:

      - **Exactly one** checkbox emitted → the field is NOT emitted into the
        sub-capability configurations at all. Instead a serializer
        ``computed_fields`` rule is registered that injects ``<yml_name>: true``
        into the lifecycle notification when ``capability_id`` is ``on`` (RULE 5
        style). With only one fetch mode there is no user choice to make, so the
        platform auto-enables it — no hidden toggle is carried over.
      - **Two (or more)** checkboxes emitted → ALL are SHOWN (``hidden: False``)
        and defaulted to ``False``. The user explicitly picks which fetch mode
        to enable. (Unchanged from the legacy behavior.)

    **No-real-fetch-flag carve-out** (``has_real_fetch_flag=False``): the
    integration declares neither ``script.isfetch``/``script.isfetchevents``
    nor a fetch checkbox param — the only reason this fetch capability exists
    is that ``longRunning`` was routed to it (e.g. QRadar v3, Retarus Secure
    Email Gateway). There is no genuine user fetch choice, so:

      - the **synthetic fetch toggle** (``fetch_toggle_field_id``) is dropped
        and appears NOWHERE — it gets neither a manifest field nor a serializer
        rule (its value is implied by selecting the sub-capability);
      - ``longRunning`` is dropped from configurations and moved to a serializer
        ``computed_fields`` rule gated on the sub-capability selection (same
        ``any_of`` shape as the single-checkbox case).

    This branch returns ``[]`` regardless of how many checkboxes are present.

    Only the checkbox fields are passed in; interval / dynamic-select fields are
    never touched by this rule.

    Returns the list of checkbox fields that should REMAIN in the manifest:
      - single-checkbox / no-real-flag case → returns ``[]`` (the dropped
        checkbox values that need serialization are moved to the serializer);
      - multi-checkbox case → returns the (mutated, shown + default-False)
        fields unchanged.

    ``capability_id``, ``handler_dir`` and ``field_id_to_yml_name`` are used to
    register the computed_fields rule. When ``handler_dir`` is missing the rule
    cannot be written (legacy callers); the field is still dropped and a
    warning logged.
    """
    if not checkbox_fields:
        return []

    def _serialize_checkbox(field: dict) -> None:
        """Drop a checkbox and push ``<yml_name>: true`` to computed_fields."""
        field_id = str(field.get("id") or "")
        yml_name = str((field_id_to_yml_name or {}).get(field_id, field_id))
        if handler_dir is not None and capability_id:
            rule = build_capability_gated_computed_field(
                output_id=yml_name,
                value=True,
                sub_capability_ids=[capability_id],
            )
            register_computed_field_entry(handler_dir, rule)
        else:
            logger.warning(
                f"[manifest_generator] Fetch checkbox '{field_id}' "
                f"dropped but could not register computed_fields rule "
                f"(handler_dir/capability_id missing)."
            )

    # No-real-fetch-flag carve-out: the integration declares neither a real
    # fetch flag nor a fetch checkbox param. This carve-out ONLY changes
    # behavior when an EXTRA checkbox (longRunning) was routed here alongside
    # the synthetic fetch toggle — i.e. the fetch capability exists solely
    # because longRunning is part of the fetch flow. In that case the synthetic
    # fetch toggle appears NOWHERE (no manifest field, no serializer rule) and
    # every OTHER checkbox (longRunning) is serialized via computed_fields gated
    # on the sub-capability.
    #
    # When the synthetic fetch toggle is the ONLY checkbox (no longRunning), we
    # fall through to the standard single-checkbox path below, which serializes
    # the lone fetch toggle so the capability auto-enables on selection
    # (unchanged legacy behavior).
    non_toggle_checkboxes = [
        f for f in checkbox_fields
        if str(f.get("id") or "") != fetch_toggle_field_id
    ]
    if not has_real_fetch_flag and non_toggle_checkboxes:
        for field in non_toggle_checkboxes:
            _serialize_checkbox(field)
        # The synthetic fetch toggle is dropped silently (appears nowhere).
        return []

    if len(checkbox_fields) == 1:
        _serialize_checkbox(checkbox_fields[0])
        return []

    # Two or more checkboxes: shown + default False (user picks the mode).
    for field in checkbox_fields:
        options = field.setdefault("options", {})
        options["default_value"] = False
        for modifier_key in ("create_modifiers", "edit_modifiers"):
            modifier = options.setdefault(modifier_key, {})
            modifier["hidden"] = False
    return checkbox_fields


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
    # --- §1. Strip the original yml name from mapper results ------------
    # Mapper results are keyed by yml-param-name (NOT by connector
    # field-id), so we strip the literal "isFetchCredentials" so it is not
    # re-emitted as a manifest field by the generic param-mapping pass.
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n for n in names if n != ISFETCHCREDENTIALS_PARAM_NAME
        ]

    # --- §2. Serializer-first: no hidden toggle is emitted -------------
    # Previously this capability emitted a hidden, default-True
    # ``isFetchCredentials`` toggle. Per the no-more-hidden-defaults rule we
    # instead push ``isFetchCredentials: true`` into the lifecycle
    # notification via a serializer computed_fields rule, gated on THIS
    # capability being enabled (RULE 5 style). The output id is the original
    # XSOAR yml param name so the handler reads it unchanged.
    if handler_dir is not None:
        rule = build_capability_gated_computed_field(
            output_id=ISFETCHCREDENTIALS_PARAM_NAME,
            value=True,
            sub_capability_ids=[capability_id],
        )
        register_computed_field_entry(handler_dir, rule)

    return {
        "capability_id": capability_id,
        "fields": [],
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

# The mapper bucket key for the Log Collection capability. Must match
# ``connector_param_mapper.FETCH_EVENTS_CAPABILITIES`` — it is the key under
# which ``map_params_to_capabilities`` places this capability's params (incl.
# ``longRunning`` when Rule 7 routes long-running here, e.g. Akamai WAF SIEM
# via INTEGRATION_TO_LONGRUNNING_CAPABILITY). Used by
# ``add_log_collection_capability`` to decide whether to emit the longRunning
# checkbox in THIS capability.
LOG_COLLECTION_BUCKET_KEY = "Log Collection"


def _build_isfetchevents_field(
    yml_param: dict | None,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``isFetchEvents`` toggle field.

    Path A (no yml_param): synthetic but VISIBLE — default False, shown in
    both modifier blocks (``hidden: false``), required False. The fetch
    toggle is presented to the user so they decide whether to collect
    events; it is not forced on.

    Path B (yml_param present): delegate to :func:`_map_type_8` so the
    shape matches what every other type-8 param produces (preserves
    ``defaultvalue``, ``hidden``, ``required``). Then override the
    ``id`` (since the caller may have renamed it for the sub-cap path)
    and re-apply the resolved ``title``.
    """
    if yml_param is None:
        return {
            "id": field_id,
            "title": title,
            "field_type": "toggle",
            "options": {
                "default_value": False,
                "create_modifiers": {"required": False, "hidden": False},
                "edit_modifiers": {"required": False, "hidden": False},
            },
        }
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
                "output_format": "minutes",
                "default_value": default_value,
                "create_modifiers": {"hidden": False},
                "edit_modifiers": {"hidden": False},
            },
        }

    # yml-driven path: _map_type_19 already emits a fully-formed duration
    # field (units / output_format / per-unit default_value / hidden
    # honoured / required stripped). We only override the connector-side id
    # and title for this capability's field.
    field = _map_type_19(yml_param)
    field["id"] = field_id
    field["title"] = title
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
    integration_yml: dict | None = None,
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

    # longRunning: emitted ONLY when the param-capability mapper routed
    # ``longRunning`` to THIS capability's ``"Log Collection"`` bucket (e.g.
    # Akamai WAF SIEM via INTEGRATION_TO_LONGRUNNING_CAPABILITY). The raw
    # ``script.longRunning`` flag is NOT consulted here — routing is owned by
    # the mapper.
    emit_longrunning = LONGRUNNING_PARAM_NAME in (
        mapped_params.get(LOG_COLLECTION_BUCKET_KEY) or []
    )
    lr_field_id = (
        f"{capability_id}_{LONGRUNNING_PARAM_NAME}"
        if is_sub_capability
        else LONGRUNNING_PARAM_NAME
    )
    # The fetch-checkbox set for this capability is {isFetchEvents, longRunning}.
    # isFetchEvents is always emitted; longRunning only when routed here.
    fetch_checkbox_fields: list[dict] = [ifc_field]
    if emit_longrunning:
        lr_field = _build_longrunning_field(
            field_id=lr_field_id,
            title=_LONGRUNNING_DEFAULT_TITLE,
        )
        fields.append(lr_field)
        fetch_checkbox_fields.append(lr_field)

    # Apply the "count both checkboxes together" rule (serializer-first): a lone
    # checkbox is DROPPED from the manifest and its ``true`` value moved to a
    # serializer computed_fields rule gated on this capability; when both are
    # present they are shown + default False. eventFetchInterval is never
    # touched by this rule.
    #
    # No-real-fetch-flag carve-out: when the integration declares neither
    # ``script.isfetchevents: true`` NOR an ``isFetchEvents`` config param, the
    # synthetic fetch toggle is not a genuine user choice — the capability only
    # exists because ``longRunning`` was routed here. In that case the synthetic
    # fetch toggle appears nowhere and ``longRunning`` moves to the serializer
    # computed_fields gated on the sub-capability (see the visibility helper).
    _script = (integration_yml.get("script") or {}) if integration_yml else {}
    has_real_fetch_flag = (
        _script.get("isfetchevents") is True
        or bool(
            yml_params_by_name and ISFETCHEVENTS_PARAM_NAME in yml_params_by_name
        )
    )
    _checkbox_yml_names = {ifc_field_id: ISFETCHEVENTS_PARAM_NAME}
    if emit_longrunning:
        _checkbox_yml_names[lr_field_id] = LONGRUNNING_PARAM_NAME
    kept_checkboxes = _apply_fetch_checkbox_visibility_rule(
        fetch_checkbox_fields,
        capability_id=capability_id,
        handler_dir=handler_dir,
        field_id_to_yml_name=_checkbox_yml_names,
        has_real_fetch_flag=has_real_fetch_flag,
        fetch_toggle_field_id=ifc_field_id,
    )
    # Drop any checkbox field that the rule removed (single-checkbox case).
    _kept_ids = {f.get("id") for f in kept_checkboxes}
    _dropped_ids = {
        f.get("id") for f in fetch_checkbox_fields if f.get("id") not in _kept_ids
    }
    if _dropped_ids:
        fields[:] = [f for f in fields if f.get("id") not in _dropped_ids]

    # --- §5. Strip yml names from mapper results -----------------------
    stripped = {ISFETCHEVENTS_PARAM_NAME, EVENTFETCHINTERVAL_PARAM_NAME}
    if emit_longrunning:
        stripped.add(LONGRUNNING_PARAM_NAME)
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [n for n in names if n not in stripped]

    # --- §6. Sub-cap rename bridges (per emitted field) -----------------
    # Skip the bridge for any checkbox that was dropped by the visibility rule
    # (single-checkbox case) — its value already flows via computed_fields, so
    # there is no manifest field left to rename.
    if is_sub_capability and handler_dir is not None:
        if (
            ifc_field_id != ISFETCHEVENTS_PARAM_NAME
            and ifc_field_id not in _dropped_ids
        ):
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
        if (
            emit_longrunning
            and lr_field_id != LONGRUNNING_PARAM_NAME
            and lr_field_id not in _dropped_ids
        ):
            register_renamed_field_serializer_entry(
                handler_dir,
                original_id=LONGRUNNING_PARAM_NAME,
                renamed_id=lr_field_id,
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

    # --- §4. Build the fields -------------------------------------------
    # isFetchAssets: previously an ALWAYS-synthetic hidden default-True toggle.
    # Per the no-more-hidden-defaults rule it is NO LONGER emitted as a field;
    # its ``true`` value is pushed via a serializer computed_fields rule gated
    # on THIS capability being enabled (§6 below). The output id is the
    # original XSOAR yml param name so the handler reads it unchanged.
    # assetsFetchInterval: yml-driven if present, else synthetic fallback —
    # this is a visible interval field and is still emitted.
    afi_field = _build_assetsfetchinterval_field(
        yml_param=afi_yml, field_id=afi_field_id, title=afi_title
    )

    fields: list[dict] = [afi_field]

    # --- §5. Strip both yml names from mapper results -------------------
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n
            for n in names
            if n not in (ISFETCHASSETS_PARAM_NAME, ASSETSFETCHINTERVAL_PARAM_NAME)
        ]

    # --- §6. Serializer bridges + isFetchAssets computed_field ----------
    if handler_dir is not None:
        # isFetchAssets value injected via computed_fields (no hidden toggle).
        register_computed_field_entry(
            handler_dir,
            build_capability_gated_computed_field(
                output_id=ISFETCHASSETS_PARAM_NAME,
                value=True,
                sub_capability_ids=[capability_id],
            ),
        )
        # assetsFetchInterval: bridge the sub-cap-prefixed id back to the
        # original yml name when renamed.
        if is_sub_capability and afi_field_id != ASSETSFETCHINTERVAL_PARAM_NAME:
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
_FEEDFETCHINTERVAL_DEFAULT_TITLE = "Feed Fetch Interval"
_FEEDRELIABILITY_DEFAULT_TITLE = "Source Reliability"
_FEEDEXPIRATIONPOLICY_DEFAULT_TITLE = ""  # module.go does not set a display
_FEEDEXPIRATIONINTERVAL_DEFAULT_TITLE = ""  # no display name per spec
_FEEDREPUTATION_DEFAULT_TITLE = "Indicator Verdict"
_FEEDBYPASSEXCLUSIONLIST_DEFAULT_TITLE = "Bypass exclusion list"
_FEEDINCREMENTAL_DEFAULT_TITLE = "Incremental Feed"

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
FEEDINCREMENTAL_PARAM_NAME = "feedIncremental"

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
        FEEDINCREMENTAL_PARAM_NAME,
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
        if yml_param.get("required") is None:
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
    """Build the ``feedExpirationInterval`` ``duration`` field.

    Per spec: **no display name** (title omitted), **hidden by default**
    (revealed via a trigger when ``feedExpirationPolicy == interval``).
    Default ``"20160"`` (2 weeks in minutes) from module.go, converted to
    a per-unit ``duration`` object (``{"days": 14}``).

    Per the duration migration contract (§2.15) the field is a
    ``duration`` picker — NOT a numeric ``input`` — with
    ``units == ["days", "hours", "minutes"]`` and
    ``output_format: "minutes"``; ``required`` is forbidden.

    When ``yml_param`` is provided, honor its ``defaultvalue`` (a minute
    count) and ``additionalinfo`` but force hidden=True regardless.
    """
    if yml_param is not None:
        # _map_type_19 emits the full duration shape (units / output_format /
        # per-unit default / required stripped).
        field = _map_type_19(yml_param)
        field["id"] = field_id
        # No display name per spec.
        field.pop("title", None)
        options = field.setdefault("options", {})
        # Force hidden — the trigger reveals it.
        for mod_key in ("create_modifiers", "edit_modifiers"):
            mod = options.setdefault(mod_key, {})
            mod["hidden"] = True
        return field

    # Synthetic fallback path — duration field, hidden, no title.
    minutes = _coerce_interval_minutes(FEED_EXPIRATION_INTERVAL_DEFAULT)
    default_value = _minutes_to_duration_default(
        minutes if minutes is not None else 1
    )
    return {
        "id": field_id,
        "field_type": "duration",
        "options": {
            "units": list(DURATION_UNITS),
            "output_format": "minutes",
            "default_value": default_value,
            "create_modifiers": {"hidden": True},
            "edit_modifiers": {"hidden": True},
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


def _build_feedincremental_field(
    yml_param: dict,
    field_id: str,
    title: str,
) -> dict:
    """Build the ``feedIncremental`` checkbox field from the integration yml.

    Unlike the other feed fields, ``feedIncremental`` has NO synthetic
    fallback: it is emitted ONLY when the integration yml carries the
    param (the caller guarantees ``yml_param`` is not None). Its
    ``hidden``, ``defaultvalue`` (default_value) and ``display`` (title)
    are taken verbatim from the yml via :func:`_map_type_8`.
    """
    field = _map_type_8(yml_param)
    field["id"] = field_id
    field["title"] = title
    return field


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

      1. ``feedFetchInterval`` — duration picker (fallback 240 min = 4h)
      2. ``feedReliability`` — select (required, fallback Undetermined)
      3. ``feedExpirationPolicy`` — select (type 17 hardcoded values)
      4. ``feedExpirationInterval`` — numeric input (hidden, no display,
         revealed via trigger when feedExpirationPolicy == interval)
      5. ``feedReputation`` — select (type 18 hardcoded values)
      6. ``feedBypassExclusionList`` — checkbox
      7. ``feedIncremental`` — checkbox, emitted **only when present in the
         integration yml** (no synthetic fallback). Its ``hidden``,
         ``display`` (title) and ``defaultvalue`` (default_value) are taken
         verbatim from the yml. When the yml omits it, this field is not
         emitted and the capability keeps its 7 standard fields.

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

    ffi_field_id = _field_id(FEEDFETCHINTERVAL_PARAM_NAME)
    fr_field_id = _field_id(FEEDRELIABILITY_PARAM_NAME)
    fep_field_id = _field_id(FEEDEXPIRATIONPOLICY_PARAM_NAME)
    fei_field_id = _field_id(FEEDEXPIRATIONINTERVAL_PARAM_NAME)
    frep_field_id = _field_id(FEEDREPUTATION_PARAM_NAME)
    fbe_field_id = _field_id(FEEDBYPASSEXCLUSIONLIST_PARAM_NAME)

    # --- §2. Resolve titles (generic helper) ----------------------------
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
    fi_title = _resolve_title_from_yml(
        yml_params_by_name, FEEDINCREMENTAL_PARAM_NAME,
        fallback=_FEEDINCREMENTAL_DEFAULT_TITLE,
    )

    # --- §3. Look up yml params (may be None) ---------------------------
    def _yml(name: str) -> dict | None:
        return yml_params_by_name.get(name) if yml_params_by_name else None

    # --- §4. Build the fields -------------------------------------------
    # NOTE: ``feed`` is NOT emitted as a configurations field. Like
    # ``isFetch`` / ``isFetchEvents``, the feed toggle is auto-enabled via
    # a serializer ``computed_fields`` rule (registered in §6 below) that
    # injects ``feed: true`` into the lifecycle notification when this
    # capability is ``on``. There is no long-running case for feed and no
    # user choice to make, so the platform turns it on implicitly when the
    # sub-capability is selected — no hidden checkbox is carried over.
    fields: list[dict] = []

    # 1. feedFetchInterval — duration picker
    fields.append(_build_feedfetchinterval_field(
        yml_param=_yml(FEEDFETCHINTERVAL_PARAM_NAME),
        field_id=ffi_field_id, title=ffi_title,
    ))

    # 2. feedReliability — select (required)
    fields.append(_build_feedreliability_field(
        yml_param=_yml(FEEDRELIABILITY_PARAM_NAME),
        field_id=fr_field_id, title=fr_title,
    ))

    # 3. feedExpirationPolicy — select (type 17)
    fields.append(_build_feedexpirationpolicy_field(
        yml_param=_yml(FEEDEXPIRATIONPOLICY_PARAM_NAME),
        field_id=fep_field_id, title=fep_title,
    ))

    # 4. feedExpirationInterval — numeric input (hidden, no display)
    fields.append(_build_feedexpirationinterval_field(
        yml_param=_yml(FEEDEXPIRATIONINTERVAL_PARAM_NAME),
        field_id=fei_field_id,
    ))

    # 5. feedReputation — select (type 18)
    fields.append(_build_feedreputation_field(
        yml_param=_yml(FEEDREPUTATION_PARAM_NAME),
        field_id=frep_field_id, title=frep_title,
    ))

    # 6. feedBypassExclusionList — checkbox
    fields.append(_build_feedbypassexclusionlist_field(
        yml_param=_yml(FEEDBYPASSEXCLUSIONLIST_PARAM_NAME),
        field_id=fbe_field_id, title=fbe_title,
    ))

    # 7. feedIncremental — checkbox, emitted ONLY when present in the yml.
    #    hidden/display/default_value are taken verbatim from the yml.
    fi_yml_param = _yml(FEEDINCREMENTAL_PARAM_NAME)
    fi_field_id = _field_id(FEEDINCREMENTAL_PARAM_NAME)
    if fi_yml_param is not None:
        fields.append(_build_feedincremental_field(
            yml_param=fi_yml_param,
            field_id=fi_field_id, title=fi_title,
        ))

    # --- §5. Strip all feed param names from mapper results -------------
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n for n in names if n not in _FEED_STRIPPED_PARAMS
        ]

    # --- §6a. Feed auto-enable via serializer computed_fields ------------
    # Like ``isFetch`` / ``isFetchEvents``, the ``feed`` toggle is NOT a
    # configurations field. Instead we inject ``feed: true`` into the
    # lifecycle notification when this capability is ``on`` (RULE 5 style).
    # There is no long-running case for feed, so this is unconditional.
    if handler_dir is not None:
        register_computed_field_entry(
            handler_dir,
            build_capability_gated_computed_field(
                output_id=FEED_PARAM_NAME,
                value=True,
                sub_capability_ids=[capability_id],
            ),
        )

    # --- §6. Sub-cap rename bridges (per emitted field) -----------------
    if is_sub_capability and handler_dir is not None:
        _original_to_renamed = {
            FEEDFETCHINTERVAL_PARAM_NAME: ffi_field_id,
            FEEDRELIABILITY_PARAM_NAME: fr_field_id,
            FEEDEXPIRATIONPOLICY_PARAM_NAME: fep_field_id,
            FEEDEXPIRATIONINTERVAL_PARAM_NAME: fei_field_id,
            FEEDREPUTATION_PARAM_NAME: frep_field_id,
            FEEDBYPASSEXCLUSIONLIST_PARAM_NAME: fbe_field_id,
        }
        # feedIncremental only gets a bridge when it was actually emitted.
        if fi_yml_param is not None:
            _original_to_renamed[FEEDINCREMENTAL_PARAM_NAME] = fi_field_id
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
_ISFETCH_DEFAULT_TITLE = "Fetch Issues"
# Per migration guide §line 890: the Platform incident-type field is
# user-visible with the hardcoded title "Issue Type" (NOT derived from the
# XSOAR yml ``display``, which is the legacy "Incident type").
_INCIDENTTYPE_DEFAULT_TITLE = "Issue Type"
_INCIDENTFETCHINTERVAL_DEFAULT_TITLE = "Issues Fetch Interval"
_MAPPER_INCOMING_DEFAULT_TITLE = "Incoming Mapper"
_CLASSIFIER_DEFAULT_TITLE = "Classifier"
_LONGRUNNING_DEFAULT_TITLE = "Long running instance"

# Per migration guide §line 890: the incident-type select carries a tooltip
# and a placeholder on the Platform.
_incidentType_HELP_TEXT = "select if classifier doesn't exist"
_incidentType_PLACEHOLDER = "Select an issue type"

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

# The mapper bucket key for the Fetch Issues capability. Must match
# ``connector_param_mapper.FETCH_ISSUES_CAPABILITIES`` — it is the key under
# which ``map_params_to_capabilities`` places this capability's params (incl.
# ``longRunning`` when Rule 7 routes long-running here). Used by
# ``add_fetch_issues_capability`` to decide whether to emit the longRunning
# checkbox in THIS capability.
FETCH_ISSUES_BUCKET_KEY = "Fetch Issues"

# Connector-side (Platform) field ids for the fetch-issues type/interval
# fields. Per migration guide §line 889-890 the Platform renames the legacy
# XSOAR ``incidentType``/``incidentFetchInterval`` params to ``incidentType``/
# ``alertFetchInterval`` on the connector side. The original XSOAR names are
# still consumed by the integration at runtime, so a serializer field_mapping
# bridges the Platform id back to the XSOAR name (see §6 of
# ``add_fetch_issues_capability``). ``dynamicField`` keeps the XSOAR provider
# hint ``"incident-type"`` regardless of the connector-side id.
incidentType_FIELD_ID = "incidentType"
ALERTFETCHINTERVAL_FIELD_ID = "alertFetchInterval"

# Connector-side field ids for the dynamic fields (mapper + classifier).
# These mirror the XSOAR instance-level field names (per migration guide
# Appendix J / §3.7): the classifier is stored under ``mappingId`` and the
# incoming mapper under ``incomingMapperId`` — NOT under the dynamic-field
# provider hints (``classifier`` / ``mapper-incoming``), which are passed
# separately as ``dynamicField``.
MAPPER_INCOMING_FIELD_ID = "incomingMapperId"
CLASSIFIER_FIELD_ID = "mappingId"

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
    """Build the ``isFetch`` checkbox field — visible, default ``False``.

    The fetch toggle is presented to the user (``hidden: false``) and is NOT
    forced on (``default_value: false``); enabling the capability plus this
    toggle is what turns fetching on. The user decides.
    """
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "options": {
            "default_value": False,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
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
    help_text: str = "",
    placeholder: str = "",
    config_type: str = "",
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
    if config_type:
        field["metadata"]["xsoar"] = {"config_type": config_type}
    if default_value:
        field["options"]["default_value"] = default_value
    if description:
        field["options"]["description"] = description
    if help_text:
        field["options"]["help_text"] = help_text
    if placeholder:
        field["options"]["placeholder"] = placeholder
    return field


def _build_longrunning_field(
    field_id: str,
    title: str,
) -> dict:
    """Build the ``longRunning`` checkbox field — visible, default ``False``.

    Emitted in whichever capability the param-capability mapper routed
    ``longRunning`` to (Fetch Issues or Log Collection). The toggle is
    presented to the user (``hidden: false``) and NOT forced on
    (``default_value: false``) — the user decides whether to run long-running.
    """
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "options": {
            "default_value": False,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
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
      6. ``longRunning`` — checkbox
         (only when the mapper routed ``longRunning`` to this capability's
         ``"Fetch Issues"`` bucket)

    Caller contract (mirrors the other ``add_<capability>_capability``
    builders):
      - ``capability_id``: connector-side capability id. Pass
        ``"fetch-issues"`` for the top-level case or a sub-cap id.
      - ``is_sub_capability``: flips the field-id naming.
      - ``is_long_running``: retained for backward compatibility only. The
        ``longRunning`` checkbox is now emitted (and stripped from
        ``mapped_params``) based on whether the param-capability mapper placed
        ``longRunning`` in this capability's ``"Fetch Issues"`` bucket — NOT
        on this flag. An integration may declare ``script.longRunning: true``
        yet have its long-running concept routed to another capability.
      - ``integration_yml``: the full integration YAML dict — needed for
        ``commonfields.id`` (dynamic field ``integrationID`` param),
        ``defaultmapperin``, and ``defaultclassifier``.

    Side effects:
      1. Strips ``isFetch``, ``incidentType``, ``incidentFetchInterval``,
         ``alertFetchInterval`` from every bucket of ``mapped_params``.
         When the mapper routed ``longRunning`` here, also strips
         ``longRunning``.
      2. Rename bridges via serializer for each renamed field. The
         Platform "alert" renames (``incidentType`` -> ``incidentType`` and
         ``incidentFetchInterval`` -> ``alertFetchInterval``, guide
         §line 889-890) always apply, so bridges are registered in BOTH the
         top-level and sub-capability paths whenever ``handler_dir`` is set;
         sub-cap prefixing adds bridges for the remaining fields.

    Returns:
      ``{"capability_id", "fields", "triggers"}`` — triggers is always
      empty for fetch-issues (no conditional reveal needed).
    """
    integration_id = (integration_yml.get("commonfields") or {}).get("id", "")

    # The ``longRunning`` checkbox is emitted here ONLY when the
    # param-capability mapper actually placed ``longRunning`` in THIS
    # capability's bucket (``"Fetch Issues"``). The raw ``script.longRunning``
    # flag is NOT sufficient: an integration may declare ``longRunning: true``
    # yet have its long-running concept routed to a different capability (e.g.
    # Akamai WAF SIEM routes it to Log Collection via
    # INTEGRATION_TO_LONGRUNNING_CAPABILITY). ``is_long_running`` is retained
    # in the signature for backward compatibility but no longer gates emission.
    emit_longrunning = LONGRUNNING_PARAM_NAME in (
        mapped_params.get(FETCH_ISSUES_BUCKET_KEY) or []
    )

    # --- §1. Resolve the connector-side field ids (sub-cap rename) ------
    def _field_id(original: str) -> str:
        return f"{capability_id}_{original}" if is_sub_capability else original

    isfetch_field_id = _field_id(ISFETCH_PARAM_NAME)
    # Per migration guide §line 889-890: the connector-side ids are the
    # Platform "alert" names, not the legacy XSOAR "incident" names. The
    # XSOAR names are bridged back via the serializer in §6 below.
    inctype_field_id = _field_id(incidentType_FIELD_ID)
    incfi_field_id = _field_id(ALERTFETCHINTERVAL_FIELD_ID)
    mapper_field_id = _field_id(MAPPER_INCOMING_FIELD_ID)
    classifier_field_id = _field_id(CLASSIFIER_FIELD_ID)
    lr_field_id = _field_id(LONGRUNNING_PARAM_NAME) if emit_longrunning else ""

    # --- §2. Resolve titles (generic helper) ----------------------------
    def align_incidents_to_issues(title: str) -> str:
        """Replace the legacy "Incidents" terminology with Platform "Issues".

        Per migration guide §3.7 field rule 2 / Appendix A: every occurrence
        of "Incidents"/"incidents" in a user-visible title must become
        "Issues" on the Platform marketplace. Returns the rewritten title
        (the previous implementation discarded the ``str.replace`` result and
        returned the input unchanged).
        """
        return title.replace("Incidents", "Issues").replace("incidents", "Issues")

    isfetch_title = _resolve_title_from_yml(
        yml_params_by_name, ISFETCH_PARAM_NAME,
        fallback=_ISFETCH_DEFAULT_TITLE,
    )
    isfetch_title = align_incidents_to_issues(isfetch_title)
    # Per migration guide §line 890: the incident-type field's title is the
    # hardcoded Platform label "Issue Type" — it is NOT derived from the XSOAR
    # yml ``display`` (which is the legacy "Incident type").
    inctype_title = _INCIDENTTYPE_DEFAULT_TITLE
    incfi_title = _resolve_title_from_yml(
        yml_params_by_name, INCIDENTFETCHINTERVAL_PARAM_NAME,
        fallback=_INCIDENTFETCHINTERVAL_DEFAULT_TITLE,
    )
    incfi_title = align_incidents_to_issues(incfi_title)

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

    # 1. isFetch — always emitted. Its visibility / default is decided by the
    # "count both checkboxes together" rule applied in §4b below.
    isfetch_field = _build_isfetch_field(
        field_id=isfetch_field_id, title=isfetch_title,
    )
    fields.append(isfetch_field)

    # 2. incidentType (XSOAR incidentType) — dynamic select.
    # Migration rule (Issue #8): emit the alert field ONLY when the source
    # XSOAR param exists in the integration yml. When present we carry its
    # ``defaultvalue`` (resolved into ``inctype_default`` above). The field is
    # migrated as ``incidentType`` with NO serializer bridge back to
    # ``incidentType`` — the platform consumes ``incidentType`` directly.
    fields.append(_build_dynamic_select_field(
        field_id=inctype_field_id,
        title=inctype_title,
        dynamic_field_type="incident-type",
        integration_id=integration_id,
        default_value=inctype_default,
        help_text=_incidentType_HELP_TEXT,
        placeholder=_incidentType_PLACEHOLDER,
    ))

    # 3. alertFetchInterval (XSOAR incidentFetchInterval) — duration picker.
    # Same migration rule: emit ONLY when the source param exists in the yml,
    # carrying its yml default. Migrated as ``alertFetchInterval`` with NO
    # serializer bridge back to ``incidentFetchInterval``.
    incfi_yml = _yml(INCIDENTFETCHINTERVAL_PARAM_NAME)
    fields.append(_build_incidentfetchinterval_field(
        yml_param=incfi_yml,
        field_id=incfi_field_id, title=incfi_title,
    ))

    # 4. incomingMapperId — dynamic select (backend-managed, Appendix J)
    fields.append(_build_dynamic_select_field(
        field_id=mapper_field_id,
        title=_MAPPER_INCOMING_DEFAULT_TITLE,
        dynamic_field_type="mapper-incoming",
        integration_id=integration_id,
        default_value=mapper_default,
        config_type="backend",
    ))

    # 5. mappingId (Classifier) — dynamic select (backend-managed, Appendix J)
    fields.append(_build_dynamic_select_field(
        field_id=classifier_field_id,
        title=_CLASSIFIER_DEFAULT_TITLE,
        dynamic_field_type="classifier",
        integration_id=integration_id,
        default_value=classifier_default,
        config_type="backend",
    ))

    # 6. longRunning — only when the mapper routed longRunning to this
    # capability's bucket (see ``emit_longrunning`` above).
    lr_field: dict | None = None
    if emit_longrunning:
        lr_field = _build_longrunning_field(
            field_id=lr_field_id,
            title=_LONGRUNNING_DEFAULT_TITLE,
        )
        fields.append(lr_field)

    # --- §4b. Fetch-checkbox visibility rule ----------------------------
    # The fetch-checkbox set for this capability is {isFetch, longRunning}.
    # isFetch is always emitted; longRunning only when routed here. A lone
    # checkbox is DROPPED from the manifest and its ``true`` value moved to a
    # serializer computed_fields rule gated on this capability; when both are
    # present they are shown + default False. The interval / dynamic-select
    # fields are never touched.
    #
    # No-real-fetch-flag carve-out: when the integration declares neither
    # ``script.isfetch: true`` NOR an ``isFetch`` config param, the synthetic
    # fetch toggle is not a genuine user choice — the capability only exists
    # because ``longRunning`` was routed here. In that case the synthetic fetch
    # toggle appears nowhere and ``longRunning`` moves to the serializer
    # computed_fields gated on the sub-capability (see the visibility helper).
    _script = (integration_yml.get("script") or {})
    has_real_fetch_flag = (
        _script.get("isfetch") is True
        or bool(yml_params_by_name and ISFETCH_PARAM_NAME in yml_params_by_name)
    )
    fetch_checkbox_fields = [isfetch_field]
    _checkbox_yml_names = {isfetch_field_id: ISFETCH_PARAM_NAME}
    if lr_field is not None:
        fetch_checkbox_fields.append(lr_field)
        _checkbox_yml_names[lr_field_id] = LONGRUNNING_PARAM_NAME
    kept_checkboxes = _apply_fetch_checkbox_visibility_rule(
        fetch_checkbox_fields,
        capability_id=capability_id,
        handler_dir=handler_dir,
        field_id_to_yml_name=_checkbox_yml_names,
        has_real_fetch_flag=has_real_fetch_flag,
        fetch_toggle_field_id=isfetch_field_id,
    )
    _kept_ids = {f.get("id") for f in kept_checkboxes}
    _dropped_ids = {
        f.get("id") for f in fetch_checkbox_fields if f.get("id") not in _kept_ids
    }
    if _dropped_ids:
        fields[:] = [f for f in fields if f.get("id") not in _dropped_ids]

    # --- §5. Strip fetch-issues param names from mapper results ---------
    stripped = set(_FETCH_ISSUES_STRIPPED_PARAMS)
    if emit_longrunning:
        stripped.add(LONGRUNNING_PARAM_NAME)
    for cap_name in list(mapped_params.keys()):
        names = mapped_params.get(cap_name) or []
        mapped_params[cap_name] = [
            n for n in names if n not in stripped
        ]

    # --- §6. Rename bridges (per emitted field) ------------------------
    # Serializer field_mappings bridge the connector-side id back to the XSOAR
    # yml param name. The ONLY rename source here is the sub-capability prefix
    # (``<capability_id>_<name>``), applied to every field when
    # ``is_sub_capability`` is True.
    #
    # Migration rule (Issue #8): the Platform "alert" renames
    # (``incidentType`` -> ``incidentType`` and
    # ``incidentFetchInterval`` -> ``alertFetchInterval``) are NO LONGER
    # bridged — the alert fields are migrated as ``incidentType`` /
    # ``alertFetchInterval`` and the platform consumes those names directly.
    # They are therefore excluded from the bridge map. (Sub-cap prefixing is
    # also not bridged for the alert fields, matching the no-serialization
    # contract.)
    if handler_dir is not None:
        _original_to_renamed = {
            ISFETCH_PARAM_NAME: isfetch_field_id,
            MAPPER_INCOMING_FIELD_ID: mapper_field_id,
            CLASSIFIER_FIELD_ID: classifier_field_id,
        }
        if emit_longrunning:
            _original_to_renamed[LONGRUNNING_PARAM_NAME] = lr_field_id
        for original, renamed in _original_to_renamed.items():
            # Skip checkboxes dropped by the visibility rule — their value
            # already flows via computed_fields, no manifest field to rename.
            if renamed in _dropped_ids:
                continue
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
            "placeholder": "Enter a unique name for this instance",
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


def _required_license_for_capability(sub_cap_ids: list[str]) -> list[str]:
    """Compute ``config.required_license`` for a capability.

    The capability's licenses are the deduped UNION of the licenses of every
    sub-capability registered under it, resolved from
    ``sub_capabilities_to_licenses.json`` (the single source of truth). There
    is no ``supportedModules`` fallback and no agentix/xsiam post-filtering.

    Args:
        sub_cap_ids: the sub_capability ids registered under this capability
            (e.g. ``["automation-and-remediation_absolute"]``).

    Returns:
        The deduped union license list (sorted for deterministic output).

    Raises:
        RuntimeError: if any sub_capability id is absent from the JSON
            (propagated from :func:`union_licenses_for_sub_caps`).
    """
    return union_licenses_for_sub_caps(sub_cap_ids)


def _set_capability_required_license(cap_entry: dict) -> None:
    """Set ``cap_entry["config"]["required_license"]`` from its sub-caps.

    Recomputes the capability's ``config.required_license`` as the deduped
    union of the licenses of every sub-capability currently listed under
    ``cap_entry["sub_capabilities"]`` (resolved from
    ``sub_capabilities_to_licenses.json``). Mutates ``cap_entry`` in place.

    Used by the append-handler path so a parent capability always reflects
    the licenses of ALL its registered sub-capabilities after one is added
    or the capability is promoted from flat to sub-cap form.

    Raises:
        RuntimeError: if any sub_capability id is absent from the JSON
            (propagated from :func:`union_licenses_for_sub_caps`).
    """
    sub_cap_ids = [
        sub.get("id", "")
        for sub in cap_entry.get("sub_capabilities") or []
        if sub.get("id")
    ]
    cap_entry["config"] = {
        "required_license": union_licenses_for_sub_caps(sub_cap_ids)
    }


def build_capabilities_yaml(
    mapped_params: dict[str, Any],
    yml_params_by_name: dict[str, dict] | None = None,
    handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
    integration_name: str = "",
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
      - ``default_enabled: False`` (per Salesforce reference §4.3)
      - ``required: false`` (per guide §3.4: "Always false")

    ``config.required_license`` is the union of the licenses of the
    capability's sub-capabilities, resolved from
    ``sub_capabilities_to_licenses.json`` (single source of truth). It is
    only emitted when ``handler_id`` is supplied (so a sub-capability id
    exists to resolve licenses for). Legacy callers omitting ``handler_id``
    get bare-id capability entries with no ``config``.

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
            "default_enabled": False,
            "required": False,
        }
        # Capabilities are ALWAYS modelled as parent + one sub-capability,
        # even on a fresh connector. The parent carries the canonical family
        # id/title; the lone sub-capability is keyed by this handler's sub-cap
        # id ``<capability_id>_<integration-id-slug>`` (the id the
        # handler.yaml and configurations.yaml entries reference) and titled
        # after the integration's display ``name``. The bare-slug fallback
        # only applies when no handler_id is supplied (legacy callers).
        #
        # Per guide §3.1 item 13: a capability with exactly ONE
        # sub-capability marks that lone sub-cap ``required: true`` so
        # selecting the parent implies the sub-cap.
        if handler_id:
            sub_cap_id = make_sub_capability_id(handler_id, cap_name)
            parent_entry["sub_capabilities"] = [
                build_sub_capability_entry(
                    sub_cap_id,
                    cap_name,
                    integration_name=integration_name,
                )
            ]
            # config.required_license — the union of the licenses of every
            # sub-capability registered under this capability (here, the one
            # this handler exposes), resolved from
            # sub_capabilities_to_licenses.json (single source of truth).
            parent_entry["config"] = {
                "required_license": _required_license_for_capability(
                    [sub_cap_id]
                )
            }
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
        _dump_yaml(capabilities_data, fh)


# ---------------------------------------------------------------------------
# Per-handler general_configurations fields
# ---------------------------------------------------------------------------
# Per the grouped-example reference, every handler added to a connector
# gets an ``integrationLogLevel`` field in configurations.yaml →
# general_configurations, inside a view_group-pinned field group where
# view_group id = handler id. By default the field keeps its bare canonical
# id (``integrationLogLevel``) with NO handler-id prefix and NO serializer
# entry. Only when the bare id collides with another emitted field is it
# renamed to ``<handler_id>_<id>`` and bridged back to its canonical name
# via a serializer ``field_mappings`` entry.
#
# The ``defaultIgnore`` field ("Do not use in CLI by default") is NO longer
# emitted unconditionally in general_configurations. It only makes sense for
# handlers exposing automation/CLI commands, so it is injected under the
# ``automation-and-remediation`` (sub-)capability entry in
# configurations.yaml — and ONLY when the handler declares the Automation
# capability (the ``"Automation"`` bucket key in ``mapped_params``).

# Canonical base param names (the XSOAR runtime expects these).
_INTEGRATION_LOG_LEVEL_PARAM = "integrationLogLevel"
_DEFAULT_IGNORE_PARAM = "defaultIgnore"

# The mapper bucket key that maps to the automation-and-remediation
# capability. ``defaultIgnore`` is only emitted when this bucket is present.
_AUTOMATION_BUCKET_KEY = "Automation"


def _per_handler_log_level_field(handler_id: str, field_id: str) -> dict:
    """Build the per-handler ``integrationLogLevel`` field.

    Each handler gets an ``integrationLogLevel`` select field in
    ``configurations.yaml`` → ``general_configurations``, pinned to
    the handler's ``view_group``. ``field_id`` is the resolved
    connector id (bare ``integrationLogLevel`` by default, or
    ``<handler_id>_integrationLogLevel`` only when the bare id
    collides — in which case the caller registers the serializer
    mapping back to ``integrationLogLevel``).

    Shape matches the grouped-example reference (lines 100-124 of
    ``configurations.yaml``).
    """
    return {
        "id": field_id,
        "title": "Log Level",
        "field_type": "select",
        "metadata": {
            "xsoar": {
                "config_type": "backend",
            },
        },
        "options": {
            "description": f"Set the log level for {handler_id}.",
            "placeholder": "Select log level",
            "default_value": "Off",
            # Every select/multi_select must be searchable + clearable
            # (guide §2.15).
            "searchable": True,
            "clearable": True,
            "values": [
                {"key": "Off", "label": "Off"},
                {"key": "Debug", "label": "Debug"},
                {"key": "Verbose", "label": "Verbose"},
            ],
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def _per_handler_default_ignore_field(field_id: str) -> dict:
    """Build the ``defaultIgnore`` checkbox field.

    Per the grouped-example reference (lines 325-338 of
    ``configurations.yaml``): "Do not use in CLI by default" — a
    visible checkbox, always default ``false``, backend-managed.
    ``field_id`` is the resolved connector id (bare ``defaultIgnore``
    by default, or ``<handler_id>_defaultIgnore`` only on collision).

    This field is emitted under the ``automation-and-remediation``
    (sub-)capability entry in ``configurations.yaml`` (NOT in
    general_configurations) and only when the handler declares the
    Automation capability — it controls whether the connector's automation
    commands are used in the CLI by default.

    Shape matches the grouped-example reference.
    """
    return {
        "id": field_id,
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


def build_default_ignore_capability_field(
    handler_id: str,
    handler_dir: Path,
    existing_ids: set[str] | None = None,
) -> dict:
    """Build the ``defaultIgnore`` field for the automation capability.

    Resolves the connector field id via the same collision-based dedup as the
    other per-handler fields: by default it keeps the bare canonical id
    (``defaultIgnore``) with NO prefix and NO serializer entry; only when the
    bare id already collides with another emitted field does
    :func:`dedup_field_id_and_register` rename it to
    ``<handler_id>_defaultIgnore`` and append the serializer ``field_mappings``
    bridge back to the canonical name. ``existing_ids`` is mutated in place.

    The returned field is intended to be injected (by the caller) into the
    ``automation-and-remediation`` (sub-)capability entry in
    ``configurations.yaml`` — and ONLY when the handler declares the Automation
    capability.
    """
    ids = existing_ids if existing_ids is not None else set()
    default_ignore_id = dedup_field_id_and_register(
        ids, handler_id, handler_dir, _DEFAULT_IGNORE_PARAM
    )
    return _per_handler_default_ignore_field(default_ignore_id)


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

    The ``integrationLogLevel`` field keeps its bare canonical id by default
    (no prefix, no serializer entry). Only on an id collision is it renamed
    to ``<handler_id>_<id>`` and a serializer ``field_mappings`` entry
    registered so the XSOAR runtime still receives the canonical param name.

    NOTE: ``defaultIgnore`` is NO longer emitted here. It is injected under
    the ``automation-and-remediation`` (sub-)capability entry in
    ``configurations.yaml`` — and only when the handler declares the
    Automation capability — via :func:`build_default_ignore_capability_field`.

    The caller is responsible for:
      1. Adding the returned dict to
         ``configurations_data["general_configurations"]["configurations"]``.
      2. Adding a ``view_groups`` registry entry
         ``{"id": handler_id, "label": handler_id}`` to
         ``configurations_data["view_groups"]``.
    """
    # Resolve the connector field id via collision-based dedup: by default
    # ``integrationLogLevel`` keeps its bare canonical id with NO prefix and
    # NO serializer entry. Only when the bare id already collides with another
    # emitted field does ``dedup_field_id_and_register`` rename it to
    # ``<handler_id>_<id>`` and append the serializer ``field_mappings`` bridge
    # back to the canonical name. ``existing_ids`` is mutated in place.
    ids = existing_ids if existing_ids is not None else set()
    log_level_id = dedup_field_id_and_register(
        ids, handler_id, handler_dir, _INTEGRATION_LOG_LEVEL_PARAM
    )

    log_level = _per_handler_log_level_field(handler_id, log_level_id)

    fields: list[dict] = [log_level]

    # User-mapped general_configurations params — emitted here (in
    # configurations.yaml) rather than in capabilities.yaml, each
    # pinned to this handler's view_group.
    reserved_ids = {"instance_name", "integrationLogLevel", "defaultIgnore"}
    # general_configurations params are NOT attached to any single capability,
    # so hidden-default ones moved to serializer computed_fields are gated on
    # ALL of the handler's capabilities (OR logic).
    all_cap_ids = (
        [
            (
                make_sub_capability_id(handler_id, cap_name)
                if handler_id
                else slugify_capability_name(cap_name)
            )
            for cap_name in mapped_params
            if cap_name != "general_configurations"
        ]
        if mapped_params
        else []
    )
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
                    gating_capability_ids=all_cap_ids,
                )
            )

    result: dict = {
        "view_group": view_group_id_for_handler(handler_id),
        "fields": fields,
    }

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
    # Pre-compute the set of all sub-capability ids for this handler — used to
    # gate ``general_configurations`` hidden-default params (which are not
    # attached to any single capability) across ALL of the handler's
    # capabilities (OR logic) when moved to serializer computed_fields.
    all_cap_ids = [
        (
            make_sub_capability_id(handler_id, cap_name)
            if handler_id
            else slugify_capability_name(cap_name)
        )
        for cap_name in mapped_params
        if cap_name != "general_configurations"
    ]

    configurations = []
    for cap_name, params in mapped_params.items():
        if cap_name == "general_configurations":
            continue
        # Capabilities are ALWAYS modelled as sub-capabilities — key each
        # per-capability configuration entry by the sub-cap id
        # ``<capability_id>_<integration-id-slug>`` so it matches the
        # sub-capability emitted
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
                    # Capability-attached hidden-default params gate on THIS
                    # sub-capability being enabled.
                    gating_capability_ids=[cap_id],
                )
            )
        entry: dict = {
            "id": cap_id,
            "configurations": [{"fields": fields}],
        }
        # Per grouped-example reference: each per-capability entry carries a
        # ``view_group`` tile id so the FE knows which tile to render it under.
        # The tile id is the integration slug (== connection.yaml's tile id),
        # NOT the handler id, so connection + configuration rows share a tile.
        if handler_id:
            entry["view_group"] = view_group_id_for_handler(handler_id)
        configurations.append(entry)

    return {
        "metadata": {
            "title": "Configuration",
            "description": "Adjust and refine your configuration",
        },
        "configurations": configurations,
    }


def inject_synthetic_capability_fields(
    configurations_data: dict,
    cap_name: str,
    synthetic_fields: list[dict],
    handler_id: str = "",
) -> None:
    """Prepend builder-produced synthetic fields into a sub-capability entry.

    Capability builders such as :func:`add_fetch_issues_capability` and
    :func:`add_indicators_capability` return their platform-mandated fields
    (e.g. ``isFetch`` / ``incidentType`` / ``incidentFetchInterval`` /
    ``mapper-incoming`` / ``classifier`` for fetch-issues) SEPARATELY from
    ``mapped_params`` — and strip the corresponding raw param names from
    ``mapped_params`` so they are not emitted twice. Those returned fields
    must still be written into the matching ``configurations.yaml``
    sub-capability entry, otherwise they are silently lost (the historical
    bug: callers only consumed the builder's ``triggers`` and discarded its
    ``fields``).

    This injects ``synthetic_fields`` at the FRONT of the matching sub-cap
    entry's first field group (so the platform fields render before any
    remaining user-mapped params). The entry is matched by re-deriving its id
    from ``cap_name`` the same way :func:`build_configurations_yaml` does
    (``make_sub_capability_id(handler_id, cap_name)`` when ``handler_id`` is
    set, else the bare slug). When no matching entry exists yet (e.g. the
    bucket had no raw params so it was skipped), a new entry is created.
    """
    if not synthetic_fields:
        return

    cap_id = (
        make_sub_capability_id(handler_id, cap_name)
        if handler_id
        else slugify_capability_name(cap_name)
    )

    entries = configurations_data.setdefault("configurations", [])
    target = next((e for e in entries if e.get("id") == cap_id), None)

    if target is None:
        target = {"id": cap_id, "configurations": [{"fields": []}]}
        if handler_id:
            target["view_group"] = view_group_id_for_handler(handler_id)
        entries.append(target)

    groups = target.setdefault("configurations", [{"fields": []}])
    if not groups:
        groups.append({"fields": []})
    first_group = groups[0]
    existing = first_group.setdefault("fields", [])
    # Prepend, skipping any field id already present (idempotent / no dupes).
    existing_ids = {f.get("id") for f in existing}
    to_add = [f for f in synthetic_fields if f.get("id") not in existing_ids]
    first_group["fields"] = to_add + existing


def _is_sweep_removed_field(field: dict) -> bool:
    """Return True if ``field`` is a hidden+default field the sweep will REMOVE.

    :func:`sweep_hidden_defaults_to_serializer` moves hidden fields that carry a
    ``default_value`` OUT of configurations.yaml into the handler's serializer
    ``computed_fields``, matching them by their ORIGINAL (builder) id. Such
    fields must therefore NOT be id-renamed by the connector-wide dedup at
    injection time: renaming would (a) hide them from the sweep's original-name
    match and (b) leave a hidden+default field in configurations.yaml, tripping
    :func:`assert_no_hidden_defaults_in_configurations`.

    EXCEPTION — :data:`SWEEP_EXCLUDED_PARAMS` (currently only
    ``feedExpirationInterval``): these are the one class of fields that
    legitimately STAY in configurations.yaml hidden+with-default (revealed by a
    visibility trigger). They are NOT removed by the sweep, so they DO get
    deduped+serialized like every other field (and their trigger is updated to
    the renamed id by the caller). Hence they return False here.

    Detection mirrors the guard: hidden when EITHER ``create_modifiers`` or
    ``edit_modifiers`` has ``hidden: True``, and a ``default_value`` is present.
    """
    if str(field.get("id", "")) in SWEEP_EXCLUDED_PARAMS:
        # Stays in configurations.yaml — dedup it like a normal field.
        return False
    options = field.get("options")
    if not isinstance(options, dict):
        return False
    if "default_value" not in options:
        return False
    for mod_key in ("create_modifiers", "edit_modifiers"):
        mod = options.get(mod_key)
        if isinstance(mod, dict) and mod.get("hidden") is True:
            return True
    return False


def _rewrite_trigger_field_ids(
    triggers: list[dict], rename_map: dict[str, str]
) -> list[dict]:
    """Rewrite every ``id`` reference inside ``triggers`` using ``rename_map``.

    Capability builders emit visibility triggers (e.g. the
    ``feedExpirationInterval`` reveal trigger) keyed by the field's BARE id.
    When the connector-wide dedup renames a referenced field on a 2nd+ handler
    (``feedExpirationInterval`` -> ``<handler_id>_feedExpirationInterval``), the
    trigger must reference the renamed id too, or triggers.yaml points at a
    field that no longer exists under that id. This walks the trigger structure
    (``conditions`` / ``effects`` / nested ``children``) and replaces any ``id``
    value present in ``rename_map``. Returns the same list (mutated in place);
    a no-op when ``rename_map`` is empty.
    """
    if not rename_map:
        return triggers

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            fid = node.get("id")
            if isinstance(fid, str) and fid in rename_map:
                node["id"] = rename_map[fid]
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    for trigger in triggers:
        _walk(trigger)
    return triggers


def _inject_append_capability_fields(
    configurations_data: dict,
    sub_cap_id: str | None,
    handler_id: str,
    synthetic_fields: list[dict],
    existing_ids: set[str] | None = None,
    handler_dir: Path | None = None,
) -> dict[str, str]:
    """Inject synthetic capability fields by an already-resolved sub-cap id.

    The append path resolves each capability's sub-cap id up front
    (``cap_name_to_handler_cap_id``); this matches the configurations sub-cap
    entry by that exact id and prepends the builder's synthetic fields. When
    no matching entry exists yet, a new view_group-pinned entry is created.

    Generic id-dedup (Appendix C): every synthetic field a capability builder
    produces (``isFetch`` / ``incidentType`` / ``mappingId`` / ``feed*`` /
    ``defaultIgnore`` / assets / secrets / ... — ANY capability type) carries a
    BARE id. When ``existing_ids`` (the connector-wide claimed-id set) and
    ``handler_dir`` are supplied, each injected field is deduped against that
    set via :func:`dedup_field_id_and_register`: on collision the field is
    renamed ``<handler_id>_<id>`` and a serializer ``field_mappings`` bridge is
    registered so the XSOAR runtime still receives the canonical param name.
    ``existing_ids`` is mutated in place so later injects (and other field
    surfaces) see freshly-claimed ids. Without those args the previous
    local-only dedup applies (back-compat for callers that don't dedup).

    Returns a ``{original_id: renamed_id}`` map of every field actually renamed
    by the dedup. The caller uses this to rewrite any builder-produced TRIGGER
    that references a renamed field id (e.g. the ``feedExpirationInterval``
    reveal trigger) so triggers.yaml stays consistent with the renamed fields.

    Hidden+default fields the sweep will REMOVE (per :func:`_is_sweep_removed_field`)
    are left bare so :func:`sweep_hidden_defaults_to_serializer` can relocate
    them by their original id. The one exception class, ``SWEEP_EXCLUDED_PARAMS``
    (``feedExpirationInterval``), STAYS in configurations.yaml hidden+default and
    IS deduped like a normal field — its trigger is rewritten via the returned
    map.
    """
    rename_map: dict[str, str] = {}
    if not synthetic_fields or not sub_cap_id:
        return rename_map

    entries = configurations_data.setdefault("configurations", [])
    target = next((e for e in entries if e.get("id") == sub_cap_id), None)
    if target is None:
        target = {"id": sub_cap_id, "configurations": [{"fields": []}]}
        if handler_id:
            target["view_group"] = view_group_id_for_handler(handler_id)
        entries.append(target)

    groups = target.setdefault("configurations", [{"fields": []}])
    if not groups:
        groups.append({"fields": []})
    first_group = groups[0]
    existing = first_group.setdefault("fields", [])
    local_ids = {f.get("id") for f in existing}

    to_add: list[dict] = []
    for field in synthetic_fields:
        original_id = field.get("id")
        if original_id in local_ids:
            # Already present in THIS group (idempotent re-inject) — skip.
            continue
        if (
            original_id
            and existing_ids is not None
            and handler_dir is not None
            and not _is_sweep_removed_field(field)
        ):
            # Connector-wide dedup: rename + serializer-bridge on collision.
            # Fields the sweep will REMOVE are excluded (left bare) so the sweep
            # finds them by original id; everything else — including the
            # hidden+default ``feedExpirationInterval`` that STAYS in configs —
            # is deduped here.
            resolved_id = dedup_field_id_and_register(
                existing_ids, handler_id, handler_dir, original_id
            )
            if resolved_id != original_id:
                field = dict(field)
                field["id"] = resolved_id
                rename_map[original_id] = resolved_id
        to_add.append(field)
    first_group["fields"] = to_add + existing
    return rename_map


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
        _dump_yaml(data, fh)


def _recover_integration_name_for_handler(
    connector_dir: Path, handler_id: str
) -> str:
    """Best-effort recovery of an existing handler's integration display name.

    Used by the Case 2 promotion path, where an already-written handler's
    sub-capability must be (re)built but the original integration YAML is no
    longer in scope. We read the handler's ``handler.yaml`` and prefer the
    integration display name implied by the ``metadata.description`` (which
    :func:`build_handler_yaml` writes as ``"XSOAR handler for <name>
    integration."``). When that cannot be parsed, we fall back to a
    title-cased form of the integration-id slug recovered from the handler id
    and log a flag for manual review.
    """
    handler_yaml_path = (
        connector_dir / "components" / "handlers" / handler_id / "handler.yaml"
    )
    if handler_yaml_path.is_file():
        try:
            with open(handler_yaml_path) as fh:
                first_line = fh.readline()
                rest = fh.read()
            if not first_line.startswith("# yaml-language-server"):
                rest = first_line + rest
            data = yaml.safe_load(io.StringIO(rest)) or {}
            description = (data.get("metadata") or {}).get("description") or ""
            match = re.match(
                r"^XSOAR handler for (.+)\.$", description.strip()
            )
            if match:
                return match.group(1)
        except Exception as exc:
            logger.warning(
                f"[manifest_generator] Failed to recover integration name from "
                f"{handler_yaml_path}: {exc}; falling back to slug-derived title."
            )
    # Fallback: title-case the integration-id slug recovered from the handler id.
    slug = handler_id_to_integration_slug(handler_id)
    fallback = " ".join(w.capitalize() for w in slug.split("-") if w)
    logger.warning(
        f"[manifest_generator] Could not resolve integration display name for "
        f"existing handler '{handler_id}'; using slug-derived title "
        f"'{fallback}'. Flag for manual review."
    )
    return fallback


def append_capability_to_files(
    cap_name: str,
    cap_params: list[str],
    new_handler_id: str,
    capabilities_data: dict,
    configurations_data: dict,
    connector_dir: Path,
    yml_params_by_name: dict[str, dict] | None = None,
    existing_ids: set[str] | None = None,
    integration_name: str = "",
) -> str:
    """Process one capability for the append-handler path.

    Determines which case applies (1, 2, or 3) and mutates
    ``capabilities_data``, ``configurations_data``, and (for Case 2) the
    existing handler.yaml file.

    ``integration_name`` is the NEW handler's integration display ``name``
    (the ``name`` field from the integration YAML). It titles every
    sub-capability this call creates for the new handler. For the Case 2
    promotion path the EXISTING handler's integration name is recovered
    separately via :func:`_recover_integration_name_for_handler`.

    Returns the cap id that the NEW handler should reference in its own
    handler.yaml ``capabilities`` list — the sub-cap id
    ``<capability_id>_<integration-id-slug>`` for all cases.

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

    cap_slug = slugify_capability_name(cap_name)
    new_sub_cap_id = make_sub_capability_id(new_handler_id, cap_name)

    def _emit_fields(params: list[str]) -> list[dict]:
        result: list[dict] = []
        for p in params:
            # Skip params OWNED by a rich capability builder
            # (:func:`add_indicators_capability` /
            # :func:`add_fetch_issues_capability`). Those builders emit the
            # full-shape field (with values / triggers) and inject it
            # separately later in the append flow; emitting them here too would
            # duplicate the field in the sub-capability entry (e.g. a generic
            # ``feedReliability`` with empty ``values`` AND the rich one). The
            # from-scratch path avoids this by stripping these from
            # ``mapped_params`` BEFORE building configurations; on the append
            # path the builders run after this emit, so we filter here instead.
            if p in _FEED_STRIPPED_PARAMS or p in _FETCH_ISSUES_STRIPPED_PARAMS:
                continue
            result.extend(
                emit_field_for_param(
                    p,
                    yml_params_by_name,
                    handler_id=new_handler_id,
                    handler_dir=handler_dir,
                    existing_ids=existing_ids,
                    # Capability-attached hidden-default params gate on the
                    # sub-capability being appended.
                    gating_capability_ids=[new_sub_cap_id],
                )
            )
        return result

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
        new_cap_entry = {
            "id": cap_slug,
            "title": CANONICAL_CAPABILITY_TITLES[cap_slug],
            # capabilities.schema REQUIRES a non-empty description on every
            # capability — mirror the from-scratch build_capabilities_yaml path
            # so append-created capabilities (fetch-issues, log-collection, …)
            # are not emitted without one.
            "description": CANONICAL_CAPABILITY_DESCRIPTIONS[cap_slug],
            "default_enabled": False,
            "required": False,
            "sub_capabilities": [
                build_sub_capability_entry(
                    new_sub_cap_id,
                    cap_name,
                    integration_name=integration_name,
                )
            ],
        }
        # config.required_license — union of this capability's sub-cap
        # licenses (here, the single new sub-cap) from
        # sub_capabilities_to_licenses.json.
        _set_capability_required_license(new_cap_entry)
        capabilities_data.setdefault("capabilities", []).append(new_cap_entry)
        configurations_data.setdefault("configurations", []).append(
            {
                "id": new_sub_cap_id,
                "view_group": view_group_id_for_handler(new_handler_id),
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
        existing_integration_name = _recover_integration_name_for_handler(
            connector_dir, existing_handler_id
        )

        # Phase 2.1: rename cap id inside the existing handler.yaml.
        rename_handler_capability_id(
            existing_handler_path, cap_slug, existing_sub_cap_id
        )

        # Phase 2.2: introduce sub_capabilities on the parent in capabilities.yaml.
        existing_cap["sub_capabilities"] = [
            build_sub_capability_entry(
                existing_sub_cap_id,
                cap_name,
                integration_name=existing_integration_name,
            )
        ]

        # Phase 2.3: rename the existing top-level entry in configurations.yaml
        # (per spec: drop parent's entry — the renamed entry IS the new sub-cap entry).
        for cfg_entry in configurations_data.get("configurations", []) or []:
            if cfg_entry.get("id") == cap_slug:
                cfg_entry["id"] = existing_sub_cap_id
                break

    # Case 1 (or fall-through after promotion): append the new sub-cap.
    existing_cap.setdefault("sub_capabilities", []).append(
        build_sub_capability_entry(
            new_sub_cap_id, cap_name, integration_name=integration_name
        )
    )
    configurations_data.setdefault("configurations", []).append(
        {
            "id": new_sub_cap_id,
            "view_group": view_group_id_for_handler(new_handler_id),
            "configurations": [{"fields": _emit_fields(cap_params)}],
        }
    )

    # Recompute the parent's config.required_license as the union of ALL its
    # sub-capabilities' licenses (Case 1 append + Case 2 promotion both add a
    # sub-cap, so the parent must reflect every registered sub-cap).
    _set_capability_required_license(existing_cap)

    return new_sub_cap_id


def merge_general_configurations(
    capabilities_data: dict,
    new_general_params: list[str],
    yml_params_by_name: dict[str, dict] | None = None,
    new_handler_id: str = "",
    handler_dir: Path | None = None,
    existing_ids: set[str] | None = None,
    gating_capability_ids: list[str] | None = None,
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
            gating_capability_ids=gating_capability_ids,
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


def collect_fetch_sub_cap_ids(
    mapped_params: dict[str, Any], handler_id: str
) -> list[str]:
    """Return the fetch sub-capability ids declared by ONE handler.

    For each bucket key in ``mapped_params`` that is a fetch (collection)
    capability (:data:`_FETCH_MUTEX_BUCKET_KEYS`), compute the handler's
    sub-capability id via :func:`make_sub_capability_id`. The result drives
    the per-handler fetch mutex (guide §3.4 note 7 + §3.5).

    Order is deterministic (sorted by sub-cap id) so the emitted mutex
    triggers are stable across runs. ``general_configurations`` and any
    non-fetch capability bucket are ignored.
    """
    ids = {
        make_sub_capability_id(handler_id, cap_name)
        for cap_name in mapped_params
        if cap_name in _FETCH_MUTEX_BUCKET_KEYS
    }
    return sorted(ids)


def build_fetch_mutex_triggers(fetch_sub_cap_ids: list[str]) -> list[dict]:
    """Build the per-handler fetch-mutex triggers (guide §3.4 note 7 + §3.5).

    Given the fetch sub-capability ids of a SINGLE handler, emit one trigger
    for every ordered pair ``(other, current)`` of distinct ids. Each trigger
    locks ``current`` (``read_only: true``) while ``other`` is selected, so the
    user can enable only one of the handler's fetch capabilities at a time.

    For ``n`` fetch sub-capabilities this produces ``n × (n - 1)`` triggers
    (each direction is a separate trigger because ``effect.id`` is a single
    value). 0 or 1 fetch sub-capability → no triggers (an empty list).

    Condition shape uses the Triggers v2 capability-state form
    (``behavior: selected``, ``operator: eq``, ``value: true``); ``message``
    is allowed because the condition tree contains a capability condition.
    """
    triggers: list[dict] = []
    for other_id in fetch_sub_cap_ids:
        for current_id in fetch_sub_cap_ids:
            if other_id == current_id:
                continue
            triggers.append(
                {
                    "conditions": {
                        "id": other_id,
                        "behavior": "selected",
                        "operator": "eq",
                        "value": True,
                    },
                    "effects": [
                        {
                            "id": current_id,
                            "action": {"read_only": True},
                            "message": _FETCH_MUTEX_MESSAGE,
                        }
                    ],
                }
            )
    return triggers


def build_collection_automation_triggers(
    fetch_sub_cap_ids: list[str], automation_sub_cap_id: str
) -> list[dict]:
    """Build the collection → automation auto-enable + lock triggers (guide §3.5.1).

    For EACH of a handler's fetch (collection) sub-capability ids, emit one
    trigger that — when that collection sub-capability is selected — auto-enables
    AND locks the handler's ``automation-and-remediation`` sub-capability. Every
    fetch type also needs automation, so selecting a collection sub-cap forces
    the automation sub-cap ON (``enabled: true``) and locks it
    (``read_only: true``) until the dependency is cleared. The effect is
    reversible (guide §2.10).

    Args:
        fetch_sub_cap_ids: The handler's fetch (collection) sub-capability ids
            (e.g. from :func:`collect_fetch_sub_cap_ids`).
        automation_sub_cap_id: The handler's ``automation-and-remediation``
            sub-capability id (target of the auto-enable + lock effect).

    Returns:
        One trigger per fetch sub-cap id, all targeting
        ``automation_sub_cap_id``. Empty list when the handler contributes no
        collection sub-capabilities (nothing to gate the automation lock on)
        or has no automation sub-capability.

    Condition shape uses the Triggers v2 capability-state form
    (``behavior: selected``, ``operator: eq``, ``value: true``); ``message`` is
    allowed because the condition tree contains a capability condition.
    """
    if not automation_sub_cap_id:
        return []
    triggers: list[dict] = []
    for fetch_id in fetch_sub_cap_ids:
        triggers.append(
            {
                "conditions": {
                    "id": fetch_id,
                    "behavior": "selected",
                    "operator": "eq",
                    "value": True,
                },
                "effects": [
                    {
                        "id": automation_sub_cap_id,
                        "action": {"read_only": True, "enabled": True},
                        "message": _COLLECTION_AUTOMATION_MESSAGE,
                    }
                ],
            }
        )
    return triggers


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
        A dict ready for serialization via :func:`_dump_yaml`.
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
        _dump_yaml(triggers_data, fh)


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
    # Normalize so each field occupies its own ``fields`` block (guide §3.7
    # item 2) — applied at write time so in-memory builder state is untouched.
    connection_data = normalize_connection_field_blocks(connection_data)
    with open(connection_yaml_path, "w") as fh:
        fh.write(CONNECTION_SCHEMA_DIRECTIVE)
        _dump_yaml(connection_data, fh)


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
    field = {"id": yml_param["name"], "field_type": "input", "options": {"mask": False}}
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


def _apply_searchable_clearable(field: dict) -> dict:
    """Set ``options.searchable`` / ``options.clearable`` to ``True`` in place.

    Every ``select`` / ``multi_select`` field MUST be searchable and clearable
    (guide §2.15 / §3.7 field rule 9). Centralizes the rule so all
    select/multi_select mappers stay in lockstep. Returns ``field`` for
    chaining.
    """
    options = field.setdefault("options", {})
    options["searchable"] = True
    options["clearable"] = True
    return field


def _map_type_13(yml_param: dict) -> dict:
    """XSOAR type 13 — Single-select (system catalogue) → connectus `select`."""
    field = {
        "id": yml_param["name"],
        "field_type": "select",
        "options": {"values": _build_select_values(yml_param, label_key="label")},
    }
    _apply_searchable_clearable(field)
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
    _apply_searchable_clearable(field)
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
    _apply_searchable_clearable(field)
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
    {"key": "indicatorType", "label": "indicatorType"},
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
    _apply_searchable_clearable(field)
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
    _apply_searchable_clearable(field)
    _apply_common_field_metadata(field, yml_param)
    return field


def _map_type_19(yml_param: dict) -> dict:
    """XSOAR type 19 — Feed/Fetch Interval → connectus ``duration``.

    Per the migration guide (Appendix A type 19, §2.14/§2.15, §3.7), an
    interval field renders as a multi-unit ``duration`` picker — NOT a bare
    numeric ``input``. The XSOAR ``defaultvalue`` is a single integer count
    of MINUTES (e.g. ``"240"``) which is decomposed into a per-unit object
    via :func:`_minutes_to_duration_default`.

    The duration migration contract (§2.15) requires:
      - ``options.units == ["days", "hours", "minutes"]``
      - ``output_format: "minutes"``
      - ``required`` is FORBIDDEN on a duration field — so the
        create/edit modifiers built by :func:`_apply_common_field_metadata`
        are stripped of their ``required`` key here.

    ``hidden`` is preserved (some interval fields are hidden-by-default and
    revealed via a trigger, e.g. ``feedExpirationInterval``).
    """
    field = {"id": yml_param["name"], "field_type": "duration"}
    _apply_common_field_metadata(field, yml_param)

    options = field.setdefault("options", {})
    options["units"] = list(DURATION_UNITS)
    options["output_format"] = "minutes"

    # Convert the raw minutes default (set as a string by
    # _apply_common_field_metadata) into a per-unit object. When absent or
    # unparseable, fall back to 1 minute.
    minutes = _coerce_interval_minutes(options.get("default_value"))
    options["default_value"] = _minutes_to_duration_default(
        minutes if minutes is not None else 1
    )

    # ``required`` is forbidden on a duration field (§2.15) — drop it from
    # both modifier blocks while preserving ``hidden``.
    for mod_key in ("create_modifiers", "edit_modifiers"):
        mod = options.get(mod_key)
        if isinstance(mod, dict):
            mod.pop("required", None)

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


class UnknownXsoarParamTypeError(ValueError):
    """Raised when an XSOAR param ``type`` has no connectus field mapper.

    Per the migration guide (Appendix A, "Important Notes"): "If you come
    across a type not listed above when migrating, fail and raise a flag."

    Subclasses ``ValueError`` so existing ``except ValueError`` callers keep
    working while still allowing callers to catch this specific gap.
    """


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
    YAML's ``type`` integer. For unknown types it follows the migration guide
    (Appendix A): fail AND raise a flag — a ``[MIGRATION FLAG]`` line is logged
    before raising :class:`UnknownXsoarParamTypeError`.

    Returns a list — single-field types yield a one-element list; only
    type 9 (credentials) returns a list with multiple entries.
    """
    xsoar_type = yml_param.get("type", 0)
    mapper = MAPPERS.get(xsoar_type)
    if mapper is None:
        param_name = yml_param.get("name", "<unnamed>")
        known_types = sorted(MAPPERS.keys())
        # Guide Appendix A: "If you come across a type not listed above when
        # migrating, fail and raise a flag." Surface a structured flag for the
        # gap-analysis output, then fail.
        logger.error(
            "[MIGRATION FLAG] Unknown XSOAR param type %s for param %r — "
            "no connectus field mapper. Known types: %s. "
            "See migration guide Appendix A.",
            xsoar_type,
            param_name,
            known_types,
        )
        raise UnknownXsoarParamTypeError(
            f"No connectus field mapper for XSOAR type {xsoar_type}. "
            f"Param: {param_name}. "
            f"Known types: {known_types}"
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


def build_interpolation_mapping(
    profile_type: str, xsoar_param_map: dict[str, str]
) -> str:
    """Return the UCP ``role:xsoar_path,...`` ``interpolation_mapping`` string.

    Inverts ``xsoar_param_map`` (``{xsoar_path: role}``) into the comma-joined
    UCP form. The LEFT side is the post-remap ``auth_parameter`` (matches the
    field's ``metadata.auth.parameter`` and the runtime credentials-envelope
    key); the RIGHT side is the dotted XSOAR field path. Entries are sorted by
    ``xsoar_path`` to match the field-emit order in
    :func:`build_connection_profile`. The runtime grammar has no escaping, so
    ``,``/``:`` must not appear in roles or paths (they never do in practice).
    """
    entries: list[str] = []
    for xsoar_path in sorted(xsoar_param_map.keys()):
        role = xsoar_param_map[xsoar_path]
        auth_parameter = _auth_parameter_for_role(profile_type, role)
        # INV-4 (Plan B §6.6.2): the runtime grammar has NO escaping — ',' and
        # ':' are hard delimiters. A role/path containing them would corrupt the
        # comma-joined string, so reject at emission rather than emit a mapping
        # that silently mis-parses at runtime.
        if "," in auth_parameter or ":" in auth_parameter:
            raise InterpolationSchemaError(
                f"interpolation role '{auth_parameter}' contains a reserved "
                f"delimiter (',' or ':') (INV-4); the runtime grammar has no "
                f"escaping. profile_type={profile_type}, xsoar_path={xsoar_path}."
            )
        if "," in xsoar_path:
            raise InterpolationSchemaError(
                f"interpolation destination '{xsoar_path}' contains ',' (INV-4); "
                f"the runtime grammar has no escaping. profile_type={profile_type}."
            )
        entries.append(f"{auth_parameter}:{xsoar_path}")
    return ",".join(entries)


class InterpolationSchemaError(ValueError):
    """Raised when a built connection profile violates an interpolation invariant.

    This is the Plan B *hard gate* (see
    ``connectus/interpolated-param-schemas-and-fix.md`` §6.6): rather than let
    the generator emit a silently-broken ``interpolation_mapping`` (which the
    runtime would drop at debug-log level), generation aborts loudly with the
    connector / profile / offending-entry context.
    """


def _validate_interpolation_invariants(
    profile: dict,
    integration_id: str,
) -> None:
    """Enforce the Plan B interpolation invariants on a built profile (fail loud).

    Checks INV-1..INV-5 from ``interpolated-param-schemas-and-fix.md`` §6.6.2
    against the profile's own emitted fields + ``metadata.xsoar``. Raises
    :class:`InterpolationSchemaError` on the first violation, naming the
    connector id, the profile, and the offending entry so a broken
    ``connection.yaml`` is never written.

    - INV-1: every ``interpolation_mapping`` LEFT (role) equals an emitted
      field's ``metadata.auth.parameter`` in the SAME profile.
    - INV-2: no field lacking ``metadata.auth.parameter`` is referenced by the
      mapping (``none_*`` config fields belong to the normal params path).
    - INV-3: for ``api_key`` profiles the LEFT is ``api_key`` (the
      ``auth.parameter``), consistent with the runtime canonical-key alias
      ``api_key`` -> ``key`` — never the raw ``key`` role.
    - INV-4: no ``,`` or ``:`` in any role (LEFT) and no ``,`` in any
      destination path (RIGHT) — the runtime grammar has no escaping.
    - INV-5: ``metadata.xsoar.interpolated`` is ``True`` on every profile
      (ALWAYS-INTERPOLATE gate).
    """
    profile_type = profile.get("type", "")
    profile_id = profile.get("id", "<unknown>")
    where = (
        f"connector '{integration_id}', profile '{profile_id}' "
        f"(type={profile_type})"
    )
    xsoar_meta = (profile.get("metadata") or {}).get("xsoar") or {}
    mapping = xsoar_meta.get("interpolation_mapping", "")

    # Collect the auth.parameter of every emitted field in this profile.
    field_parameters: set[str] = set()
    for configuration in profile.get("configurations") or []:
        for field in configuration.get("fields") or []:
            parameter = ((field.get("metadata") or {}).get("auth") or {}).get(
                "parameter"
            )
            if parameter:
                field_parameters.add(parameter)

    if mapping:
        for entry in mapping.split(","):
            if ":" not in entry:
                raise InterpolationSchemaError(
                    f"{where}: interpolation_mapping entry '{entry}' has no ':' "
                    f"separator (INV-1/grammar). Expected 'role:xsoar_path'."
                )
            role, _, xsoar_path = entry.partition(":")

            # INV-4 (',' delimiter) is enforced at emission in
            # build_interpolation_mapping: once the mapping is a comma-joined
            # string, a stray ',' is indistinguishable from the entry separator
            # (it surfaces here as an entry with no ':', handled above), and a
            # ':' in a role is absorbed by the first-':' partition. The
            # validator therefore focuses on the structural invariants below.

            # INV-3 — api_key LEFT must be the auth.parameter 'api_key'.
            if profile_type == "api_key" and role == "key":
                raise InterpolationSchemaError(
                    f"{where}: api_key interpolation entry '{entry}' uses the raw "
                    f"role 'key' on the LEFT (INV-3). Emit 'api_key' (the "
                    f"metadata.auth.parameter); the runtime aliases it to the "
                    f"envelope key 'key' via _UCP_CANONICAL_FIELD_KEYS."
                )

            # INV-1 / INV-2 — LEFT must match an emitted field's auth.parameter.
            if role not in field_parameters:
                raise InterpolationSchemaError(
                    f"{where}: interpolation_mapping entry '{entry}' references "
                    f"role '{role}' with no matching field metadata.auth.parameter "
                    f"(have: {sorted(field_parameters)}) (INV-1/INV-2). Only "
                    f"auth-tagged fields may be interpolated; none_* config "
                    f"fields belong to the normal params path."
                )

    # INV-5 — every profile must be interpolated (ALWAYS-INTERPOLATE gate).
    if xsoar_meta.get("interpolated") is not True:
        raise InterpolationSchemaError(
            f"{where}: metadata.xsoar.interpolated must be True on every profile "
            f"(INV-5, ALWAYS-INTERPOLATE gate), got "
            f"{xsoar_meta.get('interpolated')!r}."
        )


def _connection_profile_title(
    profile_type: str,
    connector_title: str,
    auth_name: str = "",
) -> str:
    """Human title for a connection profile.

    Preferred source is the auth-type object's ``name`` (the input the script
    is given for each auth method) — when present and non-blank it is used
    verbatim as the profile title so the connection page reflects the auth
    method's own label. When no ``name`` is supplied, fall back to the legacy
    behaviour: a fixed per-profile-type title (canonical types) or a
    ``"<connector_title> Credentials"`` form (passthrough / free-form).
    """
    if auth_name and auth_name.strip():
        return auth_name.strip()
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
    yml_params_by_name: dict[str, dict] = {},
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
        mask = not is_username
        if "." not in map_key:
            if yml_params_by_name.get(map_key, {}).get('type', 4) in [4, 9, 14] and not is_username:
                mask = True
            
        fields.append(
            {
                "id": field_id,
                "title": _connection_field_title(field_id, yml_params_by_name),
                "field_type": "input",
                "metadata": {"auth": {"parameter": auth_parameter}},
                "options": {
                    "mask": mask,
                    "create_modifiers": {"required": True, "hidden": False},
                    "edit_modifiers": {"required": True, "hidden": False},
                },
            }
        )

    # UCP interpolation: invert xsoar_param_map into the role:path mapping
    # string. ``interpolated`` is hard-forced True on every profile per the
    # ALWAYS-INTERPOLATE gate (Plan B INV-5; ``set-auth`` forces it True
    # upstream and there is no such thing as a non-interpolated profile).
    interpolation_mapping = build_interpolation_mapping(profile_type, xsoar_param_map)
    xsoar_metadata: dict = {"interpolated": True}
    if interpolation_mapping:
        xsoar_metadata["interpolation_mapping"] = interpolation_mapping

    profile = {
        "id": profile_id,
        "type": profile_type,
        # Pin the profile to the integration's connection-page tile. This is
        # the same id the handler's ``auth_options[].view_group`` uses
        # (:func:`slugify_view_group_id`), so the connection profile and the
        # handler reference the same tile — matching the grouped-example shape
        # where each auth profile carries its view_group.
        "view_group": slugify_view_group_id(integration_id),
        "title": _connection_profile_title(
            profile_type,
            connector_title,
            auth_name=auth_type_entry.get("name", "") or "",
        ),
        "description": (
            f"Authentication profile for "
            f"{connector_title or integration_id} ({profile_type})."
        ),
        # ``metadata`` precedes ``configurations`` to match the real connector
        # manifest key order (MS365 profiles put metadata above configurations).
        "metadata": {"xsoar": xsoar_metadata},
        "configurations": [{"fields": fields}],
    }

    # Plan B hard gate: refuse to emit a silently-broken interpolation mapping.
    _validate_interpolation_invariants(profile, integration_id)

    return profile


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


def validate_other_connection_completeness(
    other_connection: list[str],
    yml_params_by_name: dict[str, dict] | None,
    integration_id: str = "",
) -> None:
    """Fail loudly when a proxy / insecure param exists in the integration YML
    but is missing from ``other_connection``.

    The connection-section classifier (:func:`classify_connection_param`)
    recognizes proxy synonyms (``proxy`` / ``useproxy`` / ``use_proxy`` …) and
    insecure synonyms (``insecure`` / ``unsecure`` / ``verify`` / ``secure`` /
    ``trust`` …). Every such param declared on the integration MUST also be
    listed in the connector's ``other_connection`` so it is materialized onto
    the connection page. If the upstream mapper dropped one, the generated
    connection.yaml would silently omit a security-relevant toggle — a
    discrepancy we refuse to migrate.

    Raises:
        ValueError: when any proxy/insecure integration param is absent from
            ``other_connection``. The message names the offending param(s) and
            directs the developer to contact Judah.
    """
    if not yml_params_by_name:
        return

    other_connection_set = set(other_connection or [])

    missing_proxy: list[str] = []
    missing_insecure: list[str] = []
    for param_name in yml_params_by_name:
        if param_name in other_connection_set:
            continue
        classification = classify_connection_param(param_name)
        if classification == "proxy":
            missing_proxy.append(param_name)
        elif classification == "insecure":
            missing_insecure.append(param_name)

    if not missing_proxy and not missing_insecure:
        return

    parts: list[str] = []
    if missing_proxy:
        parts.append(
            f"proxy param(s) {sorted(missing_proxy)} (e.g. proxy/useproxy/"
            f"use_proxy)"
        )
    if missing_insecure:
        parts.append(
            f"insecure param(s) {sorted(missing_insecure)} (e.g. insecure/"
            f"unsecure/verify/secure/trust)"
        )
    discrepancy = " and ".join(parts)
    raise ValueError(
        f"other_connection discrepancy for integration "
        f"'{integration_id or '<unknown>'}': the following are declared in the "
        f"integration YML but missing from other_connection: {discrepancy}. "
        f"This means the connection page would silently drop a "
        f"security-relevant toggle. Please contact Judah to resolve this "
        f"discrepancy before migrating."
    )


def _bool_switch_field(
    *,
    field_id: str,
    title: str,
    description: str = "",
    hidden: bool = False,
    read_only: bool = False,
) -> dict:
    """Build a non-secret boolean ``checkbox`` connection field (Part B / D-D8 home 1).

    Carries ``metadata.event.publish: true`` (legal inside a profile). The value
    is forwarded to the handler via the lifecycle event payload — it is NOT a
    backend-managed field, so NO ``metadata.xsoar.config_type`` is emitted.
    Always ``default_value: false`` (B-D6), ``mask: false``, optional.

    ``hidden`` / ``read_only`` are mirrored into both modifier blocks so a
    field can ship visible-but-locked (``read_only: true``) or hidden.
    """
    options: dict[str, Any] = {
        "mask": False,
        "default_value": False,
        "create_modifiers": {
            "required": False,
            "hidden": hidden,
            "read_only": read_only,
        },
        "edit_modifiers": {
            "required": False,
            "hidden": hidden,
            "read_only": read_only,
        },
    }
    if description:
        options["description"] = description
    return {
        "id": field_id,
        "title": title,
        "field_type": "checkbox",
        "metadata": {
            "event": {"publish": True},
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
    """Build the ``proxy`` checkbox field (id == original yml id, verbatim).

    Proxy ships VISIBLE but ``read_only: true`` (locked) by default — the
    engine-visibility trigger un-locks it (``read_only: false``) when an engine
    or engine group is selected. See :func:`build_engine_triggers`.
    """
    return _bool_switch_field(
        field_id=pid,
        title=_resolve_title(yml_params_by_name, pid, _PROXY_DEFAULT_TITLE),
        description=_field_description(yml_params_by_name, pid),
        read_only=True,
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
    """Static ``engine_mode`` horizontal radio (2-option for Appendix H, else 3-option)."""
    values = (
        _ENGINE_MODE_VALUES_SINGLE if single_engine else _ENGINE_MODE_VALUES_FULL
    )
    return {
        "id": field_id,
        "title": "Engine",
        "field_type": "radio",
        "options": {
            "mask": False,
            "orientation": "horizontal",
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
            # Mandatory empty-state message (guide §3.7 engine 3-field pattern).
            "empty_values_message": "No engines available",
            # Every select/multi_select must be searchable + clearable
            # (guide §2.15 / §3.7 field rule 9).
            "searchable": True,
            "clearable": True,
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
            # Mandatory empty-state message (guide §3.7 engine 3-field pattern).
            "empty_values_message": "No engine groups available",
            # Every select/multi_select must be searchable + clearable
            # (guide §2.15 / §3.7 field rule 9).
            "searchable": True,
            "clearable": True,
            "create_modifiers": {"required": False, "hidden": False},
            "edit_modifiers": {"required": False, "hidden": False},
        },
    }


def build_engine_triggers(
    *,
    mode_id: str,
    engine_id: str | None,
    engine_group_id: str | None,
    proxy_ids: list[str] | None = None,
) -> list[dict]:
    """Visibility triggers for the engine 3-field pattern (+ proxy reveal).

    - Hide ``engine`` unless mode==engine; hide ``engine_group`` unless
      mode==engine_group. References the (possibly prefixed) per-profile ids.
    - When ``proxy_ids`` is supplied, also emit a SINGLE "unlock proxy"
      trigger per proxy field: proxy ships ``read_only: true`` (locked) by
      default, and is unlocked (``read_only: false``) when an engine is
      actually selected — i.e. when ``engine`` is_not_empty OR
      ``engine_group`` is_not_empty. The two engine selectors are merged into
      one OR ``ConditionGroup`` so a single trigger controls each proxy field
      (instead of one trigger per engine selector).
    """
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

    # Unlock proxy when an engine value is present. Proxy ships read_only:true
    # (locked) by default (see build_proxy_field), so a SINGLE merged trigger
    # per proxy field unlocks it (read_only:false) once the user picks an
    # engine OR an engine group. The two engine selectors are combined into
    # one OR ConditionGroup so there is exactly one trigger per proxy field.
    engine_conditions = [
        {
            "id": engine_field_id,
            "behavior": "value",
            "operator": "is_not_empty",
        }
        for engine_field_id in (engine_id, engine_group_id)
        if engine_field_id
    ]
    if engine_conditions and proxy_ids:
        if len(engine_conditions) == 1:
            merged_conditions: dict = engine_conditions[0]
        else:
            merged_conditions = {
                "operator": "OR",
                "children": engine_conditions,
            }
        for proxy_id in proxy_ids:
            triggers.append(
                {
                    "conditions": merged_conditions,
                    "effects": [
                        {"id": proxy_id, "action": {"read_only": False}}
                    ],
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
    connector_existing_ids: set[str] | None = None,
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

    # Classify other_connection: proxy / insecure / engine are special; the
    # REST (host/url/port/region) are generic non-auth fields.
    proxy_ids = [p for p in other_connection if classify_connection_param(p) == "proxy"]
    insecure_ids = [
        p for p in other_connection if classify_connection_param(p) == "insecure"
    ]
    rest_ids = [
        p for p in other_connection if classify_connection_param(p) is None
    ]

    # Track ids already used across profiles for dedup-via-rename. Seed from
    # the connector-wide claimed-id set (``connector_existing_ids``) so that
    # when a SECOND handler is appended, its duplicated connection fields
    # (url / proxy / insecure / engine* / credentials_*) collide with the
    # FIRST handler's already-claimed bare ids and get a per-profile-id prefix
    # plus a serializer bridge — instead of silently re-emitting bare ids that
    # clash in the merged connection.yaml. From-scratch (single handler) passes
    # ``None``, so the first profile keeps bare ids as before. NOTE: this is a
    # COPY-free reference only for SEEDING — we copy so the local prefixing
    # logic (which expects the first-profile-keeps-bare-id semantics within
    # THIS call) is preserved, while still seeing prior-handler ids as taken.
    existing_ids: set[str] = (
        set(connector_existing_ids) if connector_existing_ids is not None else set()
    )
    all_triggers: list[dict] = []

    for profile in profiles:
        # Dedup prefix is the PROFILE's own id verbatim (auth-type agnostic),
        # NOT a single integration-wide slug. Every non-auth field is duplicated
        # into every profile; the first profile to claim a bare id keeps it, and
        # each subsequent profile prefixes its duplicate with that profile's id
        # — e.g. ``passthrough.github_passthrough_secondary_url``. Using one
        # integration slug for all profiles would make the 3rd+ profile's
        # prefixed id collide with the 2nd profile's, silently producing
        # duplicate ids across profiles. Per-profile ids are globally unique by
        # construction, so the prefixed ids never collide regardless of how many
        # profiles share a type. The profile id is used verbatim (it already
        # contains the ``<type>.<slug>`` shape, e.g. ``passthrough.github``);
        # do NOT run it through ``_slug_word`` or the leading ``.`` segment is
        # lost. Falls back to the integration slug only for an unnamed profile.
        prefix = profile.get("id", "") or _slug_word(integration_id)

        cfgs = profile.setdefault("configurations", [{"fields": []}])
        if not cfgs:
            cfgs.append({"fields": []})
        target_fields = cfgs[0].setdefault("fields", [])

        # Dedup the AUTH fields too (credentials_username / credentials_password
        # / token / api_key / ...) that ``build_connection_profile`` already
        # placed in this profile. They are id-prefixed + serializer-bridged the
        # same way as the non-auth fields below: the first profile to claim a
        # bare id keeps it; a 2nd+ profile (or a 2nd handler appended to an
        # existing connector) prefixes its duplicate with the profile id and
        # bridges the renamed id back to the original XSOAR param name. Without
        # this, two handlers sharing a connector would emit colliding bare auth
        # field ids in the merged connection.yaml.
        for cfg_group in cfgs:
            for auth_field in cfg_group.get("fields", []) or []:
                aid = auth_field.get("id")
                if not aid:
                    continue
                resolved = _maybe_prefixed_id(
                    aid, prefix, existing_ids, handler_dir, serializer_bridge, aid
                )
                if resolved != aid:
                    auth_field["id"] = resolved

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
        # Capture the resolved (possibly prefixed) proxy field id(s) for THIS
        # profile so the engine-trigger builder can emit "reveal proxy when an
        # engine is selected" rules referencing the same ids.
        profile_proxy_fids: list[str] = []
        if excl != "excluded":
            for pid in proxy_ids:
                fid = _maybe_prefixed_id(
                    pid, prefix, existing_ids, handler_dir, serializer_bridge, pid
                )
                field = build_proxy_field(pid, yml_params_by_name)
                field["id"] = fid
                target_fields.append(field)
                profile_proxy_fids.append(fid)

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
                mode_id=mode_fid,
                engine_id=engine_fid,
                engine_group_id=group_fid,
                proxy_ids=profile_proxy_fids,
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
    return s.replace("---", "-")


def view_group_id_for_handler(handler_id: str) -> str:
    """Connection/configurations tile id for a handler.

    Both connection.yaml and configurations.yaml must reference the SAME tile
    id so the grouped UI renders connection + configuration rows under one
    tile. The connection side uses ``slugify_view_group_id(integration_id)``
    (== the integration slug). A handler id is ``xsoar-<integration-slug>``
    (see :func:`derive_handler_id`), so stripping the ``xsoar-`` prefix yields
    the same integration-slug tile id — keeping the two files in lockstep
    without threading ``integration_id`` through every configurations builder.
    """
    return handler_id_to_integration_slug(handler_id)


def integration_field_prefix(integration_id: str) -> str:
    """Field-id prefix for an integration (lowercase, no separators)."""
    return _slug_word(integration_id).replace("_", "")


def build_view_groups_registry(
    integrations: list[tuple[str, str]],
    purpose = "Connection"
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
                    f"{purpose} settings for {label}."
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
    existing_ids: set[str] | None = None,
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

    # Validate that every proxy/insecure param declared on the integration YML
    # is also present in other_connection — otherwise the connection page would
    # silently drop a security-relevant toggle. Fails loudly per migration rule.
    validate_other_connection_completeness(
        other_connection, yml_params_by_name, integration_id
    )

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
        connector_existing_ids=existing_ids,
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
# CODEOWNERS registration (from-scratch flow)
# ---------------------------------------------------------------------------
# Default owners appended for every newly-scaffolded connector. The trailing
# space after the last owner is intentional to mirror the existing CODEOWNERS
# formatting convention.
CODE_OWNERS_DEFAULT_OWNERS = "@sbenyakir @ybenshalom @juschwartz"


def _find_repo_root_for_code_owners(connector_dir: Path) -> Path:
    """Locate the unified-connectors-content repo root for the CODEOWNERS file.

    The CODEOWNERS file lives at the repo root — the directory that contains
    the top-level ``connectors/`` directory. ``connector_dir`` may be nested
    at varying depths (e.g. ``<root>/connectors/<slug>`` or
    ``<root>/connectors/generated_manifest/<slug>``), so we walk upwards from
    ``connector_dir`` until we find the ancestor whose ``name`` is
    ``connectors`` and return ITS parent. Falls back to the legacy
    ``connector_dir.parent.parent`` when no ``connectors`` ancestor is found.
    """
    for ancestor in connector_dir.parents:
        if ancestor.name == "connectors":
            return ancestor.parent
    return connector_dir.parent.parent


def add_connector_to_code_owners(
    connector_dir: Path,
    connector_title: str,
) -> None:
    """Append a CODEOWNERS entry for a newly-created connector.

    The CODEOWNERS file lives at the unified-connectors-content root, i.e. the
    parent of the top-level ``connectors/`` directory. The appended block is::

        # <connector_title>
        connectors/<slug>/ @sbenyakir @ybenshalom @juschwartz

    followed by a trailing blank line. ``<slug>`` is the connector directory's
    own name (``connector_dir.name``). The file is created if it does not yet
    exist.

    The repo root is resolved by walking up to the ``connectors/`` ancestor
    (via :func:`_find_repo_root_for_code_owners`) so the CODEOWNERS file is
    always written to the repo root, even for connectors nested under
    ``connectors/generated_manifest/``.
    """
    slug = connector_dir.name
    # Resolve the repo root robustly (handles nested generated_manifest layout)
    # so the CODEOWNERS file lands at <root>/CODEOWNERS, never under connectors/.
    code_owners_path = (
        _find_repo_root_for_code_owners(connector_dir) / "CODEOWNERS"
    )

    entry = (
        f"# {connector_title}\n"
        f"connectors/{slug}/ {CODE_OWNERS_DEFAULT_OWNERS}\n"
        "\n"
    )

    with open(code_owners_path, "a") as fh:
        fh.write(entry)

    logger.info(
        f"[manifest_generator] Registered {slug!r} in {code_owners_path}"
    )


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

    # Register the new connector in the unified-connectors-content CODEOWNERS
    # file (from-scratch flow only).
    add_connector_to_code_owners(connector_dir, connector_title)

    # Copy the author image (if provided) into the connector root before
    # building connector.yaml so we can record the dest filename.
    author_image_filename = ""
    if author_image_path is not None:
        connector_id, _ = title_to_slug(connector_title), connector_title
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

    # Generate capabilities.yaml. Each capability's config.required_license is
    # the union of its sub-capabilities' licenses, resolved from
    # sub_capabilities_to_licenses.json (single source of truth).
    capabilities_data = build_capabilities_yaml(
        mapped_params,
        yml_params_by_name=yml_params_by_name,
        handler_id=handler_id,
        handler_dir=handler_dir,
        existing_ids=existing_field_ids,
        integration_name=integration_yml.get("name", ""),
    )
    capabilities_data = deep_merge_dicts(
        capabilities_data, manual_capabilities_fields or {}
    )
    capabilities_yaml_path = connector_dir / "capabilities.yaml"
    write_capabilities_yaml(capabilities_yaml_path, capabilities_data)
    logger.info(f"[manifest_generator] Generated {capabilities_yaml_path}")

    # Collect triggers from capability builders and write triggers.yaml
    # when at least one trigger exists.
    all_triggers: list[dict] = []

    # Run the capability builders (TI&E + fetch-issues) BEFORE building
    # configurations.yaml. Each builder:
    #   * STRIPS its platform-managed raw param names from ``mapped_params``
    #     (so they aren't emitted as plain per-cap fields), and
    #   * RETURNS the synthetic field set to render for that capability.
    # We capture the returned fields here keyed by the mapped_params bucket
    # name, then inject them into the matching sub-cap entry after
    # ``build_configurations_yaml`` runs. (Historically the returned fields
    # were discarded — only triggers were consumed — so fetch-issues
    # connectors emitted NONE of isFetch / incidentType / incidentFetchInterval
    # / mapper-incoming / classifier. This restores them.)
    synthetic_cap_fields: dict[str, list[dict]] = {}

    # NOTE: the builders' ``capability_id`` is used BOTH for field-id
    # prefixing (only when ``is_sub_capability=True``) AND as the serializer
    # ``computed_fields`` gating id. Capabilities are always modelled as
    # sub-capabilities in the manifest (capabilities.yaml / configurations.yaml
    # are keyed by the sub-cap id ``<capability_id>_<integration-id-slug>``),
    # so the serializer rule MUST gate on the sub-cap id — otherwise the rule
    # never fires (no top-level capability is ever ``on``). We therefore pass
    # the sub-cap id as ``capability_id`` while keeping ``is_sub_capability=False``
    # so the emitted field ids stay un-prefixed (matching the per-cap entries).
    ti_bucket_key = "Threat Intelligence & Enrichment"
    if ti_bucket_key in mapped_params:
        ti_result = add_indicators_capability(
            capability_id=make_sub_capability_id(handler_id, ti_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
        )
        all_triggers.extend(ti_result.get("triggers", []))
        synthetic_cap_fields[ti_bucket_key] = ti_result.get("fields", [])

    fi_bucket_key = "Fetch Issues"
    if fi_bucket_key in mapped_params:
        script = integration_yml.get("script") or {}
        fi_is_long_running = script.get("longRunning") is True
        fi_result = add_fetch_issues_capability(
            capability_id=make_sub_capability_id(handler_id, fi_bucket_key),
            is_sub_capability=False,
            is_long_running=fi_is_long_running,
            mapped_params=mapped_params,
            integration_yml=integration_yml,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
        )
        all_triggers.extend(fi_result.get("triggers", []))
        synthetic_cap_fields[fi_bucket_key] = fi_result.get("fields", [])

    lc_bucket_key = LOG_COLLECTION_BUCKET_KEY
    if lc_bucket_key in mapped_params:
        lc_is_long_running = LONGRUNNING_PARAM_NAME in (
            mapped_params.get(lc_bucket_key) or []
        )
        lc_result = add_log_collection_capability(
            capability_id=make_sub_capability_id(handler_id, lc_bucket_key),
            is_sub_capability=False,
            is_long_running_capability=lc_is_long_running,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
            integration_yml=integration_yml,
        )
        synthetic_cap_fields[lc_bucket_key] = lc_result.get("fields", [])

    av_bucket_key = "Fetch Assets and Vulnerabilities"
    if av_bucket_key in mapped_params:
        av_result = add_assets_capability(
            capability_id=make_sub_capability_id(handler_id, av_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
        )
        synthetic_cap_fields[av_bucket_key] = av_result.get("fields", [])

    # Fetch Secrets: the isFetchCredentials toggle is emitted ONLY as a
    # serializer computed_fields rule (gated on the sub-cap id), NOT as a
    # configurations.yaml field. add_secret_capability returns "fields": []
    # so nothing is injected into the sub-cap entry — it only registers the
    # serializer rule via handler_dir.
    fs_bucket_key = "Fetch Secrets"
    if fs_bucket_key in mapped_params:
        fs_result = add_secret_capability(
            capability_id=make_sub_capability_id(handler_id, fs_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=handler_dir,
        )
        synthetic_cap_fields[fs_bucket_key] = fs_result.get("fields", [])

    # Generate configurations.yaml (no schema directive)
    configurations_data = build_configurations_yaml(
        mapped_params,
        yml_params_by_name=yml_params_by_name,
        handler_id=handler_id,
        handler_dir=handler_dir,
        existing_ids=existing_field_ids,
    )

    # Inject the builder-produced synthetic fields into their sub-cap entries.
    for cap_name, fields in synthetic_cap_fields.items():
        inject_synthetic_capability_fields(
            configurations_data, cap_name, fields, handler_id=handler_id
        )

    # Per-handler general_configurations: add the integrationLogLevel field in
    # a view_group-pinned field group. Also register the view_groups registry
    # entry.
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
    # view_groups registry entry — use the integration tile id + display label
    # so configurations.yaml and connection.yaml reference the SAME tile.
    _cfg_integration_id = integration_yml.get("commonfields", {}).get("id", "")
    _cfg_integration_display = (
        integration_yml.get("display", "") or connector_title
    )
    configurations_data.setdefault("view_groups", []).extend(
        build_view_groups_registry(
            [(_cfg_integration_id, _cfg_integration_display)],
            "Configurations"
        )
    )

    # The ``defaultIgnore`` field ("Do not use in CLI by default") is only
    # meaningful for handlers that expose automation/CLI commands, so it is
    # injected under the automation-and-remediation sub-capability entry —
    # and ONLY when the handler declares the Automation capability.
    if _AUTOMATION_BUCKET_KEY in mapped_params:
        default_ignore_field = build_default_ignore_capability_field(
            handler_id, handler_dir, existing_ids=existing_field_ids
        )
        inject_synthetic_capability_fields(
            configurations_data,
            _AUTOMATION_BUCKET_KEY,
            [default_ignore_field],
            handler_id=handler_id,
        )

    # Authoritative final pass: move EVERY hidden+default XSOAR param out of
    # configurations.yaml and into the handler's serializer computed_fields.
    # Runs after all builders / synthetic injection so it sees every field
    # regardless of which code path produced it (e.g. eventFetchInterval via
    # the log-collection builder, or orphan config-only params like
    # max_concurrent_tasks the mapper never routed anywhere).
    sweep_hidden_defaults_to_serializer(
        configurations_data,
        integration_yml,
        handler_id,
        handler_dir,
        mapped_params=mapped_params,
        connection_param_names=connection_param_names_from_auth(auth_methods),
    )

    configurations_data = deep_merge_dicts(
        configurations_data, manual_configurations_fields or {}
    )
    # Safety net: no hidden field may carry a default_value (it must have been
    # swept to the serializer). Runs AFTER the manual merge so a manual override
    # cannot reintroduce a violation.
    assert_no_hidden_defaults_in_configurations(configurations_data)
    configurations_yaml_path = connector_dir / "configurations.yaml"
    with open(configurations_yaml_path, "w") as fh:
        _dump_yaml(_ordered_configurations(configurations_data), fh)
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
            "[manifest_generator] No dedup collisions for handler — "
            "serializer.yaml not generated (optional per guide §3.9)."
        )

    # NOTE: the TI&E + fetch-issues capability builders already ran above
    # (before build_configurations_yaml) so their synthetic fields could be
    # injected into configurations.yaml; ``all_triggers`` was populated there.

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

    # Fetch mutex (guide §3.4 note 7 + §3.5): this handler may declare more
    # than one fetch capability. Emit per-handler mutex triggers so only one
    # of THIS handler's fetch sub-capabilities can be selected at a time. The
    # capability builders strip param *values* from ``mapped_params`` but keep
    # the bucket *keys*, so the fetch sub-cap ids are still derivable here.
    fetch_sub_cap_ids = collect_fetch_sub_cap_ids(mapped_params, handler_id)
    all_triggers.extend(build_fetch_mutex_triggers(fetch_sub_cap_ids))

    # Collection → automation auto-enable + lock (guide §3.5.1): every fetch
    # sub-cap this handler contributes auto-enables AND locks the handler's
    # automation-and-remediation sub-cap. Only emitted when the handler
    # actually declares the Automation capability (there is a target to lock).
    if _AUTOMATION_BUCKET_KEY in mapped_params:
        automation_sub_cap_id = make_sub_capability_id(
            handler_id, _AUTOMATION_BUCKET_KEY
        )
        all_triggers.extend(
            build_collection_automation_triggers(
                fetch_sub_cap_ids, automation_sub_cap_id
            )
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

    pack_categories = get_pack_categories(integration_path)
    existing_tags = metadata.get("categories") or []
    merged_categories = merge_tags_case_insensitive(existing_tags, pack_categories)
    metadata["categories"] = merged_categories

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

    # NOTE: user-mapped ``general_configurations`` params are emitted ONLY in
    # configurations.yaml (view_group-pinned, dedup'd) via
    # build_per_handler_general_config below — they are intentionally NOT added
    # to capabilities.yaml, whose general_configurations carries ONLY the
    # mandatory ``instance_name`` field (mirrors the from-scratch
    # build_capabilities_yaml path). Adding them here too produced a duplicate
    # (and view-group-less) copy in capabilities.yaml.

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
            integration_name=integration_yml.get("name", ""),
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

    # Per-handler general_configurations: add the integrationLogLevel field in
    # a view_group-pinned field group. Also register the view_groups registry
    # entry (dedup: skip if already present from a prior handler addition).
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
    # view_groups registry entry — use the integration tile id + display label
    # so configurations.yaml and connection.yaml reference the SAME tile.
    _cfg_integration_id = integration_yml.get("commonfields", {}).get("id", "")
    _cfg_integration_display = (
        integration_yml.get("display", "") or _cfg_integration_id
    )
    _cfg_tile_id = view_group_id_for_handler(new_handler_id)
    if _cfg_tile_id not in existing_vg_ids:
        configurations_data.setdefault("view_groups", []).extend(
            build_view_groups_registry(
                [(_cfg_integration_id, _cfg_integration_display)],
                "Configurations"
            )
        )

    # The ``defaultIgnore`` field ("Do not use in CLI by default") is only
    # meaningful for handlers that expose automation/CLI commands, so it is
    # injected under the automation-and-remediation sub-capability entry —
    # and ONLY when the handler declares the Automation capability. The append
    # path resolves sub-cap ids up front (``cap_name_to_handler_cap_id``), so
    # inject by that exact id.
    if _AUTOMATION_BUCKET_KEY in mapped_params:
        default_ignore_field = build_default_ignore_capability_field(
            new_handler_id, new_handler_dir, existing_ids=existing_field_ids
        )
        _inject_append_capability_fields(
            configurations_data,
            cap_name_to_handler_cap_id.get(_AUTOMATION_BUCKET_KEY),
            new_handler_id,
            [default_ignore_field],
        )

    # Per Batch 7 (Part A.7.1) + guide §3.9: serializer.yaml is OPTIONAL.
    # The dedup pass writes it on-demand when collision-rename produces
    # a field_mappings entry. The per-handler general_config above also
    # writes a serializer entry on collision (for integrationLogLevel), and
    # the defaultIgnore injection above does the same for defaultIgnore.
    serializer_yaml_path = handler_yaml_path.parent / "serializer.yaml"
    if serializer_yaml_path.exists():
        logger.info(
            f"[manifest_generator] Serializer.yaml present at "
            f"{serializer_yaml_path} (populated by dedup step)"
        )
    else:
        logger.info(
            "[manifest_generator] No dedup collisions for handler — "
            "serializer.yaml not generated (optional per guide §3.9)."
        )

    # Write capabilities.yaml back (with schema directive).
    capabilities_data = deep_merge_dicts(
        capabilities_data, manual_capabilities_fields or {}
    )
    write_capabilities_yaml(capabilities_yaml_path, capabilities_data)
    logger.info(f"[manifest_generator] Updated {capabilities_yaml_path}")

    # Collect triggers from capability builders and write triggers.yaml
    # when at least one trigger exists.
    all_triggers: list[dict] = []

    # Run the capability builders (TI&E + fetch-issues) and capture their
    # synthetic fields BEFORE writing configurations.yaml, so the platform
    # fetch fields (isFetch / incidentType / incidentFetchInterval /
    # mapper-incoming / classifier) are injected into the new handler's
    # sub-cap entry rather than discarded. Inject by the SUB-CAP id the new
    # handler actually uses (``cap_name_to_handler_cap_id``), which may differ
    # from the bare-slug default.
    # See the from-scratch path note: pass the new handler's sub-cap id as
    # ``capability_id`` (keeping ``is_sub_capability=False`` so field ids stay
    # un-prefixed) so the serializer computed_fields rule gates on the sub-cap
    # id that capabilities.yaml / configurations.yaml actually expose.
    ti_bucket_key = "Threat Intelligence & Enrichment"
    if ti_bucket_key in mapped_params:
        ti_result = add_indicators_capability(
            capability_id=make_sub_capability_id(new_handler_id, ti_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
        )
        # Inject FIRST so we learn which field ids the connector-wide dedup
        # renamed (e.g. ``feedExpirationInterval`` ->
        # ``<handler_id>_feedExpirationInterval`` on a 2nd handler), then
        # rewrite the builder's reveal trigger to reference the renamed ids so
        # triggers.yaml stays consistent with configurations.yaml.
        ti_rename_map = _inject_append_capability_fields(
            configurations_data,
            cap_name_to_handler_cap_id.get(ti_bucket_key),
            new_handler_id,
            ti_result.get("fields", []),
            existing_ids=existing_field_ids,
            handler_dir=new_handler_dir,
        )
        all_triggers.extend(
            _rewrite_trigger_field_ids(ti_result.get("triggers", []), ti_rename_map)
        )

    fi_bucket_key = "Fetch Issues"
    if fi_bucket_key in mapped_params:
        script = integration_yml.get("script") or {}
        fi_is_long_running = script.get("longRunning") is True
        fi_result = add_fetch_issues_capability(
            capability_id=make_sub_capability_id(new_handler_id, fi_bucket_key),
            is_sub_capability=False,
            is_long_running=fi_is_long_running,
            mapped_params=mapped_params,
            integration_yml=integration_yml,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
        )
        all_triggers.extend(fi_result.get("triggers", []))
        _inject_append_capability_fields(
            configurations_data,
            cap_name_to_handler_cap_id.get(fi_bucket_key),
            new_handler_id,
            fi_result.get("fields", []),
            existing_ids=existing_field_ids,
            handler_dir=new_handler_dir,
        )

    lc_bucket_key = LOG_COLLECTION_BUCKET_KEY
    if lc_bucket_key in mapped_params:
        lc_is_long_running = LONGRUNNING_PARAM_NAME in (
            mapped_params.get(lc_bucket_key) or []
        )
        lc_result = add_log_collection_capability(
            capability_id=make_sub_capability_id(new_handler_id, lc_bucket_key),
            is_sub_capability=False,
            is_long_running_capability=lc_is_long_running,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
            integration_yml=integration_yml,
        )
        _inject_append_capability_fields(
            configurations_data,
            cap_name_to_handler_cap_id.get(lc_bucket_key),
            new_handler_id,
            lc_result.get("fields", []),
            existing_ids=existing_field_ids,
            handler_dir=new_handler_dir,
        )

    av_bucket_key = "Fetch Assets and Vulnerabilities"
    if av_bucket_key in mapped_params:
        av_result = add_assets_capability(
            capability_id=make_sub_capability_id(new_handler_id, av_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
        )
        _inject_append_capability_fields(
            configurations_data,
            cap_name_to_handler_cap_id.get(av_bucket_key),
            new_handler_id,
            av_result.get("fields", []),
            existing_ids=existing_field_ids,
            handler_dir=new_handler_dir,
        )

    # Fetch Secrets: emit the isFetchCredentials toggle ONLY as a serializer
    # computed_fields rule (gated on the new handler's sub-cap id), NOT as a
    # configurations.yaml field. add_secret_capability returns "fields": [] so
    # the inject call is a no-op for configurations — only the serializer rule
    # is registered via new_handler_dir.
    fs_bucket_key = "Fetch Secrets"
    if fs_bucket_key in mapped_params:
        fs_result = add_secret_capability(
            capability_id=make_sub_capability_id(new_handler_id, fs_bucket_key),
            is_sub_capability=False,
            mapped_params=mapped_params,
            yml_params_by_name=yml_params_by_name,
            handler_dir=new_handler_dir,
        )
        _inject_append_capability_fields(
            configurations_data,
            cap_name_to_handler_cap_id.get(fs_bucket_key),
            new_handler_id,
            fs_result.get("fields", []),
            existing_ids=existing_field_ids,
            handler_dir=new_handler_dir,
        )

    # Authoritative final pass: move EVERY hidden+default XSOAR param of THIS
    # new handler out of configurations.yaml into its serializer computed_fields
    # (see :func:`sweep_hidden_defaults_to_serializer`). Scoped to the new
    # handler's yml + sub-cap ids so an existing handler's fields are untouched.
    sweep_hidden_defaults_to_serializer(
        configurations_data,
        integration_yml,
        new_handler_id,
        new_handler_dir,
        mapped_params=mapped_params,
        connection_param_names=connection_param_names_from_auth(auth_methods),
    )

    # Write configurations.yaml back (no schema directive).
    configurations_data = deep_merge_dicts(
        configurations_data, manual_configurations_fields or {}
    )
    # Safety net: no hidden field may carry a default_value after the merge.
    assert_no_hidden_defaults_in_configurations(configurations_data)
    with open(configurations_yaml_path, "w") as fh:
        _dump_yaml(_ordered_configurations(configurations_data), fh)
    logger.info(f"[manifest_generator] Updated {configurations_yaml_path}")

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
            # Append path: seed the per-profile connection dedup with the
            # connector-wide claimed-id set so the new handler's duplicated
            # connection fields collide with the existing handler's bare ids
            # and get per-profile-id prefixes + serializer bridges.
            existing_ids=existing_field_ids,
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

    # Fetch mutex (guide §3.4 note 7 + §3.5): scope is PER-HANDLER, so we only
    # pair the NEW handler's own fetch sub-capabilities — existing handlers'
    # mutex triggers are already in triggers.yaml and are left untouched. The
    # new handler's fetch sub-cap ids are exactly the fetch-bucket values in
    # ``cap_name_to_handler_cap_id``.
    new_handler_fetch_sub_cap_ids = sorted(
        sub_cap_id
        for cap_name, sub_cap_id in cap_name_to_handler_cap_id.items()
        if cap_name in _FETCH_MUTEX_BUCKET_KEYS
    )
    all_triggers.extend(
        build_fetch_mutex_triggers(new_handler_fetch_sub_cap_ids)
    )

    # Collection → automation auto-enable + lock (guide §3.5.1): scope is
    # PER-HANDLER. Each of the NEW handler's fetch sub-caps auto-enables AND
    # locks the NEW handler's automation-and-remediation sub-cap. Only emitted
    # when the new handler declares the Automation capability.
    new_handler_automation_sub_cap_id = cap_name_to_handler_cap_id.get(
        _AUTOMATION_BUCKET_KEY, ""
    )
    all_triggers.extend(
        build_collection_automation_triggers(
            new_handler_fetch_sub_cap_ids, new_handler_automation_sub_cap_id
        )
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
        None,
        "--connectors-root",
        help="Root directory under which connector folders live. "
        "When omitted, resolves from $CONNECTUS_REPO_DIR (the .env value) as "
        "<CONNECTUS_REPO_DIR>/connectors, falling back to "
        "<CWD>/unified-connectors-content/connectors.",
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

    # Load the canonical root .env via the single unified loader so any
    # subprocess we spawn (e.g. `make validate`) inherits CONNECTUS_REPO_DIR.
    load_env()

    # Resolve the output root AFTER load_env() so $CONNECTUS_REPO_DIR from the
    # .env is honored when --connectors-root is not explicitly supplied.
    connectors_root = resolve_connectors_root(connectors_root)
    logger.info(f"[manifest_generator] connectors_root resolved to {connectors_root}")
    
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

    vendor = integration_yml["provider"]
    # The connector directory name must be the connector id (not a slug of
    # the title) so the on-disk path matches connector.yaml's ``id`` field.
    slug, _ = title_to_slug(connector_title), connector_title
    connector_dir = connectors_root / slug

    logger.info(
        f"[manifest_generator] integration={integration_path} "
        f"title={connector_title!r} slug={slug!r} target={connector_dir} "
        f"auth_methods_keys={list(auth_methods_dict.keys())}"
    )
    author_image_path = Path(_load_connector_id_image()[connector_title])
    if connector_exists_and_valid(connector_dir):
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
