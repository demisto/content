"""resolver — turn a single ``integration_id`` into everything the param-parity
orchestrator needs (the "brain" that makes ``check_param_parity.py`` standalone).

Given ONE input — the XSOAR ``Integration ID`` — :func:`resolve` reads the
migration pipeline CSV row, locates the connector + handler on disk (in the
``unified-connectors-content`` repo at ``$REPO_DIR``), parses the connector's
YAML files, and returns a :class:`ParityInputs` describing:

  * the integration YML path + brand,
  * the connector dir + id,
  * ALL (sub-)capabilities + profiles the handler subscribes to,
  * the compare set (every integration-YML param NOT on the hard ignore-list),
  * the serializer mapping (connector field ↔ xsoar param, for attribution),
  * the hard ignore-list (the ONLY ignore mechanism).

The ONLY two values read from the migration pipeline CSV are the
**Connector Folder Path** (connector location) and the **Integration File
Path** (integration YML location). EVERYTHING else — including the auth field
↔ xsoar param mapping — is derived from code by parsing the integration YML
and the connector YAMLs. In particular, the CSV ``Auth Details`` column is NOT
read.

Design of record: ``plans/param-parity-pipeline-integration.md`` (Phase 1 +
the "REVISED MULTI-CAPABILITY + AUTH-MAPPING DESIGN" section).

CORE METHODOLOGY (see the plan's "CORE METHODOLOGY" section):

  1. Param discovery is INTEGRATION-YML → COMPARE-EVERYTHING. We enumerate every
     param from the integration's own YML ``configuration``. The COMPARISON
     POLICY (USER-CONFIRMED): a param is IGNORED iff (a) its name is on
     :data:`HARD_IGNORE_PARAMS` (reason ``"hard_ignore_list"``) OR (b) it is
     HIDDEN in the integration YML (reason ``"hidden"`` — hidden params are not
     migrated to the connector); EVERYTHING else is compared verbatim — including
     type-4 encrypted params, auth/profile params, and type-9 ``credentials``
     (the full object). A param the connector does not deliver surfaces as
     MISSING_IN_CONNECTOR at diff time, which is correct.
  2. The handler's serializer.yaml resolves duplicate / renamed connector fields
     to the TRUE id as it appears in the integration (used only for diagnostic
     attribution in ``param_to_connector_field`` — never to gate comparison).
  3. A single handler may subscribe to MULTIPLE capabilities + sub-capabilities;
     every one of them is enumerated (normalized to its PARENT capability id).
  4. The connector profile's ``metadata.xsoar.interpolation_mapping`` is parsed
     and retained ONLY for VALUE-SEEDING (see
     :meth:`ProfileSpec.connector_field_to_xsoar_path`, consumed by
     ``ucp_capture``). It plays NO role in deciding what to compare.
  5. Two ignore mechanisms only: the hard ignore-list (reason
     ``"hard_ignore_list"``) and HIDDEN integration-YML params (reason
     ``"hidden"``). Both are ALWAYS dropped.

This module is read-only and has no network / docker dependencies — it only
reads files, so it is cheap to unit-test against a fixture connector.
"""

from __future__ import annotations

import csv
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ruamel.yaml import YAML

# Make the shared connectus env loader importable (connectus/ is not a package).
import sys as _sys  # noqa: E402

_sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader.
load_env()

log = logging.getLogger("resolver")

_yaml = YAML(typ="safe")


# ============================================================================
# Locations
# ============================================================================

#: This file lives at connectus/runtime_demisto.params_parity/resolver.py —
#: go up THREE dirs to reach the content-repo workspace root.
_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

#: The migration pipeline CSV (source of truth for Integration File Path +
#: Connector Folder Path). Kept relative to the workspace root so the resolver
#: works regardless of the caller's CWD.
PIPELINE_CSV = _WORKSPACE_ROOT / "connectus" / "connectus-migration-pipeline.csv"


def _repo_dir() -> Path:
    """The unified-connectors-content repo root (from ``$CONNECTUS_REPO_DIR`` in .env)."""
    raw = os.getenv("CONNECTUS_REPO_DIR", "").strip()
    if not raw:
        raise ResolverError(
            "CONNECTUS_REPO_DIR is not set (expected in "
            "connectus/runtime_demisto.params_parity/.env) — cannot locate the "
            "connector repo."
        )
    return Path(raw)


# ============================================================================
# Hard ignore-list — the ONLY ignore mechanism. A param is ignored iff its name
# is in this set; EVERYTHING else is compared verbatim. (USER-CONFIRMED.)
# ============================================================================

HARD_IGNORE_PARAMS: frozenset[str] = frozenset(
    {
        "brand",
        "packID",
        "engine",
        "engineGroup",
        "mappingId",
        "incomingMapperId",
        "outgoingMapperId",
        "defaultIgnore",
        "integrationLogLevel",
        # Connector-injected field (capabilities.yaml general_configurations) that
        # legitimately appears in demisto.params() on the platform; must be
        # IGNORED, never flagged EXTRA_IN_CONNECTOR.
        "instance_name",
        # Platform/UCP-injected ENCRYPTED auth container for an interpolated
        # profile's credentials (username/password packed into one blob at
        # runtime). Not declared in any connector YAML and not sent by the parity
        # tool — it appears ONLY on the connector side in demisto.params(); must
        # be IGNORED, never flagged EXTRA_IN_CONNECTOR.
        "ucp_credentials",
    }
)


# ============================================================================
# Capability → XSOAR fetch-flag mapping (SINGLE SOURCE OF TRUTH)
# ============================================================================
#
# Which fetch an integration supports is determined ENTIRELY from the connector
# side: the handler (located by its ``xsoar-integration-id``) declares the
# sub-capabilities it subscribes to; each sub-capability resolves to a PARENT
# capability via ``capabilities.yaml``; and each PARENT capability maps to exactly
# ONE XSOAR ``script`` fetch flag (fetch-exclusive) or to nothing (always-on, e.g.
# automation). We do NOT read the integration YML's script flags to decide this.
#
# Platform rule: AT MOST ONE fetch flag may be true on a single integration
# instance, and a single instance must NOT enable two sub-capabilities for
# different fetch types. The param-parity test therefore expands a handler's
# resolved parent capabilities into one VARIANT per fetch-exclusive capability
# (each bundled with the — possibly empty — always-on set). See
# ``multi_capability_variant_design.md``.
#
# Keyed by PARENT capability id (as it appears in capabilities.yaml
# ``capabilities[].id``). The VALUES are the EXACT XSOAR instance-creation toggle
# param names — so a variant's ``fetch_flags`` keys are usable verbatim both to
# create the XSOAR instance AND to drive ``be_config_params`` (one naming
# convention, no translation map). ``be_config_params`` imports the VALUE set
# (:data:`FETCH_FLAG_NAMES`) so the BE-synthesized add/strip logic and the variant
# expansion never drift apart.
CAPABILITY_FETCH_FLAG: dict[str, str] = {
    "fetch-issues": "isFetch",
    "log-collection": "isFetchEvents",
    "fetch-assets-and-vulnerabilities": "isFetchAssets",
    "threat-intelligence-and-enrichment": "feed",
    "fetch-secrets": "isFetchCredentials",
}

#: The full set of fetch-flag names the variant matrix knows about (== the XSOAR
#: toggle param names). Every variant carries ALL of these in its ``fetch_flags``
#: dict (exactly one ``True`` for a fetch variant, all ``False`` for an
#: always-on-only variant).
FETCH_FLAG_NAMES: frozenset[str] = frozenset(CAPABILITY_FETCH_FLAG.values())


def fetch_flag_for_capability(parent_capability_id: str) -> Optional[str]:
    """Return the XSOAR fetch flag a PARENT capability maps to, or ``None``.

    ``None`` means the capability is *always-on* (e.g. automation) and carries no
    fetch flag, so it can be combined with any single fetch capability.
    """
    return CAPABILITY_FETCH_FLAG.get(parent_capability_id)


# ============================================================================
# Exceptions
# ============================================================================


class ResolverError(RuntimeError):
    """Raised when the resolver cannot produce a complete ParityInputs.

    The message is operator-facing and explains the missing prerequisite
    (e.g. an empty ``Connector Folder Path`` cell, a missing handler dir).
    """


# ============================================================================
# Result types
# ============================================================================


@dataclass
class SubCapabilitySpec:
    """A sub-capability the handler subscribes to under a parent capability."""

    id: str  # e.g. "automation-and-remediation_ews-o365"
    enabled: bool = True


@dataclass
class CapabilitySpec:
    """A parent capability the handler subscribes to, with its sub-capabilities."""

    id: str  # PARENT capability id, e.g. "automation-and-remediation"
    #: sub-capabilities the handler subscribes to under this parent (resolved
    #: from handler capabilities[].id against capabilities.yaml sub_capabilities[]).
    sub_capabilities: list[SubCapabilitySpec] = field(default_factory=list)
    #: connector field ids declared for THIS (parent or sub) capability in
    #: configurations.yaml.
    config_field_ids: set[str] = field(default_factory=set)
    #: profile ids advertised by this capability's handler auth_options[]
    #: (MAY be several).
    profile_ids: list[str] = field(default_factory=list)

    @property
    def fetch_flag(self) -> Optional[str]:
        """The XSOAR fetch flag this PARENT capability maps to, or ``None``.

        ``None`` ⇒ always-on (e.g. automation), combinable with any single fetch
        capability. See :data:`CAPABILITY_FETCH_FLAG`.
        """
        return fetch_flag_for_capability(self.id)


@dataclass
class CapabilityVariant:
    """One LEGAL per-integration capability combination to test as a single instance.

    The platform forbids enabling two fetch-exclusive capabilities (``isfetch``,
    ``isfetchevents``, …) on the same integration instance. A handler that
    subscribes to several capabilities is therefore expanded into one variant per
    fetch-exclusive capability, each bundled with the (possibly empty) always-on
    set (e.g. automation). See :func:`_expand_variants` and
    ``multi_capability_variant_design.md``.
    """

    #: Stable id derived from the sorted enabled PARENT capability ids
    #: (e.g. ``"automation-and-remediation+fetch-issues"``).
    id: str
    #: The subset of :class:`CapabilitySpec` to ENABLE for this variant. The
    #: always-on capabilities plus AT MOST ONE fetch-exclusive capability.
    capabilities: list[CapabilitySpec] = field(default_factory=list)
    #: ALL known fetch flags (:data:`FETCH_FLAG_NAMES`), with exactly one ``True``
    #: for a fetch variant and all ``False`` for an always-on-only variant. Drives
    #: the XSOAR instance toggles + the BE-synthesized config-param transform.
    fetch_flags: dict[str, bool] = field(default_factory=dict)
    #: The set of config field ids (in the XSOAR-facing param namespace, i.e. after
    #: serializer renames are applied) that this variant's enabled sub-capabilities
    #: legitimately expose on the connector instance. A connector instance only
    #: delivers the config fields of the sub-capabilities ENABLED in that variant,
    #: so the diff uses this to avoid flagging a field that belongs to a DISABLED
    #: sub-capability as ``MISSING_IN_CONNECTOR``. Populated in :func:`resolve`
    #: (see :func:`build_field_ownership` / :func:`in_scope_fields_for_variant`).
    in_scope_fields: frozenset[str] = field(default_factory=frozenset)

    @property
    def enabled_capability_ids(self) -> list[str]:
        """The PARENT capability ids enabled by this variant (sorted)."""
        return sorted(c.id for c in self.capabilities)

    @property
    def enabled_ownership_units(self) -> set[str]:
        """The ownership-unit ids this variant ENABLES.

        An "ownership unit" is the id under which configurations.yaml scopes a
        capability's fields: a sub-capability id when the capability declares
        sub-capabilities, else the parent capability id itself (matching how
        :func:`_capabilities_from_handler` scopes config fields to BOTH the parent
        and sub ids). This is the per-variant subset against which
        :func:`build_field_ownership` is intersected to compute
        :attr:`in_scope_fields`.
        """
        units: set[str] = set()
        for cap in self.capabilities:
            if cap.sub_capabilities:
                units.update(sc.id for sc in cap.sub_capabilities)
            else:
                units.add(cap.id)
        return units


@dataclass
class ProfileSpec:
    """A connector auth profile the integration uses (one per advertised id).

    Interpolation is signaled by a non-empty :attr:`interpolation_mapping`
    (parsed from ``metadata.xsoar.interpolation_mapping``). The auth field ↔
    xsoar param mapping is derived entirely from this profile — combining
    :attr:`interpolation_mapping` (role → xsoar path) with
    :attr:`auth_field_to_role` (connector field id → role).
    """

    id: str  # e.g. "oauth2_client_credentials.ews_o365"
    type: str  # e.g. "oauth2_client_credentials"
    #: parsed ``metadata.xsoar.interpolation_mapping``: canonical auth ROLE
    #: (matches a field's ``metadata.auth.parameter``) -> xsoar param PATH
    #: (e.g. "credentials.identifier" or a plain "roleArn").
    interpolation_mapping: dict[str, str] = field(default_factory=dict)
    #: prefixed connector auth field id -> canonical role (metadata.auth.parameter).
    auth_field_to_role: dict[str, str] = field(default_factory=dict)
    #: all field ids declared on this profile (prefixed connector ids).
    field_ids: list[str] = field(default_factory=list)

    @property
    def interpolated(self) -> bool:
        """A profile IS interpolated iff it carries a non-empty interpolation mapping."""
        return bool(self.interpolation_mapping)

    def connector_field_to_xsoar_param(self) -> dict[str, str]:
        """Map each prefixed connector field id → the TOP-LEVEL xsoar param.

        For each ``(role, xsoar_path)`` in :attr:`interpolation_mapping`, find the
        connector field id whose ``auth_field_to_role[field_id] == role``; the
        top-level xsoar param is the segment before the first ``.`` in the path.
        """
        role_to_field: dict[str, str] = {
            role: fid for fid, role in self.auth_field_to_role.items()
        }
        out: dict[str, str] = {}
        for role, xsoar_path in self.interpolation_mapping.items():
            fid = role_to_field.get(role)
            if not fid:
                continue
            out[fid] = xsoar_path.split(".")[0]
        return out

    def connector_field_to_xsoar_path(self) -> dict[str, str]:
        """Map each connector auth field id → the FULL xsoar destination PATH
        from the interpolation mapping (e.g. credentials_username ->
        'credentials.identifier'). Unlike connector_field_to_xsoar_param (which
        returns only the top-level segment for compare-scoping), this preserves
        the dotted leaf so the connector-side value can be dug out of the shared
        instance_values at the exact sub-path the integration will see."""
        role_to_field = {role: fid for fid, role in self.auth_field_to_role.items()}
        out: dict[str, str] = {}
        for role, xsoar_path in self.interpolation_mapping.items():
            fid = role_to_field.get(role)
            if not fid:
                continue
            out[fid] = xsoar_path
        return out


@dataclass
class ParityInputs:
    """Everything ``check_param_parity`` needs, resolved from one integration id."""

    integration_id: str
    # Integration side.
    integration_yml_path: str
    integration_brand: str
    # Connector side.
    connector_id: str
    connector_dir: str            # absolute path to <REPO_DIR>/<Connector Folder Path>
    connector_folder_path: str    # the repo-relative path as stored in the CSV
    handler_dir: str              # absolute path to the handler dir
    serializer_path: Optional[str]

    # -- MULTI-CAPABILITY (replaces capability: str / profile_id: str) --
    #: EVERY (sub-)capability the handler subscribes to, normalized to PARENT ids.
    #: Retained for attribution / config-scope union; the per-instance driver is
    #: :attr:`variants` (each variant enables a LEGAL subset of these).
    capabilities: list[CapabilitySpec] = field(default_factory=list)
    #: The LEGAL per-integration capability combinations to test — one
    #: :class:`CapabilityVariant` per fetch-exclusive capability (each bundled with
    #: the always-on set), or a single always-on variant when the handler
    #: subscribes to no fetch capability. The orchestrator loops over these,
    #: creating ONE instance per variant. See :func:`_expand_variants`.
    variants: list[CapabilityVariant] = field(default_factory=list)
    #: de-duped, ordered union of every profile id any subscribed capability
    #: advertises.
    profiles: list[ProfileSpec] = field(default_factory=list)

    # Param discovery results.
    #: Integration YML param-id -> connector field-id it maps to (after serializer
    #: disambiguation). Params present in the integration YML but not found in the
    #: connector are NOT in this dict (they will surface as MISSING_IN_CONNECTOR
    #: at diff time).
    param_to_connector_field: dict[str, str] = field(default_factory=dict)
    #: Integration param ids that are in scope and SHOULD be compared.
    compare_params: set[str] = field(default_factory=set)
    #: Integration param ids explicitly ignored. Reasons are ``"hard_ignore_list"``
    #: (a name in :data:`HARD_IGNORE_PARAMS`) or ``"hidden"`` (hidden in the
    #: integration YML, not migrated to the connector); everything else is
    #: compared. Kept as a ``{name: reason}`` map for diagnostics.
    ignored_params: dict[str, str] = field(default_factory=dict)
    #: serializer maps (same shape as diff._load_serializer_mappings()).
    serializer_by_xsoar: dict[str, str] = field(default_factory=dict)
    serializer_by_connector: dict[str, str] = field(default_factory=dict)
    #: connector field id -> declared TYPE metadata from the connector manifest
    #: (configurations.yaml + connection.yaml profile fields). Each value is a
    #: ``{"field_type": str, "default_value": Any, "enum_values": list[str]}`` dict.
    #: Drives TYPE-CORRECT dummy values in the UCP creation payload so the backend
    #: doesn't reject creation (e.g. a checkbox needs a bool, a duration needs an
    #: int, a select needs a valid enum key). Missing/unknown fields are absent →
    #: the caller falls back to a string dummy.
    field_specs: dict[str, dict] = field(default_factory=dict)
    #: GLOBAL field-ownership map, keyed in the XSOAR-facing param namespace (i.e.
    #: connector field ids translated through the serializer ``by_connector`` map,
    #: falling back to identity). Value is the set of OWNERSHIP-UNIT ids
    #: (sub-capability id, or parent capability id when no sub-capabilities exist)
    #: that legitimately expose that field. Used by the diff to recognise that an
    #: integration-only field belongs to a sub-capability NOT enabled in the
    #: current variant (so it is out-of-variant-scope, not MISSING_IN_CONNECTOR).
    #: See :func:`build_field_ownership`.
    field_owning_subcapabilities: dict[str, frozenset[str]] = field(
        default_factory=dict
    )


# ============================================================================
# Helpers — slugs / yaml / csv
# ============================================================================


def slugify(integration_id: str) -> str:
    """``"Salesforce IAM"`` -> ``"salesforce-iam"``; ``"AWS - ACM"`` -> ``"aws-acm"``.

    Lowercases, turns spaces into dashes, then collapses the ``---`` produced by
    a spaced separator (`` - ``) into a single dash, matching the canonical
    ``connectus_migration.manifest_generator.title_to_slug`` used to CREATE the
    connector/handler directories on disk.
    """
    return integration_id.strip().lower().replace(" ", "-").replace("---", "-")


def handler_dir_name(integration_id: str) -> str:
    """``"Salesforce IAM"`` -> ``"xsoar-salesforce-iam"`` (USER-CONFIRMED rule)."""
    return "xsoar-" + slugify(integration_id)


def _load_yaml(path: Path) -> Any:
    """Load a YAML file, returning ``None`` when it is missing/unparseable."""
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return _yaml.load(f)
    except Exception as e:  # pragma: no cover - defensive
        log.debug("Could not parse %s: %s", path, e)
        return None


def _is_hidden_param(p: dict) -> bool:
    """True when a YML configuration param is hidden ON THE PLATFORM, so it is NOT
    migrated to the connector and must be excluded from param-parity comparison.

    XSOAR's ``hidden`` field is either a boolean (hidden in ALL marketplaces) or a
    LIST of the marketplaces/platforms where the param is hidden (e.g.
    ``["xsoar"]``, ``["marketplacev2"]``, ``["platform"]``). A param hidden only
    on a non-platform marketplace is still present on the platform and IS compared;
    only ``hidden: true`` or a list that includes ``"platform"`` counts as hidden
    here.
    """
    hidden = p.get("hidden")
    if hidden is True:
        return True
    if isinstance(hidden, (list, tuple)):
        return any(str(m).strip().lower() == "platform" for m in hidden)
    return False


def _read_csv_row(integration_id: str, csv_path: Path) -> dict[str, str]:
    """Find the integration's row in the pipeline CSV (case-insensitive)."""
    if not csv_path.exists():
        raise ResolverError(f"Pipeline CSV not found: {csv_path}")
    target = integration_id.strip().lower()
    with open(csv_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if (row.get("Integration ID") or "").strip().lower() == target:
                return row
    raise ResolverError(
        f"Integration {integration_id!r} not found in {csv_path.name}."
    )


# ============================================================================
# Connector YAML field enumeration
# ============================================================================


def _fields_from_capability_configurations(doc: Any, capability: str) -> list[str]:
    """Collect field ids from ``configurations.yaml`` scoped to ``capability``."""
    out: list[str] = []
    if not isinstance(doc, dict):
        return out
    for cap_block in doc.get("configurations") or []:
        if not isinstance(cap_block, dict):
            continue
        if cap_block.get("id") != capability:
            continue
        for conf in cap_block.get("configurations") or []:
            if not isinstance(conf, dict):
                continue
            for fld in conf.get("fields") or []:
                if isinstance(fld, dict) and fld.get("id"):
                    out.append(fld["id"])
    return out


def _view_groups_for_capability(doc: Any, capability: str) -> set[str]:
    """Return the ``view_group``(s) the capability block declares in configurations.yaml.

    A capability's ``configurations[]`` block carries a ``view_group`` that ties it
    to the general-configuration fields sharing that view group.
    """
    groups: set[str] = set()
    if not isinstance(doc, dict):
        return groups
    for cap_block in doc.get("configurations") or []:
        if isinstance(cap_block, dict) and cap_block.get("id") == capability:
            vg = cap_block.get("view_group")
            if vg:
                groups.add(vg)
    return groups


def _general_config_fields_for_view_groups(doc: Any, view_groups: set[str]) -> list[str]:
    """Collect ``general_configurations`` field ids whose ``view_group`` is enabled.

    ``general_configurations`` fields are scoped by ``view_group`` (NOT by
    capability). A field is delivered to an instance when its ``view_group`` is
    shared by an enabled capability — so we collect every general-config field
    whose ``view_group`` is in ``view_groups``.
    """
    out: list[str] = []
    if not isinstance(doc, dict) or not view_groups:
        return out
    general = doc.get("general_configurations")
    if not isinstance(general, dict):
        return out
    for conf in general.get("configurations") or []:
        if not isinstance(conf, dict):
            continue
        if conf.get("view_group") not in view_groups:
            continue
        for fld in conf.get("fields") or []:
            if isinstance(fld, dict) and fld.get("id"):
                out.append(fld["id"])
    return out


def _owned_connector_fields_for_unit(doc: Any, unit_id: str) -> set[str]:
    """The connector field ids OWNED by a single ownership unit (sub-/capability).

    An ownership unit's owned set is its **direct** configuration fields (declared
    under its ``configurations[].fields[]`` block) UNION the
    ``general_configurations`` fields sharing its ``view_group``. A unit that
    declares NO direct fields still owns its view_group's general fields (a
    sub-capability always carries at least its ``id`` + ``view_group``).

    Returned ids are CONNECTOR field ids (the manifest namespace); the caller
    translates them to the XSOAR param namespace.
    """
    owned: set[str] = set()
    owned.update(_fields_from_capability_configurations(doc, unit_id))
    owned.update(
        _general_config_fields_for_view_groups(
            doc, _view_groups_for_capability(doc, unit_id)
        )
    )
    return owned


def build_field_ownership(
    configurations_doc: Any,
    unit_ids: set[str],
    *,
    serializer_by_connector: Optional[dict[str, str]] = None,
) -> dict[str, frozenset[str]]:
    """Map every owned config field → the set of ownership units that own it.

    For each unit in ``unit_ids`` (sub-capability ids, or parent capability ids
    when a capability declares no sub-capabilities), compute its owned connector
    field set (:func:`_owned_connector_fields_for_unit`) and invert into a
    ``field -> {owning unit ids}`` mapping. A ``general_configurations`` field is
    owned by EVERY unit sharing its view_group, so it maps to several units.

    Keys are emitted in the XSOAR-facing param namespace: each connector field id
    is translated through ``serializer_by_connector`` (connector field → xsoar
    param name) when a mapping exists, else passed through unchanged. This keeps
    the map comparable to the keys the diff iterates (XSOAR param names).
    """
    rename = serializer_by_connector or {}
    out: dict[str, set[str]] = {}
    for unit_id in unit_ids:
        for connector_field in _owned_connector_fields_for_unit(
            configurations_doc, unit_id
        ):
            key = rename.get(connector_field, connector_field)
            out.setdefault(key, set()).add(unit_id)
    return {field_id: frozenset(units) for field_id, units in out.items()}


def _computed_field_owner_units(serializer_doc: Any) -> dict[str, set[str]]:
    """Map serializer COMPUTED field ids → the sub-capability ids that gate them.

    A serializer ``computed_fields[]`` entry injects one or more output fields
    (``output[].id``, already in the XSOAR-facing param namespace) only when its
    gating condition is satisfied. We treat a ``type: capability`` condition's
    ``options.capability_id`` as the OWNING sub-capability of every output field
    that entry produces — so a computed field (e.g. ``incidentFetchInterval`` gated
    on ``fetch-issues_<sub>``) can be scoped out of variants where that
    sub-capability is disabled, exactly like a directly-declared config field.

    Only ``capability``-typed conditions contribute ownership; entries gated on
    non-capability conditions (or with no condition at all) yield no owner and
    are left unmapped (so they stay always-in-scope). Multiple capability
    conditions across ``any_of`` branches all become owners of the output.
    """
    out: dict[str, set[str]] = {}
    if not isinstance(serializer_doc, dict):
        return out
    for entry in serializer_doc.get("computed_fields") or []:
        if not isinstance(entry, dict):
            continue
        output_ids = [
            o["id"]
            for o in entry.get("output") or []
            if isinstance(o, dict) and o.get("id")
        ]
        if not output_ids:
            continue
        owners: set[str] = set()
        for branch in entry.get("any_of") or []:
            if not isinstance(branch, dict):
                continue
            for cond in branch.get("conditions") or []:
                if not isinstance(cond, dict) or cond.get("type") != "capability":
                    continue
                cap_id = (cond.get("options") or {}).get("capability_id")
                if cap_id:
                    owners.add(cap_id)
        if not owners:
            continue
        for fid in output_ids:
            out.setdefault(fid, set()).update(owners)
    return out


def merge_computed_field_ownership(
    field_ownership: dict[str, frozenset[str]],
    serializer_doc: Any,
    *,
    known_units: Optional[set[str]] = None,
) -> dict[str, frozenset[str]]:
    """Fold serializer computed-field ownership into ``field_ownership``.

    Returns a NEW map where every computed output field (see
    :func:`_computed_field_owner_units`) is attributed to its gating
    sub-capability id(s), UNIONed with any ownership it already had. When
    ``known_units`` is given, only gating ids that the handler actually
    subscribes to are folded in (so a computed field gated on a foreign
    connector's sub-capability is ignored rather than mis-scoped).
    """
    computed = _computed_field_owner_units(serializer_doc)
    if not computed:
        return dict(field_ownership)
    merged: dict[str, set[str]] = {
        fid: set(units) for fid, units in field_ownership.items()
    }
    for fid, owners in computed.items():
        if known_units is not None:
            owners = owners & known_units
        if not owners:
            continue
        merged.setdefault(fid, set()).update(owners)
    return {fid: frozenset(units) for fid, units in merged.items()}


def in_scope_fields_for_variant(
    field_ownership: dict[str, frozenset[str]], enabled_units: set[str]
) -> frozenset[str]:
    """The XSOAR-namespace fields a variant legitimately exposes.

    A field is in-scope for a variant iff at least one of its owning ownership
    units is ENABLED in that variant. (Profile/connection fields and BE-synth
    fields are folded in by the caller — see :func:`resolve` — so a legitimately
    present field is never scoped out.)
    """
    return frozenset(
        field_id
        for field_id, owners in field_ownership.items()
        if owners & enabled_units
    )


def _field_spec_from_field(fld: dict) -> dict:
    """Extract the type metadata of one manifest field dict.

    Returns ``{"field_type", "default_value", "enum_values", "config_type"}``.
    ``enum_values`` is the list of valid ``key``s for select/multi_select fields
    (from ``options.values[].key``); ``default_value`` is ``options.default_value``
    when present; ``config_type`` is ``xsoar.config_type`` when present (e.g.
    ``"backend"`` for entity-reference fields the XSOAR backend resolves against
    REAL tenant entities — engines, classifiers, mappers, incident types — which
    therefore CANNOT carry an arbitrary dummy string). Used to build TYPE-CORRECT
    dummy values for the creation payload.
    """
    opts = fld.get("options") if isinstance(fld.get("options"), dict) else {}
    enum_values: list[str] = []
    for v in opts.get("values") or []:
        if isinstance(v, dict) and v.get("key") is not None:
            enum_values.append(v["key"])
    # ``config_type`` lives at ``metadata.xsoar.config_type`` in the manifest
    # (e.g. ``field.metadata.xsoar.config_type: backend`` for entity-reference
    # fields). Fall back to a top-level ``xsoar`` block defensively, in case a
    # connector/older manifest places it there.
    metadata = fld.get("metadata") if isinstance(fld.get("metadata"), dict) else {}
    xsoar = metadata.get("xsoar") if isinstance(metadata.get("xsoar"), dict) else {}
    if not xsoar and isinstance(fld.get("xsoar"), dict):
        xsoar = fld["xsoar"]
    return {
        "field_type": fld.get("field_type"),
        "default_value": opts.get("default_value"),
        "enum_values": enum_values,
        "config_type": xsoar.get("config_type"),
    }


def _collect_field_specs(configurations_doc: Any, connection_doc: Any) -> dict[str, dict]:
    """Map every connector field id → its type metadata (:func:`_field_spec_from_field`).

    Scans ALL fields in ``configurations.yaml`` (``general_configurations`` +
    per-capability ``configurations``) and every profile field in
    ``connection.yaml``. Last-writer-wins on duplicate ids is fine — duplicate
    declarations of the same id carry the same type.
    """
    specs: dict[str, dict] = {}

    def _scan_configurations(node: Any) -> None:
        if not isinstance(node, dict):
            return
        for conf in node.get("configurations") or []:
            if not isinstance(conf, dict):
                continue
            for fld in conf.get("fields") or []:
                if isinstance(fld, dict) and fld.get("id"):
                    specs[fld["id"]] = _field_spec_from_field(fld)

    if isinstance(configurations_doc, dict):
        _scan_configurations(configurations_doc.get("general_configurations"))
        for cap_block in configurations_doc.get("configurations") or []:
            _scan_configurations(cap_block)

    if isinstance(connection_doc, dict):
        for profile in connection_doc.get("profiles") or []:
            if not isinstance(profile, dict):
                continue
            for conf in profile.get("configurations") or []:
                if not isinstance(conf, dict):
                    continue
                for fld in conf.get("fields") or []:
                    if isinstance(fld, dict) and fld.get("id"):
                        specs[fld["id"]] = _field_spec_from_field(fld)

    return specs


def _parse_interpolation_mapping(profile: dict) -> dict[str, str]:
    """Parse a profile's ``metadata.xsoar.interpolation_mapping`` string.

    SINGLE source of truth for interpolation. The mapping is a comma-separated
    list of ``ROLE:XSOAR_PATH`` pairs where:

      * ``ROLE`` matches a profile field's ``metadata.auth.parameter`` (the
        connector auth role), and
      * ``XSOAR_PATH`` is the ``demisto.params()`` key path (e.g.
        ``credentials.identifier`` or a plain ``roleArn``).

    Splits on ``,`` then ``:``, trims whitespace, and ignores blank/malformed
    pairs. A profile is interpolated iff the returned dict is non-empty.

    Returns:
        ``{role: xsoar_path}``. Empty when the key is absent/blank/malformed.
    """
    meta = profile.get("metadata")
    if not isinstance(meta, dict):
        return {}
    xsoar = meta.get("xsoar")
    if not isinstance(xsoar, dict):
        return {}
    raw = xsoar.get("interpolation_mapping")
    if not isinstance(raw, str):
        return {}
    mapping: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        role, _, xsoar_path = pair.partition(":")
        role = role.strip()
        xsoar_path = xsoar_path.strip()
        if not role or not xsoar_path:
            continue
        mapping[role] = xsoar_path
    return mapping


# ============================================================================
# Capability resolution (parent / sub disambiguation)
# ============================================================================


def _resolve_capability(
    handler_cap_id: str, capabilities_doc: Any
) -> tuple[str, Optional[str]]:
    """Normalize a handler ``capabilities[].id`` to ``(parent_id, sub_id_or_None)``.

    A handler entry may be either a PARENT capability id (matches a
    ``capabilities.yaml`` ``capabilities[].id``) or a SUB-capability id (matches
    some ``capabilities[].sub_capabilities[].id`` — the parent is the owning
    ``capabilities[].id``). Unknown ids are treated as a bare parent (so the
    caller still enables them; the connector will reject genuinely-invalid ids).
    """
    caps = (capabilities_doc or {}).get("capabilities") or [] if isinstance(
        capabilities_doc, dict
    ) else []
    # Direct parent match.
    for cap in caps:
        if isinstance(cap, dict) and cap.get("id") == handler_cap_id:
            return handler_cap_id, None
    # Sub-capability match.
    for cap in caps:
        if not isinstance(cap, dict):
            continue
        for sub in cap.get("sub_capabilities") or []:
            if isinstance(sub, dict) and sub.get("id") == handler_cap_id:
                return cap.get("id") or handler_cap_id, handler_cap_id
    # Unknown — treat as a bare parent.
    return handler_cap_id, None


def _capabilities_from_handler(
    handler_doc: Any, capabilities_doc: Any, configurations_doc: Any
) -> list[CapabilitySpec]:
    """Enumerate EVERY (sub-)capability the handler subscribes to.

    Groups sub-capabilities under their parent ``CapabilitySpec``, collects each
    capability's ``auth_options[].id`` (profile ids) and its configuration field
    ids from ``configurations.yaml`` (scoped to BOTH the parent and the sub id).
    """
    by_parent: dict[str, CapabilitySpec] = {}
    order: list[str] = []

    for entry in (handler_doc or {}).get("capabilities") or []:
        if not isinstance(entry, dict):
            continue
        handler_cap_id = entry.get("id")
        if not handler_cap_id:
            continue
        parent_id, sub_id = _resolve_capability(handler_cap_id, capabilities_doc)

        spec = by_parent.get(parent_id)
        if spec is None:
            spec = CapabilitySpec(id=parent_id)
            by_parent[parent_id] = spec
            order.append(parent_id)
            # Parent-scoped configuration fields.
            spec.config_field_ids.update(
                _fields_from_capability_configurations(configurations_doc, parent_id)
            )
            # general_configurations fields are scoped by view_group, not by
            # capability — include those whose view_group matches this parent
            # capability's block so a fetch-issues-only instance still receives
            # shared SIEM config (e.g. fetchTime/fetchLimit), matching what the
            # integration reads at runtime regardless of fetch mode.
            spec.config_field_ids.update(
                _general_config_fields_for_view_groups(
                    configurations_doc,
                    _view_groups_for_capability(configurations_doc, parent_id),
                )
            )

        if sub_id is not None:
            if not any(sc.id == sub_id for sc in spec.sub_capabilities):
                spec.sub_capabilities.append(SubCapabilitySpec(id=sub_id))
            # Sub-scoped configuration fields (configurations.yaml may key on the
            # sub-capability id too).
            spec.config_field_ids.update(
                _fields_from_capability_configurations(configurations_doc, sub_id)
            )
            # general_configurations fields for the sub-capability's view_group.
            spec.config_field_ids.update(
                _general_config_fields_for_view_groups(
                    configurations_doc,
                    _view_groups_for_capability(configurations_doc, sub_id),
                )
            )

        # Profile ids advertised by this handler entry.
        for opt in entry.get("auth_options") or []:
            if isinstance(opt, dict) and opt.get("id"):
                if opt["id"] not in spec.profile_ids:
                    spec.profile_ids.append(opt["id"])

    return [by_parent[pid] for pid in order]


def _expand_variants(capabilities: list[CapabilitySpec]) -> list[CapabilityVariant]:
    """Expand a handler's resolved capabilities into LEGAL per-instance variants.

    The platform forbids enabling two fetch-exclusive capabilities on the same
    integration instance. We therefore partition ``capabilities`` into:

      * the **always-on set** — capabilities with no fetch flag (e.g. automation);
        this set MAY be empty (automation is not guaranteed to exist), and
      * the **fetch-exclusive set** — capabilities that map to a fetch flag
        (:data:`CAPABILITY_FETCH_FLAG`).

    Then:

      * if there is ≥1 fetch-exclusive capability → emit ONE variant per
        fetch-exclusive capability, each = always-on set + that single fetch cap,
        with exactly that cap's fetch flag ``True``;
      * if there are 0 fetch-exclusive capabilities → emit a SINGLE variant = the
        always-on set, with all fetch flags ``False``.

    Every variant carries the COMPLETE :data:`FETCH_FLAG_NAMES` set in
    ``fetch_flags`` (exactly one ``True`` for a fetch variant), so downstream code
    can rely on all keys being present.

    Raises:
        ResolverError: if ``capabilities`` is empty (no instance is testable).
    """
    if not capabilities:
        raise ResolverError(
            "Cannot expand variants: the handler subscribes to no capabilities."
        )

    always_on = [c for c in capabilities if c.fetch_flag is None]
    fetch_caps = [c for c in capabilities if c.fetch_flag is not None]

    def _flags(active: Optional[str]) -> dict[str, bool]:
        # ALL known flags present; exactly the active one True (if any).
        return {name: (name == active) for name in sorted(FETCH_FLAG_NAMES)}

    def _variant_id(caps: list[CapabilitySpec]) -> str:
        return "+".join(sorted(c.id for c in caps)) or "no-capability"

    variants: list[CapabilityVariant] = []

    if not fetch_caps:
        # Always-on only (e.g. automation alone, or any non-fetch combination).
        variants.append(
            CapabilityVariant(
                id=_variant_id(always_on),
                capabilities=list(always_on),
                fetch_flags=_flags(None),
            )
        )
        return variants

    # One variant per fetch-exclusive capability, bundled with the always-on set.
    for fc in fetch_caps:
        variant_caps = list(always_on) + [fc]
        variants.append(
            CapabilityVariant(
                id=_variant_id(variant_caps),
                capabilities=variant_caps,
                fetch_flags=_flags(fc.fetch_flag),
            )
        )
    return variants


# ============================================================================
# Profiles
# ============================================================================


def _profiles_from_connection(
    connection_doc: Any, profile_ids: list[str]
) -> list[ProfileSpec]:
    """Build a :class:`ProfileSpec` for each advertised profile id.

    Reads field ids, the per-field canonical role (``metadata.auth.parameter``),
    and the interpolation mapping (``metadata.xsoar.interpolation_mapping``).
    """
    if not isinstance(connection_doc, dict):
        return []
    profiles_by_id: dict[str, dict] = {}
    for profile in connection_doc.get("profiles") or []:
        if isinstance(profile, dict) and profile.get("id"):
            profiles_by_id[profile["id"]] = profile

    out: list[ProfileSpec] = []
    seen: set[str] = set()
    for pid in profile_ids:
        if pid in seen:
            continue
        seen.add(pid)
        profile = profiles_by_id.get(pid)
        if profile is None:
            # Advertised but not declared — keep a placeholder so callers know.
            out.append(ProfileSpec(id=pid, type=""))
            continue
        spec = ProfileSpec(
            id=pid,
            type=str(profile.get("type") or ""),
            interpolation_mapping=_parse_interpolation_mapping(profile),
        )
        for conf in profile.get("configurations") or []:
            if not isinstance(conf, dict):
                continue
            for fld in conf.get("fields") or []:
                if not isinstance(fld, dict) or not fld.get("id"):
                    continue
                fid = fld["id"]
                spec.field_ids.append(fid)
                role = (
                    ((fld.get("metadata") or {}).get("auth") or {}).get("parameter")
                )
                if role:
                    spec.auth_field_to_role[fid] = role
        out.append(spec)
    return out


# ============================================================================
# Serializer
# ============================================================================


def _load_serializer_maps(handler_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Parse this handler's serializer.yaml.

    Returns ``(by_xsoar, by_connector)`` mirroring
    ``diff._load_serializer_mappings`` but scoped to a SINGLE handler dir
    (we want THIS integration's serializer, not every handler's).
    """
    by_xsoar: dict[str, str] = {}
    by_connector: dict[str, str] = {}
    doc = _load_yaml(handler_dir / "serializer.yaml")
    if not isinstance(doc, dict):
        return by_xsoar, by_connector
    for entry in doc.get("field_mappings") or []:
        if not isinstance(entry, dict):
            continue
        connector_field = entry.get("id")
        xsoar_name = entry.get("field_name")
        if not connector_field or not xsoar_name:
            continue
        by_xsoar[xsoar_name] = connector_field
        by_connector[connector_field] = xsoar_name
    return by_xsoar, by_connector


# ============================================================================
# Public entry point
# ============================================================================


def resolve(integration_id: str, *, csv_path: Optional[Path] = None) -> ParityInputs:
    """Resolve ``integration_id`` into a complete :class:`ParityInputs`.

    Raises:
        ResolverError: when a prerequisite is missing — most importantly when
            the row's ``Connector Folder Path`` is empty (the connector has not
            been created / recorded yet), or when the handler dir / connector
            YAMLs cannot be found on disk.
    """
    csv_path = csv_path or PIPELINE_CSV
    row = _read_csv_row(integration_id, csv_path)

    integration_yml_path = (row.get("Integration File Path") or "").strip()
    if not integration_yml_path:
        raise ResolverError(
            f"Integration {integration_id!r} has no 'Integration File Path' in the CSV."
        )

    connector_folder_path = (row.get("Connector Folder Path") or "").strip()
    if not connector_folder_path:
        raise ResolverError(
            f"Integration {integration_id!r} has no 'Connector Folder Path' set — "
            "the connector has not been created/recorded yet. Run "
            f"`set-connector-path \"{integration_id}\" connectors/<slug>` first."
        )

    repo_dir = _repo_dir()
    connector_dir = (repo_dir / connector_folder_path).resolve()
    if not connector_dir.exists():
        raise ResolverError(
            f"Connector dir not found: {connector_dir} "
            f"(REPO_DIR={repo_dir}, Connector Folder Path={connector_folder_path!r})."
        )

    handler_dir = connector_dir / "components" / "handlers" / handler_dir_name(integration_id)
    handler_yaml_path = handler_dir / "handler.yaml"
    if not handler_yaml_path.exists():
        raise ResolverError(
            f"Handler not found for {integration_id!r}: expected {handler_yaml_path}. "
            f"(Handler dir name is computed as 'xsoar-' + slugify(Integration ID) = "
            f"{handler_dir_name(integration_id)!r}.)"
        )

    handler_doc = _load_yaml(handler_yaml_path)
    if not isinstance(handler_doc, dict):
        raise ResolverError(f"Could not parse handler.yaml: {handler_yaml_path}")

    # Correctness assertion: the handler must declare this integration id.
    label = (
        ((handler_doc.get("triggering") or {}).get("labels") or {}).get(
            "xsoar-integration-id"
        )
    )
    if label and label.strip() != integration_id.strip():
        raise ResolverError(
            f"Handler label mismatch: {handler_yaml_path} declares "
            f"xsoar-integration-id={label!r} but resolver was asked for "
            f"{integration_id!r}."
        )

    # Connector YAML docs.
    connection_doc = _load_yaml(connector_dir / "connection.yaml")
    configurations_doc = _load_yaml(connector_dir / "configurations.yaml")
    capabilities_doc = _load_yaml(connector_dir / "capabilities.yaml")

    # ── MULTI-CAPABILITY enumeration ──
    capabilities = _capabilities_from_handler(
        handler_doc, capabilities_doc, configurations_doc
    )
    if not capabilities:
        raise ResolverError(
            f"handler.yaml has no capabilities[] entry: {handler_yaml_path}"
        )

    # ── Expand into LEGAL per-instance variants (one per fetch-exclusive cap) ──
    # The platform forbids two fetch flags on one instance; _expand_variants
    # guarantees each variant carries at most one fetch capability.
    variants = _expand_variants(capabilities)

    # Ordered, de-duped union of every profile id any subscribed capability uses.
    profile_ids: list[str] = []
    for cap in capabilities:
        for pid in cap.profile_ids:
            if pid not in profile_ids:
                profile_ids.append(pid)

    profiles = _profiles_from_connection(connection_doc, profile_ids)

    # Serializer maps (this handler).
    by_xsoar, by_connector = _load_serializer_maps(handler_dir)

    # ── Per-variant field SCOPING (Bucket C) ──
    # A connector instance only exposes the config fields of the sub-capabilities
    # ENABLED in its variant. Build a GLOBAL field-ownership map (field id in the
    # XSOAR param namespace → set of owning ownership-unit ids) across EVERY
    # ownership unit the handler subscribes to, then derive each variant's
    # ``in_scope_fields`` (fields whose owner is enabled in that variant). The diff
    # uses these to avoid false MISSING_IN_CONNECTOR for a field that belongs to a
    # sub-capability disabled in the current variant.
    all_ownership_units: set[str] = set()
    for cap in capabilities:
        if cap.sub_capabilities:
            all_ownership_units.update(sc.id for sc in cap.sub_capabilities)
        else:
            all_ownership_units.add(cap.id)
    field_ownership = build_field_ownership(
        configurations_doc,
        all_ownership_units,
        serializer_by_connector=by_connector,
    )
    # Fold serializer COMPUTED-field ownership in: a computed field (e.g.
    # ``incidentFetchInterval``) is injected by the serializer only when its gating
    # sub-capability is enabled, so attribute it to that gating sub-capability id
    # (restricted to units this handler actually subscribes to) so it is scoped
    # out of variants where the gating sub-capability is disabled — exactly like a
    # directly-declared config field.
    serializer_doc = _load_yaml(handler_dir / "serializer.yaml")
    field_ownership = merge_computed_field_ownership(
        field_ownership, serializer_doc, known_units=all_ownership_units
    )

    # Profile (auth/connection) xsoar param names are ALWAYS legitimately present
    # regardless of which fetch sub-capability is enabled, so fold them into every
    # variant's in-scope set so we never scope out a real auth field.
    profile_xsoar_params: set[str] = set()
    for prof in profiles:
        profile_xsoar_params.update(prof.connector_field_to_xsoar_param().values())

    # BE-synthesized params (isFetch/eventFetchInterval/feed*/…) are injected by
    # the platform at runtime. They are treated as always in-scope so they are
    # never reclassified as out-of-variant-scope — UNLESS the connector manifest
    # ITSELF scopes the field to a specific sub-capability (i.e. it appears in
    # ``field_ownership``). A field the manifest owns (e.g. Akamai's
    # ``longRunning`` / ``eventFetchInterval`` under ``log-collection``) must obey
    # its manifest ownership so it is correctly scoped out of variants where its
    # owning sub-capability is disabled; manifest ownership is authoritative and
    # wins over the blanket BE-synth protection.
    from be_config_params import BE_SYNTHESIZED_PARAM_NAMES  # noqa: E402

    be_synth_always_in_scope = frozenset(BE_SYNTHESIZED_PARAM_NAMES) - frozenset(
        field_ownership
    )
    always_in_scope = frozenset(profile_xsoar_params) | be_synth_always_in_scope
    for variant in variants:
        variant.in_scope_fields = (
            in_scope_fields_for_variant(
                field_ownership, variant.enabled_ownership_units
            )
            | always_in_scope
        )

    # Connector field id → declared type metadata (for type-correct dummy values
    # in the UCP creation payload). Covers configurations.yaml + connection.yaml.
    field_specs = _collect_field_specs(configurations_doc, connection_doc)

    # ── Build the result shell ──
    inputs = ParityInputs(
        integration_id=integration_id,
        integration_yml_path=integration_yml_path,
        integration_brand=integration_id,  # brand == Integration ID by convention
        connector_id=connector_dir.name,
        connector_dir=str(connector_dir),
        connector_folder_path=connector_folder_path,
        handler_dir=str(handler_dir),
        serializer_path=str(handler_dir / "serializer.yaml")
        if (handler_dir / "serializer.yaml").exists()
        else None,
        capabilities=capabilities,
        variants=variants,
        profiles=profiles,
        serializer_by_xsoar=by_xsoar,
        serializer_by_connector=by_connector,
        field_specs=field_specs,
        field_owning_subcapabilities=field_ownership,
    )

    # ── Param discovery: enumerate EVERY integration-YML config param ──
    #
    # COMPARISON POLICY (USER-CONFIRMED): a param is IGNORED iff (a) its name is
    # on the resolver's HARD_IGNORE_PARAMS list (reason "hard_ignore_list"), OR
    # (b) it is HIDDEN in the integration YML (reason "hidden") — hidden params
    # are not migrated to the connector at all. EVERYTHING else is compared
    # verbatim: type-4 encrypted params, auth/profile params, and type-9
    # `credentials` (the full object) are ALL compared. The interpolation_mapping
    # is retained ONLY for value-seeding (connector_field_to_xsoar_path, used by
    # ucp_capture) — it plays NO role in deciding what to compare.
    yml_doc = _load_yaml(Path(_abs_integration_yml(integration_yml_path)))
    yml_config_entries = [
        p
        for p in ((yml_doc or {}).get("configuration") or [])
        if isinstance(p, dict) and p.get("name")
    ]
    hidden_param_names = {
        p["name"] for p in yml_config_entries if _is_hidden_param(p)
    }
    yml_params = [p["name"] for p in yml_config_entries]

    for param in yml_params:
        # 1) Hard ignore-list always wins.
        if param in HARD_IGNORE_PARAMS:
            inputs.ignored_params[param] = "hard_ignore_list"
            continue
        # 2) Hidden in the integration YML → not migrated to the connector → ignore.
        if param in hidden_param_names:
            inputs.ignored_params[param] = "hidden"
            continue
        # 3) Everything else is compared. Record the connector field this param
        #    maps to (serializer rename → identity) for diagnostics/attribution.
        connector_field = by_xsoar.get(param) or param
        inputs.param_to_connector_field[param] = connector_field
        inputs.compare_params.add(param)

    log.info(
        "Resolved %s: connector=%s capabilities=%s variants=%s profiles=%s "
        "(%d compare, %d ignored)",
        integration_id,
        connector_dir.name,
        [
            (cap.id, [sc.id for sc in cap.sub_capabilities])
            for cap in capabilities
        ],
        [
            (v.id, [f for f, on in v.fetch_flags.items() if on] or ["<none>"])
            for v in variants
        ],
        [(p.id, p.interpolated) for p in profiles],
        len(inputs.compare_params),
        len(inputs.ignored_params),
    )
    return inputs


def _abs_integration_yml(integration_yml_path: str) -> str:
    """Resolve the integration YML path against the workspace root when relative."""
    if os.path.isabs(integration_yml_path):
        return integration_yml_path
    return str((_WORKSPACE_ROOT / integration_yml_path).resolve())

