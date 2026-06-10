"""resolver — turn a single ``integration_id`` into everything the param-parity
orchestrator needs (the "brain" that makes ``check_param_parity.py`` standalone).

Given ONE input — the XSOAR ``Integration ID`` — :func:`resolve` reads the
migration pipeline CSV row, locates the connector + handler on disk (in the
``unified-connectors-content`` repo at ``$REPO_DIR``), parses the connector's
YAML files, and returns a :class:`ParityInputs` describing:

  * the integration YML path + brand,
  * the connector dir + id,
  * ALL (sub-)capabilities + profiles the handler subscribes to,
  * the in-scope param set (discovered INTEGRATION-YML → CONNECTOR),
  * the serializer mapping (connector field ↔ xsoar param),
  * the Auth Details mapping (integration → connector auth field ids),
  * the set of "interpolated" profile params that MUST be compared,
  * the hard ignore-list.

Design of record: ``plans/param-parity-pipeline-integration.md`` (Phase 1 +
the "REVISED MULTI-CAPABILITY + AUTH-MAPPING DESIGN" section).

CORE METHODOLOGY (see the plan's "CORE METHODOLOGY" section):

  1. Param discovery is INTEGRATION-YML → CONNECTOR. We enumerate every param
     from the integration's own YML ``configuration`` and look each one up in the
     connector (connection.yaml + configurations.yaml[capability] +
     capabilities.yaml general_configurations + profiles[]). The matched set is
     what's in scope for THIS integration on THIS connector.
  2. The handler's serializer.yaml resolves duplicate / renamed connector fields
     to the TRUE id as it appears in the integration.
  3. A single handler may subscribe to MULTIPLE capabilities + sub-capabilities;
     every one of them is enumerated (normalized to its PARENT capability id).
  4. Profile / auth params are IGNORED by default, but COMPARED when the profile
     carries ``metadata.xsoar.interpolated == "true"``. Interpolation is read
     from the CONNECTOR PROFILE ONLY (connection.yaml
     ``profiles[].metadata.xsoar.interpolated``); the ``Auth Details`` object is
     used ONLY for the integration → connector auth field mapping.
  5. A hard ignore-list is ALWAYS dropped (even inside an interpolated profile).

This module is read-only and has no network / docker dependencies — it only
reads files, so it is cheap to unit-test against a fixture connector.
"""

from __future__ import annotations

import csv
import json
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
# Hard ignore-list — params that NEVER appear in a comparable way in runtime
# demisto.params(), even inside an interpolated profile. (USER-CONFIRMED.)
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
    }
)


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


@dataclass
class ProfileSpec:
    """A connector auth profile the integration uses (one per advertised id)."""

    id: str  # e.g. "oauth2_client_credentials.ews_o365"
    type: str  # e.g. "oauth2_client_credentials"
    #: interpolation flag — read ONLY from profiles[].metadata.xsoar.interpolated.
    interpolated: bool = False
    #: prefixed connector auth field id -> canonical role (metadata.auth.parameter).
    auth_field_to_role: dict[str, str] = field(default_factory=dict)
    #: all field ids declared on this profile (prefixed connector ids).
    field_ids: list[str] = field(default_factory=list)


@dataclass
class AuthMappingSpec:
    """One parsed ``auth_types[]`` entry from the Auth Details CSV column.

    Interpolation is NOT carried here — it is decided per profile (ProfileSpec).
    """

    name: str  # auth_types[].name, e.g. "credentials"
    type: str  # APIKey | Plain | Passthrough | NoneRequired
    #: xsoar-leaf (e.g. "credentials.password") -> connector field id
    #: (serializer/role-resolved).
    xsoar_to_connector_field: dict[str, str] = field(default_factory=dict)


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
    capabilities: list[CapabilitySpec] = field(default_factory=list)
    #: de-duped, ordered union of every profile id any subscribed capability
    #: advertises.
    profiles: list[ProfileSpec] = field(default_factory=list)

    # -- AUTH MAPPING (interpolation NOT here; it lives on ProfileSpec) --
    auth_mappings: list[AuthMappingSpec] = field(default_factory=list)
    other_connection: list[str] = field(default_factory=list)

    # Param discovery results.
    #: Integration YML param-id -> connector field-id it maps to (after serializer
    #: disambiguation). Params present in the integration YML but not found in the
    #: connector are NOT in this dict (they will surface as MISSING_IN_CONNECTOR
    #: at diff time).
    param_to_connector_field: dict[str, str] = field(default_factory=dict)
    #: Integration param ids that are in scope and SHOULD be compared.
    compare_params: set[str] = field(default_factory=set)
    #: Integration param ids explicitly ignored (auth/profile-not-interpolated +
    #: hard ignore-list), with the reason — for diagnostics.
    ignored_params: dict[str, str] = field(default_factory=dict)
    #: serializer maps (same shape as diff._load_serializer_mappings()).
    serializer_by_xsoar: dict[str, str] = field(default_factory=dict)
    serializer_by_connector: dict[str, str] = field(default_factory=dict)


# ============================================================================
# Helpers — slugs / yaml / csv
# ============================================================================


def slugify(integration_id: str) -> str:
    """``"Salesforce IAM"`` -> ``"salesforce-iam"`` (lower + spaces -> dashes)."""
    return integration_id.strip().lower().replace(" ", "-")


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


def _fields_from_general_configurations(doc: Any) -> list[str]:
    """Collect field ids from a ``general_configurations`` block (connection /
    capabilities files share this shape)."""
    out: list[str] = []
    if not isinstance(doc, dict):
        return out
    gc = doc.get("general_configurations")
    if not isinstance(gc, dict):
        return out
    for conf in gc.get("configurations") or []:
        if not isinstance(conf, dict):
            continue
        for fld in conf.get("fields") or []:
            if isinstance(fld, dict) and fld.get("id"):
                out.append(fld["id"])
    return out


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


def _is_interpolated(profile: dict) -> bool:
    """Whether a profile's ``metadata.xsoar.interpolated`` is truthy.

    SINGLE source of truth for the interpolation flag. The Auth Details object's
    own ``interpolated`` key is intentionally NOT consulted.
    """
    meta = profile.get("metadata")
    if not isinstance(meta, dict):
        return False
    xsoar = meta.get("xsoar")
    if not isinstance(xsoar, dict):
        return False
    val = xsoar.get("interpolated")
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() == "true"
    return False


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

        if sub_id is not None:
            if not any(sc.id == sub_id for sc in spec.sub_capabilities):
                spec.sub_capabilities.append(SubCapabilitySpec(id=sub_id))
            # Sub-scoped configuration fields (configurations.yaml may key on the
            # sub-capability id too).
            spec.config_field_ids.update(
                _fields_from_capability_configurations(configurations_doc, sub_id)
            )

        # Profile ids advertised by this handler entry.
        for opt in entry.get("auth_options") or []:
            if isinstance(opt, dict) and opt.get("id"):
                if opt["id"] not in spec.profile_ids:
                    spec.profile_ids.append(opt["id"])

    return [by_parent[pid] for pid in order]


# ============================================================================
# Profiles
# ============================================================================


def _profiles_from_connection(
    connection_doc: Any, profile_ids: list[str]
) -> list[ProfileSpec]:
    """Build a :class:`ProfileSpec` for each advertised profile id.

    Reads field ids, the per-field canonical role (``metadata.auth.parameter``),
    and the interpolation flag (``metadata.xsoar.interpolated`` ONLY).
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
            interpolated=_is_interpolated(profile),
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
# Auth Details (CSV column) parsing
# ============================================================================


def _role_to_connector_field(
    role: str, profiles: list[ProfileSpec], by_xsoar: dict[str, str]
) -> str:
    """Resolve a canonical auth ROLE (metadata.auth.parameter) to the actual
    prefixed connector field id.

    Strategy: prefer a profile field whose ``metadata.auth.parameter == role``
    (the prefixed connector id). Fall back to the serializer (xsoar name -> field)
    and finally to the role itself.
    """
    for prof in profiles:
        for field_id, field_role in prof.auth_field_to_role.items():
            if field_role == role:
                return field_id
    if role in by_xsoar:
        return by_xsoar[role]
    return role


def _parse_auth_details(
    cell: str,
    profiles: list[ProfileSpec],
    by_xsoar: dict[str, str],
) -> tuple[list[AuthMappingSpec], list[str]]:
    """Parse the ``Auth Details`` CSV cell into auth mappings + other_connection.

    The cell is a JSON object ``{"auth_types": [...], "other_connection": [...]}``.
    Tolerates empty/missing/invalid → ``([], [])``. The ``interpolated`` key (if
    present on an ``auth_types[]`` entry) is IGNORED — interpolation is decided
    per profile.
    """
    cell = (cell or "").strip()
    if not cell:
        return [], []
    try:
        obj = json.loads(cell)
    except (ValueError, TypeError):
        log.debug("Auth Details cell is not valid JSON; ignoring.")
        return [], []
    if not isinstance(obj, dict):
        return [], []

    mappings: list[AuthMappingSpec] = []
    for entry in obj.get("auth_types") or []:
        if not isinstance(entry, dict):
            continue
        spec = AuthMappingSpec(
            name=str(entry.get("name") or ""),
            type=str(entry.get("type") or ""),
        )
        xsoar_param_map = entry.get("xsoar_param_map") or {}
        if isinstance(xsoar_param_map, dict):
            for xsoar_leaf, role in xsoar_param_map.items():
                if not xsoar_leaf or not role:
                    continue
                spec.xsoar_to_connector_field[xsoar_leaf] = _role_to_connector_field(
                    str(role), profiles, by_xsoar
                )
        mappings.append(spec)

    other_connection = [
        str(x) for x in (obj.get("other_connection") or []) if x
    ]
    return mappings, other_connection


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

    # Ordered, de-duped union of every profile id any subscribed capability uses.
    profile_ids: list[str] = []
    for cap in capabilities:
        for pid in cap.profile_ids:
            if pid not in profile_ids:
                profile_ids.append(pid)

    profiles = _profiles_from_connection(connection_doc, profile_ids)

    # Serializer maps (this handler).
    by_xsoar, by_connector = _load_serializer_maps(handler_dir)

    # ── Auth Details mapping (interpolation NOT here) ──
    auth_mappings, other_connection = _parse_auth_details(
        row.get("Auth Details") or "", profiles, by_xsoar
    )

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
        profiles=profiles,
        auth_mappings=auth_mappings,
        other_connection=other_connection,
        serializer_by_xsoar=by_xsoar,
        serializer_by_connector=by_connector,
    )

    # ── Param discovery: INTEGRATION YML → CONNECTOR ──
    yml_doc = _load_yaml(Path(_abs_integration_yml(integration_yml_path)))
    yml_params = [
        p.get("name")
        for p in ((yml_doc or {}).get("configuration") or [])
        if isinstance(p, dict) and p.get("name")
    ]

    # Non-profile connector fields: connection general + (UNION of all capability
    # config fields) + instance-level (capabilities.yaml general_configurations).
    connection_fields = set(_fields_from_general_configurations(connection_doc))
    instance_fields = set(_fields_from_general_configurations(capabilities_doc))
    capability_fields: set[str] = set()
    for cap in capabilities:
        capability_fields |= cap.config_field_ids
    non_profile_fields = connection_fields | capability_fields | instance_fields

    # Profile-field → owning ProfileSpec (for the per-profile interpolation gate).
    profile_field_owner: dict[str, ProfileSpec] = {}
    for prof in profiles:
        for fid in prof.field_ids:
            profile_field_owner.setdefault(fid, prof)

    # Auth-mapping leaves keyed by xsoar leaf → (connector field, owning profile).
    auth_leaf_to_field: dict[str, str] = {}
    for am in auth_mappings:
        auth_leaf_to_field.update(am.xsoar_to_connector_field)

    for param in yml_params:
        # 1) Hard ignore-list always wins.
        if param in HARD_IGNORE_PARAMS:
            inputs.ignored_params[param] = "hard_ignore_list"
            continue

        # 2) Resolve which connector field this integration param maps to.
        #    Auth Details mapping wins, then serializer, then identity.
        connector_field = (
            auth_leaf_to_field.get(param)
            or by_xsoar.get(param)
            or param
        )

        # 3) Is this a profile (auth) field? Gate on THAT profile's interpolation.
        owning_profile = (
            profile_field_owner.get(connector_field)
            or profile_field_owner.get(param)
        )
        if owning_profile is not None:
            if owning_profile.interpolated:
                inputs.param_to_connector_field[param] = connector_field
                inputs.compare_params.add(param)
            else:
                inputs.ignored_params[param] = "profile_not_interpolated"
            continue

        # 4) Non-profile connector field → compare if the connector declares it.
        if connector_field in non_profile_fields:
            inputs.param_to_connector_field[param] = connector_field
            inputs.compare_params.add(param)
        else:
            # Param exists in the integration YML but the connector doesn't
            # declare a matching field. Still compare it — it should surface as
            # MISSING_IN_CONNECTOR (a real bug) rather than be silently dropped.
            inputs.compare_params.add(param)

    log.info(
        "Resolved %s: connector=%s capabilities=%s profiles=%s "
        "(%d compare, %d ignored)",
        integration_id,
        connector_dir.name,
        [
            (cap.id, [sc.id for sc in cap.sub_capabilities])
            for cap in capabilities
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
