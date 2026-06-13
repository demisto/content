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
    capabilities: list[CapabilitySpec] = field(default_factory=list)
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

    # Ordered, de-duped union of every profile id any subscribed capability uses.
    profile_ids: list[str] = []
    for cap in capabilities:
        for pid in cap.profile_ids:
            if pid not in profile_ids:
                profile_ids.append(pid)

    profiles = _profiles_from_connection(connection_doc, profile_ids)

    # Serializer maps (this handler).
    by_xsoar, by_connector = _load_serializer_maps(handler_dir)

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
        serializer_by_xsoar=by_xsoar,
        serializer_by_connector=by_connector,
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
