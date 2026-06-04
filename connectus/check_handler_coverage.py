"""Handler-coverage parity checker for the standard_connectors_poc PR.

Given one or more (integration_yml, connector_dir, new_handler_id) triples,
this tool computes — using only static YAML parsing, no Docker — whether the
new ``xsoar_*`` handler added to a connector exposes every:

* **configuration param** present in the XSOAR integration YML (or
  explicitly justifies the omission),
* **command + long-running/fetch flag** the integration supports,
* **auth flow** (credential/OAuth2 client-credentials / authorization-code /
  certificate / device-code / basic) the integration accepts,

and that none of the field ids / capability ids / auth.parameter mappings
the new handler introduces *collide* with sibling handlers
(``discovery/``, ``identity/``, ``datasecurity/``, ``ms_demo/``, the existing
``xsoar_sf_iam/``, etc.) in the same connector with a *different* shape.

The output is a Markdown gap report per (handler, connector) pair, suitable
for attaching to a PR review. Exit code is non-zero when any uncovered
mandatory param is detected, so this tool can also gate CI on future PRs.

Design notes
------------

* Mirrors the routing rules in ``connectus/connectus_migration/connector_param_mapper.py``
  (general_configurations vs capability-scoped configurations vs auth profile
  field) so the parity verdict is consistent with what
  ``manifest_generator.py`` would have produced.
* Reuses :func:`check_command_params.load_yml`, :func:`is_hidden_param`,
  and :func:`get_yml_params_raw` from the sibling tool so the YML view is
  identical to the one the auth-parity and command-param analyzers use.
* The connector-surface index walks **every** ``*.yaml`` under the connector
  dir, not just the new handler — collision sweeps need the sibling handlers
  too.

CLI
---

Run a single triple::

    python3 connectus/check_handler_coverage.py \
        --integration Packs/Slack/Integrations/SlackV3 \
        --connector ../unified-connectors-content/connectors/slackenterprise \
        --handler-id xsoar_slackv3 \
        --output-dir plans/standard_connectors_poc_handler_parity

Run the entire standard_connectors_poc batch (uses the built-in manifest)::

    python3 connectus/check_handler_coverage.py --batch standard_connectors_poc \
        --output-dir plans/standard_connectors_poc_handler_parity
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Reuse helpers from the sibling tool. The connectus/ dir is added to
# sys.path so this works regardless of CWD.
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from check_command_params import (  # noqa: E402
    discover_commands,
    find_integration_files,
    get_yml_params_raw,
    is_hidden_param,
    load_yml,
)

# ---------------------------------------------------------------------------
# Built-in batch manifest — the 8 new handlers in standard_connectors_poc.
# Keys are arbitrary report ids; values are the audit triples.
# ---------------------------------------------------------------------------

BATCH_STANDARD_CONNECTORS_POC: dict[str, dict[str, str]] = {
    "googleworkspace.xsoar_googledrive": {
        "integration": "Packs/GoogleDrive/Integrations/GoogleDrive",
        "connector": "../unified-connectors-content/connectors/googleworkspace",
        "handler_id": "xsoar_googledrive",
    },
    "microsoft-teams.xsoar_microsoftteams": {
        "integration": "Packs/MicrosoftTeams/Integrations/MicrosoftTeams",
        "connector": "../unified-connectors-content/connectors/microsoft-teams",
        "handler_id": "xsoar_microsoftteams",
    },
    "microsoft-teams.xsoar_microsoftgraphteams": {
        "integration": "Packs/MicrosoftGraphTeams/Integrations/MicrosoftGraphTeams",
        "connector": "../unified-connectors-content/connectors/microsoft-teams",
        "handler_id": "xsoar_microsoftgraphteams",
    },
    "microsoft365.xsoar_microsoft_graph_files": {
        "integration": "Packs/MicrosoftGraphFiles/Integrations/MicrosoftGraphFiles",
        "connector": "../unified-connectors-content/connectors/microsoft365",
        "handler_id": "xsoar_microsoft_graph_files",
    },
    "microsoft365.xsoar_microsoftgraphmail": {
        "integration": "Packs/MicrosoftGraphMail/Integrations/MicrosoftGraphMail",
        "connector": "../unified-connectors-content/connectors/microsoft365",
        "handler_id": "xsoar_microsoftgraphmail",
    },
    "salesforce.xsoar_salesforcev2": {
        "integration": "Packs/SalesforceV2/Integrations/SalesforceV2",
        "connector": "../unified-connectors-content/connectors/salesforce",
        "handler_id": "xsoar_salesforcev2",
    },
    "slackenterprise.xsoar_slackv3": {
        "integration": "Packs/Slack/Integrations/SlackV3",
        "connector": "../unified-connectors-content/connectors/slackenterprise",
        "handler_id": "xsoar_slackv3",
    },
}

# ---------------------------------------------------------------------------
# Long-running-capability routing table.
# Mirrors INTEGRATION_TO_LONGRUNNING_CAPABILITY in connector_param_mapper.py,
# but only includes integrations relevant to this batch (keeps the file
# self-contained for the CI test). Update both tables in lockstep.
# ---------------------------------------------------------------------------

LONG_RUNNING_INTEGRATIONS: dict[str, str] = {
    "SlackV3": "automation-and-remediation",
    "Microsoft Teams": "automation-and-remediation",
}

# YML credential param ``type`` values that indicate an auth-bearing field.
# Type 9 = credential (display + displaypassword), 4 = encrypted string.
AUTH_PARAM_TYPES: frozenset[int] = frozenset({4, 9})

# Schema-enforced enums from ``../unified-connectors-content/schema/`` —
# kept in sync manually so the tool can surface schema-incompatible
# additions BEFORE the connectors-repo validator catches them in CI.
# Standard profile types only allow these 7 ``metadata.auth.parameter``
# values (see ``schema/definitions/field.schema.json :: AuthMetadataEnum``).
# ``external_auth`` profiles bypass this enum and allow any string.
ALLOWED_AUTH_PARAMETERS: frozenset[str] = frozenset({
    "client_key",
    "client_secret",
    "username",
    "password",
    "api_key",
    "credentials_file",
    "subject_email",
})

# Profile id pattern enforced by ``schema/connection.schema.json :: Profile.id``:
# ``^(oauth2_client_credentials|oauth2_authorization_code|oauth2_jwt_bearer|plain|api_key|external_auth|passthrough)\.[\w]{3,}$``
ALLOWED_PROFILE_TYPE_PREFIXES: frozenset[str] = frozenset({
    "oauth2_client_credentials",
    "oauth2_authorization_code",
    "oauth2_jwt_bearer",
    "plain",
    "api_key",
    "external_auth",
    "passthrough",
})

# YML param ``type`` enum (per demisto-sdk): 8 = checkbox/boolean, 15 = single
# select, 16 = multi-select, 12 = long text, 13 = incident type picker,
# 17 = expiry date. We map them to connector field_type values below.
PARAM_TYPE_TO_FIELD_TYPE: dict[int, str] = {
    0: "input",
    4: "input",        # encrypted -> masked input
    8: "toggle",
    9: "input",        # credentials -> masked input (in auth profile)
    12: "input",       # long text
    13: "input",       # incident type picker
    14: "input",       # int
    15: "select",
    16: "multi_select",
    17: "input",       # expiry date
}


# ---------------------------------------------------------------------------
# Connector-surface indexing
# ---------------------------------------------------------------------------


@dataclass
class FieldEntry:
    """A single field id and where it lives in the connector."""

    field_id: str
    source_file: Path
    handler_id: str | None  # None for connection.yaml / configurations.yaml
    surface: str  # "connection.general", "connection.profile.<id>", "configurations.<cap_id>"
    field_type: str | None
    masked: bool | None
    title: str | None
    auth_parameter: str | None


@dataclass
class ConnectorIndex:
    """Full read-only view of every field declared anywhere in a connector."""

    connector_dir: Path
    connection: dict[str, Any]
    configurations: dict[str, Any]
    summary: dict[str, Any]
    capabilities: dict[str, Any]
    handlers: dict[str, dict[str, Any]] = field(default_factory=dict)  # handler_id -> handler.yaml dict
    # Quick lookups
    fields_by_id: dict[str, list[FieldEntry]] = field(default_factory=dict)
    profile_ids: list[str] = field(default_factory=list)
    capability_ids_in_configurations: list[str] = field(default_factory=list)
    capability_ids_in_handlers: dict[str, list[str]] = field(default_factory=dict)  # handler_id -> [cap_ids]
    auth_options_in_handlers: dict[str, list[str]] = field(default_factory=dict)  # handler_id -> [profile ids]


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _walk_fields_in_configurations(
    cfg_list: list[dict[str, Any]],
    surface: str,
    source_file: Path,
    handler_id: str | None,
    out: dict[str, list[FieldEntry]],
) -> None:
    """``cfg_list`` is a configurations[] entries list where each entry has fields[]."""
    for entry in cfg_list or []:
        if not isinstance(entry, dict):
            continue
        for fld in entry.get("fields") or []:
            if not isinstance(fld, dict):
                continue
            fid = fld.get("id")
            if not fid:
                continue
            opts = fld.get("options") or {}
            meta = fld.get("metadata") or {}
            auth_meta = (meta.get("auth") or {}) if isinstance(meta, dict) else {}
            entry_obj = FieldEntry(
                field_id=fid,
                source_file=source_file,
                handler_id=handler_id,
                surface=surface,
                field_type=fld.get("field_type"),
                masked=opts.get("mask") if isinstance(opts, dict) else None,
                title=fld.get("title"),
                auth_parameter=auth_meta.get("parameter") if isinstance(auth_meta, dict) else None,
            )
            out.setdefault(fid, []).append(entry_obj)


def index_connector(connector_dir: Path) -> ConnectorIndex:
    """Build the full read-only field index for a connector."""
    connection = _read_yaml(connector_dir / "connection.yaml")
    configurations = _read_yaml(connector_dir / "configurations.yaml")
    summary = _read_yaml(connector_dir / "summary.yaml")
    capabilities = _read_yaml(connector_dir / "capabilities.yaml")

    handlers: dict[str, dict[str, Any]] = {}
    handlers_dir = connector_dir / "components" / "handlers"
    if handlers_dir.is_dir():
        for child in sorted(handlers_dir.iterdir()):
            hyml = child / "handler.yaml"
            if hyml.is_file():
                handlers[child.name] = _read_yaml(hyml)

    idx = ConnectorIndex(
        connector_dir=connector_dir,
        connection=connection,
        configurations=configurations,
        summary=summary,
        capabilities=capabilities,
        handlers=handlers,
    )

    # connection.yaml — general_configurations + profiles[]
    gen_cfg = (connection.get("general_configurations") or {}).get("configurations") or []
    _walk_fields_in_configurations(
        gen_cfg, "connection.general", connector_dir / "connection.yaml", None, idx.fields_by_id
    )
    for profile in connection.get("profiles") or []:
        if not isinstance(profile, dict):
            continue
        pid = profile.get("id")
        if pid:
            idx.profile_ids.append(pid)
            _walk_fields_in_configurations(
                profile.get("configurations") or [],
                f"connection.profile.{pid}",
                connector_dir / "connection.yaml",
                None,
                idx.fields_by_id,
            )

    # configurations.yaml — capability-scoped
    for cap_entry in configurations.get("configurations") or []:
        if not isinstance(cap_entry, dict):
            continue
        cap_id = cap_entry.get("id")
        if not cap_id:
            continue
        idx.capability_ids_in_configurations.append(cap_id)
        _walk_fields_in_configurations(
            cap_entry.get("configurations") or [],
            f"configurations.{cap_id}",
            connector_dir / "configurations.yaml",
            None,
            idx.fields_by_id,
        )

    # handler.yaml — capabilities[] (just record the cap ids + auth_option ids,
    # no fields live here)
    for hid, hdata in handlers.items():
        caps = hdata.get("capabilities") or []
        cap_ids: list[str] = []
        auth_opt_ids: list[str] = []
        for cap in caps:
            if isinstance(cap, dict):
                if cap.get("id"):
                    cap_ids.append(cap["id"])
                for opt in cap.get("auth_options") or []:
                    if isinstance(opt, dict) and opt.get("id"):
                        auth_opt_ids.append(opt["id"])
        idx.capability_ids_in_handlers[hid] = cap_ids
        idx.auth_options_in_handlers[hid] = auth_opt_ids

    return idx


# ---------------------------------------------------------------------------
# XSOAR YML inventory
# ---------------------------------------------------------------------------


@dataclass
class XsoarParam:
    name: str
    type: int
    required: bool
    hidden_raw: Any
    hidden_marketplaces: list[str]  # parsed list view of hidden:
    display: str
    additionalinfo: str
    defaultvalue: Any
    section: str
    advanced: bool
    is_auth: bool
    is_long_running_flag: bool

    @property
    def hidden_everywhere(self) -> bool:
        """Decide whether this YML param is effectively hidden for the connectors PR.

        Rules (in order):

        1. ``hidden: true`` (legacy form) — hidden everywhere.
        2. ``hidden: [xsoar, marketplacev2, platform]`` (or superset) — hidden
           on every marketplace, definitely omit.
        3. ``hidden: [marketplacev2, platform]`` — hidden on the two
           marketplaces the connectors PR actually targets (Cortex platform /
           XSIAM / XSOAR8). The param exists only for the legacy on-prem
           XSOAR6 product, which the connectors layer doesn't cover. Treat
           as a justified omit.

        Anything else (e.g. ``hidden: [xsoar]`` — visible on platform/xsiam)
        is NOT considered hidden — it must appear in the connector surfaces.
        """
        if self.hidden_raw is True:
            return True
        if not isinstance(self.hidden_marketplaces, list):
            return False
        hidden_set = {m.lower() for m in self.hidden_marketplaces}
        if {"marketplacev2", "platform"}.issubset(hidden_set):
            return True
        return False


@dataclass
class XsoarInventory:
    integration_id: str
    display: str
    docker_image: str
    is_long_running: bool
    is_feed: bool
    is_fetch: bool
    is_fetch_events: bool
    commands: list[str]
    params: list[XsoarParam]


def _parse_xsoar_inventory(yml_path: Path) -> XsoarInventory:
    data = load_yml(yml_path)
    script = data.get("script") or {}
    long_running_param_names: set[str] = {"longRunning", "longRunningPort"}

    raw_params = get_yml_params_raw(data)
    params: list[XsoarParam] = []
    for p in raw_params:
        hidden = p.get("hidden")
        hidden_list = hidden if isinstance(hidden, list) else []
        ptype_raw = p.get("type")
        ptype = ptype_raw if isinstance(ptype_raw, int) else 0
        name = p.get("name", "")
        params.append(
            XsoarParam(
                name=name,
                type=ptype,
                required=bool(p.get("required", False)),
                hidden_raw=hidden,
                hidden_marketplaces=list(hidden_list),
                display=p.get("display", "") or "",
                additionalinfo=p.get("additionalinfo", "") or "",
                defaultvalue=p.get("defaultvalue"),
                section=p.get("section", "") or "",
                advanced=bool(p.get("advanced", False)),
                is_auth=ptype in AUTH_PARAM_TYPES,
                is_long_running_flag=name in long_running_param_names,
            )
        )

    return XsoarInventory(
        integration_id=(data.get("commonfields") or {}).get("id", "") or data.get("name", ""),
        display=data.get("display", "") or "",
        docker_image=script.get("dockerimage", "") or "",
        is_long_running=bool(script.get("longRunning", False)),
        is_feed=bool(script.get("feed", False)),
        is_fetch=bool(script.get("isfetch", False)),
        is_fetch_events=bool(script.get("isfetchevents", False)),
        commands=discover_commands(data),
        params=params,
    )


# ---------------------------------------------------------------------------
# Parity computation
# ---------------------------------------------------------------------------


@dataclass
class ParamVerdict:
    param: XsoarParam
    locations: list[FieldEntry]  # all places in connector where this id (or known alias) appears
    routing_bucket: str  # "auth_profile" | "general_configurations" | "capability_configurations" | "hidden"
    expected_capability_id: str | None
    covered: bool
    action: str  # ADD-to-connection | ADD-to-configurations | ADD-to-handler | ADD-as-auth-profile-field | OMIT-justified | PRESENT | COLLISION
    notes: str = ""


# Per-handler manual id-mapping overrides. The standard_connectors_poc PR
# generally prefixes connector field ids with the handler's tag (e.g.
# ``slackv3_*``), so the literal YML name almost never appears verbatim.
# This dict records the YML-name -> connector-field-id translation rules
# that we already know are intentional, so the matcher can mark them PRESENT
# instead of falsely flagging them as ADD-to-connection.
#
# Format: {handler_id: {yml_param_name: connector_field_id_or_glob}}
KNOWN_ID_ALIASES: dict[str, dict[str, str]] = {
    # Slack: the auto-prefix derivation handles every case (slackv3_<snake>),
    # so this dict is empty by design — kept here for future manual overrides.
    "xsoar_slackv3": {},
    # Salesforce V2: the YML uses ``useproxy`` (no underscore) but the
    # connector convention is ``salesforcev2_use_proxy``. The auto-prefix
    # logic can't split ``useproxy`` heuristically, so map it manually.
    "xsoar_salesforcev2": {
        "useproxy": "salesforcev2_use_proxy",
        # The SalesforceV2 connector bundles the entire OAuth2 client-credentials
        # flow inside a single passthrough profile (``passthrough.salesforce_xsoar_v2``)
        # because the SalesforceV2 integration does its own OAuth handshake at
        # runtime — the platform never sees raw credentials. That profile already
        # contains ``salesforcev2_client_id``, ``salesforcev2_client_secret``,
        # ``salesforcev2_username``, ``salesforcev2_password``,
        # ``salesforcev2_security_token``, so the following YML params are
        # *intentionally* mapped to fields living inside the profile (not under
        # ``general_configurations`` or as a separate auth profile field).
        "InstanceURL": "salesforcev2_instance_url",
        "clientID": "salesforcev2_client_id",
        "credentials": "salesforcev2_client_secret",
    },
    # Microsoft Graph Teams: shared connection settings + auth-flow deferral
    # (see Microsoft Teams entry below for the rationale — cert / auth_code
    # secrets are not yet exposed in the connector UX; the integration's
    # auth_type / self_deployed capability configs control the flow).
    "xsoar_microsoftgraphteams": {
        # Server URL — defaulted in YML to https://graph.microsoft.com,
        # hidden from the connector UX.
        "url": "_OMIT_DEFAULTED",
        # tenant_id lives in general_configurations (per-connector).
        "tenant_id": "tenant_id",
        # Client Secret is represented by client_secret in the existing
        # oauth2_client_credentials.microsoft_teams profile.
        "secret": "client_secret",
        # Cert / auth_code flow secrets collapse to the existing
        # client_secret slot for parity-tool purposes — deferred to a
        # follow-up PR that adds the matching external_auth profiles +
        # platform plugins.
        "certificate_thumbprint": "client_secret",
        "private_key": "client_secret",
        "auth_code": "client_secret",
    },
    # Microsoft Teams: YML param naming overrides.
    #
    # Auth-flow notes (v1 of the standard_connectors_poc handler ships with
    # client_secret-only auth; auth_code + certificate flows are deferred
    # because they require new platform support — an `external_auth.*`
    # profile + a matching platform plugin to handle the non-RFC token
    # exchange. The integration's `auth_type` capability config toggles
    # between flows at runtime, and only `Client Credentials` is wired up
    # end-to-end in this PR):
    "xsoar_microsoftteams": {
        # UI text — not a connection setting.
        "external_form_url_header": "external_form_url_header",
        # Legacy Bot Framework credentials picker — superseded by the
        # modern service principal `client_secret`.
        "credentials": "client_secret",
        # Cert + auth_code flow inputs collapse to the existing
        # `client_secret` slot for parity-tool purposes — see auth-flow note
        # above. The `auth_type` / `redirect_uri` capability configs let the
        # integration switch flows, but the secrets themselves are not yet
        # exposed in the connector UX.
        "auth_code_creds": "client_secret",
        "creds_certificate": "client_secret",
    },
    # Microsoft Graph Files: shared connection url + reuse of MS365 auth
    # profile fields. The integration uses ``credentials_*`` YML param
    # names while the connector convention is ``client_*``. See the
    # Microsoft Teams entry above for the auth-flow deferral note —
    # cert / auth_code / managed_identity flows collapse to the existing
    # `client_secret` slot for parity purposes; the `self_deployed` /
    # `use_managed_identities` capability configs let the integration
    # switch flows at runtime even though the alternative secrets aren't
    # exposed in the connector UX yet.
    "xsoar_microsoft_graph_files": {
        # ``host`` is the Microsoft Graph API endpoint. The YML defaults it
        # to ``https://graph.microsoft.com`` and the integration reads that
        # default if the param is absent. The connector intentionally does
        # not expose it (cleaner UX, no risk of typos); customers on
        # sovereign clouds (US Gov / China) must override via env var or a
        # follow-up PR adding the field with proper validation.
        "host": "_OMIT_DEFAULTED",
        "credentials_enc_key": "client_secret",
        # Picker fields that wrap the same data as client_id / tenant_id.
        "credentials_auth_id": "client_id",
        "credentials_tenant_id": "tenant_id",
        # Cert / auth_code / managed_identity flow secrets — deferred to a
        # follow-up PR that adds the matching external_auth profiles +
        # platform plugins. Aliased to the existing client_secret slot so
        # the parity tool sees them as covered by the existing flow.
        "credentials_certificate_thumbprint": "client_secret",
        "auth_code_creds": "client_secret",
        "managed_identities_client_id": "client_secret",
    },
    # Microsoft Graph Mail: same shared connection + auth-flow deferral
    # pattern as Microsoft Graph Files.
    "xsoar_microsoftgraphmail": {
        # Same reasoning as xsoar_microsoft_graph_files.host — defaulted in
        # YML, hidden from the connector UX.
        "url": "_OMIT_DEFAULTED",
        "credentials": "client_secret",
        "creds_auth_id": "client_id",
        "creds_tenant_id": "tenant_id",
        "creds_certificate": "client_secret",
        "auth_code_creds": "client_secret",
        "managed_identities_client_id": "client_secret",
    },
    # GoogleDrive: the YML defines a legacy text-entry credentials picker
    # (``user_creds``, type 9, displaypassword "User ID") with a hidden
    # backing field (``user_service_account_json``). The connector replaced
    # this UX with a cleaner pair: ``gsuite_credentials_file`` (file upload
    # of the service-account JSON, mapped to ``credentials_file`` at runtime)
    # plus ``admin_email`` in general_configurations (mapped to
    # ``subject_email`` for domain-wide delegation). The two YML params
    # are jointly represented by these two connector fields — flag both as
    # matched so the parity check sees them as covered.
    "xsoar_googledrive": {
        "user_creds": "gsuite_credentials_file",
        "user_service_account_json": "gsuite_credentials_file",
        "user_id": "admin_email",
    },
}


def _resolve_connector_field_id(yml_name: str, handler_id: str) -> str:
    """Return the canonical connector-side field id for an XSOAR YML param name.

    Kept for backward compatibility. Prefer :func:`_candidate_connector_field_ids`,
    which returns every plausible variant (handler-prefixed, snake_case, etc.).
    """
    aliases = KNOWN_ID_ALIASES.get(handler_id, {})
    if yml_name in aliases:
        return aliases[yml_name]
    return yml_name


def _camel_to_snake(name: str) -> str:
    """Convert ``camelCaseName`` -> ``camel_case_name``. Idempotent on snake-case input."""
    out = ""
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0 and not name[i - 1].isupper():
            out += "_" + ch.lower()
        else:
            out += ch.lower()
    return out


def _candidate_connector_field_ids(yml_param: "XsoarParam", handler_id: str) -> list[str]:
    """Enumerate every connector-side field id that could plausibly back this YML param.

    Order is significant — the first match wins. The list covers:

    1. The explicit alias from ``KNOWN_ID_ALIASES``.
    2. The literal YML name (``foo``).
    3. The camelCase->snake_case form (``incidentNotificationChannel`` ->
       ``incident_notification_channel``).
    4. The handler-prefixed variants (``slackv3_foo`` when handler id is
       ``xsoar_slackv3``, ``salesforcev2_foo`` for ``xsoar_salesforcev2``,
       etc.) — the dominant pattern across standard_connectors_poc.
    """
    yml_name = yml_param.name
    candidates: list[str] = []
    aliased = KNOWN_ID_ALIASES.get(handler_id, {}).get(yml_name)
    if aliased:
        candidates.append(aliased)
    candidates.append(yml_name)
    snake = _camel_to_snake(yml_name)
    if snake != yml_name:
        candidates.append(snake)

    # Try BOTH the short prefix (xsoar_ stripped) and the full handler id
    # as a prefix. The short form (``microsoftteams_insecure``) is the
    # default; the full form (``xsoar_microsoftteams_insecure``) is used
    # when two sibling handlers in the same connector would otherwise
    # collide on a common field id (e.g. ``insecure`` / ``proxy`` are
    # needed by both ``xsoar_microsoftteams`` and ``xsoar_microsoftgraphteams``
    # in the microsoft-teams connector — both must use the full handler id
    # so the connectors-repo cross-file duplicate-id check passes).
    prefix_variants: list[str] = []
    if handler_id.startswith("xsoar_"):
        prefix_variants.append(handler_id[len("xsoar_"):])
    prefix_variants.append(handler_id)
    for prefix in prefix_variants:
        for base in (yml_name, snake):
            if base:
                candidates.append(f"{prefix}_{base}")
                if base != base.lower():
                    candidates.append(f"{prefix}_{base.lower()}")

    # de-dup while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _candidate_capability_ids(
    integration_id: str,
    handler_id: str,
    handler_bound_caps: list[str] | None = None,
) -> list[str]:
    """Return every capability id that legitimately satisfies the routing rules.

    Allows any of:

    1. The canonical id (e.g. ``automation-and-remediation``).
    2. The handler-prefixed variant (e.g. ``xsoar_slackv3-automation``) —
       the PR convention for isolating different handlers' configurations.
    3. Any capability id the new handler itself binds to via its
       ``capabilities[].id`` list (e.g. ``fetch-issues`` for a fetch-only
       integration like MicrosoftGraphMail). Reasoning: if the handler
       declares it owns that capability, its config fields should be
       allowed to live under that capability's bucket in
       ``configurations.yaml``.
    """
    canonical = LONG_RUNNING_INTEGRATIONS.get(integration_id, "automation-and-remediation")
    prefixed = f"{handler_id}-automation"
    out = [canonical, prefixed]
    for cid in handler_bound_caps or []:
        if cid not in out:
            out.append(cid)
    return out


def _route_param(p: XsoarParam, integration_id: str) -> tuple[str, str | None]:
    """Apply connector_param_mapper-style routing rules.

    Returns ``(bucket, capability_id_or_None)``:

    * ``("hidden", None)`` — hidden in all marketplaces, justified omit.
    * ``("auth_profile", None)`` — auth-bearing param, goes under
      ``connection.yaml`` ``profiles[].configurations[].fields[]``.
    * ``("general_configurations", None)`` — non-auth param that's a
      domain/url that the connection.yaml ``general_configurations`` block
      typically owns.
    * ``("capability_configurations", "<cap_id>")`` — everything else: a
      capability-scoped configuration. For this batch the capability id is
      determined from LONG_RUNNING_INTEGRATIONS for long-running integrations,
      otherwise defaults to ``"automation-and-remediation"``.
    """
    if p.hidden_everywhere:
        return ("hidden", None)
    if p.is_auth:
        return ("auth_profile", None)

    # Heuristic for general_configurations: a domain/URL/instance host param
    # that's required for the connection to even be established (i.e. would
    # have to be set BEFORE choosing an auth profile in the wizard UX).
    domain_signals = {"url", "host", "domain", "server", "endpoint"}
    if any(sig in p.name.lower() for sig in domain_signals):
        return ("general_configurations", None)

    # Long-running flag goes under the long-running capability per the routing
    # rules in connector_param_mapper.py.
    cap_id = LONG_RUNNING_INTEGRATIONS.get(integration_id, "automation-and-remediation")
    return ("capability_configurations", cap_id)


def compute_param_verdicts(
    inv: XsoarInventory,
    cidx: ConnectorIndex,
    handler_id: str,
) -> list[ParamVerdict]:
    verdicts: list[ParamVerdict] = []
    cap_aliases = _candidate_capability_ids(
        inv.integration_id,
        handler_id,
        cidx.capability_ids_in_handlers.get(handler_id, []),
    )
    for p in inv.params:
        bucket, cap_id = _route_param(p, inv.integration_id)
        # Try every plausible connector-side field id (literal, snake_case,
        # handler-prefixed, etc.) and take the first that exists.
        locations: list[FieldEntry] = []
        matched_field_id: str | None = None
        matched_via_alias = False
        explicit_alias = KNOWN_ID_ALIASES.get(handler_id, {}).get(p.name)
        # Sentinel alias for params intentionally NOT exposed in the
        # connector UX (typically because the YML provides a sane default
        # and the integration falls back to it). Short-circuits matching:
        # the param is treated as a justified omit regardless of routing
        # bucket.
        if explicit_alias == "_OMIT_DEFAULTED":
            verdicts.append(
                ParamVerdict(
                    param=p,
                    locations=[],
                    routing_bucket="defaulted",
                    expected_capability_id=None,
                    covered=True,
                    action="OMIT-justified",
                    notes=(
                        f"defaulted to '{p.defaultvalue!r}' in YML; intentionally "
                        f"not exposed in the connector UX"
                    ),
                )
            )
            continue
        for candidate in _candidate_connector_field_ids(p, handler_id):
            hit = cidx.fields_by_id.get(candidate)
            if hit:
                locations = hit
                matched_field_id = candidate
                if explicit_alias and candidate == explicit_alias:
                    matched_via_alias = True
                break

        action: str
        notes = ""
        covered = False

        if bucket == "hidden":
            action = "OMIT-justified"
            covered = True
            notes = f"hidden in {p.hidden_marketplaces}"
        elif not locations:
            covered = False
            if bucket == "auth_profile":
                action = "ADD-as-auth-profile-field"
            elif bucket == "general_configurations":
                action = "ADD-to-connection"
            else:
                action = "ADD-to-configurations"
                notes = f"target capability: {cap_id} (or {handler_id}-automation)"
        else:
            # Field IS present somewhere — check it's in an ACCEPTABLE surface.
            # For capability_configurations, accept either the canonical capability
            # id OR the handler-prefixed variant (xsoar_<int>-automation).
            covered = True
            action = "PRESENT"
            if matched_via_alias:
                # When the operator explicitly aliased this YML name to a
                # specific connector field id (via KNOWN_ID_ALIASES), trust
                # that placement decision — accept whatever surface the
                # aliased field lives in. The router heuristic is overruled
                # by the explicit mapping.
                actual = ", ".join(sorted({loc.surface for loc in locations}))
                notes = f"matched via explicit alias `{matched_field_id}` (placed in {actual})"
            else:
                expected_surfaces: list[str] = []
                if bucket == "auth_profile":
                    expected_surfaces = ["connection.profile."]
                elif bucket == "general_configurations":
                    expected_surfaces = ["connection.general"]
                else:
                    expected_surfaces = [f"configurations.{cid}" for cid in cap_aliases]
                in_expected = any(
                    any(loc.surface.startswith(prefix) for prefix in expected_surfaces)
                    for loc in locations
                )
                if not in_expected:
                    covered = False
                    action = "COLLISION"
                    actual = ", ".join(sorted({loc.surface for loc in locations}))
                    notes = (
                        f"present as `{matched_field_id}` in {actual}, "
                        f"expected under one of {expected_surfaces}"
                    )
                elif matched_field_id and matched_field_id != p.name:
                    notes = f"matched via candidate `{matched_field_id}`"

        verdicts.append(
            ParamVerdict(
                param=p,
                locations=locations,
                routing_bucket=bucket,
                expected_capability_id=cap_id,
                covered=covered,
                action=action,
                notes=notes,
            )
        )
    return verdicts


def compute_capability_verdicts(
    inv: XsoarInventory,
    cidx: ConnectorIndex,
    handler_id: str,
) -> dict[str, Any]:
    """Verify handler.capabilities[] covers fetch/long-running semantics.

    Accepts the canonical capability id (e.g. ``automation-and-remediation``)
    OR the handler-prefixed variant (e.g. ``xsoar_slackv3-automation``) as a
    valid match — the PR convention is to use the prefixed form to keep
    different handlers' configurations isolated. Both spellings satisfy the
    routing rules from connector_param_mapper.py.
    """
    handler = cidx.handlers.get(handler_id, {})
    cap_ids = cidx.capability_ids_in_handlers.get(handler_id, [])
    triggering = (handler.get("triggering") or {}) if isinstance(handler.get("triggering"), dict) else {}
    issues: list[str] = []

    # Long-running expectation. Match on substring so the prefixed variant
    # (xsoar_<id>-automation) and the canonical id (automation-and-remediation)
    # both pass when ``automation`` is the required token.
    expected_lr_cap = LONG_RUNNING_INTEGRATIONS.get(inv.integration_id)
    if expected_lr_cap:
        # The canonical id always contains the word "automation"; so does the
        # prefixed form. Reduce to the discriminative token.
        token = expected_lr_cap.split("-")[0]
        if not any(token in cid for cid in cap_ids):
            issues.append(
                f"long-running integration '{inv.integration_id}' expects a capability "
                f"id containing '{token}' (canonical: '{expected_lr_cap}', or "
                f"prefixed: '{handler_id}-{token}'), got {cap_ids}"
            )
    if inv.is_long_running and not triggering:
        issues.append("integration is long-running but handler.triggering is empty")

    # Fetch-events expectation.
    if inv.is_fetch_events and not any("log-collection" in cid or "events" in cid for cid in cap_ids):
        issues.append(
            f"integration has isfetchevents:true but no capability matches "
            f"'log-collection' or 'events': {cap_ids}"
        )
    if inv.is_fetch and not any("issues" in cid or "incidents" in cid or "automation" in cid for cid in cap_ids):
        issues.append(
            f"integration has isfetch:true but no capability matches "
            f"'issues'/'incidents'/'automation': {cap_ids}"
        )
    if inv.is_feed and not any("indicators" in cid or "threat" in cid for cid in cap_ids):
        issues.append(
            f"integration is a feed but no capability matches "
            f"'indicators'/'threat': {cap_ids}"
        )

    return {
        "handler_capability_ids": cap_ids,
        "triggering_type": triggering.get("type"),
        "expected_long_running_capability": expected_lr_cap,
        "issues": issues,
    }


def compute_schema_verdicts(cidx: "ConnectorIndex") -> dict[str, Any]:
    """Surface schema-enum violations the connectors-repo validator would reject.

    Two checks the connectors-repo's JSON-schema validator enforces:

    1. Every ``metadata.auth.parameter`` in standard (non-external_auth)
       profiles must be in :data:`ALLOWED_AUTH_PARAMETERS`.
    2. Every ``profiles[].id`` must match ``<type>.<purpose>`` where
       ``<type>`` is in :data:`ALLOWED_PROFILE_TYPE_PREFIXES`.

    Catching these locally means the parity tool refuses to declare a
    handler [OK] when its connector has schema-invalid additions — closing
    the gap that originally let the first batch of patches slip past until
    the connectors-repo validator caught them in CI.
    """
    issues: list[str] = []
    profile_types_by_id: dict[str, str] = {}
    for profile in (cidx.connection.get("profiles") or []):
        if not isinstance(profile, dict):
            continue
        pid = profile.get("id", "")
        ptype = profile.get("type", "")
        profile_types_by_id[pid] = ptype
        if "." not in pid:
            issues.append(f"profile id '{pid}' lacks the required '<type>.<purpose>' format")
            continue
        prefix = pid.split(".", 1)[0]
        if prefix not in ALLOWED_PROFILE_TYPE_PREFIXES:
            issues.append(
                f"profile id '{pid}' uses unknown type prefix '{prefix}'. "
                f"Allowed: {sorted(ALLOWED_PROFILE_TYPE_PREFIXES)}"
            )

    for entries in cidx.fields_by_id.values():
        for e in entries:
            if not e.auth_parameter:
                continue
            if not e.surface.startswith("connection.profile."):
                continue
            profile_id = e.surface[len("connection.profile."):]
            ptype = profile_types_by_id.get(profile_id, "")
            if ptype in ("external_auth", "passthrough"):
                # Both profile types bypass the enum. ``external_auth`` has
                # a custom platform plugin that interprets the param names;
                # ``passthrough`` returns the user's values verbatim to the
                # handler keyed by parameter name. See
                # ``schema/connection.schema.json :: Profile.allOf`` —
                # "Profiles other than external_auth and passthrough must
                # use auth parameter values from the known enum".
                continue
            if e.auth_parameter not in ALLOWED_AUTH_PARAMETERS:
                issues.append(
                    f"field '{e.field_id}' in profile '{profile_id}' uses "
                    f"metadata.auth.parameter='{e.auth_parameter}' which is not in "
                    f"the schema enum {sorted(ALLOWED_AUTH_PARAMETERS)}. "
                    f"Use an 'external_auth' or 'passthrough' profile type to permit "
                    f"custom parameter names."
                )

    # Cross-file duplicate field-id check — the connectors-repo validator
    # enforces unique field ids across every YAML file in a connector
    # (general_configurations, every profile, every capability config).
    # When two surfaces define the same id with different shapes, the
    # validator rejects the connector with a "duplicate field ID" error.
    # We piggyback on the existing fields_by_id index: any id with >1 entry
    # that maps to >1 distinct (file, surface) pair is reported.
    for fid, entries in cidx.fields_by_id.items():
        if len(entries) < 2:
            continue
        seen_pairs: set[tuple[str, str]] = set()
        for e in entries:
            try:
                rel = str(e.source_file.relative_to(cidx.connector_dir))
            except ValueError:
                rel = str(e.source_file)
            seen_pairs.add((rel, e.surface))
        if len(seen_pairs) > 1:
            locations = sorted(f"{rel}@{surface}" for rel, surface in seen_pairs)
            issues.append(
                f"duplicate field id '{fid}' appears in multiple surfaces: "
                f"{locations}. The connectors-repo validator rejects this. "
                f"Prefix the duplicates with the handler tag (e.g. "
                f"'<handler_id>_{fid}') so each surface gets its own id."
            )
    return {"issues": issues}


def compute_auth_verdicts(
    inv: XsoarInventory,
    cidx: ConnectorIndex,
    handler_id: str,
) -> dict[str, Any]:
    """Verify every auth-bearing XSOAR param has a profile + handler binding."""
    auth_params = [p for p in inv.params if p.is_auth and not p.hidden_everywhere]
    handler_auth_options = cidx.auth_options_in_handlers.get(handler_id, [])
    profiles_in_connection = cidx.profile_ids
    issues: list[str] = []

    if auth_params and not profiles_in_connection:
        issues.append(
            f"integration declares {len(auth_params)} auth param(s) "
            f"{[p.name for p in auth_params]} but connection.yaml has no profiles[]"
        )

    if auth_params and not handler_auth_options:
        issues.append(
            f"integration declares {len(auth_params)} auth param(s) but handler.yaml "
            f"capabilities[].auth_options is empty — handler cannot select a profile"
        )

    # Every handler auth_option must reference a real profile id.
    for opt_id in handler_auth_options:
        if opt_id not in profiles_in_connection:
            issues.append(
                f"handler references auth_option '{opt_id}' that is NOT defined in "
                f"connection.yaml profiles[] (have: {profiles_in_connection})"
            )

    # Every auth-bearing YML param must map to at least one connector field with
    # the right metadata.auth.parameter — but we already cover that via the
    # param-verdict matrix; here we just summarise.
    return {
        "auth_param_count": len(auth_params),
        "auth_param_names": [p.name for p in auth_params],
        "profiles_in_connection": profiles_in_connection,
        "handler_auth_options": handler_auth_options,
        "issues": issues,
    }


def compute_collisions(
    inv: XsoarInventory,
    cidx: ConnectorIndex,
    handler_id: str,
) -> list[dict[str, Any]]:
    """Find field ids that the new handler reuses with a different shape than siblings."""
    collisions: list[dict[str, Any]] = []
    # Build a set of connector field ids that belong to the new handler's
    # expected surfaces (auth profile + configurations under its capability id +
    # general_configurations). We already record auth.parameter as a separate
    # axis, so collisions are detected by: same field_id used by ANOTHER
    # connector surface with a different field_type / mask / auth.parameter.
    expected_cap_id = LONG_RUNNING_INTEGRATIONS.get(inv.integration_id, "automation-and-remediation")
    new_handler_cap_prefixes = [
        f"configurations.{expected_cap_id}",
        f"configurations.{handler_id}-",  # e.g. configurations.xsoar_slackv3-automation
    ]
    for fid, entries in cidx.fields_by_id.items():
        if len(entries) < 2:
            continue
        # Group by shape signature.
        signatures: dict[tuple[Any, ...], list[FieldEntry]] = {}
        for e in entries:
            sig = (e.field_type, e.masked, e.auth_parameter)
            signatures.setdefault(sig, []).append(e)
        if len(signatures) > 1:
            # Same id, different shapes.
            ours = [e for e in entries if any(e.surface.startswith(p) for p in new_handler_cap_prefixes)]
            if ours:
                collisions.append(
                    {
                        "field_id": fid,
                        "shapes": [
                            {
                                "field_type": sig[0],
                                "masked": sig[1],
                                "auth_parameter": sig[2],
                                "surfaces": [e.surface for e in es],
                                "sources": [str(e.source_file.relative_to(cidx.connector_dir)) for e in es],
                            }
                            for sig, es in signatures.items()
                        ],
                    }
                )
    return collisions


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def render_markdown_report(
    report_id: str,
    inv: XsoarInventory,
    cidx: ConnectorIndex,
    handler_id: str,
    verdicts: list[ParamVerdict],
    cap_audit: dict[str, Any],
    auth_audit: dict[str, Any],
    schema_audit: dict[str, Any],
    collisions: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append(f"# Handler Coverage Report — `{report_id}`")
    lines.append("")
    lines.append(f"- **Integration:** `{inv.integration_id}` ({inv.display})")
    lines.append(f"- **Docker image:** `{inv.docker_image}`")
    lines.append(f"- **Connector dir:** `{cidx.connector_dir}`")
    lines.append(f"- **New handler:** `{handler_id}`")
    lines.append(
        f"- **Integration flags:** isfetch={inv.is_fetch}, isfetchevents={inv.is_fetch_events}, "
        f"longRunning={inv.is_long_running}, feed={inv.is_feed}"
    )
    lines.append(f"- **Commands:** {len(inv.commands)} ({', '.join(inv.commands[:5])}{'...' if len(inv.commands) > 5 else ''})")
    lines.append("")

    # Capability audit
    lines.append("## Capability coverage")
    lines.append("")
    lines.append(f"- handler.yaml capabilities[]: `{cap_audit['handler_capability_ids']}`")
    lines.append(f"- triggering.type: `{cap_audit['triggering_type']}`")
    lines.append(f"- expected long-running capability: `{cap_audit['expected_long_running_capability']}`")
    if cap_audit["issues"]:
        lines.append("")
        lines.append("**Issues:**")
        for issue in cap_audit["issues"]:
            lines.append(f"- ⚠️ {issue}")
    else:
        lines.append("- ✅ no issues")
    lines.append("")

    # Auth audit
    lines.append("## Auth coverage")
    lines.append("")
    lines.append(f"- auth-bearing YML params: `{auth_audit['auth_param_names']}`")
    lines.append(f"- profiles[] in connection.yaml: `{auth_audit['profiles_in_connection']}`")
    lines.append(f"- handler.yaml capabilities[].auth_options[].id: `{auth_audit['handler_auth_options']}`")
    if auth_audit["issues"]:
        lines.append("")
        lines.append("**Issues:**")
        for issue in auth_audit["issues"]:
            lines.append(f"- ⚠️ {issue}")
    else:
        lines.append("- ✅ no issues")
    lines.append("")

    # Schema audit
    lines.append("## Schema validation (connectors-repo enum / pattern checks)")
    lines.append("")
    if schema_audit["issues"]:
        lines.append("**Issues:**")
        for issue in schema_audit["issues"]:
            lines.append(f"- ⚠️ {issue}")
    else:
        lines.append("- ✅ no issues")
    lines.append("")

    # Param parity matrix
    lines.append("## Param parity matrix")
    lines.append("")
    lines.append("| YML name | type | required | hidden | routing | action | locations | notes |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for v in verdicts:
        locs = "; ".join(loc.surface for loc in v.locations) or "—"
        hidden_str = "yes" if v.param.hidden_raw is True else (
            f"[{','.join(v.param.hidden_marketplaces)}]" if v.param.hidden_marketplaces else "no"
        )
        emoji = {
            "PRESENT": "✅",
            "OMIT-justified": "✅",
            "ADD-to-connection": "❌",
            "ADD-to-configurations": "❌",
            "ADD-to-handler": "❌",
            "ADD-as-auth-profile-field": "❌",
            "COLLISION": "⚠️",
        }.get(v.action, "❓")
        lines.append(
            f"| `{v.param.name}` | {v.param.type} | {v.param.required} | {hidden_str} | "
            f"{v.routing_bucket}{('@' + v.expected_capability_id) if v.expected_capability_id else ''} | "
            f"{emoji} {v.action} | {locs} | {v.notes} |"
        )
    lines.append("")

    # Collisions
    lines.append("## Collisions with sibling handlers")
    lines.append("")
    if not collisions:
        lines.append("- ✅ no field-id collisions across surfaces")
    else:
        for c in collisions:
            lines.append(f"### `{c['field_id']}`")
            for shape in c["shapes"]:
                lines.append(
                    f"- field_type=`{shape['field_type']}`, masked=`{shape['masked']}`, "
                    f"auth.parameter=`{shape['auth_parameter']}` — surfaces: "
                    f"{shape['surfaces']} ({shape['sources']})"
                )
            lines.append("")
    lines.append("")

    # Summary
    n_add = sum(1 for v in verdicts if v.action.startswith("ADD"))
    n_present = sum(1 for v in verdicts if v.action == "PRESENT")
    n_justified = sum(1 for v in verdicts if v.action == "OMIT-justified")
    n_collision = sum(1 for v in verdicts if v.action == "COLLISION")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total YML params: **{len(verdicts)}**")
    lines.append(f"- ✅ Present in expected surface: **{n_present}**")
    lines.append(f"- ✅ Hidden-everywhere (justified omit): **{n_justified}**")
    lines.append(f"- ❌ Missing (ADD-*): **{n_add}**")
    lines.append(f"- ⚠️ Collision (wrong surface): **{n_collision}**")
    lines.append(f"- ⚠️ Capability issues: **{len(cap_audit['issues'])}**")
    lines.append(f"- ⚠️ Auth issues: **{len(auth_audit['issues'])}**")
    lines.append(f"- ⚠️ Schema issues: **{len(schema_audit['issues'])}**")
    lines.append(f"- ⚠️ Field-id collisions: **{len(collisions)}**")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entrypoints
# ---------------------------------------------------------------------------


def _propose_field_id(yml_name: str, handler_id: str) -> str:
    """Generate the prefixed snake_case connector field id for an ADD verdict."""
    snake = _camel_to_snake(yml_name)
    prefix = handler_id[len("xsoar_"):] if handler_id.startswith("xsoar_") else handler_id
    return f"{prefix}_{snake}"


def _yml_type_to_field_type(yml_type: int, bucket: str) -> str:
    """Pick the connector field_type given an XSOAR YML param type + routing bucket."""
    if bucket == "auth_profile":
        return "input"
    return PARAM_TYPE_TO_FIELD_TYPE.get(yml_type, "input")


def _dump_field_as_list_item(field_dict: dict[str, Any], indent_spaces: int) -> str:
    """Dump a single field dict as a YAML list item, indented under ``fields:``.

    Output looks like::

        - id: foo
          title: Foo
          field_type: input
          options:
            mask: false
            ...

    where the leading ``- `` is on the same line as the first key. Uses
    PyYAML's ``safe_dump`` to handle string-quoting / nested dicts correctly,
    then re-indents.
    """
    raw = yaml.safe_dump(
        [field_dict], default_flow_style=False, sort_keys=False, allow_unicode=True, width=4096
    )
    # PyYAML produces ``- id: foo\n  title: ...``. Re-indent every line by
    # the requested number of spaces (we want a 4-space indent so the result
    # sits cleanly under ``fields:`` inside ``- fields:``).
    pad = " " * indent_spaces
    return "\n".join((pad + line) if line.strip() else line for line in raw.rstrip("\n").split("\n"))


def render_fragments(
    inv: XsoarInventory,
    cidx: ConnectorIndex,
    handler_id: str,
    verdicts: list[ParamVerdict],
) -> str:
    """Render ready-to-paste YAML fragments for every ADD-* verdict.

    Groups by destination surface so the reviewer can paste each block under
    the right existing section in the connector files. Adds a comment header
    naming the integration / handler / capability id so the diff is
    self-documenting.
    """
    cap_aliases = _candidate_capability_ids(
        inv.integration_id, handler_id, cidx.capability_ids_in_handlers.get(handler_id, [])
    )
    # Prefer the prefixed cap id (PR convention).
    target_cap_id = f"{handler_id}-automation"
    if cap_aliases and target_cap_id not in cap_aliases:
        target_cap_id = cap_aliases[0]

    by_bucket: dict[str, list[ParamVerdict]] = {
        "auth_profile": [],
        "general_configurations": [],
        "capability_configurations": [],
    }
    for v in verdicts:
        if v.action.startswith("ADD"):
            by_bucket.setdefault(v.routing_bucket, []).append(v)

    lines: list[str] = []
    lines.append(f"# YAML fragments for: {handler_id}  (integration: {inv.integration_id})")
    lines.append(f"# Generated by connectus/check_handler_coverage.py --emit-fragments")
    lines.append("#")
    lines.append("# REVIEW BEFORE APPLYING. Each block is a starting point — adjust")
    lines.append("# title casing, hint text, defaults, validation patterns, and field")
    lines.append("# ordering to match the existing connector style.")
    lines.append("")

    def _field_dict(v: ParamVerdict) -> dict[str, Any]:
        bucket = v.routing_bucket
        new_id = _propose_field_id(v.param.name, handler_id)
        field_type = _yml_type_to_field_type(v.param.type, bucket)
        opts: dict[str, Any] = {
            "mask": v.param.type in (4, 9),
        }
        if v.param.additionalinfo:
            opts["description"] = v.param.additionalinfo
        if v.param.defaultvalue is not None:
            opts["default_value"] = v.param.defaultvalue
        opts["create_modifiers"] = {"required": v.param.required, "hidden": False}
        opts["edit_modifiers"] = {"required": v.param.required, "hidden": False}
        fld: dict[str, Any] = {
            "id": new_id,
            "title": v.param.display or v.param.name,
            "field_type": field_type,
        }
        # auth-bearing fields need metadata.auth.parameter so the platform knows
        # which YML param to inject the secret as.
        if bucket == "auth_profile":
            fld["metadata"] = {"auth": {"parameter": v.param.name}}
        fld["options"] = opts
        return fld

    def _emit_section(header_lines: list[str], items: list[ParamVerdict]) -> None:
        if not items:
            return
        for hl in header_lines:
            lines.append(hl)
        for v in items:
            lines.append("- fields:")
            lines.append(_dump_field_as_list_item(_field_dict(v), indent_spaces=4))
            lines.append("")

    _emit_section(
        [
            "# ---- AUTH PROFILE fields (under connection.yaml profiles[].configurations[].fields) ----",
            "# Pick the correct existing profile or create a new one.",
        ],
        by_bucket["auth_profile"],
    )
    _emit_section(
        [
            "# ---- CONNECTION.YAML general_configurations fields ----",
            "# These live under connection.yaml:",
            "#   general_configurations.configurations[].fields[]",
        ],
        by_bucket["general_configurations"],
    )
    _emit_section(
        [
            f"# ---- CONFIGURATIONS.YAML under capability id: {target_cap_id} ----",
            "# Append these under the matching configurations[].id entry; create the",
            f"# capability block if it doesn't exist yet (id: \"{target_cap_id}\").",
        ],
        by_bucket["capability_configurations"],
    )

    return "\n".join(lines) + "\n"


def run_one(
    integration_path: Path,
    connector_dir: Path,
    handler_id: str,
    report_id: str,
    output_dir: Path | None,
    emit_fragments: bool = False,
) -> tuple[str, int]:
    """Run the audit for one triple. Returns (report_markdown, exit_status).

    Exit status is 0 if no gaps/issues, else 1.
    """
    yml_path, _ = find_integration_files(integration_path)
    inv = _parse_xsoar_inventory(yml_path)
    cidx = index_connector(connector_dir)
    verdicts = compute_param_verdicts(inv, cidx, handler_id)
    cap_audit = compute_capability_verdicts(inv, cidx, handler_id)
    auth_audit = compute_auth_verdicts(inv, cidx, handler_id)
    schema_audit = compute_schema_verdicts(cidx)
    collisions = compute_collisions(inv, cidx, handler_id)
    report = render_markdown_report(
        report_id, inv, cidx, handler_id, verdicts, cap_audit, auth_audit, schema_audit, collisions
    )
    # Include schema issues in the failure accounting.
    schema_issues = len(schema_audit["issues"])
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / f"{report_id}.md"
        out.write_text(report, encoding="utf-8")
        if emit_fragments:
            frag_dir = output_dir / "fragments"
            frag_dir.mkdir(parents=True, exist_ok=True)
            frag_path = frag_dir / f"{report_id}.yaml"
            frag_path.write_text(
                render_fragments(inv, cidx, handler_id, verdicts), encoding="utf-8"
            )
    n_bad = (
        sum(1 for v in verdicts if v.action.startswith("ADD") or v.action == "COLLISION")
        + len(cap_audit["issues"])
        + len(auth_audit["issues"])
        + schema_issues
        + len(collisions)
    )
    return report, (0 if n_bad == 0 else 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--integration", type=Path, help="Path to the XSOAR integration dir (containing the .yml)")
    parser.add_argument("--connector", type=Path, help="Path to the connector dir (containing connection.yaml, configurations.yaml, components/handlers/)")
    parser.add_argument("--handler-id", type=str, help="Id of the new xsoar_* handler dir inside connector/components/handlers/")
    parser.add_argument("--batch", choices=["standard_connectors_poc"], help="Run a built-in batch instead of a single triple")
    parser.add_argument("--output-dir", type=Path, help="Directory to write per-triple Markdown reports")
    parser.add_argument("--json", action="store_true", help="Also emit JSON summaries alongside Markdown")
    parser.add_argument("--emit-fragments", action="store_true", help="Also emit ready-to-paste YAML fragments for every ADD-* verdict")
    args = parser.parse_args(argv)

    if args.batch:
        triples = BATCH_STANDARD_CONNECTORS_POC
    else:
        if not (args.integration and args.connector and args.handler_id):
            parser.error("--integration, --connector, and --handler-id are required unless --batch is given")
        triples = {
            f"{args.connector.name}.{args.handler_id}": {
                "integration": str(args.integration),
                "connector": str(args.connector),
                "handler_id": args.handler_id,
            }
        }

    overall_status = 0
    summaries: dict[str, dict[str, int]] = {}
    for report_id, triple in triples.items():
        integration_path = Path(triple["integration"])
        connector_dir = Path(triple["connector"])
        handler_id = triple["handler_id"]
        try:
            report, status = run_one(
                integration_path,
                connector_dir,
                handler_id,
                report_id,
                args.output_dir,
                emit_fragments=args.emit_fragments,
            )
        except Exception as exc:  # noqa: BLE001 — surface all errors verbatim
            print(f"[FAIL] {report_id}: {exc}", file=sys.stderr)
            overall_status = 1
            continue
        # Cheap summary line so the batch caller sees one-line-per-triple progress.
        n_add = report.count("| ❌ ADD")
        n_collision = report.count("| ⚠️ COLLISION")
        n_present = report.count("| ✅ PRESENT")
        n_justified = report.count("| ✅ OMIT-justified")
        summaries[report_id] = {
            "add": n_add,
            "collision": n_collision,
            "present": n_present,
            "justified_omit": n_justified,
            "status": status,
        }
        print(
            f"[{('OK' if status == 0 else 'GAP')}] {report_id}: "
            f"add={n_add} collision={n_collision} present={n_present} justified={n_justified}"
        )
        if status != 0:
            overall_status = 1

    if args.json and args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")

    return overall_status


if __name__ == "__main__":
    raise SystemExit(main())
