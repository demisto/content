"""Verify a connector handler covers every non-hidden integration YML param.

Given a path to a connector *handler* (the directory that contains the
handler's ``handler.yaml``) and a path to the original XSOAR *integration
YML*, this tool answers a single question:

    Does the connector expose — for THIS handler — every (non-hidden)
    configuration parameter that the integration YML declares?

It collects the union of every connector parameter that is reachable from
the handler:

  * **Capability config params** — every ``fields[].id`` under the
    ``configurations`` / ``capabilities`` entries whose ``id`` is one of the
    handler's ``capabilities[].id`` (sub-capabilities included).
  * **General-configuration params** — every ``fields[].id`` inside a
    ``general_configurations`` field group whose ``view_group`` matches one
    of the handler's view groups. The handler's view groups are derived from
    the ``configurations.yaml`` (and inline ``capabilities.yaml``) config
    entries whose ``id`` is one of the handler's ``capabilities[].id`` (sub-
    capabilities included) — all sub-capabilities of a handler share the same
    view group. A general-config field group with no ``view_group`` is shared
    (belongs to every handler); a group pinned to a *different* handler's view
    group is ignored.
  * **Auth-profile params** — every ``fields[].id`` of each
    ``connection.yaml`` profile whose ``id`` is referenced by the handler's
    ``capabilities[].auth_options[].id``.

Each collected connector field id is run through the handler's
``serializer.yaml`` so that we compare against the ORIGINAL integration
param name rather than a dedup-renamed connector id. Resolution order:

  1. If the field id appears as a ``field_mappings[].id`` in any
     ``serializer.yaml`` under the handler dir, use its ``field_name``
     (the original integration param name).
  2. Otherwise use the bare field id.

Beyond the three collectors above, two more sources feed the connector
param set:

  * **Serializer computed-field outputs** — every
    ``computed_fields[].output[].id`` declared in any ``serializer.yaml``
    under the handler dir is treated as a connector param as well (resolved
    through the same serializer ``field_mappings`` pipeline).

The check is one-directional and strict: it fails when an integration-YML
param (anything not ``hidden: true`` / ``hidden: platform`` /
``hidden: [..]``) is NOT present in the collected connector param set, with
two Platform-rename special cases:

  * an integration ``incidentType`` param is considered covered when the
    connector exposes an ``incidentType`` field (bare or sub-capability
    prefixed, e.g. ``fetch-issues_<int>_incidentType``);
  * an integration ``incidentFetchInterval`` param is considered covered
    when the connector exposes an ``incidentFetchInterval`` field (bare or
    sub-capability prefixed).

One more special case covers XSOAR ``type: 9`` credentials widgets. A
credentials param is a *compound* field that the integration reads through
the dotted-leaf form ``params.get("<name>", {}).get("identifier")`` /
``.get("password")`` (see ``connectus/analyzer-manual.md``). The manifest
generator splits it on the connector side into a ``<name>_username`` +
``<name>_password`` pair (or a password-only field, with the bare ``<name>``
as its id, when the YML carries ``hiddenusername: true``). So a credentials
param is considered covered when:

  * the serializer already bridged a connector field back to the bare
    ``<name>``; OR
  * ``hiddenusername: true`` and the connector exposes the bare ``<name>``
    OR the ``<name>_password`` half; OR
  * (default) the connector exposes BOTH the ``<name>_username`` AND the
    ``<name>_password`` halves.

Leaf ids may be sub-capability prefixed (e.g.
``fetch-issues_<int>_<name>_password``), so coverage uses the same
underscore-boundary suffix match as the alert renames.

No other special-casing of backend-only or reserved framework fields is
applied on either side.

Exit codes:
  * ``0`` — every non-hidden YML param is covered.
  * ``1`` — at least one non-hidden YML param is missing (the list is
    printed to stderr).
  * ``2`` — a usage / file-resolution error (bad paths, missing connector
    root, unparseable YAML).

Usage::

    python3 connectus/check_handler_param_coverage.py \\
        --handler-path <connector>/components/handlers/<handler>/handler.yaml \\
        --integration-yml Packs/<Pack>/Integrations/<Int>/<Int>.yml
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import yaml

# Make sibling connectus modules (workflow_state) importable regardless of CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))

_REPO_ROOT = Path(__file__).resolve().parent.parent

logger = logging.getLogger(__name__)

# Exit codes.
EXIT_OK = 0
EXIT_MISSING = 1
EXIT_USAGE = 2

# Connector-root file names.
CAPABILITIES_FILE = "capabilities.yaml"
CONFIGURATIONS_FILE = "configurations.yaml"
CONNECTION_FILE = "connection.yaml"
HANDLER_FILE = "handler.yaml"
SERIALIZER_GLOB = "serializer.yaml"

# Marker directory that anchors the connector root: the handler dir lives at
# ``<connector_root>/components/handlers/<handler>/``.
COMPONENTS_DIR = "components"
HANDLERS_DIR = "handlers"

# Serializer ``computed_fields`` block: ``computed_fields[].output[].id``.
COMPUTED_FIELDS_KEY = "computed_fields"

# Platform "alert" renames. The Platform migrates the legacy XSOAR
# ``incidentType`` / ``incidentFetchInterval`` params to ``incidentType`` /
# ``incidentFetchInterval`` on the connector side with NO serializer bridge back
# to the original names. The connector id may also be sub-capability prefixed
# (e.g. ``fetch-issues_<int>_incidentType``), so coverage uses a suffix match.
INCIDENT_TYPE_PARAM = "incidentType"
ALERT_TYPE_SUFFIX = "incidentType"
INCIDENT_FETCH_INTERVAL_PARAM = "incidentFetchInterval"
ALERT_FETCH_INTERVAL_SUFFIX = "incidentFetchInterval"
IGNORED_PARAMS = {
    "is_mirroring",
    "close_alert",
    "mirroring",
    "close_ticket",
    "resolve_finding",
    "file_tag",
    "mirror_options",
    "close_incident",
    "mirror_limit",
    "mirror_direction",
    "mirror_tag",
    "incoming_tags",
    "outgoing_tags",
    "comment_tag",
    "work_notes_tag",
    "close_out",
    "close_notes",
    "longRunning",
    "close_netskope_incident",
    "close_extra_labels",
    "longRunningPort",
    "close_end_status_statuses",
    "close_extra_labels",
    "comment_tag_from_splunk",
    "comment_tag_to_splunk",
    "close_alerts_in_xdr",
    "close_xdr_incident",
    "close_xsoar_incident",
    "custom_xdr_to_xsoar_close_reason_mapping",
    "custom_xsoar_to_xdr_close_reason_mapping",
    "xdr_delay",
    "close_ibm_incident",
    "close_xsoar_incident",
    "tag_from_ibm",
    "tag_to_ibm"
}

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

# XSOAR ``type: 9`` — the credentials widget. A single integration YML param
# of this type is a *compound* field: the integration reads it as
# ``params.get("<name>", {}).get("identifier")`` / ``.get("password")`` (the
# dotted-leaf rule, see ``connectus/analyzer-manual.md``). On the connector
# side it is split by the manifest generator into TWO fields:
#   * ``<name>_username`` (from the ``.identifier`` leaf), and
#   * ``<name>_password`` (from the ``.password`` leaf).
# When the YML param carries ``hiddenusername: true`` the username half is
# suppressed and only the password half is emitted, with the *bare* ``<name>``
# as its id. Either connector id may be sub-capability prefixed (e.g.
# ``fetch-issues_<int>_<name>_password``), so coverage uses an
# underscore-boundary suffix match just like the alert renames above.
YML_TYPE_CREDENTIALS = 9
USERNAME_LEAF_SUFFIX = "_username"
PASSWORD_LEAF_SUFFIX = "_password"

class CoverageError(Exception):
    """Raised for usage / resolution errors that should exit with EXIT_USAGE."""


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------
def load_yaml(path: Path) -> dict:
    """Load a YAML file into a dict.

    Returns an empty dict for a missing file (callers decide whether that's
    fatal). Raises :class:`CoverageError` when the file exists but cannot be
    parsed into a mapping.
    """
    if not path.is_file():
        return {}
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise CoverageError(f"Could not parse YAML at {path}: {exc}") from exc
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise CoverageError(f"Expected a mapping at the top of {path}, got {type(doc).__name__}")
    return doc


# ---------------------------------------------------------------------------
# Step 2: connector-root resolution
# ---------------------------------------------------------------------------
def resolve_connector_root(handler_dir: Path) -> Path:
    """Walk up from the handler dir to find the connector root.

    Expects the layout ``<connector_root>/components/handlers/<handler>/``.
    The connector root is the parent of the ``components`` directory found
    while walking up. Raises :class:`CoverageError` if the layout can't be
    matched.
    """
    handler_dir = handler_dir.resolve()
    for parent in handler_dir.parents:
        # parent is a candidate for the ``handlers`` dir, ``components`` dir, etc.
        if parent.name == COMPONENTS_DIR and parent.parent is not None:
            return parent.parent
    raise CoverageError(
        f"Could not locate connector root from handler path {handler_dir}. "
        f"Expected layout <connector_root>/{COMPONENTS_DIR}/{HANDLERS_DIR}/<handler>/."
    )


# ---------------------------------------------------------------------------
# Step 3: integration-YML param collector
# ---------------------------------------------------------------------------
def _is_hidden(param: dict) -> bool:
    """Return True when a YML configuration param is hidden on the Platform.

    Per skill §1.3, a param is excluded from migration tooling ONLY when it is
    hidden on the *platform* target. Hidden means any of:
      * ``hidden: true`` (boolean True — hidden everywhere).
      * ``hidden: platform`` (the string form, single platform target).
      * ``hidden: [.., platform, ..]`` — a list that CONTAINS ``platform``
        (per-marketplace form, e.g. ``[platform]`` / ``[marketplacev2, platform]``).

    A ``hidden:`` list that does NOT contain ``platform`` (e.g. ``[xsoar]``,
    ``[xsoar_on_prem]``, ``[marketplacev2]``) is NOT excluded — the param is
    still visible on the platform target and must be carried through. Anything
    else (missing / ``false`` / empty list) is NOT hidden.
    """
    hidden = param.get("hidden")
    if hidden is True:
        return True
    if isinstance(hidden, str):
        return hidden == "platform"
    if isinstance(hidden, list):
        return "platform" in hidden
    return False


def collect_yml_params(integration_yml: dict) -> set[str]:
    """Collect the set of non-hidden param names from an integration YML."""
    params: set[str] = set()
    for param in integration_yml.get("configuration", []) or []:
        if not isinstance(param, dict):
            continue
        if _is_hidden(param):
            continue
        # A ``type: 9`` credentials widget with BOTH leaves suppressed
        # (``hiddenusername: true`` AND ``hiddenpassword: true``) has no live
        # leaf — per skill §1.3 it is treated as if ``hidden: true`` at the
        # whole-param level (a dead/legacy auth alternative). Exclude it from
        # coverage: the connector never exposes either leaf for it.
        if (
            param.get("type") == YML_TYPE_CREDENTIALS
            and bool(param.get("hiddenusername"))
            and bool(param.get("hiddenpassword"))
        ):
            continue
        name = param.get("name")
        if name:
            params.add(name)
    return params


def collect_type9_params(integration_yml: dict) -> dict[str, tuple[bool, bool]]:
    """Map each non-hidden ``type: 9`` credentials param to its leaf-suppression
    flags ``(hiddenusername, hiddenpassword)``.

    A credentials widget is special on the connector side: it splits into a
    ``<name>_username`` + ``<name>_password`` pair. A per-leaf suppression flag
    drops one half: ``hiddenusername: true`` emits a password-only field, while
    ``hiddenpassword: true`` emits a username-only field. The returned
    ``{name: (hiddenusername, hiddenpassword)}`` map lets
    :func:`_type9_leaf_covered` recognise that the surviving leaf(es) cover the
    original compound param. Only non-hidden params are included, matching
    :func:`collect_yml_params`.
    """
    creds: dict[str, tuple[bool, bool]] = {}
    for param in integration_yml.get("configuration", []) or []:
        if not isinstance(param, dict):
            continue
        if _is_hidden(param):
            continue
        if param.get("type") != YML_TYPE_CREDENTIALS:
            continue
        name = param.get("name")
        if name:
            creds[name] = (
                bool(param.get("hiddenusername")),
                bool(param.get("hiddenpassword")),
            )
    return creds


# ---------------------------------------------------------------------------
# Step 4: handler parser
# ---------------------------------------------------------------------------
def parse_handler(handler_yaml: dict) -> tuple[str, set[str], set[str]]:
    """Extract (view_group, capability_ids, auth_profile_ids) from a handler.

    * ``view_group`` — the handler id (``handler.yaml`` top-level ``id``).
      General-config field groups pinned to this id belong to this handler.
    * ``capability_ids`` — the set of ``capabilities[].id``.
    * ``auth_profile_ids`` — the set of every ``auth_options[].id`` across all
      capabilities (these reference ``connection.yaml`` profile ids).
    """
    view_group = handler_yaml.get("id") or ""
    capability_ids: set[str] = set()
    auth_profile_ids: set[str] = set()
    for capability in handler_yaml.get("capabilities", []) or []:
        if not isinstance(capability, dict):
            continue
        cap_id = capability.get("id")
        if cap_id:
            capability_ids.add(cap_id)
        for auth_option in capability.get("auth_options", []) or []:
            if not isinstance(auth_option, dict):
                continue
            profile_id = auth_option.get("id")
            if profile_id:
                auth_profile_ids.add(profile_id)
    return view_group, capability_ids, auth_profile_ids


# ---------------------------------------------------------------------------
# Step 5: serializer loader
# ---------------------------------------------------------------------------
def load_serializer_mappings(handler_dir: Path) -> dict[str, str]:
    """Build a connector-field-id -> original-param-name map for the handler.

    Walks every ``serializer.yaml`` under ``handler_dir`` and reads each
    ``field_mappings[]`` entry (``id`` -> ``field_name``). When the same id is
    mapped more than once the last one wins.
    """
    mappings: dict[str, str] = {}
    for serializer_path in sorted(handler_dir.rglob(SERIALIZER_GLOB)):
        doc = load_yaml(serializer_path)
        for entry in doc.get("field_mappings", []) or []:
            if not isinstance(entry, dict):
                continue
            field_id = entry.get("id")
            field_name = entry.get("field_name")
            if field_id and field_name:
                mappings[field_id] = field_name
    return mappings


def load_serializer_computed_output_ids(handler_dir: Path) -> list[str]:
    """Collect every ``computed_fields[].output[].id`` for the handler.

    Walks every ``serializer.yaml`` under ``handler_dir`` and reads each
    ``computed_fields[]`` rule's ``output[]`` entries. Synthetic output fields
    declared here count as connector params (they are resolved through the
    serializer ``field_mappings`` like any other field id by the caller).
    """
    output_ids: list[str] = []
    for serializer_path in sorted(handler_dir.rglob(SERIALIZER_GLOB)):
        doc = load_yaml(serializer_path)
        for rule in doc.get(COMPUTED_FIELDS_KEY, []) or []:
            if not isinstance(rule, dict):
                continue
            for output in rule.get("output", []) or []:
                if not isinstance(output, dict):
                    continue
                output_id = output.get("id")
                if output_id:
                    output_ids.append(output_id)
    return output_ids


# ---------------------------------------------------------------------------
# Step 6: field-id -> param resolver
# ---------------------------------------------------------------------------
def resolve_param_name(field_id: str, serializer_mappings: dict[str, str]) -> str:
    """Resolve a connector field id to the comparable integration param name.

    (1) serializer ``field_name`` when ``field_id`` is mapped, else
    (2) the bare ``field_id``.
    """
    return serializer_mappings.get(field_id, field_id)


def _iter_leaf_field_ids(fields: list) -> list[str]:
    """Yield the leaf param ids from a ``fields`` list, recursing into groups.

    A field can be a UI container (e.g. a ``checkbox_group``) that nests its
    real parameters under its own ``fields`` key. In that case the container
    id (e.g. ``user_operations``) is NOT an integration param — the nested
    children (e.g. ``create_user_enabled``) are. So:

      * a field WITH nested ``fields`` contributes only its (recursive) leaf
        children, not its own id;
      * a field WITHOUT nested ``fields`` contributes its own id.
    """
    leaves: list[str] = []
    for field in fields or []:
        if not isinstance(field, dict):
            continue
        nested = field.get("fields")
        if isinstance(nested, list) and nested:
            leaves.extend(_iter_leaf_field_ids(nested))
            continue
        field_id = field.get("id")
        if field_id:
            leaves.append(field_id)
    return leaves


def _iter_field_ids(configurations: list) -> list[str]:
    """Yield every leaf param id from a list of configuration field groups.

    Each group carries a ``fields`` list; nested ``checkbox_group`` style
    containers are flattened to their leaf ids via :func:`_iter_leaf_field_ids`.
    """
    field_ids: list[str] = []
    for group in configurations or []:
        if not isinstance(group, dict):
            continue
        field_ids.extend(_iter_leaf_field_ids(group.get("fields", [])))
    return field_ids


# ---------------------------------------------------------------------------
# Step 7: capability-config collector
# ---------------------------------------------------------------------------
def _capability_id_chain(entry: dict) -> list[str]:
    """Return the entry's id plus every nested ``sub_capabilities[].id``."""
    ids: list[str] = []
    cap_id = entry.get("id")
    if cap_id:
        ids.append(cap_id)
    for sub in entry.get("sub_capabilities", []) or []:
        if isinstance(sub, dict):
            ids.extend(_capability_id_chain(sub))
    return ids


def collect_capability_config_field_ids(
    capabilities_doc: dict,
    configurations_doc: dict,
    handler_capability_ids: set[str],
) -> list[str]:
    """Collect every field id of configs whose capability id is the handler's.

    Looks in both ``configurations.yaml`` ``configurations[]`` (keyed by
    capability id) and ``capabilities.yaml`` ``capabilities[]`` (in case a
    capability declares inline ``configurations``). Sub-capability ids are
    matched too.
    """
    field_ids: list[str] = []

    # configurations.yaml — list of {id, configurations: [...]}.
    for entry in configurations_doc.get("configurations", []) or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("id") in handler_capability_ids:
            field_ids.extend(_iter_field_ids(entry.get("configurations", [])))

    # capabilities.yaml — capabilities may carry inline configurations.
    for entry in capabilities_doc.get("capabilities", []) or []:
        if not isinstance(entry, dict):
            continue
        chain = _capability_id_chain(entry)
        if any(cid in handler_capability_ids for cid in chain):
            field_ids.extend(_iter_field_ids(entry.get("configurations", [])))
            for sub in entry.get("sub_capabilities", []) or []:
                if isinstance(sub, dict) and sub.get("id") in handler_capability_ids:
                    field_ids.extend(_iter_field_ids(sub.get("configurations", [])))
    return field_ids


# ---------------------------------------------------------------------------
# Step 8: handler view-group resolver + general-configurations collector
# ---------------------------------------------------------------------------
def resolve_handler_view_groups(
    configurations_doc: dict,
    capabilities_doc: dict,
    handler_capability_ids: set[str],
) -> set[str]:
    """Resolve the set of view groups that belong to the handler.

    All sub-capabilities of a handler share the same view group. The view
    group is not the handler id — it is the ``view_group`` slug attached to
    the per-capability config entries. This walks every ``configurations[]``
    entry in ``configurations.yaml`` (and any inline ``configurations`` block
    on a ``capabilities.yaml`` capability / sub-capability) whose ``id`` is
    one of the handler's ``capabilities[].id`` (sub-capabilities included) and
    collects the ``view_group`` value declared on that entry.
    """
    view_groups: set[str] = set()

    # configurations.yaml — list of {id, configurations, view_group}.
    for entry in configurations_doc.get("configurations", []) or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("id") in handler_capability_ids:
            view_group = entry.get("view_group")
            if view_group:
                view_groups.add(view_group)

    # capabilities.yaml — capabilities / sub-capabilities may carry an inline
    # view_group alongside inline configurations.
    for entry in capabilities_doc.get("capabilities", []) or []:
        if not isinstance(entry, dict):
            continue
        chain = _capability_id_chain(entry)
        if not any(cid in handler_capability_ids for cid in chain):
            continue
        if entry.get("id") in handler_capability_ids and entry.get("view_group"):
            view_groups.add(entry["view_group"])
        for sub in entry.get("sub_capabilities", []) or []:
            if not isinstance(sub, dict):
                continue
            if sub.get("id") in handler_capability_ids and sub.get("view_group"):
                view_groups.add(sub["view_group"])

    return view_groups


def collect_general_config_field_ids(docs: list[dict], view_groups: set[str]) -> list[str]:
    """Collect general-config field ids pinned to the handler's view groups.

    A general-config field group with no ``view_group`` is treated as shared
    (belongs to every handler) and is always included. A group whose
    ``view_group`` is in ``view_groups`` is included; a group pinned to any
    other view group is skipped.
    """
    field_ids: list[str] = []
    for doc in docs:
        general = doc.get("general_configurations")
        if not isinstance(general, dict):
            continue
        for group in general.get("configurations", []) or []:
            if not isinstance(group, dict):
                continue
            group_view_group = group.get("view_group")
            if group_view_group and group_view_group not in view_groups:
                continue
            field_ids.extend(_iter_leaf_field_ids(group.get("fields", [])))
    return field_ids


# ---------------------------------------------------------------------------
# Step 9: auth-profile collector
# ---------------------------------------------------------------------------
def collect_auth_profile_field_ids(
    connection_doc: dict, auth_profile_ids: set[str]
) -> list[str]:
    """Collect every field id of connection profiles referenced by the handler."""
    field_ids: list[str] = []
    for profile in connection_doc.get("profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        if profile.get("id") not in auth_profile_ids:
            continue
        field_ids.extend(_iter_field_ids(profile.get("configurations", [])))
    return field_ids


# ---------------------------------------------------------------------------
# Step 9b: interpolation-published params collector
# ---------------------------------------------------------------------------
def collect_interpolation_published_params(
    connection_doc: dict, auth_profile_ids: set[str]
) -> list[str]:
    """Collect the top-level integration-side param names produced by each
    referenced profile's ``metadata.xsoar.interpolation_mapping``.

    At runtime the platform parses ``interpolation_mapping`` — a CSV of
    ``FIELD_ID:dotted.dest`` pairs — and places each credential value under
    ``params[dotted.dest]`` (folding shared prefixes into nested dicts). The
    TOP-LEVEL TOKEN of ``dotted.dest`` (the substring before the first ``.``)
    is therefore the key the integration sees in ``demisto.params()`` — which
    is also the name a ``type:9`` credentials widget (or simple param)
    declares in the integration YML.

    These top tokens MUST contribute to the expected-param set so that
    interpolated profiles do not produce false-positive coverage misses for
    compound params like ``credentials``.

    Behaviour:
      * Only profiles whose ``id`` is in ``auth_profile_ids`` are considered.
      * Missing ``metadata.xsoar.interpolation_mapping`` is treated as no
        published params (returns nothing for that profile).
      * Empty / whitespace-only mapping strings yield nothing.
      * Malformed entries (no ``:`` separator) are silently skipped.
      * Whitespace around entries and around the ``:`` is trimmed.
      * Duplicates across entries and profiles are NOT deduped here — the
        caller folds them into a set when building the final connector-param
        list. Returning a list (not a set) preserves source order so
        downstream callers can do their own logging / debugging.

    These tokens MUST NOT be passed through serializer ``field_mappings`` —
    interpolation already renames them to the integration-side name. The
    caller is expected to add them to the final resolved set directly.

    Reference: ``connectus/interpolated-param-schemas-and-fix.md:13-181``.
    """
    top_tokens: list[str] = []
    for profile in connection_doc.get("profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        if profile.get("id") not in auth_profile_ids:
            continue
        metadata = profile.get("metadata")
        if not isinstance(metadata, dict):
            continue
        xsoar_meta = metadata.get("xsoar")
        if not isinstance(xsoar_meta, dict):
            continue
        mapping = xsoar_meta.get("interpolation_mapping")
        if not isinstance(mapping, str):
            continue
        for raw_entry in mapping.split(","):
            entry = raw_entry.strip()
            if not entry or ":" not in entry:
                continue
            _, _, rhs = entry.partition(":")
            rhs = rhs.strip()
            if not rhs:
                continue
            top_token, _, _ = rhs.partition(".")
            top_token = top_token.strip()
            if top_token:
                top_tokens.append(top_token)
    return top_tokens


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def collect_connector_raw_field_ids(
    handler_dir: Path,
    capabilities_doc: dict,
    configurations_doc: dict,
    connection_doc: dict,
    handler_yaml: dict,
) -> list[str]:
    """Collect every RAW connector field id reachable from the handler.

    Unions field ids from capability configs, view-group general configs, auth
    profiles, and serializer ``computed_fields[].output[].id`` — WITHOUT
    resolving them through the serializer ``field_mappings``. Raw ids are what
    the alert-rename suffix match (``incidentType`` / ``incidentFetchInterval``)
    needs, since those fields are migrated with no serializer bridge and may be
    sub-capability prefixed.
    """
    handler_view_group, capability_ids, auth_profile_ids = parse_handler(handler_yaml)

    # The handler's view groups come from the per-capability config entries
    # (all sub-capabilities of a handler share the same view group), NOT the
    # handler id. Fall back to the handler id for back-compat when no config
    # entry yields a view group.
    view_groups = resolve_handler_view_groups(
        configurations_doc, capabilities_doc, capability_ids
    )
    if not view_groups and handler_view_group:
        view_groups = {handler_view_group}

    raw_field_ids: list[str] = []
    raw_field_ids.extend(
        collect_capability_config_field_ids(
            capabilities_doc, configurations_doc, capability_ids
        )
    )
    raw_field_ids.extend(
        collect_general_config_field_ids(
            [capabilities_doc, configurations_doc, connection_doc], view_groups
        )
    )
    raw_field_ids.extend(
        collect_auth_profile_field_ids(connection_doc, auth_profile_ids)
    )
    raw_field_ids.extend(load_serializer_computed_output_ids(handler_dir))
    return raw_field_ids


def collect_connector_params(
    handler_dir: Path,
    capabilities_doc: dict,
    configurations_doc: dict,
    connection_doc: dict,
    handler_yaml: dict,
) -> set[str]:
    """Collect the full deduped set of connector params for the handler.

    Field ids from capabilities, view-group general configs, auth profiles, and
    serializer ``computed_fields[].output[].id`` are unioned and each resolved
    through the serializer into its original integration param name.

    Interpolation-published params (the top-level token of each
    ``profiles[].metadata.xsoar.interpolation_mapping`` RHS) are added to the
    set directly — they MUST NOT pass through ``serializer.field_mappings``
    because the runtime interpolation already renames them to the
    integration-side ``demisto.params()`` key.
    """
    _, _, auth_profile_ids = parse_handler(handler_yaml)
    serializer_mappings = load_serializer_mappings(handler_dir)
    raw_field_ids = collect_connector_raw_field_ids(
        handler_dir,
        capabilities_doc,
        configurations_doc,
        connection_doc,
        handler_yaml,
    )
    resolved = {resolve_param_name(fid, serializer_mappings) for fid in raw_field_ids}
    interpolation_tokens = collect_interpolation_published_params(
        connection_doc, auth_profile_ids
    )
    resolved.update(interpolation_tokens)
    return resolved


def _raw_id_matches_leaf(leaf_id: str, raw_field_ids: list[str]) -> bool:
    """Return True when a connector leaf id is present in the raw field ids.

    A leaf is present when a raw field id equals it OR ends with
    ``_<leaf_id>`` (the underscore boundary guards against partial-token
    matches while still recognising sub-capability prefixes such as
    ``fetch-issues_<int>_<name>_password``).
    """
    underscore_suffix = f"_{leaf_id}"
    return any(
        fid == leaf_id or fid.endswith(underscore_suffix) for fid in raw_field_ids
    )


def resolve_proxy(missing, id):
    """Waive the ``proxy`` coverage requirement for engine/proxy-excluded
    integrations (Appendix G).

    The manifest generator intentionally does NOT emit a ``proxy`` connection
    field for integrations in ``ENGINE_PROXY_EXCLUDED`` (see
    ``manifest_generator.engine_exclusion_class`` -> ``"excluded"``), so
    requiring it here would be a false-positive coverage gap. The excluded set
    is stored lowercased, so the integration id is lowercased before lookup.
    """
    if id.strip().lower() in ENGINE_PROXY_EXCLUDED:
        missing.discard("proxy")
    return missing


def _type9_leaf_covered(
    missing: set[str],
    raw_field_ids: list[str],
    connector_params: set[str],
    type9_params: dict[str, tuple[bool, bool]],
) -> set[str]:
    """Drop ``type: 9`` credentials params from ``missing`` when their split
    connector leaves cover them.

    A credentials widget never appears as its bare ``<name>`` on the connector
    config side — the manifest generator splits it into ``<name>_username`` +
    ``<name>_password``. A per-leaf suppression flag drops one half. So an
    integration credentials param is considered covered when:

      * the serializer already bridged a connector field back to ``<name>``
        (``<name>`` is in the resolved ``connector_params`` set); OR
      * ``hiddenusername: true`` (password-only) and the connector exposes the
        bare ``<name>`` OR the ``<name>_password`` half; OR
      * ``hiddenpassword: true`` (username-only) and the connector exposes the
        bare ``<name>`` OR the ``<name>_username`` half; OR
      * (default) the connector exposes BOTH the ``<name>_username`` AND the
        ``<name>_password`` halves.

    Leaf ids are matched against the RAW connector field ids with an
    underscore-boundary suffix match (see :func:`_raw_id_matches_leaf`) so
    sub-capability-prefixed ids are recognised.
    """
    resolved = set(missing)
    for name, (hidden_username, hidden_password) in type9_params.items():
        if name not in resolved:
            continue
        # Serializer already bridged a connector field back to the bare name.
        if name in connector_params:
            resolved.discard(name)
            continue
        password_present = _raw_id_matches_leaf(
            f"{name}{PASSWORD_LEAF_SUFFIX}", raw_field_ids
        )
        username_present = _raw_id_matches_leaf(
            f"{name}{USERNAME_LEAF_SUFFIX}", raw_field_ids
        )
        if hidden_username:
            # Only the password half is emitted; its id may be the bare name.
            if _raw_id_matches_leaf(name, raw_field_ids) or password_present:
                resolved.discard(name)
            continue
        if hidden_password:
            # Only the username half is emitted; its id may be the bare name.
            if _raw_id_matches_leaf(name, raw_field_ids) or username_present:
                resolved.discard(name)
            continue
        # Default: require BOTH the username and password halves.
        if username_present and password_present:
            resolved.discard(name)
    return resolved


def _resolve_handler_paths(handler_path: Path) -> tuple[Path, Path]:
    """Resolve ``(handler_dir, handler_yaml_path)`` from a handler path.

    Accepts either a path to the handler's ``handler.yaml`` file (the intended
    input) or, for back-compat, the handler directory that contains it.
    """
    handler_path = handler_path.resolve()
    if handler_path.is_file():
        return handler_path.parent, handler_path
    if handler_path.is_dir():
        handler_yaml_path = handler_path / HANDLER_FILE
        if not handler_yaml_path.is_file():
            raise CoverageError(
                f"No {HANDLER_FILE} found in handler path: {handler_path}"
            )
        return handler_path, handler_yaml_path
    raise CoverageError(f"Handler path does not exist: {handler_path}")


def check_coverage(handler_path: Path, integration_yml_path: Path) -> tuple[bool, set[str]]:
    """Run the full coverage check.

    ``handler_path`` is the path to the handler's ``handler.yaml`` (a handler
    directory is also accepted for back-compat). Returns ``(passed,
    missing_params)`` where ``missing_params`` is the set of non-hidden YML
    params not covered by the connector.
    """
    handler_dir, handler_yaml_path = _resolve_handler_paths(handler_path)

    if not integration_yml_path.is_file():
        raise CoverageError(f"Integration YML not found: {integration_yml_path}")

    connector_root = resolve_connector_root(handler_dir)
    capabilities_doc = load_yaml(connector_root / CAPABILITIES_FILE)
    configurations_doc = load_yaml(connector_root / CONFIGURATIONS_FILE)
    connection_doc = load_yaml(connector_root / CONNECTION_FILE)
    handler_yaml = load_yaml(handler_yaml_path)
    integration_yml = load_yaml(integration_yml_path)
    integration_id = (integration_yml.get("commonfields") or {}).get("id", "")
    yml_params = collect_yml_params(integration_yml)
    type9_params = collect_type9_params(integration_yml)
    raw_field_ids = collect_connector_raw_field_ids(
        handler_dir,
        capabilities_doc,
        configurations_doc,
        connection_doc,
        handler_yaml,
    )
    # Use collect_connector_params (single source of truth) so the
    # interpolation-published RHS top-tokens contribute alongside the raw
    # field ids. Raw ids are still kept for the type:9 leaf reconciliation
    # and the alert-suffix match below — both of which match against raw
    # connector ids, not the resolved param names.
    connector_params = collect_connector_params(
        handler_dir,
        capabilities_doc,
        configurations_doc,
        connection_doc,
        handler_yaml,
    )
    print(f"Got the following integration params: {yml_params=}")
    print(f"Got the following handler params: {connector_params=}")
    missing = yml_params - connector_params
    # type:9 credentials widgets split into <name>_username / <name>_password
    # leaves on the connector (or a password-only field when hiddenusername).
    missing = _type9_leaf_covered(
        missing, raw_field_ids, connector_params, type9_params
    )
    resolve_proxy(missing, integration_id)
    missing = missing - IGNORED_PARAMS
    return (len(missing) == 0), missing


# ---------------------------------------------------------------------------
# --integration-id resolution
# ---------------------------------------------------------------------------
def _resolve_paths_from_id(integration_id: str) -> tuple[Path, Path]:
    """Resolve ``(handler_yaml_path, integration_yml_path)`` from a CSV id.

    Reuses the workflow's own gate resolvers (the single source of truth the
    ``run manifest make validate`` gate uses), mirroring how the reference
    analyzers resolve ``--integration-id``:

    * ``workflow_state.gates._handler_dir_abs`` → the connector handler dir
      (``<connectus_repo>/<connector folder>/components/handlers/<handler-id>``),
      to which ``handler.yaml`` is appended.
    * ``workflow_state.gates._integration_yml_abs`` → the integration YML path.

    Raises ``CoverageError`` (→ exit 2) on any resolution failure so the CLI
    surfaces a clean usage error.
    """
    try:
        from workflow_state.gates import (  # type: ignore
            _handler_dir_abs,
            _integration_yml_abs,
        )
    except Exception as exc:  # noqa: BLE001
        raise CoverageError(
            f"could not import workflow_state for --integration-id "
            f"{integration_id!r}: {type(exc).__name__}: {exc}"
        ) from exc

    yml_abs = _integration_yml_abs(integration_id)
    if not yml_abs:
        raise CoverageError(
            f"--integration-id {integration_id!r}: no integration YML path "
            f"resolved (id not in CSV or 'Integration File Path' unset)."
        )
    handler_dir = _handler_dir_abs(integration_id)
    if not handler_dir:
        raise CoverageError(
            f"--integration-id {integration_id!r}: could not resolve the "
            f"connector handler dir (id not in CSV)."
        )
    return Path(handler_dir) / HANDLER_FILE, Path(yml_abs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_handler_param_coverage",
        description=(
            "Fail when a non-hidden integration YML param is not covered by "
            "the connector handler's params."
        ),
    )
    parser.add_argument(
        "--integration-id",
        type=str,
        default=None,
        help=(
            "Resolve --handler-path and --integration-yml from the workflow "
            "CSV id (preferred). Replaces the two explicit path flags."
        ),
    )
    parser.add_argument(
        "--handler-path",
        type=Path,
        default=None,
        help=(
            "Path to the handler's handler.yaml file "
            "(the handler directory is also accepted). "
            "Omit when using --integration-id."
        ),
    )
    parser.add_argument(
        "--integration-yml",
        type=Path,
        default=None,
        help="Path to the integration YML file. Omit when using --integration-id.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit the reference-aligned JSON envelope to stdout "
            "({integration, pass, missing, ignored_params})."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Override a coverage FAIL: still compute and report the uncovered "
            "params, but exit 0 (pass) and set 'forced': true in the JSON "
            "envelope. Use ONLY on explicit operator instruction when the "
            "uncovered params are known-safe to skip (e.g. a deprecated, "
            "label-less auth alternative). The real gap is never hidden — it "
            "remains in 'missing' for transparency."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if args.integration_id:
        try:
            handler_path, integration_yml_path = _resolve_paths_from_id(
                args.integration_id
            )
        except CoverageError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)  # noqa: T201
            return EXIT_USAGE
    else:
        if not args.handler_path or not args.integration_yml:
            print(  # noqa: T201
                "ERROR: provide --integration-id, OR both --handler-path and "
                "--integration-yml.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        handler_path = args.handler_path
        integration_yml_path = args.integration_yml

    try:
        passed, missing = check_coverage(handler_path, integration_yml_path)
    except CoverageError as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True))
        print(f"ERROR: {exc}", file=sys.stderr)  # noqa: T201
        return EXIT_USAGE

    sorted_missing = sorted(missing)

    # --force: a genuine FAIL is overridden to a pass, but the uncovered
    # params are NEVER hidden — they stay in 'missing' and the override is
    # recorded as 'forced': true so the decision is auditable.
    forced_pass = bool(getattr(args, "force", False)) and not passed
    effective_pass = passed or forced_pass

    if args.json:
        envelope = {
            "integration": integration_yml_path.stem,
            "pass": effective_pass,
            "missing": sorted_missing,
            "ignored_params": sorted(IGNORED_PARAMS),
            "forced": forced_pass,
        }
        print(json.dumps(envelope, indent=2, sort_keys=True))

    if passed:
        if not args.json:
            print(  # noqa: T201
                "PASS: every non-hidden integration YML param is covered by "
                "the connector handler."
            )
        return EXIT_OK

    if forced_pass:
        print(  # noqa: T201
            "FORCED PASS: the following integration YML params are NOT covered "
            f"by the connector handler ({len(sorted_missing)}), overridden via "
            "--force:",
            file=sys.stderr,
        )
        for name in sorted_missing:
            print(f"  - {name}", file=sys.stderr)  # noqa: T201
        return EXIT_OK

    print(  # noqa: T201
        "FAIL: the following integration YML params are NOT covered by the "
        f"connector handler ({len(sorted_missing)}):",
        file=sys.stderr,
    )
    for name in sorted_missing:
        print(f"  - {name}", file=sys.stderr)  # noqa: T201
    return EXIT_MISSING


if __name__ == "__main__":
    raise SystemExit(main())
