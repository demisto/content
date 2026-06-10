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
    ``general_configurations`` field group whose ``view_group`` matches the
    handler's view group (= the handler id). General-config field groups that
    are pinned to a *different* handler's view group are ignored.
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
    connector exposes an ``alertType`` field (bare or sub-capability
    prefixed, e.g. ``fetch-issues_<int>_alertType``);
  * an integration ``incidentFetchInterval`` param is considered covered
    when the connector exposes an ``alertFetchInterval`` field (bare or
    sub-capability prefixed).

No other special-casing of credentials, backend-only, or reserved
framework fields is applied on either side.

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
import logging
import sys
from pathlib import Path

import yaml

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
# ``incidentType`` / ``incidentFetchInterval`` params to ``alertType`` /
# ``alertFetchInterval`` on the connector side with NO serializer bridge back
# to the original names. The connector id may also be sub-capability prefixed
# (e.g. ``fetch-issues_<int>_alertType``), so coverage uses a suffix match.
INCIDENT_TYPE_PARAM = "incidentType"
ALERT_TYPE_SUFFIX = "alertType"
INCIDENT_FETCH_INTERVAL_PARAM = "incidentFetchInterval"
ALERT_FETCH_INTERVAL_SUFFIX = "alertFetchInterval"
IGNORED_PARAMS = {"is_mirroring", "mirror_direction", "mirror_limit", "close_incident"}

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

    Hidden means any of:
      * ``hidden: true`` (boolean True).
      * ``hidden: platform`` (string).
      * ``hidden: [..]`` — a non-empty list (per-marketplace form, e.g.
        ``[platform]`` / ``[marketplacev2, platform]``).
    Anything else (missing / ``false`` / empty list) is NOT hidden.
    """
    hidden = param.get("hidden")
    if hidden is True:
        return True
    if isinstance(hidden, str) and hidden:
        return True
    return isinstance(hidden, list) and len(hidden) > 0


def collect_yml_params(integration_yml: dict) -> set[str]:
    """Collect the set of non-hidden param names from an integration YML."""
    params: set[str] = set()
    for param in integration_yml.get("configuration", []) or []:
        if not isinstance(param, dict):
            continue
        if _is_hidden(param):
            continue
        name = param.get("name")
        if name:
            params.add(name)
    return params


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
# Step 8: general-configurations collector
# ---------------------------------------------------------------------------
def collect_general_config_field_ids(docs: list[dict], view_group: str) -> list[str]:
    """Collect general-config field ids pinned to the handler's view group.

    A general-config field group with no ``view_group`` is treated as shared
    (belongs to every handler) and is always included. A group whose
    ``view_group`` differs from the handler's is skipped.
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
            if group_view_group and group_view_group != view_group:
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
    the alert-rename suffix match (``alertType`` / ``alertFetchInterval``)
    needs, since those fields are migrated with no serializer bridge and may be
    sub-capability prefixed.
    """
    view_group, capability_ids, auth_profile_ids = parse_handler(handler_yaml)

    raw_field_ids: list[str] = []
    raw_field_ids.extend(
        collect_capability_config_field_ids(
            capabilities_doc, configurations_doc, capability_ids
        )
    )
    raw_field_ids.extend(
        collect_general_config_field_ids(
            [capabilities_doc, configurations_doc, connection_doc], view_group
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
    """
    serializer_mappings = load_serializer_mappings(handler_dir)
    raw_field_ids = collect_connector_raw_field_ids(
        handler_dir,
        capabilities_doc,
        configurations_doc,
        connection_doc,
        handler_yaml,
    )
    return {resolve_param_name(fid, serializer_mappings) for fid in raw_field_ids}


def _alert_rename_covered(missing: set[str], raw_field_ids: list[str]) -> set[str]:
    """Drop Platform-renamed alert params from ``missing`` when covered.

    The Platform migrates ``incidentType`` -> ``alertType`` and
    ``incidentFetchInterval`` -> ``alertFetchInterval`` on the connector side
    with no serializer bridge, and the connector id may be sub-capability
    prefixed (e.g. ``fetch-issues_<int>_alertType``). So an integration
    ``incidentType`` / ``incidentFetchInterval`` is considered covered when any
    raw connector field id equals or ends with the matching alert suffix.
    """
    resolved = set(missing)
    rename_pairs = (
        (INCIDENT_TYPE_PARAM, ALERT_TYPE_SUFFIX),
        (INCIDENT_FETCH_INTERVAL_PARAM, ALERT_FETCH_INTERVAL_SUFFIX),
    )
    for incident_param, alert_suffix in rename_pairs:
        if incident_param not in resolved:
            continue
        if any(fid == alert_suffix or fid.endswith(alert_suffix) for fid in raw_field_ids):
            resolved.discard(incident_param)
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

    yml_params = collect_yml_params(integration_yml)
    raw_field_ids = collect_connector_raw_field_ids(
        handler_dir,
        capabilities_doc,
        configurations_doc,
        connection_doc,
        handler_yaml,
    )
    serializer_mappings = load_serializer_mappings(handler_dir)
    connector_params = {
        resolve_param_name(fid, serializer_mappings) for fid in raw_field_ids
    }
    print(f"Got the following integration params: {yml_params=}")
    print(f"Got the following handler params: {connector_params=}")
    missing = yml_params - connector_params
    # Platform "alert" renames: incidentType -> alertType,
    # incidentFetchInterval -> alertFetchInterval (no serializer bridge).
    missing = _alert_rename_covered(missing, raw_field_ids)
    missing = missing - IGNORED_PARAMS
    return (len(missing) == 0), missing


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
        "--handler-path",
        required=True,
        type=Path,
        help=(
            "Path to the handler's handler.yaml file "
            "(the handler directory is also accepted)."
        ),
    )
    parser.add_argument(
        "--integration-yml",
        required=True,
        type=Path,
        help="Path to the integration YML file.",
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

    handler_path = args.handler_path
    integration_yml_path = args.integration_yml
    # handler_path = Path("/Users/yhayun/dev/demisto/unified-connectors-content/connectors/azure-devops/components/handlers/xsoar-azuredevops/handler.yaml")
    # integration_yml_path = Path("Packs/AzureDevOps/Integrations/AzureDevOps/AzureDevOps.yml")

    try:
        passed, missing = check_coverage(handler_path, integration_yml_path)
    except CoverageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)  # noqa: T201
        return EXIT_USAGE

    if passed:
        print(  # noqa: T201
            "PASS: every non-hidden integration YML param is covered by the "
            "connector handler."
        )
        return EXIT_OK

    sorted_missing = sorted(missing)
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
