"""ucp_capture — reusable UCP-side params capture for the param-parity test.

This module exposes the "new-side" capture flow used by the connectus param-parity
test. It creates a connector instance via the UCP Shell API, waits for the
XSOAR-mirrored instance to appear, arms it with the ``__params_parity_dump__``
magic key, and triggers ``test-module`` so the CommonServerPython probe (in
:file:`Packs/Base/Scripts/CommonServerPython/CommonServerPython.py`) fires and
emits the params dump.

The top-level entry point is :func:`capture_ucp_params`.

The payload builder (:func:`_build_instance_payload`) is generic: it is driven
by a resolved :class:`resolver.ParityInputs` and enables ALL (sub-)capabilities
the handler subscribes to, sets auth per profile (same-value when the profile is
interpolated, dummy otherwise), and pushes the SAME instance/dummy values to the
connector side that the integration side uses (never connector defaults).

UCP Shell API access requires:
    * ``gcloud`` CLI authenticated.
    * ``kubectl`` available on PATH.
    * Slack-channel permission grant for the target GKE project
      (see ``#xdr-permissions-dev``).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from typing import Any

import demisto_client
import requests
from demisto_client.demisto_api.rest import ApiException

from xsoar_capture import (
    PARAM_TYPE_SHORT_TEXT,
    PARITY_DUMP_PARAM_KEY,
    PARITY_DUMP_PARAM_VALUE,
    REQUEST_TIMEOUT,
    get_instances_by_brand,
    get_integration_config,
    run_test_module_and_capture_params,
)

# Make the shared connectus env loader importable (connectus/ is not a package).
from pathlib import Path as _Path  # noqa: E402

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402
import session_env  # noqa: E402  (single session/env authority; owns the port-forward)

# Load the canonical root .env via the single unified loader.
load_env()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ucp_capture")

# ============================================================================
# UCP / GKE connection defaults (sourced from .env when caller does not override)
# ============================================================================

# The tenant for UCP-side work — the SAME single tenant deploy.py uses. One
# tenant per shell; deploy and the UCP capture MUST target it, so there is ONE
# var (TENANT_ID) and no comma-splitting.
DEFAULT_TENANT_ID = os.getenv("TENANT_ID", "")
# Legacy/ad-hoc only: resolver-driven runs derive the connector id. Kept for
# create_ucp_instance.py standalone usage.
DEFAULT_UCP_PORT = 8080

DEFAULT_GKE_ZONE = "us-central1-f"
DEFAULT_K8S_NAMESPACE = "xdr-st"


def _ucp_base_url(port: int) -> str:
    return f"http://localhost:{port}/api/v1"


# ============================================================================
# Session assumption (port-forward is owned by session_setup, not here)
# ============================================================================
#
# Per SESSION_ENV_ARCHITECTURE.md (FINAL): the UCP capture no longer establishes
# the environment. The kubectl port-forward + GKE credentials are set up ONCE by
# the human-run ``session_setup.py`` and tracked in a session descriptor. This
# module simply ASSUMES a live session (via ``session_env.assert_session_live``,
# which auto-revives a dead tunnel and hard-stops only on gcloud-auth expiry).
#
# The old start_port_forward / stop_port_forward / _wait_for_port / atexit /
# signal machinery has been removed.


# ============================================================================
# UCP Shell API Calls
# ============================================================================


def get_creation_view(
    connector_id: str,
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
) -> dict:
    """Call ``GET /api/v1/gateway/connectors/<id>/creation`` on UCP.

    The creation view contains the pre-allocated ``instance_id``, the list of
    available capabilities, the connection methods for each capability, and
    the default values for every configuration field.

    Raises:
        RuntimeError: if UCP returns a non-200 response.
        ConnectionError: if the local port-forward is not active.
    """
    url = f"{_ucp_base_url(port)}/gateway/connectors/{connector_id}/creation"
    resp = requests.get(url, headers={"x-tenant-id": tenant_id})
    if resp.status_code != 200:
        raise RuntimeError(
            "GET {} failed with status {}: {}".format(url, resp.status_code, resp.text)
        )
    return resp.json()


def create_ucp_instance(
    payload: dict,
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
) -> dict:
    """Call ``POST /api/v1/instances`` on UCP with the given payload.

    Returns:
        The parsed response dict on success (HTTP 201).

    Raises:
        RuntimeError: on any non-201 response.
    """
    url = f"{_ucp_base_url(port)}/instances"
    resp = requests.post(
        url,
        headers={"x-tenant-id": tenant_id, "Content-Type": "application/json"},
        json=payload,
    )
    if resp.status_code != 201:
        raise RuntimeError(
            "POST {} failed with status {}: {}".format(url, resp.status_code, resp.text)
        )
    return resp.json()


def delete_ucp_instance(
    instance_id: str,
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
) -> bool:
    """Call ``DELETE /api/v1/instances/<id>`` on UCP. Best-effort.

    Returns:
        ``True`` on HTTP 204, ``False`` otherwise. Does not raise — used in
        ``finally`` cleanup paths where we don't want a cleanup failure to
        mask the real error.
    """
    url = f"{_ucp_base_url(port)}/instances/{instance_id}"
    try:
        resp = requests.delete(url, headers={"x-tenant-id": tenant_id})
    except Exception as e:
        log.error("DELETE %s raised: %s", url, e)
        return False
    if resp.status_code == 204:
        log.info("UCP instance %s deleted.", instance_id)
        return True
    log.error("DELETE %s returned status %s: %s", url, resp.status_code, resp.text)
    return False


def get_ucp_instance(
    instance_id: str,
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
) -> dict | None:
    """GET ``{base}/instances/<id>`` on UCP. Returns the parsed body on HTTP 200,
    else ``None``.

    Best-effort verification helper — never raises (a non-200 or transport error
    just yields ``None``, so callers can fall back to the list route or treat it
    as "not found"). NOTE: this single-instance GET route is NOT documented; it
    mirrors the DELETE route shape and may not exist, hence the defensiveness.
    """
    url = f"{_ucp_base_url(port)}/instances/{instance_id}"
    try:
        resp = requests.get(url, headers={"x-tenant-id": tenant_id})
    except Exception as e:
        log.warning("GET %s raised: %s", url, e)
        return None
    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            return None
    log.warning("GET %s returned status %s: %s", url, resp.status_code, resp.text[:300])
    return None


def list_ucp_instances(
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
) -> list | None:
    """GET ``{base}/instances`` on UCP. Returns the parsed list on HTTP 200, else
    ``None``.

    Best-effort — never raises. Used as a fallback to verify a created instance
    exists when the single-instance GET route is unavailable. Accepts either a
    bare JSON list or a wrapper dict (``{"instances": [...]}`` / ``{"data": [...]}``
    / ``{"items": [...]}``) since the list response shape is undocumented.
    """
    url = f"{_ucp_base_url(port)}/instances"
    try:
        resp = requests.get(url, headers={"x-tenant-id": tenant_id})
    except Exception as e:
        log.warning("GET %s raised: %s", url, e)
        return None
    if resp.status_code == 200:
        try:
            data = resp.json()
        except Exception:
            return None
        # Accept either a bare list or a wrapped {"instances":[...]} / {"data":[...]}.
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("instances", "data", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        return None
    log.warning("GET %s returned status %s: %s", url, resp.status_code, resp.text[:300])
    return None


def verify_ucp_instance_created(
    *,
    creation_view_id: str,
    post_response: dict,
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
) -> dict:
    """Verify a just-created UCP instance ACTUALLY exists (a 201 alone has been
    observed to not guarantee the instance shows up).

    Tries, in order: GET ``{base}/instances/<post_response.id>``, then
    GET ``{base}/instances/<creation_view_id>``, then the list route filtered by
    either id. Logs the POST-response id vs the creation-view id (they may
    differ) and the instance's reported status.

    Returns a dict::

        {"exists": bool, "instance_id": <id or None>,
         "status": <status or None>, "via": <"get-id"|"get-creation-id"|"list"|None>}

    Never raises.
    """
    post_id = (post_response or {}).get("id")
    status = (post_response or {}).get("status")
    if post_id and creation_view_id and post_id != creation_view_id:
        log.warning(
            "UCP POST-response id (%s) DIFFERS from creation-view instance_id (%s) "
            "— cleanup/verification must use the real one.", post_id, creation_view_id,
        )
    candidates = [cid for cid in (post_id, creation_view_id) if cid]
    for cid in candidates:
        body = get_ucp_instance(cid, tenant_id, port=port)
        if body is not None:
            via = "get-id" if cid == post_id else "get-creation-id"
            return {"exists": True, "instance_id": cid,
                    "status": body.get("status", status), "via": via}
    # Fallback: list route, filter by either candidate id.
    listed = list_ucp_instances(tenant_id, port=port)
    if listed is not None:
        ids = {i.get("id") for i in listed if isinstance(i, dict)}
        for cid in candidates:
            if cid in ids:
                match = next(i for i in listed if isinstance(i, dict) and i.get("id") == cid)
                return {"exists": True, "instance_id": cid,
                        "status": match.get("status", status), "via": "list"}
    return {"exists": False, "instance_id": post_id or creation_view_id,
            "status": status, "via": None}


# ============================================================================
# XSOAR-Mirror Polling and Magic-Key Injection
# ============================================================================


def wait_for_xsoar_mirror(
    xsoar_client,
    brand_name: str,
    *,
    max_retries: int = 15,
    poll_interval: int = 3,
    excluded_instance_ids: set[str] | None = None,
) -> dict | None:
    """Poll the XSOAR API until an instance with the given brand appears.

    UCP creates an XSOAR-mirrored instance asynchronously after the
    ``POST /instances`` call returns. Polling time on the dev tenant is
    typically 5–15 seconds.

    Args:
        xsoar_client: A configured ``demisto_client`` for the XSOAR tenant.
        brand_name: The brand string (matches the integration YML ``name``,
            e.g. ``"Salesforce IAM"``).
        max_retries: Number of polling attempts.
        poll_interval: Seconds between polls.
        excluded_instance_ids: Optional set of instance ids to ignore
            (use when there are pre-existing instances of the same brand
            from previous runs and we only want the *new* one).

    Returns:
        The first matching instance dict, or ``None`` if no match appeared
        within ``max_retries * poll_interval`` seconds.
    """
    excluded_instance_ids = excluded_instance_ids or set()
    log.info("Polling XSOAR for mirrored instance of brand %r...", brand_name)
    for attempt in range(1, max_retries + 1):
        try:
            instances = get_instances_by_brand(xsoar_client, brand_name)
        except Exception as e:
            log.warning("XSOAR poll attempt %d/%d raised: %s", attempt, max_retries, e)
            instances = []

        new_instances = [i for i in instances if i.get("id") not in excluded_instance_ids]
        if new_instances:
            chosen = new_instances[0]
            log.info(
                "Found XSOAR mirror after %d attempt(s): id=%s name=%r",
                attempt,
                chosen.get("id"),
                chosen.get("name"),
            )
            return chosen
        if attempt < max_retries:
            time.sleep(poll_interval)

    log.error(
        "No XSOAR mirror appeared for brand %r within %d attempts",
        brand_name,
        max_retries,
    )
    return None


def inject_magic_key_and_persist(
    xsoar_client,
    mirrored_instance: dict,
    *,
    refresh_configuration: bool = True,
) -> dict | None:
    """Mutate the XSOAR-mirrored instance to add the ``__params_parity_dump__`` magic
    param and PUT it back to the server so the next test-module fires the probe.

    UCP delivers a normal-looking instance to XSOAR; it doesn't know about our
    magic key. We need to add the key to ``instance["data"]`` and persist the
    mutation, then the standard ``/settings/integration/test`` endpoint will
    cause the integration container to receive the magic key in
    ``demisto.params()`` and the probe will fire.

    Args:
        xsoar_client: A configured ``demisto_client``.
        mirrored_instance: The instance dict returned by
            :func:`wait_for_xsoar_mirror`.
        refresh_configuration: When ``True``, re-fetches the server's
            integration config schema and re-attaches it to the instance dict
            (UCP-mirrored instances often arrive without a fully-populated
            ``configuration`` field, which the PUT endpoint requires).

    Returns:
        The updated instance dict (suitable for passing into
        :func:`run_test_module_and_capture_params`), or ``None`` on failure.
    """
    instance = dict(mirrored_instance)
    brand = instance.get("brand", "")
    instance_name = instance.get("name", "<unknown>")
    instance_id = instance.get("id", "")

    if refresh_configuration:
        server_config = get_integration_config(xsoar_client, brand)
        if server_config is None:
            log.error(
                "Cannot refresh configuration schema for brand %r — "
                "the integration is not installed on the tenant.",
                brand,
            )
            return None
        instance["configuration"] = server_config

    data = list(instance.get("data") or [])

    # Drop any pre-existing magic-key entry (from a prior aborted run) and re-add.
    data = [entry for entry in data if entry.get("name") != PARITY_DUMP_PARAM_KEY]
    data.append({
        "name": PARITY_DUMP_PARAM_KEY,
        "display": PARITY_DUMP_PARAM_KEY,
        "type": PARAM_TYPE_SHORT_TEXT,
        "value": PARITY_DUMP_PARAM_VALUE,
        "hasvalue": True,
        "required": False,
    })
    instance["data"] = data

    # PUT back to persist the mutation.
    try:
        res = demisto_client.generic_request_func(
            self=xsoar_client,
            method="PUT",
            path="/settings/integration",
            body=instance,
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
        )
    except ApiException as e:
        log.error(
            "PUT /settings/integration failed for instance %r (id=%s): %s",
            instance_name,
            instance_id,
            e,
        )
        return None

    if int(res[1]) != 200:
        log.error(
            "PUT /settings/integration returned non-200 status %s for instance %r",
            res[1],
            instance_name,
        )
        return None

    log.info("Magic key injected into XSOAR-mirrored instance %r (id=%s)", instance_name, instance_id)
    return instance


# ============================================================================
# Generic Multi-Capability Payload Builder
# ============================================================================


def _dummy_auth_value(field_id: str) -> str:
    """A guaranteed-non-empty dummy for a non-interpolated auth field."""
    return f"dummy_{field_id}"


def _dummy_config_value(field_id: str) -> str:
    """A guaranteed-non-empty dummy for a connector CONFIG field that has NO
    matching integration-YML param (an orphan / undeclared-rename field).

    Setting it (rather than omitting it) makes the orphan field present at
    runtime on the CONNECTOR side only, so the diff correctly reports it as
    EXTRA_IN_CONNECTOR instead of silently hiding it. The distinct prefix makes
    the value recognizable in the persisted creation payload during triage."""
    return f"dummy_config_{field_id}"


def _dig(source, dotted_path):
    # type: (Any, str) -> Any
    """Walk a dotted path into nested dicts; return None if any segment is
    missing or a non-dict is encountered. Generic — works for any depth."""
    cur = source
    for seg in dotted_path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return None
    return cur


#: Engine-related connector field ids that get the canonical "no engine" values
#: in the UCP payload (see _ENGINE_FIELD_VALUES). Pushing a dummy value
#: (e.g. engine="dummy_engine") makes UCP reject instance creation ("engine with
#: id [dummy_engine] does not exist"); the real UI payload INCLUDES these fields
#: set to no_engine/null/null, keeping the instance on "No Engine".
_ENGINE_FIELD_IDS: frozenset[str] = frozenset({"engine", "engine_group", "engineGroup", "engine_mode"})

#: Canonical "no engine" values the platform sends for engine fields. Setting
#: these (rather than omitting, or sending a dummy which UCP rejects) matches the
#: real UI payload and keeps the instance on "No Engine".
_ENGINE_FIELD_VALUES = {"engine_mode": "no_engine", "engine": None, "engine_group": None}


def _applied_for_method_ids(
    creation_view: dict, capability_id: str, profile_id: str
) -> list[str]:
    """Connection-method unique ids supporting ``(capability_id, profile_id)``."""
    connection_step = creation_view["steps"][1]
    applied_for: list[str] = []
    for method in connection_step.get("methods", []):
        if method.get("capability_id") != capability_id:
            continue
        for opt in method.get("options", []):
            if opt.get("profile_id") == profile_id:
                applied_for.append(method["method_unique_id"])
                break
    return applied_for


def _build_instance_payload(
    creation_view: dict,
    *,
    instance_name: str,
    capabilities: list,          # list[resolver.CapabilitySpec]
    profiles: list,              # list[resolver.ProfileSpec]
    instance_values: dict[str, Any],
    connector_id: str,
) -> dict:
    """Build the POST /instances payload for ANY connector from resolved inputs.

    Generalizes the old Salesforce-only builder per the "REVISED MULTI-CAPABILITY
    + AUTH-MAPPING DESIGN" in ``plans/param-parity-pipeline-integration.md``.

    Contract:
        1. **Enable ALL (sub-)capabilities** the handler subscribes to — every
           parent ``CapabilitySpec.id`` with its subscribed ``sub_capabilities``.
           A handler may subscribe to several (e.g. automation AND fetch-secrets).
        2. **Configuration scope = union over all enabled (sub-)capabilities.**
        3. **Auth per profile, interpolation from ``ProfileSpec.interpolated``
           ONLY**: interpolated → each connector auth field whose role appears in
           the profile's ``interpolation_mapping`` is set to the SAME value the
           INTEGRATION instance uses (looked up by the field's xsoar top-level
           param); fields not covered by the mapping fall back to a dummy.
           Non-interpolated → dummy-filled (never surfaced at runtime).
        4. **Bidirectional dummy push, NEVER connector defaults.** ``instance_values``
           is the SAME dict pushed to the INTEGRATION side; it is written into the
           ``configuration`` block for every connector-declared field id. Keys the
           connector doesn't declare are skipped (→ MISSING_IN_CONNECTOR at diff).

    Args:
        creation_view: dict from :func:`get_creation_view`.
        instance_name: display name for the new UCP instance.
        capabilities: resolved ``CapabilitySpec`` list (parents + sub-capabilities).
        profiles: resolved ``ProfileSpec`` list (carry the interpolation mapping
            from which the auth-field ↔ xsoar param mapping is derived).
        instance_values: the shared dummy/instance value dict (xsoar param ids →
            values) pushed to BOTH sides.
        connector_id: the UCP connector id.

    Returns:
        The fully-formed POST payload dict.

    Raises:
        RuntimeError: if the creation view doesn't expose a requested capability,
            or no connection method supports an enabled (capability, profile) pair.
    """
    instance_id = creation_view["instance_id"]

    # ── 1. Enable ALL (sub-)capabilities ──
    capabilities_step = creation_view["steps"][0]
    available_caps = {c["id"] for c in capabilities_step.get("capabilities", [])}
    enabled_values: dict[str, list[str]] = {}
    enabled_cap_ids: list[str] = []
    for cap in capabilities:
        if cap.id not in available_caps:
            raise RuntimeError(
                "Capability {!r} not in creation view (available: {})".format(
                    cap.id, sorted(available_caps)
                )
            )
        sub_ids = [sc.id for sc in cap.sub_capabilities if getattr(sc, "enabled", True)]
        enabled_values[cap.id] = sub_ids
        enabled_cap_ids.append(cap.id)
        # The (sub-)capability ids also participate in the configuration scope.
        enabled_cap_ids.extend(sub_ids)

    # ── 2. Configuration scope = union over all enabled (sub-)capabilities ──
    #
    # SOURCE OF TRUTH = the CONNECTOR MANIFEST (configurations.yaml), NOT the
    # live `GET /creation` view. The resolver already parsed every config field
    # id declared for each enabled (sub-)capability into
    # ``CapabilitySpec.config_field_ids`` (scoped to BOTH parent and sub ids).
    # The connector field ids it yields are exactly the keys the configuration
    # block must carry — and they already account for serializer field_mappings
    # because ``instance_values`` is pre-keyed by connector field id upstream
    # (see check_param_parity._build connector_instance_values).
    #
    # We previously derived ``accepted_field_ids`` from
    # ``creation_view["steps"][2].sections``; that made the configuration block
    # collapse to ``{}`` whenever the live creation view's step shape didn't
    # match (e.g. capability-gated fields not yet deployed on the tenant, a
    # different section-key shape, or step-index drift) — silently dropping every
    # behavioral param. The manifest is the authoritative declaration of what the
    # connector accepts, so we trust it and use the creation view only as a
    # logged cross-check below.
    configuration: dict[str, Any] = {}
    accepted_field_ids: set[str] = set()
    for cap in capabilities:
        accepted_field_ids.update(getattr(cap, "config_field_ids", None) or set())

    # Logged cross-check (non-fatal): compare the manifest-declared field ids to
    # what the live creation view exposes for the enabled (sub-)capabilities, so
    # UCP-side schema drift is visible without zeroing the configuration block.
    try:
        config_step = creation_view["steps"][2]
        scope = set(enabled_cap_ids)
        creation_view_field_ids: set[str] = set()
        for section in config_step.get("sections", []) or []:
            if section.get("capability_id") not in scope:
                continue
            for row in section.get("data", []) or []:
                for field in row.get("fields", []) or []:
                    fid = field.get("id")
                    if fid:
                        creation_view_field_ids.add(fid)
        only_in_manifest = accepted_field_ids - creation_view_field_ids
        only_in_creation_view = creation_view_field_ids - accepted_field_ids
        if only_in_manifest:
            log.warning(
                "Config fields declared in the connector manifest but ABSENT from "
                "the live creation view (kept anyway — likely not-yet-deployed / "
                "capability-gated on this tenant): %s",
                ", ".join(sorted(only_in_manifest)),
            )
        if only_in_creation_view:
            log.info(
                "Config fields present in the live creation view but NOT declared "
                "in the connector manifest (ignored — manifest is authoritative): %s",
                ", ".join(sorted(only_in_creation_view)),
            )
    except Exception as e:  # pragma: no cover - cross-check must never break the build
        log.debug("Creation-view config cross-check skipped: %s", e)

    # ── 4. Bidirectional push — SET EVERY manifest-declared config field ──
    #
    # CONTRACT (USER-CONFIRMED): every field the connector declares (here, the
    # per-(sub-)capability ``configurations.yaml`` fields) MUST be set in the
    # creation payload so it is present at runtime and participates in the diff.
    # Two cases per connector field id:
    #
    #   (a) It has a matching integration-YML param — ``instance_values`` carries
    #       a value under that connector field id (the upstream
    #       ``connector_instance_values`` builder already keyed serializer-renamed
    #       and identity fields by CONNECTOR field id). Set the SAME value the
    #       integration side uses → parity OK.
    #
    #   (b) It has NO integration-YML match (an orphan connector field, e.g. one
    #       whose rename is not declared in the serializer ``field_mappings``).
    #       Set a DUMMY value so the field shows up at runtime ONLY on the
    #       connector side → correctly fails as EXTRA_IN_CONNECTOR, surfacing the
    #       orphan/undeclared-rename instead of hiding it.
    #
    # The bidirectional-push contract forbids seeding connector default_values, so
    # a silently dropped param can't false-pass via server default re-injection.
    matched: list[str] = []
    orphan: list[str] = []
    for fid in sorted(accepted_field_ids):
        if fid in (instance_values or {}):
            configuration[fid] = instance_values[fid]
            matched.append(fid)
        else:
            configuration[fid] = _dummy_config_value(fid)
            orphan.append(fid)

    # instance_values keys that are NOT connector config fields (e.g. auth/profile
    # params, connection-general fields) are handled by other blocks; log them.
    non_config = [k for k in (instance_values or {}) if k not in accepted_field_ids]
    log.info(
        "UCP configuration: %d manifest-declared fields set "
        "(%d matched an integration param, %d orphan→dummy→EXTRA_IN_CONNECTOR: %s). "
        "%d instance_values not config fields (handled elsewhere: %s).",
        len(accepted_field_ids),
        len(matched),
        len(orphan),
        ", ".join(orphan) if orphan else "<none>",
        len(non_config),
        ", ".join(sorted(non_config)) if non_config else "<none>",
    )

    # ── 3. Per-profile auth, interpolation-aware ──
    profile_payloads: list[dict] = []
    for prof in profiles:
        # Which connection methods bind this profile (across all enabled caps)?
        applied_for: list[str] = []
        for cap_id in enabled_values:
            applied_for.extend(_applied_for_method_ids(creation_view, cap_id, prof.id))
        applied_for = list(dict.fromkeys(applied_for))  # de-dupe, preserve order
        if not applied_for:
            log.warning(
                "No connection method supports profile %r for any enabled capability; "
                "skipping it from the payload.",
                prof.id,
            )
            continue

        values: dict[str, Any] = {}
        # The connector-field → FULL xsoar destination PATH map is derived from
        # the profile's interpolation_mapping (role → xsoar path) + the fields'
        # metadata.auth.parameter (field id → role). The FULL dotted path lets us
        # dig the exact LEAF scalar out of the shared instance_values (e.g.
        # credentials_username → credentials.identifier → instance_values
        # ["credentials"]["identifier"]). For a NON-interpolated profile this is
        # {}, so auth fields fall through to a dummy.
        field_to_path = prof.connector_field_to_xsoar_path() if prof.interpolated else {}
        for fid in prof.field_ids:
            if fid in _ENGINE_FIELD_IDS:
                # Engine fields: include with canonical "no engine" values as the
                # UI does (no_engine / null / null), NOT skipped — a dummy here
                # makes UCP reject creation.
                values[fid] = _ENGINE_FIELD_VALUES.get(fid, None)
                continue
            is_auth_field = fid in prof.auth_field_to_role
            if is_auth_field:
                # Auth field: interpolated → the LEAF scalar dug from the shared
                # instance_values at the field's FULL xsoar path; else a dummy.
                dest_path = field_to_path.get(fid)
                leaf = _dig(instance_values, dest_path) if dest_path else None
                if leaf is not None:
                    values[fid] = leaf
                else:
                    # Field not covered by the mapping, missing leaf, or
                    # non-interpolated → dummy.
                    values[fid] = _dummy_auth_value(fid)
            else:
                # Non-auth profile CONFIG field (e.g. defaultRegion, retries,
                # insecure, proxy, timeout, sts_regional_endpoint). Push the SAME
                # shared value the integration side received (keyed by field id ==
                # xsoar param name for these); fall back to a dummy only if absent.
                if fid in (instance_values or {}):
                    values[fid] = instance_values[fid]
                else:
                    values[fid] = _dummy_auth_value(fid)

        profile_payloads.append(
            {
                "profile_id": prof.id,
                "type": prof.type or prof.id.split(".")[0],
                "applied_for": applied_for,
                "values": values,
            }
        )

    # Connection-level general configuration: push the shared values for any
    # connection-general field the connector declares (filtered the same way the
    # configuration block is — unknown keys are skipped).
    connection_general: dict[str, Any] = {}
    connection_step = creation_view["steps"][1]
    conn_accepted: set[str] = set()
    for section in connection_step.get("sections", []) or []:
        for row in section.get("data", []) or []:
            for field in row.get("fields", []) or []:
                fid = field.get("id")
                if fid:
                    conn_accepted.add(fid)
    for k, v in (instance_values or {}).items():
        if k in conn_accepted and k not in _ENGINE_FIELD_IDS:
            connection_general[k] = v

    return {
        "instance_id": instance_id,
        "connector_id": connector_id or creation_view.get("connector_id") or "",
        "capabilities": {
            "general_configurations": {"instance_name": instance_name},
            # ALL parents + their subscribed sub-capabilities.
            "values": enabled_values,
        },
        "connection": {
            "origin": "GROUPED",
            "general_configurations": connection_general,
            "profiles": profile_payloads,
        },
        "configuration": configuration,
    }


# ============================================================================
# Top-Level Capture
# ============================================================================


def capture_ucp_params(
    *,
    xsoar_client,
    xsoar_brand_name: str,
    parity_inputs,                       # resolver.ParityInputs
    instance_values: dict | None = None,
    connector_id: str | None = None,
    tenant_id: str = DEFAULT_TENANT_ID,
    instance_name: str | None = None,
    ucp_port: int = DEFAULT_UCP_PORT,
    keep_instance: bool = False,
) -> tuple[dict | None, dict | None]:
    """Run the full UCP-side capture flow end-to-end.

    Workflow:
        1. Start a kubectl port-forward to the UCP shell pod.
        2. Snapshot existing XSOAR instances of the target brand so we can
           later identify the *new* mirrored instance.
        3. GET the creation view from UCP.
        4. Build the POST payload via :func:`_build_instance_payload`
           (enables ALL handler (sub-)capabilities; per-profile auth).
        5. POST the payload to create the UCP instance.
        6. Poll XSOAR for the mirrored instance to appear.
        7. Inject the ``__params_parity_dump__`` magic key into the mirrored
           instance and persist via PUT.
        8. Run ``test-module`` and parse the probe's payload.
        9. Tear down the UCP instance (unless ``keep_instance=True``).
       10. Stop the port-forward.

    Args:
        xsoar_client: A configured ``demisto_client`` for the XSOAR tenant.
        xsoar_brand_name: Brand of the XSOAR-mirrored integration
            (e.g. ``"Salesforce IAM"``).
        parity_inputs: The resolved :class:`resolver.ParityInputs` describing the
            connector, ALL (sub-)capabilities, and profiles (which carry the
            interpolation mapping the auth-field values are derived from).
        instance_values: The SHARED dummy/instance value dict (xsoar param ids →
            values) pushed to BOTH the integration and connector sides. Empty if
            not provided.
        connector_id: UCP connector id. Defaults to ``parity_inputs.connector_id``.
        tenant_id: UCP tenant id.
        instance_name: Display name for the new UCP instance. Auto-generated
            with a uuid suffix if not provided.
        ucp_port: Local port to bind the port-forward to.
        keep_instance: When ``True``, the UCP instance is NOT deleted on
            success — useful for debugging.

    Returns:
        A 2-tuple ``(captured, payload)``:

        * ``captured`` — the captured ``demisto.params()`` dict on success, or
          ``None`` on any failure.
        * ``payload`` — the UCP-side instance-creation payload (the dict built
          by :func:`_build_instance_payload` and POSTed to ``/instances``).
          Surfaced in the persisted results envelope for debugging. It is
          ``None`` when the flow fails BEFORE the payload is built (e.g. missing
          ``tenant_id``, or a port-forward / creation-view error); otherwise it
          is returned even on later failures so the attempted payload is
          recoverable.
    """
    if not tenant_id:
        log.error("tenant_id is required (set TENANT_ID in .env or pass explicitly).")
        return None, None

    if connector_id is None:
        connector_id = parity_inputs.connector_id

    if instance_values is None:
        instance_values = {}

    if instance_name is None:
        instance_name = f"Connector_instance_for_{(connector_id).title()}_runtime_parity_{uuid.uuid4().hex[:8]}"

    # Snapshot existing XSOAR instances so we can identify only the NEW mirror.
    try:
        pre_existing = get_instances_by_brand(xsoar_client, xsoar_brand_name)
        excluded_ids = {inst.get("id") for inst in pre_existing if inst.get("id")}
        log.info(
            "Pre-existing XSOAR instances of brand %r: %d (will be excluded from mirror lookup)",
            xsoar_brand_name,
            len(excluded_ids),
        )
    except Exception as e:
        log.warning(
            "Could not snapshot pre-existing XSOAR instances (%s); will accept any matching brand.",
            e,
        )
        excluded_ids = set()

    ucp_instance_id: str | None = None
    captured: dict | None = None
    # The UCP creation payload — built inside the try AFTER the port-forward +
    # creation view. Initialized here so it's always defined for the return
    # contract (it stays None if a failure happens before it's built).
    payload: dict | None = None
    try:
        # 1. ASSUME a live session (port-forward + GKE creds established once by
        #    the human-run session_setup.py). This auto-revives a dead tunnel and
        #    raises SessionNotReady only when gcloud auth expired / no session.
        _desc = session_env.assert_session_live()
        ucp_port = _desc.ucp_port  # the descriptor is the source of truth for the port

        # 2. Creation view
        log.info("Fetching creation view for connector=%r, tenant=%r", connector_id, tenant_id)
        creation_view = get_creation_view(connector_id, tenant_id, port=ucp_port)
        ucp_instance_id = creation_view["instance_id"]

        # 3. Build payload (generic, resolver-driven).
        # The shared `instance_values` dict is pushed to the connector's
        # configuration + (interpolated) auth fields, ensuring the connector
        # delivers the SAME values the INTEGRATION side uses. This eliminates the
        # test-setup-asymmetry false positives in the diff and leaves only real
        # connector bugs visible. ALL handler (sub-)capabilities are enabled.
        payload = _build_instance_payload(
            creation_view,
            instance_name=instance_name,
            capabilities=parity_inputs.capabilities,
            profiles=parity_inputs.profiles,
            instance_values=instance_values,
            connector_id=connector_id,
        )
        log.info(
            "UCP payload built: connector=%s capabilities=%s profiles=%s, configuration fields=%d",
            connector_id,
            [c.id for c in parity_inputs.capabilities],
            [p.id for p in parity_inputs.profiles],
            len(payload["configuration"]),
        )
        log.debug("Full payload: %s", json.dumps(payload, indent=2, default=str))

        # 4. Create UCP instance
        result = create_ucp_instance(payload, tenant_id, port=ucp_port)
        # Prefer the POST-response id for cleanup/verification (the pre-allocated
        # creation-view id is not guaranteed to be the created instance's id).
        if result.get("id"):
            ucp_instance_id = result["id"]
        log.info(
            "UCP instance created: id=%s name=%r status=%s instance_name=%r",
            result.get("id"),
            result.get("name"),
            result.get("status"),
            instance_name,
        )

        # 4b. VERIFY the instance actually exists (a 201 alone has been observed
        # not to guarantee creation — confirmed missing from the UI). Fail fast
        # with an accurate message instead of waiting ~42s for a mirror that will
        # never appear.
        verify = verify_ucp_instance_created(
            creation_view_id=creation_view["instance_id"],
            post_response=result,
            tenant_id=tenant_id,
            port=ucp_port,
        )
        if not verify["exists"]:
            log.error(
                "UCP returned 201 but the instance could not be retrieved afterward "
                "(GET/list found nothing for id=%s) — the instance was not actually "
                "created. Check the UCP shell pod logs and the POST payload.",
                verify["instance_id"],
            )
            return None, payload
        log.info(
            "Verified UCP instance exists: id=%s status=%s (via %s)",
            verify["instance_id"],
            verify["status"],
            verify["via"],
        )

        # 5. Wait for XSOAR mirror
        mirror = wait_for_xsoar_mirror(
            xsoar_client,
            xsoar_brand_name,
            excluded_instance_ids=excluded_ids,
        )
        if mirror is None:
            log.error("UCP instance was created but its XSOAR mirror never appeared.")
            return None, payload

        # 6. Inject magic key and persist
        armed = inject_magic_key_and_persist(xsoar_client, mirror)
        if armed is None:
            log.error("Failed to arm the XSOAR-mirrored instance with the magic key.")
            return None, payload

        # 7. Run test-module via the reused helper from xsoar_capture.
        captured = run_test_module_and_capture_params(xsoar_client, armed)
        return captured, payload

    except session_env.SessionNotReady:
        # Session needs human action (gcloud auth expired / not set up). Let it
        # propagate so the caller maps it to exit 11 (BLOCKED) with the exact
        # human-actionable message — do NOT swallow it as a generic failure.
        raise

    except Exception as e:
        log.exception("capture_ucp_params failed: %s", e)
        return None, payload

    finally:
        # Cleanup: delete the UCP instance (which cascades to the XSOAR mirror).
        # NOTE: the port-forward is SESSION-SCOPED — established once by
        # session_setup.py and reused across integrations — so it is deliberately
        # NOT torn down here. session_teardown.py stops it at the end of the batch.
        if ucp_instance_id and not keep_instance:
            log.info("Cleaning up UCP instance %s...", ucp_instance_id)
            delete_ucp_instance(ucp_instance_id, tenant_id, port=ucp_port)
        elif keep_instance:
            log.info("keep_instance=True — leaving UCP instance %s alive for inspection", ucp_instance_id)


# ============================================================================
# Public re-export list.
# ============================================================================

__all__ = [
    "DEFAULT_TENANT_ID",
    "DEFAULT_UCP_PORT",
    "capture_ucp_params",
    "create_ucp_instance",
    "delete_ucp_instance",
    "get_creation_view",
    "get_ucp_instance",
    "inject_magic_key_and_persist",
    "list_ucp_instances",
    "verify_ucp_instance_created",
    "wait_for_xsoar_mirror",
]
