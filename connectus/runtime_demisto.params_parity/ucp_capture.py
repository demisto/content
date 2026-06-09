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

import atexit
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from typing import Any

import demisto_client
import requests
from demisto_client.demisto_api.rest import ApiException
from dotenv import load_dotenv

from xsoar_capture import (
    PARAM_TYPE_SHORT_TEXT,
    PARITY_DUMP_PARAM_KEY,
    PARITY_DUMP_PARAM_VALUE,
    REQUEST_TIMEOUT,
    get_instances_by_brand,
    get_integration_config,
    run_test_module_and_capture_params,
)

load_dotenv()

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
DEFAULT_UCP_PORT = int(os.getenv("UCP_PORT", "8080"))

DEFAULT_GKE_ZONE = "us-central1-f"
DEFAULT_K8S_NAMESPACE = "xdr-st"


def _ucp_base_url(port: int) -> str:
    return f"http://localhost:{port}/api/v1"


# ============================================================================
# Port-Forward Management
# ============================================================================

#: Singleton handle to the kubectl port-forward subprocess. Set by
#: :func:`start_port_forward`, torn down by :func:`stop_port_forward` (also
#: registered as an ``atexit`` hook).
_port_forward_proc: subprocess.Popen | None = None


def _cleanup_port_forward() -> None:
    """Terminate the port-forward subprocess if it's still running."""
    global _port_forward_proc
    if _port_forward_proc and _port_forward_proc.poll() is None:
        _port_forward_proc.terminate()
        try:
            _port_forward_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _port_forward_proc.kill()
        log.info("Port-forward stopped.")
    _port_forward_proc = None


# Idempotent atexit registration — multiple callers calling start_port_forward
# only register one cleanup hook.
atexit.register(_cleanup_port_forward)


def _wait_for_port(port: int, timeout: int = 30) -> bool:
    """Wait until ``localhost:port`` accepts a TCP connection (poll loop)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def start_port_forward(
    tenant_id: str,
    port: int = DEFAULT_UCP_PORT,
    gke_zone: str = DEFAULT_GKE_ZONE,
    k8s_namespace: str = DEFAULT_K8S_NAMESPACE,
) -> None:
    """Discover the UCP shell pod for ``tenant_id`` and start a kubectl port-forward.

    The call is blocking until the local port becomes reachable. On success,
    the subprocess is kept alive in :data:`_port_forward_proc` and the
    :func:`atexit` hook tears it down on interpreter exit. Calling this
    multiple times tears down any previous port-forward first.

    Raises:
        RuntimeError: if ``gcloud`` or ``kubectl`` is unavailable, if the pod
            cannot be located, or if the local port does not become reachable
            within 30 seconds.
    """
    global _port_forward_proc

    # Tear down any prior port-forward to keep state clean.
    _cleanup_port_forward()

    gke_project = f"qa2-test-{tenant_id}"
    gke_cluster = f"cluster-{tenant_id}"
    k8s_app_label = f"xdr-st-{tenant_id}-unified-connector-shell"

    log.info("Getting GKE credentials for cluster %s (project %s)...", gke_cluster, gke_project)
    result = subprocess.run(
        [
            "gcloud", "container", "clusters", "get-credentials",
            gke_cluster, "--zone", gke_zone, "--project", gke_project,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Failed to get GKE credentials:\n{}".format(result.stderr))
    log.info("GKE credentials configured.")

    log.info("Starting port-forward (localhost:%d → shell pod:%d)...", port, port)
    pod_result = subprocess.run(
        [
            "kubectl", "get", "pod",
            "--namespace", k8s_namespace,
            f"--selector=app={k8s_app_label}",
            "--output", "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True,
        text=True,
    )
    if pod_result.returncode != 0 or not pod_result.stdout.strip():
        raise RuntimeError("Failed to find UCP shell pod:\n{}".format(pod_result.stderr))

    pod_name = pod_result.stdout.strip()
    log.info("Pod: %s", pod_name)

    _port_forward_proc = subprocess.Popen(
        [
            "kubectl", "port-forward",
            "--namespace", k8s_namespace,
            pod_name,
            f"{port}:{port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # Re-install SIGINT/SIGTERM handlers so Ctrl-C cleanly tears down the port-forward.
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    if not _wait_for_port(port):
        stderr = _port_forward_proc.stderr.read().decode() if _port_forward_proc.stderr else ""
        raise RuntimeError("Port-forward did not become ready within 30s.\n{}".format(stderr))

    log.info("Port-forward ready on localhost:%d", port)


def stop_port_forward() -> None:
    """Public alias of the internal cleanup helper."""
    _cleanup_port_forward()


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
    auth_mappings: list,         # list[resolver.AuthMappingSpec]
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
           ONLY**: interpolated → the connector auth fields are set to the SAME
           values the INTEGRATION instance uses (via the Auth Details mapping);
           non-interpolated → dummy-filled (never surfaced at runtime).
        4. **Bidirectional dummy push, NEVER connector defaults.** ``instance_values``
           is the SAME dict pushed to the INTEGRATION side; it is written into the
           ``configuration`` block for every connector-declared field id. Keys the
           connector doesn't declare are skipped (→ MISSING_IN_CONNECTOR at diff).

    Args:
        creation_view: dict from :func:`get_creation_view`.
        instance_name: display name for the new UCP instance.
        capabilities: resolved ``CapabilitySpec`` list (parents + sub-capabilities).
        profiles: resolved ``ProfileSpec`` list (carry the interpolated flag).
        auth_mappings: parsed ``AuthMappingSpec`` list (xsoar leaf → connector field).
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
    config_step = creation_view["steps"][2]
    configuration: dict[str, Any] = {}
    accepted_field_ids: set[str] = set()
    scope = set(enabled_cap_ids)
    for section in config_step.get("sections", []):
        if section.get("capability_id") not in scope:
            continue
        for row in section.get("data", []):
            for field in row.get("fields", []):
                field_id = field.get("id")
                if not field_id:
                    continue
                accepted_field_ids.add(field_id)
                # NOTE: we intentionally DO NOT seed connector default_values —
                # the bidirectional-push contract forbids defaults so a silently
                # dropped param can't false-pass via server default re-injection.

    # ── 4. Bidirectional dummy push (never defaults) ──
    applied = 0
    skipped: list[str] = []
    for k, v in (instance_values or {}).items():
        if k in accepted_field_ids:
            configuration[k] = v
            applied += 1
        else:
            skipped.append(k)
    log.info(
        "Applied %d/%d instance_values to UCP configuration "
        "(skipped %d non-connector-declared fields: %s)",
        applied,
        len(instance_values or {}),
        len(skipped),
        ", ".join(sorted(skipped)) if skipped else "<none>",
    )

    # ── 3. Per-profile auth, interpolation-aware ──
    # Build a combined xsoar-leaf → connector-field map from all auth mappings.
    leaf_to_field: dict[str, str] = {}
    for am in auth_mappings:
        leaf_to_field.update(am.xsoar_to_connector_field)

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
        if prof.interpolated:
            # Set connector auth fields to the SAME values the integration uses.
            for leaf, connector_field in leaf_to_field.items():
                if connector_field in prof.field_ids and leaf in (instance_values or {}):
                    values[connector_field] = instance_values[leaf]
            # Any profile field not covered by the mapping still needs a value.
            for fid in prof.field_ids:
                values.setdefault(fid, _dummy_auth_value(fid))
        else:
            for fid in prof.field_ids:
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
        if k in conn_accepted:
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
            "origin": "RECOMMENDED",
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
) -> dict | None:
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
            connector, ALL (sub-)capabilities, profiles, and the auth mapping.
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
        The captured ``demisto.params()`` dict on success, ``None`` on any
        failure.
    """
    if not tenant_id:
        log.error("tenant_id is required (set TENANT_ID in .env or pass explicitly).")
        return None

    if connector_id is None:
        connector_id = parity_inputs.connector_id

    if instance_values is None:
        instance_values = {}

    if instance_name is None:
        instance_name = f"{(connector_id or 'connector').title()} Parity {uuid.uuid4().hex[:8]}"

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
    try:
        # 1. Port-forward
        start_port_forward(tenant_id=tenant_id, port=ucp_port)

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
            auth_mappings=parity_inputs.auth_mappings,
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
        log.info(
            "UCP instance created: id=%s name=%r status=%s",
            result.get("id"),
            result.get("name"),
            result.get("status"),
        )

        # 5. Wait for XSOAR mirror
        mirror = wait_for_xsoar_mirror(
            xsoar_client,
            xsoar_brand_name,
            excluded_instance_ids=excluded_ids,
        )
        if mirror is None:
            log.error("UCP instance was created but its XSOAR mirror never appeared.")
            return None

        # 6. Inject magic key and persist
        armed = inject_magic_key_and_persist(xsoar_client, mirror)
        if armed is None:
            log.error("Failed to arm the XSOAR-mirrored instance with the magic key.")
            return None

        # 7. Run test-module via the reused helper from xsoar_capture.
        captured = run_test_module_and_capture_params(xsoar_client, armed)
        return captured

    except Exception as e:
        log.exception("capture_ucp_params failed: %s", e)
        return None

    finally:
        # Cleanup: delete the UCP instance (which cascades to the XSOAR mirror).
        if ucp_instance_id and not keep_instance:
            log.info("Cleaning up UCP instance %s...", ucp_instance_id)
            delete_ucp_instance(ucp_instance_id, tenant_id, port=ucp_port)
        elif keep_instance:
            log.info("keep_instance=True — leaving UCP instance %s alive for inspection", ucp_instance_id)
        stop_port_forward()


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
    "inject_magic_key_and_persist",
    "start_port_forward",
    "stop_port_forward",
    "wait_for_xsoar_mirror",
]
