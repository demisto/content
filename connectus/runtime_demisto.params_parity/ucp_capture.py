"""ucp_capture — reusable UCP-side params capture for the param-parity test.

This module exposes the "new-side" capture flow used by the connectus param-parity
test. It creates a connector instance via the UCP Shell API, waits for the
XSOAR-mirrored instance to appear, arms it with the ``__params_parity_dump__``
magic key, and triggers ``test-module`` so the CommonServerPython probe (in
:file:`Packs/Base/Scripts/CommonServerPython/CommonServerPython.py`) fires and
emits the params dump.

The top-level entry point is :func:`capture_ucp_params`.

For the MVP, this module ships with a hard-coded Salesforce/Salesforce-IAM
payload builder (:func:`_build_salesforce_iam_payload`) that ONLY enables the
``automation-and-remediation`` capability — other capabilities like
``saas-posture-config-monitoring`` and ``identity`` stay disabled by design.
Generalizing the payload builder for other connectors is out of scope for the
POC.

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

DEFAULT_TENANT_ID = os.getenv("UCP_TENANT_ID", "")
DEFAULT_CONNECTOR_ID = os.getenv("UCP_CONNECTOR_ID", "salesforce")
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
# Hard-Coded Salesforce-IAM Payload Builder (MVP)
# ============================================================================


def _build_salesforce_iam_payload(
    creation_view: dict,
    *,
    instance_name: str,
    selected_capability: str,
    profile_id: str,
    domain_value: str,
    auth_values: dict,
) -> dict:
    """Build the POST /instances payload for the Salesforce / Salesforce-IAM MVP.

    Mirrors the original :file:`create_ucp_instance.py` logic but parameterized
    via the function arguments instead of module-level globals.

    Args:
        creation_view: The dict returned by :func:`get_creation_view`.
        instance_name: Display name for the new UCP instance.
        selected_capability: Capability id to enable. For the POC, callers
            must pass ``"automation-and-remediation"`` only — other
            capabilities (``saas-posture-config-monitoring``, ``identity``)
            stay disabled by design.
        profile_id: Connection profile id, e.g.
            ``"oauth2_client_credentials.salesforce"``.
        domain_value: Value for the connector's ``general_configurations.domain``
            field.
        auth_values: Profile-specific auth fields. For
            ``oauth2_client_credentials``, this is
            ``{"client_key": ..., "client_secret": ...}``.

    Returns:
        The fully-formed POST payload dict.

    Raises:
        RuntimeError: if the creation view doesn't expose the requested
            capability or profile.
    """
    instance_id = creation_view["instance_id"]

    capabilities_step = creation_view["steps"][0]
    available_caps = [c["id"] for c in capabilities_step.get("capabilities", [])]
    if selected_capability not in available_caps:
        raise RuntimeError(
            "Capability {!r} not in creation view (available: {})".format(
                selected_capability, available_caps
            )
        )

    connection_step = creation_view["steps"][1]
    methods = connection_step.get("methods", [])
    applied_for = []
    for method in methods:
        if method.get("capability_id") != selected_capability:
            continue
        for opt in method.get("options", []):
            if opt.get("profile_id") == profile_id:
                applied_for.append(method["method_unique_id"])
                break
    if not applied_for:
        raise RuntimeError(
            "No connection methods support capability={!r} + profile={!r}".format(
                selected_capability, profile_id
            )
        )

    # Pull default values from the configuration step, scoped to the selected capability.
    config_step = creation_view["steps"][2]
    configuration: dict[str, Any] = {}
    for section in config_step.get("sections", []):
        if section.get("capability_id") != selected_capability:
            continue
        for row in section.get("data", []):
            for field in row.get("fields", []):
                field_id = field.get("id")
                default_val = field.get("options", {}).get("default_value")
                if field_id and default_val is not None:
                    configuration[field_id] = default_val

    return {
        "instance_id": instance_id,
        "connector_id": creation_view.get("connector_id") or "salesforce",
        "capabilities": {
            "general_configurations": {"instance_name": instance_name},
            # ONLY the selected capability is enabled; the empty list means "use defaults
            # for sub-capabilities of this capability". Other capabilities not listed
            # here stay disabled by design — they're out of POC scope.
            "values": {selected_capability: []},
        },
        "connection": {
            "origin": "RECOMMENDED",
            "general_configurations": {"domain": domain_value},
            "profiles": [
                {
                    "profile_id": profile_id,
                    "type": profile_id.split(".")[0],  # e.g. "oauth2_client_credentials"
                    "applied_for": applied_for,
                    "values": auth_values,
                }
            ],
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
    connector_id: str = DEFAULT_CONNECTOR_ID,
    tenant_id: str = DEFAULT_TENANT_ID,
    profile_id: str = "oauth2_client_credentials.salesforce",
    selected_capability: str = "automation-and-remediation",
    domain_value: str = "test.salesforce.com",
    auth_values: dict | None = None,
    instance_name: str | None = None,
    ucp_port: int = DEFAULT_UCP_PORT,
    keep_instance: bool = False,
    connector_config_overrides: dict | None = None,
) -> dict | None:
    """Run the full UCP-side capture flow end-to-end.

    Workflow:
        1. Start a kubectl port-forward to the UCP shell pod.
        2. Snapshot existing XSOAR instances of the target brand so we can
           later identify the *new* mirrored instance.
        3. GET the creation view from UCP.
        4. Build the POST payload via :func:`_build_salesforce_iam_payload`.
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
        connector_id: UCP connector id (e.g. ``"salesforce"``).
        tenant_id: UCP tenant id.
        profile_id: Connection profile id.
        selected_capability: Single capability to enable. For the POC, must be
            ``"automation-and-remediation"``.
        domain_value: Value for the connector's general_configurations.domain
            field.
        auth_values: Auth profile values. Defaults to dummy oauth2
            ``client_key``/``client_secret``.
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
        log.error("tenant_id is required (set UCP_TENANT_ID in .env or pass explicitly).")
        return None

    if auth_values is None:
        auth_values = {"client_key": "dummy_client_key", "client_secret": "dummy_client_secret"}

    if instance_name is None:
        instance_name = f"{connector_id.title()} Parity {uuid.uuid4().hex[:8]}"

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

        # 3. Build payload (Salesforce-IAM-specific MVP helper).
        # The connector_config_overrides dict (when supplied by the orchestrator)
        # is merged into the payload's configuration block, ensuring the connector
        # delivers the SAME dummy values the INTEGRATION side uses. This is what
        # eliminates the test-setup-asymmetry false positives in the diff and
        # leaves only real connector bugs visible.
        payload = _build_salesforce_iam_payload(
            creation_view,
            instance_name=instance_name,
            selected_capability=selected_capability,
            profile_id=profile_id,
            domain_value=domain_value,
            auth_values=auth_values,
            config_overrides=connector_config_overrides,
        )
        log.info(
            "UCP payload built: connector=%s capability=%s profile=%s domain=%s, configuration fields=%d",
            connector_id,
            selected_capability,
            profile_id,
            domain_value,
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
    "DEFAULT_CONNECTOR_ID",
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
