"""xsoar_capture — reusable XSOAR-side params capture for the param-parity test.

This module exposes the legacy ("old-side") capture flow used by the connectus
param-parity test. Given a target integration YML, it will:

  1. Connect to the XSOAR/XSIAM tenant.
  2. Build a `demisto.params()` payload by filling the integration's YML config
     with smart dummy values + caller-supplied overrides.
  3. Automatically inject the ``__params_parity_dump__`` magic key so the
     CommonServerPython probe (see Packs/Base/Scripts/CommonServerPython/
     CommonServerPython.py, ``Params Parity Test Probe`` block) fires when the
     server invokes ``test-module``.
  4. Create the integration instance via PUT /settings/integration.
  5. Trigger ``test-module`` via POST /settings/integration/test.
  6. Parse the ``PARAMS_PARITY_DUMP::<json>`` payload out of the resulting
     ``return_error`` message.
  7. Delete the temporary instance.

The top-level entry point is :func:`capture_xsoar_params`. All helper symbols
(``create_client``, ``get_instances_by_brand``, ``parse_integration_yml`` etc.)
are public so the orchestrator and the UCP-side capture module can reuse them.

The legacy entry point :file:`main.py` in this same folder re-exports the
public symbols from this module so existing imports like
``from main import get_instances_by_brand`` continue to work.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from pprint import pformat
from typing import Any

import demisto_client
import urllib3
from demisto_client.demisto_api.rest import ApiException
from ruamel.yaml import YAML

# Make the shared connectus env loader importable (connectus/ is not a package).
import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402
from be_config_params import compute_be_synthesized_params, default_dummy_for  # noqa: E402

# Load the canonical root .env via the single unified loader.
load_env()

# ============================================================================
# Tenant connection defaults (sourced from .env when caller does not override)
# ============================================================================

DEFAULT_BASE_URL = os.getenv("DEMISTO_BASE_URL")
DEFAULT_API_KEY = os.getenv("DEMISTO_API_KEY")
DEFAULT_AUTH_ID = os.getenv("XSIAM_AUTH_ID")

# Timeout settings (seconds) — used for every HTTP call made through demisto_client.
REQUEST_TIMEOUT = 120

# ============================================================================
# XSOAR Param Type Constants (mirror of integration YML field types)
# ============================================================================

PARAM_TYPE_SHORT_TEXT = 0
PARAM_TYPE_ENCRYPTED = 4
PARAM_TYPE_BOOLEAN = 8
PARAM_TYPE_AUTH = 9
PARAM_TYPE_MULTI_LINE = 12  # Long Text / TextArea
PARAM_TYPE_INCIDENT_TYPE = 13
# NOTE: type 14 is XSOAR's ENCRYPTED Text Area (masked textarea, e.g. SSHKey /
# Zoom's `key`), NOT a multi-select. Multi-select is type 16. Previously
# MULTI_SELECT was (incorrectly) bound to 14, so every type-14 secret hit the
# multi-select branch and was emitted as a LIST `["<override_x>"]`. XSOAR cannot
# store a list into a scalar secret field, so the value came back "" on BOTH
# parity sides — a false "OK" verdict. Type-14 must fall through to the scalar
# sentinel branch ("<override_name>") like every other text field.
PARAM_TYPE_ENCRYPTED_TEXTAREA = 14
PARAM_TYPE_SINGLE_SELECT = 15
PARAM_TYPE_MULTI_SELECT = 16
PARAM_TYPE_EXPIRATION = 17  # Feed Expiration Policy (select)

# ============================================================================
# Probe protocol — must stay in sync with the CommonServerPython.py probe.
# ============================================================================

#: Magic key injected into ``demisto.params()`` to arm the probe.
PARITY_DUMP_PARAM_KEY = "__params_parity_dump__"

#: Magic value paired with :data:`PARITY_DUMP_PARAM_KEY` to arm the probe.
PARITY_DUMP_PARAM_VALUE = "1"

#: Sentinel prefix emitted by the probe via ``return_error()`` so that the
#: captured payload can be reliably extracted from arbitrary test-module
#: error messages (which often contain extra framework chatter).
PARITY_DUMP_SENTINEL = "PARAMS_PARITY_DUMP::"

# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("xsoar_capture")


# ============================================================================
# Smart Param Filler
# ============================================================================


def generate_dummy_value_for_param(param: dict) -> object:
    """Generate a dummy value that is GUARANTEED DIFFERENT from the YML default.

    Why "guaranteed different"? The XSOAR server auto-injects YML default
    values for any param NOT delivered by the instance-creation payload. So if
    we use the YML default as our INTEGRATION-side dummy value, we have NO
    WAY to distinguish "connector delivered the param correctly" from
    "connector didn't deliver the param and the server filled in the default".
    Both produce the same observed value on the CONNECTOR side.

    By making the INTEGRATION-side dummy GUARANTEED DIFFERENT from the YML
    default:

      * If the connector DOES deliver the param correctly, the diff sees
        ``dummy (integration)`` vs ``dummy (connector)`` → OK.
      * If the connector does NOT deliver the param, the XSOAR server fills
        in the YML default on the CONNECTOR side → diff sees
        ``dummy (integration)`` vs ``yml_default (connector)`` → VALUE_MISMATCH.
        The operator immediately knows the connector forgot to deliver this
        param.

    Generation rules per YML type:

      * **type 8 (boolean)**       — flip the YML default (default ``true``
        → ``False``; default ``false`` → ``True``; no default → ``True``).
      * **type 0 (short text)**    — emit the sentinel
        ``"<override_{param_name}>"``; never reuse the YML default.
      * **type 4 (encrypted)**     — ``"<override_encrypted_{name}>"`` (still
        normally IGNORE'd by the normalizer, but emitted just in case the
        user configures their own IGNORE policy).
      * **type 9 (credentials)**   — structured dict with
        ``"<override_user_{name}>"`` / ``"<override_pass_{name}>"`` —
        always overrides regardless of YML default (defaults are usually
        empty anyway).
      * **type 14 (encrypted text area, e.g. SSHKey / Zoom ``key``)** — a SCALAR
        masked secret. Emits the scalar sentinel ``"<override_{name}>"`` via the
        catch-all branch. (It must NOT be list-wrapped: type 14 is a single
        value, not a multi-select — see the constants block above.)
      * **type 15 (single select)** — pick an option that is NOT the YML
        default; fall back to ``"<override_{name}>"`` if there's only one
        option (or none) to pick from.
      * **type 16 (multi select)**  — return ``[options[0]]`` if the default
        is empty/list, otherwise return ``[]`` (the opposite of the default).
      * **All other types**        — emit ``"<override_{name}>"``.

    Args:
        param: A single entry from the integration YML's ``configuration`` list.

    Returns:
        A dummy value guaranteed to differ from any value the XSOAR server
        would auto-inject as a default. (Caller-supplied overrides via the
        ``overrides`` dict to :func:`fill_params_from_yml` still take
        precedence — this is the fallback path.)
    """
    raw_name = param.get("name", "")
    param_name = raw_name.lower()
    param_type = param.get("type", 0)
    default_value = param.get("defaultvalue")
    if default_value is None:
        default_value = param.get("defaultValue")
    options = param.get("options", []) or []

    sentinel = "<override_{}>".format(raw_name or "unknown")

    if param_type == PARAM_TYPE_BOOLEAN:
        # Coerce the YML default to a bool and flip it. The YML expresses
        # booleans as strings (``"true"``/``"false"``) MOST of the time, so
        # accept either shape.
        if isinstance(default_value, bool):
            return not default_value
        if isinstance(default_value, str):
            return default_value.strip().lower() not in ("true", "yes", "1", "on")
        # No default → emit True (server's implicit default is False).
        return True

    if param_type == PARAM_TYPE_AUTH:
        # Auth (credentials) is reduced to identifier/password by the normalizer
        # before the diff. We still emit a structured dict so the XSOAR API
        # accepts the instance creation request.
        auth_value: dict[str, Any] = {
            "credential": "",
            "password": "<override_pass_{}>".format(raw_name or "unknown"),
            "passwordChanged": False,
        }
        # For hiddenusername:true type-9 fields (e.g. Akamai's credentials_*),
        # the connector delivers no username, so injecting a dummy identifier
        # would re-introduce a spurious mismatch after the normalizer reduction
        # (which keeps identifier only when non-empty). Omit it in that case.
        if not param.get("hiddenusername"):
            auth_value["identifier"] = "<override_user_{}>".format(raw_name or "unknown")
        return auth_value

    if param_type == PARAM_TYPE_SINGLE_SELECT:
        # Pick any option that is NOT the YML default.
        non_default_options = [o for o in options if o != default_value]
        if non_default_options:
            return non_default_options[0]
        return sentinel

    if param_type == PARAM_TYPE_MULTI_SELECT:
        # If default is empty/[] return [options[0]]; if default is non-empty return [].
        if not default_value:
            return [options[0]] if options else [sentinel]
        return []

    # All other types (SHORT_TEXT, ENCRYPTED type-4, MULTI_LINE type-12,
    # INCIDENT_TYPE, ENCRYPTED_TEXTAREA type-14, EXPIRATION, etc.) — emit the
    # scalar per-param sentinel. NOTE: type 14 (encrypted text area / private
    # key) intentionally lands here as a SCALAR string, not a list.
    return sentinel


def fill_params_from_yml(yml_config: list[dict], overrides: dict | None) -> dict:
    """Fill the integration's configuration params with values.

    The returned dict is keyed by the **YML param ``name``** (not display name).
    For each param the override takes precedence (matched by ``name`` first,
    then by ``display``); otherwise :func:`generate_dummy_value_for_param`
    decides the value.

    Args:
        yml_config: The ``configuration`` list from the integration YML.
        overrides: Caller-supplied per-param overrides, keyed by param name
            or display name. May be ``None``.

    Returns:
        A dict mapping param name → filled value.
    """
    overrides = overrides or {}
    filled: dict[str, Any] = {}
    for param in yml_config:
        param_name = param.get("name", "")
        if not param_name:
            continue

        if param_name in overrides:
            filled[param_name] = overrides[param_name]
            log.debug("  Param %r: using override = %r", param_name, overrides[param_name])
            continue

        display = param.get("display", "")
        if display and display in overrides:
            filled[param_name] = overrides[display]
            log.debug("  Param %r: using override (by display) = %r", param_name, overrides[display])
            continue

        value = generate_dummy_value_for_param(param)
        filled[param_name] = value
        log.debug("  Param %r (type=%s): filled = %r", param_name, param.get("type", 0), value)

    return filled


# ============================================================================
# Tenant Client
# ============================================================================


def create_client(
    base_url: str | None = None,
    api_key: str | None = None,
    auth_id: str | None = None,
):
    """Create and return a ``demisto_client`` for the configured tenant.

    Args:
        base_url: Tenant base URL. Defaults to the ``DEMISTO_BASE_URL`` env var.
        api_key: API key. Defaults to the ``DEMISTO_API_KEY`` env var.
        auth_id: XSIAM auth id. Defaults to the ``XSIAM_AUTH_ID`` env var.

    Returns:
        A configured ``demisto_client`` instance with TLS verification disabled
        (suitable for dev tenants — do not use in production with that flag).

    PROXY BYPASS (why ``proxy=""`` below)
    -------------------------------------
    When this runs under the idex CLI / VS Code, that process injects
    ``HTTPS_PROXY`` / ``HTTP_PROXY`` into the agent subprocess. The corporate
    proxy then 403s the HTTPS ``CONNECT`` tunnel to the XSOAR tenant, producing
    ``ProxyError('Unable to connect to proxy', ...)`` against the
    ``api-<tenant>`` host. In a plain terminal (no proxy injected) the same call
    works because the SDK connects directly.

    Setting ``NO_PROXY`` does NOT help here: ``demisto_client.configure()``
    reads ``HTTPS_PROXY``/``HTTP_PROXY`` directly via ``os.getenv`` and passes
    the URL to a raw ``urllib3.ProxyManager`` (see ``demisto_api/rest.py``),
    which has no ``NO_PROXY`` bypass logic — every request is proxied
    unconditionally. The tenant is proven reachable directly (urllib 200 /
    curl 303 with no proxy), and it is the only host this client talks to, so we
    explicitly disable the proxy for this SDK client.

    Mechanism: pass ``proxy=""`` so ``configure()`` does NOT fall back to
    ``os.getenv('HTTPS_PROXY')`` (its fallback only triggers when ``proxy is
    None``); an empty string is falsy in ``rest.py``'s ``if configuration.proxy``
    check, so the SDK builds a plain ``urllib3.PoolManager`` (direct, no proxy).
    We also defensively null out ``configuration.proxy`` on the built client.
    """
    base_url = base_url or DEFAULT_BASE_URL
    api_key = api_key or DEFAULT_API_KEY
    auth_id = auth_id or DEFAULT_AUTH_ID
    if not base_url or not api_key:
        raise RuntimeError(
            "Tenant connection details missing. Set DEMISTO_BASE_URL / DEMISTO_API_KEY "
            "in .env or pass them explicitly to create_client()."
        )
    client = demisto_client.configure(
        base_url=base_url,
        api_key=api_key,
        auth_id=auth_id,
        verify_ssl=False,
        # Empty string (not None) so the SDK does NOT fall back to the injected
        # HTTPS_PROXY/HTTP_PROXY env vars. Reaches the tenant directly.
        proxy="",
    )
    # Defense-in-depth: ensure the configuration carries no proxy even if a
    # future SDK version changes how the proxy arg is interpreted.
    client.api_client.configuration.proxy = None
    client.api_client.user_agent = "connectus-params-parity/xsoar_capture"
    return client


# ============================================================================
# Integration Config from Server
# ============================================================================


def get_integration_config(client, integration_name: str) -> dict | None:
    """Fetch the server's authoritative configuration schema for an integration.

    The returned schema is what the instance-creation API requires as the
    ``configuration`` field of the PUT /settings/integration payload, so it
    must come from the server (not from the YML file on disk).

    The cloud endpoint is tried first; the on-prem search-all endpoint is the
    fallback.

    Args:
        client: The ``demisto_client``.
        integration_name: The integration's ``name`` (which equals the
            ``brand`` of any instance created from it).

    Returns:
        The integration config dict on success, ``None`` if the integration is
        not installed on the tenant.
    """
    log.info("Fetching integration config for %r from server...", integration_name)

    try:
        res_raw = demisto_client.generic_request_func(
            self=client,
            path=f"/settings/integration/search/{integration_name}",
            method="GET",
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
        )
        res = res_raw[0]
        if "Module" in res:
            log.info("Found integration config via cloud endpoint")
            return res["Module"]
    except ApiException:
        log.debug("Cloud endpoint failed, trying on-prem endpoint...")

    try:
        res_raw = demisto_client.generic_request_func(
            self=client,
            path="/settings/integration/search",
            method="POST",
            body={},
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
        )
        all_configurations = res_raw[0].get("configurations", [])
        match = [x for x in all_configurations if x.get("name") == integration_name]
        if match:
            log.info("Found integration config via on-prem endpoint")
            return match[0]
    except ApiException as e:
        log.error("Failed to get integration config: %s", e)

    log.error(
        "Integration %r not found on the server. "
        "Make sure the pack is installed on the tenant.",
        integration_name,
    )
    return None


def get_instances_by_brand(client, brand_name: str) -> list[dict]:
    """Return every existing integration instance whose ``brand`` matches.

    Used by :file:`create_ucp_instance.py` to locate the XSOAR-mirrored
    instance that UCP creates on the tenant after a UCP instance is created
    via the Shell API.

    Args:
        client: The ``demisto_client``.
        brand_name: The integration brand name (equals the YML ``name``).

    Returns:
        A possibly-empty list of instance dicts.
    """
    res, status, _ = demisto_client.generic_request_func(
        self=client,
        method="POST",
        path="/settings/integration/search",
        body={"size": 1000},
        _request_timeout=REQUEST_TIMEOUT,
        response_type="object",
    )

    if int(status) != 200 or "instances" not in res:
        return []

    return [inst for inst in res["instances"] if inst.get("brand") == brand_name]


# ============================================================================
# Instance Creation
# ============================================================================


def create_integration_instance(
    client,
    integration_name: str,
    server_configuration: dict,
    filled_params: dict,
    instance_name: str | None = None,
    extra_fields: dict | None = None,
) -> tuple[dict | None, str]:
    """Create an integration instance via PUT /settings/integration.

    Args:
        client: The ``demisto_client``.
        integration_name: The integration name (becomes the ``brand``).
        server_configuration: The schema returned by
            :func:`get_integration_config`. Used as the base for the payload's
            ``configuration`` field.
        filled_params: The dict returned by :func:`fill_params_from_yml`.
        instance_name: Optional explicit instance name. When ``None``, a
            sanity-test name with a uuid suffix is generated.
        extra_fields: Optional mapping of field name -> value for params that
            are NOT declared in the server configuration schema but must still
            be sent in the instance ``data`` list (e.g. backend-synthesized
            fetch/feed config params like ``alertFetchInterval`` / ``incidentType``
            that the BE auto-adds based on the YML script flags). Each is
            injected into ``data`` (mirroring the magic-key injection) unless a
            param of the same name is already present from the server schema.

    Returns:
        ``(module_instance_dict, error_message)``.
        On success, the module instance dict has its server-assigned ``id``
        populated and the error message is empty.
        On failure, the module instance is ``None`` and the error message is
        non-empty.
    """
    if instance_name is None:
        instance_name = f'xsoar_instance_for_{integration_name.replace(" ", "_")}_runtime_parity_{uuid.uuid4().hex[:8]}'
    log.info("Creating instance %r for integration %r...", instance_name, integration_name)

    module_configuration = server_configuration.get("configuration", []) or []

    module_instance = {
        "brand": server_configuration["name"],
        "category": server_configuration.get("category", ""),
        "configuration": server_configuration,
        "data": [],
        "enabled": "true",
        "engine": "",
        "id": "",
        "isIntegrationScript": True,
        "name": instance_name,
        "passwordProtected": False,
        "version": 0,
    }

    for param_conf in module_configuration:
        param_name = param_conf.get("name", "")
        param_display = param_conf.get("display", "")

        if param_name in filled_params:
            value = filled_params[param_name]
        elif param_display in filled_params:
            value = filled_params[param_display]
        elif param_conf.get("defaultValue"):
            value = param_conf["defaultValue"]
        else:
            value = ""

        if param_conf.get("type") == PARAM_TYPE_AUTH and isinstance(value, dict):
            param_conf["value"] = {
                "credential": value.get("credential", ""),
                "identifier": value.get("identifier", ""),
                "password": value.get("password", ""),
                "passwordChanged": False,
            }
        else:
            param_conf["value"] = value

        if value:
            param_conf["hasvalue"] = True

        module_instance["data"].append(param_conf)

    # NOTE: If the magic key is not declared in the server's configuration schema,
    # the loop above will silently drop it. Inject it explicitly into the data list
    # so the probe sees it at runtime even when the YML doesn't declare it.
    if PARITY_DUMP_PARAM_KEY in filled_params:
        already_present = any(
            entry.get("name") == PARITY_DUMP_PARAM_KEY for entry in module_instance["data"]
        )
        if not already_present:
            module_instance["data"].append({
                "name": PARITY_DUMP_PARAM_KEY,
                "display": PARITY_DUMP_PARAM_KEY,
                "type": PARAM_TYPE_SHORT_TEXT,
                "value": filled_params[PARITY_DUMP_PARAM_KEY],
                "hasvalue": True,
                "required": False,
            })
            log.debug("Injected magic key %r into module_instance.data", PARITY_DUMP_PARAM_KEY)

    # Inject backend-synthesized config params (e.g. fetch/feed fields the BE
    # auto-adds from the YML script flags) that are NOT in the server's
    # configuration schema, so they are persisted on the instance and surface in
    # demisto.params() at runtime. Mirrors the magic-key injection above.
    for field_name, field_value in (extra_fields or {}).items():
        already_present = any(
            entry.get("name") == field_name for entry in module_instance["data"]
        )
        if already_present:
            continue
        module_instance["data"].append({
            "name": field_name,
            "display": field_name,
            "type": PARAM_TYPE_SHORT_TEXT,
            "value": field_value,
            "hasvalue": bool(field_value),
            "required": False,
        })
        log.debug("Injected BE-synthesized field %r into module_instance.data", field_name)

    # [DEBUG-DIAGNOSTIC] Dump the FULL create-instance payload as pretty JSON
    # immediately before the PUT /settings/integration call. This surfaces the
    # fetch-related flags so we can confirm whether both fetch-incidents and
    # fetch-events are being armed on a single instance (XSOAR "error 52").
    # Inspect the top-level `configuration` object for `isFetch` / `isFetchEvents`
    # and the per-marketplace `isfetch` / `isfetchevents` flags. Remove when done.
    try:
        log.info(
            "XSOAR_CREATE_PAYLOAD=%s",
            json.dumps(module_instance, indent=2, default=str, sort_keys=True),
        )
    except Exception as _dbg_exc:  # noqa: BLE001 - diagnostic logging must never break the flow
        log.warning("XSOAR_CREATE_PAYLOAD serialization failed: %s", _dbg_exc)

    try:
        res = demisto_client.generic_request_func(
            self=client,
            method="PUT",
            path="/settings/integration",
            body=module_instance,
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
        )
    except ApiException as e:
        error_msg = f"Failed to create instance: {e}"
        log.error(error_msg)
        return None, error_msg

    if res[1] != 200:
        error_msg = f"Create instance failed with status {res[1]}: {pformat(res[0])}"
        log.error(error_msg)
        return None, error_msg

    module_instance["id"] = res[0]["id"]
    log.info("XSOAR Integration Instance created. ID=%s name=%r", module_instance["id"], instance_name)
    return module_instance, ""


# ============================================================================
# Test Integration Instance (modeled after Tests/test_integration.py)
# ============================================================================


def test_integration_instance(client, module_instance: dict) -> tuple[bool, str | None]:
    """Run ``test-module`` against an instance via POST /settings/integration/test.

    Includes a 5x retry loop for transient ``ReadTimeoutError`` cases (a
    well-known XSOAR API quirk under load).

    Args:
        client: The ``demisto_client``.
        module_instance: The dict returned by :func:`create_integration_instance`.

    Returns:
        ``(success, message)`` where ``message`` is the raw response message
        from the server. When the params-parity probe fires, ``success`` will
        be ``False`` and ``message`` will contain the
        ``PARAMS_PARITY_DUMP::<json>`` sentinel.
    """
    connection_retries = 5
    response_data: dict | None = None
    response_code = 0
    integration_of_instance = module_instance.get("brand", "")
    instance_name = module_instance.get("name", "")
    log.info(
        'Running "test-module" for integration instance %r of integration %r.',
        instance_name,
        integration_of_instance,
    )

    for i in range(connection_retries):
        try:
            response_data, response_code, _ = demisto_client.generic_request_func(
                self=client,
                method="POST",
                path="/settings/integration/test",
                body=module_instance,
                _request_timeout=REQUEST_TIMEOUT,
                response_type="object",
            )
            break
        except ApiException as e:
            log.exception("API exception on test-module request (attempt %s/%s): %s", i + 1, connection_retries, e)
            return False, None
        except urllib3.exceptions.ReadTimeoutError:
            log.warning(
                "Read timeout on test-module (attempt %s/%s). Retrying...",
                i + 1,
                connection_retries,
            )
    else:
        log.error("All connection retries exhausted for test-module request.")
        return False, None

    if int(response_code) != 200:
        log.error("test-module request returned non-200 status: %s", response_code)
        return False, None

    success = bool(response_data.get("success")) if response_data else False
    failure_message = response_data.get("message") if response_data else None

    if not success:
        log.info(
            'test-module returned non-success for instance %r (this is EXPECTED when '
            'the probe fires; expected message format: "%s<json>"). '
            'Raw message: %s',
            instance_name,
            PARITY_DUMP_SENTINEL,
            failure_message,
        )

    return success, failure_message


# ============================================================================
# Test Module Output Parser
# ============================================================================


# Strip the trailing "(N)" counter that the XSOAR server appends to error
# messages on retry — e.g. ``"PARAMS_PARITY_DUMP::{...} (1)"``.
_SUFFIX_RE = re.compile(r"\s*\(\d+\)\s*$")


def parse_params_dump_payload(message: str | None) -> dict | None:
    """Extract the ``demisto.params()`` dict from a test-module response.

    Recognizes two payload shapes:

    1. **Preferred (probe-emitted)**: the message contains the
       :data:`PARITY_DUMP_SENTINEL` prefix followed by a JSON object with the
       shape ``{"__params_parity_dump__": true, "params": {...}}``. This is
       what :file:`CommonServerPython.py` emits when the probe fires.

    2. **Legacy/fallback**: the message is itself a raw JSON object — used by
       integrations that emit ``demisto.params()`` directly from a custom
       ``return_error`` (pre-probe behavior). The full message is treated as
       the params dict.

    Args:
        message: The raw message string from
            :func:`test_integration_instance`, possibly with a trailing
            ``" (N)"`` counter the server appends.

    Returns:
        The params dict on success, ``None`` if parsing fails.
    """
    if message is None:
        log.warning("test-module returned no message (None)")
        return None

    cleaned = _SUFFIX_RE.sub("", message).strip()
    if not cleaned:
        log.warning("test-module message is empty after stripping suffix")
        return None

    sentinel_idx = cleaned.find(PARITY_DUMP_SENTINEL)
    if sentinel_idx >= 0:
        json_str = cleaned[sentinel_idx + len(PARITY_DUMP_SENTINEL):]
        # Defensive: trailing "(N)" may now be a different shape; re-strip.
        json_str = _SUFFIX_RE.sub("", json_str).strip()
        try:
            envelope = json.loads(json_str)
        except json.JSONDecodeError as e:
            log.error("Failed to parse PARAMS_PARITY_DUMP payload as JSON: %s", e)
            log.debug("Payload was: %s", json_str)
            return None
        if isinstance(envelope, dict) and "params" in envelope and isinstance(envelope["params"], dict):
            return envelope["params"]
        log.warning("PARAMS_PARITY_DUMP envelope missing 'params' dict; got %r", envelope)
        return None

    # Legacy fallback: try to parse the whole message as a raw params dict.
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        log.error("Failed to parse test-module output as JSON (no sentinel found): %s", e)
        log.debug("Cleaned message was: %s", cleaned)
        return None

    if not isinstance(parsed, dict):
        log.warning("Parsed test-module output is not a dict (got %s)", type(parsed).__name__)
        return None

    return parsed


# ============================================================================
# Cleanup
# ============================================================================


def delete_integration_instance(client, instance_id: str) -> bool:
    """Delete an integration instance by id."""
    log.info("Deleting integration instance %s...", instance_id)
    try:
        res = demisto_client.generic_request_func(
            self=client,
            method="DELETE",
            path=f"/settings/integration/{instance_id}",
            _request_timeout=REQUEST_TIMEOUT,
        )
        if int(res[1]) == 200:
            log.info("Instance deleted successfully")
            return True
        log.error("Delete instance failed with status %s", res[1])
        return False
    except ApiException as e:
        log.error("Failed to delete instance: %s", e)
        return False


# ============================================================================
# YML Parser
# ============================================================================


def parse_integration_yml(yml_path: str) -> dict:
    """Parse an integration YML file into a plain dict."""
    yaml = YAML()
    yaml.preserve_quotes = True
    with open(yml_path) as f:
        return yaml.load(f)


# ============================================================================
# Top-Level Capture
# ============================================================================


def run_test_module_and_capture_params(
    client,
    module_instance: dict,
) -> dict | None:
    """Run test-module on an existing instance and capture the params dump.

    This is exposed separately so the UCP-side capture flow (which creates the
    instance via UCP, not directly via XSOAR) can reuse it on the
    XSOAR-mirrored instance that UCP creates.

    Args:
        client: The ``demisto_client``.
        module_instance: An instance dict. Must contain at minimum the
            ``brand``, ``name`` and a fully-populated ``data`` list including
            the magic ``__params_parity_dump__: "1"`` entry. Must also include
            the ``configuration`` schema; the easiest way to get a usable
            dict is to take the result of :func:`get_instances_by_brand` and
            attach the schema from :func:`get_integration_config`.

    Returns:
        The captured ``demisto.params()`` dict on success, ``None`` on failure.
    """
    success, message = test_integration_instance(client, module_instance)
    if success:
        # The probe deliberately fails test-module by calling return_error.
        # A successful test-module means the probe did NOT fire — which is a
        # configuration error (magic key not delivered to the integration).
        log.error(
            "test-module unexpectedly returned success — the parity probe did NOT fire. "
            "Most likely cause: %r was not delivered to the integration at runtime.",
            PARITY_DUMP_PARAM_KEY,
        )
        return None
    return parse_params_dump_payload(message)


def capture_xsoar_params(
    integration_yml_path: str,
    overrides: dict | None = None,
    client=None,
    keep_instance: bool = False,
) -> tuple[dict | None, dict | None]:
    """Run the full legacy XSOAR-side capture flow end-to-end.

    Workflow:
        1. Parse the integration YML.
        2. Fill its params with smart dummy values + the caller's overrides.
        3. Inject the ``__params_parity_dump__`` magic key.
        4. Fetch the server-side config schema.
        5. Create an instance.
        6. Run test-module.
        7. Parse the probe's payload.
        8. Delete the instance (unless ``keep_instance`` is True).

    Args:
        integration_yml_path: Filesystem path to the integration YML.
        overrides: Optional per-param overrides keyed by param name or display
            name. The magic key is always added by this function — callers must
            not (and need not) supply it.
        client: Optional pre-built ``demisto_client``. When ``None``, one is
            built from env vars via :func:`create_client`.
        keep_instance: When ``True``, the temporary instance is NOT deleted on
            success — useful for debugging.

    Returns:
        A 2-tuple ``(captured, filled)``:

        * ``captured`` — the captured ``demisto.params()`` dict on success, or
          ``None`` on any failure.
        * ``filled`` — the XSOAR-side instance-creation payload (the filled
          params dict, including the magic key, that was sent to
          ``create_integration_instance``). This is surfaced in the persisted
          results envelope for debugging. It is ``None`` only when the flow
          fails BEFORE ``filled`` is built (the no-name case); otherwise it is
          returned even on later failures so the attempted payload is
          recoverable.

        Failures are logged with enough detail to diagnose.
    """
    overrides = dict(overrides or {})
    # Mandatory: arm the probe.
    overrides[PARITY_DUMP_PARAM_KEY] = PARITY_DUMP_PARAM_VALUE

    yml_data = parse_integration_yml(integration_yml_path)
    integration_name = yml_data.get("name", "")
    yml_params = yml_data.get("configuration", []) or []
    if not integration_name:
        log.error("Integration YML at %s does not declare a 'name'.", integration_yml_path)
        # Failure before `filled` is built — no payload available.
        return None, None

    log.info("Integration: %s (%d params declared in YML)", integration_name, len(yml_params))

    filled = fill_params_from_yml(yml_params, overrides)

    # Backend-synthesized fetch/feed config params (alertFetchInterval, etc.)
    # are NOT in the YML `configuration`, so fill_params_from_yml() drops them.
    # Compute them from the YML script flags and pull their values from the
    # caller overrides (the shared dummies) so BOTH parity sides use the same
    # value. These get injected into the instance data list by
    # create_integration_instance(extra_fields=...).
    be_added, be_stripped = compute_be_synthesized_params(yml_data.get("script"))
    extra_fields: dict = {}
    for name in be_added:
        if name in overrides:
            extra_fields[name] = overrides[name]
        else:
            extra_fields[name] = default_dummy_for(name)
    # BE strips these when no fetch flag is on — ensure they are not sent.
    for name in be_stripped:
        filled.pop(name, None)
        extra_fields.pop(name, None)

    if client is None:
        client = create_client()

    server_config = get_integration_config(client, integration_name)
    if not server_config:
        # `filled` is built — return it so the attempted payload is recoverable.
        return None, filled

    module_instance, error = create_integration_instance(
        client, integration_name, server_config, filled, extra_fields=extra_fields
    )
    if not module_instance:
        log.error("Failed to create XSOAR instance: %s", error)
        return None, filled

    instance_id = module_instance["id"]
    try:
        captured = run_test_module_and_capture_params(client, module_instance)
    finally:
        if not keep_instance:
            delete_integration_instance(client, instance_id)
        else:
            log.info("keep_instance=True — leaving instance %s alive for inspection", instance_id)

    return captured, filled


# ============================================================================
# Public re-export list (so `from xsoar_capture import *` is well-defined).
# ============================================================================

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_API_KEY",
    "DEFAULT_AUTH_ID",
    "PARAM_TYPE_AUTH",
    "PARAM_TYPE_BOOLEAN",
    "PARAM_TYPE_ENCRYPTED",
    "PARAM_TYPE_SHORT_TEXT",
    "PARITY_DUMP_PARAM_KEY",
    "PARITY_DUMP_PARAM_VALUE",
    "PARITY_DUMP_SENTINEL",
    "capture_xsoar_params",
    "create_client",
    "create_integration_instance",
    "delete_integration_instance",
    "fill_params_from_yml",
    "generate_dummy_value_for_param",
    "get_instances_by_brand",
    "get_integration_config",
    "parse_integration_yml",
    "parse_params_dump_payload",
    "run_test_module_and_capture_params",
    "test_integration_instance",
]
