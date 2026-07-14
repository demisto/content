#!/usr/bin/env python3
"""check_param_parity — the orchestrator CLI for the ConnectUs param-parity test.

Single end-to-end entry point that:

  1. Connects to the XSOAR tenant.
  2. Captures the INTEGRATION-side ``demisto.params()`` via the legacy XSOAR
     instance-creation flow (:func:`xsoar_capture.capture_xsoar_params`).
  3. Captures the CONNECTOR-side ``demisto.params()`` via the UCP Shell API
     flow (:func:`ucp_capture.capture_ucp_params`).
  4. Normalizes both dicts with the deterministic IGNORE policy
     (:func:`normalizers.normalize_for_diff`).
  5. Diffs the two normalized dicts (:func:`diff.diff_params`).
  6. Emits the JSON envelope to stdout.
  7. Exits ``0`` on parity (``status: "pass"``), non-zero on any failure
     (``status: "fail"``).

The ONLY required input is ``--integration-id``. Everything else — the connector
dir/id, the integration YML/brand, ALL (sub-)capabilities + profiles, and the
compare/ignore policy — is resolved at runtime from the migration pipeline CSV +
the connector repo by :func:`resolver.resolve`. There are NO connector-specific
defaults; this is a mass-migration tool, not a single-integration POC.

The remaining flags are OPTIONAL overrides (default ``None``): pass one to pin a
single knob the resolver would otherwise supply.

Example::

    cd connectus/runtime_demisto.params_parity
    python check_param_parity.py --integration-id "Salesforce IAM"
    # → prints the JSON envelope, exits 0 if parity OK, non-zero otherwise.

    # With allow-flags to downgrade specific findings to warn-level:
    python check_param_parity.py --integration-id "Salesforce IAM" \\
        --allow-missing --allow-mismatch

    # Pinning a single resolver-supplied knob:
    python check_param_parity.py --integration-id "Salesforce IAM" \\
        --connector-dir /path/to/other-connector/
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import resolver as resolver_mod
import results_ledger
from be_config_params import (
    apply_be_config_transform,
    connector_value_for,
    variant_toggle_overrides,
)
from diff import _load_serializer_mappings, diff_params
from normalizers import normalize_for_diff
from resolver import ResolverError
from ucp_capture import capture_ucp_params
from xsoar_capture import (
    capture_xsoar_params,
    create_client,
    fill_params_from_yml,
    parse_integration_yml,
)

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader.
load_env()

log = logging.getLogger("check_param_parity")


# ============================================================================
# CLI
# ============================================================================


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="check_param_parity",
        description=(
            "End-to-end ConnectUs param-parity test. Captures demisto.params() "
            "from both the legacy XSOAR flow (INTEGRATION side) and the new "
            "UCP flow (CONNECTOR side), then diffs them with a deterministic "
            "IGNORE policy. Everything is resolved from --integration-id."
        ),
    )

    p.add_argument(
        "--integration-id",
        required=True,
        help=(
            "XSOAR Integration ID (REQUIRED). The resolver derives the connector "
            "dir/id, integration YML/brand, ALL (sub-)capabilities + profiles, "
            "and the compare/ignore policy from the migration pipeline CSV + the "
            "connector repo."
        ),
    )

    # Optional overrides (default None) — pin a single resolver-supplied knob.
    p.add_argument(
        "--integration-yml",
        default=None,
        help=(
            "Override the resolver's integration YML path (relative to the "
            "workspace or absolute)."
        ),
    )
    p.add_argument(
        "--integration-brand",
        default=None,
        help=(
            "Override the resolver's integration brand name (equals the YML "
            "`name`). Used to find the XSOAR-mirrored instance UCP creates."
        ),
    )
    p.add_argument(
        "--connector-id",
        default=None,
        help="Override the resolver's UCP connector id.",
    )
    p.add_argument(
        "--connector-dir",
        default=None,
        help=(
            "Override the resolver's connector YAML directory. Used by the diff "
            "engine to attribute EXTRA_IN_CONNECTOR findings to their source file."
        ),
    )

    # Allow-flags: downgrade specific finding types from `fail` to `warn`.
    p.add_argument(
        "--allow-missing",
        action="store_true",
        help="Downgrade MISSING_IN_CONNECTOR findings to warn-level (no exit-code 1).",
    )
    p.add_argument(
        "--allow-extra",
        action="store_true",
        help="Downgrade EXTRA_IN_CONNECTOR findings to warn-level (no exit-code 1).",
    )
    p.add_argument(
        "--allow-mismatch",
        action="store_true",
        help="Downgrade VALUE_MISMATCH findings to warn-level (no exit-code 1).",
    )

    p.add_argument(
        "--skip-xsoar",
        action="store_true",
        help=(
            "Skip the INTEGRATION-side capture (dev convenience — pairs with "
            "--integration-capture-file to load a pre-captured dump from disk)."
        ),
    )
    p.add_argument(
        "--skip-ucp",
        action="store_true",
        help=(
            "Skip the CONNECTOR-side capture (dev convenience — pairs with "
            "--connector-capture-file to load a pre-captured dump from disk)."
        ),
    )
    p.add_argument(
        "--integration-capture-file",
        default=None,
        help="Path to a JSON file containing a pre-captured INTEGRATION-side params dict.",
    )
    p.add_argument(
        "--connector-capture-file",
        default=None,
        help="Path to a JSON file containing a pre-captured CONNECTOR-side params dict.",
    )

    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging from all capture/diff modules.",
    )

    return p.parse_args(argv)


def _load_dict_from_json_file(path: str) -> dict:
    """Read a JSON file and return its dict content. Raise on error."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("File {} does not contain a JSON object at the top level.".format(path))
    return data


# ============================================================================
# Main
# ============================================================================


def _force_drop_from(ignored_params: dict) -> set[str]:
    """Params to drop on BOTH sides: the resolver's hard ignore-list AND params
    hidden in the integration YML (not migrated to the connector)."""
    return {
        name
        for name, reason in ignored_params.items()
        if reason in ("hard_ignore_list", "hidden")
    }


def _build_connector_instance_values(shared_dummies: dict, parity_inputs) -> dict:
    """Build the CONNECTOR-keyed copy of ``shared_dummies`` for the UCP payload.

    The connector creation payload keys its ``configuration`` block by CONNECTOR
    FIELD id, while ``shared_dummies`` is keyed by the integration (xsoar) param
    name. This translates the shared dummy values onto the connector field ids so
    BOTH parity sides receive the SAME value:

      1. ``param_to_connector_field`` — serializer-renamed + interpolated auth
         fields discovered from the integration YML params.
      2. ``serializer_by_connector`` — the handler ``serializer.yaml``
         ``field_mappings`` directly. This is what carries the BE-SYNTHESIZED
         fetch fields (e.g. ``incidentFetchInterval``, ``eventFetchInterval``):
         they are NOT declared in the integration YML (so step 1 misses them) but
         ARE listed in the serializer (true runtime id == the synthesized name),
         so the connector's serialized config field must receive the same dummy
         the integration got. Without this the connector builder fell back to the
         field's type default (a ``duration`` → ``0``), breaking parity with the
         integration's ``"111"``. It fires ONLY for fields actually present in
         ``shared_dummies`` — a synthesized field for a DISABLED fetch flag is
         absent there and is never forced onto the connector side.

    Finally the connector-int / integration-string type contract is applied via
    :func:`connector_value_for`, resolving each connector field id back to its
    TRUE runtime id through ``serializer_by_connector`` first (the registry is
    keyed by the bare xsoar name, not the serializer-renamed connector id), so a
    renamed interval field (e.g. ``xsoar-<h>_incidentFetchInterval``) is coerced
    to the integer the connector expects (``111``) while the integration keeps the
    string (``"111"``). The int↔string equivalence is restored at diff time by
    :func:`be_config_params.values_match`.
    """
    by_connector = getattr(parity_inputs, "serializer_by_connector", None) or {}
    param_map = getattr(parity_inputs, "param_to_connector_field", None) or {}
    out: dict = dict(shared_dummies)
    for xsoar_param, connector_field in param_map.items():
        if xsoar_param in shared_dummies and connector_field != xsoar_param:
            out[connector_field] = shared_dummies[xsoar_param]
    for connector_field, xsoar_id in by_connector.items():
        if xsoar_id in shared_dummies and connector_field not in out:
            out[connector_field] = shared_dummies[xsoar_id]
    for key in list(out.keys()):
        true_id = by_connector.get(key, key)
        out[key] = connector_value_for(true_id, out[key])
    return out


def _run_one_variant(
    *,
    variant,                       # resolver.CapabilityVariant
    parity_inputs,
    args,
    xsoar_client,
    yml_data: dict,
    yml_configuration: list,
    yml_param_names: set,
    integration_yml: str,
    integration_brand: str,
    connector_id: str,
    connector_dir: str,
    force_keep: set,
    force_drop: set,
    force_drop_reasons: dict,
) -> tuple[dict | None, int]:
    """Run capture → normalize → diff for ONE capability variant.

    Returns ``(variant_envelope, exit_hint)`` where ``exit_hint`` is:
      * ``2`` — setup-blocked (a capture failed); ``variant_envelope`` is ``None``.
      * ``0`` — variant produced a diff envelope (``status`` inside it tells pass/fail).

    The variant's ``fetch_flags`` drive BOTH the BE-synthesized config transform
    (via ``apply_be_config_transform(..., fetch_flags=...)``) AND the explicit
    XSOAR fetch toggles (via ``variant_toggle_overrides``), so the INTEGRATION side
    models the SAME single legal fetch type the CONNECTOR side enables.
    """
    log.info("=" * 70)
    log.info(
        "VARIANT %s — enabled=%s fetch_flags=%s",
        variant.id,
        variant.enabled_capability_ids,
        [f for f, on in variant.fetch_flags.items() if on] or ["<none>"],
    )
    log.info("=" * 70)

    # ── Bidirectional push: per-variant dummy dict pushed to BOTH sides ──
    # Start from the YML dummies, then (a) apply the BE config transform scoped to
    # THIS variant's fetch flags, and (b) force the exact XSOAR fetch toggles.
    shared_dummies = fill_params_from_yml(yml_configuration, {})
    shared_dummies = apply_be_config_transform(
        shared_dummies, yml_data.get("script"), fetch_flags=variant.fetch_flags
    )
    # Explicit fetch toggles for this variant (active one True, rest False). These
    # are type-8 YML params; setting them here overrides the guaranteed-different
    # dummy so the legacy instance models exactly the variant's fetch type.
    toggle_overrides = variant_toggle_overrides(variant.fetch_flags)
    for toggle, value in toggle_overrides.items():
        if toggle in yml_param_names:
            shared_dummies[toggle] = value
    log.info(
        "Variant %s: %d shared dummy values (fetch toggles set: %s).",
        variant.id,
        len(shared_dummies),
        {k: v for k, v in toggle_overrides.items() if k in yml_param_names} or "<none>",
    )

    # CONNECTOR side keys by connector FIELD id; build a connector-keyed copy so
    # serializer-renamed + interpolated auth fields AND BE-synthesized fetch fields
    # receive the SAME value (with the int/string type contract applied). See
    # :func:`_build_connector_instance_values`.
    connector_instance_values = _build_connector_instance_values(
        shared_dummies, parity_inputs
    )

    # ── INTEGRATION-side capture (legacy XSOAR flow) ──
    try:
        integration_raw, integration_payload = capture_xsoar_params(
            integration_yml_path=integration_yml,
            overrides=shared_dummies,
            client=xsoar_client,
            # Drive the BE-synthesized add/strip off THIS variant's fetch flags so
            # a variant-driven fetch (e.g. fetch-issues → isFetch) populates
            # incidentFetchInterval on the integration side too, instead of letting
            # it fall back to the YML default and mismatch the connector.
            fetch_flags=variant.fetch_flags,
        )
    except Exception as e:  # noqa: BLE001 — a capture crash is setup-blocked, not a diff
        log.error("INTEGRATION-side capture FAILED for variant %s: %s", variant.id, e)
        return None, 2
    if integration_raw is None:
        log.error("INTEGRATION-side capture failed for variant %s.", variant.id)
        return None, 2
    log.info("Variant %s INTEGRATION-side captured %d keys.", variant.id, len(integration_raw))

    # ── CONNECTOR-side capture (new UCP flow) — only this variant's caps ──
    # Multi-profile (XOR) connectors: the variant pins exactly ONE auth profile via
    # ``variant.active_profile_id`` (set by the resolver's per-profile variant
    # expansion). Emit ONLY that profile so the runtime activates it and we capture
    # its auth secret; the OTHER profiles' secrets are scoped out by the diff
    # (out_of_variant_scope) in this variant and verified in their OWN variant.
    # When ``active_profile_id`` is None (single / no-profile connector) we pass
    # None → all profiles emitted (unchanged behaviour).
    active_profiles = None
    if getattr(variant, "active_profile_id", None):
        active_profiles = [
            p for p in parity_inputs.profiles if p.id == variant.active_profile_id
        ]
    try:
        connector_raw, connector_payload = capture_ucp_params(
            xsoar_client=xsoar_client,
            xsoar_brand_name=integration_brand,
            parity_inputs=parity_inputs,
            capabilities=variant.capabilities,
            active_profiles=active_profiles,
            instance_values=connector_instance_values,
            connector_id=connector_id,
        )
    except Exception as e:  # noqa: BLE001 — a capture crash is setup-blocked, not a diff
        log.error("CONNECTOR-side capture FAILED for variant %s: %s", variant.id, e)
        return None, 2
    if connector_raw is None:
        log.error("CONNECTOR-side capture failed for variant %s.", variant.id)
        return None, 2
    log.info("Variant %s CONNECTOR-side captured %d keys.", variant.id, len(connector_raw))

    # ── Normalize both sides with the deterministic IGNORE policy ──
    integration_norm, integration_dropped = normalize_for_diff(
        integration_raw, yml_configuration, side="integration",
        force_keep=force_keep, force_drop=force_drop,
        force_drop_reasons=force_drop_reasons,
    )
    connector_norm, connector_dropped = normalize_for_diff(
        connector_raw, yml_configuration, side="connector",
        force_keep=force_keep, force_drop=force_drop,
        force_drop_reasons=force_drop_reasons,
    )

    # ── Diff ──
    variant_envelope = diff_params(
        integration=integration_norm,
        connector=connector_norm,
        yml_param_names=yml_param_names,
        connector_dir=connector_dir,
        integration_raw=integration_raw,
        connector_raw=connector_raw,
        integration_dropped=integration_dropped,
        connector_dropped=connector_dropped,
        # Per-variant field SCOPING (Bucket C): tell the diff which fields THIS
        # variant's enabled sub-capabilities legitimately expose, plus the global
        # field→owning-sub-capability map and this variant's enabled ownership
        # units, so a field belonging to a DISABLED sub-capability is treated as
        # out-of-variant-scope (OK_IGNORED) rather than MISSING_IN_CONNECTOR.
        in_scope_fields=variant.in_scope_fields,
        field_owning_subcapabilities=parity_inputs.field_owning_subcapabilities,
        enabled_ownership_units=variant.enabled_ownership_units,
        # serialized_from/to annotation must reflect ONLY this integration's
        # handler serializer. For a grouped connector (e.g. aws) the diff's own
        # connector-wide rglob would mis-attribute a shared xsoar param name
        # (e.g. incidentType / first_fetch) to a SIBLING handler's connector
        # field id; the resolver already parsed this handler's serializer.yaml
        # into these scoped maps, so pass them through.
        serializer_by_xsoar=getattr(parity_inputs, "serializer_by_xsoar", None),
        serializer_by_connector=getattr(
            parity_inputs, "serializer_by_connector", None
        ),
        allow_missing=args.allow_missing,
        allow_extra=args.allow_extra,
        allow_mismatch=args.allow_mismatch,
    )

    # Per-variant annotations + raw captures for triage.
    variant_envelope["variant_id"] = variant.id
    variant_envelope["enabled_capabilities"] = variant.enabled_capability_ids
    variant_envelope["fetch_flags"] = dict(variant.fetch_flags)
    # The pinned auth profile for this variant (multi-profile / XOR connectors).
    # None for single / no-profile connectors.
    variant_envelope["active_profile_id"] = getattr(
        variant, "active_profile_id", None
    )
    variant_envelope["captures"] = {
        "integration": integration_raw,
        "connector": connector_raw,
    }
    variant_envelope["normalizer_dropped"] = {
        "integration": integration_dropped,
        "connector": connector_dropped,
    }
    variant_envelope["creation_payloads"] = {
        "integration": integration_payload,
        "connector": connector_payload,
    }
    return variant_envelope, 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Instance-creation payloads (what we POST/send to CREATE each side's
    # instance). Captured below and attached to the results envelope for
    # debugging. Initialized here so they're defined on EVERY path that reaches
    # the envelope build (e.g. the --skip-* file-load branches leave them None).
    integration_payload: dict | None = None
    connector_payload: dict | None = None

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Resolver: derive everything from the required --integration-id ──
    #
    # resolve() reads the migration pipeline CSV row + the connector repo and
    # produces a ParityInputs describing the connector dir/id, the integration
    # YML/brand, ALL (sub-)capabilities + profiles, the auth mapping, and the
    # compare/ignore policy. Optional CLI overrides (default None) pin a single
    # knob; otherwise the resolver value is used.
    try:
        parity_inputs = resolver_mod.resolve(args.integration_id)
    except ResolverError as e:
        log.error("Resolver failed for %r: %s", args.integration_id, e)
        return 2

    integration_yml = args.integration_yml or parity_inputs.integration_yml_path
    integration_brand = args.integration_brand or parity_inputs.integration_brand
    connector_id = args.connector_id or parity_inputs.connector_id
    connector_dir = args.connector_dir or parity_inputs.connector_dir

    # force_keep = the params the resolver decided to compare (EVERY YML param
    # that is neither hard-ignored nor hidden — including type-4 and type-9
    # credentials params). force_drop = the resolver's hard ignore-list PLUS
    # params hidden in the integration YML (those surface as OK_IGNORED, not
    # MISSING/EXTRA).
    force_keep: set[str] = set(parity_inputs.compare_params)
    force_drop: set[str] = _force_drop_from(parity_inputs.ignored_params)
    # Specific drop reason per param (so the report can explain WHY, not just
    # "hard_ignore"). Only the reasons _force_drop_from admits are relevant here.
    force_drop_reasons: dict[str, str] = {
        name: reason
        for name, reason in parity_inputs.ignored_params.items()
        if name in force_drop
    }
    log.info(
        "Resolver: connector_dir=%s connector_id=%s integration_yml=%s "
        "(%d compare, %d hard-ignored, %d capabilities, %d profiles)",
        connector_dir,
        connector_id,
        integration_yml,
        len(force_keep),
        len(force_drop),
        len(parity_inputs.capabilities),
        len(parity_inputs.profiles),
    )

    # ── Parse the integration YML once (used by both captures + the normalizer) ──
    # Resolve a relative path against the CONTENT-REPO WORKSPACE ROOT (not the CWD).
    # The CSV stores repo-relative paths (e.g. Packs/.../X.yml) and the wrapper runs
    # us with cwd=runtime_demisto.params_parity/, so os.path.abspath() (CWD-relative)
    # would look in the wrong place. resolver._abs_integration_yml resolves against
    # the workspace root (resolver._WORKSPACE_ROOT).
    if not os.path.isabs(integration_yml):
        integration_yml = resolver_mod._abs_integration_yml(integration_yml)
    if not os.path.exists(integration_yml):
        log.error("integration-yml not found: %s", integration_yml)
        return 2

    log.info("Parsing integration YML: %s", integration_yml)
    yml_data = parse_integration_yml(integration_yml)
    yml_configuration = yml_data.get("configuration", []) or []
    yml_param_names = {p.get("name") for p in yml_configuration if p.get("name")}
    log.info(
        "Integration: %s — %d params declared in YML",
        yml_data.get("name") or integration_brand,
        len(yml_param_names),
    )

    # ── Build the shared XSOAR client (reused by both capture sides) ──
    try:
        xsoar_client = create_client()
    except Exception as e:
        log.error("Could not build XSOAR client: %s", e)
        return 2

    # ── Variant matrix: one LEGAL capability combination per instance ──
    # The resolver expands the handler's capabilities into variants (one per
    # fetch-exclusive capability + the always-on set). We run capture → diff once
    # per variant (Philosophy A: per-integration isolation) and aggregate.
    #
    # NOTE: the --skip-xsoar/--skip-ucp dev shortcuts re-use a single pre-captured
    # dump and therefore only support a SINGLE variant; they are diagnostic aids,
    # not part of the migration gate.
    variants = parity_inputs.variants
    log.info(
        "Resolved %d variant(s): %s",
        len(variants),
        [v.id for v in variants],
    )

    if args.skip_xsoar or args.skip_ucp:
        if len(variants) > 1:
            log.error(
                "--skip-xsoar/--skip-ucp support only a single-variant integration "
                "(this one has %d variants: %s). Re-run without the skip flags.",
                len(variants), [v.id for v in variants],
            )
            return 2
        # Single-variant dev path: load the pre-captured dump(s) and diff once.
        variant = variants[0]
        if args.skip_xsoar:
            if not args.integration_capture_file:
                log.error("--skip-xsoar requires --integration-capture-file")
                return 2
            integration_raw = _load_dict_from_json_file(args.integration_capture_file)
            integration_payload = None
        else:
            integration_raw = None
        if args.skip_ucp:
            if not args.connector_capture_file:
                log.error("--skip-ucp requires --connector-capture-file")
                return 2
            connector_raw = _load_dict_from_json_file(args.connector_capture_file)
            connector_payload = None
        else:
            connector_raw = None
        # If only one side is skipped, capture the other live.
        shared_dummies = apply_be_config_transform(
            fill_params_from_yml(yml_configuration, {}),
            yml_data.get("script"),
            fetch_flags=variant.fetch_flags,
        )
        for toggle, value in variant_toggle_overrides(variant.fetch_flags).items():
            if toggle in yml_param_names:
                shared_dummies[toggle] = value
        if integration_raw is None:
            integration_raw, integration_payload = capture_xsoar_params(
                integration_yml_path=integration_yml,
                overrides=shared_dummies, client=xsoar_client,
            )
        if connector_raw is None:
            connector_instance_values = _build_connector_instance_values(
                shared_dummies, parity_inputs
            )
            connector_raw, connector_payload = capture_ucp_params(
                xsoar_client=xsoar_client, xsoar_brand_name=integration_brand,
                parity_inputs=parity_inputs, capabilities=variant.capabilities,
                instance_values=connector_instance_values, connector_id=connector_id,
            )
        if integration_raw is None or connector_raw is None:
            log.error("Capture failed in skip-mode. See logs above.")
            return 2
        i_norm, i_drop = normalize_for_diff(
            integration_raw, yml_configuration, side="integration",
            force_keep=force_keep, force_drop=force_drop,
            force_drop_reasons=force_drop_reasons,
        )
        c_norm, c_drop = normalize_for_diff(
            connector_raw, yml_configuration, side="connector",
            force_keep=force_keep, force_drop=force_drop,
            force_drop_reasons=force_drop_reasons,
        )
        venv = diff_params(
            integration=i_norm, connector=c_norm, yml_param_names=yml_param_names,
            connector_dir=connector_dir, integration_raw=integration_raw,
            connector_raw=connector_raw, integration_dropped=i_drop,
            connector_dropped=c_drop, allow_missing=args.allow_missing,
            allow_extra=args.allow_extra, allow_mismatch=args.allow_mismatch,
        )
        venv["variant_id"] = variant.id
        venv["enabled_capabilities"] = variant.enabled_capability_ids
        venv["fetch_flags"] = dict(variant.fetch_flags)
        venv["captures"] = {"integration": integration_raw, "connector": connector_raw}
        venv["normalizer_dropped"] = {"integration": i_drop, "connector": c_drop}
        venv["creation_payloads"] = {
            "integration": integration_payload, "connector": connector_payload,
        }
        variant_envelopes = [venv]
    else:
        # Normal path: run every variant live.
        variant_envelopes = []
        for variant in variants:
            venv, hint = _run_one_variant(
                variant=variant,
                parity_inputs=parity_inputs,
                args=args,
                xsoar_client=xsoar_client,
                yml_data=yml_data,
                yml_configuration=yml_configuration,
                yml_param_names=yml_param_names,
                integration_yml=integration_yml,
                integration_brand=integration_brand,
                connector_id=connector_id,
                connector_dir=connector_dir,
                force_keep=force_keep,
                force_drop=force_drop,
                force_drop_reasons=force_drop_reasons,
            )
            if hint == 2:
                # A capture failure is setup-blocked for the WHOLE run.
                log.error("Variant %s capture failed → setup-blocked.", variant.id)
                return 2
            variant_envelopes.append(venv)

    # ── Aggregate envelope across variants ──
    n_variants = len(variant_envelopes)
    n_pass = sum(1 for v in variant_envelopes if v.get("status") == "pass")
    n_fail = n_variants - n_pass
    aggregate = {
        "status": "pass" if n_fail == 0 else "fail",
        "integration_id": args.integration_id,
        "connector_id": connector_id,
        "summary": {
            "n_variants": n_variants,
            "n_variants_pass": n_pass,
            "n_variants_fail": n_fail,
        },
        "variants": variant_envelopes,
        "inputs": {
            "integration_id": args.integration_id,
            "integration_yml": integration_yml,
            "integration_brand": integration_brand,
            "connector_id": connector_id,
            "connector_dir": connector_dir,
            "capabilities": [
                {"id": c.id, "sub_capabilities": [sc.id for sc in c.sub_capabilities]}
                for c in parity_inputs.capabilities
            ],
            "variants": [
                {
                    "id": v.id,
                    "enabled_capabilities": v.enabled_capability_ids,
                    "fetch_flags": dict(v.fetch_flags),
                    "active_profile_id": getattr(v, "active_profile_id", None),
                }
                for v in variants
            ],
            "profiles": [
                {"id": p.id, "interpolated": p.interpolated} for p in parity_inputs.profiles
            ],
            "allow_missing": args.allow_missing,
            "allow_extra": args.allow_extra,
            "allow_mismatch": args.allow_mismatch,
        },
    }

    # ── Emit the aggregate envelope to stdout ──
    print(json.dumps(aggregate, indent=2, sort_keys=False, default=str))

    # ── Persist the run (Phase 7) ──
    # Guarded so a write failure logs a warning but NEVER changes the exit-code
    # contract (0 pass / 1 parity-fail / 2 setup-blocked).
    try:
        result_path = results_ledger.write_result(
            aggregate,
            connector_id=connector_id,
            integration_id=args.integration_id,
        )
        results_ledger.append_ledger(
            aggregate,
            integration_id=args.integration_id,
            connector_id=connector_id,
            result_file=str(result_path),
        )
        log.info("Result written: %s", result_path)
    except Exception as e:  # noqa: BLE001 — persistence must never change exit code
        log.warning("Failed to persist result (exit code unchanged): %s", e)

    # ── Exit code ──
    if aggregate["status"] == "pass":
        log.info(
            "✅ PARITY PASS — all %d variant(s) passed.", n_variants,
        )
        return 0
    else:
        log.error(
            "❌ PARITY FAIL — %d/%d variant(s) failed: %s",
            n_fail,
            n_variants,
            [v.get("variant_id") for v in variant_envelopes if v.get("status") != "pass"],
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
