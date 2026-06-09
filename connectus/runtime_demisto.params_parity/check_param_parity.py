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

from dotenv import load_dotenv

import resolver as resolver_mod
import results_ledger
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

load_dotenv()

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
        "--no-scrub-results",
        action="store_true",
        help=(
            "DEBUGGING ONLY: write the persisted result JSON with RAW captures "
            "(do NOT redact demisto.params() values). Default is to scrub, because "
            "the server may inject real tokens into demisto.params()."
        ),
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


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

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

    # force_keep = the params the resolver decided to compare (includes
    # interpolated-profile auth fields that are YML type-4/9 but DO arrive at
    # runtime). force_drop = the hard ignore-list the resolver dropped.
    force_keep: set[str] = set(parity_inputs.compare_params)
    force_drop: set[str] = {
        name
        for name, reason in parity_inputs.ignored_params.items()
        if reason == "hard_ignore_list"
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
    if not os.path.isabs(integration_yml):
        # Resolve relative paths against the workspace root (one up from this script).
        candidate = os.path.abspath(integration_yml)
        if not os.path.exists(candidate):
            log.error("integration-yml not found: %s (resolved to %s)", integration_yml, candidate)
            return 2
        integration_yml = candidate

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

    # ── Bidirectional push: pre-compute the dummy dict ONCE and pass it to BOTH
    #    sides ──
    #
    # Both sides receive the SAME guaranteed-different dummy values (never the
    # connector's configuration defaults). Any remaining diff finding is then a
    # real connector bug (missing field, extra field, or genuine value
    # transformation gone wrong) rather than test-setup drift.
    #
    # `fill_params_from_yml` walks the YML's configuration list and, for every
    # param, produces a dummy value via `generate_dummy_value_for_param`.
    shared_dummies = fill_params_from_yml(yml_configuration, {})
    log.info(
        "Pre-computed %d shared dummy values to push to BOTH sides.",
        len(shared_dummies),
    )

    # The CONNECTOR side keys configuration/auth by connector FIELD id, while
    # shared_dummies is keyed by xsoar PARAM id. Build a connector-keyed copy so
    # serializer-renamed fields (e.g. xsoar `url` → connector `domain`) and
    # interpolated auth fields receive the SAME value the integration side uses.
    connector_instance_values: dict = dict(shared_dummies)
    for xsoar_param, connector_field in parity_inputs.param_to_connector_field.items():
        if xsoar_param in shared_dummies and connector_field != xsoar_param:
            connector_instance_values[connector_field] = shared_dummies[xsoar_param]

    # ── INTEGRATION-side capture (legacy XSOAR flow) ──
    if args.skip_xsoar:
        if not args.integration_capture_file:
            log.error("--skip-xsoar requires --integration-capture-file")
            return 2
        log.info("Loading INTEGRATION-side capture from %s", args.integration_capture_file)
        integration_raw = _load_dict_from_json_file(args.integration_capture_file)
    else:
        log.info("=" * 70)
        log.info("Capturing INTEGRATION-side demisto.params() via legacy XSOAR flow...")
        log.info("=" * 70)
        integration_raw = capture_xsoar_params(
            integration_yml_path=integration_yml,
            overrides=shared_dummies,  # full pre-computed dummy dict
            client=xsoar_client,
        )
    if integration_raw is None:
        # A capture FAILURE is a setup/runtime problem (tenant unreachable, flow
        # error), NOT a real parity diff. The wrapper maps 2 → "setup-blocked"
        # (exit 11), distinct from 1 → "parity-fail" (exit 10). See design §4.
        log.error("INTEGRATION-side capture failed. See logs above.")
        return 2
    log.info("INTEGRATION-side captured %d keys.", len(integration_raw))

    # ── CONNECTOR-side capture (new UCP flow) ──
    if args.skip_ucp:
        if not args.connector_capture_file:
            log.error("--skip-ucp requires --connector-capture-file")
            return 2
        log.info("Loading CONNECTOR-side capture from %s", args.connector_capture_file)
        connector_raw = _load_dict_from_json_file(args.connector_capture_file)
    else:
        log.info("=" * 70)
        log.info("Capturing CONNECTOR-side demisto.params() via UCP flow...")
        log.info("=" * 70)
        connector_raw = capture_ucp_params(
            xsoar_client=xsoar_client,
            xsoar_brand_name=integration_brand,
            parity_inputs=parity_inputs,
            # The bidirectional push: the SAME values that fed the INTEGRATION
            # side, keyed by connector field id. The builder enables ALL handler
            # (sub-)capabilities and pushes these into the configuration + the
            # interpolated-profile auth fields (never connector defaults).
            instance_values=connector_instance_values,
            connector_id=connector_id,
        )
    if connector_raw is None:
        # Capture FAILURE = setup-blocked (return 2), not a parity diff (1).
        # See design §4 / the wrapper's exit-code mapping.
        log.error("CONNECTOR-side capture failed. See logs above.")
        return 2
    log.info("CONNECTOR-side captured %d keys.", len(connector_raw))

    # ── Normalize both sides with the deterministic IGNORE policy ──
    # force_keep carries the resolver's compare set (incl. interpolated-profile
    # auth fields); force_drop carries the hard ignore-list.
    integration_norm, integration_dropped = normalize_for_diff(
        integration_raw, yml_configuration, side="integration",
        force_keep=force_keep, force_drop=force_drop,
    )
    connector_norm, connector_dropped = normalize_for_diff(
        connector_raw, yml_configuration, side="connector",
        force_keep=force_keep, force_drop=force_drop,
    )
    log.info(
        "After normalization: INTEGRATION %d→%d (dropped %d), CONNECTOR %d→%d (dropped %d)",
        len(integration_raw), len(integration_norm), len(integration_dropped),
        len(connector_raw), len(connector_norm), len(connector_dropped),
    )

    # ── Diff ──
    log.info("=" * 70)
    log.info("Diffing normalized params...")
    log.info("=" * 70)
    envelope = diff_params(
        integration=integration_norm,
        connector=connector_norm,
        yml_param_names=yml_param_names,
        connector_dir=connector_dir,
        # Pass the raw captures + dropped-logs so the diff can synthesize
        # OK_IGNORED entries with the original raw values + drop reasons.
        integration_raw=integration_raw,
        connector_raw=connector_raw,
        integration_dropped=integration_dropped,
        connector_dropped=connector_dropped,
        allow_missing=args.allow_missing,
        allow_extra=args.allow_extra,
        allow_mismatch=args.allow_mismatch,
    )

    # Attach the raw captures (before normalization) so the report is fully
    # self-contained for triage. Operators can compare these against the
    # filtered/diffed view without re-running the live capture.
    envelope["captures"] = {
        "integration": integration_raw,
        "connector": connector_raw,
    }

    # Attach the normalizer drop-log so it's clear WHY any key didn't show up
    # in per_param or dropped.
    envelope["normalizer_dropped"] = {
        "integration": integration_dropped,
        "connector": connector_dropped,
    }

    # Attach the resolved inputs used so the report is reproducible.
    envelope["inputs"] = {
        "integration_id": args.integration_id,
        "integration_yml": integration_yml,
        "integration_brand": integration_brand,
        "connector_id": connector_id,
        "connector_dir": connector_dir,
        "capabilities": [
            {"id": c.id, "sub_capabilities": [sc.id for sc in c.sub_capabilities]}
            for c in parity_inputs.capabilities
        ],
        "profiles": [
            {"id": p.id, "interpolated": p.interpolated} for p in parity_inputs.profiles
        ],
        "allow_missing": args.allow_missing,
        "allow_extra": args.allow_extra,
        "allow_mismatch": args.allow_mismatch,
    }

    # ── Emit the envelope to stdout ──
    print(json.dumps(envelope, indent=2, sort_keys=False, default=str))

    # ── Persist the run (Phase 7) ──
    # Write the envelope JSON + append a ledger row BEFORE returning the exit
    # code. Guarded so a write failure logs a warning but NEVER changes the
    # exit-code contract (0 pass / 1 parity-fail / 2 setup-blocked). Captures
    # are scrubbed by default (the server may inject real tokens); pass
    # --no-scrub-results to keep raw values for debugging.
    try:
        result_path = results_ledger.write_result(
            envelope,
            connector_id=connector_id,
            integration_id=args.integration_id,
            scrub=not args.no_scrub_results,
        )
        results_ledger.append_ledger(
            envelope,
            integration_id=args.integration_id,
            connector_id=connector_id,
            result_file=result_path.name,
        )
        # Logged at INFO so the deploy_and_test wrapper's captured output points
        # the operator straight at the persisted artifact.
        log.info("Result written: %s", result_path)
    except Exception as e:  # noqa: BLE001 — persistence must never change exit code
        log.warning("Failed to persist result (exit code unchanged): %s", e)

    # ── Exit code ──
    if envelope["status"] == "pass":
        log.info("✅ PARITY PASS — %d/%d keys OK", envelope["summary"]["n_ok"], envelope["summary"]["n_total"])
        return 0
    else:
        log.error(
            "❌ PARITY FAIL — %d failure(s), %d warning(s) across %d total keys",
            envelope["summary"]["n_fail"],
            envelope["summary"]["n_warn"],
            envelope["summary"]["n_total"],
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
