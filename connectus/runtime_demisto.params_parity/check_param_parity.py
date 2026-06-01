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

For the MVP this is wired to:

  * Integration: Salesforce IAM
  * Connector: ``salesforce`` from :file:`test_data/connectors/salesforce/`
  * Profile: ``oauth2_client_credentials.salesforce``
  * Capability: ``automation-and-remediation`` ONLY

All knobs can be overridden via CLI flags.

Example::

    cd connectus/runtime_demisto.params_parity
    python check_param_parity.py
    # → prints the JSON envelope, exits 0 if parity OK, non-zero otherwise.

    # With allow-flags to downgrade specific findings to warn-level:
    python check_param_parity.py \\
        --allow-missing --allow-mismatch

    # Pointing at a different integration YML / connector:
    python check_param_parity.py \\
        --integration-yml /path/to/Other.yml \\
        --integration-brand "Other Integration" \\
        --connector-id other \\
        --connector-dir /path/to/other-connector/ \\
        --profile oauth2_client_credentials.other
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from diff import _load_serializer_mappings, diff_params
from normalizers import normalize_for_diff
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
# Defaults — MVP wiring for Salesforce IAM × Salesforce connector
# ============================================================================

DEFAULT_INTEGRATION_YML = "Packs/Salesforce/Integrations/Salesforce_IAM/Salesforce_IAM.yml"
DEFAULT_INTEGRATION_BRAND = "Salesforce IAM"
DEFAULT_CONNECTOR_DIR = "connectus/runtime_demisto.params_parity/test_data/connectors/salesforce"
DEFAULT_CONNECTOR_ID = "salesforce"
DEFAULT_PROFILE_ID = "oauth2_client_credentials.salesforce"
DEFAULT_CAPABILITY = "automation-and-remediation"
DEFAULT_DOMAIN_VALUE = "test.salesforce.com"
DEFAULT_AUTH_VALUES = {
    "client_key": "dummy_client_key",
    "client_secret": "dummy_client_secret",
}


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
            "IGNORE policy."
        ),
    )

    p.add_argument(
        "--integration-yml",
        default=DEFAULT_INTEGRATION_YML,
        help=(
            "Path to the integration YML to test (relative to the workspace "
            "or absolute). [default: %(default)s]"
        ),
    )
    p.add_argument(
        "--integration-brand",
        default=DEFAULT_INTEGRATION_BRAND,
        help=(
            "Integration brand name (equals the YML `name`). Used to find "
            "the XSOAR-mirrored instance UCP creates. [default: %(default)s]"
        ),
    )

    p.add_argument(
        "--connector-id",
        default=DEFAULT_CONNECTOR_ID,
        help="UCP connector id. [default: %(default)s]",
    )
    p.add_argument(
        "--connector-dir",
        default=DEFAULT_CONNECTOR_DIR,
        help=(
            "Path to the connector's YAML directory. Used by the diff engine "
            "to attribute EXTRA_IN_CONNECTOR findings to their source file. "
            "[default: %(default)s]"
        ),
    )
    p.add_argument(
        "--profile",
        default=DEFAULT_PROFILE_ID,
        help="UCP connection profile id. [default: %(default)s]",
    )
    p.add_argument(
        "--capability",
        default=DEFAULT_CAPABILITY,
        help=(
            "UCP capability to enable (POC supports ONE capability at a time). "
            "[default: %(default)s]"
        ),
    )
    p.add_argument(
        "--domain",
        default=DEFAULT_DOMAIN_VALUE,
        help="Value for the connector's general_configurations.domain field. "
             "[default: %(default)s]",
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


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Parse the integration YML once (used by both captures + the normalizer) ──
    if not os.path.isabs(args.integration_yml):
        # Resolve relative paths against the workspace root (one up from this script).
        candidate = os.path.abspath(args.integration_yml)
        if not os.path.exists(candidate):
            log.error("integration-yml not found: %s (resolved to %s)", args.integration_yml, candidate)
            return 2
        args.integration_yml = candidate

    log.info("Parsing integration YML: %s", args.integration_yml)
    yml_data = parse_integration_yml(args.integration_yml)
    yml_configuration = yml_data.get("configuration", []) or []
    yml_param_names = {p.get("name") for p in yml_configuration if p.get("name")}
    log.info(
        "Integration: %s — %d params declared in YML",
        yml_data.get("name") or args.integration_brand,
        len(yml_param_names),
    )

    # ── Build the shared XSOAR client (reused by both capture sides) ──
    try:
        xsoar_client = create_client()
    except Exception as e:
        log.error("Could not build XSOAR client: %s", e)
        return 2

    # ── Pre-load the connector's serializer mappings to auto-align dummy values ──
    #
    # The whole point of the parity test is that the integration container should
    # receive the same demisto.params() dict whether configured via XSOAR or via
    # UCP. So when the connector's serializer.yaml maps `domain → url`, the
    # INTEGRATION-side test MUST set `url` to the same value the CONNECTOR-side
    # passes as `domain`. Otherwise we get false-positive VALUE_MISMATCH findings
    # purely from test-setup drift.
    #
    # `by_xsoar_serialized[<xsoar_param>] = <connector_field>` — we use this to
    # build a per-XSOAR-param override map that mirrors the CONNECTOR-side input
    # values.
    by_xsoar_serialized, _ = _load_serializer_mappings(Path(args.connector_dir))

    # The CONNECTOR-side inputs that produce values for serialized XSOAR params.
    # For the MVP this is just the `domain` field — anything else (auth, etc.)
    # is IGNORE'd by the normalizer and never reaches the diff anyway.
    connector_inputs: dict = {
        "domain": args.domain,
        # NOTE: auth-profile values (client_key, client_secret) are intentionally
        # NOT mapped here — those map to type-4/type-9 XSOAR params and are
        # IGNORE'd by the normalizer, so aligning them buys nothing.
    }
    xsoar_overrides: dict = {}
    for xsoar_name, connector_field in by_xsoar_serialized.items():
        if connector_field in connector_inputs:
            xsoar_overrides[xsoar_name] = connector_inputs[connector_field]
            log.info(
                "Auto-aligned INTEGRATION-side override: %s = %r "
                "(via serializer mapping %s ← %s)",
                xsoar_name,
                connector_inputs[connector_field],
                xsoar_name,
                connector_field,
            )

    # ── Bidirectional override push: pre-compute the dummy dict ONCE and pass
    #    it to BOTH sides ──
    #
    # Without this step, the INTEGRATION side gets our guaranteed-different
    # dummies while the CONNECTOR side gets the connector's `configurations.yaml`
    # defaults — producing a flood of VALUE_MISMATCH false-positives that drown
    # out the real bugs. With bidirectional push, both sides see the SAME dummy
    # value, so any remaining diff finding is a real connector bug (missing
    # field, extra field, or genuine value transformation gone wrong).
    #
    # `fill_params_from_yml` walks the YML's configuration list and, for every
    # param, produces a dummy value via `generate_dummy_value_for_param` (which
    # is guaranteed-different-from-the-YML-default). The `xsoar_overrides` we
    # pass take precedence for serializer-mapped fields (e.g. `url` keeps the
    # auto-aligned domain value, NOT the generator's `<override_url>` sentinel).
    shared_dummies = fill_params_from_yml(yml_configuration, xsoar_overrides)
    log.info(
        "Pre-computed %d shared dummy values to push to BOTH sides.",
        len(shared_dummies),
    )

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
            integration_yml_path=args.integration_yml,
            overrides=shared_dummies,  # full pre-computed dummy dict (incl. auto-aligned serializer fields)
            client=xsoar_client,
        )
    if integration_raw is None:
        log.error("INTEGRATION-side capture failed. See logs above.")
        return 1
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
            xsoar_brand_name=args.integration_brand,
            connector_id=args.connector_id,
            profile_id=args.profile,
            selected_capability=args.capability,
            domain_value=args.domain,
            auth_values=DEFAULT_AUTH_VALUES,
            # The bidirectional push: same shared_dummies dict that fed the
            # INTEGRATION-side capture is also merged into the UCP payload's
            # configuration block (filtered to only fields the connector
            # declares — see ucp_capture._build_salesforce_iam_payload).
            connector_config_overrides=shared_dummies,
        )
    if connector_raw is None:
        log.error("CONNECTOR-side capture failed. See logs above.")
        return 1
    log.info("CONNECTOR-side captured %d keys.", len(connector_raw))

    # ── Normalize both sides with the deterministic IGNORE policy ──
    integration_norm, integration_dropped = normalize_for_diff(
        integration_raw, yml_configuration, side="integration",
    )
    connector_norm, connector_dropped = normalize_for_diff(
        connector_raw, yml_configuration, side="connector",
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
        connector_dir=args.connector_dir,
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

    # Attach the args used so the report is reproducible.
    envelope["inputs"] = {
        "integration_yml": args.integration_yml,
        "integration_brand": args.integration_brand,
        "connector_id": args.connector_id,
        "connector_dir": args.connector_dir,
        "profile": args.profile,
        "capability": args.capability,
        "domain": args.domain,
        "allow_missing": args.allow_missing,
        "allow_extra": args.allow_extra,
        "allow_mismatch": args.allow_mismatch,
    }

    # ── Emit the envelope to stdout ──
    print(json.dumps(envelope, indent=2, sort_keys=False, default=str))

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
