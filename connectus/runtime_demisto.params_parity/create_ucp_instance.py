#!/usr/bin/env python3
"""create_ucp_instance — thin CLI wrapper around :mod:`ucp_capture`.

Provides the interactive flow (Slack-permissions reminder, pretty-printed status
messages) by delegating all real work to :func:`ucp_capture.capture_ucp_params`.

Driven entirely by ``--integration-id`` (REQUIRED): the resolver derives the
connector, ALL (sub-)capabilities, profiles, and the auth mapping. There are NO
connector-specific defaults.

For the end-to-end parity test that diffs UCP-side params vs XSOAR-side params,
use ``check_param_parity.py`` (the orchestrator), not this script.

Prerequisites:
    1. Request permissions in the ``#xdr-permissions-dev`` Slack channel.
    2. ``gcloud`` CLI and ``kubectl`` must be installed and authenticated.
    3. ``.env`` must contain ``TENANT_ID``, ``DEMISTO_BASE_URL``,
       ``DEMISTO_API_KEY``, ``XSIAM_AUTH_ID``, and ``CONNECTUS_REPO_DIR``.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid

import resolver as resolver_mod
from resolver import ResolverError
from ucp_capture import (
    DEFAULT_TENANT_ID,
    DEFAULT_UCP_PORT,
    capture_ucp_params,
)
from xsoar_capture import create_client

# Make the shared connectus env loader importable (connectus/ is not a package).
from pathlib import Path as _Path  # noqa: E402

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader.
load_env()

log = logging.getLogger("create_ucp_instance")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="create_ucp_instance",
        description=(
            "Create a UCP connector instance (with the params-parity probe) for "
            "the integration resolved from --integration-id, then dump the "
            "captured demisto.params()."
        ),
    )
    p.add_argument(
        "--integration-id",
        required=True,
        help="XSOAR Integration ID (REQUIRED). Everything else is resolved from it.",
    )
    p.add_argument(
        "--tenant-id",
        default=DEFAULT_TENANT_ID,
        help="UCP tenant id. [default: from TENANT_ID in .env]",
    )
    p.add_argument(
        "--ucp-port",
        type=int,
        default=DEFAULT_UCP_PORT,
        help="Local port to bind the port-forward to.",
    )
    p.add_argument(
        "--keep-instance",
        action="store_true",
        help="Leave the UCP instance alive after capture (debugging).",
    )
    p.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip the interactive prerequisites prompt.",
    )
    return p.parse_args(argv)


def _prereq_reminder(gke_project: str) -> bool:
    """Show the prerequisites prompt; return True if the user wants to continue."""
    log.info("⚠️  Prerequisites:")
    log.info("    1. Request permissions in #xdr-permissions-dev:")
    log.info(
        "       permissions role=xsoar-content-tier1, project=%s, "
        "reason=port forwarding for testing, approver=<your username>",
        gke_project,
    )
    log.info("")
    try:
        input("    Press Enter to continue (or Ctrl+C to abort)... ")
        return True
    except KeyboardInterrupt:
        log.info("Aborted.")
        return False


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
        # force=True is required because importing xsoar_capture runs
        # logging.basicConfig() at module-import time (with no stream → stderr).
        # basicConfig is a no-op once the root logger already has a handler, so
        # without force=True our stream=sys.stdout would be silently ignored and
        # records would land on the pre-installed stderr handler. force=True
        # removes that handler and reinstalls one on stdout (matching the prior
        # print(...) behavior).
        force=True,
    )

    log.info("🔧 UCP Instance Creator (with params-parity probe)")
    log.info("━" * 60)
    log.info("")

    if not args.tenant_id:
        log.error("❌ TENANT_ID is not set. Add it to .env or pass --tenant-id.")
        return 2

    # Resolve everything from the integration id.
    try:
        parity_inputs = resolver_mod.resolve(args.integration_id)
    except ResolverError as e:
        log.error("❌ Resolver failed for %r: %s", args.integration_id, e)
        return 2

    gke_project = f"qa2-test-{args.tenant_id}"
    if not args.yes and not _prereq_reminder(gke_project):
        return 0
    log.info("")

    log.info("🔌 Connecting to XSOAR tenant for the mirror-lookup + magic-key inject step...")
    try:
        xsoar_client = create_client()
    except Exception as e:
        log.error("   ❌ Could not build XSOAR client: %s", e)
        return 1
    log.info("   ✅ XSOAR client ready.")
    log.info("")

    cap_ids = [c.id for c in parity_inputs.capabilities]
    profile_ids = [p.id for p in parity_inputs.profiles]
    log.info(
        "🚀 Driving UCP capture for connector=%r capabilities=%s profiles=%s...",
        parity_inputs.connector_id,
        cap_ids,
        profile_ids,
    )
    log.info("")

    instance_name = f"Connector_instance_{parity_inputs.connector_id.title()}_Parity_{uuid.uuid4().hex[:8]}"
    captured, _ = capture_ucp_params(
        xsoar_client=xsoar_client,
        xsoar_brand_name=parity_inputs.integration_brand,
        parity_inputs=parity_inputs,
        instance_values={},  # dummy-filled by the builder; no real values needed here
        connector_id=parity_inputs.connector_id,
        tenant_id=args.tenant_id,
        instance_name=instance_name,
        ucp_port=args.ucp_port,
        keep_instance=args.keep_instance,
    )

    log.info("")
    if captured is None:
        log.error("❌ Capture failed. See logs above for details.")
        return 1

    log.info("✅ Captured UCP-side demisto.params() (%d keys):", len(captured))
    log.info("Created UCP instance name: %s", instance_name)
    log.info("━" * 60)
    log.info(json.dumps(captured, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
