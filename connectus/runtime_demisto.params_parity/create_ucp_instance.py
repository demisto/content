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
    print("⚠️  Prerequisites:")
    print("    1. Request permissions in #xdr-permissions-dev:")
    print(
        f"       permissions role=xsoar-content-tier1, project={gke_project}, "
        f"reason=port forwarding for testing, approver=<your username>"
    )
    print()
    try:
        input("    Press Enter to continue (or Ctrl+C to abort)... ")
        return True
    except KeyboardInterrupt:
        print("\n    Aborted.")
        return False


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("🔧 UCP Instance Creator (with params-parity probe)")
    print("━" * 60)
    print()

    if not args.tenant_id:
        print("❌ TENANT_ID is not set. Add it to .env or pass --tenant-id.")
        return 2

    # Resolve everything from the integration id.
    try:
        parity_inputs = resolver_mod.resolve(args.integration_id)
    except ResolverError as e:
        print(f"❌ Resolver failed for {args.integration_id!r}: {e}")
        return 2

    gke_project = f"qa2-test-{args.tenant_id}"
    if not args.yes and not _prereq_reminder(gke_project):
        return 0
    print()

    print("🔌 Connecting to XSOAR tenant for the mirror-lookup + magic-key inject step...")
    try:
        xsoar_client = create_client()
    except Exception as e:
        print(f"   ❌ Could not build XSOAR client: {e}")
        return 1
    print("   ✅ XSOAR client ready.")
    print()

    cap_ids = [c.id for c in parity_inputs.capabilities]
    profile_ids = [p.id for p in parity_inputs.profiles]
    print(
        f"🚀 Driving UCP capture for connector={parity_inputs.connector_id!r} "
        f"capabilities={cap_ids} profiles={profile_ids}..."
    )
    print()

    instance_name = f"{parity_inputs.connector_id.title()} Parity {uuid.uuid4().hex[:8]}"
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

    print()
    if captured is None:
        print("❌ Capture failed. See logs above for details.")
        return 1

    print(f"✅ Captured UCP-side demisto.params() ({len(captured)} keys):")
    print(json.dumps(captured, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
