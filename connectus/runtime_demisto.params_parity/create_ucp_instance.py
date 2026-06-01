#!/usr/bin/env python3
"""create_ucp_instance — thin CLI wrapper around :mod:`ucp_capture`.

Provides the original interactive flow (Slack-permissions reminder, optional
post-test cleanup confirmation, pretty-printed status messages) by delegating
all real work to :func:`ucp_capture.capture_ucp_params`.

The MVP is wired for Salesforce + Salesforce-IAM with the
``oauth2_client_credentials.salesforce`` profile and the
``automation-and-remediation`` capability ONLY. Other capabilities are
intentionally not enabled — see docs in :mod:`ucp_capture`.

For the end-to-end parity test that diffs UCP-side params vs XSOAR-side params,
use ``check_param_parity.py`` (the orchestrator built in Phase 6), not this
script.

Prerequisites:
    1. Request permissions in the ``#xdr-permissions-dev`` Slack channel.
    2. ``gcloud`` CLI and ``kubectl`` must be installed and authenticated.
    3. ``.env`` must contain ``UCP_TENANT_ID``, ``DEMISTO_BASE_URL``,
       ``DEMISTO_API_KEY``, ``XSIAM_AUTH_ID``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid

from dotenv import load_dotenv

from ucp_capture import (
    DEFAULT_CONNECTOR_ID,
    DEFAULT_TENANT_ID,
    DEFAULT_UCP_PORT,
    capture_ucp_params,
)
from xsoar_capture import create_client

load_dotenv()

log = logging.getLogger("create_ucp_instance")


# ============================================================
# Configuration — Edit these values OR set them in .env before running
# ============================================================

TENANT_ID = DEFAULT_TENANT_ID
CONNECTOR_ID = DEFAULT_CONNECTOR_ID
INSTANCE_NAME = f"Salesforce Parity {uuid.uuid4().hex[:8]}"
DOMAIN_URL = "test.salesforce.com"
CLIENT_KEY = "dummy_client_key"
CLIENT_SECRET = "dummy_client_secret"
PORT = DEFAULT_UCP_PORT

# Only this capability is enabled — other capabilities of the Salesforce
# connector (saas-posture-config-monitoring, identity) stay disabled by
# design (out of POC scope).
SELECTED_CAPABILITY = "automation-and-remediation"
PROFILE_ID = "oauth2_client_credentials.salesforce"

# XSOAR brand of the integration the connector mirrors to.
XSOAR_BRAND_NAME = "Salesforce IAM"

# Project label used in the permissions-request Slack message (display only).
_GKE_PROJECT = f"qa2-test-{TENANT_ID}" if TENANT_ID else "qa2-test-<TENANT_ID>"


def _prereq_reminder() -> bool:
    """Show the prerequisites prompt; return True if the user wants to continue."""
    print("⚠️  Prerequisites:")
    print(f"    1. Request permissions in #xdr-permissions-dev:")
    print(f'       permissions role=xsoar-content-tier1, project={_GKE_PROJECT}, '
          f"reason=port forwarding for testing, approver=<your username>")
    print()
    try:
        input("    Press Enter to continue (or Ctrl+C to abort)... ")
        return True
    except KeyboardInterrupt:
        print("\n    Aborted.")
        return False


def main() -> int:
    print("🔧 UCP Salesforce Instance Creator (with params-parity probe)")
    print("━" * 60)
    print()

    if not TENANT_ID:
        print("❌ UCP_TENANT_ID is not set. Add it to .env or export it as an env var.")
        return 2

    if not _prereq_reminder():
        return 0
    print()

    print(f"🔌 Connecting to XSOAR tenant for the mirror-lookup + magic-key inject step...")
    try:
        xsoar_client = create_client()
    except Exception as e:
        print(f"   ❌ Could not build XSOAR client: {e}")
        return 1
    print(f"   ✅ XSOAR client ready.")
    print()

    print(f"🚀 Driving UCP capture for connector={CONNECTOR_ID!r} "
          f"capability={SELECTED_CAPABILITY!r} profile={PROFILE_ID!r}...")
    print()

    captured = capture_ucp_params(
        xsoar_client=xsoar_client,
        xsoar_brand_name=XSOAR_BRAND_NAME,
        connector_id=CONNECTOR_ID,
        tenant_id=TENANT_ID,
        profile_id=PROFILE_ID,
        selected_capability=SELECTED_CAPABILITY,
        domain_value=DOMAIN_URL,
        auth_values={"client_key": CLIENT_KEY, "client_secret": CLIENT_SECRET},
        instance_name=INSTANCE_NAME,
        ucp_port=PORT,
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
