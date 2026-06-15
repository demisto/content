#!/usr/bin/env python3
"""session_setup — establish the param-parity session ONCE, by a human.

Run this in a NORMAL terminal (NOT via the agent), on the israel-gw VPN, at the
very beginning of a migration batch. It establishes + verifies the entire
environment the per-integration ``deploy_and_test.py`` runs need, so that the
agent can then run N integrations fully unattended without doing any privileged
environment work itself.

What it does, in order (design: SESSION_ENV_ARCHITECTURE.md, FINAL):
  1. load_env(); resolve the content repo (from __file__) and CONNECTUS_REPO_DIR.
  2. VERIFY preconditions it can't fix → STOP with the exact fix on any failure:
       .env vars, branch, connectors repo, probe, gcloud/kubectl on PATH,
       gcloud authenticated, gke-gcloud-auth-plugin present.
  3. ESTABLISH (in THIS terminal, where ~/.config/gcloud + ~/.kube are writable —
     no config copy, no sandbox writability problem):
       - gcloud container clusters get-credentials  (configures kubeconfig)
       - VERIFY GKE control-plane reachable (israel-gw VPN) — after credentials.
       - start a SESSION-SCOPED, detached, idempotent kubectl port-forward.
  4. WRITE the session descriptor (.session/parity_session.json).
  5. HEALTH GATE: localhost:<port> live + gcloud account set.
  6. Print success + the one-time idex Auto-Approve→Execute reminder.

Re-running is safe (idempotent): a healthy session is reused (no duplicate
port-forward); a dead one is cleanly re-established.

Exit codes:
  * 0 — session ready.
  * 1 — a VERIFY/ESTABLISH step failed (details printed; fix and re-run).
  * 2 — usage error.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR.parent))

from env_loader import find_repo_root, load_env  # noqa: E402

load_env()

import preflight_check  # noqa: E402
import session_env  # noqa: E402

log = logging.getLogger("session_setup")


def _resolve_tenant(cli_tenant: str | None) -> str:
    if cli_tenant:
        return cli_tenant.strip()
    env_tenant = os.getenv("TENANT_ID", "").strip()
    if env_tenant:
        return env_tenant
    raise SystemExit(
        "usage error: no tenant given and TENANT_ID is unset in .env (pass --tenant <id>)."
    )


def _get_credentials(tenant_id: str) -> tuple[bool, str]:
    """Run gcloud get-credentials in THIS (human) terminal. Returns (ok, detail).

    Writable ~/.config/gcloud + ~/.kube here — no CLOUDSDK_CONFIG redirect needed.
    """
    cmd = [
        "gcloud", "container", "clusters", "get-credentials",
        session_env.gke_cluster(tenant_id),
        "--zone", session_env.DEFAULT_GKE_ZONE,
        "--project", session_env.gke_project(tenant_id),
    ]
    log.info("Configuring GKE credentials: %s", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return False, (res.stderr or "").strip()
    return True, "credentials configured"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = argparse.ArgumentParser(
        prog="session_setup",
        description="Establish the param-parity session once (human, on israel-gw VPN).",
    )
    p.add_argument("--tenant", default=None, help="Tenant id (defaults to .env TENANT_ID).")
    p.add_argument("--port", type=int, default=session_env.DEFAULT_UCP_PORT,
                   help=f"Local UCP port (default {session_env.DEFAULT_UCP_PORT}).")
    p.add_argument("--check", action="store_true",
                   help="Only CHECK whether a live session already exists; do NOT "
                        "establish anything. Exit 0 if live, non-zero if setup is needed. "
                        "(Lets the agent decide deterministically whether to prompt the human.)")
    args = p.parse_args(argv)

    # --check: deterministic liveness probe the AGENT runs at the start of the
    # param-parity step. Exit 0 (already set up → proceed, do NOT prompt) or 1
    # (not set up → the agent asks the human to run session_setup.py once).
    if args.check:
        try:
            desc = session_env.assert_session_live()
        except session_env.SessionNotReady as e:
            print(f"SESSION_NOT_READY: {e}")
            return 1
        print(f"SESSION_READY: localhost:{desc.ucp_port} (tenant {desc.tenant_id})")
        return 0

    tenant = _resolve_tenant(args.tenant)
    content_repo = str(find_repo_root())
    connectus_repo = (os.getenv("CONNECTUS_REPO_DIR") or "").strip()

    print("=" * 70)
    print("  Param-parity SESSION SETUP")
    print("=" * 70)

    # ── Step 2: VERIFY (incl. gcloud authed + auth plugin) ──
    results = preflight_check.run_preflight(None, for_session_setup=True)
    print("\nPreconditions:")
    print(preflight_check.format_results(results))
    if not preflight_check.all_passed(results):
        failed = [r.name for r in results if not r.ok]
        print(f"\n❌ Setup FAILED ({len(failed)}): " + ", ".join(failed))
        print("   Fix the above, then re-run session_setup.py.")
        return 1

    # ── Reuse a healthy existing session (idempotent) ──
    existing = session_env.load_descriptor()
    if (existing
            and existing.tenant_id == tenant
            and session_env.gcloud_auth_ok()
            and session_env._pid_alive(existing.port_forward_pid)
            and session_env.port_is_live(existing.ucp_port)):
        print(f"\n✅ A healthy session already exists "
              f"(localhost:{existing.ucp_port}, pid={existing.port_forward_pid}). Reusing it.")
        _print_ready(existing.ucp_port)
        return 0

    # ── Step 3a: ESTABLISH GKE credentials (writable terminal) ──
    ok, detail = _get_credentials(tenant)
    if not ok:
        print(f"\n❌ gcloud get-credentials failed:\n{detail}")
        low = detail.lower()
        if "operation not permitted" in low or "unable to create" in low:
            print("   This looks like a writability error — are you running this in a "
                  "NORMAL terminal (not via the agent)? Run session_setup.py yourself.")
        else:
            print("   If this is an auth error, run `gcloud auth login` and re-run.")
        return 1

    # ── Step 3b: VERIFY GKE reachable (after credentials) ──
    reach = preflight_check._check_gke_reachable()
    print(f"\n  {'✅' if reach.ok else '❌'} {reach.name}: {reach.detail}")
    if not reach.ok:
        print("   Connect to the israel-gw VPN, then re-run session_setup.py.")
        return 1

    # ── Step 3c: ESTABLISH the session-scoped, idempotent port-forward ──
    try:
        pid, pod_name = session_env.ensure_port_forward(
            tenant, args.port,
            existing_pid=(existing.port_forward_pid if existing else None),
        )
    except RuntimeError as e:
        print(f"\n❌ Port-forward failed:\n{e}")
        return 1

    # ── Step 4: WRITE the descriptor ──
    desc = session_env.SessionDescriptor(
        tenant_id=tenant,
        ucp_port=args.port,
        port_forward_pid=pid,
        pod_name=pod_name or (existing.pod_name if existing else None),
        content_repo=content_repo,
        connectus_repo=connectus_repo,
        created_ts=time.time(),
        gcloud_account=session_env.current_gcloud_account(),
    )
    session_env.write_descriptor(desc)

    # ── Step 5: HEALTH GATE ──
    if not session_env.port_is_live(args.port):
        print(f"\n❌ Health gate failed: localhost:{args.port} is not reachable after setup.")
        return 1
    if not session_env.gcloud_auth_ok():
        print("\n❌ Health gate failed: gcloud has no active account after setup.")
        return 1

    _print_ready(args.port)
    return 0


def _print_ready(port: int) -> None:
    print("\n" + "=" * 70)
    print(f"  ✅ SESSION READY — port-forward live on localhost:{port}")
    print("=" * 70)
    print("  ℹ️  One-time idex host setting (if not already on):")
    print("      Auto-Approve → Execute must be ON so the agent runs the")
    print("      per-integration commands unattended.")
    print("  ▶  Now tell the agent to proceed with the migration batch.")
    print("  ⏹  When the batch is done, run session_teardown.py to stop the tunnel.")


if __name__ == "__main__":
    sys.exit(main())
