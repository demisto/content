#!/usr/bin/env python3
"""deploy_and_test — the ONE atomic command the skill runs per integration (design §4).

The whole critical section — acquire tenant lock → ``deploy.py`` → ``check_param_parity.py``
(per integration id) → release — runs in a single ``try/finally`` so the per-tenant lock is
ALWAYS released, even if the AI shell forgets, even on an exception. ``tenant_lock`` also
registers ``atexit``/SIGINT/SIGTERM handlers as a belt-and-suspenders second line.

Determinism over model judgment (design §0): ALL waiting / retry / stale-reclaim lives in
``tenant_lock.acquire`` (which blocks internally). This wrapper makes ONE deploy + N parity
runs and exits with a single code the skill branches on. It does NOT auto-retry the lock and
it does NOT call ``markpass`` — the skill does that on exit 0.

Wrapper exit-code contract (EXACT — design §4):
  * ``0``  — deployed + ALL parity passed → skill ``markpass "param parity test passes"``.
  * ``10`` — any parity FAILED (real diff). Cell stays empty. Report params.
  * ``11`` — any parity BLOCKED (setup, e.g. handler not on disk / REPO_DIR unset).
  * ``20`` — deploy failed.
  * ``21`` — deploy timeout.
  * ``30`` — could not acquire the tenant lock (timeout). Report holder + options.

Multi-id worst-case aggregation (still report per-id): setup-block (11) > parity-fail (10)
> pass (0). A deploy failure/timeout short-circuits before any parity run.

Usage::

    cd connectus/runtime_demisto.params_parity
    python deploy_and_test.py --integration-id "Salesforce IAM"
    # future batch (one lock, one deploy, loop parity):
    python deploy_and_test.py --integration-id A --integration-id B --tenant 123
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

import preflight_check
import tenant_lock

_SCRIPT_DIR = Path(__file__).resolve().parent

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(_SCRIPT_DIR.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader.
load_env()

log = logging.getLogger("deploy_and_test")

# Subprocess command exit codes from the underlying tools (their contracts).
_DEPLOY_OK, _DEPLOY_FAIL, _DEPLOY_TIMEOUT = 0, 1, 2
_PARITY_PASS, _PARITY_FAIL, _PARITY_BLOCK = 0, 1, 2

# Wrapper exit codes (design §4).
EXIT_ALL_PASS = 0
EXIT_PARITY_FAIL = 10
EXIT_PARITY_BLOCK = 11
EXIT_DEPLOY_FAIL = 20
EXIT_DEPLOY_TIMEOUT = 21
EXIT_LOCK_BUSY = 30
EXIT_PREFLIGHT_FAIL = 40

# Absolute paths to the tools we shell out to (always run from the package dir).
_DEPLOY_PY = _SCRIPT_DIR / "deploy.py"
_PARITY_PY = _SCRIPT_DIR / "check_param_parity.py"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="deploy_and_test",
        description=(
            "Atomic deploy + param-parity wrapper. Acquires a per-tenant lock, runs "
            "deploy.py once, then check_param_parity.py for each --integration-id, and "
            "always releases the lock. Exits with a single code the skill branches on."
        ),
    )
    p.add_argument(
        "--integration-id",
        action="append",
        dest="integration_ids",
        required=True,
        help=(
            "XSOAR Integration ID (repeatable). The POC normally passes one; the list "
            "future-proofs batch (deploy ONCE, loop parity under ONE lock)."
        ),
    )
    p.add_argument(
        "--tenant",
        default=None,
        help="Tenant (ICaaS) id. Defaults to .env TENANT_ID (one tenant per shell).",
    )
    p.add_argument(
        "--max-wait",
        type=int,
        default=tenant_lock.ACQUIRE_MAX_WAIT,
        help="Max seconds acquire blocks before reporting the tenant busy (exit 30).",
    )
    p.add_argument(
        "--force-unlock",
        action="store_true",
        help="Reclaim the tenant lock even if a holder looks fresh (use when it's dead).",
    )
    p.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip the prerequisite checks (env/repo/probe/tooling/resolver). Not recommended.",
    )
    p.add_argument(
        "--skip-deploy",
        action="store_true",
        help="Skip the deploy step and go straight to param-parity (assumes the "
             "connector is ALREADY deployed to the tenant). For local iteration; "
             "default is to deploy.",
    )
    return p.parse_args(argv)


def _resolve_tenant(cli_tenant: str | None) -> str:
    """--tenant wins; else .env TENANT_ID. Usage error if neither.

    One tenant per shell — TENANT_ID is a single id (no comma list).
    """
    if cli_tenant:
        return cli_tenant.strip()
    env_tenant = os.getenv("TENANT_ID", "").strip()
    if env_tenant:
        return env_tenant
    raise SystemExit(
        "usage error: no tenant given and TENANT_ID is unset in .env "
        "(pass --tenant <id>)."
    )


# ---------------------------------------------------------------------------
# Subprocess runners (mockable seams for tests)
# ---------------------------------------------------------------------------
def _run_deploy(tenant: str, commit_path: str | None = None) -> int:
    """Run deploy.py --tenant <t> from the package dir; return its exit code.

    When ``commit_path`` is given, pass ``--commit-path`` so deploy.py
    stages+commits the connector dir before pushing (else the deploy branch may
    not contain the connector at all).
    """
    cmd = [sys.executable, str(_DEPLOY_PY), "--tenant", tenant]
    if commit_path:
        cmd += ["--commit-path", commit_path]
    log.info("Running deploy: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(_SCRIPT_DIR))
    return proc.returncode


def _run_parity(integration_id: str) -> int:
    """Run check_param_parity.py --integration-id <id>; return its exit code."""
    cmd = [sys.executable, str(_PARITY_PY), "--integration-id", integration_id]
    log.info("Running param-parity: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(_SCRIPT_DIR))
    return proc.returncode


def _summary(integration_id: str, result: str, code: int) -> None:
    """Machine-greppable per-integration summary line."""
    print(f"DEPLOY_AND_TEST_RESULT integration={integration_id} result={result} exit={code}")


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
def _run_parity_for_all(integration_ids: list[str]) -> int:
    """Run parity for every id, report per-id, aggregate worst-case.

    Worst-case ordering (design §4): setup-block (11) > parity-fail (10) > pass (0).
    """
    worst = EXIT_ALL_PASS
    for integration_id in integration_ids:
        rc = _run_parity(integration_id)
        if rc == _PARITY_PASS:
            _summary(integration_id, "PASS", EXIT_ALL_PASS)
        elif rc == _PARITY_FAIL:
            _summary(integration_id, "PARITY_FAIL", EXIT_PARITY_FAIL)
            worst = max(worst, EXIT_PARITY_FAIL)
        else:  # treat any non-0/1 as setup-blocked (parity contract: 2)
            _summary(integration_id, "SETUP_BLOCK", EXIT_PARITY_BLOCK)
            worst = max(worst, EXIT_PARITY_BLOCK)
    return worst


def _run_preflight(integration_ids: list[str]) -> bool:
    """Run preflight checks; print the report. Return True iff all passed."""
    # Use the first id for the resolver check (a per-id deploy shares one branch).
    results = preflight_check.run_preflight(integration_ids[0] if integration_ids else None)
    print("Param-parity preflight check:")
    print(preflight_check.format_results(results))
    return preflight_check.all_passed(results)


def run(
    integration_ids: list[str],
    tenant: str,
    *,
    max_wait: int,
    force: bool,
    skip_preflight: bool = False,
    skip_deploy: bool = False,
) -> int:
    """Preflight → acquire → deploy → parity(per id) → release(finally)."""
    # ── Preflight (cheap, before paying for a deploy) ──
    if not skip_preflight:
        if not _run_preflight(integration_ids):
            print(
                "\n❌ Preflight failed — fix the prerequisites above and re-run "
                "(or pass --skip-preflight to bypass).",
                file=sys.stderr,
            )
            for integration_id in integration_ids:
                _summary(integration_id, "PREFLIGHT_FAIL", EXIT_PREFLIGHT_FAIL)
            return EXIT_PREFLIGHT_FAIL

    # ── Acquire (blocks internally; NO auto-retry here) ──
    try:
        shell_id = tenant_lock.acquire(
            tenant,
            integration_id=",".join(integration_ids),
            max_wait=max_wait,
            force=force,
        )
    except tenant_lock.TenantLockTimeout as e:
        holder = e.holder or {}
        print(
            f"Tenant {tenant} is held by shell {holder.get('shell_id')} "
            f"(integration {holder.get('integration_id')}) since "
            f"{holder.get('acquired_at')} and did not free within {max_wait}s. "
            f"It may be stuck. Options: (a) wait and retry later, (b) use a different "
            f"tenant, (c) --force-unlock --tenant {tenant} if the holder is dead.",
            file=sys.stderr,
        )
        for integration_id in integration_ids:
            _summary(integration_id, "LOCK_BUSY", EXIT_LOCK_BUSY)
        return EXIT_LOCK_BUSY

    try:
        # ── Resolve the connector dir for the (first) integration so deploy.py
        # can stage+commit it before pushing. Best-effort: if resolution fails,
        # fall back to no commit (deploy assumes content already committed). ──
        import resolver as _resolver_mod
        try:
            _pi = _resolver_mod.resolve(integration_ids[0])
            commit_path = _pi.connector_folder_path
        except Exception:
            commit_path = None

        if skip_deploy:
            log.warning("--skip-deploy set: skipping deploy, running parity against the "
                        "ALREADY-deployed connector on tenant %s.", tenant)
        else:
            # ── Deploy ONCE (commit connector + ff-push + pipeline) ──
            deploy_rc = _run_deploy(tenant, commit_path)
            if deploy_rc == _DEPLOY_FAIL:
                for integration_id in integration_ids:
                    _summary(integration_id, "DEPLOY_FAIL", EXIT_DEPLOY_FAIL)
                return EXIT_DEPLOY_FAIL
            if deploy_rc == _DEPLOY_TIMEOUT:
                for integration_id in integration_ids:
                    _summary(integration_id, "DEPLOY_TIMEOUT", EXIT_DEPLOY_TIMEOUT)
                return EXIT_DEPLOY_TIMEOUT
            # deploy_rc == 0 → continue to parity.

        # ── Param-parity per id (loop under the same lock) ──
        return _run_parity_for_all(integration_ids)
    finally:
        # ── ALWAYS release the lock we hold ──
        tenant_lock.release(tenant, shell_id)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    tenant = _resolve_tenant(args.tenant)
    log.info(
        "deploy_and_test: tenant=%s integrations=%s",
        tenant, ",".join(args.integration_ids),
    )
    return run(
        args.integration_ids,
        tenant,
        max_wait=args.max_wait,
        force=args.force_unlock,
        skip_preflight=args.skip_preflight,
        skip_deploy=args.skip_deploy,
    )


if __name__ == "__main__":
    sys.exit(main())
