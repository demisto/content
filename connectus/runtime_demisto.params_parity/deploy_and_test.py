#!/usr/bin/env python3
"""deploy_and_test — the ONE command the skill runs per integration (design §4).

LOCK SCOPE (2026-06 — deploy-only lock): the per-tenant lock is held ONLY
around the ``deploy.py`` step (pack uploads + connector commit/push + GitLab
pipeline) and RELEASED before ``check_param_parity.py`` runs. The param-parity
capture phase does not mutate shared tenant state — it creates per-run
uuid-suffixed XSOAR + UCP instances, matches the XSOAR mirror by that unique
name, and deletes only its own instances — so multiple integrations can run
their (slow) capture/diff phases concurrently on one tenant with NO lock.
Serializing only the deploy keeps the lock hold-time short and unlocks
parallelism across integrations. The lock is ALWAYS released — on the normal
phase-1→2 boundary, in the ``finally`` on a deploy-phase failure, and via
``tenant_lock``'s own ``atexit``/SIGINT/SIGTERM handlers as a second line.

  * When the effective deploy mutates NOTHING on the tenant (``--skip-deploy``,
    or no packs to upload AND ``--skip-connector-deploy``), the lock is NOT
    acquired at all — the fully-parallel "everything already on the tenant"
    path (e.g. after ``preupload_parity_packs.py`` + ``--skip-all-uploads``).
  * ``--keep-lock-through-parity`` restores the legacy behavior (hold the lock
    across BOTH deploy and parity — the whole critical section serialized).
  * SAME-CONNECTOR CAVEAT: the connector manifest is shared, singular tenant
    state; two integrations under the same connector id that BOTH deploy it can
    still race (the deploy-only lock guards the write, not the capture's
    read-window). Pair concurrent same-connector siblings with
    ``--skip-connector-deploy`` so no manifest write happens during captures.

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

Prerequisite: a human runs ``session_setup.py`` ONCE per batch (on the israel-gw
VPN) to establish the param-parity session (GKE creds + the session-scoped
kubectl port-forward). This wrapper only ASSUMES that session; it never sets up
the environment itself.

Usage (run from the content-repo root; no ``cd`` needed)::

    python3 connectus/runtime_demisto.params_parity/deploy_and_test.py --integration-id "Salesforce IAM"
    # batch (one lock, one deploy, loop parity):
    python3 connectus/runtime_demisto.params_parity/deploy_and_test.py --integration-id A --integration-id B --tenant 123
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

import preflight_check
import session_env
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

# The patched Base pack (carries the param-parity probe in CommonServerPython) is
# ALWAYS uploaded alongside the integration's own pack before the connector deploy.
_BASE_PACK = "Packs/Base"


def _integration_pack_dir(integration_yml_path: str) -> str | None:
    """Derive the content-repo pack dir from an integration YML path.

    ``Packs/AMP/Integrations/AMPv2/AMPv2.yml`` -> ``Packs/AMP``. Returns None if
    the path is not under ``Packs/<pack>/`` (so the caller can skip it safely).
    """
    if not integration_yml_path:
        return None
    parts = Path(integration_yml_path).parts
    if len(parts) >= 2 and parts[0] == "Packs":
        return str(Path(parts[0]) / parts[1])
    return None


def _packs_to_upload(
    integration_yml_path: str,
    skip_base_pack: bool = False,
    skip_integration_pack: bool = False,
) -> list[str]:
    """Base pack + the integration's own pack, de-duped, order preserved.

    The patched Base pack is always first (the probe must be present before the
    integration pack so the param-parity capture works). When ``skip_base_pack``
    is True the Base pack is omitted; when ``skip_integration_pack`` is True the
    integration's own pack is omitted. With both False (the default) the
    integration's own pack is appended after Base.

    ``skip_integration_pack`` is for the "everything is already on the tenant"
    case (e.g. after a bulk pre-upload via ``preupload_parity_packs.py``): the
    parity capture only needs the probe + integration code to ALREADY be
    present, not freshly re-uploaded on every run. With both skips True this
    returns an EMPTY list (nothing to upload). An integration that itself lives
    under ``Packs/Base`` combined with ``skip_base_pack=True`` likewise yields
    an empty (or integration-only) list. All acceptable/rare.
    """
    packs = [] if skip_base_pack else [_BASE_PACK]
    if not skip_integration_pack:
        pack_dir = _integration_pack_dir(integration_yml_path)
        if pack_dir and pack_dir not in packs:
            packs.append(pack_dir)
    return packs


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
    p.add_argument(
        "--skip-connector-deploy",
        action="store_true",
        help="Do NOT deploy the ConnectUs connector manifest (skip the git commit "
             "AND the GitLab skinny pipeline), but STILL upload the integration's "
             "own pack. Unlike --skip-deploy (which skips EVERYTHING including the "
             "pack upload), this re-uploads the integration pack against an "
             "ALREADY-deployed connector. For iterating over many integrations.",
    )
    p.add_argument(
        "--skip-base-pack",
        action="store_true",
        help="Do NOT upload the Base pack, but STILL upload the integration's own "
             "pack. Unlike --skip-deploy (which skips EVERYTHING), this assumes the "
             "patched Base pack is already current on the tenant.",
    )
    p.add_argument(
        "--skip-integration-pack",
        action="store_true",
        help="Do NOT upload the integration's own pack (assume it is already "
             "current on the tenant, e.g. after a bulk pre-upload via "
             "preupload_parity_packs.py). The Base pack and connector deploy "
             "still run unless their own skip flags are also set.",
    )
    p.add_argument(
        "--skip-all-uploads",
        action="store_true",
        help="Convenience flag: skip ALL THREE deploy uploads — Base pack, the "
             "integration's own pack, AND the connector manifest deploy (git "
             "commit + GitLab pipeline) — then run parity against what is "
             "ALREADY on the tenant. Equivalent to passing --skip-base-pack "
             "--skip-integration-pack --skip-connector-deploy together. Use "
             "after a bulk pre-upload so each parity run does zero uploads. "
             "When nothing is uploaded the tenant lock is not acquired at all.",
    )
    p.add_argument(
        "--keep-lock-through-parity",
        action="store_true",
        help="Legacy behavior: hold the per-tenant lock across BOTH the deploy "
             "AND the param-parity capture phase (the whole critical section is "
             "serialized). By default the lock is held ONLY around the deploy "
             "and released before parity, so concurrent runs can overlap their "
             "capture phases. Use this for a strictly-serial run.",
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
def _run_deploy(
    tenant: str,
    commit_path: str | None = None,
    upload_packs: list[str] | None = None,
    upload_insecure: bool = False,
    skip_connector_deploy: bool = False,
) -> int:
    """Run deploy.py --tenant <t> from the package dir; return its exit code.

    When ``commit_path`` is given, pass ``--commit-path`` so deploy.py
    stages+commits the connector dir before pushing (else the deploy branch may
    not contain the connector at all).

    When ``upload_packs`` is given, pass one ``--upload-pack`` per pack dir so
    deploy.py uploads them to the tenant (patched Base pack + the integration's
    own pack) BEFORE the connector deploy — this removes the old manual
    "upload Base + integration pack" prerequisite. ``upload_insecure`` adds
    ``--upload-insecure`` (skip TLS validation) for self-signed tenant certs.

    When ``skip_connector_deploy`` is True, append BOTH ``--skip-git`` and
    ``--skip-pipeline`` so deploy.py skips the connector commit + the GitLab
    pipeline but STILL uploads the packs (the ``--upload-pack`` args remain). This
    re-uploads the integration pack against an ALREADY-deployed connector.
    """
    cmd = [sys.executable, str(_DEPLOY_PY), "--tenant", tenant]
    if commit_path:
        cmd += ["--commit-path", commit_path]
    for pack in upload_packs or []:
        cmd += ["--upload-pack", pack]
    if upload_insecure:
        cmd.append("--upload-insecure")
    if skip_connector_deploy:
        cmd += ["--skip-git", "--skip-pipeline"]
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
    skip_connector_deploy: bool = False,
    skip_base_pack: bool = False,
    skip_integration_pack: bool = False,
    keep_lock_through_parity: bool = False,
) -> int:
    """Session-gate → preflight → [lock] deploy [unlock] → parity(per id).

    LOCK SCOPE (2026-06): the per-tenant lock is held ONLY around the deploy
    step (``deploy.py``: pack uploads + connector commit/push + GitLab
    pipeline), then RELEASED before the param-parity capture phase runs. The
    capture phase (``check_param_parity.py``) does not mutate shared tenant
    state — it creates per-run uuid-suffixed XSOAR + UCP instances, matches the
    XSOAR mirror by that unique name, and deletes only its own instances — so
    multiple integrations can run their capture/diff concurrently on the same
    tenant without a lock. Serializing only the deploy keeps the lock hold-time
    short and lets parallel parity runs overlap their (slow) capture phases.

    ⚠️ SAME-CONNECTOR CAVEAT: the connector MANIFEST is shared, singular tenant
    state. Two integrations under the SAME connector id that BOTH deploy that
    connector can still race (B's deploy of ``aws@v2`` can land while A is
    capturing against ``aws``), because the deploy-only lock guards the WRITE,
    not the read-window. Pair concurrent same-connector siblings with
    ``--skip-connector-deploy`` (deploy the connector once up front, then have
    the siblings re-upload only their own pack against the already-deployed
    connector) so no connector-manifest write happens during their captures.

    ``skip_connector_deploy`` re-uploads the integration pack against an
    ALREADY-deployed connector (skips the connector commit + GitLab pipeline but
    keeps the pack upload). ``skip_base_pack`` omits the Base pack from the
    upload; ``skip_integration_pack`` omits the integration's own pack. Setting
    all three (``skip_base_pack`` + ``skip_integration_pack`` +
    ``skip_connector_deploy``) uploads nothing and deploys no connector — parity
    runs entirely against what is ALREADY on the tenant (this is what the CLI's
    ``--skip-all-uploads`` expands to). All of these are moot when
    ``skip_deploy`` is set (which skips the ENTIRE deploy step outright). When
    the effective deploy mutates NOTHING on the tenant (``skip_deploy``, or no
    packs to upload AND no connector deploy), the lock is not acquired at all.

    ``keep_lock_through_parity`` restores the legacy behavior: hold the lock
    across BOTH deploy and parity (the whole critical section is serialized).
    Use it for a strictly-serial run on a tenant where even concurrent captures
    are undesirable.

    EDGE CASE: an integration that itself lives under ``Packs/Base`` combined
    with ``skip_base_pack`` produces an empty upload list (nothing uploaded).
    Acceptable/rare.
    """
    # ── Session gate (the environment is established ONCE by the human-run
    # session_setup.py; here we only ASSUME it, auto-reviving a dead port-forward
    # and hard-stopping with an actionable message on gcloud-auth expiry / no
    # session). This replaces the old per-run gcloud/port-forward setup. ──
    try:
        session_env.assert_session_live()
    except session_env.SessionNotReady as e:
        print(f"\n❌ Param-parity session not ready: {e}", file=sys.stderr)
        for integration_id in integration_ids:
            _summary(integration_id, "SESSION_BLOCK", EXIT_PARITY_BLOCK)
        return EXIT_PARITY_BLOCK

    # ── Preflight (cheap, before paying for a deploy / lock) ──
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

    # ── Footgun visibility: warn loudly for each active skip so an upload-only /
    # iterate-many run is obvious in the logs. (No lock held yet — these are pure
    # local decisions.) ──
    if skip_connector_deploy:
        log.warning("--skip-connector-deploy set: NOT deploying connector "
                    "manifest (git commit + GitLab pipeline).")
    if skip_base_pack:
        log.warning("--skip-base-pack set: NOT uploading Base pack.")
    if skip_integration_pack:
        log.warning("--skip-integration-pack set: NOT uploading the "
                    "integration's own pack.")
    if skip_base_pack and skip_integration_pack and skip_connector_deploy:
        log.warning("All three deploy uploads skipped (Base + integration "
                    "pack + connector): running parity against what is "
                    "ALREADY on the tenant.")
    if skip_deploy and (skip_connector_deploy or skip_base_pack
                        or skip_integration_pack):
        log.warning("--skip-deploy already skips the ENTIRE deploy; "
                    "--skip-connector-deploy/--skip-base-pack/"
                    "--skip-integration-pack are redundant here.")

    # ── Resolve the connector dir + upload set for the (first) integration so
    # deploy.py can stage+commit it before pushing. Best-effort: if resolution
    # fails, fall back to no commit (deploy assumes content already committed).
    # Done BEFORE acquiring the lock — it is pure local work. ──
    import resolver as _resolver_mod
    try:
        _pi = _resolver_mod.resolve(integration_ids[0])
        commit_path = _pi.connector_folder_path
        # --skip-base-pack drops Base; --skip-integration-pack drops the
        # integration's own pack (both False = upload both).
        upload_packs = _packs_to_upload(
            _pi.integration_yml_path,
            skip_base_pack=skip_base_pack,
            skip_integration_pack=skip_integration_pack,
        )
    except Exception:
        commit_path = None
        # Fall back to at least the Base pack (probe) when resolution fails;
        # --skip-base-pack drops it (yields an empty upload list here). The
        # integration pack can't be derived without the resolver, so
        # --skip-integration-pack has no additional effect on this path.
        upload_packs = [] if skip_base_pack else [_BASE_PACK]

    # Self-signed tenant cert in the chain → demisto-sdk upload needs --insecure.
    # Off by default; opt in via DEMISTO_VERIFY_SSL=false (or UPLOAD_INSECURE=true).
    upload_insecure = (
        os.getenv("DEMISTO_VERIFY_SSL", "").strip().lower() in ("false", "0", "no")
        or os.getenv("UPLOAD_INSECURE", "").strip().lower() in ("true", "1", "yes")
    )

    # ── Does the effective deploy actually mutate shared tenant state? ──
    # It writes to the tenant when it uploads ≥1 pack OR deploys the connector
    # manifest. When it writes nothing (--skip-deploy, or no packs AND
    # --skip-connector-deploy), there is nothing to serialize, so we skip the
    # lock entirely — this is the fully-parallel "everything already on the
    # tenant" path (e.g. after a bulk preupload_parity_packs.py + --skip-all-uploads).
    deploy_writes_tenant = (not skip_deploy) and (
        bool(upload_packs) or (not skip_connector_deploy)
    )

    # ── Phase 1: DEPLOY under the (short-lived) tenant lock ──
    # The lock is acquired only when the deploy writes to the tenant, and (unless
    # keep_lock_through_parity) is released the instant the deploy finishes — so
    # the slow parity capture phase runs UNLOCKED and concurrent runs overlap.
    shell_id: str | None = None
    if deploy_writes_tenant:
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
    else:
        log.info(
            "Deploy writes nothing to tenant %s (skip_deploy=%s, packs=%d, "
            "skip_connector_deploy=%s) — NOT acquiring the tenant lock; parity "
            "runs fully unlocked.",
            tenant, skip_deploy, len(upload_packs), skip_connector_deploy,
        )

    try:
        if skip_deploy:
            log.warning("--skip-deploy set: skipping deploy, running parity against the "
                        "ALREADY-deployed connector on tenant %s.", tenant)
        elif not deploy_writes_tenant:
            log.info("Nothing to deploy (no packs + connector deploy skipped); "
                     "proceeding straight to parity.")
        else:
            # ── Deploy ONCE (upload packs + commit connector + ff-push + pipeline) ──
            deploy_rc = _run_deploy(
                tenant, commit_path, upload_packs, upload_insecure,
                skip_connector_deploy=skip_connector_deploy,
            )
            if deploy_rc == _DEPLOY_FAIL:
                for integration_id in integration_ids:
                    _summary(integration_id, "DEPLOY_FAIL", EXIT_DEPLOY_FAIL)
                return EXIT_DEPLOY_FAIL
            if deploy_rc == _DEPLOY_TIMEOUT:
                for integration_id in integration_ids:
                    _summary(integration_id, "DEPLOY_TIMEOUT", EXIT_DEPLOY_TIMEOUT)
                return EXIT_DEPLOY_TIMEOUT
            # deploy_rc == 0 → continue to parity.

        # ── Phase 1→2 boundary: release the deploy lock BEFORE parity, unless
        # the caller asked to hold it across the whole critical section. ──
        if shell_id is not None and not keep_lock_through_parity:
            tenant_lock.release(tenant, shell_id)
            shell_id = None
            log.info("Released tenant lock for %s after deploy; running parity "
                     "phase unlocked.", tenant)

        # ── Phase 2: param-parity per id (UNLOCKED unless keep_lock_through_parity) ──
        return _run_parity_for_all(integration_ids)
    finally:
        # ── ALWAYS release the lock if we still hold it (deploy-phase failure
        # before the early release, or keep_lock_through_parity). Releasing a
        # lock we already released is avoided by the shell_id=None reset. ──
        if shell_id is not None:
            tenant_lock.release(tenant, shell_id)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    tenant = _resolve_tenant(args.tenant)
    log.info(
        "deploy_and_test: tenant=%s integrations=%s",
        tenant, ",".join(args.integration_ids),
    )
    # --skip-all-uploads is sugar for the three granular skips: Base pack +
    # integration pack + connector deploy. OR it in so it composes with any
    # individually-set skip flag.
    skip_base_pack = args.skip_base_pack or args.skip_all_uploads
    skip_integration_pack = args.skip_integration_pack or args.skip_all_uploads
    skip_connector_deploy = args.skip_connector_deploy or args.skip_all_uploads
    return run(
        args.integration_ids,
        tenant,
        max_wait=args.max_wait,
        force=args.force_unlock,
        skip_preflight=args.skip_preflight,
        skip_deploy=args.skip_deploy,
        skip_connector_deploy=skip_connector_deploy,
        skip_base_pack=skip_base_pack,
        skip_integration_pack=skip_integration_pack,
        keep_lock_through_parity=args.keep_lock_through_parity,
    )


if __name__ == "__main__":
    sys.exit(main())
