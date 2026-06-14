#!/usr/bin/env python3
"""preflight_check — verify every prerequisite for a live param-parity run.

The param-parity test (deploy + capture both sides + diff) needs a fair amount
of environment set up: a configured ``.env``, the connectors repo on disk, the
runtime probe present in ``CommonServerPython.py``, the resolver able to map the
integration, and the GKE tooling (``gcloud`` / ``kubectl``) on PATH.

This module runs those checks deterministically and reports a clear pass/fail
per check, so an operator (or the deploy_and_test wrapper) gets ONE green light
before paying for a deploy + UCP capture.

Exit codes (CLI):
  * ``0`` — all checks passed.
  * ``1`` — one or more checks failed (details printed).
  * ``2`` — usage error.

Importable: :func:`run_preflight` returns a list of :class:`CheckResult` and
:func:`all_passed` collapses it to a bool, so the wrapper can gate on it without
shelling out.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Make the shared connectus env loader importable (connectus/ is not a package).
import sys as _sys

_sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader.
load_env()

# This file lives at connectus/runtime_demisto.params_parity/preflight_check.py —
# go up THREE dirs to reach the content-repo workspace root.
_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

#: Path to the runtime probe's host file + the markers that prove it's present.
_COMMON_SERVER_PYTHON = (
    _WORKSPACE_ROOT
    / "Packs" / "Base" / "Scripts" / "CommonServerPython" / "CommonServerPython.py"
)
_PROBE_MARKERS = ("__params_parity_dump__", "PARAMS_PARITY_DUMP::")

#: The deploy pushes CONNECTUS_BRANCH. To make it impossible to push over a
#: shared branch, every engineer works on ONE personal, long-lived branch named
#: ``xsoar-migration-<name>`` (e.g. ``xsoar-migration-joey``). Preflight enforces
#: this exact shape before any git op; generic/shared names are rejected. There
#: is no base branch and no reset — the engineer keeps their branch current via
#: rebase. See _check_branch_name().
import re as _re

_BRANCH_PATTERN = _re.compile(r"^xsoar-migration-[a-z0-9][a-z0-9-]*$")
#: Names that must never be a deploy target even if they were to match loosely.
_SHARED_BRANCH_DENYLIST = frozenset(
    {"stable", "master", "main", "dev", "develop", "xsoar", "xsoar-playground"}
)

#: Env vars that MUST be set for a live deploy + test.
_REQUIRED_ENV = (
    "DEMISTO_BASE_URL",
    "DEMISTO_API_KEY",
    "XSIAM_AUTH_ID",
    "CONNECTUS_REPO_DIR",
    "CONNECTUS_BRANCH",
    "TENANT_ID",
    "GITLAB_TOKEN",
)


@dataclass
class CheckResult:
    """One preflight check outcome."""

    name: str
    ok: bool
    detail: str


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_required_env() -> CheckResult:
    missing = [k for k in _REQUIRED_ENV if not (os.getenv(k) or "").strip()]
    if missing:
        return CheckResult(
            "required .env vars",
            False,
            "missing/empty: " + ", ".join(missing)
            + " (set them in connectus/runtime_demisto.params_parity/.env)",
        )
    return CheckResult("required .env vars", True, "all set: " + ", ".join(_REQUIRED_ENV))


def _check_connectus_repo() -> CheckResult:
    raw = (os.getenv("CONNECTUS_REPO_DIR") or "").strip()
    if not raw:
        return CheckResult("CONNECTUS_REPO_DIR exists", False, "CONNECTUS_REPO_DIR is unset")
    p = Path(raw)
    if not p.is_dir():
        return CheckResult(
            "CONNECTUS_REPO_DIR exists", False, f"not a directory: {p}"
        )
    if not (p / "connectors").is_dir():
        return CheckResult(
            "CONNECTUS_REPO_DIR exists",
            False,
            f"{p} has no connectors/ dir — is this the unified-connectors-content repo?",
        )
    return CheckResult("CONNECTUS_REPO_DIR exists", True, str(p))


def _check_branch_name() -> CheckResult:
    """CONNECTUS_BRANCH (the branch the deploy pushes) MUST be a personal,
    long-lived branch named ``xsoar-migration-<name>``.

    Rationale: the deploy pushes this branch. Enforcing a per-engineer namespaced
    name makes it impossible to push onto a shared branch (stable/master/dev/
    xsoar-playground) or onto a generic name many people might reuse. Each
    engineer reuses ONE branch (no per-run branches → no merge sprawl) and is
    responsible for keeping it current via rebase (there is no base/reset)."""
    branch = (os.getenv("CONNECTUS_BRANCH") or "").strip()
    name = "deploy branch is personal ('xsoar-migration-<name>')"
    if not branch:
        return CheckResult(name, False, "CONNECTUS_BRANCH is unset")
    if branch in _SHARED_BRANCH_DENYLIST:
        return CheckResult(
            name,
            False,
            f"CONNECTUS_BRANCH={branch!r} is a SHARED branch — refusing. Use a "
            f"personal branch 'xsoar-migration-<name>' (e.g. xsoar-migration-joey).",
        )
    if not _BRANCH_PATTERN.match(branch):
        return CheckResult(
            name,
            False,
            f"CONNECTUS_BRANCH={branch!r} must match 'xsoar-migration-<name>' "
            f"(lowercase, e.g. xsoar-migration-joey). The deploy pushes this "
            f"branch; only a personal, namespaced branch is allowed.",
        )
    return CheckResult(name, True, f"CONNECTUS_BRANCH={branch}")


def _check_probe() -> CheckResult:
    if not _COMMON_SERVER_PYTHON.exists():
        return CheckResult(
            "param-parity probe present",
            False,
            f"CommonServerPython.py not found at {_COMMON_SERVER_PYTHON}",
        )
    try:
        text = _COMMON_SERVER_PYTHON.read_text(encoding="utf-8", errors="replace")
    except OSError as e:  # pragma: no cover - defensive
        return CheckResult("param-parity probe present", False, f"could not read file: {e}")
    found = [m for m in _PROBE_MARKERS if m in text]
    if len(found) != len(_PROBE_MARKERS):
        missing = [m for m in _PROBE_MARKERS if m not in text]
        return CheckResult(
            "param-parity probe present",
            False,
            "probe markers missing from CommonServerPython.py: "
            + ", ".join(missing)
            + " — upload the patched Base pack (demisto-sdk upload -i Packs/Base -z -mp platform).",
        )
    return CheckResult(
        "param-parity probe present", True, "markers found in CommonServerPython.py"
    )


def _check_resolver(integration_id: str) -> CheckResult:
    """The resolver must map the integration (CSV row + connector on disk)."""
    try:
        import resolver  # local import so other checks run even if import fails
    except Exception as e:  # pragma: no cover - defensive
        return CheckResult("resolver maps integration", False, f"could not import resolver: {e}")
    try:
        pi = resolver.resolve(integration_id)
    except Exception as e:
        return CheckResult(
            "resolver maps integration",
            False,
            f"resolve({integration_id!r}) failed: {e}",
        )
    caps = ", ".join(c.id for c in pi.capabilities) or "<none>"
    return CheckResult(
        "resolver maps integration",
        True,
        f"connector={pi.connector_id} capabilities=[{caps}] "
        f"compare={len(pi.compare_params)}",
    )


def _check_tool_on_path(tool: str) -> CheckResult:
    path = shutil.which(tool)
    if path:
        return CheckResult(f"{tool} on PATH", True, path)
    return CheckResult(
        f"{tool} on PATH",
        False,
        f"{tool} not found on PATH (required for the UCP-side capture / deploy).",
    )


def _check_gcloud_authed() -> CheckResult:
    """gcloud must have an active account (a valid identity for GKE access).

    Human-only dependency: if unset/expired the operator must run
    ``gcloud auth login`` — the agent cannot perform a browser login.
    """
    import subprocess

    name = "gcloud authenticated"
    try:
        res = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:  # pragma: no cover - defensive
        return CheckResult(name, False, f"gcloud auth check failed to run: {e}")
    account = (res.stdout or "").strip()
    if res.returncode != 0 or not account or account.lower() == "(unset)":
        return CheckResult(
            name, False,
            "no active gcloud account - run `gcloud auth login` in your terminal.",
        )
    return CheckResult(name, True, account)


def _check_auth_plugin() -> CheckResult:
    """gke-gcloud-auth-plugin must be on PATH for kubectl->GKE auth.

    On failure, try to LOCATE the plugin next to the real gcloud (the Homebrew
    cask bundles it in the SDK bin but does NOT symlink it onto PATH). If found,
    emit the exact PATH remedy; otherwise give platform-appropriate install
    advice. The pass/fail semantics depend ONLY on PATH availability — locating
    the bundled binary just makes the failure detail actionable.
    """
    name = "gke-gcloud-auth-plugin present"
    path = shutil.which("gke-gcloud-auth-plugin")
    if path:
        return CheckResult(name, True, path)

    # Not on PATH. Try to find it bundled next to the real gcloud binary.
    gcloud_path = shutil.which("gcloud")
    if gcloud_path:
        real = os.path.realpath(gcloud_path)
        sdk_bin = os.path.dirname(real)
        candidate = os.path.join(sdk_bin, "gke-gcloud-auth-plugin")
        if os.path.isfile(candidate):
            return CheckResult(
                name, False,
                f"gke-gcloud-auth-plugin is installed at {candidate} but not on "
                f"PATH. Add its dir to PATH: "
                f"echo 'export PATH=\"{sdk_bin}:$PATH\"' >> ~/.zshrc && exec zsh  "
                f"(Note: 'gcloud components install' is a no-op for Homebrew-"
                f"managed gcloud, and there is no 'brew install "
                f"gke-gcloud-auth-plugin' formula.)",
            )

    # Truly missing — distinguish macOS/Homebrew from Linux.
    if _sys.platform == "darwin":
        return CheckResult(
            name, False,
            "gke-gcloud-auth-plugin not found on PATH and not bundled next to "
            "gcloud. On macOS reinstall the cask: brew reinstall --cask "
            "google-cloud-sdk, then add the SDK bin to PATH "
            "(e.g. echo 'export PATH=\"$(dirname \"$(readlink -f \"$(which "
            "gcloud)\")\"):$PATH\"' >> ~/.zshrc && exec zsh). Note: 'gcloud "
            "components install' is a no-op for Homebrew-managed gcloud.",
        )
    return CheckResult(
        name, False,
        "gke-gcloud-auth-plugin not found on PATH - install it "
        "(gcloud components install gke-gcloud-auth-plugin, or the apt package "
        "google-cloud-cli-gke-gcloud-auth-plugin).",
    )


def _check_gke_reachable() -> CheckResult:
    """The GKE control-plane must be reachable (i.e. on the israel-gw VPN).

    Lightweight ``kubectl version`` round-trip. A control-plane timeout means
    the host is not on the israel-gw VPN. Assumes ``gcloud get-credentials`` has
    already configured a kubeconfig context (run by session_setup AFTER it).
    """
    import subprocess

    name = "GKE control-plane reachable (israel-gw VPN)"
    try:
        res = subprocess.run(
            ["kubectl", "version", "--output=json", "--request-timeout=10s"],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name, False,
            "kubectl timed out reaching the cluster - connect to the 'israel-gw' VPN.",
        )
    except Exception as e:  # pragma: no cover - defensive
        return CheckResult(name, False, f"kubectl reachability check failed to run: {e}")
    low = (res.stderr or "").lower()
    if res.returncode != 0 and (
        "i/o timeout" in low
        or "unable to connect to the server" in low
        or "couldn't get current server api group list" in low
    ):
        return CheckResult(
            name, False,
            "GKE control-plane unreachable (timeout) - connect to the 'israel-gw' VPN.",
        )
    # A non-connectivity non-zero rc still proves the control-plane answered.
    return CheckResult(name, True, "control-plane answered")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_preflight(
    integration_id: Optional[str],
    *,
    for_session_setup: bool = False,
) -> list[CheckResult]:
    """Run all preflight checks; return the per-check results.

    ``integration_id`` is optional — when None, the resolver check is skipped
    (useful for a pure environment check).

    ``for_session_setup`` — when True, ALSO run the session-establishment VERIFY
    checks the human-run ``session_setup.py`` needs: gcloud authenticated and the
    gke-gcloud-auth-plugin present. (The GKE-reachability check
    ``_check_gke_reachable`` is run separately by session_setup AFTER
    get-credentials, since it needs a configured kubeconfig.)
    """
    results = [
        _check_required_env(),
        _check_branch_name(),
        _check_connectus_repo(),
        _check_probe(),
        _check_tool_on_path("gcloud"),
        _check_tool_on_path("kubectl"),
    ]
    if for_session_setup:
        results.append(_check_gcloud_authed())
        results.append(_check_auth_plugin())
    if integration_id:
        results.append(_check_resolver(integration_id))
    return results


def all_passed(results: list[CheckResult]) -> bool:
    return all(r.ok for r in results)


def format_results(results: list[CheckResult]) -> str:
    lines = []
    for r in results:
        mark = "✅" if r.ok else "❌"
        lines.append(f"  {mark} {r.name}: {r.detail}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="preflight_check",
        description="Verify all prerequisites for a live param-parity deploy + test.",
    )
    p.add_argument(
        "--integration-id",
        default=None,
        help="If given, also verify the resolver can map this integration.",
    )
    args = p.parse_args(argv)

    results = run_preflight(args.integration_id)
    print("Param-parity preflight check:")
    print(format_results(results))
    if all_passed(results):
        print("\n✅ All preflight checks passed.")
        return 0
    failed = [r.name for r in results if not r.ok]
    print(f"\n❌ Preflight FAILED ({len(failed)}): " + ", ".join(failed))
    return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
