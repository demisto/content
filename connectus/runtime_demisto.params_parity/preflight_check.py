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

from dotenv import load_dotenv

load_dotenv()

# This file lives at connectus/runtime_demisto.params_parity/preflight_check.py —
# go up THREE dirs to reach the content-repo workspace root.
_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

#: Path to the runtime probe's host file + the markers that prove it's present.
_COMMON_SERVER_PYTHON = (
    _WORKSPACE_ROOT
    / "Packs" / "Base" / "Scripts" / "CommonServerPython" / "CommonServerPython.py"
)
_PROBE_MARKERS = ("__params_parity_dump__", "PARAMS_PARITY_DUMP::")

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


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_preflight(integration_id: Optional[str]) -> list[CheckResult]:
    """Run all preflight checks; return the per-check results.

    ``integration_id`` is optional — when None, the resolver check is skipped
    (useful for a pure environment check).
    """
    results = [
        _check_required_env(),
        _check_connectus_repo(),
        _check_probe(),
        _check_tool_on_path("gcloud"),
        _check_tool_on_path("kubectl"),
    ]
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
