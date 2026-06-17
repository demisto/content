"""Self-executing checkpoint gates for the connectus migration workflow.

A *gate* is a shell command bound to a ``kind: checkpoint`` step via the
step's ``gate`` field (see :class:`workflow_state.types.Step`). When a
gated checkpoint is ``markpass``-ed, the engine RUNS the gate command and
only writes the pass marker if the command succeeds (exit 0) — mirroring
the auth-parity gate inside ``set-auth``.

This module is intentionally dependency-light: it imports only
``BASE_DIR`` from ``csv_io`` and the stdlib. It does NOT import
``workflow_state.api`` (which imports this module), so the integration's
on-disk directory is resolved by the caller and passed in as ``abs_dir``.

Design of record: ``connectus/self_executing_gates_design.md``.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402


def _repo_root() -> str:
    """Resolve the repo root (``BASE_DIR``) lazily.

    Imported lazily (not at module top) to avoid a circular import:
    ``config_loader`` imports this module, and ``csv_io`` (which defines
    ``BASE_DIR``) imports ``config_loader``.
    """
    from workflow_state.csv_io import BASE_DIR
    return BASE_DIR


# Default directory name of the ConnectUs ("unified connectors") repo,
# which lives as a SIBLING of the content repo in the shared workspace
# (e.g. ``/Users/<you>/dev/unified-connectors-content`` next to
# ``/Users/<you>/dev/content``). The ``make validate`` step runs against
# this repo's Makefile, not the content repo.
_CONNECTUS_REPO_DIRNAME = "unified-connectors-content"

# Path to the standalone handler-param-coverage checker (lives at the
# connectus/ package root, a sibling of this package's parent dir). Run as
# a subprocess by the ``handler_param_coverage`` gate.
_HANDLER_PARAM_COVERAGE_SCRIPT = str(
    Path(__file__).resolve().parent.parent / "check_handler_param_coverage.py"
)

# Path to the atomic deploy + param-parity wrapper (lives in the
# ``runtime_demisto.params_parity`` dir at the connectus/ package root, a
# sibling of this package's parent dir). Run as a subprocess by the
# ``param_parity`` gate. The wrapper acquires a per-tenant lock, deploys
# once, runs check_param_parity.py, and always releases the lock.
_DEPLOY_AND_TEST_SCRIPT = str(
    Path(__file__).resolve().parent.parent
    / "runtime_demisto.params_parity" / "deploy_and_test.py"
)

# Env var to override the auto-resolved ConnectUs repo path (e.g. when the
# sibling layout differs, or for tests). When set, it wins over the
# sibling-of-content-repo default.
_CONNECTUS_REPO_ENV = "CONNECTUS_REPO_DIR"

# Operator override for the handler_param_coverage gate. When truthy, the gate
# appends ``--force`` to the checker so a genuine coverage FAIL is overridden to
# a pass (uncovered params are still reported, never hidden). Used ONLY on
# explicit operator instruction — see the connectus-migration skill, Step 9.
_HANDLER_COVERAGE_FORCE_ENV = "CONNECTUS_HANDLER_COVERAGE_FORCE"


def _coverage_force_enabled() -> bool:
    """Whether the handler-param-coverage gate should run with ``--force``."""
    load_env()
    return os.environ.get(_HANDLER_COVERAGE_FORCE_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _connectus_repo_root() -> str:
    """Resolve the ConnectUs repo root (where ``make validate`` runs).

    Resolution order:

    1. ``$CONNECTUS_REPO_DIR`` if set (explicit override).
    2. The sibling of the content repo named ``unified-connectors-content``
       (the shared-workspace convention).

    The path is returned as-is even if it does not exist on disk — the
    gate runner surfaces a "could not be launched" verdict (cwd missing)
    rather than this resolver guessing further.
    """
    # Ensure the canonical root .env is loaded (idempotent) before reading
    # CONNECTUS_REPO_DIR, then fall back to the sibling-repo convention.
    load_env()
    override = os.environ.get(_CONNECTUS_REPO_ENV)
    if override and override.strip():
        return os.path.abspath(override.strip())
    parent = os.path.dirname(_repo_root())
    return os.path.join(parent, _CONNECTUS_REPO_DIRNAME)


def _derive_handler_id(integration_id: str) -> str:
    """Derive the connector handler folder name from an integration id.

    Mirrors ``connectus_migration.manifest_generator.derive_handler_id``
    (guide §3.8): ``"xsoar-" + integration_id`` lowercased with internal
    whitespace runs collapsed to single dashes. Inlined here (3 lines) to
    keep this dependency-light module free of a heavy manifest_generator
    import.
    """
    slug = re.sub(r"\s+", "-", integration_id.strip().lower())
    return f"xsoar-{slug}"


def _integration_yml_abs(integration_id: str) -> str:
    """Resolve the absolute integration-YML path for ``integration_id``.

    Reads the ``Integration File Path`` cell from the pipeline CSV (the
    same source :mod:`workflow_state.api` uses) and joins it to the repo
    root. Returns ``""`` when the id or its file path is not found — the
    coverage script then exits with a usage error (exit 2), which the gate
    runner surfaces as a normal failing verdict.

    Imported lazily (not at module top) to avoid a circular import:
    ``csv_io`` imports ``config_loader`` which imports this module.
    """
    from workflow_state.csv_io import find_row, load_csv

    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return ""
    yml_rel = rows[idx].get("Integration File Path", "").strip()
    if not yml_rel:
        return ""
    return os.path.join(_repo_root(), yml_rel)


def _derive_connector_folder_rel(integration_id: str) -> str:
    """Derive the default ``connectors/<slug>`` folder for an integration.

    Mirrors ``connectus_migration.manifest_generator.title_to_slug`` (the
    auto-runner uses the Integration ID itself as the connector title, so
    the on-disk slug is the id lowercased with internal whitespace runs
    collapsed to single dashes). This is the deterministic location the
    manifest generator writes to, so the gate can resolve the handler dir
    WITHOUT a manually-set ``Connector Folder Path`` CSV cell.

    Inlined (one regex) to keep this dependency-light module free of a
    heavy ``manifest_generator`` import.
    """
    slug = re.sub(r"\s+", "-", integration_id.strip().lower())
    return os.path.join("connectors", slug)


def _handler_dir_abs(integration_id: str) -> str:
    """Resolve the absolute connector handler dir for ``integration_id``.

    Layout (guide §3.8):
    ``<connectus_repo>/<Connector Folder Path>/components/handlers/<handler-id>``
    where ``<handler-id>`` is :func:`_derive_handler_id`.

    The Connector Folder Path is resolved in this order:

    1. The ``Connector Folder Path`` CSV cell, when explicitly set (an
       operator override for non-standard layouts).
    2. Otherwise it is **derived** as ``connectors/<slug>`` from the
       integration id (:func:`_derive_connector_folder_rel`) — the same
       deterministic location the manifest generator writes to. This means
       a manual ``set-connector-path`` is no longer required for the
       standard sibling-repo layout; the ConnectUs repo root itself is
       already env-wired via ``$CONNECTUS_REPO_DIR``
       (:func:`_connectus_repo_root`).

    Returns ``""`` only when the integration id is not found in the CSV —
    the coverage script then exits with a usage error (exit 2), surfaced
    as a failing verdict.

    Imported lazily (see :func:`_integration_yml_abs`).
    """
    from workflow_state.csv_io import find_row, load_csv

    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return ""
    connector_folder_rel = rows[idx].get("Connector Folder Path", "").strip()
    if not connector_folder_rel:
        # No explicit override — derive the standard connectors/<slug> path.
        connector_folder_rel = _derive_connector_folder_rel(integration_id)
    handler_id = _derive_handler_id(integration_id)
    return os.path.join(
        _connectus_repo_root(),
        connector_folder_rel,
        "components",
        "handlers",
        handler_id,
    )


# How many bytes of captured stdout/stderr to surface in a verdict. Keeps
# error envelopes readable while still showing the operator the failing
# output's tail.
_OUTPUT_TAIL_BYTES = 4000

# NOTE: there is deliberately NO bypass for checkpoint gates. Unlike the
# auth-parity gate (which has CONNECTUS_SKIP_AUTH_PARITY), a gated
# checkpoint MUST run its command and pass — there is no env var or flag
# to skip it. This no-bypass policy explicitly covers ``param_parity`` too:
# there is NO ``--no-gate`` flag and NO skip/force env var (e.g. no
# CONNECTUS_SKIP_AUTH_PARITY analogue) for it — the parity wrapper MUST run
# and exit 0. The only operator lever is the generic ``markpass --timeout=N``,
# which never bypasses the pass/fail verdict.


@dataclass(frozen=True)
class GateSpec:
    """Declarative description of one checkpoint gate.

    Attributes:
        name: Registry key (matches the step's ``gate`` field).
        build_argv: ``(abs_dir, integration_id) -> argv`` — the command to
            run, as an argv list (never a shell string).
        build_cwd: ``(abs_dir, integration_id) -> cwd`` — the working
            directory the command runs in.
        default_timeout: Seconds before the gate is killed and fails.
        description: Short human-readable summary for diagnostics.
    """

    name: str
    build_argv: Callable[[str, str], list[str]]
    build_cwd: Callable[[str, str], str]
    default_timeout: int
    description: str


# ---------------------------------------------------------------------------
# Gate registry
# ---------------------------------------------------------------------------
#
# ``precommit``, ``make_validate``, ``handler_param_coverage``, and
# ``param_parity`` are ACTIVE. Wiring a new gate is purely additive
# (register a GateSpec here + add ``gate:`` to the YAML step).

GATES: dict[str, GateSpec] = {
    "precommit": GateSpec(
        name="precommit",
        # `demisto-sdk pre-commit -i <integration dir>` runs lint, unit
        # tests, and validate in docker for the integration.
        build_argv=lambda abs_dir, iid: [
            "demisto-sdk", "pre-commit", "-i", abs_dir,
        ],
        # Run from the repo root so demisto-sdk resolves repo config.
        build_cwd=lambda abs_dir, iid: _repo_root(),
        # pre-commit pulls docker images and runs the full suite — be
        # generous. Override per-call with the CLI --timeout= flag.
        default_timeout=1800,
        description="demisto-sdk pre-commit (lint + unit tests + validate)",
    ),
    "make_validate": GateSpec(
        name="make_validate",
        # `make validate` validates all connectors (JSON Schema + OPA) in
        # the ConnectUs repo. The integration dir (`abs_dir`) is NOT used —
        # the connectors live in the sibling ConnectUs repo, not the
        # content repo, so this gate keys off that repo's Makefile instead.
        build_argv=lambda abs_dir, iid: ["make", "validate"],
        # Run from the ConnectUs repo root (the shared-workspace sibling),
        # where the Makefile with the `validate` target lives.
        build_cwd=lambda abs_dir, iid: _connectus_repo_root(),
        # JSON Schema + OPA validation over all connectors — fast relative
        # to the docker-backed precommit gate, but allow headroom.
        default_timeout=600,
        description="make validate (ConnectUs repo: JSON Schema + OPA)",
    ),
    "handler_param_coverage": GateSpec(
        name="handler_param_coverage",
        # `python3 connectus/check_handler_param_coverage.py` fails (exit 1)
        # when a non-hidden integration-YML param is NOT covered by the
        # connector handler's params, or errors (exit 2) on a path-
        # resolution problem. Runs BEFORE the make_validate gate so a
        # missing param is caught before connector-level schema validation.
        #
        # Operator override: set ``CONNECTUS_HANDLER_COVERAGE_FORCE=1`` to
        # append ``--force`` so a genuine FAIL is overridden to a pass (the
        # uncovered params are still reported, never hidden). Use ONLY on
        # explicit instruction when the uncovered params are known-safe to
        # skip (e.g. a deprecated, label-less auth alternative). See the
        # connectus-migration skill, Step 9.
        build_argv=lambda abs_dir, iid: [
            sys.executable,
            _HANDLER_PARAM_COVERAGE_SCRIPT,
            "--handler-path", _handler_dir_abs(iid),
            "--integration-yml", _integration_yml_abs(iid),
            *(["--force"] if _coverage_force_enabled() else []),
        ],
        # Run from the content repo root (paths resolved above are absolute,
        # so cwd is incidental — match the precommit gate's root cwd).
        build_cwd=lambda abs_dir, iid: _repo_root(),
        # Pure local YAML parsing — fast. Allow modest headroom.
        default_timeout=120,
        description=(
            "check_handler_param_coverage (handler covers every non-hidden "
            "integration-YML param)"
        ),
    ),
    "param_parity": GateSpec(
        name="param_parity",
        # `python3 connectus/runtime_demisto.params_parity/deploy_and_test.py
        # --integration-id <id>` performs the atomic live deploy + param-parity
        # check: acquire the per-tenant lock, run deploy.py once, run
        # check_param_parity.py, then always release the lock. It exits with a
        # single code the gate runner branches on: 0 → pass; any non-zero
        # (10 parity fail, 11 blocked, 20 deploy fail, 21 timeout, 30 lock busy,
        # 40 preflight fail, or any other) → reject. There is NO bypass: no
        # --no-gate flag and no skip/force env var.
        build_argv=lambda abs_dir, iid: [
            sys.executable,
            _DEPLOY_AND_TEST_SCRIPT,
            "--integration-id", iid,
        ],
        # The script path above is absolute and the wrapper re-roots its own
        # children, so run from the content repo root (matches precommit/
        # handler_param_coverage root cwd).
        build_cwd=lambda abs_dir, iid: _repo_root(),
        # Live deploy + parity over a tenant — be generous. Override per-call
        # with the CLI --timeout= flag.
        default_timeout=2400,
        description=(
            "deploy_and_test (live deploy + param-parity; exit 0 only, no bypass)"
        ),
    ),
}


def known_gate_names() -> list[str]:
    """Sorted list of registered gate names (for config-loader validation)."""
    return sorted(GATES.keys())


def is_known_gate(name: str) -> bool:
    """Whether ``name`` resolves to a registered gate."""
    return name in GATES


def _tail(text: Optional[str]) -> str:
    if not text:
        return ""
    return text[-_OUTPUT_TAIL_BYTES:]


def run_gate(
    gate_name: str,
    abs_dir: str,
    integration_id: str,
    timeout: Optional[int] = None,
) -> dict:
    """Run a checkpoint gate and return a verdict dict.

    The verdict mirrors the shape produced by the auth-parity evaluator:
    a boolean ``allow`` plus a human-readable ``reason``, augmented with
    the subprocess ``exit_code`` and captured output tails for
    diagnostics.

    Args:
        gate_name: Registry key (the step's ``gate`` field).
        abs_dir: Absolute path to the integration's directory on disk.
        integration_id: The integration id (for argv/cwd builders).
        timeout: Optional override of the gate's ``default_timeout``.

    Returns:
        ``{"allow": bool, "reason": str, "exit_code": int|None,
           "stdout_tail": str, "stderr_tail": str, "gate": str}``.
        Infrastructure failures (unknown gate, timeout, spawn error) set
        ``allow=False`` and ``exit_code=None``.
    """
    spec = GATES.get(gate_name)
    if spec is None:
        return {
            "allow": False,
            "reason": (
                f"unknown gate {gate_name!r}; registered: {known_gate_names()}"
            ),
            "exit_code": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "gate": gate_name,
        }

    argv = spec.build_argv(abs_dir, integration_id)
    cwd = spec.build_cwd(abs_dir, integration_id)
    effective_timeout = timeout if timeout is not None else spec.default_timeout

    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "allow": False,
            "reason": (
                f"gate {gate_name!r} timed out after {effective_timeout}s "
                f"(`{' '.join(argv)}`)"
            ),
            "exit_code": None,
            "stdout_tail": _tail(exc.stdout if isinstance(exc.stdout, str) else None),
            "stderr_tail": _tail(exc.stderr if isinstance(exc.stderr, str) else None),
            "gate": gate_name,
        }
    except (OSError, ValueError) as exc:
        # OSError: command not found / not executable. ValueError: bad argv.
        return {
            "allow": False,
            "reason": (
                f"gate {gate_name!r} could not be launched: "
                f"{type(exc).__name__}: {exc}"
            ),
            "exit_code": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "gate": gate_name,
        }

    passed = proc.returncode == 0
    reason = (
        "passed"
        if passed
        else f"`{' '.join(argv)}` exited {proc.returncode}"
    )
    return {
        "allow": passed,
        "reason": reason,
        "exit_code": proc.returncode,
        "stdout_tail": _tail(proc.stdout),
        "stderr_tail": _tail(proc.stderr),
        "gate": gate_name,
    }
