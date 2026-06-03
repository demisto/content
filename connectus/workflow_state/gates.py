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

import subprocess
from dataclasses import dataclass
from typing import Callable, Optional


def _repo_root() -> str:
    """Resolve the repo root (``BASE_DIR``) lazily.

    Imported lazily (not at module top) to avoid a circular import:
    ``config_loader`` imports this module, and ``csv_io`` (which defines
    ``BASE_DIR``) imports ``config_loader``.
    """
    from workflow_state.csv_io import BASE_DIR
    return BASE_DIR


# How many bytes of captured stdout/stderr to surface in a verdict. Keeps
# error envelopes readable while still showing the operator the failing
# output's tail.
_OUTPUT_TAIL_BYTES = 4000

# NOTE: there is deliberately NO bypass for checkpoint gates. Unlike the
# auth-parity gate (which has CONNECTUS_SKIP_AUTH_PARITY), a gated
# checkpoint MUST run its command and pass — there is no env var or flag
# to skip it.


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
# Only the ``precommit`` gate is ACTIVE in Phase 1. ``param_parity`` and
# ``make_validate`` are deferred (see the design doc §6.1 / §6.3) and are
# intentionally NOT registered yet — wiring them in later is purely
# additive (register a GateSpec here + add ``gate:`` to the YAML step).

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
