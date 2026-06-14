#!/usr/bin/env python3
"""session_teardown — stop the param-parity session (kill tunnel, clear state).

Run this in a normal terminal at the END of a migration batch. It terminates the
session-scoped kubectl port-forward started by ``session_setup.py`` and removes
the session descriptor so a later run starts clean.

Safe to run even if no session exists (no-op).

Exit codes:
  * 0 — teardown complete (or nothing to tear down).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR.parent))

import session_env  # noqa: E402

log = logging.getLogger("session_teardown")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    desc = session_env.load_descriptor()
    if desc is None:
        print("No active param-parity session — nothing to tear down.")
        return 0

    if desc.port_forward_pid:
        print(f"Stopping port-forward (pid={desc.port_forward_pid}, localhost:{desc.ucp_port})...")
        session_env.kill_port_forward(desc.port_forward_pid)
    session_env.clear_descriptor()
    print("✅ Session torn down (port-forward stopped, descriptor cleared).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
