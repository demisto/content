#!/usr/bin/env python3
"""CLI entrypoint for the ``workflow_state`` package.

Run as ``python3 connectus/workflow_state.py <command> [args ...]``.
The full implementation lives in the :mod:`workflow_state` package
sitting next to this file; this script just delegates to
:func:`workflow_state.cli.main`.
"""
from __future__ import annotations

from workflow_state.cli import main


if __name__ == "__main__":
    main()
