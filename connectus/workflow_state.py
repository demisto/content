#!/usr/bin/env python3
"""Backward-compatible shim for the legacy ``workflow_state`` module.

The real implementation now lives in the ``workflow_state/`` package
sitting next to this file. When Python resolves ``import workflow_state``
it picks the package (directory) over this file because packages take
precedence — so existing callers keep working unchanged.

This file remains so that the long-standing CLI invocation
``python3 connectus/workflow_state.py …`` continues to work: the script
runs as ``__main__`` from this file, which then delegates to
:func:`workflow_state.cli.main`. Every public name the package exports
is also re-exported here via the wildcard import for any caller that
loads this file as a path (instead of as the package).
"""
from __future__ import annotations

# Re-export everything from the package so legacy `from workflow_state
# import …` works whether the loader picked the file or the package.
from workflow_state import *  # noqa: F401,F403
# Underscore-prefixed names are NOT re-exported by `*`; pull them in
# explicitly for the few tests that import them by name.
from workflow_state import (  # noqa: F401
    _auth_other_connection_summary,
    _auth_param_sources,
    _can_advance_to,
    _check_params_to_commands_overlap,
    _example_value_for,
    _format_step_for_listing,
    _git_user_name,
    _normalize_rows_with_warning,
    _parse_next_flags,
    _project_xsoar_param_to_yml_id,
    _reset_config_for_testing,
    _resolve_row_or_exit,
    _set_json_data_step,
    _set_step_via_dispatch,
    _summary_value,
)
from workflow_state.cli import main


if __name__ == "__main__":
    main()
