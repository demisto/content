"""workflow_state — Config-driven workflow state machine for the
connectus migration pipeline.

The shape of the workflow (steps, columns, markers, cross-step
interactions) is declared in
``connectus/workflow_state_config.yml`` and loaded at import time by
:func:`workflow_state.config_loader.get_config`. The runtime engine
(cascade reset, normalization, CSV I/O, CLI dispatch) lives in this
package.

External callers should keep using ``from workflow_state import …``
(via the thin shim at ``connectus/workflow_state.py``); every public
name is re-exported here for back-compat.
"""
from __future__ import annotations

# ---- Exceptions ----------------------------------------------------------

from workflow_state.exceptions import (
    ConfigLoadError,
    WorkflowError,
)

# ---- Types / dataclasses ------------------------------------------------

from workflow_state.types import (
    IdentityColumn,
    MarkerSet,
    Step,
    StepInteraction,
    WorkflowConfig,
)

# ---- Config loader -------------------------------------------------------

from workflow_state.config_loader import (
    _reset_config_for_testing,
    default_config_path,
    get_config,
    load_config,
)

# ---- State engine --------------------------------------------------------

from workflow_state.state_machine import (
    _can_advance_to,
    _normalize_rows_with_warning,
    apply_step_action,
    current_step,
    get_current_step,
    get_step,
    get_step_index,
    has_workflow_progress,
    is_checked,
    is_done,
    markpass_step,
    normalize_row,
    reset_after,
    reset_from_step,
)

# ---- CSV I/O -------------------------------------------------------------

from workflow_state.csv_io import (
    BASE_DIR,
    CSV_PATH,
    find_row,
    load_csv,
    os,  # re-exported for tests that monkey-patch ``workflow_state.os.replace``
    save_csv,
    wipe_workflow_data,
)

# ---- Validators ----------------------------------------------------------

from workflow_state.validators import (
    auth_param_sources as _auth_param_sources,
    get_named_validator,
    is_known_cross_check,
    known_cross_check_names,
    known_validator_names,
    validate_any_json,
    validate_auth_detail,
    validate_params_to_commands,
)

# ---- Display -------------------------------------------------------------

from workflow_state.display import (
    _auth_other_connection_summary,
    _example_value_for,
    _format_step_for_listing,
    _summary_value,
    format_by_assignee,
    format_dashboard_row,
    format_next_line,
    format_status,
    format_step_for_listing,
    format_step_value,
)

# ---- Programmatic API ----------------------------------------------------

from workflow_state.api import (
    _check_params_to_commands_overlap,
    _project_xsoar_param_to_yml_id,
    assign_connector,
    auth_param_ids,
    fail_integration_step,
    get_integration_files,
    get_integration_status,
    integrations_for_assignee,
    list_by_assignee,
    list_by_connector,
    list_integrations_by_connector,
    markpass_integration_step,
    next_step_for,
    reset_integration_to_step,
    set_integration_auth,
    skip_integration_step,
)

# ---- CLI -----------------------------------------------------------------

from workflow_state.cli import (
    COMMANDS,
    _git_user_name,
    _parse_next_flags,
    _resolve_row_or_exit,
    _set_json_data_step,
    _set_step_via_dispatch,
    cmd_at_step,
    cmd_auth_params,
    cmd_dashboard,
    cmd_fail,
    cmd_files,
    cmd_help,
    cmd_list,
    cmd_list_by_assignee,
    cmd_list_by_connector,
    cmd_list_connectors,
    cmd_markpass,
    cmd_next,
    cmd_reset,
    cmd_reset_to,
    cmd_set_assignee,
    cmd_set_assignee_by_connector,
    cmd_set_auth,
    cmd_set_auth_flag,
    cmd_set_params_for_test,
    cmd_set_params_to_commands,
    cmd_set_shared_params,
    cmd_show_step,
    cmd_skip,
    cmd_status,
    cmd_status_all,
    cmd_wipe_workflow_data,
    main,
)


# ---- Derived legacy module-level constants ------------------------------
# These are computed once at import time from the loaded config so that
# `from workflow_state import STEPS` and friends keep working unchanged.
# (Tests at workflow_state_test.py:22 import all of these by name.)

from auth_config_parser import AuthType  # re-exported for back-compat


def _compute_legacy_constants() -> None:
    """Populate module-level legacy constants from the loaded config.

    Triggers the YAML load. If the YAML is malformed, ``ConfigLoadError``
    is raised here, fast — no `cmd_*` will run.
    """
    cfg = get_config()
    g = globals()
    g["CHECK"] = cfg.markers.check
    g["FAIL_MARK"] = cfg.markers.fail
    g["NA_MARK"] = cfg.markers.na
    g["VALID_FLAG_VALUES"] = set(cfg.markers.flag_values)
    g["VALID_AUTH_TYPES"] = {t.value for t in AuthType}
    g["DATA_COLUMNS"] = list(cfg.identity_column_names)
    g["STEPS"] = list(cfg.steps)
    g["STEP_BY_NAME"] = dict(cfg.step_by_name)
    g["STEP_BY_INDEX"] = dict(cfg.step_by_index)
    g["WORKFLOW_COLUMNS"] = list(cfg.workflow_columns)
    g["WORKFLOW_DATA_COLUMNS"] = list(cfg.workflow_data_columns)
    g["CHECKPOINT_COLUMNS"] = list(cfg.checkpoint_columns)
    g["JSON_VALUED_COLUMNS"] = set(cfg.json_valued_columns)
    g["AUTH_PARITY_FLAG_COLUMN"] = cfg.auth_parity_flag_column or ""
    g["ALL_COLUMNS"] = list(cfg.all_columns)
    g["EXPECTED_COLUMN_COUNT"] = cfg.expected_column_count
    g["NON_CHECKPOINT_STEPS"] = dict(cfg.non_checkpoint_steps)


_compute_legacy_constants()


__all__ = [
    # Exceptions
    "ConfigLoadError",
    "WorkflowError",
    # Types
    "IdentityColumn",
    "MarkerSet",
    "Step",
    "StepInteraction",
    "WorkflowConfig",
    "AuthType",
    # Config loader
    "default_config_path",
    "get_config",
    "load_config",
    # State engine
    "apply_step_action",
    "current_step",
    "get_current_step",
    "get_step",
    "get_step_index",
    "has_workflow_progress",
    "is_checked",
    "is_done",
    "markpass_step",
    "normalize_row",
    "reset_after",
    "reset_from_step",
    # CSV I/O
    "BASE_DIR",
    "CSV_PATH",
    "find_row",
    "load_csv",
    "save_csv",
    "wipe_workflow_data",
    # Validators
    "get_named_validator",
    "validate_any_json",
    "validate_auth_detail",
    "validate_params_to_commands",
    # Display
    "format_by_assignee",
    "format_dashboard_row",
    "format_next_line",
    "format_status",
    "format_step_value",
    "format_step_for_listing",
    # API
    "assign_connector",
    "auth_param_ids",
    "fail_integration_step",
    "get_integration_files",
    "get_integration_status",
    "integrations_for_assignee",
    "list_by_assignee",
    "list_by_connector",
    "list_integrations_by_connector",
    "markpass_integration_step",
    "next_step_for",
    "reset_integration_to_step",
    "set_integration_auth",
    "skip_integration_step",
    # CLI
    "COMMANDS",
    "main",
    "cmd_at_step",
    "cmd_auth_params",
    "cmd_dashboard",
    "cmd_fail",
    "cmd_files",
    "cmd_help",
    "cmd_list",
    "cmd_list_by_assignee",
    "cmd_list_by_connector",
    "cmd_list_connectors",
    "cmd_markpass",
    "cmd_next",
    "cmd_reset",
    "cmd_reset_to",
    "cmd_set_assignee",
    "cmd_set_assignee_by_connector",
    "cmd_set_auth",
    "cmd_set_auth_flag",
    "cmd_set_params_for_test",
    "cmd_set_params_to_commands",
    "cmd_set_shared_params",
    "cmd_show_step",
    "cmd_skip",
    "cmd_status",
    "cmd_status_all",
    "cmd_wipe_workflow_data",
    # Derived legacy constants
    "CHECK",
    "FAIL_MARK",
    "NA_MARK",
    "VALID_FLAG_VALUES",
    "VALID_AUTH_TYPES",
    "DATA_COLUMNS",
    "STEPS",
    "STEP_BY_NAME",
    "STEP_BY_INDEX",
    "WORKFLOW_COLUMNS",
    "WORKFLOW_DATA_COLUMNS",
    "CHECKPOINT_COLUMNS",
    "JSON_VALUED_COLUMNS",
    "AUTH_PARITY_FLAG_COLUMN",
    "ALL_COLUMNS",
    "EXPECTED_COLUMN_COUNT",
    "NON_CHECKPOINT_STEPS",
]
