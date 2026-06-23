"""workflow_state — Config-driven workflow state machine for the
connectus migration pipeline.

The shape of the workflow (steps, columns, markers, cross-step
interactions) is declared in
``connectus/workflow_state_config.yml`` and loaded at import time by
:func:`workflow_state.config_loader.get_config`. The runtime engine
(cascade reset, normalization, CSV I/O, CLI dispatch) lives in this
package.

External callers should use ``from workflow_state import …``.
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
    _is_flag_value_match,
    _normalize_rows_with_warning,
    apply_step_action,
    current_step,
    get_step,
    get_step_index,
    has_workflow_progress,
    is_checked,
    is_done,
    normalize_row,
    read_step_value,
    reset_after,
    step_flag_values,
)

# ---- CSV I/O -------------------------------------------------------------

from workflow_state.csv_io import (
    BASE_DIR,
    CSV_PATH,
    PIPELINE_CSV_ENV_VAR,
    _resolve_pipeline_csv,
    find_row,
    load_csv,
    os,  # re-exported for tests that monkey-patch ``workflow_state.os.replace``
    save_csv,
    wipe_workflow_data,
)

# ---- Validators ----------------------------------------------------------

from workflow_state.validators import (  # noqa: I001
    auth_param_sources as _auth_param_sources,
    get_named_validator,
    is_known_cross_check,
    known_cross_check_names,
    known_validator_names,
    validate_any_json,
    validate_auth_detail,
    validate_capabilities,
    validate_param_defaults,
    validate_params_to_capabilities,
    validate_params_to_commands,
    validate_release_notes,
    validate_shadowed_commands,
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
    collected_capabilities,
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
    test_module_params,
)

# ---- CLI -----------------------------------------------------------------

from workflow_state.cli import (
    COMMANDS,
    _git_user_name,
    _parse_next_flags,
    _resolve_column_or_exit,
    _resolve_row_or_exit,
    _set_flag_step_via_dispatch,
    _set_json_data_step,
    _set_step_via_dispatch,
    cmd_at_step,
    cmd_auth_params,
    cmd_test_module_params,
    cmd_dashboard,
    cmd_detect_shadowed_commands,
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
    cmd_set_capabilities,
    cmd_set_param_defaults,
    cmd_set_shadowed_commands,
    cmd_set_params_to_capabilities,
    cmd_set_params_to_commands,
    cmd_show_step,
    cmd_skip,
    cmd_status,
    cmd_status_all,
    cmd_wipe_workflow_data,
    main,
)


# Re-export AuthType for callers that want it from the package namespace.
from auth_config_parser import AuthType


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
    "get_step",
    "get_step_index",
    "has_workflow_progress",
    "is_checked",
    "is_done",
    "normalize_row",
    "read_step_value",
    "reset_after",
    "step_flag_values",
    # CSV I/O
    "BASE_DIR",
    "CSV_PATH",
    "PIPELINE_CSV_ENV_VAR",
    "find_row",
    "load_csv",
    "save_csv",
    "wipe_workflow_data",
    # Validators
    "get_named_validator",
    "validate_any_json",
    "validate_auth_detail",
    "validate_capabilities",
    "validate_param_defaults",
    "validate_params_to_capabilities",
    "validate_params_to_commands",
    "validate_release_notes",
    "validate_shadowed_commands",
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
    "collected_capabilities",
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
    "test_module_params",
    # CLI
    "COMMANDS",
    "main",
    "cmd_at_step",
    "cmd_auth_params",
    "cmd_dashboard",
    "cmd_detect_shadowed_commands",
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
    "cmd_set_capabilities",
    "cmd_set_param_defaults",
    "cmd_set_shadowed_commands",
    "cmd_set_params_to_capabilities",
    "cmd_set_params_to_commands",
    "cmd_show_step",
    "cmd_skip",
    "cmd_status",
    "cmd_status_all",
    "cmd_test_module_params",
    "cmd_wipe_workflow_data",
]
