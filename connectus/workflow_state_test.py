#!/usr/bin/env python3
"""
Unit tests for workflow_state.py

Tests the core state-machine logic (pure functions operating on row dicts)
without touching the real CSV file.
"""

import os

import pytest

import workflow_state
from workflow_state import (
    ALL_COLUMNS,
    AUTH_PARITY_FLAG_COLUMN,
    CHECK,
    CHECKPOINT_COLUMNS,
    DATA_COLUMNS,
    EXPECTED_COLUMN_COUNT,
    JSON_VALUED_COLUMNS,
    NA_MARK,
    NON_CHECKPOINT_STEPS,
    VALID_AUTH_TYPES,
    WORKFLOW_COLUMNS,
    WORKFLOW_DATA_COLUMNS,
    cmd_show_step,
    find_row,
    format_by_assignee,
    format_dashboard_row,
    format_status,
    format_step_value,
    get_current_step,
    get_step_index,
    is_checked,
    list_by_assignee,
    load_csv,
    markpass_step,
    reset_from_step,
    save_csv,
    set_integration_auth,
    validate_auth_detail,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_row(
    name: str = "TestIntegration",
    params_to_commands: str = "",
    params_for_test: str = "",
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create a blank workflow row dict for testing.

    All columns from ``ALL_COLUMNS`` are present (empty by default), with
    ``Integration ID`` set to ``name``.
    """
    row: dict[str, str] = {col: "" for col in ALL_COLUMNS}
    row["Integration ID"] = name
    row["Params to Commands"] = params_to_commands
    row["Params for test with default in code"] = params_for_test
    if overrides:
        row.update(overrides)
    return row


def _complete_up_to(row: dict[str, str], step_name: str) -> None:
    """Mark all checkpoint steps up to (but NOT including) ``step_name`` as ✅.

    Also sets the JSON prerequisites for ``generated manifest`` if not already
    set (since they are required to mark the first checkpoint as passed).
    """
    if not row.get("Params to Commands", "").strip():
        row["Params to Commands"] = "{}"
    if not row.get("Params for test with default in code", "").strip():
        row["Params for test with default in code"] = "[]"
    for col in CHECKPOINT_COLUMNS:
        if col == step_name:
            break
        if col == "auth parity test passes":
            flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
            if flag in ("NO", "N/A", ""):
                row[col] = NA_MARK
                continue
        row[col] = CHECK


# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

class TestSchemaConstants:
    def test_data_columns_have_expected_names(self) -> None:
        assert DATA_COLUMNS == [
            "Integration ID",
            "Integration File Path",
            "Connector ID",
            "special cases",
        ]

    def test_workflow_data_columns(self) -> None:
        assert WORKFLOW_DATA_COLUMNS == [
            "assignee",
            "Auth Details",
            "Params to Commands",
            "Params for test with default in code",
            "Params same in other handlers",
        ]

    def test_checkpoint_columns_in_order(self) -> None:
        assert CHECKPOINT_COLUMNS == [
            "generated manifest",
            "run manifest make validate",
            "wrote/checked code",
            "shadowed command test passes",
            "write tests",
            "precommit/validate/unit tests passed",
            "auth parity test passes",
            "param parity test passes",
            "code reviewed",
            "code merged",
        ]

    def test_auth_params_set_no_longer_a_checkpoint(self) -> None:
        """The old 'auth params set' checkpoint has been removed."""
        assert "auth params set" not in CHECKPOINT_COLUMNS
        assert "auth params set" not in WORKFLOW_COLUMNS

    def test_first_checkpoint_is_generated_manifest(self) -> None:
        assert CHECKPOINT_COLUMNS[0] == "generated manifest"

    def test_workflow_columns_count(self) -> None:
        # 5 workflow data columns + 10 checkpoints + 1 flag = 16
        assert len(WORKFLOW_COLUMNS) == 16

    def test_total_column_count(self) -> None:
        # 4 data + 16 workflow = 20
        assert EXPECTED_COLUMN_COUNT == 20
        assert len(ALL_COLUMNS) == 20

    def test_workflow_columns_include_flag_in_correct_position(self) -> None:
        """The flag sits after 'precommit/validate/unit tests passed' in WORKFLOW_COLUMNS."""
        flag_idx = WORKFLOW_COLUMNS.index(AUTH_PARITY_FLAG_COLUMN)
        precommit_idx = WORKFLOW_COLUMNS.index("precommit/validate/unit tests passed")
        auth_parity_idx = WORKFLOW_COLUMNS.index("auth parity test passes")
        assert precommit_idx < flag_idx < auth_parity_idx

    def test_non_checkpoint_steps_mapping(self) -> None:
        assert NON_CHECKPOINT_STEPS == {
            "assignee": "set-assignee",
            "Auth Details": "set-auth",
            "Params to Commands": "set-params-to-commands",
            "Params for test with default in code": "set-params-for-test",
            "Params same in other handlers": "set-shared-params",
            "requires auth parity test": "set-auth-flag",
        }

    def test_json_valued_columns(self) -> None:
        assert JSON_VALUED_COLUMNS == {
            "Auth Details",
            "Params to Commands",
            "Params for test with default in code",
            "Params same in other handlers",
        }

    def test_param_parity_after_auth_parity(self) -> None:
        param_idx = CHECKPOINT_COLUMNS.index("param parity test passes")
        auth_idx = CHECKPOINT_COLUMNS.index("auth parity test passes")
        assert auth_idx < param_idx

    def test_shadowed_command_after_wrote_checked_code(self) -> None:
        wrote_idx = CHECKPOINT_COLUMNS.index("wrote/checked code")
        shadowed_idx = CHECKPOINT_COLUMNS.index("shadowed command test passes")
        assert shadowed_idx == wrote_idx + 1

    def test_write_tests_after_shadowed(self) -> None:
        shadowed_idx = CHECKPOINT_COLUMNS.index("shadowed command test passes")
        write_idx = CHECKPOINT_COLUMNS.index("write tests")
        assert write_idx == shadowed_idx + 1


# ---------------------------------------------------------------------------
# is_checked
# ---------------------------------------------------------------------------

class TestIsChecked:
    def test_check_mark(self) -> None:
        assert is_checked(CHECK) is True
        assert is_checked("✅") is True

    def test_yes(self) -> None:
        assert is_checked("YES") is True

    def test_na(self) -> None:
        assert is_checked("N/A") is True
        assert is_checked(NA_MARK) is True

    def test_done_variants(self) -> None:
        assert is_checked("done") is True
        assert is_checked("Done") is True
        assert is_checked("DONE") is True

    def test_true_variants(self) -> None:
        assert is_checked("true") is True
        assert is_checked("True") is True

    def test_empty(self) -> None:
        assert is_checked("") is False

    def test_whitespace(self) -> None:
        assert is_checked("  ") is False

    def test_random_text(self) -> None:
        assert is_checked("hello") is False

    def test_no(self) -> None:
        assert is_checked("NO") is False

    def test_whitespace_padding(self) -> None:
        assert is_checked("  ✅  ") is True


# ---------------------------------------------------------------------------
# get_current_step
# ---------------------------------------------------------------------------

class TestGetCurrentStep:
    def test_blank_row_returns_first_checkpoint(self) -> None:
        row = _make_row()
        assert get_current_step(row) == "generated manifest"

    def test_first_step_done(self) -> None:
        row = _make_row()
        row["generated manifest"] = CHECK
        assert get_current_step(row) == "run manifest make validate"

    def test_second_checkpoint_done(self) -> None:
        row = _make_row()
        row["generated manifest"] = CHECK
        row["run manifest make validate"] = CHECK
        assert get_current_step(row) == "wrote/checked code"

    def test_all_done_returns_none(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        assert get_current_step(row) is None

    def test_skips_auth_parity_when_flag_no(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "NO"
        # Should skip auth parity test passes and go to param parity
        assert get_current_step(row) == "param parity test passes"

    def test_skips_auth_parity_when_flag_na(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "N/A"
        assert get_current_step(row) == "param parity test passes"

    def test_skips_auth_parity_when_flag_empty(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = ""
        assert get_current_step(row) == "param parity test passes"

    def test_auth_parity_required_when_flag_yes(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"
        assert get_current_step(row) == "auth parity test passes"


# ---------------------------------------------------------------------------
# get_step_index
# ---------------------------------------------------------------------------

class TestGetStepIndex:
    def test_valid_steps(self) -> None:
        for i, col in enumerate(CHECKPOINT_COLUMNS):
            assert get_step_index(col) == i

    def test_invalid_step_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown checkpoint step"):
            get_step_index("nonexistent step")

    def test_non_checkpoint_data_column_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown checkpoint step"):
            get_step_index("Params to Commands")

    def test_old_auth_params_set_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown checkpoint step"):
            get_step_index("auth params set")


# ---------------------------------------------------------------------------
# reset_from_step
# ---------------------------------------------------------------------------

class TestResetFromStep:
    def test_reset_from_first_clears_all(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        reset_from_step(row, "generated manifest")

        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty"
        # Auth flag should be cleared since auth parity is in the cleared range
        assert row[AUTH_PARITY_FLAG_COLUMN] == ""

    def test_reset_from_middle(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        reset_from_step(row, "wrote/checked code")

        # First two should remain
        assert row["generated manifest"] == CHECK
        assert row["run manifest make validate"] == CHECK
        # Rest should be cleared
        assert row["wrote/checked code"] == ""
        assert row["shadowed command test passes"] == ""
        assert row["code merged"] == ""

    def test_reset_from_last(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK

        reset_from_step(row, "code merged")

        assert row["code reviewed"] == CHECK
        assert row["code merged"] == ""

    def test_reset_clears_auth_flag_when_clearing_auth_parity(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        # auth parity test passes is still in the cleared range
        reset_from_step(row, "precommit/validate/unit tests passed")

        assert row[AUTH_PARITY_FLAG_COLUMN] == ""

    def test_reset_preserves_auth_flag_when_clearing_only_after_auth_parity(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        # param parity is AFTER auth parity, so auth parity stays set
        reset_from_step(row, "param parity test passes")

        assert row[AUTH_PARITY_FLAG_COLUMN] == "YES"
        assert row["auth parity test passes"] == CHECK
        assert row["param parity test passes"] == ""

    def test_data_columns_preserved(self) -> None:
        row = _make_row(params_to_commands='{"key":"val"}', params_for_test='["a"]')
        row["Integration File Path"] = "Packs/Foo/Integrations/Foo/Foo.yml"
        row["Connector ID"] = "foo-connector"
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK

        reset_from_step(row, "generated manifest")

        # Workflow data columns and identity columns are preserved
        assert row["Params to Commands"] == '{"key":"val"}'
        assert row["Params for test with default in code"] == '["a"]'
        assert row["Integration File Path"] == "Packs/Foo/Integrations/Foo/Foo.yml"
        assert row["Connector ID"] == "foo-connector"


# ---------------------------------------------------------------------------
# markpass_step
# ---------------------------------------------------------------------------

class TestMarkpassStep:
    # --- Non-checkpoint rejection ---

    def test_rejects_params_to_commands(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "Params to Commands")
        assert "ERROR" in msg
        assert "set-params-to-commands" in msg

    def test_rejects_params_for_test(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "Params for test with default in code")
        assert "ERROR" in msg
        assert "set-params-for-test" in msg

    def test_rejects_params_same_in_other_handlers(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "Params same in other handlers")
        assert "ERROR" in msg
        assert "set-shared-params" in msg

    def test_rejects_assignee(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "assignee")
        assert "ERROR" in msg
        assert "set-assignee" in msg

    def test_rejects_auth_details(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "Auth Details")
        assert "ERROR" in msg
        assert "set-auth" in msg

    def test_rejects_requires_auth_parity_test(self) -> None:
        row = _make_row()
        msg = markpass_step(row, AUTH_PARITY_FLAG_COLUMN)
        assert "ERROR" in msg
        assert "set-auth-flag" in msg

    # --- generated manifest prerequisites ---

    def test_generated_manifest_requires_params_to_commands(self) -> None:
        row = _make_row(params_to_commands="", params_for_test="[]")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "Params to Commands" in msg
        assert "set-params-to-commands" in msg

    def test_generated_manifest_requires_params_for_test(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "Params for test with default in code" in msg
        assert "set-params-for-test" in msg

    def test_generated_manifest_works_with_both_params(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_generated_manifest_does_not_require_shared_params(self) -> None:
        """Params same in other handlers is optional, not a prerequisite."""
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        # Don't set Params same in other handlers
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg

    # --- Sequential enforcement ---

    def test_cannot_skip_ahead(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        msg = markpass_step(row, "wrote/checked code")
        assert "ERROR" in msg
        assert "not up to that step" in msg
        assert "generated manifest" in msg

    def test_cannot_skip_multiple_steps(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        msg = markpass_step(row, "write tests")
        assert "ERROR" in msg
        assert "not up to that step" in msg

    def test_sequential_pass_works(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        msg1 = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg1
        assert row["generated manifest"] == CHECK

        msg2 = markpass_step(row, "run manifest make validate")
        assert "ERROR" not in msg2
        assert row["run manifest make validate"] == CHECK

        msg3 = markpass_step(row, "wrote/checked code")
        assert "ERROR" not in msg3
        assert row["wrote/checked code"] == CHECK

    # --- Already done ---

    def test_already_done(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["generated manifest"] = CHECK
        msg = markpass_step(row, "generated manifest")
        assert "already marked as passed" in msg

    # --- Auth parity special cases ---

    def test_auth_parity_requires_flag_set(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        _complete_up_to(row, "auth parity test passes")
        row[AUTH_PARITY_FLAG_COLUMN] = ""

        msg = markpass_step(row, "auth parity test passes")
        assert "ERROR" in msg
        assert "set-auth-flag" in msg

    def test_auth_parity_auto_na_when_flag_no(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        _complete_up_to(row, "auth parity test passes")
        row[AUTH_PARITY_FLAG_COLUMN] = "NO"

        msg = markpass_step(row, "auth parity test passes")
        assert "N/A" in msg
        assert row["auth parity test passes"] == NA_MARK

    def test_auth_parity_auto_na_when_flag_na(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        _complete_up_to(row, "auth parity test passes")
        row[AUTH_PARITY_FLAG_COLUMN] = "N/A"

        msg = markpass_step(row, "auth parity test passes")
        assert "N/A" in msg
        assert row["auth parity test passes"] == NA_MARK

    def test_auth_parity_passes_when_flag_yes(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        _complete_up_to(row, "auth parity test passes")
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        msg = markpass_step(row, "auth parity test passes")
        assert "ERROR" not in msg
        assert row["auth parity test passes"] == CHECK

    # --- Invalid step name ---

    def test_invalid_step_raises(self) -> None:
        row = _make_row()
        with pytest.raises(ValueError, match="Unknown checkpoint step"):
            markpass_step(row, "nonexistent step")

    # --- Full workflow ---

    def test_full_workflow_happy_path(self) -> None:
        row = _make_row(params_to_commands='{"a":1}', params_for_test='[]')
        row[AUTH_PARITY_FLAG_COLUMN] = "NO"

        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                msg = markpass_step(row, col)
                assert row[col] == NA_MARK
                continue
            msg = markpass_step(row, col)
            assert "ERROR" not in msg, f"Failed at step '{col}': {msg}"
            assert is_checked(row[col].strip()), f"Step '{col}' not checked"

        assert get_current_step(row) is None


# ---------------------------------------------------------------------------
# find_row
# ---------------------------------------------------------------------------

class TestFindRow:
    def test_finds_exact_match(self) -> None:
        rows = [_make_row("Alpha"), _make_row("Beta"), _make_row("Gamma")]
        assert find_row(rows, "Beta") == 1

    def test_case_insensitive(self) -> None:
        rows = [_make_row("Cisco Spark")]
        assert find_row(rows, "cisco spark") == 0
        assert find_row(rows, "CISCO SPARK") == 0

    def test_strips_whitespace(self) -> None:
        rows = [_make_row("Cisco Spark")]
        assert find_row(rows, "  Cisco Spark  ") == 0

    def test_not_found(self) -> None:
        rows = [_make_row("Alpha")]
        assert find_row(rows, "Nonexistent") is None

    def test_empty_list(self) -> None:
        assert find_row([], "anything") is None


# ---------------------------------------------------------------------------
# format_status
# ---------------------------------------------------------------------------

class TestFormatStatus:
    def test_blank_row_shows_current_step(self) -> None:
        row = _make_row()
        output = format_status(row)
        assert "Current step" in output
        assert "generated manifest" in output

    def test_in_progress_shows_current_step(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["generated manifest"] = CHECK
        output = format_status(row)
        assert "Current step" in output
        assert "run manifest make validate" in output

    def test_all_complete_shows_celebration(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        output = format_status(row)
        assert "All checkpoints complete" in output

    def test_shows_integration_id(self) -> None:
        row = _make_row(name="My Cool Integration")
        output = format_status(row)
        assert "My Cool Integration" in output

    def test_shows_params_to_commands_not_set(self) -> None:
        row = _make_row(params_to_commands="")
        output = format_status(row)
        assert "(not set)" in output

    def test_shows_params_to_commands_value(self) -> None:
        row = _make_row(params_to_commands='{"key":"val"}')
        output = format_status(row)
        assert '{"key":"val"}' in output


# ---------------------------------------------------------------------------
# format_dashboard_row
# ---------------------------------------------------------------------------

class TestFormatDashboardRow:
    def test_no_progress_returns_none(self) -> None:
        row = _make_row()
        assert format_dashboard_row(row) is None

    def test_with_progress_returns_string(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["generated manifest"] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        assert "TestIntegration" in result

    def test_all_done_shows_done(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        assert "DONE" in result

    def test_progress_bar_format(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["generated manifest"] = CHECK
        row["run manifest make validate"] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        assert "██" in result
        assert "░" in result


# ---------------------------------------------------------------------------
# Integration: markpass + reset round-trip
# ---------------------------------------------------------------------------

class TestMarkpassResetRoundTrip:
    def test_markpass_then_reset_to_same_step(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        markpass_step(row, "generated manifest")
        assert row["generated manifest"] == CHECK

        reset_from_step(row, "generated manifest")
        assert row["generated manifest"] == ""
        assert get_current_step(row) == "generated manifest"

    def test_markpass_several_then_reset_to_middle(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        markpass_step(row, "generated manifest")
        markpass_step(row, "run manifest make validate")
        markpass_step(row, "wrote/checked code")
        markpass_step(row, "shadowed command test passes")

        reset_from_step(row, "wrote/checked code")

        assert row["generated manifest"] == CHECK
        assert row["run manifest make validate"] == CHECK
        assert row["wrote/checked code"] == ""
        assert row["shadowed command test passes"] == ""
        assert get_current_step(row) == "wrote/checked code"

    def test_reset_then_markpass_again(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        markpass_step(row, "generated manifest")
        markpass_step(row, "run manifest make validate")

        reset_from_step(row, "generated manifest")

        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_full_reset_clears_everything(self) -> None:
        row = _make_row(params_to_commands='{"a":1}')
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        for col in WORKFLOW_COLUMNS:
            row[col] = ""

        for col in WORKFLOW_COLUMNS:
            assert row[col] == ""
        assert get_current_step(row) == "generated manifest"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_markpass_with_whitespace_in_value(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["generated manifest"] = "  "
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_params_with_complex_json(self) -> None:
        complex_json = '{"args":["a","b"],"config":{"nested":true}}'
        row = _make_row(params_to_commands=complex_json, params_for_test="[]")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_markpass_preserves_data_columns(self) -> None:
        row = _make_row(name="SpecialInt", params_to_commands="{}", params_for_test="[]")
        row["Integration File Path"] = "Packs/Foo/Integrations/Foo/Foo.yml"
        row["Connector ID"] = "foo"

        markpass_step(row, "generated manifest")

        assert row["Integration ID"] == "SpecialInt"
        assert row["Integration File Path"] == "Packs/Foo/Integrations/Foo/Foo.yml"
        assert row["Connector ID"] == "foo"

    def test_reset_preserves_data_columns(self) -> None:
        row = _make_row(name="SpecialInt", params_to_commands="{}", params_for_test="[]")
        row["Integration File Path"] = "x.yml"
        row["generated manifest"] = CHECK
        row["run manifest make validate"] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["Integration ID"] == "SpecialInt"
        assert row["Integration File Path"] == "x.yml"
        assert row["Params to Commands"] == "{}"


# ---------------------------------------------------------------------------
# Assignee
# ---------------------------------------------------------------------------

class TestAssignee:
    def test_status_shows_unassigned(self) -> None:
        row = _make_row()
        output = format_status(row)
        assert "(unassigned)" in output

    def test_status_shows_assignee(self) -> None:
        row = _make_row()
        row["assignee"] = "John Doe"
        output = format_status(row)
        assert "John Doe" in output
        assert "(unassigned)" not in output

    def test_assignee_preserved_after_reset(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["assignee"] = "Jane Smith"
        row["generated manifest"] = CHECK
        row["run manifest make validate"] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["assignee"] == "Jane Smith"

    def test_assignee_preserved_after_markpass(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        row["assignee"] = "Jane Smith"

        markpass_step(row, "generated manifest")

        assert row["assignee"] == "Jane Smith"
        assert row["generated manifest"] == CHECK

    def test_assignee_in_workflow_data_columns(self) -> None:
        assert "assignee" in WORKFLOW_DATA_COLUMNS


# ---------------------------------------------------------------------------
# Params columns
# ---------------------------------------------------------------------------

class TestParamsColumns:
    def test_params_to_commands_in_workflow_columns(self) -> None:
        assert "Params to Commands" in WORKFLOW_COLUMNS
        assert "Params to Commands" in WORKFLOW_DATA_COLUMNS

    def test_params_for_test_in_workflow_columns(self) -> None:
        assert "Params for test with default in code" in WORKFLOW_COLUMNS
        assert "Params for test with default in code" in WORKFLOW_DATA_COLUMNS

    def test_shared_params_in_workflow_columns(self) -> None:
        assert "Params same in other handlers" in WORKFLOW_COLUMNS
        assert "Params same in other handlers" in WORKFLOW_DATA_COLUMNS

    def test_params_preserved_after_reset(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test='["x"]')
        row["Params same in other handlers"] = '["y"]'
        row["generated manifest"] = CHECK
        row["run manifest make validate"] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["Params to Commands"] == "{}"
        assert row["Params for test with default in code"] == '["x"]'
        assert row["Params same in other handlers"] == '["y"]'

    def test_status_shows_params_not_set(self) -> None:
        row = _make_row()
        output = format_status(row)
        assert "Params to Commands" in output
        assert "Params for test with default in code" in output
        assert "Params same in other handlers" in output


# ---------------------------------------------------------------------------
# list_by_assignee / format_by_assignee
# ---------------------------------------------------------------------------

class TestListByAssignee:
    def test_finds_integrations_for_valid_assignee(self) -> None:
        rows = [
            _make_row(name="IntA", overrides={"assignee": "Alice"}),
            _make_row(name="IntB", overrides={"assignee": "Bob"}),
            _make_row(name="IntC", overrides={"assignee": "Alice"}),
        ]
        result = list_by_assignee(rows, "Alice")
        assert len(result) == 2
        ids = [r["Integration ID"] for r in result]
        assert "IntA" in ids
        assert "IntC" in ids

    def test_case_insensitive_matching(self) -> None:
        rows = [
            _make_row(name="IntA", overrides={"assignee": "Alice"}),
            _make_row(name="IntB", overrides={"assignee": "alice"}),
            _make_row(name="IntC", overrides={"assignee": "ALICE"}),
        ]
        result = list_by_assignee(rows, "aLiCe")
        assert len(result) == 3

    def test_no_results_found(self) -> None:
        rows = [
            _make_row(name="IntA", overrides={"assignee": "Alice"}),
            _make_row(name="IntB", overrides={"assignee": "Bob"}),
        ]
        result = list_by_assignee(rows, "Charlie")
        assert len(result) == 0


class TestFormatByAssignee:
    def test_no_matches_message(self) -> None:
        output = format_by_assignee([], "Nobody")
        assert "No integrations found for assignee 'Nobody'" in output

    def test_shows_count_and_names(self) -> None:
        rows = [
            _make_row(name="IntA", overrides={"assignee": "Alice"}),
            _make_row(name="IntB", overrides={"assignee": "Alice"}),
        ]
        output = format_by_assignee(rows, "Alice")
        assert "(2)" in output
        assert "IntA" in output
        assert "IntB" in output

    def test_shows_current_step(self) -> None:
        row = _make_row(name="IntA", overrides={"assignee": "Alice"},
                        params_to_commands="{}", params_for_test="[]")
        row["generated manifest"] = CHECK
        output = format_by_assignee([row], "Alice")
        assert "run manifest make validate" in output

    def test_shows_done_when_all_complete(self) -> None:
        row = _make_row(name="IntA", overrides={"assignee": "Alice"})
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        output = format_by_assignee([row], "Alice")
        assert "DONE" in output

    def test_shows_not_started(self) -> None:
        row = _make_row(name="IntA", overrides={"assignee": "Alice"})
        output = format_by_assignee([row], "Alice")
        assert "not started" in output


# ---------------------------------------------------------------------------
# Generated manifest is the first checkpoint
# ---------------------------------------------------------------------------

class TestGeneratedManifestFirst:
    def test_generated_manifest_is_first_checkpoint(self) -> None:
        assert CHECKPOINT_COLUMNS[0] == "generated manifest"

    def test_current_step_is_generated_manifest_on_blank_row(self) -> None:
        row = _make_row()
        assert get_current_step(row) == "generated manifest"


# ---------------------------------------------------------------------------
# validate_auth_detail
# ---------------------------------------------------------------------------

class TestValidateAuthDetail:
    """Tests for the Auth Details JSON schema validator."""

    VALID_SIMPLE: str = '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'
    VALID_NONE: str = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
    VALID_MULTI: str = '{"auth_types":[{"type":"APIKey","name":"apikey"},{"type":"Plain","name":"credentials"}],"config":"CHOICE(APIKey, Plain)","params":{"apikey":{"type":"APIKey","xsoar_type":4,"required":false},"credentials":{"type":"Plain","xsoar_type":9,"required":false}},"notes":null}'
    VALID_WITH_NOTES: str = '{"auth_types":[{"type":"Other","name":"access_key"}],"config":"REQUIRED(Other)","params":{"access_key":{"type":"Other","xsoar_type":4,"required":true}},"notes":"Uses custom HMAC signing"}'
    VALID_MULTI_TYPE_PARAM: str = '{"auth_types":[{"type":"OAuth2AuthCode","name":"app_id"}],"config":"CHOICE(OAuth2AuthCode, OAuth2ClientCreds)","params":{"app_id":{"type":["OAuth2AuthCode","OAuth2ClientCreds"],"xsoar_type":0,"required":true}},"notes":null}'

    def test_valid_simple(self) -> None:
        assert validate_auth_detail(self.VALID_SIMPLE) == []

    def test_valid_none_required(self) -> None:
        assert validate_auth_detail(self.VALID_NONE) == []

    def test_valid_multi_auth(self) -> None:
        assert validate_auth_detail(self.VALID_MULTI) == []

    def test_valid_with_notes(self) -> None:
        assert validate_auth_detail(self.VALID_WITH_NOTES) == []

    def test_valid_multi_type_param(self) -> None:
        assert validate_auth_detail(self.VALID_MULTI_TYPE_PARAM) == []

    def test_invalid_json(self) -> None:
        errors = validate_auth_detail("not json at all")
        assert len(errors) == 1
        assert "Invalid JSON" in errors[0]

    def test_not_a_dict(self) -> None:
        errors = validate_auth_detail("[]")
        assert len(errors) == 1
        assert "JSON object" in errors[0]

    def test_missing_keys(self) -> None:
        errors = validate_auth_detail('{"auth_types":[]}')
        assert len(errors) == 1
        assert "Missing required keys" in errors[0]
        assert "config" in errors[0]
        assert "params" in errors[0]
        assert "notes" in errors[0]

    def test_auth_types_not_list(self) -> None:
        errors = validate_auth_detail('{"auth_types":"bad","config":"NONE","params":{},"notes":null}')
        assert any("must be a list" in e for e in errors)

    def test_auth_types_entry_missing_type(self) -> None:
        errors = validate_auth_detail('{"auth_types":[{"name":"x"}],"config":"NONE","params":{},"notes":null}')
        assert any("missing 'type'" in e for e in errors)

    def test_auth_types_entry_missing_name(self) -> None:
        errors = validate_auth_detail('{"auth_types":[{"type":"APIKey"}],"config":"NONE","params":{},"notes":null}')
        assert any("missing 'name'" in e for e in errors)

    def test_auth_types_invalid_type(self) -> None:
        errors = validate_auth_detail('{"auth_types":[{"type":"InvalidType","name":"x"}],"config":"NONE","params":{},"notes":null}')
        assert any("invalid type 'InvalidType'" in e for e in errors)

    def test_config_not_string(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":123,"params":{},"notes":null}')
        assert any("must be a string" in e for e in errors)

    def test_params_not_dict(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":"bad","notes":null}')
        assert any("must be a dict" in e for e in errors)

    def test_param_missing_type(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"xsoar_type":4,"required":true}},"notes":null}')
        assert any("missing 'type'" in e for e in errors)

    def test_param_invalid_type(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"type":"BadType","xsoar_type":4,"required":true}},"notes":null}')
        assert any("invalid type 'BadType'" in e for e in errors)

    def test_param_invalid_type_in_list(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"type":["APIKey","BadType"],"xsoar_type":4,"required":true}},"notes":null}')
        assert any("invalid type 'BadType'" in e for e in errors)

    def test_param_missing_xsoar_type(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"type":"APIKey","required":true}},"notes":null}')
        assert any("missing 'xsoar_type'" in e for e in errors)

    def test_param_xsoar_type_not_int(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"type":"APIKey","xsoar_type":"4","required":true}},"notes":null}')
        assert any("must be int" in e for e in errors)

    def test_param_missing_required(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"type":"APIKey","xsoar_type":4}},"notes":null}')
        assert any("missing 'required'" in e for e in errors)

    def test_param_required_not_bool(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{"k":{"type":"APIKey","xsoar_type":4,"required":"yes"}},"notes":null}')
        assert any("must be bool" in e for e in errors)

    def test_notes_not_string_or_null(self) -> None:
        errors = validate_auth_detail('{"auth_types":[],"config":"NONE","params":{},"notes":123}')
        assert any("must be a string or null" in e for e in errors)

    def test_all_valid_auth_types_accepted(self) -> None:
        for auth_type in VALID_AUTH_TYPES:
            detail = f'{{"auth_types":[{{"type":"{auth_type}","name":"x"}}],"config":"NONE","params":{{}},"notes":null}}'
            errors = validate_auth_detail(detail)
            assert errors == [], f"Type '{auth_type}' should be valid but got: {errors}"


# ---------------------------------------------------------------------------
# set-auth (set Auth Details + reset workflow)
# ---------------------------------------------------------------------------

class TestSetAuth:
    def test_set_auth_updates_auth_details(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        new_auth = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        row["Auth Details"] = new_auth
        reset_from_step(row, CHECKPOINT_COLUMNS[0])
        assert row["Auth Details"] == new_auth
        assert row["generated manifest"] == ""

    def test_set_auth_resets_workflow(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        for col in CHECKPOINT_COLUMNS[:5]:
            row[col] = CHECK
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"

        row["Auth Details"] = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        reset_from_step(row, CHECKPOINT_COLUMNS[0])

        for col in CHECKPOINT_COLUMNS:
            assert row[col] == ""
        assert row[AUTH_PARITY_FLAG_COLUMN] == ""
        assert get_current_step(row) == "generated manifest"

    def test_set_auth_preserves_params_columns(self) -> None:
        row = _make_row(params_to_commands='{"key":"val"}', params_for_test='["p"]')
        row["Params same in other handlers"] = '["x"]'
        row["Auth Details"] = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        reset_from_step(row, CHECKPOINT_COLUMNS[0])
        assert row["Params to Commands"] == '{"key":"val"}'
        assert row["Params for test with default in code"] == '["p"]'
        assert row["Params same in other handlers"] == '["x"]'

    def test_set_auth_preserves_data_columns(self) -> None:
        row = _make_row(name="SpecialInt")
        row["Integration File Path"] = "x.yml"
        row["Auth Details"] = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        reset_from_step(row, CHECKPOINT_COLUMNS[0])
        assert row["Integration ID"] == "SpecialInt"
        assert row["Integration File Path"] == "x.yml"

    def test_set_auth_schema_validation_rejects_invalid(self) -> None:
        errors = validate_auth_detail('{"auth_types":[]}')
        assert len(errors) > 0
        assert "Missing required keys" in errors[0]

    def test_set_auth_schema_validation_rejects_bad_auth_type(self) -> None:
        bad = '{"auth_types":[{"type":"INVALID","name":"x"}],"config":"NONE","params":{},"notes":null}'
        errors = validate_auth_detail(bad)
        assert any("invalid type" in e for e in errors)

    def test_set_auth_schema_validation_rejects_bad_param(self) -> None:
        bad = '{"auth_types":[],"config":"NONE","params":{"k":{"type":"APIKey"}},"notes":null}'
        errors = validate_auth_detail(bad)
        assert any("missing" in e for e in errors)

    def test_set_auth_schema_validation_accepts_valid(self) -> None:
        valid = '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'
        errors = validate_auth_detail(valid)
        assert errors == []

    def test_set_auth_resets_from_late_stage(self) -> None:
        row = _make_row(params_to_commands='{"key":"val"}', params_for_test='[]')
        _complete_up_to(row, "write tests")

        assert get_current_step(row) == "write tests"

        new_auth = '{"auth_types":[{"type":"Plain","name":"credentials"}],"config":"REQUIRED(Plain)","params":{"credentials":{"type":"Plain","xsoar_type":9,"required":true}},"notes":null}'
        row["Auth Details"] = new_auth
        reset_from_step(row, CHECKPOINT_COLUMNS[0])

        for col in CHECKPOINT_COLUMNS:
            assert row[col] == ""
        assert get_current_step(row) == "generated manifest"
        assert row["Auth Details"] == new_auth
        assert row["Params to Commands"] == '{"key":"val"}'

    def test_set_auth_resets_from_fully_complete(self) -> None:
        row = _make_row(params_to_commands='{"k":"v"}', params_for_test='[]')
        row[AUTH_PARITY_FLAG_COLUMN] = "NO"
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                row[col] = NA_MARK
            else:
                row[col] = CHECK

        assert get_current_step(row) is None

        new_auth = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        row["Auth Details"] = new_auth
        reset_from_step(row, CHECKPOINT_COLUMNS[0])

        for col in CHECKPOINT_COLUMNS:
            assert row[col] == ""
        assert row[AUTH_PARITY_FLAG_COLUMN] == ""
        assert get_current_step(row) == "generated manifest"
        assert row["Auth Details"] == new_auth

    def test_set_integration_auth_api_valid(self) -> None:
        from unittest.mock import patch

        row = _make_row(name="FakeInt", params_to_commands='{"a":1}', params_for_test='[]')
        _complete_up_to(row, "write tests")
        rows = [row]

        new_auth = '{"auth_types":[{"type":"APIKey","name":"key"}],"config":"REQUIRED(APIKey)","params":{"key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'

        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv") as mock_save:
            result = set_integration_auth("FakeInt", new_auth)

        assert "error" not in result
        assert "message" in result
        assert result["current_step"] == "generated manifest"
        assert row["Auth Details"] == new_auth
        for col in CHECKPOINT_COLUMNS:
            assert row[col] == ""
        mock_save.assert_called_once_with(rows)

    def test_set_integration_auth_api_rejects_invalid_schema(self) -> None:
        from unittest.mock import patch

        with patch("workflow_state.load_csv") as mock_load:
            result = set_integration_auth("AnyInt", '{"bad": "json"}')

        assert "error" in result
        assert "schema validation failed" in result["error"].lower()
        mock_load.assert_not_called()

    def test_set_integration_auth_api_not_found(self) -> None:
        from unittest.mock import patch

        valid_auth = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'

        with patch("workflow_state.load_csv", return_value=[]), \
             patch("workflow_state.save_csv") as mock_save:
            result = set_integration_auth("NonExistent", valid_auth)

        assert "error" in result
        assert "not found" in result["error"].lower()
        mock_save.assert_not_called()


# ---------------------------------------------------------------------------
# Shadowed command test passes
# ---------------------------------------------------------------------------

class TestShadowedCommandStep:
    def test_shadowed_command_in_workflow_columns(self) -> None:
        assert "shadowed command test passes" in WORKFLOW_COLUMNS

    def test_shadowed_command_in_checkpoint_columns(self) -> None:
        assert "shadowed command test passes" in CHECKPOINT_COLUMNS

    def test_shadowed_command_after_wrote_checked_code(self) -> None:
        wrote_idx = CHECKPOINT_COLUMNS.index("wrote/checked code")
        cmd_idx = CHECKPOINT_COLUMNS.index("shadowed command test passes")
        assert cmd_idx == wrote_idx + 1

    def test_shadowed_command_before_write_tests(self) -> None:
        cmd_idx = CHECKPOINT_COLUMNS.index("shadowed command test passes")
        write_idx = CHECKPOINT_COLUMNS.index("write tests")
        assert cmd_idx < write_idx

    def test_markpass_shadowed_command(self) -> None:
        row = _make_row(params_to_commands="{}", params_for_test="[]")
        _complete_up_to(row, "shadowed command test passes")
        msg = markpass_step(row, "shadowed command test passes")
        assert "ERROR" not in msg
        assert row["shadowed command test passes"] == CHECK


# ---------------------------------------------------------------------------
# Atomic save_csv
# ---------------------------------------------------------------------------

class TestAtomicSaveCsv:
    """Verify save_csv writes atomically (tempfile + os.replace)."""

    def _sample_rows(self) -> list[dict[str, str]]:
        rows = []
        for i in range(3):
            row = _make_row(name=f"Integration{i}")
            rows.append(row)
        return rows

    def test_round_trip_preserves_rows(self, tmp_path, monkeypatch) -> None:
        csv_file = tmp_path / "integrations_report.csv"
        monkeypatch.setattr(workflow_state, "CSV_PATH", str(csv_file))

        rows = self._sample_rows()
        save_csv(rows)

        assert csv_file.exists()
        loaded = load_csv()
        assert len(loaded) == len(rows)
        for orig, got in zip(rows, loaded):
            assert orig["Integration ID"] == got["Integration ID"]
        assert list(loaded[0].keys()) == list(rows[0].keys())

    def test_failed_write_leaves_original_unchanged(
        self, tmp_path, monkeypatch
    ) -> None:
        csv_file = tmp_path / "integrations_report.csv"
        monkeypatch.setattr(workflow_state, "CSV_PATH", str(csv_file))

        original_rows = self._sample_rows()
        save_csv(original_rows)
        original_bytes = csv_file.read_bytes()

        def _boom(src, dst):
            raise OSError("simulated mid-write failure")

        monkeypatch.setattr(workflow_state.os, "replace", _boom)

        new_rows = self._sample_rows()
        new_rows[0]["Integration ID"] = "MUTATED"

        with pytest.raises(OSError, match="simulated mid-write failure"):
            save_csv(new_rows)

        assert csv_file.read_bytes() == original_bytes

        leftovers = [
            p
            for p in os.listdir(tmp_path)
            if p.startswith(".integrations_report.") and p.endswith(".tmp")
        ]
        assert leftovers == [], f"Temp files leaked: {leftovers}"


# ---------------------------------------------------------------------------
# show-step (format_step_value + cmd_show_step)
# ---------------------------------------------------------------------------

class TestFormatStepValue:
    """Tests for the format_step_value display helper."""

    def test_pretty_prints_json_params_to_commands(self) -> None:
        row = _make_row(name="IntA", params_to_commands='{"key":"val","n":1}')
        output = format_step_value(row, "Params to Commands")
        assert "IntA" in output
        assert "Params to Commands" in output
        assert '"key": "val"' in output
        assert '"n": 1' in output
        assert "\n" in output

    def test_pretty_prints_json_params_for_test(self) -> None:
        row = _make_row(name="IntA", params_for_test='["api_key","other"]')
        output = format_step_value(row, "Params for test with default in code")
        assert "IntA" in output
        assert "Params for test with default in code" in output
        assert '"api_key"' in output

    def test_pretty_prints_json_shared_params(self) -> None:
        row = _make_row(name="IntA")
        row["Params same in other handlers"] = '["x","y"]'
        output = format_step_value(row, "Params same in other handlers")
        assert "IntA" in output
        assert '"x"' in output
        assert '"y"' in output

    def test_pretty_prints_auth_details(self) -> None:
        row = _make_row(name="IntA")
        row["Auth Details"] = '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'
        output = format_step_value(row, "Auth Details")
        assert "IntA" in output
        assert "Auth Details" in output
        assert '"APIKey"' in output

    def test_displays_checkpoint_value(self) -> None:
        row = _make_row(name="IntA")
        row["generated manifest"] = CHECK
        output = format_step_value(row, "generated manifest")
        assert "IntA" in output
        assert "generated manifest" in output
        assert CHECK in output

    def test_displays_not_set_for_empty(self) -> None:
        row = _make_row(name="IntA")
        output = format_step_value(row, "wrote/checked code")
        assert "IntA" in output
        assert "wrote/checked code" in output
        assert "(not set)" in output

    def test_displays_not_set_for_whitespace_only(self) -> None:
        row = _make_row(name="IntA", overrides={"wrote/checked code": "   "})
        output = format_step_value(row, "wrote/checked code")
        assert "(not set)" in output

    def test_displays_flag_value(self) -> None:
        row = _make_row(name="IntA", overrides={AUTH_PARITY_FLAG_COLUMN: "YES"})
        output = format_step_value(row, AUTH_PARITY_FLAG_COLUMN)
        assert "IntA" in output
        assert AUTH_PARITY_FLAG_COLUMN in output
        assert "YES" in output

    def test_invalid_json_falls_back_to_raw(self) -> None:
        row = _make_row(name="IntA", params_to_commands="not really json")
        output = format_step_value(row, "Params to Commands")
        assert "IntA" in output
        assert "not really json" in output


class TestCmdShowStep:
    """Tests for the show-step CLI command."""

    def _patch_csv(self, monkeypatch, rows: list[dict[str, str]]) -> None:
        monkeypatch.setattr(workflow_state, "load_csv", lambda: rows)

    def test_show_step_happy_path_json(self, monkeypatch, capsys) -> None:
        rows = [_make_row(name="MyInt", params_to_commands='{"foo":"bar"}')]
        self._patch_csv(monkeypatch, rows)

        cmd_show_step(["MyInt", "Params to Commands"])

        out = capsys.readouterr().out
        assert "MyInt" in out
        assert "Params to Commands" in out
        assert '"foo": "bar"' in out

    def test_show_step_happy_path_checkpoint(self, monkeypatch, capsys) -> None:
        row = _make_row(name="MyInt")
        row["generated manifest"] = CHECK
        rows = [row]
        self._patch_csv(monkeypatch, rows)

        cmd_show_step(["MyInt", "generated manifest"])

        out = capsys.readouterr().out
        assert "MyInt" in out
        assert "generated manifest" in out
        assert CHECK in out

    def test_show_step_happy_path_data_column(self, monkeypatch, capsys) -> None:
        row = _make_row(name="MyInt")
        row["Integration File Path"] = "Packs/Foo/Integrations/Foo/Foo.yml"
        rows = [row]
        self._patch_csv(monkeypatch, rows)

        cmd_show_step(["MyInt", "Integration File Path"])

        out = capsys.readouterr().out
        assert "MyInt" in out
        assert "Integration File Path" in out
        assert "Packs/Foo/Integrations/Foo/Foo.yml" in out

    def test_show_step_happy_path_case_insensitive_id(
        self, monkeypatch, capsys
    ) -> None:
        rows = [_make_row(name="Cisco Spark", params_to_commands='{"k":"v"}')]
        self._patch_csv(monkeypatch, rows)

        cmd_show_step(["cisco spark", "Params to Commands"])

        out = capsys.readouterr().out
        assert "Cisco Spark" in out
        assert '"k": "v"' in out

    def test_show_step_missing_integration(self, monkeypatch, capsys) -> None:
        rows = [_make_row(name="OtherInt")]
        self._patch_csv(monkeypatch, rows)

        with pytest.raises(SystemExit) as exc_info:
            cmd_show_step(["NonExistent", "Params to Commands"])

        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "ERROR" in out
        assert "NonExistent" in out
        assert "not found" in out

    def test_show_step_unknown_step(self, monkeypatch, capsys) -> None:
        rows = [_make_row(name="MyInt")]
        self._patch_csv(monkeypatch, rows)

        with pytest.raises(SystemExit) as exc_info:
            cmd_show_step(["MyInt", "totally bogus step"])

        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "ERROR" in out
        assert "totally bogus step" in out
        assert "Valid columns" in out

    def test_show_step_missing_args_prints_usage(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc_info:
            cmd_show_step([])

        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "Usage" in out
        assert "show-step" in out

    def test_show_step_command_registered(self) -> None:
        from workflow_state import COMMANDS
        assert "show-step" in COMMANDS
        assert COMMANDS["show-step"] is cmd_show_step


# ---------------------------------------------------------------------------
# set-shared-params command registration
# ---------------------------------------------------------------------------

class TestSetSharedParamsCommand:
    def test_set_shared_params_command_registered(self) -> None:
        from workflow_state import COMMANDS, cmd_set_shared_params
        assert "set-shared-params" in COMMANDS
        assert COMMANDS["set-shared-params"] is cmd_set_shared_params
