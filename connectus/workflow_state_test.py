#!/usr/bin/env python3
"""
Unit tests for workflow_state.py

Tests the core state-machine logic (pure functions operating on row dicts)
without touching the real CSV file.
"""

import copy
import pytest

from workflow_state import (
    CHECK,
    CHECKPOINT_COLUMNS,
    NA_MARK,
    WORKFLOW_COLUMNS,
    find_row,
    format_by_assignee,
    format_dashboard_row,
    format_status,
    get_current_step,
    get_step_index,
    is_checked,
    list_by_assignee,
    markpass_step,
    reset_from_step,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_row(
    name: str = "TestIntegration",
    script_inputs: str = "",
    params_for_test: str = "",
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create a blank workflow row dict for testing."""
    row: dict[str, str] = {
        "Integration Name": name,
        "Support Level": "xsoar",
        "Provider": "TestProvider",
        "Auth Class": "APIKey",
        "Auth Mode": "SINGLE_REQUIRED",
        "Auth Detail": '{"params":{"api_key":{"types":["APIKey"],"xsoar_type":4,"required":true}},"notes":null,"required_count":{"APIKey":1}}',
        "script inputs": script_inputs,
        "params required for test": params_for_test,
    }
    for col in WORKFLOW_COLUMNS:
        if col not in row:
            row[col] = ""
    if overrides:
        row.update(overrides)
    return row


def _complete_up_to(row: dict[str, str], step_name: str) -> None:
    """Mark all checkpoint steps up to (but NOT including) step_name as ✅.

    Also sets 'script inputs' and 'params required for test' to '{}' if not
    already set, since they are prerequisites for 'generated manifest'.
    """
    if not row.get("script inputs", "").strip():
        row["script inputs"] = "{}"
    if not row.get("params required for test", "").strip():
        row["params required for test"] = "{}"
    for col in CHECKPOINT_COLUMNS:
        if col == step_name:
            break
        # Skip auth parity test passes if flag is NO/N/A
        if col == "auth parity test passes":
            flag = row.get("requires auth parity test", "").strip().upper()
            if flag in ("NO", "N/A", ""):
                row[col] = NA_MARK
                continue
        row[col] = CHECK


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
        assert get_current_step(row) == "wrote code"

    def test_all_done_returns_none(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        assert get_current_step(row) is None

    def test_skips_auth_parity_when_flag_no(self) -> None:
        row = _make_row()
        # Complete everything up to auth parity test passes
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row["requires auth parity test"] = "NO"
        # Should skip auth parity test passes and go to code reviewed
        assert get_current_step(row) == "code reviewed"

    def test_skips_auth_parity_when_flag_na(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row["requires auth parity test"] = "N/A"
        assert get_current_step(row) == "code reviewed"

    def test_skips_auth_parity_when_flag_empty(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row["requires auth parity test"] = ""
        # Empty flag also skips auth parity
        assert get_current_step(row) == "code reviewed"

    def test_auth_parity_required_when_flag_yes(self) -> None:
        row = _make_row()
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                break
            row[col] = CHECK
        row["requires auth parity test"] = "YES"
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

    def test_non_checkpoint_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown checkpoint step"):
            get_step_index("script inputs")


# ---------------------------------------------------------------------------
# reset_from_step
# ---------------------------------------------------------------------------

class TestResetFromStep:
    def test_reset_from_first_clears_all(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        reset_from_step(row, "generated manifest")

        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty"
        # Auth flag should also be cleared since we reset from before it
        assert row["requires auth parity test"] == ""

    def test_reset_from_middle(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        reset_from_step(row, "validations passed")

        # First two should remain
        assert row["generated manifest"] == CHECK
        assert row["wrote code"] == CHECK
        # Rest should be cleared
        assert row["validations passed"] == ""
        assert row["unit tests passed"] == ""
        assert row["code merged"] == ""

    def test_reset_from_last(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK

        reset_from_step(row, "code merged")

        # All but last should remain
        assert row["code reviewed"] == CHECK
        assert row["code merged"] == ""

    def test_reset_clears_auth_flag_when_before_auth_position(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        reset_from_step(row, "param parity test passes")

        assert row["requires auth parity test"] == ""

    def test_reset_preserves_auth_flag_when_after_auth_position(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        reset_from_step(row, "code reviewed")

        # Auth flag should be preserved since we reset from after it
        assert row["requires auth parity test"] == "YES"

    def test_script_inputs_preserved(self) -> None:
        row = _make_row(script_inputs='{"key": "val"}')
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["script inputs"] == '{"key": "val"}'


# ---------------------------------------------------------------------------
# markpass_step
# ---------------------------------------------------------------------------

class TestMarkpassStep:
    # --- Non-checkpoint rejection ---

    def test_rejects_script_inputs(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "script inputs")
        assert "ERROR" in msg
        assert "set-inputs" in msg

    def test_rejects_requires_auth_parity_test(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "requires auth parity test")
        assert "ERROR" in msg
        assert "set-auth-flag" in msg

    # --- Prerequisite: script inputs for generated manifest ---

    def test_generated_manifest_requires_script_inputs(self) -> None:
        row = _make_row(script_inputs="")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "script inputs" in msg
        assert "set-inputs" in msg

    def test_generated_manifest_works_with_script_inputs(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    # --- Sequential enforcement ---

    def test_cannot_skip_ahead(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        msg = markpass_step(row, "wrote code")
        assert "ERROR" in msg
        assert "not up to that step" in msg
        assert "generated manifest" in msg

    def test_cannot_skip_multiple_steps(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        msg = markpass_step(row, "unit tests passed")
        assert "ERROR" in msg
        assert "not up to that step" in msg

    def test_sequential_pass_works(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        msg1 = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg1
        assert row["generated manifest"] == CHECK

        msg2 = markpass_step(row, "wrote code")
        assert "ERROR" not in msg2
        assert row["wrote code"] == CHECK

        msg3 = markpass_step(row, "validations passed")
        assert "ERROR" not in msg3
        assert row["validations passed"] == CHECK

    # --- Already done ---

    def test_already_done(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["generated manifest"] = CHECK
        msg = markpass_step(row, "generated manifest")
        assert "already marked as passed" in msg

    # --- Auth parity special cases ---

    def test_auth_parity_requires_flag_set(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        _complete_up_to(row, "auth parity test passes")
        row["requires auth parity test"] = ""

        msg = markpass_step(row, "auth parity test passes")
        assert "ERROR" in msg
        assert "set-auth-flag" in msg

    def test_auth_parity_auto_na_when_flag_no(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        _complete_up_to(row, "auth parity test passes")
        row["requires auth parity test"] = "NO"

        msg = markpass_step(row, "auth parity test passes")
        assert "N/A" in msg
        assert row["auth parity test passes"] == NA_MARK

    def test_auth_parity_auto_na_when_flag_na(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        _complete_up_to(row, "auth parity test passes")
        row["requires auth parity test"] = "N/A"

        msg = markpass_step(row, "auth parity test passes")
        assert "N/A" in msg
        assert row["auth parity test passes"] == NA_MARK

    def test_auth_parity_passes_when_flag_yes(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        _complete_up_to(row, "auth parity test passes")
        row["requires auth parity test"] = "YES"

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
        row = _make_row(script_inputs='{"arg1": "val1"}', params_for_test='{}')
        row["requires auth parity test"] = "NO"

        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                # Should auto-set to N/A since flag is NO
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
        # A blank row still has a current step (the first checkpoint)
        assert "Current step" in output
        assert "generated manifest" in output

    def test_in_progress_shows_current_step(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["generated manifest"] = CHECK
        output = format_status(row)
        assert "Current step" in output
        assert "wrote code" in output

    def test_all_complete_shows_celebration(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        output = format_status(row)
        assert "All steps complete" in output

    def test_shows_integration_name(self) -> None:
        row = _make_row(name="My Cool Integration")
        output = format_status(row)
        assert "My Cool Integration" in output

    def test_shows_script_inputs_not_set(self) -> None:
        row = _make_row(script_inputs="")
        output = format_status(row)
        assert "(not set)" in output

    def test_shows_script_inputs_value(self) -> None:
        row = _make_row(script_inputs='{"key": "val"}')
        output = format_status(row)
        assert '{"key": "val"}' in output


# ---------------------------------------------------------------------------
# format_dashboard_row
# ---------------------------------------------------------------------------

class TestFormatDashboardRow:
    def test_no_progress_returns_none(self) -> None:
        row = _make_row()
        assert format_dashboard_row(row) is None

    def test_with_progress_returns_string(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["generated manifest"] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        assert "TestIntegration" in result

    def test_all_done_shows_done(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        assert "DONE" in result

    def test_progress_bar_format(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["generated manifest"] = CHECK
        row["wrote code"] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        # Should have 2 filled + 6 empty blocks
        assert "██" in result
        assert "░" in result


# ---------------------------------------------------------------------------
# Integration: markpass + reset-to round-trip
# ---------------------------------------------------------------------------

class TestMarkpassResetRoundTrip:
    def test_markpass_then_reset_to_same_step(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        markpass_step(row, "generated manifest")
        assert row["generated manifest"] == CHECK

        reset_from_step(row, "generated manifest")
        assert row["generated manifest"] == ""
        assert get_current_step(row) == "generated manifest"

    def test_markpass_several_then_reset_to_middle(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        markpass_step(row, "generated manifest")
        markpass_step(row, "wrote code")
        markpass_step(row, "validations passed")
        markpass_step(row, "unit tests passed")

        reset_from_step(row, "wrote code")

        assert row["generated manifest"] == CHECK
        assert row["wrote code"] == ""
        assert row["validations passed"] == ""
        assert row["unit tests passed"] == ""
        assert get_current_step(row) == "wrote code"

    def test_reset_then_markpass_again(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        markpass_step(row, "generated manifest")
        markpass_step(row, "wrote code")

        reset_from_step(row, "generated manifest")

        # Should be able to markpass again from the beginning
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_full_reset_clears_everything(self) -> None:
        row = _make_row(script_inputs='{"a": 1}')
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        # Simulate full reset (like cmd_reset does)
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
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["generated manifest"] = "  "
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_script_inputs_with_complex_json(self) -> None:
        complex_json = '{"args": ["a", "b"], "config": {"nested": true}}'
        row = _make_row(script_inputs=complex_json, params_for_test="{}")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_markpass_preserves_other_columns(self) -> None:
        row = _make_row(name="SpecialInt", script_inputs="{}", params_for_test="{}")
        original_name = row["Integration Name"]
        original_provider = row["Provider"]

        markpass_step(row, "generated manifest")

        assert row["Integration Name"] == original_name
        assert row["Provider"] == original_provider

    def test_reset_preserves_data_columns(self) -> None:
        row = _make_row(name="SpecialInt", script_inputs="{}", params_for_test="{}")
        row["generated manifest"] = CHECK
        row["wrote code"] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["Integration Name"] == "SpecialInt"
        assert row["Provider"] == "TestProvider"
        assert row["script inputs"] == "{}"


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
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["assignee"] = "Jane Smith"
        row["generated manifest"] = CHECK
        row["wrote code"] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["assignee"] == "Jane Smith"

    def test_assignee_preserved_after_markpass(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        row["assignee"] = "Jane Smith"

        markpass_step(row, "generated manifest")

        assert row["assignee"] == "Jane Smith"
        assert row["generated manifest"] == CHECK

    def test_assignee_in_data_columns(self) -> None:
        from workflow_state import DATA_COLUMNS
        assert "assignee" in DATA_COLUMNS


# ---------------------------------------------------------------------------
# Params required for test
# ---------------------------------------------------------------------------

class TestParamsRequiredForTest:
    def test_markpass_rejects_params_required_for_test(self) -> None:
        row = _make_row()
        msg = markpass_step(row, "params required for test")
        assert "ERROR" in msg
        assert "set-params-for-test" in msg

    def test_generated_manifest_requires_params(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "params required for test" in msg

    def test_generated_manifest_works_with_both_inputs(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test='{"key": "val"}')
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_params_in_workflow_columns(self) -> None:
        assert "params required for test" in WORKFLOW_COLUMNS

    def test_params_in_non_checkpoint_steps(self) -> None:
        from workflow_state import NON_CHECKPOINT_STEPS
        assert "params required for test" in NON_CHECKPOINT_STEPS
        assert NON_CHECKPOINT_STEPS["params required for test"] == "set-params-for-test"

    def test_status_shows_params_not_set(self) -> None:
        row = _make_row()
        output = format_status(row)
        # Should show (not set) for params required for test
        assert "params required for test" in output

    def test_status_shows_params_value(self) -> None:
        row = _make_row(params_for_test='{"api_key": "test123"}')
        output = format_status(row)
        assert '{"api_key": "test123"}' in output

    def test_params_preserved_after_reset(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test='{"key": "val"}')
        row["generated manifest"] = CHECK
        row["wrote code"] = CHECK

        reset_from_step(row, "generated manifest")

        # params required for test is not a checkpoint, should be preserved
        assert row["params required for test"] == '{"key": "val"}'


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
        names = [r["Integration Name"] for r in result]
        assert "IntA" in names
        assert "IntC" in names

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

    def test_multiple_integrations_same_assignee(self) -> None:
        rows = [
            _make_row(name="IntA", overrides={"assignee": "Bob"}),
            _make_row(name="IntB", overrides={"assignee": "Bob"}),
            _make_row(name="IntC", overrides={"assignee": "Bob"}),
        ]
        result = list_by_assignee(rows, "Bob")
        assert len(result) == 3
        names = [r["Integration Name"] for r in result]
        assert names == ["IntA", "IntB", "IntC"]


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
        row = _make_row(name="IntA", overrides={"assignee": "Alice"})
        row["script inputs"] = "{}"
        row["generated manifest"] = CHECK
        # Current step should be "wrote code"
        output = format_by_assignee([row], "Alice")
        assert "wrote code" in output

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
