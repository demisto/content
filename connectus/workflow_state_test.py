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
    VALID_AUTH_TYPES,
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
    set_integration_auth,
    validate_auth_detail,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_row(
    name: str = "TestIntegration",
    script_inputs: str = "",
    params_for_test: str = "",
    auth_params_set: str = "",
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create a blank workflow row dict for testing."""
    row: dict[str, str] = {
        "Integration Name": name,
        "Support Level": "xsoar",
        "Provider": "TestProvider",
        "Auth Detail": '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}',
        "auth params set": auth_params_set,
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
        assert get_current_step(row) == "auth params set"

    def test_first_step_done(self) -> None:
        row = _make_row()
        row["auth params set"] = CHECK
        assert get_current_step(row) == "generated manifest"

    def test_second_checkpoint_done(self) -> None:
        row = _make_row()
        row["auth params set"] = CHECK
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

        reset_from_step(row, "auth params set")

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
        row = _make_row(script_inputs="", auth_params_set=CHECK)
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "script inputs" in msg
        assert "set-inputs" in msg

    def test_generated_manifest_requires_auth_params_set(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}")
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "not up to that step" in msg

    def test_generated_manifest_works_with_script_inputs(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    # --- Sequential enforcement ---

    def test_cannot_skip_ahead(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        msg = markpass_step(row, "wrote code")
        assert "ERROR" in msg
        assert "not up to that step" in msg
        assert "generated manifest" in msg

    def test_cannot_skip_multiple_steps(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        msg = markpass_step(row, "unit tests passed")
        assert "ERROR" in msg
        assert "not up to that step" in msg

    def test_sequential_pass_works(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        assert "auth params set" in output

    def test_in_progress_shows_current_step(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        row["generated manifest"] = CHECK
        row["wrote code"] = CHECK
        result = format_dashboard_row(row)
        assert result is not None
        # Should have 3 filled + 6 empty blocks (auth params set + generated manifest + wrote code)
        assert "███" in result
        assert "░" in result


# ---------------------------------------------------------------------------
# Integration: markpass + reset-to round-trip
# ---------------------------------------------------------------------------

class TestMarkpassResetRoundTrip:
    def test_markpass_then_reset_to_same_step(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        markpass_step(row, "generated manifest")
        assert row["generated manifest"] == CHECK

        reset_from_step(row, "generated manifest")
        assert row["generated manifest"] == ""
        assert get_current_step(row) == "generated manifest"

    def test_markpass_several_then_reset_to_middle(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        assert get_current_step(row) == "auth params set"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_markpass_with_whitespace_in_value(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        row["generated manifest"] = "  "
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_script_inputs_with_complex_json(self) -> None:
        complex_json = '{"args": ["a", "b"], "config": {"nested": true}}'
        row = _make_row(script_inputs=complex_json, params_for_test="{}", auth_params_set=CHECK)
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_markpass_preserves_other_columns(self) -> None:
        row = _make_row(name="SpecialInt", script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
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
        row = _make_row(script_inputs="{}", params_for_test="", auth_params_set=CHECK)
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "params required for test" in msg

    def test_generated_manifest_works_with_both_inputs(self) -> None:
        row = _make_row(script_inputs="{}", params_for_test='{"key": "val"}', auth_params_set=CHECK)
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
        row = _make_row(name="IntA", overrides={"assignee": "Alice"}, auth_params_set=CHECK)
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


# ---------------------------------------------------------------------------
# Auth params set
# ---------------------------------------------------------------------------

class TestAuthParamsSet:
    def test_auth_params_set_in_workflow_columns(self) -> None:
        assert "auth params set" in WORKFLOW_COLUMNS

    def test_auth_params_set_in_checkpoint_columns(self) -> None:
        assert "auth params set" in CHECKPOINT_COLUMNS

    def test_auth_params_set_is_first_checkpoint(self) -> None:
        assert CHECKPOINT_COLUMNS[0] == "auth params set"

    def test_auth_params_set_can_be_marked_without_prerequisites(self) -> None:
        """auth params set has no prerequisites — it can be marked at any time."""
        row = _make_row()
        msg = markpass_step(row, "auth params set")
        assert "ERROR" not in msg
        assert row["auth params set"] == CHECK

    def test_auth_params_set_already_done(self) -> None:
        row = _make_row(auth_params_set=CHECK)
        msg = markpass_step(row, "auth params set")
        assert "already marked as passed" in msg

    def test_generated_manifest_requires_auth_params_set_checkpoint(self) -> None:
        """generated manifest cannot be marked unless auth params set is passed."""
        row = _make_row(script_inputs="{}", params_for_test="{}")
        # auth params set is empty — should fail
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" in msg
        assert "not up to that step" in msg
        assert "auth params set" in msg

    def test_auth_params_set_then_generated_manifest(self) -> None:
        """After marking auth params set, generated manifest can proceed."""
        row = _make_row(script_inputs="{}", params_for_test="{}")
        msg1 = markpass_step(row, "auth params set")
        assert "ERROR" not in msg1
        assert row["auth params set"] == CHECK

        msg2 = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg2
        assert row["generated manifest"] == CHECK

    def test_reset_from_auth_params_set_clears_all(self) -> None:
        """Resetting from auth params set clears all checkpoints."""
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        for col in CHECKPOINT_COLUMNS:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        reset_from_step(row, "auth params set")

        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty"
        assert row["requires auth parity test"] == ""

    def test_auth_params_set_preserved_after_later_reset(self) -> None:
        """Resetting from a later step preserves auth params set."""
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        row["generated manifest"] = CHECK
        row["wrote code"] = CHECK

        reset_from_step(row, "generated manifest")

        assert row["auth params set"] == CHECK
        assert row["generated manifest"] == ""

    def test_status_shows_auth_params_set(self) -> None:
        row = _make_row()
        output = format_status(row)
        assert "auth params set" in output

    def test_current_step_is_auth_params_set_on_blank_row(self) -> None:
        row = _make_row()
        assert get_current_step(row) == "auth params set"


# ---------------------------------------------------------------------------
# validate_auth_detail
# ---------------------------------------------------------------------------

class TestValidateAuthDetail:
    """Tests for the Auth Detail JSON schema validator."""

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
        """Every value in VALID_AUTH_TYPES is accepted in auth_types entries."""
        for auth_type in VALID_AUTH_TYPES:
            detail = f'{{"auth_types":[{{"type":"{auth_type}","name":"x"}}],"config":"NONE","params":{{}},"notes":null}}'
            errors = validate_auth_detail(detail)
            assert errors == [], f"Type '{auth_type}' should be valid but got: {errors}"


# ---------------------------------------------------------------------------
# set-auth (set Auth Detail + reset workflow)
# ---------------------------------------------------------------------------

class TestSetAuth:
    def test_set_auth_updates_auth_detail(self) -> None:
        """Setting auth detail updates the Auth Detail column."""
        row = _make_row(script_inputs="{}", params_for_test="{}", auth_params_set=CHECK)
        new_auth = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        row["Auth Detail"] = new_auth
        reset_from_step(row, "auth params set")
        assert row["Auth Detail"] == new_auth
        assert row["auth params set"] == ""

    def test_set_auth_resets_workflow(self) -> None:
        """Setting auth detail resets all workflow steps from auth params set."""
        row = _make_row(script_inputs="{}", params_for_test="{}")
        # Complete several steps
        for col in CHECKPOINT_COLUMNS[:5]:
            row[col] = CHECK
        row["requires auth parity test"] = "YES"

        # Simulate set-auth: update auth detail and reset
        row["Auth Detail"] = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        reset_from_step(row, "auth params set")

        # All checkpoints should be cleared
        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty after set-auth"
        # Auth flag should also be cleared
        assert row["requires auth parity test"] == ""
        # Current step should be auth params set
        assert get_current_step(row) == "auth params set"

    def test_set_auth_preserves_script_inputs(self) -> None:
        """Setting auth detail preserves script inputs and params for test."""
        row = _make_row(script_inputs='{"key": "val"}', params_for_test='{"p": "v"}')
        row["Auth Detail"] = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        reset_from_step(row, "auth params set")
        assert row["script inputs"] == '{"key": "val"}'
        assert row["params required for test"] == '{"p": "v"}'

    def test_set_auth_preserves_data_columns(self) -> None:
        """Setting auth detail preserves other data columns."""
        row = _make_row(name="SpecialInt")
        row["Auth Detail"] = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        reset_from_step(row, "auth params set")
        assert row["Integration Name"] == "SpecialInt"
        assert row["Provider"] == "TestProvider"

    def test_set_auth_schema_validation_rejects_invalid(self) -> None:
        """set-auth rejects values that don't match the Auth Detail schema."""
        # Missing required keys
        errors = validate_auth_detail('{"auth_types":[]}')
        assert len(errors) > 0
        assert "Missing required keys" in errors[0]

    def test_set_auth_schema_validation_rejects_bad_auth_type(self) -> None:
        """set-auth rejects auth_types with invalid enum values."""
        bad = '{"auth_types":[{"type":"INVALID","name":"x"}],"config":"NONE","params":{},"notes":null}'
        errors = validate_auth_detail(bad)
        assert any("invalid type" in e for e in errors)

    def test_set_auth_schema_validation_rejects_bad_param(self) -> None:
        """set-auth rejects params with missing or invalid fields."""
        bad = '{"auth_types":[],"config":"NONE","params":{"k":{"type":"APIKey"}},"notes":null}'
        errors = validate_auth_detail(bad)
        assert any("missing" in e for e in errors)

    def test_set_auth_schema_validation_accepts_valid(self) -> None:
        """set-auth accepts a fully valid Auth Detail JSON."""
        valid = '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'
        errors = validate_auth_detail(valid)
        assert errors == []

    def test_set_auth_resets_from_late_stage(self) -> None:
        """Setting auth when integration is at a late workflow stage resets everything."""
        row = _make_row(script_inputs='{"key": "val"}', params_for_test='{"p": "v"}')
        # Complete up to "param parity test passes" (6 checkpoints done)
        _complete_up_to(row, "param parity test passes")

        # Verify we're at a late stage
        assert get_current_step(row) == "param parity test passes"
        assert row["auth params set"] == CHECK
        assert row["generated manifest"] == CHECK
        assert row["wrote code"] == CHECK
        assert row["validations passed"] == CHECK
        assert row["unit tests passed"] == CHECK

        # Simulate set-auth: update auth detail and reset
        new_auth = '{"auth_types":[{"type":"Plain","name":"credentials"}],"config":"REQUIRED(Plain)","params":{"credentials":{"type":"Plain","xsoar_type":9,"required":true}},"notes":null}'
        row["Auth Detail"] = new_auth
        reset_from_step(row, "auth params set")

        # ALL checkpoints should be cleared
        assert row["auth params set"] == ""
        assert row["generated manifest"] == ""
        assert row["wrote code"] == ""
        assert row["validations passed"] == ""
        assert row["unit tests passed"] == ""
        assert row["param parity test passes"] == ""
        assert get_current_step(row) == "auth params set"
        # Auth detail should be updated
        assert row["Auth Detail"] == new_auth
        # Script inputs should be preserved
        assert row["script inputs"] == '{"key": "val"}'

    def test_set_auth_resets_from_fully_complete(self) -> None:
        """Setting auth when ALL steps are complete resets everything."""
        row = _make_row(script_inputs='{"key": "val"}', params_for_test='{"p": "v"}')
        row["requires auth parity test"] = "NO"
        # Complete ALL checkpoints
        for col in CHECKPOINT_COLUMNS:
            if col == "auth parity test passes":
                row[col] = NA_MARK
            else:
                row[col] = CHECK

        # Verify fully complete
        assert get_current_step(row) is None

        # Simulate set-auth
        new_auth = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'
        row["Auth Detail"] = new_auth
        reset_from_step(row, "auth params set")

        # Everything should be cleared
        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty"
        assert row["requires auth parity test"] == ""
        assert get_current_step(row) == "auth params set"
        assert row["Auth Detail"] == new_auth

    def test_set_auth_resets_from_code_reviewed(self) -> None:
        """Setting auth when integration is at 'code reviewed' resets all downstream."""
        row = _make_row(script_inputs='{"x": 1}', params_for_test='{}')
        row["requires auth parity test"] = "YES"
        _complete_up_to(row, "code reviewed")

        # Verify we're at code reviewed
        assert get_current_step(row) == "code reviewed"
        assert row["auth parity test passes"] == CHECK

        # Simulate set-auth
        new_auth = '{"auth_types":[{"type":"OAuth2ClientCreds","name":"client_creds"}],"config":"REQUIRED(OAuth2ClientCreds)","params":{"client_creds":{"type":"OAuth2ClientCreds","xsoar_type":9,"required":true}},"notes":null}'
        row["Auth Detail"] = new_auth
        reset_from_step(row, "auth params set")

        # ALL checkpoints cleared
        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty after set-auth"
        # Auth parity flag also cleared
        assert row["requires auth parity test"] == ""
        assert get_current_step(row) == "auth params set"
        assert row["Auth Detail"] == new_auth
        # Data preserved
        assert row["script inputs"] == '{"x": 1}'
        assert row["params required for test"] == '{}'

    def test_set_integration_auth_api_valid(self) -> None:
        """set_integration_auth programmatic API validates, updates, and resets."""
        from unittest.mock import patch

        # Build a fake CSV row that's progressed to "unit tests passed"
        row = _make_row(name="FakeInt", script_inputs='{"a": 1}', params_for_test='{}')
        _complete_up_to(row, "unit tests passed")
        rows = [row]

        new_auth = '{"auth_types":[{"type":"APIKey","name":"key"}],"config":"REQUIRED(APIKey)","params":{"key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'

        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv") as mock_save:
            result = set_integration_auth("FakeInt", new_auth)

        assert "error" not in result
        assert "message" in result
        assert result["current_step"] == "auth params set"
        # Verify the row was mutated correctly
        assert row["Auth Detail"] == new_auth
        for col in CHECKPOINT_COLUMNS:
            assert row[col] == "", f"Expected '{col}' to be empty"
        # save_csv should have been called once
        mock_save.assert_called_once_with(rows)

    def test_set_integration_auth_api_rejects_invalid_schema(self) -> None:
        """set_integration_auth rejects invalid Auth Detail without touching CSV."""
        from unittest.mock import patch

        with patch("workflow_state.load_csv") as mock_load:
            result = set_integration_auth("AnyInt", '{"bad": "json"}')

        assert "error" in result
        assert "schema validation failed" in result["error"].lower()
        # load_csv should NOT have been called since validation fails first
        mock_load.assert_not_called()

    def test_set_integration_auth_api_not_found(self) -> None:
        """set_integration_auth returns error when integration not found."""
        from unittest.mock import patch

        valid_auth = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'

        with patch("workflow_state.load_csv", return_value=[]), \
             patch("workflow_state.save_csv") as mock_save:
            result = set_integration_auth("NonExistent", valid_auth)

        assert "error" in result
        assert "not found" in result["error"].lower()
        mock_save.assert_not_called()
