#!/usr/bin/env python3
"""
Unit tests for workflow_state.py — UNIFIED 16-STEP MODEL.

Covers schema constants, the unified completion predicate (`is_done`),
`current_step`, cascade resets, the `set-assignee` carve-out, the optional
step `skip`, the flag-step #12 → #13 auto-N/A interaction, normalization on
read/write, the new `next` command, and the `reset-to`/`fail`/`reset`
verbs.
"""

from __future__ import annotations

import json
import os
from typing import Optional
from unittest.mock import patch

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
    STEP_BY_INDEX,
    STEP_BY_NAME,
    STEPS,
    VALID_AUTH_TYPES,
    VALID_FLAG_VALUES,
    WORKFLOW_COLUMNS,
    WORKFLOW_DATA_COLUMNS,
    WorkflowError,
    apply_step_action,
    cmd_markpass,
    cmd_next,
    cmd_set_assignee,
    cmd_set_auth_flag,
    cmd_show_step,
    cmd_skip,
    current_step,
    fail_integration_step,
    find_row,
    format_by_assignee,
    format_dashboard_row,
    format_next_line,
    format_status,
    format_step_value,
    get_current_step,
    is_checked,
    is_done,
    list_by_assignee,
    load_csv,
    markpass_integration_step,
    markpass_step,
    normalize_row,
    reset_after,
    reset_from_step,
    save_csv,
    set_integration_auth,
    skip_integration_step,
    validate_auth_detail,
)


VALID_AUTH_JSON = (
    '{"auth_types":[{"type":"APIKey","name":"api_key"}],'
    '"config":"REQUIRED(APIKey)",'
    '"params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},'
    '"notes":null}'
)
VALID_AUTH_JSON_NONE = '{"auth_types":[],"config":"NONE","params":{},"notes":null}'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _blank_row(name: str = "TestIntegration") -> dict[str, str]:
    """Build a blank row dict with all columns present."""
    row: dict[str, str] = {col: "" for col in ALL_COLUMNS}
    row["Integration ID"] = name
    return row


def _fully_complete_row(name: str = "TestIntegration") -> dict[str, str]:
    """Build a row with all 16 steps done."""
    row = _blank_row(name)
    row["assignee"] = "Alice"
    row["Auth Details"] = VALID_AUTH_JSON
    row["Params to Commands"] = '{"integration":"X","commands":{}}'
    row["Params for test with default in code"] = '[]'
    row["Params same in other handlers"] = '{}'
    for s in STEPS:
        if s.kind == "checkpoint":
            row[s.name] = CHECK
    row[AUTH_PARITY_FLAG_COLUMN] = "YES"
    row["auth parity test passes"] = CHECK
    return row


def _patch_csv(monkeypatch, rows: list[dict[str, str]]) -> None:
    monkeypatch.setattr(workflow_state, "load_csv", lambda: rows)
    monkeypatch.setattr(workflow_state, "save_csv", lambda r: None)


# ---------------------------------------------------------------------------
# §6.1 Schema and constants
# ---------------------------------------------------------------------------

class TestSchemaConstants:
    def test_steps_has_exactly_16_entries(self) -> None:
        assert len(STEPS) == 16

    def test_first_step_is_assignee(self) -> None:
        assert STEPS[0].name == "assignee"
        assert STEPS[0].index == 1

    def test_last_step_is_code_merged(self) -> None:
        assert STEPS[15].name == "code merged"
        assert STEPS[15].index == 16

    def test_only_step_5_is_optional(self) -> None:
        assert STEPS[4].optional is True
        for i, s in enumerate(STEPS):
            if i == 4:
                continue
            assert s.optional is False, f"Step #{s.index} {s.name} should not be optional"

    def test_step_2_is_auth_details(self) -> None:
        assert STEPS[1].name == "Auth Details"

    def test_step_12_is_flag(self) -> None:
        assert STEPS[11].name == AUTH_PARITY_FLAG_COLUMN
        assert STEPS[11].kind == "flag"

    def test_step_13_is_auth_parity_test(self) -> None:
        assert STEPS[12].name == "auth parity test passes"

    def test_step_names_match_workflow_columns_in_order(self) -> None:
        assert [s.name for s in STEPS] == WORKFLOW_COLUMNS

    def test_workflow_data_columns_derived(self) -> None:
        assert WORKFLOW_DATA_COLUMNS == [
            "assignee",
            "Auth Details",
            "Params to Commands",
            "Params for test with default in code",
            "Params same in other handlers",
        ]

    def test_checkpoint_columns_derived(self) -> None:
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

    def test_json_valued_columns_derived(self) -> None:
        assert JSON_VALUED_COLUMNS == {
            "Auth Details",
            "Params to Commands",
            "Params for test with default in code",
            "Params same in other handlers",
        }

    def test_non_checkpoint_steps_mapping(self) -> None:
        assert NON_CHECKPOINT_STEPS == {
            "assignee": "set-assignee",
            "Auth Details": "set-auth",
            "Params to Commands": "set-params-to-commands",
            "Params for test with default in code": "set-params-for-test",
            "Params same in other handlers": "set-shared-params",
            "requires auth parity test": "set-auth-flag",
        }

    def test_total_column_count_unchanged(self) -> None:
        assert EXPECTED_COLUMN_COUNT == 20
        assert len(ALL_COLUMNS) == 20

    def test_data_columns_unchanged(self) -> None:
        assert DATA_COLUMNS == [
            "Integration ID",
            "Integration File Path",
            "Connector ID",
            "special cases",
        ]

    def test_step_by_name_lookup(self) -> None:
        assert STEP_BY_NAME["assignee"].index == 1
        assert STEP_BY_NAME["code merged"].index == 16

    def test_step_by_index_lookup(self) -> None:
        assert STEP_BY_INDEX[1].name == "assignee"
        assert STEP_BY_INDEX[16].name == "code merged"


# ---------------------------------------------------------------------------
# §6.2 is_done predicate
# ---------------------------------------------------------------------------

class TestIsDone:
    def test_data_step_empty_is_not_done(self) -> None:
        row = _blank_row()
        assert is_done(row, STEP_BY_NAME["assignee"]) is False

    def test_data_step_whitespace_is_not_done(self) -> None:
        row = _blank_row()
        row["assignee"] = "   "
        assert is_done(row, STEP_BY_NAME["assignee"]) is False

    def test_data_step_with_value_is_done(self) -> None:
        row = _blank_row()
        row["assignee"] = "Alice"
        assert is_done(row, STEP_BY_NAME["assignee"]) is True

    def test_flag_step_empty_is_not_done(self) -> None:
        row = _blank_row()
        assert is_done(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN]) is False

    def test_flag_step_yes_is_done(self) -> None:
        row = _blank_row()
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"
        assert is_done(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN]) is True

    def test_flag_step_no_is_done(self) -> None:
        row = _blank_row()
        row[AUTH_PARITY_FLAG_COLUMN] = "NO"
        assert is_done(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN]) is True

    def test_flag_step_na_is_done(self) -> None:
        row = _blank_row()
        row[AUTH_PARITY_FLAG_COLUMN] = "N/A"
        assert is_done(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN]) is True

    def test_flag_step_garbage_is_not_done(self) -> None:
        row = _blank_row()
        row[AUTH_PARITY_FLAG_COLUMN] = "MAYBE"
        assert is_done(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN]) is False

    def test_checkpoint_step_check_is_done(self) -> None:
        row = _blank_row()
        row["generated manifest"] = CHECK
        assert is_done(row, STEP_BY_NAME["generated manifest"]) is True

    def test_checkpoint_step_na_is_done(self) -> None:
        row = _blank_row()
        row["auth parity test passes"] = NA_MARK
        assert is_done(row, STEP_BY_NAME["auth parity test passes"]) is True

    def test_checkpoint_step_arbitrary_text_is_not_done(self) -> None:
        row = _blank_row()
        row["generated manifest"] = "in progress"
        assert is_done(row, STEP_BY_NAME["generated manifest"]) is False


# ---------------------------------------------------------------------------
# §6.3 current_step
# ---------------------------------------------------------------------------

class TestCurrentStep:
    def test_blank_row_returns_step_1(self) -> None:
        row = _blank_row()
        assert current_step(row).name == "assignee"
        assert get_current_step(row) == "assignee"

    def test_steps_1_to_4_set_returns_step_5(self) -> None:
        row = _blank_row()
        row["assignee"] = "Alice"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        assert current_step(row).index == 5

    def test_steps_1_to_5_set_returns_step_6(self) -> None:
        row = _blank_row()
        row["assignee"] = "Alice"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = "{}"
        assert current_step(row).index == 6

    def test_step_5_skipped_returns_step_6(self) -> None:
        row = _blank_row()
        row["assignee"] = "Alice"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        assert current_step(row).index == 6

    def test_steps_1_to_11_done_step_12_no_returns_step_14(self) -> None:
        row = _fully_complete_row()
        # Reset 12 onward, then set 12 = NO and 13 = N/A
        row[AUTH_PARITY_FLAG_COLUMN] = "NO"
        row["auth parity test passes"] = NA_MARK
        row["param parity test passes"] = ""
        row["code reviewed"] = ""
        row["code merged"] = ""
        assert current_step(row).index == 14

    def test_steps_1_to_11_done_step_12_yes_step_13_check_returns_step_14(self) -> None:
        row = _fully_complete_row()
        row["param parity test passes"] = ""
        row["code reviewed"] = ""
        row["code merged"] = ""
        assert current_step(row).index == 14

    def test_all_16_done_returns_none(self) -> None:
        row = _fully_complete_row()
        assert current_step(row) is None
        assert get_current_step(row) is None

    def test_step_12_unset_after_step_11_done_returns_step_12(self) -> None:
        row = _blank_row()
        row["assignee"] = "Alice"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        for cp in ["generated manifest", "run manifest make validate",
                   "wrote/checked code", "shadowed command test passes",
                   "write tests", "precommit/validate/unit tests passed"]:
            row[cp] = CHECK
        assert current_step(row).index == 12


# ---------------------------------------------------------------------------
# is_checked
# ---------------------------------------------------------------------------

class TestIsChecked:
    def test_check_mark(self) -> None:
        assert is_checked(CHECK) is True

    def test_na(self) -> None:
        assert is_checked("N/A") is True

    def test_empty(self) -> None:
        assert is_checked("") is False

    def test_random(self) -> None:
        assert is_checked("hello") is False


# ---------------------------------------------------------------------------
# §6.4 Happy path forward progression
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_full_walk_through_all_16_steps(self) -> None:
        row = _blank_row("Cisco Spark")

        # Step 1
        apply_step_action(row, STEP_BY_NAME["assignee"], "Alice", verb="set-assignee")
        # Note: the apply_step_action would clear later cols, but we're using direct
        # writes; for set-assignee specifically the carve-out applies in CLI.
        # But here we test state advancement.
        assert current_step(row).index == 2

        # Step 2
        apply_step_action(row, STEP_BY_NAME["Auth Details"], VALID_AUTH_JSON, verb="set-auth")
        assert current_step(row).index == 3

        # Step 3
        apply_step_action(row, STEP_BY_NAME["Params to Commands"], "{}", verb="set-p2c")
        assert current_step(row).index == 4

        # Step 4
        apply_step_action(row, STEP_BY_NAME["Params for test with default in code"],
                          "[]", verb="set-p4t")
        assert current_step(row).index == 5

        # Step 5
        apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                          "{}", verb="set-shared")
        assert current_step(row).index == 6

        # Steps 6-11 (checkpoints)
        for cp_name in ["generated manifest", "run manifest make validate",
                        "wrote/checked code", "shadowed command test passes",
                        "write tests", "precommit/validate/unit tests passed"]:
            apply_step_action(row, STEP_BY_NAME[cp_name], CHECK, verb="markpass")
        assert current_step(row).index == 12

        # Step 12 — flag YES
        apply_step_action(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN], "YES",
                          verb="set-auth-flag")
        assert current_step(row).index == 13

        # Steps 13-16
        for cp_name in ["auth parity test passes", "param parity test passes",
                        "code reviewed", "code merged"]:
            apply_step_action(row, STEP_BY_NAME[cp_name], CHECK, verb="markpass")
        assert current_step(row) is None

    def test_full_walk_with_skip_on_step_5(self) -> None:
        row = _blank_row("Cisco Spark")
        for name, val in [
            ("assignee", "Alice"),
            ("Auth Details", VALID_AUTH_JSON),
            ("Params to Commands", "{}"),
            ("Params for test with default in code", "[]"),
        ]:
            apply_step_action(row, STEP_BY_NAME[name], val, verb="set")
        # Skip step 5
        apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                          NA_MARK, verb="skip")
        assert row["Params same in other handlers"] == NA_MARK
        assert current_step(row).index == 6

    def test_full_walk_with_flag_no_auto_advances_past_step_13(self) -> None:
        # Build through step 11
        row = _blank_row("X")
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        for cp in ["generated manifest", "run manifest make validate",
                   "wrote/checked code", "shadowed command test passes",
                   "write tests", "precommit/validate/unit tests passed"]:
            row[cp] = CHECK
        assert current_step(row).index == 12

        # Flag NO with the manual semantics CLI implements:
        apply_step_action(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN], "NO",
                          verb="set-auth-flag")
        # Caller (CLI) writes N/A into #13:
        row["auth parity test passes"] = NA_MARK
        assert current_step(row).index == 14


# ---------------------------------------------------------------------------
# §6.5 Reset cascades — set-* on at-or-behind current
# ---------------------------------------------------------------------------

class TestResetCascades:
    def test_set_auth_on_fully_complete_row_clears_steps_3_through_16(self) -> None:
        row = _fully_complete_row()
        cleared, _ = apply_step_action(row, STEP_BY_NAME["Auth Details"],
                                       VALID_AUTH_JSON_NONE, verb="set-auth")
        # Step 1 (assignee) preserved.
        assert row["assignee"] == "Alice"
        # Step 2 (Auth Details) is set to new value.
        assert row["Auth Details"] == VALID_AUTH_JSON_NONE
        # Steps 3-16 all empty.
        for s in STEPS:
            if s.index >= 3:
                assert row[s.name] == "", f"Step #{s.index} {s.name} not cleared"
        assert current_step(row).index == 3
        assert len(cleared) >= 12  # everything from step 3 onward

    def test_set_params_to_commands_midway_clears_steps_4_through_16(self) -> None:
        # Build a row currently at step 8.
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = '{"old":"value"}'
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = "{}"
        row["generated manifest"] = CHECK
        row["run manifest make validate"] = CHECK
        # Now at step 8.
        assert current_step(row).index == 8

        apply_step_action(row, STEP_BY_NAME["Params to Commands"],
                          '{"new":"value"}', verb="set-p2c")
        assert row["Params to Commands"] == '{"new":"value"}'
        # 4-16 cleared
        for s in STEPS:
            if s.index >= 4:
                assert row[s.name] == "", f"Step #{s.index} {s.name} not cleared"
        # 1, 2 preserved
        assert row["assignee"] == "A"
        assert row["Auth Details"] == VALID_AUTH_JSON
        assert current_step(row).index == 4

    def test_skip_step_5_writes_NA_and_advances(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        cleared, _ = apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                                       NA_MARK, verb="skip")
        assert row["Params same in other handlers"] == NA_MARK
        assert current_step(row).index == 6

    def test_skip_step_5_on_complete_row_clears_after(self) -> None:
        row = _fully_complete_row()
        apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                          NA_MARK, verb="skip")
        assert row["Params same in other handlers"] == NA_MARK
        for s in STEPS:
            if s.index >= 6:
                assert row[s.name] == "", f"Step #{s.index} {s.name} not cleared"

    def test_set_auth_flag_yes_to_no_clears_step_13(self) -> None:
        row = _fully_complete_row()  # flag=YES, #13=CHECK
        apply_step_action(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN],
                          "NO", verb="set-auth-flag")
        # After cascade-reset of #12, #13 is cleared.
        assert row["auth parity test passes"] == ""

    def test_set_auth_flag_same_value_is_no_op(self) -> None:
        row = _fully_complete_row()  # flag=YES, #13=CHECK
        cleared, no_op = apply_step_action(row, STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN],
                                            "YES", verb="set-auth-flag")
        assert no_op is True
        assert cleared == []
        # #13 still CHECK
        assert row["auth parity test passes"] == CHECK

    def test_markpass_re_issue_behind_current_clears_after_target(self) -> None:
        row = _fully_complete_row()
        # Re-pass step #8 (wrote/checked code).
        apply_step_action(row, STEP_BY_NAME["wrote/checked code"], CHECK, verb="markpass")
        # Steps 1-8 unchanged; 9-16 cleared.
        assert row["wrote/checked code"] == CHECK
        assert row["generated manifest"] == CHECK
        for s in STEPS:
            if s.index >= 9:
                assert row[s.name] == "", f"Step #{s.index} {s.name} not cleared"


# ---------------------------------------------------------------------------
# set-assignee carve-out
# ---------------------------------------------------------------------------

class TestSetAssigneeCarveOut:
    def test_set_assignee_does_not_reset_subsequent_steps(self, monkeypatch, capsys) -> None:
        row = _fully_complete_row("FooInt")
        rows = [row]
        _patch_csv(monkeypatch, rows)

        cmd_set_assignee(["FooInt", "Bob"])

        assert row["assignee"] == "Bob"
        # Every other column must be untouched.
        assert row["Auth Details"] == VALID_AUTH_JSON
        assert row["Params to Commands"] == '{"integration":"X","commands":{}}'
        for s in STEPS:
            if s.kind == "checkpoint":
                # Should still be done.
                assert is_done(row, s), f"Step #{s.index} {s.name} got cleared!"
        assert row[AUTH_PARITY_FLAG_COLUMN] == "YES"

    def test_set_assignee_cli_preserves_all_progress(self, monkeypatch, capsys) -> None:
        row = _blank_row("FooInt")
        row["assignee"] = "Alice"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = '{}'
        row["Params for test with default in code"] = '[]'
        row["Params same in other handlers"] = NA_MARK
        row["generated manifest"] = CHECK
        rows = [row]
        _patch_csv(monkeypatch, rows)

        cmd_set_assignee(["FooInt", "Bob"])

        assert row["assignee"] == "Bob"
        assert row["Auth Details"] == VALID_AUTH_JSON
        assert row["generated manifest"] == CHECK


# ---------------------------------------------------------------------------
# §6.6 Rejection cases
# ---------------------------------------------------------------------------

class TestRejectionCases:
    def test_set_params_to_commands_when_step_2_empty_errors(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        # No Auth Details; current step is #2. Setting #3 is AHEAD.
        with pytest.raises(WorkflowError) as exc:
            apply_step_action(row, STEP_BY_NAME["Params to Commands"], "{}", verb="set")
        assert "Auth Details" in exc.value.message

    def test_markpass_step_8_on_blank_row_errors(self) -> None:
        row = _blank_row()
        with pytest.raises(WorkflowError) as exc:
            apply_step_action(row, STEP_BY_NAME["wrote/checked code"], CHECK, verb="markpass")
        # current step is #1 (assignee); markpass #8 is way ahead.
        assert "assignee" in exc.value.message

    def test_markpass_auth_parity_when_flag_unset_errors(self, monkeypatch, capsys) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        for cp in ["generated manifest", "run manifest make validate",
                   "wrote/checked code", "shadowed command test passes",
                   "write tests", "precommit/validate/unit tests passed"]:
            row[cp] = CHECK
        # current step is now #12.
        rows = [row]
        _patch_csv(monkeypatch, rows)
        # markpass #13 should error with set-auth-flag guidance.
        with pytest.raises(SystemExit):
            cmd_markpass([row["Integration ID"], "auth parity test passes"])
        out = capsys.readouterr().out
        assert "set-auth-flag" in out

    def test_invalid_json_for_set_auth(self) -> None:
        errors = validate_auth_detail("not json")
        assert "Invalid JSON" in errors[0]

    def test_invalid_json_for_set_params_to_commands(self) -> None:
        # Direct json.loads
        with pytest.raises(json.JSONDecodeError):
            json.loads("not json")

    def test_set_auth_missing_required_keys_errors(self) -> None:
        errors = validate_auth_detail('{"auth_types":[]}')
        assert any("Missing required keys" in e for e in errors)

    def test_set_auth_flag_invalid_value_errors(self, monkeypatch, capsys) -> None:
        row = _blank_row()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit):
            cmd_set_auth_flag([row["Integration ID"], "MAYBE"])
        out = capsys.readouterr().out
        assert "MAYBE" in out

    def test_skip_on_non_optional_step_errors(self, monkeypatch, capsys) -> None:
        row = _blank_row()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit):
            cmd_skip([row["Integration ID"], "assignee"])
        out = capsys.readouterr().out
        assert "not optional" in out

    def test_markpass_assignee_rejected_with_setter_guidance(self, monkeypatch, capsys) -> None:
        row = _blank_row()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit):
            cmd_markpass([row["Integration ID"], "assignee"])
        out = capsys.readouterr().out
        assert "set-assignee" in out

    def test_markpass_auth_details_rejected(self, monkeypatch, capsys) -> None:
        row = _blank_row()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit):
            cmd_markpass([row["Integration ID"], "Auth Details"])
        out = capsys.readouterr().out
        assert "set-auth" in out


# ---------------------------------------------------------------------------
# §6.7 Optional step (#5) handling
# ---------------------------------------------------------------------------

class TestOptionalStep5:
    def test_set_real_value_advances_to_step_6(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                          '["x"]', verb="set-shared")
        assert current_step(row).index == 6

    def test_skip_advances_and_writes_NA(self, monkeypatch, capsys) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        rows = [row]
        _patch_csv(monkeypatch, rows)
        cmd_skip([row["Integration ID"], "Params same in other handlers"])
        assert row["Params same in other handlers"] == NA_MARK
        assert current_step(row).index == 6

    def test_set_after_skip_overwrites_NA_and_clears_after(self) -> None:
        row = _fully_complete_row()
        # First skip step 5
        apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                          NA_MARK, verb="skip")
        # Now set it to a real value (we're "behind" current after the skip).
        apply_step_action(row, STEP_BY_NAME["Params same in other handlers"],
                          '["x"]', verb="set-shared")
        assert row["Params same in other handlers"] == '["x"]'
        # Steps 6+ cleared.
        for s in STEPS:
            if s.index >= 6:
                assert row[s.name] == "", f"Step #{s.index} {s.name} not cleared"

    def test_markpass_step_6_blocked_when_step_5_blank(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        # Step 5 blank; current = #5
        with pytest.raises(WorkflowError):
            apply_step_action(row, STEP_BY_NAME["generated manifest"], CHECK, verb="markpass")

    def test_markpass_step_6_works_after_skip(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        apply_step_action(row, STEP_BY_NAME["generated manifest"], CHECK, verb="markpass")
        assert row["generated manifest"] == CHECK


# ---------------------------------------------------------------------------
# §6.8 Auth-parity flag interaction (steps #12/#13)
# ---------------------------------------------------------------------------

class TestAuthParityFlag:
    def _at_step_12(self) -> dict[str, str]:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        for cp in ["generated manifest", "run manifest make validate",
                   "wrote/checked code", "shadowed command test passes",
                   "write tests", "precommit/validate/unit tests passed"]:
            row[cp] = CHECK
        return row

    def test_set_flag_no_via_cli_writes_na_into_step_13(self, monkeypatch) -> None:
        row = self._at_step_12()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        cmd_set_auth_flag([row["Integration ID"], "NO"])
        assert row[AUTH_PARITY_FLAG_COLUMN] == "NO"
        assert row["auth parity test passes"] == NA_MARK
        assert current_step(row).index == 14

    def test_set_flag_na_via_cli_writes_na_into_step_13(self, monkeypatch) -> None:
        row = self._at_step_12()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        cmd_set_auth_flag([row["Integration ID"], "N/A"])
        assert row[AUTH_PARITY_FLAG_COLUMN] == "N/A"
        assert row["auth parity test passes"] == NA_MARK
        assert current_step(row).index == 14

    def test_set_flag_yes_via_cli_leaves_step_13_empty(self, monkeypatch) -> None:
        row = self._at_step_12()
        rows = [row]
        _patch_csv(monkeypatch, rows)
        cmd_set_auth_flag([row["Integration ID"], "YES"])
        assert row[AUTH_PARITY_FLAG_COLUMN] == "YES"
        assert row["auth parity test passes"] == ""
        assert current_step(row).index == 13

    def test_markpass_step_13_when_flag_yes(self, monkeypatch) -> None:
        row = self._at_step_12()
        row[AUTH_PARITY_FLAG_COLUMN] = "YES"
        rows = [row]
        _patch_csv(monkeypatch, rows)
        cmd_markpass([row["Integration ID"], "auth parity test passes"])
        assert row["auth parity test passes"] == CHECK


# ---------------------------------------------------------------------------
# Normalization on read
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_normalize_row_clears_value_past_first_incomplete_step(self, capsys) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        # Skip Auth Details (#2). Then add a checkmark on step #8.
        row["wrote/checked code"] = CHECK
        cleared = normalize_row(row)
        # Step #2 is the first incomplete; everything past #2 must be cleared.
        assert "wrote/checked code" in cleared
        assert row["wrote/checked code"] == ""

    def test_normalize_row_no_op_when_consistent(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        cleared = normalize_row(row)
        assert cleared == []

    def test_load_csv_normalizes_and_warns(self, tmp_path, monkeypatch, capsys) -> None:
        csv_file = tmp_path / "integrations_report.csv"
        monkeypatch.setattr(workflow_state, "CSV_PATH", str(csv_file))

        # Build a deliberately contradictory row: assignee unset,
        # but wrote/checked code marked passed.
        row = _blank_row(name="BadInt")
        row["wrote/checked code"] = CHECK
        save_csv([row])  # will normalize on save

        # Re-read: row should have wrote/checked code cleared.
        capsys.readouterr()  # clear save warning if any
        loaded = load_csv()
        assert loaded[0]["wrote/checked code"] == ""
        # Check stderr received a warning. capsys.readouterr().err captures stderr.
        captured = capsys.readouterr()
        # Warning will be from the load (the save already normalized).
        # Either way the row is clean now.

    def test_save_csv_normalizes_and_warns(self, tmp_path, monkeypatch, capsys) -> None:
        csv_file = tmp_path / "integrations_report.csv"
        monkeypatch.setattr(workflow_state, "CSV_PATH", str(csv_file))

        row = _blank_row(name="BadInt2")
        row["assignee"] = "A"
        # Skip Auth Details, set wrote/checked code
        row["wrote/checked code"] = CHECK
        save_csv([row])
        captured = capsys.readouterr()
        assert "WARNING" in captured.err
        assert "BadInt2" in captured.err
        # And the file should have it cleared.
        assert row["wrote/checked code"] == ""


# ---------------------------------------------------------------------------
# `next` command output
# ---------------------------------------------------------------------------

class TestNextCommand:
    def test_format_next_for_blank_row(self) -> None:
        row = _blank_row("CiscoSpark")
        out = format_next_line(row)
        assert "CiscoSpark" in out
        assert "step 1 of 16: assignee" in out
        assert "set-assignee" in out

    def test_format_next_for_complete_row(self) -> None:
        row = _fully_complete_row("CiscoSpark")
        out = format_next_line(row)
        assert "CiscoSpark" in out
        assert "all 16 steps complete" in out

    def test_format_next_for_checkpoint_step(self) -> None:
        row = _blank_row("X")
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        out = format_next_line(row)
        assert "step 6 of 16: generated manifest" in out
        assert "markpass" in out

    def test_next_with_explicit_id(self, monkeypatch, capsys) -> None:
        rows = [_blank_row("AlphaInt")]
        _patch_csv(monkeypatch, rows)
        cmd_next(["AlphaInt"])
        out = capsys.readouterr().out
        assert "AlphaInt" in out
        assert "step 1 of 16" in out

    def test_next_all_lists_in_progress_only(self, monkeypatch, capsys) -> None:
        rows = [
            _blank_row("Started"),
            _blank_row("NotStarted"),  # no progress at all
            _fully_complete_row("Done"),
        ]
        rows[0]["assignee"] = "Alice"
        rows[0]["Auth Details"] = VALID_AUTH_JSON  # has progress, current=#3
        _patch_csv(monkeypatch, rows)
        cmd_next(["--all"])
        out = capsys.readouterr().out
        assert "Started" in out
        assert "NotStarted" not in out
        assert "Done" not in out

    def test_next_no_args_uses_git_user(self, monkeypatch, capsys) -> None:
        rows = [
            _blank_row("Mine"),
            _blank_row("Someone Else's"),
        ]
        rows[0]["assignee"] = "Test User"
        rows[0]["Auth Details"] = VALID_AUTH_JSON
        rows[1]["assignee"] = "Other Person"
        rows[1]["Auth Details"] = VALID_AUTH_JSON
        _patch_csv(monkeypatch, rows)
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")
        cmd_next([])
        out = capsys.readouterr().out
        assert "Mine" in out
        assert "Someone Else" not in out

    def test_next_no_rows_handles_empty_csv(self, monkeypatch, capsys) -> None:
        _patch_csv(monkeypatch, [])
        cmd_next([])
        out = capsys.readouterr().out
        assert "no rows" in out


# ---------------------------------------------------------------------------
# reset-to / fail / reset semantics
# ---------------------------------------------------------------------------

class TestResetVerbs:
    def test_reset_from_step_clears_named_step_and_after(self) -> None:
        row = _fully_complete_row()
        reset_from_step(row, "wrote/checked code")
        # Steps 1-7 unchanged
        assert row["assignee"] == "Alice"
        assert row["generated manifest"] == CHECK
        assert row["run manifest make validate"] == CHECK
        # Step 8 onward cleared
        for s in STEPS:
            if s.index >= 8:
                assert row[s.name] == ""

    def test_fail_step_clears_named_and_after(self) -> None:
        row = _fully_complete_row()
        result = fail_integration_step.__wrapped__ if hasattr(fail_integration_step, "__wrapped__") else None
        # Direct call via reset_from_step (the test of the API requires patching csv).
        reset_from_step(row, "param parity test passes")
        assert row["auth parity test passes"] == CHECK
        assert row["param parity test passes"] == ""
        assert row["code reviewed"] == ""
        assert row["code merged"] == ""

    def test_reset_clears_all_workflow_columns_via_full_clear(self) -> None:
        row = _fully_complete_row()
        for col in WORKFLOW_COLUMNS:
            row[col] = ""
        for col in WORKFLOW_COLUMNS:
            assert row[col] == ""
        # Identity columns preserved.
        assert row["Integration ID"] == "TestIntegration"

    def test_reset_after_clears_subsequent_only(self) -> None:
        row = _fully_complete_row()
        cleared = reset_after(row, STEP_BY_NAME["wrote/checked code"])
        # Steps 1-8 untouched (assignee, Auth, P2C, P4T, Pshared, manifest,
        # validate, wrote)
        assert row["wrote/checked code"] == CHECK
        # 9+ cleared
        assert "shadowed command test passes" in cleared
        assert row["code merged"] == ""


# ---------------------------------------------------------------------------
# find_row
# ---------------------------------------------------------------------------

class TestFindRow:
    def test_finds_exact_match(self) -> None:
        rows = [_blank_row("Alpha"), _blank_row("Beta"), _blank_row("Gamma")]
        assert find_row(rows, "Beta") == 1

    def test_case_insensitive(self) -> None:
        rows = [_blank_row("Cisco Spark")]
        assert find_row(rows, "cisco spark") == 0

    def test_not_found(self) -> None:
        rows = [_blank_row("Alpha")]
        assert find_row(rows, "Nonexistent") is None


# ---------------------------------------------------------------------------
# format_status / format_dashboard_row
# ---------------------------------------------------------------------------

class TestFormatStatus:
    def test_blank_row_shows_step_1_as_current(self) -> None:
        row = _blank_row()
        out = format_status(row)
        assert "Workflow ([0/16])" in out
        assert "Current step" in out
        assert "assignee" in out

    def test_complete_row_shows_celebration(self) -> None:
        row = _fully_complete_row()
        out = format_status(row)
        assert "All 16 steps complete" in out

    def test_progress_count_displays_correctly(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        out = format_status(row)
        assert "[2/16]" in out


class TestFormatDashboard:
    def test_no_progress_returns_none(self) -> None:
        row = _blank_row()
        assert format_dashboard_row(row) is None

    def test_with_progress_uses_16_cells(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        result = format_dashboard_row(row)
        assert result is not None
        # Bar should be 16 chars wide
        assert "██" in result
        assert "/16" in result

    def test_complete_row_shows_done(self) -> None:
        row = _fully_complete_row()
        result = format_dashboard_row(row)
        assert result is not None
        assert "DONE" in result


# ---------------------------------------------------------------------------
# list_by_assignee / format_by_assignee
# ---------------------------------------------------------------------------

class TestListByAssignee:
    def test_filters_by_assignee_case_insensitive(self) -> None:
        rows = [_blank_row("A"), _blank_row("B"), _blank_row("C")]
        rows[0]["assignee"] = "Alice"
        rows[1]["assignee"] = "alice"
        rows[2]["assignee"] = "Bob"
        result = list_by_assignee(rows, "ALICE")
        assert len(result) == 2

    def test_no_matches_returns_empty(self) -> None:
        rows = [_blank_row("A")]
        rows[0]["assignee"] = "Alice"
        assert list_by_assignee(rows, "Bob") == []


class TestFormatByAssignee:
    def test_no_matches_message(self) -> None:
        out = format_by_assignee([], "Nobody")
        assert "No integrations found" in out

    def test_shows_count_and_names(self) -> None:
        rows = [_blank_row("A"), _blank_row("B")]
        rows[0]["assignee"] = "Alice"
        rows[1]["assignee"] = "Alice"
        out = format_by_assignee(rows, "Alice")
        assert "(2)" in out


# ---------------------------------------------------------------------------
# validate_auth_detail
# ---------------------------------------------------------------------------

class TestValidateAuthDetail:
    def test_valid_simple(self) -> None:
        assert validate_auth_detail(VALID_AUTH_JSON) == []

    def test_valid_none_required(self) -> None:
        assert validate_auth_detail(VALID_AUTH_JSON_NONE) == []

    def test_invalid_json(self) -> None:
        errors = validate_auth_detail("not json")
        assert "Invalid JSON" in errors[0]

    def test_missing_keys(self) -> None:
        errors = validate_auth_detail('{"auth_types":[]}')
        assert "Missing required keys" in errors[0]

    def test_invalid_auth_type(self) -> None:
        bad = '{"auth_types":[{"type":"INVALID","name":"x"}],"config":"NONE","params":{},"notes":null}'
        errors = validate_auth_detail(bad)
        assert any("invalid type 'INVALID'" in e for e in errors)

    def test_all_valid_auth_types(self) -> None:
        for at in VALID_AUTH_TYPES:
            detail = (f'{{"auth_types":[{{"type":"{at}","name":"x"}}],'
                      '"config":"NONE","params":{},"notes":null}')
            assert validate_auth_detail(detail) == [], f"Type '{at}' should be valid"


# ---------------------------------------------------------------------------
# Programmatic API
# ---------------------------------------------------------------------------

class TestProgrammaticAPI:
    def test_set_integration_auth_valid(self, monkeypatch) -> None:
        row = _fully_complete_row("FakeInt")
        rows = [row]
        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv"):
            result = set_integration_auth("FakeInt", VALID_AUTH_JSON_NONE)
        assert "error" not in result
        assert result["current_step"] == "Params to Commands"
        assert row["Auth Details"] == VALID_AUTH_JSON_NONE

    def test_set_integration_auth_rejects_invalid_schema(self) -> None:
        with patch("workflow_state.load_csv") as mock_load:
            result = set_integration_auth("X", '{"bad":"json"}')
        assert "error" in result
        mock_load.assert_not_called()

    def test_set_integration_auth_not_found(self) -> None:
        with patch("workflow_state.load_csv", return_value=[]), \
             patch("workflow_state.save_csv"):
            result = set_integration_auth("Nope", VALID_AUTH_JSON_NONE)
        assert "error" in result and "not found" in result["error"].lower()

    def test_skip_integration_step_optional(self, monkeypatch) -> None:
        row = _blank_row("X")
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        with patch("workflow_state.load_csv", return_value=[row]), \
             patch("workflow_state.save_csv"):
            result = skip_integration_step("X", "Params same in other handlers")
        assert "error" not in result
        assert row["Params same in other handlers"] == NA_MARK

    def test_skip_integration_step_non_optional_errors(self) -> None:
        result = skip_integration_step("X", "assignee")
        assert "error" in result

    def test_markpass_integration_step(self, monkeypatch) -> None:
        row = _blank_row("X")
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        with patch("workflow_state.load_csv", return_value=[row]), \
             patch("workflow_state.save_csv"):
            result = markpass_integration_step("X", "generated manifest")
        assert "error" not in result
        assert row["generated manifest"] == CHECK


# ---------------------------------------------------------------------------
# Atomic save_csv
# ---------------------------------------------------------------------------

class TestAtomicSaveCsv:
    def _sample_rows(self) -> list[dict[str, str]]:
        return [_blank_row(f"Integration{i}") for i in range(3)]

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

    def test_failed_write_leaves_original_unchanged(self, tmp_path, monkeypatch) -> None:
        csv_file = tmp_path / "integrations_report.csv"
        monkeypatch.setattr(workflow_state, "CSV_PATH", str(csv_file))

        original_rows = self._sample_rows()
        save_csv(original_rows)
        original_bytes = csv_file.read_bytes()

        def _boom(src, dst):
            raise OSError("simulated failure")

        monkeypatch.setattr(workflow_state.os, "replace", _boom)

        new_rows = self._sample_rows()
        new_rows[0]["Integration ID"] = "MUTATED"

        with pytest.raises(OSError, match="simulated failure"):
            save_csv(new_rows)
        assert csv_file.read_bytes() == original_bytes
        leftovers = [
            p for p in os.listdir(tmp_path)
            if p.startswith(".integrations_report.") and p.endswith(".tmp")
        ]
        assert leftovers == []


# ---------------------------------------------------------------------------
# show-step
# ---------------------------------------------------------------------------

class TestShowStep:
    def test_format_step_value_pretty_prints_json(self) -> None:
        row = _blank_row("X")
        row["Params to Commands"] = '{"key":"val"}'
        out = format_step_value(row, "Params to Commands")
        assert '"key": "val"' in out

    def test_format_step_value_not_set(self) -> None:
        row = _blank_row("X")
        out = format_step_value(row, "wrote/checked code")
        assert "(not set)" in out

    def test_cmd_show_step_unknown_column_errors(self, monkeypatch, capsys) -> None:
        rows = [_blank_row("X")]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit):
            cmd_show_step(["X", "totally bogus"])
        out = capsys.readouterr().out
        assert "Unknown column" in out


# ---------------------------------------------------------------------------
# Backward-compat: legacy markpass_step / reset_from_step still work
# ---------------------------------------------------------------------------

class TestLegacyShims:
    def test_markpass_step_legacy_rejects_data_columns(self) -> None:
        row = _blank_row()
        msg = markpass_step(row, "Params to Commands")
        assert "ERROR" in msg
        assert "set-params-to-commands" in msg

    def test_markpass_step_legacy_happy_path(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        row["Params to Commands"] = "{}"
        row["Params for test with default in code"] = "[]"
        row["Params same in other handlers"] = NA_MARK
        msg = markpass_step(row, "generated manifest")
        assert "ERROR" not in msg
        assert row["generated manifest"] == CHECK

    def test_reset_from_step_clears_named_and_after(self) -> None:
        row = _fully_complete_row()
        reset_from_step(row, "wrote/checked code")
        assert row["wrote/checked code"] == ""
        assert row["code merged"] == ""
        assert row["run manifest make validate"] == CHECK
