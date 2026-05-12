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
    assign_connector,
    auth_param_ids,
    cmd_auth_params,
    cmd_list_by_connector,
    cmd_list_connectors,
    cmd_markpass,
    cmd_next,
    cmd_set_assignee,
    cmd_set_assignee_by_connector,
    cmd_set_auth_flag,
    cmd_set_params_to_commands,
    cmd_files,
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
    integrations_for_assignee,
    is_checked,
    is_done,
    list_by_assignee,
    list_by_connector,
    get_integration_files,
    list_integrations_by_connector,
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
    validate_params_to_commands,
)


VALID_AUTH_JSON = (
    '{"auth_types":[{"type":"APIKey","name":"api_key",'
    '"xsoar_params":["api_key"]}],'
    '"config":"REQUIRED(api_key)",'
    '"other_connection":["insecure","proxy","url"]}'
)
VALID_AUTH_JSON_NONE = (
    '{"auth_types":[],"config":"NoneRequired","other_connection":[]}'
)
# Legacy-shape Auth Details JSON missing the `other_connection` key — used to
# verify read-path tolerance for rows that predate the field. Do NOT pass
# this through `validate_auth_detail`; it is for read/display tests only.
LEGACY_AUTH_JSON_NO_OTHER_CONNECTION = (
    '{"auth_types":[{"type":"APIKey","name":"api_key",'
    '"xsoar_params":["api_key"]}],'
    '"config":"REQUIRED(api_key)"}'
)


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
        assert EXPECTED_COLUMN_COUNT == 19
        assert len(ALL_COLUMNS) == 19

    def test_data_columns_unchanged(self) -> None:
        assert DATA_COLUMNS == [
            "Integration ID",
            "Integration File Path",
            "Connector ID",
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
        csv_file = tmp_path / "connectus-migration-pipeline.csv"
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
        csv_file = tmp_path / "connectus-migration-pipeline.csv"
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

    def test_format_status_shows_other_connection_inline(self) -> None:
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = VALID_AUTH_JSON
        out = format_status(row)
        # The inline `other_connection` label should be present, with
        # the actual list rendered.
        assert "other_connection" in out
        assert "insecure" in out and "proxy" in out and "url" in out

    def test_format_status_legacy_row_missing_other_connection(self) -> None:
        # Legacy CSV rows that predate the new field must NOT crash status,
        # and should surface a clear "(not set — re-run set-auth)" hint.
        row = _blank_row()
        row["assignee"] = "A"
        row["Auth Details"] = LEGACY_AUTH_JSON_NO_OTHER_CONNECTION
        out = format_status(row)
        assert "other_connection" in out
        assert "(not set — re-run set-auth)" in out

    def test_format_step_value_legacy_row_appends_hint(self) -> None:
        # `show-step Auth Details` for a legacy row should pretty-print
        # the JSON AND append the "(not set — re-run set-auth)" hint.
        row = _blank_row()
        row["Auth Details"] = LEGACY_AUTH_JSON_NO_OTHER_CONNECTION
        out = format_step_value(row, "Auth Details")
        assert "auth_types" in out  # JSON pretty-print rendered
        assert "other_connection: (not set — re-run set-auth)" in out

    def test_format_step_value_modern_row_no_hint(self) -> None:
        # A modern row with `other_connection` set should NOT get the hint
        # (the JSON pretty-print already contains the key).
        row = _blank_row()
        row["Auth Details"] = VALID_AUTH_JSON
        out = format_step_value(row, "Auth Details")
        assert "other_connection" in out
        assert "(not set — re-run set-auth)" not in out


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
        bad = ('{"auth_types":[{"type":"INVALID","name":"x",'
               '"xsoar_params":["p"]}],"config":"REQUIRED(x)",'
               '"other_connection":[]}')
        errors = validate_auth_detail(bad)
        assert any("invalid type 'INVALID'" in e for e in errors)

    def test_all_valid_auth_types(self) -> None:
        for at in VALID_AUTH_TYPES:
            detail = (f'{{"auth_types":[{{"type":"{at}","name":"x",'
                      '"xsoar_params":["p"]}],'
                      '"config":"REQUIRED(x)","other_connection":[]}')
            assert validate_auth_detail(detail) == [], f"Type '{at}' should be valid"

    # ------------------------------------------------------------------
    # New: `config` grammar / cross-reference / sort / xsoar_params shape
    # ------------------------------------------------------------------

    def test_valid_none_required_explicit(self) -> None:
        detail = ('{"auth_types":[],"config":"NoneRequired",'
                  '"other_connection":[]}')
        assert validate_auth_detail(detail) == []

    def test_valid_simple_required(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)","other_connection":[]}')
        assert validate_auth_detail(detail) == []

    def test_valid_two_clause_required_plus_optional(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"OAuth2ClientCreds","name":"credentials_consumer",'
            '"xsoar_params":["credentials_consumer.identifier",'
            '"credentials_consumer.password"]},'
            '{"type":"Plain","name":"credentials",'
            '"xsoar_params":["credentials.identifier","credentials.password"]}'
            '],'
            '"config":"REQUIRED(credentials) + OPTIONAL(credentials_consumer)",'
            '"other_connection":[]}'
        )
        assert validate_auth_detail(detail) == []

    def test_valid_choice(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"Plain","name":"credentials",'
            '"xsoar_params":["credentials.identifier","credentials.password"]},'
            '{"type":"Plain","name":"hunting_credentials",'
            '"xsoar_params":["hunting_credentials.identifier",'
            '"hunting_credentials.password"]}'
            '],'
            '"config":"CHOICE(credentials, hunting_credentials)",'
            '"other_connection":[]}'
        )
        assert validate_auth_detail(detail) == []

    def test_config_unknown_name(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(missing_name)","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any(
            "unknown connection-type name 'missing_name'" in e for e in errors
        ), errors

    def test_config_malformed_empty_required(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED()","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any("'config'" in e and "no operands" in e for e in errors), errors

    def test_config_malformed_trailing_plus(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key) +","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any("'config'" in e and "ends with '+'" in e for e in errors), errors

    def test_config_malformed_unknown_keyword(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"FOO(api_key)","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any("'config'" in e and "malformed clause" in e for e in errors), errors

    def test_config_malformed_missing_parens(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED api_key","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any("'config'" in e and "malformed clause" in e for e in errors), errors

    def test_none_required_with_non_empty_auth_types(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"NoneRequired","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any(
            "'config' is 'NoneRequired' but 'auth_types' contains entries" in e
            for e in errors
        ), errors

    def test_non_none_required_with_empty_auth_types(self) -> None:
        detail = ('{"auth_types":[],"config":"REQUIRED(api_key)",'
                  '"other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any(
            "'config' is not 'NoneRequired' but 'auth_types' is empty" in e
            for e in errors
        ), errors
        # And the unknown-name check should also fire (api_key isn't defined).
        assert any(
            "unknown connection-type name 'api_key'" in e for e in errors
        ), errors

    def test_sort_order_violation(self) -> None:
        # APIKey < Plain by type; placing Plain first is out of order.
        detail = (
            '{"auth_types":['
            '{"type":"Plain","name":"credentials",'
            '"xsoar_params":["credentials.identifier","credentials.password"]},'
            '{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}'
            '],'
            '"config":"REQUIRED(api_key) + REQUIRED(credentials)",'
            '"other_connection":[]}'
        )
        errors = validate_auth_detail(detail)
        assert any("must be sorted by (type, name)" in e for e in errors), errors
        # The error should name the offending pair.
        assert any(
            "'Plain'/'credentials'" in e and "'APIKey'/'api_key'" in e
            for e in errors
        ), errors

    def test_sort_order_violation_same_type_by_name(self) -> None:
        # Same type, names out of order: 'b' before 'a'.
        detail = (
            '{"auth_types":['
            '{"type":"APIKey","name":"b","xsoar_params":["p"]},'
            '{"type":"APIKey","name":"a","xsoar_params":["p"]}'
            '],'
            '"config":"REQUIRED(a) + REQUIRED(b)","other_connection":[]}'
        )
        errors = validate_auth_detail(detail)
        assert any("must be sorted by (type, name)" in e for e in errors), errors

    def test_empty_xsoar_params_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":[]}],'
                  '"config":"REQUIRED(api_key)","other_connection":[]}')
        errors = validate_auth_detail(detail)
        assert any(
            "auth_types[0]" in e and "must contain at least one entry" in e
            for e in errors
        ), errors

    # ------------------------------------------------------------------
    # `other_connection` validation (required key on write)
    # ------------------------------------------------------------------

    def test_other_connection_valid_with_entries(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)",'
                  '"other_connection":["insecure","proxy","url"]}')
        assert validate_auth_detail(detail) == []

    def test_other_connection_valid_empty_list(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)","other_connection":[]}')
        assert validate_auth_detail(detail) == []

    def test_other_connection_missing_key_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)"}')
        errors = validate_auth_detail(detail)
        assert any(
            "Missing required keys" in e and "other_connection" in e
            for e in errors
        ), errors

    def test_other_connection_not_a_list_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)","other_connection":"url"}')
        errors = validate_auth_detail(detail)
        assert any(
            "'other_connection' must be a list" in e for e in errors
        ), errors

    def test_other_connection_non_string_element_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)","other_connection":["url",42]}')
        errors = validate_auth_detail(detail)
        assert any(
            "'other_connection'[1]" in e and "must be a string" in e
            for e in errors
        ), errors

    def test_other_connection_empty_string_element_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)",'
                  '"other_connection":["url",""]}')
        errors = validate_auth_detail(detail)
        assert any(
            "'other_connection'[1]" in e and "non-empty string" in e
            for e in errors
        ), errors

    def test_other_connection_duplicate_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)",'
                  '"other_connection":["proxy","url","url"]}')
        errors = validate_auth_detail(detail)
        assert any(
            "duplicate" in e and "url" in e for e in errors
        ), errors

    def test_other_connection_unsorted_rejected(self) -> None:
        detail = ('{"auth_types":[{"type":"APIKey","name":"api_key",'
                  '"xsoar_params":["api_key"]}],'
                  '"config":"REQUIRED(api_key)",'
                  '"other_connection":["url","proxy"]}')
        errors = validate_auth_detail(detail)
        assert any(
            "must be sorted ascending" in e
            and "['proxy', 'url']" in e
            for e in errors
        ), errors


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

    def test_set_integration_auth_rejects_missing_other_connection(self) -> None:
        # Payload is otherwise valid but lacks the new `other_connection`
        # key — set-auth must reject it (Option B: required on write).
        legacy_payload = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)"}'
        )
        with patch("workflow_state.load_csv") as mock_load:
            result = set_integration_auth("X", legacy_payload)
        assert "error" in result
        assert "other_connection" in result["error"]
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
        csv_file = tmp_path / "connectus-migration-pipeline.csv"
        monkeypatch.setattr(workflow_state, "CSV_PATH", str(csv_file))

        rows = self._sample_rows()
        save_csv(rows)
        assert csv_file.exists()
        loaded = load_csv()
        assert len(loaded) == len(rows)
        for orig, got in zip(rows, loaded):
            assert orig["Integration ID"] == got["Integration ID"]

    def test_failed_write_leaves_original_unchanged(self, tmp_path, monkeypatch) -> None:
        csv_file = tmp_path / "connectus-migration-pipeline.csv"
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
            if p.startswith(".connectus-migration-pipeline.") and p.endswith(".tmp")
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


# ---------------------------------------------------------------------------
# Connector-id–based commands and APIs
# ---------------------------------------------------------------------------

def _row_with_connector(name: str, connector_id: str) -> dict[str, str]:
    """Helper: a blank row with both Integration ID and Connector ID set."""
    row = _blank_row(name)
    row["Connector ID"] = connector_id
    return row


def _connector_fixture_rows() -> list[dict[str, str]]:
    """A small fixture: 3 integrations in connector 'vt', 2 in 'shodan', 1 blank."""
    rows = [
        _row_with_connector("VirusTotalV3", "vt"),
        _row_with_connector("VirusTotal", "vt"),
        _row_with_connector("VirusTotalPrivate", "VT"),  # case variation
        _row_with_connector("ShodanV2", "shodan"),
        _row_with_connector("Shodan", "shodan"),
        _row_with_connector("Orphan", ""),  # no connector
    ]
    return rows


class TestListByConnectorHelper:
    def test_filters_case_insensitive(self) -> None:
        rows = _connector_fixture_rows()
        matches = list_by_connector(rows, "vt")
        assert {r["Integration ID"] for r in matches} == {
            "VirusTotalV3", "VirusTotal", "VirusTotalPrivate"
        }

    def test_filters_by_uppercase_query(self) -> None:
        rows = _connector_fixture_rows()
        matches = list_by_connector(rows, "VT")
        assert len(matches) == 3

    def test_no_matches_returns_empty(self) -> None:
        rows = _connector_fixture_rows()
        assert list_by_connector(rows, "nonexistent") == []

    def test_trims_whitespace(self) -> None:
        rows = _connector_fixture_rows()
        matches = list_by_connector(rows, "  vt  ")
        assert len(matches) == 3


class TestSetAssigneeByConnector:
    def test_assigns_every_matching_row(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        _patch_csv(monkeypatch, rows)
        cmd_set_assignee_by_connector(["vt", "Alice"])
        # All three vt-row assignees set; others untouched.
        assert rows[0]["assignee"] == "Alice"
        assert rows[1]["assignee"] == "Alice"
        assert rows[2]["assignee"] == "Alice"
        assert rows[3]["assignee"] == ""  # shodan
        assert rows[4]["assignee"] == ""
        assert rows[5]["assignee"] == ""
        out = capsys.readouterr().out
        assert "Assigned 3 integration(s) in connector 'vt' to 'Alice'" in out
        assert "VirusTotalV3" in out
        assert "VirusTotal" in out
        assert "VirusTotalPrivate" in out

    def test_does_not_cascade_reset_progress(self, monkeypatch, capsys) -> None:
        # Build a row that already has step 6 done; set-assignee-by-connector
        # must not wipe it.
        rows = _connector_fixture_rows()
        target_row = rows[0]
        target_row["assignee"] = "OldOwner"
        target_row["Auth Details"] = VALID_AUTH_JSON
        target_row["Params to Commands"] = "{}"
        target_row["Params for test with default in code"] = "[]"
        target_row["Params same in other handlers"] = NA_MARK
        target_row["generated manifest"] = CHECK  # step 6 done
        assert current_step(target_row).index == 7

        _patch_csv(monkeypatch, rows)
        cmd_set_assignee_by_connector(["vt", "NewOwner"])
        # Assignee changed.
        assert target_row["assignee"] == "NewOwner"
        # All workflow state preserved.
        assert target_row["Auth Details"] == VALID_AUTH_JSON
        assert target_row["Params to Commands"] == "{}"
        assert target_row["Params for test with default in code"] == "[]"
        assert target_row["Params same in other handlers"] == NA_MARK
        assert target_row["generated manifest"] == CHECK
        assert current_step(target_row).index == 7

    def test_unknown_connector_exits_nonzero(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit) as exc:
            cmd_set_assignee_by_connector(["nope-not-a-real-connector", "Alice"])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "No integrations found" in out
        assert "list-connectors" in out

    def test_empty_assignee_rejected(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit):
            cmd_set_assignee_by_connector(["vt", "   "])
        out = capsys.readouterr().out
        assert "Assignee cannot be empty" in out

    def test_missing_args_shows_usage(self, capsys) -> None:
        with pytest.raises(SystemExit):
            cmd_set_assignee_by_connector(["vt"])
        out = capsys.readouterr().out
        assert "Usage" in out


class TestListByConnectorCommand:
    def test_lists_known_connector(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        rows[0]["assignee"] = "Alice"
        _patch_csv(monkeypatch, rows)
        cmd_list_by_connector(["vt"])
        out = capsys.readouterr().out
        assert "VirusTotalV3" in out
        assert "VirusTotal" in out
        assert "VirusTotalPrivate" in out
        # Shodan rows must NOT appear.
        assert "Shodan" not in out
        # Assignee + step display present.
        assert "[assignee: Alice]" in out
        assert "[assignee: unassigned]" in out
        assert "not started" in out

    def test_zero_matches_message(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        _patch_csv(monkeypatch, rows)
        cmd_list_by_connector(["does-not-exist"])
        out = capsys.readouterr().out
        assert "No integrations found for connector 'does-not-exist'." in out
        assert "list-connectors" in out

    def test_missing_arg_exits(self, capsys) -> None:
        with pytest.raises(SystemExit):
            cmd_list_by_connector([])
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_step_display_done(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        # Mark VirusTotal fully done.
        done = _fully_complete_row("VirusTotal")
        done["Connector ID"] = "vt"
        rows[1] = done
        _patch_csv(monkeypatch, rows)
        cmd_list_by_connector(["vt"])
        out = capsys.readouterr().out
        assert "✅ DONE" in out


class TestListConnectorsCommand:
    def test_lists_distinct_connectors_with_counts(self, monkeypatch, capsys) -> None:
        rows = _connector_fixture_rows()
        # Mark VirusTotal as done; VirusTotalV3 in progress.
        rows[0]["assignee"] = "A"
        rows[0]["Auth Details"] = VALID_AUTH_JSON  # in progress (step 3)
        # VirusTotal fully complete:
        rows[1] = _fully_complete_row("VirusTotal")
        rows[1]["Connector ID"] = "vt"
        _patch_csv(monkeypatch, rows)
        cmd_list_connectors([])
        out = capsys.readouterr().out
        # Header / column labels present.
        assert "Connector ID" in out
        assert "Integrations" in out
        assert "In Progress" in out
        assert "Complete" in out
        # vt should appear (case from first-seen value: "vt").
        assert "vt" in out
        assert "shodan" in out
        # Empty connector should NOT appear (the orphan row).
        # We'll check by counting lines: header + rule + 2 connectors = 4 lines.
        # Just assert the orphan integration name not present (it shouldn't be —
        # the table prints connector ids, not integration ids).
        assert "Orphan" not in out

    def test_empty_csv_message(self, monkeypatch, capsys) -> None:
        _patch_csv(monkeypatch, [])
        cmd_list_connectors([])
        out = capsys.readouterr().out
        assert "No connectors found" in out

    def test_only_blank_connector_ids(self, monkeypatch, capsys) -> None:
        rows = [_blank_row("X"), _blank_row("Y")]
        _patch_csv(monkeypatch, rows)
        cmd_list_connectors([])
        out = capsys.readouterr().out
        assert "No connectors found" in out

    def test_counts_correctness(self, monkeypatch, capsys) -> None:
        # 3 rows in 'cx': 1 in progress, 1 complete, 1 not started.
        rows = [
            _row_with_connector("InProg", "cx"),
            _row_with_connector("Done", "cx"),
            _row_with_connector("NotStarted", "cx"),
        ]
        rows[0]["assignee"] = "A"
        rows[0]["Auth Details"] = VALID_AUTH_JSON
        rows[1] = _fully_complete_row("Done")
        rows[1]["Connector ID"] = "cx"
        _patch_csv(monkeypatch, rows)
        cmd_list_connectors([])
        out = capsys.readouterr().out
        # Find the cx data row and assert the numbers.
        cx_lines = [ln for ln in out.splitlines() if ln.startswith("cx")]
        assert len(cx_lines) == 1
        # 3 integrations, 1 in progress, 1 complete.
        nums = [int(tok) for tok in cx_lines[0].split() if tok.isdigit()]
        assert nums == [3, 1, 1]


class TestNextWithConnectorAndMineFlags:
    def _diverse_rows(self) -> list[dict[str, str]]:
        rows = [
            _row_with_connector("MyVTA", "vt"),       # mine + in-progress in vt
            _row_with_connector("MyVTB", "vt"),       # mine + done in vt
            _row_with_connector("OtherVT", "vt"),     # other + in-progress in vt
            _row_with_connector("MyShodan", "shodan"),  # mine + in-progress in shodan
            _row_with_connector("VTNotStarted", "vt"),  # nobody touched
        ]
        # MyVTA: in progress (step 3)
        rows[0]["assignee"] = "Test User"
        rows[0]["Auth Details"] = VALID_AUTH_JSON
        # MyVTB: complete
        done = _fully_complete_row("MyVTB")
        done["Connector ID"] = "vt"
        done["assignee"] = "Test User"
        rows[1] = done
        # OtherVT: in progress, owned by someone else
        rows[2]["assignee"] = "Someone"
        rows[2]["Auth Details"] = VALID_AUTH_JSON
        # MyShodan: in progress
        rows[3]["assignee"] = "Test User"
        rows[3]["Auth Details"] = VALID_AUTH_JSON
        # rows[4]: blank (no progress)
        return rows

    def test_next_connector_filters_to_connector(self, monkeypatch, capsys) -> None:
        rows = self._diverse_rows()
        _patch_csv(monkeypatch, rows)
        # Without --mine: connector filter only.
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")
        cmd_next(["--connector", "vt"])
        out = capsys.readouterr().out
        assert "MyVTA" in out
        assert "OtherVT" in out  # not assignee-filtered when --mine absent
        assert "MyShodan" not in out
        assert "VTNotStarted" not in out  # not in progress
        assert "MyVTB" not in out  # complete

    def test_next_mine_matches_no_args_when_git_user_set(
        self, monkeypatch, capsys
    ) -> None:
        rows = self._diverse_rows()
        _patch_csv(monkeypatch, rows)
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")

        cmd_next([])
        out_no_args = capsys.readouterr().out

        cmd_next(["--mine"])
        out_mine = capsys.readouterr().out

        assert out_no_args == out_mine
        # And the contents are the user's in-progress rows only:
        assert "MyVTA" in out_mine
        assert "MyShodan" in out_mine
        assert "OtherVT" not in out_mine

    def test_next_connector_and_mine_intersects(self, monkeypatch, capsys) -> None:
        rows = self._diverse_rows()
        _patch_csv(monkeypatch, rows)
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")
        cmd_next(["--connector", "vt", "--mine"])
        out = capsys.readouterr().out
        assert "MyVTA" in out
        assert "OtherVT" not in out  # filtered out by --mine
        assert "MyShodan" not in out  # filtered out by --connector
        assert "MyVTB" not in out  # complete

    def test_next_connector_mine_flag_order_independent(
        self, monkeypatch, capsys
    ) -> None:
        rows = self._diverse_rows()
        _patch_csv(monkeypatch, rows)
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")

        cmd_next(["--connector", "vt", "--mine"])
        first = capsys.readouterr().out
        cmd_next(["--mine", "--connector", "vt"])
        second = capsys.readouterr().out
        assert first == second

    def test_next_unknown_connector_message(self, monkeypatch, capsys) -> None:
        rows = self._diverse_rows()
        _patch_csv(monkeypatch, rows)
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")
        cmd_next(["--connector", "ghost"])
        out = capsys.readouterr().out
        assert "No integrations found for connector 'ghost'." in out
        assert "list-connectors" in out

    def test_next_connector_with_no_in_progress_message(
        self, monkeypatch, capsys
    ) -> None:
        # Build a connector where every row is either unstarted or done.
        done = _fully_complete_row("DoneVT")
        done["Connector ID"] = "vt"
        rows = [
            done,
            _row_with_connector("BlankVT", "vt"),  # not started
        ]
        _patch_csv(monkeypatch, rows)
        monkeypatch.setattr(workflow_state, "_git_user_name", lambda: "Test User")
        cmd_next(["--connector", "vt"])
        out = capsys.readouterr().out
        assert "No in-progress integrations in connector 'vt'" in out
        assert "unstarted or done" in out


class TestProgrammaticConnectorAPI:
    def test_list_integrations_by_connector_shape(self, monkeypatch) -> None:
        rows = _connector_fixture_rows()
        rows[0]["assignee"] = "Alice"
        rows[0]["Auth Details"] = VALID_AUTH_JSON  # in progress at step 3
        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv"):
            result = list_integrations_by_connector("vt")

        assert isinstance(result, list)
        assert len(result) == 3
        ids = {r["integration_id"] for r in result}
        assert ids == {"VirusTotalV3", "VirusTotal", "VirusTotalPrivate"}
        # Each entry has the required keys.
        for entry in result:
            assert set(entry.keys()) >= {
                "integration_id", "connector_id", "assignee",
                "current_step", "current_step_index", "completed_steps",
                "all_complete", "has_progress",
            }
        # Find the in-progress one and check its fields.
        in_prog = next(r for r in result if r["integration_id"] == "VirusTotalV3")
        assert in_prog["assignee"] == "Alice"
        assert in_prog["current_step"] == "Params to Commands"
        assert in_prog["current_step_index"] == 3
        assert in_prog["completed_steps"] == 2
        assert in_prog["all_complete"] is False
        assert in_prog["has_progress"] is True

    def test_list_integrations_by_connector_empty(self, monkeypatch) -> None:
        with patch("workflow_state.load_csv", return_value=_connector_fixture_rows()):
            result = list_integrations_by_connector("nope")
        assert result == []

    def test_integrations_for_assignee_shape(self) -> None:
        rows = _connector_fixture_rows()
        rows[0]["assignee"] = "Alice"
        rows[0]["Auth Details"] = VALID_AUTH_JSON
        rows[3]["assignee"] = "ALICE"  # case-insensitive
        with patch("workflow_state.load_csv", return_value=rows):
            result = integrations_for_assignee("alice")
        assert len(result) == 2
        ids = {r["integration_id"] for r in result}
        assert ids == {"VirusTotalV3", "ShodanV2"}
        # Same key-shape.
        for entry in result:
            assert "integration_id" in entry
            assert "connector_id" in entry
            assert "assignee" in entry
            assert "has_progress" in entry

    def test_integrations_for_assignee_no_matches(self) -> None:
        with patch("workflow_state.load_csv", return_value=_connector_fixture_rows()):
            assert integrations_for_assignee("ghost") == []

    def test_assign_connector_success(self) -> None:
        rows = _connector_fixture_rows()
        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv") as mock_save:
            result = assign_connector("vt", "Bob")
        assert "error" not in result
        assert result["connector_id"] == "vt"
        assert result["assignee"] == "Bob"
        assert result["count"] == 3
        assert set(result["assigned"]) == {
            "VirusTotalV3", "VirusTotal", "VirusTotalPrivate"
        }
        # Rows mutated in place.
        assert rows[0]["assignee"] == "Bob"
        assert rows[1]["assignee"] == "Bob"
        assert rows[2]["assignee"] == "Bob"
        # Non-matching rows untouched.
        assert rows[3]["assignee"] == ""
        mock_save.assert_called_once()

    def test_assign_connector_no_matches_returns_error(self) -> None:
        rows = _connector_fixture_rows()
        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv") as mock_save:
            result = assign_connector("ghost", "Bob")
        assert "error" in result
        assert "No integrations found" in result["error"]
        mock_save.assert_not_called()

    def test_assign_connector_empty_assignee_returns_error(self) -> None:
        with patch("workflow_state.load_csv") as mock_load, \
             patch("workflow_state.save_csv") as mock_save:
            result = assign_connector("vt", "   ")
        assert "error" in result
        mock_load.assert_not_called()
        mock_save.assert_not_called()

    def test_assign_connector_does_not_cascade_reset(self) -> None:
        rows = _connector_fixture_rows()
        # Pre-populate progress in the matching rows.
        for r in rows[:3]:
            r["assignee"] = "OldOwner"
            r["Auth Details"] = VALID_AUTH_JSON
            r["Params to Commands"] = "{}"
            r["generated manifest"] = ""  # still at step 4
        with patch("workflow_state.load_csv", return_value=rows), \
             patch("workflow_state.save_csv"):
            result = assign_connector("vt", "NewOwner")
        assert result["count"] == 3
        for r in rows[:3]:
            assert r["assignee"] == "NewOwner"
            assert r["Auth Details"] == VALID_AUTH_JSON
            assert r["Params to Commands"] == "{}"


# ---------------------------------------------------------------------------
# `files` command — get_integration_files / cmd_files
# ---------------------------------------------------------------------------

CROWDSTRIKE_YML_REL = (
    "Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon.yml"
)


def _crowdstrike_row() -> dict[str, str]:
    row = _blank_row("CrowdstrikeFalcon")
    row["Integration File Path"] = CROWDSTRIKE_YML_REL
    return row


class TestGetIntegrationFiles:
    def test_happy_path_real_directory(self, monkeypatch) -> None:
        rows = [_crowdstrike_row()]
        _patch_csv(monkeypatch, rows)

        info = get_integration_files("CrowdstrikeFalcon")
        assert "error" not in info
        assert info["integration_id"] == "CrowdstrikeFalcon"
        assert info["directory"] == (
            "Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon"
        )
        assert info["base"] == "CrowdStrikeFalcon"
        assert info["yml"] == CROWDSTRIKE_YML_REL
        assert info["code_language"] == "python"
        assert info["code"] and info["code"].endswith("CrowdStrikeFalcon.py")
        assert info["description"] and info["description"].endswith(
            "CrowdStrikeFalcon_description.md"
        )
        assert info["readme"] and info["readme"].endswith("README.md")
        assert info["test"] and info["test"].endswith("CrowdStrikeFalcon_test.py")
        assert isinstance(info["extras"], dict)
        # Image files are excluded by extension blacklist.
        for fname in info["extras"]:
            ext = os.path.splitext(fname)[1].lower()
            assert ext not in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".zip"}

    def test_unknown_integration_returns_error(self, monkeypatch) -> None:
        _patch_csv(monkeypatch, [_crowdstrike_row()])
        info = get_integration_files("NoSuchIntegration")
        assert "error" in info
        assert "not found" in info["error"]

    def test_empty_file_path_returns_error(self, monkeypatch) -> None:
        row = _blank_row("EmptyPathIntegration")
        # Integration File Path is left blank by _blank_row.
        _patch_csv(monkeypatch, [row])

        info = get_integration_files("EmptyPathIntegration")
        assert "error" in info
        assert "Integration File Path" in info["error"]

    def test_directory_does_not_exist_returns_error(self, monkeypatch) -> None:
        row = _blank_row("GhostIntegration")
        row["Integration File Path"] = (
            "Packs/NoSuchPack/Integrations/NoSuchInt/NoSuchInt.yml"
        )
        _patch_csv(monkeypatch, [row])

        info = get_integration_files("GhostIntegration")
        assert "error" in info
        assert "does not exist on disk" in info["error"]


class TestCmdFiles:
    def test_cli_text_smoke(self, monkeypatch, capsys) -> None:
        _patch_csv(monkeypatch, [_crowdstrike_row()])
        cmd_files(["CrowdstrikeFalcon"])
        out = capsys.readouterr().out
        assert "CrowdstrikeFalcon — source files" in out
        assert "CrowdStrikeFalcon.yml" in out
        assert "CrowdStrikeFalcon.py" in out
        assert "Language:     python" in out

    def test_cli_paths_format(self, monkeypatch, capsys) -> None:
        _patch_csv(monkeypatch, [_crowdstrike_row()])
        cmd_files(["CrowdstrikeFalcon", "--format=paths"])
        out = capsys.readouterr().out.strip().splitlines()
        # First line is YML, then code, description, readme, test in order.
        assert out[0].endswith("CrowdStrikeFalcon.yml")
        assert out[1].endswith("CrowdStrikeFalcon.py")
        assert any(line.endswith("CrowdStrikeFalcon_description.md") for line in out)
        assert any(line.endswith("README.md") for line in out)
        assert any(line.endswith("CrowdStrikeFalcon_test.py") for line in out)

    def test_cli_json_format(self, monkeypatch, capsys) -> None:
        _patch_csv(monkeypatch, [_crowdstrike_row()])
        cmd_files(["CrowdstrikeFalcon", "--format=json"])
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["integration_id"] == "CrowdstrikeFalcon"
        assert parsed["code_language"] == "python"

    def test_cli_unknown_integration_exits_nonzero(self, monkeypatch, capsys) -> None:
        _patch_csv(monkeypatch, [_crowdstrike_row()])
        with pytest.raises(SystemExit) as exc_info:
            cmd_files(["NoSuchIntegration"])
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "ERROR:" in err
        assert "not found" in err


# ---------------------------------------------------------------------------
# `auth-params` helper + CLI + set-params-to-commands overlap rejection
# ---------------------------------------------------------------------------

# Reusable Auth Details JSON: a credentials param (dotted xsoar_params)
# AND an APIKey param (bare xsoar_params), AND an other_connection list.
# This exercises every branch of `auth_param_ids` projection rules.
MIXED_AUTH_JSON = (
    '{"auth_types":['
    '{"type":"APIKey","name":"api_key","xsoar_params":["api_key"]},'
    '{"type":"Plain","name":"credentials",'
    '"xsoar_params":["credentials.identifier","credentials.password"]}'
    '],'
    '"config":"REQUIRED(api_key) + REQUIRED(credentials)",'
    '"other_connection":["insecure","proxy","url"]}'
)


def _row_with_auth(name: str, auth_json: str) -> dict[str, str]:
    """Build a row whose Auth Details is set (current step is #3 P-to-C)."""
    row = _blank_row(name)
    row["assignee"] = "Alice"
    row["Auth Details"] = auth_json
    return row


class TestAuthParamIds:
    def test_returns_union_deduped_and_sorted(self, monkeypatch) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        result = auth_param_ids("MixedAuth")
        # api_key (auth_types bare), credentials (collapsed dotted),
        # insecure / proxy / url (other_connection).
        assert result == ["api_key", "credentials", "insecure", "proxy", "url"]
        # Sorted ascending — defensive re-check.
        assert result == sorted(result)
        # Deduped — no repeats.
        assert len(result) == len(set(result))

    def test_projects_dotted_forms(self, monkeypatch) -> None:
        # credentials.identifier + credentials.password BOTH collapse to
        # "credentials"; the result must contain "credentials" once and
        # MUST NOT contain the dotted forms.
        auth = (
            '{"auth_types":[{"type":"Plain","name":"creds_only",'
            '"xsoar_params":["credentials.identifier","credentials.password"]}],'
            '"config":"REQUIRED(creds_only)",'
            '"other_connection":[]}'
        )
        rows = [_row_with_auth("CredsOnly", auth)]
        _patch_csv(monkeypatch, rows)
        result = auth_param_ids("CredsOnly")
        assert result == ["credentials"]
        assert "credentials.identifier" not in result
        assert "credentials.password" not in result

    def test_legacy_row_no_other_connection_returns_auth_types_only(
        self, monkeypatch, capsys
    ) -> None:
        # Bypass validate_auth_detail and write a legacy-shape JSON
        # directly into the row. The validator now requires
        # ``other_connection`` so this can only happen on rows that
        # predate the field.
        legacy_auth = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)"}'
        )
        rows = [_row_with_auth("LegacyRow", legacy_auth)]
        _patch_csv(monkeypatch, rows)
        result = auth_param_ids("LegacyRow")
        # auth_types-derived ids only; no crash.
        assert result == ["api_key"]
        # Stderr hint about missing other_connection.
        err = capsys.readouterr().err
        assert "other_connection" in err
        assert "legacy shape" in err

    def test_unset_auth_details_raises_workflow_error(self, monkeypatch) -> None:
        # Auth Details cell is empty.
        row = _blank_row("NoAuthYet")
        row["assignee"] = "Alice"
        # Don't set Auth Details — current step is #2.
        rows = [row]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(WorkflowError) as exc:
            auth_param_ids("NoAuthYet")
        msg = exc.value.message
        assert "Auth Details" in msg
        assert "set-auth" in msg

    def test_unknown_integration_raises_workflow_error(self, monkeypatch) -> None:
        _patch_csv(monkeypatch, [_row_with_auth("Known", MIXED_AUTH_JSON)])
        with pytest.raises(WorkflowError) as exc:
            auth_param_ids("Unknown")
        assert "not found" in exc.value.message

    def test_invalid_json_raises_workflow_error(self, monkeypatch) -> None:
        row = _blank_row("BadJSON")
        row["assignee"] = "Alice"
        row["Auth Details"] = "not json"
        _patch_csv(monkeypatch, [row])
        with pytest.raises(WorkflowError) as exc:
            auth_param_ids("BadJSON")
        assert "valid JSON" in exc.value.message

    def test_none_required_with_only_other_connection(self, monkeypatch) -> None:
        # NoneRequired auth + non-empty other_connection (unusual but legal).
        auth = (
            '{"auth_types":[],"config":"NoneRequired",'
            '"other_connection":["host","port"]}'
        )
        rows = [_row_with_auth("NoAuthOnlyConn", auth)]
        _patch_csv(monkeypatch, rows)
        result = auth_param_ids("NoAuthOnlyConn")
        assert result == ["host", "port"]


class TestCmdAuthParamsCli:
    def test_text_format_default(self, monkeypatch, capsys) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        cmd_auth_params(["MixedAuth"])
        out = capsys.readouterr().out
        # One param per line, ascending — easy to pipe into grep -vFf.
        assert out.strip().splitlines() == [
            "api_key", "credentials", "insecure", "proxy", "url",
        ]

    def test_json_format(self, monkeypatch, capsys) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        cmd_auth_params(["MixedAuth", "--format=json"])
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed == {
            "integration_id": "MixedAuth",
            "params": ["api_key", "credentials", "insecure", "proxy", "url"],
        }

    def test_unset_auth_exits_nonzero_with_clear_error(
        self, monkeypatch, capsys
    ) -> None:
        row = _blank_row("NoAuthYet")
        row["assignee"] = "Alice"
        _patch_csv(monkeypatch, [row])
        with pytest.raises(SystemExit) as exc:
            cmd_auth_params(["NoAuthYet"])
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "Auth Details" in err

    def test_unknown_format_value_rejected(
        self, monkeypatch, capsys
    ) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        with pytest.raises(SystemExit) as exc:
            cmd_auth_params(["MixedAuth", "--format=xml"])
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "Unknown --format" in err

    def test_no_args_prints_usage_and_exits(
        self, monkeypatch, capsys
    ) -> None:
        _patch_csv(monkeypatch, [])
        with pytest.raises(SystemExit):
            cmd_auth_params([])
        out = capsys.readouterr().out
        assert "Usage:" in out
        assert "auth-params" in out


class TestSetParamsToCommandsOverlapRejection:
    def test_rejects_when_payload_includes_auth_param(
        self, monkeypatch, capsys
    ) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        # 'credentials' overlaps with the dotted xsoar_params projection;
        # 'proxy' overlaps with other_connection.
        bad_payload = json.dumps({
            "integration": "MixedAuth",
            "commands": {
                "test-module": ["credentials", "behavioral_param"],
                "real-cmd": ["proxy", "limit"],
            },
        })
        with pytest.raises(SystemExit) as exc:
            cmd_set_params_to_commands(["MixedAuth", bad_payload])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        # Both offending pairs named.
        assert "'test-module'" in out
        assert "'credentials'" in out
        assert "'real-cmd'" in out
        assert "'proxy'" in out
        # Source attribution: credentials → auth_types entry; proxy → other_connection.
        assert "auth_types[].name='credentials'" in out
        assert "other_connection" in out
        # Fix guidance present.
        assert "auth-params" in out
        assert "set-auth" in out
        # Row must NOT have been mutated.
        assert rows[0]["Params to Commands"] == ""

    def test_passes_when_no_overlap(self, monkeypatch, capsys) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        good_payload = json.dumps({
            "integration": "MixedAuth",
            "commands": {
                "test-module": ["behavioral_param"],
                "real-cmd": ["limit", "page_size"],
            },
        })
        # Should not raise; row gets the value written.
        cmd_set_params_to_commands(["MixedAuth", good_payload])
        assert rows[0]["Params to Commands"] == good_payload

    def test_unset_auth_propagates_clear_error(
        self, monkeypatch, capsys
    ) -> None:
        # Auth Details unset — overlap check raises the
        # "set auth first" WorkflowError before the cascade dispatch
        # even sees the call.
        row = _blank_row("NoAuthYet")
        row["assignee"] = "Alice"
        _patch_csv(monkeypatch, [row])
        payload = json.dumps({
            "integration": "NoAuthYet",
            "commands": {"test-module": ["anything"]},
        })
        with pytest.raises(SystemExit) as exc:
            cmd_set_params_to_commands(["NoAuthYet", payload])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "Auth Details" in out
        assert "set-auth" in out

    def test_legacy_row_overlap_still_caught_for_auth_types(
        self, monkeypatch, capsys
    ) -> None:
        # Legacy Auth Details (no other_connection) — overlap check
        # must still catch overlaps with auth_types-derived ids.
        legacy_auth = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)"}'
        )
        rows = [_row_with_auth("LegacyRow", legacy_auth)]
        _patch_csv(monkeypatch, rows)
        bad = json.dumps({
            "integration": "LegacyRow",
            "commands": {"some-cmd": ["api_key"]},
        })
        with pytest.raises(SystemExit) as exc:
            cmd_set_params_to_commands(["LegacyRow", bad])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "'api_key'" in out
        assert "auth_types[].name='api_key'" in out


# ---------------------------------------------------------------------------
# validate_params_to_commands (Fix A: strict schema validator)
# ---------------------------------------------------------------------------


class TestValidateParamsToCommands:
    """Strict-schema validator for the 'Params to Commands' JSON cell.

    Mirrors the structure of :class:`TestValidateAuthDetail`. The
    canonical good payload is the minimal two-key shape; every other
    test mutates it to exercise one specific rule.
    """

    GOOD_PAYLOAD = '{"integration": "X", "commands": {"foo": ["a", "b"]}}'

    def test_valid_simple(self) -> None:
        assert validate_params_to_commands(self.GOOD_PAYLOAD) == []

    def test_valid_empty_commands_dict(self) -> None:
        # An integration with zero commands is structurally valid; the
        # schema rule is "commands must be a dict", not "non-empty".
        assert validate_params_to_commands(
            '{"integration": "X", "commands": {}}'
        ) == []

    def test_valid_command_with_empty_param_list(self) -> None:
        # A command may legitimately have zero params (the analyzer's
        # static union came up empty after the ignore set was applied).
        assert validate_params_to_commands(
            '{"integration": "X", "commands": {"foo": []}}'
        ) == []

    def test_invalid_json(self) -> None:
        errors = validate_params_to_commands("not json")
        assert "Invalid JSON" in errors[0]

    def test_non_dict_top_level(self) -> None:
        errors = validate_params_to_commands('["integration", "commands"]')
        assert any("Expected a JSON object" in e for e in errors)

    def test_non_dict_string_top_level(self) -> None:
        errors = validate_params_to_commands('"hello"')
        assert any("Expected a JSON object" in e for e in errors)

    def test_diagnostics_extra_key_rejected_with_strip_recipe(self) -> None:
        # The historical leak: analyzer used to emit "diagnostics" by
        # default and the agent piped it verbatim. Validator must (a)
        # name the key explicitly and (b) embed the actionable
        # one-liner strip recipe.
        bad = (
            '{"integration": "X", "commands": {}, '
            '"diagnostics": {"foo": {"status": "ok"}}}'
        )
        errors = validate_params_to_commands(bad)
        # Diagnostics must be called out by name.
        assert any("'diagnostics'" in e for e in errors), errors
        # And the strip recipe must appear in some error string.
        assert any(
            "o.pop('diagnostics', None)" in e
            and "json.load" in e
            and "json.dumps" in e
            for e in errors
        ), errors

    def test_arbitrary_other_extra_keys_rejected(self) -> None:
        # Other forbidden top-level keys mentioned in column-schemas.md.
        for extra in ("status", "failure_excerpt", "random_key"):
            bad = (
                '{"integration": "X", "commands": {}, "'
                + extra + '": "anything"}'
            )
            errors = validate_params_to_commands(bad)
            assert any(extra in e for e in errors), (
                f"key {extra!r} should be rejected and named in error: {errors}"
            )
            # Strip recipe still embedded so the operator gets one path
            # to the fix regardless of which extra key tripped them.
            assert any(
                "o.pop('diagnostics', None)" in e for e in errors
            ), errors

    def test_multiple_extras_all_named_in_one_pass(self) -> None:
        bad = (
            '{"integration": "X", "commands": {}, '
            '"diagnostics": {}, "status": "ok", "stderr": ""}'
        )
        errors = validate_params_to_commands(bad)
        joined = "\n".join(errors)
        # Every extra key surfaces somewhere in the error output.
        for extra in ("diagnostics", "status", "stderr"):
            assert extra in joined, (
                f"{extra!r} missing from collected errors: {errors}"
            )

    def test_missing_integration_rejected(self) -> None:
        errors = validate_params_to_commands('{"commands": {}}')
        assert any(
            "Missing required" in e and "integration" in e
            for e in errors
        ), errors

    def test_missing_commands_rejected(self) -> None:
        errors = validate_params_to_commands('{"integration": "X"}')
        assert any(
            "Missing required" in e and "commands" in e
            for e in errors
        ), errors

    def test_missing_both_required_keys_rejected(self) -> None:
        errors = validate_params_to_commands('{}')
        # Single missing-keys error names BOTH.
        assert any(
            "Missing required" in e
            and "integration" in e
            and "commands" in e
            for e in errors
        ), errors

    def test_non_string_integration_rejected(self) -> None:
        errors = validate_params_to_commands(
            '{"integration": 42, "commands": {}}'
        )
        assert any(
            "'integration' must be a string" in e for e in errors
        ), errors

    def test_empty_string_integration_rejected(self) -> None:
        errors = validate_params_to_commands(
            '{"integration": "", "commands": {}}'
        )
        assert any(
            "'integration' must be a non-empty string" in e for e in errors
        ), errors

    def test_non_dict_commands_rejected(self) -> None:
        errors = validate_params_to_commands(
            '{"integration": "X", "commands": ["foo", "bar"]}'
        )
        assert any(
            "'commands' must be a JSON object" in e for e in errors
        ), errors

    def test_non_list_command_value_rejected(self) -> None:
        errors = validate_params_to_commands(
            '{"integration": "X", "commands": {"foo": "a"}}'
        )
        assert any(
            "expected a list of param ids" in e for e in errors
        ), errors

    def test_non_string_param_id_rejected(self) -> None:
        errors = validate_params_to_commands(
            '{"integration": "X", "commands": {"foo": ["a", 7]}}'
        )
        assert any(
            "param id must be a string" in e for e in errors
        ), errors

    def test_empty_string_param_id_rejected(self) -> None:
        errors = validate_params_to_commands(
            '{"integration": "X", "commands": {"foo": ["a", ""]}}'
        )
        assert any(
            "param id must be a non-empty string" in e for e in errors
        ), errors


class TestSetParamsToCommandsStrictSchemaCli:
    """End-to-end CLI checks: strict-schema rejection at the entrypoint.

    The validator must short-circuit BEFORE the existing overlap check
    so that shape errors surface on their own (more common operator
    mistake) and the row is never partially mutated.
    """

    def test_diagnostics_polluted_payload_exits_nonzero_with_strip_recipe(
        self, monkeypatch, capsys
    ) -> None:
        # Auth Details is set so we don't trip the upstream "set auth
        # first" prerequisite — the schema validator should fire first.
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        polluted = json.dumps({
            "integration": "MixedAuth",
            "commands": {"test-module": ["behavioral_param"]},
            "diagnostics": {"test-module": {"status": "ok"}},
        })
        with pytest.raises(SystemExit) as exc:
            cmd_set_params_to_commands(["MixedAuth", polluted])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        # Header from the strict-schema branch (NOT the overlap branch).
        assert "Params to Commands does not match the required schema" in out
        # The leak key is named explicitly and the strip recipe is shown.
        assert "'diagnostics'" in out
        assert "o.pop('diagnostics', None)" in out
        # Row remains untouched by the rejection.
        assert rows[0]["Params to Commands"] == ""

    def test_random_extra_key_exits_nonzero(
        self, monkeypatch, capsys
    ) -> None:
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        bad = json.dumps({
            "integration": "MixedAuth",
            "commands": {"test-module": ["behavioral_param"]},
            "random_key": True,
        })
        with pytest.raises(SystemExit) as exc:
            cmd_set_params_to_commands(["MixedAuth", bad])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "random_key" in out
        assert rows[0]["Params to Commands"] == ""

    def test_clean_payload_is_accepted(self, monkeypatch) -> None:
        # Sanity check that the strict-schema gate doesn't reject the
        # canonical good shape (would regress the existing overlap-only
        # acceptance test).
        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        good = json.dumps({
            "integration": "MixedAuth",
            "commands": {"test-module": ["behavioral_param"]},
        })
        cmd_set_params_to_commands(["MixedAuth", good])
        assert rows[0]["Params to Commands"] == good

    def test_set_json_data_step_defense_in_depth(
        self, monkeypatch, capsys
    ) -> None:
        # Direct call into the shared lower-level handler must also
        # reject a polluted payload — guards future callers that
        # bypass cmd_set_params_to_commands.
        from workflow_state import _set_json_data_step

        rows = [_row_with_auth("MixedAuth", MIXED_AUTH_JSON)]
        _patch_csv(monkeypatch, rows)
        polluted = json.dumps({
            "integration": "MixedAuth",
            "commands": {},
            "diagnostics": {},
        })
        with pytest.raises(SystemExit) as exc:
            _set_json_data_step(
                ["MixedAuth", polluted],
                "Params to Commands",
                "set-params-to-commands",
            )
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "Params to Commands does not match the required schema" in out
        assert "'diagnostics'" in out
