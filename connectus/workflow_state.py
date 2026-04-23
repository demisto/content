#!/usr/bin/env python3
"""
Workflow State Machine for integrations_report.csv

This script manages the workflow tracking columns (columns 6-16) in the CSV.
It acts as a state machine where each integration progresses through ordered steps.

Data columns (not managed by this script):
  1. assignee
  2. Integration Name
  3. Support Level
  4. Provider
  5. Auth Class
  6. Auth Detail

Workflow columns (in order):
  6.  script inputs        - Free text: the inputs/args for the script
  7.  params required for test - Free text: params needed for testing
  8.  generated manifest   - ✅ when manifest is generated
  9.  wrote code           - ✅ when code is written
  10. validations passed   - ✅ when demisto-sdk validate passes
  11. unit tests passed    - ✅ when unit tests pass
  12. param parity test passes - ✅ when param parity test passes
  13. requires auth parity test - YES/NO/N/A (flag, not a checkpoint)
  14. auth parity test passes   - ✅ when auth parity test passes (or N/A)
  15. code reviewed        - ✅ when code review is done
  16. code merged          - ✅ when code is merged

Rules:
  - You must explicitly name the step you are marking as passed.
  - You cannot mark a step as passed unless all prior steps are complete.
  - "script inputs" is free text — use set-inputs, not markpass.
  - "requires auth parity test" is a flag — use set-auth-flag, not markpass.
  - reset-to <step> clears that step and everything after it.
  - reset clears ALL workflow columns.

Usage:
  # Show status of an integration
  python workflow_state.py status "Cisco Spark"

  # Show status of all integrations with any progress
  python workflow_state.py status-all

  # Show what step each in-progress integration is on
  python workflow_state.py dashboard

  # Set the assignee
  python workflow_state.py set-assignee "Cisco Spark" "John Doe"

  # Set script inputs (JSON)
  python workflow_state.py set-inputs "Cisco Spark" '{"api_key": "str"}'

  # Set params required for test (JSON)
  python workflow_state.py set-params-for-test "Cisco Spark" '{"api_key": "test123"}'

  # Mark a specific step as passed (must be the current step)
  python workflow_state.py markpass "Cisco Spark" "wrote code"

  # Mark a step as failed (resets it and all subsequent steps)
  python workflow_state.py fail "Cisco Spark" "unit tests passed"

  # Set the auth parity flag
  python workflow_state.py set-auth-flag "Cisco Spark" YES

  # Reset to a specific stage (clears that step and everything after it)
  python workflow_state.py reset-to "Cisco Spark" "wrote code"

  # Reset all workflow columns for an integration
  python workflow_state.py reset "Cisco Spark"

  # Batch: show all integrations at a specific step
  python workflow_state.py at-step "wrote code"

  # List all integration names (for scripting)
  python workflow_state.py list

  # List all integrations assigned to a specific person
  python workflow_state.py list-by-assignee "John Doe"
"""

import csv
import io
import json
import os
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "connectus", "integrations_report.csv")

# The original data columns (not managed by this script)
DATA_COLUMNS = [
    "assignee",
    "Integration Name",
    "Support Level",
    "Provider",
    "Auth Class",
    "Auth Detail",
]

# Workflow columns in order. These are the columns this script manages.
WORKFLOW_COLUMNS = [
    "script inputs",
    "params required for test",
    "generated manifest",
    "wrote code",
    "validations passed",
    "unit tests passed",
    "param parity test passes",
    "requires auth parity test",
    "auth parity test passes",
    "code reviewed",
    "code merged",
]

# Checkpoint columns (sequential, must be done in order via markpass)
# "script inputs" is free text, "requires auth parity test" is a flag
CHECKPOINT_COLUMNS = [
    "generated manifest",
    "wrote code",
    "validations passed",
    "unit tests passed",
    "param parity test passes",
    # "requires auth parity test" is a flag, not a checkpoint
    "auth parity test passes",
    "code reviewed",
    "code merged",
]

# Steps that are NOT pass/fail checkpoints — they need a different command
NON_CHECKPOINT_STEPS = {
    "script inputs": "set-inputs",
    "params required for test": "set-params-for-test",
    "requires auth parity test": "set-auth-flag",
}

CHECK = "✅"
FAIL_MARK = "❌"
NA_MARK = "N/A"

ALL_COLUMNS = DATA_COLUMNS + WORKFLOW_COLUMNS


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

def load_csv() -> list[dict[str, str]]:
    """Load the CSV file and return list of row dicts."""
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def save_csv(rows: list[dict[str, str]]) -> None:
    """Write rows back to CSV, preserving column order."""
    if not rows:
        return

    fieldnames = list(rows[0].keys())

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)

    with open(CSV_PATH, "w", encoding="utf-8") as f:
        f.write(output.getvalue())


def find_row(rows: list[dict[str, str]], integration_name: str) -> Optional[int]:
    """Find the index of a row by integration name (case-insensitive)."""
    name_lower = integration_name.lower().strip()
    for i, row in enumerate(rows):
        if row["Integration Name"].strip().lower() == name_lower:
            return i
    return None


# ---------------------------------------------------------------------------
# State logic
# ---------------------------------------------------------------------------

def is_checked(value: str) -> bool:
    """Check if a cell value represents a completed state."""
    v = value.strip()
    return v in (CHECK, "✅", "YES", NA_MARK, "N/A", "true", "True", "done", "Done", "DONE")


def get_current_step(row: dict[str, str]) -> Optional[str]:
    """
    Get the current step an integration is on (the first uncompleted checkpoint).
    Returns None if all steps are complete.
    """
    for col in CHECKPOINT_COLUMNS:
        val = row.get(col, "").strip()
        if not is_checked(val):
            # Special case: if "requires auth parity test" is NO/N/A,
            # skip "auth parity test passes"
            if col == "auth parity test passes":
                flag = row.get("requires auth parity test", "").strip().upper()
                if flag in ("NO", "N/A", ""):
                    continue
            return col
    return None


def get_step_index(step_name: str) -> int:
    """Get the index of a checkpoint column."""
    try:
        return CHECKPOINT_COLUMNS.index(step_name)
    except ValueError:
        raise ValueError(
            f"Unknown checkpoint step: '{step_name}'. "
            f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}"
        )


def reset_from_step(row: dict[str, str], step_name: str) -> None:
    """Reset a step and all subsequent checkpoint steps."""
    idx = get_step_index(step_name)
    for col in CHECKPOINT_COLUMNS[idx:]:
        row[col] = ""
    # Also reset the auth flag if we're resetting from before it
    auth_flag_position = CHECKPOINT_COLUMNS.index("auth parity test passes")
    if idx <= auth_flag_position:
        row["requires auth parity test"] = ""


def markpass_step(row: dict[str, str], step_name: str) -> str:
    """
    Mark a step as passed. Returns a status message.
    Validates that:
      1. The step is a valid checkpoint (not free-text or flag).
      2. All prior steps are complete.
      3. The step is the current step (not already done, not skipping ahead).
    """
    # Guard: reject non-checkpoint steps with corrective guidance
    if step_name in NON_CHECKPOINT_STEPS:
        correct_cmd = NON_CHECKPOINT_STEPS[step_name]
        return (
            f"ERROR: '{step_name}' is not a pass/fail checkpoint.\n"
            f"  Use '{correct_cmd}' instead.\n"
            f"  Example: workflow_state.py {correct_cmd} "
            f"\"{row['Integration Name']}\" <value>"
        )

    idx = get_step_index(step_name)

    # Check if this step is already done
    val = row.get(step_name, "").strip()
    if is_checked(val):
        return f"'{step_name}' is already marked as passed for '{row['Integration Name']}'."

    # Prerequisite: "generated manifest" requires both inputs to be set
    if step_name == "generated manifest":
        script_inputs = row.get("script inputs", "").strip()
        if not script_inputs:
            return (
                f"ERROR: Cannot mark 'generated manifest' as passed — "
                f"'script inputs' must be set first.\n"
                f"  Use 'set-inputs' to provide the script inputs (JSON).\n"
                f"  Example: workflow_state.py set-inputs "
                f"\"{row['Integration Name']}\" '{{}}'"
            )
        params_for_test = row.get("params required for test", "").strip()
        if not params_for_test:
            return (
                f"ERROR: Cannot mark 'generated manifest' as passed — "
                f"'params required for test' must be set first.\n"
                f"  Use 'set-params-for-test' to provide the params (JSON).\n"
                f"  Example: workflow_state.py set-params-for-test "
                f"\"{row['Integration Name']}\" '{{}}'"
            )

    # Check all prior steps are complete
    for prior_col in CHECKPOINT_COLUMNS[:idx]:
        prior_val = row.get(prior_col, "").strip()
        if not is_checked(prior_val):
            # Special case: auth parity test passes can be skipped
            if prior_col == "auth parity test passes":
                flag = row.get("requires auth parity test", "").strip().upper()
                if flag in ("NO", "N/A", ""):
                    continue
            current = get_current_step(row)
            return (
                f"ERROR: Cannot mark '{step_name}' as passed — "
                f"you are not up to that step yet.\n"
                f"  Current step: '{current}'\n"
                f"  Prior step '{prior_col}' is not yet complete."
            )

    # Special case: auth parity test passes requires the flag to be set
    if step_name == "auth parity test passes":
        flag = row.get("requires auth parity test", "").strip().upper()
        if flag in ("NO", "N/A"):
            row[step_name] = NA_MARK
            return f"'{step_name}' set to N/A (auth parity test not required)."
        if flag == "":
            return (
                f"ERROR: Cannot mark '{step_name}' as passed — "
                f"'requires auth parity test' flag is not set.\n"
                f"  Use 'set-auth-flag' first.\n"
                f"  Example: workflow_state.py set-auth-flag "
                f"\"{row['Integration Name']}\" YES"
            )

    row[step_name] = CHECK
    return f"✅ '{step_name}' marked as passed for '{row['Integration Name']}'."


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def format_status(row: dict[str, str]) -> str:
    """Format the workflow status of a single integration."""
    name = row["Integration Name"]
    lines = [f"\n{'=' * 60}", f"  {name}", f"{'=' * 60}"]

    # Data columns summary
    assignee = row.get("assignee", "").strip()
    lines.append(f"  Assignee:      {assignee if assignee else '(unassigned)'}")
    lines.append(f"  Support Level: {row.get('Support Level', '')}")
    lines.append(f"  Provider:      {row.get('Provider', '')}")

    # Show Auth Class
    auth_class = row.get("Auth Class", "").strip()
    lines.append(f"  Auth Class:    {auth_class if auth_class else '(not set)'}")
    lines.append("")

    # Workflow columns
    lines.append("  Workflow Progress:")
    lines.append("  " + "-" * 40)

    for col in WORKFLOW_COLUMNS:
        val = row.get(col, "").strip()
        if col in ("script inputs", "params required for test"):
            display = val if val else "(not set)"
            lines.append(f"    {col:30s} : {display}")
        elif col == "requires auth parity test":
            display = val if val else "(not set)"
            lines.append(f"    {col:30s} : {display}")
        else:
            if is_checked(val):
                display = val
            elif val:
                display = val
            else:
                display = "⬜"
            lines.append(f"    {col:30s} : {display}")

    current = get_current_step(row)
    if current:
        lines.append(f"\n  ➡️  Current step: {current}")
    else:
        has_any = any(
            row.get(c, "").strip()
            for c in WORKFLOW_COLUMNS
        )
        if has_any:
            lines.append(f"\n  🎉 All steps complete!")
        else:
            lines.append(f"\n  ⏳ Not started")

    return "\n".join(lines)


def format_dashboard_row(row: dict[str, str]) -> Optional[str]:
    """Format a single row for the dashboard view. Returns None if no progress."""
    has_progress = any(row.get(c, "").strip() for c in WORKFLOW_COLUMNS)
    if not has_progress:
        return None

    name = row["Integration Name"]
    current = get_current_step(row)

    # Count completed checkpoints
    completed = sum(
        1 for c in CHECKPOINT_COLUMNS
        if is_checked(row.get(c, "").strip())
    )
    total = len(CHECKPOINT_COLUMNS)

    # Build progress bar
    bar = ""
    for c in CHECKPOINT_COLUMNS:
        val = row.get(c, "").strip()
        if is_checked(val):
            bar += "█"
        else:
            bar += "░"

    status = current if current else "✅ DONE"
    return f"  {name:45s} [{bar}] {completed}/{total}  → {status}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(args: list[str]) -> None:
    """Show status of one or more integrations."""
    if not args:
        print("Usage: workflow_state.py status <integration_name> [name2 ...]")
        sys.exit(1)

    rows = load_csv()
    for name in args:
        idx = find_row(rows, name)
        if idx is None:
            print(f"ERROR: Integration '{name}' not found.")
            continue
        print(format_status(rows[idx]))


def cmd_status_all(_args: list[str]) -> None:
    """Show status of all integrations with any progress."""
    rows = load_csv()
    found = False
    for row in rows:
        has_progress = any(row.get(c, "").strip() for c in WORKFLOW_COLUMNS)
        if has_progress:
            print(format_status(row))
            found = True
    if not found:
        print("No integrations have workflow progress yet.")


def cmd_dashboard(_args: list[str]) -> None:
    """Show a compact dashboard of all in-progress integrations."""
    rows = load_csv()
    print(f"\n{'=' * 80}")
    print("  WORKFLOW DASHBOARD")
    print(f"{'=' * 80}")
    print(f"  {'Integration':45s} {'Progress':10s} {'Step':5s}  → Current Step")
    print(f"  {'-' * 75}")

    in_progress = 0
    completed = 0
    not_started = 0

    for row in rows:
        line = format_dashboard_row(row)
        if line:
            print(line)
            current = get_current_step(row)
            if current:
                in_progress += 1
            else:
                completed += 1
        else:
            not_started += 1

    print(f"\n  Summary: {completed} complete, {in_progress} in progress, "
          f"{not_started} not started")


def cmd_set_inputs(args: list[str]) -> None:
    """Set the script inputs for an integration (must be valid JSON)."""
    if len(args) < 2:
        print("Usage: workflow_state.py set-inputs <integration_name> '<json>'")
        print("  The value must be valid JSON (e.g. '{}', '{\"key\": \"val\"}').")
        sys.exit(1)

    name = args[0]
    inputs = " ".join(args[1:])

    # Validate JSON
    try:
        json.loads(inputs)
    except json.JSONDecodeError as e:
        print(f"ERROR: script inputs must be valid JSON.")
        print(f"  Got: {inputs}")
        print(f"  Parse error: {e}")
        print(f"  Example: workflow_state.py set-inputs \"{name}\" '{{}}'")
        sys.exit(1)

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    rows[idx]["script inputs"] = inputs
    save_csv(rows)
    print(f"Set 'script inputs' for '{rows[idx]['Integration Name']}' to: {inputs}")


def cmd_set_params_for_test(args: list[str]) -> None:
    """Set the params required for test for an integration (must be valid JSON)."""
    if len(args) < 2:
        print("Usage: workflow_state.py set-params-for-test <integration_name> '<json>'")
        print("  The value must be valid JSON (e.g. '{}', '{\"api_key\": \"test123\"}').")
        sys.exit(1)

    name = args[0]
    params = " ".join(args[1:])

    # Validate JSON
    try:
        json.loads(params)
    except json.JSONDecodeError as e:
        print(f"ERROR: params required for test must be valid JSON.")
        print(f"  Got: {params}")
        print(f"  Parse error: {e}")
        print(f"  Example: workflow_state.py set-params-for-test \"{name}\" '{{}}'")
        sys.exit(1)

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    rows[idx]["params required for test"] = params
    save_csv(rows)
    print(f"Set 'params required for test' for '{rows[idx]['Integration Name']}' to: {params}")


def cmd_markpass(args: list[str]) -> None:
    """Mark a specific checkpoint step as passed.

    The step must be the current step (all prior steps must be complete).
    Non-checkpoint steps (script inputs, requires auth parity test) are
    rejected with guidance on the correct command to use.
    """
    if len(args) < 2:
        print("Usage: workflow_state.py markpass <integration_name> <step_name>")
        print(f"\nCheckpoint steps (in order):")
        for i, s in enumerate(CHECKPOINT_COLUMNS, 1):
            print(f"  {i}. {s}")
        print(f"\nNon-checkpoint steps (use a different command):")
        for step, cmd in NON_CHECKPOINT_STEPS.items():
            print(f"  - '{step}' → use '{cmd}'")
        sys.exit(1)

    name = args[0]
    step = " ".join(args[1:])

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    msg = markpass_step(rows[idx], step)
    print(msg)

    if msg.startswith("ERROR"):
        sys.exit(1)

    # If we just completed a step and the next is auth parity test passes
    # with flag NO/N/A, auto-advance past it
    next_step = get_current_step(rows[idx])
    if next_step == "auth parity test passes":
        flag = rows[idx].get("requires auth parity test", "").strip().upper()
        if flag in ("NO", "N/A"):
            rows[idx]["auth parity test passes"] = NA_MARK
            print(f"  Auto-skipped 'auth parity test passes' (flag={flag}).")

    save_csv(rows)
    new_step = get_current_step(rows[idx])
    if new_step:
        print(f"  Next step: {new_step}")
    else:
        # Only show completion if we actually have progress
        has_any = any(
            rows[idx].get(c, "").strip()
            for c in WORKFLOW_COLUMNS
        )
        if has_any:
            print(f"  🎉 All steps complete!")


def cmd_fail(args: list[str]) -> None:
    """Mark a step as failed and reset it and all subsequent steps."""
    if len(args) < 2:
        print("Usage: workflow_state.py fail <integration_name> <step_name>")
        print(f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    name = args[0]
    step = " ".join(args[1:])

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    try:
        step_idx = get_step_index(step)
        reset_from_step(rows[idx], step)
        reset_count = len(CHECKPOINT_COLUMNS) - step_idx
        save_csv(rows)
        print(f"Reset '{step}' and {reset_count - 1} subsequent step(s) "
              f"for '{rows[idx]['Integration Name']}'.")
        new_step = get_current_step(rows[idx])
        if new_step:
            print(f"  Current step is now: {new_step}")
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def cmd_set_assignee(args: list[str]) -> None:
    """Set the assignee for an integration."""
    if len(args) < 2:
        print("Usage: workflow_state.py set-assignee <integration_name> <assignee_name>")
        sys.exit(1)

    name = args[0]
    assignee = " ".join(args[1:])

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    rows[idx]["assignee"] = assignee
    save_csv(rows)
    print(f"Set assignee for '{rows[idx]['Integration Name']}' to: {assignee}")


def cmd_set_auth_flag(args: list[str]) -> None:
    """Set the 'requires auth parity test' flag."""
    if len(args) < 2:
        print("Usage: workflow_state.py set-auth-flag <integration_name> <YES|NO|N/A>")
        sys.exit(1)

    name = args[0]
    flag = args[1].upper().strip()

    if flag not in ("YES", "NO", "N/A"):
        print(f"ERROR: Flag must be YES, NO, or N/A. Got: '{flag}'")
        sys.exit(1)

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    rows[idx]["requires auth parity test"] = flag

    # If flag is NO or N/A, auto-set auth parity test passes to N/A
    if flag in ("NO", "N/A"):
        rows[idx]["auth parity test passes"] = NA_MARK
        print(f"Set 'requires auth parity test' = {flag} "
              f"and 'auth parity test passes' = N/A "
              f"for '{rows[idx]['Integration Name']}'.")
    else:
        # If flag is YES and auth parity was N/A, reset it
        if rows[idx].get("auth parity test passes", "").strip() == NA_MARK:
            rows[idx]["auth parity test passes"] = ""
        print(f"Set 'requires auth parity test' = {flag} "
              f"for '{rows[idx]['Integration Name']}'.")

    save_csv(rows)


def cmd_reset_to(args: list[str]) -> None:
    """Reset to a specific stage: clears that step and everything after it.

    This is the "reset to stage X" command. It puts the integration back
    to the point just before the named step, so that step and all following
    columns become empty.
    """
    if len(args) < 2:
        print("Usage: workflow_state.py reset-to <integration_name> <step_name>")
        print(f"\nThis clears the named step and everything after it.")
        print(f"\nValid steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    name = args[0]
    step = " ".join(args[1:])

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    try:
        step_idx = get_step_index(step)
        reset_from_step(rows[idx], step)
        reset_count = len(CHECKPOINT_COLUMNS) - step_idx
        save_csv(rows)
        print(f"Reset to '{step}' for '{rows[idx]['Integration Name']}'.")
        print(f"  Cleared '{step}' and {reset_count - 1} subsequent step(s).")
        new_step = get_current_step(rows[idx])
        if new_step:
            print(f"  Current step is now: {new_step}")
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def cmd_reset(args: list[str]) -> None:
    """Reset all workflow columns for an integration."""
    if not args:
        print("Usage: workflow_state.py reset <integration_name>")
        sys.exit(1)

    name = args[0]
    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    for col in WORKFLOW_COLUMNS:
        rows[idx][col] = ""

    save_csv(rows)
    print(f"Reset all workflow columns for '{rows[idx]['Integration Name']}'.")


def cmd_at_step(args: list[str]) -> None:
    """List all integrations currently at a specific step."""
    if not args:
        print("Usage: workflow_state.py at-step <step_name>")
        print(f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    step = " ".join(args)
    # Validate step name
    if step not in CHECKPOINT_COLUMNS:
        print(f"ERROR: Unknown step '{step}'.")
        print(f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    rows = load_csv()
    matches = []
    for row in rows:
        current = get_current_step(row)
        if current == step:
            matches.append(row["Integration Name"])

    if matches:
        print(f"\nIntegrations currently at step '{step}' ({len(matches)}):")
        for name in matches:
            print(f"  - {name}")
    else:
        print(f"No integrations are currently at step '{step}'.")


def cmd_list(_args: list[str]) -> None:
    """List all integration names."""
    rows = load_csv()
    for row in rows:
        print(row["Integration Name"])


def list_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> list[dict[str, str]]:
    """Filter rows to those whose assignee matches (case-insensitive).

    Args:
        rows: All CSV rows.
        assignee_name: The assignee name to search for.

    Returns:
        List of row dicts where the assignee column matches.
    """
    target = assignee_name.strip().lower()
    return [row for row in rows if row.get("assignee", "").strip().lower() == target]


def format_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> str:
    """Format a list of integrations belonging to an assignee.

    Shows each matching integration's name and current workflow step,
    similar to the at-step output format.

    Args:
        rows: Filtered rows (already matched by assignee).
        assignee_name: The assignee name (used in the header).

    Returns:
        Formatted string for display.
    """
    if not rows:
        return f"No integrations found for assignee '{assignee_name}'."

    lines = [f"\nIntegrations assigned to '{assignee_name}' ({len(rows)}):"]
    for row in rows:
        name = row["Integration Name"]
        has_any = any(row.get(c, "").strip() for c in WORKFLOW_COLUMNS)
        if not has_any:
            step_display = "not started"
        else:
            current = get_current_step(row)
            step_display = current if current else "✅ DONE"
        lines.append(f"  - {name:45s} → {step_display}")
    return "\n".join(lines)


def cmd_list_by_assignee(args: list[str]) -> None:
    """List all integrations assigned to a specific person."""
    if not args:
        print("Usage: workflow_state.py list-by-assignee <assignee_name>")
        sys.exit(1)

    assignee_name = " ".join(args)
    rows = load_csv()
    matches = list_by_assignee(rows, assignee_name)
    print(format_by_assignee(matches, assignee_name))


def cmd_help(_args: list[str]) -> None:
    """Show help."""
    print(__doc__)


# ---------------------------------------------------------------------------
# Programmatic API (for use by AI agents / other scripts)
# ---------------------------------------------------------------------------

def get_integration_status(integration_name: str) -> dict:
    """
    Get the full status of an integration as a dict.
    Returns dict with keys: name, current_step, workflow (dict of col->value),
    completed_steps, total_steps, progress_pct.
    """
    rows = load_csv()
    idx = find_row(rows, integration_name)
    if idx is None:
        return {"error": f"Integration '{integration_name}' not found."}

    row = rows[idx]
    current = get_current_step(row)
    completed = sum(
        1 for c in CHECKPOINT_COLUMNS
        if is_checked(row.get(c, "").strip())
    )

    return {
        "name": row["Integration Name"],
        "current_step": current,
        "workflow": {col: row.get(col, "") for col in WORKFLOW_COLUMNS},
        "completed_steps": completed,
        "total_steps": len(CHECKPOINT_COLUMNS),
        "progress_pct": round(completed / len(CHECKPOINT_COLUMNS) * 100, 1),
        "all_complete": current is None and completed > 0,
    }


def markpass_integration_step(integration_name: str, step_name: str) -> dict:
    """
    Mark a specific step as passed for an integration. Returns status dict.
    Fails if the integration is not up to that step yet.
    """
    rows = load_csv()
    idx = find_row(rows, integration_name)
    if idx is None:
        return {"error": f"Integration '{integration_name}' not found."}

    row = rows[idx]
    msg = markpass_step(row, step_name)

    if msg.startswith("ERROR"):
        return {"error": msg}

    # Auto-skip auth parity if not required
    next_step = get_current_step(row)
    if next_step == "auth parity test passes":
        flag = row.get("requires auth parity test", "").strip().upper()
        if flag in ("NO", "N/A"):
            row["auth parity test passes"] = NA_MARK

    save_csv(rows)

    return {
        "message": msg,
        "completed_step": step_name,
        "current_step": get_current_step(row),
    }


def fail_integration_step(integration_name: str, step_name: str) -> dict:
    """
    Mark a step as failed and reset subsequent steps. Returns status dict.
    """
    rows = load_csv()
    idx = find_row(rows, integration_name)
    if idx is None:
        return {"error": f"Integration '{integration_name}' not found."}

    try:
        reset_from_step(rows[idx], step_name)
        save_csv(rows)
        return {
            "message": f"Reset '{step_name}' and subsequent steps.",
            "current_step": get_current_step(rows[idx]),
        }
    except ValueError as e:
        return {"error": str(e)}


def reset_integration_to_step(integration_name: str, step_name: str) -> dict:
    """
    Reset to a specific stage (clears that step and everything after it).
    Returns status dict.
    """
    rows = load_csv()
    idx = find_row(rows, integration_name)
    if idx is None:
        return {"error": f"Integration '{integration_name}' not found."}

    try:
        reset_from_step(rows[idx], step_name)
        save_csv(rows)
        return {
            "message": f"Reset to '{step_name}' — cleared it and all subsequent steps.",
            "current_step": get_current_step(rows[idx]),
        }
    except ValueError as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

COMMANDS = {
    "status": cmd_status,
    "status-all": cmd_status_all,
    "dashboard": cmd_dashboard,
    "set-assignee": cmd_set_assignee,
    "set-inputs": cmd_set_inputs,
    "set-params-for-test": cmd_set_params_for_test,
    "markpass": cmd_markpass,
    "fail": cmd_fail,
    "set-auth-flag": cmd_set_auth_flag,
    "reset-to": cmd_reset_to,
    "reset": cmd_reset,
    "at-step": cmd_at_step,
    "list": cmd_list,
    "list-by-assignee": cmd_list_by_assignee,
    "help": cmd_help,
}


def main() -> None:
    if len(sys.argv) < 2:
        cmd_help([])
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]

    if command not in COMMANDS:
        print(f"ERROR: Unknown command '{command}'.")
        print(f"Available commands: {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    COMMANDS[command](args)


if __name__ == "__main__":
    main()
