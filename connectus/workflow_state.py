#!/usr/bin/env python3
"""
Workflow State Machine for integrations_report.csv

This script manages the workflow tracking columns in the CSV. It acts as a
state machine where each integration progresses through ordered steps.

CSV column groups (see connectus/Readme.md and connectus/column-schemas.md):

Data columns (4) — identity / metadata, NOT managed by this script:
  1. Integration ID            - lookup key (case-insensitive)
  2. Integration File Path     - path to the integration's source files
  3. Connector ID              - the ConnectUs connector this integration belongs to
  4. special cases             - frontend/backend hardcoded special-case notes

Workflow columns (16) — managed by this script:

  Workflow data columns (free-text / JSON, set via dedicated setters):
    5.  assignee                              - free text, who is working on this
    6.  Auth Details                          - JSON, see column-schemas.md
    7.  Params to Commands                    - JSON, see column-schemas.md
    8.  Params for test with default in code  - JSON, see column-schemas.md
    9.  Params same in other handlers         - JSON (optional), see column-schemas.md

  Workflow checkpoint columns (sequential ✅ pass/fail):
    10. generated manifest                    - manifest YAML generated
    11. run manifest make validate            - `make validate` passed
    12. wrote/checked code                    - code written/reviewed
    13. shadowed command test passes          - no shadowed/conflicting commands
    14. write tests                           - unit tests written
    15. precommit/validate/unit tests passed  - precommit + validate + unit tests pass

  Workflow flag column (NOT a checkpoint):
    16. requires auth parity test             - YES / NO / N/A

  More checkpoint columns:
    17. auth parity test passes               - ✅ (auto N/A when flag is NO/N/A)
    18. param parity test passes              - ✅
    19. code reviewed                         - ✅
    20. code merged                           - ✅

Rules:
  - You must explicitly name the step you are marking as passed.
  - Checkpoint columns must be completed in order (sequential enforcement).
  - Workflow data columns are NOT checkpoints — use their dedicated setters.
  - The flag `requires auth parity test` is NOT a checkpoint — use `set-auth-flag`.
  - Setting `Auth Details` resets the workflow back to `generated manifest`.
  - Setting `Params to Commands` and `Params for test with default in code` are
    prerequisites for marking `generated manifest` as passed.
  - `Params same in other handlers` is optional and never a prerequisite.
  - reset-to <step> clears that checkpoint and everything after it.
  - reset clears ALL workflow columns.

Usage:
  python workflow_state.py status "Cisco Spark"
  python workflow_state.py status-all
  python workflow_state.py dashboard
  python workflow_state.py set-assignee "Cisco Spark" "John Doe"
  python workflow_state.py set-auth "Cisco Spark" '<auth-details json>'
  python workflow_state.py set-inputs "Cisco Spark" '<params-to-commands json>'
  python workflow_state.py set-params-for-test "Cisco Spark" '<json>'
  python workflow_state.py set-shared-params "Cisco Spark" '<json>'
  python workflow_state.py markpass "Cisco Spark" "wrote/checked code"
  python workflow_state.py fail "Cisco Spark" "write tests"
  python workflow_state.py set-auth-flag "Cisco Spark" YES
  python workflow_state.py reset-to "Cisco Spark" "wrote/checked code"
  python workflow_state.py reset "Cisco Spark"
  python workflow_state.py at-step "wrote/checked code"
  python workflow_state.py list
  python workflow_state.py list-by-assignee "John Doe"
  python workflow_state.py show-step "Cisco Spark" "Params to Commands"
"""

import csv
import io
import json
import os
import sys
import tempfile
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "connectus", "integrations_report.csv")

# Data columns (identity / metadata, not managed by this script).
DATA_COLUMNS = [
    "Integration ID",
    "Integration File Path",
    "Connector ID",
    "special cases",
]

# Workflow data columns (free-text / JSON, set via dedicated setters).
# These are NOT pass/fail checkpoints.
WORKFLOW_DATA_COLUMNS = [
    "assignee",
    "Auth Details",
    "Params to Commands",
    "Params for test with default in code",
    "Params same in other handlers",
]

# Workflow checkpoint columns (sequential ✅ markpass/fail).
# The "requires auth parity test" flag lives between
# "precommit/validate/unit tests passed" and "auth parity test passes" but
# is NOT itself a checkpoint.
CHECKPOINT_COLUMNS = [
    "generated manifest",
    "run manifest make validate",
    "wrote/checked code",
    "shadowed command test passes",
    "write tests",
    "precommit/validate/unit tests passed",
    # "requires auth parity test" -- flag, not a checkpoint
    "auth parity test passes",
    "param parity test passes",
    "code reviewed",
    "code merged",
]

# The flag column (YES / NO / N/A); not a checkpoint.
AUTH_PARITY_FLAG_COLUMN = "requires auth parity test"

# All workflow columns in CSV order. This is what `reset` clears and what the
# status/dashboard commands iterate over for display.
WORKFLOW_COLUMNS = [
    "assignee",
    "Auth Details",
    "Params to Commands",
    "Params for test with default in code",
    "Params same in other handlers",
    "generated manifest",
    "run manifest make validate",
    "wrote/checked code",
    "shadowed command test passes",
    "write tests",
    "precommit/validate/unit tests passed",
    "requires auth parity test",
    "auth parity test passes",
    "param parity test passes",
    "code reviewed",
    "code merged",
]

# Steps that look like they could be markpass'd but actually need a different
# command. Maps step name -> the correct CLI subcommand to suggest.
NON_CHECKPOINT_STEPS = {
    "assignee": "set-assignee",
    "Auth Details": "set-auth",
    "Params to Commands": "set-inputs",
    "Params for test with default in code": "set-params-for-test",
    "Params same in other handlers": "set-shared-params",
    "requires auth parity test": "set-auth-flag",
}

# Workflow data columns that must be valid JSON when set.
JSON_VALUED_COLUMNS = {
    "Auth Details",
    "Params to Commands",
    "Params for test with default in code",
    "Params same in other handlers",
}

CHECK = "✅"
FAIL_MARK = "❌"
NA_MARK = "N/A"

# Valid auth type enum values for Auth Details schema validation
VALID_AUTH_TYPES = {
    "OAuth2AuthCode",
    "OAuth2ClientCreds",
    "OAuth2JWT",
    "APIKey",
    "Plain",
    "Other",
    "NoneRequired",
}

# Full ordered column list (for CSV write/validation).
ALL_COLUMNS = DATA_COLUMNS + WORKFLOW_COLUMNS

# Total expected column count in the CSV (used for row-length sanity checks).
EXPECTED_COLUMN_COUNT = len(ALL_COLUMNS)


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

def load_csv() -> list[dict[str, str]]:
    """Load the CSV file and return list of row dicts.

    Verifies the header matches ``ALL_COLUMNS`` and warns (without raising)
    when the column set drifts, so a stale CSV doesn't silently corrupt
    downstream operations.
    """
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        if fieldnames != ALL_COLUMNS:
            missing = [c for c in ALL_COLUMNS if c not in fieldnames]
            extra = [c for c in fieldnames if c not in ALL_COLUMNS]
            print(
                "WARNING: CSV header does not match expected schema.\n"
                f"  Expected {len(ALL_COLUMNS)} columns, got {len(fieldnames)}.\n"
                f"  Missing: {missing}\n"
                f"  Extra:   {extra}",
                file=sys.stderr,
            )
        return list(reader)


def save_csv(rows: list[dict[str, str]]) -> None:
    """Write rows back to CSV atomically, preserving column order.

    Writes to a temp file in the same directory as ``CSV_PATH`` and then
    uses ``os.replace`` for an atomic rename. If the write fails partway,
    the temp file is removed and the original CSV is left unchanged.
    """
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

    target_dir = os.path.dirname(CSV_PATH) or "."
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_dir,
            prefix=".integrations_report.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp_path = tmp.name
            tmp.write(output.getvalue())
        os.replace(tmp_path, CSV_PATH)
        tmp_path = None
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def find_row(rows: list[dict[str, str]], integration_id: str) -> Optional[int]:
    """Find the index of a row by Integration ID (case-insensitive)."""
    name_lower = integration_id.lower().strip()
    for i, row in enumerate(rows):
        if row.get("Integration ID", "").strip().lower() == name_lower:
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
    """Get the current checkpoint step (the first uncompleted one).

    Returns ``None`` if all checkpoints are complete (or all skipped).
    """
    for col in CHECKPOINT_COLUMNS:
        val = row.get(col, "").strip()
        if not is_checked(val):
            # Special case: if the auth parity flag is NO/N/A (or unset),
            # skip "auth parity test passes".
            if col == "auth parity test passes":
                flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
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
    """Reset a checkpoint and all subsequent checkpoints.

    Also resets the ``requires auth parity test`` flag if we're resetting
    from at-or-before its position in the workflow.
    """
    idx = get_step_index(step_name)
    for col in CHECKPOINT_COLUMNS[idx:]:
        row[col] = ""
    # Reset the auth flag too if we cleared "auth parity test passes".
    if "auth parity test passes" in CHECKPOINT_COLUMNS[idx:]:
        row[AUTH_PARITY_FLAG_COLUMN] = ""


def validate_auth_detail(value: str) -> list[str]:
    """Validate that a string conforms to the Auth Details JSON schema.

    Returns a list of error messages. An empty list means the value is valid.

    See ``connectus/column-schemas.md`` for the full schema description.
    """
    errors: list[str] = []

    try:
        detail = json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]

    if not isinstance(detail, dict):
        return [f"Expected a JSON object, got {type(detail).__name__}"]

    # --- Top-level keys ---
    required_keys = {"auth_types", "config", "params", "notes"}
    missing = required_keys - set(detail.keys())
    if missing:
        errors.append(f"Missing required keys: {', '.join(sorted(missing))}")
        return errors  # Can't validate further without required keys

    # --- auth_types ---
    if not isinstance(detail["auth_types"], list):
        errors.append(f"'auth_types' must be a list, got {type(detail['auth_types']).__name__}")
    else:
        for i, entry in enumerate(detail["auth_types"]):
            if not isinstance(entry, dict):
                errors.append(f"auth_types[{i}]: expected object, got {type(entry).__name__}")
                continue
            if "type" not in entry:
                errors.append(f"auth_types[{i}]: missing 'type'")
            elif entry["type"] not in VALID_AUTH_TYPES:
                errors.append(f"auth_types[{i}]: invalid type '{entry['type']}'")
            if "name" not in entry:
                errors.append(f"auth_types[{i}]: missing 'name'")
            elif not isinstance(entry["name"], str):
                errors.append(f"auth_types[{i}]: 'name' must be a string")

    # --- config ---
    if not isinstance(detail["config"], str):
        errors.append(f"'config' must be a string, got {type(detail['config']).__name__}")

    # --- params ---
    if not isinstance(detail["params"], dict):
        errors.append(f"'params' must be a dict, got {type(detail['params']).__name__}")
    else:
        for param_name, param_data in detail["params"].items():
            if not isinstance(param_data, dict):
                errors.append(f"params['{param_name}']: expected object, got {type(param_data).__name__}")
                continue

            # type
            if "type" not in param_data:
                errors.append(f"params['{param_name}']: missing 'type'")
            else:
                ptype = param_data["type"]
                if isinstance(ptype, str):
                    if ptype not in VALID_AUTH_TYPES:
                        errors.append(f"params['{param_name}']: invalid type '{ptype}'")
                elif isinstance(ptype, list):
                    for t in ptype:
                        if t not in VALID_AUTH_TYPES:
                            errors.append(f"params['{param_name}']: invalid type '{t}' in list")
                else:
                    errors.append(f"params['{param_name}']: 'type' must be string or list")

            # xsoar_type
            if "xsoar_type" not in param_data:
                errors.append(f"params['{param_name}']: missing 'xsoar_type'")
            elif not isinstance(param_data["xsoar_type"], int):
                errors.append(
                    f"params['{param_name}']: 'xsoar_type' must be int, "
                    f"got {type(param_data['xsoar_type']).__name__}"
                )

            # required
            if "required" not in param_data:
                errors.append(f"params['{param_name}']: missing 'required'")
            elif not isinstance(param_data["required"], bool):
                errors.append(
                    f"params['{param_name}']: 'required' must be bool, "
                    f"got {type(param_data['required']).__name__}"
                )

    # --- notes ---
    if detail["notes"] is not None and not isinstance(detail["notes"], str):
        errors.append(f"'notes' must be a string or null, got {type(detail['notes']).__name__}")

    return errors


def markpass_step(row: dict[str, str], step_name: str) -> str:
    """Mark a checkpoint as passed. Returns a status message.

    Validates that:
      1. The step is a valid checkpoint (not a workflow data column or flag).
      2. All prior checkpoints are complete (sequential enforcement).
      3. ``generated manifest`` has its prerequisite JSON columns set.
      4. ``auth parity test passes`` has the flag set (or auto-N/A's).
    """
    integration_id = row.get("Integration ID", "")

    # Guard: reject non-checkpoint steps with corrective guidance
    if step_name in NON_CHECKPOINT_STEPS:
        correct_cmd = NON_CHECKPOINT_STEPS[step_name]
        return (
            f"ERROR: '{step_name}' is not a pass/fail checkpoint.\n"
            f"  Use '{correct_cmd}' instead.\n"
            f"  Example: workflow_state.py {correct_cmd} "
            f"\"{integration_id}\" <value>"
        )

    idx = get_step_index(step_name)

    # Already done?
    val = row.get(step_name, "").strip()
    if is_checked(val):
        return f"'{step_name}' is already marked as passed for '{integration_id}'."

    # Prerequisite: "generated manifest" needs both Params columns set.
    if step_name == "generated manifest":
        params_to_commands = row.get("Params to Commands", "").strip()
        if not params_to_commands:
            return (
                f"ERROR: Cannot mark 'generated manifest' as passed — "
                f"'Params to Commands' must be set first.\n"
                f"  Use 'set-inputs' to provide the params (JSON).\n"
                f"  Example: workflow_state.py set-inputs "
                f"\"{integration_id}\" '{{}}'"
            )
        params_for_test = row.get("Params for test with default in code", "").strip()
        if not params_for_test:
            return (
                f"ERROR: Cannot mark 'generated manifest' as passed — "
                f"'Params for test with default in code' must be set first.\n"
                f"  Use 'set-params-for-test' to provide the params (JSON).\n"
                f"  Example: workflow_state.py set-params-for-test "
                f"\"{integration_id}\" '[]'"
            )

    # Check all prior checkpoints are complete
    for prior_col in CHECKPOINT_COLUMNS[:idx]:
        prior_val = row.get(prior_col, "").strip()
        if not is_checked(prior_val):
            # Special case: auth parity test passes can be skipped
            if prior_col == "auth parity test passes":
                flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
                if flag in ("NO", "N/A", ""):
                    continue
            current = get_current_step(row)
            return (
                f"ERROR: Cannot mark '{step_name}' as passed — "
                f"you are not up to that step yet.\n"
                f"  Current step: '{current}'\n"
                f"  Prior step '{prior_col}' is not yet complete."
            )

    # Special case: auth parity test passes requires the flag to be set.
    if step_name == "auth parity test passes":
        flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
        if flag in ("NO", "N/A"):
            row[step_name] = NA_MARK
            return f"'{step_name}' set to N/A (auth parity test not required)."
        if flag == "":
            return (
                f"ERROR: Cannot mark '{step_name}' as passed — "
                f"'requires auth parity test' flag is not set.\n"
                f"  Use 'set-auth-flag' first.\n"
                f"  Example: workflow_state.py set-auth-flag "
                f"\"{integration_id}\" YES"
            )

    row[step_name] = CHECK
    return f"✅ '{step_name}' marked as passed for '{integration_id}'."


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def format_status(row: dict[str, str]) -> str:
    """Format the workflow status of a single integration."""
    integration_id = row.get("Integration ID", "")
    lines = [f"\n{'=' * 60}", f"  {integration_id}", f"{'=' * 60}"]

    # Data columns summary
    file_path = row.get("Integration File Path", "").strip()
    connector_id = row.get("Connector ID", "").strip()
    special = row.get("special cases", "").strip()
    assignee = row.get("assignee", "").strip()

    lines.append(f"  Assignee:        {assignee if assignee else '(unassigned)'}")
    lines.append(f"  File Path:       {file_path if file_path else '(not set)'}")
    lines.append(f"  Connector ID:    {connector_id if connector_id else '(not set)'}")
    if special:
        lines.append(f"  Special Cases:   {special}")
    lines.append("")

    # Workflow data columns (free text / JSON)
    lines.append("  Workflow Data:")
    lines.append("  " + "-" * 40)
    for col in WORKFLOW_DATA_COLUMNS:
        if col == "assignee":
            continue  # already shown above
        val = row.get(col, "").strip()
        display = val if val else "(not set)"
        lines.append(f"    {col:38s} : {display}")
    lines.append("")

    # Checkpoint columns
    lines.append("  Workflow Checkpoints:")
    lines.append("  " + "-" * 40)
    # Show flag in the right position too
    seq: list[str] = []
    for col in CHECKPOINT_COLUMNS:
        seq.append(col)
        if col == "precommit/validate/unit tests passed":
            seq.append(AUTH_PARITY_FLAG_COLUMN)
    for col in seq:
        val = row.get(col, "").strip()
        if col == AUTH_PARITY_FLAG_COLUMN:
            display = val if val else "(not set)"
        elif is_checked(val):
            display = val
        elif val:
            display = val
        else:
            display = "⬜"
        lines.append(f"    {col:38s} : {display}")

    current = get_current_step(row)
    if current:
        lines.append(f"\n  ➡️  Current step: {current}")
    else:
        if has_workflow_progress(row):
            lines.append("\n  🎉 All checkpoints complete!")
        else:
            lines.append("\n  ⏳ Not started")

    return "\n".join(lines)


def format_dashboard_row(row: dict[str, str]) -> Optional[str]:
    """Format a single row for the dashboard view. Returns None if no progress."""
    if not has_workflow_progress(row):
        return None

    integration_id = row.get("Integration ID", "")
    current = get_current_step(row)

    completed = sum(
        1 for c in CHECKPOINT_COLUMNS
        if is_checked(row.get(c, "").strip())
    )
    total = len(CHECKPOINT_COLUMNS)

    bar = ""
    for c in CHECKPOINT_COLUMNS:
        val = row.get(c, "").strip()
        bar += "█" if is_checked(val) else "░"

    status = current if current else "✅ DONE"
    return f"  {integration_id:45s} [{bar}] {completed}/{total}  → {status}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(args: list[str]) -> None:
    """Show status of one or more integrations."""
    if not args:
        print("Usage: workflow_state.py status <integration_id> [id2 ...]")
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
        if has_workflow_progress(row):
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
    print(f"  {'Integration ID':45s} {'Progress':10s} {'Step':5s}  → Current Step")
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


def _set_json_column(args: list[str], column: str, setter_cmd: str) -> None:
    """Shared implementation for setting JSON-valued workflow data columns."""
    if len(args) < 2:
        print(f"Usage: workflow_state.py {setter_cmd} <integration_id> '<json>'")
        print(f"  The value must be valid JSON (see connectus/column-schemas.md).")
        sys.exit(1)

    name = args[0]
    raw = " ".join(args[1:])

    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: '{column}' must be valid JSON.")
        print(f"  Got: {raw}")
        print(f"  Parse error: {e}")
        print(f"  Example: workflow_state.py {setter_cmd} \"{name}\" '{{}}'")
        sys.exit(1)

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    rows[idx][column] = raw
    save_csv(rows)
    print(f"Set '{column}' for '{rows[idx]['Integration ID']}' to: {raw}")


def cmd_set_inputs(args: list[str]) -> None:
    """Set the 'Params to Commands' JSON for an integration."""
    _set_json_column(args, "Params to Commands", "set-inputs")


def cmd_set_params_for_test(args: list[str]) -> None:
    """Set the 'Params for test with default in code' JSON."""
    _set_json_column(args, "Params for test with default in code", "set-params-for-test")


def cmd_set_shared_params(args: list[str]) -> None:
    """Set the (optional) 'Params same in other handlers' JSON."""
    _set_json_column(args, "Params same in other handlers", "set-shared-params")


def cmd_markpass(args: list[str]) -> None:
    """Mark a specific checkpoint step as passed.

    The step must be the current step (all prior steps must be complete).
    Workflow data columns and the auth parity flag are rejected with guidance
    on the correct command to use.
    """
    if len(args) < 2:
        print("Usage: workflow_state.py markpass <integration_id> <step_name>")
        print("\nCheckpoint steps (in order):")
        for i, s in enumerate(CHECKPOINT_COLUMNS, 1):
            print(f"  {i}. {s}")
        print("\nNon-checkpoint columns (use a different command):")
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

    # If the next step is "auth parity test passes" and the flag is NO/N/A,
    # auto-advance past it.
    next_step = get_current_step(rows[idx])
    if next_step == "auth parity test passes":
        flag = rows[idx].get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
        if flag in ("NO", "N/A"):
            rows[idx]["auth parity test passes"] = NA_MARK
            print(f"  Auto-skipped 'auth parity test passes' (flag={flag}).")

    save_csv(rows)
    new_step = get_current_step(rows[idx])
    if new_step:
        print(f"  Next step: {new_step}")
    else:
        if has_workflow_progress(rows[idx]):
            print("  🎉 All checkpoints complete!")


def cmd_fail(args: list[str]) -> None:
    """Mark a step as failed and reset it and all subsequent steps."""
    if len(args) < 2:
        print("Usage: workflow_state.py fail <integration_id> <step_name>")
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
              f"for '{rows[idx]['Integration ID']}'.")
        new_step = get_current_step(rows[idx])
        if new_step:
            print(f"  Current step is now: {new_step}")
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def cmd_set_assignee(args: list[str]) -> None:
    """Set the assignee for an integration."""
    if len(args) < 2:
        print("Usage: workflow_state.py set-assignee <integration_id> <assignee_name>")
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
    print(f"Set assignee for '{rows[idx]['Integration ID']}' to: {assignee}")


def cmd_set_auth_flag(args: list[str]) -> None:
    """Set the 'requires auth parity test' flag."""
    if len(args) < 2:
        print("Usage: workflow_state.py set-auth-flag <integration_id> <YES|NO|N/A>")
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

    rows[idx][AUTH_PARITY_FLAG_COLUMN] = flag

    if flag in ("NO", "N/A"):
        rows[idx]["auth parity test passes"] = NA_MARK
        print(f"Set 'requires auth parity test' = {flag} "
              f"and 'auth parity test passes' = N/A "
              f"for '{rows[idx]['Integration ID']}'.")
    else:
        if rows[idx].get("auth parity test passes", "").strip() == NA_MARK:
            rows[idx]["auth parity test passes"] = ""
        print(f"Set 'requires auth parity test' = {flag} "
              f"for '{rows[idx]['Integration ID']}'.")

    save_csv(rows)


def cmd_set_auth(args: list[str]) -> None:
    """Set the 'Auth Details' JSON for an integration.

    Validates against the Auth Details schema, then sets the column and
    resets the workflow back to the first checkpoint (``generated manifest``)
    since changing auth invalidates downstream work.
    """
    if len(args) < 2:
        print("Usage: workflow_state.py set-auth <integration_id> '<auth_details_json>'")
        print("  The value must be valid JSON matching the Auth Details schema.")
        print("  Required keys: auth_types, config, params, notes")
        sys.exit(1)

    name = args[0]
    auth_json = " ".join(args[1:])

    schema_errors = validate_auth_detail(auth_json)
    if schema_errors:
        print("ERROR: Auth Details does not match the required schema.")
        for err in schema_errors:
            print(f"  - {err}")
        sys.exit(1)

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    rows[idx]["Auth Details"] = auth_json

    # Reset all checkpoints since auth changed.
    first_step = CHECKPOINT_COLUMNS[0]
    reset_from_step(rows[idx], first_step)
    reset_count = len(CHECKPOINT_COLUMNS)

    save_csv(rows)
    print(f"Set 'Auth Details' for '{rows[idx]['Integration ID']}'.")
    print(f"  Reset workflow to '{first_step}' "
          f"(cleared {reset_count} checkpoint(s) and the auth parity flag).")
    current = get_current_step(rows[idx])
    if current:
        print(f"  Current step: {current}")


def cmd_reset_to(args: list[str]) -> None:
    """Reset to a specific stage: clears that step and everything after it."""
    if len(args) < 2:
        print("Usage: workflow_state.py reset-to <integration_id> <step_name>")
        print("\nThis clears the named step and everything after it.")
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
        print(f"Reset to '{step}' for '{rows[idx]['Integration ID']}'.")
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
        print("Usage: workflow_state.py reset <integration_id>")
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
    print(f"Reset all workflow columns for '{rows[idx]['Integration ID']}'.")


def cmd_at_step(args: list[str]) -> None:
    """List all integrations currently at a specific step."""
    if not args:
        print("Usage: workflow_state.py at-step <step_name>")
        print(f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    step = " ".join(args)
    if step not in CHECKPOINT_COLUMNS:
        print(f"ERROR: Unknown step '{step}'.")
        print(f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    rows = load_csv()
    matches = [row["Integration ID"] for row in rows if get_current_step(row) == step]

    if matches:
        print(f"\nIntegrations currently at step '{step}' ({len(matches)}):")
        for name in matches:
            print(f"  - {name}")
    else:
        print(f"No integrations are currently at step '{step}'.")


def cmd_list(_args: list[str]) -> None:
    """List all integration IDs."""
    rows = load_csv()
    for row in rows:
        print(row.get("Integration ID", ""))


def list_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> list[dict[str, str]]:
    """Filter rows to those whose assignee matches (case-insensitive)."""
    target = assignee_name.strip().lower()
    return [row for row in rows if row.get("assignee", "").strip().lower() == target]


def has_workflow_progress(row: dict[str, str]) -> bool:
    """Return True if the row has any non-trivial workflow progress.

    Being merely assigned does NOT count as progress; the integration must
    have at least one populated JSON workflow data column, checkpoint, or
    flag (anything in WORKFLOW_COLUMNS except ``assignee``).
    """
    return any(
        row.get(c, "").strip()
        for c in WORKFLOW_COLUMNS
        if c != "assignee"
    )


def format_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> str:
    """Format a list of integrations belonging to an assignee."""
    if not rows:
        return f"No integrations found for assignee '{assignee_name}'."

    lines = [f"\nIntegrations assigned to '{assignee_name}' ({len(rows)}):"]
    for row in rows:
        name = row.get("Integration ID", "")
        if not has_workflow_progress(row):
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


def format_step_value(row: dict[str, str], step_name: str) -> str:
    """Format the value stored at ``step_name`` for ``row`` for display.

    JSON-valued columns are pretty-printed when the stored value is valid JSON.
    Empty cells display ``(not set)``. The output always begins with a header
    line identifying the integration and step.
    """
    name = row.get("Integration ID", "")
    raw = row.get(step_name, "")
    value = raw.strip()

    header = (
        f"\n{'=' * 60}\n"
        f"  {name} — {step_name}\n"
        f"{'=' * 60}"
    )

    if not value:
        return f"{header}\n  (not set)"

    if step_name in JSON_VALUED_COLUMNS:
        try:
            parsed = json.loads(value)
            pretty = json.dumps(parsed, indent=2, sort_keys=False)
            return f"{header}\n{pretty}"
        except json.JSONDecodeError:
            return f"{header}\n  {value}"

    return f"{header}\n  {value}"


def cmd_show_step(args: list[str]) -> None:
    """Show the data stored for an integration at a specific column.

    The column may be any workflow column (data, checkpoint, or flag) OR any
    data column (Integration ID, Integration File Path, Connector ID, special
    cases). JSON-valued columns are pretty-printed when possible.
    """
    if len(args) < 2:
        print("Usage: workflow_state.py show-step <integration_id> <column_name>")
        print("\nValid columns:")
        for col in DATA_COLUMNS:
            print(f"  - {col} (data)")
        for col in WORKFLOW_COLUMNS:
            print(f"  - {col}")
        sys.exit(1)

    name = args[0]
    step = " ".join(args[1:])

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    valid_steps = set(WORKFLOW_COLUMNS) | set(DATA_COLUMNS)
    if step not in valid_steps:
        print(f"ERROR: Unknown column '{step}' for integration '{rows[idx]['Integration ID']}'.")
        print(f"Valid columns: {', '.join(sorted(valid_steps))}")
        sys.exit(1)

    print(format_step_value(rows[idx], step))


def cmd_help(_args: list[str]) -> None:
    """Show help."""
    print(__doc__)


# ---------------------------------------------------------------------------
# Programmatic API (for use by AI agents / other scripts)
# ---------------------------------------------------------------------------

def get_integration_status(integration_id: str) -> dict:
    """Get the full status of an integration as a dict.

    Returns a dict with keys: ``name``, ``current_step``, ``workflow``
    (dict of col→value), ``completed_steps``, ``total_steps``,
    ``progress_pct``, and ``all_complete``.
    """
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    current = get_current_step(row)
    completed = sum(
        1 for c in CHECKPOINT_COLUMNS
        if is_checked(row.get(c, "").strip())
    )

    return {
        "name": row.get("Integration ID", ""),
        "current_step": current,
        "workflow": {col: row.get(col, "") for col in WORKFLOW_COLUMNS},
        "completed_steps": completed,
        "total_steps": len(CHECKPOINT_COLUMNS),
        "progress_pct": round(completed / len(CHECKPOINT_COLUMNS) * 100, 1),
        "all_complete": current is None and completed > 0,
    }


def markpass_integration_step(integration_id: str, step_name: str) -> dict:
    """Mark a specific step as passed for an integration. Returns status dict."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    msg = markpass_step(row, step_name)

    if msg.startswith("ERROR"):
        return {"error": msg}

    # Auto-skip auth parity if not required
    next_step = get_current_step(row)
    if next_step == "auth parity test passes":
        flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
        if flag in ("NO", "N/A"):
            row["auth parity test passes"] = NA_MARK

    save_csv(rows)

    return {
        "message": msg,
        "completed_step": step_name,
        "current_step": get_current_step(row),
    }


def fail_integration_step(integration_id: str, step_name: str) -> dict:
    """Mark a step as failed and reset subsequent steps. Returns status dict."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    try:
        reset_from_step(rows[idx], step_name)
        save_csv(rows)
        return {
            "message": f"Reset '{step_name}' and subsequent steps.",
            "current_step": get_current_step(rows[idx]),
        }
    except ValueError as e:
        return {"error": str(e)}


def reset_integration_to_step(integration_id: str, step_name: str) -> dict:
    """Reset to a specific stage (clears that step and everything after it)."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    try:
        reset_from_step(rows[idx], step_name)
        save_csv(rows)
        return {
            "message": f"Reset to '{step_name}' — cleared it and all subsequent steps.",
            "current_step": get_current_step(rows[idx]),
        }
    except ValueError as e:
        return {"error": str(e)}


def set_integration_auth(integration_id: str, auth_detail_json: str) -> dict:
    """Set the 'Auth Details' JSON and reset workflow to first checkpoint.

    Validates the value against the Auth Details schema. On success, sets the
    column and resets all checkpoints + the auth parity flag.
    """
    schema_errors = validate_auth_detail(auth_detail_json)
    if schema_errors:
        return {"error": "Auth Details schema validation failed:\n" + "\n".join(f"  - {e}" for e in schema_errors)}

    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    row["Auth Details"] = auth_detail_json
    reset_from_step(row, CHECKPOINT_COLUMNS[0])
    save_csv(rows)

    return {
        "message": f"Set 'Auth Details' for '{row.get('Integration ID', '')}' and reset workflow to '{CHECKPOINT_COLUMNS[0]}'.",
        "current_step": get_current_step(row),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

COMMANDS = {
    "status": cmd_status,
    "status-all": cmd_status_all,
    "dashboard": cmd_dashboard,
    "set-assignee": cmd_set_assignee,
    "set-auth": cmd_set_auth,
    "set-inputs": cmd_set_inputs,
    "set-params-for-test": cmd_set_params_for_test,
    "set-shared-params": cmd_set_shared_params,
    "markpass": cmd_markpass,
    "fail": cmd_fail,
    "set-auth-flag": cmd_set_auth_flag,
    "reset-to": cmd_reset_to,
    "reset": cmd_reset,
    "at-step": cmd_at_step,
    "list": cmd_list,
    "list-by-assignee": cmd_list_by_assignee,
    "show-step": cmd_show_step,
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
