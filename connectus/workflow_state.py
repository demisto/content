#!/usr/bin/env python3
"""
Workflow State Machine for connectus-migration-pipeline.csv (UNIFIED 16-STEP MODEL)

This script manages the workflow tracking columns in the CSV. It models the
workflow as a single linear 16-step sequence, strictly gated. Setting any
step at-or-behind the current step resets every step that follows it
("cascade reset"). The ONLY exception is `set-assignee`, which is treated as
an administrative update and never resets later steps.

State is purely derived from row contents — there is no explicit
"current step" pointer column. The current step is defined as
``current_step(row) = first STEPS[i] where not is_done(row, STEPS[i])``.

CSV column groups:

Identity / metadata columns (4) — NOT managed by this script:
  1. Integration ID
  2. Integration File Path
  3. Connector ID
  4. special cases

Workflow columns (16) — the unified ordered sequence (see ``STEPS``):
   1. assignee                              (data, admin)
   2. Auth Details                          (data, JSON)
   3. Params to Commands                    (data, JSON)
   4. Params for test with default in code  (data, JSON)
   5. Params same in other handlers         (data, JSON, OPTIONAL — `skip`)
   6. generated manifest                    (checkpoint)
   7. run manifest make validate            (checkpoint)
   8. wrote/checked code                    (checkpoint)
   9. shadowed command test passes          (checkpoint)
  10. write tests                           (checkpoint)
  11. precommit/validate/unit tests passed  (checkpoint)
  12. requires auth parity test             (flag: YES/NO/N/A)
  13. auth parity test passes               (checkpoint, auto-N/A from #12)
  14. param parity test passes              (checkpoint)
  15. code reviewed                         (checkpoint)
  16. code merged                           (checkpoint)

Rules:
  - Strict ordering: any set/markpass/skip targeting a step AHEAD of the
    current step is rejected.
  - Cascade reset: any set/markpass/skip targeting a step AT-OR-BEHIND the
    current step writes the new value AND clears every step after it.
    (set-assignee is the ONLY exception — see ``cmd_set_assignee``.)
  - Optional step #5 may be `skip`-ped (writes the sentinel "N/A").
  - Flag step #12: setting it to NO/N/A auto-writes "N/A" into step #13.
  - Normalization on read AND write: any later-step value past the first
    incomplete step is auto-cleared. A one-line stderr warning is printed
    per row that gets normalized.

Usage examples:
  python3 connectus/workflow_state.py status "Cisco Spark"
  python3 connectus/workflow_state.py status-all
  python3 connectus/workflow_state.py dashboard
  python3 connectus/workflow_state.py next
  python3 connectus/workflow_state.py next "Cisco Spark"
  python3 connectus/workflow_state.py next --all
  python3 connectus/workflow_state.py set-assignee "Cisco Spark" "John Doe"
  python3 connectus/workflow_state.py set-auth "Cisco Spark" '<json>'
  python3 connectus/workflow_state.py set-params-to-commands "Cisco Spark" '<json>'
  python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '<json>'
  python3 connectus/workflow_state.py set-shared-params "Cisco Spark" '<json>'
  python3 connectus/workflow_state.py skip "Cisco Spark" "Params same in other handlers"
  python3 connectus/workflow_state.py markpass "Cisco Spark" "wrote/checked code"
  python3 connectus/workflow_state.py set-auth-flag "Cisco Spark" YES
  python3 connectus/workflow_state.py fail "Cisco Spark" "write tests"
  python3 connectus/workflow_state.py reset-to "Cisco Spark" "wrote/checked code"
  python3 connectus/workflow_state.py reset "Cisco Spark"
  python3 connectus/workflow_state.py at-step "wrote/checked code"
  python3 connectus/workflow_state.py list
  python3 connectus/workflow_state.py list-by-assignee "John Doe"
  python3 connectus/workflow_state.py list-connectors
  python3 connectus/workflow_state.py list-by-connector "abcd1234"
  python3 connectus/workflow_state.py set-assignee-by-connector "abcd1234" "John Doe"
  python3 connectus/workflow_state.py next --mine
  python3 connectus/workflow_state.py next --connector "abcd1234"
  python3 connectus/workflow_state.py next --connector "abcd1234" --mine
  python3 connectus/workflow_state.py show-step "Cisco Spark" "Params to Commands"
"""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "connectus", "connectus-migration-pipeline.csv")

CHECK = "✅"
FAIL_MARK = "❌"
NA_MARK = "N/A"

# Identity / metadata columns (NOT part of the workflow, never cleared).
DATA_COLUMNS = [
    "Integration ID",
    "Integration File Path",
    "Connector ID",
    "special cases",
]

VALID_FLAG_VALUES = {"YES", "NO", "N/A"}

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


# ---------------------------------------------------------------------------
# The unified 16-step sequence (single source of truth)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """A single step in the unified workflow sequence."""

    index: int               # 1..16
    name: str                # CSV column name AND user-facing identifier
    kind: str                # "data" | "checkpoint" | "flag"
    optional: bool           # True only for #5
    setter: Optional[str]    # CLI subcommand for setting; None for pure markpass
    description: str         # short human-readable summary used by `next`


# Forward declare validators set below.
_NoOp = lambda _v: []  # noqa: E731 — placeholder set after STEPS is defined


def _validate_assignee(value: str) -> list[str]:
    if not value.strip():
        return ["Assignee cannot be empty."]
    return []


def _validate_json(value: str, what: str) -> list[str]:
    try:
        json.loads(value)
    except json.JSONDecodeError as e:
        return [f"'{what}' must be valid JSON. Parse error: {e}"]
    return []


def _validate_flag(value: str) -> list[str]:
    v = value.strip().upper()
    if v not in VALID_FLAG_VALUES:
        return [f"Flag must be one of YES, NO, N/A. Got: '{value}'"]
    return []


STEPS: list[Step] = [
    Step(1, "assignee", "data", False, "set-assignee",
         "Assign an owner to drive this integration's migration."),
    Step(2, "Auth Details", "data", False, "set-auth",
         "Record the auth classification JSON (validated against the Auth Details schema)."),
    Step(3, "Params to Commands", "data", False, "set-params-to-commands",
         "Map each integration command to the parameter IDs it consumes (JSON)."),
    Step(4, "Params for test with default in code", "data", False, "set-params-for-test",
         "List the param IDs whose defaults live in the integration source (JSON)."),
    Step(5, "Params same in other handlers", "data", True, "set-shared-params",
         "Optional: list params shared verbatim with sibling handlers (or `skip`)."),
    Step(6, "generated manifest", "checkpoint", False, None,
         "Generate the ConnectUs manifest YAML for the integration."),
    Step(7, "run manifest make validate", "checkpoint", False, None,
         "Run `make validate` on the generated manifest."),
    Step(8, "wrote/checked code", "checkpoint", False, None,
         "Write or review the integration source code."),
    Step(9, "shadowed command test passes", "checkpoint", False, None,
         "Verify there are no shadowed/conflicting commands in the same connector."),
    Step(10, "write tests", "checkpoint", False, None,
         "Author unit tests for the integration."),
    Step(11, "precommit/validate/unit tests passed", "checkpoint", False, None,
         "Run pre-commit, validate, and unit tests via demisto-sdk pre-commit."),
    Step(12, "requires auth parity test", "flag", False, "set-auth-flag",
         "Decide whether the integration needs an auth-parity test (YES/NO/N/A)."),
    Step(13, "auth parity test passes", "checkpoint", False, None,
         "Run the auth-parity test (auto-N/A when step 12 is NO/N/A)."),
    Step(14, "param parity test passes", "checkpoint", False, None,
         "Run the parameter-parity test."),
    Step(15, "code reviewed", "checkpoint", False, None,
         "Complete code review."),
    Step(16, "code merged", "checkpoint", False, None,
         "Merge the integration to the branch."),
]

assert len(STEPS) == 16, "STEPS must have exactly 16 entries."

STEP_BY_NAME: dict[str, Step] = {s.name: s for s in STEPS}
STEP_BY_INDEX: dict[int, Step] = {s.index: s for s in STEPS}

# Derived constants — NEVER hand-maintain these; they reflect STEPS only.
WORKFLOW_COLUMNS: list[str] = [s.name for s in STEPS]
WORKFLOW_DATA_COLUMNS: list[str] = [s.name for s in STEPS if s.kind == "data"]
CHECKPOINT_COLUMNS: list[str] = [s.name for s in STEPS if s.kind == "checkpoint"]
JSON_VALUED_COLUMNS: set[str] = {
    s.name for s in STEPS
    if s.kind == "data" and s.name != "assignee"
}
AUTH_PARITY_FLAG_COLUMN: str = "requires auth parity test"
ALL_COLUMNS: list[str] = DATA_COLUMNS + WORKFLOW_COLUMNS
EXPECTED_COLUMN_COUNT: int = len(ALL_COLUMNS)

# Steps that look like they could be markpass'd but actually need a setter.
NON_CHECKPOINT_STEPS: dict[str, str] = {
    s.name: s.setter
    for s in STEPS
    if s.setter is not None
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class WorkflowError(Exception):
    """User-facing workflow violation. Caller prints `.message` and exits 1."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# State predicates
# ---------------------------------------------------------------------------

def is_checked(value: str) -> bool:
    """Whether a checkpoint cell value represents 'done'."""
    v = value.strip()
    return v in (CHECK, "✅", "YES", NA_MARK, "N/A", "true", "True", "done", "Done", "DONE")


def is_done(row: dict[str, str], step: Step) -> bool:
    """The unified completion predicate for any step kind."""
    val = row.get(step.name, "").strip()
    if step.kind == "data":
        return val != ""
    if step.kind == "flag":
        return val.upper() in VALID_FLAG_VALUES
    if step.kind == "checkpoint":
        return is_checked(val)
    raise AssertionError(f"Unknown step kind: {step.kind!r}")


def current_step(row: dict[str, str]) -> Optional[Step]:
    """First step that is not yet done; ``None`` if every step is done."""
    for step in STEPS:
        if not is_done(row, step):
            return step
    return None


# Backward-compatible alias for the legacy public name. Returns the step name
# (str) rather than the Step object.
def get_current_step(row: dict[str, str]) -> Optional[str]:
    """Legacy wrapper: returns the current step's name (or None)."""
    s = current_step(row)
    return s.name if s is not None else None


def get_step(name: str) -> Step:
    """Look up a Step by name; raise ``WorkflowError`` if unknown."""
    step = STEP_BY_NAME.get(name)
    if step is None:
        raise WorkflowError(
            f"Unknown step: '{name}'.\n"
            f"  Valid steps:\n" + "\n".join(f"    {s.index:2d}. {s.name}" for s in STEPS)
        )
    return step


def get_step_index(step_name: str) -> int:
    """Legacy: return the 0-based index of a checkpoint step within
    ``CHECKPOINT_COLUMNS`` (preserves old API for any external callers)."""
    try:
        return CHECKPOINT_COLUMNS.index(step_name)
    except ValueError:
        raise ValueError(
            f"Unknown checkpoint step: '{step_name}'. "
            f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}"
        )


# ---------------------------------------------------------------------------
# Cascade reset and normalization
# ---------------------------------------------------------------------------

def reset_after(row: dict[str, str], step: Step) -> list[str]:
    """Clear every step strictly after ``step``. Returns the cleared columns."""
    cleared: list[str] = []
    for s in STEPS:
        if s.index > step.index:
            if row.get(s.name, "") != "":
                cleared.append(s.name)
            row[s.name] = ""
    return cleared


def normalize_row(row: dict[str, str]) -> list[str]:
    """Auto-clear any value past the first incomplete step.

    Returns the list of column names that were cleared. The caller is
    responsible for printing a stderr warning if the list is non-empty.
    """
    # Walk steps in order; once we find the first incomplete one, every
    # subsequent step's column must be empty.
    cleared: list[str] = []
    found_incomplete = False
    for step in STEPS:
        if not found_incomplete:
            if not is_done(row, step):
                found_incomplete = True
            continue
        # We're past the first incomplete step; any value here is contradictory.
        if row.get(step.name, "").strip() != "":
            cleared.append(step.name)
            row[step.name] = ""
    return cleared


def _normalize_rows_with_warning(rows: list[dict[str, str]], context: str) -> None:
    """Normalize each row in place. Print one stderr warning per modified row."""
    for row in rows:
        cleared = normalize_row(row)
        if cleared:
            integration_id = row.get("Integration ID", "<unknown>")
            print(
                f"WARNING: normalized {context} row '{integration_id}': "
                f"cleared columns {cleared} (values were past the first incomplete step).",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# CSV I/O (with normalization on read AND write)
# ---------------------------------------------------------------------------

def load_csv() -> list[dict[str, str]]:
    """Load the CSV and return list of row dicts. Normalizes on read."""
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
        rows = list(reader)

    _normalize_rows_with_warning(rows, context="loaded")
    return rows


def save_csv(rows: list[dict[str, str]]) -> None:
    """Write rows back to CSV atomically. Normalizes on write."""
    if not rows:
        return

    _normalize_rows_with_warning(rows, context="saved")

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
            prefix=".connectus-migration-pipeline.",
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
    """Find a row by Integration ID (case-insensitive). Returns index or None."""
    name_lower = integration_id.lower().strip()
    for i, row in enumerate(rows):
        if row.get("Integration ID", "").strip().lower() == name_lower:
            return i
    return None


# ---------------------------------------------------------------------------
# Auth Details schema validation
# ---------------------------------------------------------------------------

def validate_auth_detail(value: str) -> list[str]:
    """Validate Auth Details JSON shape. Returns list of errors ([] = valid)."""
    errors: list[str] = []

    try:
        detail = json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]

    if not isinstance(detail, dict):
        return [f"Expected a JSON object, got {type(detail).__name__}"]

    required_keys = {"auth_types", "config", "params", "notes"}
    missing = required_keys - set(detail.keys())
    if missing:
        errors.append(f"Missing required keys: {', '.join(sorted(missing))}")
        return errors

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

    if not isinstance(detail["config"], str):
        errors.append(f"'config' must be a string, got {type(detail['config']).__name__}")

    if not isinstance(detail["params"], dict):
        errors.append(f"'params' must be a dict, got {type(detail['params']).__name__}")
    else:
        for param_name, param_data in detail["params"].items():
            if not isinstance(param_data, dict):
                errors.append(f"params['{param_name}']: expected object, got {type(param_data).__name__}")
                continue
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

            if "xsoar_type" not in param_data:
                errors.append(f"params['{param_name}']: missing 'xsoar_type'")
            elif not isinstance(param_data["xsoar_type"], int):
                errors.append(
                    f"params['{param_name}']: 'xsoar_type' must be int, "
                    f"got {type(param_data['xsoar_type']).__name__}"
                )

            if "required" not in param_data:
                errors.append(f"params['{param_name}']: missing 'required'")
            elif not isinstance(param_data["required"], bool):
                errors.append(
                    f"params['{param_name}']: 'required' must be bool, "
                    f"got {type(param_data['required']).__name__}"
                )

    if detail["notes"] is not None and not isinstance(detail["notes"], str):
        errors.append(f"'notes' must be a string or null, got {type(detail['notes']).__name__}")

    return errors


# ---------------------------------------------------------------------------
# Unified dispatch — the heart of the cascade-reset rule
# ---------------------------------------------------------------------------

def _can_advance_to(row: dict[str, str], target: Step) -> tuple[bool, str]:
    """True iff every step strictly before ``target`` is done."""
    for s in STEPS:
        if s.index >= target.index:
            break
        if not is_done(row, s):
            verb = s.setter if s.setter else "markpass"
            return False, (
                f"Cannot advance to '{target.name}' (step {target.index}/16) yet — "
                f"prior step #{s.index} '{s.name}' is not done.\n"
                f"  Run: workflow_state.py {verb} <id> "
                + ("<value>" if s.setter else f'"{s.name}"')
            )
    return True, ""


def apply_step_action(
    row: dict[str, str],
    target: Step,
    new_value: str,
    *,
    verb: str,
) -> tuple[list[str], bool]:
    """Apply a step action with cascade-reset semantics.

    Returns ``(cleared_columns, was_no_op)``.

    Behavior:
      - If ``target`` is AHEAD of the current step: raise ``WorkflowError``.
      - If ``target`` is AT current step: write the value (no clearing — there
        was nothing past current that wasn't already empty).
      - If ``target`` is BEHIND current (or is the same as current and was
        already done): write the new value AND ``reset_after(target)``.
      - Special case for the flag step #12: setting the same value is a no-op
        (no reset).

    NOTE: This function does NOT enforce the special ``set-assignee`` carve-out.
    The caller (``cmd_set_assignee``) bypasses this dispatch and writes
    the assignee directly, on purpose. See override #5 in the design overrides.
    """
    cur = current_step(row)
    cur_idx = cur.index if cur is not None else len(STEPS) + 1

    # AHEAD of current — reject.
    if cur is not None and target.index > cur_idx:
        raise WorkflowError(
            f"Cannot {verb} '{target.name}' (step {target.index}/16) yet — "
            f"current step is #{cur.index} '{cur.name}'.\n"
            f"  Complete it first via "
            f"'{cur.setter or 'markpass'}'."
        )

    # Flag-step idempotency: same value, no reset.
    if target.kind == "flag":
        existing = row.get(target.name, "").strip().upper()
        if existing == new_value.strip().upper() and existing in VALID_FLAG_VALUES:
            return [], True

    # AT or BEHIND current. Write then cascade-reset.
    row[target.name] = new_value
    cleared = reset_after(row, target)
    return cleared, False


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _summary_value(step: Step, raw: str) -> str:
    """Short inline display for status output."""
    val = raw.strip()
    if not val:
        if step.kind == "checkpoint":
            return "⬜"
        return "(not set)"
    if step.kind == "data" and step.name in JSON_VALUED_COLUMNS:
        # Long JSON values get summarized.
        if len(val) > 60:
            return f"{val[:57]}… (set; show-step for full)"
        return val
    return val


def format_status(row: dict[str, str]) -> str:
    """Format the workflow status of a single integration."""
    integration_id = row.get("Integration ID", "")
    cur = current_step(row)
    done_count = sum(1 for s in STEPS if is_done(row, s))

    lines = [
        f"\n{'=' * 60}",
        f"  {integration_id}",
        f"{'=' * 60}",
    ]

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

    lines.append(f"  Workflow ([{done_count}/16]):")
    lines.append("  " + "-" * 40)
    for step in STEPS:
        marker = " "
        if cur is not None and step.index == cur.index:
            marker = "▶"
        raw = row.get(step.name, "")
        display = _summary_value(step, raw)
        lines.append(f"  {marker}{step.index:2d}. {step.name:38s} : {display}")

    lines.append("")
    if cur is None:
        if has_workflow_progress(row):
            lines.append("  🎉 All 16 steps complete!")
        else:
            lines.append("  ⏳ Not started")
    else:
        verb = cur.setter or "markpass"
        lines.append(f"  ➡️  Current step: #{cur.index} {cur.name} (run: {verb})")

    return "\n".join(lines)


def format_dashboard_row(row: dict[str, str]) -> Optional[str]:
    """Compact dashboard line. Returns None for not-started rows."""
    if not has_workflow_progress(row):
        return None

    integration_id = row.get("Integration ID", "")
    cur = current_step(row)
    done_count = sum(1 for s in STEPS if is_done(row, s))
    total = len(STEPS)

    bar = "".join("█" if is_done(row, s) else "░" for s in STEPS)
    status = cur.name if cur is not None else "✅ DONE"
    return f"  {integration_id:45s} [{bar}] {done_count}/{total}  → {status}"


def format_step_value(row: dict[str, str], step_name: str) -> str:
    """Pretty-print the value at ``step_name`` for ``row``."""
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


# ---------------------------------------------------------------------------
# Helpers used by multiple commands
# ---------------------------------------------------------------------------

def has_workflow_progress(row: dict[str, str]) -> bool:
    """Return True if the row has any non-trivial workflow progress.

    Being merely assigned does NOT count as progress.
    """
    return any(
        row.get(s.name, "").strip()
        for s in STEPS
        if s.name != "assignee"
    )


def list_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> list[dict[str, str]]:
    """Filter rows to those whose assignee matches (case-insensitive)."""
    target = assignee_name.strip().lower()
    return [row for row in rows if row.get("assignee", "").strip().lower() == target]


def list_by_connector(rows: list[dict[str, str]], connector_id: str) -> list[dict[str, str]]:
    """Filter rows to those whose Connector ID matches (case-insensitive, trimmed)."""
    target = connector_id.strip().lower()
    return [
        row for row in rows
        if row.get("Connector ID", "").strip().lower() == target
    ]


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
            cur = current_step(row)
            step_display = cur.name if cur is not None else "✅ DONE"
        lines.append(f"  - {name:45s} → {step_display}")
    return "\n".join(lines)


def _git_user_name() -> Optional[str]:
    """Return ``git config user.name`` or None if unavailable."""
    try:
        out = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True, text=True, check=False, timeout=5,
        )
        name = out.stdout.strip()
        return name or None
    except (FileNotFoundError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Backward-compat shims (for old call sites and tests)
# ---------------------------------------------------------------------------

def reset_from_step(row: dict[str, str], step_name: str) -> None:
    """Legacy API: clear ``step_name`` and every later step.

    Equivalent to ``fail/reset-to step_name`` in the unified model.
    """
    step = STEP_BY_NAME.get(step_name)
    if step is None:
        raise ValueError(
            f"Unknown step: '{step_name}'. "
            f"Valid steps: {', '.join(WORKFLOW_COLUMNS)}"
        )
    # Clear the named step and everything after.
    prev_index = step.index - 1
    if prev_index < 1:
        # Clear all workflow columns
        for s in STEPS:
            row[s.name] = ""
        return
    prev = STEP_BY_INDEX[prev_index]
    row[step.name] = ""
    reset_after(row, prev)
    # Note: reset_after(prev) clears everything strictly after prev, which is
    # step.index and onward. We've also explicitly cleared step.name above
    # in case it was already cleared but we want to be belt-and-suspenders.


def markpass_step(row: dict[str, str], step_name: str) -> str:
    """Legacy API: mark a checkpoint step as passed. Returns a status message."""
    integration_id = row.get("Integration ID", "")

    if step_name in NON_CHECKPOINT_STEPS:
        correct_cmd = NON_CHECKPOINT_STEPS[step_name]
        return (
            f"ERROR: '{step_name}' is not a pass/fail checkpoint.\n"
            f"  Use '{correct_cmd}' instead.\n"
            f"  Example: workflow_state.py {correct_cmd} "
            f"\"{integration_id}\" <value>"
        )

    step = STEP_BY_NAME.get(step_name)
    if step is None:
        raise ValueError(
            f"Unknown checkpoint step: '{step_name}'. "
            f"Valid steps: {', '.join(CHECKPOINT_COLUMNS)}"
        )

    # Already done?
    if is_done(row, step):
        return f"'{step_name}' is already marked as passed for '{integration_id}'."

    # Special handling for the flag-gated #13 auth parity test.
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

    # Verify all prior steps are done (including data steps now).
    ok, reason = _can_advance_to(row, step)
    if not ok:
        cur = current_step(row)
        cur_name = cur.name if cur else "(none)"
        return (
            f"ERROR: Cannot mark '{step_name}' as passed — "
            f"you are not up to that step yet.\n"
            f"  Current step: '{cur_name}'\n"
            f"  {reason}"
        )

    row[step.name] = CHECK
    return f"✅ '{step_name}' marked as passed for '{integration_id}'."


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_status(args: list[str]) -> None:
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
    rows = load_csv()
    found = False
    for row in rows:
        if has_workflow_progress(row):
            print(format_status(row))
            found = True
    if not found:
        print("No integrations have workflow progress yet.")


def cmd_dashboard(_args: list[str]) -> None:
    rows = load_csv()
    print(f"\n{'=' * 80}")
    print("  WORKFLOW DASHBOARD")
    print(f"{'=' * 80}")
    print(f"  {'Integration ID':45s} {'Progress':18s}  → Current Step")
    print(f"  {'-' * 75}")

    in_progress = 0
    completed = 0
    not_started = 0

    for row in rows:
        line = format_dashboard_row(row)
        if line:
            print(line)
            if current_step(row) is not None:
                in_progress += 1
            else:
                completed += 1
        else:
            not_started += 1

    print(f"\n  Summary: {completed} complete, {in_progress} in progress, "
          f"{not_started} not started")


def _set_step_via_dispatch(
    row: dict[str, str],
    target: Step,
    new_value: str,
    verb: str,
) -> str:
    """Apply step action and return a user-facing message."""
    integration_id = row.get("Integration ID", "")
    cleared, no_op = apply_step_action(row, target, new_value, verb=verb)
    if no_op:
        return f"'{target.name}' already set to '{new_value}' for '{integration_id}'. No change."
    msg = f"Set '{target.name}' (step {target.index}/16) for '{integration_id}'."
    if cleared:
        msg += f"\n  Cleared {len(cleared)} subsequent step(s): {cleared}"
    return msg


def _resolve_row_or_exit(rows: list[dict[str, str]], name: str) -> int:
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)
    return idx


def _set_json_data_step(args: list[str], step_name: str, setter_cmd: str) -> None:
    """Shared CLI handler for set-auth / set-params-* / set-shared-params."""
    if len(args) < 2:
        print(f"Usage: workflow_state.py {setter_cmd} <integration_id> '<json>'")
        print(f"  The value must be valid JSON (see connectus/column-schemas.md).")
        sys.exit(1)

    name = args[0]
    raw = " ".join(args[1:])

    # JSON validation
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: '{step_name}' must be valid JSON.")
        print(f"  Got: {raw}")
        print(f"  Parse error: {e}")
        print(f"  Example: workflow_state.py {setter_cmd} \"{name}\" '{{}}'")
        sys.exit(1)

    # set-auth has a richer schema check on top.
    if step_name == "Auth Details":
        schema_errors = validate_auth_detail(raw)
        if schema_errors:
            print("ERROR: Auth Details does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    target = STEP_BY_NAME[step_name]

    try:
        msg = _set_step_via_dispatch(rows[idx], target, raw, verb=setter_cmd)
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    save_csv(rows)
    print(msg)
    cur = current_step(rows[idx])
    if cur is not None:
        print(f"  Current step: #{cur.index} {cur.name}")
    elif has_workflow_progress(rows[idx]):
        print("  🎉 All 16 steps complete!")


def cmd_set_auth(args: list[str]) -> None:
    _set_json_data_step(args, "Auth Details", "set-auth")


def cmd_set_params_to_commands(args: list[str]) -> None:
    _set_json_data_step(args, "Params to Commands", "set-params-to-commands")


def cmd_set_params_for_test(args: list[str]) -> None:
    _set_json_data_step(args, "Params for test with default in code", "set-params-for-test")


def cmd_set_shared_params(args: list[str]) -> None:
    _set_json_data_step(args, "Params same in other handlers", "set-shared-params")


def cmd_set_assignee(args: list[str]) -> None:
    """Set the assignee for an integration.

    SPECIAL CARVE-OUT (override #5 of the design): set-assignee is the ONLY
    setter that does NOT trigger ``reset_after``. Re-assigning an integration
    is administrative — it must not wipe migration progress.
    """
    if len(args) < 2:
        print("Usage: workflow_state.py set-assignee <integration_id> <assignee_name>")
        sys.exit(1)

    name = args[0]
    assignee = " ".join(args[1:])

    if not assignee.strip():
        print("ERROR: Assignee cannot be empty.")
        sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)

    # Direct write — no apply_step_action, no cascade reset.
    rows[idx]["assignee"] = assignee
    save_csv(rows)
    print(f"Set assignee for '{rows[idx]['Integration ID']}' to: {assignee}")
    cur = current_step(rows[idx])
    if cur is not None:
        print(f"  Current step: #{cur.index} {cur.name}")


def cmd_set_auth_flag(args: list[str]) -> None:
    """Set the 'requires auth parity test' flag (step #12).

    When the new value is NO/N/A, also write 'N/A' into step #13 so the
    user is auto-advanced past it (per design §1.4).
    """
    if len(args) < 2:
        print("Usage: workflow_state.py set-auth-flag <integration_id> <YES|NO|N/A>")
        sys.exit(1)

    name = args[0]
    flag = args[1].upper().strip()

    if flag not in VALID_FLAG_VALUES:
        print(f"ERROR: Flag must be YES, NO, or N/A. Got: '{args[1]}'")
        sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    target = STEP_BY_NAME[AUTH_PARITY_FLAG_COLUMN]

    try:
        cleared, no_op = apply_step_action(rows[idx], target, flag, verb="set-auth-flag")
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    # After the cascade reset, write step #13 if NO/N/A.
    auth_parity_step = STEP_BY_NAME["auth parity test passes"]
    if flag in ("NO", "N/A"):
        rows[idx][auth_parity_step.name] = NA_MARK

    save_csv(rows)

    if no_op:
        print(f"'{AUTH_PARITY_FLAG_COLUMN}' already set to '{flag}' "
              f"for '{rows[idx]['Integration ID']}'. No change.")
    else:
        print(f"Set '{AUTH_PARITY_FLAG_COLUMN}' = {flag} "
              f"for '{rows[idx]['Integration ID']}'.")
        if cleared:
            print(f"  Cleared {len(cleared)} subsequent step(s): {cleared}")
        if flag in ("NO", "N/A"):
            print(f"  Auto-set 'auth parity test passes' = N/A.")

    cur = current_step(rows[idx])
    if cur is not None:
        print(f"  Current step: #{cur.index} {cur.name}")
    elif has_workflow_progress(rows[idx]):
        print("  🎉 All 16 steps complete!")


def cmd_markpass(args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: workflow_state.py markpass <integration_id> <step_name>")
        print("\nCheckpoint steps (in order):")
        for s in STEPS:
            if s.kind == "checkpoint":
                print(f"  {s.index:2d}. {s.name}")
        print("\nNon-checkpoint columns (use a different command):")
        for step_name, cmd in NON_CHECKPOINT_STEPS.items():
            print(f"  - '{step_name}' → use '{cmd}'")
        sys.exit(1)

    name = args[0]
    step_name = " ".join(args[1:])

    # Reject non-checkpoint steps with corrective guidance.
    if step_name in NON_CHECKPOINT_STEPS:
        correct = NON_CHECKPOINT_STEPS[step_name]
        print(
            f"ERROR: '{step_name}' is not a pass/fail checkpoint.\n"
            f"  Use '{correct}' instead.\n"
            f"  Example: workflow_state.py {correct} \"{name}\" <value>"
        )
        sys.exit(1)

    target = STEP_BY_NAME.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid checkpoint steps: {', '.join(CHECKPOINT_COLUMNS)}")
        sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    row = rows[idx]

    # Special prerequisites for #13.
    if step_name == "auth parity test passes":
        flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
        if flag == "":
            print(
                f"ERROR: Cannot mark '{step_name}' as passed — "
                f"'requires auth parity test' flag is not set.\n"
                f"  Use 'set-auth-flag' first.\n"
                f"  Example: workflow_state.py set-auth-flag "
                f"\"{row['Integration ID']}\" YES"
            )
            sys.exit(1)
        if flag in ("NO", "N/A"):
            # Already auto-N/A'd; treat as already done.
            row[step_name] = NA_MARK
            save_csv(rows)
            print(f"'{step_name}' set to N/A (auth parity test not required).")
            return

    # Already done — re-pass means cascade-reset behind current.
    try:
        cleared, no_op = apply_step_action(row, target, CHECK, verb="markpass")
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    save_csv(rows)
    if no_op:
        print(f"'{step_name}' already passed. No change.")
    else:
        print(f"✅ '{step_name}' (step {target.index}/16) marked as passed "
              f"for '{row['Integration ID']}'.")
        if cleared:
            print(f"  Cleared {len(cleared)} subsequent step(s): {cleared}")

    cur = current_step(row)
    if cur is not None:
        print(f"  Next step: #{cur.index} {cur.name}")
    elif has_workflow_progress(row):
        print("  🎉 All 16 steps complete!")


def cmd_skip(args: list[str]) -> None:
    """Mark an OPTIONAL step as skipped (writes 'N/A' into the column)."""
    if len(args) < 2:
        print("Usage: workflow_state.py skip <integration_id> <step_name>")
        print("Skippable (optional) steps:")
        for s in STEPS:
            if s.optional:
                print(f"  {s.index:2d}. {s.name}")
        sys.exit(1)

    name = args[0]
    step_name = " ".join(args[1:])

    target = STEP_BY_NAME.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        sys.exit(1)

    if not target.optional:
        print(f"ERROR: step '{step_name}' is not optional and cannot be skipped.")
        sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    row = rows[idx]

    try:
        cleared, _no_op = apply_step_action(row, target, NA_MARK, verb="skip")
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    save_csv(rows)
    print(f"✓ Skipped step {target.index} ('{target.name}') for '{row['Integration ID']}'.")
    if cleared:
        print(f"  Cleared {len(cleared)} subsequent step(s): {cleared}")
    cur = current_step(row)
    if cur is not None:
        print(f"  Next step: #{cur.index} {cur.name}")


def _do_reset_to(rows: list[dict[str, str]], idx: int, step_name: str, verb: str) -> None:
    """Shared implementation for ``fail`` and ``reset-to``: clear step + after."""
    target = STEP_BY_NAME.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid steps: {', '.join(WORKFLOW_COLUMNS)}")
        sys.exit(1)

    row = rows[idx]
    integration_id = row.get("Integration ID", "")

    # Clear named step plus everything after (i.e. reset_after(prev)).
    if target.index == 1:
        for s in STEPS:
            row[s.name] = ""
    else:
        prev = STEP_BY_INDEX[target.index - 1]
        row[target.name] = ""
        reset_after(row, prev)

    save_csv(rows)
    print(f"{verb}: cleared step {target.index} ('{target.name}') and all "
          f"subsequent steps for '{integration_id}'.")
    cur = current_step(row)
    if cur is not None:
        print(f"  Current step is now: #{cur.index} {cur.name}")


def cmd_fail(args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: workflow_state.py fail <integration_id> <step_name>")
        print(f"Valid steps: {', '.join(WORKFLOW_COLUMNS)}")
        sys.exit(1)
    name = args[0]
    step_name = " ".join(args[1:])
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    _do_reset_to(rows, idx, step_name, verb="Reset (fail)")


def cmd_reset_to(args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: workflow_state.py reset-to <integration_id> <step_name>")
        print(f"Valid steps: {', '.join(WORKFLOW_COLUMNS)}")
        sys.exit(1)
    name = args[0]
    step_name = " ".join(args[1:])
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    _do_reset_to(rows, idx, step_name, verb="Reset-to")


def cmd_reset(args: list[str]) -> None:
    """Clear all 16 workflow columns. Identity columns and assignee preserved.

    Per override #10: ``reset`` clears ALL workflow columns (assignee
    included), per the existing behavior.
    """
    if not args:
        print("Usage: workflow_state.py reset <integration_id>")
        sys.exit(1)

    name = args[0]
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)

    for col in WORKFLOW_COLUMNS:
        rows[idx][col] = ""

    save_csv(rows)
    print(f"Reset all workflow columns for '{rows[idx]['Integration ID']}'.")


def cmd_at_step(args: list[str]) -> None:
    """List all integrations currently at a specific step."""
    if not args:
        print("Usage: workflow_state.py at-step <step_name>")
        print(f"Valid steps: {', '.join(WORKFLOW_COLUMNS)}")
        sys.exit(1)

    step_name = " ".join(args)
    if step_name not in STEP_BY_NAME:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid steps: {', '.join(WORKFLOW_COLUMNS)}")
        sys.exit(1)

    rows = load_csv()
    matches = [
        row["Integration ID"]
        for row in rows
        if (cur := current_step(row)) is not None and cur.name == step_name
    ]

    if matches:
        print(f"\nIntegrations currently at step '{step_name}' ({len(matches)}):")
        for name in matches:
            print(f"  - {name}")
    else:
        print(f"No integrations are currently at step '{step_name}'.")


def cmd_list(_args: list[str]) -> None:
    rows = load_csv()
    for row in rows:
        print(row.get("Integration ID", ""))


def cmd_list_by_assignee(args: list[str]) -> None:
    if not args:
        print("Usage: workflow_state.py list-by-assignee <assignee_name>")
        sys.exit(1)
    assignee_name = " ".join(args)
    rows = load_csv()
    matches = list_by_assignee(rows, assignee_name)
    print(format_by_assignee(matches, assignee_name))


def _format_step_for_listing(row: dict[str, str]) -> str:
    """Return the user-facing step display: 'not started' / step name / '✅ DONE'."""
    if not has_workflow_progress(row):
        return "not started"
    cur = current_step(row)
    return cur.name if cur is not None else "✅ DONE"


def cmd_list_by_connector(args: list[str]) -> None:
    """List every integration whose Connector ID matches (case-insensitive)."""
    if not args:
        print("Usage: workflow_state.py list-by-connector <connector_id>")
        sys.exit(1)

    connector_id = " ".join(args)
    rows = load_csv()
    matches = list_by_connector(rows, connector_id)

    if not matches:
        print(f"No integrations found for connector '{connector_id}'.")
        print("  Tip: run 'workflow_state.py list-connectors' to see all known Connector IDs.")
        return

    print(f"\nIntegrations in connector '{connector_id}' ({len(matches)}):")
    for row in matches:
        integration_id = row.get("Integration ID", "")
        assignee = row.get("assignee", "").strip() or "unassigned"
        step_display = _format_step_for_listing(row)
        print(f"  - {integration_id}  [assignee: {assignee}]  → {step_display}")


def cmd_list_connectors(_args: list[str]) -> None:
    """Print every distinct non-empty Connector ID with counts."""
    rows = load_csv()

    # Group by connector id (preserving the first-seen original casing for display).
    buckets: dict[str, dict] = {}
    for row in rows:
        cid_raw = row.get("Connector ID", "").strip()
        if not cid_raw:
            continue
        key = cid_raw.lower()
        bucket = buckets.setdefault(
            key,
            {"display": cid_raw, "rows": []},
        )
        bucket["rows"].append(row)

    if not buckets:
        print("No connectors found in the CSV.")
        return

    # Sort by display name (case-insensitive).
    sorted_keys = sorted(buckets.keys(), key=lambda k: buckets[k]["display"].lower())

    # Compute column width for the connector id.
    max_id_len = max(len(buckets[k]["display"]) for k in sorted_keys)
    id_col_width = max(max_id_len, len("Connector ID"))

    header = (
        f"{'Connector ID':<{id_col_width}}  {'Integrations':>12}  "
        f"{'In Progress':>11}  {'Complete':>8}"
    )
    rule = (
        f"{'-' * id_col_width}  {'-' * 12}  {'-' * 11}  {'-' * 8}"
    )
    print(header)
    print(rule)
    for key in sorted_keys:
        bucket = buckets[key]
        bucket_rows: list[dict[str, str]] = bucket["rows"]
        total = len(bucket_rows)
        in_progress = 0
        complete = 0
        for r in bucket_rows:
            if not has_workflow_progress(r):
                continue
            if current_step(r) is None:
                complete += 1
            else:
                in_progress += 1
        print(
            f"{bucket['display']:<{id_col_width}}  {total:>12}  "
            f"{in_progress:>11}  {complete:>8}"
        )


def cmd_set_assignee_by_connector(args: list[str]) -> None:
    """Assign an owner to every integration in a given connector.

    SPECIAL CARVE-OUT (override #5): like ``cmd_set_assignee``, this writes
    the assignee column directly with NO cascade reset. Re-assigning is an
    administrative action; existing migration progress is preserved.
    """
    if len(args) < 2:
        print(
            "Usage: workflow_state.py set-assignee-by-connector "
            "<connector_id> <assignee_name>"
        )
        sys.exit(1)

    connector_id = args[0]
    assignee = " ".join(args[1:])

    if not assignee.strip():
        print("ERROR: Assignee cannot be empty.")
        sys.exit(1)

    rows = load_csv()
    matches = list_by_connector(rows, connector_id)

    if not matches:
        print(f"ERROR: No integrations found for connector '{connector_id}'.")
        print(
            "  Tip: run 'workflow_state.py list-connectors' to see all known "
            "Connector IDs."
        )
        sys.exit(1)

    # Direct write per row — no apply_step_action, no cascade reset.
    for row in matches:
        row["assignee"] = assignee

    save_csv(rows)
    print(
        f"Assigned {len(matches)} integration(s) in connector "
        f"'{connector_id}' to '{assignee}':"
    )
    for row in matches:
        print(f"  - {row.get('Integration ID', '')}")


def cmd_show_step(args: list[str]) -> None:
    """Show the value of a specific column for an integration."""
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


# ---------------------------------------------------------------------------
# `next` command
# ---------------------------------------------------------------------------

def _example_value_for(step: Step) -> str:
    """Return a canonical example value for the example CLI line."""
    if step.kind == "data" and step.name in JSON_VALUED_COLUMNS:
        if step.name == "Auth Details":
            return ("'{\"auth_types\":[],\"config\":\"NONE\","
                    "\"params\":{},\"notes\":null}'")
        if step.name == "Params for test with default in code":
            return "'[]'"
        if step.name == "Params same in other handlers":
            return "'[]'"
        return "'{}'"
    if step.name == "assignee":
        return '"<your name>"'
    if step.kind == "flag":
        return "YES"
    return ""


def format_next_line(row: dict[str, str]) -> str:
    """Format the literal next action for a row."""
    integration_id = row.get("Integration ID", "")
    cur = current_step(row)
    if cur is None:
        return f"{integration_id} — all 16 steps complete. 🎉"

    lines = [f"{integration_id} — step {cur.index} of 16: {cur.name}"]
    if cur.setter:
        example = _example_value_for(cur)
        cmd = (f"python3 connectus/workflow_state.py {cur.setter} "
               f"\"{integration_id}\" {example}".rstrip())
        lines.append(f"  Run:    {cmd}")
        if cur.optional:
            lines.append(
                f"  Or:     python3 connectus/workflow_state.py skip "
                f"\"{integration_id}\" \"{cur.name}\""
            )
    else:
        lines.append(
            f"  Run:    python3 connectus/workflow_state.py markpass "
            f"\"{integration_id}\" \"{cur.name}\""
        )
    lines.append(f"  About:  {cur.description}")
    return "\n".join(lines)


def _parse_next_flags(args: list[str]) -> tuple[Optional[str], bool, list[str]]:
    """Parse `--connector <id>` and `--mine` out of args (order-independent).

    Returns ``(connector_id, mine_flag, leftover_args)``. Leftover args are
    the positional arguments not consumed by recognized flags; the caller
    decides what to do with them (e.g. treat as an integration ID, or as
    ``--all``).
    """
    connector_id: Optional[str] = None
    mine = False
    leftover: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--mine":
            mine = True
            i += 1
            continue
        if a == "--connector":
            if i + 1 >= len(args):
                print("ERROR: --connector requires a connector id argument.")
                sys.exit(1)
            connector_id = args[i + 1]
            i += 2
            continue
        # Allow `--connector=<id>` form too, just in case.
        if a.startswith("--connector="):
            connector_id = a[len("--connector="):]
            i += 1
            continue
        leftover.append(a)
        i += 1
    return connector_id, mine, leftover


def cmd_next(args: list[str]) -> None:
    """Print the literal next action.

    Forms:
      next <integration_id>             → that integration only
      next                              → in-progress integrations assigned to current git user
      next --mine                       → explicit alias for the no-arg form
      next --all                        → in-progress integrations for everyone
      next --connector <id>             → in-progress integrations in that connector
      next --connector <id> --mine      → intersection of the above
    """
    rows = load_csv()

    if not rows:
        print("(no rows in CSV — nothing to do)")
        return

    connector_id, mine, leftover = _parse_next_flags(args)

    # Form 1: explicit integration ID — only when no flags consumed.
    if leftover and leftover[0] != "--all" and connector_id is None and not mine:
        name = " ".join(leftover)
        idx = find_row(rows, name)
        if idx is None:
            print(f"ERROR: Integration '{name}' not found.")
            sys.exit(1)
        print(format_next_line(rows[idx]))
        return

    show_all = bool(leftover and leftover[0] == "--all")
    if show_all and (mine or connector_id is not None):
        # --all combined with selectors makes no semantic sense; let --mine /
        # --connector win and ignore --all.
        show_all = False

    # Determine the assignee filter.
    target_assignee: Optional[str] = None
    use_assignee_filter = (not show_all) and (mine or connector_id is None)
    if use_assignee_filter:
        target_assignee = _git_user_name()
        if not target_assignee:
            # If the user explicitly asked for --connector without --mine, we
            # don't need a git user. But the no-arg form does.
            if connector_id is None:
                print(
                    "ERROR: cannot determine current user via 'git config user.name'.\n"
                    "  Pass an integration ID, or use 'next --all' to list everyone's work."
                )
                sys.exit(1)
            # User passed --connector without --mine but we also have no git
            # user; that's fine because we're not filtering by assignee in
            # that branch (use_assignee_filter would be False). Defensive.
            target_assignee = None
            use_assignee_filter = False

    # If --connector was given, narrow the candidate rows first.
    candidate_rows = rows
    if connector_id is not None:
        candidate_rows = list_by_connector(rows, connector_id)
        if not candidate_rows:
            print(f"No integrations found for connector '{connector_id}'.")
            print(
                "  Tip: run 'workflow_state.py list-connectors' to see all known "
                "Connector IDs."
            )
            return

    matched_any = False
    any_in_progress_in_connector = False
    for row in candidate_rows:
        if not has_workflow_progress(row):
            continue
        if current_step(row) is None:
            continue
        any_in_progress_in_connector = True
        if use_assignee_filter:
            if row.get("assignee", "").strip().lower() != (target_assignee or "").lower():
                continue
        print(format_next_line(row))
        print()
        matched_any = True

    if matched_any:
        return

    # No matches — produce a targeted message.
    if connector_id is not None and not any_in_progress_in_connector:
        print(
            f"No in-progress integrations in connector '{connector_id}' "
            f"(all are either unstarted or done)."
        )
        return
    if connector_id is not None and use_assignee_filter:
        print(
            f"No in-progress integrations in connector '{connector_id}' "
            f"assigned to '{target_assignee}'."
        )
        return
    if connector_id is not None:
        print(f"No in-progress integrations in connector '{connector_id}'.")
        return
    if show_all:
        print("No in-progress integrations.")
        return
    print(f"No in-progress integrations assigned to '{target_assignee}'.")


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def cmd_help(_args: list[str]) -> None:
    print(__doc__)


# ---------------------------------------------------------------------------
# Programmatic API (for use by AI agents / other scripts)
# ---------------------------------------------------------------------------

def get_integration_status(integration_id: str) -> dict:
    """Return a dict summary of an integration's workflow state."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    cur = current_step(row)
    completed = sum(1 for s in STEPS if is_done(row, s))
    return {
        "name": row.get("Integration ID", ""),
        "current_step": cur.name if cur else None,
        "current_step_index": cur.index if cur else None,
        "workflow": {col: row.get(col, "") for col in WORKFLOW_COLUMNS},
        "completed_steps": completed,
        "total_steps": len(STEPS),
        "progress_pct": round(completed / len(STEPS) * 100, 1),
        "all_complete": cur is None and completed > 0,
    }


def next_step_for(integration_id: str) -> dict:
    """Return the next-action info for an integration."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}
    row = rows[idx]
    cur = current_step(row)
    if cur is None:
        return {"complete": True, "message": format_next_line(row)}
    return {
        "complete": False,
        "step_index": cur.index,
        "step_name": cur.name,
        "setter": cur.setter,
        "description": cur.description,
        "message": format_next_line(row),
    }


def _row_summary_dict(row: dict[str, str]) -> dict:
    """JSON-serializable snapshot of an integration row's workflow state."""
    cur = current_step(row)
    completed = sum(1 for s in STEPS if is_done(row, s))
    return {
        "integration_id": row.get("Integration ID", ""),
        "connector_id": row.get("Connector ID", "").strip(),
        "assignee": row.get("assignee", "").strip(),
        "current_step": cur.name if cur else None,
        "current_step_index": cur.index if cur else None,
        "completed_steps": completed,
        "all_complete": cur is None and has_workflow_progress(row),
        "has_progress": has_workflow_progress(row),
    }


def list_integrations_by_connector(connector_id: str) -> list[dict]:
    """Return one summary dict per integration matching ``connector_id``.

    Match is case-insensitive on the trimmed Connector ID.
    """
    rows = load_csv()
    matches = list_by_connector(rows, connector_id)
    return [_row_summary_dict(row) for row in matches]


def integrations_for_assignee(assignee_name: str) -> list[dict]:
    """Return one summary dict per integration assigned to ``assignee_name``.

    Match is case-insensitive on the trimmed assignee column.
    """
    rows = load_csv()
    matches = list_by_assignee(rows, assignee_name)
    return [_row_summary_dict(row) for row in matches]


def assign_connector(connector_id: str, assignee_name: str) -> dict:
    """Assign every integration in ``connector_id`` to ``assignee_name``.

    Mirrors ``cmd_set_assignee_by_connector``: NO cascade reset. Returns
    ``{"connector_id", "assignee", "assigned": [<ids>], "count": N}`` on
    success, or ``{"error": "..."}`` if no rows match or the assignee is
    empty.
    """
    if not assignee_name or not assignee_name.strip():
        return {"error": "Assignee cannot be empty."}

    rows = load_csv()
    matches = list_by_connector(rows, connector_id)
    if not matches:
        return {
            "error": (
                f"No integrations found for connector '{connector_id}'. "
                "Use list-connectors to see all known Connector IDs."
            )
        }

    assigned_ids: list[str] = []
    for row in matches:
        row["assignee"] = assignee_name
        assigned_ids.append(row.get("Integration ID", ""))

    save_csv(rows)
    return {
        "connector_id": connector_id,
        "assignee": assignee_name,
        "assigned": assigned_ids,
        "count": len(assigned_ids),
    }


def markpass_integration_step(integration_id: str, step_name: str) -> dict:
    """Mark a checkpoint as passed via the unified dispatch."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    target = STEP_BY_NAME.get(step_name)
    if target is None:
        return {"error": f"Unknown step '{step_name}'."}
    if step_name in NON_CHECKPOINT_STEPS:
        return {"error": f"'{step_name}' is not a checkpoint; use {NON_CHECKPOINT_STEPS[step_name]}."}

    if step_name == "auth parity test passes":
        flag = row.get(AUTH_PARITY_FLAG_COLUMN, "").strip().upper()
        if flag in ("NO", "N/A"):
            row[step_name] = NA_MARK
            save_csv(rows)
            cur = current_step(row)
            return {
                "message": f"'{step_name}' set to N/A.",
                "completed_step": step_name,
                "current_step": cur.name if cur else None,
            }
        if flag == "":
            return {"error": f"'{step_name}' requires the flag to be set first."}

    try:
        cleared, no_op = apply_step_action(row, target, CHECK, verb="markpass")
    except WorkflowError as e:
        return {"error": e.message}

    save_csv(rows)
    cur = current_step(row)
    return {
        "message": (f"'{step_name}' marked passed."
                    + (f" Cleared: {cleared}" if cleared else "")
                    + (" (no-op)" if no_op else "")),
        "completed_step": step_name,
        "current_step": cur.name if cur else None,
    }


def fail_integration_step(integration_id: str, step_name: str) -> dict:
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}
    target = STEP_BY_NAME.get(step_name)
    if target is None:
        return {"error": f"Unknown step '{step_name}'."}
    row = rows[idx]
    if target.index == 1:
        for s in STEPS:
            row[s.name] = ""
    else:
        prev = STEP_BY_INDEX[target.index - 1]
        row[target.name] = ""
        reset_after(row, prev)
    save_csv(rows)
    cur = current_step(row)
    return {
        "message": f"Reset '{step_name}' and subsequent steps.",
        "current_step": cur.name if cur else None,
    }


def reset_integration_to_step(integration_id: str, step_name: str) -> dict:
    return fail_integration_step(integration_id, step_name)


def skip_integration_step(integration_id: str, step_name: str) -> dict:
    """Skip an optional step (writes 'N/A')."""
    target = STEP_BY_NAME.get(step_name)
    if target is None:
        return {"error": f"Unknown step '{step_name}'."}
    if not target.optional:
        return {"error": f"Step '{step_name}' is not optional and cannot be skipped."}
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}
    row = rows[idx]
    try:
        cleared, _ = apply_step_action(row, target, NA_MARK, verb="skip")
    except WorkflowError as e:
        return {"error": e.message}
    save_csv(rows)
    cur = current_step(row)
    return {
        "message": f"Skipped '{step_name}'." + (f" Cleared: {cleared}" if cleared else ""),
        "current_step": cur.name if cur else None,
    }


def set_integration_auth(integration_id: str, auth_detail_json: str) -> dict:
    """Set Auth Details and cascade-reset every later step."""
    schema_errors = validate_auth_detail(auth_detail_json)
    if schema_errors:
        return {"error": "Auth Details schema validation failed:\n"
                + "\n".join(f"  - {e}" for e in schema_errors)}

    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    target = STEP_BY_NAME["Auth Details"]
    try:
        cleared, _ = apply_step_action(row, target, auth_detail_json, verb="set-auth")
    except WorkflowError as e:
        return {"error": e.message}
    save_csv(rows)
    cur = current_step(row)
    return {
        "message": f"Set 'Auth Details' for '{row.get('Integration ID', '')}'."
                   + (f" Cleared: {cleared}" if cleared else ""),
        "current_step": cur.name if cur else None,
    }


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

COMMANDS: dict[str, Callable[[list[str]], None]] = {
    "status": cmd_status,
    "status-all": cmd_status_all,
    "dashboard": cmd_dashboard,
    "next": cmd_next,
    "set-assignee": cmd_set_assignee,
    "set-auth": cmd_set_auth,
    "set-params-to-commands": cmd_set_params_to_commands,
    "set-params-for-test": cmd_set_params_for_test,
    "set-shared-params": cmd_set_shared_params,
    "set-auth-flag": cmd_set_auth_flag,
    "markpass": cmd_markpass,
    "skip": cmd_skip,
    "fail": cmd_fail,
    "reset-to": cmd_reset_to,
    "reset": cmd_reset,
    "at-step": cmd_at_step,
    "list": cmd_list,
    "list-by-assignee": cmd_list_by_assignee,
    "list-by-connector": cmd_list_by_connector,
    "list-connectors": cmd_list_connectors,
    "set-assignee-by-connector": cmd_set_assignee_by_connector,
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
