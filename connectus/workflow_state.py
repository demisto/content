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

Identity / metadata columns (3) — NOT managed by this script:
  1. Integration ID
  2. Integration File Path
  3. Connector ID

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
  python3 connectus/workflow_state.py files "Cisco Spark"
  python3 connectus/workflow_state.py auth-params "Cisco Spark"
  python3 connectus/workflow_state.py auth-params "Cisco Spark" --format=json
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
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

# Regexes for the Auth Details `config` mini-grammar.
_AUTH_CONFIG_CLAUSE_RE = re.compile(
    r"^\s*(REQUIRED|OPTIONAL|CHOICE)\s*\(\s*([^)]*?)\s*\)\s*$"
)
_AUTH_CONFIG_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Split clauses on `+` surrounded by optional whitespace. We use a manual
# split rather than re.split so we can detect leading/trailing `+` (which
# would produce empty segments).
_AUTH_CONFIG_SPLIT_RE = re.compile(r"\s*\+\s*")


def _parse_auth_config(config: str) -> tuple[list[str], list[str]]:
    """Parse the Auth Details ``config`` expression mini-grammar.

    Returns ``(referenced_names, parse_errors)`` where ``referenced_names``
    is the (order-preserving, possibly duplicate) list of operand names
    appearing inside any ``REQUIRED(...)``, ``OPTIONAL(...)`` or
    ``CHOICE(...)`` clause, and ``parse_errors`` is a list of human-readable
    issues with the expression itself (malformed clauses, bad operand
    names, stray ``+``, etc.).

    Grammar (case-sensitive on keywords):

        config       := "NoneRequired" | clause ( " + " clause )*
        clause       := ("REQUIRED" | "OPTIONAL" | "CHOICE") "(" name_list ")"
        name_list    := name ("," name)*
        name         := /[A-Za-z_][A-Za-z0-9_]*/

    Surrounding whitespace inside clauses and around ``+`` / ``,`` is
    tolerated. Empty clauses (``REQUIRED()``) are rejected.
    """
    referenced_names: list[str] = []
    parse_errors: list[str] = []

    stripped = config.strip()
    if stripped == "":
        parse_errors.append("config expression is empty")
        return referenced_names, parse_errors
    if stripped == "NoneRequired":
        return referenced_names, parse_errors

    # Detect leading/trailing `+` before splitting, so the resulting empty
    # segments give a clear error message.
    if stripped.startswith("+"):
        parse_errors.append("config expression starts with '+' (no leading clause)")
    if stripped.endswith("+"):
        parse_errors.append("config expression ends with '+' (no trailing clause)")

    segments = _AUTH_CONFIG_SPLIT_RE.split(stripped)
    for seg_idx, segment in enumerate(segments):
        if segment.strip() == "":
            # Already covered by the leading/trailing checks above OR a
            # genuine "+ +" in the middle.
            if not (seg_idx == 0 and stripped.startswith("+")) and not (
                seg_idx == len(segments) - 1 and stripped.endswith("+")
            ):
                parse_errors.append("empty clause between '+' separators")
            continue
        m = _AUTH_CONFIG_CLAUSE_RE.match(segment)
        if not m:
            parse_errors.append(
                f"malformed clause '{segment}' (expected "
                "REQUIRED(...), OPTIONAL(...), or CHOICE(...))"
            )
            continue
        keyword, inner = m.group(1), m.group(2)
        if inner.strip() == "":
            parse_errors.append(f"clause '{keyword}(...)' has no operands")
            continue
        operands = [op.strip() for op in inner.split(",")]
        for op in operands:
            if op == "":
                parse_errors.append(
                    f"clause '{keyword}(...)' has an empty operand "
                    "(stray comma?)"
                )
                continue
            if not _AUTH_CONFIG_NAME_RE.fullmatch(op):
                parse_errors.append(
                    f"clause '{keyword}(...)' operand '{op}' is not a "
                    "valid identifier (must match [A-Za-z_][A-Za-z0-9_]*)"
                )
                continue
            referenced_names.append(op)

    return referenced_names, parse_errors


def validate_auth_detail(value: str) -> list[str]:
    """Validate Auth Details JSON shape. Returns list of errors ([] = valid).

    Shape: ``{"auth_types": [{"type": <enum>, "name": <logical_name>,
    "xsoar_params": [<xsoar_param_id>, ...], "interpolated"?: <bool>},
    ...], "config": <expression>,
    "other_connection": [<yml_param_id>, ...]}``.

    Each ``auth_types[]`` entry describes one prospective ConnectUs
    connection type that the migrated integration should expose. ``name``
    is a free-form logical id chosen for that connection type and must be
    unique across entries within this row. ``xsoar_params`` is the list
    of XSOAR parameter ids whose values feed the secrets for that
    connection type (the same XSOAR param may appear in multiple entries
    if it supplies several connection types). ``config`` references the
    entry ``name``s (not the XSOAR param ids).

    ``other_connection`` is a flat sorted list of YML param ids that are
    connection-adjacent but not auth secrets — e.g. ``url``, ``proxy``,
    ``insecure``, ``port``, ``host``, ``region``. The list captures the
    ids exactly as they appear in the integration YML's
    ``configuration[].name``. An empty list ``[]`` is valid (= the
    integration has no connection-adjacent params besides its auth
    secrets). The validator does NOT check overlap with
    ``auth_types[].xsoar_params`` — keeping the two lists disjoint is the
    classifier's responsibility.

    Validation performed (in addition to the per-entry shape checks):

      - ``xsoar_params`` must be a non-empty list of non-empty strings.
      - ``auth_types`` entries must be sorted by ``(type, name)``
        ascending. The first out-of-order pair is reported.
      - ``config`` must conform to the mini-grammar parsed by
        :func:`_parse_auth_config` (``NoneRequired`` or one or more
        ``REQUIRED/OPTIONAL/CHOICE`` clauses joined by ``+``).
      - Every operand name referenced by ``config`` must appear as some
        ``auth_types[].name`` in the same row.
      - If ``config == "NoneRequired"`` then ``auth_types`` must be
        empty; otherwise ``auth_types`` must be non-empty.
      - ``other_connection`` is REQUIRED on write. It must be a list of
        non-empty unique strings, sorted ascending. ``[]`` is allowed.

    NOTE on backward compatibility: legacy CSV rows written before this
    field existed lack ``other_connection`` entirely. The read/display
    path tolerates that (see ``format_status`` / ``format_step_value``)
    and renders a ``(not set — re-run set-auth)`` hint, but ``set-auth``
    writes go through this validator and MUST include the key.
    """
    errors: list[str] = []

    try:
        detail = json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]

    if not isinstance(detail, dict):
        return [f"Expected a JSON object, got {type(detail).__name__}"]

    required_keys = {"auth_types", "config", "other_connection"}
    missing = required_keys - set(detail.keys())
    if missing:
        errors.append(f"Missing required keys: {', '.join(sorted(missing))}")
        return errors

    seen_names: set[str] = set()
    # Track per-entry validity for the sort check (only consider entries
    # whose `type` and `name` are both well-formed).
    sortable: list[tuple[int, str, str]] = []
    valid_auth_types_list = isinstance(detail["auth_types"], list)
    if not valid_auth_types_list:
        errors.append(f"'auth_types' must be a list, got {type(detail['auth_types']).__name__}")
    else:
        for i, entry in enumerate(detail["auth_types"]):
            if not isinstance(entry, dict):
                errors.append(f"auth_types[{i}]: expected object, got {type(entry).__name__}")
                continue
            entry_type_ok = False
            entry_name_ok = False
            if "type" not in entry:
                errors.append(f"auth_types[{i}]: missing 'type'")
            elif entry["type"] not in VALID_AUTH_TYPES:
                errors.append(f"auth_types[{i}]: invalid type '{entry['type']}'")
            else:
                entry_type_ok = True
            if "name" not in entry:
                errors.append(f"auth_types[{i}]: missing 'name'")
            elif not isinstance(entry["name"], str):
                errors.append(f"auth_types[{i}]: 'name' must be a string")
            elif not entry["name"]:
                errors.append(f"auth_types[{i}]: 'name' must be a non-empty string")
            elif entry["name"] in seen_names:
                errors.append(
                    f"auth_types[{i}]: duplicate 'name' '{entry['name']}' "
                    "(each entry must have a unique logical name)"
                )
            else:
                seen_names.add(entry["name"])
                entry_name_ok = True
            if "xsoar_params" not in entry:
                errors.append(f"auth_types[{i}]: missing 'xsoar_params'")
            elif not isinstance(entry["xsoar_params"], list):
                errors.append(
                    f"auth_types[{i}]: 'xsoar_params' must be a list, "
                    f"got {type(entry['xsoar_params']).__name__}"
                )
            elif len(entry["xsoar_params"]) == 0:
                errors.append(
                    f"auth_types[{i}]: 'xsoar_params' must contain at least one entry"
                )
            else:
                for j, p in enumerate(entry["xsoar_params"]):
                    if not isinstance(p, str) or not p:
                        errors.append(
                            f"auth_types[{i}]: xsoar_params[{j}] must be a non-empty string"
                        )
            if "interpolated" in entry and not isinstance(entry["interpolated"], bool):
                errors.append(
                    f"auth_types[{i}]: 'interpolated' must be a bool, "
                    f"got {type(entry['interpolated']).__name__}"
                )

            if entry_type_ok and entry_name_ok:
                sortable.append((i, entry["type"], entry["name"]))

        # Sort-order check: report the first out-of-order adjacent pair
        # among the entries that have valid `type` and `name`.
        for k in range(len(sortable) - 1):
            i_a, type_a, name_a = sortable[k]
            i_b, type_b, name_b = sortable[k + 1]
            if (type_a, name_a) > (type_b, name_b):
                errors.append(
                    f"auth_types must be sorted by (type, name); entry "
                    f"[{i_a}] '{type_a}'/'{name_a}' should come after "
                    f"entry [{i_b}] '{type_b}'/'{name_b}'"
                )
                break

    if not isinstance(detail["config"], str):
        errors.append(f"'config' must be a string, got {type(detail['config']).__name__}")
    else:
        config_str = detail["config"]
        referenced_names, parse_errors = _parse_auth_config(config_str)
        for pe in parse_errors:
            errors.append(f"'config': {pe}")
        for n in referenced_names:
            if n not in seen_names:
                errors.append(
                    f"'config' references unknown connection-type name "
                    f"'{n}' (must match an auth_types[].name)"
                )
        # Coherence between `config` and `auth_types`.
        if valid_auth_types_list:
            auth_types_empty = len(detail["auth_types"]) == 0
            if config_str.strip() == "NoneRequired":
                if not auth_types_empty:
                    errors.append(
                        "'config' is 'NoneRequired' but 'auth_types' "
                        "contains entries; remove the entries or change "
                        "'config'"
                    )
            else:
                # Only flag the empty-auth_types mismatch if the config
                # itself parsed cleanly (otherwise the parse error is
                # the more informative signal).
                if not parse_errors and auth_types_empty:
                    errors.append(
                        "'config' is not 'NoneRequired' but 'auth_types' is empty"
                    )

    other_connection = detail["other_connection"]
    if not isinstance(other_connection, list):
        errors.append(
            f"'other_connection' must be a list, got "
            f"{type(other_connection).__name__}"
        )
    else:
        all_strings = True
        for j, item in enumerate(other_connection):
            if not isinstance(item, str):
                errors.append(
                    f"'other_connection'[{j}]: must be a string, got "
                    f"{type(item).__name__}"
                )
                all_strings = False
            elif not item:
                errors.append(
                    f"'other_connection'[{j}]: must be a non-empty string"
                )
                all_strings = False
        if all_strings:
            if len(set(other_connection)) != len(other_connection):
                seen: set[str] = set()
                dups: list[str] = []
                for item in other_connection:
                    if item in seen and item not in dups:
                        dups.append(item)
                    seen.add(item)
                errors.append(
                    "'other_connection' contains duplicate entries: "
                    f"{dups}"
                )
            sorted_oc = sorted(other_connection)
            if other_connection != sorted_oc:
                errors.append(
                    "'other_connection' must be sorted ascending; got "
                    f"{other_connection}, expected {sorted_oc}"
                )

    return errors


# Hint embedded in every "extra top-level key" error reported by
# :func:`validate_params_to_commands`. The one-liner is documented as
# the canonical strip recipe so the calling agent can recover from a
# polluted analyzer payload (e.g. ``check_command_params.py`` invoked
# without ``--with-diagnostics`` was the historical leak source) by
# re-piping the JSON through ``json.load`` / ``pop`` / ``json.dumps``
# without re-running the analyzer. Kept in sync with
# ``connectus/column-schemas.md`` §Params to Commands.
_PARAMS_TO_COMMANDS_STRIP_HINT = (
    "strip it before persisting (see column-schemas.md "
    "§Params to Commands). One-liner: python3 -c "
    "\"import sys, json; o = json.load(sys.stdin); "
    "o.pop('diagnostics', None); print(json.dumps(o))\""
)


def validate_params_to_commands(value: str) -> list[str]:
    """Validate Params to Commands JSON shape. Returns errors ([] = valid).

    Strict shape (per ``connectus/column-schemas.md`` §Params to Commands)::

        {
          "integration": "<non-empty string>",
          "commands": {
            "<command_id>": ["<param_id>", ...],
            ...
          }
        }

    Validation rules:

      - The top level must be a JSON object.
      - The set of top-level keys MUST equal exactly
        ``{"integration", "commands"}``. Missing keys are reported.
        Extra top-level keys (the historical leak: ``diagnostics``,
        ``status``, ``failure_excerpt``, ``captured_requests``,
        ``error``, ``stderr``, etc.) are ALL named in a single error
        and the error embeds the canonical strip recipe (see
        :data:`_PARAMS_TO_COMMANDS_STRIP_HINT`).
      - ``integration`` must be a non-empty string.
      - ``commands`` must be a dict. Each value must be a list, and
        every element of every list must be a non-empty string.

    Mirrors :func:`validate_auth_detail`'s contract: returns a list of
    human-readable error strings. An empty list means the payload is
    valid. Multiple errors are accumulated rather than bailing on the
    first — callers print all of them so the operator can fix the
    payload in a single pass.
    """
    errors: list[str] = []

    try:
        payload = json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]

    if not isinstance(payload, dict):
        return [f"Expected a JSON object, got {type(payload).__name__}"]

    expected_keys = {"integration", "commands"}
    actual_keys = set(payload.keys())
    missing = expected_keys - actual_keys
    extras = actual_keys - expected_keys

    if missing:
        errors.append(
            f"Missing required top-level key(s): {sorted(missing)}; "
            f"payload must contain exactly {sorted(expected_keys)}."
        )

    if extras:
        sorted_extras = sorted(extras)
        # Call out diagnostics by name when present — it is the known
        # common offender (analyzer leaked it under the old default).
        if "diagnostics" in extras:
            errors.append(
                f"Extra top-level key 'diagnostics' is forbidden in "
                f"'Params to Commands' (it is internal analyzer "
                f"metadata, not pipeline data); "
                f"{_PARAMS_TO_COMMANDS_STRIP_HINT}"
            )
            other_extras = [k for k in sorted_extras if k != "diagnostics"]
            if other_extras:
                errors.append(
                    f"Extra top-level key(s) {other_extras} are "
                    f"forbidden; {_PARAMS_TO_COMMANDS_STRIP_HINT}"
                )
        else:
            errors.append(
                f"Extra top-level key(s) {sorted_extras} are forbidden; "
                f"{_PARAMS_TO_COMMANDS_STRIP_HINT}"
            )

    if "integration" in payload:
        integration = payload["integration"]
        if not isinstance(integration, str):
            errors.append(
                f"'integration' must be a string, got "
                f"{type(integration).__name__}"
            )
        elif integration == "":
            errors.append("'integration' must be a non-empty string")

    if "commands" in payload:
        commands = payload["commands"]
        if not isinstance(commands, dict):
            errors.append(
                f"'commands' must be a JSON object, got "
                f"{type(commands).__name__}"
            )
        else:
            for cmd, param_list in commands.items():
                if not isinstance(param_list, list):
                    errors.append(
                        f"commands[{cmd!r}]: expected a list of param "
                        f"ids, got {type(param_list).__name__}"
                    )
                    continue
                for i, p in enumerate(param_list):
                    if not isinstance(p, str):
                        errors.append(
                            f"commands[{cmd!r}][{i}]: param id must be "
                            f"a string, got {type(p).__name__}"
                        )
                        continue
                    if p == "":
                        errors.append(
                            f"commands[{cmd!r}][{i}]: param id must be "
                            f"a non-empty string"
                        )

    return errors


# ---------------------------------------------------------------------------
# Auth-derived ignore set (cross-step exclusion plumbing)
# ---------------------------------------------------------------------------

def _project_xsoar_param_to_yml_id(xsoar_param: str) -> str:
    """Project a single ``auth_types[].xsoar_params`` entry to its YML param id.

    Bare ids (``api_key``) pass through unchanged. Dotted forms like
    ``credentials.identifier`` / ``credentials.password`` collapse to the
    segment before the first ``.`` (``credentials``) — that's the actual
    YML ``configuration[].name`` so it can be cross-checked against the
    ``Params to Commands`` payload (whose values are bare YML ids).
    """
    if not isinstance(xsoar_param, str):
        return ""
    return xsoar_param.split(".", 1)[0]


def _auth_param_sources(auth_detail: dict) -> dict[str, list[str]]:
    """Return ``{yml_param_id: [<source description>, ...]}`` for an Auth
    Details object.

    Used by :func:`auth_param_ids` and the ``set-params-to-commands``
    overlap-rejection error message — the latter needs to name *where*
    each offending param was declared (``auth_types[].name='credentials'
    (xsoar_params=[...])`` vs ``other_connection``).

    Tolerates legacy-shape Auth Details that lack ``other_connection``
    by simply omitting that source — see :func:`auth_param_ids` for
    the user-visible error/warning behaviour.
    """
    sources: dict[str, list[str]] = {}

    auth_types = auth_detail.get("auth_types")
    if isinstance(auth_types, list):
        for entry in auth_types:
            if not isinstance(entry, dict):
                continue
            entry_name = entry.get("name", "<unnamed>")
            xsoar_params = entry.get("xsoar_params")
            if not isinstance(xsoar_params, list):
                continue
            projected_for_entry: list[str] = []
            for xp in xsoar_params:
                yml_id = _project_xsoar_param_to_yml_id(xp)
                if yml_id:
                    projected_for_entry.append(yml_id)
            # Group source description by entry — every projected id
            # cites the same entry-level (name, xsoar_params) pair so
            # the overlap message can quote the dotted forms verbatim.
            # Dedupe per-yml_id so dotted forms collapsing to the same
            # bare id (credentials.identifier + credentials.password →
            # credentials) don't repeat the same descriptor twice.
            descriptor = (
                f"auth_types[].name={entry_name!r} "
                f"(xsoar_params={list(xsoar_params)!r})"
            )
            seen_for_entry: set[str] = set()
            for yml_id in projected_for_entry:
                if yml_id in seen_for_entry:
                    continue
                seen_for_entry.add(yml_id)
                sources.setdefault(yml_id, []).append(descriptor)

    other_connection = auth_detail.get("other_connection")
    if isinstance(other_connection, list):
        for item in other_connection:
            if isinstance(item, str) and item:
                sources.setdefault(item, []).append("other_connection")

    return sources


def auth_param_ids(integration_id: str) -> list[str]:
    """Return the union of YML param ids declared in an integration's
    ``Auth Details``.

    Returns the deduplicated, ascending-sorted list of bare YML
    ``configuration[].name`` values composed from:

    * Every ``auth_types[].xsoar_params`` entry, projected via
      :func:`_project_xsoar_param_to_yml_id` (bare ids pass through;
      dotted forms like ``credentials.identifier`` collapse to
      ``credentials``).
    * Every entry in ``other_connection`` (already bare YML ids — no
      projection needed).

    Behaviour for edge cases:

    * Integration not in the CSV → :class:`WorkflowError`.
    * ``Auth Details`` cell empty (the workflow prerequisite for
      populating ``Params to Commands``) → :class:`WorkflowError` with
      a clear "set auth first" message.
    * ``Auth Details`` JSON unparseable → :class:`WorkflowError`.
    * Legacy ``Auth Details`` row that lacks the ``other_connection``
      key entirely → degrade gracefully: log a one-line stderr hint
      and return only the auth_types-derived ids. The downstream
      analyzer / set-params-to-commands callers must keep working on
      these legacy rows; surfacing this as a hard error would block
      the existing CSV from loading.
    """
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        raise WorkflowError(
            f"Integration '{integration_id}' not found in the CSV."
        )

    raw = rows[idx].get("Auth Details", "").strip()
    if not raw:
        raise WorkflowError(
            f"'Auth Details' is not set for integration "
            f"'{rows[idx].get('Integration ID', integration_id)}'. "
            f"Run 'set-auth' first — populating 'Params to Commands' "
            f"requires the auth classification to be in place so the "
            f"two columns stay disjoint."
        )

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise WorkflowError(
            f"'Auth Details' for integration '{integration_id}' is not "
            f"valid JSON: {e}. Re-run 'set-auth' with a corrected payload."
        )
    if not isinstance(parsed, dict):
        raise WorkflowError(
            f"'Auth Details' for integration '{integration_id}' is not a "
            f"JSON object (got {type(parsed).__name__}). Re-run 'set-auth'."
        )

    if "other_connection" not in parsed:
        # Legacy-shape row from before the field existed. Don't crash
        # — the helper is consumed by tools that must keep working on
        # historical rows. Surface a stderr hint so the next set-auth
        # run gets it right.
        print(
            f"WARNING: Auth Details for '{integration_id}' is missing "
            f"'other_connection' (legacy shape). Re-run 'set-auth' to "
            f"populate it; auth_param_ids() returning only the "
            f"auth_types-derived ids in the meantime.",
            file=sys.stderr,
        )

    sources = _auth_param_sources(parsed)
    return sorted(sources.keys())


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


def _auth_other_connection_summary(raw: str) -> str:
    """Return a one-line ``other_connection`` summary for an Auth Details
    JSON blob. Tolerates legacy rows that predate the field by returning
    a clear ``(not set — re-run set-auth)`` hint instead of crashing."""
    val = raw.strip()
    if not val:
        return "(not set)"
    try:
        parsed = json.loads(val)
    except json.JSONDecodeError:
        return "(invalid JSON — cannot extract other_connection)"
    if not isinstance(parsed, dict):
        return "(invalid Auth Details object)"
    if "other_connection" not in parsed:
        return "(not set — re-run set-auth)"
    oc = parsed["other_connection"]
    if not isinstance(oc, list):
        return f"(malformed: expected list, got {type(oc).__name__})"
    if not oc:
        return "[] (none)"
    return json.dumps(oc)


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
    assignee = row.get("assignee", "").strip()

    lines.append(f"  Assignee:        {assignee if assignee else '(unassigned)'}")
    lines.append(f"  File Path:       {file_path if file_path else '(not set)'}")
    if file_path:
        lines.append(f"                   (run 'workflow_state.py files {integration_id}' to list all source files)")
    lines.append(f"  Connector ID:    {connector_id if connector_id else '(not set)'}")
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
        # Surface other_connection inline for Auth Details (legacy-tolerant).
        if step.name == "Auth Details" and raw.strip():
            oc_summary = _auth_other_connection_summary(raw)
            lines.append(f"     {'other_connection':38s} : {oc_summary}")

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
            # Legacy-row tolerance: pre-other_connection Auth Details rows
            # don't include the new key. Don't crash; surface the gap so
            # the user knows to re-run set-auth.
            if (
                step_name == "Auth Details"
                and isinstance(parsed, dict)
                and "other_connection" not in parsed
            ):
                pretty += (
                    "\n\n  other_connection: (not set — re-run set-auth)"
                )
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
    # Defense-in-depth: catch a polluted "Params to Commands" payload
    # even if the caller bypassed cmd_set_params_to_commands and
    # invoked _set_json_data_step directly.
    elif step_name == "Params to Commands":
        schema_errors = validate_params_to_commands(raw)
        if schema_errors:
            print("ERROR: Params to Commands does not match the required schema.")
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


def _check_params_to_commands_overlap(
    integration_id: str, payload: dict
) -> None:
    """Reject ``set-params-to-commands`` payloads that overlap with auth.

    The workflow tool is the single source of truth for the per-integration
    "auth ignore set" — :func:`auth_param_ids` is consulted (which reads
    the same ``Auth Details`` cell that ``set-auth`` populated). If ANY
    ``(command, param_id)`` in the payload references a param that is
    already declared in ``Auth Details`` (either as a projected
    ``auth_types[].xsoar_params`` entry or in ``other_connection``),
    raise :class:`WorkflowError` with:

    * every offending pair, AND
    * for each offending param, the precise auth-detail source it came
      from (so the agent can decide whether to strip the param from the
      per-command payload OR revert to ``set-auth`` and remove it from
      ``Auth Details``).

    The caller is :func:`cmd_set_params_to_commands`; ``Auth Details``
    being unset is an upstream prerequisite enforced by
    :func:`auth_param_ids` (raises a clearer "set auth first" error).
    """
    # Re-load the Auth Details JSON once so we can attribute the source
    # of each offending param (auth_types vs other_connection).
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        # Defensive — caller already resolved the row, but the helper
        # can be invoked outside that context too.
        raise WorkflowError(
            f"Integration '{integration_id}' not found in the CSV."
        )
    raw_auth = rows[idx].get("Auth Details", "").strip()
    auth_detail: dict = {}
    if raw_auth:
        try:
            parsed = json.loads(raw_auth)
            if isinstance(parsed, dict):
                auth_detail = parsed
        except json.JSONDecodeError:
            pass
    sources = _auth_param_sources(auth_detail) if auth_detail else {}

    # The helper raises when Auth Details is unset; let that propagate.
    auth_ids = set(auth_param_ids(integration_id))

    commands_block = payload.get("commands") if isinstance(payload, dict) else None
    if not isinstance(commands_block, dict):
        # Shape mismatch is not THIS check's concern; let the
        # downstream consumer (or future schema validator) surface it.
        return

    offenders: list[tuple[str, str]] = []
    for cmd, param_list in commands_block.items():
        if not isinstance(param_list, list):
            continue
        for p in param_list:
            if isinstance(p, str) and p in auth_ids:
                offenders.append((str(cmd), p))

    if not offenders:
        return

    # Build a deterministic, human-readable error.
    lines = [
        f"'Params to Commands' for '{integration_id}' contains "
        f"{len(offenders)} param(s) that are already declared in "
        f"'Auth Details'. The two columns MUST be disjoint.",
        "",
        "Offending (command, param) pairs:",
    ]
    for cmd, p in sorted(offenders):
        lines.append(f"  - ({cmd!r}, {p!r})")

    # One source line per distinct offending param.
    lines.append("")
    lines.append("Source of each offending param in 'Auth Details':")
    seen_params: set[str] = set()
    for _cmd, p in sorted(offenders):
        if p in seen_params:
            continue
        seen_params.add(p)
        srcs = sources.get(p)
        if srcs:
            for src in srcs:
                lines.append(f"  - param {p!r} overlaps with {src}")
        else:
            # Defensive — overlap was reported but source attribution
            # missed it (e.g. legacy row without other_connection).
            lines.append(
                f"  - param {p!r} overlaps with Auth Details "
                f"(source not attributable; legacy row?)"
            )

    lines.extend([
        "",
        "Fix:",
        f"  Re-derive the per-command lists with the auth-aware ignore "
        f"set — run:",
        f"    python3 connectus/workflow_state.py auth-params "
        f"\"{integration_id}\"",
        f"  to see exactly what to exclude. The analyzer can pull this "
        f"list automatically: pass --integration-id "
        f"\"{integration_id}\" to "
        f"connectus/check_command_params.py.",
        "",
        f"  If a listed param is *truly* used per-command and was "
        f"misclassified into 'Auth Details', revert to Step 1 with "
        f"'set-auth' and remove it from 'auth_types[].xsoar_params' "
        f"or 'other_connection' first. Do NOT bypass this rejection "
        f"by hand-stripping just to make the call go through.",
    ])

    raise WorkflowError("\n".join(lines))


def cmd_set_params_to_commands(args: list[str]) -> None:
    # Two pre-flight checks ahead of the cascade-write so a bad payload
    # can never partially mutate the row:
    #
    #   (1) STRICT SCHEMA: top-level keys MUST equal exactly
    #       {"integration", "commands"}; the historical leak was the
    #       analyzer emitting a top-level "diagnostics" key that the
    #       agent piped verbatim. Reported FIRST because shape errors
    #       are the more common mistake and the overlap check is a
    #       deeper semantic check that only makes sense once the
    #       payload shape is valid.
    #
    #   (2) OVERLAP: reject payloads whose per-command param lists
    #       overlap with the integration's auth-derived ignore set.
    #       Auth Details being unset is already an upstream
    #       prerequisite (apply_step_action would reject the call
    #       ahead-of-current); auth_param_ids() re-asserts it with a
    #       more specific error if we reach the overlap check first.
    if len(args) >= 2:
        name = args[0]
        raw = " ".join(args[1:])
        # (1) Strict schema check — done up-front and on the raw text
        # so we report extra/missing top-level keys (esp. the leaked
        # "diagnostics" key) before any other check looks at the body.
        schema_errors = validate_params_to_commands(raw)
        if schema_errors:
            print("ERROR: Params to Commands does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)
        # (2) Overlap check — only meaningful once the payload shape is
        # valid (validator above guaranteed parseability + dict shape).
        payload = json.loads(raw)
        if isinstance(payload, dict):
            try:
                _check_params_to_commands_overlap(name, payload)
            except WorkflowError as e:
                print(f"ERROR: {e.message}")
                sys.exit(1)
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
# `files` command — resolve all source files for an integration
# ---------------------------------------------------------------------------

# Filename extensions that should NOT be included in the `extras` map
# (binary blobs, images, archives — not useful as text source files).
_EXTRAS_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".zip",
}


def cmd_files(args: list[str]) -> None:
    """Print all known source-file paths for an integration.

    Usage: workflow_state.py files <integration_id> [--format=text|json|paths]
    """
    fmt = "text"
    positional: list[str] = []
    for a in args:
        if a.startswith("--format="):
            fmt = a[len("--format="):]
        else:
            positional.append(a)

    if not positional:
        print("Usage: workflow_state.py files <integration_id> [--format=text|json|paths]")
        sys.exit(1)

    if fmt not in {"text", "json", "paths"}:
        print(f"ERROR: Unknown --format value '{fmt}'. Valid: text, json, paths.", file=sys.stderr)
        sys.exit(1)

    integration_id = " ".join(positional)
    info = get_integration_files(integration_id)

    if "error" in info:
        print(f"ERROR: {info['error']}", file=sys.stderr)
        sys.exit(1)

    if fmt == "json":
        print(json.dumps(info, indent=2))
        return

    if fmt == "paths":
        for key in ("yml", "code", "description", "readme", "test"):
            val = info.get(key)
            if val:
                print(val)
        return

    # Default: text
    name = info["integration_id"]
    lines = [
        f"\n{'=' * 60}",
        f"  {name} — source files",
        f"{'=' * 60}",
        f"  Directory:    {info['directory']}",
        f"  Base:         {info['base']}",
        f"  Language:     {info['code_language'] if info['code_language'] else '(unknown)'}",
        "",
        f"  YML:          {info['yml'] if info['yml'] else '(missing)'}",
        f"  Code:         {info['code'] if info['code'] else '(missing)'}",
        f"  Description:  {info['description'] if info['description'] else '(missing)'}",
        f"  README:       {info['readme'] if info['readme'] else '(missing)'}",
        f"  Test:         {info['test'] if info['test'] else '(missing)'}",
    ]
    extras = info.get("extras") or {}
    if extras:
        lines.append("")
        lines.append("  Other files in directory:")
        for fname in sorted(extras.keys()):
            lines.append(f"    - {fname}")
    print("\n".join(lines))


# ---------------------------------------------------------------------------
# `auth-params` command — print the auth-derived YML param ignore set
# ---------------------------------------------------------------------------

def cmd_auth_params(args: list[str]) -> None:
    """Print the union of YML param ids declared in the integration's
    ``Auth Details``.

    Usage: workflow_state.py auth-params <integration_id> [--format=text|json]

    Default format is ``text`` (one param id per line — easy to pipe
    into ``grep -vFf`` / ``xargs``). ``--format=json`` prints
    ``{"integration_id": "...", "params": [...]}`` for programmatic
    consumption (mirrors the ``files`` subcommand's format flag).
    """
    fmt = "text"
    positional: list[str] = []
    for a in args:
        if a.startswith("--format="):
            fmt = a[len("--format="):]
        else:
            positional.append(a)

    if not positional:
        print(
            "Usage: workflow_state.py auth-params <integration_id> "
            "[--format=text|json]"
        )
        sys.exit(1)

    if fmt not in {"text", "json"}:
        print(
            f"ERROR: Unknown --format value '{fmt}'. Valid: text, json.",
            file=sys.stderr,
        )
        sys.exit(1)

    integration_id = " ".join(positional)
    try:
        params = auth_param_ids(integration_id)
    except WorkflowError as e:
        print(f"ERROR: {e.message}", file=sys.stderr)
        sys.exit(1)

    if fmt == "json":
        print(json.dumps(
            {"integration_id": integration_id, "params": params},
            indent=2,
        ))
        return

    # Default: one param id per line. Empty list → nothing printed
    # (consistent with `grep -vFf`-friendly output).
    for p in params:
        print(p)


# ---------------------------------------------------------------------------
# `next` command
# ---------------------------------------------------------------------------

def _example_value_for(step: Step) -> str:
    """Return a canonical example value for the example CLI line."""
    if step.kind == "data" and step.name in JSON_VALUED_COLUMNS:
        if step.name == "Auth Details":
            return ("'{\"auth_types\":[],\"config\":\"NoneRequired\","
                    "\"other_connection\":[]}'")
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


def get_integration_files(integration_id: str) -> dict:
    """Return all known source-file paths for an integration.

    The integration's ``Integration File Path`` column holds the YML file
    path (relative to the repo root). All other integration source files
    live in the same directory and follow demisto-sdk conventions::

        <dir>/<base>.yml                 ← YML (manifest)
        <dir>/<base>.py                  ← Python source (or .js / .ps1)
        <dir>/<base>_description.md      ← short UI blurb
        <dir>/README.md                  ← long-form docs (filename is fixed)
        <dir>/<base>_test.py             ← unit tests (Python only)

    Returns a dict with the following keys (str values are repo-relative
    paths; ``None`` means "not present on disk")::

        {
            "integration_id": "<id>",
            "directory":      "<repo-relative dir>",
            "base":           "<basename without extension>",
            "yml":            "<path>" | None,
            "code":           "<path>" | None,
            "code_language":  "python" | "javascript" | "powershell" | None,
            "description":    "<path>" | None,
            "readme":         "<path>" | None,
            "test":           "<path>" | None,
            "extras":         {"<filename>": "<path>", ...},
        }

    Errors return ``{"error": "..."}`` (matching the convention used by
    ``get_integration_status`` and ``next_step_for``).
    """
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    yml_rel = row.get("Integration File Path", "").strip()
    if not yml_rel:
        return {
            "error": (
                f"Integration '{integration_id}' has no Integration File Path "
                f"set in the CSV."
            )
        }

    # Normalize separators for the relative path components, but resolve
    # against BASE_DIR for existence checks.
    directory_rel = os.path.dirname(yml_rel)
    basename = os.path.basename(yml_rel)
    # Strip a `.yml` extension specifically — leave anything else intact.
    if basename.lower().endswith(".yml"):
        base = basename[:-4]
    else:
        base = os.path.splitext(basename)[0]

    abs_dir = os.path.join(BASE_DIR, directory_rel)
    if not os.path.isdir(abs_dir):
        return {
            "error": (
                f"Integration directory '{directory_rel}' (from CSV) does "
                f"not exist on disk."
            )
        }

    def _rel_if_exists(filename: str) -> Optional[str]:
        abs_path = os.path.join(abs_dir, filename)
        if os.path.isfile(abs_path):
            return os.path.join(directory_rel, filename) if directory_rel else filename
        return None

    yml_path = _rel_if_exists(basename)

    code_path: Optional[str] = None
    code_language: Optional[str] = None
    for ext, lang in (("py", "python"), ("js", "javascript"), ("ps1", "powershell")):
        candidate = _rel_if_exists(f"{base}.{ext}")
        if candidate is not None:
            code_path = candidate
            code_language = lang
            break

    description_path = _rel_if_exists(f"{base}_description.md")
    readme_path = _rel_if_exists("README.md")

    test_path: Optional[str] = None
    if code_language == "python":
        test_path = _rel_if_exists(f"{base}_test.py")

    canonical_filenames = {
        basename,
        f"{base}.py",
        f"{base}.js",
        f"{base}.ps1",
        f"{base}_description.md",
        "README.md",
        f"{base}_test.py",
    }

    extras: dict[str, str] = {}
    try:
        entries = os.listdir(abs_dir)
    except OSError:
        entries = []
    for fname in entries:
        if fname in canonical_filenames:
            continue
        abs_entry = os.path.join(abs_dir, fname)
        # Only list regular files (skip subdirectories like test_data/).
        if not os.path.isfile(abs_entry):
            continue
        ext = os.path.splitext(fname)[1].lower()
        if ext in _EXTRAS_BINARY_EXTENSIONS:
            continue
        extras[fname] = (
            os.path.join(directory_rel, fname) if directory_rel else fname
        )

    return {
        "integration_id": row.get("Integration ID", ""),
        "directory": directory_rel,
        "base": base,
        "yml": yml_path,
        "code": code_path,
        "code_language": code_language,
        "description": description_path,
        "readme": readme_path,
        "test": test_path,
        "extras": extras,
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
    "files": cmd_files,
    "auth-params": cmd_auth_params,
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
