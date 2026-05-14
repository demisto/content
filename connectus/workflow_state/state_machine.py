"""The cascade-reset engine and state predicates.

All step-shape decisions (which step indices exist, which are flags,
which are checkpoints, which markers count as "done") flow from the
:class:`~workflow_state.types.WorkflowConfig` returned by
:func:`~workflow_state.config_loader.get_config`. The legacy module-level
constants (``STEPS``, ``CHECK``, …) are derived from it via
:mod:`workflow_state.api`.
"""
from __future__ import annotations

import sys
from typing import Optional

from workflow_state.config_loader import get_config
from workflow_state.exceptions import WorkflowError
from workflow_state.types import Step


# ---------------------------------------------------------------------------
# State predicates
# ---------------------------------------------------------------------------

def is_checked(value: str) -> bool:
    """Whether a checkpoint cell value represents 'done'.

    Q2 BREAKING CHANGE (2026-05): only the canonical values listed in
    ``markers.checkpoint_done_values`` are accepted (default: ``"✅"``
    and ``"N/A"``). Historical aliases (``YES``, ``true``, ``True``,
    ``done``, ``Done``, ``DONE``) are NO LONGER recognized.
    """
    cfg = get_config()
    return value.strip() in cfg.markers.checkpoint_done_values


def is_done(row: dict[str, str], step: Step) -> bool:
    """The unified completion predicate for any step kind."""
    cfg = get_config()
    val = row.get(step.name, "").strip()
    if step.kind == "data":
        return val != ""
    if step.kind == "flag":
        return val.upper() in set(cfg.markers.flag_values)
    if step.kind == "checkpoint":
        return is_checked(val)
    raise AssertionError(f"Unknown step kind: {step.kind!r}")


def current_step(row: dict[str, str]) -> Optional[Step]:
    """First step that is not yet done; ``None`` if every step is done."""
    cfg = get_config()
    for step in cfg.steps:
        if not is_done(row, step):
            return step
    return None


def get_current_step(row: dict[str, str]) -> Optional[str]:
    """Legacy wrapper: returns the current step's name (or None)."""
    s = current_step(row)
    return s.name if s is not None else None


def get_step(name: str) -> Step:
    """Look up a Step by name; raise :class:`WorkflowError` if unknown."""
    cfg = get_config()
    step = cfg.step_by_name.get(name)
    if step is None:
        raise WorkflowError(
            f"Unknown step: '{name}'.\n"
            f"  Valid steps:\n"
            + "\n".join(f"    {s.index:2d}. {s.name}" for s in cfg.steps)
        )
    return step


def get_step_index(step_name: str) -> int:
    """Return the 0-based index of a checkpoint step within
    ``CHECKPOINT_COLUMNS`` (preserves old API for any external callers).
    """
    cfg = get_config()
    checkpoint_columns = cfg.checkpoint_columns
    try:
        return checkpoint_columns.index(step_name)
    except ValueError:
        raise ValueError(
            f"Unknown checkpoint step: '{step_name}'. "
            f"Valid steps: {', '.join(checkpoint_columns)}"
        )


# ---------------------------------------------------------------------------
# Cascade reset and normalization
# ---------------------------------------------------------------------------

def reset_after(row: dict[str, str], step: Step) -> list[str]:
    """Clear every step strictly after ``step``. Returns the cleared columns."""
    cfg = get_config()
    cleared: list[str] = []
    for s in cfg.steps:
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
    cfg = get_config()
    cleared: list[str] = []
    found_incomplete = False
    for step in cfg.steps:
        if not found_incomplete:
            if not is_done(row, step):
                found_incomplete = True
            continue
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
# Unified dispatch — the heart of the cascade-reset rule
# ---------------------------------------------------------------------------

def _can_advance_to(row: dict[str, str], target: Step) -> tuple[bool, str]:
    """True iff every step strictly before ``target`` is done."""
    cfg = get_config()
    for s in cfg.steps:
        if s.index >= target.index:
            break
        if not is_done(row, s):
            verb = s.setter if s.setter else "markpass"
            return False, (
                f"Cannot advance to '{target.name}' (step {target.index}/{len(cfg.steps)}) yet — "
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
      - If ``target`` is AHEAD of the current step: raise :class:`WorkflowError`.
      - If ``target`` is AT current step: write the value (no clearing).
      - If ``target`` is BEHIND current (or already done): write the new
        value AND ``reset_after(target)`` — UNLESS ``target.cascade_on_set``
        is False (the YAML-driven assignee carve-out), in which case the
        write is performed without resetting.
      - For ``flag`` steps: setting the same value is a no-op (no reset).
    """
    cfg = get_config()
    cur = current_step(row)
    cur_idx = cur.index if cur is not None else len(cfg.steps) + 1

    if cur is not None and target.index > cur_idx:
        raise WorkflowError(
            f"Cannot {verb} '{target.name}' (step {target.index}/{len(cfg.steps)}) yet — "
            f"current step is #{cur.index} '{cur.name}'.\n"
            f"  Complete it first via "
            f"'{cur.setter or 'markpass'}'."
        )

    if target.kind == "flag":
        existing = row.get(target.name, "").strip().upper()
        if existing == new_value.strip().upper() and existing in set(cfg.markers.flag_values):
            return [], True

    # YAML-driven carve-out: when cascade_on_set=False (e.g. assignee),
    # write but DO NOT cascade-reset later steps.
    if not target.cascade_on_set:
        row[target.name] = new_value
        return [], False

    row[target.name] = new_value
    cleared = reset_after(row, target)
    return cleared, False


# ---------------------------------------------------------------------------
# Helpers used by multiple commands
# ---------------------------------------------------------------------------

def has_workflow_progress(row: dict[str, str]) -> bool:
    """Return True if the row has any non-trivial workflow progress.

    Being merely assigned does NOT count as progress.
    """
    cfg = get_config()
    return any(
        row.get(s.name, "").strip()
        for s in cfg.steps
        if s.name != "assignee"
    )


# ---------------------------------------------------------------------------
# Backward-compat shims (for old call sites and tests)
# ---------------------------------------------------------------------------

def reset_from_step(row: dict[str, str], step_name: str) -> None:
    """Legacy API: clear ``step_name`` and every later step."""
    cfg = get_config()
    step = cfg.step_by_name.get(step_name)
    if step is None:
        raise ValueError(
            f"Unknown step: '{step_name}'. "
            f"Valid steps: {', '.join(cfg.workflow_columns)}"
        )
    prev_index = step.index - 1
    if prev_index < 1:
        for s in cfg.steps:
            row[s.name] = ""
        return
    prev = cfg.step_by_index[prev_index]
    row[step.name] = ""
    reset_after(row, prev)


def markpass_step(row: dict[str, str], step_name: str) -> str:
    """Legacy API: mark a checkpoint step as passed. Returns a status message."""
    cfg = get_config()
    integration_id = row.get("Integration ID", "")
    non_checkpoint = cfg.non_checkpoint_steps

    if step_name in non_checkpoint:
        correct_cmd = non_checkpoint[step_name]
        return (
            f"ERROR: '{step_name}' is not a pass/fail checkpoint.\n"
            f"  Use '{correct_cmd}' instead.\n"
            f"  Example: workflow_state.py {correct_cmd} "
            f"\"{integration_id}\" <value>"
        )

    step = cfg.step_by_name.get(step_name)
    if step is None:
        raise ValueError(
            f"Unknown checkpoint step: '{step_name}'. "
            f"Valid steps: {', '.join(cfg.checkpoint_columns)}"
        )

    if is_done(row, step):
        return f"'{step_name}' is already marked as passed for '{integration_id}'."

    # Honour any flag_auto_na_target interaction whose target_step matches.
    for inter in cfg.step_interactions:
        if inter.kind == "flag_auto_na_target" and inter.target_step == step_name:
            flag = row.get(inter.when_step, "").strip().upper()
            if flag in {v.upper() for v in inter.when_value_in}:
                row[step_name] = inter.write_value
                return f"'{step_name}' set to {inter.write_value} (auth parity test not required)."
            if flag == "":
                return (
                    f"ERROR: Cannot mark '{step_name}' as passed — "
                    f"'{inter.when_step}' flag is not set.\n"
                    f"  Use 'set-auth-flag' first.\n"
                    f"  Example: workflow_state.py set-auth-flag "
                    f"\"{integration_id}\" YES"
                )

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

    row[step.name] = cfg.markers.check
    return f"✅ '{step_name}' marked as passed for '{integration_id}'."
