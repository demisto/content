"""The cascade-reset engine and state predicates.

All step-shape decisions (which step indices exist, which are flags,
which are checkpoints, which markers count as "done") flow from the
:class:`~workflow_state.types.WorkflowConfig` returned by
:func:`~workflow_state.config_loader.get_config`.
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


def step_flag_values(step: Step) -> tuple[str, ...]:
    """Return the effective enum for a flag step.

    Per-step ``Step.flag_values`` win over the global
    ``markers.flag_values``. Returns an empty tuple for non-flag steps.
    """
    if step.kind != "flag":
        return ()
    if step.flag_values is not None:
        return step.flag_values
    cfg = get_config()
    return tuple(cfg.markers.flag_values)


def _is_flag_value_match(step: Step, candidate: str) -> bool:
    """True iff ``candidate`` matches any of the step's enum values.

    Per-step enums (declared via a step's own ``flag_values`` list)
    are matched case-sensitively. The global YES/NO/N/A enum is
    matched case-insensitively for friendlier CLI behaviour.
    """
    values = step_flag_values(step)
    if step.flag_values is not None:
        return candidate in values
    return candidate.upper() in {v.upper() for v in values}


def read_step_value(row: dict[str, str], step: Step) -> str:
    """Return the cell value for ``step``, applying read-side defaults.

    For ``kind: flag`` steps with a declared ``default``, an empty cell
    returns the default value (read-side fallback only — the CSV cell
    is NOT auto-written). For all other shapes, returns the raw value.
    """
    raw = row.get(step.name, "")
    if step.kind == "flag" and step.default is not None and raw.strip() == "":
        return step.default
    return raw


def is_done(row: dict[str, str], step: Step) -> bool:
    """The unified completion predicate for any step kind."""
    val = read_step_value(row, step).strip()
    if step.kind == "data":
        return val != ""
    if step.kind == "flag":
        return _is_flag_value_match(step, val)
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
    the checkpoint columns list.
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

def reset_after(
    row: dict[str, str],
    step: Step,
    *,
    respect_preserve: bool = False,
) -> tuple[list[str], list[str]]:
    """Clear every step strictly after ``step``.

    Args:
        row: The integration row, mutated in place.
        step: The pivot step. Steps with ``index > step.index`` are
            candidates for clearing.
        respect_preserve: When ``True``, candidate steps whose
            ``preserve_on_reset`` flag is True are kept intact (their
            names are returned in the second tuple element so the
            caller can warn the user). When ``False`` (the default),
            preserve flags are ignored and every later step is cleared.
            NOTE: the ``set-auth``/``apply_step_action`` cascade now
            passes ``respect_preserve=True`` so the capability-mapping
            columns survive an Auth Details re-apply. The
            ``respect_preserve=False`` default here remains for the plain
            whole-row ``reset`` verb, which still wipes everything.

    Returns:
        ``(cleared, preserved)`` — both lists of column names. ``cleared``
        contains every step that was non-empty before the call AND was
        wiped; ``preserved`` lists every step that was non-empty AND was
        kept due to ``respect_preserve=True``. Empty values are not
        reported in either list.
    """
    cfg = get_config()
    cleared: list[str] = []
    preserved: list[str] = []
    for s in cfg.steps:
        if s.index <= step.index:
            continue
        had_value = row.get(s.name, "") != ""
        if respect_preserve and s.preserve_on_reset:
            if had_value:
                preserved.append(s.name)
            continue
        if had_value:
            cleared.append(s.name)
        row[s.name] = ""
    return cleared, preserved


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
        write is performed without resetting. The cascade reset HONORS
        ``preserve_on_reset``: tagged columns (e.g. the capability-mapping
        columns) survive even a ``set-auth`` reset; only ``reset`` (the
        whole-row wipe) ignores the flag.
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
        existing_raw = row.get(target.name, "").strip()
        new_raw = new_value.strip()
        # Compare with per-step enum awareness. The global YES/NO/N/A
        # enum is matched case-insensitively; per-step enums are
        # case-sensitive (matching their declared spelling).
        if target.flag_values is not None:
            same = existing_raw == new_raw and existing_raw in target.flag_values
        else:
            same = (
                existing_raw.upper() == new_raw.upper()
                and existing_raw.upper() in {v.upper() for v in cfg.markers.flag_values}
            )
        if same:
            return [], True

    # YAML-driven carve-out: when cascade_on_set=False (e.g. assignee),
    # write but DO NOT cascade-reset later steps.
    if not target.cascade_on_set:
        row[target.name] = new_value
        return [], False

    row[target.name] = new_value
    # set-auth/markpass cascade now HONORS preserve_on_reset. Columns
    # explicitly tagged preserve_on_reset (e.g. "Collect Capabilities",
    # "Params to Commands", "Params to Capabilities") survive this cascade
    # so that re-applying Auth Details — which the Step 3b elevation flow
    # does to inject a required test-module param into other_connection —
    # resets the workflow back to the Auth Details step WITHOUT discarding
    # the capability-mapping work. Everything not tagged is still wiped,
    # since auth-classification changes invalidate the rest of the
    # downstream artifacts. Plain ``reset`` (the "wipe the whole row" verb)
    # still ignores the flag.
    cleared, _preserved = reset_after(row, target, respect_preserve=True)
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
