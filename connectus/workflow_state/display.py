"""Pretty-print and rendering helpers for workflow_state."""
from __future__ import annotations

import json
from typing import Optional

from workflow_state.config_loader import get_config
from workflow_state.state_machine import (
    current_step,
    has_workflow_progress,
    is_done,
)
from workflow_state.types import Step


def _summary_value(step: Step, raw: str) -> str:
    """Short inline display for status output."""
    cfg = get_config()
    val = raw.strip()
    if not val:
        if step.kind == "checkpoint":
            return "⬜"
        return "(not set)"
    if step.kind == "data" and step.name in cfg.json_valued_columns:
        if len(val) > 60:
            return f"{val[:57]}… (set; show-step for full)"
        return val
    return val


def _auth_other_connection_summary(raw: str) -> str:
    """One-line ``other_connection`` summary for an Auth Details JSON blob."""
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
    cfg = get_config()
    integration_id = row.get("Integration ID", "")
    cur = current_step(row)
    done_count = sum(1 for s in cfg.steps if is_done(row, s))
    total = len(cfg.steps)

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
        lines.append(
            f"                   (run 'workflow_state.py files {integration_id}' "
            f"to list all source files)"
        )
    lines.append(f"  Connector ID:    {connector_id if connector_id else '(not set)'}")
    lines.append("")

    lines.append(f"  Workflow ([{done_count}/{total}]):")
    lines.append("  " + "-" * 40)
    for step in cfg.steps:
        marker = " "
        if cur is not None and step.index == cur.index:
            marker = "▶"
        raw = row.get(step.name, "")
        display = _summary_value(step, raw)
        lines.append(f"  {marker}{step.index:2d}. {step.name:38s} : {display}")
        if step.name == "Auth Details" and raw.strip():
            oc_summary = _auth_other_connection_summary(raw)
            lines.append(f"     {'other_connection':38s} : {oc_summary}")

    lines.append("")
    if cur is None:
        if has_workflow_progress(row):
            lines.append(f"  🎉 All {total} steps complete!")
        else:
            lines.append("  ⏳ Not started")
    else:
        verb = cur.setter or "markpass"
        lines.append(f"  ➡️  Current step: #{cur.index} {cur.name} (run: {verb})")

    return "\n".join(lines)


def format_dashboard_row(row: dict[str, str]) -> Optional[str]:
    """Compact dashboard line. Returns None for not-started rows."""
    cfg = get_config()
    if not has_workflow_progress(row):
        return None

    integration_id = row.get("Integration ID", "")
    cur = current_step(row)
    done_count = sum(1 for s in cfg.steps if is_done(row, s))
    total = len(cfg.steps)

    bar = "".join("█" if is_done(row, s) else "░" for s in cfg.steps)
    status = cur.name if cur is not None else "✅ DONE"
    return f"  {integration_id:45s} [{bar}] {done_count}/{total}  → {status}"


def format_step_value(row: dict[str, str], step_name: str) -> str:
    """Pretty-print the value at ``step_name`` for ``row``."""
    cfg = get_config()
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

    if step_name in cfg.json_valued_columns:
        try:
            parsed = json.loads(value)
            pretty = json.dumps(parsed, indent=2, sort_keys=False)
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


def format_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> str:
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


# ---------------------------------------------------------------------------
# `next` command formatting
# ---------------------------------------------------------------------------

def _example_value_for(step: Step) -> str:
    """Return a canonical example value for the example CLI line."""
    cfg = get_config()
    if step.kind == "data" and step.name in cfg.json_valued_columns:
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
    cfg = get_config()
    integration_id = row.get("Integration ID", "")
    cur = current_step(row)
    if cur is None:
        return f"{integration_id} — all {len(cfg.steps)} steps complete. 🎉"

    lines = [f"{integration_id} — step {cur.index} of {len(cfg.steps)}: {cur.name}"]
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


def format_step_for_listing(row: dict[str, str]) -> str:
    """Return the user-facing step display: 'not started' / step name / '✅ DONE'."""
    if not has_workflow_progress(row):
        return "not started"
    cur = current_step(row)
    return cur.name if cur is not None else "✅ DONE"


# Legacy alias (private name used internally).
_format_step_for_listing = format_step_for_listing
