"""CLI commands and main dispatch.

Each ``cmd_*`` function is the implementation of one CLI verb. They look
up validators / cross-checks by their ``Step.json_schema`` /
``Step.cross_check`` field rather than hardcoding step names.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Callable, Optional

from workflow_state.api import (
    _check_params_to_commands_overlap,
    auth_param_ids,
    get_integration_files,
)
from workflow_state.config_loader import get_config
from workflow_state.csv_io import (
    find_row,
)


def load_csv():  # type: ignore[no-redef]
    """Indirect to ``workflow_state.load_csv`` so tests can monkey-patch
    the package-level binding without having to know which submodule
    actually owns the function.
    """
    import workflow_state as _ws
    return _ws.load_csv()


def save_csv(rows):  # type: ignore[no-redef]
    """Indirect to ``workflow_state.save_csv`` so tests can monkey-patch."""
    import workflow_state as _ws
    return _ws.save_csv(rows)
from workflow_state.display import (
    format_by_assignee,
    format_dashboard_row,
    format_next_line,
    format_status,
    format_step_for_listing,
    format_step_value,
)
from workflow_state.exceptions import WorkflowError
from workflow_state.state_machine import (
    apply_step_action,
    current_step,
    has_workflow_progress,
    reset_after,
)
from workflow_state.types import Step
from workflow_state.validators import (
    get_named_validator,
    validate_auth_detail,
    validate_params_to_commands,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _resolve_git_user_name() -> Optional[str]:
    """Indirect to ``workflow_state._git_user_name`` so tests can monkey-patch."""
    import workflow_state as _ws
    return _ws._git_user_name()


def _resolve_row_or_exit(rows: list[dict[str, str]], name: str) -> int:
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)
    return idx


def _set_step_via_dispatch(
    row: dict[str, str],
    target: Step,
    new_value: str,
    verb: str,
) -> str:
    """Apply step action and return a user-facing message."""
    cfg = get_config()
    integration_id = row.get("Integration ID", "")
    cleared, no_op = apply_step_action(row, target, new_value, verb=verb)
    if no_op:
        return f"'{target.name}' already set to '{new_value}' for '{integration_id}'. No change."
    msg = f"Set '{target.name}' (step {target.index}/{len(cfg.steps)}) for '{integration_id}'."
    if cleared:
        msg += f"\n  Cleared {len(cleared)} subsequent step(s): {cleared}"
    return msg


# ---------------------------------------------------------------------------
# Status / dashboard / next
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


# ---------------------------------------------------------------------------
# Setters for JSON-shaped data steps
# ---------------------------------------------------------------------------

def _set_json_data_step(args: list[str], step_name: str, setter_cmd: str) -> None:
    """Shared CLI handler for set-auth / set-params-* / set-shared-params."""
    cfg = get_config()
    if len(args) < 2:
        print(f"Usage: workflow_state.py {setter_cmd} <integration_id> '<json>'")
        print("  The value must be valid JSON (see connectus/column-schemas.md).")
        sys.exit(1)

    name = args[0]
    raw = " ".join(args[1:])

    # JSON validation (always required for any json_schema-bound step)
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: '{step_name}' must be valid JSON.")
        print(f"  Got: {raw}")
        print(f"  Parse error: {e}")
        print(f"  Example: workflow_state.py {setter_cmd} \"{name}\" '{{}}'")
        sys.exit(1)

    target = cfg.step_by_name.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        sys.exit(1)

    # Look up the validator from the YAML config (Q3: bound by name).
    validator = get_named_validator(target.json_schema) if target.json_schema else None
    if validator is not None and target.json_schema not in (None, "any_json"):
        schema_errors = validator(raw)
        if schema_errors:
            label = step_name
            print(f"ERROR: {label} does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)

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
        print(f"  🎉 All {len(cfg.steps)} steps complete!")


def cmd_set_auth(args: list[str]) -> None:
    _set_json_data_step(args, "Auth Details", "set-auth")


def cmd_set_params_to_commands(args: list[str]) -> None:
    cfg = get_config()
    if len(args) >= 2:
        name = args[0]
        raw = " ".join(args[1:])
        # Strict schema check
        schema_errors = validate_params_to_commands(raw)
        if schema_errors:
            print("ERROR: Params to Commands does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)
        # Cross-check (overlap with Auth Details)
        target = cfg.step_by_name.get("Params to Commands")
        if target is not None and target.cross_check == "params_to_commands_no_auth_overlap":
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


# ---------------------------------------------------------------------------
# Assignee (with carve-out: cascade_on_set=False on the YAML step)
# ---------------------------------------------------------------------------

def cmd_set_assignee(args: list[str]) -> None:
    """Set the assignee for an integration.

    The carve-out (no cascade reset) is now driven by the YAML
    ``cascade_on_set: false`` field on the ``assignee`` step, which the
    state machine honours in :func:`apply_step_action`. We still write
    the cell directly to keep behaviour identical (no normalization
    surprises) and to bypass `apply_step_action`'s kind-specific paths.
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

    rows[idx]["assignee"] = assignee
    save_csv(rows)
    print(f"Set assignee for '{rows[idx]['Integration ID']}' to: {assignee}")
    cur = current_step(rows[idx])
    if cur is not None:
        print(f"  Current step: #{cur.index} {cur.name}")


def cmd_set_assignee_by_connector(args: list[str]) -> None:
    """Bulk-assign every integration in a connector. NO cascade reset."""
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

    from workflow_state.api import list_by_connector
    rows = load_csv()
    matches = list_by_connector(rows, connector_id)

    if not matches:
        print(f"ERROR: No integrations found for connector '{connector_id}'.")
        print(
            "  Tip: run 'workflow_state.py list-connectors' to see all known "
            "Connector IDs."
        )
        sys.exit(1)

    for row in matches:
        row["assignee"] = assignee

    save_csv(rows)
    print(
        f"Assigned {len(matches)} integration(s) in connector "
        f"'{connector_id}' to '{assignee}':"
    )
    for row in matches:
        print(f"  - {row.get('Integration ID', '')}")


# ---------------------------------------------------------------------------
# Flag setters / markpass / skip / fail / reset
# ---------------------------------------------------------------------------

def cmd_set_auth_flag(args: list[str]) -> None:
    """Set the 'requires auth parity test' flag (or whatever YAML configures).

    When the new value triggers a configured ``flag_auto_na_target``
    interaction, also write that interaction's ``write_value`` into the
    target step so the user is auto-advanced past it.
    """
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py set-auth-flag <integration_id> <YES|NO|N/A>")
        sys.exit(1)

    name = args[0]
    flag = args[1].upper().strip()

    if flag not in set(cfg.markers.flag_values):
        print(f"ERROR: Flag must be one of {list(cfg.markers.flag_values)}. Got: '{args[1]}'")
        sys.exit(1)

    flag_col = cfg.auth_parity_flag_column
    if flag_col is None:
        print("ERROR: no flag_auto_na_target interaction configured.")
        sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    target = cfg.step_by_name[flag_col]

    try:
        cleared, no_op = apply_step_action(rows[idx], target, flag, verb="set-auth-flag")
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    interaction = cfg.find_flag_auto_na_target(flag_col)
    if interaction is not None and flag in {v.upper() for v in interaction.when_value_in}:
        rows[idx][interaction.target_step] = interaction.write_value

    save_csv(rows)

    if no_op:
        print(f"'{flag_col}' already set to '{flag}' "
              f"for '{rows[idx]['Integration ID']}'. No change.")
    else:
        print(f"Set '{flag_col}' = {flag} "
              f"for '{rows[idx]['Integration ID']}'.")
        if cleared:
            print(f"  Cleared {len(cleared)} subsequent step(s): {cleared}")
        if interaction is not None and flag in {v.upper() for v in interaction.when_value_in}:
            print(f"  Auto-set '{interaction.target_step}' = {interaction.write_value}.")

    cur = current_step(rows[idx])
    if cur is not None:
        print(f"  Current step: #{cur.index} {cur.name}")
    elif has_workflow_progress(rows[idx]):
        print(f"  🎉 All {len(cfg.steps)} steps complete!")


def cmd_markpass(args: list[str]) -> None:
    cfg = get_config()
    non_checkpoint = cfg.non_checkpoint_steps

    if len(args) < 2:
        print("Usage: workflow_state.py markpass <integration_id> <step_name>")
        print("\nCheckpoint steps (in order):")
        for s in cfg.steps:
            if s.kind == "checkpoint":
                print(f"  {s.index:2d}. {s.name}")
        print("\nNon-checkpoint columns (use a different command):")
        for step_name, cmd in non_checkpoint.items():
            print(f"  - '{step_name}' → use '{cmd}'")
        sys.exit(1)

    name = args[0]
    step_name = " ".join(args[1:])

    if step_name in non_checkpoint:
        correct = non_checkpoint[step_name]
        print(
            f"ERROR: '{step_name}' is not a pass/fail checkpoint.\n"
            f"  Use '{correct}' instead.\n"
            f"  Example: workflow_state.py {correct} \"{name}\" <value>"
        )
        sys.exit(1)

    target = cfg.step_by_name.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid checkpoint steps: {', '.join(cfg.checkpoint_columns)}")
        sys.exit(1)

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    row = rows[idx]

    # Honour any configured flag_auto_na_target interaction whose
    # target_step matches.
    for inter in cfg.step_interactions:
        if inter.kind == "flag_auto_na_target" and inter.target_step == step_name:
            flag = row.get(inter.when_step, "").strip().upper()
            if flag == "":
                print(
                    f"ERROR: Cannot mark '{step_name}' as passed — "
                    f"'{inter.when_step}' flag is not set.\n"
                    f"  Use 'set-auth-flag' first.\n"
                    f"  Example: workflow_state.py set-auth-flag "
                    f"\"{row['Integration ID']}\" YES"
                )
                sys.exit(1)
            if flag in {v.upper() for v in inter.when_value_in}:
                row[step_name] = inter.write_value
                save_csv(rows)
                print(
                    f"'{step_name}' set to {inter.write_value} (auth parity test not required)."
                )
                return

    try:
        cleared, no_op = apply_step_action(row, target, cfg.markers.check, verb="markpass")
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    save_csv(rows)
    if no_op:
        print(f"'{step_name}' already passed. No change.")
    else:
        print(f"✅ '{step_name}' (step {target.index}/{len(cfg.steps)}) marked as passed "
              f"for '{row['Integration ID']}'.")
        if cleared:
            print(f"  Cleared {len(cleared)} subsequent step(s): {cleared}")

    cur = current_step(row)
    if cur is not None:
        print(f"  Next step: #{cur.index} {cur.name}")
    elif has_workflow_progress(row):
        print(f"  🎉 All {len(cfg.steps)} steps complete!")


def cmd_skip(args: list[str]) -> None:
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py skip <integration_id> <step_name>")
        print("Skippable (optional) steps:")
        for s in cfg.steps:
            if s.optional:
                print(f"  {s.index:2d}. {s.name}")
        sys.exit(1)

    name = args[0]
    step_name = " ".join(args[1:])

    target = cfg.step_by_name.get(step_name)
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
        cleared, _no_op = apply_step_action(row, target, cfg.markers.na, verb="skip")
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
    """Shared implementation for ``fail`` and ``reset-to``."""
    cfg = get_config()
    target = cfg.step_by_name.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)

    row = rows[idx]
    integration_id = row.get("Integration ID", "")

    if target.index == 1:
        for s in cfg.steps:
            row[s.name] = ""
    else:
        prev = cfg.step_by_index[target.index - 1]
        row[target.name] = ""
        reset_after(row, prev)

    save_csv(rows)
    print(f"{verb}: cleared step {target.index} ('{target.name}') and all "
          f"subsequent steps for '{integration_id}'.")
    cur = current_step(row)
    if cur is not None:
        print(f"  Current step is now: #{cur.index} {cur.name}")


def cmd_fail(args: list[str]) -> None:
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py fail <integration_id> <step_name>")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)
    name = args[0]
    step_name = " ".join(args[1:])
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    _do_reset_to(rows, idx, step_name, verb="Reset (fail)")


def cmd_reset_to(args: list[str]) -> None:
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py reset-to <integration_id> <step_name>")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)
    name = args[0]
    step_name = " ".join(args[1:])
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    _do_reset_to(rows, idx, step_name, verb="Reset-to")


def cmd_reset(args: list[str]) -> None:
    cfg = get_config()
    if not args:
        print("Usage: workflow_state.py reset <integration_id>")
        sys.exit(1)

    name = args[0]
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)

    for col in cfg.workflow_columns:
        rows[idx][col] = ""

    save_csv(rows)
    print(f"Reset all workflow columns for '{rows[idx]['Integration ID']}'.")


# ---------------------------------------------------------------------------
# Listing commands
# ---------------------------------------------------------------------------

def cmd_at_step(args: list[str]) -> None:
    cfg = get_config()
    if not args:
        print("Usage: workflow_state.py at-step <step_name>")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)

    step_name = " ".join(args)
    if step_name not in cfg.step_by_name:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
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
    from workflow_state.api import list_by_assignee
    matches = list_by_assignee(rows, assignee_name)
    print(format_by_assignee(matches, assignee_name))


def cmd_list_by_connector(args: list[str]) -> None:
    if not args:
        print("Usage: workflow_state.py list-by-connector <connector_id>")
        sys.exit(1)

    connector_id = " ".join(args)
    rows = load_csv()
    from workflow_state.api import list_by_connector
    matches = list_by_connector(rows, connector_id)

    if not matches:
        print(f"No integrations found for connector '{connector_id}'.")
        print("  Tip: run 'workflow_state.py list-connectors' to see all known Connector IDs.")
        return

    print(f"\nIntegrations in connector '{connector_id}' ({len(matches)}):")
    for row in matches:
        integration_id = row.get("Integration ID", "")
        assignee = row.get("assignee", "").strip() or "unassigned"
        step_display = format_step_for_listing(row)
        print(f"  - {integration_id}  [assignee: {assignee}]  → {step_display}")


def cmd_list_connectors(_args: list[str]) -> None:
    rows = load_csv()

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

    sorted_keys = sorted(buckets.keys(), key=lambda k: buckets[k]["display"].lower())

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


def cmd_show_step(args: list[str]) -> None:
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py show-step <integration_id> <column_name>")
        print("\nValid columns:")
        for col in cfg.identity_column_names:
            print(f"  - {col} (data)")
        for col in cfg.workflow_columns:
            print(f"  - {col}")
        sys.exit(1)

    name = args[0]
    step = " ".join(args[1:])

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    valid_steps = set(cfg.workflow_columns) | set(cfg.identity_column_names)
    if step not in valid_steps:
        print(f"ERROR: Unknown column '{step}' for integration '{rows[idx]['Integration ID']}'.")
        print(f"Valid columns: {', '.join(sorted(valid_steps))}")
        sys.exit(1)

    print(format_step_value(rows[idx], step))


# ---------------------------------------------------------------------------
# files / auth-params
# ---------------------------------------------------------------------------

def cmd_files(args: list[str]) -> None:
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


def cmd_auth_params(args: list[str]) -> None:
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

    for p in params:
        print(p)


# ---------------------------------------------------------------------------
# next
# ---------------------------------------------------------------------------

def _parse_next_flags(args: list[str]) -> tuple[Optional[str], bool, list[str]]:
    """Parse `--connector <id>` and `--mine` out of args (order-independent)."""
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
        if a.startswith("--connector="):
            connector_id = a[len("--connector="):]
            i += 1
            continue
        leftover.append(a)
        i += 1
    return connector_id, mine, leftover


def cmd_next(args: list[str]) -> None:
    rows = load_csv()

    if not rows:
        print("(no rows in CSV — nothing to do)")
        return

    connector_id, mine, leftover = _parse_next_flags(args)

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
        show_all = False

    target_assignee: Optional[str] = None
    use_assignee_filter = (not show_all) and (mine or connector_id is None)
    if use_assignee_filter:
        target_assignee = _resolve_git_user_name()
        if not target_assignee:
            if connector_id is None:
                print(
                    "ERROR: cannot determine current user via 'git config user.name'.\n"
                    "  Pass an integration ID, or use 'next --all' to list everyone's work."
                )
                sys.exit(1)
            target_assignee = None
            use_assignee_filter = False

    candidate_rows = rows
    if connector_id is not None:
        from workflow_state.api import list_by_connector
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
# Help & main dispatch
# ---------------------------------------------------------------------------

_DOC = """Workflow State Machine for connectus-migration-pipeline.csv (UNIFIED 16-STEP MODEL)

This script manages the workflow tracking columns in the CSV. The shape
of the workflow (steps, columns, markers) is declared in
connectus/workflow_state_config.yml. The runtime engine lives in the
connectus/workflow_state/ Python package.

Usage examples:
  python3 connectus/workflow_state.py status "Cisco Spark"
  python3 connectus/workflow_state.py dashboard
  python3 connectus/workflow_state.py next
  python3 connectus/workflow_state.py set-assignee "Cisco Spark" "John Doe"
  python3 connectus/workflow_state.py set-auth "Cisco Spark" '<json>'
  python3 connectus/workflow_state.py markpass "Cisco Spark" "wrote/checked code"
"""


def cmd_help(_args: list[str]) -> None:
    print(_DOC)


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


# Re-exports for back-compat: tests and external callers can import
# `validate_auth_detail` / `validate_params_to_commands` from the module
# (both were CLI-side names in the legacy file).
__all__ = sorted({
    *COMMANDS.keys(),
    "main",
    "_set_json_data_step",
    "_check_params_to_commands_overlap",
    "_resolve_row_or_exit",
    "_set_step_via_dispatch",
    "_parse_next_flags",
    "_git_user_name",
    "validate_auth_detail",
    "validate_params_to_commands",
})
