"""Programmatic API and auth-derived helpers.

Returns plain dicts. Consumed by the SKILL via subprocess and (when
imported in-process) by other Python callers.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

from auth_config_parser import (
    project_xsoar_param_to_yml_id as _pkg_project_xsoar_param_to_yml_id,
)
from workflow_state.config_loader import get_config
from workflow_state.csv_io import (
    BASE_DIR,
    find_row,
)


def load_csv():  # type: ignore[no-redef]
    """Indirect to ``workflow_state.load_csv`` so tests can monkey-patch."""
    import workflow_state as _ws
    return _ws.load_csv()


def save_csv(rows):  # type: ignore[no-redef]
    """Indirect to ``workflow_state.save_csv`` so tests can monkey-patch."""
    import workflow_state as _ws
    return _ws.save_csv(rows)
from workflow_state.exceptions import WorkflowError
from workflow_state.state_machine import (
    apply_step_action,
    current_step,
    has_workflow_progress,
    is_done,
    reset_after,
)
from workflow_state.validators import (
    auth_param_sources as _auth_param_sources,
    validate_auth_detail,
)


# ---------------------------------------------------------------------------
# Auth-derived ignore set (cross-step exclusion plumbing)
# ---------------------------------------------------------------------------

def _project_xsoar_param_to_yml_id(xsoar_param: str) -> str:
    """Backward-compatible wrapper — delegates to the package."""
    return _pkg_project_xsoar_param_to_yml_id(xsoar_param)


def auth_param_ids(integration_id: str) -> list[str]:
    """Return the union of YML param ids declared in an integration's
    ``Auth Details``.
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
# Programmatic dict-returning API
# ---------------------------------------------------------------------------

def get_integration_status(integration_id: str) -> dict:
    """Return a dict summary of an integration's workflow state."""
    cfg = get_config()
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    cur = current_step(row)
    completed = sum(1 for s in cfg.steps if is_done(row, s))
    return {
        "name": row.get("Integration ID", ""),
        "current_step": cur.name if cur else None,
        "current_step_index": cur.index if cur else None,
        "workflow": {col: row.get(col, "") for col in cfg.workflow_columns},
        "completed_steps": completed,
        "total_steps": len(cfg.steps),
        "progress_pct": round(completed / len(cfg.steps) * 100, 1),
        "all_complete": cur is None and completed > 0,
    }


# Filename extensions that should NOT be included in the `extras` map.
_EXTRAS_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".zip",
}


def get_integration_files(integration_id: str) -> dict:
    """Return all known source-file paths for an integration."""
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

    directory_rel = os.path.dirname(yml_rel)
    basename = os.path.basename(yml_rel)
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


# Forward declaration needed for next_step_for; defined in display.py.
def _format_next_line(row: dict[str, str]) -> str:
    from workflow_state.display import format_next_line
    return format_next_line(row)


def next_step_for(integration_id: str) -> dict:
    """Return the next-action info for an integration."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}
    row = rows[idx]
    cur = current_step(row)
    if cur is None:
        return {"complete": True, "message": _format_next_line(row)}
    return {
        "complete": False,
        "step_index": cur.index,
        "step_name": cur.name,
        "setter": cur.setter,
        "description": cur.description,
        "message": _format_next_line(row),
    }


def _row_summary_dict(row: dict[str, str]) -> dict:
    cfg = get_config()
    cur = current_step(row)
    completed = sum(1 for s in cfg.steps if is_done(row, s))
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


def list_by_assignee(rows: list[dict[str, str]], assignee_name: str) -> list[dict[str, str]]:
    """Filter rows to those whose assignee matches (case-insensitive)."""
    target = assignee_name.strip().lower()
    return [row for row in rows if row.get("assignee", "").strip().lower() == target]


def list_by_connector(rows: list[dict[str, str]], connector_id: str) -> list[dict[str, str]]:
    """Filter rows to those whose Connector ID matches (case-insensitive)."""
    target = connector_id.strip().lower()
    return [
        row for row in rows
        if row.get("Connector ID", "").strip().lower() == target
    ]


def list_integrations_by_connector(connector_id: str) -> list[dict]:
    rows = load_csv()
    matches = list_by_connector(rows, connector_id)
    return [_row_summary_dict(row) for row in matches]


def integrations_for_assignee(assignee_name: str) -> list[dict]:
    rows = load_csv()
    matches = list_by_assignee(rows, assignee_name)
    return [_row_summary_dict(row) for row in matches]


def assign_connector(connector_id: str, assignee_name: str) -> dict:
    """Assign every integration in ``connector_id`` to ``assignee_name``.

    Mirrors the ``set-assignee-by-connector`` carve-out: NO cascade reset.
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
    cfg = get_config()
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    target = cfg.step_by_name.get(step_name)
    if target is None:
        return {"error": f"Unknown step '{step_name}'."}
    non_checkpoint = cfg.non_checkpoint_steps
    if step_name in non_checkpoint:
        return {"error": f"'{step_name}' is not a checkpoint; use {non_checkpoint[step_name]}."}

    # Honour any flag_auto_na_target interaction whose target_step matches.
    for inter in cfg.step_interactions:
        if inter.kind == "flag_auto_na_target" and inter.target_step == step_name:
            flag = row.get(inter.when_step, "").strip().upper()
            if flag in {v.upper() for v in inter.when_value_in}:
                row[step_name] = inter.write_value
                save_csv(rows)
                cur = current_step(row)
                return {
                    "message": f"'{step_name}' set to {inter.write_value}.",
                    "completed_step": step_name,
                    "current_step": cur.name if cur else None,
                }
            if flag == "":
                return {"error": f"'{step_name}' requires the flag to be set first."}

    try:
        cleared, no_op = apply_step_action(row, target, cfg.markers.check, verb="markpass")
    except WorkflowError as e:
        return {"error": e.message}

    save_csv(rows)
    cur = current_step(row)
    return {
        "message": (
            f"'{step_name}' marked passed."
            + (f" Cleared: {cleared}" if cleared else "")
            + (" (no-op)" if no_op else "")
        ),
        "completed_step": step_name,
        "current_step": cur.name if cur else None,
    }


def fail_integration_step(integration_id: str, step_name: str) -> dict:
    """Programmatic ``fail`` / ``reset-to`` (they share semantics).

    Honours ``preserve_on_reset`` on later steps. The named ``step_name``
    is always cleared even if it is itself preserved (explicit-target
    carve-out).
    """
    cfg = get_config()
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}
    target = cfg.step_by_name.get(step_name)
    if target is None:
        return {"error": f"Unknown step '{step_name}'."}
    row = rows[idx]
    # Explicit-target carve-out: clear the named target even if it's
    # tagged preserve_on_reset.
    row[target.name] = ""
    cleared, preserved = reset_after(row, target, respect_preserve=True)
    save_csv(rows)
    cur = current_step(row)
    msg = f"Reset '{step_name}' and subsequent non-preserved steps."
    if preserved:
        msg += f" Preserved (preserve_on_reset=true): {preserved}."
    return {
        "message": msg,
        "current_step": cur.name if cur else None,
        "preserved": preserved,
    }


def reset_integration_to_step(integration_id: str, step_name: str) -> dict:
    return fail_integration_step(integration_id, step_name)


def skip_integration_step(integration_id: str, step_name: str) -> dict:
    cfg = get_config()
    target = cfg.step_by_name.get(step_name)
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
        cleared, _ = apply_step_action(row, target, cfg.markers.na, verb="skip")
    except WorkflowError as e:
        return {"error": e.message}
    save_csv(rows)
    cur = current_step(row)
    return {
        "message": f"Skipped '{step_name}'." + (f" Cleared: {cleared}" if cleared else ""),
        "current_step": cur.name if cur else None,
    }


def set_integration_auth(integration_id: str, auth_detail_json: str) -> dict:
    cfg = get_config()
    schema_errors = validate_auth_detail(auth_detail_json)
    if schema_errors:
        return {
            "error": "Auth Details schema validation failed:\n"
            + "\n".join(f"  - {e}" for e in schema_errors)
        }

    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {"error": f"Integration '{integration_id}' not found."}

    row = rows[idx]
    target = cfg.step_by_name["Auth Details"]
    try:
        cleared, _ = apply_step_action(row, target, auth_detail_json, verb="set-auth")
    except WorkflowError as e:
        return {"error": e.message}
    save_csv(rows)
    cur = current_step(row)
    return {
        "message": (
            f"Set 'Auth Details' for '{row.get('Integration ID', '')}'."
            + (f" Cleared: {cleared}" if cleared else "")
        ),
        "current_step": cur.name if cur else None,
    }


# ---------------------------------------------------------------------------
# Cross-check: implementation referenced by the validators registry name
# `params_to_commands_no_auth_overlap`. Lives here because it consults the
# CSV (load_csv) and auth_param_ids; importing those into validators.py
# would create a cycle.
# ---------------------------------------------------------------------------

def _check_params_to_commands_overlap(integration_id: str, payload: dict) -> None:
    """Reject ``set-params-to-commands`` payloads that overlap with auth."""
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
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

    auth_ids = set(auth_param_ids(integration_id))

    commands_block = payload.get("commands") if isinstance(payload, dict) else None
    if not isinstance(commands_block, dict):
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

    lines = [
        f"'Params to Commands' for '{integration_id}' contains "
        f"{len(offenders)} param(s) that are already declared in "
        f"'Auth Details'. The two columns MUST be disjoint.",
        "",
        "Offending (command, param) pairs:",
    ]
    for cmd, p in sorted(offenders):
        lines.append(f"  - ({cmd!r}, {p!r})")

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
        f"'set-auth' and remove it from 'auth_types[].xsoar_param_map' "
        f"(drop the offending key) or 'other_connection' first. Do NOT "
        f"bypass this rejection by hand-stripping just to make the "
        f"call go through.",
    ])

    raise WorkflowError("\n".join(lines))
