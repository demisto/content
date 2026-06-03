"""Programmatic API and auth-derived helpers.

Returns plain dicts. Consumed by the SKILL via subprocess and (when
imported in-process) by other Python callers.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
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
    validate_seed_overrides_no_auth_overlap as _validate_seed_overrides_no_auth_overlap,
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
        raise WorkflowError(
            f"'Auth Details' for integration '{integration_id}' is "
            f"missing required key 'other_connection'. Re-run "
            f"'set-auth' with a corrected payload."
        )

    sources = _auth_param_sources(parsed)
    return sorted(sources.keys())


def test_module_params(integration_id: str) -> list[str]:
    """Return the param ids that ``test-module`` consumes for an integration.

    Reads the ``Params to Commands`` cell, parses it as JSON, and returns
    the list under ``commands["test-module"]``. This is the canonical
    qualification source for ``Params for test with default in code``
    (Step 3a) — instead of re-doing source-code review to figure out
    which params test-module reads, callers consume the validated
    per-command list that was already curated in Step 2.

    Returns an empty list when ``test-module`` is present in the JSON
    but maps to no params (the analyzer's normal "test-module consumed
    nothing besides auth" case).

    Raises :class:`WorkflowError` when:
      * the integration row is missing,
      * the ``Params to Commands`` cell is not set (Step 2 hasn't run),
      * the cell is not valid JSON / not a dict / has no ``commands`` key,
      * the ``commands`` mapping has no ``test-module`` entry.

    Each of these is a precondition violation rather than a recoverable
    empty result, so the caller gets a precise error message instead of
    silently treating "missing data" as "empty list".
    """
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        raise WorkflowError(
            f"Integration '{integration_id}' not found in the CSV."
        )

    raw = rows[idx].get("Params to Commands", "").strip()
    if not raw:
        raise WorkflowError(
            f"'Params to Commands' is not set for integration "
            f"'{rows[idx].get('Integration ID', integration_id)}'. "
            f"Run 'set-params-to-commands' first — this helper is the "
            f"canonical qualification source for 'Params for test with "
            f"default in code', so the per-command analysis must be "
            f"in place."
        )

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise WorkflowError(
            f"'Params to Commands' for integration '{integration_id}' "
            f"is not valid JSON: {e}. Re-run 'set-params-to-commands' "
            f"with a corrected payload."
        )
    if not isinstance(parsed, dict):
        raise WorkflowError(
            f"'Params to Commands' for integration '{integration_id}' "
            f"is not a JSON object (got {type(parsed).__name__}). "
            f"Re-run 'set-params-to-commands'."
        )

    commands = parsed.get("commands")
    if not isinstance(commands, dict):
        raise WorkflowError(
            f"'Params to Commands' for integration '{integration_id}' "
            f"is missing the 'commands' object (or it is not a dict). "
            f"Re-run 'set-params-to-commands' with a payload conforming "
            f"to column-schemas.md §'Params to Commands'."
        )

    if "test-module" not in commands:
        raise WorkflowError(
            f"'Params to Commands' for integration '{integration_id}' "
            f"has no 'test-module' entry. Every integration's "
            f"'Params to Commands' payload must include a 'test-module' "
            f"key (use an empty list [] when test-module consumes no "
            f"non-auth params). Re-run 'set-params-to-commands' with "
            f"the test-module key included."
        )

    value = commands["test-module"]
    if not isinstance(value, list):
        raise WorkflowError(
            f"'Params to Commands' for integration '{integration_id}' "
            f"has 'commands.test-module' = {type(value).__name__}; "
            f"expected list of param-id strings."
        )

    # Defensive: ensure each entry is a string. The set-params-to-commands
    # validator should reject non-string entries, but this helper is the
    # contract boundary, so re-check.
    for i, p in enumerate(value):
        if not isinstance(p, str) or not p:
            raise WorkflowError(
                f"'Params to Commands' for integration '{integration_id}' "
                f"has 'commands.test-module[{i}]' = {p!r}; expected a "
                f"non-empty string."
            )

    return sorted(value)


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


def run_checkpoint_gate(
    integration_id: str,
    gate_name: str,
    timeout: Optional[int] = None,
) -> dict:
    """Resolve the integration directory and run a checkpoint gate.

    Thin wrapper around :func:`workflow_state.gates.run_gate` that handles
    the on-disk directory resolution (so ``gates`` stays free of an
    ``api`` import). Returns the gate verdict dict augmented with the
    integration id. Infrastructure failures (e.g. missing file path) are
    returned as a non-allowing verdict with ``exit_code: None``.
    """
    from workflow_state.gates import run_gate

    files_info = get_integration_files(integration_id)
    if "error" in files_info:
        return {
            "allow": False,
            "reason": files_info["error"],
            "exit_code": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "gate": gate_name,
            "integration_id": integration_id,
        }
    directory_rel = files_info.get("directory") or ""
    abs_dir = os.path.join(BASE_DIR, directory_rel) if directory_rel else BASE_DIR

    verdict = run_gate(gate_name, abs_dir, integration_id, timeout=timeout)
    verdict["integration_id"] = integration_id
    return verdict


def markpass_integration_step(
    integration_id: str,
    step_name: str,
    *,
    gate_timeout: Optional[int] = None,
) -> dict:
    """Mark a checkpoint as passed via the unified dispatch.

    If the checkpoint declares a ``gate`` (see :class:`Step`), the gate
    command is RUN first and the pass marker is written only if it
    succeeds — mirroring the auth-parity gate inside ``set-auth``. There
    is NO bypass: a gated checkpoint must run its command and pass.
    """
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
    # This short-circuit runs BEFORE the gate: an auto-N/A means the
    # checkpoint is "not applicable", so there is nothing to verify.
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

    # ----- Self-executing checkpoint gate -----------------------------------
    # If the step declares a gate, RUN it and reject the markpass unless it
    # passes. Persist (apply_step_action + save_csv) happens only after the
    # gate clears — the ordering IS the enforcement (same as set-auth).
    # There is NO bypass.
    if target.gate:
        verdict = run_checkpoint_gate(integration_id, target.gate, gate_timeout)
        if not verdict.get("allow"):
            return {
                "error": (
                    f"'{step_name}' rejected — gate '{target.gate}' failed: "
                    f"{verdict.get('reason')}. Fix the underlying problem and "
                    f"re-run markpass."
                ),
                "gate": verdict,
            }

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


def set_integration_auth(
    integration_id: str,
    auth_detail_json: str,
    *,
    skip_parity: bool | None = None,
    parity_timeout: int = 60,
    seed_overrides: dict | None = None,
) -> dict:
    """Commit the ``Auth Details`` cell, gated on a passing parity test.

    Schema-validates the JSON payload, then runs
    :func:`connectus.check_auth_parity.check_auth_parity` against the
    integration's source tree using the *candidate* payload. The CSV is
    only written when parity passes or structurally short-circuits.

    Args:
        integration_id: Logical integration id (CSV ``Integration ID``).
        auth_detail_json: Raw JSON string for the ``Auth Details`` cell.
        skip_parity: If ``True``, bypass the parity gate entirely. When
            ``None`` (the default), the env var ``CONNECTUS_SKIP_AUTH_PARITY``
            is consulted — set it to ``1`` to bypass. **Bypass is intended
            for tests and one-off escape hatches; the normal workflow
            requires parity to pass.**
        parity_timeout: Per-command wall-clock timeout for the parity run
            (seconds). Defaults to 60s.
        seed_overrides: Optional per-param seed-value overrides forwarded
            to the parity gate's
            :func:`check_auth_parity.check_auth_parity` call. Use for
            params whose auto-generated placeholder trips a format
            validator the analyzer cannot sentinel itself (cert
            thumbprints, JWT secrets with format validation, OIDC
            issuer URLs, etc.). The dict is NEVER persisted to the
            CSV — it only flows through to the parity gate for this
            single ``set-auth`` invocation. Overlap with the candidate
            ``Auth Details`` is rejected up front with
            ``ERROR_SEED_AUTH_OVERLAP``.

    Returns:
        On success::

            {
              "message": "Set 'Auth Details' for ...",
              "current_step": "<next step>",
              "parity": {<full check_auth_parity result>}  # or {"skipped": "..."}
            }

        On failure (parity blocked OR schema error OR not-found OR
        seed-overlap)::

            {"error": "<message>", "parity": {...}}  # parity present iff it ran
    """
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

    # ----- Seed-overrides ∩ Auth Details overlap check ---------------------
    # Computed off the CANDIDATE payload (not the persisted cell — we are
    # in the middle of writing a NEW cell). Hard-reject before the parity
    # gate runs, because such a param is supplied via UCP credential
    # injection in the new run anyway and the seed value would be silently
    # discarded by the UCP injection seam.
    if seed_overrides:
        try:
            candidate_for_overlap = json.loads(auth_detail_json)
        except json.JSONDecodeError:
            candidate_for_overlap = {}
        overlap_errors = _validate_seed_overrides_no_auth_overlap(
            seed_overrides,
            candidate_for_overlap if isinstance(candidate_for_overlap, dict) else {},
        )
        if overlap_errors:
            return {
                "error": {
                    "code": "ERROR_SEED_AUTH_OVERLAP",
                    "message": (
                        "--seed-param key(s) overlap with the candidate "
                        "Auth Details:\n"
                        + "\n".join(f"  - {e}" for e in overlap_errors)
                    ),
                    "exit_code": 2,
                },
            }

    # ----- Parity gate ------------------------------------------------------
    if skip_parity is None:
        skip_parity = os.environ.get("CONNECTUS_SKIP_AUTH_PARITY", "").strip() == "1"

    parity_payload: dict = {}
    if skip_parity:
        parity_payload = {"skipped": "CONNECTUS_SKIP_AUTH_PARITY=1 (parity gate bypassed)"}
    else:
        parity_payload = _run_auth_parity_for_set_auth(
            integration_id=row.get("Integration ID", integration_id),
            auth_detail_json=auth_detail_json,
            timeout=parity_timeout,
            seed_overrides=seed_overrides,
        )
        gate = _evaluate_parity_for_set_auth(parity_payload)
        if not gate["allow"]:
            return {
                "error": (
                    f"Auth Details rejected — parity gate failed for "
                    f"'{row.get('Integration ID', integration_id)}': "
                    f"{gate['reason']}\n\n"
                    f"Re-run `python3 connectus/check_auth_parity.py "
                    f"<integration_path> --integration-id "
                    f"'{integration_id}' --auth-details '<json>'` "
                    f"directly to inspect the full diff, then re-derive "
                    f"the Auth Details JSON before calling set-auth "
                    f"again. To bypass the gate (e.g. in a test), set "
                    f"CONNECTUS_SKIP_AUTH_PARITY=1."
                ),
                "parity": parity_payload,
            }

    # ----- Persist (parity passed or was bypassed) --------------------------
    target = cfg.step_by_name["Auth Details"]
    try:
        cleared, _ = apply_step_action(row, target, auth_detail_json, verb="set-auth")
    except WorkflowError as e:
        return {"error": e.message, "parity": parity_payload}
    save_csv(rows)
    cur = current_step(row)
    return {
        "message": (
            f"Set 'Auth Details' for '{row.get('Integration ID', '')}'."
            + (f" Cleared: {cleared}" if cleared else "")
        ),
        "current_step": cur.name if cur else None,
        "parity": parity_payload,
    }


# ---------------------------------------------------------------------------
# Auth-parity gate (in-process, called by set_integration_auth)
# ---------------------------------------------------------------------------

# Exit codes from check_auth_parity that we treat as the ONLY valid clean
# fallback for the gate: the auth is (entirely) interpolated, so there is
# genuinely nothing to parity-test. These auto-grant ``allow=True``.
#
# AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): the set was previously much
# wider and equated "the analyzer could not test this integration" with
# "this integration passed." That silently committed UNTESTED,
# non-interpolated secret-placements. The fix narrows the set to the
# interpolated cases ONLY. Every "cannot verify" code
# (ERROR_NON_PYTHON, ERROR_NO_BASECLIENT, APIMODULE_INTEGRATION_CANNOT_VERIFY,
# ERROR_INTEGRATION_REJECTS_HTTP, MULTI_SECRET_PASSTHROUGH) now falls through
# to the ``else`` branch below (allow=False) and BLOCKS the commit. The
# required operator action for those is to mark the offending auth(s)
# ``interpolated: true``, after which they flow through ERROR_ALL_INTERPOLATED
# (the clean path).
#
# Note on MULTI_SECRET_PASSTHROUGH: passthrough entries are
# required-interpolated, so a genuinely-all-interpolated passthrough bundle
# is already covered by ERROR_ALL_INTERPOLATED. Per the general-case intent
# it must NOT auto-pass merely because it is "passthrough"; it is removed
# from the skip set and only passes if it is actually all-interpolated.
_PARITY_STRUCTURAL_SKIP_CODES = {
    "ERROR_ALL_INTERPOLATED",
    "ERROR_CONNECTION_INTERPOLATED",
}

# Per-connection statuses that count as "passing" for the gate. `pass` is the
# obvious one; the `skipped_*` statuses (signed, mtls, passthrough) are
# per-connection structural skips and also count as passing.
#
# NOTE (FIXES-TODO #1, 2026-05-31): ``inconclusive`` was previously listed
# here as a permissive concession to "unrelated runtime failures." That
# silently accepted candidates whose parity verification crashed (e.g. on
# macOS without ``DEMISTO_SDK_LOG_FILE_PATH``, or on JS integrations, or
# on the UCP-strip-crash pattern). It produced false-positive ✅ rows.
# Removed per the parity-gate strictness fix. Specific recognizable
# failure classes are now detected and surfaced explicitly (see
# UCP_STRIP_CRASHED_UNCONDITIONAL_READ, etc.).
_PARITY_OK_STATUSES = {
    "pass",
    "skipped_signed",
    "skipped_mtls",
    "skipped_passthrough",
}


def _run_auth_parity_for_set_auth(
    integration_id: str,
    auth_detail_json: str,
    timeout: int,
    seed_overrides: dict | None = None,
) -> dict:
    """Invoke ``check_auth_parity.check_auth_parity`` against a candidate payload.

    The candidate ``Auth Details`` JSON is NOT yet persisted to the CSV —
    we pass it directly to the analyzer and decide based on the result
    whether the write should happen. Returns the analyzer's result
    envelope unchanged on success; returns a synthesized error envelope
    (with ``error.code``) on infrastructure failures (missing file path,
    crash inside the analyzer, etc.).
    """
    # Resolve the integration's directory on disk.
    files_info = get_integration_files(integration_id)
    if "error" in files_info:
        return {
            "error": {
                "code": "ERROR_FILES_LOOKUP",
                "message": files_info["error"],
                "exit_code": 2,
            },
        }
    directory_rel = files_info.get("directory") or ""
    abs_dir = os.path.join(BASE_DIR, directory_rel) if directory_rel else BASE_DIR

    # Lazy import — check_auth_parity has a heavy top-level (importlib,
    # docker, capture proxy) and we don't want to pay for it on every
    # workflow_state call. Only set-auth needs it.
    try:
        from check_auth_parity import check_auth_parity as _check_auth_parity
        import check_command_params as _ccp  # noqa: F401  # DockerConfig source
    except Exception as exc:  # noqa: BLE001 — defensive
        return {
            "error": {
                "code": "ERROR_PARITY_IMPORT",
                "message": (
                    f"Could not import check_auth_parity for the set-auth "
                    f"parity gate: {type(exc).__name__}: {exc}. Set "
                    f"CONNECTUS_SKIP_AUTH_PARITY=1 to bypass, or fix the "
                    f"import path."
                ),
                "exit_code": 3,
            },
        }

    try:
        candidate = json.loads(auth_detail_json)
    except json.JSONDecodeError as exc:
        # Shouldn't happen — validate_auth_detail() ran above — but be defensive.
        return {
            "error": {
                "code": "ERROR_AUTH_NOT_JSON",
                "message": f"Auth Details is not valid JSON: {exc}",
                "exit_code": 2,
            },
        }

    docker_cfg = _ccp.DockerConfig(
        mode="auto",
        default_image=None,
        use_integration_docker=True,
    )

    try:
        from pathlib import Path
        return _check_auth_parity(
            integration_path=Path(abs_dir).resolve(),
            integration_id=integration_id,
            auth_details=candidate,
            commands_filter=None,
            connection_filter=None,
            timeout=timeout,
            docker_cfg=docker_cfg,
            seed_overrides=seed_overrides,
        )
    except Exception as exc:  # noqa: BLE001 — top-level guard
        return {
            "error": {
                "code": "ERROR_PARITY_UNHANDLED",
                "message": f"check_auth_parity raised: {type(exc).__name__}: {exc}",
                "exit_code": 3,
            },
        }


def _evaluate_parity_for_set_auth(result: dict) -> dict:
    """Decide whether a check_auth_parity result clears the set-auth gate.

    Returns ``{"allow": bool, "reason": str}``. ``reason`` is the
    human-readable explanation when ``allow=False`` (and a short
    summary when ``allow=True``, for logging).
    """
    error = result.get("error")
    if isinstance(error, dict):
        code = str(error.get("code") or "")
        msg = str(error.get("message") or "")
        if code in _PARITY_STRUCTURAL_SKIP_CODES:
            return {
                "allow": True,
                "reason": f"structural skip ({code}): {msg}",
            }
        # AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): any other analyzer
        # error (cannot-verify codes, infra failures, docker/env unavailable,
        # crashes) BLOCKS. Spell out the only two valid resolutions so the
        # operator does not have to guess. (The cannot-verify messages from
        # the analyzer already carry the grep literal "Mark its auth as
        # interpolated"; we append guidance without altering them.)
        return {
            "allow": False,
            "reason": (
                f"parity errored ({code or 'unknown'}): {msg}\n"
                f"  This auth was NOT parity-tested, so it cannot be "
                f"committed. Resolve by either:\n"
                f"    (a) mark the offending auth(s) 'interpolated: true' "
                f"(then it flows through the all-interpolated clean path), or\n"
                f"    (b) make parity runnable (provide docker/env) so the "
                f"gate can actually verify the secret placement."
            ),
        }

    auth_parity = result.get("auth_parity")
    if not isinstance(auth_parity, dict) or not auth_parity:
        # AUTH-PARITY GATE STRICTNESS FIX (2026-06-03): tightened fast-allow.
        # A genuinely all-interpolated / nothing-testable payload short-circuits
        # in the analyzer as ERROR_ALL_INTERPOLATED and is handled in the error
        # branch above. Reaching this point with NO error but an empty/missing
        # auth_parity means a testable (non-interpolated) auth was expected but
        # produced zero evaluated connections — we cannot prove it passed.
        # We cannot reliably distinguish "zero testable entries existed" from
        # "testable entries were silently dropped/filtered" from this envelope
        # alone, so per the spec we choose the conservative behavior and FAIL.
        return {
            "allow": False,
            "reason": (
                "parity produced no evaluated connections, so nothing was "
                "verified. This auth cannot be committed. If the auth is "
                "fully interpolated, mark it 'interpolated: true' (it will "
                "then take the all-interpolated clean path); otherwise make "
                "parity runnable (provide docker/env)."
            ),
        }

    failing = []
    for conn_name, conn_block in auth_parity.items():
        status = (conn_block or {}).get("status")
        if status not in _PARITY_OK_STATUSES:
            failing.append((conn_name, status, conn_block or {}))

    if failing:
        # Tightened diagnostic per FIXES-TODO #1 + cross-cutting hints
        # policy: surface failure_codes + last ~10 lines of stderr_excerpt
        # from each failing connection so the user can immediately tell
        # whether this is a real auth mismatch (e.g. WRONG_LOCATION) or a
        # tooling crash (e.g. RUN_FAILED_NEW with a KeyError in stderr).
        # NO prescription text — that lives in the skill, not the tool.
        #
        # The per-command diagnostics live at the TOP LEVEL of the
        # check_auth_parity result (``result["diagnostics"][conn]["commands"]``),
        # NOT nested inside each ``auth_parity[conn]`` block. (Sweep finding
        # F3, 2026-06-03: the previous code read ``conn_block["diagnostics"]``,
        # which is always empty, so failure_codes/stderr NEVER surfaced and the
        # whole FIXES-TODO #1 tightening was silently a no-op.) Prefer the
        # top-level block; fall back to the conn_block for the unit-test
        # fixtures that inline diagnostics under the connection.
        top_diagnostics = result.get("diagnostics") or {}
        lines: list[str] = []
        for conn_name, status, conn_block in failing:
            lines.append(f"  - {conn_name}: status={status!r}")
            diag_commands = (
                (top_diagnostics.get(conn_name) or {}).get("commands")
                or (conn_block.get("diagnostics") or {}).get("commands")
                or {}
            )
            for cmd_name, cmd_diag in diag_commands.items():
                if not isinstance(cmd_diag, dict):
                    continue
                diffs = cmd_diag.get("diffs") or []
                codes = sorted({
                    str(d.get("failure_code"))
                    for d in diffs
                    if isinstance(d, dict) and d.get("failure_code")
                })
                if codes:
                    lines.append(
                        f"      {cmd_name}: failure_codes={codes}"
                    )
                    # FIXES-TODO #13: when the UCP-strip crash pattern
                    # was detected, surface a description-only note that
                    # points at skill §1.12 (two valid fix paths exist —
                    # the skill is the right place to choose between
                    # them, not the tool).
                    if "UCP_STRIP_CRASHED_UNCONDITIONAL_READ" in codes:
                        lines.append(
                            "        note: the new run crashed reading "
                            "a credential key that UCP strips from params. "
                            "See skill §1.12 for the two fix paths "
                            "(UCP override or is_ucp_enabled() gating)."
                        )
                    # F4 (sweep 2026-06-03): when BOTH runs captured zero
                    # requests the proxy saw no HTTP traffic at all. Per the
                    # Hints policy (multiple valid causes → describe + point
                    # to skill, no prescription), flag it so the operator can
                    # tell this apart from a genuine secret-placement
                    # mismatch.
                    if "NO_REQUESTS_CAPTURED" in codes:
                        lines.append(
                            "        note: the capture proxy observed no "
                            "HTTP requests in either run, so parity could "
                            "not be verified (commonly a test-module that "
                            "doesn't reach an HTTP call, or a proxy-bypassing "
                            "HTTP layer). This is inconclusive, not a "
                            "confirmed mismatch — see skill §1.9 / §1.12."
                        )
                for run_key in ("new_run", "old_run"):
                    run = cmd_diag.get(run_key) or {}
                    if not isinstance(run, dict):
                        continue
                    if run.get("status") == "crashed":
                        excerpt = str(run.get("stderr_excerpt") or "")
                        tail = "\n".join(excerpt.splitlines()[-10:])
                        if tail:
                            lines.append(
                                f"      {cmd_name}.{run_key} stderr (last 10 lines):"
                            )
                            for tail_line in tail.splitlines():
                                lines.append(f"        {tail_line}")
        details = "\n".join(lines) if lines else (
            ", ".join(f"{n}={s!r}" for n, s, _ in failing)
        )
        return {
            "allow": False,
            "reason": (
                f"{len(failing)} connection(s) did not pass:\n{details}"
            ),
        }

    statuses = sorted({(b or {}).get("status") for b in auth_parity.values()})
    return {
        "allow": True,
        "reason": f"all {len(auth_parity)} connection(s) ok: {statuses}",
    }


# ---------------------------------------------------------------------------
# Dry-run auth (set-auth --dry-run) — read-only preview of the gate
# ---------------------------------------------------------------------------

# Infrastructure error codes — these mean the gate could not be evaluated
# (file lookup failed, the analyzer could not be imported, it crashed, or the
# candidate was not JSON). They are NOT auth-mismatch verdicts; they map to
# exit-code 3 ("could not evaluate"). Distinct from ERROR_SEED_AUTH_OVERLAP
# (a user-input conflict → exit-code 2) and from a real parity block
# (→ exit-code 1).
_INFRA_ERROR_CODES = {
    "ERROR_FILES_LOOKUP",
    "ERROR_PARITY_IMPORT",
    "ERROR_PARITY_UNHANDLED",
    "ERROR_AUTH_NOT_JSON",
}


def dry_run_auth(
    integration_id: str,
    auth_detail_json: str,
    *,
    seed_overrides: dict | None = None,
    timeout: int = 60,
) -> dict:
    """Preview the ``set-auth`` gate WITHOUT writing the CSV.

    Runs the same three checks ``set_integration_auth`` runs — schema
    validation, seed-overrides/Auth-Details overlap, and the auth-parity
    gate — in the same order, short-circuiting on the first failure, but
    never persists anything. Returns an envelope describing what *would*
    happen on the real path::

        {
          "pass":            bool,   # TOP-LEVEL verdict — read THIS
          "dry_run":         True,
          "integration_id":  "<id>",
          "validator":       {"passed": bool, "errors": [...]},
          "seed_overlap":    {"passed": bool, "error": {...}}
                                | {"skipped": "<why>"},
          "parity":          {<check_auth_parity result>}
                                | {"skipped": "<why>"}
                                | {"error": {...}},
          "verdict":         {"would_commit": bool, "reason": "<why>"},
        }

    The top-level ``pass`` key is the single, unambiguous "is this payload
    good to commit?" signal — it mirrors ``verdict.would_commit`` (``True``
    when parity passed or structurally short-circuited) and is the field
    callers / the skill should branch on. The nested ``verdict`` block is
    retained for its human-readable ``reason``.

    The CSV is never read for mutation and ``save_csv`` is never called.
    Use :func:`dry_run_exit_code` to map the envelope to a process exit
    code that is symmetric with the real path's
    :func:`set_auth_exit_code`.
    """
    envelope = _dry_run_auth_impl(
        integration_id,
        auth_detail_json,
        seed_overrides=seed_overrides,
        timeout=timeout,
    )
    # Single, unambiguous top-level verdict the skill / callers branch on.
    # Mirrors verdict.would_commit; placed first for visibility.
    would_commit = bool((envelope.get("verdict") or {}).get("would_commit"))
    return {"pass": would_commit, **envelope}


def _dry_run_auth_impl(
    integration_id: str,
    auth_detail_json: str,
    *,
    seed_overrides: dict | None = None,
    timeout: int = 60,
) -> dict:
    """Internal worker for :func:`dry_run_auth`.

    Builds the envelope (sans the top-level ``pass`` key, which the public
    wrapper injects). Kept separate so every short-circuit ``return`` path
    automatically gets the ``pass`` field without repeating it five times.
    """
    skipped_marker = "not evaluated (earlier check failed)"

    # ----- 1. Schema validation -------------------------------------------
    schema_errors = validate_auth_detail(auth_detail_json)
    if schema_errors:
        return {
            "dry_run": True,
            "integration_id": integration_id,
            "validator": {"passed": False, "errors": schema_errors},
            "seed_overlap": {"skipped": skipped_marker},
            "parity": {"skipped": skipped_marker},
            "verdict": {
                "would_commit": False,
                "reason": "validator failed",
            },
        }

    validator_block = {"passed": True, "errors": []}

    # ----- 2. Integration existence ---------------------------------------
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        return {
            "dry_run": True,
            "integration_id": integration_id,
            "validator": validator_block,
            "seed_overlap": {"skipped": skipped_marker},
            "parity": {"skipped": skipped_marker},
            "verdict": {
                "would_commit": False,
                "reason": f"integration '{integration_id}' not found",
            },
        }

    row = rows[idx]

    # ----- 3. Seed-overrides ∩ Auth Details overlap -----------------------
    if seed_overrides:
        try:
            candidate_for_overlap = json.loads(auth_detail_json)
        except json.JSONDecodeError:
            candidate_for_overlap = {}
        overlap_errors = _validate_seed_overrides_no_auth_overlap(
            seed_overrides,
            candidate_for_overlap if isinstance(candidate_for_overlap, dict) else {},
        )
        if overlap_errors:
            return {
                "dry_run": True,
                "integration_id": integration_id,
                "validator": validator_block,
                "seed_overlap": {
                    "passed": False,
                    "error": {
                        "code": "ERROR_SEED_AUTH_OVERLAP",
                        "message": (
                            "--seed-param key(s) overlap with the candidate "
                            "Auth Details:\n"
                            + "\n".join(f"  - {e}" for e in overlap_errors)
                        ),
                        "exit_code": 2,
                    },
                },
                "parity": {"skipped": skipped_marker},
                "verdict": {
                    "would_commit": False,
                    "reason": "ERROR_SEED_AUTH_OVERLAP",
                },
            }

    seed_overlap_block = {"passed": True}

    # ----- 4. Parity gate (read-only) -------------------------------------
    parity_payload = _run_auth_parity_for_set_auth(
        integration_id=row.get("Integration ID", integration_id),
        auth_detail_json=auth_detail_json,
        timeout=timeout,
        seed_overrides=seed_overrides,
    )
    gate = _evaluate_parity_for_set_auth(parity_payload)
    would_commit = bool(gate["allow"])
    reason = gate["reason"]
    return {
        "dry_run": True,
        "integration_id": integration_id,
        "validator": validator_block,
        "seed_overlap": seed_overlap_block,
        "parity": parity_payload,
        "verdict": {"would_commit": would_commit, "reason": reason},
    }


def dry_run_exit_code(envelope: dict) -> int:
    """Map a :func:`dry_run_auth` envelope to a process exit code.

    Symmetric with :func:`set_auth_exit_code` (same logical branch →
    same code)::

        0  would_commit == True (parity passed or structural skip)
        2  seed-overrides/Auth-Details overlap (ERROR_SEED_AUTH_OVERLAP)
        3  infrastructure failure (could not evaluate the gate)
        1  validator failed, or a real parity block
    """
    verdict = envelope.get("verdict") or {}
    if verdict.get("would_commit") is True:
        return 0

    # Seed-overlap → 2.
    seed_overlap = envelope.get("seed_overlap") or {}
    seed_err = seed_overlap.get("error") if isinstance(seed_overlap, dict) else None
    if isinstance(seed_err, dict) and seed_err.get("code") == "ERROR_SEED_AUTH_OVERLAP":
        return 2

    # Infrastructure failure surfaced through the parity block → 3.
    parity = envelope.get("parity") or {}
    parity_err = parity.get("error") if isinstance(parity, dict) else None
    if isinstance(parity_err, dict) and str(parity_err.get("code")) in _INFRA_ERROR_CODES:
        return 3

    # Everything else that did not commit (validator fail, parity block,
    # not-found) → 1.
    return 1


def set_auth_exit_code(result: dict) -> int:
    """Map a :func:`set_integration_auth` result to a process exit code.

    Symmetric with :func:`dry_run_exit_code`::

        0  success (no "error" key)
        2  seed-overrides/Auth-Details overlap (ERROR_SEED_AUTH_OVERLAP)
        3  infrastructure failure (could not evaluate the gate)
        1  any other failure (schema, not-found, real parity block)
    """
    error = result.get("error")
    if error is None:
        return 0

    # Structured error dict (seed-overlap, parity infra failures).
    if isinstance(error, dict):
        code = str(error.get("code") or "")
        if code == "ERROR_SEED_AUTH_OVERLAP":
            return 2
        if code in _INFRA_ERROR_CODES:
            return 3
        return 1

    # String error (parity block, schema, not-found). Inspect the attached
    # parity block: an infra-code there still means "could not evaluate" → 3.
    parity = result.get("parity") or {}
    parity_err = parity.get("error") if isinstance(parity, dict) else None
    if isinstance(parity_err, dict) and str(parity_err.get("code")) in _INFRA_ERROR_CODES:
        return 3

    return 1


# ---------------------------------------------------------------------------
# Release Notes step (FIXES-TODO 2026-05-31, new workflow step)
# ---------------------------------------------------------------------------

# Exact substring the verifier looks for in the new RN file. Case-sensitive
# per the spec. Operators can include this anywhere (bullet, paragraph,
# heading) — substring match is robust to formatting variation.
RELEASE_NOTES_REQUIRED_SUBSTRING = "Enabled support for UCP"


def _integration_owns_files(integration_id: str) -> tuple[Path | None, Path | None]:
    """Resolve absolute paths to the integration's own .py and .yml files.

    Returns ``(py_abs_path, yml_abs_path)`` — either may be ``None`` if
    the file doesn't exist (e.g. JS / PowerShell integrations have no
    .py; nonexistent integrations have neither).
    """
    files_info = get_integration_files(integration_id)
    if "error" in files_info:
        return (None, None)
    directory_rel = files_info.get("directory") or ""
    abs_dir = (
        Path(BASE_DIR) / directory_rel if directory_rel else Path(BASE_DIR)
    )
    py_rel = files_info.get("code")
    yml_rel = files_info.get("yml")
    py_abs = (
        (Path(BASE_DIR) / py_rel).resolve()
        if py_rel and files_info.get("code_language") == "python"
        else None
    )
    yml_abs = (Path(BASE_DIR) / yml_rel).resolve() if yml_rel else None
    # Sanity: both should live under abs_dir (which always exists when
    # the CSV row's Integration File Path is valid).
    _ = abs_dir  # touched for future use; keeps mypy happy
    return (py_abs, yml_abs)


def _release_notes_trigger_required(integration_id: str) -> bool:
    """True when the migration touched the integration's own .py/.yml.

    Implementation: ``git diff HEAD --name-only -- <py> <yml>``. Empty
    output → no code touch → RN not required. Non-empty → RN required.
    Per the spec the trigger looks at the integration's own .py and
    .yml only (NOT broader pack files like README / images).
    """
    py_abs, yml_abs = _integration_owns_files(integration_id)
    paths: list[str] = []
    if py_abs is not None and py_abs.exists():
        paths.append(str(py_abs))
    if yml_abs is not None and yml_abs.exists():
        paths.append(str(yml_abs))
    if not paths:
        # Defensive: no files to diff against → treat as "not required."
        return False
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD", "--name-only", "--"] + paths,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # If git is unavailable or times out, fail safe by requiring the
        # RN — operators can still set required=false explicitly if they
        # know the migration didn't touch code.
        return True
    return bool(result.stdout.strip())


_VERSION_FILENAME_RE = re.compile(
    r"^(?P<major>\d+)_(?P<minor>\d+)_(?P<patch>\d+)\.md$",
    re.IGNORECASE,
)


def _pack_release_notes_dir_for(integration_id: str) -> Path | None:
    """Return the absolute path to the integration's pack ReleaseNotes/ dir."""
    files_info = get_integration_files(integration_id)
    if "error" in files_info:
        return None
    directory_rel = files_info.get("directory") or ""
    # Pack root = Packs/<PackName>; integration lives at
    # Packs/<PackName>/Integrations/<IntegrationName>/. Walk up two
    # levels to find the pack root.
    parts = directory_rel.split(os.sep)
    if len(parts) < 3 or parts[0] != "Packs":
        return None
    pack_root = Path(BASE_DIR) / parts[0] / parts[1]
    rn_dir = pack_root / "ReleaseNotes"
    return rn_dir if rn_dir.is_dir() else rn_dir  # return path regardless; caller checks .is_dir()


def find_newest_release_notes_file(integration_id: str) -> Path | None:
    """Return the newest (largest version) RN .md file in the pack.

    Per the spec: if multiple RN files exist, check the newest one.
    Version is parsed from the filename (e.g. ``1_2_3.md`` →
    ``(1, 2, 3)``). Files that don't match the version pattern are
    ignored.
    """
    rn_dir = _pack_release_notes_dir_for(integration_id)
    if rn_dir is None or not rn_dir.is_dir():
        return None
    best: tuple[tuple[int, int, int], Path] | None = None
    for entry in rn_dir.iterdir():
        if not entry.is_file():
            continue
        m = _VERSION_FILENAME_RE.match(entry.name)
        if not m:
            continue
        version = (int(m.group("major")), int(m.group("minor")), int(m.group("patch")))
        if best is None or version > best[0]:
            best = (version, entry)
    return best[1] if best is not None else None


def verify_release_notes_substring(rn_path: Path) -> bool:
    """True iff the RN file contains :data:`RELEASE_NOTES_REQUIRED_SUBSTRING`.

    Exact case-sensitive substring match, anywhere in the file.
    """
    try:
        contents = rn_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return RELEASE_NOTES_REQUIRED_SUBSTRING in contents


def evaluate_release_notes_for_integration(integration_id: str) -> dict:
    """Compute the canonical ``Release Notes`` cell shape for the row.

    Returns ``{"required": bool, "path": str | None, "verified": bool}``
    suitable for direct serialization into the cell. The caller (the
    setter) is responsible for invoking the validator on the JSON
    before writing.

    Decision tree:
    * If the migration didn't touch the integration's .py/.yml →
      ``{"required": false, "path": null, "verified": false}``.
    * If it did, find the newest RN file in the pack and check for the
      required substring.
      - Found + substring present → ``required=true, path=<rel>, verified=true``
      - Found + substring missing → ``required=true, path=<rel>, verified=false``
      - Not found → ``required=true, path=null, verified=false``
    """
    required = _release_notes_trigger_required(integration_id)
    if not required:
        return {"required": False, "path": None, "verified": False}
    newest = find_newest_release_notes_file(integration_id)
    if newest is None:
        return {"required": True, "path": None, "verified": False}
    try:
        rel = newest.resolve().relative_to(Path(BASE_DIR).resolve())
        path_str: Optional[str] = str(rel)
    except ValueError:
        path_str = str(newest)
    verified = verify_release_notes_substring(newest)
    return {"required": True, "path": path_str, "verified": verified}


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
                f"(source not attributable)"
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
