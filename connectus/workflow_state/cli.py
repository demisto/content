"""CLI commands and main dispatch.

Each ``cmd_*`` function is the implementation of one CLI verb. They look
up validators / cross-checks by their ``Step.json_schema`` /
``Step.cross_check`` field rather than hardcoding step names.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Callable, Optional

from workflow_state.api import (
    _check_params_to_commands_overlap,
    auth_param_ids,
    dry_run_auth,
    dry_run_exit_code,
    get_integration_files,
    get_integration_status,
    set_auth_exit_code,
    set_integration_auth,
    test_module_params,
)
from workflow_state.config_loader import get_config
from workflow_state.csv_io import (
    find_row,
    wipe_workflow_data,
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
    validate_param_defaults,
    validate_params_to_capabilities,
    validate_params_to_commands,
    validate_shadowed_commands,
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


def _resolve_column_or_exit(
    ref: str,
    *,
    allow_identity: bool = True,
    verb: str = "this operation",
) -> str:
    """Resolve a column reference (name or 1-based number) or exit(1).

    See :meth:`workflow_state.types.WorkflowConfig.resolve_column_ref`
    for the resolution rules. CLI-side wrapper that prints the error
    and exits on failure (since every CLI call site does the same thing).
    """
    cfg = get_config()
    try:
        return cfg.resolve_column_ref(ref, allow_identity=allow_identity, verb=verb)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


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
    # Extract --format=text|json (position-insensitive, '=' form only —
    # matching cmd_files / cmd_auth_params). Default stays "text" so the
    # historical byte-for-byte text output is preserved for callers/tests
    # that depend on it.
    fmt = "text"
    positional: list[str] = []
    for a in args:
        if a.startswith("--format="):
            fmt = a[len("--format="):]
        else:
            positional.append(a)

    if not positional:
        print(
            "Usage: workflow_state.py status <integration_id> [id2 ...] "
            "[--format=text|json]"
        )
        sys.exit(1)

    if fmt not in {"text", "json"}:
        print(
            f"ERROR: Unknown --format value '{fmt}'. Valid: text, json.",
            file=sys.stderr,
        )
        sys.exit(1)

    rows = load_csv()

    if fmt == "json":
        # Multi-id behaviour: emit the get_integration_status(...) dict
        # for each id. We mirror the text path's "skip unknown ids and
        # keep going" behaviour, but in JSON an unknown id surfaces as an
        # {"error": ...} dict (from get_integration_status) rather than a
        # stderr line, so the document stays a complete, parseable record
        # of every requested id. To keep the shape predictable we ALWAYS
        # emit a JSON list (one element per requested id) — even for a
        # single id — so machine consumers never have to branch on
        # "list vs object" based on arg count.
        payload = [get_integration_status(name) for name in positional]
        print(json.dumps(payload, indent=2))
        return

    for name in positional:
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
    """Shared CLI handler for JSON-shaped data setters (currently
    ``set-auth`` and ``set-params-to-commands``).
    """
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


def _parse_seed_param_flags(args: list[str]) -> tuple[list[str], dict[str, str]]:
    """Extract repeatable ``--seed-param NAME=VALUE`` flags from ``args``.

    Returns ``(remaining_args, seed_overrides_dict)``. The dotted-leaf
    rules (``NAME.identifier`` / ``NAME.password`` for YML type:9
    credentials; flat ``NAME=VALUE`` on a type:9 widget rejected with
    exit code 2) are NOT enforced here — they fire inside
    :func:`check_command_params.build_param_values` once the YML param
    types are known. This parser only handles the surface CLI shape:
    repeatable flag, ``NAME=VALUE`` payload, duplicate-NAME rejection.

    Exits with code 2 on malformed input (missing ``=``, empty NAME,
    duplicate NAME) — same shape as ``check_command_params.py``.
    """
    remaining: list[str] = []
    raw_pairs: list[str] = []
    it = iter(args)
    for arg in it:
        if arg == "--seed-param":
            value = next(it, None)
            if value is None:
                print(
                    "ERROR: --seed-param requires a NAME=VALUE argument",
                    file=sys.stderr,
                )
                sys.exit(2)
            raw_pairs.append(value)
        elif arg.startswith("--seed-param="):
            raw_pairs.append(arg[len("--seed-param="):])
        else:
            remaining.append(arg)
    seed_overrides: dict[str, str] = {}
    for entry in raw_pairs:
        if "=" not in entry:
            print(
                f"ERROR: --seed-param entry missing '=' separator: "
                f"{entry!r}; expected NAME=VALUE",
                file=sys.stderr,
            )
            sys.exit(2)
        name, _, value = entry.partition("=")
        name = name.strip()
        if not name:
            print(
                f"ERROR: --seed-param entry has empty NAME: {entry!r}; "
                f"expected NAME=VALUE",
                file=sys.stderr,
            )
            sys.exit(2)
        if name in seed_overrides:
            print(
                f"ERROR: --seed-param NAME={name!r} supplied more than once",
                file=sys.stderr,
            )
            sys.exit(2)
        seed_overrides[name] = value
    return remaining, seed_overrides


def _parse_set_auth_flags(
    args: list[str],
) -> tuple[list[str], bool, Optional[int], str]:
    """Extract ``--dry-run`` / ``--timeout=N`` / ``--format=json|text``.

    Returns ``(remaining_args, dry_run, timeout, fmt)`` where:

    - ``dry_run`` is ``True`` when ``--dry-run`` is present.
    - ``timeout`` is the positive int from ``--timeout=N`` (``None`` when
      omitted). Only the ``=`` form is accepted; the space form
      (``--timeout 5``) is rejected with ``SystemExit(1)``. A
      non-integer or non-positive value is rejected the same way.
    - ``fmt`` is the lower-cased value of ``--format=json|text``
      (``""`` when omitted, so the caller can default it per mode). The
      space form (``--format json``) and any unknown value are rejected
      with ``SystemExit(1)``.

    Only the surface flag shape is handled here; ``--seed-param`` is
    handled separately by :func:`_parse_seed_param_flags`.
    """
    remaining: list[str] = []
    dry_run = False
    timeout: Optional[int] = None
    fmt = ""

    for arg in args:
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--timeout":
            print(
                "ERROR: --timeout requires the '=' form, e.g. --timeout=120 "
                "(space-separated --timeout 120 is not supported).",
                file=sys.stderr,
            )
            sys.exit(1)
        elif arg.startswith("--timeout="):
            value = arg[len("--timeout="):]
            try:
                parsed = int(value)
            except ValueError:
                print(
                    f"ERROR: --timeout value must be a positive integer; "
                    f"got {value!r}.",
                    file=sys.stderr,
                )
                sys.exit(1)
            if parsed <= 0:
                print(
                    f"ERROR: --timeout must be a positive integer; "
                    f"got {parsed}.",
                    file=sys.stderr,
                )
                sys.exit(1)
            timeout = parsed
        elif arg == "--format":
            print(
                "ERROR: --format requires the '=' form, e.g. --format=json "
                "(space-separated --format json is not supported).",
                file=sys.stderr,
            )
            sys.exit(1)
        elif arg.startswith("--format="):
            value = arg[len("--format="):].lower()
            if value not in ("json", "text"):
                print(
                    f"ERROR: --format must be 'json' or 'text'; got {value!r}.",
                    file=sys.stderr,
                )
                sys.exit(1)
            fmt = value
        else:
            remaining.append(arg)

    return remaining, dry_run, timeout, fmt


def cmd_set_auth(args: list[str]) -> None:
    """Set the ``Auth Details`` cell via the parity-gated API.

    Supports repeatable ``--seed-param NAME=VALUE`` flags that are
    forwarded to the parity gate's analyzer for params whose
    auto-generated placeholder trips a format validator the analyzer
    cannot sentinel itself (cert thumbprints, JWT secrets with format
    validation, OIDC issuer URLs, etc.). Seed-overrides are NEVER
    persisted to the CSV — they only flow through to the parity gate
    for this single ``set-auth`` invocation.

    Overlap with the candidate ``Auth Details`` is hard-rejected
    before the parity gate runs (see
    :func:`workflow_state.validators.validate_seed_overrides_no_auth_overlap`).
    """
    args, dry_run, timeout, fmt = _parse_set_auth_flags(args)
    args, seed_overrides = _parse_seed_param_flags(args)
    if len(args) < 2:
        print("Usage: workflow_state.py set-auth <integration_id> '<json>' "
              "[--dry-run] [--timeout=N] [--format=json|text] "
              "[--seed-param NAME=VALUE ...]")
        print("  The value must be valid JSON (see connectus/column-schemas.md).")
        sys.exit(1)

    name = args[0]
    raw = " ".join(args[1:])

    # Schema validation (same shape as _set_json_data_step) — defensive
    # JSON-parse here so we can give a clean CLI error before the API
    # rejects with the same error.
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        print("ERROR: 'Auth Details' must be valid JSON.")
        print(f"  Got: {raw}")
        print(f"  Parse error: {e}")
        print(f"  Example: workflow_state.py set-auth \"{name}\" '{{}}'")
        sys.exit(1)

    # ----- Dry-run branch (read-only preview; never writes the CSV) --------
    if dry_run:
        # Default to JSON output for the dry-run preview (machine-readable),
        # unless the operator explicitly asked for text.
        out_fmt = fmt or "json"
        env = dry_run_auth(
            name,
            raw,
            seed_overrides=seed_overrides or None,
            timeout=timeout if timeout is not None else 60,
        )
        if out_fmt == "json":
            print(json.dumps(env, indent=2, sort_keys=True))
        else:
            _print_dry_run_text(env)
        sys.exit(dry_run_exit_code(env))

    # ----- Real path (gated commit) ---------------------------------------
    # Default to text output for the real path (human-readable), unless the
    # operator explicitly asked for JSON.
    out_fmt = fmt or "text"
    # Only forward parity_timeout when explicitly set, so the default call
    # signature stays identical to the historical one (preserves callers /
    # test stubs that don't accept the keyword).
    extra_kwargs = {"parity_timeout": timeout} if timeout is not None else {}
    result = set_integration_auth(
        name,
        raw,
        seed_overrides=seed_overrides or None,
        **extra_kwargs,
    )

    exit_code = set_auth_exit_code(result)

    if out_fmt == "json":
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        # Only raise on failure so the historical success path (which
        # returns normally) is preserved for callers/tests.
        if exit_code != 0:
            sys.exit(exit_code)
        return

    error = result.get("error")
    if error:
        # Unwrap dict-shaped error envelopes (e.g. ERROR_SEED_AUTH_OVERLAP).
        if isinstance(error, dict):
            msg = error.get("message") or str(error)
            print(f"ERROR: {msg}")
        else:
            print(f"ERROR: {error}")
        sys.exit(exit_code or 1)

    msg = result.get("message")
    if msg:
        print(msg)
    cur_step = result.get("current_step")
    if cur_step:
        cfg = get_config()
        target = cfg.step_by_name.get(cur_step)
        if target is not None:
            print(f"  Current step: #{target.index} {cur_step}")
        else:
            print(f"  Current step: {cur_step}")
    elif msg:
        # current_step is None and we got a success message → workflow
        # is fully complete (mirrors _set_json_data_step's all-done
        # branch).
        cfg = get_config()
        print(f"  🎉 All {len(cfg.steps)} steps complete!")
    # Success: return normally (exit code 0), matching the historical
    # behaviour the seed-param forwarding tests rely on.


def _print_dry_run_text(env: dict) -> None:
    """Render a :func:`dry_run_auth` envelope as a human-readable report.

    ASCII-safe, no JSON braces — a plain-text summary of the validator,
    seed-overlap, parity, and verdict sections.
    """
    verdict = env.get("verdict") or {}
    would = verdict.get("would_commit")
    print("set-auth dry-run preview")
    print(f"  integration: {env.get('integration_id')}")

    validator = env.get("validator") or {}
    if validator.get("passed"):
        print("  validator:   PASS")
    elif "skipped" in validator:
        print(f"  validator:   skipped ({validator['skipped']})")
    else:
        print("  validator:   FAIL")
        for e in validator.get("errors") or []:
            print(f"    - {e}")

    seed_overlap = env.get("seed_overlap") or {}
    if "skipped" in seed_overlap:
        print(f"  seed-check:  skipped ({seed_overlap['skipped']})")
    elif seed_overlap.get("passed"):
        print("  seed-check:  PASS")
    else:
        print("  seed-check:  FAIL")
        err = seed_overlap.get("error") or {}
        if err.get("message"):
            for line in str(err["message"]).splitlines():
                print(f"    {line}")

    parity = env.get("parity") or {}
    if "skipped" in parity:
        print(f"  parity:      skipped ({parity['skipped']})")
    elif isinstance(parity.get("error"), dict):
        perr = parity["error"]
        print(f"  parity:      ERROR ({perr.get('code')}): {perr.get('message')}")
    else:
        print("  parity:      evaluated")

    verdict_label = "WOULD COMMIT" if would else "WOULD NOT COMMIT"
    print(f"  verdict:     {verdict_label}")
    reason = verdict.get("reason")
    if reason:
        for line in str(reason).splitlines():
            print(f"    {line}")


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


def cmd_set_param_defaults(args: list[str]) -> None:
    if len(args) >= 2:
        raw = " ".join(args[1:])
        schema_errors = validate_param_defaults(raw)
        if schema_errors:
            print("ERROR: Params for test with default in code does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)
    _set_json_data_step(args, "Params for test with default in code", "set-param-defaults")


# ---------------------------------------------------------------------------
# Shadowed Integration Commands — detector helper + CLI verbs
# ---------------------------------------------------------------------------

_SHADOWED_BRAND_INVALID_RE = re.compile(r"[^a-z0-9]+")


def _normalize_brand(raw: str) -> str:
    """Lowercase ``raw``, replace runs of non-alphanumeric chars with '-',
    strip leading/trailing '-'. Used to derive the integration brand
    suffix for renamed commands.
    """
    return _SHADOWED_BRAND_INVALID_RE.sub("-", raw.lower()).strip("-")


def _load_yaml_commands(yml_path: str) -> tuple[Optional[str], list[str]]:
    """Read ``yml_path`` and return ``(yml_name, [command_name, ...])``.

    Returns ``(None, [])`` if the file is unreadable / malformed / has no
    ``script.commands``. Warns on stderr for missing files.
    """
    import yaml  # local import — yaml is a project dep already

    if not os.path.isfile(yml_path):
        print(f"WARN: YML not found: {yml_path}", file=sys.stderr)
        return None, []
    try:
        with open(yml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as e:
        print(f"WARN: failed to parse YML {yml_path}: {e}", file=sys.stderr)
        return None, []
    if not isinstance(data, dict):
        return None, []
    name = data.get("name") if isinstance(data.get("name"), str) else None
    script = data.get("script") or {}
    if not isinstance(script, dict):
        return name, []
    commands = script.get("commands") or []
    if not isinstance(commands, list):
        return name, []
    out: list[str] = []
    for c in commands:
        if isinstance(c, dict):
            cname = c.get("name")
            if isinstance(cname, str) and cname:
                out.append(cname)
    return name, out


def _detect_shadowed_commands_for_integration(integration_id: str) -> dict[str, str]:
    """Scan all integration rows sharing this integration's Connector ID,
    parse each sibling's YML for top-level ``script.commands[].name``, and
    return a dict mapping any command name in THIS integration that also
    appears in at least one sibling integration (i.e. is shadowed within
    the connector) to the proposed renamed form ``f"{name}-{brand}"``.

    ``brand`` is derived from THIS integration's YML top-level ``name``
    (lowercased, non-alphanumerics replaced with ``-``, collapsed,
    stripped). If the YML has no ``name``, falls back to the
    ``Integration ID`` cell transformed the same way.

    Returns ``{}`` if no shadowed commands are detected. Raises
    ``WorkflowError`` if ``integration_id`` is unknown.
    """
    rows = load_csv()
    idx = find_row(rows, integration_id)
    if idx is None:
        raise WorkflowError(
            f"Integration '{integration_id}' not found in pipeline CSV."
        )

    me = rows[idx]
    my_connector = me.get("Connector ID", "").strip()
    if not my_connector:
        # No connector grouping → nothing to compare against.
        return {}
    my_yml = me.get("Integration File Path", "").strip()

    my_yml_name, my_commands = _load_yaml_commands(my_yml) if my_yml else (None, [])
    if not my_commands:
        return {}

    # Brand derivation.
    brand_source = my_yml_name or integration_id
    brand = _normalize_brand(brand_source)
    if not brand:
        # Fall back to a stripped integration id if even that yielded nothing
        brand = _normalize_brand(integration_id) or "integration"

    # Collect sibling command names.
    sibling_command_names: set[str] = set()
    for i, row in enumerate(rows):
        if i == idx:
            continue
        if row.get("Connector ID", "").strip() != my_connector:
            continue
        sib_yml = row.get("Integration File Path", "").strip()
        if not sib_yml:
            continue
        _sib_name, sib_commands = _load_yaml_commands(sib_yml)
        sibling_command_names.update(sib_commands)

    if not sibling_command_names:
        return {}

    shadowed: dict[str, str] = {}
    seen: set[str] = set()
    for cname in my_commands:
        if cname in seen:
            continue
        seen.add(cname)
        if cname in sibling_command_names:
            shadowed[cname] = f"{cname}-{brand}"
    return shadowed


def cmd_detect_shadowed_commands(args: list[str]) -> None:
    """CLI: detect-shadowed-commands <Integration ID>.

    Prints the JSON rename-map (one line) to stdout. Empty dict ``{}``
    if no shadowed commands are detected. On error, prints to stderr
    and exits 1.
    """
    if len(args) != 1 or not args[0]:
        print(
            "Usage: workflow_state.py detect-shadowed-commands <Integration ID>",
            file=sys.stderr,
        )
        sys.exit(1)
    integration_id = args[0]
    try:
        result = _detect_shadowed_commands_for_integration(integration_id)
    except WorkflowError as e:
        print(f"ERROR: {e.message}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


def cmd_set_shadowed_commands(args: list[str]) -> None:
    """CLI: set-shadowed-commands <Integration ID> '<JSON>'.

    Follows the cmd_set_param_defaults pattern. After schema validation
    passes, performs on-commit semantic validation:

      1. Each ``original`` must currently be detected as shadowed
         within the connector (re-runs the detector).
      2. The integration's YML must now contain a command named
         ``renamed`` and must NOT contain a command named ``original``.

    Any failure prints all collected semantic errors and exits 1 BEFORE
    the cell is written. Otherwise delegates to ``_set_json_data_step``.
    """
    if len(args) >= 2:
        integration_id = args[0]
        raw = " ".join(args[1:])

        # Step 1: schema validation (same shape as cmd_set_param_defaults)
        schema_errors = validate_shadowed_commands(raw)
        if schema_errors:
            print("ERROR: Shadowed Integration Commands does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)

        # Parse for semantic validation.
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            # Cannot happen here (schema validator already caught it), but
            # be defensive.
            print(f"ERROR: invalid JSON: {e}")
            sys.exit(1)

        if not isinstance(payload, dict):
            print("ERROR: top-level value must be a JSON object.")
            sys.exit(1)

        # Step 2: semantic validation (skip when payload is empty {})
        if payload:
            semantic_errors: list[str] = []

            # Re-run the detector to confirm each original was shadowed.
            try:
                detected = _detect_shadowed_commands_for_integration(integration_id)
            except WorkflowError as e:
                print(f"ERROR: {e.message}")
                sys.exit(1)

            rows = load_csv()
            row_idx = find_row(rows, integration_id)
            if row_idx is None:
                print(f"ERROR: Integration '{integration_id}' not found.")
                sys.exit(1)
            row = rows[row_idx]
            connector_id = row.get("Connector ID", "").strip() or "<unset>"
            my_yml_path = row.get("Integration File Path", "").strip()
            _yml_name, current_commands = (
                _load_yaml_commands(my_yml_path) if my_yml_path else (None, [])
            )
            current_command_names = set(current_commands)

            for original, renamed in payload.items():
                if original not in detected:
                    semantic_errors.append(
                        f"'{original}' was not detected as a shadowed "
                        f"command within connector '{connector_id}'"
                    )
                if renamed not in current_command_names:
                    semantic_errors.append(
                        f"renamed command '{renamed}' is not present in "
                        f"this integration's YML ({my_yml_path or '<no path>'})"
                    )
                if original in current_command_names:
                    semantic_errors.append(
                        f"original command '{original}' is still present "
                        f"in this integration's YML "
                        f"({my_yml_path or '<no path>'}); rename it to "
                        f"'{renamed}' in both .py and .yml before committing"
                    )

            if semantic_errors:
                print("ERROR: Shadowed Integration Commands semantic checks failed:")
                for err in semantic_errors:
                    print(f"  - {err}")
                sys.exit(1)

    _set_json_data_step(args, "Shadowed Integration Commands", "set-shadowed-commands")


def cmd_set_params_to_capabilities(args: list[str]) -> None:
    if len(args) >= 2:
        raw = " ".join(args[1:])
        schema_errors = validate_params_to_capabilities(raw)
        if schema_errors:
            print("ERROR: Params to Capabilities does not match the required schema.")
            for err in schema_errors:
                print(f"  - {err}")
            sys.exit(1)
    _set_json_data_step(args, "Params to Capabilities", "set-params-to-capabilities")


def cmd_set_release_notes(args: list[str]) -> None:
    """Set the ``Release Notes`` cell.

    Usage::

        workflow_state.py set-release-notes <integration_id>

    Auto-computes the cell shape from the working tree (no payload
    argument needed). The computation:

    1. ``git diff HEAD --name-only -- <integration>.py <integration>.yml``.
       Empty → ``{"required": false, "path": null, "verified": false}``;
       cell committed.
    2. Non-empty → look for the newest RN .md file in
       ``Packs/<PackName>/ReleaseNotes/`` (highest version number).
    3. Substring-match ``"Enabled support for UCP"`` (exact,
       case-sensitive) anywhere in the file. Present → cell committed
       with ``verified=true``; absent or no RN found → REJECT with a
       diagnostic that includes the recommended ``demisto-sdk
       update-release-notes`` invocation.

    Per the FIXES-TODO Hints policy: the prescription is unambiguous
    (run update-release-notes + add the substring), so the rejection
    diagnostic includes a one-line operator-actionable hint.
    """
    from workflow_state.api import (
        evaluate_release_notes_for_integration as _evaluate_rn,
        RELEASE_NOTES_REQUIRED_SUBSTRING,
    )

    if len(args) < 1:
        print(
            "Usage: workflow_state.py set-release-notes <integration_id>"
        )
        sys.exit(1)
    name = args[0]
    if len(args) > 1:
        # The cell is auto-computed; reject extra args to avoid confusion
        # with the JSON-payload pattern used by other setters.
        print(
            "ERROR: set-release-notes takes only the integration ID. "
            "The cell shape is auto-computed from the working tree."
        )
        sys.exit(1)

    payload = _evaluate_rn(name)
    # Reject when an RN was required but the verification didn't pass.
    if payload.get("required") is True and payload.get("verified") is not True:
        path = payload.get("path")
        if path is None:
            reason = (
                f"the integration's .py/.yml were modified but NO release-"
                f"notes file was found in the pack's ReleaseNotes/ "
                f"directory."
            )
        else:
            reason = (
                f"the newest release-notes file ({path}) does NOT contain "
                f"the required substring '{RELEASE_NOTES_REQUIRED_SUBSTRING}'."
            )
        print(f"ERROR: Release Notes step rejected for '{name}': {reason}")
        # Operator-actionable hint per the Hints policy
        # (cross-cutting decision #1): prescription is unambiguous.
        print(
            "  HINT: run `demisto-sdk update-release-notes -i "
            "Packs/<PackName>` (use --update-type documentation if "
            "the SDK exposes it), then edit the generated RN file to "
            f"include the substring '{RELEASE_NOTES_REQUIRED_SUBSTRING}' "
            "and re-run set-release-notes."
        )
        sys.exit(1)

    # Hand the computed payload to the JSON-data step machinery so
    # validation + cascade reset semantics match every other data step.
    _set_json_data_step(
        [name, json.dumps(payload)],
        "Release Notes",
        "set-release-notes",
    )


# (Removed 2026-05) ``set-params-for-test`` and ``set-shared-params``:
# the ``Params for test with default in code`` and ``Params same in other
# handlers`` columns were retired in the schema simplification. See the
# §11 decisions log for rationale.


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

def _set_flag_step_via_dispatch(
    args: list[str],
    step_name: str,
    setter_cmd: str,
) -> None:
    """Generic CLI handler for any ``kind: flag`` step.

    Validates the candidate value against the step's effective enum
    (per-step ``flag_values`` win over global ``markers.flag_values``),
    routes through the cascade-reset dispatcher, and honours any
    configured ``flag_auto_na_target`` interaction whose ``when_step``
    matches.
    """
    from workflow_state.state_machine import step_flag_values

    cfg = get_config()
    target = cfg.step_by_name.get(step_name)
    if target is None or target.kind != "flag":
        print(f"ERROR: Internal: {step_name!r} is not a configured flag step.")
        sys.exit(1)

    enum = list(step_flag_values(target))
    if len(args) < 2:
        print(
            f"Usage: workflow_state.py {setter_cmd} <integration_id> "
            f"<{'|'.join(enum)}>"
        )
        sys.exit(1)

    name = args[0]
    raw_value = args[1].strip()

    # Per-step enums match case-sensitively; global YES/NO/N/A is case-insensitive.
    if target.flag_values is not None:
        if raw_value not in enum:
            print(
                f"ERROR: '{step_name}' must be one of {enum}. Got: '{args[1]}'"
            )
            sys.exit(1)
        chosen = raw_value
    else:
        upper = raw_value.upper()
        upper_to_canonical = {v.upper(): v for v in enum}
        if upper not in upper_to_canonical:
            print(
                f"ERROR: '{step_name}' must be one of {enum}. Got: '{args[1]}'"
            )
            sys.exit(1)
        chosen = upper_to_canonical[upper]

    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)

    try:
        cleared, no_op = apply_step_action(
            rows[idx], target, chosen, verb=setter_cmd
        )
    except WorkflowError as e:
        print(f"ERROR: {e.message}")
        sys.exit(1)

    interaction = cfg.find_flag_auto_na_target(step_name)
    if interaction is not None and chosen.upper() in {
        v.upper() for v in interaction.when_value_in
    }:
        rows[idx][interaction.target_step] = interaction.write_value

    save_csv(rows)

    if no_op:
        print(
            f"'{step_name}' already set to '{chosen}' "
            f"for '{rows[idx]['Integration ID']}'. No change."
        )
    else:
        print(
            f"Set '{step_name}' = {chosen} "
            f"for '{rows[idx]['Integration ID']}'."
        )
        if cleared:
            print(f"  Cleared {len(cleared)} subsequent step(s): {cleared}")
        if interaction is not None and chosen.upper() in {
            v.upper() for v in interaction.when_value_in
        }:
            print(
                f"  Auto-set '{interaction.target_step}' = {interaction.write_value}."
            )

    cur = current_step(rows[idx])
    if cur is not None:
        print(f"  Current step: #{cur.index} {cur.name}")
    elif has_workflow_progress(rows[idx]):
        print(f"  🎉 All {len(cfg.steps)} steps complete!")


def cmd_markpass(args: list[str]) -> None:
    cfg = get_config()
    non_checkpoint = cfg.non_checkpoint_steps

    if len(args) < 2:
        print("Usage: workflow_state.py markpass <integration_id> <step_name|step_number>")
        print("  (column name or 1-based number into the full CSV column list)")
        print("\nCheckpoint steps (in order):")
        for s in cfg.steps:
            if s.kind == "checkpoint":
                # CSV column number = identity columns + step index
                csv_num = len(cfg.identity_columns) + s.index
                print(f"  #{csv_num:2d} (step {s.index:2d}). {s.name}")
        print("\nNon-checkpoint columns (use a different command):")
        for step_name, cmd in non_checkpoint.items():
            print(f"  - '{step_name}' → use '{cmd}'")
        sys.exit(1)

    name = args[0]
    raw_step = " ".join(args[1:])
    step_name = _resolve_column_or_exit(
        raw_step, allow_identity=False, verb="markpass"
    )

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
                src = cfg.step_by_name.get(inter.when_step)
                setter = src.setter if src and src.setter else "<setter>"
                print(
                    f"ERROR: Cannot mark '{step_name}' as passed — "
                    f"'{inter.when_step}' flag is not set.\n"
                    f"  Use {setter!r} first."
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
        print("Usage: workflow_state.py skip <integration_id> <step_name|step_number>")
        print("Skippable (optional) steps:")
        for s in cfg.steps:
            if s.optional:
                csv_num = len(cfg.identity_columns) + s.index
                print(f"  #{csv_num:2d} (step {s.index:2d}). {s.name}")
        sys.exit(1)

    name = args[0]
    raw_step = " ".join(args[1:])
    step_name = _resolve_column_or_exit(
        raw_step, allow_identity=False, verb="skip"
    )

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
    """Shared implementation for ``fail`` and ``reset-to``.

    Honours ``preserve_on_reset``: steps tagged as preserved retain
    their value across this operation, EXCEPT when the user names the
    preserved step explicitly as ``target`` — in that case the user's
    intent wins for that one step (it is cleared) but later preserved
    steps in the same blast radius are still preserved.

    ``step_name`` here is the resolved column name; column-number /
    identity-column rejection happens in the caller before reaching us.
    """
    cfg = get_config()
    target = cfg.step_by_name.get(step_name)
    if target is None:
        print(f"ERROR: Unknown step '{step_name}'.")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)

    row = rows[idx]
    integration_id = row.get("Integration ID", "")

    # Explicit-target carve-out: clear the named target even if it's
    # tagged preserve_on_reset (the user named it on purpose).
    row[target.name] = ""

    # Then clear everything strictly after, honouring preserve_on_reset
    # for those later steps. When target.index == 1 there is nothing
    # before it; otherwise we still pivot on `target` itself (which has
    # already been cleared above) and rely on reset_after's strict
    # "index > step.index" filter.
    cleared, preserved = reset_after(row, target, respect_preserve=True)

    save_csv(rows)
    print(f"{verb}: cleared step {target.index} ('{target.name}') and all "
          f"subsequent non-preserved steps for '{integration_id}'.")
    if preserved:
        print(
            f"  Preserved (preserve_on_reset=true): {preserved}"
        )
    cur = current_step(row)
    if cur is not None:
        print(f"  Current step is now: #{cur.index} {cur.name}")


def cmd_fail(args: list[str]) -> None:
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py fail <integration_id> <step_name|step_number>")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)
    name = args[0]
    raw_step = " ".join(args[1:])
    step_name = _resolve_column_or_exit(
        raw_step, allow_identity=False, verb="fail"
    )
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    _do_reset_to(rows, idx, step_name, verb="Reset (fail)")


def cmd_reset_to(args: list[str]) -> None:
    cfg = get_config()
    if len(args) < 2:
        print("Usage: workflow_state.py reset-to <integration_id> <step_name|step_number>")
        print(f"Valid steps: {', '.join(cfg.workflow_columns)}")
        sys.exit(1)
    name = args[0]
    raw_step = " ".join(args[1:])
    step_name = _resolve_column_or_exit(
        raw_step, allow_identity=False, verb="reset-to"
    )
    rows = load_csv()
    idx = _resolve_row_or_exit(rows, name)
    _do_reset_to(rows, idx, step_name, verb="Reset-to")


def cmd_wipe_workflow_data(args: list[str]) -> None:
    """⚠️  Bulk-wipe every workflow column in the pipeline CSV.

    Identity columns (Integration ID, Integration File Path, Connector ID,
    plus any future identity columns from the YAML) are preserved
    verbatim. The header is regenerated from the YAML config so the
    columns are re-aligned to the current workflow plan.

    Use this only when the workflow plan changes shape and you want to
    keep the integration roster but drop every per-row state cell. To
    reset a single integration, use 'reset' instead.

    Requires --yes-i-am-sure to proceed. Writes a sibling backup at
    ``<csv>.bak.<unix-timestamp>`` unless --no-backup is given.
    """
    sure = "--yes-i-am-sure" in args
    no_backup = "--no-backup" in args

    banner = (
        "\n"
        "╔══════════════════════════════════════════════════════════════════════════╗\n"
        "║   ⚠️   DESTRUCTIVE OPERATION: wipe-workflow-data                         ║\n"
        "║                                                                          ║\n"
        "║   This will CLEAR every workflow column for EVERY row in the             ║\n"
        "║   connectus pipeline CSV. Identity columns are preserved.                ║\n"
        "║   The header is rewritten from connectus/workflow_state_config.yml       ║\n"
        "║   so the file aligns with the current workflow plan.                     ║\n"
        "║                                                                          ║\n"
        "║   Use 'reset <integration_id>' instead if you only want to reset         ║\n"
        "║   one row. There is no undo for this operation other than the            ║\n"
        "║   timestamped backup file written next to the CSV.                       ║\n"
        "╚══════════════════════════════════════════════════════════════════════════╝\n"
    )
    print(banner)

    if not sure:
        print(
            "Refusing to run without --yes-i-am-sure.\n"
            "  Re-run as: workflow_state.py wipe-workflow-data --yes-i-am-sure\n"
            "  Add --no-backup to skip the timestamped backup file."
        )
        sys.exit(1)

    try:
        result = wipe_workflow_data(confirm=True, backup=not no_backup)
    except FileNotFoundError as e:
        print(f"ERROR: pipeline CSV not found: {e}")
        sys.exit(1)

    header_cols = result["header"]
    n_header = len(header_cols) if isinstance(header_cols, list) else 0
    print(f"✅ Wiped {result['cells_cleared']} workflow cell(s) "
          f"across {result['rows_touched']} row(s).")
    print(f"   Rows preserved:   {result['rows']}")
    print(f"   Header columns:   {n_header}")
    if result["backup_path"]:
        print(f"   Backup written:   {result['backup_path']}")
    else:
        print("   Backup written:   (skipped via --no-backup)")
    print(f"   CSV path:         {result['csv_path']}")


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
    """Read one cell for one integration.

    Default output is the human-readable decorated form produced by
    :func:`format_step_value` (header + pretty JSON). Pass ``--raw`` to
    emit ONLY the raw cell value verbatim — no header, no decoration,
    no flag-default substitution, no JSON pretty-printing. An empty
    cell prints nothing in ``--raw`` mode. ``--raw`` is the contract
    for machine consumers (e.g. ``check_auth_parity.py``) that want to
    ``json.loads`` the output directly.
    """
    cfg = get_config()
    # Extract --raw flag from args (position-insensitive) before
    # consuming the rest as positionals.
    raw_mode = False
    positional: list[str] = []
    for a in args:
        if a == "--raw":
            raw_mode = True
        else:
            positional.append(a)

    if len(positional) < 2:
        print("Usage: workflow_state.py show-step [--raw] <integration_id> <column_name|column_number>")
        print("  (column name or 1-based number into the full CSV column list)")
        print("  --raw  Emit the raw cell value verbatim (no header, no")
        print("         pretty-printing, no flag default). Empty cell prints")
        print("         nothing. Intended for machine consumers.")
        print("\nValid columns:")
        idx_cols = cfg.identity_column_names
        for n, col in enumerate(idx_cols, start=1):
            print(f"  #{n:2d} {col} (identity)")
        for s in cfg.steps:
            csv_num = len(idx_cols) + s.index
            print(f"  #{csv_num:2d} {s.name} ({s.kind})")
        sys.exit(1)

    name = positional[0]
    raw_step = " ".join(positional[1:])

    # show-step is read-only and may target identity columns.
    step = _resolve_column_or_exit(
        raw_step, allow_identity=True, verb="show-step"
    )

    rows = load_csv()
    idx = find_row(rows, name)
    if idx is None:
        print(f"ERROR: Integration '{name}' not found.")
        sys.exit(1)

    if raw_mode:
        # Emit the cell value verbatim. No decoration, no flag-default
        # substitution, no JSON pretty-printing. Empty cell → no output.
        value = (rows[idx].get(step, "") or "").strip()
        if value:
            print(value)
        return

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
# test-module-params
# ---------------------------------------------------------------------------

def cmd_test_module_params(args: list[str]) -> None:
    """Print the test-module param list from the Params to Commands cell.

    This is the canonical qualification source for Step 3a
    ('Params for test with default in code'). Step 3a iterates over
    exactly these params; the per-param branch (a/b/c) decision still
    happens per-param, but the QUALIFICATION question ('does this param
    qualify?') is answered by membership in this list rather than by
    re-reading the integration source.
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
            "Usage: workflow_state.py test-module-params <integration_id> "
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
        params = test_module_params(integration_id)
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
# context — single-document aggregate read (reduces agent round-trips)
# ---------------------------------------------------------------------------

# The JSON-valued data columns surfaced under `data_columns`. Each is
# parsed to its JSON value (or null when unset / unparseable) so the
# agent does not have to do a second `show-step --raw` + json.loads per
# cell. Kept as an explicit list (rather than cfg.json_valued_columns)
# so the `context` shape is stable and documented even if the config's
# json-valued set changes for unrelated reasons.
_CONTEXT_DATA_COLUMNS = (
    "Auth Details",
    "Params to Commands",
    "Params for test with default in code",
    "Params to Capabilities",
    "Release Notes",
)


def _parse_data_column(row: dict[str, str], column: str) -> Any:
    """Return the parsed-JSON value of ``column`` in ``row``.

    Returns ``None`` when the cell is empty OR cannot be parsed as JSON
    (graceful degradation — `context` is a read-only convenience verb,
    so a malformed cell should not abort the aggregate). Mirrors
    display.py's defensive json.loads handling.
    """
    raw = (row.get(column, "") or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def cmd_context(args: list[str]) -> None:
    """Emit, as a SINGLE pretty-printed JSON document, everything an
    agent would otherwise gather via multiple separate calls: workflow
    data columns + file paths + current/completed step info + the
    auth-derived ignore set.

    Read-only — never mutates the CSV. Composes the existing api.py
    helpers (``get_integration_status`` / ``get_integration_files`` /
    ``auth_param_ids``) rather than re-deriving anything.

    Errors:
      * Unknown integration id → stderr message + exit 1 (consistent
        with ``files`` / ``auth-params``).
      * A stale/missing Integration File Path does NOT abort the whole
        command: ``file_paths`` is set to null and a ``file_paths_error``
        key carries the message, so the rest of the document still
        emits (graceful degradation per the spec).
    """
    positional: list[str] = [a for a in args if not a.startswith("--")]

    if not positional:
        print(
            "Usage: workflow_state.py context <integration_id>",
            file=sys.stderr,
        )
        sys.exit(1)

    integration_id = " ".join(positional)

    # ----- Status (also our unknown-id gate) ------------------------------
    status = get_integration_status(integration_id)
    if "error" in status:
        # Unknown id (or other status error) → stderr + non-zero exit,
        # matching files/auth-params bad-id handling.
        print(f"ERROR: {status['error']}", file=sys.stderr)
        sys.exit(1)

    rows = load_csv()
    idx = find_row(rows, integration_id)
    # idx cannot be None here (get_integration_status already found it),
    # but be defensive for the monkeypatch-divergence case.
    row = rows[idx] if idx is not None else {}

    # ----- File paths (graceful degradation) ------------------------------
    files_info = get_integration_files(integration_id)
    file_paths: Optional[dict[str, Optional[str]]] = None
    file_paths_error: Optional[str] = None
    if "error" in files_info:
        file_paths_error = files_info["error"]
    else:
        file_paths = {
            "yml": files_info.get("yml"),
            "code": files_info.get("code"),
            "description": files_info.get("description"),
            "readme": files_info.get("readme"),
            "test": files_info.get("test"),
        }

    # ----- Auth-derived ignore set (reuse auth_param_ids) -----------------
    # If Auth Details is unset (or otherwise rejected by auth_param_ids),
    # degrade to an empty list rather than throwing — the spec requires
    # `context` to stay read-only and non-fatal here.
    try:
        auth_ignore_params = auth_param_ids(integration_id)
    except WorkflowError:
        auth_ignore_params = []

    # ----- Data columns (parsed JSON or null) -----------------------------
    data_columns = {
        column: _parse_data_column(row, column)
        for column in _CONTEXT_DATA_COLUMNS
    }

    payload: dict[str, Any] = {
        "integration_id": status.get("name", integration_id),
        "connector_id": row.get("Connector ID", "").strip(),
        "assignee": row.get("assignee", "").strip(),
        "file_paths": file_paths,
        "data_columns": data_columns,
        "auth_ignore_params": auth_ignore_params,
        "current_step": status.get("current_step"),
        "current_step_index": status.get("current_step_index"),
        "completed_steps": status.get("completed_steps"),
        "total_steps": status.get("total_steps"),
        "all_complete": status.get("all_complete"),
    }
    if file_paths_error is not None:
        payload["file_paths_error"] = file_paths_error

    print(json.dumps(payload, indent=2))


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

_DOC = """Workflow State Machine for connectus-migration-pipeline.csv (UNIFIED 12-STEP MODEL)

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
  python3 connectus/workflow_state.py markpass "Cisco Spark" "write tests"
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
    "set-param-defaults": cmd_set_param_defaults,
    "set-shadowed-commands": cmd_set_shadowed_commands,
    "detect-shadowed-commands": cmd_detect_shadowed_commands,
    "set-params-to-capabilities": cmd_set_params_to_capabilities,
    "set-release-notes": cmd_set_release_notes,
    "markpass": cmd_markpass,
    "skip": cmd_skip,
    "fail": cmd_fail,
    "reset-to": cmd_reset_to,
    "reset": cmd_reset,
    "wipe-workflow-data": cmd_wipe_workflow_data,
    "at-step": cmd_at_step,
    "list": cmd_list,
    "list-by-assignee": cmd_list_by_assignee,
    "list-by-connector": cmd_list_by_connector,
    "list-connectors": cmd_list_connectors,
    "set-assignee-by-connector": cmd_set_assignee_by_connector,
    "show-step": cmd_show_step,
    "files": cmd_files,
    "auth-params": cmd_auth_params,
    "test-module-params": cmd_test_module_params,
    "context": cmd_context,
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


# Re-exports so tests and external callers can import
# `validate_auth_detail` / `validate_params_to_commands` from this module.
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
    "validate_param_defaults",
    "validate_params_to_capabilities",
    "validate_shadowed_commands",
    "_detect_shadowed_commands_for_integration",
})
