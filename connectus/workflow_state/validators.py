"""Per-cell JSON validators and the named-validator registry.

The state machine and CLI never call these functions by name directly —
they look them up by the YAML config's ``json_schema`` / ``cross_check``
fields via :func:`get_named_validator` / :func:`get_named_cross_check`.
This makes the binding declarative without giving up the rich, hand-written
validation logic for the two real schemas.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from auth_config_parser import (
    auth_param_ids_with_sources as _pkg_auth_param_ids_with_sources,
    parse_auth_details as _pkg_parse_auth_details,
    validate_auth_details as _pkg_validate_auth_details,
)


# ---------------------------------------------------------------------------
# Auth Details — delegates to the auth_config_parser package
# ---------------------------------------------------------------------------

def validate_auth_detail(value: str) -> list[str]:
    """Validate Auth Details JSON shape. Returns list of errors ([] = valid).

    Backward-compatible wrapper that delegates to
    :func:`auth_config_parser.validate_auth_details`.
    """
    return _pkg_validate_auth_details(value)


# ---------------------------------------------------------------------------
# Params to Commands
# ---------------------------------------------------------------------------

# Hint embedded in every "extra top-level key" error reported by
# :func:`validate_params_to_commands`. Kept in sync with
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
# Params for test with default in code
# ---------------------------------------------------------------------------

def validate_param_defaults(value: str) -> list[str]:
    """Validate ``Params for test with default in code`` JSON shape. Returns errors ([] = valid).

    Strict shape::

        { "<yml_param_name>": <any JSON value>, ... }

    Top-level object. Keys non-empty strings. Values can be any JSON type
    (string, number, boolean, null, list, object). Empty {} is valid.
    Consumed by connectus/connectus_migration/connector_param_mapper.py
    as the PARAM_DEFAULTS_JSON positional arg.
    """
    errors: list[str] = []
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]
    if not isinstance(payload, dict):
        return [f"Expected a JSON object, got {type(payload).__name__}"]
    for k in payload:
        if not isinstance(k, str):
            errors.append(f"Key {k!r} must be a string, got {type(k).__name__}")
            continue
        if k == "":
            errors.append("Empty-string key is not allowed")
    return errors


# ---------------------------------------------------------------------------
# Params to Capabilities
# ---------------------------------------------------------------------------

# Closed enum of capability keys (mirrors the constants in
# connectus/connectus_migration/connector_param_mapper.py lines 13-18
# plus the literal "general_configurations" used on line 141).
_PARAMS_TO_CAPABILITIES_ALLOWED_KEYS: frozenset[str] = frozenset({
    "general_configurations",
    "Fetch Assets and Vulnerabilities",
    "Fetch Issues",
    "Log Collection",
    "Fetch Secrets",
    "Threat Intelligence & Enrichment",
    "Automation",
})


def validate_params_to_capabilities(value: str) -> list[str]:
    """Validate Params to Capabilities JSON shape. Returns errors ([] = valid).

    Strict shape (bare capability dict, exactly as
    connectus/connectus_migration/connector_param_mapper.py writes it)::

        {
          "general_configurations": ["param_id", ...],
          "Fetch Issues": ["param_id", ...],
          ... etc, capability key -> list of yml param ids ...
        }

    Top-level keys MUST be drawn from the closed enum
    ``_PARAMS_TO_CAPABILITIES_ALLOWED_KEYS``. No keys are required
    (empty {} is valid). Values are lists of non-empty unique strings.
    """
    errors: list[str] = []
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]
    if not isinstance(payload, dict):
        return [f"Expected a JSON object, got {type(payload).__name__}"]

    allowed = _PARAMS_TO_CAPABILITIES_ALLOWED_KEYS
    for cap, params in payload.items():
        if not isinstance(cap, str) or cap == "":
            errors.append(f"Capability key {cap!r} must be a non-empty string")
            continue
        if cap not in allowed:
            errors.append(
                f"Unknown capability key {cap!r}; allowed keys are "
                f"{sorted(allowed)}"
            )
            continue
        if not isinstance(params, list):
            errors.append(
                f"capabilities[{cap!r}]: expected a list of param ids, "
                f"got {type(params).__name__}"
            )
            continue
        seen: set = set()
        for i, p in enumerate(params):
            if not isinstance(p, str):
                errors.append(
                    f"capabilities[{cap!r}][{i}]: param id must be a "
                    f"string, got {type(p).__name__}"
                )
                continue
            if p == "":
                errors.append(
                    f"capabilities[{cap!r}][{i}]: param id must be a "
                    f"non-empty string"
                )
                continue
            if p in seen:
                errors.append(
                    f"capabilities[{cap!r}]: duplicate param id {p!r}"
                )
                continue
            seen.add(p)
    return errors


# ---------------------------------------------------------------------------
# Generic "any JSON" validator (used by the JSON-shaped data steps that
# don't have a richer schema, e.g. "Params for test with default in code").
# ---------------------------------------------------------------------------

def validate_any_json(value: str) -> list[str]:
    """Accept anything that parses as JSON; return errors ([] = valid)."""
    try:
        json.loads(value)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]
    return []


# ---------------------------------------------------------------------------
# Auth-derived param sources (helper for cross-check + auth_param_ids API)
# ---------------------------------------------------------------------------

def auth_param_sources(auth_detail: dict) -> dict[str, list[str]]:
    """Return ``{yml_param_id: [<source description>, ...]}`` for a raw
    Auth Details dict.

    Returns an empty dict if the dict is structurally invalid.
    """
    from auth_config_parser import AuthConfigParseError

    try:
        details = _pkg_parse_auth_details(auth_detail)
    except AuthConfigParseError:
        return {}
    return _pkg_auth_param_ids_with_sources(details)


# ---------------------------------------------------------------------------
# Named-validator registries (consulted by the state machine / CLI)
# ---------------------------------------------------------------------------

ValidatorFn = Callable[[str], list[str]]


_NAMED_VALIDATORS: dict[str, ValidatorFn] = {
    "auth_details": validate_auth_detail,
    "params_to_commands": validate_params_to_commands,
    "param_defaults": validate_param_defaults,
    "params_to_capabilities": validate_params_to_capabilities,
    "any_json": validate_any_json,
}


def get_named_validator(name: str) -> Optional[ValidatorFn]:
    """Look up a per-cell validator by its YAML name."""
    return _NAMED_VALIDATORS.get(name)


def known_validator_names() -> list[str]:
    """Return the sorted list of known per-cell validator names."""
    return sorted(_NAMED_VALIDATORS.keys())


# Cross-check registry: takes (integration_id, payload_dict) and raises
# WorkflowError on conflict. Implementations are wired in
# :mod:`state_machine` because they consult the CSV and ``auth_param_ids``.

_NAMED_CROSS_CHECKS: dict[str, str] = {
    # Maps the YAML name → a stable identifier the engine uses to look up
    # the actual implementation. The implementation lives in the state
    # machine module to avoid an import cycle (cross-checks consult the
    # CSV which lives in csv_io).
    "params_to_commands_no_auth_overlap": "params_to_commands_no_auth_overlap",
}


def known_cross_check_names() -> list[str]:
    """Return the sorted list of known cross-check validator names."""
    return sorted(_NAMED_CROSS_CHECKS.keys())


def is_known_cross_check(name: str) -> bool:
    return name in _NAMED_CROSS_CHECKS
