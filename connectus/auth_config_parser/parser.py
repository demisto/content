"""Pure parsing functions for the auth_config_parser package.

Converts raw input (strings, dicts, JSON) into typed data model objects.
Raises :class:`~auth_config_parser.exceptions.AuthConfigParseError` on
invalid input.
"""
from __future__ import annotations

import json
import re

from auth_config_parser.exceptions import AuthConfigParseError
from auth_config_parser.types import (
    AuthDetails,
    AuthEntry,
    AuthType,
    ClauseOperator,
    ConfigClause,
    ConfigExpression,
)

# ---------------------------------------------------------------------------
# Regex constants (ported from workflow_state.py)
# ---------------------------------------------------------------------------

_CLAUSE_RE = re.compile(
    r"^\s*(REQUIRED|OPTIONAL|CHOICE)\s*\(\s*([^)]*?)\s*\)\s*$"
)
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SPLIT_RE = re.compile(r"\s*\+\s*")

# Valid auth type string values (for fast membership check during parsing).
_VALID_AUTH_TYPE_VALUES = {t.value for t in AuthType}


# ---------------------------------------------------------------------------
# Per-type allowed role-value table (for the xsoar_param_map values).
# The parser only enforces the structural rules (non-empty strings); the
# role-enum check happens in the validator. This table is kept here as
# the canonical reference and is re-used by validator.py.
# ---------------------------------------------------------------------------

# Types whose xsoar_param_map values are constrained to a fixed enum.
# Types not present in this mapping (OAuth2*, Other) accept any non-empty
# string. ``NoneRequired`` never appears in ``auth_types[]``.
_ROLE_ENUM_BY_TYPE: dict[AuthType, set[str]] = {
    AuthType.APIKey: {"key"},
    AuthType.Plain: {"username", "password"},
}


def _legacy_xsoar_params_error(index: int) -> str:
    """Build the standard migration-help error for the legacy key.

    Fired by both the parser and the validator whenever an
    ``auth_types[]`` entry still uses the old ``xsoar_params`` field.
    The message names the offending field path, the new field name,
    points the reader at the schema doc, and inlines a copy-paste
    example so the migration is mechanical.
    """
    return (
        f"auth_types[{index}].xsoar_params: legacy key 'xsoar_params' "
        "is no longer supported. Migrate to 'xsoar_param_map' (a "
        "dict mapping each XSOAR field path to the role that secret "
        "plays for this connection). For 'APIKey' the only allowed "
        "value is \"key\"; for 'Plain' values must be in "
        '{"username", "password"}; for OAuth2*/Other any non-empty '
        "string is accepted. See connectus/column-schemas.md "
        "§Auth Details for examples. Example: "
        '{"type": "APIKey", "name": "credentials", '
        '"xsoar_param_map": {"credentials.password": "key"}}.'
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_config_impl(config: str) -> tuple[ConfigExpression, list[str]]:
    """Core config parsing implementation.

    Returns ``(ConfigExpression, parse_errors)`` where ``parse_errors``
    is a list of human-readable issues with the expression.

    This is the internal workhorse extracted from
    ``workflow_state._parse_auth_config()``. The public
    :func:`parse_config` raises on errors; the validator calls this
    directly to collect errors without raising.
    """
    parse_errors: list[str] = []
    clauses: list[ConfigClause] = []

    stripped = config.strip()
    if stripped == "":
        parse_errors.append("config expression is empty")
        return ConfigExpression(), parse_errors
    if stripped == "NoneRequired":
        return ConfigExpression(none_required=True), parse_errors

    # Detect leading/trailing `+` before splitting.
    if stripped.startswith("+"):
        parse_errors.append(
            "config expression starts with '+' (no leading clause)"
        )
    if stripped.endswith("+"):
        parse_errors.append(
            "config expression ends with '+' (no trailing clause)"
        )

    segments = _SPLIT_RE.split(stripped)
    for seg_idx, segment in enumerate(segments):
        if segment.strip() == "":
            # Already covered by the leading/trailing checks above OR a
            # genuine "+ +" in the middle.
            if not (seg_idx == 0 and stripped.startswith("+")) and not (
                seg_idx == len(segments) - 1 and stripped.endswith("+")
            ):
                parse_errors.append("empty clause between '+' separators")
            continue
        m = _CLAUSE_RE.match(segment)
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
        clause_names: list[str] = []
        for op in operands:
            if op == "":
                parse_errors.append(
                    f"clause '{keyword}(...)' has an empty operand "
                    "(stray comma?)"
                )
                continue
            if not _NAME_RE.fullmatch(op):
                parse_errors.append(
                    f"clause '{keyword}(...)' operand '{op}' is not a "
                    "valid identifier (must match [A-Za-z_][A-Za-z0-9_]*)"
                )
                continue
            clause_names.append(op)
        if clause_names:
            clauses.append(
                ConfigClause(
                    operator=ClauseOperator(keyword),
                    names=clause_names,
                )
            )

    return ConfigExpression(none_required=False, clauses=clauses), parse_errors


def _parse_auth_entry(index: int, raw_dict: dict) -> tuple[AuthEntry | None, list[str]]:
    """Parse one ``auth_types[]`` entry dict into an :class:`AuthEntry`.

    Returns ``(entry_or_none, errors)``. If the entry is structurally
    invalid, ``entry_or_none`` is ``None`` and ``errors`` describes the
    problems.
    """
    errors: list[str] = []

    if not isinstance(raw_dict, dict):
        errors.append(
            f"auth_types[{index}]: expected object, got "
            f"{type(raw_dict).__name__}"
        )
        return None, errors

    # --- type ---
    entry_type: AuthType | None = None
    if "type" not in raw_dict:
        errors.append(f"auth_types[{index}]: missing 'type'")
    elif raw_dict["type"] not in _VALID_AUTH_TYPE_VALUES:
        errors.append(f"auth_types[{index}]: invalid type '{raw_dict['type']}'")
    else:
        entry_type = AuthType(raw_dict["type"])

    # --- name ---
    entry_name: str | None = None
    if "name" not in raw_dict:
        errors.append(f"auth_types[{index}]: missing 'name'")
    elif not isinstance(raw_dict["name"], str):
        errors.append(f"auth_types[{index}]: 'name' must be a string")
    elif not raw_dict["name"]:
        errors.append(f"auth_types[{index}]: 'name' must be a non-empty string")
    else:
        entry_name = raw_dict["name"]

    # --- xsoar_param_map ---
    xsoar_param_map: dict[str, str] | None = None
    if "xsoar_params" in raw_dict:
        # Legacy key — hard-reject with migration-help guidance.
        errors.append(_legacy_xsoar_params_error(index))
    if "xsoar_param_map" not in raw_dict:
        # Only emit the missing-key error when the legacy key isn't
        # present — otherwise the legacy-rejection message is the more
        # informative signal.
        if "xsoar_params" not in raw_dict:
            errors.append(
                f"auth_types[{index}].xsoar_param_map: missing "
                "'xsoar_param_map' (required and non-empty). See "
                "connectus/column-schemas.md §Auth Details for the new "
                "shape."
            )
    elif not isinstance(raw_dict["xsoar_param_map"], dict):
        errors.append(
            f"auth_types[{index}].xsoar_param_map: must be an object "
            f"(dict), got {type(raw_dict['xsoar_param_map']).__name__}. "
            "See connectus/column-schemas.md §Auth Details for the new "
            "shape."
        )
    elif len(raw_dict["xsoar_param_map"]) == 0:
        errors.append(
            f"auth_types[{index}].xsoar_param_map: must be a non-empty "
            "object (each entry must declare at least one xsoar field "
            "path). See connectus/column-schemas.md §Auth Details."
        )
    else:
        xsoar_param_map = {}
        for k, v in raw_dict["xsoar_param_map"].items():
            if not isinstance(k, str) or not k:
                errors.append(
                    f"auth_types[{index}].xsoar_param_map: key "
                    f"{k!r} must be a non-empty string"
                )
                continue
            if not isinstance(v, str):
                errors.append(
                    f"auth_types[{index}].xsoar_param_map: value for "
                    f"key '{k}' must be a string, got "
                    f"{type(v).__name__}"
                )
                continue
            if not v:
                errors.append(
                    f"auth_types[{index}].xsoar_param_map: value for "
                    f"key '{k}' must be a non-empty string"
                )
                continue
            xsoar_param_map[k] = v

    # --- interpolated (optional, defaults to False) ---
    interpolated = False
    if "interpolated" in raw_dict:
        if not isinstance(raw_dict["interpolated"], bool):
            errors.append(
                f"auth_types[{index}]: 'interpolated' must be a bool, "
                f"got {type(raw_dict['interpolated']).__name__}"
            )
        else:
            interpolated = raw_dict["interpolated"]

    if errors:
        return None, errors

    # All fields validated — safe to construct.
    assert entry_type is not None
    assert entry_name is not None
    assert xsoar_param_map is not None
    return AuthEntry(
        type=entry_type,
        name=entry_name,
        xsoar_param_map=xsoar_param_map,
        interpolated=interpolated,
    ), errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_config(expr: str) -> ConfigExpression:
    """Parse a config expression string into a ConfigExpression.

    Args:
        expr: The config expression string, e.g.
            ``'REQUIRED(api_key) + OPTIONAL(oauth_creds)'``
            or ``'NoneRequired'``.

    Returns:
        A :class:`~auth_config_parser.types.ConfigExpression` with
        parsed clauses.

    Raises:
        AuthConfigParseError: If the expression is malformed.

    Examples:
        >>> parse_config("NoneRequired")
        ConfigExpression(none_required=True, clauses=[])

        >>> parse_config("REQUIRED(api_key)")
        ConfigExpression(none_required=False, clauses=[ConfigClause(operator=<ClauseOperator.REQUIRED: 'REQUIRED'>, names=['api_key'])])

        >>> parse_config("REQUIRED(creds) + OPTIONAL(oauth)")
        ConfigExpression(none_required=False, clauses=[ConfigClause(operator=<ClauseOperator.REQUIRED: 'REQUIRED'>, names=['creds']), ConfigClause(operator=<ClauseOperator.OPTIONAL: 'OPTIONAL'>, names=['oauth'])])
    """
    result, errors = _parse_config_impl(expr)
    if errors:
        raise AuthConfigParseError(
            f"config parse errors: {'; '.join(errors)}",
            errors=errors,
        )
    return result


def parse_auth_details(data: str | dict) -> AuthDetails:
    """Parse Auth Details from a JSON string or pre-parsed dict.

    Performs structural parsing only — converts raw JSON into typed
    objects. Does NOT perform cross-referencing validation (e.g.
    checking that config names match auth_types names). Use
    :func:`~auth_config_parser.validator.validate_auth_details` for
    full validation.

    Args:
        data: Either a JSON string or an already-parsed dict.

    Returns:
        An :class:`~auth_config_parser.types.AuthDetails` object.

    Raises:
        AuthConfigParseError: If the input is not valid JSON, not a
            dict, or is missing required keys / has wrong types.

    Examples:
        >>> details = parse_auth_details({
        ...     "auth_types": [{"type": "APIKey", "name": "api_key",
        ...                     "xsoar_param_map": {"api_key": "key"}}],
        ...     "config": "REQUIRED(api_key)",
        ...     "other_connection": ["url", "proxy"],
        ... })
        >>> details.auth_types[0].type
        <AuthType.APIKey: 'APIKey'>
        >>> details.auth_types[0].xsoar_param_map
        {'api_key': 'key'}
        >>> details.config.clauses[0].operator
        <ClauseOperator.REQUIRED: 'REQUIRED'>
    """
    errors: list[str] = []

    # --- Parse JSON if string ---
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            raise AuthConfigParseError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise AuthConfigParseError(
            f"Expected a JSON object, got {type(data).__name__}"
        )

    # --- Check required keys (auth_types and config are always required;
    #     other_connection is optional for legacy compat) ---
    required_keys = {"auth_types", "config"}
    missing = required_keys - set(data.keys())
    if missing:
        raise AuthConfigParseError(
            f"Missing required keys: {', '.join(sorted(missing))}"
        )

    # --- Parse auth_types ---
    auth_entries: list[AuthEntry] = []
    if not isinstance(data["auth_types"], list):
        raise AuthConfigParseError(
            f"'auth_types' must be a list, got "
            f"{type(data['auth_types']).__name__}"
        )

    for i, raw_entry in enumerate(data["auth_types"]):
        entry, entry_errors = _parse_auth_entry(i, raw_entry)
        if entry_errors:
            errors.extend(entry_errors)
        if entry is not None:
            auth_entries.append(entry)

    # --- Parse config ---
    if not isinstance(data["config"], str):
        errors.append(
            f"'config' must be a string, got "
            f"{type(data['config']).__name__}"
        )
        config_expr = ConfigExpression()
    else:
        config_expr, config_errors = _parse_config_impl(data["config"])
        for ce in config_errors:
            errors.append(f"'config': {ce}")

    # --- Parse other_connection (optional) ---
    other_connection: list[str] | None = None
    if "other_connection" in data:
        oc = data["other_connection"]
        if not isinstance(oc, list):
            errors.append(
                f"'other_connection' must be a list, got "
                f"{type(oc).__name__}"
            )
        else:
            other_connection = []
            for j, item in enumerate(oc):
                if not isinstance(item, str):
                    errors.append(
                        f"'other_connection'[{j}]: must be a string, got "
                        f"{type(item).__name__}"
                    )
                elif not item:
                    errors.append(
                        f"'other_connection'[{j}]: must be a non-empty string"
                    )
                else:
                    other_connection.append(item)

    if errors:
        raise AuthConfigParseError(
            f"auth details parse errors: {'; '.join(errors)}",
            errors=errors,
        )

    return AuthDetails(
        auth_types=auth_entries,
        config=config_expr,
        other_connection=other_connection,
    )
