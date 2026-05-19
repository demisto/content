"""Validation functions for the auth_config_parser package.

Returns error lists (empty = valid). Never raises. Matches the current
``validate_auth_detail()`` contract in ``workflow_state.py``.
"""
from __future__ import annotations

import json

from auth_config_parser.parser import (
    _ROLE_ENUM_BY_TYPE,
    _VALID_AUTH_TYPE_VALUES,
    _legacy_xsoar_params_error,
    _parse_config_impl,
)
from auth_config_parser.types import AuthType


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_config(expr: str) -> list[str]:
    """Validate a config expression string.

    Returns a list of human-readable error strings. Empty list means
    the expression is syntactically valid.

    This validates syntax only — it does NOT check that operand names
    match any ``auth_types[].name``. Use :func:`validate_auth_details`
    for cross-referencing validation.

    Args:
        expr: The config expression string.

    Returns:
        List of error strings (empty = valid).

    Examples:
        >>> validate_config("REQUIRED(api_key)")
        []
        >>> validate_config("NoneRequired")
        []
        >>> validate_config("REQUIRED()")
        ["clause 'REQUIRED(...)' has no operands"]
        >>> validate_config("FOO(bar)")  # doctest: +ELLIPSIS
        ["malformed clause 'FOO(bar)' ..."]
    """
    _, errors = _parse_config_impl(expr)
    return errors


def validate_auth_details(data: str | dict) -> list[str]:
    """Validate Auth Details JSON shape. Returns list of errors ([] = valid).

    Performs ALL validation currently done by ``workflow_state.py``'s
    ``validate_auth_detail()``, including:

    - JSON parsing
    - Required keys: ``auth_types``, ``config``, ``other_connection``
    - ``auth_types[]`` entry shape (type enum, name uniqueness,
      ``xsoar_param_map`` non-empty ``dict[str, str]`` with non-empty
      keys and non-empty role values, ``interpolated`` bool)
    - ``xsoar_param_map`` role-value enum enforcement per
      ``auth_types[].type``:

      * ``APIKey`` → values must be from ``{"key"}``.
      * ``Plain`` → values must be from ``{"username", "password"}``.
      * ``OAuth2ClientCreds`` / ``OAuth2AuthCode`` / ``OAuth2JWT`` /
        ``Other`` → any non-empty string (enum deliberately
        undefined for now; to be narrowed in a future PR).
      * ``NoneRequired`` → no entries in ``auth_types[]``; rule moot.
    - Legacy ``xsoar_params`` key is **rejected** with a
      migration-help error pointing at
      ``connectus/column-schemas.md`` §Auth Details.
    - ``auth_types[]`` sort order by ``(type, name)``
    - ``config`` expression syntax (via :func:`validate_config`)
    - ``config`` operand names cross-referenced against
      ``auth_types[].name``
    - ``NoneRequired`` ↔ empty ``auth_types`` coherence
    - ``other_connection``: list of non-empty unique sorted strings

    Args:
        data: JSON string or pre-parsed dict.

    Returns:
        List of error strings (empty = valid).

    Examples:
        >>> validate_auth_details('{"auth_types":[],'
        ...     '"config":"NoneRequired","other_connection":[]}')
        []
    """
    errors: list[str] = []

    # --- Parse JSON if string ---
    if isinstance(data, str):
        try:
            detail = json.loads(data)
        except json.JSONDecodeError as e:
            return [f"Invalid JSON: {e}"]
    else:
        detail = data

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
        errors.append(
            f"'auth_types' must be a list, got "
            f"{type(detail['auth_types']).__name__}"
        )
    else:
        for i, entry in enumerate(detail["auth_types"]):
            if not isinstance(entry, dict):
                errors.append(
                    f"auth_types[{i}]: expected object, got "
                    f"{type(entry).__name__}"
                )
                continue
            entry_type_ok = False
            entry_name_ok = False
            if "type" not in entry:
                errors.append(f"auth_types[{i}]: missing 'type'")
            elif entry["type"] not in _VALID_AUTH_TYPE_VALUES:
                errors.append(
                    f"auth_types[{i}]: invalid type '{entry['type']}'"
                )
            else:
                entry_type_ok = True
            if "name" not in entry:
                errors.append(f"auth_types[{i}]: missing 'name'")
            elif not isinstance(entry["name"], str):
                errors.append(f"auth_types[{i}]: 'name' must be a string")
            elif not entry["name"]:
                errors.append(
                    f"auth_types[{i}]: 'name' must be a non-empty string"
                )
            elif entry["name"] in seen_names:
                errors.append(
                    f"auth_types[{i}]: duplicate 'name' '{entry['name']}' "
                    "(each entry must have a unique logical name)"
                )
            else:
                seen_names.add(entry["name"])
                entry_name_ok = True
            # --- xsoar_param_map validation ---
            # Legacy key: hard-reject with migration-help guidance.
            # The rejection fires whether or not xsoar_param_map is
            # also present.
            legacy_present = "xsoar_params" in entry
            if legacy_present:
                errors.append(_legacy_xsoar_params_error(i))
            if "xsoar_param_map" not in entry:
                # Only emit the missing-key error when the legacy key
                # is absent — otherwise the legacy-rejection message
                # is the more informative signal.
                if not legacy_present:
                    errors.append(
                        f"auth_types[{i}].xsoar_param_map: missing "
                        "'xsoar_param_map' (required and non-empty). "
                        "See connectus/column-schemas.md §Auth Details "
                        "for the new shape."
                    )
            elif not isinstance(entry["xsoar_param_map"], dict):
                errors.append(
                    f"auth_types[{i}].xsoar_param_map: must be an "
                    f"object, got "
                    f"{type(entry['xsoar_param_map']).__name__}. See "
                    "connectus/column-schemas.md §Auth Details for "
                    "the new shape."
                )
            elif len(entry["xsoar_param_map"]) == 0:
                errors.append(
                    f"auth_types[{i}].xsoar_param_map: must be a "
                    "non-empty object (each entry must declare at "
                    "least one xsoar field path). See "
                    "connectus/column-schemas.md §Auth Details."
                )
            else:
                # Structural per-(key,value) check.
                structural_ok = True
                for k, v in entry["xsoar_param_map"].items():
                    if not isinstance(k, str) or not k:
                        errors.append(
                            f"auth_types[{i}].xsoar_param_map: key "
                            f"{k!r} must be a non-empty string"
                        )
                        structural_ok = False
                        continue
                    if not isinstance(v, str):
                        errors.append(
                            f"auth_types[{i}].xsoar_param_map: value "
                            f"for key '{k}' must be a string, got "
                            f"{type(v).__name__}"
                        )
                        structural_ok = False
                        continue
                    if not v:
                        errors.append(
                            f"auth_types[{i}].xsoar_param_map: value "
                            f"for key '{k}' must be a non-empty string"
                        )
                        structural_ok = False
                        continue
                # Per-type role-enum check (only when the entry's
                # type parsed cleanly AND every (key, value) pair
                # passed the structural check).
                if entry_type_ok and structural_ok:
                    enum_at = AuthType(entry["type"])
                    allowed = _ROLE_ENUM_BY_TYPE.get(enum_at)
                    if allowed is not None:
                        for k, v in entry["xsoar_param_map"].items():
                            if v not in allowed:
                                allowed_list = sorted(allowed)
                                errors.append(
                                    f"auth_types[{i}].xsoar_param_map "
                                    f"(type={enum_at.value}): value for "
                                    f"key '{k}' must be one of "
                                    f"{allowed_list} (got '{v}'). See "
                                    "connectus/column-schemas.md "
                                    "§Auth Details for the role table."
                                )
            if "interpolated" in entry and not isinstance(
                entry["interpolated"], bool
            ):
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
        errors.append(
            f"'config' must be a string, got "
            f"{type(detail['config']).__name__}"
        )
    else:
        config_str = detail["config"]
        config_expr, parse_errors = _parse_config_impl(config_str)
        for pe in parse_errors:
            errors.append(f"'config': {pe}")
        for n in config_expr.referenced_names:
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
                        "'config' is not 'NoneRequired' but 'auth_types' "
                        "is empty"
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
