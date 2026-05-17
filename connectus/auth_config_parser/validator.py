"""Validation functions for the auth_config_parser package.

Returns error lists (empty = valid). Never raises. Matches the current
``validate_auth_detail()`` contract in ``workflow_state.py``.
"""
from __future__ import annotations

import json

from auth_config_parser.parser import _VALID_AUTH_TYPE_VALUES, _parse_config_impl


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
      xsoar_params non-empty list of non-empty strings, interpolated
      bool)
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
            if "xsoar_params" not in entry:
                errors.append(f"auth_types[{i}]: missing 'xsoar_params'")
            elif not isinstance(entry["xsoar_params"], list):
                errors.append(
                    f"auth_types[{i}]: 'xsoar_params' must be a list, "
                    f"got {type(entry['xsoar_params']).__name__}"
                )
            elif len(entry["xsoar_params"]) == 0:
                errors.append(
                    f"auth_types[{i}]: 'xsoar_params' must contain at "
                    "least one entry"
                )
            else:
                for j, p in enumerate(entry["xsoar_params"]):
                    if not isinstance(p, str) or not p:
                        errors.append(
                            f"auth_types[{i}]: xsoar_params[{j}] must be "
                            "a non-empty string"
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
