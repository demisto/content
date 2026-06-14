"""Validation functions for the auth_config_parser package.

Returns error lists (empty = valid). Never raises. Matches the
``validate_auth_detail()`` contract in
:mod:`workflow_state.validators` (which is a thin wrapper around
:func:`validate_auth_details` defined here).
"""
from __future__ import annotations

import json

from auth_config_parser.parser import (
    _ROLE_ENUM_BY_TYPE,
    _VALID_AUTH_TYPE_VALUES,
)
from auth_config_parser.types import AuthType


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_auth_details(data: str | dict) -> list[str]:
    """Validate Auth Details JSON shape. Returns list of errors ([] = valid).

    Performs ALL validation:

    - JSON parsing
    - Required keys: ``auth_types`` (a list)
    - ``auth_types[]`` entry shape (type enum, name uniqueness,
      ``xsoar_param_map`` non-empty ``dict[str, str]`` with non-empty
      keys and non-empty role values, ``interpolated`` bool)
    - ``xsoar_param_map`` role-value enum enforcement per
      ``auth_types[].type``:

      * ``APIKey`` → values must be from ``{"key"}``.
      * ``Plain`` → values must be from ``{"username", "password"}``.
      * ``OAuth2ClientCreds`` / ``OAuth2JWT`` / ``Passthrough`` →
        any non-empty string (enum deliberately undefined for now;
        to be narrowed in a future PR).
      * ``NoneRequired`` → no entries in ``auth_types[]``; rule moot.
    - ``auth_types[]`` sort order by ``(type, name)``
    - ``auth_types[]`` distinct XSOAR keysets: no two profiles may
      consume the exact same set of XSOAR fields (``xsoar_param_map``
      keys), so a connection can always be attributed to exactly one
      profile.
    - ``other_connection``: list of non-empty unique sorted strings
      (required; may be an empty list)

    Args:
        data: JSON string or pre-parsed dict.

    Returns:
        List of error strings (empty = valid).

    Examples:
        >>> # NoneRequired equivalent: empty auth_types.
        >>> validate_auth_details('{"auth_types":[],"other_connection":[]}')
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

    # --- Required keys ---
    if "auth_types" not in detail:
        errors.append("Missing required key: auth_types")
        return errors

    seen_names: set[str] = set()
    # Track per-entry validity for the sort check (only consider entries
    # whose `type` and `name` are both well-formed).
    sortable: list[tuple[int, str, str]] = []
    # Track each entry's set of XSOAR field paths for the cross-entry
    # distinctness check (two profiles must not consume the same fields).
    keyset_by_entry: list[tuple[int, frozenset[str]]] = []
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
            # 'NoneRequired' describes an integration with no credentials,
            # so it is exempt from the non-empty xsoar_param_map rule: the
            # map may be absent or empty. If it IS present and non-empty,
            # the structural checks below still apply.
            is_none_required = entry.get("type") == AuthType.NoneRequired.value
            if "xsoar_param_map" not in entry:
                if not is_none_required:
                    errors.append(
                        f"auth_types[{i}].xsoar_param_map: missing "
                        "'xsoar_param_map' (required and non-empty). "
                        "See connectus/column-schemas.md §Auth Details "
                        "for the shape."
                    )
            elif not isinstance(entry["xsoar_param_map"], dict):
                errors.append(
                    f"auth_types[{i}].xsoar_param_map: must be an "
                    f"object, got "
                    f"{type(entry['xsoar_param_map']).__name__}. See "
                    "connectus/column-schemas.md §Auth Details for "
                    "the shape."
                )
            elif len(entry["xsoar_param_map"]) == 0:
                if not is_none_required:
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
                        # OPA Check 17 (column-schemas.md §Auth Details):
                        # duplicate auth.parameter values within a single
                        # canonical profile are rejected — a canonical
                        # profile type (APIKey / Plain) has a FIXED field
                        # shape (APIKey = one 'key'; Plain = one 'username'
                        # + one 'password'). If two XSOAR params map to the
                        # same role the shape no longer fits a canonical
                        # profile and the integration MUST be classified as
                        # 'Passthrough' (the shape-fallback). Catching it
                        # here, at set-auth time, beats failing later at the
                        # OPA gate. Sweep finding F5 (2026-06-03).
                        role_counts: dict[str, list[str]] = {}
                        for k, v in entry["xsoar_param_map"].items():
                            if v in allowed:
                                role_counts.setdefault(v, []).append(k)
                        for role, keys in role_counts.items():
                            if len(keys) > 1:
                                errors.append(
                                    f"auth_types[{i}].xsoar_param_map "
                                    f"(type={enum_at.value}): role '{role}' "
                                    f"is assigned to {len(keys)} params "
                                    f"{sorted(keys)}, but a '{enum_at.value}' "
                                    f"profile allows it exactly once "
                                    f"(OPA Check 17 rejects duplicate "
                                    f"auth.parameter values). An auth flow "
                                    f"that needs two of the same role does "
                                    f"not fit a canonical profile — classify "
                                    f"it as 'Passthrough'. See "
                                    "connectus/column-schemas.md §Auth Details."
                                )
            if "interpolated" in entry and not isinstance(
                entry["interpolated"], bool
            ):
                errors.append(
                    f"auth_types[{i}]: 'interpolated' must be a bool, "
                    f"got {type(entry['interpolated']).__name__}"
                )
            if "verify_connection_skip" in entry and not isinstance(
                entry["verify_connection_skip"], bool
            ):
                errors.append(
                    f"auth_types[{i}]: 'verify_connection_skip' must be a bool, "
                    f"got {type(entry['verify_connection_skip']).__name__}"
                )

            if entry_type_ok and entry_name_ok:
                sortable.append((i, entry["type"], entry["name"]))

            # Collect the set of XSOAR field paths this profile consumes,
            # for the cross-entry distinctness check below. Only entries
            # with a well-formed, non-empty dict map (string keys) are
            # considered — malformed maps already produce their own errors.
            if isinstance(entry.get("xsoar_param_map"), dict) and entry[
                "xsoar_param_map"
            ]:
                keys = {
                    k
                    for k in entry["xsoar_param_map"]
                    if isinstance(k, str) and k
                }
                if keys:
                    keyset_by_entry.append((i, frozenset(keys)))

        # Distinct-xsoar-keyset check: every profile must consume a
        # distinct SET of XSOAR fields so a connection can always be
        # attributed back to exactly one profile. Two profiles that read
        # the exact same set of XSOAR fields are indistinguishable at
        # runtime — there is no way to tell which profile a connection
        # came from. Report each colliding group once.
        seen_keysets: dict[frozenset[str], list[int]] = {}
        for idx, keyset in keyset_by_entry:
            seen_keysets.setdefault(keyset, []).append(idx)
        for keyset, indices in seen_keysets.items():
            if len(indices) > 1:
                errors.append(
                    f"auth_types entries {indices} share the same set of "
                    f"XSOAR fields {sorted(keyset)}; each profile must "
                    "consume a distinct set of XSOAR fields so a "
                    "connection can be attributed to exactly one profile. "
                    "See connectus/column-schemas.md §Auth Details."
                )

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

    # --- other_connection (required) ---
    if "other_connection" not in detail:
        errors.append("Missing required key: other_connection")
    else:
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
