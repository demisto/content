"""Pure parsing functions for the auth_config_parser package.

Converts raw input (strings, dicts, JSON) into typed data model objects.
Raises :class:`~auth_config_parser.exceptions.AuthConfigParseError` on
invalid input.

The relationship between profiles is implicit (see
:class:`auth_config_parser.types.AuthDetails`): 0 entries → no auth, 1
entry → the single profile is always used, ≥2 entries → exclusive-OR.
"""
from __future__ import annotations

import json

from auth_config_parser.exceptions import AuthConfigParseError
from auth_config_parser.types import (
    AuthDetails,
    AuthEntry,
    AuthType,
)

# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

# Valid auth type string values (for fast membership check during parsing).
_VALID_AUTH_TYPE_VALUES = {t.value for t in AuthType}


# ---------------------------------------------------------------------------
# Per-type allowed role-value table (for the xsoar_param_map values).
# The parser only enforces the structural rules (non-empty strings); the
# role-enum check happens in the validator. This table is kept here as
# the canonical reference and is re-used by validator.py.
# ---------------------------------------------------------------------------

# Canonical role-name sets per profile type. Per the
# "AND-ed secrets go in one profile" rule, these sets are NOT
# exhaustive — the validator privileges them (at least one canonical
# role MUST appear in the map) but accepts ANY non-empty string for
# additional "extras" keys (vendor-required certs, HMAC salts, etc.).
# Types not present in this mapping (``Passthrough``) accept any
# non-empty string for every key. ``NoneRequired`` never appears in
# ``auth_types[]``.
_CANONICAL_ROLES_BY_TYPE: dict[AuthType, set[str]] = {
    AuthType.APIKey: {"key"},
    AuthType.Plain: {"username", "password"},
}

# Alias used by validator.py.
_ROLE_ENUM_BY_TYPE = _CANONICAL_ROLES_BY_TYPE


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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
    if "xsoar_param_map" not in raw_dict:
        errors.append(
            f"auth_types[{index}].xsoar_param_map: missing "
            "'xsoar_param_map' (required and non-empty). See "
            "connectus/column-schemas.md §Auth Details for the "
            "shape."
        )
    elif not isinstance(raw_dict["xsoar_param_map"], dict):
        errors.append(
            f"auth_types[{index}].xsoar_param_map: must be an object "
            f"(dict), got {type(raw_dict['xsoar_param_map']).__name__}. "
            "See connectus/column-schemas.md §Auth Details for the "
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

    # --- verify_connection_skip (optional, defaults to False) ---
    verify_connection_skip = False
    if "verify_connection_skip" in raw_dict:
        if not isinstance(raw_dict["verify_connection_skip"], bool):
            errors.append(
                f"auth_types[{index}]: 'verify_connection_skip' must be a bool, "
                f"got {type(raw_dict['verify_connection_skip']).__name__}"
            )
        else:
            verify_connection_skip = raw_dict["verify_connection_skip"]

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
        verify_connection_skip=verify_connection_skip,
    ), errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_auth_details(data: str | dict) -> AuthDetails:
    """Parse Auth Details from a JSON string or pre-parsed dict.

    Performs structural parsing only — converts raw JSON into typed
    objects. Does NOT perform cross-referencing validation (e.g.
    checking ``auth_types[].name`` uniqueness or sort order). Use
    :func:`~auth_config_parser.validator.validate_auth_details` for
    full validation.

    Args:
        data: Either a JSON string or an already-parsed dict. Must
            contain the keys ``auth_types`` (a list) and
            ``other_connection`` (a list — may be empty).

    Returns:
        An :class:`~auth_config_parser.types.AuthDetails` object.

    Raises:
        AuthConfigParseError: If the input is not valid JSON, not a
            dict, is missing required keys, or has wrong types.

    Examples:
        >>> details = parse_auth_details({
        ...     "auth_types": [{"type": "APIKey", "name": "api_key",
        ...                     "xsoar_param_map": {"api_key": "key"}}],
        ...     "other_connection": ["proxy", "url"],
        ... })
        >>> details.auth_types[0].type
        <AuthType.APIKey: 'APIKey'>
        >>> details.auth_types[0].xsoar_param_map
        {'api_key': 'key'}
        >>> details.is_none_required
        False
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

    # --- Required keys ---
    if "auth_types" not in data:
        raise AuthConfigParseError(
            "Missing required key: auth_types"
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

    # --- Parse other_connection (required) ---
    other_connection: list[str] = []
    if "other_connection" not in data:
        errors.append("Missing required key: other_connection")
    else:
        oc = data["other_connection"]
        if not isinstance(oc, list):
            errors.append(
                f"'other_connection' must be a list, got "
                f"{type(oc).__name__}"
            )
        else:
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
        other_connection=other_connection,
    )
