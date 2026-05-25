"""Pure parsing functions for the auth_config_parser package.

Converts raw input (strings, dicts, JSON) into typed data model objects.
Raises :class:`~auth_config_parser.exceptions.AuthConfigParseError` on
invalid input.

The 2026-05 schema simplification removed the ``config`` expression
entirely. The relationship between profiles is implicit (see
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

# Canonical role-name sets per profile type. Per the 2026-05
# "AND-ed secrets go in one profile" rule, these sets are NO LONGER
# exhaustive — the validator privileges them (at least one canonical
# role MUST appear in the map) but accepts ANY non-empty string for
# additional "extras" keys (vendor-required certs, HMAC salts, etc.).
# Types not present in this mapping (``OAuth2*``, ``Passthrough``)
# accept any non-empty string for every key. ``NoneRequired`` never
# appears in ``auth_types[]``.
_CANONICAL_ROLES_BY_TYPE: dict[AuthType, set[str]] = {
    AuthType.APIKey: {"key"},
    AuthType.Plain: {"username", "password"},
}

# Back-compat alias (read by validator.py).
_ROLE_ENUM_BY_TYPE = _CANONICAL_ROLES_BY_TYPE


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
        '{"username", "password"}; for OAuth2*/Passthrough any non-empty '
        "string is accepted. See connectus/column-schemas.md "
        "§Auth Details for examples. Example: "
        '{"type": "APIKey", "name": "credentials", '
        '"xsoar_param_map": {"credentials.password": "key"}}.'
    )


def _legacy_config_key_error() -> str:
    """Build the standard migration-help error for the legacy ``config`` key.

    Fired by both the parser and the validator whenever an ``Auth
    Details`` payload still contains the pre-2026-05 ``config``
    expression field. The error names the offending key, explains
    why it was removed (the only inter-profile relation is exclusive
    OR, so ``config`` carried no information beyond ``auth_types``),
    and tells the caller exactly what to do (drop the key).
    """
    return (
        "'config': the 'config' expression key was removed in the "
        "2026-05 schema simplification and is no longer accepted. "
        "The relationship between profiles is now implicit: "
        "len(auth_types) == 0 means no auth, == 1 means the single "
        "profile is always used, >= 2 means the user picks exactly "
        "one (exclusive OR). AND-ed secrets within one auth flow "
        "live inside one profile's xsoar_param_map. Drop the "
        "'config' key from the payload. See connectus/column-schemas.md "
        "§Auth Details for the new shape."
    )


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

    The 2026-05 schema removed the ``config`` expression field. If a
    payload still contains it, the parser raises with a migration-help
    error pointing at this fact — do not pass through pre-2026-05
    rows without first stripping the ``config`` key.

    Args:
        data: Either a JSON string or an already-parsed dict. Must
            contain the key ``auth_types`` (a list). ``other_connection``
            is optional. The legacy ``config`` key is hard-rejected.

    Returns:
        An :class:`~auth_config_parser.types.AuthDetails` object.

    Raises:
        AuthConfigParseError: If the input is not valid JSON, not a
            dict, is missing required keys, has wrong types, or still
            contains the removed ``config`` key.

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

    # --- Legacy config key (2026-05): hard-reject with migration help ---
    if "config" in data:
        raise AuthConfigParseError(
            _legacy_config_key_error(),
            errors=[_legacy_config_key_error()],
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
        other_connection=other_connection,
    )
