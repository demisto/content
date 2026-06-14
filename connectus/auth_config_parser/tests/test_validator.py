"""Tests for auth_config_parser.validator — validate_auth_details().

Covers the structural rules of the ``xsoar_param_map`` shape plus
the per-type role-enum rules.
"""
from __future__ import annotations

import json

from auth_config_parser import (
    AuthType,
    validate_auth_details,
)

# ---------------------------------------------------------------------------
# Reusable test data
# ---------------------------------------------------------------------------

VALID_AUTH_JSON = (
    '{"auth_types":[{"type":"APIKey","name":"api_key",'
    '"xsoar_param_map":{"api_key":"key"}}],'
    '"other_connection":["insecure","proxy","url"]}'
)

VALID_AUTH_JSON_NONE = (
    '{"auth_types":[],"other_connection":[]}'
)

VALID_AUTH_TYPES = {t.value for t in AuthType}


def _wrap(entry_dict: dict, *, other_connection: list | None = None) -> str:
    """Helper: build a complete auth-details JSON document around one
    ``auth_types[]`` entry dict. ``other_connection`` defaults to ``[]``."""
    payload: dict = {
        "auth_types": [entry_dict],
        "other_connection": other_connection if other_connection is not None else [],
    }
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# validate_auth_details() core tests
# ---------------------------------------------------------------------------


class TestValidateAuthDetails:
    def test_valid_simple(self) -> None:
        assert validate_auth_details(VALID_AUTH_JSON) == []

    def test_valid_none_required(self) -> None:
        """Empty auth_types list = the integration requires no auth."""
        assert validate_auth_details(VALID_AUTH_JSON_NONE) == []

    def test_invalid_json(self) -> None:
        errors = validate_auth_details("not json")
        assert "Invalid JSON" in errors[0]

    def test_missing_auth_types_key(self) -> None:
        errors = validate_auth_details('{}')
        assert any("Missing required key" in e and "auth_types" in e
                   for e in errors)

    def test_invalid_auth_type(self) -> None:
        bad = (
            '{"auth_types":[{"type":"INVALID","name":"x",'
            '"xsoar_param_map":{"p":"key"}}]}'
        )
        errors = validate_auth_details(bad)
        assert any("invalid type 'INVALID'" in e for e in errors)

    def test_all_valid_auth_types(self) -> None:
        # APIKey requires role "key"; Plain requires "username"/"password";
        # the rest accept any non-empty string. NoneRequired is handled
        # separately (no auth_types[] entry exists for it).
        per_type_map: dict[str, dict[str, str]] = {
            "APIKey": {"p": "key"},
            "Plain": {"u": "username", "p": "password"},
            "OAuth2ClientCreds": {"p": "client_secret"},
            "OAuth2JWT": {"p": "private_key"},
            "Passthrough": {"p": "anything"},
        }
        for at in VALID_AUTH_TYPES:
            if at == "NoneRequired":
                detail = '{"auth_types":[],"other_connection":[]}'
                assert validate_auth_details(detail) == [], (
                    f"NoneRequired (empty auth_types) should be valid"
                )
                continue
            map_json = json.dumps(per_type_map[at])
            detail = (
                f'{{"auth_types":[{{"type":"{at}","name":"x",'
                f'"xsoar_param_map":{map_json}}}],'
                f'"other_connection":[]}}'
            )
            assert validate_auth_details(detail) == [], (
                f"Type '{at}' should be valid"
            )

    def test_valid_two_profile_choice(self) -> None:
        """Two profiles → implicit exclusive-OR."""
        detail = (
            '{"auth_types":['
            '{"type":"OAuth2ClientCreds","name":"credentials_consumer",'
            '"xsoar_param_map":{"credentials_consumer.identifier":"client_id",'
            '"credentials_consumer.password":"client_secret"}},'
            '{"type":"Plain","name":"credentials",'
            '"xsoar_param_map":{"credentials.identifier":"username",'
            '"credentials.password":"password"}}'
            '],"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_valid_choice_of_two_plain(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"Plain","name":"credentials",'
            '"xsoar_param_map":{"credentials.identifier":"username",'
            '"credentials.password":"password"}},'
            '{"type":"Plain","name":"hunting_credentials",'
            '"xsoar_param_map":{"hunting_credentials.identifier":"username",'
            '"hunting_credentials.password":"password"}}'
            '],"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_sort_order_violation(self) -> None:
        # APIKey < Plain by type; placing Plain first is out of order.
        detail = (
            '{"auth_types":['
            '{"type":"Plain","name":"credentials",'
            '"xsoar_param_map":{"credentials.identifier":"username",'
            '"credentials.password":"password"}},'
            '{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}'
            ']}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "must be sorted by (type, name)" in e for e in errors
        ), errors
        # The error should name the offending pair.
        assert any(
            "'Plain'/'credentials'" in e and "'APIKey'/'api_key'" in e
            for e in errors
        ), errors

    def test_sort_order_same_type_by_name(self) -> None:
        # Same type, names out of order: 'b' before 'a'.
        detail = (
            '{"auth_types":['
            '{"type":"APIKey","name":"b","xsoar_param_map":{"p":"key"}},'
            '{"type":"APIKey","name":"a","xsoar_param_map":{"p":"key"}}'
            ']}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "must be sorted by (type, name)" in e for e in errors
        ), errors

    def test_duplicate_name(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"APIKey","name":"x","xsoar_param_map":{"p":"key"}},'
            '{"type":"APIKey","name":"x","xsoar_param_map":{"q":"key"}}'
            ']}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "duplicate 'name' 'x'" in e for e in errors
        ), errors

    def test_other_connection_valid(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":["insecure","proxy","url"]}'
        )
        assert validate_auth_details(detail) == []

    def test_other_connection_empty_list(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_other_connection_missing_key_rejected(self) -> None:
        """``other_connection`` is required."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "Missing required key" in e and "other_connection" in e
            for e in errors
        ), errors

    def test_other_connection_not_list(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":"url"}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'other_connection' must be a list" in e for e in errors
        ), errors

    def test_other_connection_non_string(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":["url",42]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'other_connection'[1]" in e and "must be a string" in e
            for e in errors
        ), errors

    def test_other_connection_empty_string(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":["url",""]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'other_connection'[1]" in e and "non-empty string" in e
            for e in errors
        ), errors

    def test_other_connection_duplicates(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":["proxy","url","url"]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "duplicate" in e and "url" in e for e in errors
        ), errors

    def test_other_connection_unsorted(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"other_connection":["url","proxy"]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "must be sorted ascending" in e
            and "['proxy', 'url']" in e
            for e in errors
        ), errors

    def test_accepts_dict_input(self) -> None:
        """validate_auth_details() accepts pre-parsed dict."""
        data = {
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "other_connection": [],
        }
        assert validate_auth_details(data) == []

    def test_not_dict_input(self) -> None:
        """validate_auth_details() rejects non-dict JSON."""
        errors = validate_auth_details("[]")
        assert any("Expected a JSON object" in e for e in errors)

    def test_auth_types_not_list(self) -> None:
        detail = (
            '{"auth_types":"not a list","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'auth_types' must be a list" in e for e in errors
        ), errors

    def test_auth_types_entry_not_dict(self) -> None:
        detail = (
            '{"auth_types":["not a dict"],"other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "auth_types[0]" in e and "expected object" in e
            for e in errors
        ), errors

    def test_interpolated_non_bool(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"},"interpolated":"yes"}]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'interpolated' must be a bool" in e for e in errors
        ), errors

    # --- verify_connection_skip ---

    def test_verify_connection_skip_absent_is_valid(self) -> None:
        """Absence of the optional key is valid (defaults to False)."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"}}],"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_verify_connection_skip_true_is_valid(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"},"verify_connection_skip":true}],'
            '"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_verify_connection_skip_false_is_valid(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"},"verify_connection_skip":false}],'
            '"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_verify_connection_skip_non_bool_string_rejected(self) -> None:
        """String ``"true"`` is NOT a JSON bool — must be rejected."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"},"verify_connection_skip":"true"}]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'verify_connection_skip' must be a bool" in e for e in errors
        ), errors

    def test_verify_connection_skip_non_bool_int_rejected(self) -> None:
        """Int ``1`` is NOT a JSON bool — must be rejected."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"},"verify_connection_skip":1}]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'verify_connection_skip' must be a bool" in e for e in errors
        ), errors

    def test_verify_connection_skip_per_profile_mixed(self) -> None:
        """A multi-profile (exclusive-OR) row may set the key on one
        profile and leave it default on the other."""
        detail = (
            '{"auth_types":['
            '{"type":"OAuth2ClientCreds","name":"client_creds",'
            '"xsoar_param_map":{"credentials.identifier":"client_id",'
            '"credentials.password":"client_secret"},'
            '"interpolated":true},'
            '{"type":"Passthrough","name":"auth_code",'
            '"xsoar_param_map":{"auth_code":"authorization_code"},'
            '"interpolated":true,"verify_connection_skip":true}'
            '],"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []


# ---------------------------------------------------------------------------
# xsoar_param_map structural + role-enum tests
# ---------------------------------------------------------------------------


class TestXsoarParamMapStructural:
    def test_missing_xsoar_param_map_rejected(self) -> None:
        detail = _wrap({"type": "APIKey", "name": "x"})
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "auth_types[0].xsoar_param_map" in joined
        assert "missing 'xsoar_param_map'" in joined
        assert "connectus/column-schemas.md" in joined

    def test_xsoar_param_map_must_be_dict_list(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": ["p"],
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "auth_types[0].xsoar_param_map" in joined
        assert "must be an object" in joined

    def test_xsoar_param_map_must_be_dict_string(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": "p",
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "must be an object" in joined

    def test_xsoar_param_map_must_be_dict_null(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": None,
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "must be an object" in joined

    def test_empty_xsoar_param_map_rejected_for_apikey(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x", "xsoar_param_map": {},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "auth_types[0].xsoar_param_map" in joined
        assert "non-empty" in joined

    def test_empty_xsoar_param_map_rejected_for_plain(self) -> None:
        detail = _wrap({
            "type": "Plain", "name": "x", "xsoar_param_map": {},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "non-empty" in joined

    def test_missing_xsoar_param_map_allowed_for_none_required(self) -> None:
        """NoneRequired describes no-credential auth, so an absent
        xsoar_param_map is valid (unlike credential profile types)."""
        detail = _wrap({
            "type": "NoneRequired", "name": "No authentication",
            "interpolated": True,
        })
        assert validate_auth_details(detail) == []

    def test_empty_xsoar_param_map_allowed_for_none_required(self) -> None:
        """An explicitly empty xsoar_param_map is also valid for
        NoneRequired."""
        detail = _wrap({
            "type": "NoneRequired", "name": "No authentication",
            "xsoar_param_map": {}, "interpolated": True,
        })
        assert validate_auth_details(detail) == []

    def test_xsoar_param_map_value_must_be_string(self) -> None:
        """Non-string values rejected with field path named."""
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {"p": 42},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "auth_types[0].xsoar_param_map" in joined
        assert "must be a string" in joined

    def test_xsoar_param_map_value_must_be_string_null(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {"p": None},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "must be a string" in joined

    def test_oauth_value_empty_string_rejected(self) -> None:
        """Empty role value rejected regardless of type (structural)."""
        detail = _wrap({
            "type": "OAuth2ClientCreds", "name": "x",
            "xsoar_param_map": {"p": ""},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "non-empty string" in joined

    def test_interpolated_entry_still_requires_non_empty_map(self) -> None:
        """``interpolated: true`` does NOT exempt the entry from the
        non-empty-map rule."""
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {},
            "interpolated": True,
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "auth_types[0].xsoar_param_map" in joined
        assert "non-empty" in joined


class TestXsoarParamMapRoleEnum:
    def test_apikey_value_must_be_key_positive(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {"x": "key"},
        })
        assert validate_auth_details(detail) == []

    def test_apikey_value_must_be_key_negative(self) -> None:
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {"x": "secret"},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "auth_types[0].xsoar_param_map" in joined
        assert "type=APIKey" in joined
        # Allowed-values list is named.
        assert "['key']" in joined
        # Offending value is named.
        assert "'secret'" in joined
        # Key is named.
        assert "'x'" in joined
        # Schema-doc pointer.
        assert "connectus/column-schemas.md" in joined

    def test_plain_value_username_positive(self) -> None:
        detail = _wrap({
            "type": "Plain", "name": "x",
            "xsoar_param_map": {"u": "username", "p": "password"},
        })
        assert validate_auth_details(detail) == []

    def test_plain_value_password_positive(self) -> None:
        detail = _wrap({
            "type": "Plain", "name": "x",
            "xsoar_param_map": {"p": "password"},
        })
        assert validate_auth_details(detail) == []

    def test_plain_value_other_rejected(self) -> None:
        detail = _wrap({
            "type": "Plain", "name": "x",
            "xsoar_param_map": {"p": "token"},
        })
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "type=Plain" in joined
        # Allowed-values list (sorted) is named.
        assert "['password', 'username']" in joined
        assert "'token'" in joined

    def test_oauth_value_any_string_positive(self) -> None:
        detail = _wrap({
            "type": "OAuth2ClientCreds", "name": "x",
            "xsoar_param_map": {"x": "client_id"},
        })
        assert validate_auth_details(detail) == []

    def test_oauth_jwt_value_any_string_positive(self) -> None:
        detail = _wrap({
            "type": "OAuth2JWT", "name": "x",
            "xsoar_param_map": {"x": "private_key"},
        })
        assert validate_auth_details(detail) == []

    def test_passthrough_value_any_string_positive(self) -> None:
        detail = _wrap({
            "type": "Passthrough", "name": "x",
            "xsoar_param_map": {"weird_path": "arbitrary_role"},
        })
        assert validate_auth_details(detail) == []

    def test_apikey_two_paths_same_role_rejected(self) -> None:
        """APIKey with two paths both mapping to 'key' — REJECTED.

        Sweep finding F5 (2026-06-03): a canonical APIKey profile has a
        fixed single-'key' shape. Two params mapping to 'key' violate
        OPA Check 17 (duplicate auth.parameter values) — the auth flow no
        longer fits a canonical profile and must be classified as
        'Passthrough' (the shape-fallback). The validator now catches this
        at set-auth time instead of letting it fail later at the OPA gate.
        """
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {"a": "key", "b": "key"},
        })
        errors = validate_auth_details(detail)
        assert errors, "expected duplicate-'key' role to be rejected"
        assert any("OPA Check 17" in e and "Passthrough" in e for e in errors)

    def test_plain_two_passwords_rejected(self) -> None:
        """Plain with two 'password' roles — REJECTED (OPA Check 17).

        A canonical Plain profile is exactly one username + one password.
        Two passwords (sweep finding F5, e.g. the Rapid7 basic-auth +
        optional 2FA token case) do not fit the canonical shape and must
        be classified as 'Passthrough'.
        """
        detail = _wrap({
            "type": "Plain", "name": "x",
            "xsoar_param_map": {
                "credentials.identifier": "username",
                "credentials.password": "password",
                "token.password": "password",
            },
        })
        errors = validate_auth_details(detail)
        assert errors, "expected duplicate-'password' role to be rejected"
        assert any("OPA Check 17" in e and "Passthrough" in e for e in errors)

    def test_passthrough_duplicate_role_still_allowed(self) -> None:
        """Passthrough is the free-form shape-fallback: the duplicate-role
        rule does NOT apply (its role enum is deliberately undefined)."""
        detail = _wrap({
            "type": "Passthrough", "name": "x", "interpolated": True,
            "xsoar_param_map": {"a": "token", "b": "token"},
        })
        assert validate_auth_details(detail) == []

    def test_plain_proper_one_each_allowed(self) -> None:
        """Sanity: the proper one-username + one-password Plain shape
        is still accepted after the F5 duplicate-role check."""
        detail = _wrap({
            "type": "Plain", "name": "x",
            "xsoar_param_map": {"u": "username", "p": "password"},
        })
        assert validate_auth_details(detail) == []

    def test_hiddenusername_suppression_is_classifier_side(self) -> None:
        """The validator does NOT enforce the hidden-leaf
        suppression rule (e.g. that APIKey with a ``.identifier``
        key in its map should have been suppressed by the
        classifier). Confirm a payload with ``credentials.identifier``
        + APIKey passes structurally — the suppression is the
        classifier's job per the SKILL."""
        detail = _wrap({
            "type": "APIKey", "name": "credentials",
            "xsoar_param_map": {"credentials.identifier": "key"},
        })
        assert validate_auth_details(detail) == []
