"""Tests for auth_config_parser.validator — validate_auth_details().

Covers the structural rules ported from ``workflow_state.py``'s
``validate_auth_detail()`` (now under the new ``xsoar_param_map``
shape and the 2026-05 schema simplification that removed the
``config`` expression entirely) plus the per-type role-enum rules
and the two legacy-shape rejections (``xsoar_params`` and ``config``).
"""
from __future__ import annotations

import json

from auth_config_parser import (
    AuthType,
    validate_auth_details,
)

# ---------------------------------------------------------------------------
# Reusable test data (post-2026-05 shape — no `config` key)
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
    ``auth_types[]`` entry dict."""
    payload: dict = {"auth_types": [entry_dict]}
    if other_connection is not None:
        payload["other_connection"] = other_connection
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

    def test_valid_none_required_no_other_connection(self) -> None:
        """``other_connection`` is optional — its absence is tolerated."""
        assert validate_auth_details('{"auth_types":[]}') == []

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
                detail = '{"auth_types":[]}'
                assert validate_auth_details(detail) == [], (
                    f"NoneRequired (empty auth_types) should be valid"
                )
                continue
            map_json = json.dumps(per_type_map[at])
            detail = (
                f'{{"auth_types":[{{"type":"{at}","name":"x",'
                f'"xsoar_param_map":{map_json}}}]}}'
            )
            assert validate_auth_details(detail) == [], (
                f"Type '{at}' should be valid"
            )

    def test_valid_two_profile_choice(self) -> None:
        """Two profiles → implicit exclusive-OR (no `config` needed)."""
        detail = (
            '{"auth_types":['
            '{"type":"OAuth2ClientCreds","name":"credentials_consumer",'
            '"xsoar_param_map":{"credentials_consumer.identifier":"client_id",'
            '"credentials_consumer.password":"client_secret"}},'
            '{"type":"Plain","name":"credentials",'
            '"xsoar_param_map":{"credentials.identifier":"username",'
            '"credentials.password":"password"}}'
            ']}'
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
            ']}'
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

    def test_other_connection_missing_key_tolerated(self) -> None:
        """Absence of ``other_connection`` is now tolerated (it was
        required pre-2026-05 alongside ``config``; both were dropped
        from the required-keys set when ``config`` was removed)."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}]}'
        )
        assert validate_auth_details(detail) == []

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


# ---------------------------------------------------------------------------
# Legacy `config` key rejection (2026-05 schema simplification)
# ---------------------------------------------------------------------------


class TestLegacyConfigKeyRejection:
    def test_legacy_config_required_rejected(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_param_map":{"api_key":"key"}}],'
            '"config":"REQUIRED(api_key)",'
            '"other_connection":["insecure","proxy","url"]}'
        )
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "'config'" in joined
        assert "2026-05" in joined
        assert "removed" in joined
        assert "exclusive OR" in joined or "exclusive-OR" in joined.lower()
        assert "connectus/column-schemas.md" in joined

    def test_legacy_config_none_required_rejected(self) -> None:
        detail = (
            '{"auth_types":[],"config":"NoneRequired",'
            '"other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any("'config'" in e and "removed" in e for e in errors)

    def test_legacy_config_choice_rejected(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"APIKey","name":"a","xsoar_param_map":{"p":"key"}},'
            '{"type":"APIKey","name":"b","xsoar_param_map":{"q":"key"}}'
            '],"config":"CHOICE(a, b)"}'
        )
        errors = validate_auth_details(detail)
        assert any("'config'" in e and "removed" in e for e in errors)

    def test_legacy_config_optional_rejected(self) -> None:
        """OPTIONAL was part of the legacy grammar; payload-level
        rejection of the `config` key fires before grammar parsing
        can complain about OPTIONAL specifically."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_param_map":{"p":"key"}}],'
            '"config":"OPTIONAL(x)"}'
        )
        errors = validate_auth_details(detail)
        assert any("'config'" in e and "removed" in e for e in errors)

    def test_legacy_config_rejection_is_immediate(self) -> None:
        """The ``config`` rejection short-circuits — downstream errors
        from other broken parts of the payload are NOT piled on, so the
        migration error stands alone and isn't drowned out."""
        detail = (
            '{"auth_types":[{"type":"INVALID","name":""}],'
            '"config":"REQUIRED(x)","other_connection":"not a list"}'
        )
        errors = validate_auth_details(detail)
        # Only the config-rejection should be present.
        assert len(errors) == 1
        assert "'config'" in errors[0]
        assert "removed" in errors[0]


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

    def test_legacy_other_value_rejected(self) -> None:
        """The pre-2026-05 ``Other`` enum value was renamed to
        ``Passthrough`` with no alias — payloads using the legacy
        name MUST be rejected so the migration error is loud."""
        detail = _wrap({
            "type": "Other", "name": "x",
            "xsoar_param_map": {"x": "anything"},
        })
        errors = validate_auth_details(detail)
        assert any("invalid type 'Other'" in e for e in errors)

    def test_legacy_oauth2authcode_value_rejected(self) -> None:
        """The pre-2026-05 ``OAuth2AuthCode`` enum value was removed
        without an alias — Authorization Code flows are now
        classified as ``Passthrough``. Payloads using the legacy
        name MUST be rejected."""
        detail = _wrap({
            "type": "OAuth2AuthCode", "name": "x",
            "xsoar_param_map": {"x": "auth_code"},
        })
        errors = validate_auth_details(detail)
        assert any("invalid type 'OAuth2AuthCode'" in e for e in errors)

    def test_apikey_two_paths_same_role_allowed(self) -> None:
        """APIKey with two paths both mapping to 'key' — accepted
        (dict-value uniqueness is NOT enforced)."""
        detail = _wrap({
            "type": "APIKey", "name": "x",
            "xsoar_param_map": {"a": "key", "b": "key"},
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


class TestLegacyXsoarParamsRejection:
    def test_legacy_xsoar_params_rejected_with_migration_hint(self) -> None:
        """Old-shape input rejected by validator with full
        migration-help error."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_params":["api_key"]}]}'
        )
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "legacy key 'xsoar_params' is no longer supported" in joined
        assert "xsoar_param_map" in joined
        assert "connectus/column-schemas.md" in joined
        assert "auth_types[0].xsoar_params" in joined

    def test_legacy_xsoar_params_rejected_even_when_new_key_present(self) -> None:
        """Both old + new keys → legacy rejection still fires."""
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_params":["api_key"],'
            '"xsoar_param_map":{"api_key":"key"}}]}'
        )
        errors = validate_auth_details(detail)
        joined = "\n".join(errors)
        assert "legacy key 'xsoar_params' is no longer supported" in joined
