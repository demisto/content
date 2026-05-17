"""Tests for auth_config_parser.validator — validate_auth_details() and validate_config().

These tests mirror the existing ``TestValidateAuthDetail`` in
``workflow_state_test.py`` with identical assertions to ensure
backward-compatible error messages.
"""
from __future__ import annotations

import json

import pytest

from auth_config_parser import (
    AuthType,
    validate_auth_details,
    validate_config,
)

# ---------------------------------------------------------------------------
# Reusable test data
# ---------------------------------------------------------------------------

VALID_AUTH_JSON = (
    '{"auth_types":[{"type":"APIKey","name":"api_key",'
    '"xsoar_params":["api_key"]}],'
    '"config":"REQUIRED(api_key)",'
    '"other_connection":["insecure","proxy","url"]}'
)

VALID_AUTH_JSON_NONE = (
    '{"auth_types":[],"config":"NoneRequired","other_connection":[]}'
)

VALID_AUTH_TYPES = {t.value for t in AuthType}


# ---------------------------------------------------------------------------
# validate_config() standalone tests
# ---------------------------------------------------------------------------


class TestValidateConfig:
    def test_valid_required(self) -> None:
        assert validate_config("REQUIRED(api_key)") == []

    def test_valid_none_required(self) -> None:
        assert validate_config("NoneRequired") == []

    def test_valid_multi_clause(self) -> None:
        assert validate_config("REQUIRED(a) + OPTIONAL(b)") == []

    def test_valid_choice(self) -> None:
        assert validate_config("CHOICE(a, b)") == []

    def test_empty_expression(self) -> None:
        errors = validate_config("")
        assert any("config expression is empty" in e for e in errors)

    def test_empty_operands(self) -> None:
        errors = validate_config("REQUIRED()")
        assert any("no operands" in e for e in errors)

    def test_bad_keyword(self) -> None:
        errors = validate_config("FOO(bar)")
        assert any("malformed clause" in e for e in errors)

    def test_trailing_plus(self) -> None:
        errors = validate_config("REQUIRED(a) +")
        assert any("ends with '+'" in e for e in errors)

    def test_leading_plus(self) -> None:
        errors = validate_config("+ REQUIRED(a)")
        assert any("starts with '+'" in e for e in errors)

    def test_bad_operand_name(self) -> None:
        errors = validate_config("REQUIRED(123bad)")
        assert any("not a valid identifier" in e for e in errors)

    def test_stray_comma(self) -> None:
        errors = validate_config("REQUIRED(a,,b)")
        assert any("empty operand" in e for e in errors)


# ---------------------------------------------------------------------------
# validate_auth_details() tests — mirrors TestValidateAuthDetail
# ---------------------------------------------------------------------------


class TestValidateAuthDetails:
    def test_valid_simple(self) -> None:
        assert validate_auth_details(VALID_AUTH_JSON) == []

    def test_valid_none_required(self) -> None:
        assert validate_auth_details(VALID_AUTH_JSON_NONE) == []

    def test_invalid_json(self) -> None:
        errors = validate_auth_details("not json")
        assert "Invalid JSON" in errors[0]

    def test_missing_keys(self) -> None:
        errors = validate_auth_details('{"auth_types":[]}')
        assert "Missing required keys" in errors[0]

    def test_invalid_auth_type(self) -> None:
        bad = (
            '{"auth_types":[{"type":"INVALID","name":"x",'
            '"xsoar_params":["p"]}],"config":"REQUIRED(x)",'
            '"other_connection":[]}'
        )
        errors = validate_auth_details(bad)
        assert any("invalid type 'INVALID'" in e for e in errors)

    def test_all_valid_auth_types(self) -> None:
        for at in VALID_AUTH_TYPES:
            detail = (
                f'{{"auth_types":[{{"type":"{at}","name":"x",'
                '"xsoar_params":["p"]}],'
                '"config":"REQUIRED(x)","other_connection":[]}'
            )
            assert validate_auth_details(detail) == [], (
                f"Type '{at}' should be valid"
            )

    def test_valid_two_clause_config(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"OAuth2ClientCreds","name":"credentials_consumer",'
            '"xsoar_params":["credentials_consumer.identifier",'
            '"credentials_consumer.password"]},'
            '{"type":"Plain","name":"credentials",'
            '"xsoar_params":["credentials.identifier",'
            '"credentials.password"]}'
            '],'
            '"config":"REQUIRED(credentials) + OPTIONAL(credentials_consumer)",'
            '"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_valid_choice(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"Plain","name":"credentials",'
            '"xsoar_params":["credentials.identifier",'
            '"credentials.password"]},'
            '{"type":"Plain","name":"hunting_credentials",'
            '"xsoar_params":["hunting_credentials.identifier",'
            '"hunting_credentials.password"]}'
            '],'
            '"config":"CHOICE(credentials, hunting_credentials)",'
            '"other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_config_unknown_name(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(missing_name)","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "unknown connection-type name 'missing_name'" in e
            for e in errors
        ), errors

    def test_config_empty_required(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED()","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config'" in e and "no operands" in e for e in errors
        ), errors

    def test_config_trailing_plus(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key) +","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config'" in e and "ends with '+'" in e for e in errors
        ), errors

    def test_config_unknown_keyword(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"FOO(api_key)","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config'" in e and "malformed clause" in e for e in errors
        ), errors

    def test_config_missing_parens(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED api_key","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config'" in e and "malformed clause" in e for e in errors
        ), errors

    def test_none_required_with_entries(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"NoneRequired","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config' is 'NoneRequired' but 'auth_types' contains entries"
            in e
            for e in errors
        ), errors

    def test_non_none_required_empty_types(self) -> None:
        detail = (
            '{"auth_types":[],"config":"REQUIRED(api_key)",'
            '"other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config' is not 'NoneRequired' but 'auth_types' is empty" in e
            for e in errors
        ), errors
        # And the unknown-name check should also fire.
        assert any(
            "unknown connection-type name 'api_key'" in e for e in errors
        ), errors

    def test_sort_order_violation(self) -> None:
        # APIKey < Plain by type; placing Plain first is out of order.
        detail = (
            '{"auth_types":['
            '{"type":"Plain","name":"credentials",'
            '"xsoar_params":["credentials.identifier",'
            '"credentials.password"]},'
            '{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}'
            '],'
            '"config":"REQUIRED(api_key) + REQUIRED(credentials)",'
            '"other_connection":[]}'
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
            '{"type":"APIKey","name":"b","xsoar_params":["p"]},'
            '{"type":"APIKey","name":"a","xsoar_params":["p"]}'
            '],'
            '"config":"REQUIRED(a) + REQUIRED(b)","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "must be sorted by (type, name)" in e for e in errors
        ), errors

    def test_empty_xsoar_params(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":[]}],'
            '"config":"REQUIRED(api_key)","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "auth_types[0]" in e and "must contain at least one entry" in e
            for e in errors
        ), errors

    def test_duplicate_name(self) -> None:
        detail = (
            '{"auth_types":['
            '{"type":"APIKey","name":"x","xsoar_params":["p"]},'
            '{"type":"APIKey","name":"x","xsoar_params":["q"]}'
            '],'
            '"config":"REQUIRED(x)","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "duplicate 'name' 'x'" in e for e in errors
        ), errors

    def test_other_connection_valid(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)",'
            '"other_connection":["insecure","proxy","url"]}'
        )
        assert validate_auth_details(detail) == []

    def test_other_connection_empty_list(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)","other_connection":[]}'
        )
        assert validate_auth_details(detail) == []

    def test_other_connection_missing_key(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)"}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "Missing required keys" in e and "other_connection" in e
            for e in errors
        ), errors

    def test_other_connection_not_list(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)","other_connection":"url"}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'other_connection' must be a list" in e for e in errors
        ), errors

    def test_other_connection_non_string(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)","other_connection":["url",42]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'other_connection'[1]" in e and "must be a string" in e
            for e in errors
        ), errors

    def test_other_connection_empty_string(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)",'
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
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)",'
            '"other_connection":["proxy","url","url"]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "duplicate" in e and "url" in e for e in errors
        ), errors

    def test_other_connection_unsorted(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"api_key",'
            '"xsoar_params":["api_key"]}],'
            '"config":"REQUIRED(api_key)",'
            '"other_connection":["url","proxy"]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "must be sorted ascending" in e
            and "['proxy', 'url']" in e
            for e in errors
        ), errors

    def test_validate_config_standalone(self) -> None:
        """validate_config() works independently of validate_auth_details()."""
        assert validate_config("REQUIRED(api_key)") == []
        assert validate_config("NoneRequired") == []
        errors = validate_config("FOO(bar)")
        assert len(errors) > 0
        assert any("malformed clause" in e for e in errors)

    def test_accepts_dict_input(self) -> None:
        """validate_auth_details() accepts pre-parsed dict."""
        data = {
            "auth_types": [
                {"type": "APIKey", "name": "x", "xsoar_params": ["p"]}
            ],
            "config": "REQUIRED(x)",
            "other_connection": [],
        }
        assert validate_auth_details(data) == []

    def test_not_dict_input(self) -> None:
        """validate_auth_details() rejects non-dict JSON."""
        errors = validate_auth_details("[]")
        assert any("Expected a JSON object" in e for e in errors)

    def test_auth_types_not_list(self) -> None:
        detail = (
            '{"auth_types":"not a list","config":"NoneRequired",'
            '"other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'auth_types' must be a list" in e for e in errors
        ), errors

    def test_auth_types_entry_not_dict(self) -> None:
        detail = (
            '{"auth_types":["not a dict"],"config":"REQUIRED(x)",'
            '"other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "auth_types[0]" in e and "expected object" in e
            for e in errors
        ), errors

    def test_config_not_string(self) -> None:
        detail = (
            '{"auth_types":[],"config":42,"other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'config' must be a string" in e for e in errors
        ), errors

    def test_interpolated_non_bool(self) -> None:
        detail = (
            '{"auth_types":[{"type":"APIKey","name":"x",'
            '"xsoar_params":["p"],"interpolated":"yes"}],'
            '"config":"REQUIRED(x)","other_connection":[]}'
        )
        errors = validate_auth_details(detail)
        assert any(
            "'interpolated' must be a bool" in e for e in errors
        ), errors
