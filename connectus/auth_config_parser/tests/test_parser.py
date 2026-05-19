"""Tests for auth_config_parser.parser — parse_config() and parse_auth_details()."""
from __future__ import annotations

import json

import pytest

from auth_config_parser import (
    AuthConfigParseError,
    AuthDetails,
    AuthEntry,
    AuthType,
    ClauseOperator,
    ConfigClause,
    ConfigExpression,
    parse_auth_details,
    parse_config,
)


# ---------------------------------------------------------------------------
# parse_config() tests
# ---------------------------------------------------------------------------


class TestParseConfig:
    def test_parse_config_none_required(self) -> None:
        result = parse_config("NoneRequired")
        assert result == ConfigExpression(none_required=True, clauses=[])
        assert result.none_required is True
        assert result.clauses == []
        assert result.referenced_names == []

    def test_parse_config_single_required(self) -> None:
        result = parse_config("REQUIRED(api_key)")
        assert result.none_required is False
        assert len(result.clauses) == 1
        assert result.clauses[0].operator == ClauseOperator.REQUIRED
        assert result.clauses[0].names == ["api_key"]

    def test_parse_config_single_optional(self) -> None:
        result = parse_config("OPTIONAL(oauth)")
        assert result.none_required is False
        assert len(result.clauses) == 1
        assert result.clauses[0].operator == ClauseOperator.OPTIONAL
        assert result.clauses[0].names == ["oauth"]

    def test_parse_config_single_choice(self) -> None:
        result = parse_config("CHOICE(a, b)")
        assert result.none_required is False
        assert len(result.clauses) == 1
        assert result.clauses[0].operator == ClauseOperator.CHOICE
        assert result.clauses[0].names == ["a", "b"]

    def test_parse_config_multi_clause(self) -> None:
        result = parse_config("REQUIRED(a) + OPTIONAL(b)")
        assert result.none_required is False
        assert len(result.clauses) == 2
        assert result.clauses[0] == ConfigClause(
            operator=ClauseOperator.REQUIRED, names=["a"]
        )
        assert result.clauses[1] == ConfigClause(
            operator=ClauseOperator.OPTIONAL, names=["b"]
        )

    def test_parse_config_whitespace_tolerance(self) -> None:
        # Extra spaces around +, commas, and parens.
        result = parse_config("  REQUIRED( api_key )  +  OPTIONAL( oauth ) ")
        assert len(result.clauses) == 2
        assert result.clauses[0].names == ["api_key"]
        assert result.clauses[1].names == ["oauth"]

    def test_parse_config_empty_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("")
        assert "config expression is empty" in exc_info.value.errors[0]

    def test_parse_config_whitespace_only_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("   ")
        assert "config expression is empty" in exc_info.value.errors[0]

    def test_parse_config_leading_plus_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("+ REQUIRED(a)")
        assert any(
            "starts with '+'" in e for e in exc_info.value.errors
        )

    def test_parse_config_trailing_plus_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("REQUIRED(a) +")
        assert any(
            "ends with '+'" in e for e in exc_info.value.errors
        )

    def test_parse_config_empty_operands_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("REQUIRED()")
        assert any(
            "no operands" in e for e in exc_info.value.errors
        )

    def test_parse_config_bad_keyword_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("FOO(a)")
        assert any(
            "malformed clause" in e for e in exc_info.value.errors
        )

    def test_parse_config_bad_operand_name_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("REQUIRED(123bad)")
        assert any(
            "not a valid identifier" in e for e in exc_info.value.errors
        )

    def test_parse_config_stray_comma_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("REQUIRED(a,,b)")
        assert any(
            "empty operand" in e for e in exc_info.value.errors
        )

    def test_parse_config_referenced_names(self) -> None:
        result = parse_config("REQUIRED(a) + CHOICE(b, c) + OPTIONAL(d)")
        assert result.referenced_names == ["a", "b", "c", "d"]

    def test_parse_config_referenced_names_with_duplicates(self) -> None:
        result = parse_config("REQUIRED(a) + OPTIONAL(a)")
        assert result.referenced_names == ["a", "a"]

    def test_parse_config_missing_parens_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("REQUIRED api_key")
        assert any(
            "malformed clause" in e for e in exc_info.value.errors
        )

    def test_parse_config_case_sensitive_keywords(self) -> None:
        # Lowercase keywords should fail.
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_config("required(a)")
        assert any(
            "malformed clause" in e for e in exc_info.value.errors
        )


# ---------------------------------------------------------------------------
# parse_auth_details() tests
# ---------------------------------------------------------------------------


class TestParseAuthDetails:
    def test_parse_auth_details_valid_simple(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "api_key",
                    "xsoar_param_map": {"api_key": "key"},
                }
            ],
            "config": "REQUIRED(api_key)",
            "other_connection": ["proxy", "url"],
        })
        assert isinstance(details, AuthDetails)
        assert len(details.auth_types) == 1
        assert details.auth_types[0].type == AuthType.APIKey
        assert details.auth_types[0].name == "api_key"
        assert details.auth_types[0].xsoar_param_map == {"api_key": "key"}
        assert details.auth_types[0].interpolated is False
        assert details.config.none_required is False
        assert len(details.config.clauses) == 1
        assert details.config.clauses[0].operator == ClauseOperator.REQUIRED
        assert details.other_connection == ["proxy", "url"]

    def test_parse_auth_details_valid_none_required(self) -> None:
        details = parse_auth_details({
            "auth_types": [],
            "config": "NoneRequired",
            "other_connection": [],
        })
        assert details.auth_types == []
        assert details.config.none_required is True
        assert details.other_connection == []

    def test_parse_auth_details_from_dict(self) -> None:
        data = {
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "config": "REQUIRED(x)",
            "other_connection": [],
        }
        details = parse_auth_details(data)
        assert details.auth_types[0].name == "x"

    def test_parse_auth_details_from_string(self) -> None:
        data = json.dumps({
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "config": "REQUIRED(x)",
            "other_connection": [],
        })
        details = parse_auth_details(data)
        assert details.auth_types[0].name == "x"

    def test_parse_auth_details_invalid_json_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details("not json")
        assert "Invalid JSON" in exc_info.value.message

    def test_parse_auth_details_not_dict_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details("[]")
        assert "Expected a JSON object" in exc_info.value.message

    def test_parse_auth_details_missing_keys_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({"auth_types": []})
        assert "Missing required keys" in exc_info.value.message
        assert "config" in exc_info.value.message

    def test_parse_auth_details_invalid_auth_type_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "INVALID", "name": "x",
                     "xsoar_param_map": {"p": "key"}}
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        assert any(
            "invalid type 'INVALID'" in e for e in exc_info.value.errors
        )

    def test_parse_auth_details_interpolated_default_false(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "config": "REQUIRED(x)",
            "other_connection": [],
        })
        assert details.auth_types[0].interpolated is False

    def test_parse_auth_details_interpolated_true(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "x",
                    "xsoar_param_map": {"p": "key"},
                    "interpolated": True,
                }
            ],
            "config": "REQUIRED(x)",
            "other_connection": [],
        })
        assert details.auth_types[0].interpolated is True

    def test_parse_auth_details_legacy_no_other_connection(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "config": "REQUIRED(x)",
        })
        assert details.other_connection is None

    def test_parse_auth_details_auth_types_not_list_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": "not a list",
                "config": "NoneRequired",
                "other_connection": [],
            })
        assert "'auth_types' must be a list" in exc_info.value.message

    def test_parse_auth_details_missing_name_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey",
                     "xsoar_param_map": {"p": "key"}}
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        assert any(
            "missing 'name'" in e for e in exc_info.value.errors
        )

    def test_parse_auth_details_all_auth_types_valid(self) -> None:
        for at in AuthType:
            if at == AuthType.NoneRequired:
                # NoneRequired requires empty auth_types.
                continue
            details = parse_auth_details({
                "auth_types": [
                    {"type": at.value, "name": "x",
                     "xsoar_param_map": {"p": "anyrole"}}
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
            assert details.auth_types[0].type == at

    def test_parse_auth_details_interpolated_non_bool_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_param_map": {"p": "key"},
                        "interpolated": "yes",
                    }
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        assert any(
            "'interpolated' must be a bool" in e
            for e in exc_info.value.errors
        )

    def test_parse_auth_details_other_connection_not_list_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [],
                "config": "NoneRequired",
                "other_connection": "url",
            })
        assert any(
            "'other_connection' must be a list" in e
            for e in exc_info.value.errors
        )

    # ---------------------------------------------------------------
    # NEW xsoar_param_map tests (plan §5.2)
    # ---------------------------------------------------------------

    def test_xsoar_param_map_parsed_for_apikey(self) -> None:
        """Happy path: APIKey entry with xsoar_param_map round-trips."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "credentials",
                    "xsoar_param_map": {"credentials.password": "key"},
                }
            ],
            "config": "REQUIRED(credentials)",
            "other_connection": ["insecure", "proxy", "url"],
        })
        assert details.auth_types[0].xsoar_param_map == {
            "credentials.password": "key"
        }

    def test_xsoar_param_map_parsed_for_plain(self) -> None:
        """Happy path: Plain entry with two-leaf xsoar_param_map."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "credentials",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                }
            ],
            "config": "REQUIRED(credentials)",
            "other_connection": [],
        })
        assert details.auth_types[0].xsoar_param_map == {
            "credentials.identifier": "username",
            "credentials.password": "password",
        }

    def test_legacy_xsoar_params_rejected_with_migration_hint(self) -> None:
        """Old-shape input is rejected; the error names the new key
        and points at the schema doc."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_params": ["api_key"],
                    }
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "legacy key 'xsoar_params' is no longer supported" in joined
        assert "xsoar_param_map" in joined
        assert "connectus/column-schemas.md" in joined
        # field path is named
        assert "auth_types[0].xsoar_params" in joined

    def test_legacy_xsoar_params_rejected_even_when_new_key_present(self) -> None:
        """When BOTH old and new keys are present, the legacy
        rejection still fires."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_params": ["p"],
                        "xsoar_param_map": {"p": "key"},
                    }
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "legacy key 'xsoar_params' is no longer supported" in joined

    def test_missing_xsoar_param_map_rejected(self) -> None:
        """Entry without the new key is rejected."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey", "name": "x"}
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "missing 'xsoar_param_map'" in joined
        assert "auth_types[0].xsoar_param_map" in joined

    @pytest.mark.parametrize(
        "bad_value",
        [
            ["api_key"],          # list (old shape value)
            "api_key",            # string
            None,                 # null
            42,                   # int
        ],
    )
    def test_xsoar_param_map_must_be_dict(self, bad_value: object) -> None:
        """List/string/null/int inputs for xsoar_param_map are rejected."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_param_map": bad_value,
                    }
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "xsoar_param_map" in joined
        assert "must be an object" in joined or "must be a dict" in joined

    def test_empty_xsoar_param_map_rejected_in_parser(self) -> None:
        """Empty dict is rejected at parse time."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey", "name": "x",
                     "xsoar_param_map": {}}
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "xsoar_param_map" in joined
        assert "non-empty" in joined or "at least one" in joined

    def test_xsoar_param_map_value_non_string_rejected(self) -> None:
        """Non-string values rejected at parse time."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_param_map": {"p": 42},
                    }
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "xsoar_param_map" in joined
        assert "must be a string" in joined or "non-empty string" in joined

    def test_xsoar_param_map_value_empty_string_rejected(self) -> None:
        """Empty-string values rejected at parse time."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_param_map": {"p": ""},
                    }
                ],
                "config": "REQUIRED(x)",
                "other_connection": [],
            })
        joined = "\n".join(exc_info.value.errors)
        assert "xsoar_param_map" in joined
        assert "non-empty string" in joined
