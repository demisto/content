"""Tests for auth_config_parser.parser — parse_auth_details()."""
from __future__ import annotations

import json

import pytest

from auth_config_parser import (
    AuthConfigParseError,
    AuthDetails,
    AuthEntry,
    AuthType,
    parse_auth_details,
)


# ---------------------------------------------------------------------------
# parse_auth_details() — happy paths
# ---------------------------------------------------------------------------


class TestParseAuthDetails:
    def test_parse_valid_simple(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "api_key",
                    "xsoar_param_map": {"api_key": "key"},
                }
            ],
            "other_connection": ["proxy", "url"],
        })
        assert isinstance(details, AuthDetails)
        assert len(details.auth_types) == 1
        assert details.auth_types[0].type == AuthType.APIKey
        assert details.auth_types[0].name == "api_key"
        assert details.auth_types[0].xsoar_param_map == {"api_key": "key"}
        assert details.auth_types[0].interpolated is False
        assert details.other_connection == ["proxy", "url"]

    def test_parse_none_required_via_empty_auth_types(self) -> None:
        """The 2026-05 model: empty auth_types = no auth required."""
        details = parse_auth_details({
            "auth_types": [],
            "other_connection": [],
        })
        assert details.auth_types == []
        assert details.is_none_required is True
        assert details.requires_choice is False

    def test_parse_choice_two_profiles(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "a",
                 "xsoar_param_map": {"a": "key"}},
                {"type": "APIKey", "name": "b",
                 "xsoar_param_map": {"b": "key"}},
            ],
            "other_connection": [],
        })
        assert details.requires_choice is True
        assert details.is_none_required is False
        assert details.auth_type_names == {"a", "b"}

    def test_parse_from_dict(self) -> None:
        data = {
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "other_connection": [],
        }
        details = parse_auth_details(data)
        assert details.auth_types[0].name == "x"

    def test_parse_from_string(self) -> None:
        data = json.dumps({
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "other_connection": [],
        })
        details = parse_auth_details(data)
        assert details.auth_types[0].name == "x"

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details("not json")
        assert "Invalid JSON" in exc_info.value.message

    def test_parse_not_dict_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details("[]")
        assert "Expected a JSON object" in exc_info.value.message

    def test_parse_missing_auth_types_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({})
        assert "Missing required key" in exc_info.value.message
        assert "auth_types" in exc_info.value.message

    def test_parse_invalid_auth_type_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "INVALID", "name": "x",
                     "xsoar_param_map": {"p": "key"}}
                ],
            })
        assert any(
            "invalid type 'INVALID'" in e for e in exc_info.value.errors
        )

    def test_parse_interpolated_default_false(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "other_connection": [],
        })
        assert details.auth_types[0].interpolated is False

    def test_parse_interpolated_true(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "x",
                    "xsoar_param_map": {"p": "key"},
                    "interpolated": True,
                }
            ],
            "other_connection": [],
        })
        assert details.auth_types[0].interpolated is True

    def test_parse_missing_other_connection_raises(self) -> None:
        """``other_connection`` is required; absence raises."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey", "name": "x",
                     "xsoar_param_map": {"p": "key"}}
                ],
            })
        assert "other_connection" in exc_info.value.message

    def test_parse_auth_types_not_list_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": "not a list",
            })
        assert "'auth_types' must be a list" in exc_info.value.message

    def test_parse_missing_name_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey",
                     "xsoar_param_map": {"p": "key"}}
                ],
            })
        assert any(
            "missing 'name'" in e for e in exc_info.value.errors
        )

    def test_parse_all_auth_types_valid(self) -> None:
        for at in AuthType:
            if at == AuthType.NoneRequired:
                # NoneRequired requires empty auth_types.
                continue
            details = parse_auth_details({
                "auth_types": [
                    {"type": at.value, "name": "x",
                     "xsoar_param_map": {"p": "anyrole"}}
                ],
                "other_connection": [],
            })
            assert details.auth_types[0].type == at

    def test_parse_interpolated_non_bool_raises(self) -> None:
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
            })
        assert any(
            "'interpolated' must be a bool" in e
            for e in exc_info.value.errors
        )

    # --- verify_connection_skip (optional, defaults to False) ---

    def test_parse_verify_connection_skip_default_false(self) -> None:
        """Absence of the key → ``verify_connection_skip`` is False."""
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "x",
                 "xsoar_param_map": {"p": "key"}}
            ],
            "other_connection": [],
        })
        assert details.auth_types[0].verify_connection_skip is False

    def test_parse_verify_connection_skip_true(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "x",
                    "xsoar_param_map": {"p": "key"},
                    "verify_connection_skip": True,
                }
            ],
            "other_connection": [],
        })
        assert details.auth_types[0].verify_connection_skip is True

    def test_parse_verify_connection_skip_false_explicit(self) -> None:
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "x",
                    "xsoar_param_map": {"p": "key"},
                    "verify_connection_skip": False,
                }
            ],
            "other_connection": [],
        })
        assert details.auth_types[0].verify_connection_skip is False

    def test_parse_verify_connection_skip_round_trip_per_profile(self) -> None:
        """Multi-profile (exclusive-OR) row: one profile may set
        ``verify_connection_skip: true`` while a sibling profile leaves
        it at the default."""
        details = parse_auth_details({
            "auth_types": [
                {"type": "OAuth2ClientCreds", "name": "client_creds",
                 "xsoar_param_map": {"credentials.identifier": "client_id",
                                     "credentials.password": "client_secret"},
                 "interpolated": True},
                {"type": "Passthrough", "name": "auth_code",
                 "xsoar_param_map": {"auth_code": "authorization_code"},
                 "interpolated": True,
                 "verify_connection_skip": True},
            ],
            "other_connection": [],
        })
        # Sorted by (type, name): OAuth2ClientCreds < Passthrough.
        assert details.auth_types[0].name == "client_creds"
        assert details.auth_types[0].verify_connection_skip is False
        assert details.auth_types[1].name == "auth_code"
        assert details.auth_types[1].verify_connection_skip is True

    @pytest.mark.parametrize(
        "bad_value",
        ["true", "false", 1, 0, None, [], {}],
    )
    def test_parse_verify_connection_skip_non_bool_raises(
        self, bad_value: object,
    ) -> None:
        """Strings, ints, null, list, dict are all rejected — must be a JSON bool."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {
                        "type": "APIKey",
                        "name": "x",
                        "xsoar_param_map": {"p": "key"},
                        "verify_connection_skip": bad_value,
                    }
                ],
            })
        assert any(
            "'verify_connection_skip' must be a bool" in e
            for e in exc_info.value.errors
        )

    def test_parse_other_connection_not_list_raises(self) -> None:
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [],
                "other_connection": "url",
            })
        assert any(
            "'other_connection' must be a list" in e
            for e in exc_info.value.errors
        )


# ---------------------------------------------------------------------------
# xsoar_param_map structural tests
# ---------------------------------------------------------------------------


class TestXsoarParamMap:
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
            "other_connection": [],
        })
        assert details.auth_types[0].xsoar_param_map == {
            "credentials.identifier": "username",
            "credentials.password": "password",
        }

    def test_missing_xsoar_param_map_rejected(self) -> None:
        """Entry without the new key is rejected."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey", "name": "x"}
                ],
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
            })
        joined = "\n".join(exc_info.value.errors)
        assert "xsoar_param_map" in joined
        assert "must be an object" in joined or "must be a dict" in joined

    def test_empty_xsoar_param_map_rejected(self) -> None:
        """Empty dict is rejected at parse time."""
        with pytest.raises(AuthConfigParseError) as exc_info:
            parse_auth_details({
                "auth_types": [
                    {"type": "APIKey", "name": "x",
                     "xsoar_param_map": {}}
                ],
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
            })
        joined = "\n".join(exc_info.value.errors)
        assert "xsoar_param_map" in joined
        assert "non-empty string" in joined
