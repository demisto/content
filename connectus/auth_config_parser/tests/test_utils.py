"""Tests for auth_config_parser.utils — utility functions."""
from __future__ import annotations

import pytest

from auth_config_parser import (
    AuthDetails,
    AuthEntry,
    AuthType,
    ClauseOperator,
    ConfigClause,
    ConfigExpression,
    auth_param_ids,
    auth_param_ids_with_sources,
    parse_auth_details,
    project_xsoar_param_to_yml_id,
)


# ---------------------------------------------------------------------------
# project_xsoar_param_to_yml_id() tests
# ---------------------------------------------------------------------------


class TestProjectXsoarParamToYmlId:
    def test_project_bare_id(self) -> None:
        assert project_xsoar_param_to_yml_id("api_key") == "api_key"

    def test_project_dotted_identifier(self) -> None:
        assert project_xsoar_param_to_yml_id("credentials.identifier") == "credentials"

    def test_project_dotted_password(self) -> None:
        assert project_xsoar_param_to_yml_id("credentials.password") == "credentials"

    def test_project_empty_string(self) -> None:
        assert project_xsoar_param_to_yml_id("") == ""

    def test_project_non_string(self) -> None:
        # Non-string input should return empty string.
        assert project_xsoar_param_to_yml_id(42) == ""  # type: ignore[arg-type]
        assert project_xsoar_param_to_yml_id(None) == ""  # type: ignore[arg-type]

    def test_project_multi_dot(self) -> None:
        # Only the first dot matters.
        assert project_xsoar_param_to_yml_id("a.b.c") == "a"


# ---------------------------------------------------------------------------
# auth_param_ids() tests
# ---------------------------------------------------------------------------


class TestAuthParamIds:
    def test_auth_param_ids_mixed(self) -> None:
        """APIKey + Plain + other_connection → correct union."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "api_key",
                    "xsoar_param_map": {"api_key": "key"},
                },
                {
                    "type": "Plain",
                    "name": "credentials",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                },
            ],
            "config": "REQUIRED(api_key) + REQUIRED(credentials)",
            "other_connection": ["insecure", "proxy", "url"],
        })
        result = auth_param_ids(details)
        assert result == {"api_key", "credentials", "insecure", "proxy", "url"}

    def test_auth_param_ids_deduped(self) -> None:
        """Dotted forms collapsing to same id → single entry."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "creds",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                }
            ],
            "config": "REQUIRED(creds)",
            "other_connection": [],
        })
        result = auth_param_ids(details)
        assert result == {"credentials"}
        assert "credentials.identifier" not in result
        assert "credentials.password" not in result

    def test_auth_param_ids_none_required(self) -> None:
        """NoneRequired + other_connection → only other_connection."""
        details = parse_auth_details({
            "auth_types": [],
            "config": "NoneRequired",
            "other_connection": ["host", "port"],
        })
        result = auth_param_ids(details)
        assert result == {"host", "port"}

    def test_auth_param_ids_no_other_connection(self) -> None:
        """Legacy None → only auth_types ids."""
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_param_map": {"api_key": "key"}}
            ],
            "config": "REQUIRED(api_key)",
        })
        assert details.other_connection is None
        result = auth_param_ids(details)
        assert result == {"api_key"}

    def test_auth_param_ids_empty(self) -> None:
        """NoneRequired + no other_connection → empty set."""
        details = parse_auth_details({
            "auth_types": [],
            "config": "NoneRequired",
            "other_connection": [],
        })
        result = auth_param_ids(details)
        assert result == set()

    def test_auth_param_ids_sorted_output(self) -> None:
        """Callers that need sorted output can call sorted()."""
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_param_map": {"api_key": "key"}},
                {
                    "type": "Plain",
                    "name": "credentials",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                },
            ],
            "config": "REQUIRED(api_key) + REQUIRED(credentials)",
            "other_connection": ["insecure", "proxy", "url"],
        })
        result = sorted(auth_param_ids(details))
        assert result == ["api_key", "credentials", "insecure", "proxy", "url"]

    def test_auth_param_ids_returns_map_keys_sorted(self) -> None:
        """The set produced by auth_param_ids() is the set of projected
        map keys; ``sorted()`` returns them lex-sorted. The descriptor
        consumer (workflow_state.api) explicitly sorts before display."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "creds",
                    "xsoar_param_map": {
                        "zeta_user": "username",
                        "alpha_pass": "password",
                    },
                }
            ],
            "config": "REQUIRED(creds)",
            "other_connection": [],
        })
        # Both projected ids should be present; sorting yields the
        # stable lex order.
        result = sorted(auth_param_ids(details))
        assert result == ["alpha_pass", "zeta_user"]


# ---------------------------------------------------------------------------
# auth_param_ids_with_sources() tests
# ---------------------------------------------------------------------------


class TestAuthParamIdsWithSources:
    def test_auth_param_ids_with_sources_mixed(self) -> None:
        """Correct source descriptors for each param."""
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_param_map": {"api_key": "key"}},
                {
                    "type": "Plain",
                    "name": "credentials",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                },
            ],
            "config": "REQUIRED(api_key) + REQUIRED(credentials)",
            "other_connection": ["url"],
        })
        sources = auth_param_ids_with_sources(details)

        # api_key comes from auth_types entry.
        assert "api_key" in sources
        assert len(sources["api_key"]) == 1
        assert "auth_types[].name='api_key'" in sources["api_key"][0]
        assert "xsoar_param_map=" in sources["api_key"][0]
        assert "'api_key': 'key'" in sources["api_key"][0]

        # credentials comes from dotted forms.
        assert "credentials" in sources
        assert len(sources["credentials"]) == 1
        assert "auth_types[].name='credentials'" in sources["credentials"][0]
        assert "credentials.identifier" in sources["credentials"][0]
        assert "credentials.password" in sources["credentials"][0]
        assert "xsoar_param_map=" in sources["credentials"][0]

        # url comes from other_connection.
        assert "url" in sources
        assert sources["url"] == ["other_connection"]

    def test_auth_param_ids_with_sources_dotted_dedup(self) -> None:
        """Two dotted forms → one descriptor per entry."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "creds",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                }
            ],
            "config": "REQUIRED(creds)",
            "other_connection": [],
        })
        sources = auth_param_ids_with_sources(details)
        # Both dotted forms collapse to "credentials" — only one descriptor.
        assert "credentials" in sources
        assert len(sources["credentials"]) == 1

    def test_auth_param_ids_with_sources_other_connection(self) -> None:
        """other_connection items → 'other_connection' source."""
        details = parse_auth_details({
            "auth_types": [],
            "config": "NoneRequired",
            "other_connection": ["proxy", "url"],
        })
        sources = auth_param_ids_with_sources(details)
        assert sources["proxy"] == ["other_connection"]
        assert sources["url"] == ["other_connection"]

    def test_auth_param_ids_with_sources_no_other_connection(self) -> None:
        """Legacy None other_connection → only auth_types sources."""
        details = parse_auth_details({
            "auth_types": [
                {"type": "APIKey", "name": "api_key",
                 "xsoar_param_map": {"api_key": "key"}}
            ],
            "config": "REQUIRED(api_key)",
        })
        sources = auth_param_ids_with_sources(details)
        assert "api_key" in sources
        assert len(sources) == 1

    def test_auth_param_ids_with_sources_multiple_entries_same_yml_id(self) -> None:
        """Multiple auth_types entries projecting to the same YML id."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "Plain",
                    "name": "creds_a",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                },
                {
                    "type": "Plain",
                    "name": "creds_b",
                    "xsoar_param_map": {
                        "credentials.identifier": "username",
                        "credentials.password": "password",
                    },
                },
            ],
            "config": "CHOICE(creds_a, creds_b)",
            "other_connection": [],
        })
        sources = auth_param_ids_with_sources(details)
        # "credentials" should have two descriptors — one per entry.
        assert "credentials" in sources
        assert len(sources["credentials"]) == 2
        assert any("creds_a" in d for d in sources["credentials"])
        assert any("creds_b" in d for d in sources["credentials"])

    def test_auth_param_ids_with_sources_descriptor_shape(self) -> None:
        """Descriptor quotes the new field name verbatim and includes
        the full map (keys + role values) inline so the cross-check
        rejection messages can show the operator both sides."""
        details = parse_auth_details({
            "auth_types": [
                {
                    "type": "APIKey",
                    "name": "credentials",
                    "xsoar_param_map": {"credentials.password": "key"},
                }
            ],
            "config": "REQUIRED(credentials)",
            "other_connection": [],
        })
        sources = auth_param_ids_with_sources(details)
        assert "credentials" in sources
        descriptor = sources["credentials"][0]
        # New-shape field name (not legacy ``xsoar_params=``).
        assert "xsoar_param_map={" in descriptor
        assert "xsoar_params=" not in descriptor
        # The full map (keys + role values) is quoted verbatim.
        assert "'credentials.password': 'key'" in descriptor
        # The entry-level name is also quoted.
        assert "auth_types[].name='credentials'" in descriptor
