"""NodeZero Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests for the NodeZero Integration.

More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import re
import string

import demistomock as demisto
import pytest
import requests
from pydantic_core import ValidationError
from unittest.mock import MagicMock, patch

from datetime import datetime, UTC

import NodeZero
from NodeZero import (
    Client,
    HELLO_WORLD_QUERY,
    WEAKNESSES_PAGE_QUERY,
    build_user_agent,
    Params,
    Weakness,
    LastRun,
    GetWeaknessesArgs,
    _test_module,
    fetch_incidents,
    fetch_all_weaknesses_pages,
    get_weaknesses_command,
    authenticate,
    dedup_by_ids,
    UnauthenticatedError,
    ResponseValidationError,
    DEFAULT_MAX_FETCH,
    DEFAULT_FIRST_FETCH,
)


# Test data fixtures
SAMPLE_WEAKNESS = {
    "uuid": "test-uuid-123",
    "created_at": "2024-01-15T10:30:00",
    "vuln_id": "CVE-2024-1234",
    "vuln_name": "Test Vulnerability Name",
    "vuln_short_name": "Test Vuln",
    "vuln_category": "Credential Access",
    "vuln_cisa_kev": True,
    "vuln_known_ransomware_campaign_use": False,
    "ip": "192.168.1.100",
    "has_proof": True,
    "score": 9.5,
    "severity": "CRITICAL",
    "affected_asset_uuid": "asset-uuid-456",
    "affected_asset_display_name": "test-server-01",
    "attack_paths_count": 3,
    "op_id": "op-123",
}

SAMPLE_PAGE_INFO = {
    "page_num": 1,
    "page_size": 100,
}

SAMPLE_WEAKNESSES_PAGE_RESPONSE = {
    "data": {
        "weaknesses_page": {
            "weaknesses": [SAMPLE_WEAKNESS],
            "page_info": SAMPLE_PAGE_INFO,
        }
    }
}

SAMPLE_AUTH_RESPONSE = {"token": "test-jwt-token-123"}

SAMPLE_HELLO_RESPONSE = {"data": {"hello": "world"}}


def create_test_client(base_url: str = "https://test.horizon3ai.com") -> Client:
    """Create a test client instance."""
    return Client(
        base_url=base_url,
        api_key="test-api-key",
        verify=False,
        proxy=False,
    )


class TestWeaknessModel:
    """Tests for the Weakness Pydantic model."""

    def test_weakness_parsing(self):
        """Test that a weakness is correctly parsed from API response."""
        weakness = Weakness.model_validate(SAMPLE_WEAKNESS)

        assert weakness.uuid == "test-uuid-123"
        assert weakness.severity == "CRITICAL"
        assert weakness.has_proof is True
        assert weakness.attack_paths_count == 3

    def test_weakness_to_incident(self):
        """Test that a weakness is correctly converted to an XSOAR incident."""
        weakness = Weakness.model_validate(SAMPLE_WEAKNESS)
        incident = weakness.to_incident()

        assert incident["name"] == "Test Vuln on test-server-01"
        assert incident["occurred"] == "2024-01-15T10:30:00Z"
        assert incident["dbotMirrorId"] == "test-uuid-123"
        assert "rawJSON" in incident

    def test_weakness_to_incident_with_missing_optional_fields(self):
        """Test incident conversion when optional fields are None."""
        weakness_data = {
            "uuid": "test-uuid",
            "created_at": "2024-01-15T10:30:00",
            "vuln_id": "CVE-2024-0001",
            "vuln_name": None,
            "vuln_short_name": None,
            "vuln_category": None,
            "vuln_cisa_kev": None,
            "vuln_known_ransomware_campaign_use": None,
            "ip": None,
            "has_proof": None,
            "score": None,
            "severity": None,
            "affected_asset_uuid": None,
            "affected_asset_display_name": None,
            "attack_paths_count": 0,
            "op_id": None,
        }
        weakness = Weakness.model_validate(weakness_data)
        incident = weakness.to_incident()

        # Should fall back to vuln_id when vuln_short_name and vuln_name are None
        assert incident["name"] == "CVE-2024-0001 on Unknown Asset"


class TestParamsModel:
    """Tests for the Params Pydantic model."""

    def test_params_parsing_with_defaults(self):
        """Test that params are parsed with default values."""
        params_data = {
            "url": "https://portal.horizon3ai.com",
            "credentials": {"password": "test-key"},
        }
        params = Params.model_validate(params_data)

        assert params.url == "https://portal.horizon3ai.com"
        assert params.credentials.password == "test-key"
        assert params.insecure is False
        assert params.proxy is False
        assert params.max_fetch == DEFAULT_MAX_FETCH
        assert params.first_fetch == DEFAULT_FIRST_FETCH

    def test_params_parsing_with_custom_values(self):
        """Test that params are parsed with custom values."""
        params_data = {
            "url": "https://custom.horizon3ai.com",
            "credentials": {"password": "custom-key"},
            "insecure": True,
            "proxy": True,
            "max_fetch": 50,
            "first_fetch": "14 days",
        }
        params = Params.model_validate(params_data)

        assert params.max_fetch == 50
        assert params.first_fetch == "14 days"
        assert params.insecure is True


class TestClientAuthentication:
    """Tests for Client authentication functionality."""

    def test_load_integration_context_restores_token(self):
        """Test that client loads JWT and expiry from integration context."""
        import time

        stored_jwt = "stored-jwt-token"
        stored_expiry = int(time.time()) + 3600

        with patch("NodeZero.get_integration_context") as mock_get_context:
            mock_get_context.return_value = {"jwt": stored_jwt, "expiry": stored_expiry}
            client = create_test_client()

        assert client._jwt == stored_jwt
        assert client._expiry == stored_expiry
        assert client.is_authenticated() is True

    def test_load_integration_context_handles_empty_context(self):
        """Test that client handles empty integration context."""
        with patch("NodeZero.get_integration_context") as mock_get_context:
            mock_get_context.return_value = {}
            client = create_test_client()

        assert client._jwt is None
        assert client._expiry == 0
        assert client.is_authenticated() is False

    def test_is_authenticated_when_no_token(self):
        """Test is_authenticated returns False when no token exists."""
        client = create_test_client()
        client._jwt = None
        client._expiry = 0

        assert client.is_authenticated() is False

    def test_is_authenticated_when_token_expired(self):
        """Test is_authenticated returns False when token is expired."""
        client = create_test_client()
        client._jwt = "some-token"
        client._expiry = 0  # Expired

        assert client.is_authenticated() is False

    def test_is_authenticated_when_valid_token(self):
        """Test is_authenticated returns True when token is valid."""
        import time

        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = int(time.time()) + 3600  # 1 hour from now

        assert client.is_authenticated() is True

    def test_authenticate_success(self, requests_mock):
        """Test successful authentication."""
        client = create_test_client()
        requests_mock.post(
            "https://test.horizon3ai.com/v1/auth",
            json=SAMPLE_AUTH_RESPONSE,
        )

        with patch("NodeZero.set_integration_context"):
            client.authenticate()

        assert client._jwt == "test-jwt-token-123"
        assert client._expiry > 0

    def test_authenticate_401_error(self, requests_mock):
        """Test authentication fails with 401."""
        client = create_test_client()
        requests_mock.post(
            "https://test.horizon3ai.com/v1/auth",
            status_code=401,
        )

        with pytest.raises(UnauthenticatedError):
            client.authenticate()


class TestClientGraphQL:
    """Tests for Client GraphQL functionality."""

    def test_hello_world_success(self, requests_mock):
        """Test hello_world query succeeds."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_HELLO_RESPONSE,
        )

        # Should not raise
        client.hello_world()

    def test_graphql_401_error(self, requests_mock):
        """Test GraphQL request fails with 401."""
        client = create_test_client()
        client._jwt = "invalid-token"
        client._expiry = 9999999999

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            status_code=401,
        )

        with pytest.raises(UnauthenticatedError):
            client.hello_world()

    def test_query_weaknesses_page_invalid_response(self, requests_mock):
        """Test that invalid API response raises ResponseValidationError."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        # Missing required fields in the response
        invalid_response = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [{"uuid": "test-uuid"}],  # Missing required fields
                    "page_info": {
                        "page_num": 1,
                        "page_size": 100,
                    },
                }
            }
        }

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=invalid_response,
        )

        with pytest.raises(ResponseValidationError):
            client.query_weaknesses_page(page_num=1, page_size=100, since_date="2024-01-01")


class TestTestModule:
    """Tests for the test_module command."""

    def test_test_module_success(self, requests_mock):
        """Test test_module succeeds with valid credentials."""
        client = create_test_client()

        requests_mock.post(
            "https://test.horizon3ai.com/v1/auth",
            json=SAMPLE_AUTH_RESPONSE,
        )
        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_HELLO_RESPONSE,
        )

        with patch("NodeZero.set_integration_context"):
            result = _test_module(client)

        assert result == "ok"


class TestFetchIncidents:
    """Tests for the fetch_incidents command."""

    @patch("NodeZero.demisto")
    def test_fetch_incidents_first_run(self, mock_demisto, requests_mock):
        """Test fetch_incidents on first run (no last_run state)."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        mock_demisto.getLastRun.return_value = {}

        # Mock the weaknesses page response
        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        first_fetch_time = datetime(2024, 1, 8, 0, 0, 0, tzinfo=UTC)
        incidents, next_run = fetch_incidents(client, max_fetch=100, first_fetch_time=first_fetch_time)

        assert len(incidents) == 1
        assert incidents[0]["name"] == "Test Vuln on test-server-01"
        # Verify deduplication state is set
        assert next_run.last_fetch_date == "2024-01-15T10:30:00"
        assert next_run.last_ids == ["test-uuid-123"]

    @patch("NodeZero.demisto")
    def test_fetch_incidents_subsequent_run(self, mock_demisto, requests_mock):
        """Test fetch_incidents with existing last_run state."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        mock_demisto.getLastRun.return_value = {"last_fetch_date": "2024-01-10T00:00:00", "last_ids": []}

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        first_fetch_time = datetime(2024, 1, 8, 0, 0, 0, tzinfo=UTC)
        incidents, next_run = fetch_incidents(client, max_fetch=100, first_fetch_time=first_fetch_time)

        assert len(incidents) == 1
        assert next_run.last_fetch_date == "2024-01-15T10:30:00"
        assert next_run.last_ids == ["test-uuid-123"]

    @patch("NodeZero.demisto")
    def test_fetch_incidents_deduplicates_by_id(self, mock_demisto, requests_mock):
        """Test fetch_incidents filters out previously fetched incidents."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        # Simulate a previous run that already fetched this weakness
        mock_demisto.getLastRun.return_value = {
            "last_fetch_date": "2024-01-15T10:30:00",
            "last_ids": ["test-uuid-123"],
        }

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        first_fetch_time = datetime(2024, 1, 8, 0, 0, 0, tzinfo=UTC)
        incidents, next_run = fetch_incidents(client, max_fetch=100, first_fetch_time=first_fetch_time)

        # Should return no incidents since the only one was already fetched
        assert len(incidents) == 0
        # Timestamp should advance by 1s to prevent infinite loop; last_ids cleared
        assert next_run.last_fetch_date == "2024-01-15T10:30:01"
        assert next_run.last_ids == []

    @patch("NodeZero.demisto")
    def test_fetch_incidents_tracks_ids_at_same_timestamp(self, mock_demisto, requests_mock):
        """Test that last_ids includes all UUIDs at the latest timestamp."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        mock_demisto.getLastRun.return_value = {}

        # Create response with multiple weaknesses at same timestamp
        same_timestamp = "2024-01-15T10:30:00"
        multi_weakness_response = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [
                        {**SAMPLE_WEAKNESS, "uuid": "uuid-1", "created_at": same_timestamp},
                        {**SAMPLE_WEAKNESS, "uuid": "uuid-2", "created_at": same_timestamp},
                        {**SAMPLE_WEAKNESS, "uuid": "uuid-3", "created_at": "2024-01-14T10:30:00"},  # older
                    ],
                    "page_info": SAMPLE_PAGE_INFO,
                }
            }
        }

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=multi_weakness_response,
        )

        first_fetch_time = datetime(2024, 1, 8, 0, 0, 0, tzinfo=UTC)
        incidents, next_run = fetch_incidents(client, max_fetch=100, first_fetch_time=first_fetch_time)

        assert len(incidents) == 3
        # Only IDs at the latest timestamp should be in last_ids
        assert next_run.last_fetch_date == same_timestamp
        assert set(next_run.last_ids) == {"uuid-1", "uuid-2"}


class TestFetchAllWeaknessesPages:
    """Tests for pagination in fetch_all_weaknesses_pages."""

    def test_fetch_single_page(self, requests_mock):
        """Test fetching a single page of weaknesses."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        weaknesses = fetch_all_weaknesses_pages(client, since_date="2024-01-01T00:00:00", max_fetch=100)

        assert len(weaknesses) == 1
        assert weaknesses[0].uuid == "test-uuid-123"

    def test_fetch_respects_max_fetch(self, requests_mock):
        """Test that max_fetch limits the number of results."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        # Create response with multiple weaknesses
        multi_weakness_response = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [{**SAMPLE_WEAKNESS, "uuid": f"uuid-{i}"} for i in range(10)],
                    "page_info": {
                        "page_num": 1,
                        "page_size": 100,
                    },
                }
            }
        }

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=multi_weakness_response,
        )

        weaknesses = fetch_all_weaknesses_pages(client, since_date="2024-01-01T00:00:00", max_fetch=5)

        assert len(weaknesses) == 5

    def test_fetch_multiple_pages(self, requests_mock):
        """Test fetching multiple pages when first page is full."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        # First page returns exactly page_size (100) items, triggering next page fetch
        page1_response = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [{**SAMPLE_WEAKNESS, "uuid": f"page1-uuid-{i}"} for i in range(100)],
                    "page_info": {
                        "page_num": 1,
                        "page_size": 100,
                    },
                }
            }
        }

        # Second page returns fewer than page_size, indicating last page
        page2_response = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [{**SAMPLE_WEAKNESS, "uuid": f"page2-uuid-{i}"} for i in range(50)],
                    "page_info": {
                        "page_num": 2,
                        "page_size": 100,
                    },
                }
            }
        }

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            [{"json": page1_response}, {"json": page2_response}],
        )

        weaknesses = fetch_all_weaknesses_pages(client, since_date="2024-01-01T00:00:00", max_fetch=200)

        assert len(weaknesses) == 150
        # Verify we got items from both pages
        assert weaknesses[0].uuid == "page1-uuid-0"
        assert weaknesses[100].uuid == "page2-uuid-0"


class TestLastRunModel:
    """Tests for the LastRun state model."""

    def test_last_run_with_date(self):
        """Test LastRun model with a date value."""
        last_run = LastRun(last_fetch_date="2024-01-15T10:30:00")
        assert last_run.last_fetch_date == "2024-01-15T10:30:00"
        assert last_run.last_ids == []

    def test_last_run_with_ids(self):
        """Test LastRun model with last_ids."""
        last_run = LastRun(last_fetch_date="2024-01-15T10:30:00", last_ids=["uuid-1", "uuid-2"])
        assert last_run.last_fetch_date == "2024-01-15T10:30:00"
        assert last_run.last_ids == ["uuid-1", "uuid-2"]

    def test_last_run_empty(self):
        """Test LastRun model with no date (first run)."""
        last_run = LastRun.model_validate({})
        assert last_run.last_fetch_date is None
        assert last_run.last_ids == []


class TestDedupByIds:
    """Tests for the dedup_by_ids helper function."""

    def test_dedup_filters_matching_ids(self):
        """Test that weaknesses with matching IDs are filtered out."""
        weaknesses = [
            Weakness.model_validate({**SAMPLE_WEAKNESS, "uuid": "uuid-1"}),
            Weakness.model_validate({**SAMPLE_WEAKNESS, "uuid": "uuid-2"}),
            Weakness.model_validate({**SAMPLE_WEAKNESS, "uuid": "uuid-3"}),
        ]

        result = dedup_by_ids(weaknesses, ["uuid-1", "uuid-3"])

        assert len(result) == 1
        assert result[0].uuid == "uuid-2"

    def test_dedup_empty_skip_list(self):
        """Test that empty skip list returns all weaknesses."""
        weaknesses = [
            Weakness.model_validate({**SAMPLE_WEAKNESS, "uuid": "uuid-1"}),
            Weakness.model_validate({**SAMPLE_WEAKNESS, "uuid": "uuid-2"}),
        ]

        result = dedup_by_ids(weaknesses, [])

        assert len(result) == 2

    def test_dedup_all_filtered(self):
        """Test that all weaknesses can be filtered out."""
        weaknesses = [
            Weakness.model_validate({**SAMPLE_WEAKNESS, "uuid": "uuid-1"}),
        ]

        result = dedup_by_ids(weaknesses, ["uuid-1"])

        assert len(result) == 0

    def test_dedup_empty_weaknesses(self):
        """Test with empty weaknesses list."""
        result = dedup_by_ids([], ["uuid-1", "uuid-2"])

        assert len(result) == 0


class TestAuthenticateHelper:
    """Tests for the authenticate helper function."""

    def test_authenticate_when_not_authenticated(self, requests_mock):
        """Test authenticate() calls client.authenticate() when not authenticated."""
        client = create_test_client()
        client._jwt = None
        client._expiry = 0

        requests_mock.post(
            "https://test.horizon3ai.com/v1/auth",
            json=SAMPLE_AUTH_RESPONSE,
        )

        with patch("NodeZero.set_integration_context"):
            authenticate(client)

        assert client._jwt == "test-jwt-token-123"

    def test_authenticate_skips_when_authenticated(self):
        """Test authenticate() skips auth when already authenticated."""
        import time

        client = create_test_client()
        client._jwt = "existing-token"
        client._expiry = int(time.time()) + 3600

        # Should not make any requests
        authenticate(client)

        assert client._jwt == "existing-token"


class TestGetWeaknessesCommand:
    """Tests for the nodezero-get-weaknesses command."""

    def test_get_weaknesses_returns_results(self, requests_mock):
        """Test that the command returns weaknesses as CommandResults."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        args = GetWeaknessesArgs(since_date="2024-01-01T00:00:00", limit=10)
        result = get_weaknesses_command(client, args)

        assert result.outputs_prefix == "NodeZero.Weakness"
        assert result.outputs_key_field == "uuid"
        assert len(result.outputs) == 1
        assert result.outputs[0]["uuid"] == "test-uuid-123"
        assert "NodeZero Weaknesses" in result.readable_output

    def test_get_weaknesses_default_args(self, requests_mock):
        """Test that the command works with default arguments."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        result = get_weaknesses_command(client, GetWeaknessesArgs())

        assert result.outputs_prefix == "NodeZero.Weakness"
        assert len(result.outputs) == 1

    def test_get_weaknesses_empty_results(self, requests_mock):
        """Test that the command handles empty results."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        empty_response = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [],
                    "page_info": {"page_num": 1, "page_size": 50},
                }
            }
        }
        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=empty_response,
        )

        args = GetWeaknessesArgs(since_date="2024-01-01T00:00:00")
        result = get_weaknesses_command(client, args)

        assert result.outputs == []

    def test_get_weaknesses_limit_capped(self, requests_mock):
        """Test that limit is capped at 1000."""
        client = create_test_client()
        client._jwt = "valid-token"
        client._expiry = 9999999999

        requests_mock.post(
            "https://test.horizon3ai.com/v1/graphql",
            json=SAMPLE_WEAKNESSES_PAGE_RESPONSE,
        )

        # pydantic le=1000 constraint should clamp/reject values > 1000
        args = GetWeaknessesArgs.model_validate({"since_date": "2024-01-01T00:00:00", "limit": "1000"})
        result = get_weaknesses_command(client, args)

        assert result.outputs_prefix == "NodeZero.Weakness"


TEST_URL = "https://test.horizon3ai.com"
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


def authenticated_test_client() -> Client:
    client = create_test_client()
    client._jwt = "valid-token"
    client._expiry = 9999999999
    return client


class TestUserAgent:
    """User-Agent is NodeZero-Cortex/<pack version> (NodeZero; Cortex <platform version>)."""

    def test_user_agent_uses_pack_and_platform_versions(self):
        with (
            patch("NodeZero.get_pack_version", return_value="2.0.0"),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0", "buildNumber": "1"}),
        ):
            assert build_user_agent() == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"

    def test_user_agent_in_unit_tests_has_unknown_pack_version(self):
        """get_pack_version() returns '' when the integration is not unified."""
        with patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0"}):
            assert build_user_agent() == "NodeZero-Cortex/unknown (NodeZero; Cortex 8.7.0)"

    @pytest.mark.parametrize(
        "pack_version_patch",
        [
            {"return_value": ""},
            {"return_value": None},
            {"return_value": "   "},
            {"return_value": "2.0.0\r\nX-Injected: 1"},
            {"return_value": "2.0.0 beta"},
            {"side_effect": RuntimeError("boom")},
        ],
    )
    def test_pack_version_falls_back_to_unknown(self, pack_version_patch):
        with (
            patch("NodeZero.get_pack_version", **pack_version_patch),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0"}),
        ):
            assert build_user_agent() == "NodeZero-Cortex/unknown (NodeZero; Cortex 8.7.0)"

    @pytest.mark.parametrize(
        "platform_version_patch",
        [
            {"return_value": {}},
            {"return_value": {"version": ""}},
            {"return_value": {"version": None}},
            {"return_value": {"version": 8}},
            {"return_value": {"version": "8.7.0\nX-Injected: 1"}},
            {"return_value": None},
            {"return_value": "8.7.0"},
            {"side_effect": KeyError("version")},
        ],
    )
    def test_platform_version_falls_back_to_unknown(self, platform_version_patch):
        with (
            patch("NodeZero.get_pack_version", return_value="2.0.0"),
            patch("NodeZero.demisto.demistoVersion", **platform_version_patch),
        ):
            assert build_user_agent() == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex unknown)"

    def test_both_versions_missing(self):
        with (
            patch("NodeZero.get_pack_version", side_effect=Exception("no pack")),
            patch("NodeZero.demisto.demistoVersion", side_effect=Exception("no platform")),
        ):
            assert build_user_agent() == "NodeZero-Cortex/unknown (NodeZero; Cortex unknown)"

    def test_version_is_stripped(self):
        with (
            patch("NodeZero.get_pack_version", return_value=" 2.0.0 "),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0\n"}),
        ):
            assert build_user_agent() == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"


class TestRequestIdentityHeaders:
    """Every request carries the User-Agent and X-Request-ID "<run id>-<n>"."""

    def test_every_request_carries_user_agent_and_numbered_request_id(self, requests_mock):
        with (
            patch("NodeZero.get_pack_version", return_value="2.0.0"),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0"}),
        ):
            client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        with patch("NodeZero.set_integration_context"):
            assert _test_module(client) == "ok"

        assert RUN_ID_PATTERN.fullmatch(client.run_id)
        history = requests_mock.request_history
        assert [r.path for r in history] == ["/v1/auth", "/v1/graphql"]
        assert [r.headers["X-Request-ID"] for r in history] == [f"{client.run_id}-1", f"{client.run_id}-2"]
        for request in history:
            assert request.headers["User-Agent"] == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"

    def test_graphql_request_keeps_authorization_header(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        client.hello_world()

        headers = requests_mock.last_request.headers
        assert headers["Authorization"] == "Bearer valid-token"
        assert headers["X-Request-ID"] == f"{client.run_id}-1"
        assert headers["User-Agent"].startswith("NodeZero-Cortex/")

    def test_request_counter_continues_across_pages(self, requests_mock):
        client = authenticated_test_client()
        full_page = {
            "data": {
                "weaknesses_page": {
                    "weaknesses": [{**SAMPLE_WEAKNESS, "uuid": f"uuid-{i}"} for i in range(100)],
                    "page_info": {"page_num": 1, "page_size": 100},
                }
            }
        }
        requests_mock.post(
            f"{TEST_URL}/v1/graphql",
            [{"json": full_page}, {"json": full_page}, {"json": SAMPLE_WEAKNESSES_PAGE_RESPONSE}],
        )

        fetch_all_weaknesses_pages(client, since_date="2024-01-01T00:00:00", max_fetch=250)

        request_ids = [r.headers["X-Request-ID"] for r in requests_mock.request_history]
        assert request_ids == [f"{client.run_id}-{n}" for n in (1, 2, 3)]

    def test_each_command_run_gets_its_own_run_id(self):
        first_client = create_test_client()
        second_client = create_test_client()

        assert first_client.run_id != second_client.run_id
        assert RUN_ID_PATTERN.fullmatch(first_client.run_id)
        assert RUN_ID_PATTERN.fullmatch(second_client.run_id)

    def test_headers_carry_no_secret_or_tenant(self, requests_mock):
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)

        with patch("NodeZero.set_integration_context"):
            client.authenticate()

        headers = requests_mock.last_request.headers
        for header in ("User-Agent", "X-Request-ID"):
            assert "test-api-key" not in headers[header]
            assert "horizon3ai.com" not in headers[header]
        assert requests_mock.last_request.json() == {"key": "test-api-key"}


class TestRunIdLogging:
    """The run ID is logged once per command run, at debug level."""

    def test_run_id_logged_once_at_debug(self):
        with (
            patch("NodeZero.demisto.debug") as mock_debug,
            patch("NodeZero.demisto.info") as mock_info,
        ):
            client = create_test_client()

        lines = [call.args[0] for call in mock_debug.call_args_list]
        run_id_lines = [line for line in lines if client.run_id in line]
        assert len(run_id_lines) == 1
        assert "test-api-key" not in run_id_lines[0]
        assert "horizon3ai.com" not in run_id_lines[0]
        mock_info.assert_not_called()

    def test_requests_do_not_log_the_run_id_again(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        with patch("NodeZero.demisto.debug") as mock_debug:
            client.hello_world()

        assert not [call for call in mock_debug.call_args_list if client.run_id in str(call)]


class TestOperationNames:
    """The integration's GraphQL operations are named CortexXsoar..."""

    def test_query_constants_use_cortex_xsoar_names(self):
        assert HELLO_WORLD_QUERY == "query CortexXsoarConnectivity { hello }"
        assert WEAKNESSES_PAGE_QUERY.strip().startswith("query CortexXsoarWeaknessesPage($page_input: PageInput!) {")
        assert "HelloWorld" not in HELLO_WORLD_QUERY
        assert "query WeaknessesPage" not in WEAKNESSES_PAGE_QUERY

    def test_connectivity_check_sends_cortex_xsoar_connectivity(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        client.hello_world()

        assert requests_mock.last_request.json() == {"query": "query CortexXsoarConnectivity { hello }", "variables": {}}

    def test_weaknesses_page_sends_cortex_xsoar_weaknesses_page(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_WEAKNESSES_PAGE_RESPONSE)

        client.query_weaknesses_page(page_num=2, page_size=100, since_date="2024-01-01T00:00:00")

        body = requests_mock.last_request.json()
        assert body["query"] == WEAKNESSES_PAGE_QUERY
        assert "query CortexXsoarWeaknessesPage(" in body["query"]
        assert body["variables"] == {
            "page_input": {
                "page_num": 2,
                "page_size": 100,
                "filter_by_inputs": [
                    {"field_name": "severity", "values": ["HIGH", "CRITICAL"]},
                    {"field_name": "created_at", "greater_than_or_equal": "2024-01-01T00:00:00"},
                ],
                "order_by": "created_at",
                "sort_order": "ASC",
            }
        }


class TestHttpErrorMessages:
    """User-facing HTTP errors name the failed request's X-Request-ID."""

    def test_graphql_http_error_names_request_id(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", status_code=500, reason="Internal Server Error")

        with pytest.raises(requests.HTTPError) as error_info:
            client.hello_world()

        message = str(error_info.value)
        assert message == (
            f"NodeZero v1/graphql request failed: HTTP 500 Internal Server Error (X-Request-ID: {client.run_id}-1)"
        )
        assert "horizon3ai.com" not in message
        assert error_info.value.response.status_code == 500

    def test_auth_http_error_names_request_id(self, requests_mock):
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", status_code=503, reason="")

        with pytest.raises(requests.HTTPError) as error_info:
            client.authenticate()

        assert str(error_info.value) == f"NodeZero v1/auth request failed: HTTP 503 (X-Request-ID: {client.run_id}-1)"

    def test_401_error_names_request_id(self, requests_mock):
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", status_code=401)

        with pytest.raises(UnauthenticatedError) as error_info:
            client.authenticate()

        assert str(error_info.value) == (f"Authentication failed: invalid or expired API key (X-Request-ID: {client.run_id}-1)")
        assert "test-api-key" not in str(error_info.value)

    @pytest.mark.parametrize("status", [400, 403, 404, 407, 429])
    @pytest.mark.parametrize("endpoint", ["v1/auth", "v1/graphql"])
    def test_other_4xx_still_raise_http_error(self, requests_mock, status, endpoint):
        """Every non-2xx response raises; only 401 is UnauthenticatedError."""
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/{endpoint}", status_code=status, reason="Client Error")

        with pytest.raises(requests.HTTPError) as error_info:
            client.authenticate() if endpoint == "v1/auth" else client.hello_world()

        assert error_info.value.response.status_code == status
        assert str(error_info.value) == (
            f"NodeZero {endpoint} request failed: HTTP {status} Client Error (X-Request-ID: {client.run_id}-1)"
        )

    def test_unauthenticated_error_without_request_id(self):
        assert str(UnauthenticatedError()) == "Authentication failed: invalid or expired API key"

    def test_failed_second_request_names_its_own_request_id(self, requests_mock):
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", status_code=502, reason="Bad Gateway")

        with patch("NodeZero.set_integration_context"), pytest.raises(requests.HTTPError) as error_info:
            _test_module(client)

        assert f"(X-Request-ID: {client.run_id}-2)" in str(error_info.value)


# Invariants: pinned constants, paging contract, request identity across a whole command run.

FAKE_NOW = 1_800_000_000  # injected clock for time.time()
API_KEY = "test-api-key"
JWT = "test-jwt-token-123"
INSTANCE_NAME = "NodeZero_instance_1"
LICENSE_ID = "license-id-sentinel-0001"
FORBIDDEN_VALUES = (API_KEY, JWT, "test.horizon3ai.com", INSTANCE_NAME, LICENSE_ID)
MAIN_PARAMS = {"url": TEST_URL, "credentials": {"identifier": "", "password": API_KEY}}

# The weaknesses query from pack 1.x, with only the operation name changed.
EXPECTED_WEAKNESSES_PAGE_QUERY = """
query CortexXsoarWeaknessesPage($page_input: PageInput!) {
  weaknesses_page(page_input: $page_input) {
    weaknesses {
        uuid
        created_at
        vuln_id
        vuln_name
        vuln_short_name
        vuln_category
        vuln_cisa_kev
        vuln_known_ransomware_campaign_use
        ip
        has_proof
        score
        severity
        affected_asset_uuid
        affected_asset_display_name
        attack_paths_count
        op_id
    }
    page_info {
      page_num
      page_size
    }
  }
}
"""


class FakeDatetime(datetime):
    """datetime with an injected now(), so date defaults can be checked exactly."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)


def weakness_rows(count: int, created_at: str = "2024-01-15T10:30:00") -> list[dict]:
    return [{**SAMPLE_WEAKNESS, "uuid": f"uuid-{i:04d}", "created_at": created_at} for i in range(count)]


class PagedServer:
    """Serves weaknesses_page from a fixed row list, using the page_num and page_size the client sends."""

    def __init__(self, rows: list[dict]):
        self.rows = rows
        self.page_inputs: list[dict] = []

    def __call__(self, request, context) -> dict:
        if "page_input" not in request.json()["variables"]:
            return SAMPLE_HELLO_RESPONSE
        page_input = request.json()["variables"]["page_input"]
        self.page_inputs.append(page_input)
        size, num = page_input["page_size"], page_input["page_num"]
        page = self.rows[(num - 1) * size : num * size]
        return {"data": {"weaknesses_page": {"weaknesses": page, "page_info": {"page_num": num, "page_size": size}}}}


class TestPinnedConstants:
    """A one-step change to any constant or default must fail a test."""

    def test_module_constants(self):
        assert NodeZero.MAX_PAGE_SIZE == 100
        assert NodeZero.DEFAULT_MAX_FETCH == 200
        assert NodeZero.DEFAULT_FIRST_FETCH == "7 days"
        assert NodeZero.AUTH_ENDPOINT == "v1/auth"
        assert NodeZero.GRAPHQL_ENDPOINT == "v1/graphql"
        assert NodeZero.USER_AGENT_PRODUCT == "NodeZero-Cortex"
        assert NodeZero.INTEGRATION_NAME == "NodeZero"
        assert NodeZero.UNKNOWN_VERSION == "unknown"

    def test_params_defaults_are_literal(self):
        params = Params.model_validate({"url": TEST_URL, "credentials": {"password": API_KEY}})

        assert params.max_fetch == 200
        assert params.first_fetch == "7 days"

    def test_get_weaknesses_limit_default_and_boundary(self):
        assert GetWeaknessesArgs(since_date="2024-01-01T00:00:00").limit == 50
        assert GetWeaknessesArgs(since_date="2024-01-01T00:00:00", limit=1000).limit == 1000
        with pytest.raises(ValidationError):
            GetWeaknessesArgs(since_date="2024-01-01T00:00:00", limit=1001)

    def test_get_weaknesses_default_since_date_is_seven_days_back(self):
        with patch("NodeZero.datetime", FakeDatetime):
            assert GetWeaknessesArgs().since_date == "2026-10-22T12:00:00"

    @patch("NodeZero.demisto")
    def test_fetch_default_since_date_is_seven_days_back(self, mock_demisto, requests_mock):
        """No last run and no first fetch time: fetch from now minus 7 days."""
        mock_demisto.getLastRun.return_value = {}
        client = authenticated_test_client()
        server = PagedServer([])
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=server)

        with patch("NodeZero.datetime", FakeDatetime):
            fetch_incidents(client, max_fetch=10, first_fetch_time=None)

        assert server.page_inputs[0]["filter_by_inputs"][1] == {
            "field_name": "created_at",
            "greater_than_or_equal": "2026-10-22T12:00:00",
        }

    def test_token_expiry_is_one_hour_minus_60_seconds(self, requests_mock):
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)

        with patch("NodeZero.time.time", return_value=FAKE_NOW), patch("NodeZero.set_integration_context") as mock_set:
            client.authenticate()

        assert client._expiry == FAKE_NOW + 3540
        mock_set.assert_called_once_with({"jwt": JWT, "expiry": FAKE_NOW + 3540})

    @pytest.mark.parametrize(("expiry_offset", "authenticated"), [(0, False), (1, True)])
    def test_cached_token_expiry_boundary(self, expiry_offset, authenticated):
        client = create_test_client()
        client._jwt = "cached"
        client._expiry = FAKE_NOW + expiry_offset

        with patch("NodeZero.time.time", return_value=FAKE_NOW):
            assert client.is_authenticated() is authenticated

    @patch("NodeZero.demisto")
    def test_all_duplicates_advance_fetch_date_by_one_second(self, mock_demisto, requests_mock):
        mock_demisto.getLastRun.return_value = {"last_fetch_date": "2024-01-15T10:30:59", "last_ids": ["uuid-0000"]}
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=PagedServer(weakness_rows(1, "2024-01-15T10:30:59")))

        incidents, next_run = fetch_incidents(authenticated_test_client(), max_fetch=10)

        assert incidents == []
        assert next_run.model_dump() == {"last_fetch_date": "2024-01-15T10:31:00", "last_ids": []}


class TestPagingContract:
    """Invariant 6: paging requests every page once, in order, and returns no lost or repeated rows."""

    def test_pages_are_requested_in_order_without_gaps_or_repeats(self, requests_mock):
        rows = weakness_rows(250)
        server = PagedServer(rows)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=server)

        weaknesses = fetch_all_weaknesses_pages(authenticated_test_client(), since_date="2024-01-01T00:00:00", max_fetch=1000)

        assert [w.uuid for w in weaknesses] == [row["uuid"] for row in rows]
        assert [(p["page_num"], p["page_size"]) for p in server.page_inputs] == [(1, 100), (2, 100), (3, 100)]

    @pytest.mark.parametrize(
        ("available", "max_fetch", "expected_pages", "expected_count"),
        [
            (99, 100, [(1, 100)], 99),
            (100, 200, [(1, 100), (2, 100)], 100),
            (200, 200, [(1, 100), (2, 100)], 200),
            (250, 200, [(1, 100), (2, 100)], 200),
            (50, 50, [(1, 50)], 50),
            (101, 101, [(1, 100), (2, 100)], 101),
            (300, 101, [(1, 100), (2, 100)], 101),
            (5, 1, [(1, 1)], 1),
        ],
    )
    def test_page_size_and_max_fetch_boundaries(self, requests_mock, available, max_fetch, expected_pages, expected_count):
        rows = weakness_rows(available)
        server = PagedServer(rows)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=server)

        weaknesses = fetch_all_weaknesses_pages(
            authenticated_test_client(), since_date="2024-01-01T00:00:00", max_fetch=max_fetch
        )

        assert [(p["page_num"], p["page_size"]) for p in server.page_inputs] == expected_pages
        assert [w.uuid for w in weaknesses] == [row["uuid"] for row in rows[:expected_count]]


class TestOperationNamesOnly:
    """Invariant 5: only the operation names changed; bodies carry no operationName."""

    def test_weaknesses_query_differs_from_before_only_by_name(self):
        assert WEAKNESSES_PAGE_QUERY == EXPECTED_WEAKNESSES_PAGE_QUERY

    def test_request_bodies_have_only_query_and_variables(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=PagedServer([]))

        client.hello_world()
        client.query_weaknesses_page(page_num=1, page_size=100, since_date="2024-01-01T00:00:00")

        assert [set(r.json()) for r in requests_mock.request_history] == [{"query", "variables"}] * 2


class ExplodingStrip(str):
    def strip(self, *args):
        raise RuntimeError("strip failed")


class ExplodingGet:
    def get(self, key):
        raise RuntimeError("get failed")


class StripsToVersion:
    """Not a string, but has a strip() that returns a plain version."""

    def strip(self):
        return "2.0.0"


class TestUserAgentNeverRaises:
    """Invariant 4 and the HEADER_SAFE_VERSION comment: only plain version strings of up to 64 characters are used."""

    @pytest.mark.parametrize(
        ("pack_version", "expected"),
        [
            (7, "unknown"),
            (2.0, "unknown"),
            (b"2.0.0", "unknown"),
            (["2.0.0"], "unknown"),
            ({"version": "2.0.0"}, "unknown"),
            (object(), "unknown"),
            (ExplodingStrip("2.0.0"), "unknown"),
            (StripsToVersion(), "unknown"),
            (".2.0", "unknown"),
            ("8.7.0 (beta)", "unknown"),
            ("2.0.0;", "unknown"),
            ("2.0.0+build.1", "2.0.0+build.1"),
            ("v2.0.0-rc_1", "v2.0.0-rc_1"),
            ("9" * 64, "9" * 64),
            ("9" * 65, "unknown"),
        ],
    )
    def test_pack_version_values(self, pack_version, expected):
        with (
            patch("NodeZero.get_pack_version", return_value=pack_version),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0"}),
        ):
            assert build_user_agent() == f"NodeZero-Cortex/{expected} (NodeZero; Cortex 8.7.0)"

    @pytest.mark.parametrize(
        ("platform_patch", "expected"),
        [
            ({"return_value": ExplodingGet()}, "unknown"),
            ({"return_value": {"version": ["8.7.0"]}}, "unknown"),
            ({"return_value": {"version": "8.7.0 (beta)"}}, "unknown"),
            ({"return_value": {"version": "8" * 64}}, "8" * 64),
            ({"return_value": {"version": "8" * 65}}, "unknown"),
            ({"side_effect": ValueError("no server")}, "unknown"),
        ],
    )
    def test_platform_version_values(self, platform_patch, expected):
        with (
            patch("NodeZero.get_pack_version", return_value="2.0.0"),
            patch("NodeZero.demisto.demistoVersion", **platform_patch),
        ):
            assert build_user_agent() == f"NodeZero-Cortex/2.0.0 (NodeZero; Cortex {expected})"

    def test_client_still_sends_headers_when_both_versions_fail(self, requests_mock):
        with (
            patch("NodeZero.get_pack_version", side_effect=RuntimeError("no pack")),
            patch("NodeZero.demisto.demistoVersion", side_effect=RuntimeError("no platform")),
        ):
            client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        client.hello_world()

        headers = requests_mock.last_request.headers
        assert headers["User-Agent"] == "NodeZero-Cortex/unknown (NodeZero; Cortex unknown)"
        assert headers["X-Request-ID"] == f"{client.run_id}-1"


def run_main(command: str, last_run: dict | None = None, args: dict | None = None) -> dict:
    """Run main() once, as the platform would, and capture everything it sends and logs."""
    calls: dict = {}
    with (
        patch.object(demisto, "params", return_value=MAIN_PARAMS),
        patch.object(demisto, "command", return_value=command),
        patch.object(demisto, "args", return_value=args or {}),
        patch.object(demisto, "getLastRun", return_value=last_run or {}),
        patch.object(demisto, "setLastRun") as set_last_run,
        patch.object(demisto, "incidents") as incidents,
        patch.object(demisto, "integrationInstance", return_value=INSTANCE_NAME),
        patch.object(demisto, "getLicenseID", return_value=LICENSE_ID),
        patch.object(demisto, "demistoVersion", return_value={"version": "8.7.0"}),
        patch.object(demisto, "debug") as debug,
        patch.object(demisto, "info") as info,
        patch.object(demisto, "error") as error,
        patch("NodeZero.get_pack_version", return_value="2.0.0"),
        patch("NodeZero.get_integration_context", return_value={}),
        patch("NodeZero.set_integration_context"),
        patch("NodeZero.return_results") as return_results,
        patch("NodeZero.return_error") as return_error,
    ):
        NodeZero.main()
    calls["set_last_run"] = set_last_run
    calls["incidents"] = incidents
    calls["return_results"] = return_results
    calls["return_error"] = return_error
    calls["logs"] = [str(call) for mock in (debug, info, error) for call in mock.mock_calls]
    calls["run_id_lines"] = [line for line in calls["logs"] if "NodeZero run ID" in line]
    return calls


def identity_headers(requests_mock) -> list[tuple[str, str]]:
    return [(r.headers.get("User-Agent", ""), r.headers.get("X-Request-ID", "")) for r in requests_mock.request_history]


def assert_one_run(requests_mock, captured: dict) -> str:
    """Invariants 1 and 2 for one main() run; returns its run ID."""
    headers = identity_headers(requests_mock)
    assert headers
    run_id = headers[0][1].rsplit("-", 1)[0]
    assert RUN_ID_PATTERN.fullmatch(run_id)
    assert headers == [("NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)", f"{run_id}-{n}") for n in range(1, len(headers) + 1)]
    assert len(captured["run_id_lines"]) == 1
    assert run_id in captured["run_id_lines"][0]
    return run_id


def assert_nothing_forbidden(requests_mock, captured: dict) -> None:
    """Invariant 3: the identity headers and every log line carry no secret, tenant or instance value."""
    values = [value for pair in identity_headers(requests_mock) for value in pair] + captured["logs"]
    values += [str(call) for call in captured["return_error"].mock_calls]
    for value in values:
        for forbidden in FORBIDDEN_VALUES:
            assert forbidden not in value


class TestMainCommandRuns:
    """Invariants 1, 2, 3 and 6 for whole command runs through main()."""

    def test_fetch_incidents_run(self, requests_mock):
        rows = [
            {**SAMPLE_WEAKNESS, "uuid": "uuid-0", "created_at": "2024-01-15T10:30:00"},
            {**SAMPLE_WEAKNESS, "uuid": "uuid-1", "created_at": "2024-01-15T10:30:00"},
            {**SAMPLE_WEAKNESS, "uuid": "uuid-2", "created_at": "2024-01-15T10:31:00"},
        ]
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=PagedServer(rows))

        captured = run_main("fetch-incidents", last_run={"last_fetch_date": "2024-01-15T10:30:00", "last_ids": ["uuid-0"]})

        captured["return_error"].assert_not_called()
        assert [r.path for r in requests_mock.request_history] == ["/v1/auth", "/v1/graphql"]
        assert_one_run(requests_mock, captured)
        assert_nothing_forbidden(requests_mock, captured)
        captured["set_last_run"].assert_called_once_with({"last_fetch_date": "2024-01-15T10:31:00", "last_ids": ["uuid-2"]})
        incidents = captured["incidents"].call_args.args[0]
        assert [(i["dbotMirrorId"], i["occurred"], i["name"]) for i in incidents] == [
            ("uuid-1", "2024-01-15T10:30:00Z", "Test Vuln on test-server-01"),
            ("uuid-2", "2024-01-15T10:31:00Z", "Test Vuln on test-server-01"),
        ]

    def test_get_weaknesses_run_over_three_pages(self, requests_mock):
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=PagedServer(weakness_rows(250)))

        captured = run_main("nodezero-get-weaknesses", args={"since_date": "2024-01-01T00:00:00", "limit": "1000"})

        captured["return_error"].assert_not_called()
        assert len(requests_mock.request_history) == 4
        assert_one_run(requests_mock, captured)
        assert_nothing_forbidden(requests_mock, captured)
        assert len(captured["return_results"].call_args.args[0].outputs) == 250

    def test_two_runs_get_different_run_ids(self, requests_mock):
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        first = run_main("test-module")
        first_run_id = assert_one_run(requests_mock, first)
        first["return_results"].assert_called_once_with("ok")
        requests_mock.reset_mock()
        second = run_main("test-module")
        second_run_id = assert_one_run(requests_mock, second)

        assert first_run_id != second_run_id

    @pytest.mark.parametrize(("status", "error_text"), [(500, "HTTP 500 Internal Server Error"), (401, "Authentication failed")])
    def test_failed_run_reports_request_id_without_secrets(self, requests_mock, status, error_text):
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", status_code=status, reason="Internal Server Error")

        captured = run_main("test-module")

        run_id = assert_one_run(requests_mock, captured)
        assert_nothing_forbidden(requests_mock, captured)
        message = captured["return_error"].call_args.args[0]
        assert error_text in message
        assert message.endswith(f"(X-Request-ID: {run_id}-2)")


class TestRequestIdUnit:
    def test_caller_headers_cannot_replace_identity_headers(self, requests_mock):
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        client._post("v1/graphql", {"query": "q", "variables": {}}, {"User-Agent": "other", "X-Request-ID": "other"})

        headers = requests_mock.last_request.headers
        assert headers["User-Agent"] == client._user_agent
        assert headers["X-Request-ID"] == f"{client.run_id}-1"

    def test_request_id_is_run_id_and_counter(self):
        client = create_test_client()

        assert [client._next_request_id() for _ in range(3)] == [f"{client.run_id}-{n}" for n in (1, 2, 3)]

    def test_run_id_comes_from_uuid4(self):
        fake_uuid = MagicMock(hex="0123456789abcdef0123456789abcdef")
        with patch("NodeZero.uuid.uuid4", return_value=fake_uuid):
            assert create_test_client().run_id == "0123456789abcdef0123456789abcdef"


class FormatBomb(str):
    def __format__(self, spec):
        raise RuntimeError("__format__ raised")


class StripToFormatBomb(str):
    """A str subclass whose strip() returns a str that raises when formatted."""

    def strip(self, *args):
        return FormatBomb(str(self))


class TestEdgeCases:
    """Edge cases: version characters and types, redirects, statuses, the token clock and the saved last run."""

    def test_version_character_set_is_exact(self):
        """The HEADER_SAFE_VERSION comment: letters, digits and ._+- only, starting with a letter or digit."""
        allowed = set(string.ascii_letters + string.digits + "._+-")
        for char in map(chr, range(128)):
            assert (NodeZero._header_safe_version(f"1{char}0") == f"1{char}0") is (char in allowed), repr(char)
            assert (NodeZero._header_safe_version(f"{char}1") == f"{char}1") is (char in allowed - set("._+-")), repr(char)

    def test_returned_str_subclass_cannot_break_the_user_agent(self):
        with (
            patch("NodeZero.get_pack_version", return_value=StripToFormatBomb("2.0.0")),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": StripToFormatBomb("8.7.0")}),
        ):
            user_agent = build_user_agent()

        assert user_agent == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"
        assert type(user_agent) is str

    def test_pack_version_prefers_the_unified_constant(self):
        """The content build writes CONSTANT_PACK_VERSION; get_pack_version() is not called when it is there."""
        with (
            patch.dict(NodeZero.__dict__, {"CONSTANT_PACK_VERSION": "2.0.0"}),
            patch("NodeZero.get_pack_version", side_effect=AssertionError("get_pack_version() called")),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0"}),
        ):
            assert build_user_agent() == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"

    def test_server_redirect_is_followed_and_reuses_the_request_id(self, requests_mock):
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", status_code=307, headers={"Location": f"{TEST_URL}/v1/auth-moved"})
        requests_mock.post(f"{TEST_URL}/v1/auth-moved", json=SAMPLE_AUTH_RESPONSE)

        with patch("NodeZero.set_integration_context"):
            client.authenticate()

        assert [r.path for r in requests_mock.request_history] == ["/v1/auth", "/v1/auth-moved"]
        assert [r.headers["X-Request-ID"] for r in requests_mock.request_history] == [f"{client.run_id}-1"] * 2
        assert client._jwt == JWT

    @pytest.mark.parametrize("status", [200, 201, 204, 304])
    def test_non_error_statuses_do_not_raise(self, status):
        """As with raise_for_status, only 4xx and 5xx responses raise."""
        response = requests.Response()
        response.status_code = status

        authenticated_test_client()._raise_for_status(response, "v1/graphql", "run-1")

    def test_token_lifetime_counts_from_before_the_request(self, requests_mock):
        clock = {"now": FAKE_NOW}

        def slow_auth(request, context):
            clock["now"] += 30  # the auth request takes 30 s on the injected clock
            return SAMPLE_AUTH_RESPONSE

        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", json=slow_auth)
        with patch("NodeZero.time.time", side_effect=lambda: clock["now"]), patch("NodeZero.set_integration_context"):
            client.authenticate()

        assert client._expiry == FAKE_NOW + 3540

    def test_unauthenticated_error_with_empty_request_id(self):
        assert str(UnauthenticatedError(request_id="")) == "Authentication failed: invalid or expired API key"

    @pytest.mark.parametrize(
        ("last_run", "rows", "expected"),
        [
            ({}, [], {"last_fetch_date": None, "last_ids": []}),
            (
                {"last_fetch_date": "2024-01-15T10:30:00", "last_ids": ["uuid-0000"]},
                weakness_rows(1, "2024-01-15T10:30:00"),
                {"last_fetch_date": "2024-01-15T10:30:01", "last_ids": []},
            ),
        ],
    )
    def test_main_persists_the_exact_last_run(self, requests_mock, last_run, rows, expected):
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=PagedServer(rows))

        captured = run_main("fetch-incidents", last_run=last_run)

        captured["return_error"].assert_not_called()
        captured["set_last_run"].assert_called_once_with(expected)


class BoolBomb(str):
    """A str subclass that raises when tested for truth (the constant is read with `or`)."""

    def __bool__(self):
        raise RuntimeError("__bool__ raised")


@pytest.fixture
def unexpected_get_pack_version():
    """get_pack_version() that must not be used: it returns a version no test expects."""
    with patch("NodeZero.get_pack_version", return_value="9.9.9") as mock_get_pack_version:
        yield mock_get_pack_version


@pytest.fixture
def platform_870():
    with patch("NodeZero.demisto.demistoVersion", return_value={"version": "8.7.0"}):
        yield


class TestUnifiedPackVersionConstant:
    """_pack_version reads the CONSTANT_PACK_VERSION the content build writes, then get_pack_version().

    On Base packs older than 1.41.4 get_pack_version() makes internal Cortex API calls, so it must not run when the
    constant is set.
    """

    def test_module_has_no_constant_outside_the_unified_script(self):
        """The fallback tests below rely on this: only the content build adds the constant."""
        assert "CONSTANT_PACK_VERSION" not in vars(NodeZero)

    def test_constant_is_used_and_get_pack_version_is_not_called(self, monkeypatch, unexpected_get_pack_version, platform_870):
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", "2.0.0", raising=False)

        assert build_user_agent() == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"
        assert unexpected_get_pack_version.call_count == 0

    def test_constant_reaches_every_request(self, monkeypatch, requests_mock, unexpected_get_pack_version, platform_870):
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", "2.0.0", raising=False)
        client = create_test_client()
        requests_mock.post(f"{TEST_URL}/v1/auth", json=SAMPLE_AUTH_RESPONSE)
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        with patch("NodeZero.set_integration_context"):
            assert _test_module(client) == "ok"

        assert [r.headers["User-Agent"] for r in requests_mock.request_history] == [
            "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"
        ] * 2
        assert unexpected_get_pack_version.call_count == 0

    def test_constant_absent_falls_back_to_get_pack_version(self, unexpected_get_pack_version, platform_870):
        assert build_user_agent() == "NodeZero-Cortex/9.9.9 (NodeZero; Cortex 8.7.0)"
        assert unexpected_get_pack_version.call_count == 1

    @pytest.mark.parametrize("empty_constant", ["", None])
    def test_empty_constant_falls_back_to_get_pack_version(
        self, monkeypatch, unexpected_get_pack_version, platform_870, empty_constant
    ):
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", empty_constant, raising=False)

        assert build_user_agent() == "NodeZero-Cortex/9.9.9 (NodeZero; Cortex 8.7.0)"
        assert unexpected_get_pack_version.call_count == 1

    @pytest.mark.parametrize("get_pack_version_patch", [{"return_value": ""}, {"side_effect": RuntimeError("no pack")}])
    def test_no_constant_and_no_pack_version_gives_unknown(self, platform_870, get_pack_version_patch):
        with patch("NodeZero.get_pack_version", **get_pack_version_patch) as mock_get_pack_version:
            assert build_user_agent() == "NodeZero-Cortex/unknown (NodeZero; Cortex 8.7.0)"
        assert mock_get_pack_version.call_count == 1

    @pytest.mark.parametrize(
        "unusable_constant", ["   ", "2.0.0 beta", "2.0.0\r\nX-Injected: 1", 2], ids=["blank", "space", "crlf", "int"]
    )
    def test_set_but_unusable_constant_gives_unknown_without_fallback(
        self, monkeypatch, unexpected_get_pack_version, platform_870, unusable_constant
    ):
        """A non-empty constant is the build's answer: it is filtered like any version, not replaced by the lookup."""
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", unusable_constant, raising=False)

        assert build_user_agent() == "NodeZero-Cortex/unknown (NodeZero; Cortex 8.7.0)"
        assert unexpected_get_pack_version.call_count == 0

    def test_constant_is_stripped(self, monkeypatch, unexpected_get_pack_version, platform_870):
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", " 2.0.0\n", raising=False)

        assert build_user_agent() == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"


class TestStrSubclassVersions:
    """A str subclass from either lookup gives "unknown" or the plain version, never an exception."""

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            (ExplodingStrip("2.0.0"), "unknown"),
            (FormatBomb("2.0.0"), "2.0.0"),
            (StripToFormatBomb("2.0.0"), "2.0.0"),
            (BoolBomb("2.0.0"), "unknown"),
        ],
        ids=["exploding_strip", "format_bomb", "strip_to_format_bomb", "bool_bomb"],
    )
    def test_constant_str_subclass(self, monkeypatch, unexpected_get_pack_version, platform_870, version, expected):
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", version, raising=False)

        user_agent = build_user_agent()

        assert user_agent == f"NodeZero-Cortex/{expected} (NodeZero; Cortex 8.7.0)"
        assert type(user_agent) is str
        assert unexpected_get_pack_version.call_count == 0

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            (ExplodingStrip("2.0.0"), "unknown"),
            (FormatBomb("2.0.0"), "2.0.0"),
            (StripToFormatBomb("2.0.0"), "2.0.0"),
            (BoolBomb("2.0.0"), "2.0.0"),  # only the constant is truth-tested
        ],
        ids=["exploding_strip", "format_bomb", "strip_to_format_bomb", "bool_bomb"],
    )
    def test_get_pack_version_str_subclass(self, platform_870, version, expected):
        with patch("NodeZero.get_pack_version", return_value=version):
            user_agent = build_user_agent()

        assert user_agent == f"NodeZero-Cortex/{expected} (NodeZero; Cortex 8.7.0)"
        assert type(user_agent) is str

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            (ExplodingStrip("8.7.0"), "unknown"),
            (FormatBomb("8.7.0"), "8.7.0"),
            (StripToFormatBomb("8.7.0"), "8.7.0"),
        ],
        ids=["exploding_strip", "format_bomb", "strip_to_format_bomb"],
    )
    def test_platform_version_str_subclass(self, version, expected):
        with (
            patch("NodeZero.get_pack_version", return_value="2.0.0"),
            patch("NodeZero.demisto.demistoVersion", return_value={"version": version}),
        ):
            user_agent = build_user_agent()

        assert user_agent == f"NodeZero-Cortex/2.0.0 (NodeZero; Cortex {expected})"
        assert type(user_agent) is str

    @pytest.mark.parametrize(
        "raw_version", [FormatBomb(" 2.0.0 "), StripToFormatBomb("2.0.0")], ids=["format_bomb", "strip_to_format_bomb"]
    )
    def test_header_safe_version_returns_a_plain_str(self, raw_version):
        version = NodeZero._header_safe_version(raw_version)

        assert version == "2.0.0"
        assert type(version) is str

    def test_client_user_agent_is_a_plain_str(self, monkeypatch, requests_mock, platform_870):
        monkeypatch.setattr(NodeZero, "CONSTANT_PACK_VERSION", StripToFormatBomb("2.0.0"), raising=False)
        client = authenticated_test_client()
        requests_mock.post(f"{TEST_URL}/v1/graphql", json=SAMPLE_HELLO_RESPONSE)

        client.hello_world()

        assert type(client._user_agent) is str
        assert requests_mock.last_request.headers["User-Agent"] == "NodeZero-Cortex/2.0.0 (NodeZero; Cortex 8.7.0)"

    @pytest.mark.parametrize("interrupt", [SystemExit(0), KeyboardInterrupt()], ids=["system_exit", "keyboard_interrupt"])
    def test_interpreter_exits_from_a_lookup_are_not_swallowed(self, interrupt):
        """The build_user_agent docstring: SystemExit and KeyboardInterrupt raised by a lookup are not caught."""
        with patch("NodeZero.get_pack_version", side_effect=interrupt), pytest.raises(type(interrupt)):
            build_user_agent()
        with (
            patch("NodeZero.get_pack_version", return_value="2.0.0"),
            patch("NodeZero.demisto.demistoVersion", side_effect=interrupt),
            pytest.raises(type(interrupt)),
        ):
            build_user_agent()
