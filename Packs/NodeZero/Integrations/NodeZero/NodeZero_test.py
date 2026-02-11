"""NodeZero Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests for the NodeZero Integration.

More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import pytest
from unittest.mock import patch

from datetime import datetime, UTC

from NodeZero import (
    Client,
    Params,
    Weakness,
    LastRun,
    _test_module,
    fetch_incidents,
    fetch_all_weaknesses_pages,
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
