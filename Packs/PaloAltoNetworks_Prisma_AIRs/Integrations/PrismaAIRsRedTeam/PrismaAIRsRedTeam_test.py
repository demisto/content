import json
import pytest
import demistomock as demisto
from unittest.mock import Mock, patch
from PrismaAIRsRedTeam import (
    Client,
    test_module as run_test_module,
    redteam_categories_list_command,
    redteam_network_channels_list_command,
    redteam_network_channels_create_command,
    redteam_network_channels_stats_command,
    redteam_network_channels_get_command,
    redteam_network_channels_update_command,
    redteam_languages_list_command,
    redteam_eula_status_command,
    redteam_eula_content_command,
    redteam_eula_accept_command,
    redteam_prompt_sets_create_command,
    redteam_prompt_sets_list_command,
    redteam_prompt_sets_get_command,
    redteam_prompt_sets_update_command,
    redteam_prompt_sets_archive_command,
    redteam_prompt_sets_download_command,
    redteam_prompt_sets_upload_command,
    redteam_prompt_sets_reference_command,
    redteam_prompt_sets_version_info_command,
    redteam_prompt_sets_active_list_command,
    redteam_custom_attack_report_get_command,
    redteam_custom_attack_report_prompt_sets_command,
    redteam_custom_attack_report_prompts_command,
    redteam_custom_attack_report_prompt_get_command,
    redteam_custom_attacks_list_command,
    redteam_custom_attack_outputs_command,
    redteam_custom_attack_property_stats_command,
    redteam_prompts_create_command,
    redteam_prompts_list_command,
    redteam_prompts_get_command,
    redteam_prompts_update_command,
    redteam_prompts_delete_command,
    redteam_scan_create_command,
    redteam_scans_list_command,
    redteam_scan_get_command,
    redteam_scan_abort_command,
    redteam_report_get_command,
    redteam_registry_credentials_get_command,
    redteam_targets_create_command,
    redteam_targets_list_command,
    redteam_targets_get_command,
    redteam_targets_delete_command,
    redteam_targets_update_command,
    redteam_targets_probe_command,
    redteam_instances_create_command,
    redteam_instances_get_command,
    redteam_instances_update_command,
    redteam_instances_delete_command,
    redteam_devices_create_command,
    redteam_devices_update_command,
    redteam_devices_delete_command,
    redteam_adapters_list_command,
    redteam_adapters_get_command,
    redteam_adapters_create_command,
    redteam_adapters_update_command,
    redteam_adapters_delete_command,
    redteam_adapters_validate_command,
    redteam_targets_profile_command,
    redteam_targets_update_profile_command,
    redteam_properties_add_value_command,
    redteam_properties_create_command,
    redteam_properties_list_command,
    redteam_properties_values_command,
    redteam_sentiment_get_command,
    redteam_sentiment_update_command,
    redteam_targets_error_logs_command,
    redteam_targets_metadata_command,
    redteam_targets_templates_command,
    redteam_targets_validate_auth_command,
)


@pytest.fixture
def mock_client() -> Client:
    """Create a mock Prisma AIRs client for testing.

    Returns:
        Client: Mock client instance.
    """
    return Client(
        base_url="https://api.sase.paloaltonetworks.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
        tsg_id="1234567890",
        runtime_api_key="test_runtime_api_key_12345",
        scanner_base_url="https://service.api.aisecurity.paloaltonetworks.com",
        dlp_base_url="https://api.dlp.paloaltonetworks.com",
        verify=False,
        proxy=False,
        headers={},
    )


class TestClient:
    """Test cases for Client class."""

    def test_client_initialization(self, mock_client: Client) -> None:
        """Test that Client initializes correctly.

        Args:
            mock_client: Mock client fixture.
        """
        assert mock_client.client_id == "test_client_id"
        assert mock_client.client_secret == "test_client_secret"
        assert mock_client.tsg_id == "1234567890"
        assert mock_client.runtime_api_key == "test_runtime_api_key_12345"
        assert mock_client.scanner_base_url == "https://service.api.aisecurity.paloaltonetworks.com"
        assert mock_client.dlp_base_url == "https://api.dlp.paloaltonetworks.com"
        assert mock_client._access_token is None

    def test_client_base_url_defaults(self) -> None:
        """Test that scanner/DLP base URLs fall back to defaults when not configured.

        The integration takes scanner_base_url and dlp_base_url as direct configuration
        parameters. When omitted (None), the client must fall back to the documented
        global defaults.
        """
        client = Client(
            base_url="https://api.sase.paloaltonetworks.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tsg_id="1234567890",
            runtime_api_key="test_runtime_api_key",
            scanner_base_url=None,
            dlp_base_url=None,
            verify=False,
            proxy=False,
            headers={},
        )

        assert client.scanner_base_url == "https://service.api.aisecurity.paloaltonetworks.com"
        assert client.dlp_base_url == "https://api.dlp.paloaltonetworks.com"

    def test_client_base_url_override(self) -> None:
        """Test that explicitly configured scanner/DLP base URLs are stored as provided."""
        client = Client(
            base_url="https://api.sase.paloaltonetworks.com",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tsg_id="1234567890",
            runtime_api_key="test_runtime_api_key",
            scanner_base_url="https://service-de.api.aisecurity.paloaltonetworks.com",
            dlp_base_url="https://api-de.dlp.paloaltonetworks.com",
            verify=False,
            proxy=False,
            headers={},
        )

        assert client.scanner_base_url == "https://service-de.api.aisecurity.paloaltonetworks.com"
        assert client.dlp_base_url == "https://api-de.dlp.paloaltonetworks.com"

    @patch.object(Client, "_http_request")
    def test_get_access_token_success(self, mock_http_request: Mock, mock_client: Client) -> None:
        """Test successful OAuth2 token retrieval.

        Args:
            mock_http_request: Mocked HTTP request method.
            mock_client: Mock client fixture.
        """
        mock_http_request.return_value = {"access_token": "test_access_token_12345", "token_type": "Bearer", "expires_in": 3600}

        token = mock_client.get_access_token()

        assert token == "test_access_token_12345"
        assert mock_client._access_token == "test_access_token_12345"
        mock_http_request.assert_called_once()

    @patch.object(Client, "_http_request")
    def test_get_access_token_cached(self, mock_http_request: Mock, mock_client: Client) -> None:
        """Test that access token is cached and not re-requested.

        Args:
            mock_http_request: Mocked HTTP request method.
            mock_client: Mock client fixture.
        """
        mock_client._access_token = "cached_token"

        token = mock_client.get_access_token()

        assert token == "cached_token"
        mock_http_request.assert_not_called()


class TestCommands:
    """Test cases for integration commands."""

    @patch.object(Client, "get_access_token")
    def test_test_module_success(self, mock_get_token: Mock, mock_client: Client) -> None:
        """Test that test-module returns ok on successful connection.

        Args:
            mock_get_token: Mocked get_access_token method.
            mock_client: Mock client fixture.
        """
        mock_get_token.return_value = "test_token"

        result = run_test_module(mock_client)

        assert result == "ok"
        mock_get_token.assert_called_once()

    @patch.object(Client, "get_access_token")
    def test_test_module_failure(self, mock_get_token: Mock, mock_client: Client) -> None:
        """Test that test-module returns error message on failure.

        Args:
            mock_get_token: Mocked get_access_token method.
            mock_client: Mock client fixture.
        """
        mock_get_token.side_effect = Exception("Authentication failed")

        result = run_test_module(mock_client)

        assert "Test failed" in result
        assert "Authentication failed" in result


    @patch.object(Client, "http_request")
    def test_redteam_targets_profile_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets profile command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "target_id": "target-uuid-123",
            "target_version": 1,
            "status": "READY",
            "profiling_status": "COMPLETED",
            "target_background": {"industry": "Healthcare", "use_case": "Patient Support"},
            "additional_context": {"base_model": "GPT-4", "languages_supported": ["en", "es"]},
            "ai_generated_fields": {"sensitivity": "high"},
            "other_details": {"region": "us-west-2"},
        }

        args = {"target_uuid": "target-uuid-123"}
        result = redteam_targets_profile_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetProfile"
        assert result.outputs["target_id"] == "target-uuid-123"
        assert result.outputs["target_version"] == 1
        assert result.outputs["status"] == "READY"
        assert result.outputs["profiling_status"] == "COMPLETED"
        assert result.outputs["target_background"]["industry"] == "Healthcare"
        assert result.outputs["additional_context"]["base_model"] == "GPT-4"

    @patch.object(Client, "http_request")
    def test_redteam_targets_update_profile_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets update profile command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "target-uuid-123",
            "name": "prod-chatbot",
            "status": "READY",
            "active": True,
            "validated": True,
            "updated_at": "2024-01-15T10:30:00Z",
            "target_background": {"industry": "Healthcare", "use_case": "Patient Support"},
            "additional_context": {"base_model": "GPT-4"},
        }

        args = {
            "target_uuid": "target-uuid-123",
            "target_background": '{"industry": "Healthcare", "use_case": "Patient Support"}',
            "additional_context": '{"base_model": "GPT-4"}',
        }
        result = redteam_targets_update_profile_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetUpdateProfile"
        assert result.outputs["uuid"] == "target-uuid-123"
        assert result.outputs["name"] == "prod-chatbot"
        assert result.outputs["status"] == "READY"
        assert result.outputs["target_background"]["industry"] == "Healthcare"
        assert result.outputs["additional_context"]["base_model"] == "GPT-4"

        # Verify http_request was called with correct body
        call_args = mock_http.call_args
        body = call_args[1]["json_data"]
        assert body["target_background"]["industry"] == "Healthcare"
        assert body["additional_context"]["base_model"] == "GPT-4"

    @patch.object(Client, "http_request")
    def test_redteam_targets_metadata_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets metadata command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "rate_limit": {"type": "number", "required": False},
            "multi_turn": {"type": "boolean", "required": False},
            "content_filter": {"type": "boolean", "required": False},
            "base_model": {"type": "string", "required": True},
        }

        args: dict[str, str] = {}
        result = redteam_targets_metadata_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetMetadata"
        assert "rate_limit" in result.outputs
        assert result.outputs["rate_limit"]["type"] == "number"
        assert result.outputs["multi_turn"]["type"] == "boolean"
        assert result.outputs["base_model"]["required"] is True

    @patch.object(Client, "http_request")
    def test_redteam_targets_validate_auth_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets validate-auth command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"validated": True, "token_preview": "sk-***xyz", "expires_in": 3600}

        args = {"auth_type": "HEADERS", "auth_config": '{"Authorization": "Bearer sk-xxx"}'}
        result = redteam_targets_validate_auth_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetAuthValidation"
        assert result.outputs["validated"] is True
        assert result.outputs["expires_in"] == 3600

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/target/validate-auth"
        assert kwargs["use_redteam_mgmt"] is True
        assert kwargs["json_data"]["auth_type"] == "HEADERS"
        assert kwargs["json_data"]["auth_config"] == {"Authorization": "Bearer sk-xxx"}

    @patch.object(Client, "http_request")
    def test_redteam_targets_templates_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets templates command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "OPENAI": {"api_key": "string", "model": "string"},
            "REST": {"url": "string", "headers": "object"},
        }

        args: dict[str, str] = {}
        result = redteam_targets_templates_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetTemplate"
        assert "OPENAI" in result.outputs
        assert result.outputs["OPENAI"]["model"] == "string"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/template/target-templates"
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_properties_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam properties list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"data": ["category", "severity"]}

        args: dict[str, str] = {}
        result = redteam_properties_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamProperty"
        assert result.outputs == ["category", "severity"]

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attack/property-names"
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_properties_values_single_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam properties values command with a single property_name.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"name": "severity", "values": ["low", "medium", "high"]}

        args = {"property_name": "severity"}
        result = redteam_properties_values_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPropertyValue"
        assert result.outputs == [{"name": "severity", "values": ["low", "medium", "high"]}]

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attack/property-values/severity"
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_properties_values_multiple_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam properties values command with multiple property_names (batch lookup).

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"data": {"category": ["jailbreak", "pii"], "severity": ["low", "high"]}}

        args = {"property_names": "category,severity"}
        result = redteam_properties_values_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPropertyValue"
        assert {"name": "category", "values": ["jailbreak", "pii"]} in result.outputs
        assert {"name": "severity", "values": ["low", "high"]} in result.outputs

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attack/property-values"
        assert kwargs["params"]["property_names"] == ["category", "severity"]
        assert kwargs["use_redteam_mgmt"] is True

    def test_redteam_properties_values_requires_arg(self, mock_client: Client) -> None:
        """Test redteam properties values command raises when no argument is provided.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="property_name"):
            redteam_properties_values_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_properties_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam properties create command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "ok", "status": 200}

        args = {"name": "severity"}
        result = redteam_properties_create_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPropertyCreate"
        assert result.outputs["name"] == "severity"
        assert result.outputs["status"] == 200

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/custom-attack/property-names"
        assert kwargs["json_data"] == {"name": "severity"}
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_properties_add_value_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam properties add-value command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "ok", "status": 200}

        args = {"property_name": "severity", "property_value": "critical"}
        result = redteam_properties_add_value_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPropertyValueCreate"
        assert result.outputs["property_name"] == "severity"
        assert result.outputs["property_value"] == "critical"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/custom-attack/property-values"
        assert kwargs["json_data"] == {"property_name": "severity", "property_value": "critical"}
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_sentiment_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam sentiment get command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"job_id": "job-1", "up_vote": True}

        result = redteam_sentiment_get_command(mock_client, {"job_id": "job-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamSentiment"
        assert result.outputs_key_field == "job_id"
        assert result.outputs["job_id"] == "job-1"
        assert result.outputs["up_vote"] is True

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/sentiment/job-1"
        assert kwargs["use_redteam_data"] is True

    def test_redteam_sentiment_get_requires_job_id(self, mock_client: Client) -> None:
        """Test redteam sentiment get command raises when job_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="job_id"):
            redteam_sentiment_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_targets_error_logs_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets error-logs command routing, params, and parsing.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "pagination": {"total_items": 1},
            "data": [
                {
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "target_id": "target-1",
                    "error_type": "PROBE",
                    "error_source": "profiler",
                    "error_message": "connection refused",
                    "job_id": None,
                }
            ],
        }

        result = redteam_targets_error_logs_command(
            mock_client, {"target_id": "target-1", "limit": "10", "skip": "5", "search": "refused"}
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetErrorLog"
        assert len(result.outputs) == 1
        entry = result.outputs[0]
        assert entry["error_type"] == "PROBE"
        assert entry["error_message"] == "connection refused"
        # assign_params drops the None job_id.
        assert "job_id" not in entry

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/error-log/target-profile/target-1"
        assert kwargs["use_redteam_data"] is True
        assert kwargs["params"] == {"limit": 10, "skip": 5, "search": "refused"}

    @patch.object(Client, "http_request")
    def test_redteam_targets_error_logs_default_limit(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam targets error-logs applies the default limit and omits optional params.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"pagination": {}, "data": []}

        redteam_targets_error_logs_command(mock_client, {"target_id": "target-1"})

        _, kwargs = mock_http.call_args
        assert kwargs["params"] == {"limit": 50}  # DEFAULT_LIMIT
        assert "skip" not in kwargs["params"]
        assert "search" not in kwargs["params"]

    def test_redteam_targets_error_logs_requires_target_id(self, mock_client: Client) -> None:
        """Test redteam targets error-logs raises when target_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="target_id"):
            redteam_targets_error_logs_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_sentiment_update_up_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam sentiment update command with an up-vote.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"job_id": "job-1", "up_vote": True}

        result = redteam_sentiment_update_command(mock_client, {"job_id": "job-1", "vote": "up"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamSentiment"
        assert result.outputs["job_id"] == "job-1"
        assert result.outputs["up_vote"] is True

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/sentiment"
        assert kwargs["json_data"] == {"job_id": "job-1", "up_vote": True}
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_sentiment_update_down_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test redteam sentiment update command with a down-vote and empty API echo.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # API echoes an empty body; command should fall back to the requested vote.
        mock_http.return_value = {}

        result = redteam_sentiment_update_command(mock_client, {"job_id": "job-2", "vote": "down"})

        assert result.outputs["job_id"] == "job-2"
        assert result.outputs["down_vote"] is True
        assert result.outputs["up_vote"] is False

        _, kwargs = mock_http.call_args
        assert kwargs["json_data"] == {"job_id": "job-2", "down_vote": True}

    def test_redteam_sentiment_update_requires_vote(self, mock_client: Client) -> None:
        """Test redteam sentiment update command raises for a missing/invalid vote.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="vote"):
            redteam_sentiment_update_command(mock_client, {"job_id": "job-1"})


    @patch.object(Client, "http_request")
    def test_redteam_categories_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-categories-list returns categories keyed by id, with parsed sub-categories.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = [
            {
                "id": "cat-1",
                "display_name": "Jailbreak",
                "description": "Jailbreak attacks",
                "preselect": True,
                "sub_categories": [{"id": "sub-1", "display_name": "DAN", "description": "", "preselect": True, "active": True}],
            }
        ]

        result = redteam_categories_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCategory"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "cat-1"
        assert result.outputs[0]["sub_category_count"] == 1
        assert result.outputs[0]["sub_categories"][0]["id"] == "sub-1"

    @patch.object(Client, "http_request")
    def test_redteam_eula_status_command(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-eula-status returns the acceptance record keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "eula-1",
            "is_accepted": True,
            "accepted_at": "2026-01-01T00:00:00Z",
            "accepted_by_user_id": "user-1",
        }

        result = redteam_eula_status_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamEula"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "eula-1"
        assert result.outputs["is_accepted"] is True

    @patch.object(Client, "http_request")
    def test_redteam_eula_content_command(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-eula-content writes to its own key (not the acceptance record) with no key field.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"content": "EULA legal text"}

        result = redteam_eula_content_command(mock_client, {})

        # Own key, separate from RedTeamEula (the acceptance record) to avoid shape pollution
        assert result.outputs_prefix == "PrismaAIRs.RedTeamEulaContent"
        assert result.outputs_key_field is None
        assert result.outputs["content"] == "EULA legal text"
        assert result.outputs["content_length"] == len("EULA legal text")

    @patch.object(Client, "http_request")
    def test_redteam_eula_accept_command(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-eula-accept fetches content then POSTs it, returning the acceptance record.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # First call (GET content) then second call (POST accept)
        mock_http.side_effect = [
            {"content": "EULA legal text"},
            {
                "uuid": "eula-1",
                "is_accepted": True,
                "accepted_at": "2026-01-01T00:00:00Z",
                "accepted_by_user_id": "user-1",
            },
        ]

        result = redteam_eula_accept_command(mock_client, {})

        assert mock_http.call_count == 2
        get_call, post_call = mock_http.call_args_list
        assert get_call.kwargs["method"] == "GET"
        assert post_call.kwargs["method"] == "POST"
        # The accept request must echo back the fetched EULA content
        assert post_call.kwargs["json_data"]["eula_content"] == "EULA legal text"

        assert result.outputs_prefix == "PrismaAIRs.RedTeamEula"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["is_accepted"] is True

    @patch.object(Client, "http_request")
    def test_redteam_eula_accept_command_no_content(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-eula-accept raises if EULA content cannot be retrieved.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"content": ""}

        with pytest.raises(ValueError, match="Failed to retrieve EULA content"):
            redteam_eula_accept_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-create writes to its own action context, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ps-1", "name": "set-1", "status": "ACTIVE"}

        result = redteam_prompt_sets_create_command(mock_client, {"name": "set-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetCreate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ps-1"

    def test_redteam_prompt_sets_create_requires_name(self, mock_client: Client) -> None:
        """prompt-sets-create raises when name is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="name is required"):
            redteam_prompt_sets_create_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-list returns the list keyed by uuid under its own key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"prompt_sets": [{"uuid": "ps-1", "name": "set-1"}], "total": 1}

        result = redteam_prompt_sets_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSets"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-get writes to its own query context, separate from create/update.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ps-1", "name": "set-1"}

        result = redteam_prompt_sets_get_command(mock_client, {"uuid": "ps-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ps-1"

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-update writes to its own action context, separate from create/get.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ps-1", "name": "renamed"}

        result = redteam_prompt_sets_update_command(mock_client, {"uuid": "ps-1", "name": "renamed"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetUpdate"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_archive_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-archive writes to its own action context (not the registry-credentials bug key).

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ps-1", "name": "set-1", "archive": True, "status": "ARCHIVED"}

        result = redteam_prompt_sets_archive_command(mock_client, {"uuid": "ps-1", "archive": "true"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetArchive"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ps-1"

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_download_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-download returns a fileResult dict (CSV file) for the war room.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = "prompt,goal\nsample,optional"

        result = redteam_prompt_sets_download_command(mock_client, {"uuid": "ps-1"})

        # fileResult returns a dict with the file name and a file entry type
        assert isinstance(result, dict)
        assert result.get("File") == "prompt_set_template_ps-1.csv"
        # CSV requested as plain text
        assert mock_http.call_args.kwargs["resp_type"] == "text"

    @patch.object(Client, "_http_request")
    @patch.object(Client, "get_access_token")
    @patch.object(demisto, "getFilePath")
    def test_redteam_prompt_sets_upload_command(
        self, mock_get_file: Mock, mock_token: Mock, mock_http: Mock, mock_client: Client, tmp_path
    ) -> None:
        """prompt-sets-upload reads a war-room CSV via getFilePath and POSTs it as multipart.

        Args:
            mock_get_file: Mocked demisto.getFilePath.
            mock_token: Mocked Client.get_access_token.
            mock_http: Mocked Client._http_request.
            mock_client: Mock client fixture.
            tmp_path: pytest temp directory.
        """
        csv_file = tmp_path / "prompts.csv"
        csv_file.write_text("prompt,goal\nhello,world")

        mock_get_file.return_value = {"path": str(csv_file), "name": "prompts.csv"}
        mock_token.return_value = "tok"
        mock_http.return_value = {"message": "ok", "status": 200}

        result = redteam_prompt_sets_upload_command(mock_client, {"uuid": "ps-1", "entryID": "42"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetUpload"
        assert result.outputs_key_field == "prompt_set_uuid"
        assert result.outputs["prompt_set_uuid"] == "ps-1"
        # multipart upload uses the files= parameter and the resolved bearer token
        assert "files" in mock_http.call_args.kwargs
        assert mock_http.call_args.kwargs["headers"]["Authorization"] == "Bearer tok"

    def test_redteam_prompt_sets_upload_requires_entry_id(self, mock_client: Client) -> None:
        """prompt-sets-upload raises when entryID is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="entryID is required"):
            redteam_prompt_sets_upload_command(mock_client, {"uuid": "ps-1"})

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_reference_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-reference resolves a single reference object on the mgmt plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "ps-1",
            "name": "jailbreaks",
            "status": "READY",
            "active": True,
            "tsg_id": "tsg-1",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
        }

        result = redteam_prompt_sets_reference_command(mock_client, {"uuid": "ps-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetReference"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ps-1"
        assert result.outputs["name"] == "jailbreaks"
        assert result.outputs["active"] is True

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attack/custom-prompt-set/ps-1/reference"
        assert kwargs["use_redteam_mgmt"] is True

    def test_redteam_prompt_sets_reference_requires_uuid(self, mock_client: Client) -> None:
        """prompt-sets-reference raises when uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="uuid is required"):
            redteam_prompt_sets_reference_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_version_info_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-version-info returns version info and flattens stats for the table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "ps-1",
            "status": "READY",
            "is_latest": True,
            "version": "gen-123",
            "stats": {"total_prompts": 10, "active_prompts": 8, "inactive_prompts": 2},
            "snapshot_created_at": "2026-01-03T00:00:00Z",
        }

        result = redteam_prompt_sets_version_info_command(mock_client, {"uuid": "ps-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetVersionInfo"
        assert result.outputs["uuid"] == "ps-1"
        assert result.outputs["is_latest"] is True
        assert result.outputs["stats"]["total_prompts"] == 10

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attack/custom-prompt-set/ps-1/version-info"
        assert kwargs["params"] is None
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_version_info_with_version(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-version-info passes the version query param when provided.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ps-1", "status": "READY", "is_latest": False, "version": "gen-9"}

        redteam_prompt_sets_version_info_command(mock_client, {"uuid": "ps-1", "version": "gen-9"})

        _, kwargs = mock_http.call_args
        assert kwargs["params"] == {"version": "gen-9"}

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_active_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-active-list normalizes the data array into reference records.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "data": [
                {"uuid": "ps-1", "name": "jailbreaks", "status": "READY", "active": True},
                {"uuid": "ps-2", "name": "pii", "status": "READY", "active": True},
            ]
        }

        result = redteam_prompt_sets_active_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSetActive"
        assert result.outputs_key_field == "uuid"
        assert len(result.outputs) == 2
        assert result.outputs[0]["uuid"] == "ps-1"
        assert result.outputs[1]["name"] == "pii"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attack/active-custom-prompt-sets"
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_active_list_empty(self, mock_http: Mock, mock_client: Client) -> None:
        """prompt-sets-active-list handles a missing/empty data array gracefully.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {}

        result = redteam_prompt_sets_active_list_command(mock_client, {})

        assert result.outputs == []

    @patch.object(Client, "http_request")
    def test_redteam_custom_attack_report_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attack-report-get returns the summary keyed by job_id on the data plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "total_prompts": 100,
            "total_attacks": 80,
            "total_threats": 12,
            "failed_attacks": 0,
            "score": 0.85,
            "asr": 0.15,
        }

        result = redteam_custom_attack_report_get_command(mock_client, {"job_id": "job-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttackReport"
        assert result.outputs_key_field == "job_id"
        assert result.outputs["job_id"] == "job-1"
        assert result.outputs["total_threats"] == 12
        assert result.outputs["asr"] == 0.15

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/custom-attacks/report/job-1"
        assert kwargs["use_redteam_data"] is True

    def test_redteam_custom_attack_report_get_requires_job_id(self, mock_client: Client) -> None:
        """custom-attack-report-get raises when job_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="job_id is required"):
            redteam_custom_attack_report_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_custom_attack_report_prompt_sets_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attack-report-prompt-sets normalizes the prompt_sets array.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "total_prompt_sets": 1,
            "prompt_sets": [
                {
                    "prompt_set_id": "ps-1",
                    "prompt_set_name": "jailbreaks",
                    "total_prompts": 10,
                    "total_attacks": 8,
                    "total_threats": 3,
                    "failed_attacks": 0,
                    "threat_rate": 0.375,
                }
            ],
        }

        result = redteam_custom_attack_report_prompt_sets_command(mock_client, {"job_id": "job-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttackReportPromptSet"
        assert result.outputs_key_field == "prompt_set_id"
        assert len(result.outputs) == 1
        assert result.outputs[0]["prompt_set_name"] == "jailbreaks"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/custom-attacks/report/job-1/prompt-sets"
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_custom_attack_report_prompts_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attack-report-prompts parses the array and passes filter params.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = [
            {"prompt_id": "p-1", "prompt_text": "inject", "threat": True, "asr": 1.0},
            {"prompt_id": "p-2", "prompt_text": "benign", "threat": False},
        ]

        result = redteam_custom_attack_report_prompts_command(
            mock_client,
            {"job_id": "job-1", "prompt_set_id": "ps-1", "is_threat": "true", "limit": "20"},
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttackPrompt"
        assert result.outputs_key_field == "prompt_id"
        assert len(result.outputs) == 2
        assert result.outputs[0]["prompt_id"] == "p-1"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/custom-attacks/report/job-1/prompt-set/ps-1/prompts"
        assert kwargs["params"] == {"limit": "20", "is_threat": "true"}
        assert kwargs["use_redteam_data"] is True

    def test_redteam_custom_attack_report_prompts_requires_prompt_set_id(self, mock_client: Client) -> None:
        """custom-attack-report-prompts raises when prompt_set_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="prompt_set_id is required"):
            redteam_custom_attack_report_prompts_command(mock_client, {"job_id": "job-1"})

    @patch.object(Client, "http_request")
    def test_redteam_custom_attack_report_prompt_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attack-report-prompt-get returns a single prompt keyed by prompt_id.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "prompt_id": "p-1",
            "prompt_text": "inject system prompt",
            "goal": "exfiltrate",
            "threat": True,
        }

        result = redteam_custom_attack_report_prompt_get_command(mock_client, {"job_id": "job-1", "prompt_id": "p-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttackPrompt"
        assert result.outputs["prompt_id"] == "p-1"
        assert result.outputs["goal"] == "exfiltrate"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/custom-attacks/report/job-1/prompt/p-1"
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_custom_attacks_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attacks-list returns attacks + summary and serializes filters.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "pagination": {"total_items": 3},
            "data": [{"uuid": "a-1"}, {"uuid": "a-2"}, {"uuid": "a-3"}],
            "total_attacks": 3,
            "total_threats": 1,
        }

        result = redteam_custom_attacks_list_command(
            mock_client,
            {"job_id": "job-1", "threat": "true", "prompt_set_id": "ps-1", "property_value": "jailbreak", "limit": "20"},
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttack"
        assert result.outputs["job_id"] == "job-1"
        assert len(result.outputs["attacks"]) == 3
        assert result.outputs["summary"]["total_attacks"] == 3
        assert result.outputs["summary"]["total_items"] == 3

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/custom-attacks/job/job-1/list-custom-attacks"
        assert kwargs["params"] == {
            "limit": "20",
            "threat": "true",
            "prompt_set_id": "ps-1",
            "property_value": "jailbreak",
        }
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_custom_attack_outputs_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attack-outputs normalizes the outputs array keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = [
            {
                "uuid": "o-1",
                "tsg_id": "tsg-1",
                "custom_attack_id": "a-1",
                "job_id": "job-1",
                "target_id": "t-1",
                "output": "response text",
                "threat": True,
                "marked_safe": False,
            }
        ]

        result = redteam_custom_attack_outputs_command(mock_client, {"job_id": "job-1", "attack_id": "a-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttackOutput"
        assert result.outputs_key_field == "uuid"
        assert result.outputs[0]["output"] == "response text"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/custom-attacks/job/job-1/attack/a-1/list-outputs"
        assert kwargs["use_redteam_data"] is True

    def test_redteam_custom_attack_outputs_requires_attack_id(self, mock_client: Client) -> None:
        """custom-attack-outputs raises when attack_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="attack_id is required"):
            redteam_custom_attack_outputs_command(mock_client, {"job_id": "job-1"})

    @patch.object(Client, "http_request")
    def test_redteam_custom_attack_property_stats_command(self, mock_http: Mock, mock_client: Client) -> None:
        """custom-attack-property-stats keeps nested values and flattens rows for display.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = [
            {
                "property_name": "category",
                "values": [{"value": "jailbreak", "successful_attack_count": 3, "total_attack_count": 10, "success_rate": 0.3}],
            }
        ]

        result = redteam_custom_attack_property_stats_command(mock_client, {"job_id": "job-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamCustomAttackPropertyStat"
        assert result.outputs_key_field == "property_name"
        assert result.outputs[0]["property_name"] == "category"
        assert result.outputs[0]["values"][0]["value"] == "jailbreak"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/custom-attacks/job/job-1/property-stats"
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_prompts_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompts-create writes to its own action context, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "p-1", "prompt": "hello"}

        result = redteam_prompts_create_command(mock_client, {"prompt_set_uuid": "ps-1", "prompt": "hello"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptCreate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "p-1"

    def test_redteam_prompts_create_requires_prompt(self, mock_client: Client) -> None:
        """prompts-create raises when the prompt text is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="prompt is required"):
            redteam_prompts_create_command(mock_client, {"prompt_set_uuid": "ps-1"})

    @patch.object(Client, "http_request")
    def test_redteam_prompts_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompts-list returns the prompt list keyed by uuid under its own key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"prompts": [{"uuid": "p-1", "prompt": "hello"}], "total": 1}

        result = redteam_prompts_list_command(mock_client, {"prompt_set_uuid": "ps-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPrompts"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_redteam_prompts_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompts-get writes to its own query context, separate from create/update.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "p-1", "prompt": "hello"}

        result = redteam_prompts_get_command(mock_client, {"prompt_set_uuid": "ps-1", "prompt_uuid": "p-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "p-1"

    @patch.object(Client, "http_request")
    def test_redteam_prompts_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompts-update writes to its own action context, separate from create/get.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "p-1", "prompt": "updated"}

        result = redteam_prompts_update_command(
            mock_client, {"prompt_set_uuid": "ps-1", "prompt_uuid": "p-1", "prompt": "updated"}
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptUpdate"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_redteam_prompts_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """prompts-delete writes to its own context, keyed by prompt_uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = None

        result = redteam_prompts_delete_command(mock_client, {"prompt_set_uuid": "ps-1", "prompt_uuid": "p-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptDeleted"
        assert result.outputs_key_field == "prompt_uuid"
        assert result.outputs["prompt_uuid"] == "p-1"

    def test_redteam_prompts_delete_requires_prompt_uuid(self, mock_client: Client) -> None:
        """prompts-delete raises when prompt_uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="prompt_uuid is required"):
            redteam_prompts_delete_command(mock_client, {"prompt_set_uuid": "ps-1"})

    @patch.object(Client, "http_request")
    def test_redteam_scan_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """scan-create writes to its own action context, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "job-1", "name": "scan-1", "status": "RUNNING"}

        result = redteam_scan_create_command(mock_client, {"name": "scan-1", "target_uuid": "t-1", "scan_type": "STATIC"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamScanCreate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "job-1"

    @patch.object(Client, "http_request")
    def test_redteam_scans_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """scans-list returns the scan list under the base RedTeamScan key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"jobs": [{"uuid": "job-1", "name": "scan-1", "status": "DONE"}]}

        result = redteam_scans_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamScan"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_redteam_scan_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """scan-get writes to its own query context, separate from create/list.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "job-1", "name": "scan-1", "status": "DONE"}

        result = redteam_scan_get_command(mock_client, {"job_id": "job-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamScanGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "job-1"

    @patch.object(Client, "http_request")
    def test_redteam_scan_abort_command(self, mock_http: Mock, mock_client: Client) -> None:
        """scan-abort writes its own context keyed by job_id and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"job_id": "job-1", "message": "Scan aborted"}

        result = redteam_scan_abort_command(mock_client, {"job_id": "job-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamScanAbort"
        assert result.outputs_key_field == "job_id"
        assert result.outputs["job_id"] == "job-1"
        # human-readable table (not a bullet list)
        assert "|" in result.readable_output

    @patch.object(Client, "http_request")
    def test_redteam_report_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """report-get returns the report keyed by job_id.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "score": 42,
            "asr": 0.42,
            "report_summary": "summary",
            "severity_report": {"total_attacks": 10, "successful": 4, "failed": 6, "severity_stats": []},
        }

        result = redteam_report_get_command(mock_client, {"job_id": "job-1", "job_type": "STATIC"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamReport"
        assert result.outputs_key_field == "job_id"
        assert result.outputs["job_id"] == "job-1"

    @patch.object(Client, "http_request")
    def test_redteam_registry_credentials_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """registry-credentials-get is a singleton (no key field) and renders a table with a truncated token.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"token": "abcdefgh12345678ZYXWVUTS", "expiry": "2026-01-01T00:00:00Z"}

        result = redteam_registry_credentials_get_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamRegistryCredentials"
        assert result.outputs_key_field is None
        # full token preserved in context for playbook use
        assert result.outputs["token"] == "abcdefgh12345678ZYXWVUTS"
        # token is truncated in the human-readable table (not shown in full)
        assert "abcdefgh12345678ZYXWVUTS" not in result.readable_output
        assert "|" in result.readable_output

    @patch.object(Client, "http_request")
    def test_redteam_targets_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-create writes to its own action context, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "t-1", "name": "target-1", "status": "ACTIVE"}

        result = redteam_targets_create_command(mock_client, {"name": "target-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetCreate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "t-1"

    def test_redteam_targets_create_requires_name(self, mock_client: Client) -> None:
        """targets-create raises when name is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="name is required"):
            redteam_targets_create_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_targets_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-list returns the target list under the base RedTeamTarget key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"targets": [{"uuid": "t-1", "name": "target-1"}]}

        result = redteam_targets_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTarget"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_redteam_targets_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-get writes to its own query context, separate from create/list.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "t-1", "name": "target-1"}

        result = redteam_targets_get_command(mock_client, {"uuid": "t-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "t-1"

    @patch.object(Client, "http_request")
    def test_redteam_targets_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-delete writes its own context keyed by uuid and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "Target deleted successfully", "status": 200}

        result = redteam_targets_delete_command(mock_client, {"uuid": "t-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetDelete"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "t-1"
        assert "|" in result.readable_output

    @patch.object(Client, "http_request")
    def test_redteam_targets_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-update writes to its own action context, separate from list/get.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "t-1", "name": "renamed", "status": "ACTIVE"}

        result = redteam_targets_update_command(mock_client, {"uuid": "t-1", "name": "renamed"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetUpdate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "t-1"

    @patch.object(Client, "http_request")
    def test_redteam_targets_probe_command(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-probe writes to its own action context, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "t-1", "name": "target-1", "status": "PROBED"}

        result = redteam_targets_probe_command(mock_client, {"name": "target-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetProbe"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "t-1"

    @patch.object(Client, "http_request")
    def test_redteam_instances_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """instances-create posts required fields to the mgmt plane, keyed by tenant_id.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "is_success": True}

        result = redteam_instances_create_command(
            mock_client, {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "region": "us"}
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamInstanceCreate"
        assert result.outputs_key_field == "tenant_id"
        assert result.outputs["tenant_id"] == "tn-1"
        # Verify it targets the mgmt plane instances endpoint via POST
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/instances"
        assert kwargs["use_redteam_mgmt"] is True
        assert kwargs["json_data"]["region"] == "us"

    def test_redteam_instances_create_requires_fields(self, mock_client: Client) -> None:
        """instances-create raises when a required field is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="tsg_id is required"):
            redteam_instances_create_command(mock_client, {})
        with pytest.raises(ValueError, match="tenant_id is required"):
            redteam_instances_create_command(mock_client, {"tsg_id": "tsg-1"})
        with pytest.raises(ValueError, match="app_id is required"):
            redteam_instances_create_command(mock_client, {"tsg_id": "tsg-1", "tenant_id": "tn-1"})
        with pytest.raises(ValueError, match="region is required"):
            redteam_instances_create_command(mock_client, {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1"})

    @patch.object(Client, "http_request")
    def test_redteam_instances_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """instances-get reads a single instance from the mgmt plane by tenant_id.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "tsg_id": "tsg-1",
            "tenant_id": "tn-1",
            "app_id": "app-1",
            "region": "us",
            "tenant_instance_name": "inst-1",
        }

        result = redteam_instances_get_command(mock_client, {"tenant_id": "tn-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamInstanceGet"
        assert result.outputs_key_field == "tenant_id"
        assert result.outputs["tenant_id"] == "tn-1"
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/instances/tn-1"
        assert kwargs["use_redteam_mgmt"] is True

    def test_redteam_instances_get_requires_tenant_id(self, mock_client: Client) -> None:
        """instances-get raises when tenant_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="tenant_id is required"):
            redteam_instances_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_instances_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """instances-update fetches the current instance then PUTs a merged body preserving required fields.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.side_effect = [
            # GET current instance
            {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "region": "us"},
            # PUT response
            {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "is_success": True},
        ]

        result = redteam_instances_update_command(mock_client, {"tenant_id": "tn-1", "tenant_instance_name": "renamed"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamInstanceUpdate"
        assert result.outputs_key_field == "tenant_id"
        assert result.outputs["tenant_id"] == "tn-1"
        # Second call is the PUT; it must preserve schema-required fields from GET
        put_args, put_kwargs = mock_http.call_args_list[1]
        assert put_kwargs["method"] == "PUT"
        assert put_kwargs["url_suffix"] == "/v1/instances/tn-1"
        assert put_kwargs["json_data"]["tsg_id"] == "tsg-1"
        assert put_kwargs["json_data"]["app_id"] == "app-1"
        assert put_kwargs["json_data"]["region"] == "us"
        assert put_kwargs["json_data"]["tenant_instance_name"] == "renamed"

    def test_redteam_instances_update_requires_tenant_id(self, mock_client: Client) -> None:
        """instances-update raises when tenant_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="tenant_id is required"):
            redteam_instances_update_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_instances_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """instances-delete removes an instance from the mgmt plane and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "is_success": True}

        result = redteam_instances_delete_command(mock_client, {"tenant_id": "tn-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamInstanceDelete"
        assert result.outputs_key_field == "tenant_id"
        assert result.outputs["tenant_id"] == "tn-1"
        assert "|" in result.readable_output
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "DELETE"
        assert kwargs["url_suffix"] == "/v1/instances/tn-1"
        assert kwargs["use_redteam_mgmt"] is True

    def test_redteam_instances_delete_requires_tenant_id(self, mock_client: Client) -> None:
        """instances-delete raises when tenant_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="tenant_id is required"):
            redteam_instances_delete_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_devices_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-create resolves the instance block via GET then POSTs a single device.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.side_effect = [
            # GET parent instance to resolve app_id/region/tsg_id
            {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "region": "us"},
            # POST devices response
            {"devices": [{"serial_number": "SN-0001", "status": "CREATED"}]},
        ]

        result = redteam_devices_create_command(mock_client, {"tenant_id": "tn-1", "serial_number": "SN-0001"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamDeviceCreate"
        assert result.outputs_key_field == "serial_number"
        assert result.outputs[0]["serial_number"] == "SN-0001"
        # Second call is the POST to the devices sub-resource with the resolved instance block
        _, post_kwargs = mock_http.call_args_list[1]
        assert post_kwargs["method"] == "POST"
        assert post_kwargs["url_suffix"] == "/v1/instances/tn-1/devices"
        assert post_kwargs["use_redteam_mgmt"] is True
        assert post_kwargs["json_data"]["instance"] == {
            "app_id": "app-1",
            "region": "us",
            "tenant_id": "tn-1",
            "tsg_id": "tsg-1",
        }
        assert post_kwargs["json_data"]["devices"] == [{"serial_number": "SN-0001"}]

    @patch.object(Client, "http_request")
    def test_redteam_devices_create_explicit_instance_skips_get(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-create does not GET the parent when all instance fields are provided.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"devices": [{"serial_number": "SN-0001", "status": "CREATED"}]}

        redteam_devices_create_command(
            mock_client,
            {"tenant_id": "tn-1", "serial_number": "SN-0001", "app_id": "app-1", "region": "us", "tsg_id": "tsg-1"},
        )

        # Only the POST should fire — no resolving GET.
        assert mock_http.call_count == 1
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"

    @patch.object(Client, "http_request")
    def test_redteam_devices_create_batch_json(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-create accepts a JSON batch and passes it through.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"devices": [{"serial_number": "SN-1", "status": "CREATED"}]}

        redteam_devices_create_command(
            mock_client,
            {
                "tenant_id": "tn-1",
                "app_id": "app-1",
                "region": "us",
                "tsg_id": "tsg-1",
                "devices": '[{"serial_number": "SN-1"}, {"serial_number": "SN-2"}]',
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["json_data"]["devices"] == [{"serial_number": "SN-1"}, {"serial_number": "SN-2"}]

    def test_redteam_devices_create_requires_tenant_id(self, mock_client: Client) -> None:
        """devices-create raises when tenant_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="tenant_id is required"):
            redteam_devices_create_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_devices_create_requires_a_device(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-create raises when neither serial_number nor devices is provided.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"tsg_id": "tsg-1", "tenant_id": "tn-1", "app_id": "app-1", "region": "us"}

        with pytest.raises(ValueError, match="Either serial_number or devices"):
            redteam_devices_create_command(mock_client, {"tenant_id": "tn-1"})

    @patch.object(Client, "http_request")
    def test_redteam_devices_create_batch_limit(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-create raises when the batch exceeds 5 devices.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        six = json.dumps([{"serial_number": f"SN-{i}"} for i in range(6)])
        with pytest.raises(ValueError, match="maximum of 5 devices"):
            redteam_devices_create_command(
                mock_client, {"tenant_id": "tn-1", "app_id": "a", "region": "r", "tsg_id": "t", "devices": six}
            )

    @patch.object(Client, "http_request")
    def test_redteam_devices_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-update PATCHes the devices sub-resource.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"devices": [{"serial_number": "SN-0001", "status": "UPDATED"}]}

        result = redteam_devices_update_command(
            mock_client,
            {"tenant_id": "tn-1", "serial_number": "SN-0001", "device_name": "renamed", "app_id": "a", "region": "r", "tsg_id": "t"},
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamDeviceUpdate"
        assert result.outputs_key_field == "serial_number"
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PATCH"
        assert kwargs["url_suffix"] == "/v1/instances/tn-1/devices"
        assert kwargs["json_data"]["devices"][0]["device_name"] == "renamed"

    @patch.object(Client, "http_request")
    def test_redteam_devices_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """devices-delete sends serial_numbers as a comma-separated query param.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "devices": [
                {"serial_number": "SN-1", "status": "DELETED"},
                {"serial_number": "SN-2", "status": "DELETED"},
            ]
        }

        result = redteam_devices_delete_command(mock_client, {"tenant_id": "tn-1", "serial_numbers": "SN-1,SN-2"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamDeviceDelete"
        assert result.outputs_key_field == "serial_number"
        assert "|" in result.readable_output
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "DELETE"
        assert kwargs["url_suffix"] == "/v1/instances/tn-1/devices"
        assert kwargs["params"] == {"serial_numbers": "SN-1,SN-2"}
        assert kwargs["use_redteam_mgmt"] is True

    def test_redteam_devices_delete_requires_tenant_id(self, mock_client: Client) -> None:
        """devices-delete raises when tenant_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="tenant_id is required"):
            redteam_devices_delete_command(mock_client, {"serial_numbers": "SN-1"})

    def test_redteam_devices_delete_requires_serial_numbers(self, mock_client: Client) -> None:
        """devices-delete raises when serial_numbers is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="serial_numbers is required"):
            redteam_devices_delete_command(mock_client, {"tenant_id": "tn-1"})

    @patch.object(Client, "http_request")
    def test_redteam_adapters_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-list parses the data envelope and hits the mgmt plane, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "pagination": {"limit": 50, "skip": 0},
            "data": [
                {"uuid": "ad-1", "name": "keycloak", "status": "ACTIVE", "target_count": 2},
                {"uuid": "ad-2", "name": "draft-agent", "status": "DRAFT"},
            ],
        }

        result = redteam_adapters_list_command(mock_client, {"limit": "10", "skip": "5", "search": "agent"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamAdapter"
        assert result.outputs_key_field == "uuid"
        assert [a["uuid"] for a in result.outputs] == ["ad-1", "ad-2"]
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/adapters"
        assert kwargs["use_redteam_mgmt"] is True
        assert kwargs["params"] == {"limit": 10, "skip": 5, "search": "agent"}

    @patch.object(Client, "http_request")
    def test_redteam_adapters_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-get reads a single adapter by uuid from the mgmt plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "ad-1",
            "name": "keycloak",
            "status": "ACTIVE",
            "script_b64": "cHJpbnQoJ2hpJyk=",
            "variables": [{"key": "endpoint", "value": "http://svc", "type": "VAR"}],
        }

        result = redteam_adapters_get_command(mock_client, {"uuid": "ad-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamAdapter"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ad-1"
        assert result.outputs["script_b64"] == "cHJpbnQoJ2hpJyk="
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/adapters/ad-1"
        assert kwargs["use_redteam_mgmt"] is True

    def test_redteam_adapters_get_requires_uuid(self, mock_client: Client) -> None:
        """adapters-get raises when uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="uuid is required"):
            redteam_adapters_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_adapters_create_encodes_plain_script(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-create base64-encodes a plain script, passes validate param, and posts to mgmt plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # Only the create POST is called: validate=false skips the channel preflight.
        mock_http.return_value = {"uuid": "ad-9", "name": "new", "status": "DRAFT"}

        result = redteam_adapters_create_command(
            mock_client,
            {
                "name": "new",
                "prompt": "Hello",
                "script": "print('hi')",
                "variables": '[{"key":"endpoint","value":"http://svc","type":"VAR"}]',
                "validate": "false",
            },
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamAdapter"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ad-9"
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/adapters"
        assert kwargs["use_redteam_mgmt"] is True
        assert kwargs["params"] == {"validate": "false"}
        # Plain script is base64-encoded for us.
        assert kwargs["json_data"]["script_b64"] == "cHJpbnQoJ2hpJyk="
        assert kwargs["json_data"]["variables"][0]["key"] == "endpoint"

    @patch.object(Client, "http_request")
    def test_redteam_adapters_create_validate_runs_channel_preflight(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-create with validate=true runs the ONLINE channel preflight before creating.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.side_effect = [
            # channel preflight GET (data plane)
            {"uuid": "ch-1", "status": "ONLINE"},
            # create POST
            {"uuid": "ad-1", "name": "new", "status": "ACTIVE"},
        ]

        result = redteam_adapters_create_command(
            mock_client,
            {"name": "new", "prompt": "Hello", "script_b64": "abc", "network_broker_channel_uuid": "ch-1"},
        )

        assert result.outputs["status"] == "ACTIVE"
        # First call is the data-plane channel preflight; second is the mgmt-plane create.
        first, second = mock_http.call_args_list
        assert first.kwargs["url_suffix"] == "/network-broker/v1/channels/ch-1"
        assert first.kwargs["use_redteam_data"] is True
        assert second.kwargs["method"] == "POST"
        assert second.kwargs["params"] == {"validate": "true"}

    @patch.object(Client, "http_request")
    def test_redteam_adapters_create_offline_channel_raises(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-create raises a clear error when the broker channel is not ONLINE.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ch-1", "status": "OFFLINE"}

        with pytest.raises(ValueError, match="not ONLINE"):
            redteam_adapters_create_command(
                mock_client,
                {"name": "new", "prompt": "Hello", "script_b64": "abc", "network_broker_channel_uuid": "ch-1"},
            )

    def test_redteam_adapters_create_requires_script(self, mock_client: Client) -> None:
        """adapters-create raises when neither script nor script_b64 is provided.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="script"):
            redteam_adapters_create_command(mock_client, {"name": "new", "prompt": "Hello", "validate": "false"})

    def test_redteam_adapters_create_rejects_bad_variable(self, mock_client: Client) -> None:
        """adapters-create rejects a variable missing its type.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="key.*type|type"):
            redteam_adapters_create_command(
                mock_client,
                {
                    "name": "new",
                    "prompt": "Hello",
                    "script_b64": "abc",
                    "validate": "false",
                    "variables": '[{"key":"endpoint","value":"x"}]',
                },
            )

    @patch.object(Client, "http_request")
    def test_redteam_adapters_update_merges_and_preserves_secrets(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-update GETs the current record, preserves fields, and resends stored secrets as null.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.side_effect = [
            # GET current adapter
            {
                "uuid": "ad-1",
                "name": "keycloak",
                "status": "ACTIVE",
                "script_b64": "b3JpZw==",
                "network_broker_channel_uuid": "ch-1",
                "variables": [
                    {"key": "endpoint", "value": "http://svc", "type": "VAR"},
                    {"key": "api_key", "value": "**********", "type": "SECRET", "is_redacted": True},
                ],
            },
            # channel preflight GET
            {"uuid": "ch-1", "status": "ONLINE"},
            # PUT response
            {"uuid": "ad-1", "name": "keycloak", "status": "ACTIVE"},
        ]

        result = redteam_adapters_update_command(
            mock_client, {"uuid": "ad-1", "prompt": "Hello", "description": "staging"}
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamAdapter"
        put_call = mock_http.call_args_list[-1]
        assert put_call.kwargs["method"] == "PUT"
        assert put_call.kwargs["url_suffix"] == "/v1/adapters/ad-1"
        body = put_call.kwargs["json_data"]
        # Required fields backfilled from the current record.
        assert body["name"] == "keycloak"
        assert body["script_b64"] == "b3JpZw=="
        assert body["prompt"] == "Hello"
        # Stored variables resent; the redacted secret is sent back as null to keep its value.
        secret = next(v for v in body["variables"] if v["key"] == "api_key")
        assert secret["value"] is None
        endpoint = next(v for v in body["variables"] if v["key"] == "endpoint")
        assert endpoint["value"] == "http://svc"

    def test_redteam_adapters_update_requires_prompt(self, mock_client: Client) -> None:
        """adapters-update raises when prompt is missing (never stored server-side).

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="prompt is required"):
            redteam_adapters_update_command(mock_client, {"uuid": "ad-1"})

    def test_redteam_adapters_update_requires_uuid(self, mock_client: Client) -> None:
        """adapters-update raises when uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="uuid is required"):
            redteam_adapters_update_command(mock_client, {"prompt": "Hello"})

    @patch.object(Client, "http_request")
    def test_redteam_adapters_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-delete issues a DELETE to the mgmt plane, keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"is_success": True}

        result = redteam_adapters_delete_command(mock_client, {"uuid": "ad-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamAdapterDelete"
        assert result.outputs_key_field == "uuid"
        assert result.outputs == {"uuid": "ad-1", "is_success": True}
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "DELETE"
        assert kwargs["url_suffix"] == "/v1/adapters/ad-1"
        assert kwargs["use_redteam_mgmt"] is True

    @patch.object(Client, "http_request")
    def test_redteam_adapters_delete_empty_body(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-delete defaults is_success to True when the API returns an empty body.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = None

        result = redteam_adapters_delete_command(mock_client, {"uuid": "ad-1"})

        assert result.outputs == {"uuid": "ad-1", "is_success": True}

    def test_redteam_adapters_delete_requires_uuid(self, mock_client: Client) -> None:
        """adapters-delete raises when uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="uuid is required"):
            redteam_adapters_delete_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_adapters_validate_command(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-validate runs the preflight then POSTs to the validate endpoint (no name field).

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.side_effect = [
            # channel preflight GET
            {"uuid": "ch-1", "status": "ONLINE"},
            # validate POST
            {"validated": True, "stdout": "ok", "stderr": None},
        ]

        result = redteam_adapters_validate_command(
            mock_client,
            {"network_broker_channel_uuid": "ch-1", "prompt": "Hello", "script_b64": "abc", "adapter_uuid": "ad-1"},
        )

        assert result.outputs_prefix == "PrismaAIRs.RedTeamAdapterValidation"
        assert result.outputs["validated"] is True
        validate_call = mock_http.call_args_list[-1]
        assert validate_call.kwargs["method"] == "POST"
        assert validate_call.kwargs["url_suffix"] == "/v1/adapters/validate"
        assert validate_call.kwargs["use_redteam_mgmt"] is True
        body = validate_call.kwargs["json_data"]
        assert "name" not in body
        assert body["adapter_uuid"] == "ad-1"

    @patch.object(Client, "http_request")
    def test_redteam_adapters_validate_reports_failure(self, mock_http: Mock, mock_client: Client) -> None:
        """adapters-validate surfaces validated=False and the stderr/traceback outcome.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.side_effect = [
            {"uuid": "ch-1", "status": "ONLINE"},
            {"validated": False, "stderr": "boom", "traceback": "Traceback..."},
        ]

        result = redteam_adapters_validate_command(
            mock_client, {"network_broker_channel_uuid": "ch-1", "prompt": "Hello", "script_b64": "abc"}
        )

        assert result.outputs["validated"] is False
        assert result.outputs["stderr"] == "boom"
        assert result.outputs["traceback"] == "Traceback..."

    def test_redteam_adapters_validate_requires_channel(self, mock_client: Client) -> None:
        """adapters-validate raises when network_broker_channel_uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="network_broker_channel_uuid is required"):
            redteam_adapters_validate_command(mock_client, {"prompt": "Hello", "script_b64": "abc"})

    @patch.object(Client, "http_request")
    def test_redteam_network_channels_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """network-channels-list parses the data envelope, serializes status list, and hits the data-plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "pagination": {"total_items": 1},
            "data": [{"uuid": "ch-1", "name": "prod-relay", "status": "ONLINE"}],
        }

        result = redteam_network_channels_list_command(mock_client, {"status": "ONLINE,DRAFT", "limit": "10", "skip": "5"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamNetworkChannel"
        assert result.outputs_key_field == "uuid"
        assert result.outputs[0]["uuid"] == "ch-1"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/network-broker/v1/channels"
        assert kwargs["use_redteam_data"] is True
        assert kwargs["params"]["status"] == ["ONLINE", "DRAFT"]
        assert kwargs["params"]["limit"] == 10
        assert kwargs["params"]["skip"] == 5

    @patch.object(Client, "http_request")
    def test_redteam_network_channels_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """network-channels-create posts name/description and writes to the create context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ch-1", "name": "prod-relay", "status": "DRAFT"}

        result = redteam_network_channels_create_command(mock_client, {"name": "prod-relay", "description": "Production broker"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamNetworkChannelCreate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ch-1"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/network-broker/v1/channels"
        assert kwargs["json_data"] == {"name": "prod-relay", "description": "Production broker"}
        assert kwargs["use_redteam_data"] is True

    def test_redteam_network_channels_create_command_requires_name(self, mock_client: Client) -> None:
        """network-channels-create raises when name is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="name is required"):
            redteam_network_channels_create_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_network_channels_stats_command(self, mock_http: Mock, mock_client: Client) -> None:
        """network-channels-stats maps the stats fields and hits the /stats sub-path.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "network_channels_server_domain": "broker.example.com",
            "online_channels": 3,
            "total_channels": 5,
            "client_version": "1.4.0",
        }

        result = redteam_network_channels_stats_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamNetworkChannelStats"
        assert result.outputs["online_channels"] == 3
        assert result.outputs["client_version"] == "1.4.0"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/network-broker/v1/channels/stats"
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_network_channels_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """network-channels-get fetches a single channel by UUID.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ch-1", "name": "prod-relay", "status": "ONLINE"}

        result = redteam_network_channels_get_command(mock_client, {"channel_id": "ch-1"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamNetworkChannel"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ch-1"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/network-broker/v1/channels/ch-1"
        assert kwargs["use_redteam_data"] is True

    def test_redteam_network_channels_get_command_requires_channel_id(self, mock_client: Client) -> None:
        """network-channels-get raises when channel_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="channel_id is required"):
            redteam_network_channels_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_network_channels_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """network-channels-update PATCHes only provided fields to the update context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "ch-1", "name": "prod-relay", "description": "Updated", "status": "ONLINE"}

        result = redteam_network_channels_update_command(mock_client, {"channel_id": "ch-1", "description": "Updated"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamNetworkChannelUpdate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ch-1"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PATCH"
        assert kwargs["url_suffix"] == "/network-broker/v1/channels/ch-1"
        assert kwargs["json_data"] == {"description": "Updated"}
        assert kwargs["use_redteam_data"] is True

    def test_redteam_network_channels_update_command_requires_channel_id(self, mock_client: Client) -> None:
        """network-channels-update raises when channel_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="channel_id is required"):
            redteam_network_channels_update_command(mock_client, {"name": "x"})

    def test_redteam_network_channels_update_command_requires_a_field(self, mock_client: Client) -> None:
        """network-channels-update raises when no updatable field is provided.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="At least one of name or description is required"):
            redteam_network_channels_update_command(mock_client, {"channel_id": "ch-1"})

    @patch.object(Client, "http_request")
    def test_redteam_languages_list_command_data_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """languages-list defaults to the data plane and keeps metadata with the language list.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "multilingual_enabled": True,
            "supported_job_types": ["STATIC", "DYNAMIC", "CUSTOM"],
            "languages": [{"code": "en", "name": "English"}, {"code": "es", "name": "Spanish"}],
        }

        result = redteam_languages_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamLanguages"
        assert result.outputs["multilingual_enabled"] is True
        assert result.outputs["supported_job_types"] == ["STATIC", "DYNAMIC", "CUSTOM"]
        assert result.outputs["plane"] == "data"
        assert result.outputs["languages"] == [{"code": "en", "name": "English"}, {"code": "es", "name": "Spanish"}]

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/languages"
        assert kwargs["use_redteam_data"] is True

    @patch.object(Client, "http_request")
    def test_redteam_languages_list_command_management_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """languages-list with use_management=true routes to the management plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "multilingual_enabled": True,
            "supported_job_types": ["STATIC"],
            "languages": [{"code": "en", "name": "English"}],
        }

        result = redteam_languages_list_command(mock_client, {"use_management": "true"})

        assert result.outputs_prefix == "PrismaAIRs.RedTeamLanguages"
        assert result.outputs["plane"] == "management"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/languages"
        assert kwargs["use_redteam_mgmt"] is True


    # ----- DLP patterns: create/patch/replace (coverage) -----


    # ----- Red Team: scan-create + list commands (coverage) -----
    @patch.object(Client, "http_request")
    def test_redteam_scan_create_static_command(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-scan-create (STATIC) builds the job body and writes RedTeamScanCreate.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "job-1", "name": "scan", "job_type": "STATIC", "status": "PENDING"}

        result = redteam_scan_create_command(
            mock_client, {"name": "scan", "target_uuid": "t-1", "job_type": "STATIC", "categories": '{"jailbreak":{}}'}
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        body = kwargs["json_data"]
        assert body["target"] == {"uuid": "t-1"}
        assert body["job_type"] == "STATIC"
        assert body["job_metadata"]["categories"] == {"jailbreak": {}}
        assert result.outputs_prefix == "PrismaAIRs.RedTeamScanCreate"
        assert result.outputs["uuid"] == "job-1"

    @patch.object(Client, "http_request")
    def test_redteam_scan_create_dynamic_command(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-scan-create (DYNAMIC) sets stream params + attack_goals.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "job-2", "job_type": "DYNAMIC", "status": "PENDING"}

        result = redteam_scan_create_command(
            mock_client,
            {
                "name": "dyn",
                "target_uuid": "t-1",
                "job_type": "DYNAMIC",
                "stream_breadth": "3",
                "stream_depth": "5",
                "attack_goals": '["leak secrets"]',
            },
        )

        body = mock_http.call_args.kwargs["json_data"]
        assert body["job_metadata"]["stream_breadth"] == 3
        assert body["job_metadata"]["stream_depth"] == 5
        assert body["job_metadata"]["attack_goals"] == ["leak secrets"]
        assert result.outputs_prefix == "PrismaAIRs.RedTeamScanCreate"

    def test_redteam_scan_create_validates(self, mock_client: Client) -> None:
        """redteam-scan-create validates name/target and job_type.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="name is required"):
            redteam_scan_create_command(mock_client, {})
        with pytest.raises(ValueError, match="target_uuid is required"):
            redteam_scan_create_command(mock_client, {"name": "x"})
        with pytest.raises(ValueError, match="job_type must be one of"):
            redteam_scan_create_command(mock_client, {"name": "x", "target_uuid": "t", "job_type": "BOGUS"})

    @patch.object(Client, "http_request")
    def test_redteam_prompts_list_full(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-prompts-list parses data + writes RedTeamPrompts.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "pagination": {"total_items": 1},
            "data": [{"uuid": "pr-1", "prompt": "hi", "status": "active", "active": True, "goal": "g"}],
        }

        result = redteam_prompts_list_command(
            mock_client,
            {"prompt_set_uuid": "ps-1", "limit": "10", "skip": "0", "search": "hi", "status": "active", "active": "true"},
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert "ps-1/list-custom-prompts" in kwargs["url_suffix"]
        assert kwargs["params"]["active"] == "true"
        assert result.outputs_prefix == "PrismaAIRs.RedTeamPrompts"
        assert result.outputs[0]["uuid"] == "pr-1"

    def test_redteam_prompts_list_requires_set(self, mock_client: Client) -> None:
        """redteam-prompts-list requires prompt_set_uuid.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="prompt_set_uuid is required"):
            redteam_prompts_list_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_redteam_prompt_sets_list_full(self, mock_http: Mock, mock_client: Client) -> None:
        """redteam-prompt-sets-list parses data + writes RedTeamPromptSets.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "pagination": {"total_items": 1},
            "data": [{"uuid": "ps-1", "name": "set", "active": True, "archive": False, "status": "active", "description": "d"}],
        }

        result = redteam_prompt_sets_list_command(
            mock_client, {"limit": "10", "skip": "0", "search": "set", "status": "active", "active": "true", "archive": "false"}
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert "list-custom-prompt-sets" in kwargs["url_suffix"]
        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptSets"
        assert result.outputs[0]["uuid"] == "ps-1"

    # ----- Security profiles: get/create/update (coverage) -----


    # ----- Custom topics: create/get/update (coverage) -----


    # ----- model-security scans-get + DLP patch + prompts-create (coverage) -----


    @patch.object(Client, "http_request")
    def test_redteam_prompts_create_full(self, mock_http: Mock, mock_client: Client) -> None:
        """prompts-create posts a prompt and writes RedTeamPromptCreate.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "pr-1", "prompt": "hi", "status": "active"}

        result = redteam_prompts_create_command(
            mock_client, {"prompt_set_uuid": "ps-1", "prompt": "hi", "user_defined_goal": "g"}
        )

        assert mock_http.call_args.kwargs["method"] == "POST"
        assert result.outputs_prefix == "PrismaAIRs.RedTeamPromptCreate"
        assert result.outputs["uuid"] == "pr-1"

    # ----- runtime-scan + probe + labels-delete + filtering-replace (coverage) -----


    @patch.object(Client, "http_request")
    def test_redteam_targets_probe_full(self, mock_http: Mock, mock_client: Client) -> None:
        """targets-probe builds the probe body (optional fields) and writes RedTeamTargetProbe.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "t-1", "name": "tgt", "status": "ok", "validated": True}

        result = redteam_targets_probe_command(
            mock_client,
            {
                "name": "tgt",
                "uuid": "t-1",
                "description": "d",
                "target_type": "OPEN_AI",
                "connection_type": "api",
                "api_endpoint_type": "chat",
                "response_mode": "sync",
                "connection_params": '{"model":"gpt-4"}',
                "probe_fields": "multi_turn,rate_limit",
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        body = kwargs["json_data"]
        assert body["connection_params"] == {"model": "gpt-4"}
        assert body["probe_fields"] == ["multi_turn", "rate_limit"]
        assert result.outputs_prefix == "PrismaAIRs.RedTeamTargetProbe"

    def test_redteam_targets_probe_requires_name(self, mock_client: Client) -> None:
        """targets-probe requires name.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="name is required for target probe"):
            redteam_targets_probe_command(mock_client, {})


    # ----- model-security: rules -----
    # ----- model-security: scans core -----
    # ----- model-security: labels -----
    # ----- model-security: groups CRUD -----
    # ----- model-security: rule-instances list -----
