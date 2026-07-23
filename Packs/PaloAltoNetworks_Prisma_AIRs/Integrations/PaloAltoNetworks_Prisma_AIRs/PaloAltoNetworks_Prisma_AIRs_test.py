import json
import pytest
import demistomock as demisto
from unittest.mock import Mock, patch
from PaloAltoNetworks_Prisma_AIRs import (
    Client,
    test_module as run_test_module,
    runtime_scan_command,
    runtime_bulk_scan_command,
    runtime_api_keys_list_command,
    runtime_api_keys_create_command,
    runtime_api_keys_regenerate_command,
    runtime_api_keys_delete_command,
    runtime_profiles_list_command,
    runtime_profiles_get_command,
    runtime_profiles_create_command,
    runtime_profiles_update_command,
    runtime_profiles_delete_command,
    runtime_customer_apps_list_command,
    runtime_customer_apps_get_command,
    runtime_customer_apps_update_command,
    runtime_customer_apps_consumption_command,
    runtime_customer_apps_violations_command,
    runtime_customer_apps_delete_command,
    runtime_deployment_profiles_list_command,
    runtime_dlp_profiles_list_command,
    runtime_dlp_profiles_delete_command,
    runtime_dlp_profiles_get_command,
    runtime_dlp_profiles_create_command,
    runtime_dlp_profiles_patch_command,
    runtime_dlp_profiles_replace_command,
    runtime_dlp_dictionaries_list_command,
    runtime_dlp_dictionaries_get_command,
    runtime_dlp_dictionaries_create_command,
    runtime_dlp_dictionaries_patch_command,
    runtime_dlp_dictionaries_replace_command,
    runtime_dlp_dictionaries_delete_command,
    runtime_dlp_patterns_list_command,
    runtime_dlp_patterns_get_command,
    runtime_dlp_patterns_create_command,
    runtime_dlp_patterns_patch_command,
    runtime_dlp_patterns_replace_command,
    runtime_dlp_patterns_delete_command,
    runtime_dlp_filtering_profiles_list_command,
    runtime_dlp_filtering_profiles_get_command,
    runtime_dlp_filtering_profiles_replace_command,
    runtime_topics_apply_command,
    runtime_topics_list_command,
    runtime_topics_get_command,
    runtime_topics_create_command,
    runtime_topics_update_command,
    runtime_topics_delete_command,
    model_security_labels_add_command,
    model_security_labels_set_command,
    model_security_labels_delete_command,
    model_security_labels_values_command,
    model_security_rule_instances_get_command,
    model_security_rule_instances_update_command,
    model_security_scans_violations_command,
    model_security_scans_evaluations_command,
    model_security_scans_files_command,
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
    model_security_scans_list_command,
    model_security_models_list_command,
    model_security_models_get_command,
    model_security_models_versions_command,
    model_security_models_version_get_command,
    model_security_models_files_command,
    model_security_groups_list_command,
    model_security_rules_list_command,
    model_security_rules_get_command,
    model_security_scans_create_command,
    model_security_scans_get_command,
    model_security_scans_evaluation_command,
    model_security_scans_violation_command,
    model_security_labels_keys_command,
    model_security_groups_get_command,
    model_security_groups_create_command,
    model_security_groups_update_command,
    model_security_groups_delete_command,
    model_security_rule_instances_list_command,
    redteam_targets_profile_command,
    redteam_targets_update_profile_command,
    redteam_targets_metadata_command,
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

    @patch.object(Client, "scanner_request")
    def test_runtime_scan_command_basic(self, mock_scanner: Mock, mock_client: Client) -> None:
        """Test runtime scan command with basic arguments.

        Args:
            mock_scanner: Mocked scanner_request method.
            mock_client: Mock client fixture.
        """
        # Mock scanner API response
        mock_scanner.return_value = {
            "scan_id": "scan-123",
            "report_id": "report-123",
            "action": "allow",
            "category": "benign",
            "prompt_detected": {
                "topic_violation": False,
                "injection": False,
                "toxic_content": False,
                "dlp": False,
                "url_cats": False,
                "malicious_code": False,
            },
        }

        args = {"profile_name": "test-profile", "prompt": "What is the weather today?"}

        result = runtime_scan_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.RuntimeScan"
        assert result.outputs["prompt"] == "What is the weather today?"
        assert result.outputs["scan_id"] == "scan-123"
        assert result.outputs["action"] == "allow"
        assert result.outputs["detected"] is False

    @patch.object(Client, "scanner_request")
    def test_runtime_scan_command_with_detection(self, mock_scanner: Mock, mock_client: Client) -> None:
        """Test runtime scan command with threat detection.

        Args:
            mock_scanner: Mocked scanner_request method.
            mock_client: Mock client fixture.
        """
        mock_scanner.return_value = {
            "scan_id": "scan-456",
            "report_id": "report-456",
            "action": "block",
            "category": "malicious",
            "prompt_detected": {
                "topic_violation": False,
                "injection": True,
                "toxic_content": True,
                "dlp": False,
                "url_cats": False,
                "malicious_code": False,
            },
        }

        args = {"profile_name": "security-profile", "prompt": "How do I hack a computer?", "response": "I cannot help with that."}

        result = runtime_scan_command(mock_client, args)

        assert result.outputs["action"] == "block"
        assert result.outputs["category"] == "malicious"
        assert result.outputs["detected"] is True
        # Detections are nested under prompt_detected / response_detected (forward-compatible shape)
        assert result.outputs["prompt_detected"]["injection"] is True
        assert result.outputs["prompt_detected"]["toxic_content"] is True

    def test_runtime_scan_command_missing_args(self, mock_client: Client) -> None:
        """Test runtime scan command fails with missing required arguments.

        Args:
            mock_client: Mock client fixture.
        """
        args = {
            "profile_name": "test-profile"
            # Missing prompt
        }

        with pytest.raises(ValueError, match="profile_name and prompt are required"):
            runtime_scan_command(mock_client, args)

    @patch.object(Client, "http_request")
    def test_runtime_api_keys_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test runtime API keys list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # SDK returns snake_case field names
        mock_http.return_value = {
            "api_keys": [
                {
                    "api_key_id": "00000000-0000-0000-0000-000000000001",
                    "api_key_name": "test-api-key-1",
                    "api_key_last8": "ABCD1234",
                    "created_at": "2024-01-01T00:00:00Z",
                    "expiration": "2025-01-01T00:00:00Z",
                    "revoked": False,
                },
                {
                    "api_key_id": "00000000-0000-0000-0000-000000000002",
                    "api_key_name": "test-api-key-2",
                    "api_key_last8": "EFGH5678",
                    "created_at": "2024-02-01T00:00:00Z",
                    "expiration": "2025-02-01T00:00:00Z",
                    "revoked": False,
                },
            ],
            "next_offset": 10,
        }

        args = {"limit": "10"}
        result = runtime_api_keys_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ApiKey"
        assert len(result.outputs) == 2
        assert result.outputs[0]["id"] == "00000000-0000-0000-0000-000000000001"
        assert result.outputs[0]["name"] == "test-api-key-1"
        assert result.outputs[0]["last8"] == "ABCD1234"
        assert result.outputs[0]["revoked"] is False

    @patch.object(Client, "http_request")
    def test_runtime_profiles_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test runtime profiles list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "ai_profiles": [
                {
                    "profile_id": "550e8400-e29b-41d4-a716-446655440000",
                    "profile_name": "production-profile",
                    "revision": 1,
                    "active": True,
                    "created_by": "admin@example.com",
                    "updated_by": "admin@example.com",
                    "last_modified_ts": "2024-01-15T00:00:00Z",
                    "tsg_id": "1234567890",
                },
                {
                    "profile_id": "550e8400-e29b-41d4-a716-446655440001",
                    "profile_name": "staging-profile",
                    "revision": 2,
                    "active": False,
                    "created_by": "user@example.com",
                    "updated_by": "user@example.com",
                    "last_modified_ts": "2024-02-10T00:00:00Z",
                    "tsg_id": "1234567890",
                },
            ],
            "next_offset": 10,
        }

        args = {"limit": "10"}
        result = runtime_profiles_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.SecurityProfile"
        assert len(result.outputs) == 2
        assert result.outputs[0]["id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result.outputs[0]["name"] == "production-profile"
        assert result.outputs[0]["revision"] == 1
        assert result.outputs[0]["active"] is True
        assert result.outputs[0]["created_by"] == "admin@example.com"
        assert result.outputs[0]["last_modified_ts"] == "2024-01-15T00:00:00Z"

    @patch.object(Client, "http_request")
    def test_runtime_customer_apps_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test runtime customer apps list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "customer_apps": [
                {
                    "customer_appId": "app-123",
                    "app_name": "test-app-1",
                    "model_name": "gpt-4",
                    "cloud_provider": "AWS",
                    "environment": "production",
                    "ai_agent_framework": "langchain",
                    "tsg_id": "1234567890",
                }
            ],
            "next_offset": 10,
        }

        args = {"limit": "10"}
        result = runtime_customer_apps_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.CustomerApp"
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "app-123"
        assert result.outputs[0]["name"] == "test-app-1"
        assert result.outputs[0]["cloud_provider"] == "AWS"

    @patch.object(Client, "http_request")
    def test_runtime_deployment_profiles_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test runtime deployment profiles list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "deployment_profiles": [
                {
                    "dp_name": "us-deployment",
                    "auth_code": "ac123",
                    "tsg_id": "1234567890",
                    "status": "active",
                    "expiration_date": "2025-12-31",
                    "ave_text_records": 1000,
                }
            ],
            "status": "success",
        }

        args = {"limit": "10", "unactivated": "false"}
        result = runtime_deployment_profiles_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.DeploymentProfile"
        assert len(result.outputs) == 1
        assert result.outputs[0]["name"] == "us-deployment"
        assert result.outputs[0]["status"] == "active"
        assert result.outputs[0]["auth_code"] == "ac123"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test runtime DLP profiles list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # DLP Data Profiles list returns a Spring Page envelope (content/page), not "dlp_profiles".
        mock_http.return_value = {
            "content": [
                {
                    "id": "dlp-123",
                    "name": "pci-dss",
                    "description": "PCI DSS profile",
                    "tenant_id": "tenant-1",
                    "type": "predefined",
                    "profile_status": "active",
                    "profile_type": "basic",
                    "version": "1.0",
                    "audit_metadata": {"created_at": "2026-01-01T00:00:00Z"},
                }
            ],
            "page": {"total_elements": 1, "total_pages": 1},
        }

        args = {"page": "0", "size": "50"}
        result = runtime_dlp_profiles_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.DlpProfile"
        assert len(result.outputs) == 1
        assert result.outputs[0]["id"] == "dlp-123"
        assert result.outputs[0]["name"] == "pci-dss"
        assert result.outputs[0]["profile_status"] == "active"
        assert result.outputs[0]["profile_type"] == "basic"

    @patch.object(Client, "http_request")
    def test_model_security_scans_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test model security scans list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "scans": [
                {
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "model_uri": "hf://org/model-name",
                    "eval_outcome": "ALLOWED",
                    "source_type": "HUGGING_FACE",
                    "security_group_uuid": "group-uuid-123",
                    "security_group_name": "hf-strict",
                    "scan_origin": "CLI",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:10:00Z",
                    "created_by": "user@example.com",
                }
            ],
            "pagination": {"total_items": 1},
        }

        args = {"limit": "10"}
        result = model_security_scans_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityScan"
        assert len(result.outputs) == 1
        assert result.outputs[0]["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result.outputs[0]["model_uri"] == "hf://org/model-name"
        assert result.outputs[0]["eval_outcome"] == "ALLOWED"

    @patch.object(Client, "http_request")
    def test_model_security_groups_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test model security groups list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "security_groups": [
                {
                    "uuid": "group-uuid-123",
                    "name": "hf-strict",
                    "description": "Block unsafe Hugging Face models",
                    "source_type": "HUGGING_FACE",
                    "state": "ACTIVE",
                    "is_tombstone": False,
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-15T00:00:00Z",
                    "tsg_id": "1234567890",
                }
            ],
            "pagination": {"total_items": 1},
        }

        args = {"limit": "10"}
        result = model_security_groups_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityGroup"
        assert len(result.outputs) == 1
        assert result.outputs[0]["uuid"] == "group-uuid-123"
        assert result.outputs[0]["name"] == "hf-strict"
        assert result.outputs[0]["source_type"] == "HUGGING_FACE"

    @patch.object(Client, "http_request")
    def test_model_security_models_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """models-list parses the catalog, forwards filters, and hits the data plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "models": [
                {
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "name": "org/llama",
                    "latest_version_uuid": "660e8400-e29b-41d4-a716-446655440000",
                    "latest_version_revision": "main",
                    "latest_version_outcome": "PASSED",
                    "latest_version_formats": ["safetensors"],
                    "latest_version_source_types": ["HUGGING_FACE"],
                    "latest_version_scan_time": "2024-01-01T00:00:00Z",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-02T00:00:00Z",
                }
            ],
            "pagination": {"total_items": 1},
        }

        args = {"limit": "10", "search_query": "llama", "latest_version_outcomes": "PASSED,FAILED"}
        result = model_security_models_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityModel"
        assert len(result.outputs) == 1
        assert result.outputs[0]["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result.outputs[0]["name"] == "org/llama"
        assert result.outputs[0]["latest_version_outcome"] == "PASSED"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/models"
        assert kwargs["use_model_sec_data"] is True
        assert kwargs["params"]["search_query"] == "llama"
        assert kwargs["params"]["latest_version_outcomes"] == ["PASSED", "FAILED"]

    @patch.object(Client, "http_request")
    def test_model_security_models_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """models-get returns a single model keyed by uuid on the data plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "550e8400-e29b-41d4-a716-446655440000",
            "name": "org/model",
            "latest_version_uuid": "660e8400-e29b-41d4-a716-446655440000",
            "latest_version_outcome": "PASSED",
        }

        result = model_security_models_get_command(mock_client, {"uuid": "550e8400-e29b-41d4-a716-446655440000"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityModel"
        assert result.outputs["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result.outputs["name"] == "org/model"

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["url_suffix"] == "/v1/models/550e8400-e29b-41d4-a716-446655440000"
        assert kwargs["use_model_sec_data"] is True

    @patch.object(Client, "http_request")
    def test_model_security_models_versions_command(self, mock_http: Mock, mock_client: Client) -> None:
        """models-versions lists a model's versions on the data plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "model_versions": [
                {
                    "uuid": "660e8400-e29b-41d4-a716-446655440000",
                    "model_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "revision": "main",
                    "file_count": 12,
                    "last_eval_outcome": "PASSED",
                }
            ],
            "pagination": {"total_items": 1},
        }

        args = {"model_uuid": "550e8400-e29b-41d4-a716-446655440000", "sort_order": "desc"}
        result = model_security_models_versions_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityModelVersion"
        assert len(result.outputs) == 1
        assert result.outputs[0]["uuid"] == "660e8400-e29b-41d4-a716-446655440000"
        assert result.outputs[0]["file_count"] == 12

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/models/550e8400-e29b-41d4-a716-446655440000/model-versions"
        assert kwargs["use_model_sec_data"] is True
        assert kwargs["params"]["sort_order"] == "desc"

    @patch.object(Client, "http_request")
    def test_model_security_models_version_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """models-version-get returns a single version keyed by uuid on the data plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "660e8400-e29b-41d4-a716-446655440000",
            "model_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "revision": "main",
            "last_eval_outcome": "PASSED",
        }

        result = model_security_models_version_get_command(mock_client, {"uuid": "660e8400-e29b-41d4-a716-446655440000"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityModelVersion"
        assert result.outputs["uuid"] == "660e8400-e29b-41d4-a716-446655440000"
        assert result.outputs["revision"] == "main"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/model-versions/660e8400-e29b-41d4-a716-446655440000"
        assert kwargs["use_model_sec_data"] is True

    @patch.object(Client, "http_request")
    def test_model_security_models_files_command(self, mock_http: Mock, mock_client: Client) -> None:
        """models-files lists a version's files on the data plane.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "files": [
                {
                    "uuid": "770e8400-e29b-41d4-a716-446655440000",
                    "path": "/model.safetensors",
                    "type": "FILE",
                    "result": "SUCCESS",
                    "formats": ["safetensors"],
                    "model_version_uuid": "660e8400-e29b-41d4-a716-446655440000",
                }
            ],
            "pagination": {"total_items": 1},
        }

        args = {"model_version_uuid": "660e8400-e29b-41d4-a716-446655440000", "limit": "50"}
        result = model_security_models_files_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityModelFile"
        assert len(result.outputs) == 1
        assert result.outputs[0]["path"] == "/model.safetensors"
        assert result.outputs[0]["result"] == "SUCCESS"

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/model-versions/660e8400-e29b-41d4-a716-446655440000/files"
        assert kwargs["use_model_sec_data"] is True

    @patch.object(Client, "http_request")
    def test_model_security_rules_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test model security rules list command.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "rules": [
                {
                    "uuid": "rule-uuid-123",
                    "name": "Pickle Scan",
                    "description": "Detect unsafe pickle operations",
                    "rule_type": "ARTIFACT",
                    "compatible_sources": ["HUGGING_FACE", "LOCAL"],
                    "default_state": "BLOCKING",
                }
            ],
            "pagination": {"total_items": 1},
        }

        args = {"limit": "10"}
        result = model_security_rules_list_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityRule"
        assert len(result.outputs) == 1
        assert result.outputs[0]["uuid"] == "rule-uuid-123"
        assert result.outputs[0]["name"] == "Pickle Scan"
        assert result.outputs[0]["rule_type"] == "ARTIFACT"

    @patch.object(Client, "http_request")
    def test_runtime_topics_apply_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test runtime topics apply command - orchestrates multiple API calls.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # Mock response 1: List topics to find topic by name
        topics_response = {
            "custom_topics": [
                {
                    "topic_id": "topic-uuid-123",
                    "topic_name": "credit-cards",
                    "revision": 2,
                    "active": True,
                    "description": "Detects credit card numbers",
                    "examples": ["4111-1111-1111-1111"],
                }
            ]
        }

        # Mock response 2: List profiles to find profile by name
        profiles_response = {
            "ai_profiles": [
                {
                    "profile_id": "profile-uuid-456",
                    "profile_name": "production-profile",
                    "active": True,
                    "policy": {
                        "ai-security-profiles": [
                            {
                                "model-type": "default",
                                "model-configuration": {
                                    "model-protection": [{"name": "topic-guardrails", "action": "block", "topic-list": []}]
                                },
                            }
                        ]
                    },
                }
            ]
        }

        # Mock response 3: Update profile response
        update_response = {"profile_id": "profile-uuid-456", "profile_name": "production-profile", "active": True}

        # Configure mock to return different responses based on call order
        mock_http.side_effect = [topics_response, profiles_response, update_response]

        args = {
            "profile_name": "production-profile",
            "topic_name": "credit-cards",
            "action": "block",
            "guardrail_action": "block",
        }
        result = runtime_topics_apply_command(mock_client, args)

        # Verify outputs
        assert result.outputs_prefix == "PrismaAIRs.TopicApplied"
        assert result.outputs["profile_name"] == "production-profile"
        assert result.outputs["topic_name"] == "credit-cards"
        assert result.outputs["topic_id"] == "topic-uuid-123"
        assert result.outputs["topic_revision"] == 2
        assert result.outputs["action"] == "block"
        assert result.outputs["guardrail_action"] == "block"
        assert result.outputs["applied"] is True

        # Verify http_request was called 3 times (list topics, list profiles, update profile)
        assert mock_http.call_count == 3

        # Verify the update call included the modified policy
        update_call = mock_http.call_args_list[2]
        update_body = update_call[1]["json_data"]
        assert update_body["profile_name"] == "production-profile"
        assert "policy" in update_body
        # Verify topic was added to topic-list
        policy = update_body["policy"]
        model_protection = policy["ai-security-profiles"][0]["model-configuration"]["model-protection"]
        topic_guardrails = next(mp for mp in model_protection if mp["name"] == "topic-guardrails")
        assert len(topic_guardrails["topic-list"]) == 1
        assert topic_guardrails["topic-list"][0]["action"] == "block"
        assert len(topic_guardrails["topic-list"][0]["topic"]) == 1
        applied_topic = topic_guardrails["topic-list"][0]["topic"][0]
        assert applied_topic["topic_id"] == "topic-uuid-123"
        assert applied_topic["topic_name"] == "credit-cards"
        assert applied_topic["revision"] == 2

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
    def test_runtime_dlp_profiles_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """Test DLP data profile soft-delete (GET to resolve fields, then PATCH to deleted).

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        # First call (GET) returns the existing profile; second call (PATCH) returns the updated profile.
        mock_http.side_effect = [
            {"id": "profile-123", "name": "pci-dss", "profile_type": "basic", "profile_status": "active"},
            {"id": "profile-123", "name": "pci-dss", "profile_type": "basic", "profile_status": "deleted"},
        ]

        args = {"profile_id": "profile-123"}
        result = runtime_dlp_profiles_delete_command(mock_client, args)

        # Two calls: GET then PATCH
        assert mock_http.call_count == 2
        get_call, patch_call = mock_http.call_args_list
        assert get_call.kwargs["method"] == "GET"
        assert patch_call.kwargs["method"] == "PATCH"

        # PATCH body must carry name + profile_type (required by merge-patch) and profile_status=deleted
        patch_body = patch_call.kwargs["json_data"]
        assert patch_body["profile_status"] == "deleted"
        assert patch_body["name"] == "pci-dss"
        assert patch_body["profile_type"] == "basic"
        assert patch_call.kwargs["headers"]["Content-Type"] == "application/merge-patch+json"

        # Context output uses its own action-tracking key
        assert result.outputs_prefix == "PrismaAIRs.DlpProfileDelete"
        assert result.outputs["id"] == "profile-123"
        assert result.outputs["deleted"] is True
        assert result.outputs["profile_status"] == "deleted"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_delete_command_missing_id(self, mock_http: Mock, mock_client: Client) -> None:
        """Test DLP data profile delete raises when profile_id is missing.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="profile_id is required"):
            runtime_dlp_profiles_delete_command(mock_client, {})
        mock_http.assert_not_called()

    @patch.object(Client, "http_request")
    def test_labels_add_accumulates_by_scan_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """labels-add keys context by scan_uuid so repeated runs accumulate distinct scan entries.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {}
        args = {"scan_uuid": "scan-1", "labels": '[{"key": "env", "value": "prod"}]'}

        result = model_security_labels_add_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityLabelsAdd"
        assert result.outputs_key_field == "scan_uuid"
        assert result.outputs["scan_uuid"] == "scan-1"
        # The DT-keyed context path is what makes repeated runs accumulate instead of overwrite.
        context = result.to_context()["EntryContext"]
        assert "PrismaAIRs.ModelSecurityLabelsAdd(val.scan_uuid && val.scan_uuid == obj.scan_uuid)" in context

    @patch.object(Client, "http_request")
    def test_labels_set_accumulates_by_scan_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """labels-set keys context by scan_uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {}
        args = {"scan_uuid": "scan-2", "labels": '[{"key": "env", "value": "staging"}]'}

        result = model_security_labels_set_command(mock_client, args)

        assert result.outputs_key_field == "scan_uuid"
        assert result.outputs["scan_uuid"] == "scan-2"

    @patch.object(Client, "http_request")
    def test_labels_delete_accumulates_by_scan_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """labels-delete keys context by scan_uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = None
        args = {"scan_uuid": "scan-3", "keys": "env,team"}

        result = model_security_labels_delete_command(mock_client, args)

        assert result.outputs_key_field == "scan_uuid"
        assert result.outputs["scan_uuid"] == "scan-3"
        assert result.outputs["keys_deleted"] == ["env", "team"]

    @patch.object(Client, "http_request")
    def test_labels_values_accumulates_by_key(self, mock_http: Mock, mock_client: Client) -> None:
        """labels-values keys context by the queried label key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"values": ["prod", "staging"], "pagination": {"total_items": 2}}
        args = {"key": "env"}

        result = model_security_labels_values_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityLabelValues"
        assert result.outputs_key_field == "key"
        assert result.outputs["key"] == "env"
        context = result.to_context()["EntryContext"]
        assert "PrismaAIRs.ModelSecurityLabelValues(val.key && val.key == obj.key)" in context

    @patch.object(Client, "http_request")
    def test_rule_instances_get_uses_own_keyed_context(self, mock_http: Mock, mock_client: Client) -> None:
        """rule-instances-get writes to its own context key, keyed by the instance uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "ri-1",
            "security_group_uuid": "sg-1",
            "security_rule_uuid": "sr-1",
            "state": "BLOCKING",
            "rule": {"name": "PII", "rule_type": "dlp"},
        }
        args = {"security_group_uuid": "sg-1", "rule_instance_uuid": "ri-1"}

        result = model_security_rule_instances_get_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityRuleInstanceGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ri-1"
        context = result.to_context()["EntryContext"]
        assert "PrismaAIRs.ModelSecurityRuleInstanceGet(val.uuid && val.uuid == obj.uuid)" in context

    @patch.object(Client, "http_request")
    def test_rule_instances_update_uses_own_keyed_context(self, mock_http: Mock, mock_client: Client) -> None:
        """rule-instances-update writes to its own context key, keyed by the instance uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "ri-2",
            "security_group_uuid": "sg-1",
            "security_rule_uuid": "sr-1",
            "state": "DISABLED",
            "rule": {"name": "PII", "rule_type": "dlp"},
        }
        args = {"security_group_uuid": "sg-1", "rule_instance_uuid": "ri-2", "state": "DISABLED"}

        result = model_security_rule_instances_update_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityRuleInstanceUpdate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "ri-2"
        # Verify it does NOT pollute the list/get context keys
        context = result.to_context()["EntryContext"]
        assert "PrismaAIRs.ModelSecurityRuleInstanceUpdate(val.uuid && val.uuid == obj.uuid)" in context

    @patch.object(Client, "http_request")
    def test_scans_violations_accumulates_by_scan_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """scans-violations (list) keys its per-scan wrapper by scan_uuid (not the missing top-level uuid).

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"violations": [{"uuid": "v-1"}], "pagination": {"total_items": 1}}
        args = {"uuid": "scan-1"}

        result = model_security_scans_violations_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityViolation"
        assert result.outputs_key_field == "scan_uuid"
        assert result.outputs["scan_uuid"] == "scan-1"
        context = result.to_context()["EntryContext"]
        assert "PrismaAIRs.ModelSecurityViolation(val.scan_uuid && val.scan_uuid == obj.scan_uuid)" in context

    @patch.object(Client, "http_request")
    def test_scans_evaluations_accumulates_by_scan_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """scans-evaluations (list) keys its per-scan wrapper by scan_uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"evaluations": [{"uuid": "e-1"}], "pagination": {"total_items": 1}}
        args = {"scan_uuid": "scan-2"}

        result = model_security_scans_evaluations_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityEvaluations"
        assert result.outputs_key_field == "scan_uuid"
        assert result.outputs["scan_uuid"] == "scan-2"

    @patch.object(Client, "http_request")
    def test_scans_files_accumulates_by_scan_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """scans-files (list) keys its per-scan wrapper by scan_uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"files": [{"uuid": "f-1"}], "pagination": {"total_items": 1}}
        args = {"scan_uuid": "scan-3"}

        result = model_security_scans_files_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityFiles"
        assert result.outputs_key_field == "scan_uuid"
        assert result.outputs["scan_uuid"] == "scan-3"

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

    @patch.object(Client, "http_request")
    def test_runtime_api_keys_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """api-keys-create writes to its own action context (keyed by id) and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "api_key_id": "k-1",
            "api_key_name": "prod-key",
            "api_key": "SECRET-FULL-VALUE",
            "api_key_last8": "FULLVALU",
            "expiration": "2026-12-31",
        }
        args = {
            "api_key_name": "prod-key",
            "auth_code": "ac-1",
            "cust_app": "app-1",
            "rotation_time_interval": "90",
            "rotation_time_unit": "days",
            "created_by": "user@example.com",
        }

        result = runtime_api_keys_create_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ApiKeyCreate"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "k-1"
        assert "|" in result.readable_output

    @patch.object(Client, "http_request")
    def test_runtime_api_keys_regenerate_command(self, mock_http: Mock, mock_client: Client) -> None:
        """api-keys-regenerate writes to its own action context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "api_key_id": "k-2",
            "api_key_name": "prod-key",
            "api_key": "NEW-SECRET",
            "api_key_last8": "WSECRET1",
            "expiration": "2027-01-01",
        }
        args = {"api_key_id": "k-1", "rotation_time_interval": "90", "rotation_time_unit": "days"}

        result = runtime_api_keys_regenerate_command(mock_client, args)

        assert result.outputs_prefix == "PrismaAIRs.ApiKeyRegenerate"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "k-2"
        assert "|" in result.readable_output

    @patch.object(Client, "http_request")
    def test_runtime_api_keys_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """api-keys-delete writes its own context keyed by api_key_name and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "successfully deleted apiKeyName: prod-key"}

        result = runtime_api_keys_delete_command(mock_client, {"api_key_name": "prod-key", "updated_by": "user@example.com"})

        assert result.outputs_prefix == "PrismaAIRs.ApiKeyDeleted"
        assert result.outputs_key_field == "api_key_name"
        assert result.outputs["api_key_name"] == "prod-key"
        assert result.outputs["deleted"] is True
        assert "|" in result.readable_output

    def test_runtime_api_keys_delete_requires_updated_by(self, mock_client: Client) -> None:
        """api-keys-delete raises when updated_by is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="updated_by is required"):
            runtime_api_keys_delete_command(mock_client, {"api_key_name": "prod-key"})

    @patch.object(Client, "http_request")
    def test_runtime_customer_apps_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """customer-apps-get writes to its own query context, separate from list/update.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"customer_appId": "app-1", "app_name": "chatbot"}

        result = runtime_customer_apps_get_command(mock_client, {"app_name": "chatbot"})

        assert result.outputs_prefix == "PrismaAIRs.CustomerAppGet"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "app-1"

    @patch.object(Client, "http_request")
    def test_runtime_customer_apps_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """customer-apps-update writes to its own action context, separate from list/get.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"customer_appId": "app-1", "app_name": "chatbot-renamed"}

        result = runtime_customer_apps_update_command(
            mock_client,
            {
                "customer_app_id": "app-1",
                "app_name": "chatbot-renamed",
                "cloud_provider": "AWS",
                "environment": "production",
            },
        )

        assert result.outputs_prefix == "PrismaAIRs.CustomerAppUpdate"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "app-1"

    @patch.object(Client, "http_request")
    def test_runtime_customer_apps_consumption_command(self, mock_http: Mock, mock_client: Client) -> None:
        """customer-apps-consumption writes to its own context keyed by app id.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "id": "app-1",
            "name": "chatbot",
            "token_consumption": {},
            "session_stats": {},
            "violation_breakdown": {},
        }

        result = runtime_customer_apps_consumption_command(
            mock_client, {"app_id": "app-1", "app_name": "chatbot", "time_interval": "30"}
        )

        assert result.outputs_prefix == "PrismaAIRs.CustomerAppConsumption"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_customer_apps_violations_command(self, mock_http: Mock, mock_client: Client) -> None:
        """customer-apps-violations writes to its own context keyed by app_id.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"violations": [], "total": 0}

        result = runtime_customer_apps_violations_command(
            mock_client, {"app_id": "app-1", "app_name": "chatbot", "time_interval": "30"}
        )

        assert result.outputs_prefix == "PrismaAIRs.CustomerAppViolations"
        assert result.outputs_key_field == "app_id"

    @patch.object(Client, "http_request")
    def test_runtime_customer_apps_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """customer-apps-delete writes its own context keyed by app_name and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "deleted"}

        result = runtime_customer_apps_delete_command(mock_client, {"app_name": "chatbot", "updated_by": "user@example.com"})

        assert result.outputs_prefix == "PrismaAIRs.CustomerAppDeleted"
        assert result.outputs_key_field == "app_name"
        assert result.outputs["app_name"] == "chatbot"
        assert result.outputs["deleted"] is True
        assert "|" in result.readable_output

    def test_runtime_customer_apps_delete_requires_updated_by(self, mock_client: Client) -> None:
        """customer-apps-delete raises when updated_by is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="updated_by is required"):
            runtime_customer_apps_delete_command(mock_client, {"app_name": "chatbot"})

    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-dictionaries-list returns the list under the base DlpDictionary key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"content": [{"id": "d-1", "name": "ssn"}], "total_elements": 1}

        result = runtime_dlp_dictionaries_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.DlpDictionary"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-dictionaries-get writes to its own query context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "d-1", "name": "ssn"}

        result = runtime_dlp_dictionaries_get_command(mock_client, {"dictionary_id": "d-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpDictionaryGet"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "d-1"

    @patch.object(demisto, "getFilePath")
    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_create_command(
        self, mock_http: Mock, mock_get_file: Mock, mock_client: Client, tmp_path
    ) -> None:
        """dlp-dictionaries-create writes to its own action context (uploads a keyword file).

        Args:
            mock_http: Mocked http_request method.
            mock_get_file: Mocked demisto.getFilePath.
            mock_client: Mock client fixture.
            tmp_path: pytest temp directory.
        """
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("term1\nterm2")
        mock_get_file.return_value = {"path": str(kw_file), "name": "keywords.txt"}
        mock_http.return_value = {"id": "d-1", "name": "ssn"}

        result = runtime_dlp_dictionaries_create_command(
            mock_client,
            {"name": "ssn", "category": "custom", "region_name": "us", "entry_id": "42"},
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpDictionaryCreate"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_patch_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-dictionaries-patch writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "d-1", "name": "ssn"}

        result = runtime_dlp_dictionaries_patch_command(
            mock_client,
            {"dictionary_id": "d-1", "name": "ssn", "category": "custom", "original_file_name": "ssn.txt"},
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpDictionaryPatch"
        assert result.outputs_key_field == "id"

    @patch.object(demisto, "getFilePath")
    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_replace_command(
        self, mock_http: Mock, mock_get_file: Mock, mock_client: Client, tmp_path
    ) -> None:
        """dlp-dictionaries-replace writes to its own action context (uploads a keyword file).

        Args:
            mock_http: Mocked http_request method.
            mock_get_file: Mocked demisto.getFilePath.
            mock_client: Mock client fixture.
            tmp_path: pytest temp directory.
        """
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("term1\nterm2")
        mock_get_file.return_value = {"path": str(kw_file), "name": "keywords.txt"}
        mock_http.return_value = {"id": "d-1", "name": "ssn-v2"}

        result = runtime_dlp_dictionaries_replace_command(
            mock_client,
            {"dictionary_id": "d-1", "name": "ssn-v2", "category": "custom", "region_name": "us", "entry_id": "42"},
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpDictionaryReplace"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-dictionaries-delete writes a delete-confirmation context and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = None

        result = runtime_dlp_dictionaries_delete_command(mock_client, {"dictionary_id": "d-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpDictionaryDelete"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "d-1"
        assert result.outputs["deleted"] is True
        assert "|" in result.readable_output

    def test_runtime_dlp_dictionaries_delete_requires_id(self, mock_client: Client) -> None:
        """dlp-dictionaries-delete raises when dictionary_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="dictionary_id is required"):
            runtime_dlp_dictionaries_delete_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-list returns the list under the base DlpPattern key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"content": [{"id": "p-1", "name": "ssn"}], "total_elements": 1}

        result = runtime_dlp_patterns_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.DlpPattern"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-get writes to its own query context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn"}

        result = runtime_dlp_patterns_get_command(mock_client, {"pattern_id": "p-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpPatternGet"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "p-1"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-create writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn"}

        result = runtime_dlp_patterns_create_command(
            mock_client, {"name": "ssn", "type": "CUSTOM", "detection_technique": "regex"}
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpPatternCreate"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_patch_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-patch writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn"}

        result = runtime_dlp_patterns_patch_command(
            mock_client, {"pattern_id": "p-1", "name": "ssn", "type": "CUSTOM", "detection_technique": "regex"}
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpPatternPatch"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_replace_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-replace writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn-v2"}

        result = runtime_dlp_patterns_replace_command(
            mock_client, {"pattern_id": "p-1", "name": "ssn-v2", "type": "CUSTOM", "detection_technique": "regex"}
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpPatternReplace"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-delete writes a delete-confirmation context and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = None

        result = runtime_dlp_patterns_delete_command(mock_client, {"pattern_id": "p-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpPatternDelete"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "p-1"
        assert result.outputs["deleted"] is True
        assert "|" in result.readable_output

    def test_runtime_dlp_patterns_delete_requires_id(self, mock_client: Client) -> None:
        """dlp-patterns-delete raises when pattern_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="pattern_id is required"):
            runtime_dlp_patterns_delete_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_runtime_dlp_filtering_profiles_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-filtering-profiles-list returns the list under the base DlpFilteringProfile key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"content": [{"id": "fp-1", "name": "filter"}], "total_elements": 1}

        result = runtime_dlp_filtering_profiles_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.DlpFilteringProfile"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_filtering_profiles_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-filtering-profiles-get writes to its own query context, separate from list/replace.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "fp-1", "name": "filter"}

        result = runtime_dlp_filtering_profiles_get_command(mock_client, {"profile_id": "fp-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpFilteringProfileGet"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "fp-1"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_filtering_profiles_replace_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-filtering-profiles-replace writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "fp-1", "name": "filter-v2"}

        result = runtime_dlp_filtering_profiles_replace_command(mock_client, {"profile_id": "fp-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpFilteringProfileReplace"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-profiles-get writes to its own query context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "dp-1", "name": "pci"}

        result = runtime_dlp_profiles_get_command(mock_client, {"profile_id": "dp-1"})

        assert result.outputs_prefix == "PrismaAIRs.DlpProfileGet"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "dp-1"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-profiles-create writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "dp-1", "name": "pci"}

        result = runtime_dlp_profiles_create_command(mock_client, {"name": "pci", "detection_rules": "[]"})

        assert result.outputs_prefix == "PrismaAIRs.DlpProfileCreate"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_patch_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-profiles-patch writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "dp-1", "name": "pci"}

        result = runtime_dlp_profiles_patch_command(mock_client, {"profile_id": "dp-1", "name": "pci", "profile_type": "basic"})

        assert result.outputs_prefix == "PrismaAIRs.DlpProfilePatch"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_replace_command(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-profiles-replace writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "dp-1", "name": "pci-v2"}

        result = runtime_dlp_profiles_replace_command(
            mock_client, {"profile_id": "dp-1", "name": "pci-v2", "detection_rules": "[]"}
        )

        assert result.outputs_prefix == "PrismaAIRs.DlpProfileReplace"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_profiles_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-profiles-get writes to its own query context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"ai_profiles": [{"profile_id": "sp-1", "profile_name": "default", "revision": 1}]}

        result = runtime_profiles_get_command(mock_client, {"profile_id": "sp-1"})

        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileGet"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "sp-1"

    @patch.object(Client, "http_request")
    def test_runtime_profiles_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-profiles-create writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"profile_id": "sp-1", "profile_name": "default", "revision": 1}

        result = runtime_profiles_create_command(mock_client, {"profile_name": "default"})

        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileCreate"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "sp-1"

    @patch.object(Client, "http_request")
    def test_runtime_profiles_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-profiles-update writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"profile_id": "sp-1", "profile_name": "default", "revision": 2}

        result = runtime_profiles_update_command(mock_client, {"profile_id": "sp-1", "profile_name": "default"})

        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileUpdate"
        assert result.outputs_key_field == "id"

    @patch.object(Client, "http_request")
    def test_runtime_profiles_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-profiles-delete writes its own context keyed by profile_id and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "deleted"}

        result = runtime_profiles_delete_command(mock_client, {"profile_id": "sp-1"})

        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileDeleted"
        assert result.outputs_key_field == "profile_id"
        assert result.outputs["profile_id"] == "sp-1"
        assert result.outputs["deleted"] is True
        assert "|" in result.readable_output

    def test_runtime_profiles_delete_requires_id(self, mock_client: Client) -> None:
        """runtime-profiles-delete raises when profile_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="profile_id is required"):
            runtime_profiles_delete_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_runtime_topics_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-topics-list returns the list under the base Topic key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"custom_topics": [{"topic_id": "t-1", "topic_name": "Violence"}], "total": 1}

        result = runtime_topics_list_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.Topic"
        assert result.outputs_key_field == "topic_id"

    @patch.object(Client, "http_request")
    def test_runtime_topics_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-topics-get writes to its own query context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"custom_topics": [{"topic_id": "t-1", "topic_name": "Custom", "revision": 1}]}

        result = runtime_topics_get_command(mock_client, {"topic_id": "t-1"})

        assert result.outputs_prefix == "PrismaAIRs.TopicGet"
        assert result.outputs_key_field == "topic_id"
        assert result.outputs["topic_id"] == "t-1"

    @patch.object(Client, "http_request")
    def test_runtime_topics_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-topics-create writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"topic_id": "t-1", "topic_name": "Custom", "revision": 1}

        result = runtime_topics_create_command(mock_client, {"topic_name": "Custom", "description": "desc", "examples": "a,b"})

        assert result.outputs_prefix == "PrismaAIRs.TopicCreate"
        assert result.outputs_key_field == "topic_id"
        assert result.outputs["topic_id"] == "t-1"

    @patch.object(Client, "http_request")
    def test_runtime_topics_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-topics-update writes to its own action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"topic_id": "t-1", "topic_name": "Custom", "revision": 2}

        result = runtime_topics_update_command(mock_client, {"topic_id": "t-1", "topic_name": "Custom"})

        assert result.outputs_prefix == "PrismaAIRs.TopicUpdate"
        assert result.outputs_key_field == "topic_id"

    @patch.object(Client, "http_request")
    def test_runtime_topics_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-topics-delete writes its own context keyed by topic_id and renders a table.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "deleted"}

        result = runtime_topics_delete_command(mock_client, {"topic_id": "t-1"})

        assert result.outputs_prefix == "PrismaAIRs.TopicDeleted"
        assert result.outputs_key_field == "topic_id"
        assert result.outputs["topic_id"] == "t-1"
        assert result.outputs["deleted"] is True
        assert "|" in result.readable_output

    def test_runtime_topics_delete_requires_id(self, mock_client: Client) -> None:
        """runtime-topics-delete raises when topic_id is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="topic_id is required"):
            runtime_topics_delete_command(mock_client, {})

    @patch.object(Client, "scanner_request")
    def test_runtime_bulk_scan_command(self, mock_scanner: Mock, mock_client: Client) -> None:
        """runtime-bulk-scan scans each CSV prompt and writes results keyed by scan_id.

        Args:
            mock_scanner: Mocked scanner_request method.
            mock_client: Mock client fixture.
        """
        mock_scanner.return_value = {"scan_id": "s-1", "action": "allow", "category": "benign"}

        result = runtime_bulk_scan_command(mock_client, {"profile_name": "default", "prompts_csv": "prompt\nhello\nworld"})

        assert result.outputs_prefix == "PrismaAIRs.BulkScan"
        assert result.outputs_key_field == "scan_id"
        # one scanner call per CSV prompt
        assert mock_scanner.call_count == 2

    def test_runtime_bulk_scan_requires_args(self, mock_client: Client) -> None:
        """runtime-bulk-scan raises when required args are missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="profile_name and prompts_csv are required"):
            runtime_bulk_scan_command(mock_client, {"profile_name": "default"})

    # ----- DLP patterns: create/patch/replace (coverage) -----
    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_create_full(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-create builds the request body (incl. optional fields) and writes DlpPatternCreate.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn", "type": "custom", "status": "active"}

        result = runtime_dlp_patterns_create_command(
            mock_client,
            {
                "name": "ssn",
                "type": "custom",
                "detection_technique": "regex",
                "supported_confidence_levels": "low,medium",
                "description": "SSN pattern",
                "matching_rules": '{"regexes":[{"regex":"x","weight":1}]}',
                "tags": '{"classification":["pii"]}',
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        body = kwargs["json_data"]
        assert body["detection_config"]["technique"] == "regex"
        assert body["detection_config"]["supported_confidence_levels"] == ["low", "medium"]
        assert body["matching_rules"] == {"regexes": [{"regex": "x", "weight": 1}]}
        assert body["tags"] == {"classification": ["pii"]}
        assert result.outputs_prefix == "PrismaAIRs.DlpPatternCreate"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "p-1"

    def test_runtime_dlp_patterns_create_requires_fields(self, mock_client: Client) -> None:
        """dlp-patterns-create validates required name/type/detection_technique.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="name is required"):
            runtime_dlp_patterns_create_command(mock_client, {})
        with pytest.raises(ValueError, match="type is required"):
            runtime_dlp_patterns_create_command(mock_client, {"name": "x"})
        with pytest.raises(ValueError, match="detection_technique is required"):
            runtime_dlp_patterns_create_command(mock_client, {"name": "x", "type": "custom"})

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_patch_full(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-patch sends a merge-patch (incl. clear-to-null) and writes DlpPatternPatch.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn", "type": "custom", "status": "active"}

        result = runtime_dlp_patterns_patch_command(
            mock_client,
            {
                "pattern_id": "p-1",
                "name": "ssn",
                "type": "custom",
                "detection_technique": "regex",
                "description": "updated",
                "matching_rules": "null",
                "tags": "null",
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PATCH"
        assert kwargs["url_suffix"].endswith("/p-1")
        assert kwargs["headers"]["Content-Type"] == "application/merge-patch+json"
        assert kwargs["json_data"]["matching_rules"] is None
        assert kwargs["json_data"]["tags"] is None
        assert result.outputs_prefix == "PrismaAIRs.DlpPatternPatch"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_patterns_replace_full(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-patterns-replace does a full PUT and writes DlpPatternReplace.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "p-1", "name": "ssn", "type": "custom", "status": "active"}

        result = runtime_dlp_patterns_replace_command(
            mock_client,
            {
                "pattern_id": "p-1",
                "name": "ssn",
                "type": "custom",
                "detection_technique": "regex",
                "supported_confidence_levels": '["high"]',
                "description": "v2",
                "matching_rules": '{"regexes":[{"regex":"y","weight":2}]}',
                "tags": '{"compliance":["pci"]}',
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PUT"
        assert kwargs["url_suffix"].endswith("/p-1")
        assert kwargs["json_data"]["detection_config"]["supported_confidence_levels"] == ["high"]
        assert result.outputs_prefix == "PrismaAIRs.DlpPatternReplace"

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
    @patch.object(Client, "http_request")
    def test_runtime_profiles_get_by_name_command(self, mock_http: Mock, mock_client: Client) -> None:
        """profiles-get filters by name (highest revision) and renders the policy summary.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "ai_profiles": [
                {"profile_id": "pf-1", "profile_name": "p", "revision": 1, "active": True},
                {
                    "profile_id": "pf-2",
                    "profile_name": "p",
                    "revision": 2,
                    "active": True,
                    "policy": {"ai-security-profiles": [{}], "dlp-data-profiles": []},
                },
            ]
        }

        result = runtime_profiles_get_command(mock_client, {"profile_name": "p"})

        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileGet"
        assert result.outputs["id"] == "pf-2"  # highest revision selected

    def test_runtime_profiles_get_requires_identifier(self, mock_client: Client) -> None:
        """profiles-get needs profile_id or profile_name.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="Either profile_id or profile_name is required"):
            runtime_profiles_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_runtime_profiles_create_full(self, mock_http: Mock, mock_client: Client) -> None:
        """profiles-create posts the policy and renders the policy summary.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "profile_id": "pf-1",
            "profile_name": "p",
            "revision": 1,
            "active": True,
            "policy": {"ai-security-profiles": [{}], "dlp-data-profiles": []},
        }

        result = runtime_profiles_create_command(
            mock_client,
            {"profile_name": "p", "active": "true", "policy": '{"ai-security-profiles":[{}],"dlp-data-profiles":[]}'},
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["json_data"]["policy"]["ai-security-profiles"] == [{}]
        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileCreate"
        assert result.outputs["id"] == "pf-1"

    @patch.object(Client, "http_request")
    def test_runtime_profiles_update_full(self, mock_http: Mock, mock_client: Client) -> None:
        """profiles-update PUTs by id and bumps revision.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "profile_id": "pf-1",
            "profile_name": "p",
            "revision": 2,
            "active": True,
            "policy": {"ai-security-profiles": [], "dlp-data-profiles": []},
        }

        result = runtime_profiles_update_command(
            mock_client,
            {
                "profile_id": "pf-1",
                "profile_name": "p",
                "active": "true",
                "policy": '{"ai-security-profiles":[],"dlp-data-profiles":[]}',
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PUT"
        assert kwargs["url_suffix"].endswith("/profile/uuid/pf-1")
        assert result.outputs_prefix == "PrismaAIRs.SecurityProfileUpdate"
        assert result.outputs["revision"] == 2

    @patch.object(Client, "http_request")
    def test_model_security_rules_get_full_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-rules-get parses remediation + editable fields into RuleGet context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "r-1",
            "name": "PII Rule",
            "rule_type": "PII",
            "compatible_sources": ["S3", "GCS"],
            "default_state": "BLOCKING",
            "remediation": {"description": "fix it", "steps": ["a", "b"], "url": "https://example.com"},
            "editable_fields": ["state"],
            "constant_values": {"x": 1},
            "default_values": {"y": 2},
        }

        result = model_security_rules_get_command(mock_client, {"uuid": "r-1"})

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/security-rules/r-1"
        assert kwargs["use_model_sec_mgmt"] is True
        assert result.outputs["uuid"] == "r-1"
        assert result.outputs["remediation_steps"] == ["a", "b"]
        assert result.outputs["editable_fields"] == ["state"]

    # ----- Custom topics: create/get/update (coverage) -----
    @patch.object(Client, "http_request")
    def test_runtime_topics_create_full(self, mock_http: Mock, mock_client: Client) -> None:
        """topics-create posts the topic and renders the examples section.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"topic_id": "tp-1", "topic_name": "t", "revision": 1, "active": True, "examples": ["a", "b"]}

        result = runtime_topics_create_command(
            mock_client, {"topic_name": "t", "description": "d", "examples": "a,b", "active": "true"}
        )

        assert mock_http.call_args.kwargs["method"] == "POST"
        assert result.outputs_prefix == "PrismaAIRs.TopicCreate"
        assert result.outputs["topic_id"] == "tp-1"

    def test_runtime_topics_create_validates(self, mock_client: Client) -> None:
        """topics-create validates required fields.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="topic_name is required"):
            runtime_topics_create_command(mock_client, {})
        with pytest.raises(ValueError, match="description is required"):
            runtime_topics_create_command(mock_client, {"topic_name": "t"})
        with pytest.raises(ValueError, match="examples is required"):
            runtime_topics_create_command(mock_client, {"topic_name": "t", "description": "d"})

    @patch.object(Client, "http_request")
    def test_runtime_topics_get_by_name_full(self, mock_http: Mock, mock_client: Client) -> None:
        """topics-get filters the list by name and renders examples.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "custom_topics": [{"topic_id": "tp-1", "topic_name": "t", "revision": 1, "active": True, "examples": ["x"]}]
        }

        result = runtime_topics_get_command(mock_client, {"topic_name": "t"})

        assert result.outputs_prefix == "PrismaAIRs.TopicGet"
        assert result.outputs["topic_id"] == "tp-1"

    def test_runtime_topics_get_requires_identifier(self, mock_client: Client) -> None:
        """topics-get needs topic_id or topic_name.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="Either topic_id or topic_name is required"):
            runtime_topics_get_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_runtime_topics_update_full(self, mock_http: Mock, mock_client: Client) -> None:
        """topics-update PUTs by id with optional fields.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"topic_id": "tp-1", "topic_name": "t", "revision": 2, "active": True, "examples": ["a"]}

        result = runtime_topics_update_command(
            mock_client, {"topic_id": "tp-1", "topic_name": "t", "description": "d2", "examples": "a", "active": "false"}
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PUT"
        assert kwargs["url_suffix"].endswith("/topic/uuid/tp-1")
        assert result.outputs_prefix == "PrismaAIRs.TopicUpdate"
        assert result.outputs["revision"] == 2

    # ----- model-security scans-get + DLP patch + prompts-create (coverage) -----
    @patch.object(Client, "http_request")
    def test_model_security_scans_get_full(self, mock_http: Mock, mock_client: Client) -> None:
        """scans-get parses eval_summary + error + model_formats branches.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {
            "uuid": "s-1",
            "eval_outcome": "BLOCKED",
            "eval_summary": {"rules_passed": 3, "rules_failed": 1, "total_rules": 4},
            "error_code": "E1",
            "error_message": "bad",
            "model_formats": ["safetensors"],
        }

        result = model_security_scans_get_command(mock_client, {"uuid": "s-1"})

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"] == "/v1/scans/s-1"
        assert kwargs["use_model_sec_data"] is True
        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityScanGet"
        assert result.outputs["rules_failed"] == 1
        assert result.outputs["error_code"] == "E1"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_profiles_patch_full(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-profiles-patch sends a merge-patch and writes DlpProfilePatch.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "dp-1", "name": "pii", "profile_type": "advanced"}

        result = runtime_dlp_profiles_patch_command(
            mock_client, {"profile_id": "dp-1", "name": "pii", "profile_type": "advanced", "description": "x"}
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PATCH"
        assert kwargs["headers"]["Content-Type"] == "application/merge-patch+json"
        assert result.outputs_prefix == "PrismaAIRs.DlpProfilePatch"

    @patch.object(Client, "http_request")
    def test_runtime_dlp_dictionaries_patch_full(self, mock_http: Mock, mock_client: Client) -> None:
        """dlp-dictionaries-patch sends a merge-patch and writes DlpDictionaryPatch.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "dd-1", "name": "terms", "category": "Confidential"}

        result = runtime_dlp_dictionaries_patch_command(
            mock_client,
            {
                "dictionary_id": "dd-1",
                "name": "terms",
                "category": "Confidential",
                "original_file_name": "f.txt",
                "description": "x",
            },
        )

        assert mock_http.call_args.kwargs["method"] == "PATCH"
        assert result.outputs_prefix == "PrismaAIRs.DlpDictionaryPatch"

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
    @patch.object(Client, "scanner_request")
    def test_runtime_scan_full(self, mock_scan: Mock, mock_client: Client) -> None:
        """runtime-scan builds the scanner request (with metadata) and parses detections.

        Args:
            mock_scan: Mocked scanner_request method.
            mock_client: Mock client fixture.
        """
        mock_scan.return_value = {
            "scan_id": "sc-1",
            "report_id": "r-1",
            "action": "block",
            "category": "malicious",
            "prompt_detected": {"injection": True, "dlp": False},
            "response_detected": {"dlp": False},
            "tr_id": "tr-1",
            "session_id": "se-1",
            "profile_id": "pid",
            "profile_name": "p",
            "source": "src",
        }

        result = runtime_scan_command(
            mock_client,
            {
                "profile_name": "p",
                "prompt": "hi",
                "response": "there",
                "tr_id": "tr-1",
                "session_id": "se-1",
                "app_name": "app",
                "app_user": "user",
                "ai_model": "gpt",
                "user_ip": "1.2.3.4",
                "agent_id": "ag",
                "agent_version": "1",
                "agent_arn": "arn",
            },
        )

        sent = mock_scan.call_args.args[0]
        assert sent["ai_profile"]["profile_name"] == "p"
        assert sent["contents"][0]["response"] == "there"
        assert sent["metadata"]["app_name"] == "app"
        assert result.outputs_prefix == "PrismaAIRs.RuntimeScan"
        assert result.outputs_key_field == "scan_id"
        assert result.outputs["category"] == "malicious"
        assert result.outputs["detected"] is True

    def test_runtime_scan_requires_args(self, mock_client: Client) -> None:
        """runtime-scan requires profile_name and prompt.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="profile_name and prompt are required"):
            runtime_scan_command(mock_client, {"profile_name": "p"})

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

    @patch.object(Client, "http_request")
    def test_model_security_labels_delete_full(self, mock_http: Mock, mock_client: Client) -> None:
        """labels-delete sends a DELETE and writes ModelSecurityLabelsDelete.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {}

        result = model_security_labels_delete_command(mock_client, {"scan_uuid": "s-1", "keys": "env,team"})

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "DELETE"
        assert kwargs["params"]["keys"] == ["env", "team"]
        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityLabelsDelete"
        assert result.outputs["keys_deleted"] == ["env", "team"]

    def test_model_security_labels_delete_validates(self, mock_client: Client) -> None:
        """labels-delete requires scan_uuid and keys.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="scan_uuid is required"):
            model_security_labels_delete_command(mock_client, {})
        with pytest.raises(ValueError, match="keys is required"):
            model_security_labels_delete_command(mock_client, {"scan_uuid": "s-1"})

    @patch.object(Client, "http_request")
    def test_runtime_dlp_filtering_profiles_replace_full(self, mock_http: Mock, mock_client: Client) -> None:
        """filtering-profiles-replace PUTs the full body (optional fields) and writes the replace context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"id": "fp-1", "name": "filter", "file_based": True, "non_file_based": True}

        result = runtime_dlp_filtering_profiles_replace_command(
            mock_client,
            {
                "profile_id": "fp-1",
                "file_based": "true",
                "non_file_based": "true",
                "description": "d",
                "direction": "BOTH",
                "log_severity": "high",
                "scan_type": "inline",
                "data_profile_id": "5",
                "euc_template_id": "euc-1",
                "is_end_user_coaching_enabled": "true",
                "is_granular_profile": "false",
                "file_type": "pdf,docx",
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "PUT"
        body = kwargs["json_data"]
        assert body["file_based"] is True
        assert body["data_profile_id"] == 5
        assert body["file_type"] == ["pdf", "docx"]
        assert result.outputs_prefix == "PrismaAIRs.DlpFilteringProfileReplace"

    # ----- model-security: rules -----
    @patch.object(Client, "http_request")
    def test_model_security_rules_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-rules-get writes to its own query context, separate from list.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "r-1", "name": "PII Rule"}

        result = model_security_rules_get_command(mock_client, {"uuid": "r-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityRuleGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "r-1"

    # ----- model-security: scans core -----
    @patch.object(Client, "http_request")
    def test_model_security_scans_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-scans-create writes to its own action context, separate from list/get.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "scan-1", "status": "PENDING"}

        result = model_security_scans_create_command(mock_client, {"model_uri": "hf://bert", "security_group_uuid": "sg-1"})

        # scan_origin defaults to MODEL_SECURITY_API when not provided.
        assert mock_http.call_args.kwargs["json_data"]["scan_origin"] == "MODEL_SECURITY_API"
        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityScanCreate"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "scan-1"

    @patch.object(Client, "http_request")
    def test_model_security_scans_create_scan_origin_override(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-scans-create passes an explicit scan_origin through to the request body.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "scan-2", "status": "PENDING"}

        model_security_scans_create_command(
            mock_client,
            {"model_uri": "hf://bert", "security_group_uuid": "sg-1", "scan_origin": "HUGGING_FACE"},
        )

        assert mock_http.call_args.kwargs["json_data"]["scan_origin"] == "HUGGING_FACE"

    @patch.object(Client, "http_request")
    def test_model_security_scans_create_with_labels(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-scans-create passes labels through and echoes them in context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        labels = [{"key": "env", "value": "prod"}, {"key": "team", "value": "ml"}]
        mock_http.return_value = {"uuid": "scan-3", "status": "PENDING", "labels": labels}

        result = model_security_scans_create_command(
            mock_client,
            {"model_uri": "hf://bert", "security_group_uuid": "sg-1", "labels": json.dumps(labels)},
        )

        assert mock_http.call_args.kwargs["json_data"]["labels"] == labels
        assert result.outputs["labels"] == labels

    def test_model_security_scans_create_invalid_labels(self, mock_client: Client) -> None:
        """model-security-scans-create rejects malformed labels.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="labels must be a valid JSON array"):
            model_security_scans_create_command(
                mock_client, {"model_uri": "hf://bert", "security_group_uuid": "sg-1", "labels": "not-json"}
            )
        with pytest.raises(ValueError, match="each with 'key' and 'value'"):
            model_security_scans_create_command(
                mock_client,
                {"model_uri": "hf://bert", "security_group_uuid": "sg-1", "labels": '[{"key": "env"}]'},
            )

    @patch.object(Client, "http_request")
    def test_model_security_scans_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-scans-get writes to its own query context, separate from list/create.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "scan-1", "status": "DONE"}

        result = model_security_scans_get_command(mock_client, {"uuid": "scan-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityScanGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "scan-1"

    @patch.object(Client, "http_request")
    def test_model_security_scans_evaluation_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-scans-evaluation returns a single evaluation keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "e-1", "result": "PASS"}

        result = model_security_scans_evaluation_command(mock_client, {"uuid": "e-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityEvaluation"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_model_security_scans_violation_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-scans-violation returns a single violation keyed by uuid.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "v-1", "severity": "HIGH"}

        result = model_security_scans_violation_command(mock_client, {"uuid": "v-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityViolationDetail"
        assert result.outputs_key_field == "uuid"

    # ----- model-security: labels -----
    @patch.object(Client, "http_request")
    def test_model_security_labels_keys_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-labels-keys returns the global key snapshot (no key field).

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"keys": ["env", "team"], "pagination": {"total_items": 2}}

        result = model_security_labels_keys_command(mock_client, {})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityLabelKeys"
        assert result.outputs_key_field is None
        assert result.outputs["keys"] == ["env", "team"]

    # ----- model-security: groups CRUD -----
    @patch.object(Client, "http_request")
    def test_model_security_groups_get_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-groups-get writes to its own query context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "g-1", "name": "grp"}

        result = model_security_groups_get_command(mock_client, {"uuid": "g-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityGroupGet"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "g-1"

    @patch.object(Client, "http_request")
    def test_model_security_groups_create_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-groups-create writes to the Add action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "g-1", "name": "grp"}

        result = model_security_groups_create_command(mock_client, {"name": "grp", "source_type": "HUGGING_FACE"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityGroupAdd"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "g-1"

    @patch.object(Client, "http_request")
    def test_model_security_groups_update_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-groups-update writes to the Update action context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"uuid": "g-1", "name": "grp-renamed"}

        result = model_security_groups_update_command(mock_client, {"uuid": "g-1", "name": "grp-renamed"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityGroupUpdate"
        assert result.outputs_key_field == "uuid"

    @patch.object(Client, "http_request")
    def test_model_security_groups_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-groups-delete writes the Delete confirmation context.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = None

        result = model_security_groups_delete_command(mock_client, {"uuid": "g-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityGroupDelete"
        assert result.outputs_key_field == "uuid"
        assert result.outputs["uuid"] == "g-1"
        assert result.outputs["deleted"] is True

    def test_model_security_groups_delete_requires_uuid(self, mock_client: Client) -> None:
        """model-security-groups-delete raises when uuid is missing.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="uuid is required"):
            model_security_groups_delete_command(mock_client, {})

    # ----- model-security: rule-instances list -----
    @patch.object(Client, "http_request")
    def test_model_security_rule_instances_list_command(self, mock_http: Mock, mock_client: Client) -> None:
        """model-security-rule-instances-list returns instances under the base key.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"rule_instances": [{"uuid": "ri-1"}], "pagination": {"total_items": 1}}

        result = model_security_rule_instances_list_command(mock_client, {"security_group_uuid": "sg-1"})

        assert result.outputs_prefix == "PrismaAIRs.ModelSecurityRuleInstance"
        assert result.outputs_key_field == "uuid"
