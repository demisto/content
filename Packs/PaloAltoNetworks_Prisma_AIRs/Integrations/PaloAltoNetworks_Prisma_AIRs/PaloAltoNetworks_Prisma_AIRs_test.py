import pytest
from unittest.mock import Mock, patch
from PaloAltoNetworks_Prisma_AIRs import (
    Client,
    test_module as run_test_module,
    runtime_scan_command,
    runtime_api_keys_list_command,
    runtime_profiles_list_command,
    runtime_customer_apps_list_command,
    runtime_deployment_profiles_list_command,
    runtime_dlp_profiles_list_command,
    runtime_dlp_profiles_delete_command,
    runtime_topics_apply_command,
    model_security_scans_list_command,
    model_security_groups_list_command,
    model_security_rules_list_command,
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

        assert result.outputs_prefix == "PrismaAIRs.RedTeamTarget"
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
