import json  # noqa: F401
import pytest
import demistomock as demisto  # noqa: F401
from unittest.mock import Mock, patch
from PrismaAIRsRuntime import (
    Client,
    runtime_scan_command,
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
    runtime_dlp_profiles_get_command,
    runtime_dlp_profiles_create_command,
    runtime_dlp_profiles_patch_command,
    runtime_dlp_profiles_replace_command,
    runtime_dlp_profiles_delete_command,
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
    runtime_topics_list_command,
    runtime_topics_get_command,
    runtime_topics_create_command,
    runtime_topics_update_command,
    runtime_topics_delete_command,
    runtime_topics_apply_command,
    runtime_bulk_scan_command,
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


class TestRuntime:
    """Tests for the Prisma AIRS AI Runtime Security + DLP commands."""

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
            "cust_env": "production",
            "cust_cloud_provider": "aws",
            "rotation_time_interval": "90",
            "rotation_time_unit": "days",
            "created_by": "user@example.com",
        }

        result = runtime_api_keys_create_command(mock_client, args)

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/mgmt/apikey"
        # cust_env/cust_cloud_provider are required in practice - the customer app record mandates them.
        assert kwargs["json_data"]["cust_env"] == "production"
        assert kwargs["json_data"]["cust_cloud_provider"] == "aws"
        assert result.outputs_prefix == "PrismaAIRs.ApiKeyCreate"
        assert result.outputs_key_field == "id"
        assert result.outputs["id"] == "k-1"
        assert "|" in result.readable_output

    @pytest.mark.parametrize("missing", ["cust_env", "cust_cloud_provider"])
    def test_runtime_api_keys_create_requires_customer_app_fields(self, mock_client: Client, missing: str) -> None:
        """create must reject a missing cust_env/cust_cloud_provider before calling the API.

        These are optional in the API schema but the customer app record mandates them; guarding
        here turns the opaque upstream 400 ("Error inserting/updating customer app record") into a
        clear, actionable error.

        Args:
            mock_client: Mock client fixture.
            missing: The required customer-app argument to omit.
        """
        args = {
            "api_key_name": "prod-key",
            "auth_code": "ac-1",
            "cust_app": "app-1",
            "cust_env": "production",
            "cust_cloud_provider": "aws",
            "rotation_time_interval": "90",
            "rotation_time_unit": "days",
            "created_by": "user@example.com",
        }
        del args[missing]

        with pytest.raises(ValueError, match=f"{missing} is required"):
            runtime_api_keys_create_command(mock_client, args)

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

        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "POST"
        assert kwargs["url_suffix"] == "/v1/mgmt/apikey/regenerate/k-1"
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
    def test_runtime_profiles_force_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-profiles-delete with force hits the /force endpoint and passes updated_by.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "force deleted"}

        result = runtime_profiles_delete_command(
            mock_client, {"profile_id": "sp-1", "force": "true", "updated_by": "admin@example.com"}
        )

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"].endswith("/profile/sp-1/force")
        assert kwargs["params"] == {"updated_by": "admin@example.com"}
        assert result.outputs["force"] is True
        assert result.outputs["deleted"] is True

    def test_runtime_profiles_force_delete_requires_updated_by(self, mock_client: Client) -> None:
        """runtime-profiles-delete with force but no updated_by raises.

        Args:
            mock_client: Mock client fixture.
        """
        with pytest.raises(ValueError, match="updated_by is required when force is true"):
            runtime_profiles_delete_command(mock_client, {"profile_id": "sp-1", "force": "true"})

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

    @patch.object(Client, "http_request")
    def test_runtime_topics_force_delete_command(self, mock_http: Mock, mock_client: Client) -> None:
        """runtime-topics-delete with force hits /topic/force/{id}; updated_by is optional.

        Args:
            mock_http: Mocked http_request method.
            mock_client: Mock client fixture.
        """
        mock_http.return_value = {"message": "force deleted"}

        result = runtime_topics_delete_command(mock_client, {"topic_id": "t-1", "force": "true"})

        _, kwargs = mock_http.call_args
        assert kwargs["url_suffix"].endswith("/topic/force/t-1")
        assert kwargs["params"] is None
        assert result.outputs["force"] is True
        assert result.outputs["deleted"] is True

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
