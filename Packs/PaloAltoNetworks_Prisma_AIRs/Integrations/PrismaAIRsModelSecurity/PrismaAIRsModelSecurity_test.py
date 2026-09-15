"""Unit tests for the Prisma AIRs AI Model Security integration."""

import json
from unittest.mock import Mock, patch

import pytest
from PrismaAIRsModelSecurity import (
    Client,
    model_security_groups_create_command,
    model_security_groups_delete_command,
    model_security_groups_get_command,
    model_security_groups_list_command,
    model_security_groups_update_command,
    model_security_labels_add_command,
    model_security_labels_delete_command,
    model_security_labels_keys_command,
    model_security_labels_set_command,
    model_security_labels_values_command,
    model_security_models_files_command,
    model_security_models_get_command,
    model_security_models_list_command,
    model_security_models_version_get_command,
    model_security_models_versions_command,
    model_security_rule_instances_get_command,
    model_security_rule_instances_list_command,
    model_security_rule_instances_update_command,
    model_security_rules_get_command,
    model_security_rules_list_command,
    model_security_scans_create_command,
    model_security_scans_evaluation_command,
    model_security_scans_evaluations_command,
    model_security_scans_files_command,
    model_security_scans_get_command,
    model_security_scans_list_command,
    model_security_scans_violation_command,
    model_security_scans_violations_command,
)


@pytest.fixture
def mock_client() -> Client:
    """Create a mock Prisma AIRs client scoped to the Model Security plane."""
    return Client(
        base_url="https://api.sase.paloaltonetworks.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
        tsg_id="1234567890",
        verify=False,
        proxy=False,
        headers={},
    )


class TestModelSecurity:
    """Test cases for Prisma AIRs AI Model Security commands."""

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
