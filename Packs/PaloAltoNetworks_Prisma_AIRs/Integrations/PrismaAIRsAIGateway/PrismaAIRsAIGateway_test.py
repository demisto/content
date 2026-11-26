"""Unit tests for the Prisma AIRS AI Gateway integration."""

import re
from unittest.mock import Mock, patch

import pytest
from PrismaAIRsAIGateway import (
    Client,
    DemistoException,
    api_keys_service_create_command,
    api_keys_service_delete_command,
    api_keys_service_get_command,
    api_keys_service_list_command,
    api_keys_service_rotate_command,
    api_keys_service_update_command,
    api_keys_user_create_command,
    api_keys_user_list_command,
    bool_arg,
    config_versions_list_command,
    configs_create_command,
    configs_delete_command,
    configs_get_command,
    configs_list_command,
    deployment_ping_command,
    deployments_create_command,
    deployments_delete_command,
    deployments_list_command,
    guardrails_catalog_command,
    guardrails_create_command,
    guardrails_delete_command,
    guardrails_get_command,
    guardrails_list_command,
    guardrails_mcp_server_set_command,
    guardrails_mcp_servers_list_command,
    guardrails_mcp_servers_sync_command,
    guardrails_update_command,
    integrations_catalog_command,
    integrations_create_command,
    integrations_delete_command,
    integrations_get_command,
    integrations_list_command,
    integrations_models_delete_command,
    integrations_models_list_command,
    integrations_models_set_command,
    integrations_update_command,
    integrations_workspaces_list_command,
    integrations_workspaces_set_command,
    json_arg,
    mcp_integrations_capabilities_list_command,
    mcp_integrations_capabilities_set_command,
    mcp_integrations_create_command,
    mcp_integrations_list_command,
    mcp_integrations_metadata_get_command,
    mcp_integrations_workspaces_list_command,
    mcp_integrations_workspaces_set_command,
    mcp_server_test_command,
    mcp_servers_capabilities_list_command,
    mcp_servers_capabilities_set_command,
    mcp_servers_connections_delete_command,
    mcp_servers_connections_list_command,
    mcp_servers_create_command,
    mcp_servers_list_command,
    mcp_servers_user_access_list_command,
    mcp_servers_user_access_set_command,
    model_pricing_get_command,
    org_guardrails_list_command,
    organisations_auth_settings_get_command,
    organisations_auth_settings_update_command,
    organisations_info_get_command,
    organisations_self_get_command,
    organisations_self_update_command,
    pagination_params,
    plugins_create_command,
    plugins_list_command,
    providers_create_command,
    providers_delete_command,
    providers_get_command,
    providers_list_command,
    providers_update_command,
    rate_limit_policies_create_command,
    rate_limit_policies_list_command,
    scopes_bind_command,
    scopes_create_command,
    scopes_delete_command,
    scopes_get_command,
    scopes_list_command,
    scopes_update_command,
    secret_references_create_command,
    secret_references_list_command,
    usage_limit_policies_create_command,
    usage_limit_policy_entities_list_command,
    usage_limit_policy_entity_reset_command,
    workspaces_archive_command,
    workspaces_create_command,
    workspaces_get_command,
    workspaces_list_command,
    workspaces_provision_command,
    workspaces_update_command,
)

# Aliased so pytest does not collect the integration's own probe (name starts with "test_") as a test case.
from PrismaAIRsAIGateway import test_connection as run_connection_check


@pytest.fixture
def mock_client() -> Client:
    """Create a mock Prisma AIRS client scoped to the AI Gateway plane."""
    return Client(
        base_url="https://api.apps.paloaltonetworks.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
        tsg_id="1234567890",
        verify=False,
        proxy=False,
        headers={},
    )


class TestHelpers:
    """Test cases for the module helper functions."""

    def test_json_arg_parses_string(self) -> None:
        """A JSON string argument is parsed into a Python object."""
        assert json_arg({"checks": '[{"id": "x"}]'}, "checks") == [{"id": "x"}]

    def test_json_arg_passthrough_object(self) -> None:
        """An already-parsed object argument is returned unchanged."""
        assert json_arg({"actions": {"block": True}}, "actions") == {"block": True}

    def test_json_arg_absent_returns_none(self) -> None:
        """An absent or empty argument yields None."""
        assert json_arg({}, "checks") is None
        assert json_arg({"checks": ""}, "checks") is None

    def test_json_arg_invalid_raises(self) -> None:
        """An invalid JSON string raises a ValueError."""
        with pytest.raises(ValueError, match="must be a valid JSON"):
            json_arg({"checks": "{not json"}, "checks")

    def test_bool_arg(self) -> None:
        """Boolean arguments are coerced, with None for absent values."""
        assert bool_arg({"is_default": "true"}, "is_default") is True
        assert bool_arg({"is_default": "false"}, "is_default") is False
        assert bool_arg({}, "is_default") is None

    def test_pagination_params_default(self) -> None:
        """Pagination defaults page_size to the shared DEFAULT_LIMIT."""
        assert pagination_params({}) == {"page_size": 50}

    def test_pagination_params_explicit(self) -> None:
        """Explicit pagination values are honored."""
        assert pagination_params({"page_size": "10", "current_page": "2"}) == {
            "page_size": 10,
            "current_page": 2,
        }


class TestControlPlaneCommands:
    """Commands that must route to the AI Gateway control plane."""

    @patch.object(Client, "http_request")
    def test_guardrails_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing guardrails hits the control plane and unwraps the data envelope."""
        mock_http.return_value = {"data": [{"id": "g1", "name": "Block PII"}]}
        result = guardrails_list_command(mock_client, {"workspace_id": "ws1", "page_size": "5"})

        args, kwargs = mock_http.call_args
        assert args[0] == "GET"
        assert args[1] == "/guardrails"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"] == {"workspace_id": "ws1", "page_size": 5}
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayGuardrail"
        assert result.outputs == [{"id": "g1", "name": "Block PII"}]

    @patch.object(Client, "http_request")
    def test_guardrails_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating a guardrail parses nested JSON args into the request body."""
        mock_http.return_value = {"id": "g2", "slug": "block-pii"}
        guardrails_create_command(
            mock_client,
            {"name": "Block PII", "target": "llm", "checks": '[{"id": "pii"}]'},
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["json_data"] == {
            "name": "Block PII",
            "target": "llm",
            "checks": [{"id": "pii"}],
        }

    @patch.object(Client, "http_request")
    def test_guardrails_get(self, mock_http: Mock, mock_client: Client) -> None:
        """Getting a guardrail builds the id path on the control plane."""
        mock_http.return_value = {"id": "g1"}
        guardrails_get_command(mock_client, {"guardrail_id": "g1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/guardrails/g1"
        assert kwargs["use_aigw_cp"] is True

    @patch.object(Client, "http_request")
    def test_guardrails_update(self, mock_http: Mock, mock_client: Client) -> None:
        """Updating a guardrail issues a PUT on the control plane."""
        mock_http.return_value = {"id": "g1", "version_id": "v2"}
        guardrails_update_command(mock_client, {"guardrail_id": "g1", "name": "New"})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/guardrails/g1"
        assert kwargs["use_aigw_cp"] is True

    @patch.object(Client, "http_request")
    def test_guardrails_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Deleting a guardrail requests an empty response and confirms success."""
        mock_http.return_value = None
        result = guardrails_delete_command(mock_client, {"guardrail_id": "g1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["return_empty_response"] is True
        assert "deleted successfully" in result.readable_output

    @patch.object(Client, "http_request")
    def test_configs_list_unwraps_envelope(self, mock_http: Mock, mock_client: Client) -> None:
        """Config responses are wrapped as {success, data} and are unwrapped."""
        mock_http.return_value = {"success": True, "data": [{"id": "c1", "slug": "default"}]}
        result = configs_list_command(mock_client, {"workspace_id": "ws-1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/configs"
        assert kwargs["use_aigw_cp"] is True
        # workspace_id is required by the data plane; omitting it returns 404 AB02.
        assert kwargs["params"]["workspace_id"] == "ws-1"
        assert result.outputs == [{"id": "c1", "slug": "default"}]
        # Slug must be a visible column (within the first 5) so operators can identify configs in the War Room.
        header_row = result.readable_output.splitlines()[1]
        columns = [c.strip() for c in header_row.strip("|").split("|")]
        assert "Slug" in columns
        assert columns.index("Slug") < 5

    @patch.object(Client, "http_request")
    def test_configs_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating a config parses the config JSON arg and unwraps data."""
        mock_http.return_value = {"data": {"id": "c2", "slug": "new"}}
        result = configs_create_command(mock_client, {"name": "new", "config": '{"routes": []}'})

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert kwargs["json_data"] == {"name": "new", "config": {"routes": []}}
        assert result.outputs == {"id": "c2", "slug": "new"}

    @patch.object(Client, "http_request")
    def test_configs_get_by_id(self, mock_http: Mock, mock_client: Client) -> None:
        """Getting a config uses the config UUID path (not the slug)."""
        mock_http.return_value = {"data": {"id": "c1", "slug": "default"}}
        configs_get_command(mock_client, {"config_id": "764cf9cd-4ebf-449e-b669-08149b0fbbbc"})

        args, _ = mock_http.call_args
        assert args[1] == "/configs/764cf9cd-4ebf-449e-b669-08149b0fbbbc"

    @patch.object(Client, "http_request")
    def test_configs_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Deleting a config confirms success."""
        mock_http.return_value = None
        result = configs_delete_command(mock_client, {"config_id": "764cf9cd-4ebf-449e-b669-08149b0fbbbc"})
        assert "deleted successfully" in result.readable_output

    @patch.object(Client, "http_request")
    def test_config_versions_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing config versions uses the nested versions path."""
        mock_http.return_value = {"data": [{"id": "v1"}]}
        config_versions_list_command(mock_client, {"config_id": "764cf9cd-4ebf-449e-b669-08149b0fbbbc"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/configs/764cf9cd-4ebf-449e-b669-08149b0fbbbc/versions"
        assert kwargs["use_aigw_cp"] is True

    @patch.object(Client, "http_request")
    def test_rate_limit_policies_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing rate-limit policies passes filter params to the control plane."""
        mock_http.return_value = {"data": [{"id": "p1"}]}
        rate_limit_policies_list_command(mock_client, {"type": "requests", "unit": "rpm"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/policies/rate-limits"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"]["type"] == "requests"
        assert kwargs["params"]["unit"] == "rpm"

    @patch.object(Client, "http_request")
    def test_rate_limit_policies_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating a rate-limit policy coerces value to a number and parses JSON args."""
        mock_http.return_value = {"id": "p1"}
        rate_limit_policies_create_command(
            mock_client,
            {
                "conditions": "[]",
                "group_by": '["user"]',
                "type": "requests",
                "unit": "rpm",
                "value": "100",
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["json_data"]["value"] == 100
        assert kwargs["json_data"]["group_by"] == ["user"]

    @patch.object(Client, "http_request")
    def test_usage_limit_policies_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating a usage-limit policy coerces credit_limit to a number."""
        mock_http.return_value = {"id": "u1"}
        usage_limit_policies_create_command(
            mock_client,
            {"conditions": "[]", "group_by": "[]", "type": "cost", "credit_limit": "500"},
        )

        _, kwargs = mock_http.call_args
        assert kwargs["json_data"]["credit_limit"] == 500
        assert kwargs["use_aigw_cp"] is True

    @patch.object(Client, "http_request")
    def test_usage_limit_policy_entities_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing policy entities uses the nested entities path."""
        mock_http.return_value = {"data": [{"id": "e1"}]}
        usage_limit_policy_entities_list_command(mock_client, {"policy_id": "u1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/policies/usage-limits/u1/entities"
        assert kwargs["use_aigw_cp"] is True

    @patch.object(Client, "http_request")
    def test_usage_limit_policy_entity_reset(self, mock_http: Mock, mock_client: Client) -> None:
        """Resetting an entity issues a PUT to the reset path and confirms success."""
        mock_http.return_value = None
        result = usage_limit_policy_entity_reset_command(mock_client, {"policy_id": "u1", "entity_id": "e1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/policies/usage-limits/u1/entities/e1/reset"
        assert "reset successfully" in result.readable_output

    @patch.object(Client, "http_request")
    def test_mcp_servers_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing MCP servers routes to the control plane."""
        mock_http.return_value = {"data": [{"id": "m1"}]}
        mcp_servers_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-servers"
        assert kwargs["use_aigw_cp"] is True

    @patch.object(Client, "http_request")
    def test_mcp_servers_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating an MCP server sends name and integration id in the body."""
        mock_http.return_value = {"id": "m1", "slug": "srv"}
        mcp_servers_create_command(mock_client, {"name": "srv", "mcp_integration_id": "i1"})

        _, kwargs = mock_http.call_args
        assert kwargs["json_data"] == {"name": "srv", "mcp_integration_id": "i1"}

    @patch.object(Client, "http_request")
    def test_mcp_server_test(self, mock_http: Mock, mock_client: Client) -> None:
        """Testing an MCP server posts to the test path and injects the server id."""
        mock_http.return_value = {"success": True, "status_code": 200}
        result = mcp_server_test_command(mock_client, {"mcp_server_id": "m1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/mcp-servers/m1/test"
        assert kwargs["use_aigw_cp"] is True
        assert result.outputs["mcp_server_id"] == "m1"
        assert result.outputs["success"] is True


class TestAdminPlaneCommands:
    """Commands that must route to the AI Gateway admin plane."""

    @patch.object(Client, "http_request")
    def test_org_guardrails_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Org guardrails route to the admin plane, not the control plane."""
        mock_http.return_value = {"data": [{"id": "og1"}]}
        result = org_guardrails_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/guardrails"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayOrgGuardrail"

    @patch.object(Client, "http_request")
    def test_deployments_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Deployments route to the admin plane and support list filters."""
        mock_http.return_value = {"data": [{"id": "d1"}]}
        deployments_list_command(mock_client, {"workspace_slug": "a,b", "status": "active"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/deployments"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["params"]["workspace_slug"] == ["a", "b"]

    @patch.object(Client, "http_request")
    def test_deployments_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating a deployment parses nested config and boolean args."""
        mock_http.return_value = {"id": "d1"}
        deployments_create_command(
            mock_client,
            {"name": "prod", "deployment_config": '{"a": 1}', "is_default": "true"},
        )

        _, kwargs = mock_http.call_args
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"]["deployment_config"] == {"a": 1}
        assert kwargs["json_data"]["is_default"] is True

    @patch.object(Client, "http_request")
    def test_deployments_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Deleting a deployment confirms success on the admin plane."""
        mock_http.return_value = None
        result = deployments_delete_command(mock_client, {"deployment_id": "d1"})

        _, kwargs = mock_http.call_args
        assert kwargs["use_aigw_admin"] is True
        assert "deleted successfully" in result.readable_output

    @patch.object(Client, "http_request")
    def test_deployment_ping(self, mock_http: Mock, mock_client: Client) -> None:
        """Pinging a deployment uses the ping path and injects the deployment id."""
        mock_http.return_value = {"status": "healthy", "gateway_base_url": "https://gw"}
        result = deployment_ping_command(mock_client, {"deployment_id": "d1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/deployments/d1/ping"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs["deployment_id"] == "d1"
        assert result.outputs["status"] == "healthy"

    @patch.object(Client, "http_request")
    def test_secret_references_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Secret references route to the admin plane."""
        mock_http.return_value = {"data": [{"id": "s1"}]}
        secret_references_list_command(mock_client, {"manager_type": "aws_sm"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/secret-references"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["params"]["manager_type"] == "aws_sm"

    @patch.object(Client, "http_request")
    def test_secret_references_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating a secret reference parses auth_config JSON on the admin plane."""
        mock_http.return_value = {"id": "s1", "slug": "sec"}
        secret_references_create_command(
            mock_client,
            {
                "name": "sec",
                "manager_type": "aws_sm",
                "auth_config": '{"role_arn": "x"}',
                "secret_path": "/prod/key",
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"]["auth_config"] == {"role_arn": "x"}
        assert kwargs["json_data"]["secret_path"] == "/prod/key"

    @patch.object(Client, "http_request")
    def test_mcp_integrations_list(self, mock_http: Mock, mock_client: Client) -> None:
        """MCP integrations route to the admin plane."""
        mock_http.return_value = {"data": [{"id": "i1"}]}
        result = mcp_integrations_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-integrations"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayMcpIntegration"

    @patch.object(Client, "http_request")
    def test_mcp_integrations_create(self, mock_http: Mock, mock_client: Client) -> None:
        """Creating an MCP integration sends required fields on the admin plane."""
        mock_http.return_value = {"id": "i1", "slug": "int"}
        mcp_integrations_create_command(
            mock_client,
            {
                "name": "int",
                "url": "https://mcp",
                "auth_type": "none",
                "transport": "http",
            },
        )

        _, kwargs = mock_http.call_args
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"] == {
            "name": "int",
            "url": "https://mcp",
            "auth_type": "none",
            "transport": "http",
        }


class TestWorkspaces:
    """Test cases for the workspace discovery commands."""

    @patch.object(Client, "http_request")
    def test_workspaces_list_defaults_to_data_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """Without a plane arg, the list reads the data plane and unwraps the envelope."""
        mock_http.return_value = {"success": True, "data": [{"id": "ws-1", "name": "Prod"}]}
        result = workspaces_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/workspaces"
        assert kwargs["use_aigw_cp"] is True
        assert "use_aigw_admin" not in kwargs
        assert result.outputs == [{"id": "ws-1", "name": "Prod"}]

    @patch.object(Client, "http_request")
    def test_workspaces_list_admin_plane_with_status(self, mock_http: Mock, mock_client: Client) -> None:
        """plane=admin routes to the admin plane and the status filter is forwarded."""
        mock_http.return_value = {"data": []}
        workspaces_list_command(mock_client, {"plane": "admin", "status": "archived"})

        args, kwargs = mock_http.call_args
        assert kwargs["use_aigw_admin"] is True
        assert "use_aigw_cp" not in kwargs
        assert kwargs["params"] == {"status": "archived"}

    @patch.object(Client, "http_request")
    def test_workspaces_get_by_ref(self, mock_http: Mock, mock_client: Client) -> None:
        """Get reads /workspaces/<ref> and unwraps a data envelope when present."""
        mock_http.return_value = {"data": {"id": "ws-1", "slug": "prod"}}
        result = workspaces_get_command(mock_client, {"workspace_ref": "prod"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/workspaces/prod"
        assert kwargs["use_aigw_cp"] is True
        assert result.outputs == {"id": "ws-1", "slug": "prod"}

    @patch.object(Client, "http_request")
    def test_workspaces_create_sends_body_on_admin_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """Create POSTs to the admin plane with name + scope_name and forwards optional JSON fields."""
        mock_http.return_value = {"id": "ws-9", "name": "New", "slug": "new-a1b2", "scope_name": "ws_new_x1"}
        result = workspaces_create_command(
            mock_client,
            {
                "name": "New",
                "scope_name": "ws_new_x1",
                "description": "desc",
                "users": "u1,u2",
                "defaults": '{"allow_config_override": true}',
            },
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/workspaces"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"] == {
            "name": "New",
            "scope_name": "ws_new_x1",
            "description": "desc",
            "users": ["u1", "u2"],
            "defaults": {"allow_config_override": True},
        }
        assert result.outputs["id"] == "ws-9"

    @patch.object(Client, "http_request")
    def test_workspaces_update_partial_patch(self, mock_http: Mock, mock_client: Client) -> None:
        """Update PUTs only the supplied fields to /workspaces/<ref> on the admin plane."""
        mock_http.return_value = {}
        workspaces_update_command(mock_client, {"workspace_ref": "prod", "description": "changed"})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/workspaces/prod"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"] == {"description": "changed"}

    def test_workspaces_update_requires_a_field(self, mock_client: Client) -> None:
        """Update with no updatable field raises rather than sending an empty patch."""
        with pytest.raises(ValueError, match="at least one field"):
            workspaces_update_command(mock_client, {"workspace_ref": "prod"})

    @patch.object(Client, "http_request")
    def test_workspaces_archive_soft_deletes(self, mock_http: Mock, mock_client: Client) -> None:
        """Archive issues a DELETE to /workspaces/<ref> on the admin plane."""
        mock_http.return_value = {}
        result = workspaces_archive_command(mock_client, {"workspace_ref": "prod"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/workspaces/prod"
        assert kwargs["use_aigw_admin"] is True
        assert "archived" in result.readable_output


class TestWorkspaceProvision:
    """Test cases for the end-to-end workspace provisioning composite (admin + IAM planes)."""

    @patch.object(Client, "http_request")
    def test_provision_generates_scope_and_runs_full_sequence(self, mock_http: Mock, mock_client: Client) -> None:
        """A generated scope name drives scope create -> workspace create -> scope bind, in order."""
        mock_http.side_effect = [
            {"name": "ws_truffles_abc123"},  # scope create
            {"data": {"id": "ws-9", "slug": "ws-truffl-03e7d9"}},  # workspace create
            {"resources": [], "description": ""},  # scope get (for bind)
            {
                "name": "ws_truffles_abc123",
                "resources": [{"resource_type": "workspace", "resource_id": "ws-truffl-03e7d9"}],
            },  # bind PUT
        ]
        result = workspaces_provision_command(mock_client, {"name": "Truffles", "description": "recipes"})

        calls = mock_http.call_args_list
        # Step 1: IAM-plane scope create with a generated ws_<stem>_<suffix> name.
        assert calls[0].args[0] == "POST"
        assert calls[0].args[1] == "/scopes"
        assert calls[0].kwargs["use_aigw_iam"] is True
        created_scope = calls[0].kwargs["json_data"]["name"]
        assert re.fullmatch(r"ws_truffles_[a-z0-9]{6}", created_scope)
        # Step 2: admin-plane workspace create bound to that scope_name.
        assert calls[1].args[0] == "POST"
        assert calls[1].args[1] == "/workspaces"
        assert calls[1].kwargs["use_aigw_admin"] is True
        assert calls[1].kwargs["json_data"]["scope_name"] == created_scope
        # Step 3: IAM-plane bind PUT that adds the new slug to the scope resources.
        assert calls[3].args[0] == "PUT"
        assert calls[3].args[1] == f"/scopes/{created_scope}"
        assert calls[3].kwargs["json_data"]["resources"][0]["resource_id"] == "ws-truffl-03e7d9"

        assert result.outputs_prefix == "PrismaAIRs.AIGatewayWorkspaceProvision"
        assert result.outputs["workspace_slug"] == "ws-truffl-03e7d9"
        assert result.outputs["scope_created"] is True

    @patch.object(Client, "http_request")
    def test_provision_existing_scope_skips_scope_create(self, mock_http: Mock, mock_client: Client) -> None:
        """existing_scope=true reuses the scope: no create call, and scope_created is False."""
        mock_http.side_effect = [
            {"data": {"id": "ws-9", "slug": "ws-stage-1"}},  # workspace create
            {"resources": [{"resource_type": "workspace", "resource_id": "ws-old"}], "description": "d"},  # scope get
            {"name": "ws_staging_q1x8mz"},  # bind PUT
        ]
        result = workspaces_provision_command(
            mock_client, {"name": "Staging", "scope_name": "ws_staging_q1x8mz", "existing_scope": "true"}
        )

        calls = mock_http.call_args_list
        assert len(calls) == 3  # no scope-create call
        assert calls[0].args[1] == "/workspaces"
        # The existing binding is preserved and the new slug appended.
        put_resources = calls[2].kwargs["json_data"]["resources"]
        assert {"resource_type": "workspace", "resource_id": "ws-old", "metadata": []} in put_resources
        assert any(r["resource_id"] == "ws-stage-1" for r in put_resources)
        assert result.outputs["scope_created"] is False

    def test_provision_existing_scope_requires_scope_name(self, mock_client: Client) -> None:
        """existing_scope=true without scope_name is rejected before any request."""
        with pytest.raises(ValueError, match="scope_name is required"):
            workspaces_provision_command(mock_client, {"name": "Staging", "existing_scope": "true"})

    @patch.object(Client, "http_request")
    def test_provision_rolls_back_scope_when_workspace_create_fails(self, mock_http: Mock, mock_client: Client) -> None:
        """If workspace create fails after the scope was created, the scope is deleted again."""
        mock_http.side_effect = [
            {"name": "ws_prod_zzz999"},  # scope create OK
            DemistoException("workspace create boom"),  # workspace create fails
            None,  # scope delete (rollback) OK
        ]
        with pytest.raises(DemistoException, match="deleted again"):
            workspaces_provision_command(mock_client, {"name": "Prod"})

        calls = mock_http.call_args_list
        assert calls[2].args[0] == "DELETE"
        assert calls[2].args[1].startswith("/scopes/ws_prod_")
        assert calls[2].kwargs["use_aigw_iam"] is True


class TestScopes:
    """Test cases for the SCM IAM scope commands (use_aigw_iam plane)."""

    @patch.object(Client, "http_request")
    def test_scopes_list_unwraps_items(self, mock_http: Mock, mock_client: Client) -> None:
        """List reads /scopes on the IAM plane and unwraps the {count, items} envelope."""
        mock_http.return_value = {"count": 1, "items": [{"name": "ws_prod_ab12cd", "id": "ws_prod_ab12cd:1001"}]}
        result = scopes_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/scopes"
        assert kwargs["use_aigw_iam"] is True
        assert result.outputs == [{"name": "ws_prod_ab12cd", "id": "ws_prod_ab12cd:1001"}]

    @patch.object(Client, "http_request")
    def test_scopes_get_by_name(self, mock_http: Mock, mock_client: Client) -> None:
        """Get reads /scopes/<name> and returns the scope object directly (no envelope)."""
        mock_http.return_value = {"name": "ws_prod_ab12cd", "description": "prod", "resources": []}
        result = scopes_get_command(mock_client, {"name": "ws_prod_ab12cd"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/scopes/ws_prod_ab12cd"
        assert kwargs["use_aigw_iam"] is True
        assert result.outputs["name"] == "ws_prod_ab12cd"

    @patch.object(Client, "http_request")
    def test_scopes_create_sends_full_body(self, mock_http: Mock, mock_client: Client) -> None:
        """Create POSTs name plus always-present description and resources, mirroring SCM."""
        mock_http.return_value = {"name": "ws_new_zz99", "id": "ws_new_zz99:1001"}
        scopes_create_command(mock_client, {"name": "ws_new_zz99"})

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/scopes"
        assert kwargs["json_data"] == {"name": "ws_new_zz99", "description": "", "resources": []}
        assert kwargs["use_aigw_iam"] is True

    @patch.object(Client, "http_request")
    def test_scopes_update_full_replacement(self, mock_http: Mock, mock_client: Client) -> None:
        """Update PUTs to /scopes/<name> with name echoed into the body."""
        mock_http.return_value = {"name": "ws_prod_ab12cd"}
        resources = '[{"resource_type":"workspace","resource_id":"ws-prod-1"}]'
        scopes_update_command(mock_client, {"name": "ws_prod_ab12cd", "description": "d", "resources": resources})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/scopes/ws_prod_ab12cd"
        assert kwargs["json_data"]["name"] == "ws_prod_ab12cd"
        assert kwargs["json_data"]["resources"] == [{"resource_type": "workspace", "resource_id": "ws-prod-1"}]

    @patch.object(Client, "http_request")
    def test_scopes_bind_appends_workspace(self, mock_http: Mock, mock_client: Client) -> None:
        """Bind reads the scope, appends the workspace binding, then PUTs the merged resources."""
        mock_http.side_effect = [
            {"name": "ws_prod_ab12cd", "description": "d", "resources": [{"resource_type": "app", "resource_id": "a1"}]},
            {"name": "ws_prod_ab12cd"},
        ]
        scopes_bind_command(mock_client, {"name": "ws_prod_ab12cd", "workspace_slug": "ws-prod-1"})

        # Second call is the PUT with the merged resource list.
        put_args, put_kwargs = mock_http.call_args
        assert put_args[0] == "PUT"
        assert put_kwargs["json_data"]["resources"] == [
            {"resource_type": "app", "resource_id": "a1", "metadata": []},
            {"resource_type": "workspace", "resource_id": "ws-prod-1", "metadata": []},
        ]

    @patch.object(Client, "http_request")
    def test_scopes_bind_is_idempotent(self, mock_http: Mock, mock_client: Client) -> None:
        """Binding an already-bound workspace does not duplicate the resource."""
        mock_http.side_effect = [
            {
                "name": "ws_prod_ab12cd",
                "description": "d",
                "resources": [{"resource_type": "workspace", "resource_id": "ws-prod-1", "metadata": []}],
            },
            {"name": "ws_prod_ab12cd"},
        ]
        scopes_bind_command(mock_client, {"name": "ws_prod_ab12cd", "workspace_slug": "ws-prod-1"})

        _, put_kwargs = mock_http.call_args
        assert put_kwargs["json_data"]["resources"] == [
            {"resource_type": "workspace", "resource_id": "ws-prod-1", "metadata": []}
        ]

    @patch.object(Client, "http_request")
    def test_scopes_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Delete confirms success on the IAM plane."""
        mock_http.return_value = None
        result = scopes_delete_command(mock_client, {"name": "ws_prod_ab12cd"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/scopes/ws_prod_ab12cd"
        assert kwargs["use_aigw_iam"] is True
        assert "deleted successfully" in result.readable_output


class TestIntegrations:
    """Test cases for the credential integrations commands (use_aigw_admin plane)."""

    @patch.object(Client, "http_request")
    def test_integrations_catalog_reads_static_resources(self, mock_http: Mock, mock_client: Client) -> None:
        """The catalog reads the static provider resources on the admin plane."""
        mock_http.return_value = {"data": [{"id": "prov-uuid", "slug": "open-ai", "name": "OpenAI"}]}
        result = integrations_catalog_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/utils/static-resources/ai-providers"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs == [{"id": "prov-uuid", "slug": "open-ai", "name": "OpenAI"}]

    @patch.object(Client, "http_request")
    def test_integrations_list_unwraps_envelope(self, mock_http: Mock, mock_client: Client) -> None:
        """List reads /integrations on the admin plane and unwraps the data envelope."""
        mock_http.return_value = {"data": [{"id": "int-1", "slug": "openai-prod"}]}
        result = integrations_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/integrations"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs == [{"id": "int-1", "slug": "openai-prod"}]

    @patch.object(Client, "http_request")
    def test_integrations_get_by_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """Get reads /integrations/<id> on the admin plane."""
        mock_http.return_value = {"data": {"id": "int-1", "name": "OpenAI prod"}}
        result = integrations_get_command(mock_client, {"integration_id": "int-1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/integrations/int-1"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs["id"] == "int-1"

    @patch.object(Client, "http_request")
    def test_integrations_models_list_reads_subresource(self, mock_http: Mock, mock_client: Client) -> None:
        """Models list reads the /models sub-resource of an integration."""
        mock_http.return_value = {"data": [{"slug": "gpt-4o", "name": "GPT-4o"}]}
        result = integrations_models_list_command(mock_client, {"integration_id": "int-1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/integrations/int-1/models"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs == [{"slug": "gpt-4o", "name": "GPT-4o"}]

    @patch.object(Client, "http_request")
    def test_integrations_workspaces_list_reads_subresource(self, mock_http: Mock, mock_client: Client) -> None:
        """Workspaces list reads the /workspaces sub-resource of an integration."""
        mock_http.return_value = {"data": [{"id": "ws-1"}]}
        result = integrations_workspaces_list_command(mock_client, {"integration_id": "int-1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/integrations/int-1/workspaces"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs == [{"id": "ws-1"}]

    @patch.object(Client, "http_request")
    def test_integrations_create_defaults_org_id_to_tsg(self, mock_http: Mock, mock_client: Client) -> None:
        """Create POSTs to /integrations and defaults organisation_id to the tenant TSG id."""
        mock_http.return_value = {"data": {"id": "int-1", "slug": "openai-prod"}}
        integrations_create_command(mock_client, {"ai_provider_id": "prov-uuid", "name": "OpenAI prod", "slug": "openai-prod"})

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/integrations"
        assert kwargs["use_aigw_admin"] is True
        # organisation_id falls back to the client's configured TSG id.
        assert kwargs["json_data"]["organisation_id"] == "1234567890"
        assert kwargs["json_data"]["ai_provider_id"] == "prov-uuid"

    @patch.object(Client, "http_request")
    def test_integrations_create_honors_explicit_org_id(self, mock_http: Mock, mock_client: Client) -> None:
        """An explicit organisation_id overrides the TSG default."""
        mock_http.return_value = {"data": {"id": "int-1"}}
        integrations_create_command(
            mock_client,
            {"ai_provider_id": "prov-uuid", "name": "n", "slug": "s", "organisation_id": "9999"},
        )

        _, kwargs = mock_http.call_args
        assert kwargs["json_data"]["organisation_id"] == "9999"

    @patch.object(Client, "http_request")
    def test_integrations_update_requires_a_field(self, mock_http: Mock, mock_client: Client) -> None:
        """Update with no updatable fields raises before any request is made."""
        with pytest.raises(ValueError, match="at least one field"):
            integrations_update_command(mock_client, {"integration_id": "int-1"})
        mock_http.assert_not_called()

    @patch.object(Client, "http_request")
    def test_integrations_update_partial_patch(self, mock_http: Mock, mock_client: Client) -> None:
        """Update PUTs only the provided fields to /integrations/<id>."""
        mock_http.return_value = None
        integrations_update_command(mock_client, {"integration_id": "int-1", "name": "renamed"})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/integrations/int-1"
        assert kwargs["json_data"] == {"name": "renamed"}

    @patch.object(Client, "http_request")
    def test_integrations_delete_sends_org_param(self, mock_http: Mock, mock_client: Client) -> None:
        """Delete sends the required organisation_id query param, defaulting to the TSG id."""
        mock_http.return_value = None
        result = integrations_delete_command(mock_client, {"integration_id": "int-1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/integrations/int-1"
        assert kwargs["params"]["organisation_id"] == "1234567890"
        assert "deleted successfully" in result.readable_output

    @patch.object(Client, "http_request")
    def test_integrations_models_set_sends_models(self, mock_http: Mock, mock_client: Client) -> None:
        """Models set PUTs the parsed models array to the /models sub-resource."""
        mock_http.return_value = None
        integrations_models_set_command(mock_client, {"integration_id": "int-1", "models": '[{"slug":"gpt-4o"}]'})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/integrations/int-1/models"
        assert kwargs["json_data"]["models"] == [{"slug": "gpt-4o"}]

    @patch.object(Client, "http_request")
    def test_integrations_models_delete_joins_slugs(self, mock_http: Mock, mock_client: Client) -> None:
        """Models delete sends the slugs as a comma-joined query param."""
        mock_http.return_value = None
        integrations_models_delete_command(mock_client, {"integration_id": "int-1", "slugs": "gpt-4o,gpt-4o-mini"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/integrations/int-1/models"
        assert kwargs["params"]["slugs"] == "gpt-4o,gpt-4o-mini"

    @patch.object(Client, "http_request")
    def test_integrations_workspaces_set_requires_a_field(self, mock_http: Mock, mock_client: Client) -> None:
        """Workspaces set with no fields raises before any request is made."""
        with pytest.raises(ValueError, match="at least one field"):
            integrations_workspaces_set_command(mock_client, {"integration_id": "int-1"})
        mock_http.assert_not_called()


class TestProviders:
    """Test cases for the provider binding commands (use_aigw_cp plane)."""

    @patch.object(Client, "http_request")
    def test_providers_list_sends_workspace_id(self, mock_http: Mock, mock_client: Client) -> None:
        """List sends workspace_id on the control plane and unwraps the data envelope."""
        mock_http.return_value = {"data": [{"id": "p-1", "slug": "openai-calvin", "integration_id": "int-1"}]}
        result = providers_list_command(mock_client, {"workspace_id": "ws-1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/providers"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"]["workspace_id"] == "ws-1"
        assert result.outputs == [{"id": "p-1", "slug": "openai-calvin", "integration_id": "int-1"}]

    @patch.object(Client, "http_request")
    def test_providers_list_strips_secret_key(self, mock_http: Mock, mock_client: Client) -> None:
        """Raw credential material (key) is stripped from list output; masked_api_key is kept."""
        mock_http.return_value = {"data": [{"id": "p-1", "key": "sk-secret", "masked_api_key": "sk-****"}]}
        result = providers_list_command(mock_client, {"workspace_id": "ws-1"})

        assert "key" not in result.outputs[0]
        assert result.outputs[0]["masked_api_key"] == "sk-****"

    @patch.object(Client, "http_request")
    def test_providers_get_strips_secret_key(self, mock_http: Mock, mock_client: Client) -> None:
        """Get reads /providers/<id> and strips the raw API key from every surface."""
        mock_http.return_value = {"id": "p-1", "name": "openai", "key": "sk-secret", "masked_api_key": "sk-****"}
        result = providers_get_command(mock_client, {"provider_id": "p-1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/providers/p-1"
        assert kwargs["use_aigw_cp"] is True
        assert "key" not in result.outputs
        assert "key" not in (result.raw_response or {})
        assert result.outputs["masked_api_key"] == "sk-****"

    @patch.object(Client, "http_request")
    def test_providers_create_sends_binding_body(self, mock_http: Mock, mock_client: Client) -> None:
        """Create POSTs the workspace/provider/integration binding to /providers on the control plane."""
        mock_http.return_value = {"id": "p-1", "slug": "openai-calvin", "object": "provider"}
        providers_create_command(
            mock_client,
            {
                "workspace_id": "ws-1",
                "ai_provider_id": "prov-uuid",
                "integration_id": "int-1",
                "name": "openai-calvin",
                "slug": "openai-calvin",
            },
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/providers"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["json_data"]["workspace_id"] == "ws-1"
        assert kwargs["json_data"]["ai_provider_id"] == "prov-uuid"
        assert kwargs["json_data"]["integration_id"] == "int-1"

    @patch.object(Client, "http_request")
    def test_providers_update_requires_a_field(self, mock_http: Mock, mock_client: Client) -> None:
        """Update with no updatable fields raises before any request is made."""
        with pytest.raises(ValueError, match="at least one field"):
            providers_update_command(mock_client, {"provider_id": "p-1"})
        mock_http.assert_not_called()

    @patch.object(Client, "http_request")
    def test_providers_update_partial_patch(self, mock_http: Mock, mock_client: Client) -> None:
        """Update PUTs only the provided fields to /providers/<id>."""
        mock_http.return_value = None
        providers_update_command(mock_client, {"provider_id": "p-1", "note": "rotated"})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/providers/p-1"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["json_data"] == {"note": "rotated"}

    @patch.object(Client, "http_request")
    def test_providers_delete_is_hard_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Delete issues a DELETE to /providers/<id> on the control plane."""
        mock_http.return_value = None
        result = providers_delete_command(mock_client, {"provider_id": "p-1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/providers/p-1"
        assert kwargs["use_aigw_cp"] is True
        assert "deleted successfully" in result.readable_output


class TestModelPricing:
    """Test cases for the public model-pricing catalog command (unauthenticated, off-gateway)."""

    @patch.object(Client, "_http_request")
    def test_model_pricing_get_hits_public_catalog_unauthenticated(self, mock_raw: Mock, mock_client: Client) -> None:
        """The pricing read goes to the public catalog via a direct full_url call with no auth header."""
        mock_raw.return_value = {"currency": "USD", "pay_as_you_go": {"request_token": {"price": 0.01}}}
        result = model_pricing_get_command(mock_client, {"provider": "openai", "model": "gpt-4o"})

        _, kwargs = mock_raw.call_args
        assert kwargs["full_url"] == "https://api.portkey.ai/model-configs/pricing/openai/gpt-4o"
        # No Authorization / x-tsg-id: this is an off-gateway public read.
        assert "Authorization" not in kwargs["headers"]
        assert "x-tsg-id" not in kwargs["headers"]
        # provider/model are echoed into the context for identification.
        assert result.outputs["provider"] == "openai"
        assert result.outputs["model"] == "gpt-4o"
        assert result.outputs["currency"] == "USD"

    @patch.object(Client, "_http_request")
    def test_model_pricing_get_encodes_and_honors_endpoint(self, mock_raw: Mock, mock_client: Client) -> None:
        """A custom endpoint is used and provider/model path segments are URL-encoded."""
        mock_raw.return_value = {"currency": "USD"}
        model_pricing_get_command(
            mock_client, {"provider": "open ai", "model": "gpt/4o", "endpoint": "https://pricing.example.com/"}
        )

        _, kwargs = mock_raw.call_args
        assert kwargs["full_url"] == "https://pricing.example.com/model-configs/pricing/open%20ai/gpt%2F4o"

    @patch.object(Client, "_http_request")
    def test_model_pricing_get_rejects_non_https_endpoint(self, mock_raw: Mock, mock_client: Client) -> None:
        """A non-HTTPS, non-loopback endpoint is rejected before any request is made."""
        with pytest.raises(ValueError, match="HTTPS"):
            model_pricing_get_command(
                mock_client, {"provider": "openai", "model": "gpt-4o", "endpoint": "http://evil.example.com"}
            )
        mock_raw.assert_not_called()


class TestMcpServerSubresources:
    """MCP server capability / user-access / connection sub-resources (control plane)."""

    @patch.object(Client, "http_request")
    def test_capabilities_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing capabilities routes to the control-plane sub-path and forwards paging + type."""
        mock_http.return_value = {"data": [{"name": "lookup", "type": "tool", "enabled": True}]}
        result = mcp_servers_capabilities_list_command(
            mock_client, {"mcp_server_id": "m1", "type": "tool", "page": "2", "page_size": "10"}
        )

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-servers/m1/capabilities"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"] == {"page": 2, "page_size": 10, "type": "tool"}
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayMcpServerCapability"
        assert result.outputs == [{"name": "lookup", "type": "tool", "enabled": True}]

    @patch.object(Client, "http_request")
    def test_capabilities_set(self, mock_http: Mock, mock_client: Client) -> None:
        """Setting capabilities PUTs the parsed JSON array to the control-plane sub-path."""
        mock_http.return_value = None
        result = mcp_servers_capabilities_set_command(
            mock_client,
            {"mcp_server_id": "m1", "capabilities": '[{"name": "lookup", "type": "tool", "enabled": false}]'},
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/mcp-servers/m1/capabilities"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["json_data"] == {"capabilities": [{"name": "lookup", "type": "tool", "enabled": False}]}
        assert "updated successfully" in result.readable_output

    def test_capabilities_set_requires_a_field(self, mock_client: Client) -> None:
        """Omitting capabilities raises the at-least-one-field guard."""
        with pytest.raises(ValueError, match="at least one field"):
            mcp_servers_capabilities_set_command(mock_client, {"mcp_server_id": "m1"})

    @patch.object(Client, "http_request")
    def test_user_access_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing user access routes to the control-plane sub-path and forwards search."""
        mock_http.return_value = {"data": [{"user_id": "u1", "enabled": True}]}
        result = mcp_servers_user_access_list_command(mock_client, {"mcp_server_id": "m1", "search": "ann"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-servers/m1/user-access"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"] == {"search": "ann"}
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayMcpServerUserAccess"

    @patch.object(Client, "http_request")
    def test_user_access_set(self, mock_http: Mock, mock_client: Client) -> None:
        """Setting user access PUTs the parsed array plus the default value."""
        mock_http.return_value = None
        result = mcp_servers_user_access_set_command(
            mock_client,
            {
                "mcp_server_id": "m1",
                "user_access": '[{"user_id": "u1", "enabled": true}]',
                "default_user_access": "disabled",
            },
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/mcp-servers/m1/user-access"
        assert kwargs["json_data"] == {
            "user_access": [{"user_id": "u1", "enabled": True}],
            "default_user_access": "disabled",
        }
        assert "updated successfully" in result.readable_output

    def test_user_access_set_requires_a_field(self, mock_client: Client) -> None:
        """Omitting all fields raises the at-least-one-field guard."""
        with pytest.raises(ValueError, match="at least one field"):
            mcp_servers_user_access_set_command(mock_client, {"mcp_server_id": "m1"})

    @patch.object(Client, "http_request")
    def test_connections_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing connections routes to the control-plane sub-path and forwards filters."""
        mock_http.return_value = {"data": [{"user_id": "u1", "connected": True}]}
        result = mcp_servers_connections_list_command(
            mock_client, {"mcp_server_id": "m1", "user_id": "u1", "workspace_id": "w1", "current_page": "0"}
        )

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-servers/m1/connections"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"] == {"user_id": "u1", "workspace_id": "w1", "current_page": 0}
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayMcpServerConnection"

    @patch.object(Client, "http_request")
    def test_connections_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Deleting connections issues a scoped DELETE on the control plane."""
        mock_http.return_value = None
        result = mcp_servers_connections_delete_command(mock_client, {"mcp_server_id": "m1", "user_id": "u1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/mcp-servers/m1/connections"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"] == {"user_id": "u1"}
        assert "deleted successfully" in result.readable_output


class TestMcpIntegrationSubresources:
    """MCP integration workspace / capability / metadata sub-resources (admin plane)."""

    @patch.object(Client, "http_request")
    def test_workspaces_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing integration workspaces routes to the admin-plane sub-path and forwards version."""
        mock_http.return_value = {"data": [{"id": "w1", "enabled": True}]}
        result = mcp_integrations_workspaces_list_command(mock_client, {"mcp_integration_id": "i1", "version": "2"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-integrations/i1/workspaces"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["params"] == {"version": "2"}
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayMcpIntegrationWorkspace"

    @patch.object(Client, "http_request")
    def test_capabilities_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing integration capabilities routes to the admin-plane sub-path."""
        mock_http.return_value = {"data": [{"name": "lookup", "type": "tool"}]}
        result = mcp_integrations_capabilities_list_command(mock_client, {"mcp_integration_id": "i1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-integrations/i1/capabilities"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayMcpIntegrationCapability"

    @patch.object(Client, "http_request")
    def test_metadata_get_injects_id(self, mock_http: Mock, mock_client: Client) -> None:
        """Metadata read routes to the admin-plane sub-path and injects the integration id."""
        mock_http.return_value = {"sync_status": "synced", "protocol_version": "1.0"}
        result = mcp_integrations_metadata_get_command(mock_client, {"mcp_integration_id": "i1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/mcp-integrations/i1/metadata"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs["mcp_integration_id"] == "i1"
        assert result.outputs["sync_status"] == "synced"

    @patch.object(Client, "http_request")
    def test_capabilities_set(self, mock_http: Mock, mock_client: Client) -> None:
        """Setting integration capabilities PUTs the parsed array on the admin plane."""
        mock_http.return_value = None
        result = mcp_integrations_capabilities_set_command(
            mock_client,
            {"mcp_integration_id": "i1", "capabilities": '[{"name": "lookup", "type": "tool", "enabled": true}]'},
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/mcp-integrations/i1/capabilities"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"] == {"capabilities": [{"name": "lookup", "type": "tool", "enabled": True}]}
        assert "updated successfully" in result.readable_output

    def test_capabilities_set_requires_a_field(self, mock_client: Client) -> None:
        """Omitting capabilities raises the at-least-one-field guard."""
        with pytest.raises(ValueError, match="at least one field"):
            mcp_integrations_capabilities_set_command(mock_client, {"mcp_integration_id": "i1"})

    @patch.object(Client, "http_request")
    def test_workspaces_set(self, mock_http: Mock, mock_client: Client) -> None:
        """Setting integration workspaces PUTs parsed bindings + booleans on the admin plane."""
        mock_http.return_value = None
        result = mcp_integrations_workspaces_set_command(
            mock_client,
            {
                "mcp_integration_id": "i1",
                "workspaces": '[{"id": "w1", "enabled": true}]',
                "override_existing_workspace_access": "true",
            },
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/mcp-integrations/i1/workspaces"
        assert kwargs["use_aigw_admin"] is True
        assert kwargs["json_data"] == {
            "workspaces": [{"id": "w1", "enabled": True}],
            "override_existing_workspace_access": True,
        }
        assert "updated successfully" in result.readable_output

    def test_workspaces_set_requires_a_field(self, mock_client: Client) -> None:
        """Omitting all fields raises the at-least-one-field guard."""
        with pytest.raises(ValueError, match="at least one field"):
            mcp_integrations_workspaces_set_command(mock_client, {"mcp_integration_id": "i1"})


class TestConnection:
    """Test cases for the connectivity check."""

    @patch.object(Client, "http_request")
    def test_test_connection_ok(self, mock_http: Mock, mock_client: Client) -> None:
        """A successful admin-plane organisation read returns 'ok'."""
        mock_http.return_value = {"data": {}}
        assert run_connection_check(mock_client) == "ok"

        args, kwargs = mock_http.call_args
        # Probes /organisations/self on the admin plane: no workspace param, so no 404 AB02.
        assert args[1] == "/organisations/self"
        assert kwargs["use_aigw_admin"] is True

    @patch.object(Client, "_http_request")
    @patch.object(Client, "get_access_token")
    def test_aigw_uses_oauth_token(self, mock_token: Mock, mock_raw: Mock, mock_client: Client) -> None:
        """AI Gateway requests authenticate via the shared SCM OAuth2 token, not a static key."""
        mock_token.return_value = "oauth-access-token"
        mock_raw.return_value = {"data": []}

        mock_client.http_request("GET", "/guardrails", use_aigw_cp=True)

        mock_token.assert_called_once()
        _, kwargs = mock_raw.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer oauth-access-token"
        assert kwargs["headers"]["service-name"] == "api"
        # Every AI Gateway endpoint requires the tenant header on top of the bearer token.
        assert kwargs["headers"]["x-tsg-id"] == "1234567890"
        assert kwargs["full_url"] == "https://api.apps.paloaltonetworks.com/ai_gw/v2/guardrails"


class TestGuardrailSubresources:
    """Test cases for the guardrail catalog and MCP-server mapping sub-resources."""

    @patch.object(Client, "http_request")
    def test_guardrails_catalog_uses_admin_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """The evaluator catalog is an admin-plane static-resources read scoped to guardrails."""
        mock_http.return_value = {"data": [{"id": "panw-prisma-airs.intercept", "name": "Prisma AIRS"}]}
        result = guardrails_catalog_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[0] == "GET"
        assert args[1] == "/utils/static-resources/schema"
        assert kwargs["params"] == {"resource": "guardrails"}
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayGuardrailCatalog"
        assert result.outputs[0]["id"] == "panw-prisma-airs.intercept"

    @patch.object(Client, "http_request")
    def test_guardrails_mcp_servers_list(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing mappings hits the control-plane sub-path and unwraps the data envelope."""
        mock_http.return_value = {"data": [{"id": "m1", "mcp_server_id": "s1", "run_on": ["request"]}]}
        result = guardrails_mcp_servers_list_command(mock_client, {"guardrail_id": "g1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "GET"
        assert args[1] == "/guardrails/g1/mcp-servers"
        assert kwargs["use_aigw_cp"] is True
        assert result.outputs[0]["id"] == "m1"

    @patch.object(Client, "http_request")
    def test_guardrails_mcp_servers_sync(self, mock_http: Mock, mock_client: Client) -> None:
        """Bulk sync PUTs the mcp_servers map and echoes the guardrail id into outputs."""
        mock_http.return_value = {"changed": True, "added": 1, "updated": 0, "removed": 2}
        result = guardrails_mcp_servers_sync_command(
            mock_client,
            {"guardrail_id": "g1", "mcp_servers": '{"s1": {"run_on": ["request"]}}'},
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/guardrails/g1/mcp-servers"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["json_data"] == {"mcp_servers": {"s1": {"run_on": ["request"]}}}
        assert result.outputs["guardrail_id"] == "g1"
        assert result.outputs["added"] == 1

    def test_guardrails_mcp_servers_sync_requires_body(self, mock_client: Client) -> None:
        """Bulk sync with no mcp_servers payload is rejected before any request."""
        with pytest.raises(ValueError, match="at least one field"):
            guardrails_mcp_servers_sync_command(mock_client, {"guardrail_id": "g1"})

    @patch.object(Client, "http_request")
    def test_guardrails_mcp_server_set(self, mock_http: Mock, mock_client: Client) -> None:
        """Single mapping PUTs run_on/capability lists and echoes both ids into outputs."""
        mock_http.return_value = {"map_id": "m9"}
        result = guardrails_mcp_server_set_command(
            mock_client,
            {"guardrail_id": "g1", "mcp_server_id": "s1", "run_on": "request,response"},
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/guardrails/g1/mcp-servers/s1"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["json_data"] == {"run_on": ["request", "response"]}
        assert result.outputs["map_id"] == "m9"
        assert result.outputs["guardrail_id"] == "g1"
        assert result.outputs["mcp_server_id"] == "s1"

    def test_guardrails_mcp_server_set_requires_field(self, mock_client: Client) -> None:
        """A mapping set with neither run_on nor capability ids is rejected before any request."""
        with pytest.raises(ValueError, match="at least one field"):
            guardrails_mcp_server_set_command(mock_client, {"guardrail_id": "g1", "mcp_server_id": "s1"})


class TestPlugins:
    """Test cases for the organisation-level plugin binding commands (admin plane)."""

    @patch.object(Client, "http_request")
    def test_plugins_list_uses_admin_plane_and_redacts(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing hits the admin plane and masks any credential value that is not already server-masked."""
        mock_http.return_value = {
            "data": [
                {
                    "id": "p1",
                    "integration_slug": "openai",
                    "plugin_provider_slug": "openai",
                    "status": "active",
                    "credentials": {"api_key": "sk-secret-value", "masked": "sk-****1234"},
                }
            ]
        }
        result = plugins_list_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[0] == "GET"
        assert args[1] == "/plugins"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayPlugin"
        creds = result.outputs[0]["credentials"]
        # a raw secret is masked, an already server-masked value is preserved.
        assert creds["api_key"] == "***REDACTED***"
        assert creds["masked"] == "sk-****1234"

    @patch.object(Client, "http_request")
    def test_plugins_create_posts_body_on_admin_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """Create posts integration_id/credentials/organisation_id to the admin plane, defaulting org to the tsg."""
        mock_http.return_value = {"data": {"id": "p9", "status": "active"}}
        result = plugins_create_command(
            mock_client,
            {"integration_id": "int-1", "credentials": '{"api_key": "sk-live"}'},
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/plugins"
        assert kwargs["use_aigw_admin"] is True
        body = kwargs["json_data"]
        assert body["integration_id"] == "int-1"
        assert body["credentials"] == {"api_key": "sk-live"}
        assert body["organisation_id"] == mock_client.tsg_id
        assert result.outputs["id"] == "p9"

    @patch.object(Client, "http_request")
    def test_plugins_create_never_echoes_secrets(self, mock_http: Mock, mock_client: Client) -> None:
        """A create response that reflects back raw credentials is redacted before it reaches outputs."""
        mock_http.return_value = {"data": {"id": "p9", "credentials": {"api_key": "sk-live"}}}
        result = plugins_create_command(
            mock_client,
            {"integration_id": "int-1", "credentials": '{"api_key": "sk-live"}'},
        )
        assert result.outputs["credentials"]["api_key"] == "***REDACTED***"

    def test_plugins_create_requires_credentials(self, mock_client: Client) -> None:
        """Create without credentials is rejected before any request is made."""
        with pytest.raises(ValueError, match="credentials is required"):
            plugins_create_command(mock_client, {"integration_id": "int-1"})


class TestApiKeys:
    """Test cases for the service/user API-key commands (data plane, separate sub-collections)."""

    @patch.object(Client, "http_request")
    def test_service_list_scopes_to_workspace_on_data_plane(self, mock_http: Mock, mock_client: Client) -> None:
        """Listing service keys hits /api-keys/service on the data plane with the workspace_id param."""
        mock_http.return_value = {"data": [{"id": "k1", "name": "ci", "type": "workspace"}]}
        result = api_keys_service_list_command(mock_client, {"workspace_id": "ws-1"})

        args, kwargs = mock_http.call_args
        assert args[0] == "GET"
        assert args[1] == "/api-keys/service"
        assert kwargs["use_aigw_cp"] is True
        assert kwargs["params"]["workspace_id"] == "ws-1"
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayApiKey"
        assert result.outputs[0]["id"] == "k1"

    @patch.object(Client, "http_request")
    def test_user_list_uses_user_subcollection(self, mock_http: Mock, mock_client: Client) -> None:
        """User keys are a distinct sub-collection under /api-keys/user."""
        mock_http.return_value = {"data": []}
        api_keys_user_list_command(mock_client, {"workspace_id": "ws-1"})

        args, _ = mock_http.call_args
        assert args[1] == "/api-keys/user"

    @patch.object(Client, "http_request")
    def test_service_list_enriches_workspace_name(self, mock_http: Mock, mock_client: Client) -> None:
        """Each listed key is enriched with a workspace_name resolved once per workspace (lookups are cached)."""
        mock_http.side_effect = [
            {
                "data": [
                    {"id": "k1", "name": "ci", "workspace_id": "ws-1"},
                    {"id": "k2", "name": "cd", "workspace_id": "ws-1"},
                ]
            },
            {"data": {"id": "ws-1", "name": "production"}},
        ]
        result = api_keys_service_list_command(mock_client, {"workspace_id": "ws-1"})

        # list call + a single cached workspace lookup for the shared workspace_id
        assert mock_http.call_count == 2
        lookup_args, lookup_kwargs = mock_http.call_args
        assert lookup_args[1] == "/workspaces/ws-1"
        assert lookup_kwargs["use_aigw_cp"] is True
        assert result.outputs[0]["workspace_name"] == "production"
        assert result.outputs[1]["workspace_name"] == "production"
        # the raw workspace_id is preserved alongside the resolved name
        assert result.outputs[0]["workspace_id"] == "ws-1"

    @patch.object(Client, "http_request")
    def test_service_list_enrichment_survives_lookup_failure(self, mock_http: Mock, mock_client: Client) -> None:
        """A failed workspace lookup must not break the list; the key is returned without a workspace_name."""
        mock_http.side_effect = [
            {"data": [{"id": "k1", "name": "ci", "workspace_id": "ws-1"}]},
            DemistoException("boom"),
        ]
        result = api_keys_service_list_command(mock_client, {"workspace_id": "ws-1"})

        assert result.outputs[0]["id"] == "k1"
        assert "workspace_name" not in result.outputs[0]

    @patch.object(Client, "http_request")
    def test_service_get_by_uuid(self, mock_http: Mock, mock_client: Client) -> None:
        """Getting one key appends the UUID to the sub-collection path and never returns a secret."""
        mock_http.return_value = {"id": "k1", "name": "ci"}
        result = api_keys_service_get_command(mock_client, {"key_id": "k1"})

        args, kwargs = mock_http.call_args
        assert args[1] == "/api-keys/service/k1"
        assert kwargs["use_aigw_cp"] is True
        assert "key" not in result.outputs

    @patch.object(Client, "http_request")
    def test_service_create_posts_body_and_returns_one_time_key(self, mock_http: Mock, mock_client: Client) -> None:
        """Create posts name/scopes/type/org/workspace and surfaces the one-time secret with a warning."""
        mock_http.return_value = {"data": {"id": "k9", "key": "sk-live-secret", "version_id": "v1"}}
        result = api_keys_service_create_command(
            mock_client,
            {
                "name": "ci-runner",
                "scopes": "completions.write,logs.write",
                "workspace_id": "ws-1",
            },
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/api-keys/service"
        assert kwargs["use_aigw_cp"] is True
        body = kwargs["json_data"]
        assert body["name"] == "ci-runner"
        assert body["scopes"] == ["completions.write", "logs.write"]
        assert body["type"] == "workspace"
        assert body["organisation_id"] == mock_client.tsg_id
        assert body["workspace_id"] == "ws-1"
        # the one-time secret is returned to the caller with a save-it-now warning.
        assert result.outputs["key"] == "sk-live-secret"
        assert "only once" in result.readable_output

    @patch.object(Client, "http_request")
    def test_service_create_requires_scopes(self, mock_http: Mock, mock_client: Client) -> None:
        """Create without scopes is rejected before any request is made."""
        with pytest.raises(ValueError, match="scopes is required"):
            api_keys_service_create_command(mock_client, {"name": "ci", "workspace_id": "ws-1"})
        mock_http.assert_not_called()

    def test_user_create_requires_user_id(self, mock_client: Client) -> None:
        """A user key requires user_id in addition to the shared create fields."""
        with pytest.raises(ValueError, match="user_id is required"):
            api_keys_user_create_command(
                mock_client,
                {"name": "laptop", "scopes": "completions.write", "workspace_id": "ws-1"},
            )

    @patch.object(Client, "http_request")
    def test_user_create_sends_user_id(self, mock_http: Mock, mock_client: Client) -> None:
        """A valid user create posts user_id to the user sub-collection."""
        mock_http.return_value = {"data": {"id": "k9", "key": "sk"}}
        api_keys_user_create_command(
            mock_client,
            {"name": "laptop", "scopes": "completions.write", "workspace_id": "ws-1", "user_id": "u-1"},
        )

        args, kwargs = mock_http.call_args
        assert args[1] == "/api-keys/user"
        assert kwargs["json_data"]["user_id"] == "u-1"

    @patch.object(Client, "http_request")
    def test_service_update_puts_fields(self, mock_http: Mock, mock_client: Client) -> None:
        """Update PUTs to the key path with an empty-response write and reports success."""
        mock_http.return_value = None
        result = api_keys_service_update_command(mock_client, {"key_id": "k1", "name": "renamed"})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/api-keys/service/k1"
        assert kwargs["json_data"] == {"name": "renamed"}
        assert "updated successfully" in result.readable_output

    def test_service_update_requires_a_field(self, mock_client: Client) -> None:
        """Update with no fields is rejected before any request is made."""
        with pytest.raises(ValueError, match="at least one field"):
            api_keys_service_update_command(mock_client, {"key_id": "k1"})

    @patch.object(Client, "http_request")
    def test_service_delete_is_hard_delete(self, mock_http: Mock, mock_client: Client) -> None:
        """Delete issues a DELETE against the key path and reports success."""
        mock_http.return_value = None
        result = api_keys_service_delete_command(mock_client, {"key_id": "k1"})

        args, _ = mock_http.call_args
        assert args[0] == "DELETE"
        assert args[1] == "/api-keys/service/k1"
        assert "deleted successfully" in result.readable_output

    @patch.object(Client, "http_request")
    def test_service_rotate_returns_new_one_time_key(self, mock_http: Mock, mock_client: Client) -> None:
        """Rotate POSTs to /rotate, optionally carries the transition period, and surfaces the new secret."""
        mock_http.return_value = {
            "id": "k1",
            "key": "sk-new-secret",
            "key_transition_expires_at": "2026-10-01T00:00:00Z",
        }
        result = api_keys_service_rotate_command(mock_client, {"key_id": "k1", "key_transition_period_ms": "1800000"})

        args, kwargs = mock_http.call_args
        assert args[0] == "POST"
        assert args[1] == "/api-keys/service/k1/rotate"
        assert kwargs["json_data"] == {"key_transition_period_ms": 1800000}
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayApiKeyRotation"
        assert result.outputs["key"] == "sk-new-secret"
        assert "only once" in result.readable_output


class TestOrganisations:
    """Test cases for the organisation settings commands (admin plane)."""

    @patch.object(Client, "http_request")
    def test_info_get_defaults_org_to_tsg(self, mock_http: Mock, mock_client: Client) -> None:
        """info-get builds /organisations/{tsg}/info on the admin plane, defaulting org to the tsg."""
        mock_http.return_value = {"id": "org1", "name": "Acme", "object": "organisation"}
        result = organisations_info_get_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[0] == "GET"
        assert args[1] == f"/organisations/{mock_client.tsg_id}/info"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs_prefix == "PrismaAIRs.AIGatewayOrganisationInfo"
        assert result.outputs["name"] == "Acme"

    @patch.object(Client, "http_request")
    def test_self_get_unwraps_envelope(self, mock_http: Mock, mock_client: Client) -> None:
        """self-get reads /organisations/self and unwraps the {success,data} envelope."""
        mock_http.return_value = {"success": True, "data": {"id": "org1", "name": "Acme"}}
        result = organisations_self_get_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == "/organisations/self"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs == {"id": "org1", "name": "Acme"}

    @patch.object(Client, "http_request")
    def test_self_update_merges_settings(self, mock_http: Mock, mock_client: Client) -> None:
        """self-update PUTs name plus any merged settings JSON to /organisations/self."""
        mock_http.return_value = {"id": "org1"}
        result = organisations_self_update_command(mock_client, {"name": "Acme", "settings": '{"debug_log": 1}'})

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == "/organisations/self"
        assert kwargs["json_data"] == {"name": "Acme", "debug_log": 1}
        assert "updated successfully" in result.readable_output

    def test_self_update_requires_a_field(self, mock_client: Client) -> None:
        """self-update with no fields is rejected before any request is made."""
        with pytest.raises(ValueError, match="at least one field"):
            organisations_self_update_command(mock_client, {})

    @patch.object(Client, "http_request")
    def test_auth_settings_get_redacts_scim_token(self, mock_http: Mock, mock_client: Client) -> None:
        """auth-settings-get masks scim_token and nested client_secret in the output."""
        mock_http.return_value = {
            "success": True,
            "data": {
                "domains": ["acme.com"],
                "scim_token": "live-scim-secret",
                "auth_settings": {"client_secret": "live-client-secret", "issuer": "https://idp"},
            },
        }
        result = organisations_auth_settings_get_command(mock_client, {})

        args, kwargs = mock_http.call_args
        assert args[1] == f"/organisations/{mock_client.tsg_id}/auth-settings"
        assert kwargs["use_aigw_admin"] is True
        assert result.outputs["scim_token"] == "***REDACTED***"
        assert result.outputs["auth_settings"]["client_secret"] == "***REDACTED***"
        # non-secret fields are preserved.
        assert result.outputs["domains"] == ["acme.com"]
        assert result.outputs["auth_settings"]["issuer"] == "https://idp"

    @patch.object(Client, "http_request")
    def test_auth_settings_update_sends_secret_but_redacts_response(self, mock_http: Mock, mock_client: Client) -> None:
        """auth-settings-update sends the secret scim_token but never echoes it back."""
        mock_http.return_value = {"data": {"scim_token": "live-scim-secret", "domains": ["acme.com"]}}
        result = organisations_auth_settings_update_command(
            mock_client, {"scim_token": "live-scim-secret", "domains": "acme.com,acme.io"}
        )

        args, kwargs = mock_http.call_args
        assert args[0] == "PUT"
        assert args[1] == f"/organisations/{mock_client.tsg_id}/auth-settings"
        assert kwargs["json_data"]["scim_token"] == "live-scim-secret"
        assert kwargs["json_data"]["domains"] == ["acme.com", "acme.io"]
        assert result.outputs["scim_token"] == "***REDACTED***"

    def test_auth_settings_update_requires_a_field(self, mock_client: Client) -> None:
        """auth-settings-update with no fields is rejected before any request is made."""
        with pytest.raises(ValueError, match="at least one field"):
            organisations_auth_settings_update_command(mock_client, {})
