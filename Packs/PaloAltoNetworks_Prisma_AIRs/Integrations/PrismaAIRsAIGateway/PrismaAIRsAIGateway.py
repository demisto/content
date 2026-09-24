import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from PrismaAirsApiModule import *  # noqa # pylint: disable=unused-wildcard-import

from typing import Any

# CONSTANTS (AI Gateway specific; shared constants such as DEFAULT_LIMIT / PA_OUTPUT_PREFIX
# and the plane-routing transport come from PrismaAirsApiModule).
#
# Plane routing (see PrismaAirsApiModule._project/planes.yaml):
#   control plane (use_aigw_cp)  -> /ai_gw/v2      : Guardrails, Configs, Rate/Usage Policies, MCP Servers
#   admin plane   (use_aigw_admin) -> /ai_gw/admin/v2 : Org Guardrails, Deployments, Secret References, MCP Integrations
GUARDRAILS_ENDPOINT = "/guardrails"
CONFIGS_ENDPOINT = "/configs"
DEPLOYMENTS_ENDPOINT = "/deployments"
RATE_LIMITS_ENDPOINT = "/policies/rate-limits"
USAGE_LIMITS_ENDPOINT = "/policies/usage-limits"
SECRET_REFERENCES_ENDPOINT = "/secret-references"
MCP_SERVERS_ENDPOINT = "/mcp-servers"
MCP_INTEGRATIONS_ENDPOINT = "/mcp-integrations"
# Workspaces span BOTH planes: reads default to the data plane (only workspaces the service
# account is scoped to) and can be routed to the admin plane (whole tenant). Writes are admin-only.
WORKSPACES_ENDPOINT = "/workspaces"
# Admin-plane organisation record for the calling tenant; takes no workspace/query params,
# so it is the connectivity probe used by test-module.
ORGANISATIONS_ENDPOINT = "/organisations"
ORGANISATION_SELF_ENDPOINT = "/organisations/self"
# SCM IAM scopes (use_aigw_iam -> /iam/v1). A workspace's scope_name must name an existing scope
# here before the workspace can be created; scopes are keyed by name, not UUID.
SCOPES_ENDPOINT = "/scopes"
# API keys (data plane): service and user keys are DISTINCT sub-collections; there is no combined
# /api-keys endpoint (it is OPA-denied). The secret is only ever returned once, at create/rotate.
API_KEYS_SERVICE_ENDPOINT = "/api-keys/service"
API_KEYS_USER_ENDPOINT = "/api-keys/user"
# Admin-plane credential integrations (upstream provider bindings): distinct from /mcp-integrations.
# The static provider catalog maps a slug (e.g. "open-ai") to the ai_provider_id a provider needs.
INTEGRATIONS_ENDPOINT = "/integrations"
PROVIDER_CATALOG_ENDPOINT = "/utils/static-resources/ai-providers"
# Data-plane provider bindings inside a workspace (each ties an integration to a workspace).
PROVIDERS_ENDPOINT = "/providers"
PLUGINS_ENDPOINT = "/plugins"
# Public model-pricing catalog: NOT on the SCM gateway host. It is an unauthenticated read against a
# caller-supplied public catalog (default https://api.portkey.ai) and carries no OAuth2/x-tsg-id auth.
# Prices are upstream catalog data, not effective tenant billing or Prisma cost telemetry.
MODEL_PRICING_DEFAULT_ENDPOINT = "https://api.portkey.ai"
MODEL_PRICING_PATH = "/model-configs/pricing"


# HELPER FUNCTIONS


def table(name: str, data: Any, headers: list[str] | None = None) -> str:
    """Render a Markdown table with the pack's standard header transform."""
    return tableToMarkdown(
        name,
        data,
        headers=headers,
        headerTransform=lambda h: h.replace("_", " ").title(),
        removeNull=True,
    )


def json_arg(args: dict[str, Any], key: str) -> Any:
    """Parse an argument that carries a JSON object/array. Returns None when absent."""
    raw = args.get(key)
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict | list):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError(f"Argument '{key}' must be a valid JSON object/array.")


def bool_arg(args: dict[str, Any], key: str) -> bool | None:
    """Parse an optional boolean argument. Returns None when absent."""
    val = args.get(key)
    return argToBoolean(val) if val not in (None, "") else None


def pagination_params(args: dict[str, Any]) -> dict[str, Any]:
    """Build the common page_size/current_page query params."""
    return assign_params(
        page_size=arg_to_number(args.get("page_size")) or DEFAULT_LIMIT,
        current_page=arg_to_number(args.get("current_page")),
    )


def plane_flags(args: dict[str, Any]) -> dict[str, bool]:
    """Map a 'plane' argument ('data' default, or 'admin') to the http_request routing flag.

    Only workspace reads accept a caller-chosen plane; the data plane returns just the workspaces
    the service account is scoped to, while the admin plane enumerates the whole tenant.
    """
    return {"use_aigw_admin": True} if args.get("plane") == "admin" else {"use_aigw_cp": True}


# GUARDRAILS (control plane)


def guardrails_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List guardrails."""
    params = assign_params(workspace_id=args.get("workspace_id"), **pagination_params(args))
    response = client.http_request("GET", GUARDRAILS_ENDPOINT, params=params, use_aigw_cp=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrail",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Guardrails", data),
        raw_response=response,
    )


def guardrails_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a guardrail."""
    body = assign_params(
        name=args.get("name"),
        target=args.get("target"),
        workspace_id=args.get("workspace_id"),
        checks=json_arg(args, "checks"),
        actions=json_arg(args, "actions"),
    )
    response = client.http_request("POST", GUARDRAILS_ENDPOINT, json_data=body, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrail",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway Guardrail Created", response),
        raw_response=response,
    )


def guardrails_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a guardrail by ID."""
    guardrail_id = args["guardrail_id"]
    response = client.http_request("GET", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}", use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrail",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Guardrail {guardrail_id}", response),
        raw_response=response,
    )


def guardrails_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a guardrail."""
    guardrail_id = args["guardrail_id"]
    body = assign_params(
        name=args.get("name"),
        checks=json_arg(args, "checks"),
        actions=json_arg(args, "actions"),
    )
    response = client.http_request("PUT", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}", json_data=body, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrail",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Guardrail {guardrail_id} Updated", response),
        raw_response=response,
    )


def guardrails_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a guardrail."""
    guardrail_id = args["guardrail_id"]
    client.http_request(
        "DELETE", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}", use_aigw_cp=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ Guardrail {guardrail_id} deleted successfully.")


def guardrails_catalog_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List available guardrail evaluators and their parameter schemas (not configured guardrail instances)."""
    response = client.http_request(
        "GET", "/utils/static-resources/schema", params={"resource": "guardrails"}, use_aigw_admin=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrailCatalog",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Guardrail Catalog", data),
        raw_response=response,
    )


def guardrails_mcp_servers_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the MCP server mappings attached to a guardrail."""
    guardrail_id = args["guardrail_id"]
    response = client.http_request("GET", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}/mcp-servers", use_aigw_cp=True)
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrailMcpServer",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Guardrail {guardrail_id} MCP Servers", data),
        raw_response=response,
    )


def guardrails_mcp_servers_sync_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Replace all MCP server mappings on a guardrail (bulk sync)."""
    guardrail_id = args["guardrail_id"]
    body = assign_params(mcp_servers=json_arg(args, "mcp_servers"))
    if not body:
        raise ValueError("Provide at least one field to update (mcp_servers).")
    response = client.http_request(
        "PUT", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}/mcp-servers", json_data=body, use_aigw_cp=True
    )
    outputs = dict(response) if isinstance(response, dict) else {"result": response}
    outputs["guardrail_id"] = guardrail_id
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrailMcpServerSync",
        outputs_key_field="guardrail_id",
        outputs=outputs,
        readable_output=table(f"AI Gateway Guardrail {guardrail_id} MCP Server Sync", response),
        raw_response=response,
    )


def guardrails_mcp_server_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Enable or disable a single MCP server mapping on a guardrail."""
    guardrail_id = args["guardrail_id"]
    mcp_server_id = args["mcp_server_id"]
    body = assign_params(
        run_on=argToList(args.get("run_on")),
        mcp_integration_capability_ids=argToList(args.get("mcp_integration_capability_ids")),
    )
    if not body:
        raise ValueError("Provide at least one field to update (run_on, mcp_integration_capability_ids).")
    response = client.http_request(
        "PUT", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}/mcp-servers/{mcp_server_id}", json_data=body, use_aigw_cp=True
    )
    outputs = dict(response) if isinstance(response, dict) else {"result": response}
    outputs["guardrail_id"] = guardrail_id
    outputs["mcp_server_id"] = mcp_server_id
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayGuardrailMcpServerMapping",
        outputs_key_field="map_id",
        outputs=outputs,
        readable_output=table(f"AI Gateway Guardrail {guardrail_id} MCP Server {mcp_server_id} Mapping", response),
        raw_response=response,
    )


# ORG GUARDRAILS (admin plane)


def org_guardrails_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List organization-level guardrails."""
    params = assign_params(workspace_id=args.get("workspace_id"), **pagination_params(args))
    response = client.http_request("GET", GUARDRAILS_ENDPOINT, params=params, use_aigw_admin=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrgGuardrail",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Organization Guardrails", data),
        raw_response=response,
    )


def org_guardrails_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create an organization-level guardrail."""
    body = assign_params(
        name=args.get("name"),
        target=args.get("target"),
        workspace_id=args.get("workspace_id"),
        checks=json_arg(args, "checks"),
        actions=json_arg(args, "actions"),
    )
    response = client.http_request("POST", GUARDRAILS_ENDPOINT, json_data=body, use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrgGuardrail",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway Organization Guardrail Created", response),
        raw_response=response,
    )


def org_guardrails_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get an organization-level guardrail by ID."""
    guardrail_id = args["guardrail_id"]
    response = client.http_request("GET", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}", use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrgGuardrail",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Organization Guardrail {guardrail_id}", response),
        raw_response=response,
    )


def org_guardrails_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an organization-level guardrail."""
    guardrail_id = args["guardrail_id"]
    body = assign_params(
        name=args.get("name"),
        checks=json_arg(args, "checks"),
        actions=json_arg(args, "actions"),
    )
    response = client.http_request("PUT", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}", json_data=body, use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrgGuardrail",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Organization Guardrail {guardrail_id} Updated", response),
        raw_response=response,
    )


def org_guardrails_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete an organization-level guardrail."""
    guardrail_id = args["guardrail_id"]
    client.http_request(
        "DELETE", f"{GUARDRAILS_ENDPOINT}/{guardrail_id}", use_aigw_admin=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ Organization guardrail {guardrail_id} deleted successfully.")


# CONFIGS (control plane) - responses are wrapped as {success, data}


def configs_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List gateway configs."""
    params = assign_params(workspace_id=args.get("workspace_id"), **pagination_params(args))
    response = client.http_request("GET", CONFIGS_ENDPOINT, params=params, use_aigw_cp=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayConfig",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Configs", data, headers=["id", "name", "slug", "status", "workspace_id"]),
        raw_response=response,
    )


def configs_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a gateway config."""
    body = assign_params(
        name=args.get("name"),
        config=json_arg(args, "config"),
        workspace_id=args.get("workspace_id"),
    )
    response = client.http_request("POST", CONFIGS_ENDPOINT, json_data=body, use_aigw_cp=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayConfig",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Config Created", data),
        raw_response=response,
    )


def configs_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a gateway config by ID."""
    config_id = args["config_id"]
    response = client.http_request("GET", f"{CONFIGS_ENDPOINT}/{config_id}", use_aigw_cp=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayConfig",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Config {config_id}", data),
        raw_response=response,
    )


def configs_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a gateway config."""
    config_id = args["config_id"]
    body = assign_params(
        name=args.get("name"),
        config=json_arg(args, "config"),
        status=args.get("status"),
    )
    response = client.http_request("PUT", f"{CONFIGS_ENDPOINT}/{config_id}", json_data=body, use_aigw_cp=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayConfig",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Config {config_id} Updated", data),
        raw_response=response,
    )


def configs_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a gateway config."""
    config_id = args["config_id"]
    client.http_request(
        "DELETE", f"{CONFIGS_ENDPOINT}/{config_id}", use_aigw_cp=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ Config {config_id} deleted successfully.")


def config_versions_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List versions of a gateway config."""
    config_id = args["config_id"]
    response = client.http_request("GET", f"{CONFIGS_ENDPOINT}/{config_id}/versions", use_aigw_cp=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayConfigVersion",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Config {config_id} Versions", data),
        raw_response=response,
    )


# DEPLOYMENTS (admin plane)


def deployments_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List deployments."""
    params = assign_params(
        status=args.get("status"),
        type=args.get("type"),
        workspace_slug=argToList(args.get("workspace_slug")),
        search=args.get("search"),
    )
    response = client.http_request("GET", DEPLOYMENTS_ENDPOINT, params=params, use_aigw_admin=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayDeployment",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Deployments", data),
        raw_response=response,
    )


def deployments_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a deployment."""
    body = assign_params(
        name=args.get("name"),
        slug=args.get("slug"),
        type=args.get("type"),
        deployment_config=json_arg(args, "deployment_config"),
        is_default=bool_arg(args, "is_default"),
        auth_settings=json_arg(args, "auth_settings"),
        tags=json_arg(args, "tags"),
    )
    response = client.http_request("POST", DEPLOYMENTS_ENDPOINT, json_data=body, use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayDeployment",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway Deployment Created", response),
        raw_response=response,
    )


def deployments_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a deployment by ID."""
    deployment_id = args["deployment_id"]
    response = client.http_request("GET", f"{DEPLOYMENTS_ENDPOINT}/{deployment_id}", use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayDeployment",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Deployment {deployment_id}", response),
        raw_response=response,
    )


def deployments_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a deployment."""
    deployment_id = args["deployment_id"]
    body = assign_params(
        name=args.get("name"),
        type=args.get("type"),
        status=args.get("status"),
        deployment_config=json_arg(args, "deployment_config"),
        is_default=bool_arg(args, "is_default"),
        rotate_auth=bool_arg(args, "rotate_auth"),
        override_existing=bool_arg(args, "override_existing"),
        auth_settings=json_arg(args, "auth_settings"),
        tags=json_arg(args, "tags"),
    )
    client.http_request(
        "PUT",
        f"{DEPLOYMENTS_ENDPOINT}/{deployment_id}",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Deployment {deployment_id} updated successfully.")


def deployments_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a deployment."""
    deployment_id = args["deployment_id"]
    client.http_request(
        "DELETE",
        f"{DEPLOYMENTS_ENDPOINT}/{deployment_id}",
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Deployment {deployment_id} deleted successfully.")


def deployment_ping_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Ping a deployment to check connectivity/health."""
    deployment_id = args["deployment_id"]
    response = client.http_request("GET", f"{DEPLOYMENTS_ENDPOINT}/{deployment_id}/ping", use_aigw_admin=True)
    outputs = dict(response)
    outputs["deployment_id"] = deployment_id
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayDeploymentPing",
        outputs_key_field="deployment_id",
        outputs=outputs,
        readable_output=table(f"AI Gateway Deployment {deployment_id} Ping", response),
        raw_response=response,
    )


# RATE LIMIT POLICIES (control plane)


def rate_limit_policies_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List rate-limit policies."""
    params = assign_params(
        workspace_id=args.get("workspace_id"),
        status=args.get("status"),
        type=args.get("type"),
        unit=args.get("unit"),
        target=args.get("target"),
        **pagination_params(args),
    )
    response = client.http_request("GET", RATE_LIMITS_ENDPOINT, params=params, use_aigw_cp=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayRateLimitPolicy",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Rate Limit Policies", data),
        raw_response=response,
    )


def rate_limit_policies_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a rate-limit policy."""
    body = assign_params(
        name=args.get("name"),
        conditions=json_arg(args, "conditions"),
        group_by=json_arg(args, "group_by"),
        type=args.get("type"),
        unit=args.get("unit"),
        value=arg_to_number(args.get("value")),
        target=args.get("target"),
        workspace_id=args.get("workspace_id"),
    )
    response = client.http_request("POST", RATE_LIMITS_ENDPOINT, json_data=body, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayRateLimitPolicy",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway Rate Limit Policy Created", response),
        raw_response=response,
    )


def rate_limit_policies_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a rate-limit policy by ID."""
    policy_id = args["policy_id"]
    params = assign_params(status=args.get("status"))
    response = client.http_request("GET", f"{RATE_LIMITS_ENDPOINT}/{policy_id}", params=params, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayRateLimitPolicy",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Rate Limit Policy {policy_id}", response),
        raw_response=response,
    )


def rate_limit_policies_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a rate-limit policy."""
    policy_id = args["policy_id"]
    body = assign_params(
        name=args.get("name"),
        unit=args.get("unit"),
        value=arg_to_number(args.get("value")),
        conditions=json_arg(args, "conditions"),
    )
    client.http_request(
        "PUT",
        f"{RATE_LIMITS_ENDPOINT}/{policy_id}",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Rate limit policy {policy_id} updated successfully.")


def rate_limit_policies_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a rate-limit policy."""
    policy_id = args["policy_id"]
    client.http_request(
        "DELETE", f"{RATE_LIMITS_ENDPOINT}/{policy_id}", use_aigw_cp=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ Rate limit policy {policy_id} deleted successfully.")


# USAGE LIMIT POLICIES (control plane)


def usage_limit_policies_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List usage-limit policies."""
    params = assign_params(
        workspace_id=args.get("workspace_id"),
        status=args.get("status"),
        type=args.get("type"),
        **pagination_params(args),
    )
    response = client.http_request("GET", USAGE_LIMITS_ENDPOINT, params=params, use_aigw_cp=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayUsageLimitPolicy",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Usage Limit Policies", data),
        raw_response=response,
    )


def usage_limit_policies_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a usage-limit policy."""
    body = assign_params(
        name=args.get("name"),
        conditions=json_arg(args, "conditions"),
        group_by=json_arg(args, "group_by"),
        type=args.get("type"),
        credit_limit=arg_to_number(args.get("credit_limit")),
        alert_threshold=arg_to_number(args.get("alert_threshold")),
        periodic_reset=args.get("periodic_reset"),
        workspace_id=args.get("workspace_id"),
    )
    response = client.http_request("POST", USAGE_LIMITS_ENDPOINT, json_data=body, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayUsageLimitPolicy",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway Usage Limit Policy Created", response),
        raw_response=response,
    )


def usage_limit_policies_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a usage-limit policy by ID."""
    policy_id = args["policy_id"]
    params = assign_params(status=args.get("status"), include_usage=bool_arg(args, "include_usage"))
    response = client.http_request("GET", f"{USAGE_LIMITS_ENDPOINT}/{policy_id}", params=params, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayUsageLimitPolicy",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Usage Limit Policy {policy_id}", response),
        raw_response=response,
    )


def usage_limit_policies_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a usage-limit policy."""
    policy_id = args["policy_id"]
    body = assign_params(
        name=args.get("name"),
        description=args.get("description"),
        conditions=json_arg(args, "conditions"),
        credit_limit=arg_to_number(args.get("credit_limit")),
        alert_threshold=arg_to_number(args.get("alert_threshold")),
        periodic_reset=args.get("periodic_reset"),
    )
    client.http_request(
        "PUT",
        f"{USAGE_LIMITS_ENDPOINT}/{policy_id}",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Usage limit policy {policy_id} updated successfully.")


def usage_limit_policies_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a usage-limit policy."""
    policy_id = args["policy_id"]
    client.http_request(
        "DELETE", f"{USAGE_LIMITS_ENDPOINT}/{policy_id}", use_aigw_cp=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ Usage limit policy {policy_id} deleted successfully.")


def usage_limit_policy_entities_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List entities tracked by a usage-limit policy."""
    policy_id = args["policy_id"]
    params = assign_params(status=args.get("status"), search=args.get("search"), **pagination_params(args))
    response = client.http_request(
        "GET", f"{USAGE_LIMITS_ENDPOINT}/{policy_id}/entities", params=params, use_aigw_cp=True
    )
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayUsageLimitPolicyEntity",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Usage Limit Policy {policy_id} Entities", data),
        raw_response=response,
    )


def usage_limit_policy_entity_reset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Reset the usage counter of a single entity within a usage-limit policy."""
    policy_id = args["policy_id"]
    entity_id = args["entity_id"]
    client.http_request(
        "PUT",
        f"{USAGE_LIMITS_ENDPOINT}/{policy_id}/entities/{entity_id}/reset",
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Entity {entity_id} of usage limit policy {policy_id} reset successfully.")


# SECRET REFERENCES (admin plane)


def secret_references_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List secret references."""
    params = assign_params(
        manager_type=args.get("manager_type"),
        tags=args.get("tags"),
        search=args.get("search"),
        **pagination_params(args),
    )
    response = client.http_request("GET", SECRET_REFERENCES_ENDPOINT, params=params, use_aigw_admin=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewaySecretReference",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Secret References", data),
        raw_response=response,
    )


def secret_references_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a secret reference."""
    body = assign_params(
        name=args.get("name"),
        slug=args.get("slug"),
        description=args.get("description"),
        manager_type=args.get("manager_type"),
        auth_config=json_arg(args, "auth_config"),
        secret_path=args.get("secret_path"),
        secret_key=args.get("secret_key"),
        allow_all_workspaces=bool_arg(args, "allow_all_workspaces"),
        allowed_workspaces=argToList(args.get("allowed_workspaces")),
        tags=json_arg(args, "tags"),
    )
    response = client.http_request("POST", SECRET_REFERENCES_ENDPOINT, json_data=body, use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewaySecretReference",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway Secret Reference Created", response),
        raw_response=response,
    )


def secret_references_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get a secret reference by ID."""
    secret_reference_id = args["secret_reference_id"]
    response = client.http_request(
        "GET", f"{SECRET_REFERENCES_ENDPOINT}/{secret_reference_id}", use_aigw_admin=True
    )
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewaySecretReference",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway Secret Reference {secret_reference_id}", response),
        raw_response=response,
    )


def secret_references_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a secret reference."""
    secret_reference_id = args["secret_reference_id"]
    body = assign_params(
        name=args.get("name"),
        description=args.get("description"),
        auth_config=json_arg(args, "auth_config"),
        secret_path=args.get("secret_path"),
        secret_key=args.get("secret_key"),
        allow_all_workspaces=bool_arg(args, "allow_all_workspaces"),
        allowed_workspaces=argToList(args.get("allowed_workspaces")),
        tags=json_arg(args, "tags"),
    )
    client.http_request(
        "PUT",
        f"{SECRET_REFERENCES_ENDPOINT}/{secret_reference_id}",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Secret reference {secret_reference_id} updated successfully.")


def secret_references_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a secret reference."""
    secret_reference_id = args["secret_reference_id"]
    client.http_request(
        "DELETE",
        f"{SECRET_REFERENCES_ENDPOINT}/{secret_reference_id}",
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Secret reference {secret_reference_id} deleted successfully.")


# MCP SERVERS (control plane)


def mcp_servers_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List MCP servers."""
    params = assign_params(
        workspace_id=args.get("workspace_id"),
        id=args.get("id"),
        search=args.get("search"),
        **pagination_params(args),
    )
    response = client.http_request("GET", MCP_SERVERS_ENDPOINT, params=params, use_aigw_cp=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServer",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway MCP Servers", data),
        raw_response=response,
    )


def mcp_servers_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create an MCP server."""
    body = assign_params(
        workspace_id=args.get("workspace_id"),
        name=args.get("name"),
        description=args.get("description"),
        mcp_integration_id=args.get("mcp_integration_id"),
        slug=args.get("slug"),
    )
    response = client.http_request("POST", MCP_SERVERS_ENDPOINT, json_data=body, use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServer",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway MCP Server Created", response),
        raw_response=response,
    )


def mcp_servers_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get an MCP server by ID."""
    mcp_server_id = args["mcp_server_id"]
    response = client.http_request("GET", f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}", use_aigw_cp=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServer",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway MCP Server {mcp_server_id}", response),
        raw_response=response,
    )


def mcp_servers_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an MCP server."""
    mcp_server_id = args["mcp_server_id"]
    body = assign_params(name=args.get("name"), description=args.get("description"))
    client.http_request(
        "PUT",
        f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP server {mcp_server_id} updated successfully.")


def mcp_servers_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete an MCP server."""
    mcp_server_id = args["mcp_server_id"]
    client.http_request(
        "DELETE", f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}", use_aigw_cp=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ MCP server {mcp_server_id} deleted successfully.")


def mcp_server_test_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Test connectivity to an MCP server."""
    mcp_server_id = args["mcp_server_id"]
    response = client.http_request("POST", f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/test", use_aigw_cp=True)
    outputs = dict(response)
    outputs["mcp_server_id"] = mcp_server_id
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServerTest",
        outputs_key_field="mcp_server_id",
        outputs=outputs,
        readable_output=table(f"AI Gateway MCP Server {mcp_server_id} Test", response),
        raw_response=response,
    )


def mcp_servers_capabilities_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List an MCP server's discovered capabilities (tools, prompts, resources, resource templates)."""
    mcp_server_id = args["mcp_server_id"]
    params = assign_params(
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        type=args.get("type"),
    )
    response = client.http_request(
        "GET", f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/capabilities", params=params, use_aigw_cp=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServerCapability",
        outputs_key_field="name",
        outputs=data,
        readable_output=table(f"AI Gateway MCP Server {mcp_server_id} Capabilities", data),
        raw_response=response,
    )


def mcp_servers_capabilities_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bulk-update capability enablement on an MCP server."""
    mcp_server_id = args["mcp_server_id"]
    body = assign_params(capabilities=json_arg(args, "capabilities"))
    if not body:
        raise ValueError("Provide at least one field to update (capabilities).")
    client.http_request(
        "PUT",
        f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/capabilities",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP server {mcp_server_id} capabilities updated successfully.")


def mcp_servers_user_access_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List per-user access for an MCP server."""
    mcp_server_id = args["mcp_server_id"]
    params = assign_params(
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        search=args.get("search"),
    )
    response = client.http_request(
        "GET", f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/user-access", params=params, use_aigw_cp=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServerUserAccess",
        outputs_key_field="user_id",
        outputs=data,
        readable_output=table(f"AI Gateway MCP Server {mcp_server_id} User Access", data),
        raw_response=response,
    )


def mcp_servers_user_access_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bulk-update per-user access for an MCP server. Requires at least one field."""
    mcp_server_id = args["mcp_server_id"]
    body = assign_params(
        user_access=json_arg(args, "user_access"),
        default_user_access=args.get("default_user_access"),
    )
    if not body:
        raise ValueError("Provide at least one field to update (user_access, default_user_access).")
    client.http_request(
        "PUT",
        f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/user-access",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP server {mcp_server_id} user access updated successfully.")


def mcp_servers_connections_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List user connections established against an MCP server."""
    mcp_server_id = args["mcp_server_id"]
    params = assign_params(
        user_id=args.get("user_id"),
        workspace_id=args.get("workspace_id"),
        current_page=arg_to_number(args.get("current_page")),
        page_size=arg_to_number(args.get("page_size")),
    )
    response = client.http_request(
        "GET", f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/connections", params=params, use_aigw_cp=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpServerConnection",
        outputs_key_field="user_id",
        outputs=data,
        readable_output=table(f"AI Gateway MCP Server {mcp_server_id} Connections", data),
        raw_response=response,
    )


def mcp_servers_connections_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete MCP server user connection(s), optionally scoped by user_id and/or workspace_id."""
    mcp_server_id = args["mcp_server_id"]
    params = assign_params(user_id=args.get("user_id"), workspace_id=args.get("workspace_id"))
    client.http_request(
        "DELETE",
        f"{MCP_SERVERS_ENDPOINT}/{mcp_server_id}/connections",
        params=params,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP server {mcp_server_id} connection(s) deleted successfully.")


# MCP INTEGRATIONS (admin plane)


def mcp_integrations_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List MCP integrations."""
    params = assign_params(
        type=args.get("type"),
        workspace_id=args.get("workspace_id"),
        search=args.get("search"),
        **pagination_params(args),
    )
    response = client.http_request("GET", MCP_INTEGRATIONS_ENDPOINT, params=params, use_aigw_admin=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpIntegration",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway MCP Integrations", data),
        raw_response=response,
    )


def mcp_integrations_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create an MCP integration."""
    body = assign_params(
        workspace_id=args.get("workspace_id"),
        slug=args.get("slug"),
        name=args.get("name"),
        description=args.get("description"),
        configurations=json_arg(args, "configurations"),
        url=args.get("url"),
        auth_type=args.get("auth_type"),
        transport=args.get("transport"),
        secret_mappings=json_arg(args, "secret_mappings"),
    )
    response = client.http_request("POST", MCP_INTEGRATIONS_ENDPOINT, json_data=body, use_aigw_admin=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpIntegration",
        outputs_key_field="id",
        outputs=response,
        readable_output=table("AI Gateway MCP Integration Created", response),
        raw_response=response,
    )


def mcp_integrations_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get an MCP integration by ID."""
    mcp_integration_id = args["mcp_integration_id"]
    response = client.http_request(
        "GET", f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}", use_aigw_admin=True
    )
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpIntegration",
        outputs_key_field="id",
        outputs=response,
        readable_output=table(f"AI Gateway MCP Integration {mcp_integration_id}", response),
        raw_response=response,
    )


def mcp_integrations_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an MCP integration."""
    mcp_integration_id = args["mcp_integration_id"]
    body = assign_params(
        name=args.get("name"),
        description=args.get("description"),
        configurations=json_arg(args, "configurations"),
        url=args.get("url"),
        auth_type=args.get("auth_type"),
        transport=args.get("transport"),
        secret_mappings=json_arg(args, "secret_mappings"),
    )
    client.http_request(
        "PUT",
        f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP integration {mcp_integration_id} updated successfully.")


def mcp_integrations_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete an MCP integration."""
    mcp_integration_id = args["mcp_integration_id"]
    client.http_request(
        "DELETE",
        f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}",
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP integration {mcp_integration_id} deleted successfully.")


def mcp_integrations_workspaces_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List which workspaces an MCP integration is exposed to. The optional version selects the envelope."""
    mcp_integration_id = args["mcp_integration_id"]
    params = assign_params(version=args.get("version"))
    response = client.http_request(
        "GET", f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}/workspaces", params=params, use_aigw_admin=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpIntegrationWorkspace",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway MCP Integration {mcp_integration_id} Workspaces", data),
        raw_response=response,
    )


def mcp_integrations_capabilities_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List capabilities discovered from an MCP integration (tools, prompts, resources, resource templates)."""
    mcp_integration_id = args["mcp_integration_id"]
    response = client.http_request(
        "GET", f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}/capabilities", use_aigw_admin=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpIntegrationCapability",
        outputs_key_field="name",
        outputs=data,
        readable_output=table(f"AI Gateway MCP Integration {mcp_integration_id} Capabilities", data),
        raw_response=response,
    )


def mcp_integrations_metadata_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get metadata discovered from an MCP integration's server (identity, protocol, sync state)."""
    mcp_integration_id = args["mcp_integration_id"]
    response = client.http_request(
        "GET", f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}/metadata", use_aigw_admin=True
    )
    outputs = {**response, "mcp_integration_id": mcp_integration_id} if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayMcpIntegrationMetadata",
        outputs_key_field="mcp_integration_id",
        outputs=outputs,
        readable_output=table(f"AI Gateway MCP Integration {mcp_integration_id} Metadata", response),
        raw_response=response,
    )


def mcp_integrations_capabilities_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bulk-update capability enablement on an MCP integration."""
    mcp_integration_id = args["mcp_integration_id"]
    body = assign_params(capabilities=json_arg(args, "capabilities"))
    if not body:
        raise ValueError("Provide at least one field to update (capabilities).")
    client.http_request(
        "PUT",
        f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}/capabilities",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP integration {mcp_integration_id} capabilities updated successfully.")


def mcp_integrations_workspaces_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bulk-set which workspaces may use an MCP integration. Requires at least one field."""
    mcp_integration_id = args["mcp_integration_id"]
    body = assign_params(
        workspaces=json_arg(args, "workspaces"),
        global_workspace_access=json_arg(args, "global_workspace_access"),
        override_existing_workspace_access=bool_arg(args, "override_existing_workspace_access"),
    )
    if not body:
        raise ValueError("Provide at least one field (workspaces, global_workspace_access, override_existing_workspace_access).")
    client.http_request(
        "PUT",
        f"{MCP_INTEGRATIONS_ENDPOINT}/{mcp_integration_id}/workspaces",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ MCP integration {mcp_integration_id} workspace access updated successfully.")


# WORKSPACES (data plane by default, admin plane on request)


def workspaces_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List workspaces and their IDs.

    Use this to discover the ``workspace_id`` values required by the data-plane list commands
    (configs, guardrails, rate/usage-limit policies, MCP servers). The default (data) plane
    returns only active workspaces the service account is scoped to; pass ``plane=admin`` to
    enumerate the whole tenant, and ``status=archived`` to include archived workspaces.
    """
    params = assign_params(status=args.get("status"))
    response = client.http_request("GET", WORKSPACES_ENDPOINT, params=params, **plane_flags(args))
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayWorkspace",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(
            "AI Gateway Workspaces", data, headers=["id", "name", "slug", "scope_name", "status", "description"]
        ),
        raw_response=response,
    )


def workspaces_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one workspace by UUID or slug, including its settings blocks."""
    workspace_ref = args["workspace_ref"]
    response = client.http_request("GET", f"{WORKSPACES_ENDPOINT}/{workspace_ref}", **plane_flags(args))
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayWorkspace",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Workspace {workspace_ref}", data),
        raw_response=response,
    )


def workspaces_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a workspace (admin plane).

    ``scope_name`` must name an IAM scope that already exists (create one first with
    ``prisma-airs-aigateway-scopes-create``); the API rejects a body missing either ``name`` or
    ``scope_name``. The response is most of the record but omits ``status``/``icon``/limit blocks -
    call ``prisma-airs-aigateway-workspaces-get`` for the full detail.
    """
    body = assign_params(
        name=args.get("name"),
        scope_name=args.get("scope_name"),
        description=args.get("description"),
        icon=args.get("icon"),
        defaults=json_arg(args, "defaults"),
        users=argToList(args.get("users")),
        usage_limits=json_arg(args, "usage_limits"),
        rate_limits=json_arg(args, "rate_limits"),
    )
    response = client.http_request("POST", WORKSPACES_ENDPOINT, json_data=body, use_aigw_admin=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayWorkspace",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Workspace Created", data),
        raw_response=response,
    )


def workspaces_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a workspace by UUID or slug (admin plane).

    Partial patch - at least one updatable field must be supplied. ``scope_name`` is not
    updatable here; rebind through the IAM scope instead.
    """
    workspace_ref = args["workspace_ref"]
    body = assign_params(
        name=args.get("name"),
        description=args.get("description"),
        icon=args.get("icon"),
        defaults=json_arg(args, "defaults"),
        usage_limits=json_arg(args, "usage_limits"),
        rate_limits=json_arg(args, "rate_limits"),
    )
    if not body:
        raise ValueError("Provide at least one field to update (name, description, icon, defaults, usage_limits, rate_limits).")
    client.http_request(
        "PUT",
        f"{WORKSPACES_ENDPOINT}/{workspace_ref}",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Workspace {workspace_ref} updated successfully.")


def workspaces_archive_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Archive (soft-delete) a workspace by UUID or slug (admin plane).

    This is a soft delete: the workspace is archived, not purged. A subsequent
    ``prisma-airs-aigateway-workspaces-get`` returns ``404 AB08``, but the row is still listed by
    ``prisma-airs-aigateway-workspaces-list status=archived``.
    """
    workspace_ref = args["workspace_ref"]
    client.http_request(
        "DELETE",
        f"{WORKSPACES_ENDPOINT}/{workspace_ref}",
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Workspace {workspace_ref} archived successfully.")


def _generate_workspace_scope_name(name: str) -> str:
    """Generate an SCM-style workspace scope name: ``ws_<slug>_<6 random alphanumerics>``.

    Mirrors SCM's own generator - the display name is lower-cased with every non-alphanumeric run
    collapsed to ``_``, then a six-char random suffix keeps repeated display names from colliding.
    Scope names are lowercase alphanumerics + underscores only, so the suffix joins with ``_``.
    """
    import re
    import secrets

    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    stem = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    suffix = "".join(secrets.choice(alphabet) for _ in range(6))
    return f"ws_{stem or 'workspace'}_{suffix}"


def workspaces_provision_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Provision a workspace end to end, mirroring the SCM UI's three-step flow (admin + IAM planes).

    1. Create the IAM scope (skipped when ``existing_scope=true``; ``scope_name`` is then required).
       When ``scope_name`` is omitted, one is generated as ``ws_<name>_<suffix>``.
    2. Create the workspace bound to that ``scope_name`` (admin plane).
    3. Bind the scope to the new workspace slug (read-modify-write, preserving existing bindings).

    Partial failures are surfaced, not hidden: if step 2 fails after step 1 created the scope, the
    scope is deleted again (best effort) and the error reports whether that rollback succeeded; if
    step 3 fails, the workspace exists but is unbound and the error names both so you can finish with
    ``prisma-airs-aigateway-scopes-bind``.
    """
    name = args["name"]
    existing_scope = argToBoolean(args.get("existing_scope", False))
    scope_name = args.get("scope_name")
    description = args.get("description") or ""

    if existing_scope and not scope_name:
        raise ValueError("When existing_scope=true, scope_name is required.")
    if not scope_name:
        scope_name = _generate_workspace_scope_name(name)
    scope_created = not existing_scope

    # Step 1: create the IAM scope (unless reusing one). SCM always sends description + resources.
    if scope_created:
        client.http_request(
            "POST",
            SCOPES_ENDPOINT,
            json_data={"name": scope_name, "description": description, "resources": []},
            use_aigw_iam=True,
        )

    # Step 2: create the workspace bound to the scope_name (admin plane).
    workspace_body = assign_params(
        name=name,
        scope_name=scope_name,
        description=args.get("description"),
        icon=args.get("icon"),
        defaults=json_arg(args, "defaults"),
        users=argToList(args.get("users")),
        usage_limits=json_arg(args, "usage_limits"),
        rate_limits=json_arg(args, "rate_limits"),
    )
    try:
        ws_response = client.http_request("POST", WORKSPACES_ENDPOINT, json_data=workspace_body, use_aigw_admin=True)
    except Exception as err:
        if not scope_created:
            raise
        rollback = f"IAM scope {scope_name} was deleted again"
        try:
            client.http_request(
                "DELETE",
                f"{SCOPES_ENDPOINT}/{scope_name}",
                use_aigw_iam=True,
                resp_type="response",
                return_empty_response=True,
            )
        except Exception as rollback_err:
            rollback = (
                f"IAM scope {scope_name} was created and is still present (rollback failed: {rollback_err}); "
                "delete it or reuse it with existing_scope=true"
            )
        raise DemistoException(f"Workspace create failed after creating its IAM scope - {rollback}: {err}")

    workspace = ws_response.get("data", ws_response) if isinstance(ws_response, dict) else ws_response
    workspace_slug = workspace.get("slug")

    # Step 3: bind the scope to the new workspace slug (read-modify-write, preserving bindings).
    try:
        current = client.http_request("GET", f"{SCOPES_ENDPOINT}/{scope_name}", use_aigw_iam=True)
        resources = [
            {"resource_type": r.get("resource_type"), "resource_id": r.get("resource_id"), "metadata": r.get("metadata") or []}
            for r in current.get("resources", [])
        ]
        if not any(r.get("resource_type") == "workspace" and r.get("resource_id") == workspace_slug for r in resources):
            resources.append({"resource_type": "workspace", "resource_id": workspace_slug, "metadata": []})
        scope = client.http_request(
            "PUT",
            f"{SCOPES_ENDPOINT}/{scope_name}",
            json_data={"name": scope_name, "description": current.get("description") or "", "resources": resources},
            use_aigw_iam=True,
        )
    except Exception as err:
        raise DemistoException(
            f"Workspace {workspace_slug} was created but could not be bound to IAM scope {scope_name}; "
            f"finish with prisma-airs-aigateway-scopes-bind name={scope_name} workspace_slug={workspace_slug}: {err}"
        )

    outputs = {
        "workspace_slug": workspace_slug,
        "workspace_id": workspace.get("id"),
        "scope_name": scope_name,
        "scope_created": scope_created,
        "workspace": workspace,
        "scope": scope,
    }
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayWorkspaceProvision",
        outputs_key_field="workspace_slug",
        outputs=outputs,
        readable_output=table(
            f"AI Gateway Workspace Provisioned - {workspace_slug}",
            {
                "workspace_slug": workspace_slug,
                "workspace_id": workspace.get("id"),
                "scope_name": scope_name,
                "scope_created": scope_created,
            },
        ),
        raw_response={"workspace": ws_response, "scope": scope},
    )


# IAM SCOPES (SCM IAM plane, /iam/v1) - the objects a workspace's scope_name points at.
# Scopes are keyed by name (not UUID); the list response is a {count, items} envelope, and the
# single-scope reads/writes return the scope object directly (no {success, data} wrapper).


def scopes_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List every IAM scope in the tenant."""
    response = client.http_request("GET", SCOPES_ENDPOINT, use_aigw_iam=True)
    data = response.get("items", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayScope",
        outputs_key_field="name",
        outputs=data,
        readable_output=table("AI Gateway IAM Scopes", data, headers=["name", "description", "tsg_id", "id"]),
        raw_response=response,
    )


def scopes_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one IAM scope by name."""
    name = args["name"]
    response = client.http_request("GET", f"{SCOPES_ENDPOINT}/{name}", use_aigw_iam=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayScope",
        outputs_key_field="name",
        outputs=response,
        readable_output=table(f"AI Gateway IAM Scope {name}", response),
        raw_response=response,
    )


def scopes_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create an unbound IAM scope (step 1 of workspace provisioning)."""
    # SCM always sends description and resources, even when empty; mirror that so the request
    # is byte-for-byte what the UI produces.
    body = {
        "name": args["name"],
        "description": args.get("description") or "",
        "resources": json_arg(args, "resources") or [],
    }
    response = client.http_request("POST", SCOPES_ENDPOINT, json_data=body, use_aigw_iam=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayScope",
        outputs_key_field="name",
        outputs=response,
        readable_output=table(f"AI Gateway IAM Scope {args['name']} Created", response),
        raw_response=response,
    )


def scopes_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an IAM scope. Full replacement (PUT) - omitting resources unbinds everything."""
    name = args["name"]
    body = {
        "name": name,
        "description": args.get("description") or "",
        "resources": json_arg(args, "resources") or [],
    }
    response = client.http_request("PUT", f"{SCOPES_ENDPOINT}/{name}", json_data=body, use_aigw_iam=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayScope",
        outputs_key_field="name",
        outputs=response,
        readable_output=table(f"AI Gateway IAM Scope {name} Updated", response),
        raw_response=response,
    )


def scopes_bind_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bind a workspace to an existing IAM scope (step 3 of workspace provisioning).

    Read-modify-write: fetch the scope, append the workspace binding unless it is already present
    (so existing bindings survive and re-running after a partial failure is safe), then PUT.
    SCM binds by workspace slug, not UUID.
    """
    name = args["name"]
    workspace_slug = args["workspace_slug"]
    current = client.http_request("GET", f"{SCOPES_ENDPOINT}/{name}", use_aigw_iam=True)
    resources = [
        {"resource_type": r.get("resource_type"), "resource_id": r.get("resource_id"), "metadata": r.get("metadata") or []}
        for r in current.get("resources", [])
    ]
    already_bound = any(
        r.get("resource_type") == "workspace" and r.get("resource_id") == workspace_slug for r in resources
    )
    if not already_bound:
        resources.append({"resource_type": "workspace", "resource_id": workspace_slug, "metadata": []})
    body = {"name": name, "description": current.get("description") or "", "resources": resources}
    response = client.http_request("PUT", f"{SCOPES_ENDPOINT}/{name}", json_data=body, use_aigw_iam=True)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayScope",
        outputs_key_field="name",
        outputs=response,
        readable_output=table(f"AI Gateway IAM Scope {name} - Bound {workspace_slug}", response),
        raw_response=response,
    )


def scopes_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete an IAM scope by name."""
    name = args["name"]
    client.http_request(
        "DELETE", f"{SCOPES_ENDPOINT}/{name}", use_aigw_iam=True, resp_type="response", return_empty_response=True
    )
    return CommandResults(readable_output=f"✅ IAM scope {name} deleted successfully.")


# INTEGRATIONS (admin plane, /integrations): credential provider bindings + static catalog.
# Read/discovery commands only; writes (create/update/delete, models/workspaces set) are deferred.


def integrations_catalog_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the static provider catalog (slug -> ai_provider_id) used when binding an integration."""
    response = client.http_request("GET", PROVIDER_CATALOG_ENDPOINT, use_aigw_admin=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayProviderCatalog",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Provider Catalog", data, headers=["id", "slug", "name"]),
        raw_response=response,
    )


def integrations_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List credential integrations for the tenant."""
    response = client.http_request("GET", INTEGRATIONS_ENDPOINT, params=pagination_params(args), use_aigw_admin=True)
    data = response.get("data", [])
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayIntegration",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Integrations", data, headers=["id", "name", "slug", "status", "ai_provider_id"]),
        raw_response=response,
    )


def integrations_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one credential integration by UUID."""
    integration_id = args["integration_id"]
    response = client.http_request("GET", f"{INTEGRATIONS_ENDPOINT}/{integration_id}", use_aigw_admin=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayIntegration",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Integration {integration_id}", data),
        raw_response=response,
    )


def integrations_models_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the models bound to a credential integration."""
    integration_id = args["integration_id"]
    response = client.http_request("GET", f"{INTEGRATIONS_ENDPOINT}/{integration_id}/models", use_aigw_admin=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayIntegrationModel",
        outputs_key_field="slug",
        outputs=data,
        readable_output=table(f"AI Gateway Integration {integration_id} Models", data),
        raw_response=response,
    )


def integrations_workspaces_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List the workspaces a credential integration is exposed to (plus global-access settings)."""
    integration_id = args["integration_id"]
    response = client.http_request("GET", f"{INTEGRATIONS_ENDPOINT}/{integration_id}/workspaces", use_aigw_admin=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayIntegrationWorkspace",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Integration {integration_id} Workspaces", data),
        raw_response=response,
    )


def _organisation_id(client: Client, args: dict[str, Any]) -> str:
    """Resolve the numeric organisation id for integration writes, defaulting to the tenant TSG id."""
    return args.get("organisation_id") or client.tsg_id or ""


def integrations_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a credential integration (upstream provider binding). Takes secret credential material."""
    body = assign_params(
        organisation_id=_organisation_id(client, args),
        ai_provider_id=args.get("ai_provider_id"),
        name=args.get("name"),
        slug=args.get("slug"),
        workspace_id=args.get("workspace_id"),
        description=args.get("description"),
        configurations=json_arg(args, "configurations"),
        key=args.get("key"),
        secret_mappings=json_arg(args, "secret_mappings"),
        create_default_provider=bool_arg(args, "create_default_provider"),
        default_provider_slug=args.get("default_provider_slug"),
        pricing_adjustments=json_arg(args, "pricing_adjustments"),
    )
    response = client.http_request("POST", INTEGRATIONS_ENDPOINT, json_data=body, use_aigw_admin=True)
    data = response.get("data", response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayIntegration",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Integration Created", data),
        raw_response=response,
    )


def integrations_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a credential integration. Requires at least one field."""
    integration_id = args["integration_id"]
    body = assign_params(
        name=args.get("name"),
        description=args.get("description"),
        configurations=json_arg(args, "configurations"),
        key=args.get("key"),
        secret_mappings=json_arg(args, "secret_mappings"),
        pricing_adjustments=json_arg(args, "pricing_adjustments"),
    )
    if not body:
        raise ValueError("Provide at least one field to update (name, description, configurations, key, secret_mappings, pricing_adjustments).")
    client.http_request(
        "PUT",
        f"{INTEGRATIONS_ENDPOINT}/{integration_id}",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Integration {integration_id} updated successfully.")


def integrations_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a credential integration. Requires the organisation_id query param (defaults to the tenant TSG id)."""
    integration_id = args["integration_id"]
    client.http_request(
        "DELETE",
        f"{INTEGRATIONS_ENDPOINT}/{integration_id}",
        params={"organisation_id": _organisation_id(client, args)},
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Integration {integration_id} deleted successfully.")


def integrations_models_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bulk-set the models bound to a credential integration."""
    integration_id = args["integration_id"]
    body = assign_params(
        models=json_arg(args, "models"),
        allow_all_models=bool_arg(args, "allow_all_models"),
    )
    client.http_request(
        "PUT",
        f"{INTEGRATIONS_ENDPOINT}/{integration_id}/models",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Integration {integration_id} models updated successfully.")


def integrations_models_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Remove specific model slugs from a credential integration."""
    integration_id = args["integration_id"]
    slugs = argToList(args.get("slugs"))
    client.http_request(
        "DELETE",
        f"{INTEGRATIONS_ENDPOINT}/{integration_id}/models",
        params={"slugs": ",".join(slugs)},
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Integration {integration_id} models {', '.join(slugs)} removed successfully.")


def integrations_workspaces_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bulk-set which workspaces a credential integration is exposed to. Requires at least one field."""
    integration_id = args["integration_id"]
    body = assign_params(
        workspaces=json_arg(args, "workspaces"),
        global_workspace_access=json_arg(args, "global_workspace_access"),
        override_existing_workspace_access=bool_arg(args, "override_existing_workspace_access"),
        create_default_provider=bool_arg(args, "create_default_provider"),
        default_provider_slug=args.get("default_provider_slug"),
    )
    if not body:
        raise ValueError("Provide at least one field (workspaces, global_workspace_access, override_existing_workspace_access, create_default_provider, default_provider_slug).")
    client.http_request(
        "PUT",
        f"{INTEGRATIONS_ENDPOINT}/{integration_id}/workspaces",
        json_data=body,
        use_aigw_admin=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Integration {integration_id} workspace access updated successfully.")


# PROVIDERS (data plane, /providers): per-workspace provider bindings.
# Read/discovery commands only; writes (create/update/delete) are deferred.

# Secret-bearing fields on a provider read; stripped from outputs so credentials are never persisted.
PROVIDER_SECRET_FIELDS = ("key",)


def _redact_provider(data: Any) -> Any:
    """Drop raw credential fields from a provider record before it reaches the context/war room."""
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if k not in PROVIDER_SECRET_FIELDS}
    if isinstance(data, list):
        return [_redact_provider(item) for item in data]
    return data


def providers_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List provider bindings in a workspace."""
    params = assign_params(workspace_id=args.get("workspace_id"), **pagination_params(args))
    response = client.http_request("GET", PROVIDERS_ENDPOINT, params=params, use_aigw_cp=True)
    data = _redact_provider(response.get("data", []))
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayProvider",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Providers", data, headers=["id", "name", "slug", "status", "integration_id"]),
        raw_response=data,
    )


def providers_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one provider binding by UUID. The raw API key is stripped; masked_api_key is retained."""
    provider_id = args["provider_id"]
    response = client.http_request("GET", f"{PROVIDERS_ENDPOINT}/{provider_id}", use_aigw_cp=True)
    data = _redact_provider(response.get("data", response))
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayProvider",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Provider {provider_id}", data),
        raw_response=data,
    )


def providers_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a provider binding in a workspace. Needs workspace_id, ai_provider_id and integration_id."""
    body = assign_params(
        workspace_id=args.get("workspace_id"),
        ai_provider_id=args.get("ai_provider_id"),
        integration_id=args.get("integration_id"),
        name=args.get("name"),
        slug=args.get("slug"),
        note=args.get("note"),
        usage_limits=json_arg(args, "usage_limits"),
        rate_limits=json_arg(args, "rate_limits"),
        expires_at=args.get("expires_at"),
    )
    response = client.http_request("POST", PROVIDERS_ENDPOINT, json_data=body, use_aigw_cp=True)
    data = _redact_provider(response.get("data", response))
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayProvider",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Provider Created", data),
        raw_response=data,
    )


def providers_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a provider binding. Requires at least one field."""
    provider_id = args["provider_id"]
    body = assign_params(
        name=args.get("name"),
        note=args.get("note"),
        usage_limits=json_arg(args, "usage_limits"),
        rate_limits=json_arg(args, "rate_limits"),
        expires_at=args.get("expires_at"),
        reset_usage=bool_arg(args, "reset_usage"),
    )
    if not body:
        raise ValueError("Provide at least one field to update (name, note, usage_limits, rate_limits, expires_at, reset_usage).")
    client.http_request(
        "PUT",
        f"{PROVIDERS_ENDPOINT}/{provider_id}",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Provider {provider_id} updated successfully.")


def providers_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a provider binding. This is a HARD delete - the provider is removed entirely."""
    provider_id = args["provider_id"]
    client.http_request(
        "DELETE",
        f"{PROVIDERS_ENDPOINT}/{provider_id}",
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ Provider {provider_id} deleted successfully.")


# PLUGINS (admin plane, /plugins): organisation-level plugin bindings. list returns masked credentials;
# create binds a plugin and takes live secret credential material.


def _redact_plugin(data: Any) -> Any:
    """Mask any credential value that is not already server-masked, so raw secrets never persist."""
    if isinstance(data, list):
        return [_redact_plugin(item) for item in data]
    if isinstance(data, dict):
        redacted = dict(data)
        credentials = redacted.get("credentials")
        if isinstance(credentials, dict):
            redacted["credentials"] = {
                key: (value if isinstance(value, str) and "*" in value else "***REDACTED***")
                for key, value in credentials.items()
            }
        return redacted
    return data


def plugins_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List organisation plugin bindings. Credential values are masked."""
    response = client.http_request("GET", PLUGINS_ENDPOINT, use_aigw_admin=True)
    data = _redact_plugin(response.get("data", []) if isinstance(response, dict) else response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayPlugin",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(
            "AI Gateway Plugins", data, headers=["id", "integration_slug", "plugin_provider_slug", "status"]
        ),
        raw_response=data,
    )


def plugins_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Bind a plugin to the organisation. Takes secret credential material (never echoed back)."""
    body = assign_params(
        organisation_id=_organisation_id(client, args),
        integration_id=args.get("integration_id"),
        credentials=json_arg(args, "credentials"),
    )
    if not body.get("credentials"):
        raise ValueError("credentials is required (a JSON object of credential name/value pairs).")
    response = client.http_request("POST", PLUGINS_ENDPOINT, json_data=body, use_aigw_admin=True)
    data = _redact_plugin(response.get("data", response) if isinstance(response, dict) else response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayPlugin",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Plugin Created", data),
        raw_response=data,
    )


# API KEYS (data plane, /api-keys/{service,user}): two distinct sub-collections. The secret `key` is
# returned ONLY once, at create/rotate - it is surfaced to the caller (with a warning) and cannot be
# recovered afterwards. list/get never return the secret.

ONE_TIME_KEY_WARNING = (
    "⚠️ Save the **key** value now - it is shown only once and cannot be retrieved later."
)


def _api_keys_create_body(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    """Build a service/user API-key create body. Shared by both create commands (user adds user_id)."""
    return assign_params(
        name=args.get("name"),
        description=args.get("description"),
        scopes=argToList(args.get("scopes")),
        type=args.get("type") or "workspace",
        organisation_id=_organisation_id(client, args),
        workspace_id=args.get("workspace_id"),
        alert_emails=argToList(args.get("alert_emails")),
        expires_at=args.get("expires_at"),
        rate_limits=json_arg(args, "rate_limits"),
        usage_limits=json_arg(args, "usage_limits"),
        defaults=json_arg(args, "defaults"),
        rotation_policy=json_arg(args, "rotation_policy"),
    )


def _api_keys_update_body(args: dict[str, Any]) -> dict[str, Any]:
    """Build a service/user API-key update body. At least one field is required by the caller."""
    return assign_params(
        name=args.get("name"),
        description=args.get("description"),
        scopes=argToList(args.get("scopes")),
        alert_emails=argToList(args.get("alert_emails")),
        expires_at=args.get("expires_at"),
        rate_limits=json_arg(args, "rate_limits"),
        usage_limits=json_arg(args, "usage_limits"),
        defaults=json_arg(args, "defaults"),
        rotation_policy=json_arg(args, "rotation_policy"),
        reset_usage=bool_arg(args, "reset_usage"),
    )


def _api_keys_list(client: Client, args: dict[str, Any], endpoint: str, title: str) -> CommandResults:
    """List API keys in a workspace (workspace_id is required). Secrets are never returned by list."""
    params = assign_params(workspace_id=args.get("workspace_id"), **pagination_params(args))
    response = client.http_request("GET", endpoint, params=params, use_aigw_cp=True)
    data = response.get("data", []) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayApiKey",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(title, data, headers=["id", "name", "type", "status", "object"]),
        raw_response=data,
    )


def _api_keys_get(client: Client, key_id: str, endpoint: str, title: str) -> CommandResults:
    """Get one API key by UUID. The secret is never returned by get."""
    response = client.http_request("GET", f"{endpoint}/{key_id}", use_aigw_cp=True)
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayApiKey",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(title, data),
        raw_response=data,
    )


def _api_keys_create(client: Client, args: dict[str, Any], body: dict[str, Any], endpoint: str, title: str) -> CommandResults:
    """Create an API key. The response carries the one-time secret `key`, surfaced with a warning."""
    if not body.get("scopes"):
        raise ValueError("scopes is required (a comma-separated list of at least one scope).")
    response = client.http_request("POST", endpoint, json_data=body, use_aigw_cp=True)
    data = response.get("data", response) if isinstance(response, dict) else response
    readable = table(title, data)
    if isinstance(data, dict) and data.get("key"):
        readable = f"{readable}\n\n{ONE_TIME_KEY_WARNING}"
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayApiKey",
        outputs_key_field="id",
        outputs=data,
        readable_output=readable,
        raw_response=data,
    )


def _api_keys_update(client: Client, key_id: str, body: dict[str, Any], endpoint: str, label: str) -> CommandResults:
    """Update an API key. Requires at least one field."""
    if not body:
        raise ValueError(
            "Provide at least one field to update "
            "(name, description, scopes, alert_emails, expires_at, rate_limits, usage_limits, defaults, "
            "rotation_policy, reset_usage)."
        )
    client.http_request(
        "PUT",
        f"{endpoint}/{key_id}",
        json_data=body,
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ {label} API key {key_id} updated successfully.")


def _api_keys_delete(client: Client, key_id: str, endpoint: str, label: str) -> CommandResults:
    """Permanently delete an API key. This is a HARD delete."""
    client.http_request(
        "DELETE",
        f"{endpoint}/{key_id}",
        use_aigw_cp=True,
        resp_type="response",
        return_empty_response=True,
    )
    return CommandResults(readable_output=f"✅ {label} API key {key_id} deleted successfully.")


def _api_keys_rotate(client: Client, args: dict[str, Any], key_id: str, endpoint: str, title: str) -> CommandResults:
    """Rotate an API key. The response carries the new one-time secret `key`, surfaced with a warning."""
    body = assign_params(key_transition_period_ms=arg_to_number(args.get("key_transition_period_ms")))
    response = client.http_request("POST", f"{endpoint}/{key_id}/rotate", json_data=body, use_aigw_cp=True)
    data = response.get("data", response) if isinstance(response, dict) else response
    readable = table(title, data)
    if isinstance(data, dict) and data.get("key"):
        readable = f"{readable}\n\n{ONE_TIME_KEY_WARNING}"
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayApiKeyRotation",
        outputs_key_field="id",
        outputs=data,
        readable_output=readable,
        raw_response=data,
    )


def api_keys_service_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List service API keys in a workspace."""
    return _api_keys_list(client, args, API_KEYS_SERVICE_ENDPOINT, "AI Gateway Service API Keys")


def api_keys_user_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List user API keys in a workspace."""
    return _api_keys_list(client, args, API_KEYS_USER_ENDPOINT, "AI Gateway User API Keys")


def api_keys_service_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one service API key by UUID."""
    key_id = args["key_id"]
    return _api_keys_get(client, key_id, API_KEYS_SERVICE_ENDPOINT, f"AI Gateway Service API Key {key_id}")


def api_keys_user_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one user API key by UUID."""
    key_id = args["key_id"]
    return _api_keys_get(client, key_id, API_KEYS_USER_ENDPOINT, f"AI Gateway User API Key {key_id}")


def api_keys_service_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a service API key. The one-time secret is returned only in this response."""
    body = _api_keys_create_body(client, args)
    return _api_keys_create(client, args, body, API_KEYS_SERVICE_ENDPOINT, "AI Gateway Service API Key Created")


def api_keys_user_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a user API key (requires user_id). The one-time secret is returned only in this response."""
    body = _api_keys_create_body(client, args)
    body["user_id"] = args.get("user_id")
    if not body.get("user_id"):
        raise ValueError("user_id is required to create a user API key.")
    return _api_keys_create(client, args, body, API_KEYS_USER_ENDPOINT, "AI Gateway User API Key Created")


def api_keys_service_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a service API key. Requires at least one field."""
    return _api_keys_update(client, args["key_id"], _api_keys_update_body(args), API_KEYS_SERVICE_ENDPOINT, "Service")


def api_keys_user_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a user API key. Requires at least one field."""
    return _api_keys_update(client, args["key_id"], _api_keys_update_body(args), API_KEYS_USER_ENDPOINT, "User")


def api_keys_service_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Permanently delete a service API key."""
    return _api_keys_delete(client, args["key_id"], API_KEYS_SERVICE_ENDPOINT, "Service")


def api_keys_user_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Permanently delete a user API key."""
    return _api_keys_delete(client, args["key_id"], API_KEYS_USER_ENDPOINT, "User")


def api_keys_service_rotate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Rotate a service API key. The new one-time secret is returned only in this response."""
    return _api_keys_rotate(client, args, args["key_id"], API_KEYS_SERVICE_ENDPOINT, "AI Gateway Service API Key Rotated")


def api_keys_user_rotate_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Rotate a user API key. The new one-time secret is returned only in this response."""
    return _api_keys_rotate(client, args, args["key_id"], API_KEYS_USER_ENDPOINT, "AI Gateway User API Key Rotated")


# ORGANISATIONS (admin plane, /organisations): tenant-level settings. info/self are reads; self/auth-settings
# updates are writes. Auth settings carry a live scim_token (and nested client_secret) - always redacted.

AUTH_SETTINGS_SECRET_FIELDS = ("scim_token", "client_secret")


def _redact_auth_settings(data: Any) -> Any:
    """Recursively mask scim_token / client_secret so live auth secrets never persist in context."""
    if isinstance(data, list):
        return [_redact_auth_settings(item) for item in data]
    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            if key in AUTH_SETTINGS_SECRET_FIELDS and value not in (None, ""):
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = _redact_auth_settings(value)
        return redacted
    return data


def organisations_info_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get one organisation's capabilities/settings. organisation_id defaults to the tenant TSG."""
    org_id = _organisation_id(client, args)
    response = client.http_request("GET", f"{ORGANISATIONS_ENDPOINT}/{org_id}/info", use_aigw_admin=True)
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrganisationInfo",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Organisation {org_id} Info", data),
        raw_response=data,
    )


def organisations_self_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get the calling organisation's record."""
    response = client.http_request("GET", ORGANISATION_SELF_ENDPOINT, use_aigw_admin=True)
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrganisation",
        outputs_key_field="id",
        outputs=data,
        readable_output=table("AI Gateway Organisation", data),
        raw_response=data,
    )


def organisations_self_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update the calling organisation's settings. Requires at least one field."""
    body = assign_params(name=args.get("name"))
    settings = json_arg(args, "settings")
    if isinstance(settings, dict):
        body.update(settings)
    if not body:
        raise ValueError("Provide at least one field to update (name and/or a settings JSON object).")
    response = client.http_request(
        "PUT", ORGANISATION_SELF_ENDPOINT, json_data=body, use_aigw_admin=True
    )
    data = response.get("data", response) if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrganisation",
        outputs_key_field="id",
        outputs=data or None,
        readable_output="✅ Organisation settings updated successfully.",
        raw_response=data,
    )


def organisations_auth_settings_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Get an organisation's auth settings. scim_token and client_secret are redacted."""
    org_id = _organisation_id(client, args)
    response = client.http_request(
        "GET", f"{ORGANISATIONS_ENDPOINT}/{org_id}/auth-settings", use_aigw_admin=True
    )
    data = _redact_auth_settings(response.get("data", response) if isinstance(response, dict) else response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrganisationAuthSettings",
        outputs_key_field="id",
        outputs=data,
        readable_output=table(f"AI Gateway Organisation {org_id} Auth Settings", data),
        raw_response=data,
    )


def organisations_auth_settings_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update an organisation's auth settings. Takes a secret scim_token; the response is redacted."""
    org_id = _organisation_id(client, args)
    body = assign_params(
        auth_settings=json_arg(args, "auth_settings"),
        domains=argToList(args.get("domains")),
        scim_token=args.get("scim_token"),
    )
    if not body:
        raise ValueError("Provide at least one field to update (auth_settings, domains, scim_token).")
    response = client.http_request(
        "PUT", f"{ORGANISATIONS_ENDPOINT}/{org_id}/auth-settings", json_data=body, use_aigw_admin=True
    )
    data = _redact_auth_settings(response.get("data", response) if isinstance(response, dict) else response)
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayOrganisationAuthSettings",
        outputs_key_field="id",
        outputs=data or None,
        readable_output=f"✅ Organisation {org_id} auth settings updated successfully.",
        raw_response=data,
    )


# MODEL PRICING (public catalog, NOT the SCM gateway): unauthenticated GET against a caller-supplied host.


def model_pricing_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Read one provider/model's public pricing catalog entry.

    This is NOT an SCM gateway call: it hits an unauthenticated public catalog at a caller-supplied
    host, bypassing the OAuth2 / x-tsg-id transport every other command uses.
    """
    from urllib.parse import quote

    provider = args["provider"]
    model = args["model"]
    endpoint = (args.get("endpoint") or MODEL_PRICING_DEFAULT_ENDPOINT).rstrip("/")
    if not (endpoint.startswith("https://") or endpoint.startswith(("http://localhost", "http://127.0.0.1"))):
        raise ValueError("The model pricing endpoint must be an HTTPS URL (HTTP is allowed only on loopback).")
    full_url = f"{endpoint}{MODEL_PRICING_PATH}/{quote(provider, safe='')}/{quote(model, safe='')}"
    # Direct unauthenticated GET: no Bearer token / x-tsg-id (public third-party catalog).
    response = client._http_request(
        method="GET",
        full_url=full_url,
        headers={"Accept": "application/json"},
        resp_type="json",
    )
    data = {"provider": provider, "model": model, **response} if isinstance(response, dict) else response
    return CommandResults(
        outputs_prefix=f"{PA_OUTPUT_PREFIX}AIGatewayModelPricing",
        outputs_key_field=["provider", "model"],
        outputs=data,
        readable_output=table(f"AI Gateway Model Pricing - {provider}/{model}", data),
        raw_response=response,
    )


# TEST


def test_connection(client: Client) -> str:
    """Verify AI Gateway connectivity by issuing a lightweight authenticated read.

    The shared ``test_module`` only validates the SCM OAuth2 token exchange; this probe
    additionally confirms the token (and ``x-tsg-id`` tenant header) is accepted by the AI
    Gateway host. It reads the calling organisation record, which needs no workspace or query
    params - unlike the workspace-scoped guardrails list, which returns ``404 AB02`` without a
    ``workspace_id``.

    Args:
        client: Prisma AIRS API client.

    Returns:
        str: 'ok' if the request succeeds.
    """
    client.http_request("GET", ORGANISATION_SELF_ENDPOINT, use_aigw_admin=True)
    return "ok"


# MAIN


def main() -> None:
    """Main entry point for the AI Gateway integration."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", DEFAULT_AIGW_BASE_URL)
    credentials = params.get("credentials", {})
    client_id = credentials.get("identifier", "")
    client_secret = credentials.get("password", "")
    tsg_id = params.get("tsg_id")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")

    commands: dict[str, Any] = {
        "prisma-airs-aigateway-guardrails-list": guardrails_list_command,
        "prisma-airs-aigateway-guardrails-create": guardrails_create_command,
        "prisma-airs-aigateway-guardrails-get": guardrails_get_command,
        "prisma-airs-aigateway-guardrails-update": guardrails_update_command,
        "prisma-airs-aigateway-guardrails-delete": guardrails_delete_command,
        "prisma-airs-aigateway-guardrails-catalog": guardrails_catalog_command,
        "prisma-airs-aigateway-guardrails-mcp-servers-list": guardrails_mcp_servers_list_command,
        "prisma-airs-aigateway-guardrails-mcp-servers-sync": guardrails_mcp_servers_sync_command,
        "prisma-airs-aigateway-guardrails-mcp-server-set": guardrails_mcp_server_set_command,
        "prisma-airs-aigateway-org-guardrails-list": org_guardrails_list_command,
        "prisma-airs-aigateway-org-guardrails-create": org_guardrails_create_command,
        "prisma-airs-aigateway-org-guardrails-get": org_guardrails_get_command,
        "prisma-airs-aigateway-org-guardrails-update": org_guardrails_update_command,
        "prisma-airs-aigateway-org-guardrails-delete": org_guardrails_delete_command,
        "prisma-airs-aigateway-configs-list": configs_list_command,
        "prisma-airs-aigateway-configs-create": configs_create_command,
        "prisma-airs-aigateway-configs-get": configs_get_command,
        "prisma-airs-aigateway-configs-update": configs_update_command,
        "prisma-airs-aigateway-configs-delete": configs_delete_command,
        "prisma-airs-aigateway-config-versions-list": config_versions_list_command,
        "prisma-airs-aigateway-deployments-list": deployments_list_command,
        "prisma-airs-aigateway-deployments-create": deployments_create_command,
        "prisma-airs-aigateway-deployments-get": deployments_get_command,
        "prisma-airs-aigateway-deployments-update": deployments_update_command,
        "prisma-airs-aigateway-deployments-delete": deployments_delete_command,
        "prisma-airs-aigateway-deployment-ping": deployment_ping_command,
        "prisma-airs-aigateway-rate-limit-policies-list": rate_limit_policies_list_command,
        "prisma-airs-aigateway-rate-limit-policies-create": rate_limit_policies_create_command,
        "prisma-airs-aigateway-rate-limit-policies-get": rate_limit_policies_get_command,
        "prisma-airs-aigateway-rate-limit-policies-update": rate_limit_policies_update_command,
        "prisma-airs-aigateway-rate-limit-policies-delete": rate_limit_policies_delete_command,
        "prisma-airs-aigateway-usage-limit-policies-list": usage_limit_policies_list_command,
        "prisma-airs-aigateway-usage-limit-policies-create": usage_limit_policies_create_command,
        "prisma-airs-aigateway-usage-limit-policies-get": usage_limit_policies_get_command,
        "prisma-airs-aigateway-usage-limit-policies-update": usage_limit_policies_update_command,
        "prisma-airs-aigateway-usage-limit-policies-delete": usage_limit_policies_delete_command,
        "prisma-airs-aigateway-usage-limit-policy-entities-list": usage_limit_policy_entities_list_command,
        "prisma-airs-aigateway-usage-limit-policy-entity-reset": usage_limit_policy_entity_reset_command,
        "prisma-airs-aigateway-secret-references-list": secret_references_list_command,
        "prisma-airs-aigateway-secret-references-create": secret_references_create_command,
        "prisma-airs-aigateway-secret-references-get": secret_references_get_command,
        "prisma-airs-aigateway-secret-references-update": secret_references_update_command,
        "prisma-airs-aigateway-secret-references-delete": secret_references_delete_command,
        "prisma-airs-aigateway-mcp-servers-list": mcp_servers_list_command,
        "prisma-airs-aigateway-mcp-servers-create": mcp_servers_create_command,
        "prisma-airs-aigateway-mcp-servers-get": mcp_servers_get_command,
        "prisma-airs-aigateway-mcp-servers-update": mcp_servers_update_command,
        "prisma-airs-aigateway-mcp-servers-delete": mcp_servers_delete_command,
        "prisma-airs-aigateway-mcp-server-test": mcp_server_test_command,
        "prisma-airs-aigateway-mcp-servers-capabilities-list": mcp_servers_capabilities_list_command,
        "prisma-airs-aigateway-mcp-servers-capabilities-set": mcp_servers_capabilities_set_command,
        "prisma-airs-aigateway-mcp-servers-user-access-list": mcp_servers_user_access_list_command,
        "prisma-airs-aigateway-mcp-servers-user-access-set": mcp_servers_user_access_set_command,
        "prisma-airs-aigateway-mcp-servers-connections-list": mcp_servers_connections_list_command,
        "prisma-airs-aigateway-mcp-servers-connections-delete": mcp_servers_connections_delete_command,
        "prisma-airs-aigateway-mcp-integrations-list": mcp_integrations_list_command,
        "prisma-airs-aigateway-mcp-integrations-create": mcp_integrations_create_command,
        "prisma-airs-aigateway-mcp-integrations-get": mcp_integrations_get_command,
        "prisma-airs-aigateway-mcp-integrations-update": mcp_integrations_update_command,
        "prisma-airs-aigateway-mcp-integrations-delete": mcp_integrations_delete_command,
        "prisma-airs-aigateway-mcp-integrations-workspaces-list": mcp_integrations_workspaces_list_command,
        "prisma-airs-aigateway-mcp-integrations-capabilities-list": mcp_integrations_capabilities_list_command,
        "prisma-airs-aigateway-mcp-integrations-metadata-get": mcp_integrations_metadata_get_command,
        "prisma-airs-aigateway-mcp-integrations-capabilities-set": mcp_integrations_capabilities_set_command,
        "prisma-airs-aigateway-mcp-integrations-workspaces-set": mcp_integrations_workspaces_set_command,
        "prisma-airs-aigateway-workspaces-list": workspaces_list_command,
        "prisma-airs-aigateway-workspaces-get": workspaces_get_command,
        "prisma-airs-aigateway-workspaces-create": workspaces_create_command,
        "prisma-airs-aigateway-workspaces-update": workspaces_update_command,
        "prisma-airs-aigateway-workspaces-archive": workspaces_archive_command,
        "prisma-airs-aigateway-workspaces-provision": workspaces_provision_command,
        "prisma-airs-aigateway-scopes-list": scopes_list_command,
        "prisma-airs-aigateway-scopes-get": scopes_get_command,
        "prisma-airs-aigateway-scopes-create": scopes_create_command,
        "prisma-airs-aigateway-scopes-update": scopes_update_command,
        "prisma-airs-aigateway-scopes-bind": scopes_bind_command,
        "prisma-airs-aigateway-scopes-delete": scopes_delete_command,
        "prisma-airs-aigateway-integrations-catalog": integrations_catalog_command,
        "prisma-airs-aigateway-integrations-list": integrations_list_command,
        "prisma-airs-aigateway-integrations-get": integrations_get_command,
        "prisma-airs-aigateway-integrations-create": integrations_create_command,
        "prisma-airs-aigateway-integrations-update": integrations_update_command,
        "prisma-airs-aigateway-integrations-delete": integrations_delete_command,
        "prisma-airs-aigateway-integrations-models-list": integrations_models_list_command,
        "prisma-airs-aigateway-integrations-models-set": integrations_models_set_command,
        "prisma-airs-aigateway-integrations-models-delete": integrations_models_delete_command,
        "prisma-airs-aigateway-integrations-workspaces-list": integrations_workspaces_list_command,
        "prisma-airs-aigateway-integrations-workspaces-set": integrations_workspaces_set_command,
        "prisma-airs-aigateway-providers-list": providers_list_command,
        "prisma-airs-aigateway-providers-get": providers_get_command,
        "prisma-airs-aigateway-providers-create": providers_create_command,
        "prisma-airs-aigateway-providers-update": providers_update_command,
        "prisma-airs-aigateway-providers-delete": providers_delete_command,
        "prisma-airs-aigateway-plugins-list": plugins_list_command,
        "prisma-airs-aigateway-plugins-create": plugins_create_command,
        "prisma-airs-aigateway-api-keys-service-list": api_keys_service_list_command,
        "prisma-airs-aigateway-api-keys-user-list": api_keys_user_list_command,
        "prisma-airs-aigateway-api-keys-service-get": api_keys_service_get_command,
        "prisma-airs-aigateway-api-keys-user-get": api_keys_user_get_command,
        "prisma-airs-aigateway-api-keys-service-create": api_keys_service_create_command,
        "prisma-airs-aigateway-api-keys-user-create": api_keys_user_create_command,
        "prisma-airs-aigateway-api-keys-service-update": api_keys_service_update_command,
        "prisma-airs-aigateway-api-keys-user-update": api_keys_user_update_command,
        "prisma-airs-aigateway-api-keys-service-delete": api_keys_service_delete_command,
        "prisma-airs-aigateway-api-keys-user-delete": api_keys_user_delete_command,
        "prisma-airs-aigateway-api-keys-service-rotate": api_keys_service_rotate_command,
        "prisma-airs-aigateway-api-keys-user-rotate": api_keys_user_rotate_command,
        "prisma-airs-aigateway-organisations-info-get": organisations_info_get_command,
        "prisma-airs-aigateway-organisations-self-get": organisations_self_get_command,
        "prisma-airs-aigateway-organisations-self-update": organisations_self_update_command,
        "prisma-airs-aigateway-organisations-auth-settings-get": organisations_auth_settings_get_command,
        "prisma-airs-aigateway-organisations-auth-settings-update": organisations_auth_settings_update_command,
        "prisma-airs-aigateway-model-pricing-get": model_pricing_get_command,
    }

    try:
        client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            verify=verify,
            proxy=proxy,
            headers={},
        )

        if command == "test-module":
            return_results(test_connection(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
