Manage Palo Alto Networks Prisma AIRS AI Gateway governance resources, including guardrails, gateway configs, deployments, rate- and usage-limit policies, secret references, and MCP servers and integrations.
This integration was integrated and tested with the Palo Alto Networks Prisma AIRS AI Gateway API (v3.0.0).

## Configure Palo Alto Networks Prisma AIRS - AI Gateway in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Client ID |  | True |
| API Client Secret |  | True |
| Tenant Services Group ID | Default Tenant Services Group ID to use for API calls. Example: 1234567890. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### prisma-airs-aigateway-guardrails-list

***
Lists guardrails on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID to list guardrails for. Required; omitting it returns a 404 (errorCode AB02). | Required |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrail.id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayGuardrail.name | String | The guardrail name. |
| PrismaAIRs.AIGatewayGuardrail.slug | String | The guardrail slug. |
| PrismaAIRs.AIGatewayGuardrail.target | String | The guardrail target \(llm or mcp_tools\). |
| PrismaAIRs.AIGatewayGuardrail.status | String | The guardrail status \(active or archived\). |

#### Command example

```
!prisma-airs-aigateway-guardrails-list workspace_id=8f51ae59-921e-4256-acda-6e312dd222d7
```

#### Context Example

```json
{
    "created_at": "2026-09-02T19:08:06.000Z",
    "id": "3b6220df-e7a6-43c3-816b-f64d630da287",
    "last_updated_at": "2026-09-21T15:35:38.000Z",
    "name": "Prisma_AIRS_Guardrail_ep-airs-api-bedrock",
    "object": "guardrail",
    "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
    "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
    "slug": "pg-prisma-58d82b",
    "status": "active",
    "target": "llm",
    "updated_by": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
    "workspace_id": "8f51ae59-921e-4256-acda-6e312dd222d7"
}
```

#### Human Readable Output

>### AI Gateway Guardrails
>
>|Created At|Id|Last Updated At|Name|Object|Organisation Id|Owner Id|Slug|Status|Target|Updated By|Workspace Id|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2026-09-02T19:08:06.000Z | 3b6220df-e7a6-43c3-816b-f64d630da287 | 2026-09-21T15:35:38.000Z | Prisma_AIRS_Guardrail_ep-airs-api-bedrock | guardrail | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | pg-prisma-58d82b | active | llm | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | 8f51ae59-921e-4256-acda-6e312dd222d7 |

### prisma-airs-aigateway-guardrails-create

***
Creates a guardrail on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The guardrail name. | Required |
| target | The guardrail target. Possible values are: llm, mcp_tools. | Optional |
| workspace_id | The workspace ID the guardrail belongs to. | Optional |
| checks | A JSON array of guardrail checks. For example, '[{"id":"...","parameters":{}}]'. | Optional |
| actions | A JSON object describing the guardrail actions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrail.id | String | The created guardrail ID. |
| PrismaAIRs.AIGatewayGuardrail.slug | String | The created guardrail slug. |
| PrismaAIRs.AIGatewayGuardrail.version_id | String | The created guardrail version ID. |

### prisma-airs-aigateway-guardrails-get

***
Retrieves a guardrail by ID from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrail.id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayGuardrail.name | String | The guardrail name. |
| PrismaAIRs.AIGatewayGuardrail.slug | String | The guardrail slug. |
| PrismaAIRs.AIGatewayGuardrail.target | String | The guardrail target. |
| PrismaAIRs.AIGatewayGuardrail.status | String | The guardrail status. |
| PrismaAIRs.AIGatewayGuardrail.workspace_id | String | The workspace ID. |
| PrismaAIRs.AIGatewayGuardrail.created_at | Date | The creation timestamp. |

### prisma-airs-aigateway-guardrails-update

***
Updates a guardrail on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |
| name | The updated guardrail name. | Optional |
| checks | A JSON array of guardrail checks. | Optional |
| actions | A JSON object describing the guardrail actions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrail.id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayGuardrail.slug | String | The guardrail slug. |
| PrismaAIRs.AIGatewayGuardrail.version_id | String | The new guardrail version ID. |

### prisma-airs-aigateway-guardrails-delete

***
Deletes a guardrail from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-guardrails-catalog

***
Lists the available guardrail evaluators and their parameter schemas (the catalog of check types), not configured guardrail instances. Uses the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-guardrails-catalog`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrailCatalog.id | String | The guardrail evaluator ID. |
| PrismaAIRs.AIGatewayGuardrailCatalog.name | String | The guardrail evaluator name. |

### prisma-airs-aigateway-guardrails-mcp-servers-list

***
Lists the MCP server mappings attached to a guardrail on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-mcp-servers-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrailMcpServer.id | String | The mapping ID. |
| PrismaAIRs.AIGatewayGuardrailMcpServer.guardrail_id | String | The guardrail ID the mapping belongs to. |
| PrismaAIRs.AIGatewayGuardrailMcpServer.mcp_server_id | String | The mapped MCP server ID. |
| PrismaAIRs.AIGatewayGuardrailMcpServer.run_on | Unknown | The stages the guardrail runs on for this MCP server. |

### prisma-airs-aigateway-guardrails-mcp-servers-sync

***
Replaces all MCP server mappings on a guardrail in one bulk sync on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-mcp-servers-sync`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |
| mcp_servers | A JSON object keyed by MCP server ID, each value an object with optional run_on and mcp_integration_capability_ids arrays. Example: {"&lt;mcp_server_id&gt;": {"run_on": ["request"], "mcp_integration_capability_ids": []}}. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrailMcpServerSync.guardrail_id | String | The guardrail ID that was synced. |
| PrismaAIRs.AIGatewayGuardrailMcpServerSync.changed | Boolean | Whether any mapping changed. |
| PrismaAIRs.AIGatewayGuardrailMcpServerSync.added | Number | The number of mappings added. |
| PrismaAIRs.AIGatewayGuardrailMcpServerSync.updated | Number | The number of mappings updated. |
| PrismaAIRs.AIGatewayGuardrailMcpServerSync.removed | Number | The number of mappings removed. |

### prisma-airs-aigateway-guardrails-mcp-server-set

***
Enables or disables a single MCP server mapping on a guardrail on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-guardrails-mcp-server-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |
| mcp_server_id | The MCP server ID to map. | Required |
| run_on | A comma-separated list of stages the guardrail runs on for this MCP server. | Optional |
| mcp_integration_capability_ids | A comma-separated list of MCP integration capability IDs to scope the mapping to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayGuardrailMcpServerMapping.map_id | String | The mapping ID. |
| PrismaAIRs.AIGatewayGuardrailMcpServerMapping.guardrail_id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayGuardrailMcpServerMapping.mcp_server_id | String | The mapped MCP server ID. |

### prisma-airs-aigateway-org-guardrails-list

***
Lists organization-level guardrails on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-org-guardrails-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | Filters guardrails by workspace ID. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrgGuardrail.id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayOrgGuardrail.name | String | The guardrail name. |
| PrismaAIRs.AIGatewayOrgGuardrail.slug | String | The guardrail slug. |
| PrismaAIRs.AIGatewayOrgGuardrail.status | String | The guardrail status. |

### prisma-airs-aigateway-org-guardrails-create

***
Creates an organization-level guardrail on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-org-guardrails-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The guardrail name. | Required |
| target | The guardrail target. Possible values are: llm, mcp_tools. | Optional |
| workspace_id | The workspace ID the guardrail belongs to. | Optional |
| checks | A JSON array of guardrail checks. | Optional |
| actions | A JSON object describing the guardrail actions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrgGuardrail.id | String | The created guardrail ID. |
| PrismaAIRs.AIGatewayOrgGuardrail.slug | String | The created guardrail slug. |
| PrismaAIRs.AIGatewayOrgGuardrail.version_id | String | The created guardrail version ID. |

### prisma-airs-aigateway-org-guardrails-get

***
Retrieves an organization-level guardrail by ID from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-org-guardrails-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrgGuardrail.id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayOrgGuardrail.name | String | The guardrail name. |
| PrismaAIRs.AIGatewayOrgGuardrail.status | String | The guardrail status. |

### prisma-airs-aigateway-org-guardrails-update

***
Updates an organization-level guardrail on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-org-guardrails-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |
| name | The updated guardrail name. | Optional |
| checks | A JSON array of guardrail checks. | Optional |
| actions | A JSON object describing the guardrail actions. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrgGuardrail.id | String | The guardrail ID. |
| PrismaAIRs.AIGatewayOrgGuardrail.version_id | String | The new guardrail version ID. |

### prisma-airs-aigateway-org-guardrails-delete

***
Deletes an organization-level guardrail from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-org-guardrails-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guardrail_id | The guardrail ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-configs-list

***
Lists gateway configs on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-configs-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID to list configs for. Required; omitting it returns a 404 (errorCode AB02). | Required |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayConfig.id | String | The config ID. |
| PrismaAIRs.AIGatewayConfig.name | String | The config name. |
| PrismaAIRs.AIGatewayConfig.slug | String | The config slug. |

### prisma-airs-aigateway-configs-create

***
Creates a gateway config on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-configs-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The config name. | Optional |
| config | A JSON object describing the config definition. | Optional |
| workspace_id | The workspace ID the config belongs to. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayConfig.id | String | The created config ID. |
| PrismaAIRs.AIGatewayConfig.slug | String | The created config slug. |

### prisma-airs-aigateway-configs-get

***
Retrieves a gateway config by ID from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-configs-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The config ID (UUID) from prisma-airs-aigateway-configs-list. Must be the UUID, not the slug; a slug returns a 404 (errorCode AB02). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayConfig.id | String | The config ID. |
| PrismaAIRs.AIGatewayConfig.name | String | The config name. |
| PrismaAIRs.AIGatewayConfig.slug | String | The config slug. |

### prisma-airs-aigateway-configs-update

***
Updates a gateway config on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-configs-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The config ID (UUID) from prisma-airs-aigateway-configs-list. Must be the UUID, not the slug; a slug returns a 404 (errorCode AB02). | Required |
| name | The updated config name. | Optional |
| config | A JSON object describing the config definition. | Optional |
| status | The config status. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayConfig.id | String | The config ID. |
| PrismaAIRs.AIGatewayConfig.slug | String | The config slug. |

### prisma-airs-aigateway-configs-delete

***
Deletes a gateway config from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-configs-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The config ID (UUID) from prisma-airs-aigateway-configs-list. Must be the UUID, not the slug; a slug returns a 404 (errorCode AB02). | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-config-versions-list

***
Lists the versions of a gateway config on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-config-versions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The config ID (UUID) from prisma-airs-aigateway-configs-list. Must be the UUID, not the slug; a slug returns a 404 (errorCode AB02). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayConfigVersion.id | String | The config version ID. |

### prisma-airs-aigateway-deployments-list

***
Lists deployments on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-deployments-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Filters deployments by status. Possible values are: active, archived. | Optional |
| type | Filters deployments by type. Possible values are: production, non_production. | Optional |
| workspace_slug | A comma-separated list of workspace slugs to filter by. | Optional |
| search | Filters deployments by a search term. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayDeployment.id | String | The deployment ID. |
| PrismaAIRs.AIGatewayDeployment.name | String | The deployment name. |
| PrismaAIRs.AIGatewayDeployment.slug | String | The deployment slug. |
| PrismaAIRs.AIGatewayDeployment.type | String | The deployment type. |
| PrismaAIRs.AIGatewayDeployment.status | String | The deployment status. |

### prisma-airs-aigateway-deployments-create

***
Creates a deployment on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-deployments-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The deployment name. | Required |
| slug | The deployment slug. | Optional |
| type | The deployment type. Possible values are: production, non_production. | Optional |
| deployment_config | A JSON object describing the deployment configuration. | Optional |
| is_default | Whether this deployment is the default. Possible values are: true, false. | Optional |
| auth_settings | A JSON object describing the deployment auth settings. | Optional |
| tags | A JSON object of deployment tags. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayDeployment.id | String | The created deployment ID. |

### prisma-airs-aigateway-deployments-get

***
Retrieves a deployment by ID from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-deployments-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deployment_id | The deployment ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayDeployment.id | String | The deployment ID. |
| PrismaAIRs.AIGatewayDeployment.name | String | The deployment name. |
| PrismaAIRs.AIGatewayDeployment.status | String | The deployment status. |
| PrismaAIRs.AIGatewayDeployment.connection_status | String | The deployment connection status. |

### prisma-airs-aigateway-deployments-update

***
Updates a deployment on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-deployments-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deployment_id | The deployment ID. | Required |
| name | The updated deployment name. | Optional |
| type | The deployment type. Possible values are: production, non_production. | Optional |
| status | The deployment status. Possible values are: active, archived. | Optional |
| deployment_config | A JSON object describing the deployment configuration. | Optional |
| is_default | Whether this deployment is the default. Possible values are: true, false. | Optional |
| rotate_auth | Whether to rotate the deployment auth credentials. Possible values are: true, false. | Optional |
| override_existing | Whether to override the existing deployment configuration. Possible values are: true, false. | Optional |
| auth_settings | A JSON object describing the deployment auth settings. | Optional |
| tags | A JSON object of deployment tags. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-deployments-delete

***
Deletes a deployment from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-deployments-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deployment_id | The deployment ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-deployment-ping

***
Pings a deployment to check its connectivity and health on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-deployment-ping`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deployment_id | The deployment ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayDeploymentPing.deployment_id | String | The deployment ID. |
| PrismaAIRs.AIGatewayDeploymentPing.status | String | The deployment health status \(healthy, partial, or unhealthy\). |
| PrismaAIRs.AIGatewayDeploymentPing.gateway_base_url | String | The gateway base URL. |

### prisma-airs-aigateway-rate-limit-policies-list

***
Lists rate-limit policies on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-rate-limit-policies-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID to list rate-limit policies for. Required; omitting it returns a 404 (errorCode AB02). | Required |
| status | Filters policies by status. Possible values are: active, archived. | Optional |
| type | Filters policies by type. Possible values are: requests, tokens. | Optional |
| unit | Filters policies by unit. Possible values are: rpm, rph, rpd, rpw. | Optional |
| target | Filters policies by target. Possible values are: llm, mcp_tools. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayRateLimitPolicy.id | String | The policy ID. |
| PrismaAIRs.AIGatewayRateLimitPolicy.name | String | The policy name. |
| PrismaAIRs.AIGatewayRateLimitPolicy.type | String | The policy type. |
| PrismaAIRs.AIGatewayRateLimitPolicy.unit | String | The policy unit. |
| PrismaAIRs.AIGatewayRateLimitPolicy.value | Number | The policy limit value. |
| PrismaAIRs.AIGatewayRateLimitPolicy.status | String | The policy status. |

### prisma-airs-aigateway-rate-limit-policies-create

***
Creates a rate-limit policy on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-rate-limit-policies-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The policy name. | Optional |
| conditions | A JSON array of policy conditions. | Required |
| group_by | A JSON array describing how usage is grouped. | Required |
| type | The policy type. Possible values are: requests, tokens. | Required |
| unit | The policy unit. Possible values are: rpm, rph, rpd, rpw. | Required |
| value | The rate-limit value. | Required |
| target | The policy target. Possible values are: llm, mcp_tools. | Optional |
| workspace_id | The workspace ID the policy belongs to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayRateLimitPolicy.id | String | The created policy ID. |

### prisma-airs-aigateway-rate-limit-policies-get

***
Retrieves a rate-limit policy by ID from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-rate-limit-policies-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |
| status | Filters by policy status. Possible values are: active, archived. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayRateLimitPolicy.id | String | The policy ID. |
| PrismaAIRs.AIGatewayRateLimitPolicy.name | String | The policy name. |
| PrismaAIRs.AIGatewayRateLimitPolicy.value | Number | The policy limit value. |
| PrismaAIRs.AIGatewayRateLimitPolicy.status | String | The policy status. |

### prisma-airs-aigateway-rate-limit-policies-update

***
Updates a rate-limit policy on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-rate-limit-policies-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |
| name | The updated policy name. | Optional |
| unit | The policy unit. Possible values are: rpm, rph, rpd, rpw. | Optional |
| value | The rate-limit value. | Optional |
| conditions | A JSON array of policy conditions. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-rate-limit-policies-delete

***
Deletes a rate-limit policy from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-rate-limit-policies-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-usage-limit-policies-list

***
Lists usage-limit policies on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policies-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID to list usage-limit policies for. Required; omitting it returns a 404 (errorCode AB02). | Required |
| status | Filters policies by status. Possible values are: active, archived. | Optional |
| type | Filters policies by type. Possible values are: cost, tokens. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayUsageLimitPolicy.id | String | The policy ID. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.name | String | The policy name. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.type | String | The policy type. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.credit_limit | Number | The policy credit limit. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.status | String | The policy status. |

### prisma-airs-aigateway-usage-limit-policies-create

***
Creates a usage-limit policy on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policies-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The policy name. | Optional |
| conditions | A JSON array of policy conditions. | Required |
| group_by | A JSON array describing how usage is grouped. | Required |
| type | The policy type. Possible values are: cost, tokens. | Required |
| credit_limit | The usage credit limit. | Required |
| alert_threshold | The alert threshold value. | Optional |
| periodic_reset | The periodic reset interval. Possible values are: monthly, weekly. | Optional |
| workspace_id | The workspace ID the policy belongs to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayUsageLimitPolicy.id | String | The created policy ID. |

### prisma-airs-aigateway-usage-limit-policies-get

***
Retrieves a usage-limit policy by ID from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policies-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |
| status | Filters by policy status. Possible values are: active, archived. | Optional |
| include_usage | Whether to include current usage details in the response. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayUsageLimitPolicy.id | String | The policy ID. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.name | String | The policy name. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.credit_limit | Number | The policy credit limit. |
| PrismaAIRs.AIGatewayUsageLimitPolicy.status | String | The policy status. |

### prisma-airs-aigateway-usage-limit-policies-update

***
Updates a usage-limit policy on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policies-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |
| name | The updated policy name. | Optional |
| description | The updated policy description. | Optional |
| conditions | A JSON array of policy conditions. | Optional |
| credit_limit | The usage credit limit. | Optional |
| alert_threshold | The alert threshold value. | Optional |
| periodic_reset | The periodic reset interval. Possible values are: monthly, weekly. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-usage-limit-policies-delete

***
Deletes a usage-limit policy from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policies-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-usage-limit-policy-entities-list

***
Lists the entities tracked by a usage-limit policy on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policy-entities-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |
| status | Filters entities by status. Possible values are: active, exhausted. | Optional |
| search | Filters entities by a search term. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayUsageLimitPolicyEntity.id | String | The entity ID. |

### prisma-airs-aigateway-usage-limit-policy-entity-reset

***
Resets the usage counter of a single entity within a usage-limit policy on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-usage-limit-policy-entity-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required |
| entity_id | The entity ID to reset. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-secret-references-list

***
Lists secret references on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-secret-references-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manager_type | Filters secret references by secret manager type. Possible values are: aws_sm, azure_kv, hashicorp_vault. | Optional |
| tags | Filters secret references by tags. | Optional |
| search | Filters secret references by a search term. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewaySecretReference.id | String | The secret reference ID. |
| PrismaAIRs.AIGatewaySecretReference.name | String | The secret reference name. |
| PrismaAIRs.AIGatewaySecretReference.manager_type | String | The secret manager type. |
| PrismaAIRs.AIGatewaySecretReference.status | String | The secret reference status. |

### prisma-airs-aigateway-secret-references-create

***
Creates a secret reference on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-secret-references-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The secret reference name. | Required |
| slug | The secret reference slug. | Optional |
| description | The secret reference description. | Optional |
| manager_type | The secret manager type. Possible values are: aws_sm, azure_kv, hashicorp_vault. | Required |
| auth_config | A JSON object describing the secret manager auth configuration. | Required |
| secret_path | The path to the secret in the secret manager. | Required |
| secret_key | The key of the secret within the secret path. | Optional |
| allow_all_workspaces | Whether the secret reference is available to all workspaces. Possible values are: true, false. | Optional |
| allowed_workspaces | A comma-separated list of workspace IDs allowed to use the secret reference. | Optional |
| tags | A JSON object of tags. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewaySecretReference.id | String | The created secret reference ID. |
| PrismaAIRs.AIGatewaySecretReference.slug | String | The created secret reference slug. |

### prisma-airs-aigateway-secret-references-get

***
Retrieves a secret reference by ID from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-secret-references-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_reference_id | The secret reference ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewaySecretReference.id | String | The secret reference ID. |
| PrismaAIRs.AIGatewaySecretReference.name | String | The secret reference name. |
| PrismaAIRs.AIGatewaySecretReference.manager_type | String | The secret manager type. |
| PrismaAIRs.AIGatewaySecretReference.secret_path | String | The path to the secret. |
| PrismaAIRs.AIGatewaySecretReference.status | String | The secret reference status. |

### prisma-airs-aigateway-secret-references-update

***
Updates a secret reference on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-secret-references-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_reference_id | The secret reference ID. | Required |
| name | The updated secret reference name. | Optional |
| description | The updated secret reference description. | Optional |
| auth_config | A JSON object describing the secret manager auth configuration. | Optional |
| secret_path | The path to the secret in the secret manager. | Optional |
| secret_key | The key of the secret within the secret path. | Optional |
| allow_all_workspaces | Whether the secret reference is available to all workspaces. Possible values are: true, false. | Optional |
| allowed_workspaces | A comma-separated list of workspace IDs allowed to use the secret reference. | Optional |
| tags | A JSON object of tags. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-secret-references-delete

***
Deletes a secret reference from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-secret-references-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_reference_id | The secret reference ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-servers-list

***
Lists MCP servers on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-mcp-servers-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID to list MCP servers for. Required; omitting it returns a 404 (errorCode AB02). | Required |
| id | Filters MCP servers by ID. | Optional |
| search | Filters MCP servers by a search term. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServer.id | String | The MCP server ID. |
| PrismaAIRs.AIGatewayMcpServer.name | String | The MCP server name. |
| PrismaAIRs.AIGatewayMcpServer.slug | String | The MCP server slug. |
| PrismaAIRs.AIGatewayMcpServer.status | String | The MCP server status. |

#### Command example

```
!prisma-airs-aigateway-mcp-servers-list workspace_id=8f51ae59-921e-4256-acda-6e312dd222d7
```

#### Context Example

```json
[
    {
        "auth_type": "oauth_auto",
        "created_at": "2026-09-04T15:55:30.000Z",
        "description": "Created automatically on MCP integration access grant",
        "id": "2d36e43e-8000-4be0-bbc9-fc30b658f461",
        "last_updated_at": "2026-09-04T15:55:30.000Z",
        "mcp_integration_id": "fc0ce135-a729-4b72-a1fa-1f34afff9d2d",
        "mcp_integration_slug": "figma",
        "mcp_integration_url": "https://mcp.figma.com/mcp",
        "metadata": {
            "description": null,
            "icons": null,
            "last_synced_at": null,
            "protocol_version": null,
            "server_name": null,
            "server_version": null,
            "sync_status": "pending",
            "title": null,
            "website_url": null
        },
        "name": "figma",
        "object": "mcp-server",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "figma",
        "status": "active",
        "url": "https://mcp-aigw.portkey.ai/figma/mcp",
        "workspace_id": "8f51ae59-921e-4256-acda-6e312dd222d7",
        "workspace_name": "aws_gateway",
        "workspace_slug": "ws-aws-ga-2a753e"
    },
    {
        "auth_type": "headers",
        "created_at": "2026-08-28T14:34:44.000Z",
        "description": "Created automatically on MCP integration access grant",
        "id": "b0a9d458-0c84-4cad-bfe7-c46cd31acf3a",
        "last_updated_at": "2026-08-28T14:34:44.000Z",
        "mcp_integration_id": "9ec57c07-5eb4-47a4-846d-9fdcf0a40328",
        "mcp_integration_slug": "huggingface-mcp",
        "mcp_integration_url": "https://huggingface.co/mcp",
        "metadata": {
            "description": null,
            "icons": [
                {
                    "src": "https://huggingface.co/favicon.ico"
                }
            ],
            "last_synced_at": "2026-09-21T15:17:51.000Z",
            "protocol_version": null,
            "server_name": "huggingface.co/mcp",
            "server_version": "0.4.21",
            "sync_status": "synced",
            "title": "Hugging Face",
            "website_url": "https://huggingface.co/mcp"
        },
        "name": "huggingface-mcp",
        "object": "mcp-server",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "huggingface-mcp",
        "status": "active",
        "url": "https://mcp-aigw.portkey.ai/huggingface-mcp/mcp",
        "workspace_id": "8f51ae59-921e-4256-acda-6e312dd222d7",
        "workspace_name": "aws_gateway",
        "workspace_slug": "ws-aws-ga-2a753e"
    },
    {
        "auth_type": "headers",
        "created_at": "2026-08-28T14:34:44.000Z",
        "description": "Created automatically on MCP integration access grant",
        "id": "abf39d83-3809-4906-8969-cd4b3d062ed2",
        "last_updated_at": "2026-08-28T14:34:44.000Z",
        "mcp_integration_id": "ffd50390-067d-41e2-8c7f-05e7a1598112",
        "mcp_integration_slug": "postman-minimal-mcp",
        "mcp_integration_url": "https://mcp.postman.com/minimal",
        "metadata": {
            "description": "Find and manage Postman workspaces, collections, environments, mocks, monitors, and API specifications, run collections, and publish API documentation.",
            "icons": null,
            "last_synced_at": "2026-09-21T13:25:31.000Z",
            "protocol_version": null,
            "server_name": "postman-api-mcp-server-minimal",
            "server_version": "1.8.0",
            "sync_status": "synced",
            "title": "Postman",
            "website_url": "https://www.postman.com"
        },
        "name": "postman-minimal-mcp",
        "object": "mcp-server",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "postman-minimal-mcp",
        "status": "active",
        "url": "https://mcp-aigw.portkey.ai/postman-minimal-mcp/mcp",
        "workspace_id": "8f51ae59-921e-4256-acda-6e312dd222d7",
        "workspace_name": "aws_gateway",
        "workspace_slug": "ws-aws-ga-2a753e"
    }
]
```

#### Human Readable Output

>### AI Gateway MCP Servers
>
>|Auth Type|Created At|Description|Id|Last Updated At|Mcp Integration Id|Mcp Integration Slug|Mcp Integration Url|Metadata|Name|Object|Organisation Id|Owner Id|Slug|Status|Url|Workspace Id|Workspace Name|Workspace Slug|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| oauth_auto | 2026-09-04T15:55:30.000Z | Created automatically on MCP integration access grant | 2d36e43e-8000-4be0-bbc9-fc30b658f461 | 2026-09-04T15:55:30.000Z | fc0ce135-a729-4b72-a1fa-1f34afff9d2d | figma | https://mcp.figma.com/mcp | title: null<br>description: null<br>icons: null<br>server_name: null<br>server_version: null<br>protocol_version: null<br>sync_status: pending<br>last_synced_at: null<br>website_url: null | figma | mcp-server | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | figma | active | https://mcp-aigw.portkey.ai/figma/mcp | 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e |
>| headers | 2026-08-28T14:34:44.000Z | Created automatically on MCP integration access grant | b0a9d458-0c84-4cad-bfe7-c46cd31acf3a | 2026-08-28T14:34:44.000Z | 9ec57c07-5eb4-47a4-846d-9fdcf0a40328 | huggingface-mcp | https://huggingface.co/mcp | title: Hugging Face<br>description: null<br>icons: {'src': 'https://huggingface.co/favicon.ico'}<br>server_name: huggingface.co/mcp<br>server_version: 0.4.21<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T15:17:51.000Z<br>website_url: https://huggingface.co/mcp | huggingface-mcp | mcp-server | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | huggingface-mcp | active | https://mcp-aigw.portkey.ai/huggingface-mcp/mcp | 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e |
>| headers | 2026-08-28T14:34:44.000Z | Created automatically on MCP integration access grant | abf39d83-3809-4906-8969-cd4b3d062ed2 | 2026-08-28T14:34:44.000Z | ffd50390-067d-41e2-8c7f-05e7a1598112 | postman-minimal-mcp | https://mcp.postman.com/minimal | title: Postman<br>description: Find and manage Postman workspaces, collections, environments, mocks, monitors, and API specifications, run collections, and publish API documentation.<br>icons: null<br>server_name: postman-api-mcp-server-minimal<br>server_version: 1.8.0<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T13:25:31.000Z<br>website_url: https://www.postman.com | postman-minimal-mcp | mcp-server | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | postman-minimal-mcp | active | https://mcp-aigw.portkey.ai/postman-minimal-mcp/mcp | 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e |
>| headers | 2026-08-28T14:34:44.000Z | Created automatically on MCP integration access grant | 9f4595bc-3a0b-4155-a896-26ba3efd8865 | 2026-08-28T14:34:44.000Z | bde48eb8-d97e-49bc-b122-2f55696f4e62 | exa-mcp-server | https://mcp.exa.ai/mcp | title: Exa<br>description: null<br>icons: {'src': 'https://exa.ai/images/favicon-32x32.png', 'sizes': ['32x32'], 'mimeType': 'image/png'}<br>server_name: exa-search-server<br>server_version: 3.2.1<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T15:16:29.000Z<br>website_url: https://exa.ai | exa-mcp-server | mcp-server | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | exa-mcp-server | active | https://mcp-aigw.portkey.ai/exa-mcp-server/mcp | 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e |
>| headers | 2026-08-28T14:34:44.000Z | Created automatically on MCP integration access grant | 924c5748-9231-4f6d-8534-a0589ec7aa3d | 2026-08-28T14:34:44.000Z | 5e978cc8-a38f-4380-a3ab-6116a5c6b84b | context7-mcp-server | https://mcp.context7.com/mcp | title: null<br>description: Context7 provides up-to-date documentation and code examples for libraries and frameworks.<br>icons: {'src': 'https://context7.com/context7-icon-green.png', 'mimeType': 'image/png'}<br>server_name: Context7<br>server_version: 4.1.1<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T15:16:29.000Z<br>website_url: https://context7.com | context7-mcp-server | mcp-server | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | context7-mcp-server | active | https://mcp-aigw.portkey.ai/context7-mcp-server/mcp | 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e |
>| none | 2026-08-28T14:34:44.000Z | Created automatically on MCP integration access grant | 24445e80-0f51-4606-a005-366a80472b6c | 2026-08-28T14:34:44.000Z | da4e86fe-45a5-4652-b175-c50d11b8b47b | deepwiki-mcp | https://mcp.deepwiki.com/mcp | title: null<br>description: null<br>icons: null<br>server_name: DeepWiki<br>server_version: 2.14.3<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T13:25:32.000Z<br>website_url: null | deepwiki-mcp | mcp-server | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | deepwiki-mcp | active | https://mcp-aigw.portkey.ai/deepwiki-mcp/mcp | 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e |
>| ... | _(7 rows total; truncated for brevity)_ |

### prisma-airs-aigateway-mcp-servers-create

***
Creates an MCP server on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-mcp-servers-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The MCP server name. | Required |
| mcp_integration_id | The MCP integration ID the server is based on. | Required |
| description | The MCP server description. | Optional |
| workspace_id | The workspace ID the MCP server belongs to. | Optional |
| slug | The MCP server slug. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServer.id | String | The created MCP server ID. |
| PrismaAIRs.AIGatewayMcpServer.slug | String | The created MCP server slug. |

### prisma-airs-aigateway-mcp-servers-get

***
Retrieves an MCP server by ID from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-mcp-servers-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServer.id | String | The MCP server ID. |
| PrismaAIRs.AIGatewayMcpServer.name | String | The MCP server name. |
| PrismaAIRs.AIGatewayMcpServer.status | String | The MCP server status. |
| PrismaAIRs.AIGatewayMcpServer.mcp_integration_id | String | The MCP integration ID the server is based on. |

### prisma-airs-aigateway-mcp-servers-update

***
Updates an MCP server on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-mcp-servers-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| name | The updated MCP server name. | Optional |
| description | The updated MCP server description. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-servers-delete

***
Deletes an MCP server from the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-mcp-servers-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-server-test

***
Tests connectivity to an MCP server on the AI Gateway control plane.

#### Base Command

`prisma-airs-aigateway-mcp-server-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServerTest.mcp_server_id | String | The MCP server ID. |
| PrismaAIRs.AIGatewayMcpServerTest.success | Boolean | Whether the test succeeded. |
| PrismaAIRs.AIGatewayMcpServerTest.status_code | Number | The HTTP status code returned by the MCP server. |
| PrismaAIRs.AIGatewayMcpServerTest.response_time_ms | Number | The response time in milliseconds. |

### prisma-airs-aigateway-mcp-servers-capabilities-list

***
Lists the capabilities (tools, prompts, resources, resource templates) discovered on an MCP server (AI Gateway control plane).

#### Base Command

`prisma-airs-aigateway-mcp-servers-capabilities-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| type | Filters capabilities by type. Possible values are: tool, prompt, resource, resource_template. | Optional |
| page | The page number to retrieve. | Optional |
| page_size | The number of results to return per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServerCapability.name | String | The capability name. |
| PrismaAIRs.AIGatewayMcpServerCapability.type | String | The capability type. |
| PrismaAIRs.AIGatewayMcpServerCapability.enabled | Boolean | Whether the capability is enabled. |

### prisma-airs-aigateway-mcp-servers-capabilities-set

***
Bulk-updates capability enablement on an MCP server (AI Gateway control plane).

#### Base Command

`prisma-airs-aigateway-mcp-servers-capabilities-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| capabilities | A JSON array of capability enablement objects, each: {"name": ..., "type": ..., "enabled": true\|false}. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-servers-user-access-list

***
Lists per-user access for an MCP server (AI Gateway control plane).

#### Base Command

`prisma-airs-aigateway-mcp-servers-user-access-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| search | Filters users by a search term. | Optional |
| page | The page number to retrieve. | Optional |
| page_size | The number of results to return per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServerUserAccess.user_id | String | The user ID. |
| PrismaAIRs.AIGatewayMcpServerUserAccess.enabled | Boolean | Whether the user has access. |
| PrismaAIRs.AIGatewayMcpServerUserAccess.connection_status | String | The user's connection status. |

### prisma-airs-aigateway-mcp-servers-user-access-set

***
Bulk-updates per-user access for an MCP server (AI Gateway control plane). Provide at least one field.

#### Base Command

`prisma-airs-aigateway-mcp-servers-user-access-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| user_access | A JSON array of per-user access objects, each: {"user_id": ..., "enabled": true\|false}. | Optional |
| default_user_access | The default access applied to users without an explicit override. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-servers-connections-list

***
Lists user connections established against an MCP server (AI Gateway control plane).

#### Base Command

`prisma-airs-aigateway-mcp-servers-connections-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| user_id | Filters connections by user ID. | Optional |
| workspace_id | Filters connections by workspace ID. | Optional |
| current_page | The page number to retrieve. | Optional |
| page_size | The number of results to return per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpServerConnection.user_id | String | The user ID. |
| PrismaAIRs.AIGatewayMcpServerConnection.connected | Boolean | Whether the user is connected. |

### prisma-airs-aigateway-mcp-servers-connections-delete

***
Deletes MCP server user connection(s), optionally scoped by user ID and/or workspace ID (AI Gateway control plane).

#### Base Command

`prisma-airs-aigateway-mcp-servers-connections-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_server_id | The MCP server ID. | Required |
| user_id | Deletes only the connection for this user ID. | Optional |
| workspace_id | Deletes only connections within this workspace ID. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-integrations-list

***
Lists MCP integrations on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Filters MCP integrations by type. Possible values are: workspace, organisation, all. | Optional |
| workspace_id | Filters MCP integrations by workspace ID. | Optional |
| search | Filters MCP integrations by a search term. | Optional |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpIntegration.id | String | The MCP integration ID. |
| PrismaAIRs.AIGatewayMcpIntegration.name | String | The MCP integration name. |
| PrismaAIRs.AIGatewayMcpIntegration.status | String | The MCP integration status. |

#### Command example

```
!prisma-airs-aigateway-mcp-integrations-list
```

#### Context Example

```json
[
    {
        "auth_type": "headers",
        "configurations": "{\"encrypted\": \"eyJjcHQiOiJLdDh0ZFJkd2JhMGNhNXVFc2dENlR4UDJFRUVYM2NhQ0pBVmRGcDhRdmRLREFNVEM4a1RMeC9TNEM1OFhQSHFvZXFSbEZJUmVoWnBrUFUyU1J2S0xqSStqYTYzakU4NUk3aHlLT0JqVzRETy9Ld04vTERNdHRMOUZZNCsvblFpNExzZ3ZZNG9LdC8va3hNWVh3Q3FPcEMrc2tHcTFqcjNYUzBlT0cvRG5rcXM9IiwibWV0YWRhdGEiOnsiaXYiOiIyVzExTm5rY1d5a2RycTZqIiwidGFnIjoiL2oxOFZjMVhwR3d1L1VDTE54STNndz09In19\"}",
        "created_at": "2026-07-27T21:42:14.000Z",
        "description": null,
        "id": "ffd50390-067d-41e2-8c7f-05e7a1598112",
        "last_updated_at": "2026-08-20T14:33:23.000Z",
        "metadata": {
            "description": "Find and manage Postman workspaces, collections, environments, mocks, monitors, and API specifications, run collections, and publish API documentation.",
            "icons": null,
            "last_synced_at": "2026-09-21T13:25:31.000Z",
            "protocol_version": null,
            "server_name": "postman-api-mcp-server-minimal",
            "server_version": "1.8.0",
            "sync_status": "synced",
            "title": "Postman"
        },
        "name": "postman-minimal_mcp",
        "object": "mcp-integration",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "postman-minimal-mcp",
        "status": "active",
        "transport": "http",
        "type": "organisation",
        "url": "https://mcp.postman.com/minimal",
        "workspace_id": null,
        "workspaces_count": 2
    },
    {
        "auth_type": "headers",
        "configurations": "{\"encrypted\": \"eyJjcHQiOiJMaE85K01VaG1vcnVTaEhqdkxzSVNFYnJQdUpXQkhrRFBQYnZoN3VVOWJmaElrOEpHQlBBQ2ZTeE0yYmQ4MXR5a3NmS21qaTN4QzZhZnlTOXlxMHUvVTQyTUsxeiIsIm1ldGFkYXRhIjp7Iml2IjoiT20veVZqaG9YTWw1NzNlciIsInRhZyI6IlhVVTdYV0llS3AwSFhIYUs2SjEvTXc9PSJ9fQ==\"}",
        "created_at": "2026-07-27T19:10:13.000Z",
        "description": null,
        "id": "9ec57c07-5eb4-47a4-846d-9fdcf0a40328",
        "last_updated_at": "2026-09-04T16:55:44.000Z",
        "metadata": {
            "description": null,
            "icons": [
                {
                    "src": "https://huggingface.co/favicon.ico"
                }
            ],
            "last_synced_at": "2026-09-21T15:17:51.000Z",
            "protocol_version": null,
            "server_name": "huggingface.co/mcp",
            "server_version": "0.4.21",
            "sync_status": "synced",
            "title": "Hugging Face"
        },
        "name": "huggingface_mcp",
        "object": "mcp-integration",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "huggingface-mcp",
        "status": "active",
        "transport": "http",
        "type": "organisation",
        "url": "https://huggingface.co/mcp",
        "workspace_id": null,
        "workspaces_count": 3
    },
    {
        "auth_type": "oauth_auto",
        "configurations": "{\"encrypted\": \"eyJjcHQiOiJ4SldaTDZ4ZVpaby9nbGx1dXJadHVuaXRHSzRSNWRldGJ2Yz0iLCJtZXRhZGF0YSI6eyJpdiI6Im9zczRKWWRTZTVwYUJxZHciLCJ0YWciOiJDUnRPNWNNaUEyb01neWNDS1YzODZBPT0ifX0=\"}",
        "created_at": "2026-07-17T01:10:08.000Z",
        "description": null,
        "id": "fc0ce135-a729-4b72-a1fa-1f34afff9d2d",
        "last_updated_at": "2026-09-04T15:55:30.000Z",
        "metadata": {
            "description": null,
            "icons": null,
            "last_synced_at": null,
            "protocol_version": null,
            "server_name": null,
            "server_version": null,
            "sync_status": "pending",
            "title": null
        },
        "name": "figma_mcp",
        "object": "mcp-integration",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "figma",
        "status": "active",
        "transport": "http",
        "type": "organisation",
        "url": "https://mcp.figma.com/mcp",
        "workspace_id": null,
        "workspaces_count": 2
    }
]
```

#### Human Readable Output

>### AI Gateway MCP Integrations
>
>|Auth Type|Configurations|Created At|Id|Last Updated At|Metadata|Name|Object|Organisation Id|Owner Id|Slug|Status|Transport|Type|Url|Workspaces Count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| headers | {"encrypted": "eyJjcHQiOiJLdDh0ZFJkd2JhMGNhNXVFc2dENlR4UDJFRUVYM2NhQ0pBVmRGcDhRdmRLREFNVEM4a1RMeC9TNEM1OFhQSHFvZXFSbEZJUmVoWnBrUFUyU1J2S0xqSStqYTYzakU4NUk3aHlLT0JqVzRETy9Ld04vTERNdHRMOUZZNCsvblFpNExzZ3ZZNG9LdC8va3hNWVh3Q3FPcEMrc2tHcTFqcjNYUzBlT0cvRG5rcXM9IiwibWV0YWRhdGEiOnsiaXYiOiIyVzExTm5rY1d5a2RycTZqIiwidGFnIjoiL2oxOFZjMVhwR3d1L1VDTE54STNndz09In19"} | 2026-07-27T21:42:14.000Z | ffd50390-067d-41e2-8c7f-05e7a1598112 | 2026-08-20T14:33:23.000Z | title: Postman<br>description: Find and manage Postman workspaces, collections, environments, mocks, monitors, and API specifications, run collections, and publish API documentation.<br>icons: null<br>server_name: postman-api-mcp-server-minimal<br>server_version: 1.8.0<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T13:25:31.000Z | postman-minimal_mcp | mcp-integration | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | postman-minimal-mcp | active | http | organisation | https://mcp.postman.com/minimal | 2 |
>| headers | {"encrypted": "eyJjcHQiOiJMaE85K01VaG1vcnVTaEhqdkxzSVNFYnJQdUpXQkhrRFBQYnZoN3VVOWJmaElrOEpHQlBBQ2ZTeE0yYmQ4MXR5a3NmS21qaTN4QzZhZnlTOXlxMHUvVTQyTUsxeiIsIm1ldGFkYXRhIjp7Iml2IjoiT20veVZqaG9YTWw1NzNlciIsInRhZyI6IlhVVTdYV0llS3AwSFhIYUs2SjEvTXc9PSJ9fQ=="} | 2026-07-27T19:10:13.000Z | 9ec57c07-5eb4-47a4-846d-9fdcf0a40328 | 2026-09-04T16:55:44.000Z | title: Hugging Face<br>description: null<br>icons: {'src': 'https://huggingface.co/favicon.ico'}<br>server_name: huggingface.co/mcp<br>server_version: 0.4.21<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T15:17:51.000Z | huggingface_mcp | mcp-integration | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | huggingface-mcp | active | http | organisation | https://huggingface.co/mcp | 3 |
>| oauth_auto | {"encrypted": "eyJjcHQiOiJ4SldaTDZ4ZVpaby9nbGx1dXJadHVuaXRHSzRSNWRldGJ2Yz0iLCJtZXRhZGF0YSI6eyJpdiI6Im9zczRKWWRTZTVwYUJxZHciLCJ0YWciOiJDUnRPNWNNaUEyb01neWNDS1YzODZBPT0ifX0="} | 2026-07-17T01:10:08.000Z | fc0ce135-a729-4b72-a1fa-1f34afff9d2d | 2026-09-04T15:55:30.000Z | title: null<br>description: null<br>icons: null<br>server_name: null<br>server_version: null<br>protocol_version: null<br>sync_status: pending<br>last_synced_at: null | figma_mcp | mcp-integration | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | figma | active | http | organisation | https://mcp.figma.com/mcp | 2 |
>| headers | {"encrypted": "eyJjcHQiOiJteVJ4NVBFOVFxMlI5bmlCUE9OcmJWaWxZRmNlNDRVNFhOTFl6MktkdXdiR1NTTXZxNk5rRjRabjA2UTJjS0Y2cWQ0RVIwRFhNdG5HSk1ZcS9HbUM3Yy8zc1dQNFdTd1VETDR4N0pHUkZDMU5qMzJweWhwMVJPOHEzUnNWQ2JXTUN6VEhNRnRKSUE9PSIsIm1ldGFkYXRhIjp7Iml2IjoiT0c4U24xdWNzdjNldTlpMiIsInRhZyI6ImNzNG9xRzFtZGtIL29ndTYvdW4rd3c9PSJ9fQ=="} | 2026-07-17T01:09:35.000Z | feb03543-af15-4012-ba88-a4e9ddea3e2d | 2026-07-27T18:33:26.000Z | title: null<br>description: null<br>icons: null<br>server_name: null<br>server_version: null<br>protocol_version: null<br>sync_status: pending<br>last_synced_at: null | prismaairs_mcp | mcp-integration | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | prisma-airs-mcp | active | http | organisation | https://service.api.aisecurity.paloaltonetworks.com/mcp | 3 |
>| headers | {"encrypted": "eyJjcHQiOiJ6Y2Vyc0sxTjVRcElJZUw5UjhIZzVxK2xwTVlOcWxtT0VrS3BPd3BRc0JEc1UwQnFZQUFpMVViWS9QOFpHYWZpTlZ0cFd0S3RQY1ViZEdwQVREdXFDVHlTWERYS0tsMDZ0N2xaNSs0cmVYNThlUkNHdUh6V3ovd1ZwQ1EyYmpTNmVhZ2ZnUTJxMlE9PSIsIm1ldGFkYXRhIjp7Iml2IjoidjkycGNtdHhyKzl3QlNVUCIsInRhZyI6InBHb09ic3c3SG9KN1kvc0RuWm5tM0E9PSJ9fQ=="} | 2026-07-17T01:08:48.000Z | 5e978cc8-a38f-4380-a3ab-6116a5c6b84b | 2026-07-27T20:13:31.000Z | title: null<br>description: Context7 provides up-to-date documentation and code examples for libraries and frameworks.<br>icons: {'src': 'https://context7.com/context7-icon-green.png', 'mimeType': 'image/png'}<br>server_name: Context7<br>server_version: 4.1.1<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T15:16:29.000Z | context7_mcp | mcp-integration | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | context7-mcp-server | active | http | organisation | https://mcp.context7.com/mcp | 7 |
>| none | {"encrypted": "eyJjcHQiOiJua0xqM0xUTy8zNC9LS2VSYlE0STBVeElpWVNCQXIrWUFrTT0iLCJtZXRhZGF0YSI6eyJpdiI6IjRvQUJIRElaVEUwaUlGcFMiLCJ0YWciOiJnY2hKU1FnRDVvaTRGYU56UUwxZUlRPT0ifX0="} | 2026-07-17T01:08:02.000Z | da4e86fe-45a5-4652-b175-c50d11b8b47b | 2026-09-04T16:20:28.000Z | title: null<br>description: null<br>icons: null<br>server_name: DeepWiki<br>server_version: 2.14.3<br>protocol_version: null<br>sync_status: synced<br>last_synced_at: 2026-09-21T13:25:32.000Z | deepwiki_mcp | mcp-integration | 7f194769-8f30-4b84-95ad-e277466e3427 | 59087f43-bd63-4d7d-940d-2ff5dd9382b3 | deepwiki-mcp | active | http | organisation | https://mcp.deepwiki.com/mcp | 7 |
>| ... | _(7 rows total; truncated for brevity)_ |

### prisma-airs-aigateway-mcp-integrations-create

***
Creates an MCP integration on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The MCP integration name. | Required |
| url | The MCP server URL the integration connects to. | Required |
| auth_type | The authentication type for the MCP integration. Possible values are: oauth_auto, headers, none. | Required |
| transport | The transport protocol for the MCP integration. Possible values are: http, sse. | Required |
| description | The MCP integration description. | Optional |
| workspace_id | The workspace ID the MCP integration belongs to. | Optional |
| slug | The MCP integration slug. | Optional |
| configurations | A JSON object describing the MCP integration configurations. | Optional |
| secret_mappings | A JSON array of secret mappings. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpIntegration.id | String | The created MCP integration ID. |
| PrismaAIRs.AIGatewayMcpIntegration.slug | String | The created MCP integration slug. |

### prisma-airs-aigateway-mcp-integrations-get

***
Retrieves an MCP integration by ID from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpIntegration.id | String | The MCP integration ID. |
| PrismaAIRs.AIGatewayMcpIntegration.name | String | The MCP integration name. |
| PrismaAIRs.AIGatewayMcpIntegration.url | String | The MCP server URL. |
| PrismaAIRs.AIGatewayMcpIntegration.auth_type | String | The authentication type. |
| PrismaAIRs.AIGatewayMcpIntegration.transport | String | The transport protocol. |

### prisma-airs-aigateway-mcp-integrations-update

***
Updates an MCP integration on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |
| name | The updated MCP integration name. | Optional |
| description | The updated MCP integration description. | Optional |
| url | The MCP server URL the integration connects to. | Optional |
| auth_type | The authentication type for the MCP integration. Possible values are: oauth_auto, headers, none. | Optional |
| transport | The transport protocol for the MCP integration. Possible values are: http, sse. | Optional |
| configurations | A JSON object describing the MCP integration configurations. | Optional |
| secret_mappings | A JSON array of secret mappings. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-integrations-delete

***
Deletes an MCP integration from the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-integrations-workspaces-list

***
Lists which workspaces an MCP integration is exposed to (AI Gateway admin plane).

#### Base Command

`prisma-airs-aigateway-mcp-integrations-workspaces-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |
| version | Selects the upstream response envelope version. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpIntegrationWorkspace.id | String | The workspace ID. |
| PrismaAIRs.AIGatewayMcpIntegrationWorkspace.enabled | Boolean | Whether the workspace may use the MCP integration. |

### prisma-airs-aigateway-mcp-integrations-capabilities-list

***
Lists the capabilities (tools, prompts, resources, resource templates) discovered from an MCP integration (AI Gateway admin plane).

#### Base Command

`prisma-airs-aigateway-mcp-integrations-capabilities-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpIntegrationCapability.name | String | The capability name. |
| PrismaAIRs.AIGatewayMcpIntegrationCapability.type | String | The capability type. |
| PrismaAIRs.AIGatewayMcpIntegrationCapability.enabled | Boolean | Whether the capability is enabled. |

### prisma-airs-aigateway-mcp-integrations-metadata-get

***
Retrieves metadata discovered from an MCP integration's server (identity, protocol, capability flags, sync state) on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-metadata-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayMcpIntegrationMetadata.mcp_integration_id | String | The MCP integration ID. |
| PrismaAIRs.AIGatewayMcpIntegrationMetadata.sync_status | String | The server metadata sync status. |

### prisma-airs-aigateway-mcp-integrations-capabilities-set

***
Bulk-updates capability enablement on an MCP integration (AI Gateway admin plane).

#### Base Command

`prisma-airs-aigateway-mcp-integrations-capabilities-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |
| capabilities | A JSON array of capability enablement objects, each: {"name": ..., "type": ..., "enabled": true\|false}. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-mcp-integrations-workspaces-set

***
Bulk-sets which workspaces may use an MCP integration (AI Gateway admin plane). Provide at least one field.

#### Base Command

`prisma-airs-aigateway-mcp-integrations-workspaces-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mcp_integration_id | The MCP integration ID. | Required |
| workspaces | A JSON array of workspace bindings, each: {"id": ..., "enabled": true\|false}. | Optional |
| global_workspace_access | A JSON object toggling global workspace access, e.g. {"enabled": false}. | Optional |
| override_existing_workspace_access | Whether to replace existing workspace access rather than merge. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-workspaces-list

***
Lists AI Gateway workspaces and their IDs. Use this to discover the workspace_id values required by the data-plane list commands.

#### Base Command

`prisma-airs-aigateway-workspaces-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plane | Which plane to read from. 'data' (default) returns only active workspaces the service account is scoped to; 'admin' enumerates the whole tenant. Possible values are: data, admin. Default is data. | Optional |
| status | Filter by lifecycle state. Omitting this returns active workspaces only; archived workspaces are invisible unless requested explicitly. Possible values are: active, archived. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayWorkspace.id | String | The workspace ID \(UUID\). |
| PrismaAIRs.AIGatewayWorkspace.name | String | The workspace name. |
| PrismaAIRs.AIGatewayWorkspace.slug | String | The workspace slug. |
| PrismaAIRs.AIGatewayWorkspace.scope_name | String | The SCM scope name that grants data-plane access to the workspace. |
| PrismaAIRs.AIGatewayWorkspace.status | String | The workspace lifecycle state. |

#### Command example

```
!prisma-airs-aigateway-workspaces-list
```

#### Context Example

```json
[
    {
        "created_at": "2026-08-28T14:34:45.000Z",
        "description": null,
        "icon": null,
        "id": "8f51ae59-921e-4256-acda-6e312dd222d7",
        "is_default": 0,
        "last_updated_at": "2026-09-11T21:06:18.000Z",
        "name": "aws_gateway",
        "object": "workspace",
        "scope_name": "ws_aws_gateway_mwxlau",
        "slug": "ws-aws-ga-2a753e",
        "status": "active"
    },
    {
        "created_at": "2026-07-22T16:43:34.000Z",
        "description": null,
        "icon": null,
        "id": "bc98d4ef-d9d4-4227-a9d0-3fcebd65160d",
        "is_default": 0,
        "last_updated_at": "2026-09-11T21:06:18.000Z",
        "name": "azure_gateway",
        "object": "workspace",
        "scope_name": "ws_azure_gateway_bhw5tg",
        "slug": "ws-azure-f901bd",
        "status": "active"
    },
    {
        "created_at": "2026-07-24T21:27:19.000Z",
        "description": null,
        "icon": null,
        "id": "95438b1d-df31-418d-9660-e0cc8f6963a1",
        "is_default": 0,
        "last_updated_at": "2026-09-21T00:00:17.000Z",
        "name": "dev_team",
        "object": "workspace",
        "scope_name": "ws_dev_team_o4e127",
        "slug": "ws-dev-te-994d38",
        "status": "active"
    }
]
```

#### Human Readable Output

>### AI Gateway Workspaces
>
>|Id|Name|Slug|Scope Name|Status|Description|
>|---|---|---|---|---|---|
>| 8f51ae59-921e-4256-acda-6e312dd222d7 | aws_gateway | ws-aws-ga-2a753e | ws_aws_gateway_mwxlau | active |  |
>| bc98d4ef-d9d4-4227-a9d0-3fcebd65160d | azure_gateway | ws-azure-f901bd | ws_azure_gateway_bhw5tg | active |  |
>| 95438b1d-df31-418d-9660-e0cc8f6963a1 | dev_team | ws-dev-te-994d38 | ws_dev_team_o4e127 | active |  |
>| 67c665ef-7012-4f3b-b498-a7344d5242e5 | eHomeLab | ws-ehomel-12f1a1 | ws_ehomelab_a0p949 | active |  |
>| e796d679-f630-42c9-a6d6-36722b2ed80c | eLaptop | ws-elab-1fb741 | ws_elab_a77h91 | active |  |
>| d9dbffba-403b-482e-a6fb-22726b45986f | gcp_gateway | ws-gcp-ga-3ffd5a | ws_gcp_gateway_6b6bgw | active |  |
>| ... | _(7 rows total; truncated for brevity)_ |

### prisma-airs-aigateway-workspaces-get

***
Gets one AI Gateway workspace by UUID or slug, including its settings blocks.

#### Base Command

`prisma-airs-aigateway-workspaces-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_ref | The workspace UUID or slug. | Required |
| plane | Which plane to read from. 'data' (default) reads workspaces the service account is scoped to; 'admin' reads a workspace outside your workspace scope. Possible values are: data, admin. Default is data. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayWorkspace.id | String | The workspace ID \(UUID\). |
| PrismaAIRs.AIGatewayWorkspace.name | String | The workspace name. |
| PrismaAIRs.AIGatewayWorkspace.slug | String | The workspace slug. |

### prisma-airs-aigateway-workspaces-create

***
Creates an AI Gateway workspace (admin plane). scope_name must name an IAM scope that already exists - create one first with prisma-airs-aigateway-scopes-create. The response omits status/icon/limit blocks; call prisma-airs-aigateway-workspaces-get for full detail.

#### Base Command

`prisma-airs-aigateway-workspaces-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The workspace display name. | Required |
| scope_name | The name of an existing SCM IAM scope that grants access to this workspace. Must already exist (see prisma-airs-aigateway-scopes-create). | Required |
| description | The workspace description. | Optional |
| icon | The workspace icon identifier. | Optional |
| defaults | Default settings for the workspace as a JSON object (e.g. {"config_id": "...", "allow_config_override": true, "metadata": {}}). | Optional |
| users | Comma-separated list of user IDs to seed as workspace members. | Optional |
| usage_limits | Usage-limit definitions as a JSON array. | Optional |
| rate_limits | Rate-limit definitions as a JSON array. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayWorkspace.id | String | The workspace ID \(UUID\). |
| PrismaAIRs.AIGatewayWorkspace.name | String | The workspace name. |
| PrismaAIRs.AIGatewayWorkspace.slug | String | The workspace slug. |
| PrismaAIRs.AIGatewayWorkspace.scope_name | String | The SCM scope name that grants data-plane access to the workspace. |

### prisma-airs-aigateway-workspaces-update

***
Updates an AI Gateway workspace by UUID or slug (admin plane). Partial patch - supply at least one field. scope_name is not updatable here; rebind through the IAM scope instead.

#### Base Command

`prisma-airs-aigateway-workspaces-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_ref | The workspace slug (its UUID is also accepted) identifying the workspace to update. | Required |
| name | The new workspace display name. | Optional |
| description | The new workspace description. | Optional |
| icon | The new workspace icon identifier. | Optional |
| defaults | Default settings for the workspace as a JSON object of key/value pairs (e.g. {"config_id": "9ff8ead5-2438-xxxx"}). | Optional |
| usage_limits | Usage-limit definitions as a JSON array. | Optional |
| rate_limits | Rate-limit definitions as a JSON array. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-workspaces-archive

***
Archives (soft-deletes) an AI Gateway workspace by UUID or slug (admin plane). This is a soft delete: a subsequent workspaces-get returns 404 (errorCode AB08), but the row is still listed by prisma-airs-aigateway-workspaces-list status=archived.

#### Base Command

`prisma-airs-aigateway-workspaces-archive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_ref | The workspace UUID or slug to archive. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-workspaces-provision

***
Provisions a workspace end to end the way the SCM UI does (admin + IAM planes): creates the IAM scope, creates the workspace bound to that scope_name, then binds the scope to the new workspace slug. On a partial failure the scope create is rolled back (best effort) and the error reports how to recover. Use this instead of orchestrating scopes-create + workspaces-create + scopes-bind yourself.

#### Base Command

`prisma-airs-aigateway-workspaces-provision`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The workspace display name. | Required |
| scope_name | The IAM scope name to use. When omitted, one is generated as ws_&lt;name&gt;_&lt;suffix&gt;. Required when existing_scope is true. | Optional |
| existing_scope | Whether to bind to a scope that already exists instead of creating one. When true, scope_name is required. Possible values are: true, false. Default is false. | Optional |
| description | The workspace (and, when created, the IAM scope) description. | Optional |
| icon | The workspace icon identifier. | Optional |
| defaults | Default settings for the workspace as a JSON object (e.g. {"config_id": "...", "allow_config_override": true, "metadata": {}}). | Optional |
| users | Comma-separated list of user IDs to seed as workspace members. | Optional |
| usage_limits | Usage-limit definitions as a JSON array. | Optional |
| rate_limits | Rate-limit definitions as a JSON array. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayWorkspaceProvision.workspace_slug | String | The provisioned workspace slug. |
| PrismaAIRs.AIGatewayWorkspaceProvision.workspace_id | String | The provisioned workspace ID \(UUID\). |
| PrismaAIRs.AIGatewayWorkspaceProvision.scope_name | String | The IAM scope name bound to the workspace. |
| PrismaAIRs.AIGatewayWorkspaceProvision.scope_created | Boolean | Whether a new IAM scope was created \(false when an existing scope was reused\). |

### prisma-airs-aigateway-scopes-list

***
Lists every SCM IAM scope in the tenant. Scopes are the objects a workspace's scope_name points at; unbound scopes have no resources.

#### Base Command

`prisma-airs-aigateway-scopes-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayScope.name | String | The scope name \(the path key, e.g. ws_production_bx7qw0\). |
| PrismaAIRs.AIGatewayScope.description | String | The scope description. |
| PrismaAIRs.AIGatewayScope.tsg_id | String | The Tenant Services Group ID the scope belongs to. |
| PrismaAIRs.AIGatewayScope.id | String | The scope ID \(name:tsg_id\). Display only; the path key is the name. |
| PrismaAIRs.AIGatewayScope.resources | Unknown | The resources bound to the scope. |

#### Command example

```
!prisma-airs-aigateway-scopes-list
```

#### Context Example

```json
[
    {
        "description": "This scope corresponds to the default workspace for this tenant.",
        "id": "main_airs_workspace_1082076864:1082076864",
        "name": "main_airs_workspace_1082076864",
        "resources": [
            {
                "metadata": [],
                "resource_id": "ws-main-a-761b65",
                "resource_type": "workspace"
            }
        ],
        "tsg_id": "1082076864"
    },
    {
        "description": "",
        "id": "ws_aws_gateway_mwxlau:1082076864",
        "name": "ws_aws_gateway_mwxlau",
        "resources": [
            {
                "metadata": [],
                "resource_id": "ws-aws-ga-2a753e",
                "resource_type": "workspace"
            }
        ],
        "tsg_id": "1082076864"
    },
    {
        "description": "",
        "id": "ws_azure_gateway_bhw5tg:1082076864",
        "name": "ws_azure_gateway_bhw5tg",
        "resources": [
            {
                "metadata": [],
                "resource_id": "ws-azure-f901bd",
                "resource_type": "workspace"
            }
        ],
        "tsg_id": "1082076864"
    }
]
```

#### Human Readable Output

>### AI Gateway IAM Scopes
>
>|Name|Description|Tsg Id|Id|
>|---|---|---|---|
>| main_airs_workspace_1082076864 | This scope corresponds to the default workspace for this tenant. | 1082076864 | main_airs_workspace_1082076864:1082076864 |
>| ws_aws_gateway_mwxlau |  | 1082076864 | ws_aws_gateway_mwxlau:1082076864 |
>| ws_azure_gateway_bhw5tg |  | 1082076864 | ws_azure_gateway_bhw5tg:1082076864 |
>| ws_azure_gateway_x5oiz0 |  | 1082076864 | ws_azure_gateway_x5oiz0:1082076864 |
>| ws_dev_team_o4e127 |  | 1082076864 | ws_dev_team_o4e127:1082076864 |
>| ws_ehomelab_a0p949 |  | 1082076864 | ws_ehomelab_a0p949:1082076864 |
>| ... | _(8 rows total; truncated for brevity)_ |

### prisma-airs-aigateway-scopes-get

***
Gets one SCM IAM scope by name.

#### Base Command

`prisma-airs-aigateway-scopes-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The scope name (e.g. ws_production_bx7qw0). This is the path key, not the id (name:tsg_id). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayScope.name | String | The scope name. |
| PrismaAIRs.AIGatewayScope.description | String | The scope description. |
| PrismaAIRs.AIGatewayScope.tsg_id | String | The Tenant Services Group ID the scope belongs to. |
| PrismaAIRs.AIGatewayScope.id | String | The scope ID \(name:tsg_id\). |
| PrismaAIRs.AIGatewayScope.resources | Unknown | The resources bound to the scope. |

### prisma-airs-aigateway-scopes-create

***
Creates an unbound SCM IAM scope. This is step 1 of workspace provisioning; a workspace's scope_name must name a scope that already exists.

#### Base Command

`prisma-airs-aigateway-scopes-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The scope name. Must be unique in the tenant, e.g. ws_production_bx7qw0. | Required |
| description | The scope description. | Optional |
| resources | A JSON array of resources to bind at creation time. For example, '[{"resource_type":"workspace","resource_id":"ws-produc-985697"}]'. Usually omitted; bind later with prisma-airs-aigateway-scopes-bind. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayScope.name | String | The created scope name. |
| PrismaAIRs.AIGatewayScope.id | String | The created scope ID \(name:tsg_id\). |

### prisma-airs-aigateway-scopes-update

***
Updates an SCM IAM scope. This is a full replacement (PUT), not a patch - omitting resources unbinds everything. To add a workspace without dropping existing bindings, use prisma-airs-aigateway-scopes-bind.

#### Base Command

`prisma-airs-aigateway-scopes-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The scope name (path key). | Required |
| description | The new scope description. | Optional |
| resources | A JSON array of resources that fully replaces the scope's current resources. For example, '[{"resource_type":"workspace","resource_id":"ws-produc-985697"}]'. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayScope.name | String | The scope name. |
| PrismaAIRs.AIGatewayScope.id | String | The scope ID \(name:tsg_id\). |

### prisma-airs-aigateway-scopes-bind

***
Binds a workspace to an existing SCM IAM scope. This is step 3 of workspace provisioning; existing bindings are preserved. SCM binds by workspace slug, not UUID.

#### Base Command

`prisma-airs-aigateway-scopes-bind`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The scope name to bind the workspace to. | Required |
| workspace_slug | The workspace slug (e.g. ws-produc-985697) to bind. Not the UUID - SCM binds by slug. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayScope.name | String | The scope name. |
| PrismaAIRs.AIGatewayScope.resources | Unknown | The resources now bound to the scope. |

### prisma-airs-aigateway-scopes-delete

***
Deletes an SCM IAM scope by name. Note that scope deletion is not verified upstream; the API may decline with a 404 or 405.

#### Base Command

`prisma-airs-aigateway-scopes-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The scope name to delete. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-integrations-catalog

***
Lists the static provider catalog on the AI Gateway admin plane. Maps a provider slug (for example open-ai or x-ai) to the ai_provider_id UUID required when binding an integration or creating a provider.

#### Base Command

`prisma-airs-aigateway-integrations-catalog`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayProviderCatalog.id | String | The upstream provider \(ai_provider_id\) UUID. |
| PrismaAIRs.AIGatewayProviderCatalog.slug | String | The provider catalog slug \(for example open-ai\). |
| PrismaAIRs.AIGatewayProviderCatalog.name | String | The provider display name. |

#### Command example

```
!prisma-airs-aigateway-integrations-catalog
```

#### Context Example

```json
[
    {
        "created_at": "2026-07-16T03:41:32.000Z",
        "description": "Cohere offers models for text generation & more.",
        "id": "05dee6cc-31ce-11ee-b93b-0e06f1aa7f7c",
        "last_updated_at": "2026-07-16T03:41:32.000Z",
        "name": "cohere",
        "slug": "cohere",
        "status": "active"
    },
    {
        "created_at": "2026-07-16T03:41:32.000Z",
        "description": "Anthropic offers models for text generation like Claude & more.",
        "id": "05def66c-31ce-11ee-b93b-0e06f1aa7f7c",
        "last_updated_at": "2026-07-16T03:41:32.000Z",
        "name": "anthropic",
        "slug": "anthropic",
        "status": "active"
    },
    {
        "created_at": "2026-07-16T03:41:32.000Z",
        "description": "Azure OpenAI provides SOTA models deployed on MS Azure.",
        "id": "05defd2e-31ce-11ee-b93b-0e06f1aa7f7c",
        "last_updated_at": "2026-07-16T03:41:32.000Z",
        "name": "azure-openai",
        "slug": "azure-openai",
        "status": "active"
    }
]
```

#### Human Readable Output

>### AI Gateway Provider Catalog
>
>|Id|Slug|Name|
>|---|---|---|
>| 05dee6cc-31ce-11ee-b93b-0e06f1aa7f7c | cohere | cohere |
>| 05def66c-31ce-11ee-b93b-0e06f1aa7f7c | anthropic | anthropic |
>| 05defd2e-31ce-11ee-b93b-0e06f1aa7f7c | azure-openai | azure-openai |
>| 05df033c-31ce-11ee-b93b-0e06f1aa7f7c | hugging-face | hugging-face |
>| 0954e0c5-d898-11ee-9c04-1235d6b0b075 | groq | groq |
>| 0a9635da-bd84-11ef-9c04-1235d6b0b075 | x-ai | x-ai |
>| ... | _(77 rows total; truncated for brevity)_ |

### prisma-airs-aigateway-integrations-list

***
Lists credential integrations (upstream provider bindings) for the tenant on the AI Gateway admin plane. Distinct from mcp-integrations.

#### Base Command

`prisma-airs-aigateway-integrations-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayIntegration.id | String | The integration ID. |
| PrismaAIRs.AIGatewayIntegration.name | String | The integration name. |
| PrismaAIRs.AIGatewayIntegration.slug | String | The integration slug. |
| PrismaAIRs.AIGatewayIntegration.status | String | The integration status. |
| PrismaAIRs.AIGatewayIntegration.ai_provider_id | String | The bound upstream provider \(ai_provider_id\) UUID. |

#### Command example

```
!prisma-airs-aigateway-integrations-list
```

#### Context Example

```json
[
    {
        "ai_provider_id": "76cf26c8-03cf-11ef-9c04-1235d6b0b075",
        "created_at": "2026-09-21T13:59:40.000Z",
        "description": "",
        "id": "10ec807b-fc95-47d3-bf88-23a29777da89",
        "last_updated_at": "2026-09-21T14:24:49.000Z",
        "name": "gke-vertex-wif",
        "object": "integration",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "gke-vertex-wif",
        "status": "active",
        "tags": null,
        "type": "organisation",
        "workspace_id": null,
        "workspaces_count": 1
    },
    {
        "ai_provider_id": "2a4c9504-d350-11ee-9c04-1235d6b0b075",
        "created_at": "2026-08-31T17:09:09.000Z",
        "description": null,
        "id": "469f8505-efb9-4d35-906b-9ec231ba295c",
        "last_updated_at": "2026-09-08T16:00:35.000Z",
        "name": "aws-bedrock-irsa",
        "object": "integration",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "aws-bedrock-irsa",
        "status": "active",
        "tags": null,
        "type": "organisation",
        "workspace_id": null,
        "workspaces_count": 1
    },
    {
        "ai_provider_id": "de7d7d50-31cd-11ee-b93b-0e06f1aa7f7c",
        "created_at": "2026-07-17T01:30:22.000Z",
        "description": null,
        "id": "40a4beb4-5f9f-4ee0-af53-8d22c9f2fca9",
        "last_updated_at": "2026-09-21T14:00:47.000Z",
        "name": "gke-ollama",
        "object": "integration",
        "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
        "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "slug": "gke-ollama",
        "status": "active",
        "tags": null,
        "type": "organisation",
        "workspace_id": null,
        "workspaces_count": 1
    }
]
```

#### Human Readable Output

>### AI Gateway Integrations
>
>|Id|Name|Slug|Status|Ai Provider Id|
>|---|---|---|---|---|
>| 10ec807b-fc95-47d3-bf88-23a29777da89 | gke-vertex-wif | gke-vertex-wif | active | 76cf26c8-03cf-11ef-9c04-1235d6b0b075 |
>| 469f8505-efb9-4d35-906b-9ec231ba295c | aws-bedrock-irsa | aws-bedrock-irsa | active | 2a4c9504-d350-11ee-9c04-1235d6b0b075 |
>| 40a4beb4-5f9f-4ee0-af53-8d22c9f2fca9 | gke-ollama | gke-ollama | active | de7d7d50-31cd-11ee-b93b-0e06f1aa7f7c |
>| 410280a9-5650-44a7-ab19-875f5ae74ca3 | vertex | vertex | active | 76cf26c8-03cf-11ef-9c04-1235d6b0b075 |
>| 56728ea3-ac8f-4fdb-a302-b55eaf7a14ac | openai | openai | active | de7d7d50-31cd-11ee-b93b-0e06f1aa7f7c |
>| 73957494-c3ec-4507-9258-49dfb1519e94 | ce2-az-foundry | ce2-az-foundry | active | f0529938-67b0-11ef-9c04-1235d6b0b075 |
>| ... | _(7 rows total; truncated for brevity)_ |

### prisma-airs-aigateway-integrations-get

***
Gets one credential integration by UUID on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-integrations-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayIntegration.id | String | The integration ID. |
| PrismaAIRs.AIGatewayIntegration.name | String | The integration name. |
| PrismaAIRs.AIGatewayIntegration.slug | String | The integration slug. |
| PrismaAIRs.AIGatewayIntegration.status | String | The integration status. |

### prisma-airs-aigateway-integrations-models-list

***
Lists the models bound to a credential integration on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-integrations-models-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayIntegrationModel.slug | String | The model slug. |
| PrismaAIRs.AIGatewayIntegrationModel.name | String | The model display name. |

### prisma-airs-aigateway-integrations-workspaces-list

***
Lists the workspaces a credential integration is exposed to, plus global-access settings, on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-integrations-workspaces-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayIntegrationWorkspace.id | String | The bound workspace ID. |

### prisma-airs-aigateway-integrations-create

***
Creates a credential integration (upstream provider binding) on the AI Gateway admin plane. Accepts secret credential material via the key/secret_mappings arguments.

#### Base Command

`prisma-airs-aigateway-integrations-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ai_provider_id | The upstream provider UUID (from integrations-catalog). | Required |
| name | The integration display name. | Required |
| slug | The integration slug. | Required |
| organisation_id | The numeric organisation ID. Defaults to the configured tenant TSG ID when omitted. | Optional |
| workspace_id | Optional upstream workspace scope. | Optional |
| description | A free-form description. | Optional |
| configurations | Provider-specific configuration object (JSON). | Optional |
| key | The upstream API key / credential (secret). | Optional |
| secret_mappings | Secret mapping entries (JSON array). | Optional |
| create_default_provider | Whether to create a default provider binding for this integration. Possible values are: true, false. | Optional |
| default_provider_slug | Slug for the default provider when create_default_provider is set. | Optional |
| pricing_adjustments | Pricing adjustment settings (JSON). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayIntegration.id | String | The created integration ID. |
| PrismaAIRs.AIGatewayIntegration.slug | String | The created integration slug. |

### prisma-airs-aigateway-integrations-update

***
Updates a credential integration on the AI Gateway admin plane. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-integrations-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |
| name | The integration display name. | Optional |
| description | A free-form description. | Optional |
| configurations | Provider-specific configuration object (JSON). | Optional |
| key | The upstream API key / credential (secret). | Optional |
| secret_mappings | Secret mapping entries (JSON array). | Optional |
| pricing_adjustments | Pricing adjustment settings (JSON). | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-integrations-delete

***
Deletes a credential integration on the AI Gateway admin plane. The organisation_id query param is required and defaults to the configured tenant TSG ID.

#### Base Command

`prisma-airs-aigateway-integrations-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |
| organisation_id | The numeric organisation ID. Defaults to the configured tenant TSG ID when omitted. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-integrations-models-set

***
Bulk-sets the models bound to a credential integration on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-integrations-models-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |
| models | The model entries to set (JSON array of objects, at least one). | Required |
| allow_all_models | Whether to allow all models for this integration. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-integrations-models-delete

***
Removes specific model slugs from a credential integration on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-integrations-models-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |
| slugs | Comma-separated list of model slugs to remove. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-integrations-workspaces-set

***
Bulk-sets which workspaces a credential integration is exposed to, on the AI Gateway admin plane. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-integrations-workspaces-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The integration UUID. | Required |
| workspaces | Workspace binding entries (JSON array). | Optional |
| global_workspace_access | Global workspace access settings object (JSON) with enabled/rate_limits/usage_limits. | Optional |
| override_existing_workspace_access | Whether to override existing workspace access. Possible values are: true, false. | Optional |
| create_default_provider | Whether to create a default provider binding. Possible values are: true, false. | Optional |
| default_provider_slug | Slug for the default provider when create_default_provider is set. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-providers-list

***
Lists provider bindings in a workspace on the AI Gateway control plane. Raw credential material is stripped from the output.

#### Base Command

`prisma-airs-aigateway-providers-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID (UUID) to list providers for. | Required |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayProvider.id | String | The provider ID. |
| PrismaAIRs.AIGatewayProvider.name | String | The provider name. |
| PrismaAIRs.AIGatewayProvider.slug | String | The provider slug. |
| PrismaAIRs.AIGatewayProvider.status | String | The provider status. |
| PrismaAIRs.AIGatewayProvider.integration_id | String | The credential integration this provider is bound to. |

#### Command example

```
!prisma-airs-aigateway-providers-list workspace_id=8f51ae59-921e-4256-acda-6e312dd222d7
```

#### Context Example

```json
{
    "ai_provider_id": "2a4c9504-d350-11ee-9c04-1235d6b0b075",
    "ai_provider_slug": "bedrock",
    "created_at": "2026-08-31T17:09:11.000Z",
    "expires_at": null,
    "id": "af676a04-6cea-43e9-989c-be55fd56f0c4",
    "integration_id": "469f8505-efb9-4d35-906b-9ec231ba295c",
    "integration_slug": "aws-bedrock-irsa",
    "last_reset_at": null,
    "masked_api_key": "",
    "model_config": null,
    "name": "aws-bedrock-irsa",
    "note": "Created automatically on integration access grant",
    "object": "provider",
    "organisation_id": "7f194769-8f30-4b84-95ad-e277466e3427",
    "owner_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
    "rate_limits": null,
    "reset_usage": null,
    "slug": "aws-bedrock-irsa",
    "status": "active",
    "tags": null,
    "usage_limits": null,
    "workspace_id": "8f51ae59-921e-4256-acda-6e312dd222d7",
    "workspace_name": "aws_gateway"
}
```

#### Human Readable Output

>### AI Gateway Providers
>
>|Id|Name|Slug|Status|Integration Id|
>|---|---|---|---|---|
>| af676a04-6cea-43e9-989c-be55fd56f0c4 | aws-bedrock-irsa | aws-bedrock-irsa | active | 469f8505-efb9-4d35-906b-9ec231ba295c |

### prisma-airs-aigateway-providers-get

***
Gets one provider binding by UUID on the AI Gateway control plane. The raw API key is stripped from the output; the masked_api_key value is retained.

#### Base Command

`prisma-airs-aigateway-providers-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider_id | The provider UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayProvider.id | String | The provider ID. |
| PrismaAIRs.AIGatewayProvider.name | String | The provider name. |
| PrismaAIRs.AIGatewayProvider.slug | String | The provider slug. |
| PrismaAIRs.AIGatewayProvider.status | String | The provider status. |
| PrismaAIRs.AIGatewayProvider.masked_api_key | String | The masked upstream API key. |

### prisma-airs-aigateway-providers-create

***
Creates a provider binding inside a workspace on the AI Gateway control plane. Requires workspace_id, ai_provider_id (from integrations-catalog) and integration_id (from integrations-list).

#### Base Command

`prisma-airs-aigateway-providers-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace UUID to create the provider in. | Required |
| ai_provider_id | The upstream provider UUID (from integrations-catalog). | Required |
| integration_id | The credential integration UUID (from integrations-list). | Required |
| name | The provider display name. | Required |
| slug | The provider slug. | Required |
| note | A free-form note. | Optional |
| usage_limits | Usage limit settings (JSON). | Optional |
| rate_limits | Rate limit settings (JSON). | Optional |
| expires_at | Expiry timestamp (ISO 8601). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayProvider.id | String | The created provider ID. |
| PrismaAIRs.AIGatewayProvider.slug | String | The created provider slug. |

### prisma-airs-aigateway-providers-update

***
Updates a provider binding on the AI Gateway control plane. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-providers-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider_id | The provider UUID. | Required |
| name | The provider display name. | Optional |
| note | A free-form note. | Optional |
| usage_limits | Usage limit settings (JSON). | Optional |
| rate_limits | Rate limit settings (JSON). | Optional |
| expires_at | Expiry timestamp (ISO 8601). | Optional |
| reset_usage | Whether to reset the accumulated usage counters. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-providers-delete

***
Deletes a provider binding on the AI Gateway control plane. This is a hard delete - the provider is removed entirely (not archived).

#### Base Command

`prisma-airs-aigateway-providers-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider_id | The provider UUID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-plugins-list

***
Lists organisation-level plugin bindings on the AI Gateway admin plane. Credential values are masked in the output.

#### Base Command

`prisma-airs-aigateway-plugins-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayPlugin.id | String | The plugin binding ID. |
| PrismaAIRs.AIGatewayPlugin.integration_id | String | The credential integration the plugin is bound to. |
| PrismaAIRs.AIGatewayPlugin.integration_slug | String | The credential integration slug. |
| PrismaAIRs.AIGatewayPlugin.plugin_provider_slug | String | The plugin provider slug. |
| PrismaAIRs.AIGatewayPlugin.status | String | The plugin binding status. |

### prisma-airs-aigateway-plugins-create

***
Binds a plugin to the organisation on the AI Gateway admin plane. Takes live secret credential material, which is never echoed back in the output.

#### Base Command

`prisma-airs-aigateway-plugins-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The credential integration UUID to bind the plugin to. | Required |
| credentials | A JSON object of provider-specific credential name/value pairs. Example: {"AIRS_API_KEY": "&lt;secret&gt;"}. | Required |
| organisation_id | The numeric organisation ID. Defaults to the configured tenant TSG ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayPlugin.id | String | The created plugin binding ID. |
| PrismaAIRs.AIGatewayPlugin.version_id | String | The created plugin binding version ID. |

### prisma-airs-aigateway-api-keys-service-list

***
Lists service API keys in a workspace on the AI Gateway data plane. The key secret is never returned by list.

#### Base Command

`prisma-airs-aigateway-api-keys-service-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID (UUID) to list service keys for. | Required |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKey.id | String | The API key ID. |
| PrismaAIRs.AIGatewayApiKey.name | String | The API key name. |
| PrismaAIRs.AIGatewayApiKey.type | String | The API key type. |
| PrismaAIRs.AIGatewayApiKey.status | String | The API key status. |
| PrismaAIRs.AIGatewayApiKey.workspace_id | String | The workspace ID \(UUID\) the API key belongs to. |
| PrismaAIRs.AIGatewayApiKey.workspace_name | String | The human-readable workspace name the API key belongs to, resolved from the workspace ID. |

### prisma-airs-aigateway-api-keys-user-list

***
Lists user API keys in a workspace on the AI Gateway data plane. The key secret is never returned by list.

#### Base Command

`prisma-airs-aigateway-api-keys-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID (UUID) to list user keys for. | Required |
| page_size | The number of results to return per page. Default is 50. | Optional |
| current_page | The page number to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKey.id | String | The API key ID. |
| PrismaAIRs.AIGatewayApiKey.name | String | The API key name. |
| PrismaAIRs.AIGatewayApiKey.type | String | The API key type. |
| PrismaAIRs.AIGatewayApiKey.status | String | The API key status. |
| PrismaAIRs.AIGatewayApiKey.workspace_id | String | The workspace ID \(UUID\) the API key belongs to. |
| PrismaAIRs.AIGatewayApiKey.workspace_name | String | The human-readable workspace name the API key belongs to, resolved from the workspace ID. |

### prisma-airs-aigateway-api-keys-service-get

***
Gets one service API key by UUID on the AI Gateway data plane. The key secret is never returned by get.

#### Base Command

`prisma-airs-aigateway-api-keys-service-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKey.id | String | The API key ID. |
| PrismaAIRs.AIGatewayApiKey.name | String | The API key name. |
| PrismaAIRs.AIGatewayApiKey.type | String | The API key type. |
| PrismaAIRs.AIGatewayApiKey.status | String | The API key status. |

### prisma-airs-aigateway-api-keys-user-get

***
Gets one user API key by UUID on the AI Gateway data plane. The key secret is never returned by get.

#### Base Command

`prisma-airs-aigateway-api-keys-user-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKey.id | String | The API key ID. |
| PrismaAIRs.AIGatewayApiKey.name | String | The API key name. |
| PrismaAIRs.AIGatewayApiKey.type | String | The API key type. |
| PrismaAIRs.AIGatewayApiKey.status | String | The API key status. |

### prisma-airs-aigateway-api-keys-service-create

***
Creates a service API key in a workspace on the AI Gateway data plane. The one-time secret key is returned ONLY in this response and cannot be retrieved afterwards - capture it immediately.

#### Base Command

`prisma-airs-aigateway-api-keys-service-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The API key display name. | Required |
| scopes | A comma-separated list of at least one scope (for example: completions.write,logs.write). | Required |
| workspace_id | The workspace UUID to create the key in. | Required |
| type | The API key type. Default is workspace. | Optional |
| organisation_id | The numeric organisation ID. Defaults to the configured tenant TSG ID. | Optional |
| description | A free-form description. | Optional |
| alert_emails | A comma-separated list of alert notification email addresses. | Optional |
| expires_at | Expiry timestamp (ISO 8601). | Optional |
| rate_limits | Rate limit settings (JSON array). | Optional |
| usage_limits | Usage limit settings (JSON object). | Optional |
| defaults | Default settings (JSON object). | Optional |
| rotation_policy | Rotation policy settings (JSON object). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKey.id | String | The created API key ID. |
| PrismaAIRs.AIGatewayApiKey.key | String | The one-time secret key value. Shown only once - capture it immediately. |
| PrismaAIRs.AIGatewayApiKey.version_id | String | The created API key version ID. |

### prisma-airs-aigateway-api-keys-user-create

***
Creates a user API key in a workspace on the AI Gateway data plane. Requires user_id. The one-time secret key is returned ONLY in this response and cannot be retrieved afterwards - capture it immediately.

#### Base Command

`prisma-airs-aigateway-api-keys-user-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The API key display name. | Required |
| scopes | A comma-separated list of at least one scope (for example: completions.write). | Required |
| workspace_id | The workspace UUID to create the key in. | Required |
| user_id | The user UUID the key belongs to. | Required |
| type | The API key type. Default is workspace. | Optional |
| organisation_id | The numeric organisation ID. Defaults to the configured tenant TSG ID. | Optional |
| description | A free-form description. | Optional |
| alert_emails | A comma-separated list of alert notification email addresses. | Optional |
| expires_at | Expiry timestamp (ISO 8601). | Optional |
| rate_limits | Rate limit settings (JSON array). | Optional |
| usage_limits | Usage limit settings (JSON object). | Optional |
| defaults | Default settings (JSON object). | Optional |
| rotation_policy | Rotation policy settings (JSON object). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKey.id | String | The created API key ID. |
| PrismaAIRs.AIGatewayApiKey.key | String | The one-time secret key value. Shown only once - capture it immediately. |
| PrismaAIRs.AIGatewayApiKey.version_id | String | The created API key version ID. |

### prisma-airs-aigateway-api-keys-service-update

***
Updates a service API key on the AI Gateway data plane. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-api-keys-service-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |
| name | The API key display name. | Optional |
| description | A free-form description. | Optional |
| scopes | A comma-separated list of at least one scope. | Optional |
| alert_emails | A comma-separated list of alert notification email addresses. | Optional |
| expires_at | Expiry timestamp (ISO 8601). | Optional |
| rate_limits | Rate limit settings (JSON array). | Optional |
| usage_limits | Usage limit settings (JSON object). | Optional |
| defaults | Default settings (JSON object). | Optional |
| rotation_policy | Rotation policy settings (JSON object). | Optional |
| reset_usage | Whether to reset the accumulated usage counters. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-api-keys-user-update

***
Updates a user API key on the AI Gateway data plane. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-api-keys-user-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |
| name | The API key display name. | Optional |
| description | A free-form description. | Optional |
| scopes | A comma-separated list of at least one scope. | Optional |
| alert_emails | A comma-separated list of alert notification email addresses. | Optional |
| expires_at | Expiry timestamp (ISO 8601). | Optional |
| rate_limits | Rate limit settings (JSON array). | Optional |
| usage_limits | Usage limit settings (JSON object). | Optional |
| defaults | Default settings (JSON object). | Optional |
| rotation_policy | Rotation policy settings (JSON object). | Optional |
| reset_usage | Whether to reset the accumulated usage counters. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-api-keys-service-delete

***
Permanently deletes a service API key on the AI Gateway data plane. This is a hard delete.

#### Base Command

`prisma-airs-aigateway-api-keys-service-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-api-keys-user-delete

***
Permanently deletes a user API key on the AI Gateway data plane. This is a hard delete.

#### Base Command

`prisma-airs-aigateway-api-keys-user-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-api-keys-service-rotate

***
Rotates a service API key on the AI Gateway data plane. The new one-time secret key is returned ONLY in this response - capture it immediately.

#### Base Command

`prisma-airs-aigateway-api-keys-service-rotate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |
| key_transition_period_ms | The grace period (in milliseconds, minimum 1800000) during which the old key remains valid. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKeyRotation.id | String | The rotated API key ID. |
| PrismaAIRs.AIGatewayApiKeyRotation.key | String | The new one-time secret key value. Shown only once - capture it immediately. |
| PrismaAIRs.AIGatewayApiKeyRotation.key_transition_expires_at | String | When the previous key stops being accepted. |

### prisma-airs-aigateway-api-keys-user-rotate

***
Rotates a user API key on the AI Gateway data plane. The new one-time secret key is returned ONLY in this response - capture it immediately.

#### Base Command

`prisma-airs-aigateway-api-keys-user-rotate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_id | The API key UUID. | Required |
| key_transition_period_ms | The grace period (in milliseconds, minimum 1800000) during which the old key remains valid. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayApiKeyRotation.id | String | The rotated API key ID. |
| PrismaAIRs.AIGatewayApiKeyRotation.key | String | The new one-time secret key value. Shown only once - capture it immediately. |
| PrismaAIRs.AIGatewayApiKeyRotation.key_transition_expires_at | String | When the previous key stops being accepted. |

### prisma-airs-aigateway-organisations-info-get

***
Gets one organisation's capabilities and settings on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-organisations-info-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organisation_id | The numeric organisation (TSG) ID. Defaults to the configured tenant TSG ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrganisationInfo.id | String | The organisation ID. |
| PrismaAIRs.AIGatewayOrganisationInfo.name | String | The organisation name. |
| PrismaAIRs.AIGatewayOrganisationInfo.subscription.type | String | The subscription type. |
| PrismaAIRs.AIGatewayOrganisationInfo.subscription.name | String | The subscription name. |

### prisma-airs-aigateway-organisations-self-get

***
Gets the calling organisation's record on the AI Gateway admin plane.

#### Base Command

`prisma-airs-aigateway-organisations-self-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrganisation.id | String | The organisation ID. |
| PrismaAIRs.AIGatewayOrganisation.name | String | The organisation name. |

### prisma-airs-aigateway-organisations-self-update

***
Updates the calling organisation's settings on the AI Gateway admin plane. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-organisations-self-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The organisation display name. | Optional |
| settings | Additional organisation settings to update (JSON object). Merged into the update body. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrganisation.id | String | The organisation ID. |

### prisma-airs-aigateway-organisations-auth-settings-get

***
Gets an organisation's auth settings on the AI Gateway admin plane. The scim_token and any client_secret values are redacted from the output.

#### Base Command

`prisma-airs-aigateway-organisations-auth-settings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organisation_id | The numeric organisation (TSG) ID. Defaults to the configured tenant TSG ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayOrganisationAuthSettings.domains | Unknown | The configured SSO/SCIM domains. |
| PrismaAIRs.AIGatewayOrganisationAuthSettings.scim_token | String | The SCIM token \(always redacted in the output\). |

### prisma-airs-aigateway-organisations-auth-settings-update

***
Updates an organisation's auth settings on the AI Gateway admin plane. Takes a secret scim_token as input; the response is redacted. Provide at least one field.

#### Base Command

`prisma-airs-aigateway-organisations-auth-settings-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organisation_id | The numeric organisation (TSG) ID. Defaults to the configured tenant TSG ID. | Optional |
| auth_settings | Auth settings to update (JSON object). | Optional |
| domains | A comma-separated list of SSO/SCIM domains. | Optional |
| scim_token | The SCIM token (secret). Never echoed back in the output. | Optional |

#### Context Output

There is no context output for this command.

### prisma-airs-aigateway-model-pricing-get

***
Reads one provider/model entry from the public model-pricing catalog. Note: this is NOT an SCM gateway call - it is an unauthenticated read against a public catalog host and carries no OAuth2/tenant credentials. Prices are upstream catalog data, not effective tenant billing.

#### Base Command

`prisma-airs-aigateway-model-pricing-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| provider | The provider slug (for example openai). | Required |
| model | The model identifier (for example gpt-4o or text-embedding-3-small). | Required |
| endpoint | The public pricing catalog base URL (HTTPS; HTTP allowed only on loopback). Default is https://api.portkey.ai. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.AIGatewayModelPricing.provider | String | The provider slug the pricing was requested for. |
| PrismaAIRs.AIGatewayModelPricing.model | String | The model the pricing was requested for. |
| PrismaAIRs.AIGatewayModelPricing.currency | String | The pricing currency \(USD\). |
| PrismaAIRs.AIGatewayModelPricing.pay_as_you_go | Unknown | The pay-as-you-go rate configuration. |
| PrismaAIRs.AIGatewayModelPricing.calculate | Unknown | The unevaluated price calculation expressions. |

#### Command example

```
!prisma-airs-aigateway-model-pricing-get provider=openai model=gpt-4o
```

#### Context Example

```json
{
    "batch_config": {
        "request_token": {
            "price": 0.000125
        },
        "response_token": {
            "price": 0.0005
        }
    },
    "calculate": {
        "request": {
            "operands": [
                {
                    "operands": [
                        {
                            "value": "input_tokens"
                        },
                        {
                            "value": "rates.request_token"
                        }
                    ],
                    "operation": "multiply"
                },
                {
                    "operands": [
                        {
                            "value": "cache_write_tokens"
                        },
                        {
                            "value": "rates.cache_write_input_token"
                        }
                    ],
                    "operation": "multiply"
                },
                {
                    "operands": [
                        {
                            "value": "cache_read_tokens"
                        },
                        {
                            "value": "rates.cache_read_input_token"
                        }
                    ],
                    "operation": "multiply"
                },
                {
                    "operands": [
                        {
                            "value": "audio_input_tokens"
                        },
                        {
                            "value": "rates.request_audio_token"
                        }
                    ],
                    "operation": "multiply"
                },
                {
                    "operands": [
                        {
                            "value": "cache_read_audio_tokens"
                        },
                        {
                            "value": "rates.cache_read_audio_input_token"
                        }
                    ],
                    "operation": "multiply"
                }
            ],
            "operation": "sum"
        },
        "response": {
            "operands": [
                {
                    "operands": [
                        {
                            "value": "output_tokens"
                        },
                        {
                            "value": "rates.response_token"
                        }
                    ],
                    "operation": "multiply"
                },
                {
                    "operands": [
                        {
                            "value": "audio_output_tokens"
                        },
                        {
                            "value": "rates.response_audio_token"
                        }
                    ],
                    "operation": "multiply"
                }
            ],
            "operation": "sum"
        }
    },
    "currency": "USD",
    "custom_pricing": {
        "regions": {
            "default": {
                "execution_modes": {
                    "batch": {
                        "pricing_config": {
                            "pay_as_you_go": {
                                "additional_units": {
                                    "file_search": {
                                        "price": 0.25
                                    },
                                    "web_search": {
                                        "price": 1
                                    }
                                },
                                "request_token": {
                                    "price": 0.000125
                                },
                                "response_token": {
                                    "price": 0.0005
                                }
                            }
                        }
                    },
                    "priority": {
                        "pricing_config": {
                            "pay_as_you_go": {
                                "additional_units": {
                                    "file_search": {
                                        "price": 0.25
                                    },
                                    "web_search": {
                                        "price": 1
                                    }
                                },
                                "cache_read_input_token": {
                                    "price": 0.0002125
                                },
                                "request_token": {
                                    "price": 0.000425
                                },
                                "response_token": {
                                    "price": 0.0017
                                }
                            }
                        }
                    },
                    "standard": {
                        "pricing_config": {
                            "pay_as_you_go": {
                                "additional_units": {
                                    "file_search": {
                                        "price": 0.25
                                    },
                                    "web_search": {
                                        "price": 1
                                    }
                                },
                                "cache_read_input_token": {
                                    "price": 0.000125
                                },
                                "request_token": {
                                    "price": 0.00025
                                },
                                "response_token": {
                                    "price": 0.001
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "model": "gpt-4o",
    "pay_as_you_go": {
        "additional_units": {
            "file_search": {
                "price": 0.25
            },
            "web_search": {
                "price": 1
            }
        },
        "cache_read_input_token": {
            "price": 0.000125
        },
        "cache_write_input_token": {
            "price": 0
        },
        "request_token": {
            "price": 0.00025
        },
        "response_token": {
            "price": 0.001
        }
    },
    "provider": "openai"
}
```

#### Human Readable Output

>### AI Gateway Model Pricing - openai/gpt-4o
>
>|Batch Config|Calculate|Currency|Custom Pricing|Model|Pay As You Go|Provider|
>|---|---|---|---|---|---|---|
>| request_token: {"price": 0.000125}<br>response_token: {"price": 0.0005} | request: {"operation": "sum", "operands": [{"operation": "multiply", "operands": [{"value": "input_tokens"}, {"value": "rates.request_token"}]}, {"operation": "multiply", "operands": [{"value": "cache_write_tokens"}, {"value": "rates.cache_write_input_token"}]}, {"operation": "multiply", "operands": [{"value": "cache_read_tokens"}, {"value": "rates.cache_read_input_token"}]}, {"operation": "multiply", "operands": [{"value": "audio_input_tokens"}, {"value": "rates.request_audio_token"}]}, {"operation": "multiply", "operands": [{"value": "cache_read_audio_tokens"}, {"value": "rates.cache_read_audio_input_token"}]}]}<br>response: {"operation": "sum", "operands": [{"operation": "multiply", "operands": [{"value": "output_tokens"}, {"value": "rates.response_token"}]}, {"operation": "multiply", "operands": [{"value": "audio_output_tokens"}, {"value": "rates.response_audio_token"}]}]} | USD | regions: {"default": {"execution_modes": {"standard": {"pricing_config": {"pay_as_you_go": {"request_token": {"price": 0.00025}, "cache_read_input_token": {"price": 0.000125}, "response_token": {"price": 0.001}, "additional_units": {"web_search": {"price": 1}, "file_search": {"price": 0.25}}}}}, "batch": {"pricing_config": {"pay_as_you_go": {"request_token": {"price": 0.000125}, "response_token": {"price": 0.0005}, "additional_units": {"web_search": {"price": 1}, "file_search": {"price": 0.25}}}}}, "priority": {"pricing_config": {"pay_as_you_go": {"request_token": {"price": 0.000425}, "cache_read_input_token": {"price": 0.0002125}, "response_token": {"price": 0.0017}, "additional_units": {"web_search": {"price": 1}, "file_search": {"price": 0.25}}}}}}}} | gpt-4o | request_token: {"price": 0.00025}<br>response_token: {"price": 0.001}<br>cache_write_input_token: {"price": 0}<br>cache_read_input_token: {"price": 0.000125}<br>additional_units: {"web_search": {"price": 1}, "file_search": {"price": 0.25}} | openai |
