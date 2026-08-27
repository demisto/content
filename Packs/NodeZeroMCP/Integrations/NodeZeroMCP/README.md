## NodeZero MCP

Connects Cortex XSOAR to the [NodeZero](https://www.horizon3.ai/nodezero/) autonomous penetration testing platform MCP server, automatically discovering NodeZero's pentesting tools and exposing them as agentic system actions.

## Configure NodeZero MCP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **NodeZero MCP**.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
|-----------|-------------|----------|
| MCP Server URL | The NodeZero MCP server endpoint. Select the region that matches your NodeZero deployment: `https://mcp.horizon3ai.com` (US), `https://mcp.horizon3ai.eu` (EU), or `https://mcp.horizon3ai.au` (AU). | True |

4. Run `!nodezero-mcp-generate-login-url` and follow the returned instructions to authenticate.
5. Run `!nodezero-mcp-auth-test` to verify the connection.

## Commands

### nodezero-mcp-generate-login-url

Registers this integration with your NodeZero portal using Dynamic Client Registration, then returns a login URL. Open the URL and complete sign-in through the NodeZero portal to authorize the integration.

### nodezero-mcp-auth-test

Tests OAuth authentication and connectivity to the NodeZero MCP server.

### list-tools

Retrieves the list of tools available on the NodeZero MCP server.

### call-tool

Invokes a specific NodeZero tool by name with optional arguments.
