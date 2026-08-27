## NodeZero MCP

Connects Cortex XSOAR to the [NodeZero](https://www.horizon3.ai/nodezero/) autonomous penetration testing platform MCP server, automatically discovering NodeZero's pentesting tools and exposing them as agentic system actions.

## Configure NodeZero MCP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **NodeZero MCP**.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
|-----------|-------------|----------|
| Server URL | Base URL of the NodeZero MCP server. Defaults to `https://mcp.horizon3ai.com`. | False |
| Scope | Space-separated OAuth scopes to request. Default: `read write offline_access`. | False |
| Redirect URI | URI the OAuth server redirects to after authorization. Default: `https://oproxy.demisto.ninja/authcode`. | False |
| Server Name | Override the display name used for the MCP server in tool names. | False |

4. Run `!nodezero-mcp-generate-login-url` and follow the returned instructions to authenticate.
5. Run `!nodezero-mcp-auth-test` to verify the connection.

## Commands

### nodezero-mcp-generate-login-url

Registers this integration as an OAuth client with the NodeZero OAuth proxy using Dynamic Client Registration, then returns a login URL. Open the URL and complete sign-in through the NodeZero portal to authorize the integration.

### nodezero-mcp-auth-test

Tests OAuth authentication and connectivity to the NodeZero MCP server.

### list-tools

Retrieves the list of tools available on the NodeZero MCP server.

### call-tool

Invokes a specific NodeZero tool by name with optional arguments.
