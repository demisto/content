## NodeZero MCP

Connects Cortex XSOAR to the NodeZero MCP server, automatically discovering NodeZero's pentesting tools and exposing them as agentic system actions.

## Configure NodeZero MCP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **NodeZero MCP**.
3. Click **Add instance** to create and configure a new integration instance.

| Parameter | Description | Required |
|-----------|-------------|----------|
| Server URL | Base URL of the NodeZero MCP server. | True |
| API Key | NodeZero API key for Bearer token authentication. | True |
| Custom headers | Additional headers to include with each request (`HeaderName: HeaderValue`, one per line). | False |
| Server Name | Override the server name used in tool names. | False |
| Trust any certificate (not secure) | Disable TLS verification. | False |

4. Click **Test** to validate connectivity.

## Commands

### list-tools

Retrieves the list of tools available on the NodeZero MCP server.

### call-tool

Invokes a specific NodeZero tool by name with optional arguments.

### nodezero-mcp-auth-test

Tests the API key and connectivity to the NodeZero MCP server.
