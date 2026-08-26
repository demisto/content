## NodeZero MCP Integration Description

This integration connects Cortex XSOAR to the NodeZero MCP server using OAuth 2.0 Dynamic Client Registration (DCR). The integration automatically registers itself as a public OAuth client with the NodeZero OAuth proxy — no pre-issued Client ID or Client Secret is required. Authentication flows through the NodeZero portal backed by AWS Cognito.

### Setup steps

1. Configure the **Server URL** (defaults to `https://mcp.horizon3ai.com` for US).
2. Run `!nodezero-mcp-generate-login-url` to register the client and get a login URL.
3. Open the URL and complete sign-in through the NodeZero portal.
4. Run `!nodezero-mcp-auth-test` to verify the connection.

### Configuration parameters

1. **Server URL**: The NodeZero MCP server URL. Defaults to `https://mcp.horizon3ai.com` (US). Change for other regions:
    - EU: `https://mcp.horizon3ai.eu`
    - AU: `https://mcp.horizon3ai.au`

2. **Scope**: OAuth scopes to request. Default: `read write offline_access`.

### Advanced parameters

* **Redirect URI**: URI the OAuth server redirects to after authorization. Default: `https://oproxy.demisto.ninja/authcode`.
* **Server Name**: Override the display name used for the MCP server in tool names.
