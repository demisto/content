## NodeZero MCP Integration Description

This integration connects Cortex XSOAR to the NodeZero MCP server using OAuth 2.0 Dynamic Client Registration (DCR). The integration automatically registers itself as a public OAuth client with the NodeZero OAuth proxy — no pre-issued Client ID or Client Secret is required. Authentication flows through the NodeZero portal backed by AWS Cognito.

### Setup steps

1. Select the **MCP Server URL** for your region.
2. Run `!nodezero-mcp-generate-login-url` to register the client and get a login URL.
3. Open the URL and complete sign-in through the NodeZero portal. Copy the authorization code from the redirect page.
4. Paste the authorization code into the **Authorization Code** parameter and save the instance.
5. Run `!nodezero-mcp-auth-test` to verify the connection.

### Configuration parameters

**MCP Server URL** (required): Select the NodeZero MCP endpoint for your region:

- **US**: `https://mcp.horizon3ai.com`
- **EU**: `https://mcp.horizon3ai.eu`
- **AU**: `https://mcp.horizon3ai.au`

**Authorization Code**: The code returned after completing sign-in through the NodeZero portal. Obtained by running `!nodezero-mcp-generate-login-url` and completing the browser flow.
