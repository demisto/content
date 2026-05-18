## ServiceNowMCP Integration

This integration connects securely with a ServiceNow Model Context Protocol (MCP) server, allowing you to access its tools in real time.

## Prerequisites

1. In your ServiceNow instance, navigate to **All > MCP Server Console** and ensure an MCP server is configured (or use the preconfigured **Quickstart Server**).
2. Create an **OAuth Inbound Integration** in **Machine Identity Console** with the **OAuth - Authorization code grant** type.
   - Set the **Redirect URL** to `https://oproxy.demisto.ninja/authcode` (or your custom redirect URI).
   - Set the **Token Format** to **JWT**.
   - Save the integration and note the **Client ID** and **Client Secret**.

## Configuration

1. Enter your **ServiceNow Instance** subdomain (e.g., `dev12345` for `https://dev12345.service-now.com`).
2. Enter the **MCP Server Name** (defaults to `sn_mcp_server_default` for the Quickstart Server).
3. Enter the **Client ID** and **Client Secret** from the OAuth Inbound Integration.
4. Save the integration instance.
5. Run the command `!servicenow-mcp-generate-login-url` from the Playground and follow the instructions to authenticate.
6. Copy the generated **Authorization code** into the integration instance and save.
7. Run the command `!servicenow-mcp-auth-test` from the Playground to verify connectivity.
