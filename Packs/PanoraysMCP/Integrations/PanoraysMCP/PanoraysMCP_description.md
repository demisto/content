## Panorays Axis MCP

This integration connects securely with the Panorays Axis Model Context Protocol (MCP) server, allowing you to access its tools in real time.

Select one of the following authentication types.

## Bearer

1. Log in to your Panorays platform.
2. Navigate to **Settings → Integrations → Public API**.
3. Click **Generate API Key** and assign it a role.
4. Copy the token into the **API Token** parameter.
5. Save the integration instance and click **Test**.

## OAuth 2.0 Authorization Code

### Prerequisites

Contact Panorays support at **support@panorays.com** to create an OAuth client for Cortex. Ask for a client with:

- The **Authorization Code** and **Refresh Token** grant types.
- The redirect URI `https://oproxy.demisto.ninja/authcode` (or your custom redirect URI).
- PKCE disabled.

Panorays support will provide a **Client ID** and **Client Secret**.

### Configuration

1. Enter the **Client ID** and **Client Secret** provided by Panorays support.
2. Save the integration instance.
3. Run the command `!panorays-mcp-generate-login-url` from the Playground and follow the instructions to authenticate.
4. Copy the generated **Authorization code** into the integration instance and save.
5. Run the command `!panorays-mcp-auth-test` from the Playground to verify connectivity.

## Support

For assistance, contact Panorays support at **support@panorays.com**.
