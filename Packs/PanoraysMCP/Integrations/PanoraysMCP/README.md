Use this integration to connect securely with the Panorays Axis Model Context Protocol (MCP) server and access its tools in real time.

## Prerequisites

Prepare the credentials for the authentication type you plan to use.

### Bearer

1. Log in to your Panorays platform.
2. Navigate to **Settings → Integrations → Public API**.
3. Click **Generate API Key** and assign it a role.
4. Copy the token. You will enter it in the **API Token** parameter.

### OAuth 2.0 Authorization Code

Contact Panorays support at **support@panorays.com** to create an OAuth client for Cortex. Ask for a client with:

- The **Authorization Code** and **Refresh Token** grant types.
- The redirect URI `https://oproxy.demisto.ninja/authcode` (or your custom redirect URI).
- PKCE disabled.

Panorays support will provide a **Client ID** and **Client Secret**.

## Configure Panorays Axis MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Authentication Type | The authentication method. | True |
| API Token | The Panorays API token. Required for Bearer authentication. | False |
| Client ID | The Client ID provided by Panorays support. Required for OAuth authentication. | False |
| Client Secret | The Client Secret provided by Panorays support. Required for OAuth authentication. | False |
| Authorization code | The authorization code returned after running the \`\!panorays-mcp-generate-login-url\` command and authenticating. Required for OAuth authentication. | False |
| Redirect URI | The redirect URI registered on the Panorays OAuth client. Must match the URI configured by Panorays support. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### panorays-mcp-auth-test

***
Tests the authentication configuration with the MCP server.

#### Base Command

`panorays-mcp-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### panorays-mcp-generate-login-url

***
Generates an authentication login URL. Only available for OAuth authentication.

#### Base Command

`panorays-mcp-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
