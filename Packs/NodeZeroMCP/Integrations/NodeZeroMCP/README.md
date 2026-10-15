# NodeZeroMCP

Connects Cortex to the [NodeZero](https://www.horizon3.ai/nodezero/) autonomous penetration testing platform MCP server, automatically discovering NodeZero's pentesting tools and exposing them as agentic system actions.

This integration uses OAuth 2.0 Dynamic Client Registration (DCR). It registers itself as a public OAuth client with the NodeZero OAuth proxy, so no pre-issued Client ID or Client Secret is required. Authentication flows through the NodeZero portal.

## What does this pack do?

- Fetches HIGH and CRITICAL severity weaknesses from NodeZero pentest operations
- Creates incidents with full weakness context including severity scores, attack paths, and proof status
- Tracks CISA KEV (Known Exploited Vulnerabilities) and ransomware campaign associations
- Enables automated remediation workflows based on weakness severity and exploitability

## Configure NodeZero MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| MCP Server URL | The NodeZero MCP server endpoint. Select the region that matches your NodeZero deployment. | True |
| Authorization Code | The authorization code returned by the \!nodezero-mcp-generate-login-url command. Paste it here, then run \!nodezero-mcp-auth-test to complete authentication. |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list-tools

***
Retrieves a list of available tools in the NodeZero MCP server.

#### Base Command

`list-tools`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### call-tool

***
Calls a specific tool on the NodeZero MCP server with optional input parameters.

#### Base Command

`call-tool`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the tool to call. | Optional |
| arguments | Parameters for the tool execution. | Optional |

#### Context Output

There is no context output for this command.

### nodezero-mcp-generate-login-url

***
Register this integration with your NodeZero portal and generate a login URL. Follow the returned instructions to authenticate via the NodeZero portal.

#### Base Command

`nodezero-mcp-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!nodezero-mcp-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>
>1. Click on the login URL to sign in and grant Cortex permissions for your MCP server.
> You will be automatically redirected to a link with the following structure:
> ```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter) and paste it in the instance configuration under the **Authorization code** parameter.
>3. Save the instance configuration.
> **IMPORTANT NOTE**: Authentication code is time-sensitive and expires quickly.
> Please copy the Authorization code to the instance configuration within a short time frame after generating the login URL.
>
>4. To check connectivity, run the **!nodezero-mcp-auth-test** command.

### nodezero-mcp-auth-test

***
Test the OAuth authentication configuration with the NodeZero MCP server.

#### Base Command

`nodezero-mcp-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!nodezero-mcp-auth-test```

#### Human Readable Output

>✅ Authentication successful.
