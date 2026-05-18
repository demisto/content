Use this integration to connect securely with a ServiceNow Model Context Protocol (MCP) server and access its tools in real time.
This integration was integrated and tested with the latest version of ServiceNow MCP.

## Configure ServiceNow MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ServiceNow Instance URL | The ServiceNow instance URL \(e.g., \`https://dev12345.service-now.com\`\).<br/> | True |
| MCP Server Name | The name of the MCP server on the ServiceNow instance. Defaults to the preconfigured Quickstart Server \`sn_mcp_server_default\`.<br/> |  |
| Client ID | The Client ID and Client Secret from the OAuth Inbound Integration created on the ServiceNow instance.<br/> | True |
| Client Secret |  | True |
| Authorization code | Authorization code returned after running the \`\!servicenow-mcp-generate-login-url\` command and authenticating.<br/> |  |
| Redirect URI | The redirect URI registered in the ServiceNow OAuth Inbound Integration. Must match the URI configured on the ServiceNow side.<br/> |  |
| Trust any certificate (not secure) |  |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### servicenow-mcp-auth-test

***
Test the authentication configuration with the MCP server.

#### Base Command

`servicenow-mcp-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### servicenow-mcp-generate-login-url

***
Generate an authentication login URL.

#### Base Command

`servicenow-mcp-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
