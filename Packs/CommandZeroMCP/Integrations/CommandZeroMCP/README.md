Use this integration to connect securely with the Command Zero Model Context Protocol (MCP) server and access its investigation tools in real time.

## Configure Command Zero MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Region | The region that hosts your Command Zero organization. | True |
| Authorization code | Run the command-zero-mcp-generate-login-url command to obtain the Authorization code. | False |
| Custom Server URL | Overrides the Region parameter. Use only when instructed by Command Zero. | False |
| Redirect URI | The URI registered with Command Zero to receive the authorization code. | False |
| Custom headers | Add custom headers to be sent with each request. | False |
| Trust any certificate (not secure) | | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### command-zero-mcp-auth-test

***
Test the authentication configuration with the Command Zero MCP server.

#### Base Command

`command-zero-mcp-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### command-zero-mcp-generate-login-url

***
Generate an authentication login URL.

#### Base Command

`command-zero-mcp-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
