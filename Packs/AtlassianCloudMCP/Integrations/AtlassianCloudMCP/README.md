Use this integration to connect securely with a Atlassian Cloud Model Context Protocol (MCP) server and access its tools in real time.

## Configure Atlassian Cloud MCP in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Authorization code |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list-tools

***
Retrieves a list of available tools in the Atlassian Cloud MCP server.

#### Base Command

`list-tools`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### call-tool

***
Calls a specific tool on the MCP server with optional input parameters.

#### Base Command

`call-tool`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the tool to call. | Optional |
| arguments | Parameters for the tool execution. | Optional |

#### Context Output

There is no context output for this command.

### atlassian-cloud-mcp-auth-test

***
Test the authentication configuration with the MCP server.

#### Base Command

`atlassian-cloud-mcp-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### atlassian-cloud-mcp-generate-login-url

***
Generate an authentication login URL.

#### Base Command

`atlassian-cloud-mcp-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
