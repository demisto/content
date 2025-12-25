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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ListTools.Tools.annotations | Unknown | The annotations of the tool. |
| ListTools.Tools.description | String | The description of the tool. |
| ListTools.Tools.icons | Unknown | The icons associated with the tool. |
| ListTools.Tools.inputSchema.properties | Unknown | The properties of the input schema for each tool. |
| ListTools.Tools.inputSchema.required | String | The required input parameters. |
| ListTools.Tools.inputSchema.title | String | The title of the input schema. |
| ListTools.Tools.inputSchema.type | String | The type of the input schema. |
| ListTools.Tools.meta | Unknown | Metadata about the tool. |
| ListTools.Tools.name | String | The name of the tool. |
| ListTools.Tools.outputSchema.properties.result | Unknown | The result of the tool execution. |
| ListTools.Tools.outputSchema.required | String | The required fields in the output schema. |
| ListTools.Tools.outputSchema.title | String | The title of the output schema. |
| ListTools.Tools.outputSchema.type | String | The type of the output schema. |
| ListTools.Tools.title | String | The title of the tool. |

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CallTool.Tool.type | String | The type of the tool output. |
| CallTool.Tool.text | String | The text content of the tool output. |
| CallTool.Tool.annotations.audience | Unknown | The audience for the tool output annotations. |
| CallTool.Tool.annotations.priority | Unknown | The priority of the tool output annotations. |
| CallTool.Tool.meta | Unknown | Metadata associated with the tool output. |
| CallTool.Tool.data | Unknown | The data content of the tool output. |
| CallTool.Tool.mimeType | String | The MIME type of the tool output. |
| CallTool.Tool.resource.uri | String | The URI of the resource in the tool output. |
| CallTool.Tool.resource.mimeType | String | The MIME type of the resource in the tool output. |
| CallTool.Tool.resource.meta | Unknown | Metadata of the resource in the tool output. |
| CallTool.Tool.resource.text | String | The text content of the resource in the tool output. |
| CallTool.Tool.resource.blob | Unknown | The blob content of the resource in the tool output. |

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

### atlassian-cloud-mcp-auth-reset

***
Reset the authentication configuration for the MCP server.

#### Base Command

`atlassian-cloud-mcp-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
