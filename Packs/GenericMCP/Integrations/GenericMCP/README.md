Use this integration to connect securely with any MCP server and access its tools in real time.
This integration was integrated and tested with version xx of GenericMCP.

## Configure Generic MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Authentication Type | Select the authentication method. | True |
| Client ID |  |  |
| Client Secret |  |  |
| Authorization code |  |  |
| Custom headers | Add custom headers to be sent with each API request.<br/>Enter each header on a new line in the format: HeaderName: HeaderValue. |  |
| API Token / API Key | API Token or API Key to access the service REST API. | False |
| Username | Username &amp;amp; Password to use for basic authentication. | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list-tools

***
Retrieves a list of available tools in the GitHub MCP server.

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

### generic-mcp-auth-test

***
Test the authentication configuration with the MCP server.

#### Base Command

`generic-mcp-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### generic-mcp-generate-login-url

***
Generate an authentication login URL.

#### Base Command

`generic-mcp-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### generic-mcp-auth-reset

***
Reset the authentication configuration for the MCP server.

#### Base Command

`generic-mcp-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
