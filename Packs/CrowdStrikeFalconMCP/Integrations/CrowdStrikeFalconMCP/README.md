Use this integration to connect securely with a CrowdStrike Falcon MCP Model Context Protocol (MCP) server and access its tools in real time.
This integration was integrated and tested with version xx of CrowdStrikeFalconMCP.

## Configure CrowdStrike Falcon MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server API Region |  | True |
| Client ID |  | True |
| Client Secret |  | True |
| Enabled Modules | If no modules are selected all modules will be enabled. |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list-tools

***
Retrieves a list of available tools in the CrowdStrike Falcon MCP server.

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
| ListTools.Tools.inputSchema.properties.ids.description | String | The description of the input parameter 'ids'. |
| ListTools.Tools.inputSchema.properties.ids.items.type | String | The type of items in the 'ids' input parameter. |
| ListTools.Tools.inputSchema.properties.ids.title | String | The title of the 'ids' input parameter. |
| ListTools.Tools.inputSchema.properties.ids.type | String | The type of the 'ids' input parameter. |
| ListTools.Tools.inputSchema.properties.include_hidden.default | Boolean | The default value for the 'include_hidden' input parameter. |
| ListTools.Tools.inputSchema.properties.include_hidden.description | String | The description of the 'include_hidden' input parameter. |
| ListTools.Tools.inputSchema.properties.include_hidden.title | String | The title of the 'include_hidden' input parameter. |
| ListTools.Tools.inputSchema.properties.include_hidden.type | String | The type of the 'include_hidden' input parameter. |
| ListTools.Tools.inputSchema.required | String | The required input parameters. |
| ListTools.Tools.inputSchema.title | String | The title of the input schema. |
| ListTools.Tools.inputSchema.type | String | The type of the input schema. |
| ListTools.Tools.meta | Unknown | Metadata about the tool. |
| ListTools.Tools.name | String | The name of the tool. |
| ListTools.Tools.outputSchema.properties.result.anyOf.items.additionalProperties | Boolean | Additional properties for the result items in the output schema. |
| ListTools.Tools.outputSchema.properties.result.anyOf.items.type | String | The type of items in the result of the output schema. |
| ListTools.Tools.outputSchema.properties.result.anyOf.type | String | The type of the result in the output schema. |
| ListTools.Tools.outputSchema.properties.result.anyOf.additionalProperties | Boolean | Additional properties for the result in the output schema. |
| ListTools.Tools.outputSchema.properties.result.title | String | The title of the result in the output schema. |
| ListTools.Tools.outputSchema.required | String | The required fields in the output schema. |
| ListTools.Tools.outputSchema.title | String | The title of the output schema. |
| ListTools.Tools.outputSchema.type | String | The type of the output schema. |
| ListTools.Tools.title | Unknown | The title of the tool. |

### call-tool

***
Calls a specific tool on the CrowdStrike Falcon MCP server with optional input parameters.

#### Base Command

`call-tool`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the tool to call. | Required |
| arguments | Parameters for the tool execution. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CallTool.Tool.content.annotations | Unknown | The annotations of the tool content. |
| CallTool.Tool.content.meta | Unknown | Metadata about the tool content. |
| CallTool.Tool.content.text | String | The text content returned by the tool. |
| CallTool.Tool.content.type | String | The type of content returned by the tool. |
| CallTool.Tool.isError | Boolean | Indicates if the tool call resulted in an error. |
| CallTool.Tool.meta | Unknown | Metadata about the tool call. |
| CallTool.Tool.structuredContent | Unknown | The structured content returned by the tool. |
