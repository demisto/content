Use this integration to connect securely with any MCP server and access its tools in real time.

## Configure Generic MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Authentication Type | Select the authentication method. | True |
| Client ID |  |  |
| Client Secret |  |  |
| Authorization code |  |  |
| Redirect URI |  |  |
| Custom headers | Add custom headers to be sent with each API request.<br/>Enter each header on a new line in the format: HeaderName: HeaderValue. |  |
| Authorization Endpoint | The URL for the OAuth 2.0 authorization endpoint. If not provided, the default will be the origin of the \`base_url\` followed by \`/oauth2/authorize\`.<br/>For example, if \`base_url\` is \`https://example.com/mcp\`, the default \`Authorization Endpoint\` will be \`https://example.com/oauth2/authorize\`.<br/> |  |
| Token Endpoint | The URL for the OAuth 2.0 token endpoint. If not provided, the default will be the origin of the \`base_url\` followed by \`/oauth2/token\`.<br/>For example, if \`base_url\` is \`https://example.com/mcp\`, the default \`Token Endpoint\` will be \`https://example.com/oauth2/token\`.<br/> |  |
| Scope | Space-separated permission identifiers. |  |
| API Token / API Key | API Token or API Key to access the service REST API. | False |
| Username | Username &amp;amp; Password to use for basic authentication. | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |

## Authentication Type Options

| Parameter | Description | Type |
|---|---|---|
| Server URL | The base URL of the MCP server. This is a required parameter for all authentication types. | String |
| Authentication Type | Select the authentication method to use for connecting to the MCP server. | Enum |
| &nbsp;&nbsp;&nbsp;&nbsp;Basic | Uses a username and password for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Username & Password | Provide the username and password for basic authentication. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;Token | Uses a single API token or key for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;API Token / API Key | Provide the API Token or API Key to access the service REST API. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;Bearer | Uses a Bearer token for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;API Token / API Key | Provide the Bearer Token to access the service REST API. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;Api-Key | Uses an API key for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;API Token / API Key | Provide the API Key to access the service REST API. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;RawToken | Uses a raw token for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;API Token / API Key | Provide the raw token to access the service REST API. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;OAuth 2.0 Authorization Code | Uses the OAuth 2.0 Authorization Code flow for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client ID | The Client ID for your application. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Secret | The Client Secret for your application. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Authorization code | Required to obtain the access token. To get this code, run the `generic-mcp-generate-login-url` command and follow its instructions. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Scope | Space-separated permission identifiers requested from the authorization server. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;OAuth 2.0 Client Credentials | Uses the OAuth 2.0 Client Credentials flow for authentication. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client ID | The Client ID for your application. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Secret | The Client Secret for your application. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Scope | Space-separated permission identifiers requested from the authorization server. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;OAuth 2.0 Dynamic Client Registration | Uses OAuth 2.0 Dynamic Client Registration. | |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Authorization code | Required to obtain the access token. To get this code, run the `generic-mcp-generate-login-url` command and follow its instructions. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Scope | Space-separated permission identifiers requested from the authorization server. | String |
| &nbsp;&nbsp;&nbsp;&nbsp;No Authorization | No authentication is used. | |
| Redirect URI | The URI to which the authorization server redirects the user-agent after granting authorization. This is typically used in OAuth 2.0 Authorization Code flow. Default: `https://oproxy.demisto.ninja/authcode`. | String |
| Custom headers | Add custom headers to be sent with each API request. Enter each header on a new line in the format: `HeaderName: HeaderValue`. | String |
| Authorization Endpoint | The URL for the OAuth 2.0 authorization endpoint. If not provided, the default will be the origin of the `base_url` followed by `/oauth2/authorize`. For example, if `base_url` is `https://example.com/mcp`, the default `Authorization Endpoint` will be `https://example.com/oauth2/authorize`. | String |
| Token Endpoint | The URL for the OAuth 2.0 token endpoint. If not provided, the default will be the origin of the `base_url` followed by `/oauth2/token`. For example, if `base_url` is `https://example.com/mcp`, the default `Token Endpoint` will be `https://example.com/oauth2/token`. | String |
| Trust any certificate (not secure) | Select this option to trust any certificate. This is not recommended for production environments. | Boolean |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list-tools

***
Retrieves a list of available tools in the MCP server.

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
