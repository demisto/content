Use this integration to connect securely with the Command Zero Model Context Protocol (MCP) server and access its investigation tools in real time.

## Configure Command Zero MCP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Region | The region that hosts your Command Zero organization. | True |
| API Key | The Command Zero API key. The integration can perform only the actions allowed by the key's role. | True |
| Organization ID | The ID of the Command Zero organization to connect to. Required only if the API key has access to more than one organization. | False |
| Custom Server URL | Overrides the Region parameter. Use only when instructed by Command Zero. | False |
| Custom headers | Add custom headers to be sent with each request. | False |
| Trust any certificate (not secure) | | False |

## Commands

This integration has no user-facing commands. The Command Zero MCP server tools are discovered automatically and exposed as agentic system actions.
