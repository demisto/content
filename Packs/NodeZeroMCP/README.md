# NodeZero MCP

NodeZero is an autonomous penetration testing platform that continuously identifies exploitable weaknesses across your infrastructure. By simulating real-world attack paths, NodeZero provides proof-based findings that help security teams prioritize remediation efforts.

This pack integrates NodeZero's MCP server with Cortex XSOAR to automatically discover NodeZero's pentesting tools and exposing them as agentic system actions.

## What Does This Pack Do?

- Authorizes your Cortex agent to Horizon3's NodeZero MCP server.
- Exposes MCP server commands to integrate your agentic system with NodeZero.

## Configure NodeZero MCP in Cortex

| **Parameter** | **Description** | **Required** |
|-----------|-------------|----------|
| Server URL | Base URL of the NodeZero MCP server. Defaults to `https://mcp.horizon3ai.com`. | False |
| Scope | Space-separated OAuth scopes to request. Default: `read write offline_access`. | False |
| Redirect URI | URI the OAuth server redirects to after authorization. Default: `https://oproxy.demisto.ninja/authcode`. | False |
| Server Name | Override the display name used for the MCP server in tool names. | False |
