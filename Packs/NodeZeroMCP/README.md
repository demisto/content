# NodeZero MCP

NodeZero is an autonomous penetration testing platform that continuously identifies exploitable weaknesses across your infrastructure. By simulating real-world attack paths, NodeZero provides proof-based findings that help security teams prioritize remediation efforts.

This pack integrates NodeZero's MCP server with Cortex XSOAR to automatically discover NodeZero's pentesting tools and exposing them as agentic system actions.

## What Does This Pack Do?

This pack is intended for the Cortex Agentic AI.

Authorizes your Cortex agent to Horizon3's NodeZero MCP server. Exposes MCP server commands to integrate your agentic system with NodeZero.

## Tools

This MCP server provides the following tools for interacting with Horizon3 (H3) NodeZero (NZ) pentesting data.

### get_pentest_details

- **Type**: Read
- **Purpose**: Retrieve pentest information without requiring GraphQL knowledge. Search by date range, user, text, status, vulnerability content, or vulnerability severity, with configurable inclusion of hosts, credentials, vulnerabilities, attack paths, and statistics.
- **Example**: "Show me my pentests from last week", "Did we check for CVE-2023-1234?"

### get_vulnerability_details

- **Type**: Read
- **Purpose**: Retrieve vulnerability (weakness) details via a pentest-based scan. `limit` caps the number of vulnerabilities returned; `pentest_limit` controls how many recent pentests are scanned.

### get_h3_terminology

- **Type**: Read
- **Purpose**: Look up H3-specific term definitions (e.g. weakness vs. vulnerability, context score, attack path) to keep terminology accurate.

### setup_pentest_scope

- **Type**: Write
- **Purpose**: Create a new pentest via the `create_op` mutation with a `ScheduleOpFormInput`. Scope parameters depend on `op_type` (default `NodeZero`); see the tool's parameter docs for details.

### fetch_h3_graphql_docs

- **Type**: Read
- **Purpose**: Fetch H3 GraphQL schema documentation for a given (type, field, enum, etc.) to help construct valid queries.

### run_h3_graphql_query

- **Type**: Read
- **Purpose**: Run an arbitrary read-only GraphQL query against the H3 API for advanced use cases. Prefer the purpose-built tools above for common queries.
