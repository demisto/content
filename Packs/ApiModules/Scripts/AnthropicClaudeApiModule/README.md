# AnthropicClaudeApiModule

Common Anthropic Claude Compliance API code shared by:

- The full `AnthropicClaude` integration (parent pack, all commands + event collector).
- The narrower `AnthropicClaudeStandardConnector` integration (ConnectUs satellite pack, delete commands only).

The module carries only what the two irreversible compliance delete commands
(`claude-chat-file-delete` and `claude-project-document-delete`) need. The LLM
client, the compliance list/get commands, and the event collector stay inline
in the parent pack because they are not shared.

## What lives here

- `Config` — retry/back-off constants and the compliance-key docs URL.
- `ApiPaths` — the two flat delete paths (`CHAT_FILES`, `PROJECT_DOCUMENTS`).
- `ComplianceClient` — subclass of `BaseClient` that:
  - Pre-populates the `x-api-key` header on the legacy Cortex XSOAR path.
  - Overrides `_apply_ucp_api_key` to write `x-api-key` (not `Authorization: Bearer …`) on the ConnectUs / UCP path.
- `ensure_compliance_key`, `_delete_command`, `chat_file_delete_command`, `project_document_delete_command`.

## UCP auth override

The ConnectUs profile for this connector uses `type: api_key` with
`metadata.auth.parameter: api_key`. The Content Serialization Protocol aliases
that to the envelope key `key`. Because the Anthropic Compliance API rejects
Bearer auth and requires `x-api-key`, the client overrides the default
`BaseClient._apply_ucp_api_key` and writes the header directly.
