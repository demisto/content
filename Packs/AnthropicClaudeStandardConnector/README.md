# Anthropic Claude (Standard Connector)

## What does this pack do?

Satellite pack of the Anthropic Claude integration used for the Standard
Connector deployment. It ships a narrow integration exposing only the two
irreversible Compliance API delete commands
(`claude-chat-file-delete`, `claude-project-document-delete`), sharing all
its code with the parent Anthropic Claude pack via the
`AnthropicClaudeApiModule`.

This pack is configured automatically as part of the Anthropic Claude
Standard Connector. Do **not** configure the integration directly — set it up
from the connector page instead.
