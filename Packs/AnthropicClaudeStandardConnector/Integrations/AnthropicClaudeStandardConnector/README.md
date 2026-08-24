Wired to the Anthropic Claude connector to expose two irreversible hard-delete commands from the Anthropic Compliance API. Configured automatically as part of the connector setup — do not add an instance of this integration directly.

## Authentication

Authenticates with the Anthropic Compliance Access Key (`sk-ant-api01-...`) via the `x-api-key` header. The key must have the `delete:compliance_user_data` scope.

- On the ConnectUs (UCP) path (standard connector, this integration's normal deployment), the credential is supplied by the connector profile and injected at request time.
- On the legacy XSOAR path (direct configuration, not recommended), set the "Compliance Access Key" integration parameter.

For details on obtaining a Compliance Access Key, see the [Anthropic Compliance API documentation](https://platform.claude.com/docs/en/manage-claude/compliance-api-access).

## Configuration

This integration is configured automatically as part of the **Anthropic Claude Standard Connector**. Set it up from the connector page, not from **Settings → Integrations**.

| Parameter | Description | Required |
| --- | --- | --- |
| Compliance Access Key | The Anthropic Compliance Access Key. Requires the `delete:compliance_user_data` scope. | True |
| Trust any certificate (not secure) | Bypass TLS certificate validation. | False |
| Use system proxy settings | Route requests through the system HTTPS proxy. | False |

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.

### claude-chat-file-delete

***
Permanently delete a Claude file (a conversation file or a project binary file) via the Compliance API. This is an irreversible hard delete, and it requires a Compliance Access Key with the `delete:compliance_user_data` scope. Deleting an already-deleted or unknown file ID succeeds (idempotent).

#### Base Command

`claude-chat-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The Claude file ID to permanently delete (e.g., `claude_file_...`). Deletes a file uploaded in a conversation or a project binary file (`project_file`). This is an irreversible hard delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.DeletedFile.id | String | The ID of the file that was deleted. |
| AnthropicClaude.DeletedFile.type | String | The deletion confirmation type (`claude_file_deleted`). |
| AnthropicClaude.DeletedFile.Deleted | Boolean | The deletion result for the file (`true` when deleted). |

### claude-project-document-delete

***
Permanently delete a Claude project document (a plain-text `project_doc`) via the Compliance API. This is an irreversible hard delete, and it requires a Compliance Access Key with the `delete:compliance_user_data` scope. Deleting an already-deleted or unknown document ID succeeds (idempotent).

#### Base Command

`claude-project-document-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_id | The Claude project document ID to permanently delete (e.g., `claude_proj_doc_...`). Applies to project plain-text documents (`project_doc`). This is an irreversible hard delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.DeletedProjectDocument.id | String | The ID of the project document that was deleted. |
| AnthropicClaude.DeletedProjectDocument.type | String | The deletion confirmation type (`claude_project_document_deleted`). |
| AnthropicClaude.DeletedProjectDocument.Deleted | Boolean | The deletion result for the project document (`true` when deleted). |
