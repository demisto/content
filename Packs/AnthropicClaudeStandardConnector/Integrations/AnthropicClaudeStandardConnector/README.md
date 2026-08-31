This integration is configured automatically as part of the Anthropic Claude Standard Connector. Do not configure this integration directly — set it up from the connector page instead.

## Configure Anthropic Claude (Standard Connector) in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Compliance Access Key | The Anthropic Compliance Access Key \(sk-ant-api01-...\) used for the delete commands. Requires the delete:compliance_user_data scope. | False |
| Use system proxy settings | Route requests through the system HTTPS proxy configured on the server. | False |
| Trust any certificate (not secure) | Bypass TLS certificate validation. Not recommended for production use. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### claude-chat-file-delete

***
Permanently delete a Claude file (a conversation file or a project binary file) via the Compliance API. This is an irreversible hard delete, and it requires a Compliance Access Key with the delete:compliance_user_data scope. Deleting an already-deleted or unknown file ID succeeds (idempotent).

#### Base Command

`claude-chat-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The Claude file ID to permanently delete (e.g., claude_file_...). Deletes a file uploaded in a conversation or a project binary file (project_file). This is an irreversible hard delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.DeletedFile.id | String | The ID of the file that was deleted. |
| AnthropicClaude.DeletedFile.type | String | The deletion confirmation type \(claude_file_deleted\). |
| AnthropicClaude.DeletedFile.Deleted | Boolean | The deletion result for the file \(true when deleted\). |

#### Command example

```!claude-chat-file-delete file_id=claude_file_011CbqYrHZoNLmjzW2AC53fK```

#### Context Example

```json
{
    "AnthropicClaude": {
        "DeletedFile": {
            "Deleted": true,
            "id": "claude_file_011CbqYrHZoNLmjzW2AC53fK",
            "type": "claude_file_deleted"
        }
    }
}
```

#### Human Readable Output

>### File deleted
>
>|id|type|Deleted|
>|---|---|---|
>| claude_file_011CbqYrHZoNLmjzW2AC53fK | claude_file_deleted | true |

### claude-project-document-delete

***
Permanently delete a Claude project document (a plain-text project_doc) via the Compliance API. This is an irreversible hard delete, and it requires a Compliance Access Key with the delete:compliance_user_data scope. Deleting an already-deleted or unknown document ID succeeds (idempotent).

#### Base Command

`claude-project-document-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_id | The Claude project document ID to permanently delete (e.g., claude_proj_doc_...). Applies to project plain-text documents (project_doc). This is an irreversible hard delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.DeletedProjectDocument.id | String | The ID of the project document that was deleted. |
| AnthropicClaude.DeletedProjectDocument.type | String | The deletion confirmation type \(claude_project_document_deleted\). |
| AnthropicClaude.DeletedProjectDocument.Deleted | Boolean | The deletion result for the project document \(true when deleted\). |

#### Command example

```!claude-project-document-delete document_id=claude_proj_doc_011CbqYrHZoNLmjzW2AC53fK```

#### Context Example

```json
{
    "AnthropicClaude": {
        "DeletedProjectDocument": {
            "Deleted": true,
            "id": "claude_proj_doc_011CbqYrHZoNLmjzW2AC53fK",
            "type": "claude_project_document_deleted"
        }
    }
}
```

#### Human Readable Output

>### Project document deleted
>
>|id|type|Deleted|
>|---|---|---|
>| claude_proj_doc_011CbqYrHZoNLmjzW2AC53fK | claude_project_document_deleted | true |
