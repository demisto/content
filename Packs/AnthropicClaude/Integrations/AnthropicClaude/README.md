Designed to assist security professionals with security investigations, threat hunting, and anomaly detection, leveraging Anthropic Claude's natural language conversational capabilities.

## Configure Anthropic Claude on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Anthropic Claude.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key |  | True |
| Model | The model that will process the inputs and generate the response. | False |
| Model (Optional - overrides selected choice) | The model that will process the inputs and generate the response. | False |
| Max tokens | The maximum number of tokens that can be generated for the response. Required by Anthropic's API \(defaults to 1024\). | True |
| Temperature | Sets the randomness in responses. Lower values \(closer to 0\) produce more deterministic and consistent outputs, while higher values \(up to 1\) increase randomness and variety. | False |
| Top P | Enables nucleus sampling where only the top 'p' percent \(0 to 1\) of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | False |
| Compliance Access Key | Anthropic Compliance Access Key \(sk-ant-api01-...\) used for event collection and the read-only compliance commands. Required to fetch events. | False |
| Fetch events |  | False |
| Activity types | Activity Feed types to narrow the feed. Leave empty to fetch all activity types. | False |
| Maximum number of events per fetch | The maximum number of events to fetch per cycle. Defaults to 50000 \(5000 x 10 calls\). | False |
| First fetch time | The first fetch time for events \(e.g., "1 day", "12 hours"\). | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### claude-send-message

***
Send a plain message to the selected Claude model and receive the generated response.

#### Base Command

`claude-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message that the Claude model will respond to. | Required |
| reset_conversation_history | Whether to keep previously sent messages in a conversation context or start a new conversation. Possible values are: yes, no. | Optional |
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional |
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional |
| top_p | (0-1) Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. |

### claude-check-email-header

***
Checking email header for possible security issues. It is possible to keep asking questions on the provided info using 'claude-send-message'. Resets conversation context by default.

#### Base Command

`claude-check-email-header`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of an uploaded '.eml' file. | Required |
| additional_instructions | Additional instructions or security issue to focus on. | Optional |
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional |
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional |
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. |

### claude-check-email-body

***
Check email body for possible security issues. It is possible to keep asking questions on the provided info using 'claude-send-message'. Resets conversation context by default.

#### Base Command

`claude-check-email-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of an uploaded '.eml' file. | Required |
| additional_instructions | Additional instructions or security issue to focus on. | Optional |
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional |
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional |
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. |

### claude-create-soc-email-template

***
Create an email template out of the conversation context to be sent from the SOC.

#### Base Command

`claude-create-soc-email-template`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| additional_instructions | Additional instructions or security issue to focus on. | Optional |
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional |
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional |
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. |

### claude-list-project-attachments

***
List the attachments of a project (Compliance API).

#### Base Command

`claude-list-project-attachments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID. | Required |
| next_token | Page token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Project.Attachment.id | String | The attachment ID. |
| AnthropicClaude.Project.Attachment.filename | String | The attachment filename. |
| AnthropicClaude.Project.Attachment.mime_type | String | The attachment MIME type. |
| AnthropicClaude.Project.Attachment.type | String | The attachment type \(project_file or project_doc\). |
| AnthropicClaude.Project.Attachment.created_at | Date | The attachment creation time. |

### claude-list-organization-users

***
List the users of an organization (Compliance API).

#### Base Command

`claude-list-organization-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_uuid | Organization UUID. | Required |
| limit | Maximum number of users to return. Maximum: 1000. Default is 50. | Optional |
| next_token | Page token from a previous response's next_page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Organization.User.id | String | The user ID. |
| AnthropicClaude.Organization.User.full_name | String | The user full name. |
| AnthropicClaude.Organization.User.email | String | The user email. |
| AnthropicClaude.Organization.User.organization_role | String | The user's role in the organization. |
| AnthropicClaude.Organization.User.created_at | Date | The user creation time. |

### claude-get-events

***
Manually retrieve Activity Feed events from the Anthropic Compliance API for testing and troubleshooting.

#### Base Command

`claude-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of events to retrieve. Default is 50. | Optional |
| should_push_events | If true, the events are pushed to XSIAM. Possible values are: true, false. Default is false. | Optional |
| activity_types | A comma-separated list of Activity Feed types to narrow the feed. | Optional |

#### Context Output

There is no context output for this command.

### claude-get-project-document

***
Retrieve a project document including its text content (Compliance API).

#### Base Command

`claude-get-project-document`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID. | Required |
| document_id | Project document ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Project.Document.id | String | The document ID. |
| AnthropicClaude.Project.Document.filename | String | The document filename. |
| AnthropicClaude.Project.Document.mime_type | String | The document MIME type. |
| AnthropicClaude.Project.Document.created_at | Date | The document creation time. |
| AnthropicClaude.Project.Document.content | String | The document text content. |

### claude-list-roles

***
List roles of an organization, or retrieve a single role when role_id is provided (Compliance API).

#### Base Command

`claude-list-roles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_uuid | Organization UUID. | Required |
| role_id | When provided, returns that single role instead of the list. | Optional |
| limit | Maximum number of roles to return. Maximum: 1000. Default is 50. | Optional |
| next_token | Page token (list mode only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Organization.Role.id | String | The role ID. |
| AnthropicClaude.Organization.Role.name | String | The role name. |
| AnthropicClaude.Organization.Role.description | String | The role description. |
| AnthropicClaude.Organization.Role.created_at | Date | The role creation time. |
| AnthropicClaude.Organization.Role.updated_at | Date | The role update time. |

### claude-list-chats

***
List chats metadata (Compliance API).

#### Base Command

`claude-list-chats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | Up to 10 user IDs. Run claude-list-organization-users first to obtain them. | Required |
| organization_ids | Filter by organization UUID(s). | Optional |
| project_ids | Filter by project ID(s). | Optional |
| created_at_gte | RFC 3339 lower bound on creation time (example: 2025-06-07T08:09:10Z). | Optional |
| created_at_lte | RFC 3339 upper bound on creation time. | Optional |
| updated_at_gte | RFC 3339 lower bound on update time. | Optional |
| updated_at_lte | RFC 3339 upper bound on update time. | Optional |
| limit | Page size. | Optional |
| after_id | Cursor - walk toward newer chats. | Optional |
| before_id | Cursor - walk toward older chats. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Chat.id | String | The chat ID. |
| AnthropicClaude.Chat.name | String | The chat name. |
| AnthropicClaude.Chat.created_at | Date | The chat creation time. |
| AnthropicClaude.Chat.updated_at | Date | The chat update time. |
| AnthropicClaude.Chat.model | String | The model used in the chat. |
| AnthropicClaude.Chat.organization_uuid | String | The organization UUID. |
| AnthropicClaude.Chat.project_id | String | The project ID. |

### claude-list-projects

***
List projects, or retrieve a single project when project_id is provided (Compliance API).

#### Base Command

`claude-list-projects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | When provided, returns that single project instead of the list. | Optional |
| limit | Maximum number of projects to return. Maximum: 100. Default is 50. | Optional |
| next_token | Page token (list mode only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Project.id | String | The project ID. |
| AnthropicClaude.Project.name | String | The project name. |
| AnthropicClaude.Project.is_private | Boolean | Whether the project is private. |
| AnthropicClaude.Project.organization_uuid | String | The organization UUID. |
| AnthropicClaude.Project.created_at | Date | The project creation time. |
| AnthropicClaude.Project.updated_at | Date | The project update time. |

### claude-list-role-permissions

***
List the permissions of a role (Compliance API).

#### Base Command

`claude-list-role-permissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_uuid | Organization UUID. | Required |
| role_id | Role ID. | Required |
| limit | Maximum number of permissions to return. Maximum: 1000. Default is 50. | Optional |
| next_token | Page token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Organization.Role.Permission.resource_type | String | The permission resource type. |
| AnthropicClaude.Organization.Role.Permission.resource_id | String | The permission resource ID. |
| AnthropicClaude.Organization.Role.Permission.action | String | The permission action. |

### claude-list-groups

***
List groups, or retrieve a single group when group_id is provided (Compliance API).

#### Base Command

`claude-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | When provided, returns that single group instead of the list. | Optional |
| limit | Page size (list mode only). | Optional |
| next_token | Page token (list mode only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Group.id | String | The group ID. |
| AnthropicClaude.Group.name | String | The group name. |
| AnthropicClaude.Group.description | String | The group description. |
| AnthropicClaude.Group.source_type | String | The group source type \(direct or scim\). |
| AnthropicClaude.Group.roles | Unknown | Array of role IDs assigned to the group. |
| AnthropicClaude.Group.created_at | Date | The group creation time. |
| AnthropicClaude.Group.updated_at | Date | The group update time. |

### claude-list-chat-messages

***
List the messages of a chat (Compliance API).

#### Base Command

`claude-list-chat-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chat_id | Chat ID. | Required |
| limit | Maximum number of messages to return. Maximum: 1000. Default is 50. | Optional |
| after_id | Cursor. | Optional |
| before_id | Cursor. | Optional |
| order | Sort direction. Possible values are: asc, desc. | Optional |
| created_at_gte | RFC 3339 lower bound on creation time. | Optional |
| created_at_lte | RFC 3339 upper bound on creation time. | Optional |
| updated_at_gte | RFC 3339 lower bound on update time. | Optional |
| updated_at_lte | RFC 3339 upper bound on update time. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Chat.Message.id | String | The message ID. |
| AnthropicClaude.Chat.Message.role | String | The message role \(user or assistant\). |
| AnthropicClaude.Chat.Message.created_at | Date | The message creation time. |

### claude-list-organizations

***
List the organizations under the parent organization (Compliance API).

#### Base Command

`claude-list-organizations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Client-side cap on the number of organizations returned. Maximum: 1000. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Organization.uuid | String | The organization UUID. |
| AnthropicClaude.Organization.name | String | The organization name. |
| AnthropicClaude.Organization.created_at | Date | The organization creation time. |

### claude-list-group-members

***
List the members of a group (Compliance API).

#### Base Command

`claude-list-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID. | Required |
| limit | Maximum number of members to return. Maximum: 1000. Default is 50. | Optional |
| next_token | Page token. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Group.Member.user_id | String | The member user ID. |
| AnthropicClaude.Group.Member.email | String | The member email. |
| AnthropicClaude.Group.Member.created_at | Date | The membership creation time. |
| AnthropicClaude.Group.Member.updated_at | Date | The membership update time. |
