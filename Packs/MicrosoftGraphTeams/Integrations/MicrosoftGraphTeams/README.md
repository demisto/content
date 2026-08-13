Microsoft Graph lets your app get authorized access to a user's Teams app in a personal or organization account.

This is a long-running integration. For more information about long-running integrations, see the [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations), [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) or [Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) documentation.

## Configure O365 Teams (Using Graph API) in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Tenant ID | Token or Tenant ID - see Detailed Instructions \(?\) | True |
| Client ID | ID or Client ID - see Detailed Instructions \(?\) | True |
| Client Secret | Key or Client Secret - see Detailed Instructions \(?\) | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Use a self deployed Azure Application |  | False |
| Application redirect URI (for Authorization Code flow mode) |  | False |
| Authorization Code | Authorization code on behalf of a user, used with self deployed Azure Applications. | False |
| Email address of the XSOAR delegated Teams user (e.g. "example@demisto.com") |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Suppress Errors for Non Found Users |  | False |

#### Required Permissions

Chat.Create - Delegated
Chat.Read - Delegated
Chat.ReadBasic - Delegated
Chat.ReadWrite - Delegated
ChatMember.Read - Delegated
ChatMember.ReadWrite - Delegated
ChatMessage.Read - Delegated
ChatMessage.Send - Delegated

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-teams-list-chats

***
Retrieve the list of chats that the user is part of.

#### Base Command

`msgraph-teams-list-chats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID to use Teams as (can be principal ID (email address)). | Optional |
| odata | An OData query. See README for OData usage examples. | Optional |
| limit | Limit chats to fetch in one request. Default is 20. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChat.ID | String | The ID of the chat. |
| MSGraphTeamsChat.UserID | String | The ID of the user. |
| MSGraphTeamsChat.Subject | String | The title of the chat. |
| MSGraphTeamsChat.Created | Date | The time the chat was created. |
| MSGraphTeamsChat.LastUpdatedTime | Date | The time the chat was last updated. |
| MSGraphTeamsChat.Type | String | The type of chat. |

### msgraph-teams-create-chat

***
Create a new chat.

#### Base Command

`msgraph-teams-create-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID to use Teams as (can be principal ID (email address)). | Optional |
| subject | The title of the chat. | Required |
| type | Specifies the type of chat. Possible values are: group and oneOnOne. Possible values are: group, oneOnOne. Default is group. | Optional |
| members | A comma-separated list members that should be added. using user principal name (email). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChat.ID | String | The ID of the chat. |
| MSGraphTeamsChat.UserID | String | The ID of the user. |
| MSGraphTeamsChat.Subject | String | The title of the chat. |
| MSGraphTeamsChat.Created | Date | The time the chat was created. |
| MSGraphTeamsChat.LastUpdatedTime | Date | The time the chat was last updated. |
| MSGraphTeamsChat.Type | String | The type of chat. |

### msgraph-teams-get-chat

***
Retrieve a single chat (without its messages).

#### Base Command

`msgraph-teams-get-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID to use Teams as (can be principal ID (email address)). | Optional |
| chat_id | The chat's unique identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChat.ID | String | The ID of the chat. |
| MSGraphTeamsChat.UserID | String | The ID of the user. |
| MSGraphTeamsChat.Subject | String | The title of the chat. |
| MSGraphTeamsChat.Created | Date | The time the chat was created. |
| MSGraphTeamsChat.LastUpdatedTime | Date | The time the chat was last updated. |
| MSGraphTeamsChat.Type | String | The type of chat. |

### msgraph-teams-update-chat

***
Update the properties of a chat object.

#### Base Command

`msgraph-teams-update-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chat_id | The chat's unique identifier. | Required |
| subject | The title of the chat. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChat.ID | String | The ID of the chat. |
| MSGraphTeamsChat.UserID | String | The ID of the user. |
| MSGraphTeamsChat.Subject | String | The title of the chat. |
| MSGraphTeamsChat.Created | Date | The time the chat was created. |
| MSGraphTeamsChat.LastUpdatedTime | Date | The time the chat was last updated. |
| MSGraphTeamsChat.Type | String | The type of chat. |

### msgraph-teams-list-members

***
List all conversation members in a chat.

#### Base Command

`msgraph-teams-list-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID to use Teams as (can be principal ID (email address)). | Optional |
| chat_id | The chat's unique identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChatMember.ID | String | The ID of the chat member. |
| MSGraphTeamsChatMember.Name | String | The display name of the chat member. |
| MSGraphTeamsChatMember.HistoryStartTime | Date | The timestamp denoting how far back a conversation's history is shared with the conversation member. This property is settable only for members of a chat. |
| MSGraphTeamsChatMember.ChatID | unknown | The ID of the chat. |

### msgraph-teams-add-member

***
Add a conversationMember to a chat.

#### Base Command

`msgraph-teams-add-member`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chat_id | The chat's unique identifier. | Required |
| user_id | User ID to add to Teams chat (can be principal ID (email address)). | Required |
| share_history | Allowing sharing of the whole history of the chat. Possible values are: true, false. Default is true. | Optional |

#### Context Output

There is no context output for this command.

### msgraph-teams-list-messages

***
Retrieve the list of messages in a chat.

#### Base Command

`msgraph-teams-list-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID to use Teams as (can be principal ID (email address)). | Optional |
| chat_id | The chat's unique identifier. | Required |
| limit | Limit messages to fetch in one request. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChatMessage.ID | String | The ID of the message. |
| MSGraphTeamsChatMessage.ChatID | String | The ID of the chat. |
| MSGraphTeamsChatMessage.From | String | The Name of the sender of the chat message. |
| MSGraphTeamsChatMessage.Created | Date | Timestamp of when the chat message was created. |
| MSGraphTeamsChatMessage.LastModifiedTime | Date | Timestamp when the chat message is created \(initial setting\) or modified, including when a reaction is added or removed. |
| MSGraphTeamsChatMessage.Body | htmlBody | HTML representation of the content of the chat message. Representation is specified by the contentType inside the body. |

### msgraph-teams-send-message

***
Send a new message in a chat.

#### Base Command

`msgraph-teams-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chat_id | The chat's unique identifier. | Required |
| body | HTML representation of the content of the chat message. Representation is specified by the contentType inside the body. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeamsChatMessage.ID | String | The ID of the message. |
| MSGraphTeamsChatMessage.chatID | String | The ID of the chat. |
| MSGraphTeamsChatMessage.From | String | The Name of the sender of the chat message. |
| MSGraphTeamsChatMessage.Created | Date | Timestamp of when the chat message was created. |
| MSGraphTeamsChatMessage.LastModifiedTime | Date | Timestamp when the chat message is created \(initial setting\) or modified, including when a reaction is added or removed. |
| MSGraphTeamsChatMessage.Body | htmlBody | HTML representation of the content of the chat message. Representation is specified by the contentType inside the body. |

### msgraph-teams-test

***
Tests connectivity to Microsoft Graph Teams.

#### Base Command

`msgraph-teams-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### msgraph-teams-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-teams-auth-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### msgraph-teams-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`msgraph-teams-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### microsoft-teams-message-update-policy-violation

***
Applies a data loss prevention policy violation to a Microsoft Teams message, quarantining a chat message, a channel message, or a channel reply. HTTP error responses from Microsoft Graph are surfaced verbatim as a command error.

#### Base Command

`microsoft-teams-message-update-policy-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chat_id | The chat ID hosting the message. Provide this for a chat message. Retrieve chat IDs from the Microsoft Teams client URL or via the Microsoft Graph list chats endpoint. Mutually exclusive with team_id and channel_id. | Optional |
| team_id | The team ID hosting the channel message. Provide together with channel_id for a channel message. Retrieve team IDs from the Microsoft Teams admin center or via the Microsoft Graph list joinedTeams endpoint. | Optional |
| channel_id | The channel ID hosting the message. Provide together with team_id for a channel message. Retrieve channel IDs from the Microsoft Teams client URL or via the Microsoft Graph list channels endpoint. | Optional |
| parent_message_id | The parent message ID when targeting a channel reply. Only supported for channel messages. Retrieve message IDs via the Microsoft Graph list channel messages endpoint. | Optional |
| message_id | The ID of the message to update. Retrieve message IDs via the Microsoft Graph list messages endpoint for the chat or channel. | Required |
| dlp_action | The action taken on the message. One of NoAction, BlockAccess, BlockAccessExternal. Possible values are: NoAction, BlockAccess, BlockAccessExternal. | Optional |
| policy_tip_general_text | The explanatory text shown to the user in the policy tip. | Optional |
| verdict_details | The reviewer actions available on the flagged message. One of None, AllowOverride, AllowOverrideWithoutJustification, AllowOverrideWithJustification. When omitted, Microsoft Graph applies its default behavior. Possible values are: None, AllowOverride, AllowOverrideWithoutJustification, AllowOverrideWithJustification. | Optional |
| payment_model | The billing model appended as the model query parameter. Provide when the tenant uses a specific Microsoft Graph metered API payment model. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeams.TeamsMessagePolicyViolation.messageId | String | The ID of the message the policy violation was applied to. |
| MSGraphTeams.TeamsMessagePolicyViolation.chatId | String | The ID of the chat hosting the message, when targeting a chat message. |
| MSGraphTeams.TeamsMessagePolicyViolation.teamId | String | The ID of the team hosting the message, when targeting a channel message. |
| MSGraphTeams.TeamsMessagePolicyViolation.channelId | String | The ID of the channel hosting the message, when targeting a channel message. |
| MSGraphTeams.TeamsMessagePolicyViolation.parentMessageId | String | The ID of the parent message, when targeting a channel reply. |
| MSGraphTeams.TeamsMessagePolicyViolation.dlpAction | String | The data loss prevention action that was applied to the message. |
| MSGraphTeams.TeamsMessagePolicyViolation.verdictDetails | String | The reviewer actions that were made available on the flagged message. |
