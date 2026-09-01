This integration is configured automatically as part of the Microsoft 365 Standard Connector. Do not configure this integration directly — set it up from the connector page instead.

## Configure Microsoft Graph Teams (Standard Connector) in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | False |
| Tenant ID | True |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-teams-message-update-policy-violation

***
Applies a data loss prevention (DLP) policyViolation to a Microsoft Teams message. Targets a chat message, a channel message, or a channel reply.

#### Base Command

`msgraph-teams-message-update-policy-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chat_id | The chat ID hosting the message. Provide either 'chat_id' or 'team_id' plus 'channel_id'. | Optional | 
| team_id | The team ID hosting the channel message. Required together with 'channel_id' when targeting a channel message or reply. | Optional | 
| channel_id | The channel ID hosting the message. Required together with 'team_id' when targeting a channel message or reply. | Optional | 
| parent_message_id | The parent message ID when targeting a channel reply. Only supported for channel messages, not chat messages. | Optional | 
| message_id | The ID of the message to update. | Required | 
| dlp_action | The action taken on the message by the DLP provider. Possible values are: NoAction, BlockAccess, BlockAccessExternal. | Optional | 
| policy_tip_general_text | The general explanatory text shown to the user in the policy tip. | Optional | 
| verdict_details | The reviewer actions available on the flagged message. Omit to let Microsoft Graph apply its default (permanent) behavior. | Optional | 
| payment_model | The billing model appended as the model query parameter when provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphTeams.TeamsMessagePolicyViolation.messageId | String | The ID of the message the policy violation was applied to. | 
| MSGraphTeams.TeamsMessagePolicyViolation.chatId | String | The chat ID hosting the message \(when targeting a chat message\). | 
| MSGraphTeams.TeamsMessagePolicyViolation.teamId | String | The team ID hosting the message \(when targeting a channel message\). | 
| MSGraphTeams.TeamsMessagePolicyViolation.channelId | String | The channel ID hosting the message \(when targeting a channel message\). | 
| MSGraphTeams.TeamsMessagePolicyViolation.parentMessageId | String | The parent message ID \(when targeting a channel reply\). | 
| MSGraphTeams.TeamsMessagePolicyViolation.dlpAction | String | The DLP action applied to the message. | 
| MSGraphTeams.TeamsMessagePolicyViolation.verdictDetails | String | The reviewer actions available on the flagged message. | 
