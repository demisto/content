This integration is configured automatically as part of the Microsoft 365 Standard Connector. Do not configure this integration directly — set it up from the connector page instead.

## Configure Microsoft Graph Teams (Standard Connector) in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Microsoft Graph server URL. | False |
| Tenant ID | The Microsoft Entra ID tenant ID of the registered application. | True |
| Client ID | The application \(client\) ID of the registered application. | True |
| Client Secret | The client secret of the registered application. | True |
| Trust any certificate (not secure) | Whether to trust any certificate presented by the server. | False |
| Use system proxy settings | Whether to route requests through the system proxy. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-teams-message-update-policy-violation

***
Applies a data loss prevention (DLP) policy violation to a Microsoft Teams message. Targets a chat message, a channel message, or a channel reply.

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

#### Command example

```!msgraph-teams-message-update-policy-violation chat_id=19:2da4c29f6d7041eca70b638b43d45437@thread.v2 message_id=1616990032035 dlp_action=BlockAccess policy_tip_general_text="This message contains sensitive content." verdict_details=AllowFalsePositiveOverride```

#### Context Example

```json
{
    "MSGraphTeams": {
        "TeamsMessagePolicyViolation": {
            "chatId": "19:2da4c29f6d7041eca70b638b43d45437@thread.v2",
            "dlpAction": "BlockAccess",
            "messageId": "1616990032035",
            "verdictDetails": "AllowFalsePositiveOverride"
        }
    }
}
```

#### Human Readable Output

>### Teams Message Policy Violation
>
>|Chat Id|Dlp Action|Message Id|Verdict Details|
>|---|---|---|---|
>| 19:2da4c29f6d7041eca70b638b43d45437@thread.v2 | BlockAccess | 1616990032035 | AllowFalsePositiveOverride |
