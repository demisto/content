This script sends a notification message to a user, group, or channel Supports sending messages to Slack, Microsoft Teams, Mattermost or Zoom.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| brand | The brand to send the message to. Valid options: Microsoft Teams, Slack, Mattermost, Zoom. |
| message | The message content to send. |
| to | The user to send the message to. Can be a username, id or email. |
| channel | The channel to send the message to. |
| channel_id | The ID of the channel to send the message to. |
| team | The team in which the specified channel exists. Leave blank to use the default team configured in the integration parameters. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftTeams.Message.ID | The id of the message sent. | String |
| Slack.Thread.ID | The Slack thread ID. | String |
