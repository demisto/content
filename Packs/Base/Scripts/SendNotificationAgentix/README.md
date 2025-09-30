Sends a notification message to a user, group, or channel. Supports sending messages to Slack, Microsoft Teams, Mattermost or Zoom.


## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* send-notification

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| message | The message content to send. |
| brand | Integration brand to send the message to. Valid options: Microsoft Teams, Slack, Mattermost, Zoom.<br/> |
| to | The user to send the message to. Can be a username, id or email. |
| channel | The channel to send the message to. |
| channel_id | \(Supported only for Slack and Zoom\)<br/>The ID of the channel to send the message to.<br/> |
| team | \(Supported only for Microsoft Teams\)<br/>The team in which the specified channel exists.<br/>Leave blank to use the default team configured in the integration parameters.<br/> |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftTeams.Message.ID | ID of the message sent. | String |
| Slack.Thread.ID | The Slack thread ID. | String |
