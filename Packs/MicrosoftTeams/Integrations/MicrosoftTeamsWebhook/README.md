Integration for sending notifications to a Microsoft Teams channel via and incoming webhook. 
## Configure Microsoft Teams via Webhook on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Teams via Webhook.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the URLs, token, and connection.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Microsoft Webhook URL | The webhook URL in the Teams Channel | True |

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ms-teams-message
***
Send a message to Microsoft Teams via an incoming webhook.
#### Base Command
`ms-teams-message`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message to send.  For example: "This is a message from Cortex XSOAR". Default is None. | Optional | 
| team_webhook | The alternative webhook for a different team.  If not defined, the integration's default webhook is used. | Optional | 
#### Context Output
There is no context output for this command.
