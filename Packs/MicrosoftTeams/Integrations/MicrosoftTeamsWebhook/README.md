Integration for sending notifications to a Microsoft Teams channel via Incoming Webhook.
This integration was integrated and tested with version 6.8 of Microsoft Teams via Webhook

## Configure Microsoft Teams via Webhook on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Teams via Webhook.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the URLs, token, and connection.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Microsoft Webhook URL | The webhook URL in the Teams Channel | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ms-teams-message

***
Send a message to Microsoft Teams via Incoming Webhook.

#### Base Command

`ms-teams-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message to send.  For example: "This is a message from Cortex XSOAR,". Default is None. | Optional | 
| team_webhook | The alternative webhook for a different team.  If not defined, the integration's default webhook is used. | Optional | 
| alternative_url | The alternative URL to send in place of the link to the XSOAR Investigation. | Optional | 
| url_title | The title for the link, defaults to "Cortex XSOAR URL". Default is Cortex XSOAR URL. | Optional | 
| adaptive_cards_format | Should the adaptive cards format be used?. | Optional | 

#### Context Output

There is no context output for this command.

## Troubleshooting
By default the message is being sent with a message template: `X Used a Workflow template to send this card`.
In order to eliminate this line you can follow the following approach:
- Navigate to Microsoft’s Power Automate portal and sign into your Microsoft Teams account where you’ve previously [set up](https://make.powerautomate.com/) the Flow.
- Click on “My flows” from the left side menu.
- Click on the newly created Flow to open its details page.
- On the Flow’s details page, click on “Save As” button on top.
- Give your new Flow a name and click on the “Save” button.
- Navigate back to “My flows” from the left side menu.
- Find the copy Flow and click its name to access its details page.
- On the Flow’s details page, click on the “Turn On” button at the top.
- In order to find the new url link navigate to the edit tab on the Flow’s details page.
- Click on the action task and copy the HTTP URL.
- Configure an instance of the integration and add the copied Workflow URL for the Teams channel.