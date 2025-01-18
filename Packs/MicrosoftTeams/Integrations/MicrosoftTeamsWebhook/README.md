Integration for sending notifications to a Microsoft Teams channel via workflow.
This integration was integrated and tested with version 6.8 of Microsoft Teams via Webhook

## Configure Microsoft Teams via Webhook in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Microsoft workflow URL | The workflow URL in the Teams Channel | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| alternative_url | The alternative URL to send in place of the link to the Cortex XSOAR Investigation. | Optional |
| url_title | The title for the link. Defaults to "Cortex XSOAR URL". Default is Cortex XSOAR URL. | Optional |
| adaptive_cards_format | Whether the adaptive card format be used or a single text message. | Optional |
| overwrite_adaptive_card_json | JSON object used to overwrite the default adaptive card JSON. | Optional |

#### Context Output

There is no context output for this command.

## Troubleshooting
By default the message is being sent with a message template: `X Used a Workflow template to send this card`.
In order to eliminate this line you can use the following approach:

1. Navigate to Microsoft’s Power Automate portal and sign into your Microsoft Teams account where you’ve previously [set up](https://make.powerautomate.com/) the Flow.
2. Click **My flows** from the left side menu.
3. Click the newly created Flow to open its details page.
4. On the Flow’s details page, click **Save As**.
5. Give your new Flow a name and click **Save"".
6. Navigate back to **My flows** from the left side menu.
8. Find the copy Flow and click its name to access its details page.
9. On the Flow’s details page, click **Turn On**.
10. In order to find the new URL link, navigate to the **Edit** tab on the Flow’s details page.
11. Click the action task and copy the HTTP URL.
12. Configure an instance of the integration and add the copied Workflow URL for the Teams channel.