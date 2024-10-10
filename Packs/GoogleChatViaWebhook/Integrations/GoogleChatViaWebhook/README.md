Integration for sending notifications to a Google Chat space via Incoming Webhook.
## Configure Google Chat via Webhook on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Chat via Webhook.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Google Chat Space ID | This is located in the Webhook URL as a query parameter | True |
    | Google Chat Space Key | Google Chat Space Key \(found in Google Chat Webhook URL\) | True |
    | Google Chat Space Key |  | True |
    | Google Chat Space Token | This is located in the Webhook URL as a query parameter | True |
    | Google Chat Space Token |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### send-google-chat-message

***
Send a message to Google Chat Space via Incoming Webhook.

#### Base Command

`send-google-chat-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message to send.  For example: "This is a message from Cortex XSOAR". Default is None. | Required | 
| threadName | If replying to a thread, use this argument to specify the thread name to reply to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChatWebhook.Message.Name | unknown | Google Chat space name | 
| GoogleChatWebhook.Message.Message | unknown | Google Chat message that was sent | 
| GoogleChatWebhook.Message.ThreadName | unknown | Google Chat message thread name | 
| GoogleChatWebhook.Message.Space | unknown | Google Chat space name | 

### send-google-chat-custom-card

***
Send a customizable card to Google Chat Space via Incoming Webhook

#### Base Command

`send-google-chat-custom-card`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| blocks | JSON blocks copied from https://addons.gsuite.google.com/uikit/builder. | Required | 
| threadName | If replying to a thread, use this argument to specify the thread name to reply to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChatWebhook.CustomCard.Name | unknown | Google Chat custom card name | 
| GoogleChatWebhook.CustomCard.SpaceName | unknown | Google Chat space name | 
| GoogleChatWebhook.CustomCard.Thread | unknown | Google Chat custom card thread name | 