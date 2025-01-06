Integration for sending notifications to a Google Chat space via Incoming Webhook.
## Configure Google Chat via Webhook in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Google Chat Space ID | This is located in the Webhook URL as a query parameter | True |
| Google Chat Space Key | Google Chat Space Key \(found in Google Chat Webhook URL\) | True |
| Google Chat Space Key |  | True |
| Google Chat Space Token | This is located in the Webhook URL as a query parameter | True |
| Google Chat Space Token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| GoogleChatWebhook.Message.SpaceType | unknown | Google Chat space type | 
| GoogleChatWebhook.Message.SenderName | unknown | Google Chat message sender name | 
| GoogleChatWebhook.Message.ThreadReply | unknown | Determines if a message is in a thread reply | 
| GoogleChatWebhook.Message.SpaceDisplayName | unknown | Google Chat space display name | 
| GoogleChatWebhook.Message.Message | unknown | Google Chat message | 
| GoogleChatWebhook.Message.Name | unknown | Google Chat space full name | 
| GoogleChatWebhook.Message.SenderType | unknown | Google Chat message sender type | 
| GoogleChatWebhook.Message.SpaceName | unknown | Google Chat space name | 
| GoogleChatWebhook.Message.CreatedTime | unknown | Google Chat message creation time | 
| GoogleChatWebhook.Message.ThreadName | unknown | Google Chat thread name | 
| GoogleChatWebhook.Message.SenderDisplayName | unknown | Google Chat message sender display name | 

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
| GoogleChatWebhook.CustomCard.Cards | unknown | Google Chat custom card details | 
| GoogleChatWebhook.CustomCard.SpaceType | unknown | Google Chat space type | 
| GoogleChatWebhook.CustomCard.SenderName | unknown | Google Chat custom card sender name | 
| GoogleChatWebhook.CustomCard.ThreadReply | unknown | Determines if a custom card is in a thread reply | 
| GoogleChatWebhook.CustomCard.SpaceDisplayName | unknown | Google Chat space display name | 
| GoogleChatWebhook.CustomCard.Name | unknown | Google Chat space full name | 
| GoogleChatWebhook.CustomCard.SenderType | unknown | Google Chat custom card sender type | 
| GoogleChatWebhook.CustomCard.SpaceName | unknown | Google Chat space name | 
| GoogleChatWebhook.CustomCard.CreatedTime | unknown | Google Chat custom card creation time | 
| GoogleChatWebhook.CustomCard.ThreadName | unknown | Google Chat thread name | 
| GoogleChatWebhook.CustomCard.SenderDisplayName | unknown | Google Chat custom card sender display name | 