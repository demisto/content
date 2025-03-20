This is the Hello World integration for getting started.
## Configure LineMessageAPI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LineMessageAPI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | channel_access_token | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### line-send-message

***

#### Base Command

`line-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | 接收者的 User ID 或群組 ID. | Required | 
| message | 傳送的訊息內容. | Required | 

#### Context Output

There is no context output for this command.
### line-reply-message

***

#### Base Command

`line-reply-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| replytoken | Replytoken. | Required | 
| message | 回覆的訊息內容. | Required | 

#### Context Output

There is no context output for this command.
