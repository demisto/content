The LINE API Integration is used for sending a message to LINE Group.

This integration was integrated and tested with LINE version 7.0.3 of LINENotify

## Configure LINENotify on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LINENotify.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Token of LINE Group | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### LINE-send-message
***
Send message/notification to LINE Group


#### Base Command

`LINE-send-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | Message to be sent. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!line-send-message messgae="Hello World" ```



