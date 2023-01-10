This is the UltraMSG integration for getting started made by Trustnet
## Configure UltraMSG on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for UltraMSG.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Token | When creating an instance, you'll get a token Example: ty37deadbeef37xx | True |
    | Instance | When creating an instance, you'll get an instance id. Example: instance12345 | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### send-whatsapp
***
Send WhatsApp Message


#### Base Command

`send-whatsapp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Phone Number or Group ID. Example: +972501234567. | Required | 
| text | Message Body. | Required | 


#### Context Output

There is no context output for this command.