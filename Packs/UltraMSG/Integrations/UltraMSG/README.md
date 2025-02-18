This is the UltraMSG integration for getting started made by Trustnet
## Configure UltraMSG in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Token | When creating an instance, you'll get a token Example: ty37deadbeef37xx | True |
| Instance | When creating an instance, you'll get an instance id. Example: instance12345 | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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