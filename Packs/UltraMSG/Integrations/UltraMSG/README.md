This is the UltraMSG integration for getting started made by Trustnet
## Configure UltraMSG on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for UltraMSG.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Token | When you creating an Instamce you'll get an Token Example: ty49xcwlhiogro9x | True |
    | Instance | When you creating an Instamce you'll get an instance id. Example: instance12345 | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### send-whatapp
***
 


#### Base Command

`send-whatapp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Phone Number (With Country Code) or Group Id. Example: +972501234567. | Required | 
| text | Free text. | Required | 


#### Context Output

There is no context output for this command.