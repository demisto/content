[This integration is used to execute Actions like LogOff User, Start Session Recording, Disable User, etc in Citrix Virtual Apps & Desktop.]
This integration was integrated and tested with version 1 of CitrixAnalyticsActions

## Configure Citrix Analytics Actions on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Citrix Analytics Actions.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Citrix Cloud Token URL | True |
    | Citrix Cloud Client ID | True |
    | Citrix Cloud Client Secret | True |
    | Citrix Analytics Actions API URL | True |
    | Citrix Cloud Customer ID | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### baseintegration-executeCASAction
***
Executes an Action in Citrix Analytics


#### Base Command

`baseintegration-executeCASAction`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cas_user_id | CAS User ID. This can be samAccountName, email address, etc. | Required | 
| action_reason | Reason for executing Action in CAS. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BaseIntegration.Output | String | \[Enter a description of the data returned in this output.\] | 
