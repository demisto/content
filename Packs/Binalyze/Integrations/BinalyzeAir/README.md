Collect your forensics data under 10 minutes.
This integration was integrated and tested with version xx of Binalyze AIR

## Configure Binalyze AIR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Binalyze AIR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | AIR SERVER URL | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### binalyze-air-isolate
***
Isolate an endpoint


#### Base Command

`binalyze-air-isolate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | Hostname of endpoint. | Required | 
| organization_id | Organization ID of the endpoint. Possible values are: 0, 1, 2. Default is 0. | Required | 
| isolation | To isolate use enable. Possible values are: enable, disable. | Required | 


#### Context Output

There is no context output for this command.
### binalyze-air-acquire
***
Acquire evidence from an endpoint


#### Base Command

`binalyze-air-acquire`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | Hostname of endpoint. | Required | 
| profile | Acquisition profile. Possible values are: compromise-assessment, browsing-history, event-logs, memory-ram-pagefile, quick, full. | Required | 
| caseid | ID for the case,e.g. Acquisition Case 2022-001. Default is C-2022-0001. | Required | 
| organization_id | Organization ID of the endpoint. Possible values are: 0, 1, 2. Default is 0. | Required | 


#### Context Output

There is no context output for this command.