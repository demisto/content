## Binalyze AIR Integration
This integration allows you to use the Binalyze AIR's isolation and evidence collecting features easily.
---

Collect your forensics data under 10 minutes.
This integration was integrated and tested with version 2.6.2 of Binalyze AIR

## Configure Binalyze AIR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Binalyze AIR.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the URLs, token, and connection.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Binalyze AIR Server URL | Binalyze AIR Server URL | True |
    | API Key | e.g.: api_1234567890abcdef1234567890abcdef | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
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
| hostname | Hostname of endpoint. | Required |
| organization_id | Organization ID of the endpoint. Possible values are: 0, 1, 2. | Required |
| isolation | To isolate use enable. Possible values are: enable, disable. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Isolate.result._id | string | Isolation unique task ID |
| BinalyzeAIR.Isolate.result.name | string | Isolation task name |
| BinalyzeAIR.Isolate.result.organizationId | number | Organization Id of endpoint |

### binalyze-air-acquire
***
Acquire evidence from an endpoint


#### Base Command

`binalyze-air-acquire`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname of endpoint. | Required |
| profile | Acquisition profile. Possible values are: compromise-assessment, browsing-history, event-logs, memory-ram-pagefile, quick, full. | Required |
| case_id | ID for the case,e.g. C-2022-0001. | Required |
| organization_id | Organization ID of the endpoint. Possible values are: 0, 1, 2. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BinalyzeAIR.Acquire.result._id | string | Acquisition unique task ID |
| BinalyzeAIR.Acquire.result.name | string | Acquisiton task name |
| BinalyzeAIR.Acquire.result.organizationId | number | Organization Id of endpoint |