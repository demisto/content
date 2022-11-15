[Enter a comprehensive, yet concise, description of what the integration does, what use cases it is designed for, etc.]
This integration was integrated and tested with version v1.0.0 of BaseIntegration

## Configure Starter Base Integration - Name the integration as it will appear in the XSOAR UI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Starter Base Integration - Name the integration as it will appear in the XSOAR UI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### baseintegration-dummy
***
[Enter a description of the command, including any important information users need to know, for example required permissions.]


#### Base Command

`baseintegration-dummy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dummy | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BaseIntegration.Output | String | \[Enter a description of the data returned in this output.\] | 
