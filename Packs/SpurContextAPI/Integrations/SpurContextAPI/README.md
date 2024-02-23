Enrich indicators using the Spur Context API.
This integration was integrated and tested with version v2 of SpurContextAPI.

## Configure SpurContextAPI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SpurContextAPI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Token | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### spur-context-api-enrich

***
Enrich an IP address with the Spur Context API

#### Base Command

`spur-context-api-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpurContextAPI.Context.ip | string |  | 
| SpurContextAPI.Context.as | unknown |  | 
| SpurContextAPI.Context.organization | string |  | 
| SpurContextAPI.Context.infrastructure | string |  | 
| SpurContextAPI.Context.location | unknown |  | 
| SpurContextAPI.Context.services | unknown |  | 
| SpurContextAPI.Context.tunnels | unknown |  | 
| SpurContextAPI.Context.risks | unknown |  | 
| SpurContextAPI.Context.client_concentration | number |  | 
| SpurContextAPI.Context.client_countries | unknown |  | 
| SpurContextAPI.Context.client_spread | number |  | 
| SpurContextAPI.Context.client_proxies | unknown |  | 
| SpurContextAPI.Context.client_count | number |  | 
| SpurContextAPI.Context.client_behaviors | unknown |  | 
| SpurContextAPI.Context.client_types | unknown |  | 
