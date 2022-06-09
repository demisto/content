Fetch reports from Cisco Umbrella that provides visibility into your core network and security activities and Umbrella logs.
This integration was integrated and tested with version 2 of Cisco Umbrella Reporting APIs

## Configure Cisco Umbrella Reporting on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Umbrella Reporting.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Cisco Token URL | True |
    | Organization ID | True |
    | Cisco Reporting v2 URL | True |
    | API Key | True |
    | API Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### umbrella-get-summary
***
Get a summary of top identities, destinations, URLs, categories, threats, threat types, events and IPs being observed in your organization within a specific timeframe.


#### Base Command

`umbrella-get-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | A timestamp or relative time string (for example: -1days). Filter for data that appears after this time. | Required | 
| to | A timestamp or relative time string (for example: now).Filter for data that appears before this time. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.Summary | Dict | Summary of activity observed | 

### umbrella-list-top-threats
***
List top threats within timeframe. Returns both DNS and Proxy data.


#### Base Command

`umbrella-list-top-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from | A timestamp or relative time string (for example: -1days). Filter for data that appears after this time. | Required | 
| to | A timestamp or relative time string (for example: now).Filter for data that appears before this time. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaReporting.TopThreats.threat | String | Threat name | 
| UmbrellaReporting.TopThreats.threattype | String | Threat Type | 
| UmbrellaReporting.TopThreats.count | Number | Threat Count | 
