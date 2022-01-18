Use the Cortex XDR - IOCs feed integration to sync indicators from Cortex XSOAR to Cortex XDR and back to Cortex XSOAR. Cortex XDR is the world's first detection and response app that natively integrates network, endpoint and cloud data to stop sophisticated attacks.
This integration was integrated and tested with version xx of Cortex Core - IOC

## Configure Indicators detection on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Indicators detection.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://example.net) |  | True |
    | API Key ID |  | True |
    | API Key |  | True |
    | Fetch indicators |  | False |
    | Auto Sync | When enabled, indicators will be synced from Cortex XSOAR to Cortex XDR. Disable if you prefer to use a playbook to sync indicators. | False |
    | Cortex XDR Severity | Map the severity of each indicator that will be synced to Cortex XDR. | True |
    | Tags | Supports CSV values. | False |
    | Sync Query | The query used to collect indicators to sync from Cortex XSOAR to Cortex XDR. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    |  |  | False |
    |  |  | False |
    | Incremental Feed |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### core-iocs-sync
***
Sync your IOC with Cortex XDR and delete the old.


#### Base Command

`core-iocs-sync`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstTime | For first sync, set to true.<br/>(do NOT run this twice!). Possible values are: true, false. Default is false. | Optional | 


#### Context Output

There is no context output for this command.
### core-iocs-push
***
Push modified IOCs to Cortex XDR.


#### Base Command

`core-iocs-push`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | IOCs to push. leave empty to push all recently modified IOCs.the indicators. | Optional | 


#### Context Output

There is no context output for this command.
### core-iocs-set-sync-time
***
Set sync time manually (Do not use this command unless you unredstandard the consequences).


#### Base Command

`core-iocs-set-sync-time`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time | The time of the file creation (use UTC time zone). | Required | 


#### Context Output

There is no context output for this command.
### core-iocs-create-sync-file
***
Creates the sync file for the manual process. Run this command when instructed by the XDR support team.


#### Base Command

`core-iocs-create-sync-file`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### core-iocs-enable
***
Enables IOCs in the XDR server.


#### Base Command

`core-iocs-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to enable. | Required | 


#### Context Output

There is no context output for this command.
### core-iocs-disable
***
Disables IOCs in the XDR server.


#### Base Command

`core-iocs-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to disable. | Required | 


#### Context Output

There is no context output for this command.