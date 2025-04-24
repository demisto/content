The Cortex Core - IOCs integration uses the Cortex API for detection and response, by natively integrating network, endpoint, and cloud data to stop sophisticated attacks.

## Configure Indicators detection


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) |  | False |
| API Key ID |  | False |
| API Key |  | False |
| Cortex XDR Severity | Map the severity of each indicator that will be synced to Cortex. | True |
| Tags | Supports CSV values. | False |
| Sync Query | The query used to collect indicators to sync from Cortex. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### core-iocs-sync
***
Sync your IOC with Cortex and delete the previous version.


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
Push modified IOCs to Cortex.


#### Base Command

`core-iocs-push`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | IOCs to push. leave empty to push all recently modified IOCs.the indicators. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!core-iocs-push indicator='test.com'```
#### Human Readable Output

>push done.

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
Creates the sync file for the manual process. Run this command when instructed by the Cortex support team.


#### Base Command

`core-iocs-create-sync-file`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### core-iocs-enable
***
Enables IOCs in the Cortex server.


#### Base Command

`core-iocs-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to enable. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!core-iocs-enable indicator=11.11.11.11```
#### Human Readable Output

>indicators 11.11.11.11 enabled.

### core-iocs-disable
***
Disables IOCs in the Cortex server.


#### Base Command

`core-iocs-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to disable. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!core-iocs-disable indicator=22.22.22.22```
#### Human Readable Output

>indicators 22.22.22.22 disabled.