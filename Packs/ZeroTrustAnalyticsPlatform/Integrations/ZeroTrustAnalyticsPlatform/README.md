Zero Trust Analytics Platform (ZTAP) is the underlying investigation platform and user interface for Critical Start's MDR service.
This integration was integrated and tested with version 2021-06-25 of ZeroTrustAnalyticsPlatform

## Configure ZeroTrustAnalyticsPlatform in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ZTAP server URL |  | True |
| API Key | The API Key to use for connection | True |
| Escalation Organization |  | True |
| Escalation Group |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Incident Mirroring Direction |  | False |
| Comment entry tag |  |  |
| Escalate entry tag |  |  |
| ZTAP input tag |  |  |
| Fetch attachments for comments from ZTAP |  |  |
| Sync closing incidents with ZTAP |  |  |
| Sync reopening incidents with ZTAP |  |  |
| First fetch timestamp |  | False |
| Maximum number of incidents to fetch |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-mapping-fields
***
Get mapping fields from remote incident.


#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!get-mapping-fields```

#### Human Readable Output



### get-remote-data
***
Get remote data from a remote incident. This command should only be called manually for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident id. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```
!get-remote-data id=1 lastUpdate=2000-01-1
```

#### Human Readable Output



### ztap-get-alert-entries
***
Get the entries data from a remote incident.


#### Base Command

`ztap-get-alert-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ztap-get-alert-entries id=1```

#### Human Readable Output

>```
>Example comment.
>Sent by User (test@test) via ZTAP
>```