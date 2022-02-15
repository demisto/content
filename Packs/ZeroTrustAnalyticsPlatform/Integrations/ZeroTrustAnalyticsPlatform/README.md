Zero Trust Analytics Platform (ZTAP) is the underlying investigation platform and user interface for CriticalStart's MDR service.
This integration was integrated and tested with version 2021-06-25 of ZeroTrustAnalyticsPlatform

## Configure ZeroTrustAnalyticsPlatform on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ZeroTrustAnalyticsPlatform.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
>{
>    "contents": "Example comment.",
>    "files": [],
>    "occurred": "2021-10-28T18:57:01Z",
>    "type": "comment"
>}
>```
