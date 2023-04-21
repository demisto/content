multi-scanning engine uses 30+ anti-malware engines to scan files for threats, significantly increasing malware detection.
This integration was integrated and tested with version 5.0.0 of OPSWAT-Metadefender V2.

## Configure OPSWAT-Metadefender v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OPSWAT-Metadefender v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. http://localhost:8008/metascan_rest/) | True |
    | API Key - Needed in cloud based solutions | False |
    | Cloud based | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | The high threshold | False |
    | The low threshold | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opswat-scan-file
***
Scan file in OPSWAT


#### Base Command

`opswat-scan-file fileId=1191@302`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileId | Entry id of a file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OPSWAT.FileName | string | OPSWAT file name to scan | 
| OPSWAT.ScanId | string | OPSWAT scan id of the scan | 

### opswat-hash
***
Check file hash on OPSWAT


#### Base Command

`opswat-hash hash=cc273fe9d442850fa18c31c88c823e07`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | File hash (Can be any hash type). | Required | 


#### Context Output

There is no context output for this command.
### opswat-scan-result
***
Get OPSWAT result


#### Base Command

`opswat-scan-result id=123`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | OPSWAT scan id. | Required | 


#### Context Output

There is no context output for this command.
