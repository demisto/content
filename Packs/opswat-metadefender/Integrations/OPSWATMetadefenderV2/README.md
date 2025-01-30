multi-scanning engine uses 30+ anti-malware engines to scan files for threats, significantly increasing malware detection.
This integration was integrated and tested with version 5.0.0 of OPSWAT-Metadefender V2.

## Configure OPSWAT-Metadefender v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. http://localhost:8008/metascan_rest/) | True |
| API Key - Needed in cloud based solutions | False |
| API Key - Needed in cloud based solutions | False |
| Cloud based | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| The high threshold | False |
| The low threshold | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### opswat-scan-file

***
Scan file in OPSWAT

#### Base Command

`opswat-scan-file fileId=1191@302`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileId | Entry id of a file in XSOAR. | Required | 
| scanRule | Name of the Rule to use for scanning (Optional). | Optional | 

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
### opswat-sanitization-result

***
Get OPSWAT sanitization result (Requires CDR feature).
In order to have sanitized versions of the file, the DeepCDR feature needs to be enabled in the Workflow rule used for scanning the file.

#### Base Command

`opswat-sanitization-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | OPSWAT scan id. | Required | 

#### Context Output

There is no context output for this command.