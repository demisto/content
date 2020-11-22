This playbook returns a file sample correlating to a path into the war-room using the following sub-playbooks:
inputs:
1) Get File Sample From Path - D2.
2) Get File Sample From Path - VMware Carbon Black EDR (Live Response API).


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample From Path - VMware Carbon Black EDR - Live Response API
* Get File Sample From Path - D2

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UseD2 | Determines whether a D2 agent will be used to retrieve the file.<br/>Default is no. |  | Optional |
| Hostname | Hostname of the machine on which the file is located. |  | Optional |
| Path | File path. |  | Optional |
| Sensor_ID | Carbon Black sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The file to sample. | unknown |
| CbLiveResponse.File.Size | File size. | unknown |
| CbLiveResponse.File.SHA1 | File SHA1. | unknown |
| CbLiveResponse.File.SHA256 | File SHA256. | unknown |
| CbLiveResponse.File.Name | File name. | unknown |
| CbLiveResponse.File.SSDeep | File SSDeep. | unknown |
| CbLiveResponse.File.EntryID | File EntryID. | unknown |
| CbLiveResponse.File.Info | File info. | unknown |
| CbLiveResponse.File.Type | File type. | unknown |
| CbLiveResponse.File.MD5 | File MD5. | unknown |
| CbLiveResponse.File.Extension | File extension. | unknown |

## Playbook Image
---
![Get File Sample From Path - Generic V2](https://raw.githubusercontent.com/demisto/content/8eb0c6e3e592d9eedbcf72b025c403d44a5ba395/Packs/CommonPlaybooks/doc_files/Get_File_Sample_From_Path_-_Generic_V2.png)