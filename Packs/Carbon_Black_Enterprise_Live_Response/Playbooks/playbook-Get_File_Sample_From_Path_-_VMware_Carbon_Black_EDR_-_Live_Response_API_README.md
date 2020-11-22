This playbook retrieve file from endpoints by path using VMware Carbon Black EDR (Live Response API).
Make sure to provide Carbon Black sensor ID of the endpoint from which you want to retrieve the file.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* integration-Carbon_Black_Enterprise_Live_Response
* carbonblackliveresponse

### Scripts
* Exists

### Commands
* cb-list-sessions
* cb-get-file-from-endpoint
* cb-session-create
* cb-session-close

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Sensor_ID | The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically. |  | Optional |
| Path | Path of the file on the endpoint |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File  | The file to sample. | unknown |
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
![Get File Sample From Path - VMware Carbon Black EDR - Live Response API](https://raw.githubusercontent.com/demisto/content/8eb0c6e3e592d9eedbcf72b025c403d44a5ba395/Packs/Carbon_Black_Enterprise_Live_Response/doc_files/Get_File_Sample_From_Path_-_VMware_Carbon_Black_EDR_(Live_Response_API).png)