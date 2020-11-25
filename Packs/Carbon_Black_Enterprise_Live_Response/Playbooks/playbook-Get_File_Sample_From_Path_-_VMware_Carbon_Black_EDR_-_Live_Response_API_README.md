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
* cb-session-close
* cb-session-create
* cb-get-file-from-endpoint

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Sensor_ID | The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically. |  | Optional |
| Path | The path of the file to retrieve.<br/>For example:<br/>C:\\users\\folder\\file.txt |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File  | The file to sample. | string |
| CbLiveResponse.File.Size | File size. | number |
| CbLiveResponse.File.SHA1 | File SHA1. | string |
| CbLiveResponse.File.SHA256 | File SHA256. | string |
| CbLiveResponse.File.Name | File name. | string |
| CbLiveResponse.File.SSDeep | File SSDeep. | string |
| CbLiveResponse.File.EntryID | File EntryID. | string |
| CbLiveResponse.File.Info | File info. | string |
| CbLiveResponse.File.Type | File type. | string |
| CbLiveResponse.File.MD5 | File MD5. | string |
| CbLiveResponse.File.Extension | File extension. | string |

## Playbook Image
---
![Get File Sample From Path - VMware Carbon Black EDR - Live Response API](https://raw.githubusercontent.com/demisto/content/8eb0c6e3e592d9eedbcf72b025c403d44a5ba395/Packs/Carbon_Black_Enterprise_Live_Response/doc_files/Get_File_Sample_From_Path_-_VMware_Carbon_Black_EDR_(Live_Response_API).png)