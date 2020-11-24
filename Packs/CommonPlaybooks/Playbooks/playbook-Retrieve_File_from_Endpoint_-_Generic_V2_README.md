This playbook retrieves a file sample from an endpoint using the following playbooks:
- Get File Sample From Path - Generic v2.
- Get File Sample By Hash - Generic v3.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample From Path - Generic V2
* Get File Sample By Hash - Generic v3

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
| MD5 | Get file sample from MD5 input. |  | Optional |
| SHA256 | Get file sample from SHA256 input. |  | Optional |
| Hostname | Hostname of the machine on which the file is located. |  | Optional |
| Path | File path. |  | Optional |
| UseD2 | Determines whether a D2 agent will be used to retrieve the file.<br/>Default is no. |  | Optional |
| Sensor ID | The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | File sample object | unknown |
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
| File.SHA256 | SHA256 hash of the file. | unknown |
| File.Name | File name. | unknown |
| File.Size | File size. | unknown |
| File.Safelisted | Whether the file is on the Safe List. | unknown |
| File.Timestamp | Timestamp. | unknown |
| File.MD5 | MD5 hash of the file. | unknown |
| File.Company | Name of the company that released a binary. | unknown |
| File.OS | The OS. | unknown |
| File.ProductName | The product name. | unknown |
| File.Path | The binary path. | unknown |
| File.LastSeen | LThe lst time the binary was seen. | unknown |
| File.Description | The binary description. | unknown |
| File.Hostname | The binary hostname. | unknown |
| File.Extension | The binary extension. | unknown |
| File.ServerAddedTimestamp | The timestamp when the server was added. | unknown |
| File.InternalName | The internal name. | unknown |

## Playbook Image
---
![Retrieve File from Endpoint - Generic V2](Insert the link to your image here)