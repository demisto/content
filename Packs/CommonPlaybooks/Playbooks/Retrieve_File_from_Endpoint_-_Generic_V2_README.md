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

## Playbook Image
---
![Retrieve File from Endpoint - Generic V2](https://raw.githubusercontent.com/demisto/content/8eb0c6e3e592d9eedbcf72b025c403d44a5ba395/Packs/CommonPlaybooks/doc_files/Retrieve_File_from_Endpoint_-_Generic_V2.png)