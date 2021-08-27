This playbook returns a file sample correlating to a path into the War Room using the following sub-playbooks:
inputs:
1) Get File Sample From Path - D2.
2) Get File Sample From Path - VMware Carbon Black EDR (Live Response API).


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample From Path - D2
* Get File Sample From Path - VMware Carbon Black EDR - Live Response API

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
| UseD2 | Determines whether a D2 agent will be used to retrieve the file.<br/>Options:<br/>no \(default\)<br/>yes |  | Optional |
| Hostname | Hostname of the machine on which the file is located. |  | Optional |
| Path | The path of the file to retrieve.<br/>For example:<br/>C:\\users\\folder\\file.txt<br/> |  | Optional |
| Agent_ID | The ID of the agent in the relevant integration \(such as EDR\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Size | The size of the file. | number |
| File.Type | The type of the file. | string |
| File.Info | General information of the file.  | string |
| File.MD5 | The MD5 hash of the file. | string |
| File.SHA1 | The SHA1 hash of the file. | string |
| File.SHA256 | The SHA256 hash of the file. | string |
| File.SHA512 | The SHA512 hash of the file. | string |
| File.EntryID | The file entry ID. | string |
| File.Extension | The file extension. | string |
| File.Name | The file name. | string |
| File.SSDeep | File SSDeep. | string |

## Playbook Image
---
![Get File Sample From Path - Generic V2](https://raw.githubusercontent.com/demisto/content/8eb0c6e3e592d9eedbcf72b025c403d44a5ba395/Packs/CommonPlaybooks/doc_files/Get_File_Sample_From_Path_-_Generic_V2.png)
