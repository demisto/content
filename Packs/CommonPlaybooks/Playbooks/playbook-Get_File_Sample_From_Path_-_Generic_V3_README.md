This playbook returns a file sample from a specified path and host that you input in the following playbooks:
1) PS Remote Get File Sample From Path.
2) Get File Sample From Path - VMware Carbon Black EDR (Live Response API).


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample From Path - VMware Carbon Black EDR - Live Response API
* PS Remote Get File Sample From Path

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
| Host | Hostname of the machine on which the file is located, for PS remote it can also be an IP address. |  | Optional |
| Path | The path of the file to retrieve.<br/>For example:<br/>C:\\users\\folder\\file.txt<br/> |  | Optional |
| Agent_ID | The ID of the agent, or of the endpoint, in the relevant integration \(such as EDR\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Size | The size of the file. | number |
| File.Type | The type of the file. | string |
| File.Info | General information of the file. | string |
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
![Get File Sample From Path - Generic V3](https://raw.githubusercontent.com/demisto/content/9ff8937d773367e86e5cc47ade33a90854fa291b/Packs/CommonPlaybooks/doc_files/Get_File_Sample_From_Path_-_Generic_V3.png)