'This playbook retrieves a file sample from an endpoint using the following playbooks:'
- Get File Sample From Path - Generic v2.
- Get File Sample By Hash - Generic v3.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample By Hash - Generic v3
* Get File Sample From Path - Generic V3

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
| MD5 | The MD5 hash value for the file to retrieve. |  | Optional |
| SHA256 | The SHA256 hash value for the file to retrieve. |  | Optional |
| Host | Hostname of the machine on which the file is located. |  | Optional |
| Path | The path of the file to retrieve.<br/>For example:<br/>C:\\users\\folder\\file.txt |  | Optional |
| Agent_ID | The ID of the agent in the relevant integration \(such as EDR\). |  | Optional |

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
| File.EntryID | File entry ID. | string |
| File.Extension | The file extension. | string |
| File.Name | The file name. | string |
| File.SSDeep | The file SSDeep. | string |

## Playbook Image
---
![Retrieve File from Endpoint - Generic V3](https://raw.githubusercontent.com/demisto/content/9ff8937d773367e86e5cc47ade33a90854fa291b/Packs/CommonPlaybooks/doc_files/Retrieve_File_from_Endpoint_-_Generic_V3.png)