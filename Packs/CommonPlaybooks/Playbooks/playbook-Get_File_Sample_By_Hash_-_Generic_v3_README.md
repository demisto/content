This playbook returns a file sample correlating to a hash in the war-room using the following sub-playbooks:
- Get binary file by MD5 hash from Carbon Black telemetry data. - VMware Carbon Black EDR v2.
- Get the threat (file) attached to a specific SHA256 hash- Cylance Protect v2.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get binary file from Carbon Black by MD5 hash
* Get File Sample By Hash - Cylance Protect v2

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
| MD5 | Get file sample from MD5 input |  | Optional |
| SHA256 | Get file sample from SHA256 input |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | File sample object | unknown |
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
![Get File Sample By Hash - Generic v3](Insert the link to your image here)