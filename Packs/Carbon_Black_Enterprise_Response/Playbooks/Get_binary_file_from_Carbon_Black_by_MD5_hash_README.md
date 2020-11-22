This playbook retrieve binary file by MD5 hash from Carbon Black telemetry data.   

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* integration-Carbon_Black_Enterprise_Response

### Scripts
* IsIntegrationAvailable

### Commands
* cb-binary-download

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | MD5 of the binary file to be retrieved  | File.MD5 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.InternalName | The internal name. | unknown |
| File.ServerAddedTimestamp | The timestamp when the server was added. | unknown |
| File.Name | The binary name. | unknown |
| File.Extension | The binary extension. | unknown |
| File.Timestamp | The binary timestamp. | unknown |
| File.Hostname | The binary hostname. | unknown |
| File.Description | The binary description. | unknown |
| File.LastSeen | LThe lst time the binary was seen. | unknown |
| File.Path | The binary path. | unknown |
| File.ProductName | The product name. | unknown |
| File.OS | The OS. | unknown |
| File.MD5 | The MD5 hash of the binary. | unknown |
| File.Company | Name of the company that released a binary. | unknown |

## Playbook Image
---
![Get binary file from Carbon Black by MD5 hash](Insert the link to your image here)