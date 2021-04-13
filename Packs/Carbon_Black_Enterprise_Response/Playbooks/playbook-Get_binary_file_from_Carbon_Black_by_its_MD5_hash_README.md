This playbook retrieves the binary file by its MD5 hash from the Carbon Black telemetry data.   

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
integration-Carbon_Black_Enterprise_Response

### Scripts
IsIntegrationAvailable

### Commands
cb-binary-download

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | MD5 hash of the binary file to be retrieved,  | File.MD5 | Optional |

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
| File.SSDeep | The file SSDeep. | string |
| File.Name | The file name. | string |
| File.EntryID | File entry ID. | string |
| File.Extension | The file extension. | string |

## Playbook Image
---
![Get binary file from Carbon Black by its MD5 hash](https://raw.githubusercontent.com/demisto/content/8eb0c6e3e592d9eedbcf72b025c403d44a5ba395/Packs/Carbon_Black_Enterprise_Response/doc_files/Get_binary_file_from_Carbon_Black_by_MD5_hash.png)
