Retrieve files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints.
Retrieves files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints.
Inputs for this playbook are:
- A comma-separated list of endpoint IDs.
- A comma-separated list of file paths for your operating system, either Windows, Linux, or Mac. At least one file path is required.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Cortex XDR - IR

### Scripts
* PrintErrorEntry

### Commands
* xdr-retrieve-files
* xdr-retrieve-file-details

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. |  | Required |
| windows_file_paths | A comma-separated list of Windows paths. Enter at least one path for either Windows, Linux, or Mac. |  | Optional |
| linux_file_paths | A comma-separated list of Linux paths. Enter at least one path for either Windows, Linux, or Mac. |  | Optional |
| mac_file_paths | A comma-separated list of Mac paths. Enter at least one path for either Windows, Linux, or Mac. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | Retrieves the file details command results. | unknown |
| File.Name | The full file name \(including file extension\). | String |
| File.EntryID | The ID for locating the file in the War Room. | String |
| File.Size | The size of the file in bytes. | Number |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.Extension | The file extension. For example, 'xls'. | String |
| File.Type | The file type, as determined by libmagic \(same as displayed in file entries\). | String |

## Playbook Image
---
![Cortex XDR - Retrieve File Playbook](https://raw.githubusercontent.com/demisto/content/0b71472b92a1bfa604215334b27c49a40c0260dd/Packs/CortexXDR/doc_files/Cortex%20XDR%20-%20Retrieve%20File%20Playbook.png)
