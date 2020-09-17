This playbook searches for files via Code42 security events by either MD5 or SHA256 hash. The data is output to the Code42.SecurityData context for use.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Code42

### Scripts
This playbook does not use any scripts.

### Commands
* code42-securitydata-search
* code42-download-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | MD5 hash to search for | File.MD5 | Optional |
| SHA256 | SHA256 hash to search for | File.SHA256 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Size | File size in bytes | unknown |
| File.SHA1 | The SHA1 hash of the file. | unknown |
| File.SHA256 | SHA256 hash of file | unknown |
| File.Name | File name | unknown |
| File.SSDeep | The SSDeep hash of the file. | unknown |
| File.EntryID | The entry ID of the file. | unknown |
| File.Info | File information. | unknown |
| File.Type | The file type. | unknown |
| File.MD5 | The MD5 hash of the file. | unknown |
| File.Extension | The file extension. | unknown |

## Playbook Image
---
![Code42 Exfiltration Playbook](https://raw.githubusercontent.com/demisto/content/dd418027433970a18ce06ebef97933c70a92a940/Packs/Code42/doc_files/Code42_File_Download.png)