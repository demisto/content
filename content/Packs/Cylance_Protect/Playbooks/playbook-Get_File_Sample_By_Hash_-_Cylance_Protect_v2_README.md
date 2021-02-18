This playbook returns a file sample to the War Room given the file's SHA256 hash, using Cylance Protect v2 integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cylance Protect v2

### Scripts
This playbook does not use any scripts.

### Commands
* cylance-protect-download-threat

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SHA256 |  | File.SHA256 | Optional |
| unzip | Specifies whether the downloaded file will be unzipped. The command default is 'no'.<br/>Yes - unzip automatically<br/>No - will not unzip |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.SHA256 | SHA256 hash of the file. | unknown |
| File.Name | File name. | unknown |
| File.Size | File size. | unknown |
| File.Safelisted | Whether the file is on the Safe List. | unknown |
| File.Timestamp | Timestamp. | unknown |
| File.MD5 | MD5 hash of the file. | unknown |

## Playbook Image
---
![Get File Sample By Hash - Cylance Protect v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Get_File_Sample_By_Hash_Cylance_Protect_v2.png)
