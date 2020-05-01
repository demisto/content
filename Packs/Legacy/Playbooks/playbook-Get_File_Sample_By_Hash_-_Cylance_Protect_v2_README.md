Returns a file sample to the War Room, given the file's SHA256 hash, using Cylance Protect v2 integration.

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

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| SHA256 | The SHA256 hash of the file. | SHA256 | File | Optional |
| unzip | Specifies whether the downloaded file will be unzipped. The default is 'no'. Yes will unzip automatically. No will not unzip automatically. | - | - | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Get_File_Sample_By_Hash_Cylance_Protect_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Get_File_Sample_By_Hash_Cylance_Protect_v2.png)
