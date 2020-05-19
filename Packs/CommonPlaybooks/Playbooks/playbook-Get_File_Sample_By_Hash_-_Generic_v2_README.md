Returns a file sample correlating to a hash in the War Room using the following sub-playbooks:
- Get File Sample By Hash - Carbon Black Enterprise Response
- Get File Sample By Hash - Cylance Protect v2

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Get File Sample By Hash - Cylance Protect v2
* Get File Sample By Hash - Carbon Black Enterprise Response

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| MD5 | Returns the file sample from the MD5 hash input file. | MD5 | File | Optional |
| SHA256 | Returns the file sample from the SHA256 hash input file. | SHA256 | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The file sample object, | unknown |

## Playbook Image
---
![Get_File_Sample_By_Hash_Generic_v2](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Get_File_Sample_By_Hash_Generic_v2.png)
