Returns a file sample correlating to SHA256 hashes to the War Room, in the inputs using Cylance Protect integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cylance Protect v2
* Cylance Protect

### Scripts
* UnzipFile
* Exists
* http

### Commands
* cylance-protect-download-threat

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| SHA256 | The SHA256 hash of the file to download. | SHA256 | File | Optional |
| ZipPassword | The password for the zip file. | infected | - | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The sample file. | unknown |


![Get_File_Sample_By_Hash_Cylance_Protect](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Get_File_Sample_By_Hash_Cylance_Protect.png)
