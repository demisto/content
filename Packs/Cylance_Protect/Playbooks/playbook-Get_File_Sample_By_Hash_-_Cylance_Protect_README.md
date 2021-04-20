Returns to the war-room a file sample correlating to SHA256 hashes in the inputs using Cylance Protect integration

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Cylance Protect
* Cylance Protect v2

### Scripts
* UnzipFile
* http
* Exists

### Commands
* cylance-protect-download-threat

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SHA256 | The SHA256 hash of the file we want to download | File.SHA256 | Optional |
| ZipPassword | The password for the zip file | infected | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File | The sample file | unknown |

## Playbook Image
---
![Get File Sample By Hash - Cylance Protect](Insert the link to your image here)