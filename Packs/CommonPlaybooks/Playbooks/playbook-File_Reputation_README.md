This playbook checks the file reputation and sets the verdict as a new context key.

The verdict is composed by 3 main components:

* VirusTotal detection rate
* Digital certificate signers
* NSRL DB

Note: a user can provide a list of trusted signers of his own using the playbook inputs
 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* http
* ParseJSON
* Set

### Commands
* file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DetectionThreshold | The minimum number of positive engines needed to mark file as malicious. | 5 | Optional |
| TrustedPublishers | A list of trusted publishers | Microsoft Root Authority,Microsoft Timestamping Service,<br/>Microsoft Code Signing PCA, Microsoft Corporation | Optional |
| FileSHA256 | The file SHA256. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VTFileVerdict | VirusTotal file verdict. | unknown |
| NSRLFileVerdict | NSRL file verdict. | unknown |
| VTFileSigners | VirusTotal file signers. | unknown |
| XDRFileSigners | XDR file signers. | unknown |

## Playbook Image
---
![File Reputation](https://raw.githubusercontent.com/demisto/content/48a7f1a1a628a2755201c55c24bc68d94e0dd49c/Packs/CommonPlaybooks/doc_files/File_Reputation.png)