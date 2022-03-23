This playbook checks the file reputation and sets the verdict as a new context key.

The verdict contains three main components:

* VirusTotal detection rate
* Digital certificate signers
* NSRL DB

**Note:** A user can provide a list of trusted signers of his own using the playbook inputs.
 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* http
* Set
* ParseJSON

### Commands
***file***

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DetectionThreshold | The minimum number of positive engines needed to mark file as malicious. | 5 | Optional |
| TrustedPublishers | A list of trusted publishers | Microsoft Root Authority,Microsoft Timestamping Service,<br/>Microsoft Code Signing PCA, Microsoft Corporation | Optional |
| FileSHA256 |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VTFileVerdict |  | unknown |
| NSRLFileVerdict |  | unknown |
| VTFileSigners |  | unknown |
| XDRFileSigners |  | unknown |

## Playbook Image
---
![File Reputation](https://raw.githubusercontent.com/demisto/content/7df4a9f44ec165fd2ada5db51510745f12518296/Packs/CommonPlaybooks/doc_files/File_Reputation.png)
