The playbook uploads detonates and analyzes files for FalconX.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* CrowdStrikeFalconX

### Scripts
* IsIntegrationAvailable
* Set

### Commands
* cs-fx-upload-file
* cs-fx-submit-uploaded-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The details of the file to detonate. |  | Optional |
| AlertOS | The operating system for which the alert was raised.<br/>accepted values are Windows, Linux, Android<br/><br/>.. | ${incident.sourceosversion} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| csfalconx.resource.tags | Analysis tags. | unknown |
| csfalconx.resource.sha256 | SHA256 hash of the scanned file. | unknown |
| csfalconx.resource.file_name | Name of the uploaded file.  | unknown |
| csfalconx.resource.sandbox | Falcon X findings results. | unknown |
| csfalconx.resource.intel | Falcon X intelligence results. | unknown |

## Playbook Image
---
![FalconX Detonate and Analyze File](../doc_files/FalconX_Detonate_and_Analyze.png)