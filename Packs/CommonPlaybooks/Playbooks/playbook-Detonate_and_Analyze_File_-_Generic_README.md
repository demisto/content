The playbook uploads detonates and analyzes files for supported sandboxes. Currently supported sandboxes are Falcon X and Wildfire. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Mitre Attack - Extract Technique Information From ID
* FalconX Detonate and Analyze File 
* Wildfire Detonate and Analyze File

### Integrations
This playbook does not use any integrations.

### Scripts
* IsIntegrationAvailable

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The details of the file to search for. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| csfalconx.resource.tags | Analysis tags. | string |
| csfalconx.resource.sha256 | SHA256 hash of the scanned file. | string |
| csfalconx.resource.file_name | Name of the uploaded file.  | string |
| csfalconx.resource.sandbox | Falcon X findings results. | string |
| csfalconx.resource.intel | Falcon X intelligence results. | string |
| WildFire.Report | Wildfire findings results. | string |

## Playbook Image
---
![Detonate and Analyze File - Generic](../doc_files/Detonate_and_Analyze_File_-_Generic.png)