This playbook processes file indicator by tagging them with the relevant file hash type tag, such as Sha256, Sha1, and Md5.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/TIM_Processing/doc_files/TIM_-_Process_File_Indicators_With_File_Hash_Type.png)