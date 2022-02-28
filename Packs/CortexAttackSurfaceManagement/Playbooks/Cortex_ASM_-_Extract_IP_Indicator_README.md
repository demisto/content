# Playbook to Extract IP indicators from ASM alerts and associate indicators with the alert

This playbook aims to extract the related IP address from ASM alert data and associated the newly created indicator with the alert. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
There are no sub-playbooks for this playbook.

### Integrations
There are no integrations for this playbook.

### Scripts
There are no scripts for this playbook.

### Commands
* extractIndicators
* createNewIndicator
* associateIndicatorToAlert

## Playbook Inputs
---
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AlertName | The formatted name of the alert | | Optional |


## Playbook Outputs
---
| **Name** | **Description** |
| --- | --- |
| ExtractedIndicators | outputs.extractindicators |

## Playbook Image
---
![Cortex ASM - Extract IP Indicator](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_Extract_IP_Indicator.png)