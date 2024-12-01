This playbook queries indicators based on a pre-defined query or results from a parent playbook, and adds the resulting indicators to a QRadar Reference Set. The Reference Set name must be defined in the playbook inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* QRadar_v2
* QRadar

### Scripts
This playbook does not use any scripts.

### Commands
* qradar-update-reference-set-value
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| QRadarBlackListDomainReferenceSetName | The name of the QRadar block list Domain reference set to insert the data to. |  | Optional |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| QRadarWhiteListDomainReferenceSetName | The name of the QRadar allow list Domain reference set to insert the data in to. |  | Optional |
| QRadarWatchListDomainReferenceSetName | The name of the QRadar allow list Domain reference set to insert the data in to. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](../doc_files/TIM_-_QRadar_Add_Domain_Indicators.png)