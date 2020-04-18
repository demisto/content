This playbook queries indicators based on a pre-defined query or results from a parent playbook, and adds the resulting indicators to a QRadar Reference Set. The Reference Set name must be defined in the playbook inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* appendIndicatorField
* qradar-update-reference-set-value

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| QRadarBlackListDomainReferenceSetName | The name of the QRadar black list Domain reference set to insert the data to. |  |  | Optional |
|  |  |  |  | Optional |
| QRadarWhiteListDomainReferenceSetName | The name of the QRadar white list Domain reference set to insert the data in to. |  |  | Optional |
| QRadarWatchListDomainReferenceSetName | The name of the QRadar watch list Domain reference set to insert the data in to. |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - QRadar Add Domain Indicators](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_QRadar_Add_Domain_Indicators.png)