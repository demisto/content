This playbook queries indicators based on a pre-defined query or results from a parent playbook, and adds the resulting indicators to a QRadar Reference Set. The Reference Set name must be defined in the playbook inputs.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
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
| QRadarBlackListIPReferenceSetName | The name of the QRadar black list IP reference set to insert the data to. |  | Optional |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| QRadarWhiteListIPReferenceSetName | The name of the QRadar white list IP reference set to insert the data in to. |  | Optional |
| QRadarWatchListIPReferenceSetName | The name of the QRadar watch list IP reference set to insert the data in to. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/QRadar/doc_files/TIM_-_QRadar_Add_IP_Indicators.png)