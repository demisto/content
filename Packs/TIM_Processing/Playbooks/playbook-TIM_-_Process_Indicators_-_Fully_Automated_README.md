This playbook tags indicators ingested from high reliability feeds. The playbook is triggered due to a Cortex XSOAR job. The indicators are tagged as approved_allow, approved_block, approved_watchlist. The tagged indicators will be ready for consumption for 3rd party systems such as SIEM, EDR etc.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* TIM - Indicator Auto Processing

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
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/TIM_Processing/doc_files/TIM_-_Process_Indicators_-_Fully_Automated.png)
