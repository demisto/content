This playbook tags indicators ingested from high reliability feeds. The playbook is triggered due to a Cortex XSOAR job. The indicators are tagged as approved_white, approved_black, approved_watchlist. The tagged indicators will be ready for consumption for 3rd party systems such as SIEM, EDR etc.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* TIM - Indicator Auto Processing

### Integrations
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
|  |  |  |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - Process Indicators - Fully Automated](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Process_Indicators_-_Fully_Automated.png)