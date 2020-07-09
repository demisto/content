This playbook triggers automated remediation for all non-behavioral  indicators generated from SafeBreach Insights. Then it reruns related insights and classifies the indicators as Remediated or Not Remediated post validation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* SafeBreach - Compare and Validate Insight Indicators (draft)
* Block Indicators - Generic v2
* SafeBreach - Rerun Insights (draft)

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* Sleep

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | sourceBrands:["SafeBreach*"] and -safebreachisbehavioral:T | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![SafeBreach - Process Non-Behavioral Insights Feed (draft)](Insert the link to your image here)