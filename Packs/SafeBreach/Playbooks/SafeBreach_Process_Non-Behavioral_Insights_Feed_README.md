This playbook automatically remediates all non-behavioral indicators generated from SafeBreach Insights. To validate the remediation, it reruns the related insights and classifies the indicators as Remediated or Not Remediated.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block Indicators - Generic v2
* SafeBreach Compare and Tag Insight Indicators (draft)
* SafeBreach - Rerun Insights (draft)

### Integrations
* SafeBreach_v2

### Scripts
* Set
* Sleep

### Commands
* safebreach-get-insights
* safebreach-get-remediation-data

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
![SafeBreach - Process Non-Behavioral Insights Feed](Insert the link to your image here)