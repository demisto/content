This playbook automatically remediates all non-behavioral indicators generated from SafeBreach Insights. To validate the remediation, it reruns the related insights and classifies the indicators as Remediated or Not Remediated.
A special feed based triggered job is required to initiate this playbook for every new SafeBreach generated indicator.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* SafeBreach - Compare and Validate Insight Indicators
* SafeBreach - Rerun Insights
* Block Indicators - Generic v2
* SafeBreach - Create Incidents per Insight and Associate Indicators

### Integrations
* SafeBreach_v2

### Scripts
* Sleep
* Set

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
![SafeBreach - Process Non-Behavioral Insights Feed](https://github.com/demisto/content/raw/6af01e00312a5558e9e2fecdb22534e98414bc9c/Packs/SafeBreach/doc_imgs/SafeBreach_Process_Non-Behavioral_Insights_Feed.png)