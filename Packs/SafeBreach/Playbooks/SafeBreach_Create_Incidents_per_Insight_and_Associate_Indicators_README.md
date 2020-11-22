This is a sub-playbook that creates incidents per SafeBreach insight, enriched with all the related indicators and additional SafeBreach insight contextual information. Used in main SafeBreach playbooks, such as "SafeBreach - Process Behavioral Insights Feed" and "SafeBreach - Process Non-Behavioral Insights Feed".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeBreach_v2

### Scripts
* Set
* SearchIncidentsV2

### Commands
* associateIndicatorToIncident
* safebreach-get-insights
* createNewIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | safebreachisbehavioral:T | Optional |
| insightIds | List of Insight ids to create incidents for. |  | Required |
| indicators | List of indicators that to be assigned to created incidents |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| incident | Incidents created from SafeBreach Insights | Array |

## Playbook Image
---
![SafeBreach - Create Incidents per Insight and Associate Indicators](https://github.com/demisto/content/raw/6af01e00312a5558e9e2fecdb22534e98414bc9c/Packs/SafeBreach/doc_imgs/SafeBreach_Create_Incidents_per_Insight_and_Associate_Indicators.png)