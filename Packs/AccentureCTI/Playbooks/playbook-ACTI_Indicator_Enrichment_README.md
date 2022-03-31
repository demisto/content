This playbook enriches indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* ACTI Indicator Query

### Scripts
* Exists

### Commands
* ip
* domain
* url

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP_Pre_Enrich | The extracted IP. | ${ExtractedIndicators.IP} | Optional |
| Domain_Pre_Enrich | The extracted Domain. | ${ExtractedIndicators.Domain} | Optional |
| URL_Pre_Enrich | The extracted URL. | ${ExtractedIndicators.URL} | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The enriched IP. | unknown |
| DBotScore | DBotScore of indicators. | unknown |
| Domain | The enriched Domain. | unknown |
| URL | The enriched URL | unknown |
| intelligence_alerts | The Intelligence Alerts related to indicators. | unknown |
| intelligence_reports | The Intelligence Reports related to indicators. | unknown |

## Playbook Image
---
![ACTI Indicator Enrichment](Insert the link to your image here)