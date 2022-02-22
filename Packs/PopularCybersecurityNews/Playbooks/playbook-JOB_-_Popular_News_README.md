Playbook can be run ad-hoc or as a Job to fetch results from Popular News sites

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Popular News

### Scripts
* SetGridField
* DeleteContext

### Commands
* get-news-TheHackerNews
* get-news-Threatpost
* get-news-KrebsOnSecurity
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| KrebsOnSecurity |  | true | Optional |
| ThreatPost |  | true | Optional |
| TheHackerNews |  | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
