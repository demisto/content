Enrichment of CVE IOC types - sub-playbook for IOC Assessment & Enrichment playbook

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Digital Shadows

### Scripts
* AddEvidence

### Commands
* associateIndicatorsToIncident
* createNewIndicator
* ds-search

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IoC_CVE | The ID of the CVE to assess and enrich | CVE.ID | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | Indicator Value | string |
| DBotScore.Type | Indicator Type | string |