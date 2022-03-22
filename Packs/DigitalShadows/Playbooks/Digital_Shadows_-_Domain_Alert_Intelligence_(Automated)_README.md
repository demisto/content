Provides intelligence and reputation outputs based on the most recent Impersonating Domain, Subdomain or Phishing URL reported by Digital Shadows SearchLight

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Digital Shadows

### Scripts
* AddEvidence

### Commands
* ds-search
* associateIndicatorsToIncident
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Phishing Attempt Incident ID | The ID of the SearchLight Phishing Attempt Incident to analyse | incident.id | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Digital Shadows - Domain Alert Intelligence (Automated)](Insert the link to your image here)