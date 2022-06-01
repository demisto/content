Provides intelligence and reputation outputs based on the most recent Impersonating Domain, Subdomain or Phishing URL reported by Digital Shadows SearchLight.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Digital Shadows

### Scripts
* AddEvidence

### Commands
* createNewIndicator
* ds-search
* associateIndicatorsToIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Phishing Attempt Incident ID | The ID of a Phishing Attempt incident raised by Digital Shadows SearchLight | incident.id | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.