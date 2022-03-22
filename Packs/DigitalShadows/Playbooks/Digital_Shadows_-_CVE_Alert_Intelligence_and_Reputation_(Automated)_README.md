Provides intelligence and reputation outputs to the Client based on the most recent CVE alert reported on their infrastructure by Digital Shadows SearchLight.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Digital Shadows

### Scripts
* AddEvidence

### Commands
* ds-find-vulnerabilities
* ds-search

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Incident ID | The ID of a CVE incident raised by Digital Shadows SearchLight | incident.None | Required |

## Playbook Outputs
---
There are no outputs for this playbook.
