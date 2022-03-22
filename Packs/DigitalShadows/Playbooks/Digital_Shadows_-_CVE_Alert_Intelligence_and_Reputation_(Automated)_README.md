Provides intelligence and reputation outputs to the Client based on the most recent CVE alert reported on their infrastructure by Digital Shadows SearchLight

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
* ds-find-vulnerabilities

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Incident ID | The ID of the SearchLight CVE Incident to analyse | incident.None | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Digital Shadows - CVE Alert Intelligence and Reputation (Automated)](Insert the link to your image here)