This playbook covers an XDR Best Practice Assessment for existing XDR deployments. It provides surveys for each domain of the assessment. 

The assessment covers the following domains: Configurations, Agent Management, Policy and Profiles, Profile Extensions, Incident Management, and Incident Response. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SurveyOwner | Input the email address of the individual who will be filling out the survey. Default is the owner of the incident in XSOAR. | ${incident.owner} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
