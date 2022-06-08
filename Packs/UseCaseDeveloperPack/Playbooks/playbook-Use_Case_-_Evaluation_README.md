Initial workflow for evaluating automation requests. This is a basic evaluation using the submitted data from the customer.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* AssignAnalystToIncident
* ExposeIncidentOwner
* CalculateUseCaseDates
* Exists

### Commands
* setIncident
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExternalTicketId | If this value is blank, this part of the playbook will be skipped. Logic will need to be defined according to your system configuration. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Use Case - Evaluation](Insert the link to your image here)