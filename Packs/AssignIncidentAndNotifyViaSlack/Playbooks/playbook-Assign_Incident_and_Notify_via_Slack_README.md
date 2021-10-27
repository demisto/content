Assign an incident to an analyst and notify them of the assignment via Slack with a customizable message. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SlackV2

### Scripts
* AssignAnalystToIncident

### Commands
* send-notification

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MessageToAnalyst | Specific message to an analyst. This will be printed to Slack. | :404owl: Custom message not defined for this alert | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Assign Incident and Notify via Slack](Insert the link to your image here)