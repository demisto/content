Creates a new Policy Planner Ticket for PolicyPlanner in FMOS box.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* FireMonSecurityManager

### Scripts
* IsIntegrationAvailable

### Commands
* firemon-create-pp-ticket

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain Id | Enter Domain Id \(Integer\) | incident.domainid | Required |
| Workflow Name | Enter Workflow Name | incident.workflowname | Required |
| Requirements | Enter list of Requirements containing Sources, Service, Destinations and Action | incident.requirements | Required |
| Priority | Set the Priority | incident.priority | Required |
| Due Date | Enter Due date  | incident.ppticketduedate | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![FireMon Create Policy Planner Ticket](https://raw.githubusercontent.com/demisto/content/daf3dab8a76d316777520a23d4747d2c9fbda5aa/Packs/FireMonSecurityManager/Playbooks/playbook-FireMon_Create_Policy_Planner_Ticket.png)
