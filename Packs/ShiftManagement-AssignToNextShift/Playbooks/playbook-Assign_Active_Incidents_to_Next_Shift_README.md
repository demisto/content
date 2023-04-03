This playbook reassigns Active Incidents to the current users on call, requires shift management to be setup. Can be run as a job a few minutes after the scheduled shift change time.

Update the playbook input with a different search query if required.  Will also branch if there are no Incidents that match the query, and no users on call. 

Search results are the default 100 Incidents returned by the query.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SearchIncidentsV2
* AssignToNextShift

### Commands
* closeInvestigation
* getUsers

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IncidentSearchQuery | Query for the Incidents to reassign.  Incidents need to be active for this to work, it will not reassign pending Incidents.  | status:Active -category:job | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
