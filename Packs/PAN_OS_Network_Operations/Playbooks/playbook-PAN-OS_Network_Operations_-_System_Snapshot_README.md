Takes two snapshots of the PAN-OS operational topology before and after a change, comparing the two for differences.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* getIncidentByID
* CompareTables
* DeleteContext

### Commands
* closeInvestigation
* linkIncidents
* createNewIncident
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| change_threshold | Default change threshold. Greater or equal than the number equals a medium severity, greater or equal to double the number is high, and 5x the number is critical. | 2 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - System Snapshot](../doc_files/PAN-OS_Network_Operations_-_System_Snapshot.png)