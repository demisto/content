Sub-playbook to select specific entries from the Pentera action report and create incidents for each of the selected entries

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
* SetAndHandleEmpty
* PenteraOperationToIncident

### Commands
* createNewIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Filter password cracking | Filter all password cracking operation types | True | Required |
| Filter BlueKeep vulnerability | Filter all BlueKeep operation types | True | Required |
| Filter Minimum Severity | Filters actions according to given value. 
Will not filter anything if got zero \(0\) as value. | 0 | Required |
| FullActionReport | Pentera Full Action Report is the summary of the given TaskName in a CSV format, that contains all the actions that Pentera performed during the task run. 
The value will be provided from Pentera Run Scan and Create Incidents playbook. |  | Required |
| Filter MS17-010 vulnerability | Filter all MS17\-010 operation types | True | Required |
| Filter network device default password usage | Filter all network device default password operation types | True | Required |
| Filter open shares  | Filter all open shares operation types | True | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->