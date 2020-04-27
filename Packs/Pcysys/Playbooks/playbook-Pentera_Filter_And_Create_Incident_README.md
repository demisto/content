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

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Filter password cracking | Filter all password cracking operation types | True |  | Required |
| Filter BlueKeep vulnerability | Filter all BlueKeep operation types | True |  | Required |
| Filter Minimum Severity | Filters actions according to given value. 
Will not filter anything if got zero \(0\) as value. | 0 |  | Required |
| FullActionReport | Pentera Full Action Report | TaskRun.FullActionReport | Pentera | Required |
| Filter MS17-010 vulnerability | Filter all MS17\-010 operation types | True |  | Required |
| Filter network device default password usage | Filter all network device default password operation types | True |  | Required |
| Filter open shares  | Filter all open shares operation types | True |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

![Pentera_Filter_And_Create_Incident](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Pentera_Filter_And_Create_Incident.png)
