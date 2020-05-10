Manages a crisis event where employees have to work remotely due to a pandemic, issues with the workplace or similar situations. Sends a questionnaire to all direct reports under a given manager. The questionnaire asks the employees for their health status and whether they need any help. The data is saved as employee indicators in Cortex XSOAR, while IT and HR incidents are created to provide assistance to employees who requested it.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Continuously Process Survey Responses
* Process Survey Response

### Integrations
* Builtin

### Scripts
* Set

### Commands
* msgraph-direct-reports
* closeInvestigation
* msgraph-user-get
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ManagerEmail | The email of the manager whose direct reports should be contacted for their health status and offered assistance. | incident.manageremail | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->