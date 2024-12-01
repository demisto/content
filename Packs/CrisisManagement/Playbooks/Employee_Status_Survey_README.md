Note: This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the playbook during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the playbook to help us identify issues, fix them, and continually improve. Manages a crisis event where employees have to work remotely due to a pandemic, issues with the workplace or similar situations. Sends a questionnaire to all direct reports under a given manager. The questionnaire asks the employees for their health status and whether they need any help. The data is saved as employee indicators in Cortex XSOAR, while IT and HR incidents are created to provide assistance to employees who requested it. The questionnaire expires after 24 hours by default, and during that time the responses are processed every 5 minutes. These settings can be edited via the task that sends the questionnaire and the loop settings of the Continuously Process Survey Responses playbook, respectively.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Process Survey Response
* Continuously Process Survey Responses

### Integrations
* Azure Active Directory Users

### Scripts
* Set

### Commands
* closeInvestigation
* msgraph-user-get
* msgraph-direct-reports
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ManagerEmail | The email of the manager whose direct reports should be contacted for their health status and offered assistance. | incident.manageremail | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Employee_Status_Survey](../doc_files/Employee_Status_Survey.png)