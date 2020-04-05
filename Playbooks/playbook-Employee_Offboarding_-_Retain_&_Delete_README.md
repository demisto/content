Performs retention and deletion of user information as part of the IT - Employee Offboarding playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* send-mail
* setIncident
* gvault-delete-hold
* ad-add-to-group
* gmail-delete-user
* gvault-create-hold
* ad-disable-account
* gvault-matter-update-state
* gvault-create-matter
* ad-delete-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| UserManagerEmail | The email address of the manager of the user you are offboarding. | employeemanageremail | incident | Optional |
| OffboardingUserEmail | The email address of the user that you are offboarding. | employeeemail | incident | Required |
| OldEmployeeGroupName | The name of the group in the active directory that contains old employee user accounts. If a group name is specified, the user will be added to that group instead of getting deleted at the end of the offboarding process. | Old Employees | - | Optional |
| PerformPotentiallyHarmfulActions | Whether to perform potentially harmful actions, such as revoking user permissions and deleting the user. Taking the actions is necessary for a more complete offboarding process, and if set to False - the actions will have to be taken manually. | False | - | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Employee_Offboarding_Retain_&_Delete](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Employee_Offboarding_Retain_%26_Delete.png)
