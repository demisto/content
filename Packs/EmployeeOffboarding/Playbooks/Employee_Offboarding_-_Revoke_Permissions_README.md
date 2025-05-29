Revokes user permissions as part of the IT - Employee Offboarding playbook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Builtin
* google

### Scripts
This playbook does not use any scripts.

### Commands
* googleapps-device-action
* duoadmin-dissociate-device-from-user
* gmail-revoke-user-role
* setIncident
* gmail-hide-user-in-directory
* okta-deactivate-user
* ad-set-new-password
* gmail-set-password

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| UserManagerEmail | The email of the manager of the user you are offboarding. | employeemanageremail | incident | Optional |
| OffboardingUserEmail | The email address of the user that you are offboarding. | employeeemail | incident | Required |
| WipeAccountFromMobile | Whether the Google account of the user should be removed from the mobile device of the user. | False | -  | Optional |
| LogisticsEmail | The email address of the logistics department who has the data about which company property the user has. | - | - | Optional |
| DuoUsername | The username, in Duo, of the user you are offboarding. | - | - | Optional |
| CompanyPropertyReceiverEmail | The email of the department responsible for receiving returned company property from the user you are offboarding. In some organizations, this may be the same as the LogisticsEmail playbook input. | - | - | Optional |
| OldEmployeeGroupName | The name of the group in Active Directory that contains old employee user accounts. If a group name is specified, the user will be added to that group instead of getting deleted at the end of the offboarding process. | Old Employees | - | Optional |
| ServiceNowAssetsTableName | The name of the "Assets" table in ServiceNow. This will be used to get the assets that belong to the user you are offboarding. | alm_asset | - | Optional |
| PerformPotentiallyHarmfulActions | Whether to perform potentially harmful actions, such as revoking user permissions and deleting the user. Taking the actions is necessary for a more complete offboarding process, and if set to False - the actions will have to be taken manually. | False | - | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Employee_Offboarding_Revoke_Permissions](../doc_files/Employee_Offboarding_-_Revoke_Permissions.png)
