Returns the email address of the user's manager of an email address or a username of a user account in Active Directory.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
* Active Directory Query v2

## Scripts
* Set

## Commands
* ad-get-user

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Username | Searches for the user by the sAMAccountName attribute in Active Directory. | - |-  | Optional |
| UserEmail | Searches for the user by the email attribute in Active Directory. | Email | Account | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| UserManagerEmail | The email of the user's manager. | unknown |
| UserManagerDisplayName | The display name of the user's manager. | unknown |

## Playbook Image
---
![Active Directory_Get User Manager Details](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Active_Directory_-_Get_User_Manager_Details.png)
