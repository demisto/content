Lookup a User and their Manager in Active Directory

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | training, incident-action-button |
| Cortex XSOAR Version | 6.8.0 |

## Dependencies

---
This script uses the following commands and scripts.

* ad-get-user

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| email | Email address of the user to lookup in Active Directory. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ADUserAndManager.UserName | The Display Name of the User | Unknown |
| ADUserAndManager.UserEmail | The Email of the User | Unknown |
| ADUserAndManager.UserGroups | AD Groups of the User | Unknown |
| ADUserAndManager.UserSamAccountName | The samAccountName of the User | Unknown |
| ADUserAndManager.ManagerName | The Display Name of the Users Manager | Unknown |
| ADUserAndManager.ManagerEmail | The Email of the Users Manager | Unknown |
