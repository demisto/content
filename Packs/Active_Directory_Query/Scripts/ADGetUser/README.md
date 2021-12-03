Retrieves detailed information about a user account. The user can be specified by "name", "email" or as an "Active Directory Distinguished Name" (DN). 
If no filter is provided, the result will show all users.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | active directory, enhancement, username |

## Dependencies
---
This script uses the following commands and scripts.
* ad-search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| dn | The Active Directory Distinguished Name for the desired user. |
| name | The name of the desired user. |
| attributes | Include these AD attributes of the resulting objects in addition to the default ones. |
| customFieldType | Search for a user by this custom field type. |
| customFieldData | Search for a user by this custom field data (relevant only if `customFieldType` is provided). |
| headers | The columns headers to show the order by. |
| nestedSearch | Select "true" to allow nested groups search as well. |
| username | The `samAccountName` of the desire user. |
| limit | The maximum number of objects to return. The default is 20. |
| email | The mail attribute of desire user. |
| userAccountControlOut | Include verbose translation for `UserAccountControl` flags. |
| using | The instance name. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The Active Directory acount. | Unknown |
| Account.Type | The type of the Account entity. | string |
| Account.ID | The unique Account DN (Distinguished Name). | string |
| Account.Username | The Account username. | string |
| Account.Email | The email object associated with the Account. | Unknown |
| Account.Groups | The groups the Account is part of. | string |
| Account.DisplayName | The Account display name. | string |
| Account.Manager | The Account's manager. | string |
| Account.Email.Address | The email address object associated with the Account. | string |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator's type. | string |
| DBotScore.Vendor | The indicator's vendor. | string |
| DBotScore.Score | The indicator's score. | number |
