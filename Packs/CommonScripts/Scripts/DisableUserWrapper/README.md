This script allows disabling a specified user using one or more of the following integrations: SailPointIdentityIQ, ActiveDirectoryQuery, Okta, MicrosoftGraphUser, and IAM.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| username | The username of the user to disable. |
| approve_action | Whether to run the command. This is used to prevent unwanted calls to the command. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IdentityIQ.AccountDisable.active | Indicates the status of account \(should be false after request is successfully completed\). | Boolean |
| IAM.UserProfile | The user profile. | Unknown |
| IAM.Vendor.active | Gives the active status of user. Can be true or false. | Boolean |
| IAM.Vendor.brand | The integration name. | String |
| IAM.Vendor.details | Tells the user if the API was successful, otherwise provides error information. | Unknown |
| IAM.Vendor.email | The employee email address. | String |
| IAM.Vendor.errorCode | The HTTP error response code. | Number |
| IAM.Vendor.errorMessage | The reason the API failed. | String |
| IAM.Vendor.id | The employee user ID in the app. | String |
| IAM.Vendor.instanceName | The integration instance name. | Unknown |
| IAM.Vendor.success | If true, the command was executed successfully. | Boolean |
| IAM.Vendor.username | The employee username in the app. | String |
| IAM.Vendor.action | The command name. | String |
