This script gathers user data from multiple integrations and returns an Account entity with consolidated information to the context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* disable-user
* silent-Suspicious Local User Account Creation
* A user executed multiple LDAP enumeration queries
* silent-A user executed multiple LDAP enumeration queries Test

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user_id | List of users IDs of the user to retrieve. |
| user_name | List of names of the users to retrieve. |
| user_sid | List of users security identifiers to retrieve. Supported by Azure AD only.|
| user_email | List of emails of the users to retrieve. |
| attributes | list of AD user's attributes to retrieve, separated by comma. |
| domain | The domain to retrieve users from. Available only for the iam-get-user command. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select provide a comma-separated list. For example: "SailPointIdentityNow,Active Directory Query v2,PingOne". |
| verbose | Whether to fetch a human-readable entry for each command or just the final result. If set to true, all commands will have human-readable entries. If set to false, only the final result will be human-readable. |
| additional_fields | Whether to return unmapped fields to the context output under the "AdditionalFields" path. |
| list_non_risky_users | Whether to return only risky users from Core/XDR brands or all given users. If set to true, the execution might take some time. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| UserData.Brand | The brand \(integration\) used to disable the user. | String |
| UserData.Instance | The integration instance used to disable the user. | String |
| UserData.ID | The user ID. | String |
| UserData.Username | The username in the relevant system. | String |
| UserData.Email | The email address of the account. | String |
| UserData.RiskLevel | The risk level of the user. | String |
| UserData.AdditionalFields | All the other outputs returned. | String |
| UserData.Status | Status of the results returned from the command. | String |
