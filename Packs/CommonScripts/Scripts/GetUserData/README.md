Returns the user data.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user_id | List of users IDs of the user to retrieve. |
| user_name | List of users names of the user to retrieve. |
| user_email | List of users emails of the user to retrieve. |
| domain | The user domain to retrieve users from, available only for the iam-get-user command. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.Type | The account type. The most common value is 'AD', but can be 'LocalOS', 'Google', 'AppleID'. | String |
| Account.ID | The unique ID for the account \(integration specific\). For AD accounts this is the Distinguished Name \(DN\). | String |
| Account.Username | The username in the relevant system. | String |
| Account.DisplayName | The display name. | String |
| Account.Groups | Groups to which the account belongs \(integration specific\). For example, for AD these are groups of which the account is memberOf. | String |
| Account.Domain | The domain of the account. | String |
| Account.OrganizationUnit | The Organization Unit \(OU\) of the account. | String |
| Account.Email.Address | The email address of the account. | String |
| Account.TelephoneNumber | The phone number associated with the account. | String |
| Account.Office | The office where the person associated with the account works. | String |
| Account.JobTitle | The job title of the account. | String |
| Account.Department | The department of the account. | String |
| Account.Country | The country associated with the account. | String |
| Account.State | The state where the account works. | String |
| Account.City | The city associated with the account. | String |
| Account.Street | The street associated with the account. | String |
| Account.IsEnabled | Whether the account is enabled or disabled. 'True' means the account is enabled. | Bool |
| Account.CloudApplications.Application Name | Cloud application name that is assosciated with this account. | String |
| Account.ChangePasswordAtNextLogin | Whether this account should change its password at the next login. 'True' means the account have to change its password. | Bool |
| Account.IsInternal | Whether the account is internal or external to the organization. 'True' means the account is internal. | Bool |
| Account.Manager.Email | The email address of the manager. | String |
| Account.Manager.DisplayName | The display name of the manager. | String |
| Account.RiskLevel | The risk level associated with the account. This could be 'LOW', 'MEDIUM', or 'HIGH'. | String |
