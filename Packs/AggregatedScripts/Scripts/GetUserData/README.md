This script gathers user data from multiple integrations and returns an Account entity with consolidated information to the context.

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
| user_id | List of IDs of the user to retrieve. |
| user_name | List of names of the users to retrieve. |
| user_email | List of emails of the users to retrieve. |
| domain | The domain to retrieve users from. Available only for the iam-get-user command. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select provide a comma-separated list. For example: "SailPointIdentityNow,Active Directory Query v2,PingOne". |
| verbose | Whether to retrieve human readable entry for every command or only the final result.  True means to retrieve human readable entry for every command. False means to human readable only for the final result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account.ID.Value | The user ID. | String |
| Account.ID.Source | The source of the account ID, for example, the integration name. | String |
| Account.Username | The username in the relevant system. | String |
| Account.DisplayName | The display name. | String |
| Account.Email.Address | The email address of the account. | String |
| Account.Groups | Groups to which the account belongs \(integration specific\). For example, for AD these are groups of which the account is memberOf. | String |
| Account.Type | The account type. The most common value is 'AD', but can be 'LocalOS', 'Google', 'AppleID'. | String |
| Account.JobTitle | The job title of the account. | String |
| Account.Office | The office where the person associated with the account works. | String |
| Account.TelephoneNumber | The phone number associated with the account. | String |
| Account.IsEnabled | Whether the account is enabled or disabled. 'True' means the account is enabled. | Bool |
| Account.Manager.Email | The email address of the manager. | String |
| Account.Manager.DisplayName | The display name of the manager. | String |
| Account.RiskLevel | The risk level associated with the account. This could be 'LOW', 'MEDIUM', or 'HIGH'. | String |
