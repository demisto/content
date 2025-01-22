This script clears user sessions across multiple integrations for a list of usernames.

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
| user_name | List of names of the users to retrieve. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.  For multi-select provide a comma-separated list. For example: "Okta v2,Microsoft Graph User". |
| verbose | Whether to retrieve human readable entry for every command or only the final result. True means to retrieve human readable entry for every command. False means to retrieve human readable entry only for the final result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SessionClearResults.UserName | The username for which the session clearing process was executed. | String |
| SessionClearResults.Result | The result of the session clearing process for the user (*Success* or *Failed*). | String |
| SessionClearResults.Source | The integrations (e.g., *Microsoft Graph*, *Okta v2*) where the session clearing succeeded. | List |
| SessionClearResults.Message | Additional information or error details if the session clearing process failed. | String |
