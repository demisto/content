Checks if an email address's domain is trying to squat other domain using Levenshtein distance algorithm.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email, reputation |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email address to check. |
| domain | The domain list to check against for squatting (comma separated). |
| threshold | The similarity threshold. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Account | The user account.  | Unknown |
| Account.Email | The account's email object. | Unknown |
| Account.Email.Username | The account's email username. | string |
| Account.Email.Address | The account's email address. | string |
| Account.Email.Domain | The account's email domain. | string |
| Account.Email.Distance | The email address distance compared to the domains in the query. | number |
| Account.Email.Distance.Domain | The compared domain. | string |
| Account.Email.Distance.Value | The distance between the email domain and the compared domain.  | number |
| DBotScore.Indicator | The indicator. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The DBot vendor score. | string |
| DBotScore.Score | The DBot score. | number |
