This script expires users password for multiple services.

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
| user_id | List of user IDs whose passwords will be expired. At least one of user_id, user_name, or user_email is required. |
| user_name | List of user names whose passwords will be expired. At least one of user_id, user_name, or user_email is required. |
| user_email | List of emails of the users to expire their password. At least one of user_id, user_name, or user_email is required. |
| brands | List of brands to expire password from. |
| verbose | Whether to fetch a human-readable entry for each command or just the final result. If set to true, all commands will have human-readable entries. If set to false, only the final result will be human-readable. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExpirePassword.Brand | The brand \(integration\) used to expire the user’s password. | String |
| ExpirePassword.Instance | The integration instance used to expire the user’s password. | String |
| ExpirePassword.Result | Indicates whether the expire password action was successful. Possible values are: "Success", "Failed". | String |
| ExpirePassword.Message | The output message of the expire-password action \(for example, error details or confirmation\). | String |
| ExpirePassword.UserProfile.Username | The username of the user whose password was expired. | String |
| ExpirePassword.UserProfile.ID | The ID of the user whose password was expired. | String |
| ExpirePassword.UserProfile.Email | The email address of the user whose password was expired. | String |
