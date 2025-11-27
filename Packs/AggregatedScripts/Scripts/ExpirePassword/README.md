This script expires users' passwords across multiple services by enforcing a password reset on next sign-in.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* get-user-data
* ad-modify-password-never-expire
* ad-expire-password
* msgraph-user-force-reset-password
* okta-expire-password
* gsuite-user-reset-password
* aws-iam-update-login-profile

## Inputs

---

| **Argument Name** | **Description** | **Required** | **Default Value** |
| --- | --- | --- | --- |
| user_id | List of users IDs of the users to expire their password. At least one of "user_id", "user_name" or "user_email" is required. | Optional | |
| user_name | List of names of the users to expire their password. At least one of "user_id", "user_name" or "user_email" is required. | Optional | |
| user_email | List of emails of the users to expire their password. At least one of "user_id", "user_name" or "user_email" is required. | Optional | |
| brands | List of brands to expire password from. | Optional | Active Directory Query v2,Microsoft Graph User,Okta v2,GSuiteAdmin,AWS - IAM |
| verbose | Whether to fetch a human-readable entry for each command or just the final result. If set to true, all commands will have human-readable entries. If set to false, only the final result will be human-readable. | Optional | false |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExpirePassword.Brand | The brand (integration) used to expire the user’s password. | String |
| ExpirePassword.Instance | The integration instance used to expire the user’s password. | String |
| ExpirePassword.Result | Indicates whether the expire password action was successful. Possible values are: "Success", "Failed". | String |
| ExpirePassword.Message | The output message of the expire-password action (for example, error details or confirmation). | String |
| ExpirePassword.UserProfile.Username | The username of the user whose password was expired. | String |
| ExpirePassword.UserProfile.ID | The ID of the user whose password was expired. | String |
| ExpirePassword.UserProfile.Email | The email address of the user whose password was expired. | String |