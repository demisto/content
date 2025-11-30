This script disables users for multiple services.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Dependencies

---
This script uses the following commands and scripts.

* get-user-data

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| user_id | List of users IDs of the users to disable. At least one of "user_id", "user_name" or "user_email" is required. |
| user_name | List of names of the users to disable. At least one of "user_id", "user_name" or "user_email" is required. |
| user_email | List of emails of the users to disable. At least one of "user_id", "user_name" or "user_email" is required. |
| brands | List of brands to disable users from. |
| verbose | Whether to fetch a human-readable entry for each command or just the final result. If set to true, all commands will have human-readable entries. If set to false, only the final result will be human-readable. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DisableUser.Brand | The brand \(integration\) used to disable the user. | String |
| DisableUser.Instance | The integration instance used to disable the user. | String |
| DisableUser.Disabled | Whether the user is disabled. | Boolean |
| DisableUser.Result | Whether the disable action was successful. The result does not indicate whether the user is disabled. Possible values are: "Success", "Failed" | String |
| DisableUser.Message | The output message of the disable action. | String |
| DisableUser.UserProfile.Username | The username of the user. | String |
| DisableUser.UserProfile.ID | The ID of the user. | String |
| DisableUser.UserProfile.Email | The Email address of the user. | String |
