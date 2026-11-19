# Sprinklr - Suspicious User Activity Response

This playbook retrieves a Sprinklr Governance user and recent Reporting API activity for the corresponding author. It can then deactivate or permanently deprovision the user through separately controlled response stages.

Deactivation runs only when `ConfirmDeactivate` is set to `True`. Permanent SCIM deprovisioning is fail-closed: `ConfirmDeprovision` must be `True`, and an analyst must then approve the interactive **Confirm permanent deprovision** task. Declining confirmation ends the path without deleting the user.

## Dependencies

Configure an enabled instance of **Sprinklr Event Collector**. The OAuth application needs read access to the Reporting and Governance APIs and the appropriate SCIM permissions for enabled response actions.

## Inputs

| Name | Description | Required |
|---|---|---|
| UserEmail | Sprinklr user email address. | Yes |
| AuthorID | Sprinklr author ID used for activity retrieval. | Yes |
| UserID | Sprinklr SCIM user ID used for response actions. | Yes |
| Lookback | Activity lookback supplied to the integration. | No |
| ConfirmDeactivate | Must be `True` to deactivate the user. | Yes |
| ConfirmDeprovision | Must be `True` to expose the permanent-deprovision path; an interactive analyst confirmation is also required. | Yes |

## Outputs

| Path | Description |
|---|---|
| `Sprinklr.Response.User` | Governance user details. |
| `Sprinklr.Investigation.UserActivity` | Recent author activity. |
| `Sprinklr.Response.Action` | Response action performed by the integration. |

![Sprinklr response flow](../doc_files/sprinklr_response_flow.png)
