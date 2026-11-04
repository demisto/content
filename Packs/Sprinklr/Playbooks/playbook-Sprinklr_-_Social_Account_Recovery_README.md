# Sprinklr - Social Account Recovery

This playbook restores a Sprinklr page or advertising account to a selected team after containment.

The playbook does not make a change unless `ConfirmAction` is set to `True`. It selects the appropriate command according to `AccountKind`:

- `ad`: Runs `sprinklr-attach-ad-account-to-team`.
- `page`: Runs `sprinklr-attach-page-account-to-team`.

## Dependencies

Configure an enabled instance of **Sprinklr Event Collector** with permission to use the Sprinklr Governance Account Management API.

## Inputs

| Name | Description | Required |
|---|---|---|
| TeamID | Sprinklr team ID. | Yes |
| AccountID | Sprinklr page or advertising account ID. | Yes |
| AccountKind | Account type: `ad` or `page`. | Yes |
| ConfirmAction | Must be `True` to perform recovery. | Yes |

## Outputs

| Path | Description |
|---|---|
| `Sprinklr.Response.Action` | Action performed by the integration. |

![Sprinklr response flow](../doc_files/sprinklr_response_flow.png)
