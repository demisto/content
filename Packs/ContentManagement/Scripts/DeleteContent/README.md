Delete content to keep XSOAR tidy.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | configuration, Content Management |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| include_ids_dict | The content items ids to delete, in a JSON format. |
| exclude_ids_dict | The content items IDs to preserve, in a JSON format. |
| dry_run | If set to true, the flow will work as usuall except that no content items will be deleted from the system. |
| verify_cert | If true, verify certificates when accessing github. |
| skip_proxy | If true, skip system proxy settings. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ConfigurationSetup.Deletion.successfully_deleted | Deleted ids | String |
| ConfigurationSetup.Deletion.not_deleted | Not deleted ids | String |
| ConfigurationSetup.Deletion.status | Deletion status | String |
