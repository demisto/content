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
| include_ids | The ids to deleting. If set, delete only these ids. |
| exclude_ids | The ids to exclude from deleting. If set, will delete everything else. |
| dry_run | When set to false, will delete content. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ConfigurationSetup.Deletion.successfully_deleted | Deleted ids | String |
| ConfigurationSetup.Deletion.not_deleted | Not deleted ids | String |
| ConfigurationSetup.Deletion.status | Deletion status | String |
