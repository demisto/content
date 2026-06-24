Creates a war room entry for up to 20 cases and/or issues. At least one of `issue_ids` or `case_ids` must be provided.

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
| issue_ids | A comma-separated list of issue IDs for which to create the war room entry. |
| case_ids | A comma-separated list of case IDs for which to create the war room entry. |
| content | The content for the war room entry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CortexCreateWarRoomEntry.result | The entry IDs in case of success. | String |
| CortexCreateWarRoomEntry.errors | A list of errors that occurred during the operation. | Array |
