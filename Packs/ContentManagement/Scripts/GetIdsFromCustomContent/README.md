Extract custom content ids from custom content bundle file and exclude ids as specified.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| exclude_ids_list | list of dicts of ids to exclude n json format \(e.g. \[\{"job": \["job1", "job2"\], "pack": \["pack1"\]\}, \{"job": \["job3"\]\}\] |
| file_entry_id | The entry id of the custom content tar file. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GetIdsFromCustomContent.ids | Dictionary of IDs of custom content excluding the ones specified. | Unknown |
