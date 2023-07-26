Extract custom content IDs from custom content bundle file and exclude IDs as specified.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| exclude_ids_list | List of dictionaries of IDs to exclude in a JSON format \(e.g., \[\{"job": \["job1", "job2"\], "pack": \["pack1"\]\}, \{"job": \["job3"\]\}\] |
| file_entry_id | The entry ID of the custom content tar file. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GetIdsFromCustomContent.included_ids | Dictionary of IDs of custom content excluding the ones specified. | Unknown |
| GetIdsFromCustomContent.excluded_ids | Dictionary of IDs of custom content excluding the ones specified. | Unknown |
