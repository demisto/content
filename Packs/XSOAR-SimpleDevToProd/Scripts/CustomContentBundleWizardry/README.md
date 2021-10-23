This automation accepts an XSOAR custom content bundle, and either returns a list of file names, or the files you want to the war room.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The EntryID of the custom content bundle from the war room. |
| action | Whether to list the files in the bundle, or return the selected files to the war room. |
| file_names | Array of file names to export, generated from the listfiles action. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CustomContent | List of files in the custom content bundle | Unknown |
