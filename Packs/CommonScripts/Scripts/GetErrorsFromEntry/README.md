Get the error(s) associated with a given entry/entries. Use ${lastCompletedTaskEntries} to check the previous task entries. The automation will return an array of the error contents from those entries.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.2.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | Entry to check |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ErrorEntries | Contents of the errors associated with the entry/entries | Unknown |
