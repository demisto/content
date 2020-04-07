Checks whether a given entry(ies) return an error. Use `${lastCompletedTaskEntries}` to check the previous task entries. If an array is provided, it will return "yes" if one of the entries returned an error.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Condition, Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryId | The entry to check. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| True | If one or more entries is an error. | Unknown |
| False | If none of the entries is not an error. | Unknown |
