Cuts a string by delimiter and returns specific fields.

Examples:
=================
input: "A-B-C-D-E"
delimiter: "-"
fields: "1,5"

return: "A-E"

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transformer, string |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to split. |
| delimiter | The delimiter to cut the string by. Pass '' to set delimiter to be empty string. |
| fields | The comma-separated field numbers. For example, "1,5,7". |

## Outputs
---
There are no outputs for this script.
