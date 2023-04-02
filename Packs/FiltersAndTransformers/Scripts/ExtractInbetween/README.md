Extract strings from in between other strings using a single command.

- If the start or end input is a single character, the script looks for the first and last instances,
respectively, and returns the string that is in between the two instances.
- If the start or end input is greater than a single character, regex is used to find the first and
last instances, repectively, and returns the string that is in between the two instances.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transform, general, Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to extract the data from. |
| start | The string from which to start extracting. |
| end | The string to which to stop extracting. |

## Outputs
---
None
