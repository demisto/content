Replaces regex match/es that are found in the string.
This script will return the string after the replacement was preformed.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| data | The string to preform the replacement on. |
| regex | The regex used to find matches that will be replaced with a new value. |
| newValue | The new value to replace the regex match. Pass '' to remove regex match. |
| replaceAll | Wether to replace matches. Pass true to replace all matches, false to replace only the first occurrence. |
| caseInsensitive | Whether to preform a case-insensitive search and replace. Pass true to preform case-insensitive search and replace, false for case-sensitive. |
| multiLine | Pass true to indicate 'data'  is a multi-line string, false otherwise. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| StringReplace.Result | The string after the replacement was preformed. | Unknown |


