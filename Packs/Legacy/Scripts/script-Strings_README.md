Extracts strings from a file with an optional filter. This is similar to `binutils` strings command.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | server, file |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry | The entry ID of a file entry to retrieve strings from. |
| chars | The number of consecutive characters needed in order for it to be considered a string. The default is 4. |
| size | The display first 'size' results. The default is 1024. |
| filter | The regex to filter the strings. This will be compiled with the ignore case. |

## Outputs
---
There are no outputs for this script.
