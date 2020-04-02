Downloads files from a specified machine without requiring approval.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | GRR |


## Dependencies
---
This script uses the following commands and scripts.
* grr_get_files

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| hostname | The target host. Can be, "FQDN" or "client ID". |
| paths | Fetches the number of elements, an array of path strings. |
| max_file_size | The maximum size of the file that will download. |
| action | The action to apply to the found files. Can be, "STAT", "HASH" or "DOWNLOAD". |
| pathtype | The path type to glob in. Can be, "UNSET", "OS", "TSK", "REGISTRY", "MEMORY", or "TMPFILE". |

## Outputs
---
There are no outputs for this script.
