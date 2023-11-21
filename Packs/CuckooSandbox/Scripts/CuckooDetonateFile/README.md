Deprecated. Use the 'cuckoo-create-task-from-file' command instead.

Adds a file to the list of pending tasks. Returns the ID of the newly created task.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | cuckoo |


## Dependencies
---
This script uses the following commands and scripts.
* cuckoo-create-task-from-file

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The ID of the entry containing the file to detonate. |
| machine | The label of the machine to use for analysis. (optional)  |
| package | The analysis package to be used for the analysis. (optional)  |
| timeout | The analysis timeout (in seconds). (optional)  |
| enforce_timeout | Enforces the execution for the full timeout value when enables. (optional) |
| platform | The name of the platform to select the analysis machine from (e.g. “windows”). (optional)  |
| tags | The machine to define to start by tags. The platform must be set to use this (comma-separated). (optional)  |
| memory | Creates a full memory dump of the analysis machine when enabled. (optional)  |
| options | The options to pass to the analysis package. (optional)  |

## Outputs
---
There are no outputs for this script.
