Parses the Nexpose report into a clear table that contain risk score and vulnerability count for each server, and creates a new incident for each server.

## Script Data
---

| **Name** | **Description** |
| --- | --- | 
| Script Type | javascript |
| Tags | nexpose, ingestion |


## Dependencies
---
This script uses the following commands and scripts.
* nexpose

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| report | The full XML contents of the Nexpose report. If this is not provided, it will be taken from the incident details. |

## Outputs
---
There are no outputs for this script. 
