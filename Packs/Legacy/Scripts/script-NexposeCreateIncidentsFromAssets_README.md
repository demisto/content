Creates incidents based on the Nexpose asset ID and vulnerability ID.
Duplicate incidents are not created for the same asset ID and vulnerability ID.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | nexpose |


## Dependencies
---
This script uses the following commands and scripts.
* nexpose-get-asset

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| assetID | The list of Nexpose assets' IDs. |
| minSeverity | The minimum Nexpose severity to create incidents for. |
| incidentType | The incident type to create incidents for. The default is "Vulnerability". |

## Outputs
---
There are no outputs for this script.
