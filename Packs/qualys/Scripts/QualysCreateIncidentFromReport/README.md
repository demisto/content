Creates incidents from a Qualys report (XML), based on the Qualys asset ID and vulnerability ID (QID).
Duplicates the incidents that are not created for the same asset ID and QID.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | qualys |


## Dependencies
---
This script uses the following commands and scripts.
* qualys-host-list

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The War Room entryID of the XML report. |
| maxFileSize | The maximum file size to load, in bytes. The default is 1024 KB. |
| minSeverity | The minimum Qualys severity to create incidents for. |
| incidentType | The incident type to create incidents for. The default is "Vulnerability". |

## Outputs
---
There are no outputs for this script.
