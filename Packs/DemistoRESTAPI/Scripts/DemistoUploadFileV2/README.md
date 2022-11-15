Copies a file from this incident to the specified incident. The file is recorded as an entry in the specified incident’s War Room.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DemistoAPI |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-multipart

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | File entry ID |
| incidentID | Incident ID to upload the file to |
| body | Request body |
| target | Where to upload the file<br/>- Available options are:<br/>- \`war room entry\`: the file will be uploaded as war room entry.<br/>- \`incident attachment\`: the file will be uploaded as incident attachment.<br/>- default are \`war room entry\` |

## Outputs
---
There are no outputs for this script.
