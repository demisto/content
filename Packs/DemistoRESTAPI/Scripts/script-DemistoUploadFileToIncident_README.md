Deprecated. Use the *DemistoUploadFileV2* script instead.
Copies a file from an incident to the specified incident. The file is uploaded as an attachment to the specified incident's summary page, and recorded as an entry in the War Room.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | DemistoAPI |


## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-multipart

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incident_id | The ID of incident to upload to. |
| entryID | The entry ID of file to upload. |
| body | The request body. |

## Outputs
---
There are no outputs for this script.
