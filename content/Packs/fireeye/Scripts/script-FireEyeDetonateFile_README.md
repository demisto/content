Detonates a file or URL through FireEye.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | fireeye, file, enhancement |


## Dependencies
---
This script uses the following commands and scripts.
* fe-submit-result
* fe-submit-status
* fe-submit

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| file | The file/entry ID to detonate. |
| profiles | The FireEye profiles to use (comma-separated). |
| analysistype | Specifies live or sandbox analysis mode. "Sandbox", analyzes suspected malware objects in a closed, protected environment. "Live", analyzes suspected malware objects live within the MAS Multivector Virtual Execution (MVX) analysis engine. |
| prefetch | Whether to determine the file target based on an internal determination rather than browsing to the target location. Can be, "No" or "Yes". |

## Outputs
---
There are no outputs for this script.
