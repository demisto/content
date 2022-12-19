This automation uses the Demisto REST API Integration to batch export Incidents to CSV and return the resulting CSV file to the war room.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-get
* demisto-api-post

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query for the Incidents that you want to export. \(e.g. status:closed -category:job\). You can and should generate the query from the Incidents search screen. |
| fetchdays | Number of days you want to fetch back for \(default is 7\).  Needs to be a number. |
| columns | Comma separated list of columns \(fields\) for the CSV.  \(Default is: id,name,type,severity,status,owner,roles,playbookId,occurred,created,modified,closed\) |

## Outputs
---
There are no outputs for this script.
