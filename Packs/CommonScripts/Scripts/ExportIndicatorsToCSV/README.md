This automation uses the Demisto REST API Integration to batch export Indicators to CSV and return the resulting CSV file to the war room.

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
| query | The query for the Indicators that you want to export. \(e.g. type:IP and reputation:Bad and expirationStatus:active\). You can and should generate the query from the Indicators search screen. |
| seenDays | Indicator last seen days  \(default is 7\).  Needs to be a number. |
| columns | Comma separated list of columns \(fields\) for the CSV.  \(Default is: id,indicator_type,value,source,score,relatedIncCount,setBy,sourceBrands,modified\) |

## Outputs
---
There are no outputs for this script.
