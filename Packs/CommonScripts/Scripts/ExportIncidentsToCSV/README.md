This automation uses the Core REST API Integration to batch export Incidents to CSV and return the resulting CSV file to the war room.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Dependencies

---
This script uses the following commands and scripts.

* core-api-get
* core-api-post

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query for the Incidents that you want to export. \(e.g. status:closed -category:job\). You can and should generate the query from the Incidents search screen. |
| fetchdays | The number of days back to fetch incidents. This argument acts as the primary time filter and is always applied, even when using the query argument. The command first filters for all incidents created in the last fetchdays and then applies the query argument to that subset of incidents. **Warning**: If the query argument contains a created: time range (for example, **created:>=now-90d**), you must set *fetchdays* to a value equal to or larger than that range. If *fetchdays* is smaller that the window in the query, the results will be truncated. \(default is 7\).  Must be a number. |
| columns | Comma separated list of columns \(fields\) for the CSV.  \(Default is: id,name,type,severity,status,owner,roles,playbookId,occurred,created,modified,closed\) |

## Outputs

---
There are no outputs for this script.
