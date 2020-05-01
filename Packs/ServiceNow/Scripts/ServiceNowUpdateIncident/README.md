Wraps the generic `update-record` command in ServiceNow. Fields can be added that update the record with as script arguments or in the code and work with the records easily.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | servicenow |


## Dependencies
---
This script uses the following commands and scripts.
* servicenow-query-table
* servicenow-update-record

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| severity | The severity of the incident. |
| assignee | The assignee name of the incident. For example, "John Smith". |
| description | The description of the incident. |
| assigned_group | The assigned group name of the incident. For example, "Incident Management Group". |
| id | The incident ID to update. |
| number | The incident number to update. |
| query | The query to use.  |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ServiceNow.Incident.ID | The ID of the incident. | string |
| ServiceNow.Incident.Number | The number of the incident. | string |
