Wraps the generic `create-record` command in ServiceNow. Fields can be added that create the record with a script argument or in the code and work with the records.

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
* servicenow-create-record

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| severity | The incident severity. |
| assignee | The incident assignee name. For example, "John Smith". |
| description | The incident description. |
| assigned_group | The incident assigned group name. For example, "Incident Management Group". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ServiceNow.Incident.ID | The ID of the incident. | string |
| ServiceNow.Incident.Number | The number of the incident. | string |
