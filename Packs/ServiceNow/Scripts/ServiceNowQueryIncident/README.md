Wraps the generic `query-table` command in ServiceNow. Fields can be added to use as inputs and outputs from the record as script arguments or in the code and work with the records.

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

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| id | The system ID of the incident. |
| number | Th number of the incident. |
| assignee | The assignee name of the incident. For example, "John Smith". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ServiceNow.Incident.ID | THe ID of the incident. | string |
| ServiceNow.Incident.Description | The description of the incident. | string |
| ServiceNow.Incident.Number | The number of the incident. | number |
| ServiceNow.Incident.Caller | The caller of the incident. | string |
