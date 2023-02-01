Searches Cortex XSOAR Incidents. Default search range is the last 30 days, if you want to change this, use the fromDate argument. 

Returns the id, name, type, severity, status, owner, and created/closed times to context.  You can add additional fields using the add_field_to_context argument.

This automation runs using the default Limited User role, unless you explicitly change the permissions.  Based on the SearchIncidentsV2 from the Common Scripts pack, but more efficient.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| id | A comma-separated list of incident IDs by which to filter the results. |
| name | A comma-separated list of incident names by which to filter the results. |
| status | A comma-separated list of incident statuses by which to filter the results. For example: assigned. |
| notstatus | A comma-separated list of incident statuses to exclude from the results.  For example: assigned. |
| reason | A comma-separated list of incident close reasons by which to filter the results. |
| fromdate | Filter by from date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\), default is "30 days ago" |
| todate | Filter by to date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| fromclosedate | Filter by from close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| toclosedate | Filter by to close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| fromduedate | Filter by from due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| toduedate | Filter by to due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\) |
| level | Filter by Severity |
| owner | Filter by incident owners |
| details | Filter by incident details |
| type | Filter by incident type |
| query | Use free form query \(use Lucene syntax\) as filter. All other filters will be ignored when this filter is used. |
| page | Filter by the page number |
| trimevents | The number of events to return from the alert JSON. The default is 0, which returns all events.<br/>Note that the count is from the head of the list, regardless of event time or other properties. |
| size | Number of incidents per page \(per fetch\) |
| sort | Sort in format of field.asc,field.desc,... |
| searchresultslabel | If provided, the value of this argument will be set under the searchResultsLabel context key for each incident found. |
| add_fields_to_context | A comma seperated list of fields to return to the context, \(default: id,name,type,severity,status,owner,created,closed\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIncidents.id | A list of incident IDs returned from the query. | Unknown |
| foundIncidents.name | A list of incident names returned from the query. | Unknown |
| foundIncidents.severity | A list of incident severities returned from the query. | Unknown |
| foundIncidents.status | A list of incident statuses returned from the query. | Unknown |
| foundIncidents.owner | A list of incident owners returned from the query. | Unknown |
| foundIncidents.created | A list of the incident create date returned from the query. | Unknown |
| foundIncidents.closed | A list of incident close dates returned from the query. | Unknown |
| foundIncidents.incidentLink | A list with links to the incidents returned from the query. | Unknown |
| foundIncidents.searchResultsLabel | The value provided in the searchresultslabel argument. | String |
