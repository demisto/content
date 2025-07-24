Searches Cortex Issues.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| id | A comma-separated list of incident IDs by which to filter the results. |
| name | A comma-separated list of incident names by which to filter the results. |
| status | A comma-separated list of incident statuses to filter the results by. Options: new, in_progress, and resolved. |
| notstatus | A comma-separated list of incident statuses to exclude from the results. Options: new, in_progress, resolved. |
| reason | A comma-separated list of incident close reasons by which to filter the results. |
| fromdate | Filter by from date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| todate | Filter by to date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| fromclosedate | Filter by from close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| toclosedate | Filter by to close date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| fromduedate | Filter by from due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| toduedate | Filter by to due date \(e.g. 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| level | Filter by Severity. |
| owner | Filter by incident owners. |
| details | Filter by incident details. |
| type | Filter by incident type. |
| query | Use free form query \(use Lucene syntax\) as filter. All other filters will be ignored when this filter is used. |
| page | Filter by the page number. |
| trimevents | The number of events to return from the alert JSON. The default is 0, which returns all events.<br/>Note that the count is from the head of the list, regardless of event time or other properties. |
| size | Number of incidents per page \(per fetch\). |
| limit | The maximum number of incidents to be returned. |
| sort | Sort in format of field.asc,field.desc,... |
| searchresultslabel | If provided, the value of this argument will be set under the searchResultsLabel context key for each incident found. |
| summarizedversion | If enabled runs a summarized version of this script. Disables auto-extract, sets fromDate to 30 days, and minimizes the context output. You can add sepcific fields to context using the add_fields_to_summarize_context argument. Default is false. |
| includeinformational | When the value is set to 'True', informational severity alerts will return as part of the results. The ‘fromdate’ and ‘todate’ arguments must be provided to use this argument. The maximum value currently supported for the 'fromdate' argument to retrieve informational incidents is 5 hours. If a value greater than this is provided, it will be adjusted to 5 hours ago. To retrieve only informational incidents, use the \`query\` argument and include this limitation within the query. Default is false. |
| add_fields_to_summarize_context | A comma seperated list of fields to add to context when using summarized version, \(default- id,name,type,severity,status,owner,created,closed\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIssues.id | A list of incident IDs returned from the query. | Unknown |
| foundIssues.name | A list of incident names returned from the query. | Unknown |
| foundIssues.severity | A list of incident severities returned from the query. | Unknown |
| foundIssues.status | A list of incident statuses returned from the query. | Unknown |
| foundIssues.owner | A list of incident owners returned from the query. | Unknown |
| foundIssues.created | A list of the incident create date returned from the query. | Unknown |
| foundIssues.closed | A list of incident close dates returned from the query. | Unknown |
| foundIssues.labels | An array of labels per incident returned from the query. | Unknown |
| foundIssues.details | Details of the incidents returned from the query. | Unknown |
| foundIssues.dueDate | A list of incident due dates returned from the query. | Unknown |
| foundIssues.phase | A list of incident phases returned from the query. | Unknown |
| foundIssues.incidentLink | A list with links to the incidents returned from the query. | Unknown |
| foundIssues.searchResultsLabel | The value provided in the searchresultslabel argument. | String |
