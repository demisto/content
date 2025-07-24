Searches Demisto issues. A summarized version of this scrips is available with the summarizedversion argument.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here:
- For Cortex XSOAR 6 see https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations 
- For Cortex XSOAR 8 Cloud see https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script
- For Cortex XSOAR 8.7 On-prem see https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* getIssues

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| name | A comma-separated list of issue names by which to filter the results. |
| status | A comma-separated list of issue statuses by which to filter the results. For example: assigned. |
| notstatus | A comma-separated list of issue statuses to exclude from the results.  For example: assigned. |
| fromdate | Filter by from date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| todate | Filter by to date \(e.g. "3 days ago" or 2006-01-02T15:04:05\+07:00 or 2006-01-02T15:04:05Z\). |
| assignee | Filter by issue assignee. |
| query | Use free form query \(use Lucene syntax\) as filter. All other filters will be ignored when this filter is used. |
| page | Filter by the page number. |
| trimevents | The number of events to return from the alert JSON. The default is 0, which returns all events.<br/>Note that the count is from the head of the list, regardless of event time or other properties. |
| size | Number of issues per page \(per fetch\). |
| limit | The maximum number of issues to be returned. |
| sort | Sort in format of field.asc,field.desc,... |
| searchresultslabel | If provided, the value of this argument will be set under the searchResultsLabel context key for each issue found. |
| includeinformational | When the value is set to 'True', informational severity alerts will return as part of the results. The ‘fromdate’ and ‘todate’ arguments must be provided to use this argument. The maximum value currently supported for the 'fromdate' argument to retrieve informational issues is 5 hours. If a value greater than this is provided, it will be adjusted to 5 hours ago. To retrieve only informational issues, use the \`query\` argument and include this limitation within the query. Default is false. |
| domain | Filter by domain. |
| severity | Filter by severity. |
| description | Filter by description. |
| name | Filter by name. |
| category | Filter by category. |
| type | Filter by type. |
| assetids | Filter by assetids. |
| detectionmethod | Filter by detectionmethod. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| foundIssues.id | A list of issue IDs returned from the query. | Unknown |
| foundIssues.name | A list of issue names returned from the query. | Unknown |
| foundIssues.severity | A list of issue severities returned from the query. | Unknown |
| foundIssues.status | A list of issue statuses returned from the query. | Unknown |
| foundIssues.owner | A list of issue owners returned from the query. | Unknown |
| foundIssues.created | A list of the issue create date returned from the query. | Unknown |
| foundIssues.closed | A list of issue close dates returned from the query. | Unknown |
| foundIssues.labels | An array of labels per issue returned from the query. | Unknown |
| foundIssues.details | Details of the issues returned from the query. | Unknown |
| foundIssues.dueDate | A list of issue due dates returned from the query. | Unknown |
| foundIssues.phase | A list of issue phases returned from the query. | Unknown |
| foundIssues.issueLink | A list with links to the issues returned from the query. | Unknown |
| foundIssues.searchResultsLabel | The value provided in the searchresultslabel argument. | String |
