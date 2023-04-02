This script is used to simplify the process of creating a new Issue in Jira. 
You can specify custom fields using the `customFields` argument.


## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | jira, example |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* jira-create-issue

## Used In
---
This script is used in the following playbooks and scripts.
* Indeni Demo

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| summary | Summary of the issue, a mandatory field |
| projectKey | Project key to associate the issue |
| issueTypeName | Choose issue type by name - e.g. Problem |
| issueTypeId | Choose issue type by its numeric ID |
| projectName | Project name to associate the issue |
| description | Issue description |
| labels | comma separated list of labels |
| priority | priority name, e.g. High/Medium. |
| dueDate | Due date for the issue, in format YYYY-MM-DD |
| assignee | assignee name |
| reporter | reporter name |
| parentIssueKey | Parent issue key if you create a sub-task |
| parentIssueId | Parent issue ID if you create a sub-task |
| customFields | Comma-separated custom field keys and values to include in the created incident, e.g. \`customfield_10101=foo,customfield_10102=bar\` |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Ticket.Id | Id of ticket | Unknown |
| Ticket.Key | Key of ticket | Unknown |
