Simplifies the process of creating a new issue in Jira. Fields can be added in the record as script arguments and or in the code, and have a newly created issue easily.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | jira, example |


## Dependencies
---
This script uses the following commands and scripts.
* jira-delete-issue
* jira-create-issue

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| summary | The summary of the issue. (mandatory) |
| projectKey | The issue that will be associated with the project key. |
| issueTypeName | Select the issue type by name. For example, "Problem". |
| issueTypeId | Select the issue type by its numeric ID. |
| projectName | The project name to associate the issue with. |
| description | The issue description. |
| labels | The comma-separated list of labels.  |
| priority | The priorty name. For example, "High" or "Medium". |
| dueDate | The due date for the issue, in format: "2018-03-11" |
| assignee | The assignee name. |
| reporter | The reporter name. |
| parentIssueKey | The parent issue key, if a sub-task was created. |
| parentIssueId | The parent issue ID, if a sub-task was created. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Ticket.Id | The ID of the ticket. | Unknown |
| Ticket.Key | The key of the ticket. | Unknown |
