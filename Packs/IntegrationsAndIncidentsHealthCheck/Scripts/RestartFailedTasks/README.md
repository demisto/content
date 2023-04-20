Use this Script to re-run failed tasks. Run in the same incident after running `GetFailedTasks` for restarting all of the failed tasks or some of them.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| XSOAR Version | 6.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-post

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| playbook_exclusion | Comma Separated list of failed tasks to exclude from restart based on playbook string match |
| sleep_time | Sleep between restarting batch task \(seconds\) |
| incident_limit | Limit of number of incidents to restart tasks on |
| group_size | Integer of how many tasks you want to be restarted at a time \(grouping\) before a sleep period \(as to not overwhelm the system\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RestartedTasks.Total | The total amount of tasks that were reopened | Number |
| RestartedTasks.Task.TaskID | The ID of the task | String |
| RestartedTasks.Task.IncidentID | The ID of the incident of the task | String |
| RestartedTasks.Task.PlaybookName | The name of the playbook of the task | String |
| RestartedTasks.Task.TaskName | The name of the task | String |

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.