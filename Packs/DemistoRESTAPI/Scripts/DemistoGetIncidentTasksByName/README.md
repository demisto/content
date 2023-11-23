Gets all tasks for a specific incident by the given name.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentId | The Incident ID to get tasks from. |
| name | The The name of the task in the current Incident. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tasks | The entire task object. | Unknown |
| Tasks.id | The task ID. | string |
| Tasks.name | The task name. | string |
| Tasks.type | The type of the task. Can be, "regular", "condition", "title", "playbook", or "start". | string |
| Tasks.owner | The task owner. | string |
| Tasks.state | The task state. Can be, "inprogress", "Completed", "WillNotBeExecuted", "Error", "Waiting", "Blocked", and empty string for not started. | string |
| Tasks.scriptId | The task related script (empty if manual). | string |
| Tasks.startDate | The task start date. | unknown |
| Tasks.completedDate | The task completed date. | unknown |
| Tasks.dueDate | The task due date (SLA). | unknown |
| Tasks.parentPlaybookID | The task parent playbook ID (in case the task is part of sub-playbook). | unknown |
| Tasks.completedBy | The task completed by (username). | string |
