Gets all tasks for a specific incident by the given state, name or tag.
If multiple values are given, only tasks matching all of them are returned. 
For example, if name and state is given, only tasks with the given name in a given state are returned

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility |


## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| inc_id | The incident ID to get tasks from. |
| states | The comma-separated list of states. Can be, "New", "InProgress", "Completed", "Waiting", "Error", "LoopError", "Skipped", "Blocked". You can also leave this field empty to get all tasks. |
| name | The name of the task to search. |
| tag | The tag of the task to search.

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tasks | The entire task object. | Unknown |
| Tasks.id | The task ID. | string |
| Tasks.name | The task name. | string |
| Tasks.type | The type of the task. Can be, "regular", "condition", "title", "playbook", or "start". | string |
| Tasks.owner | The task owner. | string |
| Tasks.state | The task state. Can be, "inprogress", "Completed", "WillNotBeExecuted", "Error", "LoopError", "Waiting", "Blocked", and empty string for not started. | string |
| Tasks.scriptId | The task related script (empty if manual). | string |
| Tasks.startDate | The task start date. | unknown |
| Tasks.completedDate | The task completed date. | unknown |
| Tasks.dueDate | The task due date (SLA). | unknown |
| Tasks.parentPlaybookID | The task parent playbook ID (in case the task is part of a sub-playbook). | unknown |
| Tasks.completedBy | The task completed by (username). | string |
