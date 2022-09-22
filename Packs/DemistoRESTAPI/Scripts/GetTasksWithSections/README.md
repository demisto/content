Groups all tasks for a specific incident according to the task headers (titles).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| investigation_id | Incident ID to create the task table. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tasks | The entire task object | Unknown |
| Tasks.id | Task ID | string |
| Tasks.name | Task name | string |
| Tasks.section | Task section path | string |
| Tasks.type | Task type \(regular, condition, title, playbook, start\) | string |
| Tasks.owner | Task owner | string |
| Tasks.state | Task state \(inprogress, Completed, WillNotBeExecuted, Error, Waiting, Blocked, and empty string for not started\) | string |
| Tasks.scriptId | Task related script \(empty if manual\) | string |
| Tasks.startDate | Task start date | unknown |
| Tasks.completedDate | Task completed date | unknown |
| Tasks.dueDate | Task due date \(SLA\) | unknown |
| Tasks.parentPlaybookID | Task parent playbook ID \(if the task is part of a sub-playbook\) | unknown |
| Tasks.completedBy | Name of the user who completed the task | string |
