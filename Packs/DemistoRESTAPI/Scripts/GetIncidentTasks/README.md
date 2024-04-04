Get all tasks for a specific incident by the given state, name and/or tag.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| inc_id | Incident ID to get tasks from. |
| states | Comma-separated list of states. Possible values: New, InProgress, Completed, Waiting, Error, LoopError, Skipped, Blocked. \(Leave empty to get all tasks\). |
| name | The name of the task to search. |
| tag | The tag to search. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tasks | The entire task object. | Unknown |
| Tasks.id | Task ID. | string |
| Tasks.name | Task name. | string |
| Tasks.type | The type of the task \(regular, condition, title, playbook, start\). | string |
| Tasks.owner | Task owner. | string |
| Tasks.state | Task state \(inprogress, Completed, WillNotBeExecuted, Error, LoopError, Waiting, Blocked, and empty string for not started\). | string |
| Tasks.scriptId | Task related script \(empty if manual\). | string |
| Tasks.startDate | Task start date. | unknown |
| Tasks.completedDate | Task completed date. | unknown |
| Tasks.dueDate | Task due date \(SLA\). | unknown |
| Tasks.parentPlaybookID | Task parent playbook ID \(in case the task is part of a sub-playbook\). | unknown |
| Tasks.completedBy | Task completed by \(username\). | string |

## Script Examples

### Example command

```!GetIncidentTasks inc_id=10 name="Email Campaign Search"```

### Context Example

```json
{
    "Tasks": {
        "completedBy": "DBot",
        "completedDate": "2024-01-09T12:26:33.75641877Z",
        "dueDate": "0001-01-01T00:00:00Z",
        "id": "101",
        "name": "Email Campaign Search",
        "owner": "Dummy",
        "parentPlaybookID": null,
        "scriptId": null,
        "startDate": "0001-01-01T00:00:00Z",
        "state": "Completed",
        "type": "title"
    }
}
```

### Human Readable Output

>### Incident #10 Playbook Tasks

>|id|name|state|owner|scriptId|
>|---|---|---|---|---|
>| 101 | Email Campaign Search | Completed | Dummy |  |

