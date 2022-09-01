Wait and complete tasks by given status. Used for test playbooks.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.1.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| task_states | A comma separated list of states. Possible values: New, InProgress, Completed, Waiting, Error, Skipped, Blocked \(leave empty to get all tasks\). |
| complete_option | Outcome for a conditional task. For example, "Yes". |
| incident_id | The incident ID where the task should be completed. Leave empty to use current incident ID. |
| task_name | The name of the task that should be completed. If no task name is entered, will complete all tasks with the state `task_state`. |
| max_timeout | Timeout in seconds for the script to complete tasks. |
| interval_between_tries | Time (seconds) to wait between each check iteration.  |
| complete_task | Whether to complete the task in addition to checking if it is completed. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| WaitAndCompleteTask.CompletedTask | Task name that was completed by the script. | String |
| WaitAndCompleteTask.FoundTask | Tasks that were found by the script. | Unknown |


## Script Examples
### Example command
```!WaitAndCompleteTask incident_id=6209 task_states=Waiting complete_task=true```
### Context Example
```json
{
    "WaitAndCompleteTask": {
        "CompletedTask": [
            "Conditional task",
            "manual task 1"
        ],
        "FoundTask": []
    }
}
```

### Human Readable Output

>|Completed Task|Found Task|
>|---|---|
>| Conditional task,<br/>manual task 1 |  |
