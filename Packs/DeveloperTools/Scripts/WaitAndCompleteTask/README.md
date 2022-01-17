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
| task_states | Comma separated list of states. Possible values: New, InProgress, Completed, Waiting, Error, Skipped, Blocked \(leave empty to get all tasks\) |
| complete_option | The path to take in conditional tasks. For example, if your conditional task has "Yes" or "No", a possible value here may be "Yes". |
| incident_id | The ID of the incident where the task should be completed. Leave empty to use current incident id. |
| task_name | The name of the task that should be completed. If no task name entered, will complete all tasks which state is \`task_state\`. |
| max_timeout | Timeout time in seconds, that the script will try to complete tasks. |
| interval_between_tries | Time \(seconds\) to sleep between each check iteration.  |
| complete_task | Whether to also complete the task, or just check if it's completed. Can be True or False. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| WaitAndCompleteTask.CompletedTask | Task name that was completed by script. | String |
| WaitAndCompleteTask.FoundTask | Tasks that were found by script. | Unknown |


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

