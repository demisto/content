Runs the polling command repeatedly and completes a blocking manual task when polling is done.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | - |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ids | The list of IDs to poll. |
| pendingIds | The IDs with pending status. |
| pollingCommand | The name of the polling command to run. |
| pollingCommandArgName | The name of the argument of the polling command. |
| interval | The frequency to poll. How often the polling command should run (in minutes). |
| timeout | The amount of time to poll before declaring a timeout and resuming the playbook (in minutes). |
| playbookId | The ID of the playbook that contains the manual task which will be completed once the polling is done. |
| tag | The tag of the blocking manual task ("Wait For Polling Task To Finish"). |
| additionalPollingCommandArgNames | The names of the additional arguments for the polling command. For example, arg1,arg2,...  |
| additionalPollingCommandArgValues | The commas-separated arguments values of the polling command. |

## Outputs
---
There are no outputs for this script.
