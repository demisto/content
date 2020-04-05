Schedules the polling task. This script is called by the `GenericPolling` playbook.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | - |
| Demisto Version | 4.0.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ids | The list of IDs to poll. |
| pollingCommand | The name of the polling command to run. |
| pollingCommandArgName | The name of the argument of the polling command. |
| dt | The DT filter for polling IDs. |
| playbookId | The ID of the playbook that contains the manual task which will be completed once the polling is done. |
| interval | The frequency to poll. How often the polling command should run (in minutes). |
| timeout | The amount of time to poll before declaring a timeout and resume the playbook (in minutes). |
| tag | The tag of the blocking manual task ("Wait For Polling Task To Finish"). |
| additionalPollingCommandArgNames | The names of additional arguments for the polling command. For example, "arg1,arg2,...". |
| additionalPollingCommandArgValues | The values of the additional arguments for the polling command. For example, "value1,value2,...". |

## Outputs
---
There are no outputs for this script.
