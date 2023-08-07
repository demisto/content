Runs the polling command repeatedly, completes a blocking manual task when polling is done.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ids | List of IDs to poll |
| pendingIds | IDs with pending status |
| pollingCommand | Name of the polling command to run |
| pollingCommandArgName | Name of the argument of the polling command |
| interval | Polling frequency - how often the polling command should run \(minutes\) |
| timeout | How much time to poll before declaring a timeout and resuming the playbook \(minutes\) |
| playbookId | The ID of the playbook that contains the manual task which will be completed once the polling is done. |
| tag | The tag of the blocking manual task \("Wait For Polling Task To Finish"\) |
| additionalPollingCommandArgNames | Names of additional arguments for the polling command \(e.g. arg1,arg2,...\) |
| additionalPollingCommandArgValues | Commas separated arguments values of the polling command |
| scheduledEntryGuid | The GUID of the scheduled entry that runs the polling command. |
| endTime | The time to end the polling. |

## Outputs

---
There are no outputs for this script.
