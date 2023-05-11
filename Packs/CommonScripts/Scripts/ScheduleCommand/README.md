Schedules a command to run inside the War Room at a future time. Can be once or reoccurring.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Schedule Task and Poll

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| command | The command to schedule |
| cron | The scheduled time to run |
| endDate | When should we end the schedule. Will be only relevant if times is not provided. Optional. Format is 'Mon, 02 Jan 2006 15:04:05 MST' |
| times | The number of times to run. Optional. |
| scheduledEntryGuid | The GUID of the scheduled entry that runs the polling command. |

## Outputs

---
There are no outputs for this script.
