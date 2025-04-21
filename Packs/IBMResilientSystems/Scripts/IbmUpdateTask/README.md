Use this script to update an IBM QRadar SOAR incident's task. This script should be run within an incident.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Dependencies

---
This script uses the following commands and scripts.

* IBM Resilient Systems
* rs-update-task

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| task_id | ID of task to update. |
| name | Task name. Technically required, copy original task name if no changes are desired. |
| owner_id | User ID of the new owner. |
| due_date | Task due date in ISO format e.g. "2020-02-02T19:00:00Z. Empty date indicates that the task has no assigned due date. |
| phase | The phase to which this task belongs. |
| status | Changing the status field, completes or re-openes the task. |

## Outputs

---
There are no outputs for this script.
