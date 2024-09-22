Use this script to add a task to an IBM QRadar SOAR incident.

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
* rs-add-custom-task

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| name | Task name. |
| description | Task description. |
| instructions | Textual instructions for the task. This will override the default instructions for the task. |
| due_date | Task due date in ISO format e.g., "2020-02-02T19:00:00Z. Empty date indicates that the task has no assigned due date. |
| owner_id | The owner of the task \(ID or name as appears in IBM QRadar SOAR\). Leave empty if the task has no owner. |
| phase | Task to be added to the IBM QRadar incident. |

## Outputs

---
There are no outputs for this script.
