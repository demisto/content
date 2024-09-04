Use this script to add a task with a tag (the "Task tag to IBM" defined in the instance configuration) as an entry in XSOAR, which will then be mirrored as a task to an IBM QRadar SOAR incident. This script should be run within an incident.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description**                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------|
| note              | task to be added to the IBM QRadar SOAR incident.                                                                      |
| tags              | The task tag. Use the task entry tag \(defined in your instance configuration\) to mirror the task to IBM QRadar SOAR. |

## Outputs

---
There are no outputs for this script.
