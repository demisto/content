This script is an example script of how to link an incident to a task in Cherwell. The script wraps the cherwell-link-business-object command of the cherwell integration. When writing your own script to link business objects, follow the instructions found in the configuration section of the script, but do not change the execution section.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Cherwell |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* cherwell-link-business-objects

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_record_id | Incident record ID. |
| task_record_id | Task record ID. |

## Outputs

---
There are no outputs for this script.
