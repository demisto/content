Use this script to simplify the process of creating or updating a record in Keylight (v2). You specify custom arguments for which to populate the components. The arguments in this documentation are meant as examples only.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* kl-get-component
* kl-get-records

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| task_id | The task ID \(task name\) of the task to create. This is not a lookup field. |
| project | The project name to create. This is a lookup field. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Keylight.JSON | The format needed to create or update a record in Keylight\(v2\). | Unknown |
