Creates external ask links for the `Ask` task with the given name in the current investigation.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Core REST API
* core-api-get

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| task_name | The name of the Ask task in the playbook to generate links. |
| inc_id | The investigation id for which generate the links. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Ask.Links.taskName | The name of the task in the playbook for which this link is created. | String |
| Ask.Links.link | The link generated for the option. | String |
| Ask.Links.option | The option for which this link is created. | String |
| Ask.Links.taskID | The id of the task in the playbook for which this link is created. | Number |
