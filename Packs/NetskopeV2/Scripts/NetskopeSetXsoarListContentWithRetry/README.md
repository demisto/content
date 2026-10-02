Writes to a Cortex XSOAR List via `setList`, retrying a few times on a transient Elasticsearch version-conflict (409) error - used to track Netskope file hash list content between playbook runs.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* setList

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| listName | The name of the Cortex XSOAR List to write to. |
| listData | The full content to save to the list. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.XsoarList.Name | The name of the Cortex XSOAR List that was written. | String |
| Netskope.XsoarList.Content | The content that was saved to the list. | String |
