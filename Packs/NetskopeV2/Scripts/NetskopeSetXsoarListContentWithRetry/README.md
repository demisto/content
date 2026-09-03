Writes to an XSOAR List via `setList`, retrying a few times on a transient Elasticsearch version-conflict (409) error - used to track Netskope file hash list content between playbook runs.

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
| listName | Name of the XSOAR List to write to. |
| listData | Full content to save to the list. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| XsoarList.name | Name of the XSOAR List that was written. | String |
| XsoarList.content | Content that was saved to the list. | String |
