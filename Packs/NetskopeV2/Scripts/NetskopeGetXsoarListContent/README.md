Reads (and creates if missing) a Cortex XSOAR List by name - used to track Netskope file hash list content between playbook runs, since Netskope's v1 hash-list API has no read-back endpoint.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* getList
* createList

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| listName | The name of the Cortex XSOAR List to read (created empty if it does not already exist). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.XsoarList.Name | The name of the Cortex XSOAR List that was read. | String |
| Netskope.XsoarList.Content | The raw content of the list (empty string if it was just created). | String |
