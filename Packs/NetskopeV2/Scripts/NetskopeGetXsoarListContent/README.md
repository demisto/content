Reads (and creates if missing) an XSOAR List by name - used to track Netskope file hash list content between playbook runs, since Netskope's v1 hash-list API has no read-back endpoint.

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
| listName | Name of the XSOAR List to read (created empty if it does not already exist). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| XsoarList.name | Name of the XSOAR List that was read. | String |
| XsoarList.content | Raw content of the list (empty string if it was just created). | String |
