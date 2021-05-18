Subplaybook to support Expanse Handle Incident playbook.
Load a list to be used in Expanse playbook.
Create the list if it does not exist.

Supported Cortex XSOAR versions: 6.0.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* IsListExist

### Commands
* setList
* createList
* getList

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ListName | Name of the list to load. List will be created if it does not exist/empty. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ParsedList | Contents of parsed list. | unknown |

## Playbook Image
---
![Expanse Load-Create List](https://raw.githubusercontent.com/demisto/content/d0830e20f52f390a75c5ac3752f52c9df7ab77f1/Packs/ExpanseV2/doc_files/Expanse_Load_Create_List.png)