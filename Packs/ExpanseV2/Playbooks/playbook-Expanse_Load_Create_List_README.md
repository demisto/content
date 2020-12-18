Subplaybook for Handl Expanse Incident playbooks.
Load a list to be used in Expanse playbook.
Create the list if it does not exist.


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
* getList
* createList
* setList

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ListName | Name of the list to load. List will be created if it does not exist/empty. | {} | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ParsedList | Contents of parsed list. | unknown |

## Playbook Image
---
![Expanse Load-Create List](Insert the link to your image here)