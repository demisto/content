This playbook deletes custom content from the system. It deletes playbooks, scripts, layouts, incident types and incident fields.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext
* PrintErrorEntry
* Print
* DeleteContent
* GetIdsFromCustomContent

### Commands

core-api-download

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| dry_run | If true, will not actually delete any content entities. | true | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DeleteCustomContent](../doc_files/DeleteCustomContent.png)
