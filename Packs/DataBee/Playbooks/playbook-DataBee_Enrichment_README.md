

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

DataBee

### Scripts

* JsonToTable
* Print

### Commands

* databee-device-search
* databee-finding-search
* databee-user-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| SearchTerm | Enter a string to be used for enrichment. This string can represent a device name, username, or finding name. The command will search the provided value and return all results that contain the specified string. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![DataBee Enrichment](../doc_files/DataBee_Enrichment.png)
