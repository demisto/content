

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* MISP V3

### Scripts

* misp_setfile_atributes
* misp_setmail_attributes
* SetAndHandleEmpty
* DeleteContext

### Commands

* misp-add-url-object
* misp-add-ip-object
* misp-add-object

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| misp_event_id |  |  | Optional |
| indicator |  |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![MISP - Set Attributes to Update](../doc_files/MISP_-_Set_Attributes_to_Update.png)
