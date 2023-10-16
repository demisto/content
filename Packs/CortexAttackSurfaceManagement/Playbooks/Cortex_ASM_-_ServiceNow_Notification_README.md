This playbook is used to create ServiceNow tickets directed toward service owners to notify them of their internet exposures.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

Cortex ASM - Remediation Guidance

### Integrations

ServiceNow v2

### Scripts

GridFieldSetup

### Commands

servicenow-create-ticket

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| OwnerNotificationBody | Body of the notification \(email or ticket\) sent to the potential service owner. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - ServiceNow Notification](../doc_files/Cortex_ASM_-_ServiceNow_Notification.png)
