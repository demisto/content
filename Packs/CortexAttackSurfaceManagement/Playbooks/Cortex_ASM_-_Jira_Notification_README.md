This playbook is used to create Jira tickets directed toward service owners to notify them of their internet exposures.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

Cortex ASM - Remediation Guidance

### Integrations

This playbook does not use any integrations.

### Scripts

GridFieldSetup

### Commands

jira-create-issue

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| OwnerNotificationBody | Body of the notification \(email or ticket\) sent to the potential service owner. |  | Required |
| JiraProjectKey | The Jira project key to associate with the issue. | XPANSE | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Jira Notification](../doc_files/Cortex_ASM_-_Jira_Notification.png)
