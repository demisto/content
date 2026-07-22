This playbook is used to create Jira tickets directed toward service owners to notify them of their internet exposures. If a Jira project key is not provided in playbook input the user will be asked to input the Jira project key.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

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
| JiraProjectKey | The Jira project key to associate with the issue. |  | Optional |
| RemediationGuidance | Remediation Guidance of the Attack Surface Rule. |  | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Jira Notification](../doc_files/Cortex_ASM_-_Jira_Notification.png)
