This playbook automates notifying stakeholders via Slack v3, Microsoft Teams, or email. You have the flexibility to notify other teams via Slack, Microsoft Teams or Email by configuring the necessary integration. This playbook requires existing integrations with Slack, Microsoft Teams, Mail Sender or Gmail to perform these actions. If none of these integrations are found in your account, the playbook will exit with no action.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Microsoft Teams
* SlackV3
* mail-sender

### Scripts

* Print
* Set
* SetIfEmpty
* MapValuesTransformer

### Commands

* send-mail
* send-notification (SlackV3)
* teams-send-notification-quick-action

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Teams Channel | Provide the Microsoft Teams channel to send messages to. |  | Optional |
| Slack Channel | Provide the Slack channel to send messages to. |  | Optional |
| Email Address | Provide an email address for notifications. Use comma separated values to provide multiple addresses |  | Optional |
| Subject | For email | You have a new message for - ${issue.name} | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Notify Stakeholders](../doc_files/Notify_Stakeholders.png)
