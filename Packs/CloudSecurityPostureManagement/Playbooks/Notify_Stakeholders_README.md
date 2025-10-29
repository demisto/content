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

This playbook does not use any scripts.

### Commands

* send-mail
* slack-send-notification-quick-action
* taskReopen
* teams-send-notification-quick-action

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Teams Channel | Provide Microsoft Teams channel name to which to send messages. |  | Optional |
| Slack Channel | Provide Slack channel name to which to send messages. |  | Optional |
| Email Address | Provide an email address for notifications. Use comma separated values to provide multiple addresses | amore@paloaltonetworks.com | Optional |
| Message | The text to include in your notification. | Issue Name - ${issue.name}<br/>Severity ${issue.severity}<br/>Details - ${issue.details}<br/>Category - ${issue.alert_category}<br/>Asset Name - ${Core.CoreAsset.xdm__asset__name}<br/>Asset Type - ${Core.CoreAsset.xdm__asset__type__name}<br/>Cloud Region - ${Core.CoreAsset.xdm__asset__cloud__region}<br/>Cloud Account ID - ${Core.CoreAsset.xdm__asset__realm}<br/>Issue Created - ${issue.created} | Optional |
| Subject | For email |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Notify Stakeholders](../doc_files/Notify_Stakeholders.png)
