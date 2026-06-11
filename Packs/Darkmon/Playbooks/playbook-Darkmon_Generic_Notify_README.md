# Darkmon - Generic Notify

Provider-agnostic notification dispatcher. Reads the "Darkmon - Notification Provider" List for the configured target (`slack` | `teams` | `email` | `servicenow` | `jira`) and routes to the matching command. Falls back to logging the subject in the War Room when no provider is configured.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Slack v3
* Microsoft Teams
* Mail Sender (New)
* ServiceNow v2
* Jira V3

### Scripts

* PrintErrorEntry

### Commands

* send-notification
* send-mail
* servicenow-create-ticket
* jira-create-issue

## Playbook Inputs

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Subject | Short subject of the notification. |  | Required |
| Body | Body of the notification (markdown supported by most providers). |  | Required |
| SlackChannel | Slack channel (used only when provider=slack). | #soc-alerts | Optional |
| TeamsChannel | Teams channel (used only when provider=teams). |  | Optional |
| EmailTo | Email recipients (used only when provider=email). |  | Optional |

## Playbook Outputs

There are no outputs for this playbook.
