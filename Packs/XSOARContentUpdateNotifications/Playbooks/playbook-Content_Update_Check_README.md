Deprecated. Use "Content Update Manager" playbook instead. This playbook will check to see if there are any content updates available for installed packs and notify users via e-mail or Slack.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Check For Content Installation

### Integrations
* SlackV2

### Scripts
* GetServerURL
* Set

### Commands
* closeInvestigation
* send-notification
* setIncident
* send-mail
* demisto-api-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| notificationemail | Provide semi-colon delimited e-mail addresses that will be used for the new content notifications. You will require an integration installed and configured that supports the send-mail command. | incident.contentnotificationemail | Required |
| slackuser | Provide a Slack username to which the notifications will be sent to. You will require Slack integration to be installed and configured. | incident.contentnotificationslackusername | Optional |
| slackchannel | Provide a Slack channel to which the notifications will be sent to. You will require Slack integration to be installed and configured. Also, ensure that the XSOAR application has access to this channel. | incident.contentnotificationslackchannel | Optional |
| packs | A CSV of packs to monitor | incident.contentpackselection | Required |

## Playbook Outputs
---
There are no outputs for this playbook.
