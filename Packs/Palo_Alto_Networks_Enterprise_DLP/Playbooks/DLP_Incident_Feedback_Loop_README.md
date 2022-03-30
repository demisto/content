Collect feedback from user about blocked files

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Palo_Alto_Networks_Enterprise_DLP
* SlackV3
* Mail Sender (New)

### Scripts
* Set
* DlpAskFeedback
* isError

### Commands
* pan-dlp-update-incident
* send-notification
* slack-get-user-details
* send-mail
* setIncident
* pan-dlp-exemption-eligible

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.