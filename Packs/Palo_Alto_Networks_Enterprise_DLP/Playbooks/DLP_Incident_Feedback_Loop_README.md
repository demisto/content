This playbook collects feedback from the user about blocked files.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SlackV3
* Palo_Alto_Networks_Enterprise_DLP
* Mail Sender (New)

### Scripts
* DlpAskFeedback
* isError
* Set

### Commands
* setIncident
* pan-dlp-exemption-eligible
* send-mail
* slack-get-user-details
* pan-dlp-update-incident
* send-notification

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
