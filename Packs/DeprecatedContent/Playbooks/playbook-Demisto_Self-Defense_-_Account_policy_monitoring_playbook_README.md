Deprecated. Get list of Demisto users through the REST API, and alert if any non-SAML user accounts are found.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* slack
* Demisto REST API
* Twilio

### Scripts
* CloseInvestigation

### Commands
* demisto-api-get
* slack-send
* setIncident
* TwilioSendSMS

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Demisto Self-Defense - Account policy monitoring playbook](Insert the link to your image here)