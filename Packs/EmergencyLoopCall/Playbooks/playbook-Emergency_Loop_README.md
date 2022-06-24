This playbook implements an emergeny loop of calls using Twilio integration. Requires a list in the form of <number>|<CortexXSOARuser> and will end if a user replyes and takes charge of the emergency. Twilio integration will send an email with specific details, that will be handled by specific playbook (incident assigner) that will assign the user to the original emergency incident.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Emergency Calls

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* ListRandomizer
* GetTime
* getMailByUser

### Commands
* send-mail
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Emergency Loop](Insert the link to your image here)