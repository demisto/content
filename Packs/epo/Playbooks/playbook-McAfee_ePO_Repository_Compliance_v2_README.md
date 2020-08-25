Ensures that ePO servers are updated to the latest McAfee published AV signatures (DAT file version).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* epo

### Scripts
* Sleep
* AreValuesEqual

### Commands
* closeInvestigation
* send-mail
* epo-update-repository
* epo-get-current-dat
* setIncident
* epo-get-latest-dat

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![McAfee ePO Repository Compliance Playbook v2](Insert the link to your image here)