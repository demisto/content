### Description
This playbook will be used to send mail with list of incidents which are in risk state.We are using two custom sla fields known as containsla and resolutionsla. Initially this playbook will search incidents with any of the custom sla field on risk. If any incidents is returned than it will use automation script "AtRiskIncidentsNotification" for sending mail to analysts which contain list of incidents which are in risk state and sla is going to breach soon.Else it will close the incident.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook use EWS O365 integration.

### Scripts
* SearchIncidentsV2
* AtRiskIncidentsNotification

### Commands
This playbook does not use !send-mail command.

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![JOB-Get At Risk Incidents](Insert the link to your image here)
