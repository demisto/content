Handles each fetched Darktrace model breach by gathering additional detail about the activity and device, providing enrichment data from Darktrace and XSOAR, linking similar incidents, and giving the ability to acknowledge the model breach and close the incident.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Entity Enrichment - Generic v3

### Integrations
* Darktrace

### Scripts
* Print
* FindSimilarIncidents
* IsIntegrationAvailable

### Commands
* darktrace-get-breach
* linkIncidents
* darktrace-acknowledge
* closeInvestigation
* darktrace-list-similar-devices
* darktrace-get-device-identity-info

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Handle Darktrace Model Breach](https://raw.githubusercontent.com/katherinemcgauleydarktrace/DarktraceXSOARImages/master/Handle_Darktrace_Model_Breach_Wed_Dec_02_2020.png)