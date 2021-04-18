This playbook is intended to be run as an adhoc job to quickly create a custom content bundle with only selected items from the servers custom content.

Then you can import this new zip on the other XSOAR server.

Create a Job with the Type “XSOAR Dev to Prod”, and select this playbook to get started. For more information on Jobs: https://xsoar.pan.dev/docs/incidents/incident-jobs

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Demisto REST API

### Scripts
* CustomContentBundleWizardry
* IsDemistoRestAPIInstanceAvailable

### Commands
* setIncident
* demisto-api-download
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.