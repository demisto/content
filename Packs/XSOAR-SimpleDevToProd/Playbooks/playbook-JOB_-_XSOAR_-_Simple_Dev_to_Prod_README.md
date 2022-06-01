This playbook is intended to be run as an adhoc job to quickly create a custom content bundle with only selected items from the servers custom content.  You can import this new zip on the other XSOAR server, or push it to production using the Demisto REST API integration.

Please ensure to read the setup instructions for this pack carefully.

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
* demisto-api-download
* closeInvestigation
* demisto-api-multipart
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| dev_2_prod | Set this to True to enable pushing the selected content to the Production XSOAR server.   | True | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.