This playbook is focused on detecting Credential Dumping attack as researched by Accenture Security analysts and engineers.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Dedup - Generic v3
* Entity Enrichment - Generic v3

### Integrations
* SplunkPy
* Carbon Black Enterprise EDR
* Tanium Threat Response
* ServiceNow v2

### Scripts
* IncreaseIncidentSeverity

### Commands
* extractIndicators
* servicenow-update-ticket
* cb-eedr-device-quarantine
* isWhitelisted
* tanium-tr-get-file-info
* tanium-tr-delete-file-from-endpoint
* servicenow-create-ticket
* splunk-search

##Playbook Inputs
There are no inputs for this playbook.

## Playbook Outputs
There are no outputs for this playbook.
