DEPRECATED. Use "McAfee ePO Endpoint Compliance Playbook v2" playbook instead. Discovers endpoints that are not using the latest McAfee AV Signatures.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* ServiceNow
* epo

### Scripts
* CloseInvestigation
* commentsToContext
* IncidentSet

### Commands
* servicenow-incidents-query
* epo-update-client-dat
* servicenow-incident-create
* epo-get-current-dat
* epo-get-latest-dat

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![McAfee_ePO_Endpoint_Compliance_Playbook](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/McAfee_ePO_Endpoint_Compliance_Playbook.png)
