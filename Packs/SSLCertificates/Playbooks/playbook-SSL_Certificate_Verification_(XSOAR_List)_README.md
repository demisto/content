Demo playbook to take a list of addresses from a specified XSOAR list, process the status of the SSL certificate for each address, and generate war room and email outputs for the status of each certificate. 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* SetGridField
* SSLVerifierV2_ParseOutput
* SSLVerifierV2_GenerateEmailBody
* SSLVerifierV2

### Commands
* send-mail

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![SSL Certificate Verification (XSOAR List)](../doc_files/SSL_Certificate_Verification.png)