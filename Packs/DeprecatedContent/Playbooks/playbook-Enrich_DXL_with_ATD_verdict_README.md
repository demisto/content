Deprecated. Use "Enrich DXL with ATD verdict v2" playbook instead. Example of using McAfee ATD and pushing any malicious verdicts over DXL.
Detonates a file in ATD and if malicious - push its MD5, SHA1 and SHA256 hashes to McAfee DXL.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* 

### Integrations
* McAfee DXL

### Scripts
* Exists
* CloseInvestigation

### Commands
* dxl-send-event

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Enrich DXL with ATD verdict](Insert the link to your image here)