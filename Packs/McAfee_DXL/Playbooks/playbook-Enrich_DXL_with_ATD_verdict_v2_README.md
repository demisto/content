Uses McAfee ATD to push any malicious verdicts over DXL.
Detonates a file in ATD and if malicious, pushes its MD5, SHA1 and SHA256 hashes to McAfee DXL.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* ATD - Detonate File

### Integrations
* McAfee DXL

### Scripts
* Exists

### Commands
* closeInvestigation
* dxl-send-event

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Enrich DXL with ATD verdict v2](Insert the link to your image here)