# Primary Playbook to Handle ASM sourced Alerts.

This playbook aims to provide enrichment of ASM alerts by searching for mentions of associated IP addresses within 
Third-Party asset inventory tools (ServiceNow CMDB) and for vulnerability details from Vulnerability Assessment tools (Tenable.io.)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex ASM - Extract IP Indicator
* Cortex ASM - ServiceNow CMDB Enrichment
* Cortex ASM - Vulnerability Management Enrichment

### Integrations
There are no integrations for this playbook.

### Scripts
There are no scripts for this playbook.

### Commands
There are no commands for this playbook.

## Playbook Inputs
---
There are not inputs for this playbook.


## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - ASM Alert](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ASM_Alert.png)