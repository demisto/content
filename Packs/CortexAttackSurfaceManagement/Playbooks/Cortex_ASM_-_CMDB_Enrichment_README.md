# Playbook to Look up ASM discovered IPs in ServiceNow CMDB

This playbook will look up a CI in ServiceNow CMDB by IP.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
There are no sub-playbooks for this playbook.

### Integrations
* ServiceNow CMDB

### Scripts
There are no scripts for this playbook.

### Commands
* servicenow-cmdb-records-list
* servicenow-cmdb-record-get-by-id

## Playbook Inputs
---
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | IP address to search in ServiceNow | | True |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - ServiceNow CMDB Enrichment](https://raw.githubusercontent.com/demisto/content/master/Packs/CortexAttackSurfaceManagement/doc_files/Cortex_ASM_-_ServiceNow_CMDB_Enrichment.png)