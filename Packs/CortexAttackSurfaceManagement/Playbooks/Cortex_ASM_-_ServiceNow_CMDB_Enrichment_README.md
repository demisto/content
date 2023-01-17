Given the IP address this playbook enriches ServiceNow CMDB information relevant to ASM alerts.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* ServiceNow CMDB Search

### Integrations
* ServiceNow v2

### Scripts
* GridFieldSetup
* GetTime

### Commands
* servicenow-query-users

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | IP address of service | alert.remoteip | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - ServiceNow CMDB Enrichment](../doc_files/Cortex_ASM_-_ServiceNow_CMDB_Enrichment.png)